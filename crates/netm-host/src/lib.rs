//! # netm-host
//!
//! Host side of the NetM tunnel: accepts a guest session over TCP (or a USB
//! serial port, see [`HostConfig::serial`]), answers link-local discovery
//! probes, and terminates the guest's IP packets in a user-space TCP/IP
//! stack ([`ipstack`]) whose flows are forwarded through ordinary sockets.
//! No elevated privileges are required.
//!
//! The crate exposes a single entry point, [`run`], driven by an event channel
//! (for a TUI or a headless logger) and a command watch channel:
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! use netm_host::{run, HostCommand, HostConfig, HostEvent};
//!
//! let (events_tx, mut events_rx) = tokio::sync::mpsc::channel::<HostEvent>(256);
//! let (ctrl_tx, ctrl_rx) = tokio::sync::watch::channel(HostCommand::Run);
//! tokio::spawn(async move {
//!     while let Some(ev) = events_rx.recv().await {
//!         println!("{ev:?}");
//!     }
//! });
//! // ... later: ctrl_tx.send(HostCommand::Shutdown)?;
//! run(HostConfig::default(), events_tx, ctrl_rx).await
//! # }
//! ```
//!
//! **Runtime requirement:** `run` (and the flows it spawns) must execute on a
//! multi-threaded Tokio runtime. `ipstack` blocks briefly inside `Drop` of its
//! TCP streams via `block_in_place`, which panics on a `current_thread`
//! runtime.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use netm_proto::discovery::Responder;
use netm_proto::{Counters, LinkInterface, RateMeter, TunnelConfig, DATA_PORT};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub use netm_proto::Endpoint;

pub mod device;
pub mod dns;
pub(crate) mod flow;
pub(crate) mod session;

/// Interval of `HostEvent::Stats`.
pub const STATS_INTERVAL: Duration = Duration::from_millis(500);
/// Interval at which candidate interfaces are re-enumerated.
pub const INTERFACE_POLL_INTERVAL: Duration = Duration::from_secs(3);
/// Pause between attempts to open an unavailable serial port.
pub const SERIAL_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Where a guest is connected from: a TCP peer or a serial port. Alias of
/// [`netm_proto::Endpoint`].
pub type Peer = Endpoint;

/// Serial port the host serves a guest on, in addition to TCP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerialSettings {
    /// Device path (`/dev/tty.usbmodem1234`, `/dev/ttyACM0`, `COM5`).
    pub path: String,
    /// Line speed; default [`netm_proto::transport::serial::DEFAULT_BAUD`].
    pub baud: u32,
}

impl SerialSettings {
    /// `path` at the default baud rate.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            baud: netm_proto::transport::serial::DEFAULT_BAUD,
        }
    }
}

/// Host configuration.
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// TCP port of the data listener (default [`DATA_PORT`]). See
    /// [`bind_addr`](Self::bind_addr) for how the two interact.
    pub data_port: u16,
    /// Exact socket address to bind the data listener to (default
    /// `[::]:DATA_PORT`, dual-stack). Port `0` picks an ephemeral port (used
    /// by tests). If this field still carries the default port while
    /// `data_port` was changed, `data_port` wins, so setting only `data_port`
    /// behaves as expected. Discovery always advertises the port actually
    /// bound.
    pub bind_addr: SocketAddr,
    /// Addressing handed to the guest in the `Config` frame.
    pub tunnel: TunnelConfig,
    /// Name announced in discovery offers and `Hello` (default: hostname).
    pub host_name: String,
    /// Upstream DNS resolvers. `None` = read the system resolvers and refresh
    /// them every 30 s.
    pub dns_upstreams: Option<Vec<SocketAddr>>,
    /// Also serve a guest over this serial port (USB CDC-ACM fallback for
    /// cables that do not form a network link). The port is (re)opened
    /// every [`SERIAL_RETRY_INTERVAL`] until it exists, the host then waits
    /// for the guest's `Hello`; after a session ends the port is closed and
    /// reopened. TCP listening continues in parallel; only one guest is
    /// served at a time across both transports.
    pub serial: Option<SerialSettings>,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            data_port: DATA_PORT,
            bind_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DATA_PORT),
            tunnel: TunnelConfig::default(),
            host_name: default_host_name(),
            dns_upstreams: None,
            serial: None,
        }
    }
}

impl HostConfig {
    /// Set both `data_port` and the port of `bind_addr`.
    pub fn with_port(mut self, port: u16) -> Self {
        self.data_port = port;
        self.bind_addr.set_port(port);
        self
    }

    /// The address `run` binds: `bind_addr`, unless only `data_port` was
    /// customised.
    pub fn effective_bind_addr(&self) -> SocketAddr {
        if self.bind_addr.port() == DATA_PORT && self.data_port != DATA_PORT {
            SocketAddr::new(self.bind_addr.ip(), self.data_port)
        } else {
            self.bind_addr
        }
    }
}

/// The machine's hostname, or `"netm-host"` if it cannot be determined.
pub fn default_host_name() -> String {
    hostname::get()
        .ok()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "netm-host".to_string())
}

/// Transport protocol of a flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// A forwarded flow as seen when it was opened.
#[derive(Clone, Debug)]
pub struct FlowInfo {
    pub id: u64,
    pub proto: Proto,
    /// Guest-side endpoint (inside the tunnel).
    pub src: SocketAddr,
    /// Original destination requested by the guest.
    pub dst: SocketAddr,
    /// Bytes guest → internet (always `0` in `FlowOpened`; final value in
    /// `FlowClosed`).
    pub tx_bytes: u64,
    /// Bytes internet → guest.
    pub rx_bytes: u64,
    pub opened_at: Instant,
}

/// A connected guest.
#[derive(Clone, Debug)]
pub struct GuestInfo {
    /// TCP address or serial port the guest is connected through.
    pub peer: Peer,
    pub name: String,
    pub connected_at: Instant,
    pub assigned_ip: Ipv4Addr,
}

/// Events emitted by [`run`].
#[derive(Clone, Debug)]
pub enum HostEvent {
    /// The data listener is bound.
    Listening {
        addr: SocketAddr,
    },
    /// Candidate link interfaces; emitted on start and whenever the list
    /// changes.
    Interfaces(Vec<LinkInterface>),
    /// The configured serial port was opened (`open = true`, now waiting for
    /// a guest) or closed (`open = false`, will be reopened).
    SerialState {
        path: String,
        open: bool,
    },
    GuestConnected(GuestInfo),
    GuestDisconnected {
        peer: Peer,
        reason: String,
    },
    FlowOpened(FlowInfo),
    FlowClosed {
        id: u64,
        tx_bytes: u64,
        rx_bytes: u64,
    },
    /// Periodic (every 500 ms) traffic snapshot. `tx` = host → guest, `rx` =
    /// guest → host, rates in bit/s. Dropped (not queued) when the event
    /// channel is full.
    Stats {
        counters: Counters,
        tx_bps: f64,
        rx_bps: f64,
        active_flows: usize,
    },
    /// Human readable log line (also emitted via `tracing::info`).
    Log(String),
    /// One-shot tunnel transport capacity probe (not Internet speed).
    LinkSpeed(netm_proto::LinkSpeed),
    /// Non-fatal error description.
    Error(String),
}

/// Commands accepted by [`run`] through the watch channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostCommand {
    Run,
    Shutdown,
}

/// Event sender with the channel policy baked in: `Stats` never blocks,
/// everything else awaits capacity.
#[derive(Clone, Debug)]
pub(crate) struct Emitter {
    tx: mpsc::Sender<HostEvent>,
}

impl Emitter {
    pub(crate) fn new(tx: mpsc::Sender<HostEvent>) -> Self {
        Self { tx }
    }

    pub(crate) async fn send(&self, ev: HostEvent) {
        let _ = self.tx.send(ev).await;
    }

    pub(crate) fn try_stats(&self, ev: HostEvent) {
        let _ = self.tx.try_send(ev);
    }

    pub(crate) async fn log(&self, msg: impl Into<String>) {
        let msg = msg.into();
        tracing::info!("{msg}");
        self.send(HostEvent::Log(msg)).await;
    }

    pub(crate) async fn error(&self, msg: impl Into<String>) {
        let msg = msg.into();
        tracing::error!("{msg}");
        self.send(HostEvent::Error(msg)).await;
    }
}

/// State shared by the listener, the session and its flows.
pub(crate) struct Shared {
    pub tunnel: TunnelConfig,
    pub host_name: String,
    pub events: Emitter,
    pub meter: Arc<RateMeter>,
    pub dns: dns::Upstreams,
    pub active_flows: Arc<AtomicUsize>,
    pub next_flow_id: AtomicU64,
    /// The one guest currently served (TCP or serial).
    pub active_guest: Mutex<Option<Peer>>,
}

impl Shared {
    /// Take the single guest slot for `peer`; `false` if it is taken.
    pub(crate) fn claim_guest(&self, peer: &Peer) -> bool {
        let mut slot = self.active_guest.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return false;
        }
        *slot = Some(peer.clone());
        true
    }

    /// Free the slot if `peer` holds it.
    pub(crate) fn release_guest(&self, peer: &Peer) {
        let mut slot = self.active_guest.lock().unwrap_or_else(|e| e.into_inner());
        if slot.as_ref() == Some(peer) {
            *slot = None;
        }
    }

    pub(crate) fn active_guest(&self) -> Option<Peer> {
        self.active_guest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Run the host until `ctrl` turns to [`HostCommand::Shutdown`] (or its
/// sender is dropped), or a fatal error occurs (e.g. the listener cannot be
/// bound). Sessions are closed and background tasks aborted before returning.
///
/// Only one guest is served at a time; further connections receive `Bye`.
pub async fn run(
    cfg: HostConfig,
    events: mpsc::Sender<HostEvent>,
    mut ctrl: watch::Receiver<HostCommand>,
) -> anyhow::Result<()> {
    if *ctrl.borrow() == HostCommand::Shutdown {
        return Ok(());
    }
    let emitter = Emitter::new(events);

    let bind_addr = cfg.effective_bind_addr();
    let listener = netm_proto::transport::tcp::listen(bind_addr)
        .await
        .with_context(|| format!("cannot listen on {bind_addr}"))?;
    let local_addr = listener.local_addr().context("listener local_addr")?;
    emitter
        .send(HostEvent::Listening { addr: local_addr })
        .await;
    emitter
        .log(format!(
            "listening on {local_addr} (guest {} gateway {} mtu {})",
            cfg.tunnel.guest_ip, cfg.tunnel.gateway_ip, cfg.tunnel.mtu
        ))
        .await;

    let excluded_dns = vec![
        IpAddr::V4(cfg.tunnel.dns),
        IpAddr::V4(cfg.tunnel.gateway_ip),
    ];
    let dns_upstreams = match &cfg.dns_upstreams {
        Some(list) => dns::Upstreams::fixed(list.clone(), excluded_dns),
        None => {
            let excluded = excluded_dns;
            tokio::task::spawn_blocking(move || dns::Upstreams::from_system(excluded))
                .await
                .context("reading system DNS")?
        }
    };
    emitter
        .log(format!("DNS upstreams: {:?}", dns_upstreams.get()))
        .await;

    let shared = Arc::new(Shared {
        tunnel: cfg.tunnel.clone(),
        host_name: cfg.host_name.clone(),
        events: emitter.clone(),
        meter: Arc::new(RateMeter::default()),
        dns: dns_upstreams.clone(),
        active_flows: Arc::new(AtomicUsize::new(0)),
        next_flow_id: AtomicU64::new(1),
        active_guest: Mutex::new(None),
    });

    let root_cancel = CancellationToken::new();
    let mut background: Vec<JoinHandle<()>> = Vec::new();

    // Serial port session loop (optional, runs alongside TCP).
    let mut serial_task: Option<JoinHandle<()>> = cfg.serial.clone().map(|settings| {
        tokio::spawn(serial_loop(
            settings,
            Arc::clone(&shared),
            root_cancel.child_token(),
        ))
    });

    // Stats ticker.
    background.push(tokio::spawn(stats_task(
        Arc::clone(&shared),
        root_cancel.child_token(),
    )));
    // DNS refresh.
    if !dns_upstreams.is_fixed() {
        background.push(tokio::spawn(dns_refresh_task(
            dns_upstreams,
            root_cancel.child_token(),
        )));
    }
    // Interface watcher + discovery responder.
    background.push(tokio::spawn(discovery_task(
        local_addr.port(),
        cfg.host_name.clone(),
        emitter.clone(),
        root_cancel.child_token(),
    )));

    let mut current: Option<(Peer, JoinHandle<()>)> = None;
    let result = loop {
        tokio::select! {
            changed = ctrl.changed() => {
                let shutdown = changed.is_err() || *ctrl.borrow() == HostCommand::Shutdown;
                if shutdown {
                    emitter.log("shutdown requested").await;
                    break Ok(());
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let _ = netm_proto::transport::tcp::tune(&stream);
                    let peer = Peer::Tcp(peer);
                    // Busy if a TCP session task is still alive (it may be in
                    // its handshake) or any guest (TCP or serial) holds the slot.
                    let tcp_busy = matches!(&current, Some((_, h)) if !h.is_finished());
                    let active = if tcp_busy {
                        current.as_ref().map(|(p, _)| p.clone())
                    } else {
                        shared.active_guest()
                    };
                    if let Some(active) = active {
                        emitter
                            .log(format!("rejecting guest {peer}: {active} is already connected"))
                            .await;
                        tokio::spawn(session::reject_busy(stream));
                        continue;
                    }
                    let handle = tokio::spawn(session::run_session(
                        netm_proto::framed(stream),
                        peer.clone(),
                        Arc::clone(&shared),
                        root_cancel.child_token(),
                    ));
                    current = Some((peer, handle));
                }
                Err(e) => {
                    // Transient accept errors (EMFILE, ECONNABORTED...) should
                    // not kill the host; back off briefly.
                    emitter.error(format!("accept failed: {e}")).await;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            },
        }
    };

    // Orderly teardown: sessions send Bye and stop, then background tasks go.
    root_cancel.cancel();
    let mut sessions: Vec<JoinHandle<()>> = Vec::new();
    if let Some((_, handle)) = current.take() {
        sessions.push(handle);
    }
    if let Some(handle) = serial_task.take() {
        sessions.push(handle);
    }
    for mut handle in sessions {
        if tokio::time::timeout(Duration::from_secs(3), &mut handle)
            .await
            .is_err()
        {
            handle.abort();
        }
    }
    for h in background {
        h.abort();
    }
    drop(listener);
    result
}

/// Serve guests on a serial port until `cancel` fires: open the port
/// (retrying while it is absent), wait for a `Hello`, run the session, then
/// close and reopen the port for the next guest.
async fn serial_loop(settings: SerialSettings, shared: Arc<Shared>, cancel: CancellationToken) {
    use futures::SinkExt as _;
    let peer = Peer::Serial(settings.path.clone());
    let mut last_open_error: Option<String> = None;
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let port = match netm_proto::transport::serial::open(&settings.path, settings.baud).await {
            Ok(p) => p,
            Err(e) => {
                let msg = e.to_string();
                if last_open_error.as_deref() != Some(msg.as_str()) {
                    shared
                        .events
                        .log(format!(
                            "serial port {} unavailable ({msg}); retrying every {}s",
                            settings.path,
                            SERIAL_RETRY_INTERVAL.as_secs()
                        ))
                        .await;
                    last_open_error = Some(msg);
                }
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(SERIAL_RETRY_INTERVAL) => continue,
                }
            }
        };
        last_open_error = None;
        shared
            .events
            .log(format!(
                "serial port {} opened ({} baud), waiting for a guest",
                settings.path, settings.baud
            ))
            .await;
        shared
            .events
            .send(HostEvent::SerialState {
                path: settings.path.clone(),
                open: true,
            })
            .await;

        let mut framed = netm_proto::framed_sync(port);
        let end = match session::wait_for_hello(&mut framed, &shared, &cancel).await {
            Ok(None) => "host shutting down".to_string(),
            Ok(Some(name)) => session::serve_connected(
                framed,
                peer.clone(),
                name,
                Arc::clone(&shared),
                cancel.child_token(),
            )
            .await
            .unwrap_or_else(|| "another guest is already connected".to_string()),
            Err(e) => {
                let _ = framed.close().await;
                e
            }
        };
        shared
            .events
            .send(HostEvent::SerialState {
                path: settings.path.clone(),
                open: false,
            })
            .await;
        if cancel.is_cancelled() {
            shared
                .events
                .log(format!("serial port {} closed", settings.path))
                .await;
            return;
        }
        shared
            .events
            .log(format!(
                "serial port {} closed ({end}); reopening",
                settings.path
            ))
            .await;
        // Let the device settle (and avoid a hot loop on a flapping port).
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }
}

async fn stats_task(shared: Arc<Shared>, cancel: CancellationToken) {
    let mut tick = tokio::time::interval(STATS_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tick.tick() => {
                let (tx_bps, rx_bps) = shared.meter.rates();
                shared.events.try_stats(HostEvent::Stats {
                    counters: shared.meter.counters(),
                    tx_bps,
                    rx_bps,
                    active_flows: shared.active_flows.load(Ordering::Relaxed),
                });
            }
        }
    }
}

async fn dns_refresh_task(upstreams: dns::Upstreams, cancel: CancellationToken) {
    let mut tick = tokio::time::interval(dns::REFRESH_INTERVAL);
    tick.tick().await; // first tick fires immediately; the list was just read
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tick.tick() => {
                let u = upstreams.clone();
                let _ = tokio::task::spawn_blocking(move || u.refresh()).await;
            }
        }
    }
}

/// Keeps the interface list fresh (emitting `Interfaces` on change) and runs
/// the discovery responder, re-binding it whenever the set of usable
/// interfaces changes so newly plugged links get their multicast join.
async fn discovery_task(
    data_port: u16,
    host_name: String,
    emitter: Emitter,
    cancel: CancellationToken,
) {
    let mut last_list: Option<Vec<LinkInterface>> = None;
    let mut joined: Vec<u32> = Vec::new();
    let mut responder: Option<JoinHandle<()>> = None;
    let mut warned_bind = false;

    let mut tick = tokio::time::interval(INTERFACE_POLL_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tick.tick() => {}
        }
        let list = match tokio::task::spawn_blocking(netm_proto::list_candidate_interfaces).await {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => {
                if last_list.is_none() {
                    emitter
                        .error(format!("cannot enumerate interfaces: {e}"))
                        .await;
                    last_list = Some(Vec::new());
                }
                continue;
            }
            Err(_) => continue,
        };
        if last_list.as_ref() != Some(&list) {
            emitter.send(HostEvent::Interfaces(list.clone())).await;
            if let Some(prev) = &last_list {
                for l in &list {
                    if l.is_ready() && !prev.iter().any(|p| p.name == l.name && p.is_ready()) {
                        emitter
                            .log(format!(
                                "link {} is up ({})",
                                l.name,
                                l.link_local_v6.map(|a| a.to_string()).unwrap_or_default()
                            ))
                            .await;
                    }
                }
                for p in prev {
                    if p.is_ready() && !list.iter().any(|l| l.name == p.name && l.is_ready()) {
                        emitter.log(format!("link {} is down", p.name)).await;
                    }
                }
            }
            last_list = Some(list.clone());
        }

        // (Re)bind the responder when the set of joinable interfaces changes.
        let mut want: Vec<u32> = list
            .iter()
            .filter(|l| l.index != 0)
            .map(|l| l.index)
            .collect();
        want.sort_unstable();
        want.dedup();
        let alive = responder.as_ref().is_some_and(|h| !h.is_finished());
        if alive && want == joined {
            continue;
        }
        if let Some(h) = responder.take() {
            h.abort();
        }
        match Responder::bind(&list, data_port, host_name.clone()).await {
            Ok(r) => {
                joined = want;
                let names: Vec<&str> = list.iter().map(|l| l.name.as_str()).collect();
                tracing::info!(port = data_port, interfaces = ?names, "discovery responder ready");
                let emitter = emitter.clone();
                responder = Some(tokio::spawn(async move {
                    if let Err(e) = r.run().await {
                        emitter
                            .error(format!("discovery responder stopped: {e}"))
                            .await;
                    }
                }));
            }
            Err(e) => {
                if !warned_bind {
                    warned_bind = true;
                    emitter
                        .error(format!(
                            "discovery disabled (cannot bind UDP {}): {e}; guests must connect manually",
                            netm_proto::DISCOVERY_PORT
                        ))
                        .await;
                }
            }
        }
    }
    if let Some(h) = responder {
        h.abort();
    }
}
