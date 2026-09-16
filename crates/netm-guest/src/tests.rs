//! State-machine and packet-pump tests against an in-memory environment: a
//! fake TUN, a `tokio::io::duplex` transport with a tiny fake host, and a
//! recording platform configurator. No privileges required.

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use netm_proto::discovery::Discovered;
use netm_proto::{
    framed, framed_sync, Endpoint, Frame, FrameIo, LinkInterface, LinkKind, TunnelConfig,
};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use crate::env::GuestEnv;
use crate::guest::{next_retry_backoff, Guest, Timings};
use crate::platform::PlatformConfigurator;
use crate::tun::fake::{FakeTun, FakeTunHandle};
use crate::{GuestCommand, GuestConfig, GuestEvent, GuestState, HostTarget, RouteMode};

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type Log = Arc<Mutex<Vec<String>>>;

struct FakeConfigurator {
    log: Log,
    applied: bool,
}

impl PlatformConfigurator for FakeConfigurator {
    fn apply(
        &mut self,
        tun: &str,
        cfg: &TunnelConfig,
        routes: &RouteMode,
        set_dns: bool,
    ) -> anyhow::Result<()> {
        self.applied = true;
        self.log.lock().unwrap().push(format!(
            "apply {tun} {} {} dns={set_dns}",
            cfg.guest_ip,
            match routes {
                RouteMode::Full => "full".to_string(),
                RouteMode::Custom(v) => format!("custom{v:?}"),
            }
        ));
        Ok(())
    }
    fn revert(&mut self) -> anyhow::Result<()> {
        if self.applied {
            self.applied = false;
            self.log.lock().unwrap().push("revert".to_string());
        }
        Ok(())
    }
}

impl Drop for FakeConfigurator {
    fn drop(&mut self) {
        if self.applied {
            self.log.lock().unwrap().push("revert-on-drop".to_string());
        }
    }
}

struct FakeEnv {
    ifaces: Arc<Mutex<Vec<LinkInterface>>>,
    discovered: Option<Discovered>,
    neighbor: Option<SocketAddr>,
    links: Arc<Mutex<VecDeque<io::Result<DuplexStream>>>>,
    serials: Arc<Mutex<VecDeque<io::Result<DuplexStream>>>>,
    tuns: Arc<Mutex<VecDeque<FakeTun>>>,
    cfg_log: Log,
    probes: Arc<Mutex<u32>>,
}

impl GuestEnv for FakeEnv {
    type Tun = FakeTun;
    type Link = DuplexStream;
    type Serial = DuplexStream;

    async fn list_interfaces(&mut self) -> io::Result<Vec<LinkInterface>> {
        Ok(self.ifaces.lock().unwrap().clone())
    }

    /// Mirrors the real carrier check: tests unplug a cable by clearing the
    /// interface's link-local address.
    fn link_active(&mut self, iface: &str) -> Option<bool> {
        self.ifaces
            .lock()
            .unwrap()
            .iter()
            .find(|i| i.name == iface)
            .map(|i| i.is_ready())
    }

    async fn local_egress(&mut self) -> Option<String> {
        Some("fake-egress0".to_string())
    }

    async fn probe(
        &mut self,
        _iface: &LinkInterface,
        _timeout: Duration,
    ) -> io::Result<Option<Discovered>> {
        *self.probes.lock().unwrap() += 1;
        Ok(self.discovered.clone())
    }

    async fn neighbor_target(&mut self, _iface: &LinkInterface) -> Option<SocketAddr> {
        self.neighbor
    }

    async fn connect(&mut self, _addr: SocketAddr, _timeout: Duration) -> io::Result<DuplexStream> {
        match self.links.lock().unwrap().pop_front() {
            Some(l) => l,
            None => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "no more fake links",
            )),
        }
    }

    async fn open_serial(&mut self, _path: &str, _baud: u32) -> io::Result<DuplexStream> {
        match self.serials.lock().unwrap().pop_front() {
            Some(port) => port,
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no more fake serial ports",
            )),
        }
    }

    async fn open_tun(&mut self, _cfg: &TunnelConfig) -> io::Result<FakeTun> {
        self.tuns
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| io::Error::other("no fake tun available"))
    }

    fn configurator(&mut self) -> Box<dyn PlatformConfigurator> {
        Box::new(FakeConfigurator {
            log: self.cfg_log.clone(),
            applied: false,
        })
    }
}

fn bridge_iface(ready: bool) -> LinkInterface {
    LinkInterface {
        name: "bridge0".into(),
        index: 20,
        is_up: true,
        link_local_v6: ready.then(|| "fe80::1".parse().unwrap()),
        kind: LinkKind::ThunderboltBridge,
    }
}

fn host_addr() -> SocketAddrV6 {
    SocketAddrV6::new(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xbeef),
        netm_proto::DATA_PORT,
        0,
        20,
    )
}

/// Frames the fake host received (other than echoed packets).
struct FakeHost {
    /// Frames to inject towards the guest.
    inject: mpsc::Sender<Frame>,
    /// Control frames (Hello/Ping/Pong/Bye) and packets seen from the guest.
    seen: mpsc::Receiver<Frame>,
}

/// Spawn a host that completes the handshake, echoes `IpPacket`s, answers
/// `Ping` with `Pong`, and forwards injected frames.
fn spawn_fake_host(stream: DuplexStream, config: TunnelConfig) -> FakeHost {
    spawn_fake_host_framed(framed(stream), config)
}

fn spawn_fake_host_framed<S: FrameIo + 'static>(mut f: S, config: TunnelConfig) -> FakeHost {
    let (inject_tx, mut inject_rx) = mpsc::channel::<Frame>(16);
    let (seen_tx, seen_rx) = mpsc::channel::<Frame>(64);
    tokio::spawn(async move {
        let hello = f.next().await;
        let Some(Ok(Frame::Hello { version, name })) = hello else {
            panic!("expected Hello, got {hello:?}");
        };
        assert_eq!(version, netm_proto::PROTOCOL_VERSION);
        let _ = seen_tx.send(Frame::Hello { version, name }).await;
        f.send(Frame::Hello {
            version: netm_proto::PROTOCOL_VERSION,
            name: "fakehost".into(),
        })
        .await
        .unwrap();
        f.send(Frame::Config(config)).await.unwrap();
        let _ = netm_proto::speed::run_as_responder(&mut f, netm_proto::speed::Params::for_tests())
            .await;
        loop {
            tokio::select! {
                Some(frame) = inject_rx.recv() => {
                    let is_bye = frame == Frame::Bye;
                    if f.send(frame).await.is_err() || is_bye {
                        if is_bye {
                            // Wait a moment for the guest to drain, then close.
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                        break;
                    }
                }
                frame = f.next() => {
                    match frame {
                        Some(Ok(Frame::IpPacket(p))) => {
                            let _ = seen_tx.send(Frame::IpPacket(p.clone())).await;
                            if f.send(Frame::IpPacket(p)).await.is_err() { break; }
                        }
                        Some(Ok(Frame::Ping(t))) => {
                            let _ = seen_tx.send(Frame::Ping(t)).await;
                            if f.send(Frame::Pong(t)).await.is_err() { break; }
                        }
                        Some(Ok(other)) => {
                            let is_bye = other == Frame::Bye;
                            let _ = seen_tx.send(other).await;
                            if is_bye { break; }
                        }
                        Some(Err(_)) | None => break,
                    }
                }
            }
        }
    });
    FakeHost {
        inject: inject_tx,
        seen: seen_rx,
    }
}

fn fast_timings() -> Timings {
    Timings {
        retry_backoff: Duration::from_millis(50),
        max_retry_backoff: Duration::from_millis(200),
        probe_timeout: Duration::from_millis(100),
        connect_timeout: Duration::from_millis(500),
        handshake_timeout: Duration::from_secs(2),
        ping_interval: Duration::from_millis(150),
        keepalive_timeout: Duration::from_secs(5),
        stats_interval: Duration::from_millis(50),
        link_poll: Duration::from_millis(100),
        iface_refresh: Duration::from_millis(100),
        send_timeout: Duration::from_secs(1),
        speed: netm_proto::speed::Params::for_tests(),
    }
}

#[test]
fn reconnect_backoff_doubles_and_caps() {
    let max = Duration::from_secs(30);
    let mut delay = Duration::from_secs(1);
    let mut seen = vec![delay];
    for _ in 0..6 {
        delay = next_retry_backoff(delay, max);
        seen.push(delay);
    }
    assert_eq!(seen, [1, 2, 4, 8, 16, 30, 30].map(Duration::from_secs));
}

struct Harness {
    ifaces: Arc<Mutex<Vec<LinkInterface>>>,
    links: Arc<Mutex<VecDeque<io::Result<DuplexStream>>>>,
    serials: Arc<Mutex<VecDeque<io::Result<DuplexStream>>>>,
    tuns: Arc<Mutex<VecDeque<FakeTun>>>,
    cfg_log: Log,
    probes: Arc<Mutex<u32>>,
    events: mpsc::Receiver<GuestEvent>,
    ctrl: watch::Sender<GuestCommand>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    last_speed: Option<netm_proto::LinkSpeed>,
}

impl Harness {
    /// Build one fake link (guest side queued for `connect`) and its host.
    fn add_link(
        links: &Arc<Mutex<VecDeque<io::Result<DuplexStream>>>>,
        config: TunnelConfig,
    ) -> FakeHost {
        let (a, b) = tokio::io::duplex(64 * 1024);
        links.lock().unwrap().push_back(Ok(a));
        spawn_fake_host(b, config)
    }

    fn start(
        cfg: GuestConfig,
        ifaces: Vec<LinkInterface>,
        discovered: Option<Discovered>,
    ) -> Harness {
        Self::start_with_neighbor(cfg, ifaces, discovered, None)
    }

    fn start_with_neighbor(
        cfg: GuestConfig,
        ifaces: Vec<LinkInterface>,
        discovered: Option<Discovered>,
        neighbor: Option<SocketAddr>,
    ) -> Harness {
        let ifaces = Arc::new(Mutex::new(ifaces));
        let links = Arc::new(Mutex::new(VecDeque::new()));
        let serials = Arc::new(Mutex::new(VecDeque::new()));
        let tuns = Arc::new(Mutex::new(VecDeque::new()));
        let cfg_log: Log = Arc::default();
        let probes = Arc::new(Mutex::new(0));
        let env = FakeEnv {
            ifaces: ifaces.clone(),
            discovered,
            neighbor,
            links: links.clone(),
            serials: serials.clone(),
            tuns: tuns.clone(),
            cfg_log: cfg_log.clone(),
            probes: probes.clone(),
        };
        let (ev_tx, ev_rx) = mpsc::channel(1024);
        let (ctrl_tx, ctrl_rx) = watch::channel(GuestCommand::Run);
        let task = tokio::spawn(Guest::new(cfg, env, ev_tx, ctrl_rx, fast_timings()).run());
        Harness {
            ifaces,
            links,
            serials,
            tuns,
            cfg_log,
            probes,
            events: ev_rx,
            ctrl: ctrl_tx,
            task,
            last_speed: None,
        }
    }

    fn add_tun(&self, name: &str) -> FakeTunHandle {
        let (tun, handle) = FakeTun::new(name);
        self.tuns.lock().unwrap().push_back(tun);
        handle
    }

    fn add_serial(&self, config: TunnelConfig) -> FakeHost {
        let (guest, host) = tokio::io::duplex(64 * 1024);
        self.serials.lock().unwrap().push_back(Ok(guest));
        spawn_fake_host_framed(framed_sync(host), config)
    }

    async fn next_event(&mut self) -> GuestEvent {
        timeout(Duration::from_secs(5), self.events.recv())
            .await
            .expect("timed out waiting for event")
            .expect("event channel closed")
    }

    /// Consume events until `pred` matches, returning the matching state.
    async fn wait_state(&mut self, pred: impl Fn(&GuestState) -> bool) -> GuestState {
        loop {
            match self.next_event().await {
                GuestEvent::LinkSpeed(s) => self.last_speed = Some(s),
                GuestEvent::StateChanged(s) if pred(&s) => return s,
                _ => {}
            }
        }
    }

    async fn wait_stats(&mut self, pred: impl Fn(&netm_proto::Counters, f64, f64) -> bool) {
        loop {
            if let GuestEvent::Stats {
                counters,
                tx_bps,
                rx_bps,
            } = self.next_event().await
            {
                if pred(&counters, tx_bps, rx_bps) {
                    return;
                }
            }
        }
    }

    fn cfg_log(&self) -> Vec<String> {
        self.cfg_log.lock().unwrap().clone()
    }

    async fn finish(self) -> anyhow::Result<()> {
        timeout(Duration::from_secs(5), self.task)
            .await
            .expect("guest task did not finish")
            .expect("guest task panicked")
    }
}

async fn expect_seen(host: &mut FakeHost, pred: impl Fn(&Frame) -> bool) -> Frame {
    loop {
        let f = timeout(Duration::from_secs(5), host.seen.recv())
            .await
            .expect("timed out waiting for host to see frame")
            .expect("fake host gone");
        if pred(&f) {
            return f;
        }
    }
}

fn auto_cfg(reconnect: bool) -> GuestConfig {
    GuestConfig {
        name: "test-guest".into(),
        host: HostTarget::Auto,
        routes: RouteMode::Full,
        set_dns: true,
        reconnect,
    }
}

fn discovered() -> Discovered {
    Discovered {
        host_addr: host_addr(),
        host_name: "fakehost".into(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_session_echo_ping_stats_and_host_bye() {
    let mut h = Harness::start(
        auto_cfg(false),
        vec![bridge_iface(true)],
        Some(discovered()),
    );
    let mut tun = h.add_tun("faketun0");
    let mut host = Harness::add_link(&h.links, TunnelConfig::default());

    // Startup reports where traffic goes while there is no tunnel, then the
    // interface list.
    let mut egress = None;
    let first = loop {
        match h.next_event().await {
            GuestEvent::LocalEgress(e) => egress = e,
            GuestEvent::Log(_) | GuestEvent::LinkSpeed(_) => {}
            other => break other,
        }
    };
    assert_eq!(egress.as_deref(), Some("fake-egress0"));
    assert!(
        matches!(first, GuestEvent::Interfaces(ref l) if l.len() == 1),
        "{first:?}"
    );
    let s = h
        .wait_state(|s| matches!(s, GuestState::Discovering { .. }))
        .await;
    assert_eq!(
        s,
        GuestState::Discovering {
            iface: "bridge0".into()
        }
    );
    let s = h
        .wait_state(|s| matches!(s, GuestState::Connecting { .. }))
        .await;
    assert_eq!(
        s,
        GuestState::Connecting {
            host: Endpoint::Tcp(SocketAddr::from(host_addr()))
        }
    );
    let s = h
        .wait_state(|s| matches!(s, GuestState::Connected { .. }))
        .await;
    let GuestState::Connected {
        host: connected_host,
        host_name,
        tun: tun_name,
        config,
        ..
    } = s
    else {
        unreachable!()
    };
    assert_eq!(connected_host, Endpoint::Tcp(SocketAddr::from(host_addr())));
    assert_eq!(host_name, "fakehost");
    assert_eq!(tun_name, "faketun0");
    assert_eq!(config, TunnelConfig::default());
    assert_eq!(h.cfg_log(), vec!["apply faketun0 10.77.0.2 full dns=true"]);
    let speed = h.last_speed.expect("link speed probe should have run");
    assert!(speed.up_bytes > 0 && speed.down_bytes > 0, "{speed:?}");

    // Host saw our Hello with the configured name.
    let hello = expect_seen(&mut host, |f| matches!(f, Frame::Hello { .. })).await;
    assert_eq!(
        hello,
        Frame::Hello {
            version: netm_proto::PROTOCOL_VERSION,
            name: "test-guest".into()
        }
    );

    // TUN → host → echoed back → TUN.
    let pkt: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x1c, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    ];
    tun.inject.send(pkt.clone()).await.unwrap();
    let seen = expect_seen(&mut host, |f| matches!(f, Frame::IpPacket(_))).await;
    assert_eq!(seen, Frame::IpPacket(Bytes::from(pkt.clone())));
    let delivered = timeout(Duration::from_secs(2), tun.delivered.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivered, pkt);

    // Host Ping → guest Pong.
    host.inject.send(Frame::Ping(4242)).await.unwrap();
    let pong = expect_seen(&mut host, |f| matches!(f, Frame::Pong(_))).await;
    assert_eq!(pong, Frame::Pong(4242));

    // Guest sends its own Ping (fast interval in tests).
    expect_seen(&mut host, |f| matches!(f, Frame::Ping(_))).await;

    // Stats reflect one packet each way (16 bytes).
    h.wait_stats(|c, _, _| {
        c.tx_packets == 1 && c.rx_packets == 1 && c.tx_bytes == 16 && c.rx_bytes == 16
    })
    .await;

    // Host says Bye → Disconnected, and with reconnect=false run returns Ok.
    host.inject.send(Frame::Bye).await.unwrap();
    let s = h
        .wait_state(|s| matches!(s, GuestState::Disconnected { .. }))
        .await;
    let GuestState::Disconnected { reason } = s else {
        unreachable!()
    };
    assert!(reason.contains("Bye"), "{reason}");
    let log = h.cfg_log();
    h.finish().await.unwrap();
    assert_eq!(
        log,
        vec!["apply faketun0 10.77.0.2 full dns=true", "revert"]
    );
}

#[tokio::test]
async fn shutdown_while_connected_is_fast_and_sends_bye() {
    let mut h = Harness::start(auto_cfg(true), vec![bridge_iface(true)], Some(discovered()));
    let _tun = h.add_tun("faketun1");
    let mut host = Harness::add_link(&h.links, TunnelConfig::default());
    h.wait_state(|s| matches!(s, GuestState::Connected { .. }))
        .await;

    let t0 = std::time::Instant::now();
    h.ctrl.send(GuestCommand::Shutdown).unwrap();
    let log_before = h.cfg_log();
    let res = h.finish().await;
    assert!(
        t0.elapsed() < Duration::from_millis(500),
        "shutdown took {:?}",
        t0.elapsed()
    );
    res.unwrap();
    assert_eq!(log_before.len(), 1);
    let bye = expect_seen(&mut host, |f| matches!(f, Frame::Bye)).await;
    assert_eq!(bye, Frame::Bye);
}

#[tokio::test]
async fn waits_for_link_and_shuts_down_quickly() {
    let mut h = Harness::start(
        auto_cfg(true),
        vec![bridge_iface(false)],
        Some(discovered()),
    );
    let s = h
        .wait_state(|s| matches!(s, GuestState::WaitingForLink))
        .await;
    assert_eq!(s, GuestState::WaitingForLink);
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(
        *h.probes.lock().unwrap(),
        0,
        "must not probe an interface without link-local"
    );
    let t0 = std::time::Instant::now();
    h.ctrl.send(GuestCommand::Shutdown).unwrap();
    let probes = h.probes.clone();
    h.finish().await.unwrap();
    assert!(t0.elapsed() < Duration::from_millis(300));
    assert_eq!(*probes.lock().unwrap(), 0);
}

#[tokio::test]
async fn silent_multicast_falls_back_to_neighbour() {
    let neigh = SocketAddr::from(host_addr());
    let mut h = Harness::start_with_neighbor(
        auto_cfg(false),
        vec![bridge_iface(true)],
        None,
        Some(neigh),
    );
    let _tun = h.add_tun("faketun-usb");
    let _host = Harness::add_link(&h.links, TunnelConfig::default());
    let s = h
        .wait_state(|s| matches!(s, GuestState::Connected { .. }))
        .await;
    assert!(
        matches!(s, GuestState::Connected { ref host, .. } if host == &Endpoint::Tcp(neigh)),
        "{s:?}"
    );
    h.ctrl.send(GuestCommand::Shutdown).unwrap();
    h.finish().await.unwrap();
}

#[tokio::test]
async fn no_host_answer_keeps_discovering() {
    let mut h = Harness::start(auto_cfg(true), vec![bridge_iface(true)], None);
    h.wait_state(|s| matches!(s, GuestState::Discovering { .. }))
        .await;
    tokio::time::sleep(Duration::from_millis(650)).await;
    let probes = *h.probes.lock().unwrap();
    assert!(
        (4..=6).contains(&probes),
        "discovery should keep probing with capped exponential backoff, got {probes} attempts"
    );
    assert!(h.cfg_log().is_empty());
    h.ctrl.send(GuestCommand::Shutdown).unwrap();
    h.finish().await.unwrap();
}

#[tokio::test]
async fn link_loss_is_detected_and_reconnects() {
    let mut h = Harness::start(auto_cfg(true), vec![bridge_iface(true)], Some(discovered()));
    let _tun_a = h.add_tun("faketun2");
    let _host_a = Harness::add_link(&h.links, TunnelConfig::default());
    h.wait_state(|s| matches!(s, GuestState::Connected { .. }))
        .await;

    // Unplug: the interface loses its link-local address.
    h.ifaces.lock().unwrap()[0].link_local_v6 = None;
    let s = h
        .wait_state(|s| matches!(s, GuestState::Disconnected { .. }))
        .await;
    let GuestState::Disconnected { reason } = s else {
        unreachable!()
    };
    assert!(reason.contains("link bridge0 lost"), "{reason}");
    h.wait_state(|s| matches!(s, GuestState::WaitingForLink))
        .await;
    assert_eq!(
        h.cfg_log(),
        vec!["apply faketun2 10.77.0.2 full dns=true", "revert"]
    );

    // Plug back in: a second session comes up on a fresh link/tun.
    let _tun_b = h.add_tun("faketun3");
    let _host_b = Harness::add_link(&h.links, TunnelConfig::default());
    h.ifaces.lock().unwrap()[0].link_local_v6 = Some("fe80::1".parse().unwrap());
    let s = h
        .wait_state(|s| matches!(s, GuestState::Connected { .. }))
        .await;
    assert!(matches!(s, GuestState::Connected { ref tun, .. } if tun == "faketun3"));

    h.ctrl.send(GuestCommand::Shutdown).unwrap();
    let log = h.cfg_log.clone();
    h.finish().await.unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "apply faketun2 10.77.0.2 full dns=true",
            "revert",
            "apply faketun3 10.77.0.2 full dns=true",
            "revert",
        ]
    );
}

#[tokio::test]
async fn manual_target_with_custom_routes_and_no_dns() {
    let addr: SocketAddr = "[fe80::abcd%20]:27778".parse().unwrap();
    let cfg = GuestConfig {
        name: "g".into(),
        host: HostTarget::Manual(addr),
        routes: RouteMode::Custom(vec!["1.1.1.1/32".parse().unwrap()]),
        set_dns: false,
        reconnect: false,
    };
    let mut h = Harness::start(cfg, vec![bridge_iface(true)], None);
    let _tun = h.add_tun("faketun4");
    let mut host = Harness::add_link(&h.links, TunnelConfig::default());
    let s = h
        .wait_state(|s| matches!(s, GuestState::Connecting { .. }))
        .await;
    assert_eq!(
        s,
        GuestState::Connecting {
            host: Endpoint::Tcp(addr)
        }
    );
    h.wait_state(|s| matches!(s, GuestState::Connected { .. }))
        .await;
    assert_eq!(*h.probes.lock().unwrap(), 0, "manual target must not probe");
    assert_eq!(
        h.cfg_log(),
        vec!["apply faketun4 10.77.0.2 custom[1.1.1.1/32] dns=false"]
    );

    // Manual + link-local scope id ⇒ link watch is active too.
    h.ifaces.lock().unwrap()[0].link_local_v6 = None;
    let s = h
        .wait_state(|s| matches!(s, GuestState::Disconnected { .. }))
        .await;
    assert!(
        matches!(s, GuestState::Disconnected { ref reason } if reason.contains("link bridge0 lost"))
    );
    h.finish().await.unwrap();
    expect_seen(&mut host, |f| matches!(f, Frame::Bye)).await;
}

/// A manual link-local target must not be dialled while its interface has no
/// carrier: the connect can only fail, and retrying once a second fills the
/// log with "No route to host" instead of showing "waiting for the cable".
#[tokio::test]
async fn manual_target_waits_for_the_cable_instead_of_dialling() {
    let addr: SocketAddr = "[fe80::abcd%20]:27778".parse().unwrap();
    let cfg = GuestConfig {
        name: "g".into(),
        host: HostTarget::Manual(addr),
        routes: RouteMode::Full,
        set_dns: false,
        reconnect: true,
    };
    // Interface present but unplugged (no link-local address).
    let mut h = Harness::start(cfg, vec![bridge_iface(false)], None);
    h.wait_state(|s| matches!(s, GuestState::WaitingForLink))
        .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        h.links.lock().unwrap().is_empty(),
        "no fake link was queued, so a connect attempt would have errored"
    );
    assert!(h.cfg_log().is_empty(), "nothing may be configured yet");

    // Plug in: now it connects to exactly the address we were given.
    let _tun = h.add_tun("faketun9");
    let _host = Harness::add_link(&h.links, TunnelConfig::default());
    h.ifaces.lock().unwrap()[0].link_local_v6 = Some("fe80::1".parse().unwrap());
    let s = h
        .wait_state(|s| matches!(s, GuestState::Connected { .. }))
        .await;
    assert!(matches!(s, GuestState::Connected { host, .. } if host == Endpoint::Tcp(addr)));
    h.ctrl.send(GuestCommand::Shutdown).unwrap();
    h.finish().await.unwrap();
}

#[tokio::test]
async fn connect_failure_without_reconnect_returns_error() {
    let mut h = Harness::start(
        auto_cfg(false),
        vec![bridge_iface(true)],
        Some(discovered()),
    );
    // No link queued ⇒ connect fails with ConnectionRefused.
    let mut saw_error = false;
    loop {
        match h.next_event().await {
            GuestEvent::Error(e) => {
                assert!(e.contains("connecting"), "{e}");
                saw_error = true;
            }
            GuestEvent::StateChanged(GuestState::Disconnected { .. }) => break,
            _ => {}
        }
    }
    assert!(saw_error);
    let err = h.finish().await.unwrap_err();
    assert!(err.to_string().contains("connecting"), "{err}");
}

#[tokio::test]
async fn serial_target_uses_sync_framing_and_skips_network_discovery() {
    let path = "/dev/tty.usbmodem-netm-test";
    let cfg = GuestConfig {
        name: "serial-guest".into(),
        host: HostTarget::Serial {
            path: path.into(),
            baud: 921_600,
        },
        routes: RouteMode::Full,
        set_dns: true,
        reconnect: false,
    };
    let mut h = Harness::start(cfg, Vec::new(), None);
    let tun = h.add_tun("faketun-serial");
    let mut host = h.add_serial(TunnelConfig::default());

    let state = h
        .wait_state(|s| matches!(s, GuestState::Discovering { .. }))
        .await;
    assert_eq!(state, GuestState::Discovering { iface: path.into() });
    let state = h
        .wait_state(|s| matches!(s, GuestState::Connected { .. }))
        .await;
    assert!(matches!(
        state,
        GuestState::Connected {
            host: Endpoint::Serial(ref p),
            ref tun,
            ..
        } if p == path && tun == "faketun-serial"
    ));
    assert_eq!(*h.probes.lock().unwrap(), 0);

    let packet = vec![0x45, 0, 0, 4];
    tun.inject.send(packet.clone()).await.unwrap();
    assert_eq!(
        expect_seen(&mut host, |f| matches!(f, Frame::IpPacket(_))).await,
        Frame::IpPacket(Bytes::from(packet))
    );

    h.ctrl.send(GuestCommand::Shutdown).unwrap();
    h.finish().await.unwrap();
}

#[tokio::test]
async fn handshake_version_mismatch_is_rejected() {
    let h = Harness::start(
        auto_cfg(false),
        vec![bridge_iface(true)],
        Some(discovered()),
    );
    let _tun = h.add_tun("faketun5");
    let (a, b) = tokio::io::duplex(4096);
    h.links.lock().unwrap().push_back(Ok(a));
    tokio::spawn(async move {
        let mut f = framed(b);
        let _ = f.next().await;
        f.send(Frame::Hello {
            version: netm_proto::PROTOCOL_VERSION + 1,
            name: "old".into(),
        })
        .await
        .unwrap();
        f.send(Frame::Config(TunnelConfig::default()))
            .await
            .unwrap();
        while f.next().await.is_some() {}
    });
    let log = h.cfg_log.clone();
    let err = h.finish().await.unwrap_err();
    assert!(format!("{err:#}").contains("version mismatch"), "{err:#}");
    assert!(
        log.lock().unwrap().is_empty(),
        "no platform config before handshake succeeds"
    );
}

#[tokio::test]
async fn run_requires_root() {
    if netm_proto::privilege::is_root() {
        return; // cannot test the failure path as root
    }
    let (tx, _rx) = mpsc::channel(8);
    let (_ctl, ctl_rx) = watch::channel(GuestCommand::Run);
    let err = crate::run(GuestConfig::default(), tx, ctl_rx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("root"), "{err}");
    assert!(crate::requires_root());
}

#[test]
fn default_config_is_sane() {
    let c = GuestConfig::default();
    assert!(!c.name.is_empty());
    assert!(matches!(c.host, HostTarget::Auto));
    assert!(matches!(c.routes, RouteMode::Full));
    assert!(c.set_dns);
    assert!(c.reconnect);
    assert!(RouteMode::Full.default_set_dns());
    assert!(!RouteMode::Custom(vec![]).default_set_dns());
}
