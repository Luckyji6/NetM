//! The guest state machine: link watching → discovery → connect → handshake
//! → TUN + platform config → packet pump → teardown (→ reconnect).

use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use netm_proto::{
    framed, Frame, FramedTransport, LinkInterface, RateMeter, Transport, TunnelConfig,
};
use tokio::sync::{mpsc, watch};
use tokio::time::MissedTickBehavior;

use crate::env::GuestEnv;
use crate::platform::PlatformConfigurator;
use crate::tun::TunIo;
use crate::{GuestCommand, GuestConfig, GuestEvent, GuestState, HostTarget};

/// Tunables of the state machine (shrunk in tests).
#[derive(Clone, Debug)]
pub(crate) struct Timings {
    /// Pause between link/discovery rounds and before a reconnect attempt.
    pub retry_backoff: Duration,
    /// Discovery probe timeout per interface.
    pub probe_timeout: Duration,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Handshake (Hello/Config) timeout.
    pub handshake_timeout: Duration,
    /// Our keep-alive `Ping` interval.
    pub ping_interval: Duration,
    /// No frame received for this long ⇒ connection considered dead.
    pub keepalive_timeout: Duration,
    /// Stats event interval while connected.
    pub stats_interval: Duration,
    /// How often the carrier of the link interface is re-checked while
    /// connected.
    pub link_poll: Duration,
    /// How often the full interface list is refreshed for the UI while
    /// connected (spawns `networksetup` on macOS, so much slower than
    /// [`Self::link_poll`]).
    pub iface_refresh: Duration,
    /// Timeout for a single frame write (dead peer with a full TCP window).
    pub send_timeout: Duration,
    /// Link-capacity probe run once after the handshake.
    pub speed: netm_proto::speed::Params,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            retry_backoff: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(3),
            handshake_timeout: Duration::from_secs(5),
            // While the tunnel carries the default route, every second spent
            // not noticing that it is dead is a second of no network at all,
            // so the keep-alive is aggressive: a dead peer is detected in
            // ~6s, an unplugged cable in ~400ms via the carrier poll.
            ping_interval: Duration::from_secs(2),
            keepalive_timeout: Duration::from_secs(6),
            stats_interval: Duration::from_millis(500),
            link_poll: Duration::from_millis(400),
            iface_refresh: Duration::from_secs(3),
            send_timeout: Duration::from_secs(2),
            speed: netm_proto::speed::Params::default(),
        }
    }
}

/// Marker error: a `Shutdown` command arrived (or the control channel was
/// dropped).
#[derive(Debug)]
pub(crate) struct Shutdown;

/// Where to connect, produced by the discovery phase.
#[derive(Clone, Debug)]
struct Target {
    addr: SocketAddr,
    host_name: Option<String>,
    /// Interface whose link-local presence is watched while connected.
    link_iface: Option<String>,
}

/// How a connection attempt / session ended.
enum Outcome {
    Shutdown,
    /// Session was up and got lost.
    Lost(String),
    /// Could not get to the connected state.
    Failed(anyhow::Error),
}

enum SessionEnd {
    Shutdown,
    Lost(String),
    /// Host sent `Bye` or closed; no need to send our own `Bye`.
    HostClosed(String),
}

pub(crate) struct Guest<E: GuestEnv> {
    cfg: GuestConfig,
    env: E,
    events: mpsc::Sender<GuestEvent>,
    ctrl: watch::Receiver<GuestCommand>,
    timings: Timings,
    state: GuestState,
    last_ifaces: Option<Vec<LinkInterface>>,
}

async fn wait_shutdown(ctrl: &mut watch::Receiver<GuestCommand>) {
    // `Err` means the sender is gone: treat as shutdown too.
    let _ = ctrl.wait_for(|c| *c == GuestCommand::Shutdown).await;
}

/// Run `fut` unless/until a `Shutdown` arrives on `ctrl`.
async fn ctrl_aware<F: Future>(
    ctrl: &mut watch::Receiver<GuestCommand>,
    fut: F,
) -> Result<F::Output, Shutdown> {
    tokio::select! {
        biased;
        _ = wait_shutdown(ctrl) => Err(Shutdown),
        out = fut => Ok(out),
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Interface name for the scope id of a link-local manual target, if any.
fn iface_for_addr(addr: &SocketAddr, ifaces: &[LinkInterface]) -> Option<String> {
    match addr {
        SocketAddr::V6(v6) if v6.scope_id() != 0 => ifaces
            .iter()
            .find(|i| i.index == v6.scope_id())
            .map(|i| i.name.clone()),
        _ => None,
    }
}

async fn send_frame<T: Transport>(
    framed: &mut FramedTransport<T>,
    frame: Frame,
    timeout: Duration,
) -> Result<(), String> {
    match tokio::time::timeout(timeout, framed.send(frame)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("send failed: {e}")),
        Err(_) => Err("send timed out".to_string()),
    }
}

/// Guest side of the handshake: `Hello` → expect `Hello` then `Config`.
pub(crate) async fn handshake<T: Transport>(
    framed: &mut FramedTransport<T>,
    name: &str,
    timeout: Duration,
) -> Result<(String, TunnelConfig)> {
    let deadline = tokio::time::Instant::now() + timeout;
    tokio::time::timeout_at(
        deadline,
        framed.send(Frame::Hello {
            version: netm_proto::PROTOCOL_VERSION,
            name: name.to_string(),
        }),
    )
    .await
    .map_err(|_| anyhow!("handshake timed out sending Hello"))?
    .context("sending Hello")?;

    let host_name = match tokio::time::timeout_at(deadline, framed.next())
        .await
        .map_err(|_| anyhow!("handshake timed out waiting for Hello"))?
    {
        Some(Ok(Frame::Hello { version, name })) => {
            if version != netm_proto::PROTOCOL_VERSION {
                return Err(anyhow!(
                    "protocol version mismatch: host {version}, guest {}",
                    netm_proto::PROTOCOL_VERSION
                ));
            }
            name
        }
        Some(Ok(other)) => return Err(anyhow!("expected Hello, got {other:?}")),
        Some(Err(e)) => return Err(anyhow!("receiving Hello: {e}")),
        None => return Err(anyhow!("connection closed during handshake")),
    };

    let config = match tokio::time::timeout_at(deadline, framed.next())
        .await
        .map_err(|_| anyhow!("handshake timed out waiting for Config"))?
    {
        Some(Ok(Frame::Config(c))) => c,
        Some(Ok(other)) => return Err(anyhow!("expected Config, got {other:?}")),
        Some(Err(e)) => return Err(anyhow!("receiving Config: {e}")),
        None => return Err(anyhow!("connection closed during handshake")),
    };
    Ok((host_name, config))
}

/// Run `f` on the configurator on a blocking thread, handing it back.
async fn with_configurator<F>(
    mut c: Box<dyn PlatformConfigurator>,
    f: F,
) -> (Box<dyn PlatformConfigurator>, Result<()>)
where
    F: FnOnce(&mut dyn PlatformConfigurator) -> Result<()> + Send + 'static,
{
    match tokio::task::spawn_blocking(move || {
        let r = f(c.as_mut());
        (c, r)
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            // The closure panicked: the configurator was dropped inside the
            // blocking task, so its Drop already ran the best-effort revert.
            let err = anyhow!("platform configuration task panicked: {e}");
            (Box::new(NoopConfigurator), Err(err))
        }
    }
}

struct NoopConfigurator;

impl PlatformConfigurator for NoopConfigurator {
    fn apply(&mut self, _: &str, _: &TunnelConfig, _: &crate::RouteMode, _: bool) -> Result<()> {
        Ok(())
    }
    fn revert(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<E: GuestEnv> Guest<E> {
    pub(crate) fn new(
        cfg: GuestConfig,
        env: E,
        events: mpsc::Sender<GuestEvent>,
        ctrl: watch::Receiver<GuestCommand>,
        timings: Timings,
    ) -> Self {
        Self {
            cfg,
            env,
            events,
            ctrl,
            timings,
            state: GuestState::Disconnected {
                reason: "not started".into(),
            },
            last_ifaces: None,
        }
    }

    async fn emit(&self, ev: GuestEvent) {
        // A dropped receiver is not fatal; shutdown is signalled via `ctrl`.
        let _ = self.events.send(ev).await;
    }

    async fn log(&self, msg: impl Into<String>) {
        let msg = msg.into();
        tracing::info!("{msg}");
        self.emit(GuestEvent::Log(msg)).await;
    }

    async fn error(&self, msg: impl Into<String>) {
        let msg = msg.into();
        tracing::warn!("{msg}");
        self.emit(GuestEvent::Error(msg)).await;
    }

    async fn set_state(&mut self, new: GuestState) {
        if self.state != new {
            tracing::debug!(?new, "state");
            self.state = new.clone();
            self.emit(GuestEvent::StateChanged(new)).await;
        }
    }

    fn shutdown_requested(&self) -> bool {
        *self.ctrl.borrow() == GuestCommand::Shutdown
    }

    async fn sleep(&mut self, d: Duration) -> Result<(), Shutdown> {
        ctrl_aware(&mut self.ctrl, tokio::time::sleep(d)).await
    }

    /// Report which interface carries traffic while no tunnel is up.
    async fn report_local_egress(&mut self) {
        let iface = self.env.local_egress().await;
        match &iface {
            Some(name) => {
                self.log(format!("traffic goes through the local network via {name}"))
                    .await
            }
            None => {
                self.log("traffic goes through the local network (Wi-Fi / Ethernet)")
                    .await
            }
        }
        self.emit(GuestEvent::LocalEgress(iface)).await;
    }

    /// Re-list interfaces, emitting `Interfaces` when the list changed.
    async fn refresh_interfaces(&mut self) -> Vec<LinkInterface> {
        let list = match self.env.list_interfaces().await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "interface enumeration failed");
                Vec::new()
            }
        };
        if self.last_ifaces.as_ref() != Some(&list) {
            self.last_ifaces = Some(list.clone());
            self.emit(GuestEvent::Interfaces(list.clone())).await;
        }
        list
    }

    /// Main loop; returns after `Shutdown` (or after the first failure /
    /// disconnect when `reconnect` is off).
    pub(crate) async fn run(mut self) -> Result<()> {
        self.report_local_egress().await;
        loop {
            if self.shutdown_requested() {
                break;
            }
            let target = match self.find_target().await {
                Ok(Some(t)) => t,
                Ok(None) => continue,
                Err(Shutdown) => break,
            };
            match self.serve(target).await {
                Outcome::Shutdown => break,
                Outcome::Lost(reason) => {
                    self.set_state(GuestState::Disconnected {
                        reason: reason.clone(),
                    })
                    .await;
                    if !self.cfg.reconnect {
                        self.log(format!("disconnected ({reason}); reconnect disabled"))
                            .await;
                        return Ok(());
                    }
                    self.log(format!("disconnected ({reason}); reconnecting"))
                        .await;
                }
                Outcome::Failed(err) => {
                    let reason = format!("{err:#}");
                    self.error(reason.clone()).await;
                    self.set_state(GuestState::Disconnected {
                        reason: reason.clone(),
                    })
                    .await;
                    if !self.cfg.reconnect {
                        return Err(err);
                    }
                }
            }
            self.set_state(GuestState::WaitingForLink).await;
            if self.sleep(self.timings.retry_backoff).await.is_err() {
                break;
            }
        }
        self.log("guest stopped").await;
        Ok(())
    }

    /// Discovery phase. `Ok(None)` = nothing found this round (already
    /// slept); `Ok(Some)` = connect to this target.
    async fn find_target(&mut self) -> Result<Option<Target>, Shutdown> {
        let ifaces = self.refresh_interfaces().await;
        match self.cfg.host.clone() {
            HostTarget::Manual(addr) => {
                let link_iface = iface_for_addr(&addr, &ifaces);
                // A link-local target is unreachable until its interface has
                // a carrier; retrying regardless just fills the log with
                // "No route to host" once a second.
                if let Some(name) = link_iface.as_deref() {
                    if self.env.link_active(name) == Some(false) {
                        self.set_state(GuestState::WaitingForLink).await;
                        self.sleep(self.timings.retry_backoff).await?;
                        return Ok(None);
                    }
                }
                Ok(Some(Target {
                    addr,
                    host_name: None,
                    link_iface,
                }))
            }
            HostTarget::Auto => {
                let ready: Vec<LinkInterface> =
                    ifaces.into_iter().filter(|i| i.is_ready()).collect();
                if ready.is_empty() {
                    self.set_state(GuestState::WaitingForLink).await;
                    self.sleep(self.timings.retry_backoff).await?;
                    return Ok(None);
                }
                for iface in ready {
                    self.set_state(GuestState::Discovering {
                        iface: iface.name.clone(),
                    })
                    .await;
                    let probe = self.env.probe(&iface, self.timings.probe_timeout);
                    match ctrl_aware(&mut self.ctrl, probe).await? {
                        Ok(Some(d)) => {
                            self.log(format!(
                                "discovered host {} at {} via {}",
                                d.host_name, d.host_addr, iface.name
                            ))
                            .await;
                            return Ok(Some(Target {
                                addr: d.host_addr.into(),
                                host_name: Some(d.host_name),
                                link_iface: Some(iface.name),
                            }));
                        }
                        Ok(None) => {
                            tracing::debug!(iface = %iface.name, "no host answered multicast");
                            if let Some(addr) = self.env.neighbor_target(&iface).await {
                                self.log(format!(
                                    "组播未应答，改为直连 {} 上的邻居 {addr}",
                                    iface.name
                                ))
                                .await;
                                return Ok(Some(Target {
                                    addr,
                                    host_name: None,
                                    link_iface: Some(iface.name),
                                }));
                            }
                        }
                        Err(e) => {
                            tracing::debug!(iface = %iface.name, error = %e, "probe failed");
                        }
                    }
                }
                self.sleep(self.timings.retry_backoff).await?;
                Ok(None)
            }
        }
    }

    /// Connect, handshake, bring the tunnel up, pump until it ends, tear
    /// everything down.
    async fn serve(&mut self, target: Target) -> Outcome {
        let addr = target.addr;
        self.set_state(GuestState::Connecting { host: addr }).await;

        let link = match ctrl_aware(
            &mut self.ctrl,
            self.env.connect(addr, self.timings.connect_timeout),
        )
        .await
        {
            Err(Shutdown) => return Outcome::Shutdown,
            Ok(Err(e)) => return Outcome::Failed(anyhow!("connecting to {addr}: {e}")),
            Ok(Ok(l)) => l,
        };
        let mut framed = framed(link);

        let (host_name, tcfg) = match ctrl_aware(
            &mut self.ctrl,
            handshake(&mut framed, &self.cfg.name, self.timings.handshake_timeout),
        )
        .await
        {
            Err(Shutdown) => {
                let _ = send_frame(&mut framed, Frame::Bye, Duration::from_millis(200)).await;
                return Outcome::Shutdown;
            }
            Ok(Err(e)) => return Outcome::Failed(e.context("handshake")),
            Ok(Ok(v)) => v,
        };
        let host_name = target.host_name.clone().unwrap_or(host_name);
        self.log(format!(
            "handshake with {host_name} ok: {}/{} via {} dns {} mtu {}",
            tcfg.guest_ip, tcfg.prefix_len, tcfg.gateway_ip, tcfg.dns, tcfg.mtu
        ))
        .await;

        match ctrl_aware(
            &mut self.ctrl,
            netm_proto::speed::run_as_initiator(&mut framed, self.timings.speed),
        )
        .await
        {
            Err(Shutdown) => {
                let _ = send_frame(&mut framed, Frame::Bye, Duration::from_millis(200)).await;
                return Outcome::Shutdown;
            }
            Ok(Ok(speed)) => {
                tracing::info!(summary = %speed.summary(), "link capacity");
                self.emit(GuestEvent::LinkSpeed(speed)).await;
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "link capacity probe failed");
                self.log(format!("link capacity probe skipped: {e}")).await;
                if matches!(
                    e,
                    netm_proto::speed::Error::Closed | netm_proto::speed::Error::Codec(_)
                ) {
                    return Outcome::Failed(anyhow!("link capacity probe: {e}"));
                }
            }
        }

        let tun = match ctrl_aware(&mut self.ctrl, self.env.open_tun(&tcfg)).await {
            Err(Shutdown) => {
                let _ = send_frame(&mut framed, Frame::Bye, Duration::from_millis(200)).await;
                return Outcome::Shutdown;
            }
            Ok(Err(e)) => {
                let _ = send_frame(&mut framed, Frame::Bye, Duration::from_millis(200)).await;
                return Outcome::Failed(anyhow!("creating TUN device: {e}"));
            }
            Ok(Ok(t)) => t,
        };
        let tun_name = tun.name().to_string();

        let configurator = self.env.configurator();
        let (apply_tun, apply_cfg, apply_routes, apply_dns) = (
            tun_name.clone(),
            tcfg.clone(),
            self.cfg.routes.clone(),
            self.cfg.set_dns,
        );
        let (configurator, applied) = with_configurator(configurator, move |c| {
            c.apply(&apply_tun, &apply_cfg, &apply_routes, apply_dns)
        })
        .await;
        if let Err(e) = applied {
            let (_c, reverted) = with_configurator(configurator, |c| c.revert()).await;
            if let Err(re) = reverted {
                tracing::warn!(error = %re, "revert after failed apply reported errors");
            }
            let _ = send_frame(&mut framed, Frame::Bye, Duration::from_millis(200)).await;
            drop(tun);
            return Outcome::Failed(e.context("applying platform configuration"));
        }
        self.log(format!(
            "tunnel up on {tun_name}: routes {:?}, dns {}",
            self.cfg.routes,
            if self.cfg.set_dns { "set" } else { "untouched" }
        ))
        .await;

        self.set_state(GuestState::Connected {
            host: addr,
            host_name,
            tun: tun_name.clone(),
            config: tcfg.clone(),
            since: Instant::now(),
        })
        .await;

        let meter = RateMeter::default();
        let end = self
            .pump(&mut framed, &tun, &meter, target.link_iface.as_deref())
            .await;

        // Teardown, in reverse order of setup.
        match &end {
            SessionEnd::HostClosed(_) => {}
            _ => {
                let _ = send_frame(&mut framed, Frame::Bye, Duration::from_millis(500)).await;
            }
        }
        drop(framed);
        let (_configurator, reverted) = with_configurator(configurator, |c| c.revert()).await;
        if let Err(e) = reverted {
            self.error(format!("reverting platform configuration: {e:#}"))
                .await;
        }
        drop(_configurator);
        drop(tun);
        self.log(format!("tunnel {tun_name} torn down")).await;
        // The user was just routing everything through a cable that is now
        // gone; say where their traffic goes instead, otherwise a dropped
        // tunnel looks exactly like a broken machine.
        self.report_local_egress().await;

        match end {
            SessionEnd::Shutdown => Outcome::Shutdown,
            SessionEnd::Lost(r) | SessionEnd::HostClosed(r) => Outcome::Lost(r),
        }
    }

    /// Packet pump: TUN ⇄ frames, keep-alives, stats, link watch.
    async fn pump<T: Transport, U: TunIo>(
        &mut self,
        framed: &mut FramedTransport<T>,
        tun: &U,
        meter: &RateMeter,
        link_iface: Option<&str>,
    ) -> SessionEnd {
        let t = self.timings.clone();
        let mut buf = vec![0u8; u16::MAX as usize];
        let mut ping = tokio::time::interval_at(
            tokio::time::Instant::now() + t.ping_interval,
            t.ping_interval,
        );
        ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut stats = tokio::time::interval(t.stats_interval);
        stats.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut link =
            tokio::time::interval_at(tokio::time::Instant::now() + t.link_poll, t.link_poll);
        link.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut ifaces = tokio::time::interval_at(
            tokio::time::Instant::now() + t.iface_refresh,
            t.iface_refresh,
        );
        ifaces.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut last_rx = Instant::now();

        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut self.ctrl) => {
                    return SessionEnd::Shutdown;
                }
                frame = framed.next() => {
                    match frame {
                        Some(Ok(Frame::IpPacket(pkt))) => {
                            last_rx = Instant::now();
                            match tun.send(&pkt).await {
                                Ok(_) => meter.record_rx(pkt.len()),
                                Err(e) => {
                                    // A single bad packet must not kill the tunnel
                                    // (e.g. EINVAL for a malformed packet on utun).
                                    tracing::debug!(error = %e, len = pkt.len(), "tun write failed");
                                }
                            }
                        }
                        Some(Ok(Frame::Ping(tok))) => {
                            last_rx = Instant::now();
                            if let Err(e) = send_frame(framed, Frame::Pong(tok), t.send_timeout).await {
                                return SessionEnd::Lost(e);
                            }
                        }
                        Some(Ok(Frame::Pong(_))) => {
                            last_rx = Instant::now();
                        }
                        Some(Ok(Frame::Bye)) => {
                            return SessionEnd::HostClosed("host closed the tunnel (Bye)".into());
                        }
                        Some(Ok(Frame::SpeedChunk(_) | Frame::SpeedDone(_) | Frame::SpeedResult { .. })) => {
                            last_rx = Instant::now();
                        }
                        Some(Ok(other)) => {
                            last_rx = Instant::now();
                            tracing::debug!(?other, "unexpected frame while connected (ignored)");
                        }
                        Some(Err(e)) => {
                            return SessionEnd::HostClosed(format!("connection error: {e}"));
                        }
                        None => {
                            return SessionEnd::HostClosed("connection closed by host".into());
                        }
                    }
                }
                res = tun.recv(&mut buf) => {
                    match res {
                        Ok(0) => {}
                        Ok(n) => {
                            let pkt = Bytes::copy_from_slice(&buf[..n]);
                            if let Err(e) = send_frame(framed, Frame::IpPacket(pkt), t.send_timeout).await {
                                return SessionEnd::Lost(e);
                            }
                            meter.record_tx(n);
                        }
                        Err(e) => {
                            return SessionEnd::Lost(format!("tun read error: {e}"));
                        }
                    }
                }
                _ = ping.tick() => {
                    if last_rx.elapsed() > t.keepalive_timeout {
                        return SessionEnd::Lost(format!(
                            "no data from host for {}s (keep-alive timeout)",
                            t.keepalive_timeout.as_secs()
                        ));
                    }
                    if let Err(e) = send_frame(framed, Frame::Ping(now_millis()), t.send_timeout).await {
                        return SessionEnd::Lost(e);
                    }
                }
                _ = stats.tick() => {
                    let (tx_bps, rx_bps) = meter.rates();
                    let _ = self.events.try_send(GuestEvent::Stats {
                        counters: meter.counters(),
                        tx_bps,
                        rx_bps,
                    });
                }
                // Carrier poll: the cheapest and by far the fastest way to
                // notice that the cable was pulled. Waiting for the
                // keep-alive to expire instead would black-hole every packet
                // the default route sends into the dead tunnel meanwhile.
                _ = link.tick(), if link_iface.is_some() => {
                    let name = link_iface.unwrap_or_default();
                    if self.env.link_active(name) == Some(false) {
                        return SessionEnd::Lost(format!("link {name} lost (cable unplugged)"));
                    }
                }
                _ = ifaces.tick() => {
                    self.refresh_interfaces().await;
                }
            }
        }
    }
}
