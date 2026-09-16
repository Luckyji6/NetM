//! One guest session: handshake, frame pump, keep-alive and the user-space
//! IP stack that turns the guest's packets into flows.
//!
//! ```text
//!   guest ──TCP──▶ Framed ─┬─ IpPacket ──▶ PacketDevice ──▶ IpStack ──▶ flows ──▶ real sockets
//!                          ├─ Ping ──────▶ Pong
//!                          └─ Bye
//!   guest ◀──TCP── Framed ◀── writer task ◀── {control frames, IpPackets from the stack}
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use ipstack::{IpStack, IpStackConfig, IpStackStream, TcpConfig};
use netm_proto::{Frame, FrameError, FramedTransport, RateMeter, Transport, PROTOCOL_VERSION};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::device::PacketDevice;
use crate::{flow, GuestInfo, HostEvent, Shared};

/// Time the guest gets to send its `Hello`.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Keep-alive interval.
pub const PING_INTERVAL: Duration = Duration::from_secs(10);
/// Consecutive unanswered pings after which the guest is considered gone.
pub const MAX_MISSED_PINGS: u32 = 3;
/// Idle timeout applied by the stack to TCP sessions.
const TCP_SESSION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Stack-side UDP timeout; kept above the forwarder's own idle timeouts so
/// that those govern.
const STACK_UDP_TIMEOUT: Duration = Duration::from_secs(120);
/// Packets queued in each direction between the frame pump and the stack.
const PACKET_QUEUE: usize = 1024;

/// Outcome of validating the guest's first frame.
#[derive(Debug, PartialEq, Eq)]
pub enum HelloCheck {
    /// Valid `Hello`; carries the guest name.
    Accept(String),
    /// Reject with a human readable reason (a `Bye` is sent).
    Reject(String),
}

/// Pure handshake decision: the first frame must be a `Hello` with our
/// protocol version.
pub fn check_hello(first: Option<Result<Frame, FrameError>>) -> HelloCheck {
    match first {
        Some(Ok(Frame::Hello { version, name })) if version == PROTOCOL_VERSION => {
            HelloCheck::Accept(name)
        }
        Some(Ok(Frame::Hello { version, .. })) => HelloCheck::Reject(format!(
            "protocol version mismatch (guest {version}, host {PROTOCOL_VERSION})"
        )),
        Some(Ok(other)) => {
            HelloCheck::Reject(format!("expected Hello, got {}", frame_kind(&other)))
        }
        Some(Err(e)) => HelloCheck::Reject(format!("frame error: {e}")),
        None => HelloCheck::Reject("connection closed before Hello".into()),
    }
}

/// Frames the host answers a valid `Hello` with.
pub fn hello_reply(shared: &Shared) -> [Frame; 2] {
    [
        Frame::Hello {
            version: PROTOCOL_VERSION,
            name: shared.host_name.clone(),
        },
        Frame::Config(shared.tunnel.clone()),
    ]
}

fn frame_kind(f: &Frame) -> &'static str {
    match f {
        Frame::Hello { .. } => "Hello",
        Frame::Config(_) => "Config",
        Frame::IpPacket(_) => "IpPacket",
        Frame::Ping(_) => "Ping",
        Frame::Pong(_) => "Pong",
        Frame::Bye => "Bye",
        Frame::SpeedChunk(_) => "SpeedChunk",
        Frame::SpeedDone(_) => "SpeedDone",
        Frame::SpeedResult { .. } => "SpeedResult",
    }
}

/// Run the handshake on a framed transport. On success the guest name is
/// returned; on failure a `Bye` has been sent and the reason is returned.
pub async fn handshake<T: Transport>(
    framed: &mut FramedTransport<T>,
    shared: &Shared,
) -> Result<String, String> {
    handshake_with_timeout(framed, shared, HANDSHAKE_TIMEOUT).await
}

async fn handshake_with_timeout<T: Transport>(
    framed: &mut FramedTransport<T>,
    shared: &Shared,
    timeout: Duration,
) -> Result<String, String> {
    let first = match tokio::time::timeout(timeout, framed.next()).await {
        Ok(f) => f,
        Err(_) => {
            let _ = framed.send(Frame::Bye).await;
            return Err("handshake timed out".into());
        }
    };
    match check_hello(first) {
        HelloCheck::Accept(name) => {
            for f in hello_reply(shared) {
                framed
                    .feed(f)
                    .await
                    .map_err(|e| format!("handshake write: {e}"))?;
            }
            framed
                .flush()
                .await
                .map_err(|e| format!("handshake write: {e}"))?;
            Ok(name)
        }
        HelloCheck::Reject(reason) => {
            let _ = tokio::time::timeout(Duration::from_secs(1), framed.send(Frame::Bye)).await;
            Err(reason)
        }
    }
}

/// Send `Bye` and drop the connection; used for surplus guests.
pub async fn reject_busy<T: Transport>(transport: T) {
    let mut framed = netm_proto::framed(transport);
    // Consume the guest's Hello (if any) so the Bye is not lost in a reset.
    let _ = tokio::time::timeout(Duration::from_secs(1), framed.next()).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), framed.send(Frame::Bye)).await;
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Drive one guest connection to completion. Returns once the guest is gone
/// or `cancel` fires; emits `GuestConnected` / `GuestDisconnected`.
pub async fn run_session<T: Transport>(
    transport: T,
    peer: SocketAddr,
    shared: Arc<Shared>,
    cancel: CancellationToken,
) {
    let mut framed = netm_proto::framed(transport);
    let name = match handshake(&mut framed, &shared).await {
        Ok(name) => name,
        Err(reason) => {
            shared
                .events
                .log(format!("guest {peer} rejected: {reason}"))
                .await;
            return;
        }
    };
    shared
        .events
        .send(HostEvent::GuestConnected(GuestInfo {
            peer,
            name: name.clone(),
            connected_at: Instant::now(),
            assigned_ip: shared.tunnel.guest_ip,
        }))
        .await;
    shared
        .events
        .log(format!(
            "guest \"{name}\" connected from {peer}, assigned {}/{}",
            shared.tunnel.guest_ip, shared.tunnel.prefix_len
        ))
        .await;

    let pending = match netm_proto::speed::run_as_responder(
        &mut framed,
        netm_proto::speed::Params::default(),
    )
    .await
    {
        Ok(netm_proto::speed::ResponderOutcome::Measured(speed)) => {
            tracing::info!(summary = %speed.summary(), "link capacity");
            shared.events.send(HostEvent::LinkSpeed(speed)).await;
            None
        }
        Ok(netm_proto::speed::ResponderOutcome::Skipped { pending }) => pending,
        Err(e) => {
            shared
                .events
                .log(format!(
                    "guest \"{name}\" ({peer}) disconnected: speed test: {e}"
                ))
                .await;
            shared
                .events
                .send(HostEvent::GuestDisconnected {
                    peer,
                    reason: format!("speed test: {e}"),
                })
                .await;
            return;
        }
    };

    let reason = pump(framed, pending, &shared, cancel).await;

    shared
        .events
        .log(format!("guest \"{name}\" ({peer}) disconnected: {reason}"))
        .await;
    shared
        .events
        .send(HostEvent::GuestDisconnected { peer, reason })
        .await;
}

/// Handle one guest frame. `Some` is a disconnect reason.
fn ingest_frame(
    frame: Frame,
    shared: &Arc<Shared>,
    to_stack: &mpsc::Sender<Bytes>,
    ctrl_tx: &mpsc::Sender<Frame>,
    dropped_packets: &AtomicUsize,
    missed_pings: &mut u32,
) -> Option<String> {
    match frame {
        Frame::IpPacket(pkt) => {
            shared.meter.record_rx(pkt.len());
            if to_stack.try_send(pkt).is_err() {
                let n = dropped_packets.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() {
                    tracing::warn!(dropped = n, "stack queue full, dropping guest packets");
                }
            }
            None
        }
        Frame::Ping(t) => {
            let _ = ctrl_tx.try_send(Frame::Pong(t));
            None
        }
        Frame::Pong(_) => {
            *missed_pings = 0;
            None
        }
        Frame::Bye => Some("guest sent Bye".into()),
        other => {
            tracing::debug!(kind = frame_kind(&other), "ignoring unexpected frame");
            None
        }
    }
}

fn stack_config(shared: &Shared) -> IpStackConfig {
    let mut cfg = IpStackConfig::default();
    if cfg.mtu(shared.tunnel.mtu).is_err() {
        // ipstack insists on >= 1280 (IPv6 minimum); smaller tunnel MTUs are
        // still honoured for the read buffer.
        cfg.mtu_unchecked(shared.tunnel.mtu);
    }
    cfg.udp_timeout(STACK_UDP_TIMEOUT);
    let mut tcp = TcpConfig::default();
    tcp.timeout = TCP_SESSION_TIMEOUT;
    cfg.with_tcp_config(tcp);
    cfg
}

/// The frame pump; returns the disconnect reason.
async fn pump<T: Transport>(
    framed: FramedTransport<T>,
    pending: Option<Frame>,
    shared: &Arc<Shared>,
    cancel: CancellationToken,
) -> String {
    let (device, to_stack, from_stack) = PacketDevice::channel(PACKET_QUEUE);
    let mut stack = IpStack::new(stack_config(shared), device);

    let (sink, mut source) = framed.split();
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<Frame>(64);
    let mut writer = tokio::spawn(writer_loop(
        sink,
        ctrl_rx,
        from_stack,
        Arc::clone(&shared.meter),
    ));

    let flows_cancel = CancellationToken::new();
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut missed_pings: u32 = 0;
    let dropped_packets = AtomicUsize::new(0);
    let mut unknown_network: u64 = 0;

    if let Some(frame) = pending {
        if let Some(reason) = ingest_frame(
            frame,
            shared,
            &to_stack,
            &ctrl_tx,
            &dropped_packets,
            &mut missed_pings,
        ) {
            flows_cancel.cancel();
            let _ = ctrl_tx.try_send(Frame::Bye);
            drop(ctrl_tx);
            drop(to_stack);
            drop(stack);
            let _ = tokio::time::timeout(Duration::from_secs(1), &mut writer).await;
            return reason;
        }
    }

    let reason = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break "host shutting down".to_string(),
            frame = source.next() => match frame {
                Some(Ok(frame)) => {
                    if let Some(reason) = ingest_frame(
                        frame,
                        shared,
                        &to_stack,
                        &ctrl_tx,
                        &dropped_packets,
                        &mut missed_pings,
                    ) {
                        break reason;
                    }
                }
                Some(Err(e)) => break format!("read error: {e}"),
                None => break "connection closed by guest".to_string(),
            },
            _ = ping.tick() => {
                if missed_pings >= MAX_MISSED_PINGS {
                    break format!("keep-alive timeout ({MAX_MISSED_PINGS} pings unanswered)");
                }
                missed_pings += 1;
                if ctrl_tx.try_send(Frame::Ping(now_millis())).is_err() {
                    tracing::debug!("control queue full, ping skipped");
                }
            },
            accepted = stack.accept() => match accepted {
                Ok(stream) => dispatch(shared, stream, &flows_cancel, &mut unknown_network),
                Err(e) => break format!("ip stack stopped: {e}"),
            },
            res = &mut writer => break match res {
                Ok(Err(e)) => format!("write error: {e}"),
                Ok(Ok(())) => "writer finished".to_string(),
                Err(e) => format!("writer task failed: {e}"),
            },
        }
    };

    // Tear down: stop flows, tell the guest, stop the stack and the writer.
    flows_cancel.cancel();
    let _ = ctrl_tx.try_send(Frame::Bye);
    drop(ctrl_tx);
    drop(to_stack);
    drop(stack);
    if tokio::time::timeout(Duration::from_secs(1), &mut writer)
        .await
        .is_err()
    {
        writer.abort();
    }
    let dropped = dropped_packets.load(Ordering::Relaxed);
    if dropped > 0 || unknown_network > 0 {
        tracing::info!(
            dropped_packets = dropped,
            unknown_network_packets = unknown_network,
            "session packet statistics"
        );
    }
    reason
}

/// Hand an accepted stack stream to the right forwarder.
fn dispatch(
    shared: &Arc<Shared>,
    stream: IpStackStream,
    flows_cancel: &CancellationToken,
    unknown_network: &mut u64,
) {
    match stream {
        IpStackStream::Tcp(tcp) => {
            if !flow::destination_allowed(shared, tcp.peer_addr()) {
                tracing::trace!(dst = %tcp.peer_addr(), "ignoring tcp flow to disallowed destination");
                // Dropping without shutdown: the stack side answers with a
                // reset/timeout on its own.
                tokio::spawn(async move {
                    let mut tcp = tcp;
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut tcp).await;
                });
                return;
            }
            tokio::spawn(flow::handle_tcp(
                Arc::clone(shared),
                tcp,
                flows_cancel.child_token(),
            ));
        }
        IpStackStream::Udp(udp) => {
            if !flow::destination_allowed(shared, udp.peer_addr()) {
                tracing::trace!(dst = %udp.peer_addr(), "ignoring udp flow to disallowed destination");
                return;
            }
            tokio::spawn(flow::handle_udp(
                Arc::clone(shared),
                udp,
                flows_cancel.child_token(),
            ));
        }
        IpStackStream::UnknownTransport(u) => handle_unknown_transport(shared, u),
        IpStackStream::UnknownNetwork(pkt) => {
            // Typically IPv6 (the guest only routes IPv4 today) or malformed
            // data; counted, never logged per packet.
            *unknown_network += 1;
            tracing::trace!(
                len = pkt.len(),
                version = pkt.first().map(|b| b >> 4),
                "ignoring packet of unknown network protocol"
            );
        }
    }
}

/// ICMP echo to the gateway is answered so the guest can `ping 10.77.0.1`;
/// everything else that is neither TCP nor UDP is ignored.
fn handle_unknown_transport(shared: &Shared, u: ipstack::IpStackUnknownTransport) {
    use etherparse::{Icmpv4Header, Icmpv4Type};
    if u.ip_protocol() != ipstack::IpNumber::ICMP
        || u.dst_addr() != std::net::IpAddr::V4(shared.tunnel.gateway_ip)
    {
        tracing::trace!(proto = ?u.ip_protocol(), dst = %u.dst_addr(), "ignoring unknown transport");
        return;
    }
    let Ok((hdr, rest)) = Icmpv4Header::from_slice(u.payload()) else {
        return;
    };
    if let Icmpv4Type::EchoRequest(echo) = hdr.icmp_type {
        let mut reply = Icmpv4Header::new(Icmpv4Type::EchoReply(echo));
        reply.update_checksum(rest);
        let mut payload = reply.to_bytes().to_vec();
        payload.extend_from_slice(rest);
        if let Err(e) = u.send(payload) {
            tracing::debug!(error = %e, "icmp echo reply failed");
        }
    }
}

/// Owns the sink half: merges control frames (priority) and stack packets,
/// batching what is immediately available before each flush.
async fn writer_loop<T: Transport>(
    mut sink: SplitSink<FramedTransport<T>, Frame>,
    mut ctrl: mpsc::Receiver<Frame>,
    mut packets: mpsc::Receiver<Bytes>,
    meter: Arc<RateMeter>,
) -> Result<(), FrameError> {
    let mut ctrl_open = true;
    let mut packets_open = true;
    while ctrl_open || packets_open {
        let first = tokio::select! {
            biased;
            c = ctrl.recv(), if ctrl_open => match c {
                Some(f) => Some(f),
                None => { ctrl_open = false; None }
            },
            p = packets.recv(), if packets_open => match p {
                Some(b) => { meter.record_tx(b.len()); Some(Frame::IpPacket(b)) }
                None => { packets_open = false; None }
            },
        };
        let Some(first) = first else { continue };
        sink.feed(first).await?;
        // Drain whatever else is ready so one flush covers a burst.
        let mut budget = 64;
        while budget > 0 {
            budget -= 1;
            if let Ok(f) = ctrl.try_recv() {
                sink.feed(f).await?;
                continue;
            }
            match packets.try_recv() {
                Ok(b) => {
                    meter.record_tx(b.len());
                    sink.feed(Frame::IpPacket(b)).await?;
                }
                Err(_) => break,
            }
        }
        sink.flush().await?;
    }
    let _ = sink.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dns::Upstreams, Emitter};
    use netm_proto::TunnelConfig;

    fn shared() -> (Arc<Shared>, mpsc::Receiver<HostEvent>) {
        let (tx, rx) = mpsc::channel(64);
        let tunnel = TunnelConfig::default();
        let shared = Arc::new(Shared {
            tunnel: tunnel.clone(),
            host_name: "host-test".into(),
            events: Emitter::new(tx),
            meter: Arc::new(RateMeter::default()),
            dns: Upstreams::fixed(vec!["127.0.0.1:53".parse().unwrap()], vec![]),
            active_flows: Arc::new(AtomicUsize::new(0)),
            next_flow_id: Default::default(),
        });
        (shared, rx)
    }

    #[test]
    fn check_hello_decisions() {
        assert_eq!(
            check_hello(Some(Ok(Frame::Hello {
                version: PROTOCOL_VERSION,
                name: "g".into()
            }))),
            HelloCheck::Accept("g".into())
        );
        assert!(matches!(
            check_hello(Some(Ok(Frame::Hello { version: PROTOCOL_VERSION + 1, name: "g".into() }))),
            HelloCheck::Reject(r) if r.contains("version")
        ));
        assert!(matches!(
            check_hello(Some(Ok(Frame::Ping(1)))),
            HelloCheck::Reject(r) if r.contains("Ping")
        ));
        assert!(matches!(check_hello(None), HelloCheck::Reject(_)));
    }

    #[tokio::test]
    async fn handshake_replies_hello_then_config() {
        let (shared, _rx) = shared();
        let (host_side, guest_side) = tokio::io::duplex(4096);
        let mut guest = netm_proto::framed(guest_side);
        let host = tokio::spawn({
            let shared = Arc::clone(&shared);
            async move {
                let mut framed = netm_proto::framed(host_side);
                handshake(&mut framed, &shared).await
            }
        });
        guest
            .send(Frame::Hello {
                version: PROTOCOL_VERSION,
                name: "guest-1".into(),
            })
            .await
            .unwrap();
        let hello = guest.next().await.unwrap().unwrap();
        assert_eq!(
            hello,
            Frame::Hello {
                version: PROTOCOL_VERSION,
                name: "host-test".into()
            }
        );
        let config = guest.next().await.unwrap().unwrap();
        assert_eq!(config, Frame::Config(TunnelConfig::default()));
        assert_eq!(host.await.unwrap(), Ok("guest-1".to_string()));
    }

    #[tokio::test]
    async fn handshake_rejects_wrong_version_with_bye() {
        let (shared, _rx) = shared();
        let (host_side, guest_side) = tokio::io::duplex(4096);
        let mut guest = netm_proto::framed(guest_side);
        let host = tokio::spawn(async move {
            let mut framed = netm_proto::framed(host_side);
            handshake(&mut framed, &shared).await
        });
        guest
            .send(Frame::Hello {
                version: 99,
                name: "old".into(),
            })
            .await
            .unwrap();
        assert_eq!(guest.next().await.unwrap().unwrap(), Frame::Bye);
        assert!(host.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn handshake_times_out() {
        let (shared, _rx) = shared();
        let (host_side, guest_side) = tokio::io::duplex(4096);
        let mut guest = netm_proto::framed(guest_side);
        let mut framed = netm_proto::framed(host_side);
        let err = handshake_with_timeout(&mut framed, &shared, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        // The silent guest is told to go away.
        assert_eq!(guest.next().await.unwrap().unwrap(), Frame::Bye);
    }
}
