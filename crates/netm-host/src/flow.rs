//! Per-flow forwarding: a stream accepted from the user-space stack is
//! bridged to a real socket on the host.
//!
//! - TCP: `TcpStream::connect(original destination)` then a counted
//!   bidirectional copy.
//! - UDP: a connected `UdpSocket`, pumped in both directions with an idle
//!   timeout.
//! - DNS (destination `<tunnel dns>:53`): relayed to the host's upstream
//!   resolvers (see [`crate::dns`]) instead of the literal destination.
//!
//! # Egress safety / single-machine testing
//!
//! Flows leave the host through its ordinary routing table. When guest and
//! host run on the **same machine** for testing, only a narrow test route
//! (e.g. `1.1.1.1/32`) must point at the TUN; if the whole default route were
//! hijacked, the host's egress sockets would themselves be routed back into
//! the TUN and the traffic would loop forever. Nothing in this module can
//! detect that situation, so keep single-machine tests to `/32` routes.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipstack::{IpStackTcpStream, IpStackUdpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::dns::{self, DNS_PORT};
use crate::{FlowInfo, HostEvent, Proto, Shared};

/// TCP connect timeout towards the real destination.
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Idle timeout of generic UDP flows.
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Idle timeout of UDP DNS flows.
pub const DNS_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often an idle stack-side TCP read is re-polled (see [`pump_tcp`]).
const STACK_READ_NUDGE: Duration = Duration::from_millis(500);

const COPY_BUF: usize = 32 * 1024;
const MAX_DATAGRAM: usize = 65535;

/// Live byte counters of one flow (`tx` = guest → internet).
#[derive(Default, Debug)]
pub struct FlowCounters {
    pub tx: AtomicU64,
    pub rx: AtomicU64,
}

impl FlowCounters {
    fn add_tx(&self, n: usize) {
        self.tx.fetch_add(n as u64, Ordering::Relaxed);
    }
    fn add_rx(&self, n: usize) {
        self.rx.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Whether a flow to `dst` should be forwarded at all.
pub fn destination_allowed(shared: &Shared, dst: SocketAddr) -> bool {
    let ip = dst.ip();
    if ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_broadcast() || v4 == shared.tunnel.guest_ip {
                return false;
            }
            // Directed broadcast of the tunnel subnet (e.g. 10.77.0.255).
            let mask = if shared.tunnel.prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - shared.tunnel.prefix_len.min(32) as u32)
            };
            let net = u32::from(shared.tunnel.gateway_ip) & mask;
            if u32::from(v4) & mask == net && u32::from(v4) | mask == u32::MAX {
                return false;
            }
            true
        }
        IpAddr::V6(_) => true,
    }
}

/// Is this flow addressed to the tunnel's DNS forwarder?
pub fn is_dns(shared: &Shared, dst: SocketAddr) -> bool {
    dst.port() == DNS_PORT && dst.ip() == IpAddr::V4(shared.tunnel.dns)
}

/// Where a flow to `dst` is actually connected. Flows to the gateway address
/// itself are mapped to the host's loopback so the guest can reach services
/// running on the host via `10.77.0.1:<port>`.
pub fn remap_target(shared: &Shared, dst: SocketAddr) -> SocketAddr {
    if dst.ip() == IpAddr::V4(shared.tunnel.gateway_ip) {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), dst.port())
    } else {
        dst
    }
}

/// Book-keeping wrapper: allocates a flow id, emits `FlowOpened` /
/// `FlowClosed` and keeps the active-flow gauge accurate.
async fn run_flow<F, Fut>(shared: &Shared, proto: Proto, src: SocketAddr, dst: SocketAddr, f: F)
where
    F: FnOnce(Arc<FlowCounters>) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let id = shared.next_flow_id.fetch_add(1, Ordering::Relaxed);
    let counters = Arc::new(FlowCounters::default());
    shared.active_flows.fetch_add(1, Ordering::Relaxed);
    shared
        .events
        .send(HostEvent::FlowOpened(FlowInfo {
            id,
            proto: proto.clone(),
            src,
            dst,
            tx_bytes: 0,
            rx_bytes: 0,
            opened_at: Instant::now(),
        }))
        .await;
    tracing::debug!(id, ?proto, %src, %dst, "flow opened");

    let result = f(Arc::clone(&counters)).await;

    shared.active_flows.fetch_sub(1, Ordering::Relaxed);
    let tx_bytes = counters.tx.load(Ordering::Relaxed);
    let rx_bytes = counters.rx.load(Ordering::Relaxed);
    match result {
        Ok(()) => tracing::debug!(id, ?proto, %src, %dst, tx_bytes, rx_bytes, "flow closed"),
        Err(reason) => {
            tracing::debug!(id, ?proto, %src, %dst, tx_bytes, rx_bytes, %reason, "flow closed")
        }
    }
    shared
        .events
        .send(HostEvent::FlowClosed {
            id,
            tx_bytes,
            rx_bytes,
        })
        .await;
}

/// Forward one TCP connection accepted from the stack.
pub async fn handle_tcp(shared: Arc<Shared>, tcp: IpStackTcpStream, cancel: CancellationToken) {
    let src = tcp.local_addr();
    let dst = tcp.peer_addr();
    run_flow(&shared, Proto::Tcp, src, dst, |counters| {
        tcp_flow(Arc::clone(&shared), tcp, counters, cancel)
    })
    .await;
}

async fn tcp_flow(
    shared: Arc<Shared>,
    mut tcp: IpStackTcpStream,
    counters: Arc<FlowCounters>,
    cancel: CancellationToken,
) -> Result<(), String> {
    let dst = tcp.peer_addr();
    let connect = async {
        if is_dns(&shared, dst) {
            dns::connect_tcp(&shared.dns.get()).await
        } else {
            let target = remap_target(&shared, dst);
            let s = tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(target))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
            let _ = s.set_nodelay(true);
            Ok(s)
        }
    };
    let real = tokio::select! {
        r = connect => match r {
            Ok(s) => s,
            Err(e) => {
                // Closing the stack-side stream sends FIN to the guest.
                let _ = tcp.shutdown().await;
                return Err(format!("connect {dst}: {e}"));
            }
        },
        _ = cancel.cancelled() => return Err("session closed".into()),
    };
    pump_tcp(tcp, real, counters, cancel).await
}

/// Bidirectional copy between the stack-side stream and the real socket
/// with proper half-close propagation.
///
/// Not `tokio::io::copy_bidirectional`: `ipstack` 1.0.1 does not wake a
/// pending reader when the guest sends FIN (or when the session reaches
/// `Closed`), so a purely wake-driven copy would hang until the stack's
/// session timeout. The guest → net direction therefore re-polls the stack
/// stream every [`STACK_READ_NUDGE`] to observe EOF promptly; each nudge is
/// one cheap `poll_read`.
///
/// No explicit idle timer: the stack times out inactive TCP sessions itself
/// (see `TcpConfig::timeout` in `session.rs`).
async fn pump_tcp(
    tcp: IpStackTcpStream,
    real: TcpStream,
    counters: Arc<FlowCounters>,
    cancel: CancellationToken,
) -> Result<(), String> {
    let (mut stack_rd, mut stack_wr) = tokio::io::split(tcp);
    let (mut net_rd, mut net_wr) = real.into_split();

    let c1 = Arc::clone(&counters);
    let guest_to_net = async move {
        let mut buf = vec![0u8; COPY_BUF];
        let r: io::Result<()> = loop {
            let n = match tokio::time::timeout(STACK_READ_NUDGE, stack_rd.read(&mut buf)).await {
                Err(_) => continue, // nudge: re-poll so FIN/Closed is noticed
                Ok(Ok(0)) => break Ok(()),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => break Err(e),
            };
            if let Err(e) = net_wr.write_all(&buf[..n]).await {
                break Err(e);
            }
            c1.add_tx(n);
        };
        // Propagate the guest's FIN to the server (half-close).
        let _ = net_wr.shutdown().await;
        r
    };

    let c2 = Arc::clone(&counters);
    let net_to_guest = async move {
        let mut buf = vec![0u8; COPY_BUF];
        let r: io::Result<()> = loop {
            let n = match net_rd.read(&mut buf).await {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(e) => break Err(e),
            };
            if let Err(e) = stack_wr.write_all(&buf[..n]).await {
                break Err(e);
            }
            c2.add_rx(n);
        };
        // Propagate the server's FIN to the guest; bounded because the stack
        // waits for the guest's ACK.
        let _ = tokio::time::timeout(Duration::from_secs(2), stack_wr.shutdown()).await;
        r
    };

    tokio::pin!(guest_to_net);
    tokio::pin!(net_to_guest);
    let mut a_done = false;
    let mut b_done = false;
    loop {
        tokio::select! {
            r = &mut guest_to_net, if !a_done => {
                a_done = true;
                if let Err(e) = r {
                    return Err(format!("guest->net: {e}"));
                }
                if b_done {
                    return Ok(());
                }
            }
            r = &mut net_to_guest, if !b_done => {
                b_done = true;
                if let Err(e) = r {
                    return Err(format!("net->guest: {e}"));
                }
                if a_done {
                    return Ok(());
                }
            }
            _ = cancel.cancelled() => return Err("session closed".into()),
        }
    }
}

/// Forward one UDP "flow" (src/dst tuple) accepted from the stack.
pub async fn handle_udp(shared: Arc<Shared>, udp: IpStackUdpStream, cancel: CancellationToken) {
    let src = udp.local_addr();
    let dst = udp.peer_addr();
    if is_dns(&shared, dst) {
        run_flow(&shared, Proto::Udp, src, dst, |counters| {
            dns_udp_flow(Arc::clone(&shared), udp, counters, cancel)
        })
        .await;
    } else {
        run_flow(&shared, Proto::Udp, src, dst, |counters| {
            udp_flow(Arc::clone(&shared), udp, counters, cancel)
        })
        .await;
    }
}

fn unspecified_for(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    }
}

async fn udp_flow(
    shared: Arc<Shared>,
    mut udp: IpStackUdpStream,
    counters: Arc<FlowCounters>,
    cancel: CancellationToken,
) -> Result<(), String> {
    let dst = udp.peer_addr();
    let target = remap_target(&shared, dst);
    let sock = UdpSocket::bind(unspecified_for(target))
        .await
        .map_err(|e| format!("udp bind: {e}"))?;
    sock.connect(target)
        .await
        .map_err(|e| format!("udp connect {target}: {e}"))?;

    let mut from_guest = vec![0u8; MAX_DATAGRAM];
    let mut from_net = vec![0u8; MAX_DATAGRAM];
    loop {
        tokio::select! {
            r = tokio::time::timeout(UDP_IDLE_TIMEOUT, udp.read(&mut from_guest)) => match r {
                Err(_) => return Ok(()), // idle
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => {
                    counters.add_tx(n);
                    if let Err(e) = sock.send(&from_guest[..n]).await {
                        // ICMP unreachable etc.: keep the flow, the guest may retry.
                        tracing::debug!(%dst, error = %e, "udp send failed");
                    }
                }
                Ok(Err(e)) if e.kind() == io::ErrorKind::TimedOut => return Ok(()),
                Ok(Err(e)) => return Err(format!("udp stack read: {e}")),
            },
            r = sock.recv(&mut from_net) => match r {
                Ok(n) => {
                    counters.add_rx(n);
                    if let Err(e) = udp.write_all(&from_net[..n]).await {
                        return Err(format!("udp stack write: {e}"));
                    }
                }
                Err(e) => {
                    tracing::debug!(%dst, error = %e, "udp recv failed");
                }
            },
            _ = cancel.cancelled() => return Err("session closed".into()),
        }
    }
}

/// UDP DNS: every datagram is one query, relayed to the upstreams
/// concurrently; answers are written back on the same flow.
async fn dns_udp_flow(
    shared: Arc<Shared>,
    udp: IpStackUdpStream,
    counters: Arc<FlowCounters>,
    cancel: CancellationToken,
) -> Result<(), String> {
    let (mut rd, wr) = tokio::io::split(udp);
    let wr = Arc::new(tokio::sync::Mutex::new(wr));
    let mut inflight: JoinSet<()> = JoinSet::new();
    let mut buf = vec![0u8; 4096];
    let result = loop {
        tokio::select! {
            r = tokio::time::timeout(DNS_IDLE_TIMEOUT, rd.read(&mut buf)) => match r {
                Err(_) => break Ok(()),
                Ok(Ok(0)) => break Ok(()),
                Ok(Ok(n)) => {
                    counters.add_tx(n);
                    let query = buf[..n].to_vec();
                    let upstreams = shared.dns.get();
                    let wr = Arc::clone(&wr);
                    let counters = Arc::clone(&counters);
                    inflight.spawn(async move {
                        match dns::query_udp(&query, &upstreams).await {
                            Ok(answer) => {
                                counters.add_rx(answer.len());
                                if let Err(e) = wr.lock().await.write_all(&answer).await {
                                    tracing::debug!(error = %e, "dns answer write failed");
                                }
                            }
                            Err(e) => tracing::debug!(error = %e, "dns query failed"),
                        }
                    });
                }
                Ok(Err(e)) if e.kind() == io::ErrorKind::TimedOut => break Ok(()),
                Ok(Err(e)) => break Err(format!("dns stack read: {e}")),
            },
            Some(_) = inflight.join_next(), if !inflight.is_empty() => {}
            _ = cancel.cancelled() => break Err("session closed".into()),
        }
    };
    inflight.abort_all();
    result
}
