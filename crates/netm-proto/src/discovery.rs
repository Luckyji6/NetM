//! IPv6 link-local multicast discovery.
//!
//! The guest multicasts a [`DiscoveryMessage::Probe`] to `[ff02::1%ifindex]:`
//! [`DISCOVERY_PORT`] on a candidate interface; the host, which has a UDP
//! socket bound to `[::]:`[`DISCOVERY_PORT`], answers every valid probe with a
//! unicast [`DiscoveryMessage::Offer`] sent back to the probe's source address.
//! Because the offer is sent to a link-local destination, the kernel sources it
//! from the host's own `fe80::` address on that link, so the guest learns the
//! host address simply from `recv_from` (the kernel also fills in the
//! `scope_id`, e.g. `[fe80::1807:bd85:7f5e:f5e8%14]:27778`).
//!
//! The host must join `ff02::1` on each interface it wants to hear probes on
//! (see [`Responder::bind`]); the guest must set `IPV6_MULTICAST_IF` to the
//! probed interface, which [`probe`] does.
//!
//! Wire encoding: 4 magic bytes `b"NETM"` followed by the postcard encoding of
//! [`DiscoveryMessage`]. Datagrams without the magic prefix are ignored.

use std::hash::{BuildHasher, Hasher, RandomState};
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::link::LinkInterface;
use crate::{DISCOVERY_PORT, PROTOCOL_VERSION};

/// All-nodes link-local multicast group.
pub const MULTICAST_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Magic prefix of every discovery datagram.
pub const MAGIC: &[u8; 4] = b"NETM";

/// Maximum size of a discovery datagram we are willing to parse.
const MAX_DATAGRAM: usize = 512;

/// Interval at which [`probe`] re-sends its `Probe` while waiting for an
/// `Offer`.
const PROBE_RESEND_INTERVAL: Duration = Duration::from_millis(500);

/// Discovery datagram.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryMessage {
    /// Guest → `ff02::1`: "is there a NetM host on this link?"
    Probe {
        /// Must equal [`PROTOCOL_VERSION`].
        version: u16,
        /// Random token echoed back in the `Offer` so stale replies can be
        /// discarded.
        nonce: u64,
    },
    /// Host → guest (unicast): "yes, connect to me on `data_port`".
    Offer {
        version: u16,
        nonce: u64,
        /// TCP port of the host's data listener.
        data_port: u16,
        /// Human readable host name.
        host_name: String,
    },
}

impl DiscoveryMessage {
    /// Encode as `MAGIC ++ postcard(self)`.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(MAGIC);
        postcard::to_extend(self, out).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Decode a datagram. Returns `None` for datagrams that are not NetM
    /// discovery messages (wrong magic or malformed body).
    pub fn decode(buf: &[u8]) -> Option<Self> {
        let body = buf.strip_prefix(MAGIC.as_slice())?;
        postcard::from_bytes(body).ok()
    }
}

/// Result of a successful [`probe`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovered {
    /// Host `fe80::` address with `scope_id` = the probed interface's index and
    /// `port` = the host's data port. Pass it straight to
    /// [`crate::transport::tcp::connect`].
    pub host_addr: SocketAddrV6,
    /// Host name announced in the `Offer`.
    pub host_name: String,
}

fn new_v6_udp_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn random_nonce() -> u64 {
    // `RandomState` is seeded with fresh randomness per instance; combined with
    // the clock this is plenty for a discovery nonce (no security relevance).
    let mut h = RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.finish()
}

/// Host side: answers `Probe`s with `Offer`s.
pub struct Responder {
    socket: UdpSocket,
    data_port: u16,
    host_name: String,
}

impl Responder {
    /// Bind `[::]:`[`DISCOVERY_PORT`] (`IPV6_V6ONLY`, `SO_REUSEADDR`,
    /// `SO_REUSEPORT`) and join `ff02::1` on every given interface.
    ///
    /// **The explicit `IPV6_JOIN_GROUP` matters**: on macOS a UDP socket only
    /// receives `ff02::1` datagrams on interfaces it has joined the group on
    /// (verified: without the join, probes are silently dropped). Join
    /// failures are logged at `warn` and do **not** fail `bind`; the known
    /// benign case is macOS returning `EINVAL` for Thunderbolt ports (`en1`,
    /// `en2`, ...) that are members of `bridge0` — joining on `bridge0` covers
    /// them. Interfaces with `index == 0` are skipped. Use
    /// [`join`](Self::join) to add interfaces that appear later (before
    /// calling [`run`](Self::run)).
    pub async fn bind(
        interfaces: &[LinkInterface],
        data_port: u16,
        host_name: String,
    ) -> io::Result<Responder> {
        Self::bind_with_port(interfaces, DISCOVERY_PORT, data_port, host_name).await
    }

    /// Like [`bind`](Self::bind) but listening on an arbitrary UDP port
    /// (`0` = ephemeral). Intended for tests and non-default deployments.
    pub async fn bind_with_port(
        interfaces: &[LinkInterface],
        listen_port: u16,
        data_port: u16,
        host_name: String,
    ) -> io::Result<Responder> {
        let socket = new_v6_udp_socket()?;
        let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, listen_port, 0, 0);
        socket.bind(&SocketAddr::V6(bind_addr).into())?;
        let std_socket: std::net::UdpSocket = socket.into();
        let socket = UdpSocket::from_std(std_socket)?;
        let responder = Responder {
            socket,
            data_port,
            host_name,
        };
        for iface in interfaces {
            // Errors are already logged by `join`.
            let _ = responder.join(iface);
        }
        Ok(responder)
    }

    /// Join `ff02::1` on `iface` so probes arriving on that link are received.
    ///
    /// Interfaces with `index == 0` are ignored (returns `Ok`). Failures are
    /// logged at `warn` and returned; see [`bind`](Self::bind) for the benign
    /// macOS `EINVAL` case on bridge member ports.
    pub fn join(&self, iface: &LinkInterface) -> io::Result<()> {
        if iface.index == 0 {
            return Ok(());
        }
        match self.socket.join_multicast_v6(&MULTICAST_GROUP, iface.index) {
            Ok(()) => {
                tracing::debug!(iface = %iface.name, index = iface.index, "joined ff02::1");
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    iface = %iface.name,
                    index = iface.index,
                    error = %e,
                    "could not join ff02::1 on interface (probes on it will not be seen)"
                );
                Err(e)
            }
        }
    }

    /// Local address of the discovery socket (useful when bound to port 0).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Serve forever: reply an `Offer` to the sender of every valid `Probe`.
    ///
    /// Returns only on a fatal socket error. Run it in its own task and drop
    /// the task handle (or `abort()` it) to stop responding.
    pub async fn run(self) -> io::Result<()> {
        let mut buf = [0u8; MAX_DATAGRAM];
        loop {
            let (n, from) = match self.socket.recv_from(&mut buf).await {
                Ok(v) => v,
                // Transient errors (e.g. ICMP port unreachable surfaced on some
                // platforms) should not kill the responder.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(e) => return Err(e),
            };
            let Some(msg) = DiscoveryMessage::decode(&buf[..n]) else {
                tracing::trace!(%from, len = n, "ignoring non-NetM datagram");
                continue;
            };
            match msg {
                DiscoveryMessage::Probe { version, nonce } if version == PROTOCOL_VERSION => {
                    let offer = DiscoveryMessage::Offer {
                        version: PROTOCOL_VERSION,
                        nonce,
                        data_port: self.data_port,
                        host_name: self.host_name.clone(),
                    };
                    let bytes = offer.encode()?;
                    if let Err(e) = self.socket.send_to(&bytes, from).await {
                        tracing::warn!(%from, error = %e, "failed to send discovery offer");
                    } else {
                        tracing::debug!(%from, "answered discovery probe");
                    }
                }
                DiscoveryMessage::Probe { version, .. } => {
                    tracing::debug!(%from, version, "ignoring probe with foreign protocol version");
                }
                DiscoveryMessage::Offer { .. } => {
                    tracing::trace!(%from, "ignoring offer (we are the host)");
                }
            }
        }
    }
}

/// Guest side: multicast a `Probe` on `iface` and wait up to `timeout` for the
/// first matching `Offer`.
///
/// The probe is re-sent every 500 ms until an offer arrives or the timeout
/// expires. `Ok(None)` means no host answered in time; `Err` is a local socket
/// failure (for example the interface has no link-local address yet, which
/// surfaces as `EADDRNOTAVAIL`/`ENETUNREACH` on send).
pub async fn probe(iface: &LinkInterface, timeout: Duration) -> io::Result<Option<Discovered>> {
    let socket = new_v6_udp_socket()?;
    socket.set_multicast_if_v6(iface.index)?;
    socket.set_multicast_hops_v6(1)?;
    socket.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)).into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket)?;
    probe_with_socket(&socket, iface, MULTICAST_GROUP, DISCOVERY_PORT, timeout).await
}

/// Same as [`probe`] but with an explicit target address/port and caller-owned
/// socket. Used by [`probe`] and by tests (which target `::1`).
pub async fn probe_with_socket(
    socket: &UdpSocket,
    iface: &LinkInterface,
    target_ip: Ipv6Addr,
    target_port: u16,
    timeout: Duration,
) -> io::Result<Option<Discovered>> {
    let nonce = random_nonce();
    let probe = DiscoveryMessage::Probe {
        version: PROTOCOL_VERSION,
        nonce,
    }
    .encode()?;
    let target = SocketAddrV6::new(target_ip, target_port, 0, iface.index);

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; MAX_DATAGRAM];
    loop {
        socket.send_to(&probe, target).await?;
        let resend_at = Instant::now() + PROBE_RESEND_INTERVAL;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let wait = resend_at.min(deadline).saturating_duration_since(now);
            let recv = tokio::time::timeout(wait, socket.recv_from(&mut buf)).await;
            let (n, from) = match recv {
                Ok(Ok(v)) => v,
                Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Ok(Err(e)) => return Err(e),
                Err(_elapsed) => break, // resend or give up
            };
            let SocketAddr::V6(from6) = from else {
                continue;
            };
            match DiscoveryMessage::decode(&buf[..n]) {
                Some(DiscoveryMessage::Offer {
                    version,
                    nonce: got,
                    data_port,
                    host_name,
                }) if version == PROTOCOL_VERSION && got == nonce => {
                    let scope = if from6.scope_id() != 0 {
                        from6.scope_id()
                    } else {
                        iface.index
                    };
                    let host_addr = SocketAddrV6::new(*from6.ip(), data_port, 0, scope);
                    return Ok(Some(Discovered {
                        host_addr,
                        host_name,
                    }));
                }
                other => {
                    tracing::trace!(%from, ?other, "ignoring discovery datagram");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::LinkKind;

    #[test]
    fn probe_offer_round_trip() {
        let msgs = [
            DiscoveryMessage::Probe {
                version: PROTOCOL_VERSION,
                nonce: 0x0123_4567_89ab_cdef,
            },
            DiscoveryMessage::Offer {
                version: PROTOCOL_VERSION,
                nonce: u64::MAX,
                data_port: crate::DATA_PORT,
                host_name: "studio".to_string(),
            },
        ];
        for m in msgs {
            let bytes = m.encode().unwrap();
            assert!(bytes.starts_with(MAGIC));
            assert!(bytes.len() < 64, "discovery datagrams must stay tiny");
            assert_eq!(DiscoveryMessage::decode(&bytes), Some(m));
        }
    }

    #[test]
    fn garbage_is_rejected() {
        assert_eq!(DiscoveryMessage::decode(b""), None);
        assert_eq!(DiscoveryMessage::decode(b"NETM"), None);
        assert_eq!(DiscoveryMessage::decode(b"XXXX\x00\x01"), None);
        assert_eq!(DiscoveryMessage::decode(b"NETM\x09"), None);
    }

    fn loopback_iface() -> LinkInterface {
        LinkInterface {
            name: "lo".into(),
            index: 0,
            is_up: true,
            link_local_v6: None,
            kind: LinkKind::Other,
        }
    }

    #[tokio::test]
    async fn responder_answers_unicast_probe() {
        let Ok(responder) = Responder::bind_with_port(&[], 0, 4242, "test-host".to_string()).await
        else {
            return; // no IPv6 on this machine
        };
        let port = responder.local_addr().unwrap().port();
        let task = tokio::spawn(responder.run());

        let client = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await {
            Ok(s) => s,
            Err(_) => {
                task.abort();
                return;
            }
        };
        let iface = loopback_iface();
        let found = probe_with_socket(
            &client,
            &iface,
            Ipv6Addr::LOCALHOST,
            port,
            Duration::from_secs(2),
        )
        .await
        .unwrap()
        .expect("responder should answer");
        assert_eq!(found.host_name, "test-host");
        assert_eq!(found.host_addr.ip(), &Ipv6Addr::LOCALHOST);
        assert_eq!(found.host_addr.port(), 4242);
        task.abort();
    }

    #[tokio::test]
    async fn probe_times_out_without_host() {
        let Ok(client) = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await else {
            return;
        };
        // Port 9 (discard) on loopback: nothing answers.
        let res = probe_with_socket(
            &client,
            &loopback_iface(),
            Ipv6Addr::LOCALHOST,
            9,
            Duration::from_millis(300),
        )
        .await;
        match res {
            Ok(None) => {}
            // ICMP port unreachable may surface as an error on some platforms.
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused, "{e:?}"),
            Ok(Some(d)) => panic!("unexpected offer {d:?}"),
        }
    }
}
