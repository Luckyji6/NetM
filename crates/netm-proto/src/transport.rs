//! Transport abstraction: anything that is an async byte stream can carry
//! NetM frames (TCP over the Thunderbolt bridge, a USB serial port, an
//! in-memory duplex for tests, ...).

use tokio::io::{AsyncRead, AsyncWrite};

/// A bidirectional byte stream suitable for carrying frames.
///
/// Blanket-implemented for every `AsyncRead + AsyncWrite + Unpin + Send +
/// 'static` type, so `tokio::net::TcpStream`, `tokio_serial::SerialStream` and
/// `tokio::io::DuplexStream` all qualify without extra code.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> Transport for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

/// TCP transport helpers.
pub mod tcp {
    use std::io;
    use std::net::SocketAddr;
    use std::time::Duration;

    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::net::{TcpListener, TcpStream};

    /// Bind a TCP listener on `addr` with `SO_REUSEADDR` set.
    ///
    /// For IPv6 addresses `IPV6_V6ONLY` is cleared so an `[::]` listener also
    /// accepts IPv4 clients (dual-stack). To listen on a link-local address
    /// (`fe80::/10`) the [`std::net::SocketAddrV6`] **must** carry the
    /// interface index as `scope_id`, otherwise `bind` fails with
    /// `EADDRNOTAVAIL`.
    pub async fn listen(addr: SocketAddr) -> io::Result<TcpListener> {
        let domain = if addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        if addr.is_ipv6() {
            // Best effort: some platforms refuse to change this on an already
            // configured socket; dual-stack is a nicety, not a requirement.
            let _ = socket.set_only_v6(false);
        }
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        socket.listen(128)?;
        let std_listener: std::net::TcpListener = socket.into();
        TcpListener::from_std(std_listener)
    }

    /// Connect to `addr` within `timeout` and enable `TCP_NODELAY`.
    ///
    /// For link-local IPv6 targets the `scope_id` of the [`SocketAddr::V6`]
    /// must be the interface index of the local link (see
    /// [`crate::link::LinkInterface::index`]); this is exactly what
    /// [`crate::discovery::Discovered::host_addr`] provides.
    pub async fn connect(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp connect timed out"))??;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::{Ipv4Addr, Ipv6Addr};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[tokio::test]
        async fn listen_and_connect_v4() {
            let listener = listen(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();
            let accept = async { listener.accept().await.unwrap().0 };
            let connect = connect(addr, Duration::from_secs(2));
            let (mut server, client) = tokio::join!(accept, connect);
            let mut client = client.unwrap();
            assert!(client.nodelay().unwrap());
            client.write_all(b"hi").await.unwrap();
            let mut buf = [0u8; 2];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hi");
        }

        #[tokio::test]
        async fn listen_v6_loopback() {
            let Ok(listener) = listen(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).await else {
                // IPv6 loopback not available on this machine; nothing to test.
                return;
            };
            let addr = listener.local_addr().unwrap();
            let accept = async { listener.accept().await.unwrap() };
            let connect = connect(addr, Duration::from_secs(2));
            let (_srv, client) = tokio::join!(accept, connect);
            client.unwrap();
        }

        #[tokio::test]
        async fn connect_timeout_is_reported() {
            // 192.0.2.0/24 is TEST-NET-1: never routable, so SYNs get no answer.
            let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
            let err = connect(addr, Duration::from_millis(200)).await.unwrap_err();
            // Some hosts return ENETUNREACH immediately instead of timing out; both are errors.
            assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::NetworkUnreachable
                        | io::ErrorKind::HostUnreachable
                        | io::ErrorKind::Other
                ),
                "unexpected error kind: {err:?}"
            );
        }
    }
}
