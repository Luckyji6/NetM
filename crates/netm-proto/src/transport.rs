//! Transport abstraction: anything that is an async byte stream can carry
//! NetM frames (TCP over the Thunderbolt bridge, a USB serial port, an
//! in-memory duplex for tests, ...).

use std::fmt;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

/// A bidirectional byte stream suitable for carrying frames.
///
/// Blanket-implemented for every `AsyncRead + AsyncWrite + Unpin + Send +
/// 'static` type, so `tokio::net::TcpStream`, `tokio_serial::SerialStream` and
/// `tokio::io::DuplexStream` all qualify without extra code.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> Transport for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

/// Address of the other end of a tunnel session, independent of the
/// transport: a TCP peer or a serial port path. Used by the host for the
/// connected guest and by the guest for the host it talks to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// TCP peer address (`[fe80::…%bridge0]:27778`).
    Tcp(SocketAddr),
    /// Serial port device path (`/dev/tty.usbmodem1234`, `COM5`).
    Serial(String),
}

impl Endpoint {
    /// `true` for [`Endpoint::Serial`].
    pub fn is_serial(&self) -> bool {
        matches!(self, Endpoint::Serial(_))
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Tcp(a) => write!(f, "{a}"),
            Endpoint::Serial(p) => f.write_str(p),
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(a: SocketAddr) -> Self {
        Endpoint::Tcp(a)
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;

    #[test]
    fn display_and_conversions() {
        let addr: SocketAddr = "[fe80::1%5]:27778".parse().unwrap();
        let tcp = Endpoint::from(addr);
        assert_eq!(tcp, Endpoint::Tcp(addr));
        assert_eq!(tcp.to_string(), "[fe80::1%5]:27778");
        assert!(!tcp.is_serial());
        let serial = Endpoint::Serial("/dev/tty.usbmodem1".into());
        assert_eq!(serial.to_string(), "/dev/tty.usbmodem1");
        assert!(serial.is_serial());
        assert_ne!(tcp, serial);
    }
}

/// USB serial (CDC-ACM) transport: the fallback for cables that do not form
/// a network link. Frames on serial links use
/// [`crate::frame::SyncFrameCodec`] (see [`crate::frame::framed_sync`]).
pub mod serial {
    use std::io;

    use tokio_serial::{DataBits, FlowControl, Parity, StopBits};
    pub use tokio_serial::{SerialPortInfo, SerialPortType, SerialStream, UsbPortInfo};

    /// Default line speed. USB CDC-ACM devices ignore the value (the USB
    /// bus sets the real speed) and real UART bridges usually accept it.
    pub const DEFAULT_BAUD: u32 = 921_600;

    /// Open `path` at `baud`, 8N1, no flow control, non-exclusive (no
    /// `TIOCEXCL`, shared `flock`, so a stale lock from a previous run does
    /// not block us).
    ///
    /// On macOS `baud == 0` leaves the line speed untouched; this is the
    /// only way to open a pseudo-terminal there (`IOSSIOSPEED` fails with
    /// `ENOTTY` on ptys). Real USB devices accept any speed.
    pub async fn open(path: &str, baud: u32) -> io::Result<SerialStream> {
        let builder = tokio_serial::new(path, baud)
            .data_bits(DataBits::Eight)
            .parity(Parity::None)
            .stop_bits(StopBits::One)
            .flow_control(FlowControl::None)
            .exclusive(false);
        Ok(SerialStream::open(&builder)?)
    }

    /// Baud rate tests use for pseudo-terminal pairs (see [`open`]).
    #[doc(hidden)]
    pub const PTY_TEST_BAUD: u32 = if cfg!(target_os = "macos") {
        0
    } else {
        115_200
    };

    /// Whether a port looks like a USB serial device: either the OS reports
    /// it as such or its name follows the usual USB naming conventions
    /// (`tty.usb*`, `ttyUSB*`, `ttyACM*`).
    pub fn is_usb_like(info: &SerialPortInfo) -> bool {
        if matches!(info.port_type, SerialPortType::UsbPort(_)) {
            return true;
        }
        let name = info.port_name.rsplit('/').next().unwrap_or(&info.port_name);
        name.starts_with("tty.usb")
            || name.starts_with("cu.usb")
            || name.starts_with("ttyUSB")
            || name.starts_with("ttyACM")
    }

    /// Enumerate serial ports, keeping USB ones where the platform lets us
    /// tell. Falls back to the unfiltered list when nothing is recognised
    /// as USB (so unusual drivers are still shown).
    pub fn list_ports() -> io::Result<Vec<SerialPortInfo>> {
        let all = tokio_serial::available_ports()?;
        let usb: Vec<SerialPortInfo> = all.iter().filter(|p| is_usb_like(p)).cloned().collect();
        Ok(if usb.is_empty() { all } else { usb })
    }

    /// One line describing a port for humans (`/dev/tty.usbmodem1  USB 1a86:7523 CH340`).
    pub fn describe(info: &SerialPortInfo) -> String {
        match &info.port_type {
            SerialPortType::UsbPort(u) => {
                let mut s = format!("{}  USB {:04x}:{:04x}", info.port_name, u.vid, u.pid);
                if let Some(m) = &u.manufacturer {
                    s.push(' ');
                    s.push_str(m);
                }
                if let Some(p) = &u.product {
                    s.push(' ');
                    s.push_str(p);
                }
                s
            }
            SerialPortType::PciPort => format!("{}  PCI", info.port_name),
            SerialPortType::BluetoothPort => format!("{}  Bluetooth", info.port_name),
            SerialPortType::Unknown => info.port_name.clone(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn list_ports_does_not_fail() {
            // Whatever the machine has, enumeration must not error out.
            let ports = list_ports().unwrap();
            for p in &ports {
                assert!(!describe(p).is_empty());
            }
        }

        #[test]
        fn usb_heuristics() {
            let unknown = |name: &str| SerialPortInfo {
                port_name: name.to_string(),
                port_type: SerialPortType::Unknown,
            };
            assert!(is_usb_like(&unknown("/dev/tty.usbmodem12345")));
            assert!(is_usb_like(&unknown("/dev/ttyACM0")));
            assert!(is_usb_like(&unknown("/dev/ttyUSB0")));
            assert!(!is_usb_like(&unknown("/dev/tty.Bluetooth-Incoming-Port")));
            assert!(!is_usb_like(&unknown("COM3")));
            let usb = SerialPortInfo {
                port_name: "COM3".into(),
                port_type: SerialPortType::UsbPort(UsbPortInfo {
                    vid: 0x1a86,
                    pid: 0x7523,
                    serial_number: None,
                    manufacturer: Some("wch".into()),
                    product: Some("CH340".into()),
                }),
            };
            assert!(is_usb_like(&usb));
            assert!(describe(&usb).contains("1a86:7523"));
        }

        #[tokio::test]
        async fn open_missing_port_is_an_error() {
            let err = open("/dev/netm-definitely-missing-port", DEFAULT_BAUD)
                .await
                .unwrap_err();
            assert!(!err.to_string().is_empty());
        }

        /// Open the slave side of a pseudo-terminal pair through `open` and
        /// push bytes both ways. Proves the settings we apply are accepted
        /// by a tty and that `SerialStream` works as a `Transport`.
        #[cfg(unix)]
        #[tokio::test]
        async fn open_pty_slave_and_round_trip() {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio_serial::SerialPort;
            let (mut master, slave) = SerialStream::pair().expect("openpty");
            let path = slave.name().expect("pty slave has a path");
            let mut port = open(&path, PTY_TEST_BAUD).await.expect("open pty slave");
            master.write_all(b"hello").await.unwrap();
            let mut buf = [0u8; 5];
            tokio::time::timeout(std::time::Duration::from_secs(2), port.read_exact(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf, b"hello");
            port.write_all(b"world").await.unwrap();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                master.read_exact(&mut buf),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&buf, b"world");
            drop(slave);
        }
    }
}

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
