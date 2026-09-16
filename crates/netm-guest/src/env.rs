//! The guest's view of the outside world (interfaces, discovery, TCP, TUN,
//! platform configuration) behind one trait so the whole state machine can
//! run against fakes in unit tests.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use netm_proto::discovery::Discovered;
use netm_proto::{LinkInterface, Transport, TunnelConfig};

use crate::platform::PlatformConfigurator;
use crate::tun::TunIo;

pub(crate) trait GuestEnv: Send + 'static {
    type Tun: TunIo;
    type Link: Transport;
    type Serial: Transport;

    /// Candidate link interfaces, sorted by preference.
    fn list_interfaces(&mut self) -> impl Future<Output = io::Result<Vec<LinkInterface>>> + Send;

    /// Whether `iface` still has a carrier. Polled several times a second
    /// while the tunnel is up, so it must not spawn subprocesses.
    ///
    /// `None` when the platform cannot tell (the caller then keeps the tunnel
    /// up and relies on keep-alives).
    fn link_active(&mut self, iface: &str) -> Option<bool>;

    /// Interface the default route points at while no tunnel is up.
    fn local_egress(&mut self) -> impl Future<Output = Option<String>> + Send;

    /// Multicast-probe `iface` for a host.
    fn probe(
        &mut self,
        iface: &LinkInterface,
        timeout: Duration,
    ) -> impl Future<Output = io::Result<Option<Discovered>>> + Send;

    /// When multicast (and unicast UDP) discovery stays silent, the other
    /// Mac is often still in the neighbour table. Return its data-plane
    /// address (`fe80` / `169.254` on [`netm_proto::DATA_PORT`]) so the
    /// guest can TCP-connect without an Offer.
    fn neighbor_target(
        &mut self,
        iface: &LinkInterface,
    ) -> impl Future<Output = Option<SocketAddr>> + Send;

    /// Open the data connection to the host.
    fn connect(
        &mut self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> impl Future<Output = io::Result<Self::Link>> + Send;

    /// Open the serial port `path` at `baud` (raw byte stream to the host).
    fn open_serial(
        &mut self,
        path: &str,
        baud: u32,
    ) -> impl Future<Output = io::Result<Self::Serial>> + Send;

    /// Create the TUN interface for `cfg`.
    fn open_tun(
        &mut self,
        cfg: &TunnelConfig,
    ) -> impl Future<Output = io::Result<Self::Tun>> + Send;

    /// Fresh platform configurator (routes / DNS).
    fn configurator(&mut self) -> Box<dyn PlatformConfigurator>;
}

/// Production environment: real interfaces, discovery, TCP, serial and tun-rs.
pub(crate) struct RealEnv;

impl GuestEnv for RealEnv {
    type Tun = crate::tun::TunDevice;
    type Link = tokio::net::TcpStream;
    type Serial = netm_proto::transport::serial::SerialStream;

    async fn list_interfaces(&mut self) -> io::Result<Vec<LinkInterface>> {
        // `networksetup` is spawned under the hood on macOS: keep it off the
        // async threads.
        tokio::task::spawn_blocking(netm_proto::list_candidate_interfaces)
            .await
            .map_err(|e| io::Error::other(format!("interface listing task failed: {e}")))?
    }

    fn link_active(&mut self, iface: &str) -> Option<bool> {
        netm_proto::link::is_link_active(iface).ok()
    }

    async fn local_egress(&mut self) -> Option<String> {
        // Spawns `route`/`ip`: keep it off the async threads.
        tokio::task::spawn_blocking(crate::platform::default_egress_interface)
            .await
            .unwrap_or(None)
    }

    async fn probe(
        &mut self,
        iface: &LinkInterface,
        timeout: Duration,
    ) -> io::Result<Option<Discovered>> {
        netm_proto::discovery::probe(iface, timeout).await
    }

    async fn neighbor_target(&mut self, iface: &LinkInterface) -> Option<SocketAddr> {
        let iface = iface.clone();
        tokio::task::spawn_blocking(move || netm_proto::neighbor_data_addr(&iface))
            .await
            .ok()
            .flatten()
    }

    async fn connect(
        &mut self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> io::Result<tokio::net::TcpStream> {
        netm_proto::transport::tcp::connect(addr, timeout).await
    }

    async fn open_serial(
        &mut self,
        path: &str,
        baud: u32,
    ) -> io::Result<netm_proto::transport::serial::SerialStream> {
        netm_proto::transport::serial::open(path, baud).await
    }

    async fn open_tun(&mut self, cfg: &TunnelConfig) -> io::Result<crate::tun::TunDevice> {
        let sync_cfg = cfg.clone();
        let sync =
            tokio::task::spawn_blocking(move || crate::tun::TunDevice::create_sync(&sync_cfg))
                .await
                .map_err(|e| io::Error::other(format!("tun creation task failed: {e}")))??;
        crate::tun::TunDevice::into_async(sync, cfg)
    }

    fn configurator(&mut self) -> Box<dyn PlatformConfigurator> {
        crate::platform::system_configurator()
    }
}
