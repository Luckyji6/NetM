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

    /// Candidate link interfaces, sorted by preference.
    fn list_interfaces(&mut self) -> impl Future<Output = io::Result<Vec<LinkInterface>>> + Send;

    /// Multicast-probe `iface` for a host.
    fn probe(
        &mut self,
        iface: &LinkInterface,
        timeout: Duration,
    ) -> impl Future<Output = io::Result<Option<Discovered>>> + Send;

    /// Open the data connection to the host.
    fn connect(
        &mut self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> impl Future<Output = io::Result<Self::Link>> + Send;

    /// Create the TUN interface for `cfg`.
    fn open_tun(
        &mut self,
        cfg: &TunnelConfig,
    ) -> impl Future<Output = io::Result<Self::Tun>> + Send;

    /// Fresh platform configurator (routes / DNS).
    fn configurator(&mut self) -> Box<dyn PlatformConfigurator>;
}

/// Production environment: real interfaces, discovery, TCP and tun-rs.
pub(crate) struct RealEnv;

impl GuestEnv for RealEnv {
    type Tun = crate::tun::TunDevice;
    type Link = tokio::net::TcpStream;

    async fn list_interfaces(&mut self) -> io::Result<Vec<LinkInterface>> {
        // `networksetup` is spawned under the hood on macOS: keep it off the
        // async threads.
        tokio::task::spawn_blocking(netm_proto::list_candidate_interfaces)
            .await
            .map_err(|e| io::Error::other(format!("interface listing task failed: {e}")))?
    }

    async fn probe(
        &mut self,
        iface: &LinkInterface,
        timeout: Duration,
    ) -> io::Result<Option<Discovered>> {
        netm_proto::discovery::probe(iface, timeout).await
    }

    async fn connect(
        &mut self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> io::Result<tokio::net::TcpStream> {
        netm_proto::transport::tcp::connect(addr, timeout).await
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
