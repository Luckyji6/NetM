//! TUN device abstraction.
//!
//! [`TunIo`] is what the packet pump talks to; [`TunDevice`] implements it on
//! top of [`tun_rs::AsyncDevice`]. Packets crossing the trait are **raw IP
//! packets**: on macOS the kernel prepends a 4-byte address-family header to
//! every utun read/write, and tun-rs strips/adds it for us because
//! `packet_information` is left at its default (`false`).

use std::future::Future;
use std::io;

use netm_proto::TunnelConfig;

/// Async raw-IP packet I/O on a tunnel interface.
pub trait TunIo: Send + Sync + 'static {
    /// Read one IP packet into `buf`, returning its length.
    fn recv<'a>(&'a self, buf: &'a mut [u8])
        -> impl Future<Output = io::Result<usize>> + Send + 'a;
    /// Write one IP packet.
    fn send<'a>(&'a self, pkt: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a;
    /// OS interface name (`utun4`, `tun0`, ...).
    fn name(&self) -> &str;
}

/// [`TunIo`] backed by a real tun-rs device.
pub struct TunDevice {
    dev: tun_rs::AsyncDevice,
    name: String,
}

impl TunDevice {
    /// Create the TUN interface for `cfg`: address `guest_ip`, point-to-point
    /// destination `gateway_ip`, netmask from `prefix_len`, MTU `mtu`.
    ///
    /// tun-rs assigns the address via `SIOCAIFADDR` and (on macOS/BSD, with
    /// its default `associate_route = true`) installs the route for the
    /// tunnel subnet itself; the `/1` split routes and DNS are added by the
    /// platform configurator afterwards.
    ///
    /// The device is built synchronously (ioctls; safe to call from
    /// `spawn_blocking`); use [`TunDevice::into_async`] on a runtime thread
    /// to register it with tokio.
    pub fn create_sync(cfg: &TunnelConfig) -> io::Result<tun_rs::SyncDevice> {
        tun_rs::DeviceBuilder::new()
            .ipv4(cfg.guest_ip, cfg.prefix_len, Some(cfg.gateway_ip))
            .mtu(cfg.mtu)
            .build_sync()
    }

    /// Register a device built by [`TunDevice::create_sync`] with the current
    /// tokio runtime.
    pub fn into_async(sync: tun_rs::SyncDevice, cfg: &TunnelConfig) -> io::Result<Self> {
        let dev = tun_rs::AsyncDevice::new(sync)?;
        let name = dev.name()?;
        tracing::info!(
            tun = %name,
            ip = %cfg.guest_ip,
            gw = %cfg.gateway_ip,
            prefix = cfg.prefix_len,
            mtu = cfg.mtu,
            "created tun device"
        );
        Ok(Self { dev, name })
    }
}

impl TunIo for TunDevice {
    fn recv<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        self.dev.recv(buf)
    }

    fn send<'a>(&'a self, pkt: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        self.dev.send(pkt)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// In-memory TUN for tests: packets "sent" by the pump are pushed to
/// `to_apps`, packets fed into `from_apps` are what the pump "reads".
#[cfg(test)]
pub mod fake {
    use super::*;
    use tokio::sync::{mpsc, Mutex};

    pub struct FakeTun {
        name: String,
        from_apps: Mutex<mpsc::Receiver<Vec<u8>>>,
        to_apps: mpsc::Sender<Vec<u8>>,
    }

    /// Handles the test keeps: inject packets (as if an app sent them) and
    /// observe packets delivered to the interface.
    pub struct FakeTunHandle {
        pub inject: mpsc::Sender<Vec<u8>>,
        pub delivered: mpsc::Receiver<Vec<u8>>,
    }

    impl FakeTun {
        pub fn new(name: &str) -> (FakeTun, FakeTunHandle) {
            let (inject, from_apps) = mpsc::channel(64);
            let (to_apps, delivered) = mpsc::channel(64);
            (
                FakeTun {
                    name: name.to_string(),
                    from_apps: Mutex::new(from_apps),
                    to_apps,
                },
                FakeTunHandle { inject, delivered },
            )
        }
    }

    impl TunIo for FakeTun {
        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut rx = self.from_apps.lock().await;
            match rx.recv().await {
                Some(pkt) => {
                    let n = pkt.len().min(buf.len());
                    buf[..n].copy_from_slice(&pkt[..n]);
                    Ok(n)
                }
                None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "fake tun closed")),
            }
        }

        async fn send(&self, pkt: &[u8]) -> io::Result<usize> {
            self.to_apps
                .send(pkt.to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "fake tun closed"))?;
            Ok(pkt.len())
        }

        fn name(&self) -> &str {
            &self.name
        }
    }
}
