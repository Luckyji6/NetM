//! # netm-guest
//!
//! Guest (client) side of the NetM tunnel: waits for a Type-C link, discovers
//! the host, connects, creates a TUN interface and forwards every IP packet
//! through the host. The crate exposes a single long-running [`run`]
//! function driven by a control channel and reporting through an event
//! channel, so a TUI, a headless logger or a test can sit on top of the same
//! core.
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! use netm_guest::{run, GuestCommand, GuestConfig, GuestEvent};
//! let (events_tx, mut events_rx) = tokio::sync::mpsc::channel::<GuestEvent>(256);
//! let (ctrl_tx, ctrl_rx) = tokio::sync::watch::channel(GuestCommand::Run);
//! let guest = tokio::spawn(run(GuestConfig::default(), events_tx, ctrl_rx));
//! while let Some(ev) = events_rx.recv().await {
//!     println!("{ev:?}");
//! }
//! ctrl_tx.send(GuestCommand::Shutdown)?;
//! guest.await??;
//! # Ok(()) }
//! ```
//!
//! Platform support: macOS (utun via tun-rs, `route`/`scutil`); Linux and
//! Windows compile but return "not yet supported" from the platform
//! configurator.

use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{bail, Result};
use tokio::sync::{mpsc, watch};

mod env;
mod guest;
pub mod platform;
pub mod tun;

pub use platform::PlatformConfigurator;

/// Which traffic is sent through the tunnel.
#[derive(Clone, Debug)]
pub enum RouteMode {
    /// Everything: `0.0.0.0/1` + `128.0.0.0/1` via the TUN (the default
    /// route itself is left untouched, so the link-local transport keeps
    /// working).
    Full,
    /// Only these prefixes (e.g. `1.1.1.1/32` for a single-machine test).
    Custom(Vec<ipnet::Ipv4Net>),
}

impl RouteMode {
    /// Recommended `set_dns` for this mode: `true` for [`RouteMode::Full`],
    /// `false` for [`RouteMode::Custom`] (DNS would otherwise go through the
    /// tunnel while most traffic does not).
    pub fn default_set_dns(&self) -> bool {
        matches!(self, RouteMode::Full)
    }
}

/// How to find the host.
#[derive(Clone, Debug)]
pub enum HostTarget {
    /// Multicast discovery over every candidate link (Thunderbolt bridge
    /// first).
    Auto,
    /// Connect to this address directly. For a link-local IPv6 address the
    /// `scope_id` must be set to the interface index.
    Manual(SocketAddr),
}

/// Guest configuration.
#[derive(Clone, Debug)]
pub struct GuestConfig {
    /// Name announced in the `Hello` frame (default: hostname).
    pub name: String,
    pub host: HostTarget,
    pub routes: RouteMode,
    /// Point the system resolver at the tunnel DNS while connected
    /// (default `true`; see [`RouteMode::default_set_dns`]).
    pub set_dns: bool,
    /// Go back to waiting for a link after a disconnect (default `true`).
    /// When `false`, [`run`] returns after the first disconnect or failure.
    pub reconnect: bool,
}

impl Default for GuestConfig {
    fn default() -> Self {
        Self {
            name: default_name(),
            host: HostTarget::Auto,
            routes: RouteMode::Full,
            set_dns: true,
            reconnect: true,
        }
    }
}

fn default_name() -> String {
    hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "netm-guest".to_string())
}

/// Observable state of the guest.
#[derive(Clone, Debug, PartialEq)]
pub enum GuestState {
    /// No candidate interface has a link-local address yet (cable unplugged).
    WaitingForLink,
    /// A link is present; probing it for a host.
    Discovering {
        iface: String,
    },
    Connecting {
        host: SocketAddr,
    },
    Connected {
        host: SocketAddr,
        host_name: String,
        /// OS name of the TUN interface (`utun4`).
        tun: String,
        config: netm_proto::TunnelConfig,
        since: Instant,
    },
    /// Transient; followed by [`GuestState::WaitingForLink`] when
    /// `reconnect` is on.
    Disconnected {
        reason: String,
    },
}

/// Events reported by [`run`].
#[derive(Clone, Debug)]
pub enum GuestEvent {
    StateChanged(GuestState),
    /// Candidate interfaces (sent whenever the list changes).
    Interfaces(Vec<netm_proto::LinkInterface>),
    /// Every 500 ms while connected. Sent with `try_send`: dropped when the
    /// channel is full.
    Stats {
        counters: netm_proto::Counters,
        /// Bits per second into the tunnel (guest → host).
        tx_bps: f64,
        /// Bits per second out of the tunnel (host → guest).
        rx_bps: f64,
    },
    Log(String),
    Error(String),
}

/// Commands for [`run`].
#[derive(Clone, Debug, PartialEq)]
pub enum GuestCommand {
    Run,
    /// Tear everything down and return. Honoured from any state within
    /// ~200 ms.
    Shutdown,
}

/// Whether the guest needs root/administrator privileges on this OS.
pub fn requires_root() -> bool {
    cfg!(unix)
}

/// Run the guest until [`GuestCommand::Shutdown`] is received (or, with
/// `reconnect = false`, until the first disconnect/failure).
///
/// Returns an error immediately when root privileges are required but
/// missing. When it returns, all routes, DNS settings and the TUN device
/// have been removed.
pub async fn run(
    cfg: GuestConfig,
    events: mpsc::Sender<GuestEvent>,
    ctrl: watch::Receiver<GuestCommand>,
) -> Result<()> {
    if requires_root() && !netm_proto::privilege::is_root() {
        bail!(
            "netm guest needs root privileges to create the TUN device and change routes; \
             re-run with `sudo`"
        );
    }
    guest::Guest::new(cfg, env::RealEnv, events, ctrl, guest::Timings::default())
        .run()
        .await
}

#[cfg(test)]
mod tests;
