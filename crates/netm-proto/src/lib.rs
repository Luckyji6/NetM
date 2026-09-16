//! # netm-proto
//!
//! Shared wire protocol and platform glue for NetM, a Type-C tunnel network
//! sharing tool. The crate is used by both the host (`netm-host`) and the
//! guest (`netm-guest`) sides and by the CLI.
//!
//! Modules:
//! - [`frame`]: length-prefixed frame protocol ([`frame::Frame`], [`frame::FrameCodec`]).
//! - [`transport`]: the [`transport::Transport`] trait plus a TCP implementation.
//! - [`discovery`]: IPv6 link-local multicast discovery (`ff02::1`).
//! - [`link`]: enumeration of Thunderbolt / USB Ethernet interfaces.
//! - [`privilege`]: privilege checks.
//! - [`stats`]: byte/packet counters and a sliding-window rate meter.

pub mod discovery;
pub mod frame;
pub mod link;
pub mod privilege;
pub mod speed;
pub mod stats;
pub mod transport;

/// Protocol version carried in `Hello` frames and discovery messages. Peers
/// with a different version must not talk to each other.
pub const PROTOCOL_VERSION: u16 = 1;

/// UDP port used for link-local multicast discovery (`ff02::1`).
pub const DISCOVERY_PORT: u16 = 27777;

/// Default TCP port the host listens on for tunnel data sessions.
pub const DATA_PORT: u16 = 27778;

/// Default MTU of the virtual tunnel interface.
pub const DEFAULT_MTU: u16 = 1400;

pub use frame::{framed, Frame, FrameCodec, FrameError, FramedTransport, TunnelConfig};
pub use link::{
    list_candidate_interfaces, list_neighbors, neighbor_data_addr, LinkInterface, LinkKind,
    Neighbor,
};
pub use speed::LinkSpeed;
pub use stats::{Counters, RateMeter};
pub use transport::Transport;
