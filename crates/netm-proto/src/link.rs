//! Enumeration of physical link candidates (Thunderbolt bridge, Thunderbolt
//! ports, USB Ethernet adapters) the tunnel can run over.
//!
//! On macOS the list of interfaces comes from `getifaddrs(3)`, filtered to
//! `enN` and `bridge0`; the carrier state comes from the `SIOCGIFMEDIA` ioctl
//! (what `ifconfig` prints as `status: active`). `networksetup
//! -listallhardwareports` is consulted **only** to name and classify them —
//! it must not act as a filter, because macOS lists an interface there only
//! once it has built a network service for it, which lags behind (or never
//! happens for) a freshly plugged Type-C link.
//!
//! On Linux `getifaddrs(3)` is combined with the interface name and the
//! kernel driver bound to it (`/sys/class/net/<if>/device/driver`):
//! `thunderbolt-net` → [`LinkKind::Thunderbolt`], USB Ethernet class drivers
//! (`cdc_ncm`, `cdc_ether`, `rndis_host`, `r8152`, ...) →
//! [`LinkKind::UsbEthernet`]; wireless, virtual and tunnel interfaces are
//! skipped.
//!
//! On Windows `if-addrs` (`GetAdaptersAddresses`) supplies index, status and
//! addresses. It exposes the connection's *friendly name* ("Ethernet 2") but
//! not the adapter description ("Thunderbolt(TM) Networking"), so the
//! classification only looks for "thunderbolt"/"usb" in the friendly name and
//! otherwise reports [`LinkKind::Other`]; listing PowerShell/`Get-NetAdapter`
//! every poll would be too slow. Discovery probes every ready candidate
//! anyway, so a wrong kind only affects ordering in the UI.
//!
//! Other Unix platforms get a generic fallback that lists every up,
//! non-loopback interface with a link-local IPv6 address as
//! [`LinkKind::Other`].

use std::io;
use std::net::Ipv6Addr;

/// What kind of physical link an interface represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LinkKind {
    /// macOS "Thunderbolt Bridge" (`bridge0`) — the preferred link: it spans all
    /// Thunderbolt ports, so it does not matter which port the cable is in.
    ThunderboltBridge,
    /// An individual Thunderbolt/USB4 port (`en1`, `en2`, ...).
    Thunderbolt,
    /// USB Ethernet adapter / any "USB" or "Ethernet Adapter" hardware port.
    UsbEthernet,
    /// Anything else that could carry IPv6 link-local traffic.
    Other,
}

/// A network interface that may carry the tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkInterface {
    /// OS interface name (`bridge0`, `en1`, `eth0`, ...).
    pub name: String,
    /// Interface index (`if_nametoindex`). Use it as the `scope_id` of every
    /// link-local [`std::net::SocketAddrV6`] and as the `IPV6_MULTICAST_IF`.
    pub index: u32,
    /// Whether the link has a carrier, i.e. a cable is plugged in at both
    /// ends. On macOS this is the `SIOCGIFMEDIA` status that `ifconfig` shows
    /// as `status: active` (`IFF_UP | IFF_RUNNING` is useless there: an empty
    /// Thunderbolt port reports `RUNNING`); elsewhere it is the interface's
    /// operational state.
    pub is_up: bool,
    /// The interface's `fe80::/10` address, if it has one.
    pub link_local_v6: Option<Ipv6Addr>,
    /// Classification of the interface.
    pub kind: LinkKind,
}

impl LinkInterface {
    /// `true` when the interface is up and has a link-local IPv6 address, i.e.
    /// discovery/connection on it can be attempted right now.
    pub fn is_ready(&self) -> bool {
        self.is_up && self.link_local_v6.is_some()
    }
}

/// Runtime address/flag state of one interface, aggregated over its
/// `getifaddrs` entries.
#[cfg(unix)]
#[derive(Debug, Default, Clone)]
struct IfState {
    index: u32,
    is_up: bool,
    is_loopback: bool,
    /// `IFF_MULTICAST`: the interface can carry `ff02::1` at all.
    is_multicast: bool,
    link_local_v6: Option<Ipv6Addr>,
}

/// List candidate interfaces ordered by preference: [`LinkKind::ThunderboltBridge`]
/// first, then [`LinkKind::Thunderbolt`], [`LinkKind::UsbEthernet`], and
/// finally [`LinkKind::Other`]; interfaces of equal kind are sorted by name.
///
/// Interfaces are returned even when they are down or lack a link-local
/// address so callers can wait for a cable to be plugged in; check
/// [`LinkInterface::is_ready`] before using one.
pub fn list_candidate_interfaces() -> io::Result<Vec<LinkInterface>> {
    let mut list = platform::list()?;
    list.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.name.cmp(&b.name)));
    Ok(list)
}

/// List **every** non-loopback, multicast-capable interface the OS currently
/// knows about, without any hardware-port classification (all are reported as
/// [`LinkKind::Other`]), sorted by name.
///
/// This is the cheap, subprocess-free view (`getifaddrs(3)` on Unix,
/// `GetAdaptersAddresses` on Windows) that the discovery
/// [`Responder`](crate::discovery::Responder) uses to keep its `ff02::1`
/// memberships in sync. It deliberately does *not* go through
/// `networksetup` on macOS: a freshly attached USB/Type-C Ethernet interface
/// (`en8`) shows up here as soon as the kernel creates it, whereas
/// `-listallhardwareports` can lag behind, and the responder must be able to
/// join the group on it regardless of how the UI classifies it.
pub fn list_all_interfaces() -> io::Result<Vec<LinkInterface>> {
    let mut list = platform::list_all()?;
    list.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(list)
}

// ---------------------------------------------------------------------------
// getifaddrs-based state collection (all Unix)
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod unix_state {
    use super::IfState;
    use std::collections::BTreeMap;
    use std::io;

    use nix::net::if_::{if_nametoindex, InterfaceFlags};

    /// Aggregate `getifaddrs` output per interface name.
    pub(super) fn collect() -> io::Result<BTreeMap<String, IfState>> {
        let mut map: BTreeMap<String, IfState> = BTreeMap::new();
        for ifa in nix::ifaddrs::getifaddrs().map_err(io::Error::from)? {
            let entry = map.entry(ifa.interface_name.clone()).or_default();
            entry.is_up = ifa.flags.contains(InterfaceFlags::IFF_UP)
                && ifa.flags.contains(InterfaceFlags::IFF_RUNNING);
            entry.is_loopback = ifa.flags.contains(InterfaceFlags::IFF_LOOPBACK);
            entry.is_multicast = ifa.flags.contains(InterfaceFlags::IFF_MULTICAST);
            if let Some(addr) = ifa.address.as_ref().and_then(|a| a.as_sockaddr_in6()) {
                let ip = addr.ip();
                if ip.is_unicast_link_local() && entry.link_local_v6.is_none() {
                    entry.link_local_v6 = Some(ip);
                }
            }
        }
        for (name, st) in map.iter_mut() {
            st.index = if_nametoindex(name.as_str()).unwrap_or(0);
        }
        Ok(map)
    }
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

/// macOS classification rules. Pure functions on interface / hardware-port
/// names so they are unit-tested on every OS.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod macos_kind {
    use super::LinkKind;

    /// `true` for the only two shapes of interface name that can carry the
    /// tunnel: `bridge0` (the Thunderbolt Bridge) and `enN`.
    ///
    /// A real machine has dozens of other interfaces — `anpi*`, `ap1`,
    /// `awdl0`, `llw0`, `utun*`, `vmenet*`, `bridge100`+ (the virtualisation
    /// framework's NAT bridges), `gif0`, `stf0`, `feth*` — none of which is a
    /// physical port, so a name whitelist is both shorter and safer than
    /// blacklisting them.
    pub(super) fn is_candidate_name(name: &str) -> bool {
        if name == "bridge0" {
            return true;
        }
        matches!(name.strip_prefix("en"),
            Some(rest) if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    }

    /// Map an interface to a [`LinkKind`] given its `networksetup` hardware
    /// port name (`None` when `networksetup` does not list the interface).
    /// `None` = not a candidate.
    ///
    /// An interface missing from `networksetup` stays a candidate on purpose:
    /// macOS creates the interface as soon as a USB/Type-C Ethernet link is
    /// plugged in, but only adds a hardware port entry once it has built a
    /// network *service* for it — which may never happen. Skipping those was
    /// the reason a plugged-in Mac mini showed no link at all while its
    /// `en9`/`en10` were up with a `fe80::` address.
    pub(super) fn classify(name: &str, port: Option<&str>) -> Option<LinkKind> {
        if !is_candidate_name(name) {
            return None;
        }
        let Some(port) = port else {
            return Some(if name == "bridge0" {
                LinkKind::ThunderboltBridge
            } else {
                LinkKind::UsbEthernet
            });
        };
        let lower = port.to_ascii_lowercase();
        if lower.contains("wi-fi")
            || lower.contains("wifi")
            || lower.contains("airport")
            || lower.contains("bluetooth")
        {
            return None;
        }
        if lower.contains("thunderbolt bridge") {
            return Some(LinkKind::ThunderboltBridge);
        }
        if lower.starts_with("thunderbolt") {
            return Some(LinkKind::Thunderbolt);
        }
        if lower.contains("usb") || lower.contains("ethernet adapter") {
            return Some(LinkKind::UsbEthernet);
        }
        // Built-in "Ethernet" (the machine's own uplink) and anything else.
        Some(LinkKind::Other)
    }

    /// One `Hardware Port:` / `Device:` pair from `networksetup`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct HardwarePort {
        pub port: String,
        pub device: String,
    }

    /// Parse the output of `networksetup -listallhardwareports`.
    pub(super) fn parse_hardware_ports(text: &str) -> Vec<HardwarePort> {
        let mut out = Vec::new();
        let mut current_port: Option<String> = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("Hardware Port:") {
                current_port = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Device:") {
                if let Some(port) = current_port.take() {
                    let device = rest.trim().to_string();
                    if !device.is_empty() {
                        out.push(HardwarePort { port, device });
                    }
                }
            } else if line.is_empty() {
                current_port = None;
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Real output from a Mac mini whose Type-C link (`en9`, `en10`) is
        /// deliberately absent, as observed in the field.
        const SAMPLE: &str = "\
Hardware Port: Ethernet
Device: en0
Ethernet Address: 1c:f6:4c:57:44:af

Hardware Port: Ethernet Adapter (en5)
Device: en5
Ethernet Address: ea:cb:14:b1:42:a8

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 36:ea:2b:c7:fd:00

Hardware Port: Wi-Fi
Device: en1
Ethernet Address: 1c:f6:4c:57:48:1a

Hardware Port: Thunderbolt 1
Device: en2
Ethernet Address: 36:ea:2b:c7:fd:00

VLAN Configurations
===================
";

        #[test]
        fn parses_networksetup_output() {
            let ports = parse_hardware_ports(SAMPLE);
            let pairs: Vec<_> = ports
                .iter()
                .map(|p| (p.port.as_str(), p.device.as_str()))
                .collect();
            assert_eq!(
                pairs,
                vec![
                    ("Ethernet", "en0"),
                    ("Ethernet Adapter (en5)", "en5"),
                    ("Thunderbolt Bridge", "bridge0"),
                    ("Wi-Fi", "en1"),
                    ("Thunderbolt 1", "en2"),
                ]
            );
        }

        #[test]
        fn accepts_only_physical_port_names() {
            for name in ["en0", "en10", "bridge0"] {
                assert!(is_candidate_name(name), "{name} should be a candidate");
            }
            for name in [
                "lo0",
                "gif0",
                "stf0",
                "anpi0",
                "ap1",
                "awdl0",
                "llw0",
                "utun3",
                "vmenet0",
                "bridge100",
                "bridge101",
                "feth0",
                "en",
                "enx0",
            ] {
                assert!(!is_candidate_name(name), "{name} must be skipped");
            }
        }

        #[test]
        fn classifies_known_ports() {
            assert_eq!(
                classify("bridge0", Some("Thunderbolt Bridge")),
                Some(LinkKind::ThunderboltBridge)
            );
            assert_eq!(
                classify("en2", Some("Thunderbolt 1")),
                Some(LinkKind::Thunderbolt)
            );
            assert_eq!(
                classify("en5", Some("Ethernet Adapter (en5)")),
                Some(LinkKind::UsbEthernet)
            );
            assert_eq!(
                classify("en8", Some("iPhone USB")),
                Some(LinkKind::UsbEthernet)
            );
            assert_eq!(classify("en0", Some("Ethernet")), Some(LinkKind::Other));
            assert_eq!(classify("en1", Some("Wi-Fi")), None);
            assert_eq!(classify("en1", Some("AirPort")), None);
            assert_eq!(classify("en6", Some("Bluetooth PAN")), None);
            assert_eq!(classify("utun0", Some("Ethernet")), None);
        }

        /// The regression this module exists for: hot-plugged interfaces are
        /// candidates even though `networksetup` knows nothing about them.
        #[test]
        fn classifies_interfaces_missing_from_networksetup() {
            let ports = parse_hardware_ports(SAMPLE);
            let known = |name: &str| {
                ports
                    .iter()
                    .find(|p| p.device == name)
                    .map(|p| p.port.clone())
            };
            assert!(known("en9").is_none());
            assert_eq!(
                classify("en9", known("en9").as_deref()),
                Some(LinkKind::UsbEthernet)
            );
            assert_eq!(
                classify("en10", known("en10").as_deref()),
                Some(LinkKind::UsbEthernet)
            );
            assert_eq!(
                classify("bridge0", known("bridge0").as_deref()),
                Some(LinkKind::ThunderboltBridge)
            );
            // Wi-Fi is still excluded through its hardware port name.
            assert_eq!(classify("en1", known("en1").as_deref()), None);
        }
    }
}

/// `SIOCGIFMEDIA`: whether an interface has an actual carrier.
///
/// `IFF_UP | IFF_RUNNING` is useless on macOS — Thunderbolt ports and USB
/// Ethernet interfaces report `RUNNING` with nothing plugged in. The media
/// status is what `ifconfig` prints as `status: active` / `status: inactive`,
/// and it flips within milliseconds of the cable being pulled, which is how
/// the guest notices an unplug before its default route black-holes traffic.
#[cfg(target_os = "macos")]
mod macos_media {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use nix::libc;

    const IFM_AVALID: libc::c_int = 0x0000_0001;
    const IFM_ACTIVE: libc::c_int = 0x0000_0002;

    /// `struct ifmediareq` from `<net/if.h>`.
    ///
    /// The header wraps it in `#pragma pack(4)`, which makes it 44 bytes
    /// instead of the 48 a naturally aligned layout would give. The size is
    /// part of the ioctl request number, so getting this wrong makes every
    /// call fail with `ENOTSUP` rather than misbehave visibly.
    #[repr(C, packed(4))]
    struct IfMediaReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        current: libc::c_int,
        mask: libc::c_int,
        status: libc::c_int,
        active: libc::c_int,
        count: libc::c_int,
        ulist: *mut libc::c_int,
    }

    /// `_IOWR('i', 56, struct ifmediareq)`, computed the way `<sys/ioccom.h>`
    /// does so the struct size can never drift out of sync.
    fn siocgifmedia() -> libc::c_ulong {
        const IOC_IN: libc::c_ulong = 0x8000_0000;
        const IOC_OUT: libc::c_ulong = 0x4000_0000;
        const IOCPARM_MASK: libc::c_ulong = 0x1fff;
        let len = std::mem::size_of::<IfMediaReq>() as libc::c_ulong;
        IOC_IN | IOC_OUT | ((len & IOCPARM_MASK) << 16) | ((b'i' as libc::c_ulong) << 8) | 56
    }

    /// `true` when `name` has a carrier. `Err` when the interface does not
    /// support the media ioctl (`ENOTTY`/`EINVAL`) or does not exist.
    pub(super) fn is_active(name: &str) -> io::Result<bool> {
        if name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        // SAFETY: a plain AF_INET datagram socket; the fd is owned from here on.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, exclusively owned file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // SAFETY: `IfMediaReq` is `#[repr(C)]` and all-zero is a valid value
        // (`ulist` null, `count` 0 = "do not return the media list").
        let mut req: IfMediaReq = unsafe { std::mem::zeroed() };
        for (dst, b) in req.name.iter_mut().zip(name.as_bytes()) {
            *dst = *b as libc::c_char;
        }
        // SAFETY: `req` is a correctly sized, initialised `struct ifmediareq`
        // and `siocgifmedia()` encodes its size, so the kernel cannot write
        // out of bounds.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), siocgifmedia(), &mut req) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(req.status & IFM_AVALID != 0 && req.status & IFM_ACTIVE != 0)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn request_number_matches_the_header() {
            // `_IOWR('i', 56, struct ifmediareq)` with the header's packed
            // 44-byte layout.
            assert_eq!(std::mem::size_of::<IfMediaReq>(), 44);
            assert_eq!(siocgifmedia(), 0xc02c_6938);
        }

        #[test]
        fn loopback_has_no_media_but_does_not_crash() {
            // `lo0` does not support the ioctl; the call must fail cleanly
            // rather than panic or report a bogus carrier.
            let _ = is_active("lo0");
        }

        #[test]
        fn unknown_interface_errors() {
            assert!(is_active("en_does_not_exist").is_err());
        }
    }
}

/// `true` when `name` currently has a carrier (a cable plugged into a live
/// peer), `false` when it does not, and `Err` when the platform cannot tell.
///
/// Cheap enough to poll a few times per second, which is what the guest does
/// to notice an unplugged Type-C cable quickly.
pub fn is_link_active(name: &str) -> io::Result<bool> {
    #[cfg(target_os = "macos")]
    {
        macos_media::is_active(name)
    }
    #[cfg(target_os = "linux")]
    {
        let carrier = std::fs::read_to_string(format!("/sys/class/net/{name}/carrier"))?;
        Ok(carrier.trim() == "1")
    }
    #[cfg(windows)]
    {
        use if_addrs::IfOperStatus;
        if_addrs::get_if_addrs()?
            .into_iter()
            .find(|i| i.name == name)
            .map(|i| i.oper_status == IfOperStatus::Up)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such interface"))
    }
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
    {
        unix_state::collect()?
            .get(name)
            .map(|st| st.is_up)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such interface"))
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{macos_kind, LinkInterface};
    use std::collections::BTreeMap;
    use std::io;
    use std::process::Command;

    fn hardware_ports() -> io::Result<BTreeMap<String, String>> {
        let output = Command::new("networksetup")
            .arg("-listallhardwareports")
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "networksetup -listallhardwareports exited with {}",
                output.status
            )));
        }
        Ok(
            macos_kind::parse_hardware_ports(&String::from_utf8_lossy(&output.stdout))
                .into_iter()
                .map(|hp| (hp.device, hp.port))
                .collect(),
        )
    }

    pub(super) fn list() -> io::Result<Vec<LinkInterface>> {
        let state = super::unix_state::collect()?;
        // `getifaddrs` is the source of truth for *which* interfaces exist;
        // `networksetup` only supplies the human-facing port name used for
        // classification, so a failure here degrades the kind, not the list.
        let ports = hardware_ports().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "networksetup unavailable; classifying interfaces by name only");
            BTreeMap::new()
        });
        Ok(state
            .iter()
            .filter(|(_, st)| !st.is_loopback && st.index != 0)
            .filter_map(|(name, st)| {
                let kind = macos_kind::classify(name, ports.get(name).map(String::as_str))?;
                Some(LinkInterface {
                    name: name.clone(),
                    index: st.index,
                    // Real carrier state, not IFF_RUNNING; see `macos_media`.
                    is_up: super::macos_media::is_active(name).unwrap_or_else(|_| {
                        // Interfaces without media support (bridges on some
                        // releases): a link-local address only appears once
                        // the link is usable, so it is the best proxy.
                        st.link_local_v6.is_some()
                    }),
                    link_local_v6: st.link_local_v6,
                    kind,
                })
            })
            .collect())
    }

    /// Every physical port, unclassified, without running `networksetup`.
    pub(super) fn list_all() -> io::Result<Vec<LinkInterface>> {
        Ok(super::all_from_state(&super::unix_state::collect()?)
            .into_iter()
            .filter(|l| macos_kind::is_candidate_name(&l.name))
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Linux: interface name + sysfs driver classification
// ---------------------------------------------------------------------------

/// Linux classification rules. Platform independent (pure functions on
/// names/driver strings) so they are unit-tested on every OS.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod linux_kind {
    use super::LinkKind;

    /// Kernel drivers of USB Ethernet adapters / USB-to-Ethernet dongles.
    const USB_ETHERNET_DRIVERS: &[&str] = &[
        "cdc_ncm",
        "cdc_ether",
        "cdc_eem",
        "cdc_mbim",
        "rndis_host",
        "r8152",
        "r8153_ecm",
        "ax88179_178a",
        "asix",
        "smsc95xx",
        "smsc75xx",
        "lan78xx",
        "dm9601",
        "aqc111",
        "ipheth",
    ];

    /// Map an interface to a [`LinkKind`]; `None` = not a candidate
    /// (loopback, wireless, containers/VMs, tunnels, ...).
    ///
    /// `driver` is the last path component of
    /// `/sys/class/net/<name>/device/driver` (absent for virtual devices).
    pub(super) fn classify(name: &str, driver: Option<&str>) -> Option<LinkKind> {
        const EXCLUDED_PREFIXES: &[&str] = &[
            "lo",
            "wl",
            "ww",
            "docker",
            "veth",
            "br-",
            "virbr",
            "tun",
            "tap",
            "utun",
            "wg",
            "tailscale",
            "zt",
            "vmnet",
            "vboxnet",
            "lxc",
            "lxd",
            "podman",
            "cni",
            "flannel",
            "cali",
            "dummy",
            "bond",
            "sit",
            "ip6tnl",
            "gre",
            "vxlan",
            "nlmon",
            "ifb",
            "teql",
            "netm",
        ];
        if EXCLUDED_PREFIXES.iter().any(|p| name.starts_with(p)) {
            return None;
        }
        let driver = driver.map(|d| d.to_ascii_lowercase());
        if name.starts_with("thunderbolt") || driver.as_deref() == Some("thunderbolt-net") {
            return Some(LinkKind::Thunderbolt);
        }
        if let Some(d) = driver.as_deref() {
            if USB_ETHERNET_DRIVERS.contains(&d) {
                return Some(LinkKind::UsbEthernet);
            }
        }
        if name.starts_with("usb") || name.starts_with("enx") {
            return Some(LinkKind::UsbEthernet);
        }
        Some(LinkKind::Other)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn classifies_linux_interfaces() {
            assert_eq!(
                classify("thunderbolt0", Some("thunderbolt-net")),
                Some(LinkKind::Thunderbolt)
            );
            assert_eq!(classify("thunderbolt0", None), Some(LinkKind::Thunderbolt));
            assert_eq!(
                classify("enp0s13f0u1", Some("thunderbolt-net")),
                Some(LinkKind::Thunderbolt)
            );
            assert_eq!(
                classify("enp0s20f0u2", Some("cdc_ncm")),
                Some(LinkKind::UsbEthernet)
            );
            assert_eq!(classify("eth1", Some("r8152")), Some(LinkKind::UsbEthernet));
            assert_eq!(
                classify("enx00e04c680001", None),
                Some(LinkKind::UsbEthernet)
            );
            assert_eq!(classify("usb0", None), Some(LinkKind::UsbEthernet));
            assert_eq!(classify("eth0", Some("e1000e")), Some(LinkKind::Other));
            assert_eq!(classify("enp3s0", None), Some(LinkKind::Other));
            assert_eq!(classify("lo", None), None);
            assert_eq!(classify("wlp2s0", Some("iwlwifi")), None);
            assert_eq!(classify("docker0", None), None);
            assert_eq!(classify("veth1a2b3c", None), None);
            assert_eq!(classify("tun0", None), None);
            assert_eq!(classify("tap0", None), None);
            assert_eq!(classify("br-1234", None), None);
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{linux_kind, LinkInterface};
    use std::io;
    use std::path::Path;

    /// Last component of `/sys/class/net/<name>/device/driver` (a symlink
    /// into `/sys/bus/*/drivers/<driver>`), if any.
    fn driver_of(name: &str) -> Option<String> {
        let link = Path::new("/sys/class/net").join(name).join("device/driver");
        std::fs::read_link(link)
            .ok()?
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
    }

    pub(super) fn list() -> io::Result<Vec<LinkInterface>> {
        let state = super::unix_state::collect()?;
        Ok(state
            .iter()
            .filter(|(_, st)| !st.is_loopback && st.index != 0)
            .filter_map(|(name, st)| {
                let driver = driver_of(name);
                let kind = linux_kind::classify(name, driver.as_deref())?;
                Some(LinkInterface {
                    name: name.clone(),
                    index: st.index,
                    is_up: st.is_up,
                    link_local_v6: st.link_local_v6,
                    kind,
                })
            })
            .collect())
    }

    pub(super) fn list_all() -> io::Result<Vec<LinkInterface>> {
        Ok(super::all_from_state(&super::unix_state::collect()?))
    }
}

// ---------------------------------------------------------------------------
// Generic Unix fallback (*BSD)
// ---------------------------------------------------------------------------

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
mod platform {
    use super::LinkInterface;
    use std::io;

    pub(super) fn list() -> io::Result<Vec<LinkInterface>> {
        let state = super::unix_state::collect()?;
        Ok(super::generic_from_state(&state))
    }

    pub(super) fn list_all() -> io::Result<Vec<LinkInterface>> {
        Ok(super::all_from_state(&super::unix_state::collect()?))
    }
}

/// Every non-loopback, multicast-capable interface with a valid index, as
/// [`LinkKind::Other`] (see [`list_all_interfaces`]).
#[cfg(unix)]
fn all_from_state(state: &std::collections::BTreeMap<String, IfState>) -> Vec<LinkInterface> {
    state
        .iter()
        .filter(|(_, st)| !st.is_loopback && st.is_multicast && st.index != 0)
        .map(|(name, st)| LinkInterface {
            name: name.clone(),
            index: st.index,
            is_up: st.is_up,
            link_local_v6: st.link_local_v6,
            kind: LinkKind::Other,
        })
        .collect()
}

/// Fallback used where no hardware-port information exists: every up,
/// non-loopback interface that has a link-local IPv6 address, as `Other`.
#[cfg(unix)]
#[cfg_attr(any(target_os = "linux", target_os = "macos"), allow(dead_code))]
fn generic_from_state(state: &std::collections::BTreeMap<String, IfState>) -> Vec<LinkInterface> {
    state
        .iter()
        .filter(|(_, st)| {
            !st.is_loopback && st.is_up && st.link_local_v6.is_some() && st.index != 0
        })
        .map(|(name, st)| LinkInterface {
            name: name.clone(),
            index: st.index,
            is_up: st.is_up,
            link_local_v6: st.link_local_v6,
            kind: LinkKind::Other,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Windows (if-addrs + friendly-name heuristics)
// ---------------------------------------------------------------------------

/// Windows classification rules. Platform independent so they are
/// unit-tested on every OS.
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_kind {
    use super::LinkKind;

    /// Map a connection's friendly name (`Ethernet 2`, `Wi-Fi`, ...) to a
    /// [`LinkKind`]; `None` = not a candidate. `is_p2p` is if-addrs' flag for
    /// tunnel-type interfaces (VPNs, our own Wintun adapter).
    ///
    /// The adapter *description* (where "Thunderbolt(TM) Networking" would
    /// show up) is not available through if-addrs, so most wired adapters
    /// end up as [`LinkKind::Other`].
    pub(super) fn classify(friendly_name: &str, is_p2p: bool) -> Option<LinkKind> {
        if is_p2p {
            return None;
        }
        let lower = friendly_name.to_ascii_lowercase();
        const EXCLUDED: &[&str] = &[
            "loopback",
            "wi-fi",
            "wifi",
            "wlan",
            "wireless",
            "bluetooth",
            "vethernet",
            "vmware",
            "virtualbox",
            "hyper-v",
            "tailscale",
            "wireguard",
            "openvpn",
            "teredo",
            "isatap",
            "netm",
        ];
        if EXCLUDED.iter().any(|e| lower.contains(e)) {
            return None;
        }
        if lower.contains("thunderbolt") {
            return Some(LinkKind::Thunderbolt);
        }
        if lower.contains("usb") {
            return Some(LinkKind::UsbEthernet);
        }
        Some(LinkKind::Other)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn classifies_windows_interfaces() {
            assert_eq!(
                classify("Thunderbolt Ethernet", false),
                Some(LinkKind::Thunderbolt)
            );
            assert_eq!(classify("USB Ethernet", false), Some(LinkKind::UsbEthernet));
            assert_eq!(classify("Ethernet 2", false), Some(LinkKind::Other));
            assert_eq!(classify("Ethernet 2", true), None);
            assert_eq!(classify("Wi-Fi", false), None);
            assert_eq!(classify("WLAN", false), None);
            assert_eq!(classify("Bluetooth Network Connection", false), None);
            assert_eq!(classify("vEthernet (WSL)", false), None);
            assert_eq!(classify("Loopback Pseudo-Interface 1", false), None);
            assert_eq!(classify("NetM", false), None);
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{windows_kind, LinkInterface};
    use std::collections::BTreeMap;
    use std::io;

    use if_addrs::{IfAddr, IfOperStatus};

    pub(super) fn list() -> io::Result<Vec<LinkInterface>> {
        let mut map: BTreeMap<String, LinkInterface> = BTreeMap::new();
        for iface in if_addrs::get_if_addrs()? {
            if iface.is_loopback() {
                continue;
            }
            let Some(index) = iface.index else { continue };
            let Some(kind) = windows_kind::classify(&iface.name, iface.is_p2p) else {
                continue;
            };
            let entry = map
                .entry(iface.name.clone())
                .or_insert_with(|| LinkInterface {
                    name: iface.name.clone(),
                    index,
                    is_up: iface.oper_status == IfOperStatus::Up,
                    link_local_v6: None,
                    kind,
                });
            if let IfAddr::V6(v6) = &iface.addr {
                if v6.ip.is_unicast_link_local() && entry.link_local_v6.is_none() {
                    entry.link_local_v6 = Some(v6.ip);
                }
            }
        }
        // Down adapters are kept (like on macOS) so the UI can show them
        // while waiting for a cable; `is_ready` gates their use.
        Ok(map.into_values().collect())
    }

    pub(super) fn list_all() -> io::Result<Vec<LinkInterface>> {
        let mut map: BTreeMap<String, LinkInterface> = BTreeMap::new();
        for iface in if_addrs::get_if_addrs()? {
            if iface.is_loopback() {
                continue;
            }
            let Some(index) = iface.index else { continue };
            let entry = map
                .entry(iface.name.clone())
                .or_insert_with(|| LinkInterface {
                    name: iface.name.clone(),
                    index,
                    is_up: iface.oper_status == IfOperStatus::Up,
                    link_local_v6: None,
                    kind: super::LinkKind::Other,
                });
            if let IfAddr::V6(v6) = &iface.addr {
                if v6.ip.is_unicast_link_local() && entry.link_local_v6.is_none() {
                    entry.link_local_v6 = Some(v6.ip);
                }
            }
        }
        Ok(map.into_values().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_order_bridge_first() {
        assert!(LinkKind::ThunderboltBridge < LinkKind::Thunderbolt);
        assert!(LinkKind::Thunderbolt < LinkKind::UsbEthernet);
        assert!(LinkKind::UsbEthernet < LinkKind::Other);
    }

    #[test]
    fn list_does_not_fail() {
        // Cannot assert contents (depends on the machine) but it must not error
        // and must be sorted by kind.
        let list = list_candidate_interfaces().expect("interface enumeration");
        for w in list.windows(2) {
            assert!(w[0].kind <= w[1].kind);
        }
        for l in &list {
            assert!(!l.name.is_empty());
        }
    }

    #[test]
    fn list_all_is_a_superset_of_candidates() {
        let all = list_all_interfaces().expect("interface enumeration");
        for w in all.windows(2) {
            assert!(w[0].name < w[1].name, "sorted by name, no duplicates");
        }
        for l in &all {
            assert_ne!(l.index, 0);
            assert_eq!(l.kind, LinkKind::Other);
        }
        // Every candidate the kernel knows (index != 0) must also be in the
        // unclassified list, otherwise the responder could miss a join.
        for c in list_candidate_interfaces().unwrap() {
            if c.index != 0 {
                assert!(
                    all.iter().any(|a| a.index == c.index),
                    "candidate {} (index {}) missing from list_all_interfaces",
                    c.name,
                    c.index
                );
            }
        }
    }
}
