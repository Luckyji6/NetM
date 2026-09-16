//! Enumeration of physical link candidates (Thunderbolt bridge, Thunderbolt
//! ports, USB Ethernet adapters) the tunnel can run over.
//!
//! On macOS the hardware-port → device mapping comes from
//! `networksetup -listallhardwareports`, and `getifaddrs(3)` supplies the
//! up/running flags plus the `fe80::` link-local address.
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
    /// `IFF_UP && IFF_RUNNING`. **macOS quirk:** Thunderbolt ports report
    /// `RUNNING` even without a cable; treat `link_local_v6.is_some()` as the
    /// real "cable connected" signal and confirm with a discovery probe.
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

#[cfg(target_os = "macos")]
mod platform {
    use super::{IfState, LinkInterface, LinkKind};
    use std::collections::BTreeMap;
    use std::io;
    use std::process::Command;

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

    /// Map a hardware-port name to a [`LinkKind`]; `None` = not a candidate
    /// (Wi-Fi, Bluetooth PAN, ...).
    pub(super) fn classify(port: &str, device: &str) -> Option<LinkKind> {
        let lower = port.to_ascii_lowercase();
        if lower == "thunderbolt bridge"
            || (lower.contains("thunderbolt") && device.starts_with("bridge"))
        {
            return Some(LinkKind::ThunderboltBridge);
        }
        if lower.starts_with("thunderbolt") {
            return Some(LinkKind::Thunderbolt);
        }
        if lower.contains("usb") || lower.contains("ethernet adapter") {
            return Some(LinkKind::UsbEthernet);
        }
        if lower.contains("wi-fi")
            || lower.contains("wifi")
            || lower.contains("airport")
            || lower.contains("bluetooth")
            || device.starts_with("lo")
            || device.starts_with("utun")
            || device.starts_with("awdl")
            || device.starts_with("llw")
        {
            return None;
        }
        Some(LinkKind::Other)
    }

    fn hardware_ports() -> io::Result<Vec<HardwarePort>> {
        let output = Command::new("networksetup")
            .arg("-listallhardwareports")
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "networksetup -listallhardwareports exited with {}",
                output.status
            )));
        }
        Ok(parse_hardware_ports(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }

    pub(super) fn list() -> io::Result<Vec<LinkInterface>> {
        let state = super::unix_state::collect()?;
        match hardware_ports() {
            Ok(ports) => Ok(merge(ports, &state)),
            Err(e) => {
                tracing::warn!(error = %e, "networksetup unavailable; falling back to generic interface listing");
                Ok(super::generic_from_state(&state))
            }
        }
    }

    fn merge(ports: Vec<HardwarePort>, state: &BTreeMap<String, IfState>) -> Vec<LinkInterface> {
        let mut out = Vec::new();
        for hp in ports {
            let Some(kind) = classify(&hp.port, &hp.device) else {
                continue;
            };
            // Interfaces listed by networksetup but absent from getifaddrs
            // (e.g. bridge0 while the Thunderbolt Bridge service is disabled)
            // are reported as down with index 0 so the UI can still show them.
            let st = state.get(&hp.device).cloned().unwrap_or_default();
            if st.is_loopback {
                continue;
            }
            out.push(LinkInterface {
                name: hp.device,
                index: st.index,
                is_up: st.is_up,
                link_local_v6: st.link_local_v6,
                kind,
            });
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const SAMPLE: &str = "\
Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: c6:cf:36:60:31:6a

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 36:40:d9:d4:d1:80

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: ac:07:75:32:e2:7c

Hardware Port: Thunderbolt 1
Device: en1
Ethernet Address: 36:40:d9:d4:d1:80

Hardware Port: USB 10/100/1000 LAN
Device: en7
Ethernet Address: 00:e0:4c:68:00:01

VLAN Configurations
===================
";

        #[test]
        fn parses_networksetup_output() {
            let ports = parse_hardware_ports(SAMPLE);
            let names: Vec<_> = ports
                .iter()
                .map(|p| (p.port.as_str(), p.device.as_str()))
                .collect();
            assert_eq!(
                names,
                vec![
                    ("Ethernet Adapter (en4)", "en4"),
                    ("Thunderbolt Bridge", "bridge0"),
                    ("Wi-Fi", "en0"),
                    ("Thunderbolt 1", "en1"),
                    ("USB 10/100/1000 LAN", "en7"),
                ]
            );
        }

        #[test]
        fn classifies_ports() {
            assert_eq!(
                classify("Thunderbolt Bridge", "bridge0"),
                Some(LinkKind::ThunderboltBridge)
            );
            assert_eq!(
                classify("Thunderbolt 1", "en1"),
                Some(LinkKind::Thunderbolt)
            );
            assert_eq!(
                classify("Thunderbolt 4", "en3"),
                Some(LinkKind::Thunderbolt)
            );
            assert_eq!(
                classify("USB 10/100/1000 LAN", "en7"),
                Some(LinkKind::UsbEthernet)
            );
            assert_eq!(
                classify("Ethernet Adapter (en4)", "en4"),
                Some(LinkKind::UsbEthernet)
            );
            assert_eq!(classify("iPhone USB", "en8"), Some(LinkKind::UsbEthernet));
            assert_eq!(classify("Wi-Fi", "en0"), None);
            assert_eq!(classify("Bluetooth PAN", "en9"), None);
            assert_eq!(classify("Ethernet", "en10"), Some(LinkKind::Other));
        }

        #[test]
        fn merge_orders_and_filters() {
            let ports = parse_hardware_ports(SAMPLE);
            let mut state = BTreeMap::new();
            state.insert(
                "bridge0".to_string(),
                IfState {
                    index: 20,
                    is_up: true,
                    is_loopback: false,
                    link_local_v6: Some("fe80::1".parse().unwrap()),
                },
            );
            let mut list = merge(ports, &state);
            list.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.name.cmp(&b.name)));
            let kinds: Vec<_> = list.iter().map(|l| (l.name.as_str(), l.kind)).collect();
            assert_eq!(
                kinds,
                vec![
                    ("bridge0", LinkKind::ThunderboltBridge),
                    ("en1", LinkKind::Thunderbolt),
                    ("en4", LinkKind::UsbEthernet),
                    ("en7", LinkKind::UsbEthernet),
                ]
            );
            assert_eq!(list[0].index, 20);
            assert!(list[0].is_ready());
            assert!(!list[1].is_ready());
        }
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
}

/// Fallback used where no hardware-port information exists: every up,
/// non-loopback interface that has a link-local IPv6 address, as `Other`.
#[cfg(unix)]
#[cfg_attr(target_os = "linux", allow(dead_code))]
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
}
