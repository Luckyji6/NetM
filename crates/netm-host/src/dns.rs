//! DNS upstream discovery and forwarding.
//!
//! The guest is told to use the tunnel gateway (`10.77.0.1`) as its DNS
//! server. Queries addressed to `<dns>:53` are not terminated by the
//! user-space stack like other flows; instead they are relayed to the host's
//! real resolvers:
//!
//! - Explicit upstreams from [`crate::HostConfig::dns_upstreams`], or
//! - the system resolvers, read at start-up and refreshed every 30 s
//!   ([`REFRESH_INTERVAL`]). On Unix `/etc/resolv.conf` is parsed; macOS
//!   additionally falls back to `scutil --dns`; Windows parses
//!   `ipconfig /all`.
//!
//! UDP queries are tried against the upstreams in order with a per-upstream
//! timeout of [`UDP_QUERY_TIMEOUT`]; TCP queries are proxied to the first
//! upstream that accepts a connection.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::net::{TcpStream, UdpSocket};

/// Standard DNS port.
pub const DNS_PORT: u16 = 53;

/// How often the system resolver list is re-read.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Per-upstream wait for a UDP answer before trying the next one.
pub const UDP_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Per-upstream TCP connect timeout.
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Public resolvers used only when no system resolver can be found.
pub const FALLBACK_UPSTREAMS: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), DNS_PORT),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), DNS_PORT),
];

/// Shared, refreshable list of upstream resolvers.
#[derive(Clone, Debug)]
pub struct Upstreams {
    inner: Arc<RwLock<Vec<SocketAddr>>>,
    /// Addresses that must never be used as upstream (the tunnel's own DNS /
    /// gateway address, which would loop back into this forwarder).
    excluded: Arc<Vec<IpAddr>>,
    fixed: bool,
}

impl Upstreams {
    /// Fixed list supplied by configuration (never refreshed).
    pub fn fixed(list: Vec<SocketAddr>, excluded: Vec<IpAddr>) -> Self {
        let s = Self {
            inner: Arc::new(RwLock::new(Vec::new())),
            excluded: Arc::new(excluded),
            fixed: true,
        };
        s.set(list);
        s
    }

    /// Read the system resolvers now; call [`refresh`](Self::refresh)
    /// periodically to pick up changes.
    pub fn from_system(excluded: Vec<IpAddr>) -> Self {
        let s = Self {
            inner: Arc::new(RwLock::new(Vec::new())),
            excluded: Arc::new(excluded),
            fixed: false,
        };
        s.refresh();
        s
    }

    /// Whether the list is fixed (no refresh needed).
    pub fn is_fixed(&self) -> bool {
        self.fixed
    }

    /// Current snapshot.
    pub fn get(&self) -> Vec<SocketAddr> {
        self.inner.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Re-read the system resolvers (no-op for fixed lists). Returns `true`
    /// if the list changed.
    pub fn refresh(&self) -> bool {
        if self.fixed {
            return false;
        }
        let list = system_resolvers();
        self.set(list)
    }

    fn set(&self, list: Vec<SocketAddr>) -> bool {
        let mut list: Vec<SocketAddr> = list
            .into_iter()
            .filter(|a| !self.excluded.contains(&a.ip()))
            .collect();
        dedup(&mut list);
        if list.is_empty() {
            tracing::warn!("no usable system DNS resolvers found; using public fallback resolvers");
            list = FALLBACK_UPSTREAMS.to_vec();
        }
        let mut guard = self.inner.write().unwrap_or_else(|p| p.into_inner());
        if *guard == list {
            return false;
        }
        tracing::info!(upstreams = ?list, "DNS upstreams updated");
        *guard = list;
        true
    }
}

fn dedup(list: &mut Vec<SocketAddr>) {
    let mut seen = Vec::with_capacity(list.len());
    list.retain(|a| {
        if seen.contains(a) {
            false
        } else {
            seen.push(*a);
            true
        }
    });
}

/// Parse a nameserver token such as `8.8.8.8`, `fe80::1%en0`, `[::1]:5353`
/// or `1.1.1.1:5353` into a socket address (default port 53).
pub fn parse_nameserver(token: &str) -> Option<SocketAddr> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if let Ok(sa) = token.parse::<SocketAddr>() {
        return Some(sa);
    }
    // `[v6]` without port, or `v6%scope`.
    let (host, scope) = match token.split_once('%') {
        Some((h, s)) => (h, Some(s)),
        None => (token, None),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Some(SocketAddr::new(IpAddr::V4(v4), DNS_PORT));
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        let scope_id = scope.and_then(scope_to_index).unwrap_or(0);
        return Some(SocketAddr::V6(std::net::SocketAddrV6::new(
            v6, DNS_PORT, 0, scope_id,
        )));
    }
    // Some formats put the port after a `#` (dnsmasq / resolvectl style).
    if let Some((h, p)) = token.split_once('#') {
        if let (Ok(ip), Ok(port)) = (h.parse::<IpAddr>(), p.parse::<u16>()) {
            return Some(SocketAddr::new(ip, port));
        }
    }
    None
}

fn scope_to_index(scope: &str) -> Option<u32> {
    if let Ok(n) = scope.parse::<u32>() {
        return Some(n);
    }
    #[cfg(unix)]
    {
        if let Ok(idx) = nix::net::if_::if_nametoindex(scope) {
            return Some(idx);
        }
    }
    None
}

/// Parse `/etc/resolv.conf` content: every `nameserver` directive, in order.
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.split(['#', ';']).next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        if let Some(sa) = parts.next().and_then(parse_nameserver) {
            out.push(sa);
        }
    }
    dedup(&mut out);
    out
}

/// Parse `scutil --dns` output (macOS). Only the unscoped resolvers of the
/// first "DNS configuration" section are used, in resolver order; entries
/// carrying a `port` line honour that port.
pub fn parse_scutil_dns(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut in_first_section = false;
    let mut in_resolver = false;
    let mut current: Vec<SocketAddr> = Vec::new();
    let mut port: Option<u16> = None;

    let flush =
        |current: &mut Vec<SocketAddr>, port: &mut Option<u16>, out: &mut Vec<SocketAddr>| {
            if let Some(p) = port.take() {
                for a in current.iter_mut() {
                    a.set_port(p);
                }
            }
            out.append(current);
        };

    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("DNS configuration") {
            if in_first_section {
                // Second section = scoped queries; stop here.
                break;
            }
            in_first_section = true;
            continue;
        }
        if !in_first_section {
            continue;
        }
        if line.starts_with("resolver #") {
            flush(&mut current, &mut port, &mut out);
            in_resolver = true;
            continue;
        }
        if !in_resolver {
            continue;
        }
        if let Some(rest) = line.strip_prefix("nameserver[") {
            if let Some((_, value)) = rest.split_once(':') {
                if let Some(sa) = parse_nameserver(value) {
                    current.push(sa);
                }
            }
        } else if let Some(rest) = line.strip_prefix("port") {
            if let Some((_, value)) = rest.split_once(':') {
                port = value.trim().parse().ok();
            }
        }
    }
    flush(&mut current, &mut port, &mut out);
    dedup(&mut out);
    out
}

/// Parse `ipconfig /all` output (Windows): `DNS Servers . . . : a.b.c.d`
/// followed by continuation lines holding only an address.
pub fn parse_ipconfig_all(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut in_dns = false;
    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            in_dns = false;
            continue;
        }
        // Continuation line: just an address.
        if in_dns {
            if let Some(sa) = parse_nameserver(trimmed) {
                out.push(sa);
                continue;
            }
        }
        in_dns = false;
        // `DNS Servers . . . . : <addr>` (any locale that keeps the English key).
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim_end_matches(['.', ' ']).trim();
        if key.eq_ignore_ascii_case("DNS Servers") || key.eq_ignore_ascii_case("DNS-Server") {
            in_dns = true;
            if let Some(sa) = parse_nameserver(value) {
                out.push(sa);
            }
        }
    }
    dedup(&mut out);
    out
}

/// Read the system resolvers using the platform's mechanism.
pub fn system_resolvers() -> Vec<SocketAddr> {
    #[cfg(windows)]
    {
        return windows_resolvers();
    }
    #[cfg(not(windows))]
    {
        let list = std::fs::read_to_string("/etc/resolv.conf")
            .map(|t| parse_resolv_conf(&t))
            .unwrap_or_default();
        #[cfg(target_os = "macos")]
        let list = if list.is_empty() {
            macos_scutil_resolvers()
        } else {
            list
        };
        list
    }
}

#[cfg(target_os = "macos")]
fn macos_scutil_resolvers() -> Vec<SocketAddr> {
    match std::process::Command::new("scutil").arg("--dns").output() {
        Ok(o) if o.status.success() => parse_scutil_dns(&String::from_utf8_lossy(&o.stdout)),
        Ok(o) => {
            tracing::debug!(status = %o.status, "scutil --dns failed");
            Vec::new()
        }
        Err(e) => {
            tracing::debug!(error = %e, "scutil not available");
            Vec::new()
        }
    }
}

#[cfg(windows)]
fn windows_resolvers() -> Vec<SocketAddr> {
    match std::process::Command::new("ipconfig").arg("/all").output() {
        Ok(o) if o.status.success() => parse_ipconfig_all(&String::from_utf8_lossy(&o.stdout)),
        Ok(o) => {
            tracing::debug!(status = %o.status, "ipconfig /all failed");
            Vec::new()
        }
        Err(e) => {
            tracing::debug!(error = %e, "ipconfig not available");
            Vec::new()
        }
    }
}

/// Send one UDP DNS query to the upstreams in order, returning the first
/// answer. Each upstream gets [`UDP_QUERY_TIMEOUT`].
pub async fn query_udp(query: &[u8], upstreams: &[SocketAddr]) -> io::Result<Vec<u8>> {
    if upstreams.is_empty() {
        return Err(io::Error::other("no DNS upstreams configured"));
    }
    let mut last_err = io::Error::new(io::ErrorKind::TimedOut, "all DNS upstreams timed out");
    for &up in upstreams {
        match query_udp_one(query, up).await {
            Ok(answer) => return Ok(answer),
            Err(e) => {
                tracing::debug!(upstream = %up, error = %e, "DNS upstream failed, trying next");
                last_err = e;
            }
        }
    }
    Err(last_err)
}

async fn query_udp_one(query: &[u8], upstream: SocketAddr) -> io::Result<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(upstream).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(UDP_QUERY_TIMEOUT, sock.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS upstream timed out"))??;
    buf.truncate(n);
    Ok(buf)
}

/// Connect to the first upstream that accepts a TCP connection.
pub async fn connect_tcp(upstreams: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last_err = io::Error::other("no DNS upstreams configured");
    for &up in upstreams {
        match tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(up)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last_err = e,
            Err(_) => {
                last_err = io::Error::new(io::ErrorKind::TimedOut, "DNS TCP connect timed out")
            }
        }
        tracing::debug!(upstream = %up, error = %last_err, "DNS TCP upstream failed, trying next");
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resolv_conf() {
        let text = "\
# Generated by configd
search example.com
nameserver 192.168.1.1
nameserver 192.168.1.1   # duplicate
nameserver fe80::1%1
nameserver 2606:4700:4700::1111
options ndots:1
nameserver 10.0.0.1:5353
";
        let list = parse_resolv_conf(text);
        assert_eq!(
            list,
            vec![
                "192.168.1.1:53".parse().unwrap(),
                "[fe80::1%1]:53".parse().unwrap(),
                "[2606:4700:4700::1111]:53".parse().unwrap(),
                "10.0.0.1:5353".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn parses_scutil_dns() {
        let text = "\
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.50.1
  nameserver[1] : 1.1.1.1
  if_index : 12 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

resolver #3
  nameserver[0] : 127.0.0.1
  port     : 5300

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 9.9.9.9
  if_index : 12 (en0)
";
        let list = parse_scutil_dns(text);
        assert_eq!(
            list,
            vec![
                "192.168.50.1:53".parse().unwrap(),
                "1.1.1.1:53".parse().unwrap(),
                "127.0.0.1:5300".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn parses_ipconfig_all() {
        let text = "\
Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP
   Primary Dns Suffix  . . . . . . . :

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : lan
   IPv4 Address. . . . . . . . . . . : 192.168.1.20(Preferred)
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled

Wireless LAN adapter Wi-Fi:

   DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1
                                       1.0.0.1
";
        let list = parse_ipconfig_all(text);
        assert_eq!(
            list,
            vec![
                "192.168.1.1:53".parse().unwrap(),
                "8.8.8.8:53".parse().unwrap(),
                "[fec0:0:0:ffff::1%1]:53".parse().unwrap(),
                "1.0.0.1:53".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn excluded_and_fallback() {
        let gw: IpAddr = "10.77.0.1".parse().unwrap();
        let u = Upstreams::fixed(vec![SocketAddr::new(gw, 53)], vec![gw]);
        assert_eq!(u.get(), FALLBACK_UPSTREAMS.to_vec());
        let u = Upstreams::fixed(
            vec!["1.1.1.1:53".parse().unwrap(), SocketAddr::new(gw, 53)],
            vec![gw],
        );
        assert_eq!(u.get(), vec!["1.1.1.1:53".parse().unwrap()]);
        assert!(u.is_fixed());
        assert!(!u.refresh());
    }

    #[tokio::test]
    async fn udp_query_falls_back_to_next_upstream() {
        // First upstream never answers; second echoes.
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let live = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = live.recv_from(&mut buf).await.unwrap();
            live.send_to(&buf[..n], from).await.unwrap();
        });
        let ups = vec![dead.local_addr().unwrap(), live_addr];
        let start = std::time::Instant::now();
        let ans = query_udp(b"hello", &ups).await.unwrap();
        assert_eq!(ans, b"hello");
        assert!(start.elapsed() >= UDP_QUERY_TIMEOUT);
    }
}
