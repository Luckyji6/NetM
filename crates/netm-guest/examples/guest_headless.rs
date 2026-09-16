//! Headless guest: runs `netm_guest::run` and logs every event.
//!
//! Needs root (creates a utun and changes routes):
//!
//! ```text
//! sudo -E cargo run -p netm-guest --example guest_headless -- --route 1.1.1.1/32
//! sudo -E cargo run -p netm-guest --example guest_headless -- --host '[fe80::1%bridge0]:27778' --no-dns
//! ```
//!
//! Ctrl-C / SIGTERM / SIGHUP trigger a clean shutdown (routes, DNS and the
//! TUN device are removed before the process exits).

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use netm_guest::{GuestCommand, GuestConfig, GuestEvent, GuestState, HostTarget, RouteMode};
use tokio::sync::{mpsc, watch};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "guest_headless", about = "NetM guest without a UI")]
struct Args {
    /// Only route these IPv4 prefixes through the tunnel (repeatable). Without
    /// it everything (0.0.0.0/1 + 128.0.0.0/1) goes through the tunnel.
    #[arg(long = "route", value_name = "CIDR")]
    routes: Vec<ipnet::Ipv4Net>,

    /// Connect to this host address instead of discovering it. Link-local
    /// IPv6 needs a scope: `[fe80::1%bridge0]:27778` or `[fe80::1%20]:27778`.
    #[arg(long, value_name = "ADDR", value_parser = parse_host)]
    host: Option<SocketAddr>,

    /// Leave the system DNS untouched.
    #[arg(long)]
    no_dns: bool,

    /// Set the tunnel DNS even in --route mode (default: only in full mode).
    #[arg(long, conflicts_with = "no_dns")]
    dns: bool,

    /// Exit after the first disconnect instead of waiting for the link again.
    #[arg(long)]
    no_reconnect: bool,

    /// Name announced to the host (default: hostname).
    #[arg(long)]
    name: Option<String>,
}

/// Accept `%ifname` scopes in addition to numeric ones.
fn parse_host(s: &str) -> Result<SocketAddr, String> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    // `[fe80::1%bridge0]:27778` → resolve the interface name to an index.
    let (Some(start), Some(pct), Some(end)) = (s.find('['), s.find('%'), s.find(']')) else {
        return Err(format!("invalid socket address `{s}`"));
    };
    if !(start < pct && pct < end) {
        return Err(format!("invalid socket address `{s}`"));
    }
    let ifname = &s[pct + 1..end];
    let index = netm_proto::list_candidate_interfaces()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|i| i.name == ifname)
        .map(|i| i.index)
        .ok_or_else(|| format!("unknown interface `{ifname}`"))?;
    let rebuilt = format!("{}%{}{}", &s[..pct], index, &s[end..]);
    rebuilt
        .parse::<SocketAddr>()
        .map_err(|e| format!("invalid socket address `{s}`: {e}"))
}

fn fmt_bps(bps: f64) -> String {
    if bps >= 1e9 {
        format!("{:.2} Gbit/s", bps / 1e9)
    } else if bps >= 1e6 {
        format!("{:.2} Mbit/s", bps / 1e6)
    } else if bps >= 1e3 {
        format!("{:.1} kbit/s", bps / 1e3)
    } else {
        format!("{bps:.0} bit/s")
    }
}

async fn wait_for_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut hup = signal(SignalKind::hangup()).expect("SIGHUP handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "SIGINT",
            _ = term.recv() => "SIGTERM",
            _ = hup.recv() => "SIGHUP",
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "Ctrl-C"
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();
    let args = Args::parse();

    let routes = if args.routes.is_empty() {
        RouteMode::Full
    } else {
        RouteMode::Custom(args.routes.clone())
    };
    let set_dns = if args.no_dns {
        false
    } else if args.dns {
        true
    } else {
        routes.default_set_dns()
    };
    let mut cfg = GuestConfig {
        host: args
            .host
            .map(HostTarget::Manual)
            .unwrap_or(HostTarget::Auto),
        routes,
        set_dns,
        reconnect: !args.no_reconnect,
        ..GuestConfig::default()
    };
    if let Some(n) = args.name {
        cfg.name = n;
    }
    if netm_guest::requires_root() && !netm_proto::privilege::is_root() {
        anyhow::bail!("this program must run as root (sudo)");
    }
    tracing::info!(?cfg, "starting guest");

    let (ev_tx, mut ev_rx) = mpsc::channel::<GuestEvent>(1024);
    let (ctrl_tx, ctrl_rx) = watch::channel(GuestCommand::Run);
    let mut guest = tokio::spawn(netm_guest::run(cfg, ev_tx, ctrl_rx));

    let logger = tokio::spawn(async move {
        let mut last_stats = std::time::Instant::now();
        while let Some(ev) = ev_rx.recv().await {
            match ev {
                GuestEvent::StateChanged(s) => match s {
                    GuestState::WaitingForLink => tracing::info!("state: waiting for Type-C link"),
                    GuestState::Discovering { iface } => tracing::info!("state: discovering host on {iface}"),
                    GuestState::Connecting { host } => tracing::info!("state: connecting to {host}"),
                    GuestState::Connected {
                        host,
                        host_name,
                        tun,
                        config,
                        ..
                    } => tracing::info!(
                        "state: CONNECTED to {host_name} ({host}) via {tun}: {}/{} gw {} dns {} mtu {}",
                        config.guest_ip,
                        config.prefix_len,
                        config.gateway_ip,
                        config.dns,
                        config.mtu
                    ),
                    GuestState::Disconnected { reason } => tracing::warn!("state: disconnected: {reason}"),
                },
                GuestEvent::Interfaces(list) => {
                    for i in list {
                        tracing::info!(
                            "iface {} ({:?}) index {} up={} link-local={}",
                            i.name,
                            i.kind,
                            i.index,
                            i.is_up,
                            i.link_local_v6.map(|a| a.to_string()).unwrap_or_else(|| "-".into())
                        );
                    }
                }
                GuestEvent::Stats {
                    counters,
                    tx_bps,
                    rx_bps,
                } => {
                    // Stats arrive every 500 ms; print once per 2 s (and whenever traffic flows).
                    if last_stats.elapsed() >= Duration::from_secs(2) && (tx_bps > 0.0 || rx_bps > 0.0) {
                        last_stats = std::time::Instant::now();
                        tracing::info!(
                            "stats: tx {} ({} pkts, {} B) rx {} ({} pkts, {} B)",
                            fmt_bps(tx_bps),
                            counters.tx_packets,
                            counters.tx_bytes,
                            fmt_bps(rx_bps),
                            counters.rx_packets,
                            counters.rx_bytes
                        );
                    }
                }
                GuestEvent::Log(m) => tracing::info!("{m}"),
                GuestEvent::Error(m) => tracing::error!("{m}"),
            }
        }
    });

    tokio::select! {
        sig = wait_for_signal() => {
            tracing::info!("received {sig}; shutting down");
            let _ = ctrl_tx.send(GuestCommand::Shutdown);
            match tokio::time::timeout(Duration::from_secs(10), &mut guest).await {
                Ok(res) => res.context("guest task")??,
                Err(_) => tracing::error!("guest did not stop within 10 s"),
            }
        }
        res = &mut guest => {
            res.context("guest task")??;
            tracing::info!("guest finished");
        }
    }
    drop(ctrl_tx);
    let _ = tokio::time::timeout(Duration::from_secs(1), logger).await;
    Ok(())
}
