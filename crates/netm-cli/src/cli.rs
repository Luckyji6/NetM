//! Command line definition (clap) and the translation of arguments plus
//! saved settings into `HostConfig` / `GuestConfig`.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use netm_guest::{GuestConfig, HostTarget, RouteMode};
use netm_host::{HostConfig, SerialSettings};

#[cfg(test)]
use crate::config::Mode;
use crate::config::{Config, GuestSettings, HostSettings};

/// `netm` — share the network of one computer with another over a Type-C
/// cable.
#[derive(Parser, Debug, Clone, PartialEq)]
#[command(
    name = "netm",
    version,
    about = "NetM：通过 Type-C 线把宿主机的网络共享给客机",
    long_about = None
)]
pub struct Cli {
    /// 配置文件路径（默认 ~/.config/netm/config.toml）
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// 输出更详细的日志（可重复，-vv 为 trace）
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum Command {
    /// 重新进入首次配置（选择宿主机 / 客机）
    Setup,
    /// 以宿主机（服务端）身份运行，为客机提供网络出口
    Host(HostArgs),
    /// 以客机身份运行，通过 Type-C 借用宿主机的网络（需要管理员权限）
    Guest(GuestArgs),
}

#[derive(Args, Debug, Clone, Default, PartialEq)]
pub struct HostArgs {
    /// 监听端口（默认 27778）
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,

    /// 同时在这个 USB 串口上等待客机（例如 /dev/tty.usbmodem1234）
    #[arg(long, value_name = "PATH")]
    pub serial: Option<String>,

    /// 串口波特率（默认 921600；USB CDC 通常忽略此值）
    #[arg(long, value_name = "BAUD", requires = "serial")]
    pub baud: Option<u32>,

    /// 不进入 TUI，只在 stderr 打日志，直到 Ctrl-C / SIGTERM
    #[arg(long)]
    pub headless: bool,
}

#[derive(Args, Debug, Clone, Default, PartialEq)]
pub struct GuestArgs {
    /// 只把这些 IPv4 网段走隧道（可重复），不指定则全部流量走隧道
    #[arg(long = "route", value_name = "CIDR")]
    pub routes: Vec<ipnet::Ipv4Net>,

    /// 直接连接指定宿主机地址而不自动发现，如 "[fe80::1%bridge0]:27778"
    #[arg(long, value_name = "ADDR", value_parser = parse_host, conflicts_with = "serial")]
    pub host: Option<SocketAddr>,

    /// 通过 USB 串口连接宿主机，而不是 Type-C 网络链路
    #[arg(long, value_name = "PATH", conflicts_with = "host")]
    pub serial: Option<String>,

    /// 串口波特率（默认 921600；USB CDC 通常忽略此值）
    #[arg(long, value_name = "BAUD", requires = "serial")]
    pub baud: Option<u32>,

    /// 不修改系统 DNS
    #[arg(long)]
    pub no_dns: bool,

    /// 不进入 TUI，只在 stderr 打日志，直到 Ctrl-C / SIGTERM
    #[arg(long)]
    pub headless: bool,
}

impl Cli {
    /// Parse `std::env::args`.
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Mode fixed by the subcommand, if any.
    #[cfg(test)]
    pub fn fixed_mode(&self) -> Option<Mode> {
        match &self.command {
            Some(Command::Host(_)) => Some(Mode::Host),
            Some(Command::Guest(_)) => Some(Mode::Guest),
            _ => None,
        }
    }

    pub fn host_args(&self) -> HostArgs {
        match &self.command {
            Some(Command::Host(a)) => a.clone(),
            _ => HostArgs::default(),
        }
    }

    pub fn guest_args(&self) -> GuestArgs {
        match &self.command {
            Some(Command::Guest(a)) => a.clone(),
            _ => GuestArgs::default(),
        }
    }

    pub fn headless(&self) -> bool {
        match &self.command {
            Some(Command::Host(a)) => a.headless,
            Some(Command::Guest(a)) => a.headless,
            _ => false,
        }
    }

    /// Arguments for re-executing this program in guest mode (under `sudo`).
    /// Global options are kept; the subcommand is normalised to `guest`.
    pub fn reexec_guest_args(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(c) = &self.config {
            out.push("--config".into());
            out.push(c.display().to_string());
        }
        for _ in 0..self.verbose {
            out.push("-v".into());
        }
        out.push("guest".into());
        let g = self.guest_args();
        for r in &g.routes {
            out.push("--route".into());
            out.push(r.to_string());
        }
        if let Some(h) = g.host {
            out.push("--host".into());
            out.push(h.to_string());
        }
        if let Some(path) = g.serial {
            out.push("--serial".into());
            out.push(path);
        }
        if let Some(baud) = g.baud {
            out.push("--baud".into());
            out.push(baud.to_string());
        }
        if g.no_dns {
            out.push("--no-dns".into());
        }
        if g.headless {
            out.push("--headless".into());
        }
        out
    }
}

/// Accept `%ifname` scopes in addition to numeric ones:
/// `[fe80::1%bridge0]:27778` → `[fe80::1%20]:27778`.
pub fn parse_host(s: &str) -> Result<SocketAddr, String> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
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

/// Combine CLI routes with the saved ones: CLI wins when given, otherwise the
/// config's list; empty → [`RouteMode::Full`].
pub fn route_mode(cli_routes: &[ipnet::Ipv4Net], saved: &GuestSettings) -> Result<RouteMode> {
    if !cli_routes.is_empty() {
        return Ok(RouteMode::Custom(cli_routes.to_vec()));
    }
    if saved.routes.is_empty() {
        return Ok(RouteMode::Full);
    }
    let mut nets = Vec::with_capacity(saved.routes.len());
    for r in &saved.routes {
        let net: ipnet::Ipv4Net = r
            .parse()
            .with_context(|| format!("invalid route `{r}` in config.toml [guest].routes"))?;
        nets.push(net);
    }
    Ok(RouteMode::Custom(nets))
}

/// `set_dns`: `--no-dns` → false; else the saved override; else the route
/// mode's recommendation.
pub fn set_dns(no_dns: bool, saved: &GuestSettings, routes: &RouteMode) -> bool {
    if no_dns {
        false
    } else {
        saved.set_dns.unwrap_or_else(|| routes.default_set_dns())
    }
}

/// Build the guest configuration from arguments and saved settings.
pub fn build_guest_config(args: &GuestArgs, cfg: &Config) -> Result<GuestConfig> {
    let routes = route_mode(&args.routes, &cfg.guest)?;
    if let RouteMode::Custom(nets) = &routes {
        if nets.is_empty() {
            bail!("route list is empty");
        }
    }
    let dns = set_dns(args.no_dns, &cfg.guest, &routes);
    let host = if let Some(path) = &args.serial {
        HostTarget::Serial {
            path: path.clone(),
            baud: args.baud.unwrap_or(cfg.guest.baud),
        }
    } else if let Some(addr) = args.host {
        HostTarget::Manual(addr)
    } else if let Some(path) = &cfg.guest.serial {
        HostTarget::Serial {
            path: path.clone(),
            baud: cfg.guest.baud,
        }
    } else {
        HostTarget::Auto
    };
    Ok(GuestConfig {
        host,
        routes,
        set_dns: dns,
        reconnect: true,
        ..GuestConfig::default()
    })
}

/// Build the host configuration: `--port` beats `[host].port`.
pub fn build_host_config(args: &HostArgs, saved: &HostSettings) -> HostConfig {
    let port = args.port.unwrap_or(saved.port);
    let mut cfg = HostConfig::default().with_port(port);
    if let Some(path) = args.serial.as_ref().or(saved.serial.as_ref()) {
        cfg.serial = Some(SerialSettings {
            path: path.clone(),
            baud: args.baud.unwrap_or(saved.baud),
        });
    }
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("netm").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn no_args_means_tui_flow() {
        let cli = parse(&[]);
        assert_eq!(cli.command, None);
        assert_eq!(cli.fixed_mode(), None);
        assert!(!cli.headless());
    }

    #[test]
    fn setup_subcommand() {
        assert_eq!(parse(&["setup"]).command, Some(Command::Setup));
    }

    #[test]
    fn host_args_and_port() {
        let cli = parse(&["host", "--port", "30000", "--headless"]);
        assert_eq!(cli.fixed_mode(), Some(Mode::Host));
        assert!(cli.headless());
        let hc = build_host_config(&cli.host_args(), &HostSettings::default());
        assert_eq!(hc.effective_bind_addr().port(), 30000);

        let cli = parse(&["host"]);
        let hc = build_host_config(
            &cli.host_args(),
            &HostSettings {
                port: 31000,
                ..HostSettings::default()
            },
        );
        assert_eq!(hc.effective_bind_addr().port(), 31000);
    }

    #[test]
    fn serial_transport_args_build_both_roles_and_survive_reexec() {
        let host = parse(&[
            "host",
            "--serial",
            "/dev/tty.usbmodem-host",
            "--baud",
            "460800",
        ]);
        let hc = build_host_config(&host.host_args(), &HostSettings::default());
        let serial = hc.serial.expect("host serial settings");
        assert_eq!(serial.path, "/dev/tty.usbmodem-host");
        assert_eq!(serial.baud, 460_800);

        let guest = parse(&[
            "guest",
            "--serial",
            "/dev/tty.usbmodem-guest",
            "--baud",
            "230400",
        ]);
        let gc = build_guest_config(&guest.guest_args(), &Config::default()).unwrap();
        assert!(matches!(
            gc.host,
            HostTarget::Serial { ref path, baud }
                if path == "/dev/tty.usbmodem-guest" && baud == 230_400
        ));
        assert_eq!(
            guest.reexec_guest_args(),
            vec![
                "guest",
                "--serial",
                "/dev/tty.usbmodem-guest",
                "--baud",
                "230400"
            ]
        );

        assert!(Cli::try_parse_from([
            "netm",
            "guest",
            "--host",
            "127.0.0.1:27778",
            "--serial",
            "/dev/tty.usbmodem-guest"
        ])
        .is_err());
    }

    #[test]
    fn guest_routes_become_custom_mode_and_dns_defaults_off() {
        let cli = parse(&["guest", "--route", "1.1.1.1/32", "--route", "8.8.8.0/24"]);
        let gc = build_guest_config(&cli.guest_args(), &Config::default()).unwrap();
        match gc.routes {
            RouteMode::Custom(nets) => {
                assert_eq!(nets.len(), 2);
                assert_eq!(nets[0].to_string(), "1.1.1.1/32");
                assert_eq!(nets[1].to_string(), "8.8.8.0/24");
            }
            RouteMode::Full => panic!("expected custom routes"),
        }
        assert!(!gc.set_dns, "custom routes default to leaving DNS alone");
        assert!(matches!(gc.host, HostTarget::Auto));
    }

    #[test]
    fn guest_full_mode_sets_dns_unless_no_dns() {
        let cli = parse(&["guest"]);
        let gc = build_guest_config(&cli.guest_args(), &Config::default()).unwrap();
        assert!(matches!(gc.routes, RouteMode::Full));
        assert!(gc.set_dns);

        let cli = parse(&["guest", "--no-dns"]);
        let gc = build_guest_config(&cli.guest_args(), &Config::default()).unwrap();
        assert!(!gc.set_dns);
    }

    #[test]
    fn saved_settings_apply_when_cli_is_silent() {
        let saved = Config {
            guest: GuestSettings {
                set_dns: Some(true),
                routes: vec!["10.1.0.0/16".into()],
                ..GuestSettings::default()
            },
            ..Config::default()
        };
        let cli = parse(&["guest"]);
        let gc = build_guest_config(&cli.guest_args(), &saved).unwrap();
        match &gc.routes {
            RouteMode::Custom(nets) => assert_eq!(nets[0].to_string(), "10.1.0.0/16"),
            RouteMode::Full => panic!(),
        }
        assert!(gc.set_dns, "explicit set_dns override wins");

        // CLI routes replace saved ones.
        let cli = parse(&["guest", "--route", "1.1.1.1/32", "--no-dns"]);
        let gc = build_guest_config(&cli.guest_args(), &saved).unwrap();
        match &gc.routes {
            RouteMode::Custom(nets) => assert_eq!(nets, &vec!["1.1.1.1/32".parse().unwrap()]),
            RouteMode::Full => panic!(),
        }
        assert!(!gc.set_dns);
    }

    #[test]
    fn invalid_saved_route_is_reported() {
        let saved = Config {
            guest: GuestSettings {
                set_dns: None,
                routes: vec!["not-a-cidr".into()],
                ..GuestSettings::default()
            },
            ..Config::default()
        };
        let err = build_guest_config(&GuestArgs::default(), &saved).unwrap_err();
        assert!(err.to_string().contains("not-a-cidr"));
    }

    #[test]
    fn manual_host_with_numeric_scope() {
        let cli = parse(&["guest", "--host", "[fe80::1%5]:27778"]);
        let gc = build_guest_config(&cli.guest_args(), &Config::default()).unwrap();
        match gc.host {
            HostTarget::Manual(a) => assert_eq!(a.to_string(), "[fe80::1%5]:27778"),
            HostTarget::Auto | HostTarget::Serial { .. } => panic!(),
        }
    }

    #[test]
    fn bad_route_is_rejected_by_clap() {
        let r = Cli::try_parse_from(["netm", "guest", "--route", "1.1.1.1/33"]);
        assert!(r.is_err());
    }

    #[test]
    fn reexec_args_keep_globals_and_normalise_subcommand() {
        let cli = parse(&["-vv", "--config", "/tmp/c.toml"]);
        assert_eq!(
            cli.reexec_guest_args(),
            vec!["--config", "/tmp/c.toml", "-v", "-v", "guest"]
        );

        let cli = parse(&["guest", "--route", "1.1.1.1/32", "--no-dns", "--headless"]);
        assert_eq!(
            cli.reexec_guest_args(),
            vec!["guest", "--route", "1.1.1.1/32", "--no-dns", "--headless"]
        );

        // `setup` followed by choosing guest re-execs a plain `guest`.
        let cli = parse(&["setup"]);
        assert_eq!(cli.reexec_guest_args(), vec!["guest"]);
    }

    #[test]
    fn verbose_is_global() {
        assert_eq!(parse(&["host", "-v"]).verbose, 1);
        assert_eq!(parse(&["-v", "-v", "host"]).verbose, 2);
    }
}
