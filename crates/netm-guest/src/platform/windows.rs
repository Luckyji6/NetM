//! Windows: `netsh` / `route` driven configuration of the Wintun adapter.
//!
//! The configurator itself is platform independent (it only issues commands
//! through a [`CommandRunner`]) so its command sequences are unit-tested on
//! every OS; only [`super::system_configurator`] selects it on Windows.
//!
//! The adapter is created by tun-rs (Wintun, named [`crate::tun::WINDOWS_ADAPTER_NAME`]);
//! tun-rs also assigns the IPv4 address and MTU through `iphlpapi`. The steps
//! below make the configuration robust against that not having happened and
//! add what tun-rs does not do (split routes, DNS, interface metric).
//!
//! Every `netsh` argument is passed as one argv element in `key=value` form
//! (`name=NetM`), which is exactly what `netsh` sees after
//! `CommandLineToArgvW` when a user types `name="NetM"` in a shell.
//!
//! Commands issued by [`WindowsConfigurator::apply`] (in order):
//!
//! 1. `netsh interface ipv4 show interfaces` — parsed (see
//!    [`parse_interface_index`]) to find the interface index of the adapter;
//!    `route add ... if <idx>` needs it.
//! 2. `netsh interface ipv4 show addresses name=<tun>` to check whether the
//!    guest address is already assigned; if not:
//!    `netsh interface ipv4 set address name=<tun> source=static address=<guest> mask=<mask>`
//!    (no `gateway=`: a gateway would install a default route, which is
//!    exactly what the split routes avoid).
//! 3. `netsh interface ipv4 set subinterface interface=<tun> mtu=<mtu> store=active`.
//! 4. `netsh interface ipv4 set interface interface=<tun> metric=1 store=active`
//!    so Windows prefers this interface (and its DNS server) when several
//!    are usable.
//! 5. `route add <net> mask <mask> <gateway> metric 5 if <idx>` for every
//!    route (`0.0.0.0 mask 128.0.0.0` and `128.0.0.0 mask 128.0.0.0` in
//!    [`RouteMode::Full`], the given prefixes in [`RouteMode::Custom`]). A
//!    route that already exists is deleted and re-added once.
//! 6. When DNS is requested:
//!    `netsh interface ipv4 set dnsservers name=<tun> source=static address=<dns> register=none validate=no`
//!    followed by a best-effort `ipconfig /flushdns`.
//!
//! [`WindowsConfigurator::revert`] undoes the steps in reverse order:
//! `netsh interface ipv4 delete dnsservers name=<tun> address=all validate=no`
//! (+ `ipconfig /flushdns`), then `route delete <net> mask <mask> <gateway>
//! if <idx>` for each route (last added first). Address, MTU and metric
//! vanish with the adapter when the Wintun handle is closed.
//!
//! Everything must run from an elevated (administrator) process;
//! `netm_proto::privilege::is_root` reports elevation on Windows.

use anyhow::{anyhow, Context, Result};
use netm_proto::TunnelConfig;

use super::{prefix_to_netmask, CommandRunner, PlatformConfigurator};
use crate::RouteMode;

/// Metric used for the tunnel routes.
pub const ROUTE_METRIC: &str = "5";
/// Interface metric assigned to the tunnel adapter.
pub const INTERFACE_METRIC: &str = "1";

/// A route in `route.exe` terms: network address + dotted netmask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinRoute {
    pub network: String,
    pub mask: String,
}

/// Routes to install for `routes`.
pub fn win_routes(routes: &RouteMode) -> Vec<WinRoute> {
    match routes {
        RouteMode::Full => vec![
            WinRoute {
                network: "0.0.0.0".into(),
                mask: "128.0.0.0".into(),
            },
            WinRoute {
                network: "128.0.0.0".into(),
                mask: "128.0.0.0".into(),
            },
        ],
        RouteMode::Custom(nets) => nets
            .iter()
            .map(|n| WinRoute {
                network: n.network().to_string(),
                mask: prefix_to_netmask(n.prefix_len()).to_string(),
            })
            .collect(),
    }
}

/// Find the interface index of `name` in the output of
/// `netsh interface ipv4 show interfaces`.
///
/// The table looks like (column headers are localized, the layout is not):
///
/// ```text
/// Idx     Met         MTU          State                Name
/// ---  ----------  ----------  ------------  ---------------------------
///   1          75  4294967295  connected     Loopback Pseudo-Interface 1
///  12          25        1500  connected     Ethernet
///  34           5        1400  connected     NetM
/// ```
///
/// Each data row is parsed as four whitespace separated columns followed by
/// the (possibly space containing) interface name.
pub fn parse_interface_index(output: &str, name: &str) -> Option<u32> {
    /// `(idx, name)` of one data row; `None` for header/separator/blank lines.
    fn parse_row(line: &str) -> Option<(u32, &str)> {
        let mut rest = line.trim_start();
        let mut idx = None;
        for col in 0..4 {
            let end = rest.find(char::is_whitespace)?;
            if col == 0 {
                idx = rest[..end].parse::<u32>().ok();
            }
            rest = rest[end..].trim_start();
        }
        Some((idx?, rest.trim_end()))
    }
    output
        .lines()
        .filter_map(parse_row)
        .find(|(_, n)| *n == name)
        .map(|(idx, _)| idx)
}

/// Does `netsh interface ipv4 show addresses name=<tun>` output mention `ip`?
///
/// Labels are localized, so only whitespace delimited tokens are compared.
pub fn netsh_has_address(output: &str, ip: std::net::Ipv4Addr) -> bool {
    let ip = ip.to_string();
    output.split_whitespace().any(|t| t == ip)
}

/// `route add` failed because the route is already present?
pub fn route_already_exists(stdout: &str, stderr: &str) -> bool {
    let text = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    text.contains("already exists") || text.contains("object exists")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Undo {
    Route {
        route: WinRoute,
        gateway: String,
        if_index: String,
    },
    Dns {
        tun: String,
    },
}

/// [`PlatformConfigurator`] for Windows. Generic over the [`CommandRunner`]
/// so the exact commands can be asserted in tests.
pub struct WindowsConfigurator<R: CommandRunner> {
    runner: R,
    undo: Vec<Undo>,
    reverted: bool,
}

impl<R: CommandRunner> WindowsConfigurator<R> {
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            undo: Vec::new(),
            reverted: true,
        }
    }

    fn run_ok(&mut self, program: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
        let out = self
            .runner
            .run(program, args, stdin)
            .with_context(|| format!("failed to execute `{program}`"))?;
        if !out.success {
            // netsh / route.exe print their diagnostics to stdout.
            let msg = if out.stderr.trim().is_empty() {
                out.stdout
            } else {
                out.stderr
            };
            return Err(anyhow!(
                "`{program} {}` failed: {}",
                args.join(" "),
                msg.trim()
            ));
        }
        Ok(out.stdout)
    }

    fn interface_index(&mut self, tun: &str) -> Result<u32> {
        let out = self
            .run_ok("netsh", &["interface", "ipv4", "show", "interfaces"], None)
            .context("listing interfaces")?;
        parse_interface_index(&out, tun).ok_or_else(|| {
            anyhow!("interface `{tun}` not found in `netsh interface ipv4 show interfaces`")
        })
    }

    fn ensure_address(&mut self, tun: &str, cfg: &TunnelConfig) -> Result<()> {
        let name_arg = format!("name={tun}");
        let already = match self.runner.run(
            "netsh",
            &["interface", "ipv4", "show", "addresses", &name_arg],
            None,
        ) {
            Ok(out) if out.success => netsh_has_address(&out.stdout, cfg.guest_ip),
            _ => false,
        };
        if already {
            tracing::debug!(tun, ip = %cfg.guest_ip, "address already assigned by tun device");
        } else {
            let address = format!("address={}", cfg.guest_ip);
            let mask = format!("mask={}", prefix_to_netmask(cfg.prefix_len));
            self.run_ok(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "address",
                    &name_arg,
                    "source=static",
                    &address,
                    &mask,
                ],
                None,
            )
            .context("assigning tunnel address")?;
        }
        let iface_arg = format!("interface={tun}");
        let mtu = format!("mtu={}", cfg.mtu);
        self.run_ok(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &iface_arg,
                &mtu,
                "store=active",
            ],
            None,
        )
        .context("setting tunnel MTU")?;
        let metric = format!("metric={INTERFACE_METRIC}");
        self.run_ok(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "interface",
                &iface_arg,
                &metric,
                "store=active",
            ],
            None,
        )
        .context("setting interface metric")?;
        Ok(())
    }

    fn add_route(&mut self, route: &WinRoute, gateway: &str, if_index: &str) -> Result<()> {
        let add = [
            "add",
            &route.network,
            "mask",
            &route.mask,
            gateway,
            "metric",
            ROUTE_METRIC,
            "if",
            if_index,
        ];
        // route.exe exits 0 even when it prints an error, so the output has
        // to be inspected as well.
        let mut out = self
            .runner
            .run("route", &add, None)
            .context("executing `route add`")?;
        if out.success && !route_already_exists(&out.stdout, &out.stderr) {
            return Ok(());
        }
        if route_already_exists(&out.stdout, &out.stderr) {
            // Stale route from a crashed run: replace it.
            tracing::warn!(?route, "route already exists; replacing it");
            let _ = self.runner.run(
                "route",
                &["delete", &route.network, "mask", &route.mask],
                None,
            );
            out = self
                .runner
                .run("route", &add, None)
                .context("executing `route add`")?;
            if out.success && !route_already_exists(&out.stdout, &out.stderr) {
                return Ok(());
            }
        }
        Err(anyhow!(
            "`route add {} mask {} {gateway} metric {ROUTE_METRIC} if {if_index}` failed: {}",
            route.network,
            route.mask,
            format!("{}\n{}", out.stdout, out.stderr).trim()
        ))
    }

    fn flush_dns(&mut self) {
        if let Err(e) = self.runner.run("ipconfig", &["/flushdns"], None) {
            tracing::debug!(error = %e, "ipconfig /flushdns failed (ignored)");
        }
    }

    fn set_dns(&mut self, tun: &str, cfg: &TunnelConfig) -> Result<()> {
        let name_arg = format!("name={tun}");
        let address = format!("address={}", cfg.dns);
        self.run_ok(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                &name_arg,
                "source=static",
                &address,
                "register=none",
                "validate=no",
            ],
            None,
        )
        .context("setting DNS server")?;
        self.undo.push(Undo::Dns {
            tun: tun.to_string(),
        });
        self.flush_dns();
        Ok(())
    }
}

impl<R: CommandRunner> PlatformConfigurator for WindowsConfigurator<R> {
    fn apply(
        &mut self,
        tun_name: &str,
        cfg: &TunnelConfig,
        routes: &RouteMode,
        set_dns: bool,
    ) -> Result<()> {
        if !self.reverted {
            self.revert()?;
        }
        self.undo.clear();
        self.reverted = false;

        let if_index = self.interface_index(tun_name)?.to_string();
        self.ensure_address(tun_name, cfg)?;
        let gateway = cfg.gateway_ip.to_string();
        for route in win_routes(routes) {
            self.add_route(&route, &gateway, &if_index)?;
            self.undo.push(Undo::Route {
                route,
                gateway: gateway.clone(),
                if_index: if_index.clone(),
            });
        }
        if set_dns {
            self.set_dns(tun_name, cfg)?;
        }
        Ok(())
    }

    fn revert(&mut self) -> Result<()> {
        if self.reverted {
            return Ok(());
        }
        self.reverted = true;
        let mut first_err: Option<anyhow::Error> = None;
        while let Some(step) = self.undo.pop() {
            let res = match &step {
                Undo::Dns { tun } => {
                    let name_arg = format!("name={tun}");
                    let r = self
                        .run_ok(
                            "netsh",
                            &[
                                "interface",
                                "ipv4",
                                "delete",
                                "dnsservers",
                                &name_arg,
                                "address=all",
                                "validate=no",
                            ],
                            None,
                        )
                        .map(|_| ());
                    self.flush_dns();
                    r
                }
                Undo::Route {
                    route,
                    gateway,
                    if_index,
                } => self
                    .run_ok(
                        "route",
                        &[
                            "delete",
                            &route.network,
                            "mask",
                            &route.mask,
                            gateway,
                            "if",
                            if_index,
                        ],
                        None,
                    )
                    .map(|_| ()),
            };
            if let Err(e) = res {
                tracing::warn!(?step, error = %e, "revert step failed");
                first_err.get_or_insert(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl<R: CommandRunner> Drop for WindowsConfigurator<R> {
    fn drop(&mut self) {
        if !self.reverted {
            tracing::warn!("configurator dropped without revert; reverting now");
            if let Err(e) = self.revert() {
                tracing::error!(error = %e, "best-effort revert on drop failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::platform::{CommandOutput, RecordedCommand, RecordingRunner};

    fn cfg() -> TunnelConfig {
        TunnelConfig::default()
    }

    fn argvs(rec: &[RecordedCommand]) -> Vec<String> {
        rec.iter().map(|r| r.argv()).collect()
    }

    const SHOW_INTERFACES: &str = "
Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  ---------------------------
  1          75  4294967295  connected     Loopback Pseudo-Interface 1
 12          25        1500  connected     Ethernet
  7          35        1500  disconnected  Local Area Connection* 2
 34           5        1400  connected     NetM
";

    const SHOW_ADDRESSES: &str = "
Configuration for interface \"NetM\"
    DHCP enabled:                         No
    IP Address:                           10.77.0.2
    Subnet Prefix:                        10.77.0.0/24 (mask 255.255.255.0)
    InterfaceMetric:                      5
";

    /// Runner where `netsh` knows the adapter and tun-rs already assigned the
    /// address. Because responses are keyed on `(program, first arg)`, every
    /// `netsh interface ...` call returns the same canned output, which
    /// contains both the interface table and the address.
    fn runner_with_address_set() -> (RecordingRunner, Arc<Mutex<Vec<RecordedCommand>>>) {
        let r = RecordingRunner {
            responses: vec![(
                ("netsh".into(), "interface".into()),
                CommandOutput {
                    success: true,
                    stdout: format!("{SHOW_INTERFACES}{SHOW_ADDRESSES}"),
                    stderr: String::new(),
                },
            )],
            ..Default::default()
        };
        let log = r.log.clone();
        (r, log)
    }

    /// Runner where `netsh` lists the adapter but shows no address for it.
    fn runner_without_address() -> (RecordingRunner, Arc<Mutex<Vec<RecordedCommand>>>) {
        let r = RecordingRunner {
            responses: vec![(
                ("netsh".into(), "interface".into()),
                CommandOutput {
                    success: true,
                    stdout: SHOW_INTERFACES.into(),
                    stderr: String::new(),
                },
            )],
            ..Default::default()
        };
        let log = r.log.clone();
        (r, log)
    }

    #[test]
    fn full_mode_with_dns_command_sequence() {
        let (runner, log) = runner_with_address_set();
        let mut c = WindowsConfigurator::new(runner);
        c.apply("NetM", &cfg(), &RouteMode::Full, true).unwrap();
        assert_eq!(
            argvs(&log.lock().unwrap()),
            vec![
                "netsh interface ipv4 show interfaces",
                "netsh interface ipv4 show addresses name=NetM",
                "netsh interface ipv4 set subinterface interface=NetM mtu=9000 store=active",
                "netsh interface ipv4 set interface interface=NetM metric=1 store=active",
                "route add 0.0.0.0 mask 128.0.0.0 10.77.0.1 metric 5 if 34",
                "route add 128.0.0.0 mask 128.0.0.0 10.77.0.1 metric 5 if 34",
                "netsh interface ipv4 set dnsservers name=NetM source=static address=10.77.0.1 register=none validate=no",
                "ipconfig /flushdns",
            ]
        );

        c.revert().unwrap();
        assert_eq!(
            argvs(&log.lock().unwrap()[8..]),
            vec![
                "netsh interface ipv4 delete dnsservers name=NetM address=all validate=no",
                "ipconfig /flushdns",
                "route delete 128.0.0.0 mask 128.0.0.0 10.77.0.1 if 34",
                "route delete 0.0.0.0 mask 128.0.0.0 10.77.0.1 if 34",
            ]
        );

        // Second revert and drop are no-ops.
        c.revert().unwrap();
        assert_eq!(log.lock().unwrap().len(), 12);
        drop(c);
        assert_eq!(log.lock().unwrap().len(), 12);
    }

    #[test]
    fn custom_mode_without_dns_sets_address_when_missing() {
        let (runner, log) = runner_without_address();
        let mut c = WindowsConfigurator::new(runner);
        let routes = RouteMode::Custom(vec![
            "1.1.1.1/32".parse().unwrap(),
            "192.168.50.77/24".parse().unwrap(), // host bits are truncated
        ]);
        let mut tc = cfg();
        tc.mtu = 1380;
        tc.prefix_len = 30;
        c.apply("NetM", &tc, &routes, false).unwrap();
        assert_eq!(
            argvs(&log.lock().unwrap()),
            vec![
                "netsh interface ipv4 show interfaces",
                "netsh interface ipv4 show addresses name=NetM",
                "netsh interface ipv4 set address name=NetM source=static address=10.77.0.2 mask=255.255.255.252",
                "netsh interface ipv4 set subinterface interface=NetM mtu=1380 store=active",
                "netsh interface ipv4 set interface interface=NetM metric=1 store=active",
                "route add 1.1.1.1 mask 255.255.255.255 10.77.0.1 metric 5 if 34",
                "route add 192.168.50.0 mask 255.255.255.0 10.77.0.1 metric 5 if 34",
            ]
        );
        c.revert().unwrap();
        assert_eq!(
            argvs(&log.lock().unwrap()[7..]),
            vec![
                "route delete 192.168.50.0 mask 255.255.255.0 10.77.0.1 if 34",
                "route delete 1.1.1.1 mask 255.255.255.255 10.77.0.1 if 34",
            ]
        );
    }

    #[test]
    fn missing_interface_fails_before_any_change() {
        let runner = RecordingRunner::default(); // empty netsh output
        let log = runner.log.clone();
        let mut c = WindowsConfigurator::new(runner);
        let err = c.apply("NetM", &cfg(), &RouteMode::Full, true).unwrap_err();
        assert!(err.to_string().contains("NetM"), "{err}");
        assert_eq!(
            argvs(&log.lock().unwrap()),
            vec!["netsh interface ipv4 show interfaces"]
        );
        c.revert().unwrap();
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[test]
    fn drop_reverts_when_not_reverted() {
        let (runner, log) = runner_with_address_set();
        {
            let mut c = WindowsConfigurator::new(runner);
            c.apply("NetM", &cfg(), &RouteMode::Full, true).unwrap();
            assert_eq!(log.lock().unwrap().len(), 8);
        }
        let rec = argvs(&log.lock().unwrap());
        assert_eq!(rec.len(), 12, "drop must run the revert steps");
        assert!(rec[8].starts_with("netsh interface ipv4 delete dnsservers"));
        assert!(rec[10].starts_with("route delete 128.0.0.0"));
        assert!(rec[11].starts_with("route delete 0.0.0.0"));
    }

    #[test]
    fn failed_route_aborts_apply_and_reverts_partial_state() {
        let (mut runner, log) = runner_with_address_set();
        runner
            .failing
            .push("route add 128.0.0.0 mask 128.0.0.0".to_string());
        let mut c = WindowsConfigurator::new(runner);
        let err = c.apply("NetM", &cfg(), &RouteMode::Full, true).unwrap_err();
        assert!(err.to_string().contains("128.0.0.0"), "{err}");
        c.revert().unwrap();
        let rec = argvs(&log.lock().unwrap());
        assert_eq!(
            rec.last().unwrap(),
            "route delete 0.0.0.0 mask 128.0.0.0 10.77.0.1 if 34"
        );
        assert!(!rec.iter().any(|a| a.contains("dnsservers")));
    }

    #[test]
    fn existing_route_is_replaced() {
        let (mut runner, log) = runner_with_address_set();
        runner.responses.push((
            ("route".into(), "add".into()),
            CommandOutput {
                success: true, // route.exe exits 0 even on this error
                stdout: "The route addition failed: The object already exists.\n".into(),
                stderr: String::new(),
            },
        ));
        // Every `route add` reports "exists", so the retry fails too...
        let mut c = WindowsConfigurator::new(runner);
        let routes = RouteMode::Custom(vec!["1.1.1.1/32".parse().unwrap()]);
        assert!(c.apply("NetM", &cfg(), &routes, false).is_err());
        // ...but it must have tried delete + add in between.
        let rec = argvs(&log.lock().unwrap());
        assert_eq!(
            &rec[rec.len() - 3..],
            &[
                "route add 1.1.1.1 mask 255.255.255.255 10.77.0.1 metric 5 if 34",
                "route delete 1.1.1.1 mask 255.255.255.255",
                "route add 1.1.1.1 mask 255.255.255.255 10.77.0.1 metric 5 if 34",
            ]
        );
    }

    #[test]
    fn parses_interface_table() {
        assert_eq!(parse_interface_index(SHOW_INTERFACES, "NetM"), Some(34));
        assert_eq!(parse_interface_index(SHOW_INTERFACES, "Ethernet"), Some(12));
        assert_eq!(
            parse_interface_index(SHOW_INTERFACES, "Loopback Pseudo-Interface 1"),
            Some(1)
        );
        assert_eq!(
            parse_interface_index(SHOW_INTERFACES, "Local Area Connection* 2"),
            Some(7)
        );
        assert_eq!(parse_interface_index(SHOW_INTERFACES, "Net"), None);
        assert_eq!(parse_interface_index("", "NetM"), None);
    }

    #[test]
    fn address_detection() {
        assert!(netsh_has_address(
            SHOW_ADDRESSES,
            Ipv4Addr::new(10, 77, 0, 2)
        ));
        assert!(!netsh_has_address(
            SHOW_ADDRESSES,
            Ipv4Addr::new(10, 77, 0, 1)
        ));
        assert!(!netsh_has_address("", Ipv4Addr::new(10, 77, 0, 2)));
    }

    #[test]
    fn route_lists() {
        assert_eq!(
            win_routes(&RouteMode::Full),
            vec![
                WinRoute {
                    network: "0.0.0.0".into(),
                    mask: "128.0.0.0".into()
                },
                WinRoute {
                    network: "128.0.0.0".into(),
                    mask: "128.0.0.0".into()
                },
            ]
        );
        assert_eq!(
            win_routes(&RouteMode::Custom(vec!["10.1.2.3/16".parse().unwrap()])),
            vec![WinRoute {
                network: "10.1.0.0".into(),
                mask: "255.255.0.0".into()
            }]
        );
        assert!(route_already_exists(
            "The route addition failed: The object already exists.",
            ""
        ));
        assert!(!route_already_exists(" OK!", ""));
    }
}
