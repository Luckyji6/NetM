//! macOS: `ifconfig` / `route` / `scutil` driven configuration of a `utunN`
//! interface.
//!
//! Commands issued by [`MacosConfigurator::apply`] (in order):
//!
//! 1. `scutil` (stdin) removing a stale `State:/Network/Service/netm/{DNS,IPv4}`
//!    left behind by a crashed run.
//! 2. `ifconfig utunN` to check whether tun-rs already assigned the address;
//!    if not: `ifconfig utunN inet <guest> <gateway> netmask <mask> mtu <mtu> up`.
//! 3. `route -n add -net <cidr> -interface utunN` for every route
//!    (`0.0.0.0/1` and `128.0.0.0/1` in [`RouteMode::Full`], the given
//!    prefixes in [`RouteMode::Custom`]). A route that already exists is
//!    deleted and re-added once.
//! 4. When DNS is requested: `scutil` (stdin) creating
//!    `State:/Network/Service/netm/DNS` (`ServerAddresses`,
//!    `SupplementalMatchDomains ""`) and `State:/Network/Service/netm/IPv4`
//!    (`InterfaceName`, `Addresses`, `Router`), then `scutil --dns` to verify
//!    the resolver shows up (a warning is logged if it does not).
//!
//! [`MacosConfigurator::revert`] undoes the steps in reverse order: the
//! `scutil` keys are removed first, then `route -n delete -net <cidr>
//! -interface utunN` for each route (last added first). The utun address
//! disappears with the device itself when the tun fd is closed.

use anyhow::{anyhow, Context, Result};
use netm_proto::TunnelConfig;

use super::{prefix_to_netmask, CommandRunner, PlatformConfigurator};
use crate::RouteMode;

/// SystemConfiguration service id used for the tunnel's DNS/IPv4 state.
pub const SERVICE_ID: &str = "netm";

fn dns_key() -> String {
    format!("State:/Network/Service/{SERVICE_ID}/DNS")
}

fn ipv4_key() -> String {
    format!("State:/Network/Service/{SERVICE_ID}/IPv4")
}

/// Routes (CIDR strings) to install for `routes`.
pub fn route_cidrs(routes: &RouteMode) -> Vec<String> {
    match routes {
        RouteMode::Full => vec!["0.0.0.0/1".to_string(), "128.0.0.0/1".to_string()],
        RouteMode::Custom(nets) => nets.iter().map(|n| n.trunc().to_string()).collect(),
    }
}

/// `scutil` script that removes the netm service keys.
pub fn scutil_remove_script() -> String {
    format!("remove {}\nremove {}\nquit\n", dns_key(), ipv4_key())
}

/// `scutil` script that publishes the tunnel resolver and IPv4 state.
pub fn scutil_set_script(tun_name: &str, cfg: &TunnelConfig) -> String {
    format!(
        "d.init\n\
         d.add ServerAddresses * {dns}\n\
         d.add SupplementalMatchDomains * \"\"\n\
         set {dns_key}\n\
         d.init\n\
         d.add InterfaceName {tun}\n\
         d.add Addresses * {guest}\n\
         d.add Router {gw}\n\
         set {ipv4_key}\n\
         quit\n",
        dns = cfg.dns,
        dns_key = dns_key(),
        tun = tun_name,
        guest = cfg.guest_ip,
        gw = cfg.gateway_ip,
        ipv4_key = ipv4_key(),
    )
}

/// Does `ifconfig <tun>` output show `inet <ip>` assigned?
pub fn ifconfig_has_inet(output: &str, ip: std::net::Ipv4Addr) -> bool {
    let ip = ip.to_string();
    let mut toks = output.split_whitespace();
    while let Some(t) = toks.next() {
        if t == "inet" && toks.next() == Some(ip.as_str()) {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Undo {
    Route { cidr: String, tun: String },
    Dns,
}

/// [`PlatformConfigurator`] for macOS. Generic over the [`CommandRunner`] so
/// the exact commands can be asserted in tests.
pub struct MacosConfigurator<R: CommandRunner> {
    runner: R,
    undo: Vec<Undo>,
    reverted: bool,
}

impl<R: CommandRunner> MacosConfigurator<R> {
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
            return Err(anyhow!(
                "`{program} {}` failed: {}",
                args.join(" "),
                out.stderr.trim()
            ));
        }
        Ok(out.stdout)
    }

    fn remove_stale_scutil(&mut self) {
        let script = scutil_remove_script();
        if let Err(e) = self.runner.run("scutil", &[], Some(&script)) {
            tracing::debug!(error = %e, "scutil stale cleanup failed (ignored)");
        }
    }

    fn ensure_address(&mut self, tun: &str, cfg: &TunnelConfig) -> Result<()> {
        let already = match self.runner.run("ifconfig", &[tun], None) {
            Ok(out) if out.success => ifconfig_has_inet(&out.stdout, cfg.guest_ip),
            _ => false,
        };
        if already {
            tracing::debug!(tun, ip = %cfg.guest_ip, "address already assigned by tun device");
            return Ok(());
        }
        let mask = prefix_to_netmask(cfg.prefix_len).to_string();
        let guest = cfg.guest_ip.to_string();
        let gw = cfg.gateway_ip.to_string();
        let mtu = cfg.mtu.to_string();
        self.run_ok(
            "ifconfig",
            &[
                tun, "inet", &guest, &gw, "netmask", &mask, "mtu", &mtu, "up",
            ],
            None,
        )
        .context("assigning tunnel address")?;
        Ok(())
    }

    fn add_route(&mut self, cidr: &str, tun: &str) -> Result<()> {
        let args = ["-n", "add", "-net", cidr, "-interface", tun];
        let out = self
            .runner
            .run("route", &args, None)
            .context("executing `route`")?;
        if out.success {
            return Ok(());
        }
        if out.stderr.contains("exists") {
            // Stale route from a crashed run: replace it.
            tracing::warn!(cidr, "route already exists; replacing it");
            let _ = self.runner.run(
                "route",
                &["-n", "delete", "-net", cidr, "-interface", tun],
                None,
            );
            self.run_ok("route", &args, None)?;
            return Ok(());
        }
        Err(anyhow!(
            "`route -n add -net {cidr} -interface {tun}` failed: {}",
            out.stderr.trim()
        ))
    }

    fn set_dns(&mut self, tun: &str, cfg: &TunnelConfig) -> Result<()> {
        let script = scutil_set_script(tun, cfg);
        self.run_ok("scutil", &[], Some(&script))
            .context("publishing DNS via scutil")?;
        self.undo.push(Undo::Dns);
        match self.runner.run("scutil", &["--dns"], None) {
            Ok(out) if out.stdout.contains(&cfg.dns.to_string()) => {
                tracing::info!(dns = %cfg.dns, "tunnel resolver visible in `scutil --dns`");
            }
            Ok(_) => {
                tracing::warn!(
                    dns = %cfg.dns,
                    "tunnel resolver not visible in `scutil --dns`; DNS may still use the old servers"
                );
            }
            Err(e) => tracing::debug!(error = %e, "could not run `scutil --dns`"),
        }
        Ok(())
    }
}

impl<R: CommandRunner> PlatformConfigurator for MacosConfigurator<R> {
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

        self.remove_stale_scutil();
        self.ensure_address(tun_name, cfg)?;
        for cidr in route_cidrs(routes) {
            self.add_route(&cidr, tun_name)?;
            self.undo.push(Undo::Route {
                cidr,
                tun: tun_name.to_string(),
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
                Undo::Dns => {
                    let script = scutil_remove_script();
                    self.run_ok("scutil", &[], Some(&script)).map(|_| ())
                }
                Undo::Route { cidr, tun } => self
                    .run_ok(
                        "route",
                        &["-n", "delete", "-net", cidr, "-interface", tun],
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

impl<R: CommandRunner> Drop for MacosConfigurator<R> {
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

    fn runner_with_address_set() -> (RecordingRunner, Arc<Mutex<Vec<RecordedCommand>>>) {
        let r = RecordingRunner {
            responses: vec![
                (
                    ("ifconfig".into(), "utun7".into()),
                    CommandOutput {
                        success: true,
                        stdout: "utun7: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400\n\
                                 \tinet 10.77.0.2 --> 10.77.0.1 netmask 0xffffff00\n"
                            .into(),
                        stderr: String::new(),
                    },
                ),
                (
                    ("scutil".into(), "--dns".into()),
                    CommandOutput {
                        success: true,
                        stdout: "resolver #1\n  nameserver[0] : 10.77.0.1\n".into(),
                        stderr: String::new(),
                    },
                ),
            ],
            ..Default::default()
        };
        let log = r.log.clone();
        (r, log)
    }

    #[test]
    fn full_mode_with_dns_command_sequence() {
        let (runner, log) = runner_with_address_set();
        let mut c = MacosConfigurator::new(runner);
        c.apply("utun7", &cfg(), &RouteMode::Full, true).unwrap();
        let rec = log.lock().unwrap().clone();
        assert_eq!(
            argvs(&rec),
            vec![
                "scutil",
                "ifconfig utun7",
                "route -n add -net 0.0.0.0/1 -interface utun7",
                "route -n add -net 128.0.0.0/1 -interface utun7",
                "scutil",
                "scutil --dns",
            ]
        );
        // Stale cleanup script.
        assert_eq!(
            rec[0].stdin.as_deref(),
            Some(
                "remove State:/Network/Service/netm/DNS\nremove State:/Network/Service/netm/IPv4\nquit\n"
            )
        );
        // DNS publish script.
        assert_eq!(
            rec[4].stdin.as_deref(),
            Some(
                "d.init\n\
                 d.add ServerAddresses * 10.77.0.1\n\
                 d.add SupplementalMatchDomains * \"\"\n\
                 set State:/Network/Service/netm/DNS\n\
                 d.init\n\
                 d.add InterfaceName utun7\n\
                 d.add Addresses * 10.77.0.2\n\
                 d.add Router 10.77.0.1\n\
                 set State:/Network/Service/netm/IPv4\n\
                 quit\n"
            )
        );

        c.revert().unwrap();
        let rec = log.lock().unwrap().clone();
        assert_eq!(
            argvs(&rec[6..]),
            vec![
                "scutil",
                "route -n delete -net 128.0.0.0/1 -interface utun7",
                "route -n delete -net 0.0.0.0/1 -interface utun7",
            ]
        );
        assert_eq!(
            rec[6].stdin.as_deref(),
            Some(scutil_remove_script().as_str())
        );

        // Second revert is a no-op.
        c.revert().unwrap();
        assert_eq!(log.lock().unwrap().len(), 9);
        drop(c);
        assert_eq!(log.lock().unwrap().len(), 9);
    }

    #[test]
    fn custom_mode_without_dns_sets_address_when_missing() {
        let runner = RecordingRunner::default(); // ifconfig query returns empty stdout
        let log = runner.log.clone();
        let mut c = MacosConfigurator::new(runner);
        let routes = RouteMode::Custom(vec![
            "1.1.1.1/32".parse().unwrap(),
            "8.8.8.8/32".parse().unwrap(),
            "192.168.50.77/24".parse().unwrap(), // host bits are truncated
        ]);
        let mut tc = cfg();
        tc.mtu = 1380;
        tc.prefix_len = 30;
        c.apply("utun3", &tc, &routes, false).unwrap();
        assert_eq!(
            argvs(&log.lock().unwrap()),
            vec![
                "scutil",
                "ifconfig utun3",
                "ifconfig utun3 inet 10.77.0.2 10.77.0.1 netmask 255.255.255.252 mtu 1380 up",
                "route -n add -net 1.1.1.1/32 -interface utun3",
                "route -n add -net 8.8.8.8/32 -interface utun3",
                "route -n add -net 192.168.50.0/24 -interface utun3",
            ]
        );
        c.revert().unwrap();
        assert_eq!(
            argvs(&log.lock().unwrap()[6..]),
            vec![
                "route -n delete -net 192.168.50.0/24 -interface utun3",
                "route -n delete -net 8.8.8.8/32 -interface utun3",
                "route -n delete -net 1.1.1.1/32 -interface utun3",
            ]
        );
    }

    #[test]
    fn drop_reverts_when_not_reverted() {
        let (runner, log) = runner_with_address_set();
        {
            let mut c = MacosConfigurator::new(runner);
            c.apply("utun7", &cfg(), &RouteMode::Full, true).unwrap();
            assert_eq!(log.lock().unwrap().len(), 6);
        }
        let rec = log.lock().unwrap().clone();
        assert_eq!(rec.len(), 9, "drop must run the revert steps");
        assert_eq!(rec[6].program, "scutil");
        assert!(rec[7]
            .argv()
            .starts_with("route -n delete -net 128.0.0.0/1"));
        assert!(rec[8].argv().starts_with("route -n delete -net 0.0.0.0/1"));
    }

    #[test]
    fn failed_route_aborts_apply_and_reverts_partial_state() {
        let mut runner = RecordingRunner::default();
        runner
            .failing
            .push("route -n add -net 128.0.0.0/1".to_string());
        let log = runner.log.clone();
        let mut c = MacosConfigurator::new(runner);
        let err = c
            .apply("utun1", &cfg(), &RouteMode::Full, true)
            .unwrap_err();
        assert!(err.to_string().contains("128.0.0.0/1"), "{err}");
        // Only the first route was installed; DNS never happened.
        c.revert().unwrap();
        let rec = argvs(&log.lock().unwrap());
        assert_eq!(
            rec.last().unwrap(),
            "route -n delete -net 0.0.0.0/1 -interface utun1"
        );
        assert!(!rec.iter().any(|a| a == "scutil --dns"));
    }

    #[test]
    fn existing_route_is_replaced() {
        let runner = RecordingRunner {
            responses: vec![(
                ("route".into(), "-n".into()),
                CommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "route: writing to routing socket: File exists".into(),
                },
            )],
            ..Default::default()
        };
        let log = runner.log.clone();
        // The canned response makes *every* route call fail with "exists",
        // so the retry fails too and apply must report an error...
        let mut c = MacosConfigurator::new(runner);
        let routes = RouteMode::Custom(vec!["1.1.1.1/32".parse().unwrap()]);
        assert!(c.apply("utun1", &cfg(), &routes, false).is_err());
        // ...but it must have tried delete + add in between.
        let rec = argvs(&log.lock().unwrap());
        assert_eq!(
            &rec[3..],
            &[
                "route -n add -net 1.1.1.1/32 -interface utun1",
                "route -n delete -net 1.1.1.1/32 -interface utun1",
                "route -n add -net 1.1.1.1/32 -interface utun1",
            ]
        );
    }

    #[test]
    fn ifconfig_inet_detection() {
        let out =
            "utun4: flags=8051 mtu 1400\n\tinet 10.77.0.22 --> 10.77.0.1 netmask 0xffffff00\n";
        assert!(ifconfig_has_inet(out, Ipv4Addr::new(10, 77, 0, 22)));
        assert!(!ifconfig_has_inet(out, Ipv4Addr::new(10, 77, 0, 2)));
        assert!(!ifconfig_has_inet("", Ipv4Addr::new(10, 77, 0, 2)));
    }

    #[test]
    fn route_lists() {
        assert_eq!(
            route_cidrs(&RouteMode::Full),
            vec!["0.0.0.0/1", "128.0.0.0/1"]
        );
        assert_eq!(
            route_cidrs(&RouteMode::Custom(vec!["10.1.2.3/16".parse().unwrap()])),
            vec!["10.1.0.0/16"]
        );
        assert!(route_cidrs(&RouteMode::Custom(vec![])).is_empty());
    }
}
