//! Per-OS configuration of the tunnel interface: addresses, routes and DNS.
//!
//! The guest core only talks to the [`PlatformConfigurator`] trait; the
//! concrete implementation is selected with `cfg(target_os)`. Every
//! implementation drives external tools through the [`CommandRunner`] trait
//! so the exact command sequences can be unit-tested with a recording fake
//! (see [`RecordingRunner`]).

use std::io;
use std::process::{Command, Stdio};

use anyhow::Result;
use netm_proto::TunnelConfig;

use crate::RouteMode;

// The Linux and Windows configurators only drive external commands through
// `CommandRunner`, so they compile (and are unit-tested) everywhere; only
// `system_configurator` picks one per OS.
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod windows;

/// Applies and reverts the OS-level network configuration for a tunnel.
///
/// `apply` must be followed by exactly one `revert` (a second `revert` is a
/// no-op). Implementations also revert from `Drop` (best effort) so an
/// aborted task or a panic does not leave the machine without a default
/// route.
pub trait PlatformConfigurator: Send {
    /// Configure `tun_name` with `cfg`, install the routes selected by
    /// `routes` and (when `set_dns`) point the system resolver at `cfg.dns`.
    fn apply(
        &mut self,
        tun_name: &str,
        cfg: &TunnelConfig,
        routes: &RouteMode,
        set_dns: bool,
    ) -> Result<()>;

    /// Undo everything `apply` did, in reverse order. Errors of individual
    /// steps are logged and the remaining steps still run; the first error is
    /// returned.
    fn revert(&mut self) -> Result<()>;
}

/// Name of the interface the system's default route points at, i.e. where
/// traffic goes when no tunnel is up (`en0` for Wi-Fi on a MacBook).
///
/// Used to tell the user in plain words where their traffic went after the
/// tunnel was torn down. `None` when it cannot be determined, in which case
/// callers must not claim anything specific.
pub fn default_egress_interface() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        parse_macos_default_route(&String::from_utf8_lossy(&out.stdout))
    }
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("ip")
            .args(["-4", "route", "show", "default"])
            .output()
            .ok()?;
        parse_linux_default_route(&String::from_utf8_lossy(&out.stdout))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// Extract `interface: enN` from `route -n get default`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_macos_default_route(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("interface:"))
        .map(|v| v.trim().to_string())
        .find(|v| !v.is_empty())
}

/// Extract `dev <name>` from `ip route show default`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_linux_default_route(text: &str) -> Option<String> {
    text.split_whitespace()
        .skip_while(|w| *w != "dev")
        .nth(1)
        .map(str::to_string)
}

#[cfg(test)]
mod egress_tests {
    use super::*;

    #[test]
    fn parses_macos_default_route() {
        let out = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(parse_macos_default_route(out).as_deref(), Some("en0"));
        assert_eq!(
            parse_macos_default_route("route: writing to routing socket: not in table"),
            None
        );
    }

    #[test]
    fn parses_linux_default_route() {
        let out = "default via 192.168.1.1 dev wlp2s0 proto dhcp metric 600\n";
        assert_eq!(parse_linux_default_route(out).as_deref(), Some("wlp2s0"));
        assert_eq!(parse_linux_default_route(""), None);
    }
}

/// Output of an external command run through [`CommandRunner`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs an external command. Abstracted so tests can assert the exact
/// command lines without touching the system.
pub trait CommandRunner: Send {
    /// Run `program` with `args`, feeding `stdin` (if any) to the process.
    fn run(
        &mut self,
        program: &str,
        args: &[&str],
        stdin: Option<&str>,
    ) -> io::Result<CommandOutput>;
}

/// [`CommandRunner`] backed by [`std::process::Command`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[&str],
        stdin: Option<&str>,
    ) -> io::Result<CommandOutput> {
        tracing::debug!(program, ?args, has_stdin = stdin.is_some(), "exec");
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        if let Some(input) = stdin {
            use std::io::Write;
            if let Some(mut pipe) = child.stdin.take() {
                pipe.write_all(input.as_bytes())?;
                // Drop closes the pipe so the child sees EOF.
            }
        }
        let out = child.wait_with_output()?;
        Ok(CommandOutput {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// One recorded invocation (see [`RecordingRunner`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedCommand {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<String>,
}

impl RecordedCommand {
    /// `program` followed by its arguments, space separated (for assertions).
    pub fn argv(&self) -> String {
        let mut s = self.program.clone();
        for a in &self.args {
            s.push(' ');
            s.push_str(a);
        }
        s
    }
}

/// A [`CommandRunner`] that records every invocation and answers from a
/// scripted table. Shared through an `Arc<Mutex<..>>` so tests can inspect
/// what a configurator did after it has been moved into the guest.
#[derive(Debug, Default)]
pub struct RecordingRunner {
    pub log: std::sync::Arc<std::sync::Mutex<Vec<RecordedCommand>>>,
    /// `(program, first arg)` → canned response. Anything not listed
    /// succeeds with empty output.
    pub responses: Vec<((String, String), CommandOutput)>,
    /// `argv()` prefixes that should fail.
    pub failing: Vec<String>,
}

impl RecordingRunner {
    /// Snapshot of everything recorded so far.
    pub fn recorded(&self) -> Vec<RecordedCommand> {
        self.log.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl CommandRunner for RecordingRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[&str],
        stdin: Option<&str>,
    ) -> io::Result<CommandOutput> {
        let rec = RecordedCommand {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            stdin: stdin.map(|s| s.to_string()),
        };
        let argv = rec.argv();
        self.log.lock().unwrap_or_else(|p| p.into_inner()).push(rec);
        if self.failing.iter().any(|f| argv.starts_with(f)) {
            return Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "simulated failure".into(),
            });
        }
        let first = args.first().copied().unwrap_or("");
        for ((p, a), out) in &self.responses {
            if p == program && a == first {
                return Ok(out.clone());
            }
        }
        Ok(CommandOutput {
            success: true,
            ..Default::default()
        })
    }
}

/// Create the configurator for the current OS using real system commands.
pub fn system_configurator() -> Box<dyn PlatformConfigurator> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacosConfigurator::new(SystemRunner))
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxConfigurator::new(SystemRunner))
    }
    #[cfg(windows)]
    {
        Box::new(windows::WindowsConfigurator::new(SystemRunner))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Box::new(Unsupported)
    }
}

/// Configurator used on platforms without an implementation.
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
#[derive(Debug, Default)]
struct Unsupported;

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
impl PlatformConfigurator for Unsupported {
    fn apply(&mut self, _: &str, _: &TunnelConfig, _: &RouteMode, _: bool) -> Result<()> {
        anyhow::bail!("this platform is not yet supported")
    }
    fn revert(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Dotted-quad netmask for an IPv4 prefix length.
pub fn prefix_to_netmask(prefix_len: u8) -> std::net::Ipv4Addr {
    let bits = if prefix_len >= 32 {
        u32::MAX
    } else if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    };
    std::net::Ipv4Addr::from(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_from_prefix() {
        assert_eq!(prefix_to_netmask(24).to_string(), "255.255.255.0");
        assert_eq!(prefix_to_netmask(32).to_string(), "255.255.255.255");
        assert_eq!(prefix_to_netmask(0).to_string(), "0.0.0.0");
        assert_eq!(prefix_to_netmask(1).to_string(), "128.0.0.0");
        assert_eq!(prefix_to_netmask(30).to_string(), "255.255.255.252");
    }

    #[test]
    fn recording_runner_records_and_scripts() {
        let mut r = RecordingRunner {
            responses: vec![(
                ("ifconfig".into(), "utun9".into()),
                CommandOutput {
                    success: true,
                    stdout: "inet 1.2.3.4".into(),
                    stderr: String::new(),
                },
            )],
            failing: vec!["route -n add".into()],
            ..Default::default()
        };
        let out = r.run("ifconfig", &["utun9"], None).unwrap();
        assert!(out.stdout.contains("1.2.3.4"));
        let out = r.run("route", &["-n", "add", "x"], None).unwrap();
        assert!(!out.success);
        let out = r.run("scutil", &[], Some("quit\n")).unwrap();
        assert!(out.success);
        let rec = r.recorded();
        assert_eq!(rec.len(), 3);
        assert_eq!(rec[1].argv(), "route -n add x");
        assert_eq!(rec[2].stdin.as_deref(), Some("quit\n"));
    }
}
