//! Re-executing `netm guest` under `sudo` when the current process lacks
//! root privileges.

use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Result};

use crate::config::CONFIG_ENV;

/// Whether the guest needs elevation right now.
pub fn guest_needs_elevation() -> bool {
    netm_guest::requires_root() && !netm_proto::privilege::is_root()
}

/// Human readable instructions for running the guest manually.
pub fn manual_hint(config_path: &Path, args: &[String]) -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "netm".to_string());
    format!(
        "请手动以管理员权限运行：\n  sudo -E env {CONFIG_ENV}={} {} {}",
        shell_quote(&config_path.display().to_string()),
        shell_quote(&exe),
        args.iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

/// Build the `sudo` command line: `sudo -E env NETM_CONFIG=<path> <exe> <args>`.
pub fn sudo_command(config_path: &Path, args: &[String]) -> Result<Command> {
    let exe = std::env::current_exe().map_err(|e| anyhow!("cannot locate own executable: {e}"))?;
    let mut cmd = Command::new("sudo");
    cmd.arg("-E")
        .arg("env")
        .arg(format!("{CONFIG_ENV}={}", config_path.display()))
        .arg(exe)
        .args(args);
    Ok(cmd)
}

/// Replace the current process with `sudo … netm guest …`. Only returns on
/// failure (e.g. `sudo` missing); the caller prints [`manual_hint`].
pub fn reexec_guest(config_path: &Path, args: &[String]) -> Result<()> {
    println!("客机模式需要管理员权限，正在通过 sudo 重新启动…");
    let mut cmd = sudo_command(config_path, args)?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(anyhow!("无法执行 sudo：{err}"))
    }
    #[cfg(not(unix))]
    {
        let status = cmd.status().map_err(|e| anyhow!("无法执行 sudo：{e}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Minimal POSIX-shell quoting for display purposes.
fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=[]%".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudo_command_shape() {
        let cmd = sudo_command(
            Path::new("/Users/alice/.config/netm/config.toml"),
            &["guest".into(), "--route".into(), "1.1.1.1/32".into()],
        )
        .unwrap();
        assert_eq!(cmd.get_program(), "sudo");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "-E");
        assert_eq!(args[1], "env");
        assert_eq!(args[2], "NETM_CONFIG=/Users/alice/.config/netm/config.toml");
        assert!(args[3].ends_with("netm") || args[3].contains("netm"));
        assert_eq!(&args[4..], &["guest", "--route", "1.1.1.1/32"]);
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("1.1.1.1/32"), "1.1.1.1/32");
        assert_eq!(shell_quote("[fe80::1%5]:27778"), "[fe80::1%5]:27778");
        assert_eq!(shell_quote("/a b/c"), "'/a b/c'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn hint_mentions_sudo_and_config() {
        let h = manual_hint(Path::new("/tmp/c.toml"), &["guest".into()]);
        assert!(h.contains("sudo -E env NETM_CONFIG=/tmp/c.toml"));
        assert!(h.ends_with(" guest"));
    }
}
