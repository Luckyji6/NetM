//! Persistent configuration (`config.toml`) and resolution of the
//! configuration directory.
//!
//! The configuration lives in `<config_dir>/netm/config.toml`. `config_dir`
//! is `~/.config` on Unix and `%APPDATA%` on Windows, where `~` is the home
//! directory of the *invoking* user: when the program is re-executed under
//! `sudo`, `SUDO_USER` is honoured so that root does not read/write
//! `/var/root/.config`. The `NETM_CONFIG` environment variable (set by the
//! `sudo` re-exec) and `--config` override the file path completely.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Environment variable carrying the resolved config file path across a
/// `sudo` re-exec.
pub const CONFIG_ENV: &str = "NETM_CONFIG";
/// Name of the config directory below `~/.config` / `%APPDATA%`.
pub const APP_DIR: &str = "netm";
/// File name of the configuration.
pub const CONFIG_FILE: &str = "config.toml";
/// File name of the TUI log.
pub const LOG_FILE: &str = "netm.log";

/// Which role this machine plays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Host,
    Guest,
}

impl Mode {
    /// Chinese label used throughout the UI.
    pub fn label(self) -> &'static str {
        match self {
            Mode::Host => "宿主机",
            Mode::Guest => "客机",
        }
    }

    /// The other role.
    pub fn other(self) -> Mode {
        match self {
            Mode::Host => Mode::Guest,
            Mode::Guest => Mode::Host,
        }
    }
}

/// `[host]` section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostSettings {
    /// TCP data port the host listens on.
    pub port: u16,
}

impl Default for HostSettings {
    fn default() -> Self {
        Self {
            port: netm_proto::DATA_PORT,
        }
    }
}

/// `[guest]` section.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestSettings {
    /// Override for the DNS behaviour; `None` = decide from the route mode.
    pub set_dns: Option<bool>,
    /// IPv4 prefixes to route through the tunnel; empty = everything.
    pub routes: Vec<String>,
}

/// The whole `config.toml`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Role entered directly by `netm` without a subcommand; `None` shows
    /// the onboarding screen.
    pub default_mode: Option<Mode>,
    pub host: HostSettings,
    pub guest: GuestSettings,
}

impl Config {
    /// Parse TOML text.
    pub fn from_toml(text: &str) -> Result<Self> {
        toml::from_str(text).context("invalid config.toml")
    }

    /// Serialise to TOML text.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serialising config")
    }

    /// Load the config from `path`; a missing file yields the defaults.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => {
                Self::from_toml(&text).with_context(|| format!("reading {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Write the config to `path`, creating the parent directory. When
    /// running as root under `sudo`, ownership of the directory and file is
    /// handed back to the invoking user so they stay editable later.
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = self.to_toml()?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            chown_to_sudo_user(dir);
        }
        fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
        chown_to_sudo_user(path);
        Ok(())
    }
}

/// Environment inputs that decide where the config lives. Kept as a plain
/// struct so the resolution logic is a pure, testable function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvInfo {
    /// `NETM_CONFIG`: full path of the config file.
    pub netm_config: Option<String>,
    /// `SUDO_USER`: name of the user who ran `sudo`.
    pub sudo_user: Option<String>,
    /// `HOME` (Unix) — home directory of the current user.
    pub home: Option<String>,
    /// `APPDATA` (Windows).
    pub appdata: Option<String>,
}

impl EnvInfo {
    /// Snapshot of the process environment.
    pub fn from_process() -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            netm_config: get(CONFIG_ENV),
            sudo_user: get("SUDO_USER"),
            home: get("HOME"),
            appdata: get("APPDATA"),
        }
    }
}

/// Resolve the config *file* path.
///
/// Order: explicit `--config`, `NETM_CONFIG`, then
/// `<home>/.config/netm/config.toml` (Unix) or `%APPDATA%\netm\config.toml`
/// (Windows). `lookup_home` maps a user name to their home directory and is
/// only consulted when `SUDO_USER` is set.
pub fn resolve_config_path(
    explicit: Option<&Path>,
    env: &EnvInfo,
    lookup_home: impl Fn(&str) -> Option<PathBuf>,
) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    if let Some(p) = &env.netm_config {
        return PathBuf::from(p);
    }
    config_dir_for(env, lookup_home).join(CONFIG_FILE)
}

/// Directory holding `config.toml` and `netm.log`.
pub fn config_dir_for(env: &EnvInfo, lookup_home: impl Fn(&str) -> Option<PathBuf>) -> PathBuf {
    if cfg!(windows) {
        let base = env
            .appdata
            .as_deref()
            .map(PathBuf::from)
            .or_else(|| {
                env.home
                    .as_deref()
                    .map(|h| PathBuf::from(h).join("AppData/Roaming"))
            })
            .unwrap_or_else(|| PathBuf::from("."));
        return base.join(APP_DIR);
    }
    let home = match &env.sudo_user {
        Some(user) if user != "root" => lookup_home(user).unwrap_or_else(|| fallback_home(user)),
        _ => env
            .home
            .as_deref()
            .map(PathBuf::from)
            .or_else(current_user_home)
            .unwrap_or_else(|| PathBuf::from("/tmp")),
    };
    home.join(".config").join(APP_DIR)
}

/// Best guess of a user's home when the account database cannot be queried.
fn fallback_home(user: &str) -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Users").join(user)
    } else {
        PathBuf::from("/home").join(user)
    }
}

/// Parse `dscl . -read /Users/<name> NFSHomeDirectory` output.
pub fn parse_dscl_home(output: &str) -> Option<PathBuf> {
    output.lines().find_map(|line| {
        line.strip_prefix("NFSHomeDirectory:")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    })
}

/// Home directory of `user` via the system account database.
pub fn lookup_user_home(user: &str) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("dscl")
            .args([".", "-read", &format!("/Users/{user}"), "NFSHomeDirectory"])
            .output()
        {
            if out.status.success() {
                if let Some(p) = parse_dscl_home(&String::from_utf8_lossy(&out.stdout)) {
                    return Some(p);
                }
            }
        }
    }
    #[cfg(unix)]
    {
        nix::unistd::User::from_name(user)
            .ok()
            .flatten()
            .map(|u| u.dir)
    }
    #[cfg(not(unix))]
    {
        let _ = user;
        None
    }
}

fn current_user_home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten()
            .map(|u| u.dir)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Resolve the config path from the real environment.
pub fn default_config_path(explicit: Option<&Path>) -> PathBuf {
    resolve_config_path(explicit, &EnvInfo::from_process(), lookup_user_home)
}

/// Directory of `config_path` (where `netm.log` is written too).
pub fn dir_of(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `(uid, gid)` of the user who invoked `sudo`, when running as root.
pub fn sudo_owner() -> Option<(u32, u32)> {
    if !netm_proto::privilege::is_root() {
        return None;
    }
    let uid = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid = std::env::var("SUDO_GID").ok()?.parse().ok()?;
    Some((uid, gid))
}

/// Give `path` back to the `sudo` invoker (no-op when not applicable).
pub fn chown_to_sudo_user(path: &Path) {
    #[cfg(unix)]
    {
        if let Some((uid, gid)) = sudo_owner() {
            use nix::unistd::{chown, Gid, Uid};
            if let Err(e) = chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))) {
                tracing::warn!(path = %path.display(), error = %e, "chown to SUDO_USER failed");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_round_trip() {
        let cfg = Config {
            default_mode: Some(Mode::Guest),
            host: HostSettings { port: 30000 },
            guest: GuestSettings {
                set_dns: Some(false),
                routes: vec!["1.1.1.1/32".into(), "8.8.8.0/24".into()],
            },
        };
        let text = cfg.to_toml().unwrap();
        let back = Config::from_toml(&text).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn empty_and_partial_toml_use_defaults() {
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.host.port, netm_proto::DATA_PORT);
        assert_eq!(cfg.default_mode, None);

        let cfg =
            Config::from_toml("default_mode = \"host\"\n[guest]\nroutes = [\"10.0.0.0/8\"]\n")
                .unwrap();
        assert_eq!(cfg.default_mode, Some(Mode::Host));
        assert_eq!(cfg.guest.routes, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(cfg.guest.set_dns, None);
        assert_eq!(cfg.host.port, netm_proto::DATA_PORT);
    }

    #[test]
    fn invalid_toml_is_an_error() {
        assert!(Config::from_toml("default_mode = \"router\"").is_err());
        assert!(Config::from_toml("[host]\nport = \"abc\"").is_err());
    }

    #[test]
    fn load_missing_file_is_default_and_save_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        assert_eq!(Config::load(&path).unwrap(), Config::default());

        let cfg = Config {
            default_mode: Some(Mode::Host),
            ..Config::default()
        };
        cfg.save(&path).unwrap();
        assert!(path.exists());
        assert_eq!(Config::load(&path).unwrap(), cfg);
    }

    fn env(netm_config: Option<&str>, sudo_user: Option<&str>, home: Option<&str>) -> EnvInfo {
        EnvInfo {
            netm_config: netm_config.map(String::from),
            sudo_user: sudo_user.map(String::from),
            home: home.map(String::from),
            appdata: Some(r"C:\Users\me\AppData\Roaming".into()),
        }
    }

    fn no_lookup(_: &str) -> Option<PathBuf> {
        None
    }

    #[test]
    fn explicit_path_wins_over_everything() {
        let p = resolve_config_path(
            Some(Path::new("/tmp/x.toml")),
            &env(Some("/env/c.toml"), Some("alice"), Some("/Users/root")),
            no_lookup,
        );
        assert_eq!(p, PathBuf::from("/tmp/x.toml"));
    }

    #[test]
    fn netm_config_env_wins_over_home() {
        let p = resolve_config_path(
            None,
            &env(Some("/env/c.toml"), Some("alice"), Some("/var/root")),
            no_lookup,
        );
        assert_eq!(p, PathBuf::from("/env/c.toml"));
    }

    #[cfg(unix)]
    #[test]
    fn sudo_user_home_is_used_instead_of_root_home() {
        let p = resolve_config_path(None, &env(None, Some("alice"), Some("/var/root")), |u| {
            Some(PathBuf::from(format!("/Users/{u}")))
        });
        assert_eq!(p, PathBuf::from("/Users/alice/.config/netm/config.toml"));
    }

    #[cfg(unix)]
    #[test]
    fn sudo_user_without_lookup_falls_back_to_users_dir() {
        let p = resolve_config_path(None, &env(None, Some("bob"), Some("/var/root")), no_lookup);
        let expected = if cfg!(target_os = "macos") {
            "/Users/bob/.config/netm/config.toml"
        } else {
            "/home/bob/.config/netm/config.toml"
        };
        assert_eq!(p, PathBuf::from(expected));
    }

    #[cfg(unix)]
    #[test]
    fn plain_home_when_not_under_sudo() {
        let p = resolve_config_path(None, &env(None, None, Some("/Users/carol")), no_lookup);
        assert_eq!(p, PathBuf::from("/Users/carol/.config/netm/config.toml"));
    }

    #[cfg(unix)]
    #[test]
    fn sudo_user_root_uses_home() {
        let p = resolve_config_path(None, &env(None, Some("root"), Some("/var/root")), no_lookup);
        assert_eq!(p, PathBuf::from("/var/root/.config/netm/config.toml"));
    }

    #[test]
    fn parses_dscl_output() {
        let out = "NFSHomeDirectory: /Users/alice\n";
        assert_eq!(parse_dscl_home(out), Some(PathBuf::from("/Users/alice")));
        assert_eq!(parse_dscl_home("RecordName: alice\n"), None);
        assert_eq!(parse_dscl_home(""), None);
    }

    #[test]
    fn dir_of_config() {
        assert_eq!(dir_of(Path::new("/a/b/config.toml")), PathBuf::from("/a/b"));
    }
}
