//! `tracing` setup: stderr in headless mode, a log file in TUI mode (stderr
//! would corrupt the screen). `RUST_LOG` is honoured; `-v` raises the default
//! level.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;

fn filter(verbose: u8) -> EnvFilter {
    let default = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default))
}

/// Log to stderr (headless mode).
pub fn init_stderr(verbose: u8) {
    tracing_subscriber::fmt()
        .with_env_filter(filter(verbose))
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

/// Log to `<dir>/netm.log` (TUI mode). Returns the log file path. Falls back
/// to discarding logs if the file cannot be opened, so the TUI still runs.
pub fn init_file(dir: &Path, verbose: u8) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    crate::config::chown_to_sudo_user(dir);
    let path = dir.join(crate::config::LOG_FILE);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    crate::config::chown_to_sudo_user(&path);
    tracing_subscriber::fmt()
        .with_env_filter(filter(verbose))
        .with_target(false)
        .with_ansi(false)
        .with_writer(Mutex::new(file))
        .init();
    Ok(path)
}

/// Install a subscriber that drops everything (used when the log file cannot
/// be opened).
pub fn init_discard() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("off"))
        .with_writer(std::io::sink)
        .init();
}
