//! `netm` — Type-C tunnel network sharing. Entry point: argument parsing,
//! configuration, privilege handling, then either the TUI or headless mode.

mod cli;
mod config;
mod format;
mod headless;
mod logging;
mod privilege;
mod session;
mod signals;
mod tui;

use std::process::ExitCode;

use anyhow::Result;
use cli::{Cli, Command};
use config::{Config, Mode};
use session::Session;
use tui::{Outcome, Start};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse_args();
    match real_main(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("错误：{e:#}");
            ExitCode::from(1)
        }
    }
}

async fn real_main(cli: Cli) -> Result<ExitCode> {
    let config_path = config::default_config_path(cli.config.as_deref());
    let config_dir = config::dir_of(&config_path);
    let headless = cli.headless();

    // Logging: stderr when headless, a file otherwise (the TUI owns the
    // terminal).
    let mut log_path = None;
    if headless {
        logging::init_stderr(cli.verbose);
    } else {
        match logging::init_file(&config_dir, cli.verbose) {
            Ok(p) => log_path = Some(p),
            Err(e) => {
                eprintln!("警告：无法打开日志文件（{e:#}），日志将被丢弃");
                logging::init_discard();
            }
        }
    }
    tracing::info!(config = %config_path.display(), "netm starting");

    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("警告：配置文件无法读取（{e:#}），使用默认配置",);
            Config::default()
        }
    };

    // Decide where to start.
    let start = match &cli.command {
        Some(Command::Setup) => Start::Onboarding,
        Some(Command::Host(_)) => Start::Mode(Mode::Host),
        Some(Command::Guest(_)) => Start::Mode(Mode::Guest),
        None => match config.default_mode {
            Some(m) => Start::Mode(m),
            None => Start::Onboarding,
        },
    };

    // Guest mode needs root. In interactive mode re-exec under sudo (the
    // password prompt appears in the terminal). Headless mode is meant for
    // non-interactive use, so it just reports the problem.
    if start == Start::Mode(Mode::Guest) && privilege::guest_needs_elevation() {
        let args = cli.reexec_guest_args();
        if headless {
            eprintln!(
                "错误：客机模式需要管理员权限（创建 TUN、修改路由与 DNS），当前不是 root。\n{}",
                privilege::manual_hint(&config_path, &args)
            );
            return Ok(ExitCode::from(2));
        }
        return reexec_guest(&config_path, &args);
    }

    if headless {
        let session = match start {
            Start::Mode(Mode::Host) => {
                let cfg = cli::build_host_config(&cli.host_args(), &config.host);
                Session::start_host(cfg)
            }
            Start::Mode(Mode::Guest) => {
                let cfg = cli::build_guest_config(&cli.guest_args(), &config)?;
                Session::start_guest(cfg)
            }
            Start::Onboarding => unreachable!("headless implies a subcommand"),
        };
        return match headless::run(session).await {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("错误：{e:#}");
                Ok(ExitCode::from(1))
            }
        };
    }

    let app = tui::App::new(
        config,
        config_path.clone(),
        log_path,
        cli.host_args(),
        cli.guest_args(),
    );
    let (outcome, errors) = tui::run(app, start).await?;
    for e in &errors {
        eprintln!("运行出错：{e}");
    }
    match outcome {
        Outcome::Quit => Ok(if errors.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }),
        Outcome::ReexecGuest => reexec_guest(&config_path, &cli.reexec_guest_args()),
    }
}

/// Replace this process with `sudo … netm guest …`; on failure explain how
/// to do it by hand.
fn reexec_guest(config_path: &std::path::Path, args: &[String]) -> Result<ExitCode> {
    if let Err(e) = privilege::reexec_guest(config_path, args) {
        eprintln!("{e}\n{}", privilege::manual_hint(config_path, args));
        return Ok(ExitCode::from(2));
    }
    Ok(ExitCode::SUCCESS)
}
