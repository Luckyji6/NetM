//! TUI application state and key handling (no terminal I/O here).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use netm_guest::RouteMode;

use super::model::{GuestModel, HostModel, LogBuffer};
use crate::cli::{self, GuestArgs, HostArgs};
use crate::config::{Config, Mode};
use crate::session::{self, Event, Level, Session, SHUTDOWN_TIMEOUT};

/// Spinner frames (Braille, not emoji).
pub const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Which screen is shown.
pub enum Screen {
    Onboarding { selected: usize },
    Guest(GuestModel),
    Host(HostModel),
}

/// What happens once the current session has stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pending {
    None,
    Quit,
    Switch(Mode),
}

/// Why the TUI loop ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Quit,
    /// The user chose guest mode but the process is not root: the caller
    /// restores the terminal and re-executes under `sudo`.
    ReexecGuest,
}

/// Where to start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    Onboarding,
    Mode(Mode),
}

pub struct App {
    pub screen: Screen,
    pub log: LogBuffer,
    pub log_focus: bool,
    pub show_help: bool,
    pub pending: Pending,
    pub notice: Option<String>,
    pub ticks: u64,
    pub dirty: bool,
    pub config: Config,
    pub config_path: PathBuf,
    pub log_path: Option<PathBuf>,
    pub session: Option<Session>,
    pub host_args: HostArgs,
    pub guest_args: GuestArgs,
    /// Summary of the guest configuration for the connection panel.
    pub guest_summary: Vec<(String, String)>,
    /// Errors returned by the cores, printed after the terminal is restored.
    pub run_errors: Vec<String>,
    outcome: Option<Outcome>,
    shutdown_started: Option<Instant>,
}

impl App {
    pub fn new(
        config: Config,
        config_path: PathBuf,
        log_path: Option<PathBuf>,
        host_args: HostArgs,
        guest_args: GuestArgs,
    ) -> Self {
        Self {
            screen: Screen::Onboarding { selected: 0 },
            log: LogBuffer::default(),
            log_focus: false,
            show_help: false,
            pending: Pending::None,
            notice: None,
            ticks: 0,
            dirty: true,
            config,
            config_path,
            log_path,
            session: None,
            host_args,
            guest_args,
            guest_summary: Vec::new(),
            run_errors: Vec::new(),
            outcome: None,
            shutdown_started: None,
        }
    }

    /// Enter the initial screen.
    pub fn start(&mut self, start: Start) {
        match start {
            Start::Onboarding => {
                let selected = match self.config.default_mode {
                    Some(Mode::Guest) => 1,
                    _ => 0,
                };
                self.screen = Screen::Onboarding { selected };
            }
            Start::Mode(mode) => self.start_mode(mode),
        }
    }

    pub fn take_outcome(&mut self) -> Option<Outcome> {
        self.outcome.take()
    }

    pub fn current_mode(&self) -> Option<Mode> {
        match &self.screen {
            Screen::Onboarding { .. } => None,
            Screen::Guest(_) => Some(Mode::Guest),
            Screen::Host(_) => Some(Mode::Host),
        }
    }

    pub fn spinner(&self) -> &'static str {
        SPINNER[(self.ticks as usize) % SPINNER.len()]
    }

    pub fn is_quitting(&self) -> bool {
        self.pending != Pending::None
    }

    fn info(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        tracing::info!("{msg}");
        self.log.push(Level::Info, msg);
    }

    fn error(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        tracing::error!("{msg}");
        self.log.push(Level::Error, msg);
    }

    /// Spawn the core for `mode` and switch to its screen.
    pub fn start_mode(&mut self, mode: Mode) {
        self.dirty = true;
        match mode {
            Mode::Host => {
                let cfg = cli::build_host_config(&self.host_args, &self.config.host);
                self.screen = Screen::Host(HostModel::new(cfg.host_name.clone()));
                self.info(format!(
                    "启动宿主机模式，端口 {}",
                    cfg.effective_bind_addr().port()
                ));
                self.session = Some(Session::start_host(cfg));
            }
            Mode::Guest => {
                if crate::privilege::guest_needs_elevation() {
                    self.outcome = Some(Outcome::ReexecGuest);
                    return;
                }
                let cfg = match cli::build_guest_config(&self.guest_args, &self.config) {
                    Ok(c) => c,
                    Err(e) => {
                        self.screen = Screen::Guest(GuestModel {
                            fatal: Some(e.to_string()),
                            ..GuestModel::default()
                        });
                        self.error(format!("客机配置无效：{e:#}"));
                        return;
                    }
                };
                self.guest_summary = guest_summary(&cfg);
                self.screen = Screen::Guest(GuestModel::default());
                self.info("启动客机模式");
                self.session = Some(Session::start_guest(cfg));
            }
        }
    }

    /// Handle a core event.
    pub fn on_event(&mut self, ev: Event) {
        if let Some((level, msg)) = session::describe(&ev) {
            self.log.push(level, msg);
        }
        match (&mut self.screen, &ev) {
            (Screen::Host(m), Event::Host(h)) => {
                self.dirty |= m.apply(h);
            }
            (Screen::Guest(m), Event::Guest(g)) => {
                self.dirty |= m.apply(g);
            }
            _ => {}
        }
        self.dirty = true;
    }

    /// The core task returned.
    pub fn on_finished(&mut self, res: Result<()>) {
        self.session = None;
        self.shutdown_started = None;
        self.dirty = true;
        if let Err(e) = res {
            let text = format!("{e:#}");
            self.error(format!("运行出错：{text}"));
            self.run_errors.push(text.clone());
            match &mut self.screen {
                Screen::Guest(m) => m.fatal = Some(text),
                Screen::Host(m) => m.fatal = Some(text),
                Screen::Onboarding { .. } => {}
            }
        } else {
            self.info("已停止");
        }
        match std::mem::replace(&mut self.pending, Pending::None) {
            Pending::Quit => self.outcome = Some(Outcome::Quit),
            Pending::Switch(mode) => {
                self.notice = None;
                self.start_mode(mode);
            }
            Pending::None => {
                self.notice = Some("核心已停止，按 m 切换模式或 q 退出".into());
            }
        }
    }

    /// 100 ms tick: spinner, durations, shutdown watchdog.
    pub fn on_tick(&mut self) {
        self.ticks += 1;
        self.dirty = true;
        if let Some(started) = self.shutdown_started {
            if started.elapsed() > SHUTDOWN_TIMEOUT + Duration::from_secs(1) {
                self.error("核心未能在限定时间内停止，强制退出");
                self.session = None; // dropping aborts nothing, but the watch sender is gone
                self.on_finished(Ok(()));
            }
        }
    }

    /// Begin shutting down the running core; `pending` decides what follows.
    fn stop_session(&mut self, pending: Pending, notice: &str) {
        self.pending = pending;
        self.dirty = true;
        match self.session.as_mut() {
            Some(s) => {
                if !s.shutdown_requested() {
                    s.request_shutdown();
                    self.shutdown_started = Some(Instant::now());
                }
                self.notice = Some(notice.to_string());
            }
            None => self.on_finished(Ok(())),
        }
    }

    /// Graceful quit (key, Ctrl-C or signal).
    pub fn request_quit(&mut self, why: &str) {
        if self.pending == Pending::Quit {
            return;
        }
        self.info(format!("收到退出请求（{why}），正在清理…"));
        self.stop_session(Pending::Quit, "正在清理并退出…");
    }

    /// `m`: stop the current mode, persist the other one as default and
    /// start it.
    fn request_switch(&mut self) {
        let Some(cur) = self.current_mode() else {
            return;
        };
        if self.pending != Pending::None {
            return;
        }
        let next = cur.other();
        self.save_default(next);
        self.info(format!("切换到{}模式…", next.label()));
        self.stop_session(Pending::Switch(next), "正在停止当前模式…");
    }

    fn save_default(&mut self, mode: Mode) {
        self.config.default_mode = Some(mode);
        if let Err(e) = self.config.save(&self.config_path) {
            self.error(format!(
                "保存配置失败（{}）：{e:#}",
                self.config_path.display()
            ));
        } else {
            self.info(format!(
                "已保存默认模式：{}（{}）",
                mode.label(),
                self.config_path.display()
            ));
        }
    }

    /// Key press from crossterm.
    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        self.dirty = true;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C')) {
            self.request_quit("Ctrl-C");
            return;
        }
        if self.show_help {
            match key.code {
                KeyCode::Char('q') => self.request_quit("按键 q"),
                _ => self.show_help = false,
            }
            return;
        }
        if self.log_focus {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.log.scroll(1),
                KeyCode::Down | KeyCode::Char('j') => self.log.scroll(-1),
                KeyCode::PageUp => self.log.scroll(10),
                KeyCode::PageDown => self.log.scroll(-10),
                KeyCode::Home => self.log.scroll(isize::MAX / 2),
                KeyCode::End => self.log.follow(),
                KeyCode::Esc | KeyCode::Char('l') => {
                    self.log_focus = false;
                    self.log.follow();
                }
                KeyCode::Char('q') => self.request_quit("按键 q"),
                KeyCode::Char('?') => self.show_help = true,
                _ => {}
            }
            return;
        }
        match &mut self.screen {
            Screen::Onboarding { selected } => match key.code {
                KeyCode::Up | KeyCode::Char('k') => *selected = selected.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *selected = (*selected + 1).min(1),
                KeyCode::Enter => {
                    let mode = if *selected == 0 {
                        Mode::Host
                    } else {
                        Mode::Guest
                    };
                    self.save_default(mode);
                    self.start_mode(mode);
                }
                KeyCode::Char('q') | KeyCode::Esc => self.outcome = Some(Outcome::Quit),
                KeyCode::Char('?') => self.show_help = true,
                _ => {}
            },
            Screen::Guest(_) | Screen::Host(_) => match key.code {
                KeyCode::Char('q') => self.request_quit("按键 q"),
                KeyCode::Char('m') => self.request_switch(),
                KeyCode::Char('l') => self.log_focus = true,
                KeyCode::Char('?') => self.show_help = true,
                _ => {}
            },
        }
    }
}

/// Human readable summary of the guest configuration.
pub fn guest_summary(cfg: &netm_guest::GuestConfig) -> Vec<(String, String)> {
    let routes = match &cfg.routes {
        RouteMode::Full => "全部流量（0.0.0.0/1 + 128.0.0.0/1）".to_string(),
        RouteMode::Custom(nets) => nets
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", "),
    };
    let host = match &cfg.host {
        netm_guest::HostTarget::Auto => "自动发现".to_string(),
        netm_guest::HostTarget::Manual(a) => a.to_string(),
        netm_guest::HostTarget::Serial { path, baud } => {
            format!("串口 {path}（{baud} baud）")
        }
    };
    vec![
        ("路由".into(), routes),
        (
            "系统 DNS".into(),
            if cfg.set_dns { "接管" } else { "不修改" }.into(),
        ),
        ("宿主机".into(), host),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Keep the tempdir alive for the test by leaking it.
        std::mem::forget(dir);
        App::new(
            Config::default(),
            path,
            None,
            HostArgs::default(),
            GuestArgs::default(),
        )
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn onboarding_navigation_and_quit() {
        let mut a = app();
        a.start(Start::Onboarding);
        assert!(matches!(a.screen, Screen::Onboarding { selected: 0 }));
        a.on_key(key(KeyCode::Down));
        assert!(matches!(a.screen, Screen::Onboarding { selected: 1 }));
        a.on_key(key(KeyCode::Down));
        assert!(matches!(a.screen, Screen::Onboarding { selected: 1 }));
        a.on_key(key(KeyCode::Up));
        assert!(matches!(a.screen, Screen::Onboarding { selected: 0 }));
        a.on_key(key(KeyCode::Char('q')));
        assert_eq!(a.take_outcome(), Some(Outcome::Quit));
    }

    #[test]
    fn onboarding_preselects_saved_mode() {
        let mut a = app();
        a.config.default_mode = Some(Mode::Guest);
        a.start(Start::Onboarding);
        assert!(matches!(a.screen, Screen::Onboarding { selected: 1 }));
    }

    #[test]
    fn help_toggle_and_log_focus_scroll() {
        let mut a = app();
        a.start(Start::Onboarding);
        a.on_key(key(KeyCode::Char('?')));
        assert!(a.show_help);
        a.on_key(key(KeyCode::Esc));
        assert!(!a.show_help);

        // Log focus is only available on the mode screens.
        a.screen = Screen::Host(HostModel::new("x".into()));
        for i in 0..20 {
            a.log.push(Level::Info, format!("{i}"));
        }
        a.on_key(key(KeyCode::Char('l')));
        assert!(a.log_focus);
        a.on_key(key(KeyCode::Up));
        assert_eq!(a.log.scroll_up(), 1);
        a.on_key(key(KeyCode::PageUp));
        assert_eq!(a.log.scroll_up(), 11);
        a.on_key(key(KeyCode::Esc));
        assert!(!a.log_focus);
        assert_eq!(a.log.scroll_up(), 0);
    }

    #[test]
    fn ctrl_c_without_session_quits_immediately() {
        let mut a = app();
        a.screen = Screen::Host(HostModel::new("x".into()));
        a.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert_eq!(a.take_outcome(), Some(Outcome::Quit));
    }

    #[test]
    fn finished_with_error_records_it() {
        let mut a = app();
        a.screen = Screen::Guest(GuestModel::default());
        a.on_finished(Err(anyhow::anyhow!("boom")));
        assert_eq!(a.run_errors, vec!["boom".to_string()]);
        match &a.screen {
            Screen::Guest(m) => assert_eq!(m.fatal.as_deref(), Some("boom")),
            _ => panic!(),
        }
        assert!(a.notice.is_some());
        assert_eq!(a.take_outcome(), None);
    }

    #[test]
    fn guest_summary_lists_routes_and_dns() {
        let cfg = netm_guest::GuestConfig {
            routes: RouteMode::Custom(vec!["1.1.1.1/32".parse().unwrap()]),
            set_dns: false,
            ..Default::default()
        };
        let s = guest_summary(&cfg);
        assert_eq!(s[0].1, "1.1.1.1/32");
        assert_eq!(s[1].1, "不修改");
        assert_eq!(s[2].1, "自动发现");
    }
}
