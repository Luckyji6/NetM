//! A running host or guest core (`netm_host::run` / `netm_guest::run`) with
//! its event receiver and control channel, plus the shared event → log-line
//! mapping used by both the TUI log panel and headless mode.

use std::time::Duration;

use anyhow::{anyhow, Result};
use netm_guest::{GuestCommand, GuestConfig, GuestEvent, GuestState};
use netm_host::{HostCommand, HostConfig, HostEvent};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::config::Mode;
use crate::format::fmt_bps;

/// Capacity of the event channel. `Stats` are dropped when it is full, other
/// events make the core wait, so this only needs to absorb bursts.
const EVENT_CAPACITY: usize = 1024;
/// How long to wait for the core to finish after `Shutdown`.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Event from either core.
#[derive(Clone, Debug)]
pub enum Event {
    Host(HostEvent),
    Guest(GuestEvent),
}

enum Rx {
    Host(mpsc::Receiver<HostEvent>),
    Guest(mpsc::Receiver<GuestEvent>),
}

enum Ctrl {
    Host(watch::Sender<HostCommand>),
    Guest(watch::Sender<GuestCommand>),
}

/// A spawned core.
pub struct Session {
    mode: Mode,
    rx: Rx,
    ctrl: Option<Ctrl>,
    handle: Option<JoinHandle<Result<()>>>,
    rx_closed: bool,
    shutdown_requested: bool,
}

/// Result of [`Session::next`].
pub enum Item {
    Event(Event),
    /// The core task returned (its result is included).
    Finished(Result<()>),
}

impl Session {
    /// Spawn the host core.
    pub fn start_host(cfg: HostConfig) -> Self {
        let (tx, rx) = mpsc::channel(EVENT_CAPACITY);
        let (ctrl_tx, ctrl_rx) = watch::channel(HostCommand::Run);
        let handle = tokio::spawn(netm_host::run(cfg, tx, ctrl_rx));
        Self {
            mode: Mode::Host,
            rx: Rx::Host(rx),
            ctrl: Some(Ctrl::Host(ctrl_tx)),
            handle: Some(handle),
            rx_closed: false,
            shutdown_requested: false,
        }
    }

    /// Spawn the guest core.
    pub fn start_guest(cfg: GuestConfig) -> Self {
        let (tx, rx) = mpsc::channel(EVENT_CAPACITY);
        let (ctrl_tx, ctrl_rx) = watch::channel(GuestCommand::Run);
        let handle = tokio::spawn(netm_guest::run(cfg, tx, ctrl_rx));
        Self {
            mode: Mode::Guest,
            rx: Rx::Guest(rx),
            ctrl: Some(Ctrl::Guest(ctrl_tx)),
            handle: Some(handle),
            rx_closed: false,
            shutdown_requested: false,
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    /// Wait for either the next event or the end of the core task. Once the
    /// event channel is closed only the task is awaited; once the task has
    /// returned this stays pending.
    pub async fn next(&mut self) -> Item {
        let Session {
            rx,
            handle,
            rx_closed,
            ..
        } = self;
        loop {
            if *rx_closed {
                return match handle.as_mut() {
                    Some(h) => {
                        let res = h.await;
                        *handle = None;
                        Item::Finished(flatten(res))
                    }
                    None => std::future::pending().await,
                };
            }
            tokio::select! {
                ev = recv_rx(rx) => match ev {
                    Some(ev) => return Item::Event(ev),
                    None => *rx_closed = true,
                },
                res = finished_handle(handle) => return Item::Finished(res),
            }
        }
    }

    /// Non-blocking variant of [`recv`](Self::recv).
    pub fn try_recv(&mut self) -> Option<Event> {
        match &mut self.rx {
            Rx::Host(rx) => rx.try_recv().ok().map(Event::Host),
            Rx::Guest(rx) => rx.try_recv().ok().map(Event::Guest),
        }
    }

    /// Ask the core to stop (idempotent). Dropping the sender also counts as
    /// `Shutdown` for the cores, so this never fails.
    pub fn request_shutdown(&mut self) {
        self.shutdown_requested = true;
        match self.ctrl.take() {
            Some(Ctrl::Host(tx)) => {
                let _ = tx.send(HostCommand::Shutdown);
                drop(tx);
            }
            Some(Ctrl::Guest(tx)) => {
                let _ = tx.send(GuestCommand::Shutdown);
                drop(tx);
            }
            None => {}
        }
    }

    /// Request shutdown and wait (bounded by [`SHUTDOWN_TIMEOUT`]) for the
    /// core to return, draining events meanwhile so the core never blocks
    /// on a full channel. Events are passed to `on_event`.
    pub async fn shutdown(mut self, mut on_event: impl FnMut(Event)) -> Result<()> {
        self.request_shutdown();
        let deadline = tokio::time::Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            tokio::select! {
                item = self.next() => match item {
                    Item::Event(ev) => on_event(ev),
                    Item::Finished(res) => return res,
                },
                _ = tokio::time::sleep_until(deadline) => {
                    if let Some(h) = self.handle.take() { h.abort(); }
                    return Err(anyhow!("core did not stop within {}s", SHUTDOWN_TIMEOUT.as_secs()));
                }
            }
        }
    }
}

async fn recv_rx(rx: &mut Rx) -> Option<Event> {
    match rx {
        Rx::Host(rx) => rx.recv().await.map(Event::Host),
        Rx::Guest(rx) => rx.recv().await.map(Event::Guest),
    }
}

async fn finished_handle(handle: &mut Option<JoinHandle<Result<()>>>) -> Result<()> {
    match handle.as_mut() {
        Some(h) => {
            let res = h.await;
            *handle = None;
            flatten(res)
        }
        None => std::future::pending().await,
    }
}

fn flatten(res: Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
    match res {
        Ok(r) => r,
        Err(e) if e.is_panic() => Err(anyhow!("core task panicked")),
        Err(_) => Err(anyhow!("core task was cancelled")),
    }
}

/// Severity of a log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

/// Translate an event into a Chinese log line (if it is worth logging).
/// `Stats` yield `None`.
pub fn describe(ev: &Event) -> Option<(Level, String)> {
    match ev {
        Event::Host(h) => describe_host(h),
        Event::Guest(g) => describe_guest(g),
    }
}

fn describe_host(ev: &HostEvent) -> Option<(Level, String)> {
    Some(match ev {
        HostEvent::Listening { addr } => (Level::Info, format!("开始监听 {addr}")),
        HostEvent::Interfaces(list) => {
            let ready: Vec<&str> = list
                .iter()
                .filter(|l| l.is_ready())
                .map(|l| l.name.as_str())
                .collect();
            (
                Level::Info,
                if ready.is_empty() {
                    format!("候选网卡 {} 个，尚无已连线的链路", list.len())
                } else {
                    format!("已连线链路：{}", ready.join(", "))
                },
            )
        }
        HostEvent::GuestConnected(g) => (
            Level::Info,
            format!(
                "客机 {} 已连接（{}），分配 {}",
                g.name, g.peer, g.assigned_ip
            ),
        ),
        HostEvent::GuestDisconnected { peer, reason } => {
            (Level::Warn, format!("客机 {peer} 已断开：{reason}"))
        }
        HostEvent::FlowOpened(_) | HostEvent::FlowClosed { .. } | HostEvent::Stats { .. } => {
            return None
        }
        HostEvent::Log(m) => (Level::Info, m.clone()),
        HostEvent::Error(m) => (Level::Error, m.clone()),
    })
}

fn describe_guest(ev: &GuestEvent) -> Option<(Level, String)> {
    Some(match ev {
        GuestEvent::StateChanged(s) => match s {
            GuestState::WaitingForLink => (Level::Info, "等待 Type-C 连接".into()),
            GuestState::Discovering { iface } => {
                (Level::Info, format!("在 {iface} 上发现宿主机中"))
            }
            GuestState::Connecting { host } => (Level::Info, format!("正在连接 {host}")),
            GuestState::Connected {
                host,
                host_name,
                tun,
                config,
                ..
            } => (
                Level::Info,
                format!(
                    "已连接宿主机 {host_name}（{host}），{tun} {}/{} 网关 {} DNS {} MTU {}",
                    config.guest_ip, config.prefix_len, config.gateway_ip, config.dns, config.mtu
                ),
            ),
            GuestState::Disconnected { reason } => (Level::Warn, format!("已断开：{reason}")),
        },
        GuestEvent::Interfaces(list) => {
            let ready: Vec<&str> = list
                .iter()
                .filter(|l| l.is_ready())
                .map(|l| l.name.as_str())
                .collect();
            (
                Level::Info,
                if ready.is_empty() {
                    format!("候选网卡 {} 个，尚未检测到线缆", list.len())
                } else {
                    format!("检测到线缆：{}", ready.join(", "))
                },
            )
        }
        GuestEvent::Stats { .. } => return None,
        GuestEvent::Log(m) => (Level::Info, m.clone()),
        GuestEvent::Error(m) => (Level::Error, m.clone()),
    })
}

/// Headless logging of an event via `tracing`. Stats are summarised at most
/// every two seconds and only when traffic flows.
pub struct HeadlessLogger {
    last_stats: std::time::Instant,
}

impl Default for HeadlessLogger {
    fn default() -> Self {
        Self {
            last_stats: std::time::Instant::now() - Duration::from_secs(10),
        }
    }
}

impl HeadlessLogger {
    pub fn log(&mut self, ev: &Event) {
        // The cores already emit `Log`/`Error` through `tracing`; repeating
        // them here would print every line twice.
        if matches!(
            ev,
            Event::Host(HostEvent::Log(_) | HostEvent::Error(_))
                | Event::Guest(GuestEvent::Log(_) | GuestEvent::Error(_))
        ) {
            return;
        }
        if let Some((level, msg)) = describe(ev) {
            match level {
                Level::Info => tracing::info!("{msg}"),
                Level::Warn => tracing::warn!("{msg}"),
                Level::Error => tracing::error!("{msg}"),
            }
            return;
        }
        let (counters, tx_bps, rx_bps, extra) = match ev {
            Event::Host(HostEvent::Stats {
                counters,
                tx_bps,
                rx_bps,
                active_flows,
            }) => (
                counters,
                *tx_bps,
                *rx_bps,
                format!(" 活跃流 {active_flows}"),
            ),
            Event::Guest(GuestEvent::Stats {
                counters,
                tx_bps,
                rx_bps,
            }) => (counters, *tx_bps, *rx_bps, String::new()),
            Event::Host(HostEvent::FlowOpened(f)) => {
                tracing::debug!("流 #{} {:?} {} -> {} 打开", f.id, f.proto, f.src, f.dst);
                return;
            }
            Event::Host(HostEvent::FlowClosed {
                id,
                tx_bytes,
                rx_bytes,
            }) => {
                tracing::debug!("流 #{id} 关闭 tx {tx_bytes} B rx {rx_bytes} B");
                return;
            }
            _ => return,
        };
        if self.last_stats.elapsed() >= Duration::from_secs(2) && (tx_bps > 0.0 || rx_bps > 0.0) {
            self.last_stats = std::time::Instant::now();
            tracing::info!(
                "速率 上行 {} 下行 {}（累计 tx {} B / rx {} B）{extra}",
                fmt_bps(tx_bps),
                fmt_bps(rx_bps),
                counters.tx_bytes,
                counters.rx_bytes
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn stats_are_not_described() {
        let ev = Event::Guest(GuestEvent::Stats {
            counters: Default::default(),
            tx_bps: 1.0,
            rx_bps: 2.0,
        });
        assert!(describe(&ev).is_none());
        let ev = Event::Host(HostEvent::Stats {
            counters: Default::default(),
            tx_bps: 1.0,
            rx_bps: 2.0,
            active_flows: 3,
        });
        assert!(describe(&ev).is_none());
    }

    #[test]
    fn guest_states_map_to_chinese_lines() {
        let (lvl, msg) = describe(&Event::Guest(GuestEvent::StateChanged(
            GuestState::WaitingForLink,
        )))
        .unwrap();
        assert_eq!(lvl, Level::Info);
        assert_eq!(msg, "等待 Type-C 连接");

        let (lvl, msg) = describe(&Event::Guest(GuestEvent::StateChanged(
            GuestState::Disconnected {
                reason: "host bye".into(),
            },
        )))
        .unwrap();
        assert_eq!(lvl, Level::Warn);
        assert!(msg.contains("host bye"));
    }

    #[test]
    fn host_events_map_to_chinese_lines() {
        let addr: SocketAddr = "[::]:27778".parse().unwrap();
        let (_, msg) = describe(&Event::Host(HostEvent::Listening { addr })).unwrap();
        assert!(msg.contains("27778"));
        let (lvl, msg) = describe(&Event::Host(HostEvent::GuestConnected(
            netm_host::GuestInfo {
                peer: addr,
                name: "mbp".into(),
                connected_at: std::time::Instant::now(),
                assigned_ip: Ipv4Addr::new(10, 77, 0, 2),
            },
        )))
        .unwrap();
        assert_eq!(lvl, Level::Info);
        assert!(msg.contains("mbp") && msg.contains("10.77.0.2"));
        let (lvl, _) = describe(&Event::Host(HostEvent::Error("x".into()))).unwrap();
        assert_eq!(lvl, Level::Error);
    }
}
