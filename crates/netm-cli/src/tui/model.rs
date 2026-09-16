//! Pure, renderer-independent state of the TUI screens. Everything here is
//! plain data updated from core events so it can be unit tested without a
//! terminal.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::Instant;

use netm_guest::{GuestEvent, GuestState};
use netm_host::{FlowInfo, HostEvent, Proto};
use netm_proto::{Counters, LinkInterface};

use crate::format::now_hms;
use crate::session::Level;

/// Number of throughput samples kept for the sparkline.
pub const SPARK_SAMPLES: usize = 60;
/// Maximum log lines kept.
pub const LOG_CAPACITY: usize = 500;

/// One line in the log panel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogLine {
    pub time: String,
    pub level: Level,
    pub msg: String,
}

/// Bounded log buffer with an optional manual scroll position.
#[derive(Debug, Default)]
pub struct LogBuffer {
    lines: VecDeque<LogLine>,
    /// `None` = follow the tail; `Some(offset)` = number of lines scrolled up
    /// from the tail.
    scroll_up: Option<usize>,
}

impl LogBuffer {
    pub fn push(&mut self, level: Level, msg: impl Into<String>) {
        if self.lines.len() == LOG_CAPACITY {
            self.lines.pop_front();
            if let Some(s) = self.scroll_up.as_mut() {
                *s = s.saturating_sub(1);
            }
        }
        self.lines.push_back(LogLine {
            time: now_hms(),
            level,
            msg: msg.into(),
        });
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Lines scrolled up from the tail (0 when following).
    pub fn scroll_up(&self) -> usize {
        self.scroll_up.unwrap_or(0)
    }

    pub fn scroll(&mut self, delta: isize) {
        let max = self.lines.len().saturating_sub(1);
        let cur = self.scroll_up.unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, max as isize) as usize;
        self.scroll_up = if next == 0 { None } else { Some(next) };
    }

    pub fn follow(&mut self) {
        self.scroll_up = None;
    }

    /// The `n` lines visible when the panel shows `n` rows, honouring the
    /// scroll offset.
    pub fn visible(&self, n: usize) -> impl Iterator<Item = &LogLine> {
        let total = self.lines.len();
        let end = total.saturating_sub(self.scroll_up());
        let start = end.saturating_sub(n);
        self.lines.range(start..end)
    }
}

/// Sliding window of throughput samples plus the latest snapshot.
#[derive(Debug, Default)]
pub struct Throughput {
    pub tx_bps: f64,
    pub rx_bps: f64,
    pub counters: Counters,
    tx_hist: VecDeque<u64>,
    rx_hist: VecDeque<u64>,
}

impl Throughput {
    pub fn push(&mut self, counters: Counters, tx_bps: f64, rx_bps: f64) {
        self.counters = counters;
        self.tx_bps = tx_bps;
        self.rx_bps = rx_bps;
        push_sample(&mut self.tx_hist, tx_bps as u64);
        push_sample(&mut self.rx_hist, rx_bps as u64);
    }

    pub fn tx_history(&self) -> &VecDeque<u64> {
        &self.tx_hist
    }

    pub fn rx_history(&self) -> &VecDeque<u64> {
        &self.rx_hist
    }

    /// Reset the instantaneous rates (e.g. after a disconnect) while keeping
    /// the history.
    pub fn idle(&mut self) {
        self.tx_bps = 0.0;
        self.rx_bps = 0.0;
    }
}

fn push_sample(hist: &mut VecDeque<u64>, v: u64) {
    if hist.len() == SPARK_SAMPLES {
        hist.pop_front();
    }
    hist.push_back(v);
}

/// Chinese label of a guest state.
pub fn guest_state_label(state: &GuestState) -> &'static str {
    match state {
        GuestState::WaitingForLink => "等待 Type-C 连接",
        GuestState::Discovering { .. } => "发现宿主机中",
        GuestState::Connecting { .. } => "正在连接",
        GuestState::Connected { .. } => "已连接",
        GuestState::Disconnected { .. } => "已断开",
    }
}

/// Extra detail shown next to the state label.
pub fn guest_state_detail(state: &GuestState) -> Option<String> {
    match state {
        GuestState::WaitingForLink => None,
        GuestState::Discovering { iface } => Some(format!("网卡 {iface}")),
        GuestState::Connecting { host } => Some(host.to_string()),
        GuestState::Connected { host_name, .. } => Some(host_name.clone()),
        GuestState::Disconnected { reason } => Some(reason.clone()),
    }
}

/// Whether the state is transient and deserves a spinner.
pub fn guest_state_busy(state: &GuestState) -> bool {
    matches!(
        state,
        GuestState::WaitingForLink | GuestState::Discovering { .. } | GuestState::Connecting { .. }
    )
}

/// Chinese label of a link kind.
pub fn link_kind_label(kind: netm_proto::LinkKind) -> &'static str {
    use netm_proto::LinkKind::*;
    match kind {
        ThunderboltBridge => "雷电网桥",
        Thunderbolt => "雷电口",
        UsbEthernet => "USB 网卡",
        Other => "其他",
    }
}

/// State of the guest screen.
#[derive(Debug)]
pub struct GuestModel {
    pub state: GuestState,
    pub interfaces: Vec<LinkInterface>,
    pub throughput: Throughput,
    /// Set when `run` returned an error.
    pub fatal: Option<String>,
}

impl Default for GuestModel {
    fn default() -> Self {
        Self {
            state: GuestState::WaitingForLink,
            interfaces: Vec::new(),
            throughput: Throughput::default(),
            fatal: None,
        }
    }
}

impl GuestModel {
    /// Apply an event; returns `true` if the screen should be redrawn.
    pub fn apply(&mut self, ev: &GuestEvent) -> bool {
        match ev {
            GuestEvent::StateChanged(s) => {
                if !matches!(s, GuestState::Connected { .. }) {
                    self.throughput.idle();
                }
                self.state = s.clone();
            }
            GuestEvent::Interfaces(list) => self.interfaces = list.clone(),
            GuestEvent::Stats {
                counters,
                tx_bps,
                rx_bps,
            } => self.throughput.push(*counters, *tx_bps, *rx_bps),
            GuestEvent::Log(_) | GuestEvent::Error(_) => {}
        }
        true
    }
}

/// Aggregate state of the host's flows.
#[derive(Debug, Default)]
pub struct FlowTable {
    active: BTreeMap<u64, FlowInfo>,
    pub closed_count: u64,
    pub closed_tx_bytes: u64,
    pub closed_rx_bytes: u64,
}

impl FlowTable {
    pub fn open(&mut self, f: FlowInfo) {
        self.active.insert(f.id, f);
    }

    /// Returns `true` when the flow was known.
    pub fn close(&mut self, id: u64, tx_bytes: u64, rx_bytes: u64) -> bool {
        let known = self.active.remove(&id).is_some();
        self.closed_count += 1;
        self.closed_tx_bytes += tx_bytes;
        self.closed_rx_bytes += rx_bytes;
        known
    }

    pub fn clear_active(&mut self) {
        self.active.clear();
    }

    pub fn active_len(&self) -> usize {
        self.active.len()
    }

    /// Active flows, newest first.
    pub fn active(&self) -> impl Iterator<Item = &FlowInfo> {
        self.active.values().rev()
    }

    pub fn total_bytes(&self) -> u64 {
        self.closed_tx_bytes + self.closed_rx_bytes
    }
}

/// Short protocol label.
pub fn proto_label(p: &Proto) -> &'static str {
    match p {
        Proto::Tcp => "TCP",
        Proto::Udp => "UDP",
    }
}

/// State of the host dashboard.
#[derive(Debug, Default)]
pub struct HostModel {
    pub listening: Option<SocketAddr>,
    pub host_name: String,
    pub interfaces: Vec<LinkInterface>,
    pub guest: Option<netm_host::GuestInfo>,
    pub last_disconnect: Option<String>,
    pub flows: FlowTable,
    pub throughput: Throughput,
    pub active_flows_reported: usize,
    pub fatal: Option<String>,
}

impl HostModel {
    pub fn new(host_name: String) -> Self {
        Self {
            host_name,
            ..Self::default()
        }
    }

    /// Apply an event; returns `true` if the screen should be redrawn.
    pub fn apply(&mut self, ev: &HostEvent) -> bool {
        match ev {
            HostEvent::Listening { addr } => self.listening = Some(*addr),
            HostEvent::Interfaces(list) => self.interfaces = list.clone(),
            HostEvent::GuestConnected(g) => {
                self.guest = Some(g.clone());
                self.last_disconnect = None;
                self.flows.clear_active();
            }
            HostEvent::GuestDisconnected { reason, .. } => {
                self.guest = None;
                self.last_disconnect = Some(reason.clone());
                self.flows.clear_active();
                self.throughput.idle();
            }
            HostEvent::FlowOpened(f) => self.flows.open(f.clone()),
            HostEvent::FlowClosed {
                id,
                tx_bytes,
                rx_bytes,
            } => {
                self.flows.close(*id, *tx_bytes, *rx_bytes);
            }
            HostEvent::Stats {
                counters,
                tx_bps,
                rx_bps,
                active_flows,
            } => {
                self.throughput.push(*counters, *tx_bps, *rx_bps);
                self.active_flows_reported = *active_flows;
            }
            HostEvent::Log(_) | HostEvent::Error(_) => {}
        }
        true
    }
}

/// Age of an [`Instant`] as a short string.
pub fn age(since: Instant) -> String {
    crate::format::fmt_duration(since.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn flow(id: u64, proto: Proto) -> FlowInfo {
        FlowInfo {
            id,
            proto,
            src: "10.77.0.2:50000".parse().unwrap(),
            dst: "1.1.1.1:443".parse().unwrap(),
            tx_bytes: 0,
            rx_bytes: 0,
            opened_at: Instant::now(),
        }
    }

    #[test]
    fn flow_table_tracks_open_close_and_totals() {
        let mut t = FlowTable::default();
        t.open(flow(1, Proto::Tcp));
        t.open(flow(2, Proto::Udp));
        assert_eq!(t.active_len(), 2);
        // Newest first.
        let ids: Vec<u64> = t.active().map(|f| f.id).collect();
        assert_eq!(ids, vec![2, 1]);

        assert!(t.close(1, 100, 200));
        assert_eq!(t.active_len(), 1);
        assert_eq!(t.closed_count, 1);
        assert_eq!(t.total_bytes(), 300);

        // Closing an unknown flow still counts bytes but reports unknown.
        assert!(!t.close(99, 1, 1));
        assert_eq!(t.closed_count, 2);
        assert_eq!(t.total_bytes(), 302);

        t.clear_active();
        assert_eq!(t.active_len(), 0);
    }

    #[test]
    fn host_model_applies_events() {
        let mut m = HostModel::new("mac".into());
        let addr: SocketAddr = "[::]:27778".parse().unwrap();
        m.apply(&HostEvent::Listening { addr });
        assert_eq!(m.listening, Some(addr));

        let peer: SocketAddr = "[fe80::1]:5000".parse().unwrap();
        m.apply(&HostEvent::GuestConnected(netm_host::GuestInfo {
            peer,
            name: "win".into(),
            connected_at: Instant::now(),
            assigned_ip: Ipv4Addr::new(10, 77, 0, 2),
        }));
        assert!(m.guest.is_some());
        m.apply(&HostEvent::FlowOpened(flow(7, Proto::Tcp)));
        assert_eq!(m.flows.active_len(), 1);
        m.apply(&HostEvent::FlowClosed {
            id: 7,
            tx_bytes: 10,
            rx_bytes: 20,
        });
        assert_eq!(m.flows.active_len(), 0);
        assert_eq!(m.flows.total_bytes(), 30);

        m.apply(&HostEvent::FlowOpened(flow(8, Proto::Udp)));
        m.apply(&HostEvent::GuestDisconnected {
            peer,
            reason: "bye".into(),
        });
        assert!(m.guest.is_none());
        assert_eq!(m.last_disconnect.as_deref(), Some("bye"));
        assert_eq!(
            m.flows.active_len(),
            0,
            "active flows cleared on disconnect"
        );

        m.apply(&HostEvent::Stats {
            counters: Counters::default(),
            tx_bps: 8000.0,
            rx_bps: 16000.0,
            active_flows: 3,
        });
        assert_eq!(m.active_flows_reported, 3);
        assert_eq!(m.throughput.tx_history().back(), Some(&8000));
    }

    #[test]
    fn guest_state_labels() {
        assert_eq!(
            guest_state_label(&GuestState::WaitingForLink),
            "等待 Type-C 连接"
        );
        assert_eq!(
            guest_state_label(&GuestState::Discovering {
                iface: "bridge0".into()
            }),
            "发现宿主机中"
        );
        let host: SocketAddr = "[fe80::1%5]:27778".parse().unwrap();
        assert_eq!(
            guest_state_label(&GuestState::Connecting { host }),
            "正在连接"
        );
        let connected = GuestState::Connected {
            host,
            host_name: "mac".into(),
            tun: "utun4".into(),
            config: Default::default(),
            since: Instant::now(),
        };
        assert_eq!(guest_state_label(&connected), "已连接");
        assert_eq!(guest_state_detail(&connected).as_deref(), Some("mac"));
        assert!(!guest_state_busy(&connected));
        assert!(guest_state_busy(&GuestState::WaitingForLink));
        assert_eq!(
            guest_state_label(&GuestState::Disconnected { reason: "x".into() }),
            "已断开"
        );
    }

    #[test]
    fn guest_model_resets_rates_when_leaving_connected() {
        let mut m = GuestModel::default();
        m.apply(&GuestEvent::Stats {
            counters: Counters::default(),
            tx_bps: 100.0,
            rx_bps: 200.0,
        });
        assert_eq!(m.throughput.tx_bps, 100.0);
        m.apply(&GuestEvent::StateChanged(GuestState::Disconnected {
            reason: "cable".into(),
        }));
        assert_eq!(m.throughput.tx_bps, 0.0);
        assert_eq!(m.throughput.tx_history().len(), 1, "history is kept");
    }

    #[test]
    fn throughput_window_is_bounded() {
        let mut t = Throughput::default();
        for i in 0..(SPARK_SAMPLES as u64 + 10) {
            t.push(Counters::default(), i as f64, 0.0);
        }
        assert_eq!(t.tx_history().len(), SPARK_SAMPLES);
        assert_eq!(*t.tx_history().front().unwrap(), 10);
    }

    #[test]
    fn log_buffer_scroll_and_visible() {
        let mut l = LogBuffer::default();
        for i in 0..10 {
            l.push(Level::Info, format!("line {i}"));
        }
        let tail: Vec<&str> = l.visible(3).map(|x| x.msg.as_str()).collect();
        assert_eq!(tail, vec!["line 7", "line 8", "line 9"]);

        l.scroll(2);
        assert_eq!(l.scroll_up(), 2);
        let v: Vec<&str> = l.visible(3).map(|x| x.msg.as_str()).collect();
        assert_eq!(v, vec!["line 5", "line 6", "line 7"]);

        l.scroll(100);
        assert_eq!(l.scroll_up(), 9);
        l.scroll(-100);
        assert_eq!(l.scroll_up(), 0);

        l.scroll(3);
        l.follow();
        assert_eq!(l.scroll_up(), 0);

        for i in 10..(LOG_CAPACITY + 20) {
            l.push(Level::Warn, format!("line {i}"));
        }
        assert_eq!(l.len(), LOG_CAPACITY);
    }
}
