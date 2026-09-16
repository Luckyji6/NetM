//! Rendering of the three screens with ratatui.

use netm_guest::GuestState;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Sparkline, Table, Wrap,
};
use ratatui::Frame;

use super::app::{App, Screen};
use super::model::{
    age, guest_state_busy, guest_state_detail, guest_state_label, link_kind_label, proto_label,
    GuestModel, HostModel, LogBuffer, Throughput,
};
use crate::format::{fmt_bps, fmt_bytes};
use crate::session::Level;

const ACCENT: Color = Color::Cyan;
const OK: Color = Color::Green;
const WARN: Color = Color::Yellow;
const ERR: Color = Color::Red;
const DIM: Color = Color::DarkGray;

pub fn render(app: &App, frame: &mut Frame) {
    let area = frame.area();
    match &app.screen {
        Screen::Onboarding { selected } => render_onboarding(app, *selected, frame, area),
        Screen::Guest(m) => render_guest(app, m, frame, area),
        Screen::Host(m) => render_host(app, m, frame, area),
    }
    if app.show_help {
        render_help(app, frame, area);
    }
}

fn title_block<'a>(title: &'a str, footer: Line<'a>) -> Block<'a> {
    Block::bordered()
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                concat!("NetM v", env!("CARGO_PKG_VERSION")),
                Style::new().fg(ACCENT).bold(),
            ),
            Span::raw(format!(" · {title} ")),
        ]))
        .title_bottom(footer)
        .border_style(Style::new().fg(DIM))
}

fn key_hint<'a>(pairs: &[(&'a str, &'a str)]) -> Line<'a> {
    let mut spans = vec![Span::raw(" ")];
    for (i, (k, d)) in pairs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", Style::new()));
        }
        spans.push(Span::styled(*k, Style::new().fg(ACCENT).bold()));
        spans.push(Span::raw(format!(" {d}")));
    }
    spans.push(Span::raw(" "));
    Line::from(spans)
}

fn footer_line<'a>(app: &App) -> Line<'a> {
    if let Some(n) = &app.notice {
        return Line::from(vec![
            Span::raw(" "),
            Span::styled(n.clone(), Style::new().fg(WARN).bold()),
            Span::raw(" "),
        ]);
    }
    if app.log_focus {
        return key_hint(&[
            ("↑↓ PgUp PgDn", "滚动日志"),
            ("End", "跟随最新"),
            ("Esc/l", "退出日志"),
            ("q", "退出"),
        ]);
    }
    key_hint(&[
        ("q", "退出"),
        ("m", "切换模式"),
        ("l", "日志"),
        ("?", "帮助"),
    ])
}

// ---------------------------------------------------------------------------
// Onboarding
// ---------------------------------------------------------------------------

fn render_onboarding(app: &App, selected: usize, frame: &mut Frame, area: Rect) {
    let block = title_block(
        "首次配置",
        key_hint(&[("↑↓", "选择"), ("Enter", "确认"), ("q/Esc", "退出")]),
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [_, body, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(14),
        Constraint::Fill(1),
    ])
    .areas(inner);
    let body = body.centered_horizontally(Constraint::Max(72));

    let [title, desc, list_area, hint] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(4),
        Constraint::Length(4),
        Constraint::Length(3),
    ])
    .areas(body);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "NetM",
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        )))
        .alignment(Alignment::Center),
        title,
    );
    frame.render_widget(
        Paragraph::new(Text::from(vec![
            Line::from("用一根 Type-C（雷电 / USB4）线把一台电脑的网络借给另一台电脑。"),
            Line::from("两台机器各运行一个 netm：一台作为宿主机提供出口，另一台作为客机上网。"),
            Line::from(""),
            Line::from(Span::styled(
                "请选择这台电脑的角色（之后可按 m 随时切换）：",
                Style::new().fg(DIM),
            )),
        ]))
        .wrap(Wrap { trim: false })
        .alignment(Alignment::Left),
        desc,
    );

    let items = [
        ListItem::new(Line::from(vec![
            Span::styled("宿主机（服务端）", Style::new().bold()),
            Span::raw(" — 已接入网络，为客机提供出口"),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("客机", Style::new().bold()),
            Span::raw(" — 通过 Type-C 借用宿主机的网络（需要管理员权限）"),
        ])),
    ];
    let list = List::new(items)
        .highlight_style(Style::new().fg(Color::Black).bg(ACCENT))
        .highlight_symbol("▶ ");
    let mut state = ListState::default().with_selected(Some(selected));
    frame.render_stateful_widget(list, list_area, &mut state);

    let hint_text = format!("配置文件：{}", app.config_path.display());
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(hint_text, Style::new().fg(DIM))))
            .wrap(Wrap { trim: true }),
        hint,
    );
}

// ---------------------------------------------------------------------------
// Guest
// ---------------------------------------------------------------------------

fn render_guest(app: &App, m: &GuestModel, frame: &mut Frame, area: Rect) {
    let block = title_block("客机", footer_line(app));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let warning = m.egress_warning();
    let [status, banner, middle, thr, log] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(if warning.is_some() { 3 } else { 0 }),
        Constraint::Length(9),
        Constraint::Length(4),
        Constraint::Min(4),
    ])
    .areas(inner);

    render_guest_status(app, m, frame, status);
    if let Some(text) = warning {
        render_egress_warning(&text, frame, banner);
    }

    let [ifaces, conn] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(middle);
    render_interfaces(&m.interfaces, "链路网卡", "线缆", frame, ifaces);
    render_guest_connection(app, m, frame, conn);
    render_throughput(
        &m.throughput,
        "上行（客机 → 宿主机）",
        "下行（宿主机 → 客机）",
        frame,
        thr,
    );
    render_log(&app.log, app.log_focus, app.log_path.as_deref(), frame, log);
}

fn render_guest_status(app: &App, m: &GuestModel, frame: &mut Frame, area: Rect) {
    let (label, detail, color, spin) = if let Some(f) = &m.fatal {
        ("运行出错", Some(f.clone()), ERR, false)
    } else {
        let color = match &m.state {
            GuestState::Connected { .. } => OK,
            GuestState::Disconnected { .. } => WARN,
            _ => ACCENT,
        };
        (
            guest_state_label(&m.state),
            guest_state_detail(&m.state),
            color,
            guest_state_busy(&m.state),
        )
    };
    let mut spans = vec![Span::raw(" ")];
    if spin && !app.is_quitting() {
        spans.push(Span::styled(app.spinner(), Style::new().fg(color)));
        spans.push(Span::raw(" "));
    } else {
        spans.push(Span::styled("●", Style::new().fg(color)));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        label,
        Style::new().fg(color).add_modifier(Modifier::BOLD),
    ));
    if let Some(d) = detail {
        spans.push(Span::styled(format!("  {d}"), Style::new().fg(DIM)));
    }
    let block = Block::bordered()
        .title(" 状态 ")
        .border_style(Style::new().fg(color));
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

/// Banner shown after the tunnel went away, so the user is never left
/// guessing whether their machine still has network.
fn render_egress_warning(text: &str, frame: &mut Frame, area: Rect) {
    if area.height == 0 {
        return;
    }
    let block = Block::bordered()
        .title(" 注意 ")
        .border_style(Style::new().fg(WARN));
    let line = Line::from(vec![
        Span::raw(" "),
        Span::styled(text, Style::new().fg(WARN).add_modifier(Modifier::BOLD)),
    ]);
    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn render_interfaces(
    list: &[netm_proto::LinkInterface],
    title: &str,
    ready_col: &str,
    frame: &mut Frame,
    area: Rect,
) {
    let header = Row::new(["网卡", "类型", ready_col, "fe80 地址"])
        .style(Style::new().fg(DIM).add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = if list.is_empty() {
        vec![Row::new([
            Cell::from("（未发现候选网卡）").style(Style::new().fg(DIM)),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
        ])]
    } else {
        list.iter()
            .map(|l| {
                let ready = l.is_ready();
                let ready_cell = if ready {
                    Cell::from("是").style(Style::new().fg(OK))
                } else {
                    Cell::from("否").style(Style::new().fg(DIM))
                };
                let addr = l
                    .link_local_v6
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "-".into());
                Row::new([
                    Cell::from(l.name.clone()).style(if ready {
                        Style::new().bold()
                    } else {
                        Style::new()
                    }),
                    Cell::from(link_kind_label(l.kind)),
                    ready_cell,
                    Cell::from(addr).style(Style::new().fg(DIM)),
                ])
            })
            .collect()
    };
    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(5),
            Constraint::Fill(1),
        ],
    )
    .header(header)
    .block(
        Block::bordered()
            .title(format!(" {title} "))
            .border_style(Style::new().fg(DIM)),
    );
    frame.render_widget(table, area);
}

fn kv_lines<'a>(pairs: &[(String, String)]) -> Vec<Line<'a>> {
    let width = pairs
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    pairs
        .iter()
        .map(|(k, v)| {
            let pad = width - k.chars().count();
            Line::from(vec![
                Span::styled(format!(" {}{} ", k, "　".repeat(pad)), Style::new().fg(DIM)),
                Span::raw(v.clone()),
            ])
        })
        .collect()
}

fn render_guest_connection(app: &App, m: &GuestModel, frame: &mut Frame, area: Rect) {
    let mut pairs: Vec<(String, String)> = Vec::new();
    match &m.state {
        GuestState::Connected {
            host,
            host_name,
            tun,
            config,
            since,
        } => {
            pairs.push(("宿主机".into(), format!("{host_name}  {host}")));
            pairs.push(("TUN".into(), tun.clone()));
            pairs.push((
                "虚拟 IP".into(),
                format!("{}/{}", config.guest_ip, config.prefix_len),
            ));
            pairs.push((
                "网关 / DNS".into(),
                format!("{} / {}", config.gateway_ip, config.dns),
            ));
            pairs.push(("MTU".into(), config.mtu.to_string()));
            pairs.push(("已连接".into(), age(*since)));
            if let Some(s) = m.link_speed {
                pairs.push((
                    "线路".into(),
                    format!(
                        "↑ {}  ↓ {}",
                        crate::format::fmt_bps(s.up_bps),
                        crate::format::fmt_bps(s.down_bps)
                    ),
                ));
            }
            for (k, v) in &app.guest_summary {
                if k == "路由" || k == "系统 DNS" {
                    pairs.push((k.clone(), v.clone()));
                }
            }
        }
        _ => {
            pairs.extend(app.guest_summary.iter().cloned());
            pairs.push(("虚拟 IP".into(), "-".into()));
            pairs.push(("TUN".into(), "-".into()));
        }
    }
    let block = Block::bordered()
        .title(" 连接信息 ")
        .border_style(Style::new().fg(DIM));
    frame.render_widget(
        Paragraph::new(Text::from(kv_lines(&pairs))).block(block),
        area,
    );
}

// ---------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------

fn render_host(app: &App, m: &HostModel, frame: &mut Frame, area: Rect) {
    let block = title_block("宿主机", footer_line(app));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [header, middle, thr, log] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(10),
        Constraint::Length(4),
        Constraint::Min(4),
    ])
    .areas(inner);

    render_host_header(app, m, frame, header);
    let [guest, flows] =
        Layout::horizontal([Constraint::Length(44), Constraint::Fill(1)]).areas(middle);
    render_host_guest(m, frame, guest);
    render_flows(m, frame, flows);
    render_throughput(
        &m.throughput,
        "下发（宿主机 → 客机）",
        "上收（客机 → 宿主机）",
        frame,
        thr,
    );
    render_log(&app.log, app.log_focus, app.log_path.as_deref(), frame, log);
}

fn render_host_header(app: &App, m: &HostModel, frame: &mut Frame, area: Rect) {
    let (color, status) = if let Some(f) = &m.fatal {
        (ERR, format!("运行出错：{f}"))
    } else if let Some(a) = m.listening {
        (OK, format!("监听 {a}"))
    } else {
        (ACCENT, "正在启动…".to_string())
    };
    let mut first = vec![Span::raw(" ")];
    if m.listening.is_none() && m.fatal.is_none() && !app.is_quitting() {
        first.push(Span::styled(app.spinner(), Style::new().fg(color)));
    } else {
        first.push(Span::styled("●", Style::new().fg(color)));
    }
    first.push(Span::raw(" "));
    first.push(Span::styled(status, Style::new().fg(color).bold()));
    first.push(Span::styled(
        format!("   主机名 {}", m.host_name),
        Style::new().fg(DIM),
    ));

    let mut second = vec![Span::styled(" 链路 ", Style::new().fg(DIM))];
    if m.interfaces.is_empty() && m.serial_state.is_none() {
        second.push(Span::styled("（未发现候选网卡）", Style::new().fg(DIM)));
    }
    for (i, l) in m.interfaces.iter().enumerate() {
        if i > 0 {
            second.push(Span::raw("  "));
        }
        let ready = l.is_ready();
        second.push(Span::styled(
            l.name.clone(),
            if ready {
                Style::new().fg(OK).bold()
            } else {
                Style::new().fg(DIM)
            },
        ));
        second.push(Span::styled(
            format!("({})", if ready { "已连线" } else { "未连线" }),
            Style::new().fg(if ready { OK } else { DIM }),
        ));
    }
    if let Some((path, open)) = &m.serial_state {
        if !m.interfaces.is_empty() {
            second.push(Span::raw("  "));
        }
        second.push(Span::styled(
            format!("串口 {path}"),
            if *open {
                Style::new().fg(OK).bold()
            } else {
                Style::new().fg(DIM)
            },
        ));
        second.push(Span::styled(
            format!("({})", if *open { "已打开" } else { "已关闭" }),
            Style::new().fg(if *open { OK } else { DIM }),
        ));
    }
    let block = Block::bordered()
        .title(" 状态 ")
        .border_style(Style::new().fg(color));
    frame.render_widget(
        Paragraph::new(Text::from(vec![Line::from(first), Line::from(second)])).block(block),
        area,
    );
}

fn render_host_guest(m: &HostModel, frame: &mut Frame, area: Rect) {
    let (color, pairs): (Color, Vec<(String, String)>) = match &m.guest {
        Some(g) => {
            let mut pairs = vec![
                ("状态".into(), "已连接".into()),
                ("名称".into(), g.name.clone()),
                ("对端".into(), g.peer.to_string()),
                ("分配 IP".into(), g.assigned_ip.to_string()),
                ("连接时长".into(), age(g.connected_at)),
            ];
            if let Some(s) = m.link_speed {
                pairs.push((
                    "线路".into(),
                    format!(
                        "↑ {}  ↓ {}",
                        crate::format::fmt_bps(s.up_bps),
                        crate::format::fmt_bps(s.down_bps)
                    ),
                ));
            }
            (OK, pairs)
        }
        None => {
            let mut p = vec![("状态".into(), "等待客机连接".into())];
            if let Some(r) = &m.last_disconnect {
                p.push(("上次断开".into(), r.clone()));
            }
            (DIM, p)
        }
    };
    let block = Block::bordered()
        .title(" 客机 ")
        .border_style(Style::new().fg(color));
    frame.render_widget(
        Paragraph::new(Text::from(kv_lines(&pairs)))
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

fn render_flows(m: &HostModel, frame: &mut Frame, area: Rect) {
    let header = Row::new(["协议", "源端口", "目标", "时长"])
        .style(Style::new().fg(DIM).add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = m
        .flows
        .active()
        .map(|f| {
            Row::new([
                Cell::from(proto_label(&f.proto)),
                Cell::from(f.src.port().to_string()),
                Cell::from(f.dst.to_string()),
                Cell::from(age(f.opened_at)).style(Style::new().fg(DIM)),
            ])
        })
        .collect();
    let title = format!(
        " 活跃连接 {}   已关闭 {}   累计 {} ",
        m.flows.active_len(),
        m.flows.closed_count,
        fmt_bytes(m.flows.total_bytes())
    );
    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Fill(1),
            Constraint::Length(9),
        ],
    )
    .header(header)
    .block(
        Block::bordered()
            .title(title)
            .border_style(Style::new().fg(DIM)),
    );
    frame.render_widget(table, area);
}

// ---------------------------------------------------------------------------
// Shared panels
// ---------------------------------------------------------------------------

fn render_throughput(
    t: &Throughput,
    tx_label: &str,
    rx_label: &str,
    frame: &mut Frame,
    area: Rect,
) {
    let block = Block::bordered()
        .title(" 吞吐 ")
        .border_style(Style::new().fg(DIM));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [tx, rx] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(inner);
    render_rate(
        "↑",
        tx_label,
        t.tx_bps,
        t.counters.tx_bytes,
        t.tx_history(),
        frame,
        tx,
    );
    render_rate(
        "↓",
        rx_label,
        t.rx_bps,
        t.counters.rx_bytes,
        t.rx_history(),
        frame,
        rx,
    );
}

fn render_rate(
    arrow: &str,
    label: &str,
    bps: f64,
    total: u64,
    hist: &std::collections::VecDeque<u64>,
    frame: &mut Frame,
    area: Rect,
) {
    let [text, spark] =
        Layout::horizontal([Constraint::Length(34), Constraint::Fill(1)]).areas(area);
    let lines = vec![
        Line::from(vec![
            Span::styled(format!(" {arrow} "), Style::new().fg(ACCENT).bold()),
            Span::styled(fmt_bps(bps), Style::new().bold()),
        ]),
        Line::from(vec![
            Span::styled(format!("   {label} "), Style::new().fg(DIM)),
            Span::styled(format!("累计 {}", fmt_bytes(total)), Style::new().fg(DIM)),
        ]),
    ];
    frame.render_widget(Paragraph::new(Text::from(lines)), text);
    let width = spark.width as usize;
    let data: Vec<u64> = hist.iter().rev().take(width).rev().copied().collect();
    frame.render_widget(
        Sparkline::default()
            .data(&data)
            .style(Style::new().fg(ACCENT)),
        spark,
    );
}

fn render_log(
    log: &LogBuffer,
    focused: bool,
    path: Option<&std::path::Path>,
    frame: &mut Frame,
    area: Rect,
) {
    let mut title = String::from(" 日志 ");
    if focused {
        title.push_str(&format!("[滚动 ↑{}] ", log.scroll_up()));
    }
    let block = Block::bordered()
        .title(title)
        .title_bottom(
            path.map(|p| {
                Line::from(Span::styled(
                    format!(" {} ", p.display()),
                    Style::new().fg(DIM),
                ))
                .right_aligned()
            })
            .unwrap_or_default(),
        )
        .border_style(Style::new().fg(if focused { ACCENT } else { DIM }));
    let inner = block.inner(area);
    let rows = inner.height as usize;
    let lines: Vec<Line> = log
        .visible(rows)
        .map(|l| {
            let color = match l.level {
                Level::Info => Color::Reset,
                Level::Warn => WARN,
                Level::Error => ERR,
            };
            Line::from(vec![
                Span::styled(format!(" {} ", l.time), Style::new().fg(DIM)),
                Span::styled(l.msg.clone(), Style::new().fg(color)),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(Text::from(lines)).block(block), area);
}

fn render_help(app: &App, frame: &mut Frame, area: Rect) {
    let popup = area.centered(Constraint::Length(56), Constraint::Length(14));
    frame.render_widget(Clear, popup);
    let keys: &[(&str, &str)] = match app.screen {
        Screen::Onboarding { .. } => &[
            ("↑ / ↓", "选择角色"),
            ("Enter", "确认并保存为默认模式"),
            ("q / Esc", "退出"),
        ],
        _ => &[
            ("q / Ctrl-C", "退出（先清理路由、DNS 与 TUN）"),
            ("m", "切换宿主机 / 客机，并保存为默认"),
            ("l", "进入日志滚动；↑↓ PgUp PgDn End，Esc 退出"),
            ("?", "显示 / 关闭本帮助"),
        ],
    };
    let mut lines: Vec<Line> = keys
        .iter()
        .map(|(k, d)| {
            Line::from(vec![
                Span::styled(format!(" {k:<12}"), Style::new().fg(ACCENT).bold()),
                Span::raw(*d),
            ])
        })
        .collect();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " 终端关闭（SIGHUP）、SIGTERM 同样会触发完整清理。",
        Style::new().fg(DIM),
    )));
    lines.push(Line::from(Span::styled(
        format!(" 配置：{}", app.config_path.display()),
        Style::new().fg(DIM),
    )));
    if let Some(p) = &app.log_path {
        lines.push(Line::from(Span::styled(
            format!(" 日志：{}", p.display()),
            Style::new().fg(DIM),
        )));
    }
    let block = Block::bordered()
        .title(" 帮助（按任意键关闭） ")
        .border_style(Style::new().fg(ACCENT));
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .wrap(Wrap { trim: false })
            .block(block),
        popup,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{GuestArgs, HostArgs};
    use crate::config::Config;
    use crate::session::Level;
    use crate::tui::model::{GuestModel, HostModel};
    use netm_host::{FlowInfo, GuestInfo, Proto};
    use netm_proto::{LinkInterface, LinkKind};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::time::Instant;

    fn app() -> App {
        App::new(
            Config::default(),
            "/tmp/netm-view-test/config.toml".into(),
            Some("/tmp/netm-view-test/netm.log".into()),
            HostArgs::default(),
            GuestArgs::default(),
        )
    }

    /// Wide (CJK) glyphs leave a blank trailing cell, so compare with all
    /// spaces removed.
    fn has(screen: &str, needle: &str) -> bool {
        screen.replace(' ', "").contains(&needle.replace(' ', ""))
    }

    fn draw(app: &App, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| render(app, f)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn ifaces() -> Vec<LinkInterface> {
        vec![
            LinkInterface {
                name: "bridge0".into(),
                index: 20,
                is_up: true,
                link_local_v6: Some("fe80::1".parse().unwrap()),
                kind: LinkKind::ThunderboltBridge,
            },
            LinkInterface {
                name: "en1".into(),
                index: 10,
                is_up: true,
                link_local_v6: None,
                kind: LinkKind::Thunderbolt,
            },
        ]
    }

    #[test]
    fn onboarding_renders_both_roles() {
        let mut a = app();
        a.start(crate::tui::Start::Onboarding);
        let s = draw(&a, 100, 30);
        assert!(has(&s, concat!("NetM v", env!("CARGO_PKG_VERSION"))));
        assert!(has(&s, "宿主机（服务端）"));
        assert!(has(&s, "客机"));
        assert!(has(&s, "Enter"));
        // Tiny terminals must not panic.
        let _ = draw(&a, 20, 5);
    }

    #[test]
    fn guest_screen_renders_states() {
        let mut a = app();
        a.screen = Screen::Guest(GuestModel {
            interfaces: ifaces(),
            ..GuestModel::default()
        });
        a.log.push(Level::Info, "hello");
        let s = draw(&a, 120, 40);
        assert!(has(&s, "等待 Type-C 连接"));
        assert!(has(&s, "bridge0"));
        assert!(has(&s, "雷电网桥"));
        assert!(has(&s, "fe80::1"));
        assert!(has(&s, "hello"));

        if let Screen::Guest(m) = &mut a.screen {
            m.state = GuestState::Connected {
                host: netm_proto::Endpoint::Tcp("[fe80::1%20]:27778".parse().unwrap()),
                host_name: "mac-host".into(),
                tun: "utun4".into(),
                config: Default::default(),
                since: Instant::now(),
            };
            m.throughput
                .push(Default::default(), 1_500_000.0, 3_000_000.0);
        }
        a.show_help = true;
        let s = draw(&a, 120, 40);
        assert!(has(&s, "已连接"));
        assert!(has(&s, "mac-host"));
        assert!(has(&s, "utun4"));
        assert!(has(&s, "10.77.0.2/24"));
        assert!(has(&s, "1.50 Mbit/s"));
        assert!(has(&s, "帮助"));
        let _ = draw(&a, 30, 8);
    }

    #[test]
    fn host_screen_renders_guest_and_flows() {
        let mut a = app();
        let mut m = HostModel::new("mac".into());
        m.listening = Some("[::]:27778".parse().unwrap());
        m.interfaces = ifaces();
        m.guest = Some(GuestInfo {
            peer: netm_proto::Endpoint::Tcp("[fe80::2%20]:50000".parse().unwrap()),
            name: "win-guest".into(),
            connected_at: Instant::now(),
            assigned_ip: "10.77.0.2".parse().unwrap(),
        });
        m.flows.open(FlowInfo {
            id: 1,
            proto: Proto::Tcp,
            src: "10.77.0.2:51000".parse().unwrap(),
            dst: "1.1.1.1:443".parse().unwrap(),
            tx_bytes: 0,
            rx_bytes: 0,
            opened_at: Instant::now(),
        });
        m.flows.close(2, 1024, 2048);
        a.screen = Screen::Host(m);
        a.log_focus = true;
        let s = draw(&a, 120, 40);
        assert!(has(&s, "监听 [::]:27778"));
        assert!(has(&s, "win-guest"));
        assert!(has(&s, "1.1.1.1:443"));
        assert!(has(&s, "TCP"));
        assert!(has(&s, "51000"));
        assert!(has(&s, "已关闭 1"));
        assert!(has(&s, "3.0 KiB"));
        assert!(has(&s, "已连线"));
        let _ = draw(&a, 30, 8);
    }
}
