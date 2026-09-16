//! Terminal UI: alternate screen + raw mode, redraw on input/core events or
//! every 100 ms, graceful shutdown on `q`, Ctrl-C, SIGINT/SIGTERM/SIGHUP.
//!
//! The shutdown path never depends on the terminal being alive: draw errors
//! are ignored, a closed input stream is treated like a quit request, and
//! the session is stopped (with cleanup) before the function returns even
//! if the render loop panics.

pub mod app;
pub mod model;
pub mod view;

use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{Event as TermEvent, EventStream};
use futures::{FutureExt, StreamExt};

pub use app::{App, Outcome, Start};

use crate::session::Item;

const TICK: Duration = Duration::from_millis(100);

/// Run the TUI until the user quits or a `sudo` re-exec is required.
/// Returns the outcome plus every core error seen (to be printed after the
/// terminal is restored).
pub async fn run(mut app: App, start: Start) -> Result<(Outcome, Vec<String>)> {
    // ratatui installs a panic hook that restores the terminal first.
    let mut terminal =
        ratatui::try_init().context("无法初始化终端界面（非交互终端请使用 --headless）")?;
    app.start(start);

    let outcome = {
        let looped = std::panic::AssertUnwindSafe(event_loop(&mut app, &mut terminal));
        match looped.catch_unwind().await {
            Ok(o) => o,
            Err(_) => {
                // The panic hook already restored the terminal; make sure the
                // core is still torn down.
                Outcome::Quit
            }
        }
    };
    let _ = ratatui::try_restore();

    // If the loop ended with a live session (panic or watchdog), stop it now.
    if let Some(session) = app.session.take() {
        let _ = session.shutdown(|_| {}).await;
    }
    Ok((outcome, app.run_errors))
}

async fn event_loop(app: &mut App, terminal: &mut ratatui::DefaultTerminal) -> Outcome {
    let mut input = EventStream::new();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut signal = std::pin::pin!(crate::signals::wait_for_signal().fuse());
    let mut input_closed = false;

    loop {
        if let Some(o) = app.take_outcome() {
            return o;
        }
        if app.dirty {
            // Draw failures (terminal gone) must not stop the shutdown path.
            let _ = terminal.draw(|f| view::render(app, f));
            app.dirty = false;
        }

        tokio::select! {
            ev = input.next(), if !input_closed => match ev {
                Some(Ok(TermEvent::Key(k))) => app.on_key(k),
                Some(Ok(TermEvent::Resize(_, _))) => app.dirty = true,
                Some(Ok(_)) => {}
                Some(Err(_)) | None => {
                    input_closed = true;
                    app.request_quit("终端输入已关闭");
                }
            },
            _ = tick.tick() => app.on_tick(),
            item = next_item(&mut app.session) => match item {
                Item::Event(ev) => {
                    app.on_event(ev);
                    // Coalesce bursts so a flood of events is one redraw.
                    for _ in 0..256 {
                        match app.session.as_mut().and_then(|s| s.try_recv()) {
                            Some(ev) => app.on_event(ev),
                            None => break,
                        }
                    }
                }
                Item::Finished(res) => app.on_finished(res),
            },
            sig = &mut signal => app.request_quit(sig),
        }
    }
}

async fn next_item(session: &mut Option<crate::session::Session>) -> Item {
    match session {
        Some(s) => s.next().await,
        None => std::future::pending().await,
    }
}
