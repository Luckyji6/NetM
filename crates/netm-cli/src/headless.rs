//! `--headless`: run one core, log every event to stderr, stop on
//! SIGINT/SIGTERM/SIGHUP.

use anyhow::Result;

use crate::session::{HeadlessLogger, Item, Session};

pub async fn run(mut session: Session) -> Result<()> {
    let mode = session.mode();
    tracing::info!("{}模式已启动（headless）", mode.label());
    let mut logger = HeadlessLogger::default();
    let mut signal = std::pin::pin!(crate::signals::wait_for_signal());

    loop {
        tokio::select! {
            item = session.next() => match item {
                Item::Event(ev) => logger.log(&ev),
                Item::Finished(res) => {
                    match &res {
                        Ok(()) => tracing::info!("{}已停止", mode.label()),
                        Err(e) => tracing::error!("{}运行出错：{e:#}", mode.label()),
                    }
                    return res;
                }
            },
            sig = &mut signal => {
                tracing::info!("收到 {sig}，正在清理并退出…");
                return session.shutdown(|ev| logger.log(&ev)).await;
            }
        }
    }
}
