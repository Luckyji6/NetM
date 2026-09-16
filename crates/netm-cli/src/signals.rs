//! Process signals that must trigger a graceful shutdown (and therefore the
//! guest's route/DNS/TUN cleanup): SIGINT, SIGTERM and SIGHUP (terminal
//! window closed).

/// Resolve to the name of the first shutdown signal received.
pub async fn wait_for_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut int = signal(SignalKind::interrupt()).ok();
        let mut term = signal(SignalKind::terminate()).ok();
        let mut hup = signal(SignalKind::hangup()).ok();
        loop {
            tokio::select! {
                Some(_) = recv(&mut int) => return "SIGINT",
                Some(_) = recv(&mut term) => return "SIGTERM",
                Some(_) = recv(&mut hup) => return "SIGHUP",
                else => {
                    // No handler could be installed; never resolve.
                    std::future::pending::<()>().await;
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "Ctrl-C"
    }
}

#[cfg(unix)]
async fn recv(sig: &mut Option<tokio::signal::unix::Signal>) -> Option<()> {
    match sig {
        Some(s) => s.recv().await,
        None => std::future::pending().await,
    }
}
