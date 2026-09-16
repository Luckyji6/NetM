//! Traffic counters and a sliding-window rate meter shared by host and guest.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Cumulative traffic counters.
///
/// `tx` = bytes/packets sent **into the tunnel** by this side, `rx` = received
/// from the tunnel.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counters {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
}

#[derive(Debug, Default, Clone, Copy)]
struct Sample {
    /// Offset from `RateMeter::epoch`.
    at: Duration,
    tx: u64,
    rx: u64,
}

#[derive(Debug)]
struct Window {
    samples: VecDeque<Sample>,
}

/// Sliding-window throughput meter with cumulative counters.
///
/// `RateMeter` is `Send + Sync`; wrap it in an `Arc` and call
/// [`record_tx`](Self::record_tx) / [`record_rx`](Self::record_rx) from the
/// packet pumps while the UI polls [`rates`](Self::rates) and
/// [`counters`](Self::counters). The hot recording path is lock-free: the
/// small sample deque is touched only when the UI asks for rates.
#[derive(Debug)]
pub struct RateMeter {
    epoch: Instant,
    window: Duration,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    inner: Mutex<Window>,
}

impl Default for RateMeter {
    /// One-second sampling window.
    fn default() -> Self {
        Self::new(Duration::from_secs(1))
    }
}

impl RateMeter {
    /// Create a meter averaging over `window` (must be non-zero).
    pub fn new(window: Duration) -> Self {
        assert!(!window.is_zero(), "RateMeter window must be non-zero");
        Self {
            epoch: Instant::now(),
            window,
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            inner: Mutex::new(Window {
                samples: VecDeque::from([Sample::default()]),
            }),
        }
    }

    /// Length of the averaging window.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Record one packet of `bytes` sent into the tunnel.
    pub fn record_tx(&self, bytes: usize) {
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one packet of `bytes` received from the tunnel.
    pub fn record_rx(&self, bytes: usize) {
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Current throughput in **bits per second** as `(tx_bps, rx_bps)`,
    /// averaged over the sliding window.
    pub fn rates(&self) -> (f64, f64) {
        let now = self.epoch.elapsed();
        let current = Sample {
            at: now,
            tx: self.tx_bytes.load(Ordering::Relaxed),
            rx: self.rx_bytes.load(Ordering::Relaxed),
        };
        let mut w = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune(&mut w, now, self.window);
        let base = w.samples.front().copied().unwrap_or(current);
        if w.samples.back().map(|s| s.at) != Some(now) {
            w.samples.push_back(current);
        }
        drop(w);
        let seconds = self.window.max(now.saturating_sub(base.at)).as_secs_f64();
        (
            (current.tx.saturating_sub(base.tx) as f64) * 8.0 / seconds,
            (current.rx.saturating_sub(base.rx) as f64) * 8.0 / seconds,
        )
    }

    /// Snapshot of the cumulative counters.
    pub fn counters(&self) -> Counters {
        Counters {
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
        }
    }

    /// Reset counters and the window.
    pub fn reset(&self) {
        self.tx_bytes.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx_packets.store(0, Ordering::Relaxed);
        self.rx_packets.store(0, Ordering::Relaxed);
        let now = self.epoch.elapsed();
        let mut w = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        w.samples.clear();
        w.samples.push_back(Sample {
            at: now,
            tx: 0,
            rx: 0,
        });
    }

    fn prune(w: &mut Window, now: Duration, window: Duration) {
        let cutoff = now.saturating_sub(window);
        // Keep the newest sample at or before the cutoff as the baseline,
        // plus all newer samples. This bounds memory to roughly the UI poll
        // rate times the configured window.
        while w.samples.len() > 1 && w.samples.get(1).is_some_and(|s| s.at <= cutoff) {
            w.samples.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn counters_accumulate() {
        let m = RateMeter::default();
        assert_eq!(m.counters(), Counters::default());
        m.record_tx(100);
        m.record_tx(50);
        m.record_rx(7);
        assert_eq!(
            m.counters(),
            Counters {
                tx_bytes: 150,
                rx_bytes: 7,
                tx_packets: 2,
                rx_packets: 1,
            }
        );
        m.reset();
        assert_eq!(m.counters(), Counters::default());
        assert_eq!(m.rates(), (0.0, 0.0));
    }

    #[test]
    fn rates_reflect_window() {
        let m = RateMeter::new(Duration::from_secs(1));
        assert_eq!(m.rates(), (0.0, 0.0));
        m.record_tx(1000);
        m.record_rx(250);
        let (tx, rx) = m.rates();
        // 1000 bytes over a 1 s window = 8000 bit/s.
        assert!((tx - 8000.0).abs() < 1e-6, "tx = {tx}");
        assert!((rx - 2000.0).abs() < 1e-6, "rx = {rx}");
    }

    #[test]
    fn old_samples_expire() {
        let m = RateMeter::new(Duration::from_millis(100));
        m.record_tx(1000);
        assert!(m.rates().0 > 0.0);
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(m.rates(), (0.0, 0.0));
        // Counters are cumulative and untouched by expiry.
        assert_eq!(m.counters().tx_bytes, 1000);
    }

    #[test]
    fn is_send_sync_and_shareable() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RateMeter>();
        let m = Arc::new(RateMeter::default());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let m = Arc::clone(&m);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        m.record_tx(1);
                        m.record_rx(2);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let c = m.counters();
        assert_eq!(c.tx_packets, 4000);
        assert_eq!(c.rx_bytes, 8000);
    }
}
