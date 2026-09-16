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
struct Bucket {
    /// Offset from `RateMeter::epoch`.
    start: Duration,
    tx: u64,
    rx: u64,
}

#[derive(Debug)]
struct Window {
    buckets: VecDeque<Bucket>,
}

/// Sliding-window throughput meter with cumulative counters.
///
/// `RateMeter` is `Send + Sync`; wrap it in an `Arc` and call
/// [`record_tx`](Self::record_tx) / [`record_rx`](Self::record_rx) from the
/// packet pumps while the UI polls [`rates`](Self::rates) and
/// [`counters`](Self::counters). Recording is cheap: atomics for the counters
/// plus a short mutex hold to bump the current time bucket.
#[derive(Debug)]
pub struct RateMeter {
    epoch: Instant,
    window: Duration,
    bucket_len: Duration,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    inner: Mutex<Window>,
}

impl Default for RateMeter {
    /// One second window, 100 ms buckets.
    fn default() -> Self {
        Self::new(Duration::from_secs(1))
    }
}

impl RateMeter {
    /// Number of buckets the window is divided into.
    const BUCKETS: u32 = 10;

    /// Create a meter averaging over `window` (must be non-zero).
    pub fn new(window: Duration) -> Self {
        assert!(!window.is_zero(), "RateMeter window must be non-zero");
        Self {
            epoch: Instant::now(),
            window,
            bucket_len: window / Self::BUCKETS,
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            inner: Mutex::new(Window {
                buckets: VecDeque::with_capacity(Self::BUCKETS as usize + 1),
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
        self.bump(bytes as u64, 0);
    }

    /// Record one packet of `bytes` received from the tunnel.
    pub fn record_rx(&self, bytes: usize) {
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.bump(0, bytes as u64);
    }

    /// Current throughput in **bits per second** as `(tx_bps, rx_bps)`,
    /// averaged over the sliding window.
    pub fn rates(&self) -> (f64, f64) {
        let now = self.epoch.elapsed();
        let mut w = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune(&mut w, now, self.window);
        let (tx, rx) = w
            .buckets
            .iter()
            .fold((0u64, 0u64), |(t, r), b| (t + b.tx, r + b.rx));
        drop(w);
        let secs = self.window.as_secs_f64();
        ((tx as f64) * 8.0 / secs, (rx as f64) * 8.0 / secs)
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
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .buckets
            .clear();
    }

    fn bump(&self, tx: u64, rx: u64) {
        let now = self.epoch.elapsed();
        let mut w = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune(&mut w, now, self.window);
        let needs_new = match w.buckets.back() {
            Some(b) => now >= b.start + self.bucket_len,
            None => true,
        };
        if needs_new {
            // Align bucket start to the bucket grid so buckets don't drift.
            let idx = now.as_nanos() / self.bucket_len.as_nanos().max(1);
            let start = Duration::from_nanos((idx * self.bucket_len.as_nanos()) as u64);
            w.buckets.push_back(Bucket {
                start,
                tx: 0,
                rx: 0,
            });
        }
        let b = w.buckets.back_mut().expect("bucket just ensured");
        b.tx += tx;
        b.rx += rx;
    }

    fn prune(w: &mut Window, now: Duration, window: Duration) {
        let cutoff = now.saturating_sub(window);
        while let Some(front) = w.buckets.front() {
            // A bucket is stale once it ends before the cutoff.
            if front.start + (window / Self::BUCKETS) <= cutoff {
                w.buckets.pop_front();
            } else {
                break;
            }
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
