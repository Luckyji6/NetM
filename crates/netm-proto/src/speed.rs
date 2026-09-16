//! Short burst over the tunnel TCP to estimate the Type-C / Thunderbolt
//! *link* capacity. This is not an Internet speed test: the packets never
//! leave the two machines.
//!
//! Protocol (guest is the initiator, host the responder):
//! 1. Guest pushes [`Frame::SpeedChunk`]s then [`Frame::SpeedDone`].
//! 2. Host replies [`Frame::SpeedResult`] (guest → host) and immediately
//!    pushes its own burst the other way.
//! 3. Guest replies [`Frame::SpeedResult`] (host → guest).
//!
//! An old peer that does not speak these frames simply ignores them (host)
//! or times out (guest); the tunnel continues either way.

use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::time::timeout;

use crate::frame::{Frame, FrameError, FramedTransport};
use crate::transport::Transport;

/// Tunables of one burst. Production values fill the pipe for a fraction of
/// a second; tests use [`Params::for_tests`].
#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Size of each [`Frame::SpeedChunk`] payload.
    pub chunk: usize,
    /// Stop sending once this much wall time has elapsed (and at least one
    /// chunk has gone out).
    pub budget: Duration,
    /// Hard cap on payload bytes per direction.
    pub max_bytes: u64,
    /// How long the host waits for the guest to start the test. On timeout
    /// the host returns [`Error::Idle`] and proceeds with the tunnel.
    pub idle: Duration,
    /// How long either side waits for the next expected frame.
    pub timeout: Duration,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            chunk: 32 * 1024,
            budget: Duration::from_millis(280),
            max_bytes: 16 * 1024 * 1024,
            idle: Duration::from_millis(200),
            timeout: Duration::from_secs(3),
        }
    }
}

impl Params {
    /// Tiny burst so unit tests on an in-memory duplex finish in milliseconds.
    pub fn for_tests() -> Self {
        Self {
            chunk: 1024,
            budget: Duration::from_millis(30),
            max_bytes: 4 * 1024,
            idle: Duration::from_millis(80),
            timeout: Duration::from_secs(1),
        }
    }
}

/// Result of one link-capacity probe. Rates are bit/s.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LinkSpeed {
    /// Guest → host.
    pub up_bps: f64,
    /// Host → guest.
    pub down_bps: f64,
    pub up_bytes: u64,
    pub down_bytes: u64,
}

impl LinkSpeed {
    /// Compact log line, e.g. `up 12.4 Gbit/s / down 11.8 Gbit/s`.
    pub fn summary(&self) -> String {
        format!(
            "up {} / down {} ({} / {} bytes)",
            fmt_bps(self.up_bps),
            fmt_bps(self.down_bps),
            self.up_bytes,
            self.down_bytes
        )
    }
}

/// `bit/s` → `12.4 Gbit/s`.
pub fn fmt_bps(bps: f64) -> String {
    if !bps.is_finite() || bps <= 0.0 {
        "0 bit/s".into()
    } else if bps >= 1e9 {
        format!("{:.2} Gbit/s", bps / 1e9)
    } else if bps >= 1e6 {
        format!("{:.2} Mbit/s", bps / 1e6)
    } else if bps >= 1e3 {
        format!("{:.1} kbit/s", bps / 1e3)
    } else {
        format!("{bps:.0} bit/s")
    }
}

fn bps(bytes: u64, nanos: u64) -> f64 {
    if nanos == 0 {
        return 0.0;
    }
    (bytes as f64) * 8.0 * 1_000_000_000.0 / (nanos as f64)
}

/// Failures of a speed probe. The tunnel is only in trouble when the
/// connection itself died (`Io` / `Closed`).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("speed test timed out")]
    Timeout,
    #[error("connection closed during speed test")]
    Closed,
    #[error("unexpected frame during speed test: {0}")]
    Unexpected(&'static str),
    #[error(transparent)]
    Codec(#[from] FrameError),
}

fn kind(f: &Frame) -> &'static str {
    match f {
        Frame::Hello { .. } => "Hello",
        Frame::Config(_) => "Config",
        Frame::IpPacket(_) => "IpPacket",
        Frame::Ping(_) => "Ping",
        Frame::Pong(_) => "Pong",
        Frame::Bye => "Bye",
        Frame::SpeedChunk(_) => "SpeedChunk",
        Frame::SpeedDone(_) => "SpeedDone",
        Frame::SpeedResult { .. } => "SpeedResult",
    }
}

async fn send_burst<T: Transport>(
    framed: &mut FramedTransport<T>,
    params: Params,
) -> Result<u64, Error> {
    let payload = Bytes::from(vec![0u8; params.chunk.max(1)]);
    let start = Instant::now();
    let mut sent = 0u64;
    let chunk = payload.len() as u64;
    while sent < params.max_bytes {
        framed.feed(Frame::SpeedChunk(payload.clone())).await?;
        sent += chunk;
        if sent.is_multiple_of(chunk * 4) {
            framed.flush().await?;
        }
        if sent >= chunk && start.elapsed() >= params.budget {
            break;
        }
    }
    framed.flush().await?;
    framed.send(Frame::SpeedDone(sent)).await?;
    Ok(sent)
}

async fn next_frame<T: Transport>(
    framed: &mut FramedTransport<T>,
    wait: Duration,
) -> Result<Frame, Error> {
    match timeout(wait, framed.next()).await {
        Err(_) => Err(Error::Timeout),
        Ok(None) => Err(Error::Closed),
        Ok(Some(Err(e))) => Err(Error::Codec(e)),
        Ok(Some(Ok(Frame::Bye))) => Err(Error::Closed),
        Ok(Some(Ok(f))) => Ok(f),
    }
}

/// Receive a burst. `first` is a [`Frame::SpeedChunk`] already read, if any.
async fn recv_burst<T: Transport>(
    framed: &mut FramedTransport<T>,
    first: Option<Bytes>,
    params: Params,
) -> Result<(u64, u64), Error> {
    let mut bytes = 0u64;
    let mut started: Option<Instant> = None;
    if let Some(p) = first {
        started = Some(Instant::now());
        bytes += p.len() as u64;
    }
    loop {
        match next_frame(framed, params.timeout).await? {
            Frame::SpeedChunk(p) => {
                if started.is_none() {
                    started = Some(Instant::now());
                }
                bytes += p.len() as u64;
            }
            Frame::SpeedDone(_) => {
                let nanos = started.map(|s| s.elapsed().as_nanos() as u64).unwrap_or(0);
                return Ok((bytes, nanos));
            }
            Frame::Ping(t) => {
                framed.send(Frame::Pong(t)).await?;
            }
            Frame::Pong(_) => {}
            other => return Err(Error::Unexpected(kind(&other))),
        }
    }
}

/// Guest side: push a burst, read the host's, return both rates.
pub async fn run_as_initiator<T: Transport>(
    framed: &mut FramedTransport<T>,
    params: Params,
) -> Result<LinkSpeed, Error> {
    let _sent = send_burst(framed, params).await?;
    let up = match next_frame(framed, params.timeout).await? {
        Frame::SpeedResult { bytes, nanos } => (bytes, nanos),
        other => return Err(Error::Unexpected(kind(&other))),
    };
    let first = match next_frame(framed, params.timeout).await? {
        Frame::SpeedChunk(p) => Some(p),
        Frame::SpeedDone(_) => None,
        other => return Err(Error::Unexpected(kind(&other))),
    };
    let (down_bytes, down_nanos) = recv_burst(framed, first, params).await?;
    framed
        .send(Frame::SpeedResult {
            bytes: down_bytes,
            nanos: down_nanos,
        })
        .await?;
    Ok(LinkSpeed {
        up_bps: bps(up.0, up.1),
        down_bps: bps(down_bytes, down_nanos),
        up_bytes: up.0,
        down_bytes,
    })
}

/// What the host got instead of a speed test.
#[derive(Debug)]
pub enum ResponderOutcome {
    Measured(LinkSpeed),
    /// Guest never started the test. `pending` is a frame that arrived in
    /// the idle window (the first `IpPacket`, a `Ping`, …) and must be
    /// handled by the regular pump; `None` means the window just expired.
    Skipped {
        pending: Option<Frame>,
    },
}

/// Host side: wait briefly for the guest to start. [`ResponderOutcome::Skipped`]
/// means carry on with the tunnel (old guest, or the guest sent traffic
/// first).
pub async fn run_as_responder<T: Transport>(
    framed: &mut FramedTransport<T>,
    params: Params,
) -> Result<ResponderOutcome, Error> {
    let first = match timeout(params.idle, framed.next()).await {
        Err(_) => return Ok(ResponderOutcome::Skipped { pending: None }),
        Ok(None) => return Err(Error::Closed),
        Ok(Some(Err(e))) => return Err(Error::Codec(e)),
        Ok(Some(Ok(Frame::Bye))) => return Err(Error::Closed),
        Ok(Some(Ok(Frame::SpeedChunk(p)))) => Some(p),
        Ok(Some(Ok(Frame::SpeedDone(_)))) => None,
        Ok(Some(Ok(other))) => {
            return Ok(ResponderOutcome::Skipped {
                pending: Some(other),
            });
        }
    };
    let (up_bytes, up_nanos) = recv_burst(framed, first, params).await?;
    framed
        .send(Frame::SpeedResult {
            bytes: up_bytes,
            nanos: up_nanos,
        })
        .await?;
    let _sent = send_burst(framed, params).await?;
    let down = match next_frame(framed, params.timeout).await? {
        Frame::SpeedResult { bytes, nanos } => (bytes, nanos),
        other => return Err(Error::Unexpected(kind(&other))),
    };
    Ok(ResponderOutcome::Measured(LinkSpeed {
        up_bps: bps(up_bytes, up_nanos),
        down_bps: bps(down.0, down.1),
        up_bytes,
        down_bytes: down.0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framed;

    #[test]
    fn fmt_bps_buckets() {
        assert_eq!(fmt_bps(0.0), "0 bit/s");
        assert_eq!(fmt_bps(1_500_000.0), "1.50 Mbit/s");
        assert_eq!(fmt_bps(12.4e9), "12.40 Gbit/s");
    }

    #[tokio::test]
    async fn duplex_measures_both_directions() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let params = Params::for_tests();
        let initiator = tokio::spawn(async move {
            let mut f = framed(a);
            run_as_initiator(&mut f, params).await
        });
        let responder = tokio::spawn(async move {
            let mut f = framed(b);
            run_as_responder(&mut f, params).await
        });
        let up = initiator.await.unwrap().unwrap();
        let down = responder.await.unwrap().unwrap();
        let ResponderOutcome::Measured(down) = down else {
            panic!("expected a measurement, got skip");
        };
        assert!(up.up_bytes > 0 && up.down_bytes > 0, "{up:?}");
        assert_eq!(up.up_bytes, down.up_bytes);
        assert_eq!(up.down_bytes, down.down_bytes);
        assert!(up.up_bps > 0.0 && up.down_bps > 0.0, "{}", up.summary());
    }

    #[tokio::test]
    async fn responder_idles_when_guest_sends_nothing() {
        let (a, b) = tokio::io::duplex(1024);
        let mut params = Params::for_tests();
        params.idle = Duration::from_millis(30);
        let responder = tokio::spawn(async move {
            let mut f = framed(b);
            run_as_responder(&mut f, params).await
        });
        // Hold the initiator side open so the responder sees a timeout, not EOF.
        tokio::time::sleep(Duration::from_millis(80)).await;
        drop(a);
        let out = responder.await.unwrap().unwrap();
        assert!(
            matches!(out, ResponderOutcome::Skipped { pending: None }),
            "{out:?}"
        );
    }
}
