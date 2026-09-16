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
//! These frames were introduced with protocol version 2. The handshake must
//! reject older peers before a probe starts; sending them to a v1 peer would
//! make that peer close the connection on the unknown frame type.

use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::time::timeout;

use crate::frame::{Frame, FrameError, FrameIo, MAX_FRAME_SIZE};

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
            // Both peers may briefly wait for their UI/log event queues after
            // the handshake. Keep this comfortably above that scheduling
            // jitter so the responder does not enter the packet pump while
            // the initiator is about to start its burst.
            idle: Duration::from_secs(1),
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

/// Failures of a speed probe. Transport/codec failures mean the current
/// connection cannot safely continue; validation errors protect both sides
/// from malformed or unbounded probe traffic.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid speed test parameters: {0}")]
    InvalidParams(&'static str),
    #[error("speed test timed out")]
    Timeout,
    #[error("connection closed during speed test")]
    Closed,
    #[error("unexpected frame during speed test: {0}")]
    Unexpected(&'static str),
    #[error("speed test received more than the {max} byte limit")]
    LimitExceeded { max: u64 },
    #[error("speed test byte count mismatch (sender {sent}, receiver {received})")]
    ByteCountMismatch { sent: u64, received: u64 },
    #[error(transparent)]
    Codec(#[from] FrameError),
}

fn validate(params: Params) -> Result<(), Error> {
    if params.chunk == 0 {
        return Err(Error::InvalidParams("chunk must be greater than zero"));
    }
    if params.chunk >= MAX_FRAME_SIZE {
        return Err(Error::InvalidParams(
            "chunk must fit inside one protocol frame",
        ));
    }
    if params.max_bytes == 0 {
        return Err(Error::InvalidParams("max_bytes must be greater than zero"));
    }
    Ok(())
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

async fn send_burst<S: FrameIo>(framed: &mut S, params: Params) -> Result<u64, Error> {
    validate(params)?;
    let full_payload = Bytes::from(vec![0u8; params.chunk]);
    let start = Instant::now();
    let mut sent = 0u64;
    let mut chunks_since_flush = 0u8;
    while sent < params.max_bytes {
        let remaining = params.max_bytes - sent;
        let payload = if remaining < params.chunk as u64 {
            Bytes::from(vec![0u8; remaining as usize])
        } else {
            full_payload.clone()
        };
        let chunk = payload.len() as u64;
        framed.feed(Frame::SpeedChunk(payload)).await?;
        sent += chunk;
        chunks_since_flush += 1;
        if chunks_since_flush == 4 {
            framed.flush().await?;
            chunks_since_flush = 0;
        }
        if sent >= chunk && start.elapsed() >= params.budget {
            break;
        }
    }
    framed.flush().await?;
    framed.send(Frame::SpeedDone(sent)).await?;
    Ok(sent)
}

async fn next_frame<S: FrameIo>(framed: &mut S, wait: Duration) -> Result<Frame, Error> {
    match timeout(wait, framed.next()).await {
        Err(_) => Err(Error::Timeout),
        Ok(None) => Err(Error::Closed),
        Ok(Some(Err(e))) => Err(Error::Codec(e)),
        Ok(Some(Ok(Frame::Bye))) => Err(Error::Closed),
        Ok(Some(Ok(f))) => Ok(f),
    }
}

/// Receive a burst. `first` is a [`Frame::SpeedChunk`] already read, if any.
async fn recv_burst<S: FrameIo>(
    framed: &mut S,
    first: Option<Bytes>,
    params: Params,
) -> Result<(u64, u64), Error> {
    let mut bytes = 0u64;
    let mut started: Option<Instant> = None;
    if let Some(p) = first {
        started = Some(Instant::now());
        bytes = (p.len() as u64)
            .checked_add(bytes)
            .filter(|total| *total <= params.max_bytes)
            .ok_or(Error::LimitExceeded {
                max: params.max_bytes,
            })?;
    }
    loop {
        match next_frame(framed, params.timeout).await? {
            Frame::SpeedChunk(p) => {
                if started.is_none() {
                    started = Some(Instant::now());
                }
                bytes = bytes
                    .checked_add(p.len() as u64)
                    .filter(|total| *total <= params.max_bytes)
                    .ok_or(Error::LimitExceeded {
                        max: params.max_bytes,
                    })?;
            }
            Frame::SpeedDone(sent) => {
                if sent != bytes {
                    return Err(Error::ByteCountMismatch {
                        sent,
                        received: bytes,
                    });
                }
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
pub async fn run_as_initiator<S: FrameIo>(
    framed: &mut S,
    params: Params,
) -> Result<LinkSpeed, Error> {
    validate(params)?;
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
pub async fn run_as_responder<S: FrameIo>(
    framed: &mut S,
    params: Params,
) -> Result<ResponderOutcome, Error> {
    validate(params)?;
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
    async fn burst_honours_non_multiple_byte_cap() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut params = Params::for_tests();
        params.max_bytes = 2_500;
        let initiator = tokio::spawn(async move {
            let mut f = framed(a);
            run_as_initiator(&mut f, params).await
        });
        let responder = tokio::spawn(async move {
            let mut f = framed(b);
            run_as_responder(&mut f, params).await
        });
        let measured = initiator.await.unwrap().unwrap();
        let remote = responder.await.unwrap().unwrap();
        let ResponderOutcome::Measured(remote) = remote else {
            panic!("expected a measurement");
        };
        assert_eq!(measured.up_bytes, 2_500);
        assert_eq!(measured.down_bytes, 2_500);
        assert_eq!(remote.up_bytes, 2_500);
        assert_eq!(remote.down_bytes, 2_500);
    }

    #[tokio::test]
    async fn responder_rejects_false_byte_count() {
        let (a, b) = tokio::io::duplex(4096);
        let params = Params::for_tests();
        let responder = tokio::spawn(async move {
            let mut f = framed(b);
            run_as_responder(&mut f, params).await
        });
        let mut initiator = framed(a);
        initiator
            .send(Frame::SpeedChunk(Bytes::from_static(&[0; 16])))
            .await
            .unwrap();
        initiator.send(Frame::SpeedDone(15)).await.unwrap();
        assert!(matches!(
            responder.await.unwrap().unwrap_err(),
            Error::ByteCountMismatch {
                sent: 15,
                received: 16
            }
        ));
    }

    #[tokio::test]
    async fn invalid_chunk_is_rejected_before_io() {
        let (a, _b) = tokio::io::duplex(64);
        let mut params = Params::for_tests();
        params.chunk = MAX_FRAME_SIZE;
        let mut f = framed(a);
        assert!(matches!(
            run_as_initiator(&mut f, params).await,
            Err(Error::InvalidParams(_))
        ));
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
