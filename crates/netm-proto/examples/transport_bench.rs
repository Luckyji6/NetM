//! Local TCP/framing throughput and latency smoke benchmark.
//!
//! This deliberately excludes TUN, ipstack and a physical cable; it is a
//! repeatable lower-layer regression check, not a claim about end-to-end
//! Internet speed. Run with `cargo run -p netm-proto --release --example
//! transport_bench -- 256` (MiB, optional).

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use netm_proto::{framed, Frame, DEFAULT_MTU};

const BATCH_BYTES: usize = 64 * 1024;
const LATENCY_SAMPLES: u64 = 1_000;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mib = std::env::args()
        .nth(1)
        .map(|v| v.parse::<u64>())
        .transpose()?
        .unwrap_or(256);
    let target = mib * 1024 * 1024;

    let listener =
        netm_proto::transport::tcp::listen(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        netm_proto::transport::tcp::tune(&stream)?;
        let mut wire = framed(stream);
        let mut bytes = 0u64;
        let mut started = None;
        while let Some(frame) = wire.next().await {
            match frame? {
                Frame::IpPacket(packet) => {
                    started.get_or_insert_with(Instant::now);
                    bytes += packet.len() as u64;
                }
                Frame::SpeedDone(sent) => {
                    if sent != bytes {
                        return Err(std::io::Error::other(format!(
                            "sender reported {sent} bytes, received {bytes}"
                        )));
                    }
                    let nanos = started
                        .map(|at| at.elapsed().as_nanos() as u64)
                        .unwrap_or(0);
                    wire.send(Frame::SpeedResult { bytes, nanos }).await?;
                }
                Frame::Ping(token) => wire.send(Frame::Pong(token)).await?,
                Frame::Bye => break,
                _ => {}
            }
        }
        Ok::<(), std::io::Error>(())
    });

    let stream =
        netm_proto::transport::tcp::connect(addr, std::time::Duration::from_secs(2)).await?;
    let mut wire = framed(stream);
    let packet = Bytes::from(vec![0u8; DEFAULT_MTU as usize]);
    let start = Instant::now();
    let mut sent = 0u64;
    while sent < target {
        let mut batch = 0usize;
        while sent < target && batch < BATCH_BYTES {
            let remaining = (target - sent) as usize;
            let payload = if remaining < packet.len() {
                Bytes::from(vec![0u8; remaining])
            } else {
                packet.clone()
            };
            sent += payload.len() as u64;
            batch += payload.len();
            wire.feed(Frame::IpPacket(payload)).await?;
        }
        wire.flush().await?;
    }
    wire.send(Frame::SpeedDone(sent)).await?;
    let Frame::SpeedResult { bytes, .. } = wire.next().await.ok_or("server closed")?? else {
        return Err("expected throughput result".into());
    };
    let elapsed = start.elapsed();
    let gbps = bytes as f64 * 8.0 / elapsed.as_secs_f64() / 1e9;

    let mut latency_us = Vec::with_capacity(LATENCY_SAMPLES as usize);
    for token in 0..LATENCY_SAMPLES {
        let at = Instant::now();
        wire.send(Frame::Ping(token)).await?;
        match wire.next().await {
            Some(Ok(Frame::Pong(got))) if got == token => {
                latency_us.push(at.elapsed().as_secs_f64() * 1e6)
            }
            other => return Err(format!("expected Pong({token}), got {other:?}").into()),
        }
    }
    latency_us.sort_by(f64::total_cmp);
    let percentile = |p: f64| latency_us[((latency_us.len() - 1) as f64 * p) as usize];
    println!(
        "{mib} MiB in {:.3}s: {:.2} Gbit/s; loopback RTT p50 {:.1} us, p99 {:.1} us",
        elapsed.as_secs_f64(),
        gbps,
        percentile(0.50),
        percentile(0.99)
    );

    wire.send(Frame::Bye).await?;
    server.await??;
    Ok(())
}
