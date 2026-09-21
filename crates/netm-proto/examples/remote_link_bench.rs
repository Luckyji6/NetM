//! Measure a live NetM transport without creating a TUN or changing routes.
//!
//! The target must be a running `netm host`. The benchmark performs the
//! normal protocol handshake and bidirectional capacity probe, then measures
//! control-frame RTT. It never forwards IP traffic.
//!
//! ```text
//! cargo run -p netm-proto --release --example remote_link_bench -- \
//!   '[fe80::1%7]:27778' [chunk-kib]
//! ```

use std::error::Error;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use netm_proto::{framed, Frame, PROTOCOL_VERSION};

const RTT_SAMPLES: u64 = 200;
const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let target: SocketAddr = std::env::args()
        .nth(1)
        .ok_or("usage: remote_link_bench '[fe80::1%7]:27778' [chunk-kib]")?
        .parse()?;
    let chunk_kib = std::env::args()
        .nth(2)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(32);
    let speed_params = netm_proto::speed::Params {
        chunk: chunk_kib.checked_mul(1024).ok_or("chunk size overflow")?,
        ..Default::default()
    };

    let stream = netm_proto::transport::tcp::connect(target, IO_TIMEOUT).await?;
    netm_proto::transport::tcp::tune(&stream)?;
    let mut wire = framed(stream);

    wire.send(Frame::Hello {
        version: PROTOCOL_VERSION,
        name: "netm-link-bench".into(),
    })
    .await?;

    let host_name = match next(&mut wire).await? {
        Frame::Hello { version, name } if version == PROTOCOL_VERSION => name,
        other => return Err(format!("expected compatible Hello, got {other:?}").into()),
    };
    let config = match next(&mut wire).await? {
        Frame::Config(config) => config,
        other => return Err(format!("expected Config, got {other:?}").into()),
    };

    let speed = netm_proto::speed::run_as_initiator(&mut wire, speed_params).await?;

    let mut rtt_us = Vec::with_capacity(RTT_SAMPLES as usize);
    for token in 0..RTT_SAMPLES {
        let started = Instant::now();
        wire.send(Frame::Ping(token)).await?;
        loop {
            match next(&mut wire).await? {
                Frame::Pong(got) if got == token => {
                    rtt_us.push(started.elapsed().as_secs_f64() * 1e6);
                    break;
                }
                // The host's keepalive runs concurrently with this diagnostic.
                Frame::Ping(host_token) => wire.send(Frame::Pong(host_token)).await?,
                Frame::Pong(_) => {}
                other => return Err(format!("expected Pong({token}), got {other:?}").into()),
            }
        }
    }
    rtt_us.sort_by(f64::total_cmp);
    let percentile = |p: f64| rtt_us[((rtt_us.len() - 1) as f64 * p) as usize];

    println!("host: {host_name} ({target})");
    println!(
        "tunnel config: {}/{} via {}, mtu {}",
        config.guest_ip, config.prefix_len, config.gateway_ip, config.mtu
    );
    println!(
        "link capacity ({chunk_kib} KiB chunks): {}",
        speed.summary()
    );
    println!(
        "protocol RTT: p50 {:.3} ms, p95 {:.3} ms, p99 {:.3} ms ({} samples)",
        percentile(0.50) / 1_000.0,
        percentile(0.95) / 1_000.0,
        percentile(0.99) / 1_000.0,
        rtt_us.len()
    );

    wire.send(Frame::Bye).await?;
    Ok(())
}

async fn next<S>(wire: &mut S) -> Result<Frame, Box<dyn Error>>
where
    S: futures::Stream<Item = Result<Frame, netm_proto::FrameError>> + Unpin,
{
    match tokio::time::timeout(IO_TIMEOUT, wire.next()).await {
        Err(_) => Err("timed out waiting for host".into()),
        Ok(None) => Err("host closed the connection".into()),
        Ok(Some(Err(error))) => Err(error.into()),
        Ok(Some(Ok(Frame::Bye))) => Err("host rejected the session (already busy?)".into()),
        Ok(Some(Ok(frame))) => Ok(frame),
    }
}
