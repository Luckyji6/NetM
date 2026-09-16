//! End-to-end tests: start `netm_host::run` on loopback, connect a fake guest
//! over TCP with the real frame protocol, and push hand-crafted IPv4 packets
//! through the tunnel.
//!
//! All tests use a multi-threaded runtime because `ipstack` blocks inside
//! `Drop` of its TCP streams (`block_in_place`).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use futures::{SinkExt, StreamExt};
use netm_host::{run, HostCommand, HostConfig, HostEvent, Proto};
use netm_proto::{Frame, FramedTransport, TunnelConfig, PROTOCOL_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
const WAIT: Duration = Duration::from_secs(5);

struct Host {
    addr: SocketAddr,
    events: Arc<Mutex<Vec<HostEvent>>>,
    ctrl: watch::Sender<HostCommand>,
    task: JoinHandle<anyhow::Result<()>>,
}

impl Host {
    async fn start(dns_upstreams: Option<Vec<SocketAddr>>) -> Host {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let cfg = HostConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            host_name: "test-host".into(),
            dns_upstreams,
            ..HostConfig::default()
        };
        let (ev_tx, mut ev_rx) = mpsc::channel::<HostEvent>(256);
        let (ctrl_tx, ctrl_rx) = watch::channel(HostCommand::Run);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel::<SocketAddr>();
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = Arc::clone(&events);
        tokio::spawn(async move {
            let mut addr_tx = Some(addr_tx);
            while let Some(ev) = ev_rx.recv().await {
                if let HostEvent::Listening { addr } = &ev {
                    if let Some(tx) = addr_tx.take() {
                        let _ = tx.send(*addr);
                    }
                }
                if !matches!(ev, HostEvent::Stats { .. }) {
                    store.lock().unwrap().push(ev);
                }
            }
        });
        let task = tokio::spawn(run(cfg, ev_tx, ctrl_rx));
        let addr = tokio::time::timeout(WAIT, addr_rx)
            .await
            .expect("Listening event")
            .unwrap();
        Host {
            addr,
            events,
            ctrl: ctrl_tx,
            task,
        }
    }

    fn events(&self) -> Vec<HostEvent> {
        self.events.lock().unwrap().clone()
    }

    async fn wait_for(&self, pred: impl Fn(&HostEvent) -> bool) -> HostEvent {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            if let Some(ev) = self.events().into_iter().find(|e| pred(e)) {
                return ev;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "event not observed; events so far: {:#?}",
                self.events()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn shutdown(self) {
        self.ctrl.send(HostCommand::Shutdown).unwrap();
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("run() returns after Shutdown")
            .unwrap()
            .unwrap();
    }
}

type Guest = FramedTransport<TcpStream>;

async fn connect_guest(addr: SocketAddr) -> (Guest, TunnelConfig) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut framed = netm_proto::framed(stream);
    framed
        .send(Frame::Hello {
            version: PROTOCOL_VERSION,
            name: "fake-guest".into(),
        })
        .await
        .unwrap();
    let hello = tokio::time::timeout(WAIT, framed.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        hello,
        Frame::Hello {
            version: PROTOCOL_VERSION,
            name: "test-host".into()
        }
    );
    let config = tokio::time::timeout(WAIT, framed.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Frame::Config(cfg) = config else {
        panic!("expected Config, got {config:?}");
    };
    assert_eq!(cfg, TunnelConfig::default());
    (framed, cfg)
}

/// Next `IpPacket` from the host, answering keep-alives on the way.
async fn next_ip_packet(guest: &mut Guest) -> Bytes {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let frame = tokio::time::timeout_at(deadline, guest.next())
            .await
            .expect("timed out waiting for IpPacket")
            .expect("connection closed")
            .expect("frame error");
        match frame {
            Frame::IpPacket(b) => return b,
            Frame::Ping(t) => guest.send(Frame::Pong(t)).await.unwrap(),
            Frame::Pong(_) => {}
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

fn udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Bytes {
    let (SocketAddr::V4(s), SocketAddr::V4(d)) = (src, dst) else {
        panic!("ipv4 only")
    };
    let mut buf = Vec::new();
    PacketBuilder::ipv4(s.ip().octets(), d.ip().octets(), 64)
        .udp(s.port(), d.port())
        .write_to_vec(&mut buf, payload)
        .unwrap();
    Bytes::from(buf)
}

struct UdpView {
    src: SocketAddr,
    dst: SocketAddr,
    payload: Vec<u8>,
}

fn parse_udp(pkt: &[u8]) -> Option<UdpView> {
    let sliced = SlicedPacket::from_ip(pkt).ok()?;
    let NetSlice::Ipv4(ip) = sliced.net? else {
        return None;
    };
    let TransportSlice::Udp(udp) = sliced.transport? else {
        return None;
    };
    let h = ip.header();
    Some(UdpView {
        src: SocketAddr::from((h.source(), udp.source_port())),
        dst: SocketAddr::from((h.destination(), udp.destination_port())),
        payload: udp.payload().to_vec(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_flow_is_echoed_back_through_the_tunnel() {
    let host = Host::start(Some(vec!["127.0.0.1:1".parse().unwrap()])).await;
    let (mut guest, _cfg) = connect_guest(host.addr).await;
    host.wait_for(|e| matches!(e, HostEvent::GuestConnected(_)))
        .await;

    // Local UDP echo server standing in for "the internet".
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], from).await.unwrap();
        }
    });

    let src = SocketAddr::from((GUEST_IP, 40000));
    guest
        .send(Frame::IpPacket(udp_packet(
            src,
            echo_addr,
            b"ping-through-tunnel",
        )))
        .await
        .unwrap();

    let reply = next_ip_packet(&mut guest).await;
    let view = parse_udp(&reply).expect("reply is IPv4/UDP");
    assert_eq!(view.src, echo_addr, "source must be the echo server");
    assert_eq!(view.dst, src, "destination must be the guest socket");
    assert_eq!(view.payload, b"ping-through-tunnel");

    // Flow accounting.
    let opened = host
        .wait_for(|e| matches!(e, HostEvent::FlowOpened(f) if f.proto == Proto::Udp))
        .await;
    let HostEvent::FlowOpened(info) = opened else {
        unreachable!()
    };
    assert_eq!(info.src, src);
    assert_eq!(info.dst, echo_addr);

    // A second datagram on the same flow reuses the socket.
    guest
        .send(Frame::IpPacket(udp_packet(src, echo_addr, b"again")))
        .await
        .unwrap();
    let reply = next_ip_packet(&mut guest).await;
    assert_eq!(parse_udp(&reply).unwrap().payload, b"again");

    // Orderly guest exit.
    guest.send(Frame::Bye).await.unwrap();
    host.wait_for(|e| matches!(e, HostEvent::GuestDisconnected { .. }))
        .await;
    let closed = host
        .wait_for(|e| matches!(e, HostEvent::FlowClosed { id, .. } if *id == info.id))
        .await;
    let HostEvent::FlowClosed {
        tx_bytes, rx_bytes, ..
    } = closed
    else {
        unreachable!()
    };
    assert_eq!(
        tx_bytes,
        (b"ping-through-tunnel".len() + b"again".len()) as u64
    );
    assert_eq!(rx_bytes, tx_bytes);
    host.shutdown().await;
}

/// Localhost-only latency regression benchmark for the full path:
/// framing -> host packet pump -> ipstack -> UDP socket -> ipstack -> framing.
/// It excludes TUN and the physical cable, so it is a prerequisite rather
/// than a substitute for the two-Mac measurement.
#[ignore = "run explicitly in release mode as a latency benchmark"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn benchmark_udp_round_trip_latency() {
    const SAMPLES: u32 = 2_000;

    let host = Host::start(Some(vec!["127.0.0.1:1".parse().unwrap()])).await;
    let (mut guest, _) = connect_guest(host.addr).await;
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], from).await.unwrap();
        }
    });

    let src = SocketAddr::from((GUEST_IP, 40100));
    // Warm the flow so socket creation and the first ipstack accept are not
    // counted as steady-state game-packet latency.
    guest
        .send(Frame::IpPacket(udp_packet(src, echo_addr, b"warmup")))
        .await
        .unwrap();
    let _ = next_ip_packet(&mut guest).await;

    let mut samples_us = Vec::with_capacity(SAMPLES as usize);
    for sequence in 0..SAMPLES {
        let payload = sequence.to_be_bytes();
        let started = Instant::now();
        guest
            .send(Frame::IpPacket(udp_packet(src, echo_addr, &payload)))
            .await
            .unwrap();
        let reply = next_ip_packet(&mut guest).await;
        assert_eq!(parse_udp(&reply).unwrap().payload, payload);
        samples_us.push(started.elapsed().as_secs_f64() * 1e6);
    }
    samples_us.sort_by(f64::total_cmp);
    let p50 = samples_us[(samples_us.len() - 1) / 2];
    let p99 = samples_us[((samples_us.len() - 1) as f64 * 0.99) as usize];
    println!("full host UDP path RTT: p50 {p50:.1} us, p99 {p99:.1} us");
    if !cfg!(debug_assertions) {
        assert!(p99 < 1_000.0, "release p99 latency exceeded 1 ms: {p99:.1} us");
    }

    guest.send(Frame::Bye).await.unwrap();
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_queries_to_gateway_are_forwarded_to_upstream() {
    // Mock upstream resolver: echoes the query with a marker appended.
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let seen2 = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = upstream.recv_from(&mut buf).await.unwrap();
            seen2.lock().unwrap().push(buf[..n].to_vec());
            let mut answer = buf[..n].to_vec();
            answer.extend_from_slice(b"-ANSWER");
            upstream.send_to(&answer, from).await.unwrap();
        }
    });

    let host = Host::start(Some(vec![upstream_addr])).await;
    let (mut guest, cfg) = connect_guest(host.addr).await;

    let src = SocketAddr::from((GUEST_IP, 5353));
    let dns = SocketAddr::from((cfg.dns, 53));
    assert_eq!(cfg.dns, GATEWAY_IP);
    guest
        .send(Frame::IpPacket(udp_packet(src, dns, b"QUERY-1")))
        .await
        .unwrap();

    let reply = next_ip_packet(&mut guest).await;
    let view = parse_udp(&reply).unwrap();
    assert_eq!(
        view.src, dns,
        "answer must appear to come from the tunnel DNS"
    );
    assert_eq!(view.dst, src);
    assert_eq!(view.payload, b"QUERY-1-ANSWER");
    assert_eq!(seen.lock().unwrap().as_slice(), &[b"QUERY-1".to_vec()]);

    // Several queries on the same source port are all answered.
    for q in [&b"QUERY-2"[..], b"QUERY-3"] {
        guest
            .send(Frame::IpPacket(udp_packet(src, dns, q)))
            .await
            .unwrap();
    }
    let mut got = vec![
        parse_udp(&next_ip_packet(&mut guest).await)
            .unwrap()
            .payload,
        parse_udp(&next_ip_packet(&mut guest).await)
            .unwrap()
            .payload,
    ];
    got.sort();
    assert_eq!(
        got,
        vec![b"QUERY-2-ANSWER".to_vec(), b"QUERY-3-ANSWER".to_vec()]
    );

    host.shutdown().await;
    // Shutdown tells the guest goodbye.
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        match tokio::time::timeout_at(deadline, guest.next())
            .await
            .unwrap()
        {
            Some(Ok(Frame::Bye)) | None => break,
            Some(Ok(_)) => continue,
            Some(Err(e)) => panic!("{e}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_guest_is_rejected_with_bye() {
    let host = Host::start(Some(vec!["127.0.0.1:1".parse().unwrap()])).await;
    let (mut first, _) = connect_guest(host.addr).await;
    host.wait_for(|e| matches!(e, HostEvent::GuestConnected(_)))
        .await;

    let stream = TcpStream::connect(host.addr).await.unwrap();
    let mut second = netm_proto::framed(stream);
    second
        .send(Frame::Hello {
            version: PROTOCOL_VERSION,
            name: "intruder".into(),
        })
        .await
        .unwrap();
    let frame = tokio::time::timeout(WAIT, second.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame, Frame::Bye);
    host.wait_for(|e| matches!(e, HostEvent::Log(m) if m.contains("rejecting guest")))
        .await;

    // The first guest is unaffected: keep-alive still works.
    first.send(Frame::Ping(42)).await.unwrap();
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        match tokio::time::timeout_at(deadline, first.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        {
            Frame::Pong(42) => break,
            Frame::Ping(t) => first.send(Frame::Pong(t)).await.unwrap(),
            other => panic!("unexpected {other:?}"),
        }
    }

    // Once the first guest leaves, a new one is accepted.
    drop(first);
    host.wait_for(|e| matches!(e, HostEvent::GuestDisconnected { .. }))
        .await;
    let (_third, _) = connect_guest(host.addr).await;
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_wrong_protocol_version() {
    let host = Host::start(Some(vec!["127.0.0.1:1".parse().unwrap()])).await;
    let stream = TcpStream::connect(host.addr).await.unwrap();
    let mut guest = netm_proto::framed(stream);
    guest
        .send(Frame::Hello {
            version: PROTOCOL_VERSION + 7,
            name: "future".into(),
        })
        .await
        .unwrap();
    let frame = tokio::time::timeout(WAIT, guest.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame, Frame::Bye);
    host.wait_for(|e| matches!(e, HostEvent::Log(m) if m.contains("version mismatch")))
        .await;
    host.shutdown().await;
}

// ---------------------------------------------------------------------------
// TCP through the user-space stack with a hand-rolled three-way handshake.
// ---------------------------------------------------------------------------

struct TcpView {
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    syn: bool,
    ack_flag: bool,
    fin: bool,
    rst: bool,
    payload: Vec<u8>,
}

fn parse_tcp(pkt: &[u8]) -> Option<TcpView> {
    let sliced = SlicedPacket::from_ip(pkt).ok()?;
    let NetSlice::Ipv4(ip) = sliced.net? else {
        return None;
    };
    let TransportSlice::Tcp(tcp) = sliced.transport? else {
        return None;
    };
    let h = ip.header();
    Some(TcpView {
        src: SocketAddr::from((h.source(), tcp.source_port())),
        dst: SocketAddr::from((h.destination(), tcp.destination_port())),
        seq: tcp.sequence_number(),
        ack: tcp.acknowledgment_number(),
        syn: tcp.syn(),
        ack_flag: tcp.ack(),
        fin: tcp.fin(),
        rst: tcp.rst(),
        payload: tcp.payload().to_vec(),
    })
}

async fn next_tcp_segment(guest: &mut Guest, dst: SocketAddr) -> TcpView {
    loop {
        let pkt = next_ip_packet(guest).await;
        if let Some(v) = parse_tcp(&pkt) {
            if v.src == dst {
                return v;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_flow_reaches_local_server_and_echoes() {
    let host = Host::start(Some(vec!["127.0.0.1:1".parse().unwrap()])).await;
    let (mut guest, _) = connect_guest(host.addr).await;

    // Local TCP echo server.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let src = SocketAddr::from((GUEST_IP, 41000));
    let (SocketAddr::V4(s4), SocketAddr::V4(d4)) = (src, server_addr) else {
        unreachable!()
    };
    let build = |seq: u32| {
        PacketBuilder::ipv4(s4.ip().octets(), d4.ip().octets(), 64).tcp(
            s4.port(),
            d4.port(),
            seq,
            65535,
        )
    };

    // SYN
    let mut syn = Vec::new();
    build(1000).syn().write_to_vec(&mut syn, &[]).unwrap();
    guest.send(Frame::IpPacket(Bytes::from(syn))).await.unwrap();

    // SYN-ACK
    let synack = next_tcp_segment(&mut guest, server_addr).await;
    assert!(synack.syn && synack.ack_flag, "expected SYN-ACK");
    assert_eq!(synack.dst, src);
    assert_eq!(synack.ack, 1001);
    let server_seq = synack.seq;

    // ACK + data
    let mut data = Vec::new();
    build(1001)
        .ack(server_seq.wrapping_add(1))
        .psh()
        .write_to_vec(&mut data, b"hello over tcp")
        .unwrap();
    guest
        .send(Frame::IpPacket(Bytes::from(data)))
        .await
        .unwrap();

    host.wait_for(
        |e| matches!(e, HostEvent::FlowOpened(f) if f.proto == Proto::Tcp && f.dst == server_addr),
    )
    .await;

    // Echoed payload comes back (possibly after a bare ACK).
    let mut echoed = Vec::new();
    let mut last_seq = server_seq.wrapping_add(1);
    while echoed.len() < b"hello over tcp".len() {
        let seg = next_tcp_segment(&mut guest, server_addr).await;
        assert!(!seg.rst, "unexpected RST");
        if !seg.payload.is_empty() {
            echoed.extend_from_slice(&seg.payload);
            last_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
        }
    }
    assert_eq!(echoed, b"hello over tcp");

    // ACK the data and close our side with FIN.
    let mut fin = Vec::new();
    build(1001 + b"hello over tcp".len() as u32)
        .ack(last_seq)
        .fin()
        .write_to_vec(&mut fin, &[])
        .unwrap();
    guest.send(Frame::IpPacket(Bytes::from(fin))).await.unwrap();

    // The echo server closes too, so the stack eventually sends FIN.
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        assert!(tokio::time::Instant::now() < deadline, "no FIN from stack");
        let seg = next_tcp_segment(&mut guest, server_addr).await;
        if seg.fin {
            let mut ack = Vec::new();
            build(1002 + b"hello over tcp".len() as u32)
                .ack(seg.seq.wrapping_add(1))
                .write_to_vec(&mut ack, &[])
                .unwrap();
            guest.send(Frame::IpPacket(Bytes::from(ack))).await.unwrap();
            break;
        }
    }

    let closed = host
        .wait_for(|e| matches!(e, HostEvent::FlowClosed { tx_bytes, .. } if *tx_bytes > 0))
        .await;
    let HostEvent::FlowClosed {
        tx_bytes, rx_bytes, ..
    } = closed
    else {
        unreachable!()
    };
    assert_eq!(tx_bytes, b"hello over tcp".len() as u64);
    assert_eq!(rx_bytes, b"hello over tcp".len() as u64);
    host.shutdown().await;
}
