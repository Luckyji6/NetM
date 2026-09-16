//! Frame protocol used on every tunnel transport.
//!
//! ## Wire format
//!
//! ```text
//! +----------------+----------+-------------------------+
//! | u32 BE length  | u8 type  | payload (length-1 bytes)|
//! +----------------+----------+-------------------------+
//! ```
//!
//! `length` counts the type byte **plus** the payload (so it is `>= 1`). A
//! frame whose `length` exceeds [`MAX_FRAME_SIZE`] is rejected with
//! [`FrameError::TooLarge`] and the connection should be dropped.
//!
//! Type bytes:
//!
//! | type | variant     | payload                                             |
//! |------|-------------|-----------------------------------------------------|
//! | 1    | `Hello`     | postcard `{ version: u16, name: String }`           |
//! | 2    | `Config`    | postcard [`TunnelConfig`]                           |
//! | 3    | `IpPacket`  | raw IPv4/IPv6 packet bytes (zero-copy [`Bytes`])    |
//! | 4    | `Ping`      | 8 bytes big-endian `u64`                            |
//! | 5    | `Pong`      | 8 bytes big-endian `u64`                            |
//! | 6    | `Bye`       | empty                                               |
//! | 7    | `SpeedChunk`| raw bulk payload (link speed test, not an IP packet)|
//! | 8    | `SpeedDone` | 8 bytes big-endian `u64` (bytes the sender pushed)  |
//! | 9    | `SpeedResult` | 16 bytes: `bytes` then `nanos`, both big-endian `u64` |
//!
//! Handshake: the guest sends `Hello`, the host answers `Hello` followed by
//! `Config`; afterwards both sides exchange `IpPacket`, `Ping`/`Pong` and
//! finally `Bye`.
//!
//! ## Resynchronisable framing (serial links)
//!
//! A TCP connection always starts at a frame boundary, a serial port does
//! not: either end may start reading in the middle of a frame, and stale
//! bytes may sit in the UART buffers. On such links every frame is prefixed
//! with the 4-byte magic [`SYNC_MAGIC`] (`b"NETM"`) and decoded with
//! [`SyncFrameCodec`], which scans for the magic, discards whatever precedes
//! it and skips frames whose header or payload is invalid instead of failing
//! the connection. [`FrameCodec`] (used on TCP) is unchanged.
//!
//! ```text
//! +------+----------------+----------+-------------------------+
//! | NETM | u32 BE length  | u8 type  | payload (length-1 bytes)|
//! +------+----------------+----------+-------------------------+
//! ```

use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Sink, Stream};
use serde::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder, Framed};

use crate::transport::Transport;
use crate::DEFAULT_MTU;

/// Maximum accepted value of the length field (type byte + payload).
pub const MAX_FRAME_SIZE: usize = 65536;

/// Size of the length prefix in bytes.
pub const HEADER_LEN: usize = 4;

/// Amount of encoded data a framed transport may coalesce before applying
/// sink backpressure. The tokio-util default is 8 KiB, which forces a flush
/// after only a handful of tunnel packets and limits high-speed links.
pub const WRITE_BUFFER_BOUNDARY: usize = 128 * 1024;

/// Magic prefix of every frame on resynchronisable links (see
/// [`SyncFrameCodec`]). Same bytes as [`crate::discovery::MAGIC`].
pub const SYNC_MAGIC: &[u8; 4] = b"NETM";

const TYPE_HELLO: u8 = 1;
const TYPE_CONFIG: u8 = 2;
const TYPE_IP_PACKET: u8 = 3;
const TYPE_PING: u8 = 4;
const TYPE_PONG: u8 = 5;
const TYPE_BYE: u8 = 6;
const TYPE_SPEED_CHUNK: u8 = 7;
const TYPE_SPEED_DONE: u8 = 8;
const TYPE_SPEED_RESULT: u8 = 9;

/// Tunnel addressing handed from host to guest in the `Config` frame.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TunnelConfig {
    /// Address the guest assigns to its TUN interface.
    pub guest_ip: Ipv4Addr,
    /// Gateway (the host's virtual address inside the tunnel).
    pub gateway_ip: Ipv4Addr,
    /// Prefix length of the tunnel subnet.
    pub prefix_len: u8,
    /// DNS server the guest should use (normally the gateway).
    pub dns: Ipv4Addr,
    /// MTU of the TUN interface.
    pub mtu: u16,
}

impl Default for TunnelConfig {
    /// `10.77.0.2/24`, gateway and DNS `10.77.0.1`, MTU [`DEFAULT_MTU`].
    fn default() -> Self {
        Self {
            guest_ip: Ipv4Addr::new(10, 77, 0, 2),
            gateway_ip: Ipv4Addr::new(10, 77, 0, 1),
            prefix_len: 24,
            dns: Ipv4Addr::new(10, 77, 0, 1),
            mtu: DEFAULT_MTU,
        }
    }
}

/// A single protocol frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// Handshake. `version` must equal [`crate::PROTOCOL_VERSION`]; `name` is a
    /// human readable peer name (hostname).
    Hello { version: u16, name: String },
    /// Tunnel configuration, sent by the host after `Hello`.
    Config(TunnelConfig),
    /// A raw IP packet (IPv4 or IPv6) as read from / to be written to the TUN.
    IpPacket(Bytes),
    /// Keep-alive request carrying an opaque token (usually a timestamp).
    Ping(u64),
    /// Keep-alive reply echoing the `Ping` token.
    Pong(u64),
    /// Orderly shutdown notice.
    Bye,
    /// One chunk of a link-capacity burst (not forwarded to the TUN).
    SpeedChunk(Bytes),
    /// Sender finished its burst; payload is the number of payload bytes it
    /// pushed (not counting this frame).
    SpeedDone(u64),
    /// Receiver's measurement of the burst it just took in.
    SpeedResult { bytes: u64, nanos: u64 },
}

#[derive(Serialize, Deserialize)]
struct HelloPayload {
    version: u16,
    name: String,
}

/// Errors produced by [`FrameCodec`].
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Underlying transport I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Frame length field exceeds [`MAX_FRAME_SIZE`] (or is zero).
    #[error("frame too large: {0} bytes (max {MAX_FRAME_SIZE})")]
    TooLarge(usize),
    /// Frame has a zero length field (no type byte).
    #[error("empty frame (length field is 0)")]
    Empty,
    /// Unknown type byte.
    #[error("unknown frame type {0}")]
    UnknownType(u8),
    /// Control payload could not be (de)serialized.
    #[error("invalid payload for frame type {kind}: {source}")]
    Payload {
        kind: u8,
        #[source]
        source: postcard::Error,
    },
    /// Control payload has an unexpected fixed length (e.g. `Ping` not 8 bytes).
    #[error("invalid payload length {len} for frame type {kind}")]
    PayloadLength { kind: u8, len: usize },
}

impl From<FrameError> for std::io::Error {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Io(io) => io,
            other => std::io::Error::new(std::io::ErrorKind::InvalidData, other),
        }
    }
}

/// Stateless codec implementing the frame format described in the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct FrameCodec;

impl FrameCodec {
    /// Create a codec.
    pub fn new() -> Self {
        Self
    }

    fn encode_payload(item: &Frame) -> Result<(u8, Bytes), FrameError> {
        Ok(match item {
            Frame::Hello { version, name } => {
                let payload = HelloPayload {
                    version: *version,
                    name: name.clone(),
                };
                let v = postcard::to_allocvec(&payload).map_err(|source| FrameError::Payload {
                    kind: TYPE_HELLO,
                    source,
                })?;
                (TYPE_HELLO, Bytes::from(v))
            }
            Frame::Config(cfg) => {
                let v = postcard::to_allocvec(cfg).map_err(|source| FrameError::Payload {
                    kind: TYPE_CONFIG,
                    source,
                })?;
                (TYPE_CONFIG, Bytes::from(v))
            }
            Frame::IpPacket(b) => (TYPE_IP_PACKET, b.clone()),
            Frame::Ping(t) => (TYPE_PING, Bytes::copy_from_slice(&t.to_be_bytes())),
            Frame::Pong(t) => (TYPE_PONG, Bytes::copy_from_slice(&t.to_be_bytes())),
            Frame::Bye => (TYPE_BYE, Bytes::new()),
            Frame::SpeedChunk(b) => (TYPE_SPEED_CHUNK, b.clone()),
            Frame::SpeedDone(n) => (TYPE_SPEED_DONE, Bytes::copy_from_slice(&n.to_be_bytes())),
            Frame::SpeedResult { bytes, nanos } => {
                let mut v = [0u8; 16];
                v[..8].copy_from_slice(&bytes.to_be_bytes());
                v[8..].copy_from_slice(&nanos.to_be_bytes());
                (TYPE_SPEED_RESULT, Bytes::copy_from_slice(&v))
            }
        })
    }

    fn decode_payload(kind: u8, payload: Bytes) -> Result<Frame, FrameError> {
        match kind {
            TYPE_HELLO => {
                let h: HelloPayload = postcard::from_bytes(&payload)
                    .map_err(|source| FrameError::Payload { kind, source })?;
                Ok(Frame::Hello {
                    version: h.version,
                    name: h.name,
                })
            }
            TYPE_CONFIG => {
                let cfg: TunnelConfig = postcard::from_bytes(&payload)
                    .map_err(|source| FrameError::Payload { kind, source })?;
                Ok(Frame::Config(cfg))
            }
            TYPE_IP_PACKET => Ok(Frame::IpPacket(payload)),
            TYPE_PING | TYPE_PONG => {
                if payload.len() != 8 {
                    return Err(FrameError::PayloadLength {
                        kind,
                        len: payload.len(),
                    });
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&payload);
                let t = u64::from_be_bytes(arr);
                Ok(if kind == TYPE_PING {
                    Frame::Ping(t)
                } else {
                    Frame::Pong(t)
                })
            }
            TYPE_BYE => {
                if !payload.is_empty() {
                    return Err(FrameError::PayloadLength {
                        kind,
                        len: payload.len(),
                    });
                }
                Ok(Frame::Bye)
            }
            TYPE_SPEED_CHUNK => Ok(Frame::SpeedChunk(payload)),
            TYPE_SPEED_DONE => {
                if payload.len() != 8 {
                    return Err(FrameError::PayloadLength {
                        kind,
                        len: payload.len(),
                    });
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&payload);
                Ok(Frame::SpeedDone(u64::from_be_bytes(arr)))
            }
            TYPE_SPEED_RESULT => {
                if payload.len() != 16 {
                    return Err(FrameError::PayloadLength {
                        kind,
                        len: payload.len(),
                    });
                }
                let mut bytes = [0u8; 8];
                let mut nanos = [0u8; 8];
                bytes.copy_from_slice(&payload[..8]);
                nanos.copy_from_slice(&payload[8..]);
                Ok(Frame::SpeedResult {
                    bytes: u64::from_be_bytes(bytes),
                    nanos: u64::from_be_bytes(nanos),
                })
            }
            other => Err(FrameError::UnknownType(other)),
        }
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        if src.len() < HEADER_LEN {
            src.reserve(HEADER_LEN - src.len());
            return Ok(None);
        }
        let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
        if len == 0 {
            return Err(FrameError::Empty);
        }
        if len > MAX_FRAME_SIZE {
            return Err(FrameError::TooLarge(len));
        }
        if src.len() < HEADER_LEN + len {
            src.reserve(HEADER_LEN + len - src.len());
            return Ok(None);
        }
        src.advance(HEADER_LEN);
        let mut body = src.split_to(len);
        let kind = body.get_u8();
        let payload = body.freeze();
        Self::decode_payload(kind, payload).map(Some)
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), FrameError> {
        let (kind, payload) = Self::encode_payload(&item)?;
        let len = 1 + payload.len();
        if len > MAX_FRAME_SIZE {
            return Err(FrameError::TooLarge(len));
        }
        dst.reserve(HEADER_LEN + len);
        dst.put_u32(len as u32);
        dst.put_u8(kind);
        dst.extend_from_slice(&payload);
        Ok(())
    }
}

/// Resynchronising codec for byte streams that may start mid-frame (serial
/// ports): `SYNC_MAGIC ++ FrameCodec frame`. See the module docs.
///
/// Decoding never returns [`FrameError::TooLarge`], [`FrameError::Empty`] or
/// payload errors: such frames are treated as noise, skipped (counted in
/// [`discarded`](Self::discarded)) and the scan for the next magic
/// continues. Only I/O errors from the underlying transport are fatal.
#[derive(Debug, Default, Clone)]
pub struct SyncFrameCodec {
    discarded: u64,
}

/// Bytes preceding the payload of a sync frame: magic + length prefix.
const SYNC_PREFIX_LEN: usize = SYNC_MAGIC.len() + HEADER_LEN;

impl SyncFrameCodec {
    /// Create a codec.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of bytes discarded so far while resynchronising
    /// (junk before a magic, frames with invalid headers or payloads).
    pub fn discarded(&self) -> u64 {
        self.discarded
    }

    fn skip(&mut self, src: &mut BytesMut, n: usize) {
        if n > 0 {
            self.discarded += n as u64;
            tracing::trace!(
                bytes = n,
                total = self.discarded,
                "sync codec skipping bytes"
            );
            src.advance(n);
        }
    }
}

/// Offset of the first `SYNC_MAGIC` in `buf`, if any.
fn find_magic(buf: &[u8]) -> Option<usize> {
    buf.windows(SYNC_MAGIC.len())
        .position(|w| w == SYNC_MAGIC.as_slice())
}

/// Length of the longest suffix of `buf` that is a proper prefix of
/// `SYNC_MAGIC` (bytes that may be the start of a magic split across reads).
fn partial_magic_len(buf: &[u8]) -> usize {
    (1..SYNC_MAGIC.len())
        .rev()
        .find(|&k| buf.len() >= k && buf[buf.len() - k..] == SYNC_MAGIC[..k])
        .unwrap_or(0)
}

impl Decoder for SyncFrameCodec {
    type Item = Frame;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        loop {
            match find_magic(src) {
                Some(0) => {}
                Some(off) => self.skip(src, off),
                None => {
                    // Keep a possible partial magic at the tail, drop the rest.
                    let keep = partial_magic_len(src);
                    let drop = src.len() - keep;
                    self.skip(src, drop);
                    src.reserve(SYNC_PREFIX_LEN);
                    return Ok(None);
                }
            }
            if src.len() < SYNC_PREFIX_LEN {
                src.reserve(SYNC_PREFIX_LEN - src.len());
                return Ok(None);
            }
            let len = u32::from_be_bytes([src[4], src[5], src[6], src[7]]) as usize;
            if len == 0 || len > MAX_FRAME_SIZE {
                // Not a real frame start (magic bytes inside junk or a
                // corrupted header): step past the first byte and rescan.
                tracing::debug!(len, "sync codec: implausible length after magic, resyncing");
                self.skip(src, 1);
                continue;
            }
            // Validate the type byte as soon as it is there, so a fake
            // header does not make us wait for a body that never comes.
            if src.len() > SYNC_PREFIX_LEN
                && !(TYPE_HELLO..=TYPE_SPEED_RESULT).contains(&src[SYNC_PREFIX_LEN])
            {
                tracing::debug!(
                    kind = src[SYNC_PREFIX_LEN],
                    "sync codec: unknown type after magic, resyncing"
                );
                self.skip(src, 1);
                continue;
            }
            let total = SYNC_PREFIX_LEN + len;
            if src.len() < total {
                src.reserve(total - src.len());
                return Ok(None);
            }
            let mut body = src.split_to(total);
            body.advance(SYNC_PREFIX_LEN);
            let kind = body.get_u8();
            match FrameCodec::decode_payload(kind, body.freeze()) {
                Ok(f) => return Ok(Some(f)),
                Err(e) => {
                    // A well-delimited but invalid frame: drop it and go on.
                    self.discarded += total as u64;
                    tracing::warn!(error = %e, "sync codec: dropping invalid frame");
                }
            }
        }
    }
}

impl Encoder<Frame> for SyncFrameCodec {
    type Error = FrameError;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), FrameError> {
        dst.reserve(SYNC_PREFIX_LEN);
        dst.extend_from_slice(SYNC_MAGIC);
        let magic_at = dst.len() - SYNC_MAGIC.len();
        if let Err(e) = FrameCodec.encode(item, dst) {
            dst.truncate(magic_at);
            return Err(e);
        }
        Ok(())
    }
}

/// A transport wrapped with [`FrameCodec`]: a `Stream<Item = Result<Frame,
/// FrameError>>` + `Sink<Frame>`.
pub type FramedTransport<T> = Framed<T, FrameCodec>;

/// A transport wrapped with [`SyncFrameCodec`].
pub type SyncFramedTransport<T> = Framed<T, SyncFrameCodec>;

/// Wrap a transport with the frame codec.
pub fn framed<T: Transport>(t: T) -> FramedTransport<T> {
    let mut framed = Framed::new(t, FrameCodec);
    framed.set_backpressure_boundary(WRITE_BUFFER_BOUNDARY);
    framed
}

/// Wrap a transport with the resynchronising codec (serial links).
pub fn framed_sync<T: Transport>(t: T) -> SyncFramedTransport<T> {
    let mut framed = Framed::new(t, SyncFrameCodec::new());
    framed.set_backpressure_boundary(WRITE_BUFFER_BOUNDARY);
    framed
}

/// Anything that speaks frames: a `Stream` of decoded frames plus a `Sink`
/// for outgoing ones. Implemented by [`FramedTransport`] and
/// [`SyncFramedTransport`]; `Box<dyn FrameIo>` lets host and guest run one
/// session implementation over either codec.
pub trait FrameIo:
    Stream<Item = Result<Frame, FrameError>> + Sink<Frame, Error = FrameError> + Send + Unpin
{
}

impl<T> FrameIo for T where
    T: Stream<Item = Result<Frame, FrameError>> + Sink<Frame, Error = FrameError> + Send + Unpin
{
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frames() -> Vec<Frame> {
        vec![
            Frame::Hello {
                version: 1,
                name: "guest-mbp".to_string(),
            },
            Frame::Config(TunnelConfig::default()),
            Frame::Config(TunnelConfig {
                guest_ip: Ipv4Addr::new(192, 168, 200, 9),
                gateway_ip: Ipv4Addr::new(192, 168, 200, 1),
                prefix_len: 16,
                dns: Ipv4Addr::new(1, 1, 1, 1),
                mtu: 1280,
            }),
            Frame::IpPacket(Bytes::from_static(&[0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4])),
            Frame::IpPacket(Bytes::new()),
            Frame::Ping(0),
            Frame::Ping(u64::MAX),
            Frame::Pong(0xdead_beef_cafe_babe),
            Frame::Bye,
            Frame::SpeedChunk(Bytes::from_static(&[7; 16])),
            Frame::SpeedDone(1_048_576),
            Frame::SpeedResult {
                bytes: 1_048_576,
                nanos: 12_345_678,
            },
        ]
    }

    fn encode_all(frames: &[Frame]) -> BytesMut {
        let mut codec = FrameCodec;
        let mut buf = BytesMut::new();
        for f in frames {
            codec.encode(f.clone(), &mut buf).unwrap();
        }
        buf
    }

    #[test]
    fn round_trip_every_variant() {
        let frames = sample_frames();
        let mut buf = encode_all(&frames);
        let mut codec = FrameCodec;
        let mut out = Vec::new();
        while let Some(f) = codec.decode(&mut buf).unwrap() {
            out.push(f);
        }
        assert_eq!(out, frames);
        assert!(buf.is_empty());
    }

    #[test]
    fn header_layout_matches_spec() {
        let mut buf = BytesMut::new();
        FrameCodec
            .encode(Frame::Ping(0x0102_0304_0506_0708), &mut buf)
            .unwrap();
        // length = 1 (type) + 8 (payload) = 9
        assert_eq!(&buf[..], &[0, 0, 0, 9, TYPE_PING, 1, 2, 3, 4, 5, 6, 7, 8]);

        let mut buf = BytesMut::new();
        FrameCodec.encode(Frame::Bye, &mut buf).unwrap();
        assert_eq!(&buf[..], &[0, 0, 0, 1, TYPE_BYE]);

        let pkt = Bytes::from_static(b"\x45abc");
        let mut buf = BytesMut::new();
        FrameCodec
            .encode(Frame::IpPacket(pkt.clone()), &mut buf)
            .unwrap();
        assert_eq!(&buf[..5], &[0, 0, 0, 5, TYPE_IP_PACKET]);
        assert_eq!(&buf[5..], &pkt[..]);
    }

    #[test]
    fn partial_reads_byte_by_byte() {
        let frames = sample_frames();
        let wire = encode_all(&frames);
        let mut codec = FrameCodec;
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        for (i, b) in wire.iter().enumerate() {
            buf.put_u8(*b);
            let is_last = i + 1 == wire.len();
            match codec.decode(&mut buf).unwrap() {
                Some(f) => out.push(f),
                None => assert!(!is_last || out.len() == frames.len()),
            }
        }
        assert_eq!(out, frames);
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut buf = BytesMut::new();
        buf.put_u32((MAX_FRAME_SIZE + 1) as u32);
        buf.put_u8(TYPE_IP_PACKET);
        let err = FrameCodec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(n) if n == MAX_FRAME_SIZE + 1));

        // Exactly MAX_FRAME_SIZE is allowed on encode (type byte + payload).
        let big = Bytes::from(vec![0u8; MAX_FRAME_SIZE - 1]);
        let mut buf = BytesMut::new();
        FrameCodec
            .encode(Frame::IpPacket(big.clone()), &mut buf)
            .unwrap();
        assert_eq!(
            FrameCodec.decode(&mut buf).unwrap(),
            Some(Frame::IpPacket(big))
        );

        // One more byte and the encoder refuses.
        let too_big = Bytes::from(vec![0u8; MAX_FRAME_SIZE]);
        let mut buf = BytesMut::new();
        let err = FrameCodec
            .encode(Frame::IpPacket(too_big), &mut buf)
            .unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }

    #[test]
    fn malformed_frames_rejected() {
        let mut buf = BytesMut::new();
        buf.put_u32(0);
        assert!(matches!(
            FrameCodec.decode(&mut buf).unwrap_err(),
            FrameError::Empty
        ));

        let mut buf = BytesMut::new();
        buf.put_u32(1);
        buf.put_u8(0x7f);
        assert!(matches!(
            FrameCodec.decode(&mut buf).unwrap_err(),
            FrameError::UnknownType(0x7f)
        ));

        let mut buf = BytesMut::new();
        buf.put_u32(3);
        buf.put_u8(TYPE_PING);
        buf.put_u16(0);
        assert!(matches!(
            FrameCodec.decode(&mut buf).unwrap_err(),
            FrameError::PayloadLength {
                kind: TYPE_PING,
                len: 2
            }
        ));

        let mut buf = BytesMut::new();
        buf.put_u32(2);
        buf.put_u8(TYPE_BYE);
        buf.put_u8(0);
        assert!(matches!(
            FrameCodec.decode(&mut buf).unwrap_err(),
            FrameError::PayloadLength {
                kind: TYPE_BYE,
                len: 1
            }
        ));
    }

    #[tokio::test]
    async fn framed_over_duplex() {
        use futures::{SinkExt, StreamExt};
        let (a, b) = tokio::io::duplex(1024);
        let mut fa = framed(a);
        let mut fb = framed(b);
        let frames = sample_frames();
        let send = async {
            for f in &frames {
                fa.send(f.clone()).await.unwrap();
            }
            fa.send(Frame::Bye).await.unwrap();
        };
        let recv = async {
            let mut got = Vec::new();
            while let Some(f) = fb.next().await {
                let f = f.unwrap();
                got.push(f.clone());
                if got.len() == frames.len() + 1 {
                    break;
                }
            }
            got
        };
        let ((), got) = tokio::join!(send, recv);
        assert_eq!(&got[..frames.len()], &frames[..]);
        assert_eq!(got.last(), Some(&Frame::Bye));
    }

    // -----------------------------------------------------------------------
    // SyncFrameCodec
    // -----------------------------------------------------------------------

    fn encode_all_sync(frames: &[Frame]) -> BytesMut {
        let mut codec = SyncFrameCodec::new();
        let mut buf = BytesMut::new();
        for f in frames {
            codec.encode(f.clone(), &mut buf).unwrap();
        }
        buf
    }

    fn decode_all_sync(codec: &mut SyncFrameCodec, buf: &mut BytesMut) -> Vec<Frame> {
        let mut out = Vec::new();
        while let Some(f) = codec.decode(buf).unwrap() {
            out.push(f);
        }
        out
    }

    #[test]
    fn sync_layout_is_magic_plus_plain_frame() {
        let mut buf = BytesMut::new();
        SyncFrameCodec::new().encode(Frame::Bye, &mut buf).unwrap();
        assert_eq!(&buf[..], b"NETM\x00\x00\x00\x01\x06");
        assert_eq!(SYNC_MAGIC, crate::discovery::MAGIC);
    }

    #[test]
    fn sync_round_trip_every_variant() {
        let frames = sample_frames();
        let mut buf = encode_all_sync(&frames);
        let mut codec = SyncFrameCodec::new();
        assert_eq!(decode_all_sync(&mut codec, &mut buf), frames);
        assert!(buf.is_empty());
        assert_eq!(codec.discarded(), 0);
    }

    #[test]
    fn sync_skips_junk_and_partial_frame_before_first_magic() {
        let frames = sample_frames();
        let wire = encode_all_sync(&frames);
        // Start mid-way through the first frame (as if the reader attached
        // late), preceded by unrelated junk that even contains "NET".
        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"garbage NET garbage\x00\xff");
        let cut = 7; // inside the first frame's header
        buf.extend_from_slice(&wire[cut..]);
        let mut codec = SyncFrameCodec::new();
        let got = decode_all_sync(&mut codec, &mut buf);
        assert_eq!(
            got,
            frames[1..].to_vec(),
            "first (partial) frame is lost, rest recovered"
        );
        assert!(buf.is_empty());
        assert!(codec.discarded() > 0);
    }

    #[test]
    fn sync_partial_reads_byte_by_byte_with_leading_junk() {
        let frames = sample_frames();
        let mut wire = BytesMut::from(&b"\x01\x02NE\x03NETX"[..]);
        wire.extend_from_slice(&encode_all_sync(&frames));
        let mut codec = SyncFrameCodec::new();
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        for b in wire.iter() {
            buf.put_u8(*b);
            if let Some(f) = codec.decode(&mut buf).unwrap() {
                out.push(f);
            }
        }
        assert_eq!(out, frames);
        // Junk never accumulates: at most a partial magic is retained.
        assert!(buf.len() < SYNC_MAGIC.len());
    }

    #[test]
    fn sync_magic_inside_junk_with_bogus_length_resyncs() {
        let frames = sample_frames();
        let mut buf = BytesMut::new();
        // Magic followed by an oversized length, then a zero length.
        buf.extend_from_slice(b"NETM\xff\xff\xff\xff");
        buf.extend_from_slice(b"NETM\x00\x00\x00\x00");
        // Magic followed by a plausible (large) length but an unknown type
        // byte: must not wait for the body.
        buf.extend_from_slice(b"NETM\x00\x00\x40\x00\xaa");
        // Magic, valid length and type, but a Ping payload of 2 bytes.
        buf.extend_from_slice(b"NETM\x00\x00\x00\x03\x04\x00\x00");
        buf.extend_from_slice(&encode_all_sync(&frames));
        let mut codec = SyncFrameCodec::new();
        assert_eq!(decode_all_sync(&mut codec, &mut buf), frames);
        assert!(buf.is_empty());
    }

    #[test]
    fn sync_payload_containing_magic_is_not_split() {
        // An IP packet whose payload contains the magic and a fake header.
        let mut pkt = vec![0x45u8; 20];
        pkt.extend_from_slice(b"NETM\x00\x00\x00\x01\x06");
        pkt.extend_from_slice(b"NETM\x00\x00\x00\x09\x04");
        let frames = vec![
            Frame::IpPacket(Bytes::from(pkt)),
            Frame::Ping(7),
            Frame::Bye,
        ];
        let mut buf = encode_all_sync(&frames);
        let mut codec = SyncFrameCodec::new();
        assert_eq!(decode_all_sync(&mut codec, &mut buf), frames);
        assert_eq!(codec.discarded(), 0);
    }

    #[test]
    fn sync_encoder_rejects_oversized_and_leaves_buffer_clean() {
        let too_big = Bytes::from(vec![0u8; MAX_FRAME_SIZE]);
        let mut buf = BytesMut::new();
        let err = SyncFrameCodec::new()
            .encode(Frame::IpPacket(too_big), &mut buf)
            .unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn sync_framed_over_duplex_with_late_reader() {
        use futures::{SinkExt, StreamExt};
        use tokio::io::AsyncWriteExt;
        let (mut a, b) = tokio::io::duplex(64 * 1024);
        // Raw junk first (the "other end was already running" case),
        // ending in a partial magic.
        a.write_all(b"\x00\x11\x22NET").await.unwrap();
        let mut fa = framed_sync(a);
        let mut fb = framed_sync(b);
        let frames = sample_frames();
        for f in &frames {
            fa.send(f.clone()).await.unwrap();
        }
        let mut got = Vec::new();
        while got.len() < frames.len() {
            got.push(fb.next().await.unwrap().unwrap());
        }
        assert_eq!(got, frames);
    }

    #[test]
    fn frame_io_is_object_safe() {
        fn takes(_: &dyn FrameIo) {}
        let (a, _b) = tokio::io::duplex(16);
        let plain = framed(a);
        takes(&plain);
        let (c, _d) = tokio::io::duplex(16);
        let boxed: Box<dyn FrameIo> = Box::new(framed_sync(c));
        takes(boxed.as_ref());
    }

    #[test]
    fn framed_transports_use_tunnel_write_boundary() {
        let (a, _b) = tokio::io::duplex(16);
        assert_eq!(framed(a).backpressure_boundary(), WRITE_BUFFER_BOUNDARY);
        let (a, _b) = tokio::io::duplex(16);
        assert_eq!(
            framed_sync(a).backpressure_boundary(),
            WRITE_BUFFER_BOUNDARY
        );
    }
}
