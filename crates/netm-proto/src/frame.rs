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
//!
//! Handshake: the guest sends `Hello`, the host answers `Hello` followed by
//! `Config`; afterwards both sides exchange `IpPacket`, `Ping`/`Pong` and
//! finally `Bye`.

use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder, Framed};

use crate::transport::Transport;
use crate::DEFAULT_MTU;

/// Maximum accepted value of the length field (type byte + payload).
pub const MAX_FRAME_SIZE: usize = 65536;

/// Size of the length prefix in bytes.
pub const HEADER_LEN: usize = 4;

const TYPE_HELLO: u8 = 1;
const TYPE_CONFIG: u8 = 2;
const TYPE_IP_PACKET: u8 = 3;
const TYPE_PING: u8 = 4;
const TYPE_PONG: u8 = 5;
const TYPE_BYE: u8 = 6;

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

/// A transport wrapped with [`FrameCodec`]: a `Stream<Item = Result<Frame,
/// FrameError>>` + `Sink<Frame>`.
pub type FramedTransport<T> = Framed<T, FrameCodec>;

/// Wrap a transport with the frame codec.
pub fn framed<T: Transport>(t: T) -> FramedTransport<T> {
    Framed::new(t, FrameCodec)
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
}
