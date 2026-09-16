//! Adapter that presents the framed tunnel as the packet-oriented
//! `AsyncRead + AsyncWrite` device expected by [`ipstack`].
//!
//! `ipstack` was written for TUN file descriptors, where **one `read` returns
//! exactly one IP packet** and **one `write` sends exactly one IP packet**. A
//! byte-stream pair such as [`tokio::io::duplex`] would merge or split packets
//! and corrupt the stack's parser, so this module implements its own device:
//!
//! - [`PacketDevice::poll_read`] pops one [`Bytes`] packet from an inbound
//!   channel and copies it into the caller's buffer. A packet that does not fit
//!   the buffer (i.e. is larger than the configured MTU) is dropped with a
//!   warning instead of being truncated.
//! - [`PacketDevice::poll_write`] treats the whole `buf` as one packet, copies
//!   it into a [`Bytes`] and pushes it to an outbound channel. It always
//!   accepts the full buffer so `write_all` never splits a packet.
//!
//! The session code wraps every outbound packet into
//! [`netm_proto::Frame::IpPacket`] and feeds every inbound `IpPacket` payload
//! into the inbound channel.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

/// Packet-boundary-preserving device backed by two channels.
pub struct PacketDevice {
    /// Packets from the guest, to be read by the stack.
    inbound: mpsc::Receiver<Bytes>,
    /// Packets produced by the stack, to be sent to the guest.
    outbound: PollSender<Bytes>,
}

impl PacketDevice {
    /// Build a device from an inbound receiver and an outbound sender.
    pub fn new(inbound: mpsc::Receiver<Bytes>, outbound: mpsc::Sender<Bytes>) -> Self {
        Self {
            inbound,
            outbound: PollSender::new(outbound),
        }
    }

    /// Convenience constructor: returns the device plus the two channel ends
    /// the session uses (`to_stack` to inject guest packets, `from_stack` to
    /// collect packets destined for the guest).
    pub fn channel(capacity: usize) -> (Self, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
        let (to_stack_tx, to_stack_rx) = mpsc::channel(capacity);
        let (from_stack_tx, from_stack_rx) = mpsc::channel(capacity);
        (
            Self::new(to_stack_rx, from_stack_tx),
            to_stack_tx,
            from_stack_rx,
        )
    }
}

impl AsyncRead for PacketDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.inbound.poll_recv(cx) {
                Poll::Ready(Some(pkt)) => {
                    if pkt.len() > buf.remaining() {
                        tracing::warn!(
                            len = pkt.len(),
                            capacity = buf.remaining(),
                            "dropping oversized packet from guest (exceeds MTU)"
                        );
                        continue;
                    }
                    buf.put_slice(&pkt);
                    return Poll::Ready(Ok(()));
                }
                // The session has gone away. `ipstack` would treat `Ok(0)` as
                // an (empty) packet and spin, so park the reader instead; the
                // session drops the `IpStack`, which aborts its task.
                Poll::Ready(None) => return Poll::Pending,
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for PacketDevice {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.outbound.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                if self
                    .outbound
                    .send_item(Bytes::copy_from_slice(buf))
                    .is_err()
                {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.outbound.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn writes_preserve_packet_boundaries() {
        let (mut dev, _to_stack, mut from_stack) = PacketDevice::channel(8);
        dev.write_all(&[1, 2, 3]).await.unwrap();
        dev.write_all(&[4, 5]).await.unwrap();
        dev.write_all(&[6u8; 1400]).await.unwrap();
        assert_eq!(from_stack.recv().await.unwrap().as_ref(), &[1, 2, 3]);
        assert_eq!(from_stack.recv().await.unwrap().as_ref(), &[4, 5]);
        assert_eq!(from_stack.recv().await.unwrap().len(), 1400);
    }

    #[tokio::test]
    async fn reads_return_one_packet_each() {
        let (mut dev, to_stack, _from_stack) = PacketDevice::channel(8);
        to_stack.send(Bytes::from_static(b"abc")).await.unwrap();
        to_stack.send(Bytes::from_static(b"de")).await.unwrap();
        let mut buf = [0u8; 64];
        let n = dev.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abc");
        let n = dev.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"de");
    }

    #[tokio::test]
    async fn oversized_packets_are_dropped_not_truncated() {
        let (mut dev, to_stack, _from_stack) = PacketDevice::channel(8);
        to_stack.send(Bytes::from(vec![9u8; 100])).await.unwrap();
        to_stack.send(Bytes::from_static(b"ok")).await.unwrap();
        let mut buf = [0u8; 16];
        let n = dev.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ok");
    }

    #[tokio::test]
    async fn write_backpressure_then_release() {
        let (mut dev, _to_stack, mut from_stack) = PacketDevice::channel(1);
        dev.write_all(b"1").await.unwrap();
        // Channel full: second write must be pending until a slot frees up.
        let pending =
            tokio::time::timeout(std::time::Duration::from_millis(50), dev.write_all(b"2")).await;
        assert!(pending.is_err(), "write should block while channel is full");
        assert_eq!(from_stack.recv().await.unwrap().as_ref(), b"1");
        dev.write_all(b"2").await.unwrap();
        assert_eq!(from_stack.recv().await.unwrap().as_ref(), b"2");
    }

    #[tokio::test]
    async fn write_after_receiver_dropped_is_broken_pipe() {
        let (mut dev, _to_stack, from_stack) = PacketDevice::channel(1);
        drop(from_stack);
        let err = dev.write_all(b"x").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn read_after_sender_dropped_stays_pending() {
        let (mut dev, to_stack, _from_stack) = PacketDevice::channel(1);
        drop(to_stack);
        let mut buf = [0u8; 8];
        let r =
            tokio::time::timeout(std::time::Duration::from_millis(50), dev.read(&mut buf)).await;
        assert!(r.is_err(), "read must not return Ok(0) after close");
    }
}
