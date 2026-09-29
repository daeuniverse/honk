//! Lazy VLESS response-header stripping and XTLS Vision framing.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use crate::transport_quality::RawObserver;
use crate::transport_quality::tcp::ObservedTcp;
use bytes::{Buf, BufMut, BytesMut};
use rand::RngExt as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use super::super::encryption::EncryptedStream;
use crate::proxy::{AsyncReadWrite, ProxyStream};

mod tls;
use tls::{InnerTls, Terminal};

/// Paths a Vision Direct command selects for one direction.
///
/// Reads return `None` to keep the ordinary outer stream. The concrete TLS
/// impl switches to the raw TCP socket under the TLS session. EncryptedStream
/// bypasses only AEAD and keeps its ordinary boxed outer stream.
pub(super) trait DirectIo {
    /// Without Direct writes the uplink ends padding with End, never Direct.
    const DIRECT_WRITE: bool = false;

    fn poll_direct_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Option<Poll<io::Result<()>>> {
        None
    }

    fn poll_direct_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(no_direct_writer()))
    }

    fn poll_direct_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(no_direct_writer()))
    }

    /// Keeps the outer codec from emitting anything once the uplink is Direct.
    fn seal_outer_write(&mut self) {}

    /// Plaintext the outer codec decoded ahead of the raw stream.
    fn has_buffered_input(&self) -> bool {
        false
    }
}

fn no_direct_writer() -> io::Error {
    io::Error::other("Vision Direct write without a direct writer")
}

impl DirectIo for ObservedTcp {
    fn poll_direct_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Option<Poll<io::Result<()>>> {
        Some(AsyncRead::poll_read(self, cx, buf))
    }
}

impl DirectIo for tokio_boring::SslStream<ObservedTcp> {
    const DIRECT_WRITE: bool = true;

    fn poll_direct_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Option<Poll<io::Result<()>>> {
        if self.has_buffered_input() {
            return Some(AsyncRead::poll_read(self, cx, buf));
        }
        Some(Pin::new(self.get_mut().get_mut()).poll_read(cx, buf))
    }

    fn poll_direct_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.get_mut().get_mut()).poll_write(cx, buf)
    }

    fn poll_direct_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().get_mut()).poll_shutdown(cx)
    }

    // Reads may still dispatch a fatal alert or flush a queued KeyUpdate
    // acknowledgement; marking the write half closed makes BoringSSL drop
    // both instead of writing a TLS record into the raw uplink. It sends no
    // close_notify and leaves the read half working.
    fn seal_outer_write(&mut self) {
        use foreign_types::ForeignTypeRef as _;

        let ssl = self.ssl_mut().as_ptr();
        unsafe {
            boring_sys::SSL_set_shutdown(
                ssl,
                boring_sys::SSL_get_shutdown(ssl) | boring_sys::SSL_SENT_SHUTDOWN,
            );
        }
    }

    fn has_buffered_input(&self) -> bool {
        self.ssl().pending() > 0
    }
}

// Do not delegate into the boxed inner transport: Encryption Direct retains it.
impl DirectIo for EncryptedStream {
    const DIRECT_WRITE: bool = true;

    fn poll_direct_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Option<Poll<io::Result<()>>> {
        Some(self.get_mut().poll_direct_read(cx, buf))
    }

    fn poll_direct_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_direct_write(cx, buf)
    }

    fn poll_direct_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }

    fn has_buffered_input(&self) -> bool {
        self.has_buffered_plaintext()
    }
}

impl DirectIo for Box<dyn AsyncReadWrite> {}

/// Real servers emit the response prefix with the target's first downstream
/// bytes. Stripping it on the first read avoids deadlocking targets that wait
/// for client data before responding.
#[derive(Debug)]
pub(super) struct ResponseHeaderStrip<S> {
    inner: S,
    state: StripState,
}

#[derive(Debug)]
enum StripState {
    Header { filled: usize, buf: [u8; 2] },
    Addon { remaining: usize },
    Body,
}

impl<S: AsyncRead + Unpin> ResponseHeaderStrip<S> {
    pub(super) fn new(inner: S) -> Self {
        Self {
            inner,
            state: StripState::Header {
                filled: 0,
                buf: [0; 2],
            },
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ResponseHeaderStrip<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Self { inner, state, .. } = &mut *self;
        loop {
            match state {
                StripState::Header { filled, buf: hdr } => {
                    while *filled < 2 {
                        let mut rb = ReadBuf::new(&mut hdr[*filled..]);
                        match Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Ready(Ok(())) => {
                                if rb.filled().is_empty() {
                                    return Poll::Ready(Ok(()));
                                }
                                *filled += rb.filled().len();
                            }
                        }
                    }
                    let [version, addon_len] = *hdr;
                    if version != 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            crate::proxy::NodeFailure(anyhow::anyhow!(
                                "VLESS: server rejected request (code 0x{version:02x})"
                            )),
                        )));
                    }
                    *state = if addon_len > 0 {
                        StripState::Addon {
                            remaining: addon_len as usize,
                        }
                    } else {
                        StripState::Body
                    };
                }
                StripState::Addon { remaining } => {
                    let mut scratch = [0u8; 256];
                    let count = (*remaining).min(scratch.len());
                    let mut rb = ReadBuf::new(&mut scratch[..count]);
                    match Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            if rb.filled().is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            *remaining -= rb.filled().len();
                            if *remaining == 0 {
                                *state = StripState::Body;
                            }
                        }
                    }
                }
                StripState::Body => return Pin::new(&mut *inner).poll_read(cx, buf),
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ResponseHeaderStrip<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: DirectIo + Unpin> DirectIo for ResponseHeaderStrip<S> {
    const DIRECT_WRITE: bool = S::DIRECT_WRITE;

    fn poll_direct_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Option<Poll<io::Result<()>>> {
        Pin::new(&mut self.get_mut().inner).poll_direct_read(cx, buf)
    }

    fn poll_direct_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_direct_write(cx, buf)
    }

    fn poll_direct_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_direct_shutdown(cx)
    }

    fn seal_outer_write(&mut self) {
        self.inner.seal_outer_write();
    }

    fn has_buffered_input(&self) -> bool {
        self.inner.has_buffered_input()
    }
}

/// XTLS Vision framing in both directions.
///
/// Each direction switches independently: a downstream Direct command
/// changes only reads, and this side's own End or Direct frame changes only
/// writes. Bytes already accepted through Vision and the outer codec always
/// leave before the switched path carries anything.
#[derive(Debug)]
pub(super) struct VisionStream<S> {
    inner: S,
    uuid: [u8; 16],
    inbox: BytesMut,
    state: VisionState,
    inner_eof: bool,
    tls: InnerTls,
    write: WriteState,
    /// Accepted uplink frame bytes the outer codec has not taken yet.
    outbox: BytesMut,
}

#[derive(Debug)]
enum VisionState {
    Detect,
    Framed {
        content_remaining: usize,
        padding_remaining: usize,
        command: u8,
    },
    Raw,
    Direct,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteState {
    Padding,
    /// The terminal frame is queued; the switch happens once it has left.
    Draining {
        direct: bool,
    },
    Outer,
    Direct,
}

pub(super) const VISION_COMMAND_END: u8 = Terminal::End as u8;
pub(super) const VISION_COMMAND_DIRECT: u8 = Terminal::Direct as u8;
/// UUID, command and both length fields, as Xray budgets its 8 KiB buffer.
const FRAME_OVERHEAD: usize = 21;
const FRAME_LIMIT: usize = 8192;

/// Sends the VLESS request before the carrier is handed out, so its failures
/// and deadline stay inside the dial, then wraps `inner` for the response.
/// A Vision flow adds its first frame to the same write.
pub(super) async fn start<S>(
    mut inner: S,
    header: &[u8],
    vision: Option<[u8; 16]>,
) -> io::Result<Box<dyn AsyncReadWrite>>
where
    S: AsyncReadWrite + DirectIo + 'static,
{
    let Some(uuid) = vision else {
        inner.write_all(header).await?;
        inner.flush().await?;
        return Ok(Box::new(ResponseHeaderStrip::new(inner)));
    };
    inner.write_all(&vision_request(header, uuid)).await?;
    inner.flush().await?;
    Ok(Box::new(VisionStream::new(
        ResponseHeaderStrip::new(inner),
        uuid,
    )))
}

/// The VLESS request followed by Vision's first frame.
///
/// Xray's client sends an empty long-padded frame when no payload is ready,
/// so the request length never appears on its own.
fn vision_request(header: &[u8], uuid: [u8; 16]) -> BytesMut {
    // An empty long-padded frame is at most 5 + 1399 bytes.
    let mut request = BytesMut::with_capacity(header.len() + uuid.len() + 1404);
    request.extend_from_slice(header);
    request.extend_from_slice(&uuid);
    encode_frame(&mut request, Terminal::Continue, &[], true);
    request
}

/// Appends one Vision frame with Xray's default `testseed` padding.
fn encode_frame(out: &mut BytesMut, terminal: Terminal, content: &[u8], long_padding: bool) {
    let mut rng = rand::rng();
    let padding = if long_padding && content.len() < 900 {
        rng.random_range(0..500) + 900 - content.len()
    } else {
        rng.random_range(0..256)
    }
    .min(FRAME_LIMIT - FRAME_OVERHEAD - content.len());
    out.reserve(5 + content.len() + padding);
    out.put_u8(terminal as u8);
    out.put_u16(content.len() as u16);
    out.put_u16(padding as u16);
    out.put_slice(content);
    out.resize(out.len() + padding, 0);
}

impl<S> VisionStream<S> {
    /// Wraps a stream for Vision framing. [`start`] writes the request and
    /// first Vision frame, including the UUID prefix, before calling this.
    pub(super) fn new(inner: S, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            inbox: BytesMut::new(),
            state: VisionState::Detect,
            inner_eof: false,
            tls: InnerTls::default(),
            write: WriteState::Padding,
            outbox: BytesMut::new(),
        }
    }
}

impl<S: DirectIo> VisionStream<S> {
    /// Both directions are Direct and nothing waits in Vision or the codec,
    /// so the raw socket alone carries the rest of the connection.
    fn raw_ready(&self) -> bool {
        self.write == WriteState::Direct
            && matches!(self.state, VisionState::Direct)
            && self.inbox.is_empty()
            && !self.inner_eof
            && !self.inner.has_buffered_input()
    }
}

impl<S: AsyncWrite + DirectIo + Unpin> VisionStream<S> {
    /// Hands queued frame bytes to the outer codec, then completes a pending
    /// End or Direct switch.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.outbox.is_empty() {
            let written = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.outbox))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.outbox.advance(written);
        }
        let WriteState::Draining { direct } = self.write else {
            return Poll::Ready(Ok(()));
        };
        if direct {
            // The peer switches its reader after this frame: every outer
            // byte must precede the first raw one.
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
            self.inner.seal_outer_write();
            self.write = WriteState::Direct;
        } else {
            self.write = WriteState::Outer;
        }
        self.outbox = BytesMut::new();
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + DirectIo + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        match this.write {
            WriteState::Outer => Pin::new(&mut this.inner).poll_write(cx, buf),
            WriteState::Direct => Pin::new(&mut this.inner).poll_direct_write(cx, buf),
            WriteState::Padding | WriteState::Draining { .. } if buf.is_empty() => {
                Poll::Ready(Ok(0))
            }
            WriteState::Padding | WriteState::Draining { .. } => {
                let frame = this.tls.plan_uplink(buf, S::DIRECT_WRITE);
                encode_frame(
                    &mut this.outbox,
                    frame.terminal,
                    &buf[..frame.take],
                    frame.long_padding,
                );
                if frame.terminal != Terminal::Continue {
                    this.write = WriteState::Draining {
                        direct: frame.terminal == Terminal::Direct,
                    };
                }
                // The frame is accepted either way; a Pending drain resumes
                // on the next write or flush.
                if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(frame.take))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        match this.write {
            // The outer session no longer owns the uplink: close_notify
            // would reach the target as payload.
            WriteState::Direct => Pin::new(&mut this.inner).poll_direct_shutdown(cx),
            _ => Pin::new(&mut this.inner).poll_shutdown(cx),
        }
    }
}

impl<S: AsyncRead + DirectIo + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let start = buf.filled().len();
        let poll = Pin::new(&mut *this).poll_unpadded(cx, buf);
        if let Poll::Ready(Ok(())) = poll {
            this.tls.observe_downlink(&buf.filled()[start..]);
        }
        poll
    }
}

impl<S: AsyncRead + DirectIo + Unpin> VisionStream<S> {
    fn poll_unpadded(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let initial_filled = buf.filled().len();

        loop {
            let needs_inner_read = {
                let this = &mut *self;
                let state = std::mem::replace(&mut this.state, VisionState::Failed);
                match state {
                    VisionState::Detect => {
                        if this.inbox.len() < 21 {
                            if this.inner_eof {
                                this.state = VisionState::Raw;
                                continue;
                            }
                            this.state = VisionState::Detect;
                            true
                        } else if this.inbox[..16] == this.uuid {
                            this.inbox.advance(16);
                            this.state = VisionState::Framed {
                                content_remaining: 0,
                                padding_remaining: 0,
                                command: 0,
                            };
                            continue;
                        } else {
                            this.state = VisionState::Raw;
                            continue;
                        }
                    }
                    VisionState::Framed {
                        mut content_remaining,
                        mut padding_remaining,
                        command,
                    } => {
                        if content_remaining > 0 {
                            let count =
                                content_remaining.min(this.inbox.len()).min(buf.remaining());
                            if count > 0 {
                                buf.put_slice(&this.inbox[..count]);
                                this.inbox.advance(count);
                                content_remaining -= count;
                            }
                            this.state = VisionState::Framed {
                                content_remaining,
                                padding_remaining,
                                command,
                            };
                            if buf.remaining() == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            if content_remaining == 0 {
                                continue;
                            }
                            if this.inner_eof || buf.filled().len() > initial_filled {
                                return Poll::Ready(Ok(()));
                            }
                            true
                        } else if padding_remaining > 0 {
                            let count = padding_remaining.min(this.inbox.len());
                            this.inbox.advance(count);
                            padding_remaining -= count;
                            this.state = VisionState::Framed {
                                content_remaining,
                                padding_remaining,
                                command,
                            };
                            if padding_remaining == 0 {
                                continue;
                            }
                            if this.inner_eof || buf.filled().len() > initial_filled {
                                return Poll::Ready(Ok(()));
                            }
                            true
                        } else {
                            match command {
                                VISION_COMMAND_END => {
                                    this.state = VisionState::Raw;
                                    continue;
                                }
                                VISION_COMMAND_DIRECT => {
                                    this.state = VisionState::Direct;
                                    continue;
                                }
                                0 => {
                                    if this.inbox.len() < 5 {
                                        this.state = VisionState::Framed {
                                            content_remaining,
                                            padding_remaining,
                                            command,
                                        };
                                        if this.inner_eof || buf.filled().len() > initial_filled {
                                            return Poll::Ready(Ok(()));
                                        }
                                        true
                                    } else {
                                        let command = this.inbox[0];
                                        let content_remaining =
                                            u16::from_be_bytes([this.inbox[1], this.inbox[2]])
                                                as usize;
                                        let padding_remaining =
                                            u16::from_be_bytes([this.inbox[3], this.inbox[4]])
                                                as usize;
                                        this.inbox.advance(5);
                                        this.state = VisionState::Framed {
                                            content_remaining,
                                            padding_remaining,
                                            command,
                                        };
                                        continue;
                                    }
                                }
                                _ => {
                                    this.state = VisionState::Failed;
                                    if buf.filled().len() > initial_filled {
                                        return Poll::Ready(Ok(()));
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                    VisionState::Raw => {
                        this.state = VisionState::Raw;
                        if !this.inbox.is_empty() {
                            let count = this.inbox.len().min(buf.remaining());
                            buf.put_slice(&this.inbox[..count]);
                            this.inbox.advance(count);
                            return Poll::Ready(Ok(()));
                        }
                        if buf.filled().len() > initial_filled {
                            return Poll::Ready(Ok(()));
                        }
                        return Pin::new(&mut this.inner).poll_read(cx, buf);
                    }
                    VisionState::Direct => {
                        this.state = VisionState::Direct;
                        if !this.inbox.is_empty() {
                            let count = this.inbox.len().min(buf.remaining());
                            buf.put_slice(&this.inbox[..count]);
                            this.inbox.advance(count);
                            return Poll::Ready(Ok(()));
                        }
                        if buf.filled().len() > initial_filled {
                            return Poll::Ready(Ok(()));
                        }
                        if let Some(poll) = Pin::new(&mut this.inner).poll_direct_read(cx, buf) {
                            return poll;
                        }
                        this.state = VisionState::Raw;
                        continue;
                    }
                    VisionState::Failed => {
                        this.state = VisionState::Failed;
                        if buf.filled().len() > initial_filled {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            crate::proxy::NodeFailure(anyhow::anyhow!(
                                "vision: unknown padding command"
                            )),
                        )));
                    }
                }
            };

            debug_assert!(needs_inner_read);
            let this = &mut *self;
            let old_len = this.inbox.len();
            this.inbox.resize(old_len + 8192, 0);
            let (poll, filled) = {
                let mut read_buf = ReadBuf::new(&mut this.inbox[old_len..]);
                let poll = Pin::new(&mut this.inner).poll_read(cx, &mut read_buf);
                (poll, read_buf.filled().len())
            };
            match poll {
                Poll::Pending => {
                    this.inbox.truncate(old_len);
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => {
                    this.inbox.truncate(old_len);
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(())) => {
                    this.inbox.truncate(old_len + filled);
                    if filled == 0 {
                        this.inner_eof = true;
                    }
                }
            }
        }
    }
}

type VisionTls = VisionStream<ResponseHeaderStrip<crate::tls::TlsStream<ObservedTcp>>>;

/// An unencrypted Vision TLS/REALITY carrier whose TCP socket a relay may
/// borrow once both directions are Direct.
///
/// The whole Vision and TLS stack stays owned here while the socket is lent,
/// so a relay that cannot splice resumes through the same stream.
#[derive(Debug)]
pub struct VisionSplice {
    stream: Box<VisionTls>,
    ready: Arc<AtomicBool>,
}

impl ProxyStream {
    /// Returns the carrier as a [`VisionSplice`] when it is an unencrypted
    /// Vision TLS/REALITY stream owned by nothing else.
    pub fn into_vision_splice(self) -> Result<VisionSplice, Self> {
        // Vtable dispatch required — see `into_tcp_stream`.
        if !(*self.stream).as_any().is::<VisionTls>() {
            return Err(self);
        }
        let stream = self
            .stream
            .into_any()
            .downcast::<VisionTls>()
            .expect("Vision carrier type checked above");
        Ok(VisionSplice {
            stream,
            ready: Arc::default(),
        })
    }
}

impl VisionSplice {
    /// Set after every I/O call that leaves [`Self::raw_parts`] available.
    pub fn ready_signal(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.ready)
    }

    /// Lends the raw socket and its pressure sampler while nothing is
    /// buffered above it in either direction. Vision must not be polled
    /// until the borrow ends.
    pub fn raw_parts(&mut self) -> Option<(&TcpStream, RawObserver<'_>)> {
        if !self.stream.raw_ready() {
            return None;
        }
        Some(self.stream.inner.inner.get_mut().raw_parts())
    }

    /// Which directions have switched to Direct: `(uplink, downlink)`.
    #[cfg(test)]
    pub(in crate::proxy::vless) fn direct_state(&self) -> (bool, bool) {
        (
            self.stream.write == WriteState::Direct,
            matches!(self.stream.state, VisionState::Direct),
        )
    }

    fn publish<T>(&self, poll: Poll<T>) -> Poll<T> {
        self.ready.store(self.stream.raw_ready(), Ordering::Relaxed);
        poll
    }
}

impl AsyncRead for VisionSplice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut *self.stream).poll_read(cx, buf);
        self.publish(poll)
    }
}

impl AsyncWrite for VisionSplice {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut *self.stream).poll_write(cx, buf);
        self.publish(poll)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut *self.stream).poll_flush(cx);
        self.publish(poll)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut *self.stream).poll_shutdown(cx);
        self.publish(poll)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::AsyncReadExt as _;

    use super::*;

    #[derive(Debug)]
    struct SplitDirectReader {
        framed: VecDeque<u8>,
        direct: VecDeque<u8>,
        framed_chunks: VecDeque<usize>,
        direct_chunk: usize,
        direct_polls: Arc<AtomicUsize>,
    }

    impl AsyncRead for SplitDirectReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let limit = self.framed_chunks.pop_front().unwrap_or(self.framed.len());
            let count = limit.min(self.framed.len()).min(buf.remaining());
            let (front, _) = self.framed.as_slices();
            buf.put_slice(&front[..count]);
            self.framed.drain(..count);
            Poll::Ready(Ok(()))
        }
    }

    impl DirectIo for SplitDirectReader {
        fn poll_direct_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Option<Poll<io::Result<()>>> {
            self.direct_polls.fetch_add(1, Ordering::Relaxed);
            let count = self
                .direct_chunk
                .min(self.direct.len())
                .min(buf.remaining());
            let (front, _) = self.direct.as_slices();
            buf.put_slice(&front[..count]);
            self.direct.drain(..count);
            Some(Poll::Ready(Ok(())))
        }
    }

    #[tokio::test]
    async fn direct_waits_for_partial_frame_and_buffered_plaintext() {
        let uuid = [7_u8; 16];
        let mut framed = uuid.to_vec();
        framed.extend_from_slice(&[VISION_COMMAND_DIRECT, 0, 7, 0, 1]);
        framed.extend_from_slice(b"framed-");
        framed.push(0);
        framed.extend_from_slice(b"buffered-");
        let direct_polls = Arc::new(AtomicUsize::new(0));
        let reader = SplitDirectReader {
            framed: framed.into(),
            direct: b"direct".iter().copied().collect(),
            framed_chunks: vec![18, usize::MAX].into(),
            direct_chunk: 1,
            direct_polls: Arc::clone(&direct_polls),
        };
        let mut stream = VisionStream::new(reader, uuid);
        let mut output = Vec::new();

        stream.read_to_end(&mut output).await.unwrap();

        assert_eq!(output, b"framed-buffered-direct");
        assert!(direct_polls.load(Ordering::Relaxed) > 1);
    }
}
