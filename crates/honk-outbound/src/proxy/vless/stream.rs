//! Lazy VLESS response-header stripping and XTLS Vision response unpadding.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::super::{AsyncReadWrite, vless_encryption::EncryptedStream};

/// A read path a Vision Direct command may select without changing writes.
///
/// `None` keeps reading the ordinary outer stream. The concrete TLS impl below
/// preserves the unencrypted Vision raw-TCP switch. EncryptedStream instead
/// bypasses only AEAD and continues reading its ordinary boxed outer stream.
pub(super) trait DirectRead {
    fn poll_direct_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Option<Poll<io::Result<()>>> {
        None
    }
}

impl DirectRead for TcpStream {
    fn poll_direct_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Option<Poll<io::Result<()>>> {
        Some(AsyncRead::poll_read(self, cx, buf))
    }
}

impl DirectRead for tokio_boring::SslStream<TcpStream> {
    fn poll_direct_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Option<Poll<io::Result<()>>> {
        Some(Pin::new(self.get_mut().get_mut()).poll_read(cx, buf))
    }
}

// Do not delegate into the boxed inner transport: Encryption Direct retains it.
impl DirectRead for EncryptedStream {
    fn poll_direct_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Option<Poll<io::Result<()>>> {
        Some(self.get_mut().poll_direct_read(cx, buf))
    }
}

impl DirectRead for Box<dyn AsyncReadWrite> {}

impl<T: DirectRead + Unpin + ?Sized> DirectRead for Box<T> {
    fn poll_direct_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Option<Poll<io::Result<()>>> {
        Pin::new(&mut **self.get_mut()).poll_direct_read(cx, buf)
    }
}

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
                            format!("VLESS: server rejected request (code 0x{version:02x})"),
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

impl<S: DirectRead + Unpin> DirectRead for ResponseHeaderStrip<S> {
    fn poll_direct_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Option<Poll<io::Result<()>>> {
        Pin::new(&mut self.get_mut().inner).poll_direct_read(cx, buf)
    }
}

/// XTLS Vision response-side unpadding.
///
/// A Direct command changes only the read path. Bytes already accepted through
/// Vision and the selected outer codec are returned before the direct reader;
/// writes continue through every original wrapper.
#[derive(Debug)]
pub(super) struct VisionStream<S> {
    inner: S,
    uuid: [u8; 16],
    inbox: BytesMut,
    state: VisionState,
    inner_eof: bool,
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

pub(super) const VISION_COMMAND_END: u8 = 1;
pub(super) const VISION_COMMAND_DIRECT: u8 = 2;

impl<S> VisionStream<S> {
    pub(super) fn new(inner: S, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            inbox: BytesMut::new(),
            state: VisionState::Detect,
            inner_eof: false,
        }
    }
}

impl<S: AsyncRead + DirectRead + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
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
                            "vision: unknown padding command",
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

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
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

    impl DirectRead for SplitDirectReader {
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
