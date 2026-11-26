//! Inbound message-boundary evidence for the physical VMess WebSocket carrier.

use std::io::{self, Cursor, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::protocol::frame::{
    FrameHeader,
    coding::{Control, Data, OpCode},
};

const MAX_HEADER_LEN: usize = 14;

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct LowerReset(io::Error);

pub(super) fn restore_reset(error: io::Error) -> io::Error {
    match error.downcast::<LowerReset>() {
        Ok(LowerReset(original)) => original,
        Err(error) => error,
    }
}

#[derive(Debug)]
enum Upgrade {
    Response { started: bool, nonempty_line: bool },
    Tail,
    Finished,
}

#[derive(Clone, Copy, Debug)]
enum Boundary {
    Message,
    Fragment,
    Close,
    Invalid,
}

#[derive(Debug)]
pub(super) struct WsCloseWire<S> {
    inner: S,
    upgrade: Upgrade,
    boundary: Boundary,
    remaining: u64,
    header: [u8; MAX_HEADER_LEN],
    header_len: usize,
}

impl<S> WsCloseWire<S> {
    pub(super) fn new(inner: S) -> Self {
        Self {
            inner,
            upgrade: Upgrade::Response {
                started: false,
                nonempty_line: false,
            },
            boundary: Boundary::Message,
            remaining: 0,
            header: [0; MAX_HEADER_LEN],
            header_len: 0,
        }
    }

    pub(super) fn finish_upgrade(&mut self) {
        // The codec already owns the tail. Without a known HTTP boundary there
        // is no way to start observing frames at a known offset now.
        if !matches!(self.upgrade, Upgrade::Tail) {
            self.boundary = Boundary::Invalid;
        }
        self.upgrade = Upgrade::Finished;
    }

    /// This only witnesses framing and lower I/O. The bridge must also have
    /// received a decoded, normal peer Close and completed its reply and shutdown.
    pub(super) fn eligible_close(&self) -> bool {
        matches!(self.upgrade, Upgrade::Finished)
            && matches!(self.boundary, Boundary::Close)
            && self.remaining == 0
    }

    fn observe_codec_error(&mut self, error: io::Error) -> io::Error {
        self.boundary = Boundary::Invalid;
        // After Close, tungstenite can turn a lower reset into ConnectionClosed,
        // which the async codec reports as EOF or a successful flush.
        if matches!(self.upgrade, Upgrade::Finished)
            && error.kind() == io::ErrorKind::ConnectionReset
        {
            io::Error::other(LowerReset(error))
        } else {
            error
        }
    }

    fn observe_zero_write(&mut self) -> Poll<io::Result<usize>> {
        self.boundary = Boundary::Invalid;
        if matches!(self.upgrade, Upgrade::Finished) {
            // Match FrameCodec's synthetic reset and shield it before a
            // closing-state flush can report success.
            let original = io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Connection reset while sending",
            );
            Poll::Ready(Err(io::Error::other(LowerReset(original))))
        } else {
            Poll::Ready(Ok(0))
        }
    }

    fn observe(&mut self, mut bytes: &[u8]) {
        if let Upgrade::Response {
            started,
            nonempty_line,
        } = &mut self.upgrade
        {
            // httparse skips leading empty lines and accepts both LF and CRLF.
            // The real handshake validates the response before enabling evidence.
            let Some(end) = bytes.iter().position(|&byte| match byte {
                b'\n' if *started && !*nonempty_line => true,
                b'\n' => {
                    *nonempty_line = false;
                    false
                }
                b'\r' => false,
                _ => {
                    *started = true;
                    *nonempty_line = true;
                    false
                }
            }) else {
                return;
            };
            self.upgrade = Upgrade::Tail;
            bytes = &bytes[end + 1..];
        }

        while !bytes.is_empty() && !matches!(self.boundary, Boundary::Invalid) {
            let skip = self.remaining.min(bytes.len() as u64) as usize;
            self.remaining -= skip as u64;
            bytes = &bytes[skip..];
            if bytes.is_empty() {
                return;
            }
            // Freeze the first Close boundary. Even a partial frame after it
            // could otherwise look like clean EOF to the codec.
            if matches!(self.boundary, Boundary::Close) {
                self.boundary = Boundary::Invalid;
                return;
            }
            let Some((header, length)) = self.read_header(&mut bytes) else {
                return;
            };
            self.boundary = match (self.boundary, header.opcode) {
                (Boundary::Message, OpCode::Control(Control::Close)) if length != 1 => {
                    Boundary::Close
                }
                (boundary, OpCode::Control(Control::Ping | Control::Pong)) => boundary,
                (Boundary::Fragment, OpCode::Data(Data::Continue))
                | (Boundary::Message, OpCode::Data(Data::Binary | Data::Text)) => {
                    if header.is_final {
                        Boundary::Message
                    } else {
                        Boundary::Fragment
                    }
                }
                _ => Boundary::Invalid,
            };
            self.remaining = length;
        }
    }

    fn read_header(&mut self, bytes: &mut &[u8]) -> Option<(FrameHeader, u64)> {
        let input = if self.header_len == 0 {
            *bytes
        } else {
            // Only a split header needs scratch space. The length tag tells
            // how much header to copy without pulling any payload into it.
            let tag = if self.header_len == 1 {
                bytes[0]
            } else {
                self.header[1]
            };
            let extra = match tag & 0x7f {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            let mask_len = if tag & 0x80 == 0 { 0 } else { 4 };
            let total = 2 + extra + mask_len;
            let take = (total - self.header_len).min(bytes.len());
            let end = self.header_len + take;
            self.header[self.header_len..end].copy_from_slice(&bytes[..take]);
            self.header_len = end;
            *bytes = &bytes[take..];
            if end != total {
                return None;
            }
            &self.header[..total]
        };
        let mut cursor = Cursor::new(input);
        let (header, length) = match FrameHeader::parse(&mut cursor) {
            Ok(Some(parsed)) => parsed,
            Ok(None) if self.header_len == 0 && bytes.len() < MAX_HEADER_LEN => {
                self.header[..bytes.len()].copy_from_slice(bytes);
                self.header_len = bytes.len();
                return None;
            }
            _ => {
                self.boundary = Boundary::Invalid;
                return None;
            }
        };
        let consumed = cursor.position() as usize;
        if self.header_len == 0 {
            *bytes = &bytes[consumed..];
        } else {
            if consumed != self.header_len {
                self.boundary = Boundary::Invalid;
                return None;
            }
            self.header_len = 0;
        }
        if header.mask.is_some()
            || header.rsv1
            || header.rsv2
            || header.rsv3
            || consumed != header.len(length)
            || length > i64::MAX as u64
            || matches!(header.opcode, OpCode::Control(_)) && (!header.is_final || length > 125)
        {
            self.boundary = Boundary::Invalid;
            return None;
        }
        Some((header, length))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WsCloseWire<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        match result {
            Poll::Ready(Ok(())) if buf.filled().len() > start => {
                self.observe(&buf.filled()[start..])
            }
            Poll::Ready(Ok(())) if buf.remaining() != 0 && !self.eligible_close() => {
                self.boundary = Boundary::Invalid;
            }
            _ => {}
        }
        result.map_err(|error| self.observe_codec_error(error))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WsCloseWire<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(0))) && !buf.is_empty() {
            return self.observe_zero_write();
        }
        result.map_err(|error| self.observe_codec_error(error))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if matches!(result, Poll::Ready(Ok(0))) && bufs.iter().any(|buf| !buf.is_empty()) {
            return self.observe_zero_write();
        }
        result.map_err(|error| self.observe_codec_error(error))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            self.boundary = Boundary::Invalid;
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            self.boundary = Boundary::Invalid;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    use tokio_tungstenite::tungstenite::{
        Message,
        client::IntoClientRequest,
        http::header::{HeaderValue, SEC_WEBSOCKET_KEY},
        protocol::frame::coding::CloseCode,
    };

    #[tokio::test]
    async fn upgrade_tail_tracks_a_split_fragmented_message_until_close() {
        let header = [0x02, 126, 0, 126];
        let mut payload = [0; 126];
        payload[..2].copy_from_slice(&[0x88, 0]); // Looks like a Close only outside the payload.
        for (cut, complete) in [(1, true), (2, true), (3, true), (3, false), (4, false)] {
            let (client, mut peer) = tokio::io::duplex(4096);
            let mut request = "ws://example.test/".into_client_request().unwrap();
            request.headers_mut().insert(
                SEC_WEBSOCKET_KEY,
                HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
            );
            let mut response = b"HTTP/1.1 101 Switching Protocols\r\n\
                Upgrade: websocket\r\n\
                Connection: Upgrade\r\n\
                Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
                .to_vec();
            // The peer queues these bytes before the handshake reads, so the
            // header prefix enters the codec through its HTTP read-ahead path.
            response.extend_from_slice(&header[..cut]);
            peer.write_all(&response).await.unwrap();
            let (mut ws, _) = tokio_tungstenite::client_async(request, WsCloseWire::new(client))
                .await
                .unwrap();
            ws.get_mut().finish_upgrade();
            assert!(!ws.get_ref().eligible_close());

            peer.write_all(&header[cut..]).await.unwrap();
            peer.write_all(&payload).await.unwrap();
            if complete {
                peer.write_all(&[0x80, 0]).await.unwrap();
                let Some(Ok(Message::Binary(data))) = ws.next().await else {
                    panic!("peer's completed fragmented Binary was not delivered");
                };
                assert_eq!(data.as_ref(), &payload[..]);
                assert!(!ws.get_ref().eligible_close());
            }

            peer.write_all(&[0x88, 2, 0x03, 0xe8]).await.unwrap();
            let Some(Ok(Message::Close(Some(close)))) = ws.next().await else {
                panic!("peer's Close was not delivered");
            };
            assert_eq!(close.code, CloseCode::Normal);
            assert_eq!(ws.get_ref().eligible_close(), complete, "header cut {cut}");
        }
    }
}
