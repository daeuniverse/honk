//! gRPC gun framing over a connection-owned HTTP/2 client.

use super::AsyncReadWrite;
use super::h2_io::{DataProgress, FlushProgress};
type TrackedIo = super::h2_io::TrackedIo<IoProgress>;
type QueuedData = super::h2_io::QueuedData<Arc<IoProgress>>;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::task::{ArcWake, AtomicWaker, waker_ref};
use honk_config::node::Node;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_HEADERS: u32 = 64 * 1024;
const MAX_WRITE: usize = 16 * 1024;
const RECEIVE_WINDOW: u32 = 0x7fff_ffff;
const MIN_ENVELOPE: usize = 7;

pub(super) async fn wrap_grpc(
    node: &Node,
    inner: Box<dyn AsyncReadWrite>,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let service = node
        .transport()
        .unwrap()
        .grpc_service
        .as_deref()
        .unwrap_or("GunService");
    let scheme = if node.tls().unwrap().enabled {
        "https"
    } else {
        "http"
    };
    let authority = match node.host().parse::<std::net::Ipv6Addr>() {
        Ok(address) => http::uri::Authority::try_from(format!("[{address}]"))?,
        Err(_) => http::uri::Authority::try_from(node.host())?,
    };
    let uri = http::Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(format!("/{service}/Tun"))
        .build()?;
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", "honk")
        .body(())?;
    let progress = Arc::new(IoProgress::default());
    let (mut sender, connection) = h2::client::Builder::new()
        .enable_push(false)
        .max_local_error_reset_streams(Some(0))
        .max_header_list_size(MAX_HEADERS)
        .max_send_buffer_size(MAX_WRITE)
        .initial_window_size(RECEIVE_WINDOW)
        .initial_connection_window_size(RECEIVE_WINDOW)
        .handshake(TrackedIo {
            inner,
            progress: progress.clone(),
        })
        .await?;
    poll_fn(|cx| sender.poll_ready(cx)).await?;
    let (response, send) = sender.send_request(request, false)?;
    let mut stream = GrpcStream {
        connection: Some(Box::pin(connection)),
        connection_error: None,
        sender,
        send,
        response: Some(response),
        recv: None,
        progress,
        messages: BytesMut::new(),
        payload: Bytes::new(),
        data_seen: false,
        read_result: None,
        write_closed: false,
        write_pending: false,
        failure: None,
    };
    // The protocol request body may be needed before the peer sends response headers.
    poll_fn(|cx| {
        stream.progress.write.register(cx.waker());
        let progress = stream.progress.clone();
        let waker = waker_ref(&progress);
        let cx = &mut Context::from_waker(&waker);
        stream.poll_connection(cx);
        if stream.connection_error.is_some() {
            return stream.poll_response(cx);
        }
        stream.poll_queued(cx)
    })
    .await?;
    Ok(Box::new(stream))
}

#[derive(Debug, Default)]
struct IoProgress {
    pending: AtomicUsize,
    flushed: AtomicBool,
    read: AtomicWaker,
    write: AtomicWaker,
}

impl ArcWake for IoProgress {
    fn wake_by_ref(this: &Arc<Self>) {
        this.read.wake();
        this.write.wake();
    }
}

impl FlushProgress for IoProgress {
    fn writing(&self) {
        self.flushed.store(false, Ordering::Release);
    }
    fn flushed(&self) {
        if !self.flushed.swap(true, Ordering::AcqRel) {
            self.write.wake();
        }
    }
}

impl DataProgress for IoProgress {
    fn released(&self) {
        self.pending.fetch_sub(1, Ordering::AcqRel);
        self.write.wake();
    }
}

struct GrpcStream {
    connection: Option<Pin<Box<h2::client::Connection<TrackedIo, QueuedData>>>>,
    connection_error: Option<Arc<io::Error>>,
    sender: h2::client::SendRequest<QueuedData>,
    send: h2::SendStream<QueuedData>,
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    progress: Arc<IoProgress>,
    messages: BytesMut,
    payload: Bytes,
    data_seen: bool,
    read_result: Option<Result<(), Arc<io::Error>>>,
    write_closed: bool,
    // h2 can release a copied DATA buffer before flushing its encoded bytes.
    write_pending: bool,
    failure: Option<Arc<io::Error>>,
}

impl std::fmt::Debug for GrpcStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcStream").finish_non_exhaustive()
    }
}

impl GrpcStream {
    fn failure_error(&self) -> Option<io::Error> {
        self.failure
            .as_ref()
            .map(|error| io::Error::new(error.kind(), error.clone()))
    }

    fn fail(&mut self, error: io::Error) -> io::Error {
        let error = self.failure.get_or_insert_with(|| Arc::new(error));
        io::Error::new(error.kind(), error.clone())
    }

    fn io_error(&self, error: h2::Error) -> io::Error {
        if error.is_io()
            && let Some(cause) = &self.connection_error
        {
            return io::Error::new(cause.kind(), cause.clone());
        }
        h2_error(error)
    }

    fn poll_connection(&mut self, cx: &mut Context<'_>) {
        if let Some(connection) = &mut self.connection
            && let Poll::Ready(result) = connection.as_mut().poll(cx)
        {
            if let Err(error) = result {
                self.connection_error
                    .get_or_insert_with(|| Arc::new(h2_error(error)));
            }
            self.connection = None;
        }
        if self.connection_error.is_none()
            && let Poll::Ready(Err(error)) = self.sender.poll_ready(cx)
            && !(error.is_go_away() && error.reason() == Some(h2::Reason::NO_ERROR))
        {
            self.connection_error = Some(Arc::new(h2_error(error)));
        }
    }

    fn pending<T>(&mut self) -> Poll<io::Result<T>> {
        if let Some(error) = self.failure_error() {
            return Poll::Ready(Err(error));
        }
        if self.connection.is_some() && self.connection_error.is_none() {
            Poll::Pending
        } else {
            let error = self.connection_error.as_ref().map_or_else(
                || {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "grpc: HTTP/2 connection stopped",
                    )
                },
                |error| io::Error::new(error.kind(), error.clone()),
            );
            Poll::Ready(Err(self.fail(error)))
        }
    }

    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(response) = &mut self.response else {
            return Poll::Ready(Ok(()));
        };
        let response = match Pin::new(response).poll(cx) {
            Poll::Pending => return self.pending(),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fail(self.io_error(error)))),
            Poll::Ready(Ok(response)) => response,
        };
        self.response = None;
        if response.status() != http::StatusCode::OK {
            return Poll::Ready(Err(self.fail(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("grpc: peer answered HTTP {}", response.status().as_u16()),
            ))));
        }
        let status = grpc_status(response.headers()).map_err(|error| self.fail(error))?;
        if response.body().is_end_stream() {
            let detail = status.map_or_else(
                || "trailers-only response".to_owned(),
                |code| format!("grpc-status {code}"),
            );
            return Poll::Ready(Err(self.fail(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("grpc: stream refused by peer ({detail})"),
            ))));
        }
        if let Some(code) = status.filter(|code| *code != 0) {
            return Poll::Ready(Err(self.fail(status_error(code))));
        }
        self.recv = Some(response.into_body());
        Poll::Ready(Ok(()))
    }

    fn poll_control(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some(error) = self.failure_error() {
            return Err(error);
        }
        self.poll_connection(cx);
        if let Poll::Ready(result) = self.poll_response(cx) {
            result?;
        }
        match self.send.poll_reset(cx) {
            Poll::Ready(Ok(reason)) => {
                return Err(self.fail(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    format!(
                        "grpc: stream reset by peer (error code {})",
                        u32::from(reason)
                    ),
                )));
            }
            Poll::Ready(Err(error)) => return Err(self.fail(self.io_error(error))),
            Poll::Pending => {}
        }
        if let Some(error) = &self.connection_error {
            let error = io::Error::new(error.kind(), error.clone());
            return Err(self.fail(error));
        }
        Ok(())
    }

    fn poll_queued(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.failure_error() {
            return Poll::Ready(Err(error));
        }
        if self.progress.pending.load(Ordering::Acquire) == 0
            && self.progress.flushed.load(Ordering::Acquire)
        {
            self.write_pending = false;
            Poll::Ready(Ok(()))
        } else {
            self.pending()
        }
    }

    fn queue(&mut self, bytes: Bytes, end_stream: bool) -> io::Result<()> {
        self.write_pending = true;
        self.progress.pending.fetch_add(1, Ordering::AcqRel);
        self.progress.flushed.store(false, Ordering::Release);
        self.send
            .send_data(
                QueuedData {
                    bytes,
                    progress: self.progress.clone(),
                },
                end_stream,
            )
            .map_err(|error| self.fail(self.io_error(error)))
    }

    fn decode_message(&mut self) -> bool {
        if self.messages.len() < 5 {
            return false;
        }
        let compressed = self.messages[0];
        let len = u32::from_be_bytes(self.messages[1..5].try_into().unwrap()) as usize;
        let Some(total) = len
            .checked_add(5)
            .filter(|total| *total <= self.messages.len())
        else {
            return false;
        };
        let mut message = self.messages.split_to(total).freeze();
        message.advance(5);
        if compressed == 0
            && message.first() == Some(&0x0a)
            && let Some((len, used)) = parse_varint(&message[1..])
            && len == message.len() - 1 - used
        {
            message.advance(1 + used);
        }
        self.payload = message;
        true
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.payload.is_empty() {
                let len = self.payload.len().min(buf.remaining());
                buf.put_slice(&self.payload[..len]);
                self.payload.advance(len);
                return Poll::Ready(Ok(()));
            }
            if self.decode_message() {
                continue;
            }
            if let Some(result) = &self.read_result {
                return Poll::Ready(match result {
                    Ok(()) => Ok(()),
                    Err(error) => Err(io::Error::new(error.kind(), error.clone())),
                });
            }
            if self.recv.is_none() {
                if let Some(error) = self.failure_error() {
                    return Poll::Ready(Err(error));
                }
                self.poll_connection(cx);
                ready!(self.poll_response(cx))?;
            } else if self.failure.is_none() {
                self.poll_connection(cx);
            }
            let recv = self.recv.as_mut().expect("response established");
            match recv.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    self.data_seen = true;
                    if let Err(error) = recv.flow_control().release_capacity(data.len()) {
                        return Poll::Ready(Err(self.fail(self.io_error(error))));
                    }
                    self.messages.extend_from_slice(&data);
                    continue;
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(self.fail(self.io_error(error))));
                }
                Poll::Pending => return self.pending(),
                Poll::Ready(None) => {}
            }
            let trailers = match recv.poll_trailers(cx) {
                Poll::Ready(Ok(trailers)) => trailers,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(self.fail(self.io_error(error))));
                }
                Poll::Pending => return self.pending(),
            };
            let status = trailers
                .as_ref()
                .map(grpc_status)
                .transpose()
                .map_err(|error| self.fail(error))?
                .flatten();
            match status {
                Some(code) if !self.data_seen => {
                    return Poll::Ready(Err(self.fail(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("grpc: stream refused by peer (grpc-status {code})"),
                    ))));
                }
                Some(code) if code != 0 => return Poll::Ready(Err(self.fail(status_error(code)))),
                None if !self.data_seen && trailers.is_some() => {
                    return Poll::Ready(Err(self.fail(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "grpc: stream refused by peer (trailers-only response)",
                    ))));
                }
                _ => self.read_result = Some(Ok(())),
            }
        }
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        this.progress.read.register(cx.waker());
        let progress = this.progress.clone();
        let waker = waker_ref(&progress);
        let result = this.poll_read_inner(&mut Context::from_waker(&waker), buf);
        if matches!(result, Poll::Ready(Err(_))) {
            this.read_result = Some(Err(this
                .failure
                .as_ref()
                .expect("read errors are recorded")
                .clone()));
        }
        result
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        this.progress.write.register(cx.waker());
        let progress = this.progress.clone();
        let waker = waker_ref(&progress);
        let cx = &mut Context::from_waker(&waker);
        this.poll_control(cx)?;
        if this.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if this.write_pending {
            ready!(this.poll_queued(cx))?;
        }
        this.send
            .reserve_capacity(MAX_WRITE.min(buf.len().saturating_add(16)));
        this.poll_control(cx)?;
        while this.send.capacity() == 0 {
            match this.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(this.fail(this.io_error(error))));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(this.fail(io::ErrorKind::BrokenPipe.into())));
                }
                Poll::Pending => return this.pending(),
            }
        }
        let len = buf.len().min(MAX_WRITE - MIN_ENVELOPE - 1);
        let body_len = 1 + varint_len(len) + len;
        let mut message = Vec::with_capacity(5 + body_len);
        message.push(0);
        message.extend_from_slice(&(body_len as u32).to_be_bytes());
        message.push(0x0a);
        push_varint(&mut message, len);
        message.extend_from_slice(&buf[..len]);
        this.queue(message.into(), false)?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.progress.write.register(cx.waker());
        let progress = this.progress.clone();
        let waker = waker_ref(&progress);
        let cx = &mut Context::from_waker(&waker);
        this.poll_control(cx)?;
        this.poll_queued(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.progress.write.register(cx.waker());
        let progress = this.progress.clone();
        let waker = waker_ref(&progress);
        let cx = &mut Context::from_waker(&waker);
        this.poll_control(cx)?;
        ready!(this.poll_queued(cx))?;
        if !this.write_closed {
            this.queue(Bytes::new(), true)?;
            this.write_closed = true;
        }
        this.poll_control(cx)?;
        this.poll_queued(cx)
    }
}

fn grpc_status(headers: &http::HeaderMap) -> io::Result<Option<u32>> {
    headers
        .get("grpc-status")
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "grpc: invalid response status")
                })
        })
        .transpose()
}

fn status_error(code: u32) -> io::Error {
    io::Error::other(format!("grpc: stream ended with grpc-status {code}"))
}

fn h2_error(error: h2::Error) -> io::Error {
    let kind = error.get_io().map(io::Error::kind).unwrap_or_else(|| {
        if error.is_go_away() {
            io::ErrorKind::ConnectionAborted
        } else {
            io::ErrorKind::ConnectionReset
        }
    });
    io::Error::new(kind, error)
}

fn parse_varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    for (index, &byte) in bytes.iter().take(10).enumerate() {
        let part = usize::from(byte & 0x7f);
        let shift = u32::try_from(index * 7).ok()?;
        if part > usize::MAX.checked_shr(shift)? {
            return None;
        }
        value |= part << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

fn push_varint(out: &mut Vec<u8>, mut value: usize) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn varint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}
