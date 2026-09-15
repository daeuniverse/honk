#![cfg_attr(not(feature = "rprx"), allow(dead_code))]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use h2::client::{ResponseFuture, SendRequest};
use parking_lot::Mutex;
use rand::RngExt as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

use super::{AsyncReadWrite, MuxSession, PacketTransport};
use crate::session::{
    ManagedSession, OpenError, SessionPermit, SessionPool, SessionPoolConfig, SessionState,
};

pub(crate) const MAX_SESSIONS: usize = 2;
pub(crate) const MAX_STREAMS_PER_SESSION: usize = 128;
const PADDED_RECORDS: u8 = 16;
const MAX_RECORD_DATA: usize = u16::MAX as usize;
const MAX_ERROR_MESSAGE: usize = 64 * 1024;
// Let long-fat TCP streams grow without allowing one unread child to monopolize
// the carrier; aggregate credit still covers one maximum response frame per slot.
const H2_STREAM_RECV_WINDOW: u32 = 2 * 1024 * 1024;
const H2_CONNECTION_RECV_WINDOW: u32 =
    ((1 + 2 + super::uot::MAX_PACKET_SIZE) * MAX_STREAMS_PER_SESSION) as u32;
#[cfg(feature = "rprx")]
const MUX_MAGIC_ADDRESS: &str = "sp.mux.sing-box.arpa";
#[cfg(feature = "rprx")]
const MUX_MAGIC_PORT: u16 = 444;
const H2MUX_BACKEND: u8 = 2;
const FLAG_UDP: u16 = 1;

pub(crate) type VlessMuxPool = SessionPool<VlessMuxSession>;

pub(crate) fn session_pool_config() -> SessionPoolConfig {
    SessionPoolConfig {
        max_sessions: MAX_SESSIONS,
        max_streams_per_session: MAX_STREAMS_PER_SESSION,
        spread_sessions: false,
        max_session_age: None,
        ..SessionPoolConfig::default()
    }
}

#[cfg(feature = "rprx")]
pub(crate) fn physical_target() -> (std::net::SocketAddr, &'static str) {
    (
        std::net::SocketAddr::from(([0, 0, 0, 0], MUX_MAGIC_PORT)),
        MUX_MAGIC_ADDRESS,
    )
}

#[derive(Debug)]
pub struct VlessMuxSession {
    state: AtomicU8,
    created_at: Instant,
    capacity: Arc<tokio::sync::Semaphore>,
    sender: Mutex<SendRequest<Bytes>>,
    driver: Mutex<Option<tokio::task::AbortHandle>>,
}

impl VlessMuxSession {
    fn new(sender: SendRequest<Bytes>) -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(SessionState::Active as u8),
            created_at: Instant::now(),
            capacity: Arc::new(tokio::sync::Semaphore::new(MAX_STREAMS_PER_SESSION)),
            sender: Mutex::new(sender),
            driver: Mutex::new(None),
        })
    }

    fn install_driver(&self, driver: tokio::task::AbortHandle) {
        *self.driver.lock() = Some(driver);
    }

    fn sender(&self) -> anyhow::Result<SendRequest<Bytes>> {
        if self.state() != SessionState::Active {
            anyhow::bail!("VLESS H2MUX carrier is closed");
        }
        Ok(self.sender.lock().clone())
    }

    fn reserved_sender(&self) -> anyhow::Result<SendRequest<Bytes>> {
        if self.state() == SessionState::Closed {
            anyhow::bail!("VLESS H2MUX carrier is closed");
        }
        Ok(self.sender.lock().clone())
    }

    fn driver_finished(&self) {
        self.state
            .store(SessionState::Closed as u8, Ordering::Release);
        self.capacity.close();
    }
}

impl ManagedSession for VlessMuxSession {
    fn active_streams(&self) -> usize {
        MAX_STREAMS_PER_SESSION - self.capacity.available_permits()
    }

    fn is_closed(&self) -> bool {
        self.state() == SessionState::Closed
    }

    fn close(&self) {
        if self
            .state
            .swap(SessionState::Closed as u8, Ordering::AcqRel)
            != SessionState::Closed as u8
        {
            self.capacity.close();
            if let Some(driver) = self.driver.lock().take() {
                driver.abort();
            }
        }
    }

    fn state(&self) -> SessionState {
        match self.state.load(Ordering::Acquire) {
            value if value == SessionState::Active as u8 => SessionState::Active,
            value if value == SessionState::Draining as u8 => SessionState::Draining,
            _ => SessionState::Closed,
        }
    }

    fn created_at(&self) -> Instant {
        self.created_at
    }

    fn begin_drain(&self) {
        if self
            .state
            .compare_exchange(
                SessionState::Active as u8,
                SessionState::Draining as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
            && self.active_streams() == 0
        {
            self.close();
        }
    }

    fn permit_released(&self) {
        if self.state() == SessionState::Draining && self.active_streams() == 0 {
            self.close();
        }
    }

    fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>> {
        if self.state() != SessionState::Active {
            return None;
        }
        let permit = Arc::clone(&self.capacity).try_acquire_owned().ok()?;
        let permit = SessionPermit::new(Arc::clone(self), permit);
        if self.state() != SessionState::Active {
            drop(permit);
            return None;
        }
        Some(permit)
    }
}

#[derive(Default)]
struct PaddingReadState {
    records: u8,
    header: [u8; 4],
    header_len: usize,
    data_remaining: usize,
    padding_remaining: usize,
}

#[derive(Default)]
struct PaddingWriteState {
    records: u8,
    pending: Option<Bytes>,
    offset: usize,
}

struct PaddingStream<S> {
    inner: S,
    enabled: bool,
    read: PaddingReadState,
    write: PaddingWriteState,
}

impl<S> PaddingStream<S> {
    fn new(inner: S, enabled: bool) -> Self {
        Self {
            inner,
            enabled,
            read: PaddingReadState::default(),
            write: PaddingWriteState::default(),
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for PaddingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.enabled
            || (self.read.records >= PADDED_RECORDS
                && self.read.data_remaining == 0
                && self.read.padding_remaining == 0
                && self.read.header_len == 0)
        {
            return Pin::new(&mut self.inner).poll_read(cx, output);
        }
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.read.data_remaining != 0 {
                let limit = self.read.data_remaining.min(output.remaining());
                let target = output.initialize_unfilled_to(limit);
                let mut limited = ReadBuf::new(target);
                match Pin::new(&mut self.inner).poll_read(cx, &mut limited) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let read = limited.filled().len();
                        if read == 0 {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        output.advance(read);
                        self.read.data_remaining -= read;
                        return Poll::Ready(Ok(()));
                    }
                }
            }

            if self.read.padding_remaining != 0 {
                let mut scratch = [0; 1024];
                let limit = self.read.padding_remaining.min(scratch.len());
                let mut discard = ReadBuf::new(&mut scratch[..limit]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut discard) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let read = discard.filled().len();
                        if read == 0 {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        self.read.padding_remaining -= read;
                        continue;
                    }
                }
            }

            if self.read.records >= PADDED_RECORDS {
                return Pin::new(&mut self.inner).poll_read(cx, output);
            }

            let header_len = self.read.header_len;
            let mut bytes = [0; 4];
            let mut header = ReadBuf::new(&mut bytes[..4 - header_len]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut header) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let read = header.filled().len();
                    if read == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    self.read.header[header_len..header_len + read]
                        .copy_from_slice(&header.filled()[..read]);
                    self.read.header_len += read;
                    if self.read.header_len != 4 {
                        continue;
                    }
                    self.read.data_remaining =
                        u16::from_be_bytes([self.read.header[0], self.read.header[1]]) as usize;
                    self.read.padding_remaining =
                        u16::from_be_bytes([self.read.header[2], self.read.header[3]]) as usize;
                    self.read.header_len = 0;
                    self.read.records += 1;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> PaddingStream<S> {
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(frame) = self.write.pending.as_ref() {
            match Pin::new(&mut self.inner).poll_write(cx, &frame[self.write.offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => {
                    self.write.offset += written;
                    if self.write.offset == frame.len() {
                        self.write.pending = None;
                        self.write.offset = 0;
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PaddingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.enabled {
            return Pin::new(&mut self.inner).poll_write(cx, data);
        }
        match self.poll_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if self.write.records >= PADDED_RECORDS {
            return Pin::new(&mut self.inner).poll_write(cx, data);
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let data_len = data.len().min(MAX_RECORD_DATA);
        let padding_len = rand::rng().random_range(256..768);
        let mut frame = BytesMut::with_capacity(4 + data_len + padding_len);
        frame.extend_from_slice(&(data_len as u16).to_be_bytes());
        frame.extend_from_slice(&(padding_len as u16).to_be_bytes());
        frame.extend_from_slice(&data[..data_len]);
        frame.resize(frame.len() + padding_len, 0);
        self.write.pending = Some(frame.freeze());
        self.write.records += 1;
        cx.waker().wake_by_ref();
        Poll::Ready(Ok(data_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
        }
    }
}

fn mux_preface(padded: bool) -> Bytes {
    if !padded {
        return Bytes::from_static(&[0, H2MUX_BACKEND]);
    }
    let padding_len = rand::rng().random_range(256..768);
    let mut preface = BytesMut::with_capacity(5 + padding_len);
    preface.extend_from_slice(&[1, H2MUX_BACKEND, 1]);
    preface.extend_from_slice(&(padding_len as u16).to_be_bytes());
    preface.resize(preface.len() + padding_len, 0);
    preface.freeze()
}

pub(crate) async fn connect(
    mut stream: Box<dyn AsyncReadWrite>,
    padded: bool,
) -> anyhow::Result<Arc<VlessMuxSession>> {
    stream.write_all(&mux_preface(padded)).await?;
    stream.flush().await?;
    let carrier = PaddingStream::new(stream, padded);
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(H2_STREAM_RECV_WINDOW)
        .initial_connection_window_size(H2_CONNECTION_RECV_WINDOW);
    let (sender, connection) = builder.handshake(carrier).await?;
    let session = VlessMuxSession::new(sender);
    let weak = Arc::downgrade(&session);
    let driver = tokio::spawn(async move {
        let result = connection.await;
        if let Some(session) = weak.upgrade() {
            if let Err(error) = result {
                tracing::debug!(%error, "VLESS H2MUX carrier stopped");
            }
            session.driver_finished();
        }
    });
    session.install_driver(driver.abort_handle());
    Ok(session)
}

struct OpenedStream {
    send: h2::SendStream<Bytes>,
    response: ResponseFuture,
    permit: SessionPermit<VlessMuxSession>,
}

async fn open_h2_stream(
    session: Arc<VlessMuxSession>,
    permit: SessionPermit<VlessMuxSession>,
) -> Result<OpenedStream, OpenError> {
    let sender = session.reserved_sender().map_err(OpenError::Draining)?;
    let mut sender = sender
        .ready()
        .await
        .map_err(|error| OpenError::Draining(anyhow::Error::new(error)))?;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://localhost")
        .body(())
        .map_err(|error| OpenError::Refused(anyhow::Error::new(error)))?;
    let (response, send) = sender
        .send_request(request, false)
        .map_err(|error| OpenError::Draining(anyhow::Error::new(error)))?;
    Ok(OpenedStream {
        send,
        response,
        permit,
    })
}

fn stream_request(
    flags: u16,
    target: std::net::SocketAddr,
    target_domain: Option<&str>,
) -> io::Result<Bytes> {
    let address = super::addr::encode_address(target, target_domain)?;
    let mut request = BytesMut::with_capacity(2 + address.len());
    request.extend_from_slice(&flags.to_be_bytes());
    request.extend_from_slice(&address);
    Ok(request.freeze())
}

fn h2_io(error: h2::Error) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, error)
}

async fn send_owned(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "H2MUX stream closed"))?
            .map_err(h2_io)?;
        if capacity == 0 {
            continue;
        }
        let chunk = data.split_to(capacity.min(data.len()));
        send.send_data(chunk, false).map_err(h2_io)?;
    }
    Ok(())
}

struct MuxSendStream {
    inner: h2::SendStream<Bytes>,
    closed: bool,
}

impl MuxSendStream {
    fn new(inner: h2::SendStream<Bytes>) -> Self {
        Self {
            inner,
            closed: false,
        }
    }
}

impl AsyncWrite for MuxSendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.inner.reserve_capacity(data.len());
        match self.inner.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(h2_io(error))),
            Poll::Ready(Some(Ok(0))) => Poll::Pending,
            Poll::Ready(Some(Ok(capacity))) => {
                let written = capacity.min(data.len());
                self.inner
                    .send_data(Bytes::copy_from_slice(&data[..written]), false)
                    .map_err(h2_io)?;
                Poll::Ready(Ok(written))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.inner.send_data(Bytes::new(), true).map_err(h2_io)?;
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MuxSendStream {
    fn drop(&mut self) {
        if !self.closed {
            self.inner.send_reset(h2::Reason::CANCEL);
        }
    }
}

struct MuxResponse {
    response: Option<Pin<Box<ResponseFuture>>>,
    recv: Option<h2::RecvStream>,
    current: Bytes,
    status_ready: bool,
    error_len: Option<(u64, u32)>,
    error_remaining: Option<usize>,
    error_message: Vec<u8>,
    failed: Option<String>,
}

fn h2_clean_eof(error: &h2::Error) -> bool {
    error.is_remote() && error.is_reset() && error.reason() == Some(h2::Reason::NO_ERROR)
}
impl MuxResponse {
    fn new(response: ResponseFuture) -> Self {
        Self {
            response: Some(Box::pin(response)),
            recv: None,
            current: Bytes::new(),
            status_ready: false,
            error_len: None,
            error_remaining: None,
            error_message: Vec::new(),
            failed: None,
        }
    }

    fn error(&mut self, kind: io::ErrorKind, message: impl Into<String>) -> io::Error {
        let message = message.into();
        self.failed = Some(message.clone());
        io::Error::new(kind, message)
    }

    fn release(&mut self, size: usize) -> io::Result<()> {
        self.recv
            .as_mut()
            .expect("response body exists before data")
            .flow_control()
            .release_capacity(size)
            .map_err(h2_io)
    }

    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if !self.current.is_empty() {
            return Poll::Ready(Ok(true));
        }
        match self
            .recv
            .as_mut()
            .expect("response body initialized")
            .poll_data(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(error))) if self.status_ready && h2_clean_eof(&error) => {
                Poll::Ready(Ok(false))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(h2_io(error))),
            Poll::Ready(Some(Ok(data))) if data.is_empty() => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Ok(data))) => {
                self.current = data;
                Poll::Ready(Ok(true))
            }
            Poll::Ready(None) => Poll::Ready(Ok(false)),
        }
    }

    fn poll_status(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(message) = self.failed.as_ref() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                message.clone(),
            )));
        }
        if self.status_ready {
            return Poll::Ready(Ok(()));
        }
        if self.recv.is_none() {
            let response = self.response.as_mut().expect("response future exists");
            let response = match response.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(h2_io(error))),
                Poll::Ready(Ok(response)) => response,
            };
            if response.status() != http::StatusCode::OK {
                let status = response.status();
                return Poll::Ready(Err(self.error(
                    io::ErrorKind::ConnectionRefused,
                    format!("H2MUX CONNECT returned {status}"),
                )));
            }
            self.recv = Some(response.into_body());
            self.response = None;
        }

        loop {
            match self.poll_fill(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(false)) => {
                    return Poll::Ready(Err(self.error(
                        io::ErrorKind::UnexpectedEof,
                        "H2MUX response closed before status",
                    )));
                }
                Poll::Ready(Ok(true)) => {}
            }

            if let Some(remaining) = self.error_remaining {
                let take = remaining.min(self.current.len());
                self.error_message.extend_from_slice(&self.current[..take]);
                self.current.advance(take);
                if let Err(error) = self.release(take) {
                    return Poll::Ready(Err(error));
                }
                let remaining = remaining - take;
                self.error_remaining = Some(remaining);
                if remaining == 0 {
                    let message = String::from_utf8_lossy(&self.error_message).into_owned();
                    return Poll::Ready(Err(self.error(io::ErrorKind::ConnectionRefused, message)));
                }
                continue;
            }

            let byte = self.current[0];
            self.current.advance(1);
            if let Err(error) = self.release(1) {
                return Poll::Ready(Err(error));
            }
            if let Some((mut value, mut shift)) = self.error_len {
                if shift >= 64 || (shift == 63 && byte > 1) {
                    return Poll::Ready(Err(
                        self.error(io::ErrorKind::InvalidData, "invalid H2MUX error length")
                    ));
                }
                value |= u64::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 {
                    let Ok(length) = usize::try_from(value) else {
                        return Poll::Ready(Err(
                            self.error(io::ErrorKind::InvalidData, "invalid H2MUX error length")
                        ));
                    };
                    if length > MAX_ERROR_MESSAGE {
                        return Poll::Ready(Err(self.error(
                            io::ErrorKind::InvalidData,
                            "H2MUX error message exceeds limit",
                        )));
                    }
                    self.error_len = None;
                    self.error_remaining = Some(length);
                    if length == 0 {
                        return Poll::Ready(Err(
                            self.error(io::ErrorKind::ConnectionRefused, "H2MUX request rejected")
                        ));
                    }
                } else {
                    shift += 7;
                    self.error_len = Some((value, shift));
                }
                continue;
            }

            match byte {
                0 => {
                    self.status_ready = true;
                    return Poll::Ready(Ok(()));
                }
                1 => self.error_len = Some((0, 0)),
                _ => {
                    return Poll::Ready(Err(
                        self.error(io::ErrorKind::InvalidData, "invalid H2MUX response status")
                    ));
                }
            }
        }
    }

    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.poll_status(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        match self.poll_fill(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(false)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(true)) => {
                let copy = output.remaining().min(self.current.len());
                output.put_slice(&self.current[..copy]);
                self.current.advance(copy);
                Poll::Ready(self.release(copy))
            }
        }
    }

    fn poll_take_chunk(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        match self.poll_status(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        match self.poll_fill(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(false)) => Poll::Ready(Ok(None)),
            Poll::Ready(Ok(true)) => Poll::Ready(Ok(Some(std::mem::take(&mut self.current)))),
        }
    }
}

pub(crate) struct VlessMuxStream {
    send: MuxSendStream,
    response: MuxResponse,
    _permit: SessionPermit<VlessMuxSession>,
}

impl std::fmt::Debug for VlessMuxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessMuxStream").finish_non_exhaustive()
    }
}

impl AsyncRead for VlessMuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.response.poll_read(cx, output)
    }
}

impl AsyncWrite for VlessMuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

struct MuxUdpWriter {
    send: h2::SendStream<Bytes>,
    setup: Option<Bytes>,
    pending: bool,
}

struct MuxUdpReader {
    response: MuxResponse,
    decoder: super::uot::Decoder,
}

pub(crate) struct VlessMuxUdpTransport {
    writer: tokio::sync::Mutex<MuxUdpWriter>,
    reader: tokio::sync::Mutex<MuxUdpReader>,
    target: std::net::SocketAddr,
    _permit: SessionPermit<VlessMuxSession>,
}

impl std::fmt::Debug for VlessMuxUdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessMuxUdpTransport")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl VlessMuxUdpTransport {
    async fn send(&self, data: &[u8]) -> io::Result<()> {
        let packet = super::uot::encode_packet(data, super::uot::MAX_PACKET_SIZE)?;
        let mut writer = self.writer.lock().await;
        if writer.pending {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "VLESS H2MUX UDP write was interrupted",
            ));
        }
        let frame = if let Some(setup) = writer.setup.as_ref() {
            let mut frame = BytesMut::with_capacity(setup.len() + packet.len());
            frame.extend_from_slice(setup);
            frame.extend_from_slice(&packet);
            frame.freeze()
        } else {
            packet
        };
        writer.pending = true;
        send_owned(&mut writer.send, frame).await?;
        writer.setup = None;
        writer.pending = false;
        Ok(())
    }
}

impl Drop for VlessMuxUdpTransport {
    fn drop(&mut self) {
        if let Ok(mut writer) = self.writer.try_lock() {
            writer.send.send_reset(h2::Reason::CANCEL);
        }
    }
}

#[async_trait]
impl PacketTransport for VlessMuxUdpTransport {
    fn relay_addr(&self) -> std::net::SocketAddr {
        self.target
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.send(data).await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> io::Result<()> {
        self.send(data).await
    }

    async fn recv_packet(&self, output: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        let mut reader = self.reader.lock().await;
        loop {
            if let Some(size) = reader.decoder.next_packet(output)? {
                reader.response.release(size + 2)?;
                return Ok((size, self.target));
            }
            let chunk = std::future::poll_fn(|cx| reader.response.poll_take_chunk(cx))
                .await?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VLESS H2MUX UDP stream closed",
                    )
                })?;
            reader.decoder.push(&chunk)?;
        }
    }
}

#[allow(
    clippy::manual_async_fn,
    reason = "the MuxSession trait requires an allocation-free Send future"
)]
impl MuxSession for VlessMuxSession {
    type Stream = VlessMuxStream;
    type Packet = VlessMuxUdpTransport;
    fn check_ready(self: Arc<Self>) -> impl Future<Output = Result<(), OpenError>> + Send {
        async move {
            let sender = self.sender().map_err(OpenError::Draining)?;
            sender
                .ready()
                .await
                .map(|_| ())
                .map_err(|error| OpenError::Draining(anyhow::Error::new(error)))
        }
    }

    fn open_stream(
        self: Arc<Self>,
        permit: SessionPermit<Self>,
        target: std::net::SocketAddr,
        target_domain: Option<&str>,
    ) -> impl Future<Output = Result<Self::Stream, OpenError>> + Send {
        async move {
            let request = stream_request(0, target, target_domain)
                .map_err(|error| OpenError::Refused(anyhow::Error::new(error)))?;
            let mut opened = open_h2_stream(self, permit).await?;
            send_owned(&mut opened.send, request)
                .await
                .map_err(|error| OpenError::Draining(anyhow::Error::new(error)))?;
            Ok(VlessMuxStream {
                send: MuxSendStream::new(opened.send),
                response: MuxResponse::new(opened.response),
                _permit: opened.permit,
            })
        }
    }

    fn open_packet(
        self: Arc<Self>,
        permit: SessionPermit<Self>,
        target: std::net::SocketAddr,
        target_domain: Option<&str>,
    ) -> impl Future<Output = Result<Arc<Self::Packet>, OpenError>> + Send {
        async move {
            let setup = stream_request(FLAG_UDP, target, target_domain)
                .map_err(|error| OpenError::Refused(anyhow::Error::new(error)))?;
            let opened = open_h2_stream(self, permit).await?;
            Ok(Arc::new(VlessMuxUdpTransport {
                writer: tokio::sync::Mutex::new(MuxUdpWriter {
                    send: opened.send,
                    setup: Some(setup),
                    pending: false,
                }),
                reader: tokio::sync::Mutex::new(MuxUdpReader {
                    response: MuxResponse::new(opened.response),
                    decoder: super::uot::Decoder::default(),
                }),
                target,
                _permit: opened.permit,
            }))
        }
    }
}

#[cfg(test)]
mod tests;
