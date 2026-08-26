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
    let sender = session.sender().map_err(OpenError::Draining)?;
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
    if target_domain.is_some_and(|domain| domain.len() > u8::MAX as usize) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "H2MUX target domain exceeds 255 bytes",
        ));
    }
    let address = super::addr::encode_address(target, target_domain);
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
        if !self.current.is_empty() {
            return Poll::Ready(Ok(Some(std::mem::take(&mut self.current))));
        }
        match self
            .recv
            .as_mut()
            .expect("response body initialized")
            .poll_data(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(error))) if h2_clean_eof(&error) => Poll::Ready(Ok(None)),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(h2_io(error))),
            Poll::Ready(Some(Ok(data))) if data.is_empty() => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Ok(data))) => Poll::Ready(Ok(Some(data))),
            Poll::Ready(None) => Poll::Ready(Ok(None)),
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
mod tests {
    use super::*;
    use crate::session::SpeculativeCheckout;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn pool_policy_is_fixed_and_bounded() {
        let config = session_pool_config();
        assert_eq!(config.max_sessions, 2);
        assert_eq!(config.max_streams_per_session, 128);
        assert!(!config.spread_sessions);
        assert!(config.max_session_age.is_none());
    }

    #[test]
    fn receive_windows_cover_every_maximum_udp_frame() {
        let maximum_response_frame = 1 + 2 + super::super::uot::MAX_PACKET_SIZE;
        assert!(H2_STREAM_RECV_WINDOW as usize >= maximum_response_frame);
        assert!(
            H2_CONNECTION_RECV_WINDOW as usize >= maximum_response_frame * MAX_STREAMS_PER_SESSION
        );
    }

    #[test]
    fn physical_preface_matches_sing_mux() {
        assert_eq!(&mux_preface(false)[..], &[0, H2MUX_BACKEND]);
        let padded = mux_preface(true);
        assert_eq!(&padded[..3], &[1, H2MUX_BACKEND, 1]);
        let length = u16::from_be_bytes([padded[3], padded[4]]) as usize;
        assert!((256..768).contains(&length));
        assert_eq!(padded.len(), 5 + length);
    }

    #[test]
    fn stream_request_rejects_overlong_domains() {
        let domain = "x".repeat(256);
        assert_eq!(
            stream_request(0, "127.0.0.1:443".parse().unwrap(), Some(&domain))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn padding_frames_first_sixteen_records_per_direction() {
        let (client, mut wire) = tokio::io::duplex(1 << 20);
        let mut padded = PaddingStream::new(client, true);
        for value in 0..PADDED_RECORDS {
            padded.write_all(&[value]).await.unwrap();
            padded.flush().await.unwrap();
            let mut header = [0; 4];
            wire.read_exact(&mut header).await.unwrap();
            assert_eq!(u16::from_be_bytes([header[0], header[1]]), 1);
            let padding = u16::from_be_bytes([header[2], header[3]]) as usize;
            let mut body = vec![0; 1 + padding];
            wire.read_exact(&mut body).await.unwrap();
            assert_eq!(body[0], value);
        }
        padded.write_all(b"raw").await.unwrap();
        padded.flush().await.unwrap();
        let mut raw = [0; 3];
        wire.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw");

        for value in 0..PADDED_RECORDS {
            let padding = 256usize;
            wire.write_all(&[0, 1, 1, 0, value]).await.unwrap();
            wire.write_all(&vec![0; padding]).await.unwrap();
            let mut output = [0];
            padded.read_exact(&mut output).await.unwrap();
            assert_eq!(output[0], value);
        }
        wire.write_all(b"raw").await.unwrap();
        let mut raw = [0; 3];
        padded.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw");
    }

    async fn receive_at_least(
        recv: &mut h2::RecvStream,
        body: &mut BytesMut,
        minimum: usize,
    ) -> bool {
        while body.len() < minimum {
            let Some(Ok(data)) = recv.data().await else {
                return false;
            };
            let size = data.len();
            body.extend_from_slice(&data);
            if recv.flow_control().release_capacity(size).is_err() {
                return false;
            }
        }
        true
    }

    async fn serve_logical_stream(
        request: http::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
    ) {
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.uri().authority().unwrap().as_str(), "localhost");
        let Ok(mut send) = respond.send_response(http::Response::new(()), false) else {
            return;
        };
        let mut recv = request.into_body();
        let mut body = BytesMut::new();
        if !receive_at_least(&mut recv, &mut body, 9).await {
            return;
        }
        match u16::from_be_bytes([body[0], body[1]]) {
            0 => {
                assert_eq!(&body[2..9], &[1, 93, 184, 216, 34, 1, 187]);
                if send
                    .send_data(Bytes::from_static(b"\0hello"), false)
                    .is_err()
                    || !receive_at_least(&mut recv, &mut body, 13).await
                {
                    return;
                }
                assert_eq!(&body[9..13], b"ping");
                if send.send_data(Bytes::from_static(b"pong"), false).is_err() {
                    return;
                }
                while let Some(Ok(data)) = recv.data().await {
                    let size = data.len();
                    let _ = recv.flow_control().release_capacity(size);
                }
                let _ = send.send_data(Bytes::new(), true);
            }
            FLAG_UDP => {
                let target = &body[2..9];
                assert!(matches!(
                    target,
                    [1, 8, 8, 8, 8, 0, 53] | [1, 1, 1, 1, 1, 0, 53]
                ));
                let maximum = target[1] == 1;
                if !receive_at_least(&mut recv, &mut body, 14).await {
                    return;
                }
                assert_eq!(&body[9..14], b"\0\x03dns");
                let answer = if maximum {
                    vec![0x5a; super::super::uot::MAX_PACKET_SIZE]
                } else {
                    b"answer".to_vec()
                };
                let packet =
                    super::super::uot::encode_packet(&answer, super::super::uot::MAX_PACKET_SIZE)
                        .unwrap();
                let mut response = BytesMut::with_capacity(1 + packet.len());
                response.extend_from_slice(&[0]);
                response.extend_from_slice(&packet);
                let _ = send.send_data(response.freeze(), true);
            }
            flags => panic!("unexpected mux flags {flags}"),
        }
    }
    async fn server_carrier(
        mut wire: tokio::io::DuplexStream,
        padded: bool,
    ) -> PaddingStream<tokio::io::DuplexStream> {
        if padded {
            let mut request = [0; 5];
            wire.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..3], &[1, H2MUX_BACKEND, 1]);
            let padding = u16::from_be_bytes([request[3], request[4]]) as usize;
            let mut ignored = vec![0; padding];
            wire.read_exact(&mut ignored).await.unwrap();
        } else {
            let mut request = [0; 2];
            wire.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0, H2MUX_BACKEND]);
        }
        PaddingStream::new(wire, padded)
    }

    async fn serve_h2mux(
        wire: tokio::io::DuplexStream,
        padded: bool,
        goaway_after_first: bool,
    ) -> usize {
        let io = server_carrier(wire, padded).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let mut requests = 0;
        while let Some(request) = connection.accept().await {
            let (request, respond) = request.unwrap();
            requests += 1;
            tokio::spawn(serve_logical_stream(request, respond));
            if goaway_after_first && requests == 1 {
                connection.graceful_shutdown();
            }
        }
        requests
    }

    async fn exercise_h2mux(padded: bool) {
        let (client, server) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(serve_h2mux(server, padded, false));
        let session = connect(Box::new(client), padded).await.unwrap();

        let tcp_permit = session.try_reserve().unwrap();
        let mut tcp = Arc::clone(&session)
            .open_stream(tcp_permit, "93.184.216.34:443".parse().unwrap(), None)
            .await
            .unwrap_or_else(|_| panic!("TCP logical stream must open"));
        let mut greeting = [0; 5];
        tcp.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"hello");
        tcp.write_all(b"ping").await.unwrap();
        let mut pong = [0; 4];
        tcp.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");

        let udp_permit = session.try_reserve().unwrap();
        let udp = Arc::clone(&session)
            .open_packet(udp_permit, "8.8.8.8:53".parse().unwrap(), None)
            .await
            .unwrap_or_else(|_| panic!("UDP logical stream must open"));
        udp.send_packet_confirmed(b"dns").await.unwrap();
        assert_eq!(session.active_streams(), 2);
        assert_eq!(
            udp.recv_packet(&mut [0; 1]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut answer = [0; 16];
        assert_eq!(
            udp.recv_packet(&mut answer).await.unwrap(),
            (6, "8.8.8.8:53".parse().unwrap())
        );
        assert_eq!(&answer[..6], b"answer");

        drop(udp);
        tcp.shutdown().await.unwrap();
        drop(tcp);
        assert_eq!(session.active_streams(), 0);
        session.close();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn tcp_and_udp_share_plain_and_padded_h2mux_carriers() {
        exercise_h2mux(false).await;
        exercise_h2mux(true).await;
    }

    #[tokio::test]
    async fn maximum_udp_frame_cannot_exhaust_the_h2_receive_window() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(serve_h2mux(server, false, false));
        let session = connect(Box::new(client), false).await.unwrap();
        let permit = session.try_reserve().unwrap();
        let udp = Arc::clone(&session)
            .open_packet(permit, "1.1.1.1:53".parse().unwrap(), None)
            .await
            .unwrap_or_else(|_| panic!("maximum-frame UDP stream must open"));
        udp.send_packet_confirmed(b"dns").await.unwrap();

        let mut packet = vec![0; super::super::uot::MAX_PACKET_SIZE];
        let (size, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            udp.recv_packet(&mut packet),
        )
        .await
        .expect("maximum UoT frame deadlocked HTTP/2 flow control")
        .unwrap();
        assert_eq!(size, super::super::uot::MAX_PACKET_SIZE);
        assert_eq!(peer, "1.1.1.1:53".parse().unwrap());
        assert!(packet.iter().all(|byte| *byte == 0x5a));

        drop(udp);
        session.close();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn tcp_receive_window_admits_one_megabyte_before_reads() {
        const PAYLOAD_SIZE: usize = 1024 * 1024;

        let (client, server) = tokio::io::duplex(2 * PAYLOAD_SIZE);
        let (sent, sent_done) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let io = server_carrier(server, false).await;
            let mut connection = h2::server::handshake(io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let writer = tokio::spawn(async move {
                let mut response = BytesMut::with_capacity(PAYLOAD_SIZE + 1);
                response.extend_from_slice(&[0]);
                response.resize(PAYLOAD_SIZE + 1, 0x5a);
                send_owned(&mut send, response.freeze()).await.unwrap();
                send.send_data(Bytes::new(), true).unwrap();
                let _ = sent.send(());
            });
            while connection.accept().await.is_some() {}
            writer.await.unwrap();
        });

        let session = connect(Box::new(client), false).await.unwrap();
        let permit = session.try_reserve().unwrap();
        let mut tcp = Arc::clone(&session)
            .open_stream(permit, "93.184.216.34:443".parse().unwrap(), None)
            .await
            .unwrap_or_else(|_| panic!("large-response TCP stream must open"));
        tokio::time::timeout(std::time::Duration::from_secs(2), sent_done)
            .await
            .expect("one-megabyte response stalled behind the initial H2 stream window")
            .unwrap();
        let mut response = Vec::new();
        tcp.read_to_end(&mut response).await.unwrap();
        assert_eq!(response.len(), PAYLOAD_SIZE);
        assert!(response.iter().all(|byte| *byte == 0x5a));

        drop(tcp);
        session.close();
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn stalled_tcp_stream_leaves_connection_credit_for_udp() {
        let capacity = H2_CONNECTION_RECV_WINDOW as usize + 1024 * 1024;
        let (client, server) = tokio::io::duplex(capacity);
        let (filled, filled_done) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let io = server_carrier(server, false).await;
            let mut connection = h2::server::handshake(io).await.unwrap();
            let mut filled = Some(filled);
            let mut writers = Vec::new();
            while let Some(request) = connection.accept().await {
                let (request, mut respond) = request.unwrap();
                if let Some(filled) = filled.take() {
                    writers.push(tokio::spawn(async move {
                        let mut recv = request.into_body();
                        let mut request_body = BytesMut::new();
                        assert!(receive_at_least(&mut recv, &mut request_body, 9).await);
                        let mut send = respond
                            .send_response(http::Response::new(()), false)
                            .unwrap();
                        let mut response = BytesMut::with_capacity(H2_STREAM_RECV_WINDOW as usize);
                        response.extend_from_slice(&[0]);
                        response.resize(H2_STREAM_RECV_WINDOW as usize, 0x5a);
                        send_owned(&mut send, response.freeze()).await.unwrap();
                        send.send_data(Bytes::new(), true).unwrap();
                        let _ = filled.send(());
                    }));
                } else {
                    writers.push(tokio::spawn(serve_logical_stream(request, respond)));
                }
            }
            for writer in writers {
                writer.await.unwrap();
            }
        });

        let session = connect(Box::new(client), false).await.unwrap();
        let tcp = Arc::clone(&session)
            .open_stream(
                session.try_reserve().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
            )
            .await
            .unwrap_or_else(|error| match error {
                OpenError::Session(error)
                | OpenError::Draining(error)
                | OpenError::Refused(error) => {
                    panic!("stalled TCP stream must open: {error:#}")
                }
            });
        tokio::time::timeout(std::time::Duration::from_secs(2), filled_done)
            .await
            .expect("peer could not fill one TCP stream window")
            .unwrap();

        let udp_target = "8.8.8.8:53".parse().unwrap();
        let udp = Arc::clone(&session)
            .open_packet(session.try_reserve().unwrap(), udp_target, None)
            .await
            .unwrap_or_else(|_| panic!("sibling UDP stream must open"));
        udp.send_packet_confirmed(b"dns").await.unwrap();
        let mut answer = [0; 16];
        let (size, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            udp.recv_packet(&mut answer),
        )
        .await
        .expect("stalled TCP stream consumed all H2 connection credit")
        .unwrap();
        assert_eq!(peer, udp_target);
        assert_eq!(&answer[..size], b"answer");

        drop(udp);
        drop(tcp);
        session.close();
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn goaway_rolls_over_without_cutting_the_live_stream() {
        let pool = Arc::new(SessionPool::new(session_pool_config()));
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let servers = Arc::new(Mutex::new(Vec::new()));
        let dial = {
            let dials = Arc::clone(&dials);
            let sessions = Arc::clone(&sessions);
            let servers = Arc::clone(&servers);
            move || {
                let dials = Arc::clone(&dials);
                let sessions = Arc::clone(&sessions);
                let servers = Arc::clone(&servers);
                async move {
                    let index = dials.fetch_add(1, Ordering::AcqRel);
                    let (client, server) = tokio::io::duplex(1 << 20);
                    servers
                        .lock()
                        .push(tokio::spawn(serve_h2mux(server, false, index == 0)));
                    let session = connect(Box::new(client), false).await?;
                    sessions.lock().push(Arc::clone(&session));
                    Ok(session)
                }
            }
        };
        let open = |session: Arc<VlessMuxSession>, permit: SessionPermit<VlessMuxSession>| async move {
            session
                .open_stream(permit, "93.184.216.34:443".parse().unwrap(), None)
                .await
        };

        let mut first = pool.open_with(dial.clone(), open).await.unwrap();
        let mut greeting = [0; 5];
        first.read_exact(&mut greeting).await.unwrap();
        first.write_all(b"ping").await.unwrap();
        let mut pong = [0; 4];
        first.read_exact(&mut pong).await.unwrap();

        let first_session = Arc::clone(&sessions.lock()[0]);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if matches!(
                    Arc::clone(&first_session).check_ready().await,
                    Err(OpenError::Draining(_))
                ) {
                    first_session.begin_drain();
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let mut second = pool.open_with(dial, open).await.unwrap();
        second.read_exact(&mut greeting).await.unwrap();
        assert_eq!(dials.load(Ordering::Acquire), 2);
        assert_eq!(first_session.state(), SessionState::Draining);
        assert!(!first_session.is_closed());

        first.shutdown().await.unwrap();
        second.shutdown().await.unwrap();
        drop(first);
        drop(second);
        assert!(first_session.is_closed());
        pool.shutdown();
        let servers = std::mem::take(&mut *servers.lock());
        for server in servers {
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(2), server)
                    .await
                    .unwrap()
                    .unwrap(),
                1
            );
        }
    }
    async fn serve_idle_h2mux(wire: tokio::io::DuplexStream) -> usize {
        let io = server_carrier(wire, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let mut streams = Vec::new();
        while let Some(stream) = connection.accept().await {
            streams.push(stream.unwrap());
        }
        streams.len()
    }

    #[tokio::test]
    async fn saturated_carrier_opens_the_second_pool_slot() {
        let pool = Arc::new(SessionPool::new(session_pool_config()));
        let (first_client, first_server) = tokio::io::duplex(1 << 20);
        let first_server = tokio::spawn(serve_idle_h2mux(first_server));
        let first = connect(Box::new(first_client), false).await.unwrap();
        pool.insert(&first);
        let permits: Vec<_> = (0..MAX_STREAMS_PER_SESSION)
            .map(|_| first.try_reserve().unwrap())
            .collect();
        assert_eq!(first.active_streams(), MAX_STREAMS_PER_SESSION);

        let (second_client, second_server) = tokio::io::duplex(1 << 20);
        let second_server = tokio::spawn(serve_idle_h2mux(second_server));
        let second = pool
            .offer(move || async move { connect(Box::new(second_client), false).await })
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(pool.metrics().sessions, 2);

        drop(permits);
        pool.shutdown();
        assert_eq!(first_server.await.unwrap(), 0);
        assert_eq!(second_server.await.unwrap(), 0);
    }

    async fn prepare_detached(
        pool: &Arc<VlessMuxPool>,
    ) -> (
        super::super::PreparedUdpTransport,
        Arc<VlessMuxSession>,
        tokio::task::JoinHandle<usize>,
    ) {
        let SpeculativeCheckout::Detached(mut reservation) =
            pool.checkout_speculative().await.unwrap()
        else {
            panic!("empty pool must reserve a detached dial");
        };
        let (client, server) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(serve_idle_h2mux(server));
        let session = connect(Box::new(client), false).await.unwrap();
        reservation.attach(&session).unwrap();
        let permit = session.try_reserve().unwrap();
        let transport = Arc::clone(&session)
            .open_packet(permit, "8.8.8.8:53".parse().unwrap(), None)
            .await
            .unwrap_or_else(|_| panic!("detached UDP stream must open"));
        let transport: Arc<dyn PacketTransport> = transport;
        (
            super::super::PreparedUdpTransport::new(transport, move || async move {
                reservation.commit()?;
                Ok(())
            }),
            session,
            server,
        )
    }

    #[tokio::test]
    async fn detached_session_publishes_only_on_commit() {
        let pool = Arc::new(SessionPool::new(session_pool_config()));
        let (loser, loser_session, loser_server) = prepare_detached(&pool).await;
        assert_eq!(pool.live_session_count(), 0);
        drop(loser);
        assert!(loser_session.is_closed());
        assert!(loser_server.await.unwrap() <= 1);

        let (winner, winner_session, winner_server) = prepare_detached(&pool).await;
        assert_eq!(pool.live_session_count(), 0);
        let transport = winner.commit().await.unwrap();
        assert_eq!(pool.live_session_count(), 1);
        assert!(!winner_session.is_closed());
        drop(transport);
        pool.shutdown();
        assert!(winner_session.is_closed());
        assert!(winner_server.await.unwrap() <= 1);
    }

    #[tokio::test]
    async fn carrier_failure_fans_out_and_stream_capacity_is_bounded() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let io = server_carrier(server, false).await;
            let mut connection = h2::server::handshake(io).await.unwrap();
            let mut streams = Vec::new();
            for _ in 0..2 {
                streams.push(connection.accept().await.unwrap().unwrap());
            }
            accepted_tx.send(()).unwrap();
            drop_rx.await.unwrap();
        });
        let session = connect(Box::new(client), false).await.unwrap();
        let permits: Vec<_> = (0..MAX_STREAMS_PER_SESSION)
            .map(|_| session.try_reserve().unwrap())
            .collect();
        assert!(session.try_reserve().is_none());
        drop(permits);

        let mut first = Arc::clone(&session)
            .open_stream(
                session.try_reserve().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
            )
            .await
            .unwrap_or_else(|_| panic!("first stream must open"));
        let mut second = Arc::clone(&session)
            .open_stream(
                session.try_reserve().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
            )
            .await
            .unwrap_or_else(|_| panic!("second stream must open"));
        accepted_rx.await.unwrap();
        drop_tx.send(()).unwrap();
        server.await.unwrap();
        let mut byte = [0];
        assert!(first.read_exact(&mut byte).await.is_err());
        assert!(second.read_exact(&mut byte).await.is_err());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !session.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn dropping_logical_stream_sends_cancel_reset() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let io = server_carrier(server, false).await;
            let mut connection = h2::server::handshake(io).await.unwrap();
            let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            ready_tx.send(()).unwrap();
            tokio::select! {
                reset = std::future::poll_fn(|cx| send.poll_reset(cx)) => reset.unwrap(),
                request = connection.accept() => {
                    panic!("unexpected H2 event while awaiting reset: {request:?}");
                }
            }
        });
        let session = connect(Box::new(client), false).await.unwrap();
        let stream = Arc::clone(&session)
            .open_stream(
                session.try_reserve().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
            )
            .await
            .unwrap_or_else(|_| panic!("logical stream must open"));
        ready_rx.await.unwrap();
        drop(stream);
        let reset = tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reset, h2::Reason::CANCEL);
        session.close();
    }

    #[tokio::test]
    async fn remote_no_error_reset_is_clean_eof_after_payload() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let io = server_carrier(server, false).await;
            let mut connection = h2::server::handshake(io).await.unwrap();
            let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            send.send_data(Bytes::from_static(b"\0payload"), false)
                .unwrap();
            tokio::select! {
                result = reset_rx => result.unwrap(),
                request = connection.accept() => {
                    panic!("unexpected H2 event while awaiting reset: {request:?}");
                }
            }
            send.send_reset(h2::Reason::NO_ERROR);
            while connection.accept().await.is_some() {}
        });
        let session = connect(Box::new(client), false).await.unwrap();
        let mut stream = Arc::clone(&session)
            .open_stream(
                session.try_reserve().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
            )
            .await
            .unwrap_or_else(|_| panic!("logical stream must open"));
        let mut payload = [0; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
        reset_tx.send(()).unwrap();
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        drop(stream);
        session.close();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn mux_body_error_is_reported_lazily() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let io = server_carrier(server, false).await;
            let mut connection = h2::server::handshake(io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            send.send_data(Bytes::from_static(&[1, 3, b'b', b'a', b'd']), true)
                .unwrap();
            while connection.accept().await.is_some() {}
        });
        let session = connect(Box::new(client), false).await.unwrap();
        let mut stream = Arc::clone(&session)
            .open_stream(
                session.try_reserve().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
            )
            .await
            .unwrap_or_else(|_| panic!("logical stream must open before lazy rejection"));
        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(error.to_string().contains("bad"));
        drop(stream);
        session.close();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn logical_writes_wait_for_h2_flow_control() {
        const PAYLOAD_SIZE: usize = 4 * 1024 * 1024;
        let (client, server) = tokio::io::duplex(1 << 20);
        let release = Arc::new(tokio::sync::Notify::new());
        let server_release = Arc::clone(&release);
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (drained_tx, drained_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let io = server_carrier(server, false).await;
            let mut connection = h2::server::handshake(io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            send.send_data(Bytes::from_static(&[0]), false).unwrap();
            accepted_tx.send(()).unwrap();
            let handler = tokio::spawn(async move {
                let mut recv = request.into_body();
                server_release.notified().await;
                let mut received = 0;
                while let Some(data) = recv.data().await {
                    let data = data.unwrap();
                    received += data.len();
                    recv.flow_control().release_capacity(data.len()).unwrap();
                }
                let _ = send.send_data(Bytes::new(), true);
                drained_tx.send(received).unwrap();
            });
            while connection.accept().await.is_some() {}
            handler.await.unwrap();
        });
        let session = connect(Box::new(client), false).await.unwrap();
        let stream = Arc::clone(&session)
            .open_stream(
                session.try_reserve().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
            )
            .await
            .unwrap_or_else(|_| panic!("flow-control stream must open"));
        accepted_rx.await.unwrap();
        let mut writer = tokio::spawn(async move {
            let mut stream = stream;
            stream.write_all(&vec![0x5a; PAYLOAD_SIZE]).await?;
            stream.shutdown().await?;
            Ok::<_, io::Error>(stream)
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut writer)
                .await
                .is_err(),
            "writer must stop at the peer's H2 receive window"
        );
        release.notify_one();
        let stream = writer.await.unwrap().unwrap();
        drop(stream);
        assert!(drained_rx.await.unwrap() >= PAYLOAD_SIZE);
        session.close();
        server.await.unwrap();
    }
}
