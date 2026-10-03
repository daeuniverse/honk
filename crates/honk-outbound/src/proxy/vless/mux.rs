#![cfg_attr(all(test, not(feature = "rprx")), allow(dead_code))]

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
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

use crate::proxy::{AsyncReadWrite, MuxSession, PacketTransport};
use crate::session::{
    IdleClock, ManagedSession, OpenError, SessionPermit, SessionPool, SessionPoolConfig,
    SessionState,
};
use padding::{PaddingStream, mux_preface};

mod padding;

pub(crate) const MAX_SESSIONS: usize = 2;
pub(crate) const MAX_STREAMS_PER_SESSION: usize = 128;
const MAX_ERROR_MESSAGE: usize = 64 * 1024;
// Let long-fat TCP streams grow without allowing one unread child to monopolize
// the carrier; aggregate credit still covers one maximum response frame per slot.
const H2_STREAM_RECV_WINDOW: u32 = 2 * 1024 * 1024;
const H2_CONNECTION_RECV_WINDOW: u32 =
    ((1 + 2 + crate::proxy::uot::MAX_PACKET_SIZE) * MAX_STREAMS_PER_SESSION) as u32;
#[cfg(feature = "rprx")]
const MUX_MAGIC_ADDRESS: &str = "sp.mux.sing-box.arpa";
#[cfg(feature = "rprx")]
const MUX_MAGIC_PORT: u16 = 444;
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
    /// Idle bookkeeping for the pool janitor, stamped at stream open and close.
    idle: IdleClock,
    capacity: Arc<tokio::sync::Semaphore>,
    capacity_notify: std::sync::OnceLock<Arc<tokio::sync::Notify>>,
    sender: Mutex<SendRequest<Bytes>>,
    driver: Mutex<Option<tokio::task::AbortHandle>>,
    failure: CarrierFailure,
}

impl VlessMuxSession {
    fn new(sender: SendRequest<Bytes>) -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(SessionState::Active as u8),
            created_at: Instant::now(),
            idle: IdleClock::new(),
            capacity: Arc::new(tokio::sync::Semaphore::new(MAX_STREAMS_PER_SESSION)),
            capacity_notify: std::sync::OnceLock::new(),
            sender: Mutex::new(sender),
            driver: Mutex::new(None),
            failure: CarrierFailure::default(),
        })
    }

    fn install_driver(&self, driver: Option<tokio::task::AbortHandle>) {
        *self.driver.lock() = driver;
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
        if let Some(notify) = self.capacity_notify.get() {
            notify.notify_waiters();
        }
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
            if let Some(notify) = self.capacity_notify.get() {
                notify.notify_waiters();
            }
        }
    }

    fn bind_capacity_notify(&self, notify: Arc<tokio::sync::Notify>) {
        if let Err(notify) = self.capacity_notify.set(notify) {
            assert!(
                Arc::ptr_eq(self.capacity_notify.get().unwrap(), &notify),
                "session cannot belong to multiple pools"
            );
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
        {
            if let Some(notify) = self.capacity_notify.get() {
                notify.notify_waiters();
            }
            if self.active_streams() == 0 {
                self.close();
            }
        }
    }

    fn permit_released(&self) {
        let active = self.active_streams();
        self.idle.stream_released(active);
        if self.state() == SessionState::Draining && active == 0 {
            self.close();
        }
    }

    fn idle_since(&self) -> Option<Instant> {
        self.idle.idle_since()
    }

    fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>> {
        if self.state() != SessionState::Active {
            return None;
        }
        let permit = Arc::clone(&self.capacity).try_acquire_owned().ok()?;
        self.idle.stream_opened();
        let permit = SessionPermit::new(Arc::clone(self), permit);
        if self.state() != SessionState::Active {
            drop(permit);
            return None;
        }
        Some(permit)
    }
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
    let driver = crate::runtime::spawn_owned(async move {
        let result = connection.await;
        if let Some(session) = weak.upgrade() {
            if let Err(error) = result {
                tracing::debug!(%error, "VLESS H2MUX carrier stopped");
            }
            session.driver_finished();
        }
    });
    session.install_driver(driver);
    Ok(session)
}

struct OpenedStream {
    send: h2::SendStream<Bytes>,
    response: ResponseFuture,
    permit: SessionPermit<VlessMuxSession>,
    failure: CarrierFailure,
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
        failure: Arc::clone(&session.failure),
    })
}

fn stream_request(
    flags: u16,
    target: std::net::SocketAddr,
    target_domain: Option<&str>,
) -> io::Result<Bytes> {
    let address = crate::proxy::addr::encode_address(target, target_domain)?;
    let mut request = BytesMut::with_capacity(2 + address.len());
    request.extend_from_slice(&flags.to_be_bytes());
    request.extend_from_slice(&address);
    Ok(request.freeze())
}

/// The first transport loss any stream observes; every stream of the connection shares it.
type CarrierFailure = Arc<std::sync::OnceLock<crate::SharedError>>;

fn h2_io(carrier: &CarrierFailure, error: h2::Error) -> io::Error {
    if error.is_io() {
        let failure = carrier.get_or_init(|| {
            crate::SharedError::fanout(crate::proxy::NodeFailure(error.into()).into())
        });
        return io::Error::new(io::ErrorKind::ConnectionReset, failure.clone());
    }
    // GOAWAY refuses only later streams; earlier ones continue and may fail independently.
    if error.is_go_away() {
        return io::Error::new(
            io::ErrorKind::ConnectionReset,
            crate::proxy::NodeFailure(error.into()),
        );
    }
    io::Error::new(io::ErrorKind::ConnectionReset, error)
}

async fn send_owned(
    send: &mut h2::SendStream<Bytes>,
    carrier: &CarrierFailure,
    mut data: Bytes,
) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "H2MUX stream closed"))?
            .map_err(|error| h2_io(carrier, error))?;
        if capacity == 0 {
            continue;
        }
        let chunk = data.split_to(capacity.min(data.len()));
        send.send_data(chunk, false)
            .map_err(|error| h2_io(carrier, error))?;
    }
    Ok(())
}

struct MuxSendStream {
    inner: h2::SendStream<Bytes>,
    closed: bool,
    carrier: CarrierFailure,
}

impl MuxSendStream {
    fn new(inner: h2::SendStream<Bytes>, carrier: CarrierFailure) -> Self {
        Self {
            inner,
            closed: false,
            carrier,
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
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(h2_io(&self.carrier, error))),
            Poll::Ready(Some(Ok(0))) => Poll::Pending,
            Poll::Ready(Some(Ok(capacity))) => {
                let written = capacity.min(data.len());
                self.inner
                    .send_data(Bytes::copy_from_slice(&data[..written]), false)
                    .map_err(|error| h2_io(&self.carrier, error))?;
                Poll::Ready(Ok(written))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.inner
                .send_data(Bytes::new(), true)
                .map_err(|error| h2_io(&self.carrier, error))?;
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
    failed: Option<crate::SharedError>,
    carrier: CarrierFailure,
    observer: Option<crate::runtime::flow_observation::FlowObserver>,
}

fn h2_clean_eof(error: &h2::Error) -> bool {
    error.is_remote() && error.is_reset() && error.reason() == Some(h2::Reason::NO_ERROR)
}
impl MuxResponse {
    fn new(response: ResponseFuture, carrier: CarrierFailure) -> Self {
        Self {
            response: Some(Box::pin(response)),
            recv: None,
            current: Bytes::new(),
            status_ready: false,
            error_len: None,
            error_remaining: None,
            error_message: Vec::new(),
            failed: None,
            observer: crate::runtime::flow_observation::current(),
            carrier,
        }
    }

    fn error(&mut self, kind: io::ErrorKind, message: impl Into<String>) -> io::Error {
        let error = crate::SharedError::new(
            crate::proxy::NodeFailure(anyhow::Error::msg(message.into())).into(),
        );
        self.failed = Some(error.clone());
        io::Error::new(kind, error)
    }

    fn target_error(&mut self, message: impl Into<String>) -> io::Error {
        let error = crate::SharedError::new(
            crate::proxy::TargetFailure(anyhow::Error::msg(message.into())).into(),
        );
        self.failed = Some(error.clone());
        io::Error::new(io::ErrorKind::ConnectionRefused, error)
    }

    fn release(&mut self, size: usize) -> io::Result<()> {
        self.recv
            .as_mut()
            .expect("response body exists before data")
            .flow_control()
            .release_capacity(size)
            .map_err(|error| h2_io(&self.carrier, error))
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
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(h2_io(&self.carrier, error))),
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
                Poll::Ready(Err(error)) => return Poll::Ready(Err(h2_io(&self.carrier, error))),
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
                    return Poll::Ready(Err(self.target_error(message)));
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
                        return Poll::Ready(Err(self.target_error("H2MUX request rejected")));
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
                    if let Some(observer) = self.observer.take() {
                        observer.milestone_once(
                            crate::runtime::flow_observation::Milestone::TargetConfirmed,
                        );
                    }
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
    carrier: CarrierFailure,
    setup: Option<Bytes>,
    pending: bool,
    request_observer: Option<crate::runtime::flow_observation::FlowObserver>,
}

struct MuxUdpReader {
    response: MuxResponse,
    decoder: crate::proxy::uot::Decoder,
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
        let packet = crate::proxy::uot::encode_packet(data, crate::proxy::uot::MAX_PACKET_SIZE)?;
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
        let writer = &mut *writer;
        send_owned(&mut writer.send, &writer.carrier, frame).await?;
        if let Some(observer) = writer.request_observer.take() {
            observer.milestone_once(crate::runtime::flow_observation::Milestone::TargetRequestSent);
        }
        writer.setup = None;
        writer.pending = false;
        Ok(())
    }
}

impl Drop for VlessMuxUdpTransport {
    fn drop(&mut self) {
        self.writer.get_mut().send.send_reset(h2::Reason::CANCEL);
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
            send_owned(&mut opened.send, &opened.failure, request)
                .await
                .map_err(|error| OpenError::Draining(anyhow::Error::new(error)))?;
            crate::runtime::flow_observation::milestone(
                crate::runtime::flow_observation::Milestone::TargetRequestSent,
            );
            Ok(VlessMuxStream {
                send: MuxSendStream::new(opened.send, Arc::clone(&opened.failure)),
                response: MuxResponse::new(opened.response, opened.failure),
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
                    carrier: Arc::clone(&opened.failure),
                    setup: Some(setup),
                    pending: false,
                    request_observer: crate::runtime::flow_observation::current(),
                }),
                reader: tokio::sync::Mutex::new(MuxUdpReader {
                    response: MuxResponse::new(opened.response, opened.failure),
                    decoder: crate::proxy::uot::Decoder::default(),
                }),
                target,
                _permit: opened.permit,
            }))
        }
    }
}

#[cfg(test)]
mod tests;
