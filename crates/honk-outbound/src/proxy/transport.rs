//! Shared stream-transport helpers for proxy handlers.
//!
//! Trojan, VMess and VLESS all wrap their connections in the same order:
//!
//! ```text
//! TCP -> (TLS/REALITY) -> (WebSocket | gRPC | XHTTP) -> protocol header
//! ```
//!
//! This module provides the reusable pieces so each handler only implements
//! its own protocol handshake:
//!
//! - [`wrap_transport`]: cold or supplied TCP/TLS wrapping, including one-shot XHTTP,
//! - [`wrap_transport_runtime`]: XHTTP physical reuse owned by the node generation,
//! - [`maybe_tls_wrap`]: just the TCP/TLS step, preserving the same setup budget.
//! - [`wrap_tunnel`]: TLS and transport over a stream tunneled through earlier hops.
//! - [`grpc`]: gRPC gun framing over a connection-owned HTTP/2 client.
//! - [`xhttp`]: raw XHTTP bodies over bounded node-owned HTTP/2 carriers.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use futures_util::{SinkExt, StreamExt};
use honk_config::node::Node;
use percent_encoding::{AsciiSet, CONTROLS, PercentEncode, utf8_percent_encode};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use crate::proxy::transport::grpc::wrap_grpc;

use super::AsyncReadWrite;
use crate::transport_quality::tcp::ObservedTcp;

pub(crate) struct TransportPreparation(Option<xhttp::XhttpPreparation>);

impl TransportPreparation {
    pub(crate) fn none() -> Self {
        Self(None)
    }

    pub(crate) fn commit(self) -> anyhow::Result<()> {
        self.0.map_or(Ok(()), xhttp::XhttpPreparation::commit)
    }
}

pub(crate) async fn write_request<W: tokio::io::AsyncWrite + Unpin + ?Sized>(
    stream: &mut W,
    request: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let write = async {
        stream.write_all(request).await?;
        stream.flush().await
    };
    crate::runtime::flow_observation::request_write(std::pin::pin!(write)).await
}

/// Connect if needed, then apply TLS and `node.transport` wrapping.
pub(crate) async fn wrap_transport(
    node: &Node,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    if node.is_xhttp() {
        let owner = crate::runtime::NodeRuntime::try_ephemeral_guarded(node)?;
        let runtime = owner.runtime();
        let stream = wrap_transport_runtime(&runtime, tcp, connect_timeout).await?;
        return Ok(Box::new(crate::proxy::RuntimeOwnedIo {
            inner: stream,
            _owner: owner,
        }));
    }
    let stream = maybe_tls_wrap(node, tcp, connect_timeout).await?;
    wrap_after_tls(node, stream).await
}

/// Reuse the node-owned physical H2 pool, not a pool of logical protocol streams.
pub(crate) async fn wrap_transport_runtime(
    runtime: &std::sync::Arc<crate::runtime::NodeRuntime>,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let (stream, preparation) = prepare_transport_runtime(runtime, tcp, connect_timeout).await?;
    preparation.commit()?;
    Ok(stream)
}

/// Caller-owned preparation: unpublished XHTTP carriers roll back unless the
/// selected UDP candidate commits them through its existing preparation fence.
pub(crate) async fn prepare_transport_runtime(
    runtime: &std::sync::Arc<crate::runtime::NodeRuntime>,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
) -> anyhow::Result<(Box<dyn AsyncReadWrite>, TransportPreparation)> {
    if let Some(xhttp) = &runtime.xhttp {
        let (stream, preparation) = xhttp.prepare(runtime, tcp, connect_timeout).await?;
        return Ok((stream, TransportPreparation(Some(preparation))));
    }
    let stream = maybe_tls_wrap(&runtime.node, tcp, connect_timeout).await?;
    Ok((
        wrap_after_tls(&runtime.node, stream).await?,
        TransportPreparation::none(),
    ))
}

pub(crate) async fn wrap_after_tls(
    node: &Node,
    stream: Box<dyn AsyncReadWrite>,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    match node.transport().unwrap().transport.as_str() {
        "" | "tcp" => Ok(stream), // raw TCP/TLS
        #[cfg(feature = "rprx")]
        "ws" if node.protocol() == honk_config::types::NodeProtocol::VMess => {
            wrap_ws(node, ws_close_wire::WsCloseWire::new(stream), false).await
        }
        "ws" => wrap_ws(node, stream, false).await,
        "grpc" => wrap_grpc(node, stream).await,
        // Unknown transport must not silently degrade to raw TCP — a
        // mistyped transport means a different protocol than intended.
        other => anyhow::bail!(
            "node '{}': unsupported transport '{}' (expected tcp/ws/grpc; xhttp requires its runtime)",
            node.name,
            other
        ),
    }
}

/// Connect if needed and apply TLS or authenticated REALITY. `None` identifies
/// a cold dial whose admission may be reused after dropping its failed socket;
/// a supplied socket always needs fresh admission for a replacement.
pub(crate) async fn maybe_tls_wrap(
    node: &Node,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    match maybe_tls_wrap_concrete(node, tcp, connect_timeout).await? {
        MaybeTls::Tls(stream) => Ok(Box::new(crate::tls::BatchRead::new(stream))),
        MaybeTls::Plain(stream) => Ok(stream),
    }
}

/// [`maybe_tls_wrap`] without erasing the concrete stream type: the XTLS
/// Vision direct-copy switch must reach the raw TCP socket under the TLS
/// stream once the server abandons the outer TLS session.
pub(crate) enum MaybeTls {
    Tls(crate::tls::TlsStream<ObservedTcp>),
    Plain(Box<ObservedTcp>),
}

/// Run the protocol validator when the node sets a TLS ALPN or WebSocket
/// headers, for both the physical and the tunneled TLS path.
fn validate_stream_options(node: &Node) -> anyhow::Result<()> {
    if node.tls().is_some_and(|tls| !tls.alpn.is_empty())
        || node
            .transport()
            .is_some_and(|transport| !transport.ws_headers.is_empty())
    {
        node.validate_protocol()?;
    }
    Ok(())
}

pub(crate) async fn maybe_tls_wrap_concrete(
    node: &Node,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
) -> anyhow::Result<MaybeTls> {
    let tls = node.tls().unwrap();
    validate_stream_options(node)?;
    let cold = tcp.is_none();
    let initial_tcp = async {
        match tcp {
            Some(tcp) => {
                if let Some(observer) = crate::runtime::flow_observation::current() {
                    observer.publish(
                        crate::runtime::flow_observation::FlowEvent::TransportAttached {
                            server_addr: tcp.peer_addr().ok(),
                            resolution_location:
                                crate::runtime::flow_observation::ResolutionLocation::Unknown,
                        },
                    );
                }
                Ok(tcp)
            }
            None => {
                let addr = format!("{}:{}", node.host(), node.port);
                crate::util::connect_proxy(&addr, connect_timeout).await
            }
        }
    };
    if let Some(reality) = crate::reality::parse_reality_config(node)? {
        let deadline = tokio::time::Instant::now() + connect_timeout * 3;
        let alpn = node.is_xhttp().then_some(b"\x02h2".as_slice());
        let setup = async {
            let tcp = initial_tcp.await?;
            let peer = tcp.peer_addr()?;
            let tcp = ObservedTcp::new(tcp);
            let chrome = crate::tls::chrome_mode();
            let mut tls_stream = match crate::reality::reality_connect_with_key_shares(
                tcp, &reality, chrome, true, alpn,
            )
            .await
            {
                Ok(stream) => stream,
                Err(error) if error.is::<crate::reality::RealityMaskCertificate>() => {
                    // The failed handshake has dropped its SSL/TCP before admission
                    // transfers. Supplied sockets cannot spend another dial's credit.
                    let replacement = async {
                        let remaining =
                            deadline.saturating_duration_since(tokio::time::Instant::now());
                        if remaining.is_zero() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "REALITY setup timeout",
                            )
                            .into());
                        }
                        let tcp =
                            crate::util::connect_proxy_addr(peer, connect_timeout.min(remaining))
                                .await?;
                        let tcp = ObservedTcp::new(tcp);
                        crate::reality::reality_connect_with_key_shares(
                            tcp, &reality, chrome, false, alpn,
                        )
                        .await
                    };
                    crate::runtime::admit_replacement_dial(replacement, cold).await?
                }
                Err(error) => return Err(error),
            };
            // Xray REALITY omits server ALPN; XHTTP selects H2 after authentication.
            tls_stream.get_mut().activate();
            crate::runtime::flow_observation::milestone(
                crate::runtime::flow_observation::Milestone::TransportReady,
            );
            Ok(MaybeTls::Tls(tls_stream))
        };
        return tokio::time::timeout_at(deadline, setup)
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "REALITY setup timeout")
            })?;
    }
    let mut tcp = ObservedTcp::new(initial_tcp.await?);
    if tls.enabled {
        let connector = crate::tls::build_connector(node)?;
        let server_name = node.tls_server_name();
        let mut tls_stream = connector.connect(&server_name, tcp).await?;
        if node.is_xhttp() {
            anyhow::ensure!(
                tls_stream.ssl().selected_alpn_protocol() == Some(b"h2"),
                "XHTTP requires negotiated h2 ALPN"
            );
        }
        tls_stream.get_mut().activate();
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        return Ok(MaybeTls::Tls(tls_stream));
    }
    tcp.activate();
    crate::runtime::flow_observation::milestone(
        crate::runtime::flow_observation::Milestone::TransportReady,
    );
    Ok(MaybeTls::Plain(Box::new(tcp)))
}

/// Apply TLS or REALITY and `node.transport` over `carrier`, a stream already
/// connected to this node's server through earlier hops. Nothing here
/// connects, resolves or retries: a REALITY mask certificate stays the
/// returned error for the caller to redial with `reality_key_shares` disabled.
pub(crate) async fn wrap_tunnel(
    node: &Node,
    carrier: Box<dyn AsyncReadWrite>,
    options: crate::proxy::TunnelDialOptions,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    // XHTTP needs a node-owned pool of physical H2 carriers.
    if node.is_xhttp() {
        return Err(crate::proxy::TunnelUnsupported("xhttp").into());
    }
    let (Some(tls), Some(transport)) = (node.tls(), node.transport()) else {
        return Err(crate::proxy::TunnelUnsupported(node.protocol().as_str()).into());
    };
    validate_stream_options(node)?;
    let stream: Box<dyn AsyncReadWrite> =
        if let Some(reality) = crate::reality::parse_reality_config(node)? {
            let handshake = crate::reality::reality_connect_with_key_shares(
                carrier,
                &reality,
                crate::tls::chrome_mode(),
                options.reality_key_shares,
                None,
            );
            let tls_stream = tokio::time::timeout(options.connect_timeout * 3, handshake)
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "REALITY setup timeout")
                })??;
            Box::new(crate::tls::BatchRead::new(tls_stream))
        } else if tls.enabled {
            let connector = crate::tls::build_connector(node)?;
            let server_name = node.tls_server_name();
            // Discovery would send this hop's server name to the local
            // resolver, outside the tunnel.
            if connector.discovers_ech(&server_name) {
                return Err(crate::proxy::TunnelUnsupported("tls ech discovery").into());
            }
            let tls_stream = connector.connect(&server_name, carrier).await?;
            Box::new(crate::tls::BatchRead::new(tls_stream))
        } else {
            carrier
        };
    if transport.transport == "ws" {
        return wrap_ws(node, stream, true).await;
    }
    wrap_after_tls(node, stream).await
}

fn encode_uri_path(path: &str) -> PercentEncode<'_> {
    // Paths may already contain escapes and query delimiters; preserve both.
    const ENCODE_SET: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'<')
        .add(b'>')
        .add(b'`')
        .add(b'{')
        .add(b'}')
        .add(b'|')
        .add(b'\\')
        .add(b'^');
    utf8_percent_encode(path, ENCODE_SET)
}

// Only the physical VMess upgrade instantiates the wire witness. Other WS
// bridges carry a unit completion and drive their original socket directly.
trait WsCarrier:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug + 'static
{
    type End: Copy + Default + Send + Unpin + std::fmt::Debug + 'static;
    const TRACK_PEER_END: bool = false;

    fn finish_upgrade(&mut self) {}
    fn completion(&self, _clean: bool, _forwarded: u64, _rejected: bool) -> Self::End {
        Self::End::default()
    }
    fn shutdown_result(_end: Self::End) -> io::Result<()> {
        Ok(())
    }
    #[cfg(feature = "rprx")]
    fn forwarded(_end: Self::End) -> Option<u64> {
        None
    }
}

impl<S: AsyncReadWrite + ?Sized + 'static> WsCarrier for Box<S> {
    type End = ();
}

#[cfg(feature = "rprx")]
type FlatVmessWire = ws_close_wire::WsCloseWire<Box<dyn AsyncReadWrite>>;

#[cfg(feature = "rprx")]
#[derive(Debug, Default, Copy, Clone)]
struct FlatWsEnd {
    forwarded: Option<u64>,
    rejected_terminator: bool,
}

#[cfg(feature = "rprx")]
impl WsCarrier for FlatVmessWire {
    type End = FlatWsEnd;
    const TRACK_PEER_END: bool = true;

    fn finish_upgrade(&mut self) {
        ws_close_wire::WsCloseWire::finish_upgrade(self);
    }

    fn completion(&self, clean: bool, forwarded: u64, rejected_terminator: bool) -> FlatWsEnd {
        FlatWsEnd {
            forwarded: (clean && self.eligible_close()).then_some(forwarded),
            rejected_terminator,
        }
    }

    fn shutdown_result(end: FlatWsEnd) -> io::Result<()> {
        if end.rejected_terminator {
            use tokio_tungstenite::tungstenite::error::ProtocolError;
            return Err(io::Error::other(WsError::Protocol(
                ProtocolError::SendAfterClosing,
            )));
        }
        Ok(())
    }

    fn forwarded(end: FlatWsEnd) -> Option<u64> {
        end.forwarded
    }
}

/// Upgrade an already-connected (optionally TLS-wrapped) stream to
/// WebSocket, then bridge through a duplex so the caller gets a
/// plain `AsyncRead + AsyncWrite` handle.
async fn wrap_ws<S: WsCarrier>(
    node: &Node,
    stream: S,
    retain_carrier_failure: bool,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let transport = node.transport().unwrap();
    let ws_path = transport.ws_path.as_deref().unwrap_or("/");
    let ws_host = transport
        .ws_host
        .as_deref()
        .unwrap_or(node.host())
        .to_string();

    // Build the request from the URI so tungstenite generates the full
    // handshake header set (Sec-WebSocket-Key, Upgrade, ...); a bare
    // `http::Request` passed to `client_async` is sent as-is and real
    // servers reject the missing key.
    let uri = format!(
        "ws://{}:{}{}",
        node.host(),
        node.port,
        encode_uri_path(ws_path)
    );
    let mut request = uri
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("WebSocket request build failed: {}", e))?;
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::HOST,
        ws_host
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid WebSocket host header: {}", e))?,
    );
    for (name, value) in &transport.ws_headers {
        request.headers_mut().insert(
            name.parse::<tokio_tungstenite::tungstenite::http::HeaderName>()
                .map_err(|e| anyhow::anyhow!("invalid WebSocket header name: {}", e))?,
            value
                .parse::<tokio_tungstenite::tungstenite::http::HeaderValue>()
                .map_err(|e| anyhow::anyhow!("invalid WebSocket header value: {}", e))?,
        );
    }

    let (mut ws_stream, _response) = tokio_tungstenite::client_async(request, stream)
        .await
        .map_err(|error| anyhow::Error::new(error).context("WebSocket upgrade failed"))?;
    ws_stream.get_mut().finish_upgrade();

    Ok(Box::new(ObservedWs::bridge(
        ws_stream,
        retain_carrier_failure,
    )?))
}

#[derive(Clone)]
struct RelayWork(Arc<parking_lot::Mutex<Option<futures_util::future::BoxFuture<'static, ()>>>>);

impl RelayWork {
    fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        match &mut *self.0.lock() {
            Some(relay) => relay.as_mut().poll(cx),
            None => Poll::Ready(()),
        }
    }
}

impl Drop for RelayWork {
    fn drop(&mut self) {
        // Either owner can retire first. Finish destruction under the same lock
        // so the other cannot return while a nested bridge still owns its writer.
        *self.0.lock() = None;
    }
}

pub(super) struct RelayTask {
    _work: RelayWork,
    task: tokio::task::AbortHandle,
}

impl std::fmt::Debug for RelayTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.task, f)
    }
}

impl RelayTask {
    pub(super) fn spawn(relay: impl Future<Output = ()> + Send + 'static) -> anyhow::Result<Self> {
        let work = RelayWork(Arc::new(parking_lot::Mutex::new(Some(Box::pin(relay)))));
        let worker = work.clone();
        let task = crate::runtime::spawn_owned(std::future::poll_fn(move |cx| worker.poll(cx)))
            .ok_or(crate::proxy::PacketRejection::Cancelled)?;
        Ok(Self { _work: work, task })
    }
}

impl Drop for RelayTask {
    fn drop(&mut self) {
        // A queued Tokio abort cannot prevent a nested transport resuming first.
        // Dispose of the lower carrier and any pending send between polls.
        self.task.abort();
    }
}

#[derive(Debug)]
pub(super) enum UploadEnd<T = ()> {
    Waiting(tokio::sync::oneshot::Receiver<io::Result<T>>),
    Finished(Result<T, Arc<io::Error>>),
}

impl<T: Copy> UploadEnd<T> {
    pub(super) fn channel() -> (tokio::sync::oneshot::Sender<io::Result<T>>, Self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        (tx, Self::Waiting(rx))
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        if let Self::Waiting(rx) = self {
            let result = std::task::ready!(Pin::new(rx).poll(cx))
                .unwrap_or_else(|_| Err(io::ErrorKind::BrokenPipe.into()));
            *self = Self::Finished(result.map_err(Arc::new));
        }
        match self {
            Self::Finished(Err(error)) => Poll::Ready(Err(match error.raw_os_error() {
                Some(code) => io::Error::from_raw_os_error(code),
                None => io::Error::new(error.kind(), error.clone()),
            })),
            Self::Finished(Ok(end)) => Poll::Ready(Ok(*end)),
            Self::Waiting(_) => unreachable!(),
        }
    }
}

type WsRelayResult = Arc<OnceLock<WsRelayFailure>>;

#[derive(Debug)]
struct WsRelayFailure {
    kind: io::ErrorKind,
    cause: crate::SharedError,
    buffered: parking_lot::Mutex<Bytes>,
}

impl WsRelayFailure {
    fn io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.cause.clone())
    }
}

#[cfg(feature = "rprx")]
#[derive(Debug)]
pub(super) struct WsPeerEnd(std::sync::Weak<relay_upload::MarkerSlot>);

#[cfg(feature = "rprx")]
#[derive(Debug, thiserror::Error)]
#[error("WebSocket peer closed with {unforwarded} accepted bytes unsent")]
struct WsOmission {
    owner: WsPeerEnd,
    unforwarded: u64,
}

#[cfg(feature = "rprx")]
impl WsPeerEnd {
    pub(super) fn for_stream(stream: &dyn AsyncReadWrite) -> Option<Self> {
        let ws = stream
            .as_any()
            .downcast_ref::<ObservedWs<FlatVmessWire>>()?;
        Some(Self(ws.pipe.owner()))
    }

    pub(super) fn omitted(&self, error: &io::Error, accepted_terminator_bytes: usize) -> bool {
        // Only this immediate socket can issue the error. Walking the source
        // chain could use a buffered descendant's completion as our own.
        error
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<WsOmission>())
            .is_some_and(|end| {
                self.0.ptr_eq(&end.owner.0)
                    && usize::try_from(end.unforwarded) == Ok(accepted_terminator_bytes)
            })
    }
}

#[derive(Debug)]
struct ObservedWs<S: WsCarrier> {
    _relay: RelayTask,
    inner: tokio::io::DuplexStream,
    pipe: relay_upload::Writer,
    failure: Option<WsRelayResult>,
    finished: UploadEnd<S::End>,
}

impl<S: WsCarrier> ObservedWs<S> {
    fn bridge(
        ws: tokio_tungstenite::WebSocketStream<S>,
        retain_carrier_failure: bool,
    ) -> anyhow::Result<Self> {
        let (inner, server) = tokio::io::duplex(65536);
        // A later observed hop may write its request over this stream.
        let (pipe, reader) = relay_upload::pipe();
        let failure = retain_carrier_failure.then(Arc::default);
        let relay = ws_bridge_relay(ws, server, reader, failure.clone());
        let (done, finished) = UploadEnd::channel();
        let task = RelayTask::spawn(async move {
            let _ = done.send(relay.await);
        })?;
        Ok(Self {
            inner,
            pipe,
            failure,
            _relay: task,
            finished,
        })
    }

    fn relay_failure(&self) -> Option<&WsRelayFailure> {
        self.failure.as_ref()?.get()
    }

    fn poll_upload_error<T>(
        &mut self,
        cx: &mut Context<'_>,
        error: io::Error,
    ) -> Poll<io::Result<T>> {
        let end = std::task::ready!(self.finished.poll(cx))?;
        #[cfg(feature = "rprx")]
        if S::TRACK_PEER_END
            && relay_upload::is_terminator()
            && let Some(unforwarded) = S::forwarded(end).and_then(|n| self.pipe.unforwarded(n))
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                WsOmission {
                    owner: WsPeerEnd(self.pipe.owner()),
                    unforwarded,
                },
            )));
        }
        S::shutdown_result(end)?;
        Poll::Ready(Err(error))
    }

    fn poll_pipe_write(
        &mut self,
        cx: &mut Context<'_>,
        write: impl FnOnce(
            Pin<&mut tokio::io::DuplexStream>,
            &mut Context<'_>,
        ) -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        let inner = &mut self.inner;
        match self.pipe.poll_write(cx, |cx| write(Pin::new(inner), cx)) {
            Poll::Ready(Err(error)) => {
                if let Some(failure) = self.relay_failure() {
                    return Poll::Ready(Err(failure.io_error()));
                }
                if S::TRACK_PEER_END && relay_upload::is_terminator() {
                    return self.poll_upload_error(cx, error);
                }
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }
}

impl<S: WsCarrier> tokio::io::AsyncRead for ObservedWs<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.failure.is_none() || buf.remaining() == 0 {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && buf.filled().len() == before
            && let Some(failure) = self.relay_failure()
        {
            let mut buffered = failure.buffered.lock();
            if buffered.is_empty() {
                return Poll::Ready(Err(failure.io_error()));
            }
            let len = buffered.len().min(buf.remaining());
            buf.put_slice(&buffered[..len]);
            if len == buffered.len() {
                *buffered = Bytes::new();
            } else {
                buffered.advance(len);
            }
        }
        result
    }
}

impl<S: WsCarrier> tokio::io::AsyncWrite for ObservedWs<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll_pipe_write(cx, |inner, cx| inner.poll_write(cx, buf))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll_pipe_write(cx, |inner, cx| inner.poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(failure) = self.relay_failure() {
            return Poll::Ready(Err(failure.io_error()));
        }
        if let Err(error) = std::task::ready!(self.pipe.poll_flush(cx)) {
            return self.poll_upload_error(cx, error);
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        Poll::Ready(std::task::ready!(self.finished.poll(cx)).and_then(S::shutdown_result))
    }
}

/// Background task that bridges a WebSocket stream to a duplex half.
/// Reads binary/text messages from the WebSocket and writes them to
/// the duplex; reads from the duplex and sends as binary WebSocket
/// messages.
async fn ws_bridge_relay<S: WsCarrier>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    server: tokio::io::DuplexStream,
    pipe: relay_upload::Reader,
    failure: Option<WsRelayResult>,
) -> io::Result<S::End> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::error::ProtocolError;

    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut server_read, mut server_write) = tokio::io::split(server);

    // Keep the unforwarded part of a decoded frame if the upload fails while
    // the download is waiting for space in the duplex.
    let mut buffered = Bytes::new();
    // Shared by two futures in the same Send task, and touched only on close.
    let normal_close = AtomicBool::new(false);
    let download = async {
        loop {
            buffered = match ws_stream.next().await {
                Some(Ok(Message::Binary(data))) => data,
                Some(Ok(Message::Text(data))) => data.into(),
                Some(Ok(Message::Close(frame))) => {
                    if S::TRACK_PEER_END {
                        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
                        normal_close.store(
                            frame.is_none_or(|frame| frame.code == CloseCode::Normal),
                            Ordering::Relaxed,
                        );
                    }
                    // The peer has finished sending. A flow-controlled Close
                    // reply must not hide EOF from the copy drain supervisor.
                    server_write.shutdown().await?;
                    continue;
                }
                Some(Ok(_)) => continue,
                Some(Err(error)) => {
                    tracing::debug!(%error, "ws bridge recv error");
                    return Err(error);
                }
                // A closed download also interrupts a still-unflushed upload.
                None => return Err(WsError::ConnectionClosed),
            };
            while !buffered.is_empty() {
                let n = server_write.write(&buffered).await?;
                if n == 0 {
                    return Err(io::Error::from(io::ErrorKind::WriteZero).into());
                }
                buffered.advance(n);
            }
            buffered = Bytes::new();
        }
    };

    let mut relayed = 0u64;
    let mut certain = true;
    let mut rejected_terminator = false;
    let result = async {
        let mut download = std::pin::pin!(download);
        let mut buf = vec![0u8; 65536];
        loop {
            let n = tokio::select! {
                result = download.as_mut() => return result,
                n = server_read.read(&mut buf) => n?,
            };
            if n == 0 {
                certain = false;
                return tokio::select! {
                    result = download.as_mut() => result,
                    result = ws_sink.close() => result,
                };
            }
            let through = relayed + n as u64;
            let send = async {
                // Start the frame before a Pong or Close can flush its remainder
                // from a read poll. Both halves then drive the same request.
                tokio::select! {
                    biased;
                    result = ws_sink.send(Message::Binary(buf[..n].to_vec().into())) => {
                        // This direct codec error precedes queuing the Binary. An I/O
                        // error with the same nested source never establishes that.
                        rejected_terminator = S::TRACK_PEER_END
                            && matches!(result, Err(WsError::Protocol(ProtocolError::SendAfterClosing)))
                            && normal_close.load(Ordering::Relaxed)
                            && relay_upload::is_terminator();
                        result
                    },
                    result = download.as_mut() => result,
                }
            };
            if let Err(error) = pipe.forward(through, |_| send).await {
                // The reader can flush part of an interrupted send. Only a
                // direct prequeue rejection leaves its wire extent known.
                certain = rejected_terminator;
                return Err(error);
            }
            relayed = through;
        }
    }
    .await;
    let result = async {
        let peer_closing = match result {
            Ok(()) => false,
            Err(WsError::ConnectionClosed) => true,
            Err(WsError::Protocol(ProtocolError::SendAfterClosing)) if rejected_terminator => true,
            Err(error) => return Err(error),
        };
        let mut ws = ws_sink
            .reunite(ws_stream)
            .expect("both halves of the same websocket");
        if peer_closing {
            // The reciprocal Close can still be buffered when the reader sees FIN.
            ws.flush().await?;
        }
        ws.get_mut().shutdown().await.map_err(WsError::Io)?;
        // A peer can wait for our TCP FIN before sending its own. Its Close
        // already ruled out any further messages, but a reset must still fail.
        if rejected_terminator && ws.next().await.transpose()?.is_some() {
            return Err(WsError::Protocol(ProtocolError::ReceivedAfterClosing));
        }
        Ok(ws.get_ref().completion(
            S::TRACK_PEER_END && peer_closing && certain && normal_close.load(Ordering::Relaxed),
            relayed,
            rejected_terminator,
        ))
    }
    .await;
    let error = match result {
        Ok(end) => return Ok(end),
        Err(WsError::Io(error)) => error,
        Err(error) => return Err(io::Error::other(error)),
    };
    #[cfg(feature = "rprx")]
    let error = if S::TRACK_PEER_END {
        ws_close_wire::restore_reset(error)
    } else {
        error
    };
    if let Some(failure) = failure {
        let error = if super::error::io_node_failure(&error) || super::io_target_failure(&error) {
            // We own the error and can keep provenance outside a shared cause too.
            error
        } else if let Some(error) = super::retain_typed_io_error(&error) {
            error
        } else {
            return Err(error);
        };
        // Publish before the duplex halves drop and wake a waiter with EOF or BrokenPipe.
        let failure = failure.get_or_init(|| WsRelayFailure {
            kind: error.kind(),
            cause: crate::SharedError::new(error.into()),
            buffered: parking_lot::Mutex::new(buffered),
        });
        return Err(failure.io_error());
    }
    Err(error)
}

mod grpc;
mod h2_io;
pub(super) mod relay_upload;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tunnel_tests;
#[cfg(feature = "rprx")]
mod ws_close_wire;
pub(crate) mod xhttp;
