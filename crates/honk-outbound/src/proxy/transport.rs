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
                crate::util::connect_outbound(&addr, connect_timeout).await
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
                        let tcp = crate::util::connect_marked_addr(
                            peer,
                            Some(crate::util::bypass_mark()),
                            connect_timeout.min(remaining),
                        )
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

/// Upgrade an already-connected (optionally TLS-wrapped) stream to
/// WebSocket, then bridge through a duplex so the caller gets a
/// plain `AsyncRead + AsyncWrite` handle.
async fn wrap_ws(
    node: &Node,
    stream: Box<dyn AsyncReadWrite>,
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

    let (ws_stream, _response) = tokio_tungstenite::client_async(request, stream)
        .await
        .map_err(|error| anyhow::Error::new(error).context("WebSocket upgrade failed"))?;

    let (client_half, server_half) = tokio::io::duplex(65536);
    // Tracked even without an observer: a later hop may write its request
    // over this stream inside an observed flow.
    let pipe = crate::runtime::flow_observation::RelayedPipe::new();
    let failure = retain_carrier_failure.then(Arc::default);
    let _ = crate::runtime::spawn_owned(ws_bridge_relay(
        ws_stream,
        server_half,
        pipe.clone(),
        failure.clone(),
    ));
    Ok(Box::new(ObservedWs {
        inner: client_half,
        pipe,
        failure,
    }))
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

#[derive(Debug)]
struct ObservedWs {
    inner: tokio::io::DuplexStream,
    pipe: crate::runtime::flow_observation::RelayedPipe,
    failure: Option<WsRelayResult>,
}

impl ObservedWs {
    fn relay_failure(&self) -> Option<&WsRelayFailure> {
        self.failure.as_ref()?.get()
    }
}

impl tokio::io::AsyncRead for ObservedWs {
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

impl tokio::io::AsyncWrite for ObservedWs {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.pipe
            .poll_write(|| Pin::new(inner).poll_write(cx, buf))
            .map_err(|error| this.relay_failure().map_or(error, WsRelayFailure::io_error))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.pipe
            .poll_write(|| Pin::new(inner).poll_write_vectored(cx, bufs))
            .map_err(|error| this.relay_failure().map_or(error, WsRelayFailure::io_error))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(failure) = self.relay_failure() {
            return Poll::Ready(Err(failure.io_error()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Background task that bridges a WebSocket stream to a duplex half.
/// Reads binary/text messages from the WebSocket and writes them to
/// the duplex; reads from the duplex and sends as binary WebSocket
/// messages.
async fn ws_bridge_relay(
    ws: tokio_tungstenite::WebSocketStream<Box<dyn AsyncReadWrite>>,
    server: tokio::io::DuplexStream,
    pipe: crate::runtime::flow_observation::RelayedPipe,
    failure: Option<WsRelayResult>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut server_read, mut server_write) = tokio::io::split(server);

    // server → ws
    let s2w = async {
        let mut buf = vec![0u8; 65536];
        let mut relayed = 0u64;
        loop {
            let n = server_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            relayed += n as u64;
            let mut send = ws_sink.send(Message::Binary(buf[..n].to_vec().into()));
            let sent = match pipe.take(relayed) {
                Some(request) => request.write(Pin::new(&mut send)).await,
                None => send.await,
            };
            sent?;
        }
        ws_sink.close().await
    };

    // ws → server
    // Keep the unforwarded part of a decoded frame if the upload fails while
    // the download is waiting for space in the duplex.
    let mut buffered = Bytes::new();
    let w2s = async {
        loop {
            buffered = match ws_stream.next().await {
                Some(Ok(Message::Binary(data))) => data,
                Some(Ok(Message::Text(data))) => data.into(),
                Some(Ok(_)) => continue,
                Some(Err(error)) => {
                    tracing::debug!(%error, "ws bridge recv error");
                    return Err(error);
                }
                None => break,
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
        Ok(())
    };

    let result = tokio::select! {
        result = s2w => result,
        result = w2s => result,
    };
    if let (Some(failure), Err(WsError::Io(error))) = (failure, result) {
        let error = if super::error::io_node_failure(&error) || super::io_target_failure(&error) {
            // We own the error and can keep provenance outside a shared cause too.
            error
        } else if let Some(error) = super::retain_typed_io_error(&error) {
            error
        } else {
            return;
        };
        // Publish before the duplex halves drop and wake a waiter with EOF or BrokenPipe.
        let _ = failure.set(WsRelayFailure {
            kind: error.kind(),
            cause: crate::SharedError::new(error.into()),
            buffered: parking_lot::Mutex::new(buffered),
        });
    }
}

mod grpc;
mod h2_io;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tunnel_tests;
pub(crate) mod xhttp;
