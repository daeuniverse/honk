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

use futures_util::{SinkExt, StreamExt};
use honk_config::node::Node;
use percent_encoding::{AsciiSet, CONTROLS, PercentEncode, utf8_percent_encode};
use tokio::net::TcpStream;

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
        "ws" => wrap_ws(node, stream).await,
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
        let server_name = tls_server_name(node);
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

/// TLS server name for a plain-TLS dial: an explicit SNI wins, then the
/// WebSocket `Host` authority, then the endpoint address.
///
/// CDN-fronted nodes carry the edge IP as their address and the distribution
/// name only in the WebSocket `Host` header. An IP-literal server name sends
/// no SNI, so the edge answers with a default certificate that cannot match
/// the distribution and verification fails.
fn tls_server_name(node: &Node) -> String {
    if let Some(sni) = node.tls().and_then(|tls| tls.sni.as_deref()) {
        return sni.to_string();
    }
    // The header is an authority, so a `:port` suffix is not SNI; an empty or
    // unparsable one falls through to the endpoint address.
    node.transport()
        .filter(|transport| transport.transport == "ws")
        .and_then(|transport| transport.ws_host.as_deref())
        .and_then(|host| host.parse::<http::uri::Authority>().ok())
        .map(|authority| {
            // `Authority::host` keeps the brackets of an IPv6 literal; the connector
            // recognises (and sends no SNI for) only the bare address.
            authority
                .host()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string()
        })
        .unwrap_or_else(|| node.host().to_string())
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
    let (Some(tls), Some(_)) = (node.tls(), node.transport()) else {
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
            let server_name = tls_server_name(node);
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
        .map_err(|e| anyhow::anyhow!("WebSocket upgrade failed: {}", e))?;

    let (client_half, server_half) = tokio::io::duplex(65536);
    // Tracked even without an observer: a later hop may write its request
    // over this stream inside an observed flow.
    let pipe = crate::runtime::flow_observation::RelayedPipe::new();
    let _ = crate::runtime::spawn_owned(ws_bridge_relay(ws_stream, server_half, pipe.clone()));
    Ok(Box::new(ObservedWs {
        inner: client_half,
        pipe,
    }))
}

#[derive(Debug)]
struct ObservedWs {
    inner: tokio::io::DuplexStream,
    pipe: crate::runtime::flow_observation::RelayedPipe,
}

impl tokio::io::AsyncRead for ObservedWs {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ObservedWs {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.pipe
            .poll_write(|| std::pin::Pin::new(inner).poll_write(cx, buf))
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.pipe
            .poll_write(|| std::pin::Pin::new(inner).poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
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
) {
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut server_read, mut server_write) = tokio::io::split(server);

    // server → ws
    let s2w = async {
        let mut buf = vec![0u8; 65536];
        let mut relayed = 0u64;
        loop {
            use tokio::io::AsyncReadExt;
            let n = server_read
                .read(&mut buf)
                .await
                .map_err(|e| anyhow::anyhow!("ws bridge server read: {}", e))?;
            if n == 0 {
                break;
            }
            relayed += n as u64;
            let mut send = ws_sink.send(tokio_tungstenite::tungstenite::Message::Binary(
                buf[..n].to_vec().into(),
            ));
            let sent = match pipe.take(relayed) {
                Some(request) => request.write(std::pin::Pin::new(&mut send)).await,
                None => send.await,
            };
            sent.map_err(|e| anyhow::anyhow!("ws bridge send: {}", e))?;
        }
        let _ = ws_sink.close().await;
        Ok::<_, anyhow::Error>(())
    };

    // ws → server
    let w2s = async {
        loop {
            let msg = ws_stream.next().await;
            match msg {
                Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => {
                    use tokio::io::AsyncWriteExt;
                    server_write.write_all(&data).await?;
                }
                Some(Ok(tokio_tungstenite::tungstenite::Message::Text(data))) => {
                    use tokio::io::AsyncWriteExt;
                    server_write.write_all(data.as_bytes()).await?;
                }
                Some(Ok(
                    tokio_tungstenite::tungstenite::Message::Close(_)
                    | tokio_tungstenite::tungstenite::Message::Ping(_)
                    | tokio_tungstenite::tungstenite::Message::Pong(_),
                )) => {}
                Some(Ok(tokio_tungstenite::tungstenite::Message::Frame(_))) => {}
                Some(Err(e)) => {
                    tracing::debug!("ws bridge recv error: {}", e);
                    break;
                }
                None => break,
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = s2w => { let _ = r; },
        r = w2s => { let _ = r; },
    }
}

mod grpc;
mod h2_io;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tunnel_tests;
pub(crate) mod xhttp;
