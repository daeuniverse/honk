//! Shared stream-transport helpers for proxy handlers.
//!
//! Trojan, VMess and VLESS all wrap their connections in the same order:
//!
//! ```text
//! TCP -> (TLS) -> (WebSocket | gRPC) -> protocol header
//! ```
//!
//! This module provides the reusable pieces so each handler only implements
//! its own protocol handshake:
//!
//! - [`wrap_transport`]: optional TCP connect + TLS + WS/gRPC wrapping,
//!   shared by cold dials and supplied pooled sockets.
//! - [`maybe_tls_wrap`]: just the TCP/TLS step, preserving the same setup budget.
//! - [`grpc`]: gRPC gun framing over a connection-owned HTTP/2 client.

use futures_util::{SinkExt, StreamExt};
use honk_config::node::Node;
use tokio::net::TcpStream;

use crate::proxy::transport::grpc::wrap_grpc;

use super::AsyncReadWrite;
use crate::transport_quality::tcp::ObservedTcp;

/// Connect if needed, then apply TLS and `node.transport` wrapping.
pub(crate) async fn wrap_transport(
    node: &Node,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let stream = maybe_tls_wrap(node, tcp, connect_timeout).await?;
    wrap_after_tls(node, stream).await
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
            "node '{}': unsupported transport '{}' (expected tcp/ws/grpc)",
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

pub(crate) async fn maybe_tls_wrap_concrete(
    node: &Node,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
) -> anyhow::Result<MaybeTls> {
    let tls = node.tls().unwrap();
    if !tls.alpn.is_empty() {
        node.validate_protocol()?;
    }
    let cold = tcp.is_none();
    let initial_tcp = async {
        match tcp {
            Some(tcp) => Ok(tcp),
            None => {
                let addr = format!("{}:{}", node.host(), node.port);
                crate::util::connect_outbound(&addr, connect_timeout).await
            }
        }
    };
    if let Some(reality) = crate::reality::parse_reality_config(node)? {
        let deadline = tokio::time::Instant::now() + connect_timeout * 3;
        let setup = async {
            let tcp = initial_tcp.await?;
            let peer = tcp.peer_addr()?;
            let tcp = ObservedTcp::new(tcp);
            let chrome = crate::tls::chrome_mode();
            let mut tls_stream =
                match crate::reality::reality_connect_with_key_shares(tcp, &reality, chrome, true)
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
                                tcp, &reality, chrome, false,
                            )
                            .await
                        };
                        crate::runtime::admit_replacement_dial(replacement, cold).await?
                    }
                    Err(error) => return Err(error),
                };
            tls_stream.get_mut().activate();
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
        let server_name = tls.sni.clone().unwrap_or_else(|| node.host().to_string());
        let mut tls_stream = connector.connect(&server_name, tcp).await?;
        tls_stream.get_mut().activate();
        return Ok(MaybeTls::Tls(tls_stream));
    }
    tcp.activate();
    Ok(MaybeTls::Plain(Box::new(tcp)))
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
    let uri = format!("ws://{}:{}{}", node.host(), node.port, ws_path);
    let mut request = uri
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("WebSocket request build failed: {}", e))?;
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::HOST,
        ws_host
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid WebSocket host header: {}", e))?,
    );

    let (ws_stream, _response) = tokio_tungstenite::client_async(request, stream)
        .await
        .map_err(|e| anyhow::anyhow!("WebSocket upgrade failed: {}", e))?;

    let (client_half, server_half) = tokio::io::duplex(65536);

    tokio::spawn(ws_bridge_relay(ws_stream, server_half));

    Ok(Box::new(client_half))
}

/// Background task that bridges a WebSocket stream to a duplex half.
/// Reads binary/text messages from the WebSocket and writes them to
/// the duplex; reads from the duplex and sends as binary WebSocket
/// messages.
async fn ws_bridge_relay(
    ws: tokio_tungstenite::WebSocketStream<Box<dyn AsyncReadWrite>>,
    server: tokio::io::DuplexStream,
) {
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut server_read, mut server_write) = tokio::io::split(server);

    // server → ws
    let s2w = async {
        let mut buf = vec![0u8; 65536];
        loop {
            use tokio::io::AsyncReadExt;
            let n = server_read
                .read(&mut buf)
                .await
                .map_err(|e| anyhow::anyhow!("ws bridge server read: {}", e))?;
            if n == 0 {
                break;
            }
            ws_sink
                .send(tokio_tungstenite::tungstenite::Message::Binary(
                    buf[..n].to_vec().into(),
                ))
                .await
                .map_err(|e| anyhow::anyhow!("ws bridge send: {}", e))?;
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
#[cfg(test)]
mod tests;
