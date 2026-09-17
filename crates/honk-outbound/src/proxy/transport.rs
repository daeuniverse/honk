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
//! - [`GrpcStream`]: minimal gRPC-over-HTTP/2 framing client.

use futures_util::{SinkExt, StreamExt};
use honk_config::node::Node;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use super::AsyncReadWrite;

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
        MaybeTls::Tls(stream) => Ok(Box::new(crate::tls::BatchRead::new(*stream))),
        MaybeTls::Plain(stream) => Ok(Box::new(stream)),
    }
}

/// [`maybe_tls_wrap`] without erasing the concrete stream type: the XTLS
/// Vision direct-copy switch must reach the raw TCP socket under the TLS
/// stream once the server abandons the outer TLS session.
pub(crate) enum MaybeTls {
    Tls(Box<crate::tls::TlsStream<TcpStream>>),
    Plain(TcpStream),
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
            let chrome = crate::tls::chrome_mode();
            let tls_stream =
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
                                Some(honk_ebpf_common::DAE_BYPASS_MARK),
                                connect_timeout.min(remaining),
                            )
                            .await?;
                            crate::reality::reality_connect_with_key_shares(
                                tcp, &reality, chrome, false,
                            )
                            .await
                        };
                        crate::runtime::admit_replacement_dial(replacement, cold).await?
                    }
                    Err(error) => return Err(error),
                };
            Ok(MaybeTls::Tls(Box::new(tls_stream)))
        };
        return tokio::time::timeout_at(deadline, setup)
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "REALITY setup timeout")
            })?;
    }
    let tcp = initial_tcp.await?;
    if tls.enabled {
        let connector = crate::tls::build_connector(node)?;
        let server_name = tls.sni.clone().unwrap_or_else(|| node.host().to_string());
        let tls_stream = connector.connect(&server_name, tcp).await?;
        return Ok(MaybeTls::Tls(Box::new(tls_stream)));
    }
    Ok(MaybeTls::Plain(tcp))
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

/// Wrap an already-connected stream with minimal gRPC-over-HTTP/2
/// framing. On first read/write the HTTP/2 preface + SETTINGS +
/// HEADERS are sent, then all data is tunnelled through gRPC
/// length-prefixed DATA frames.
async fn wrap_grpc(
    node: &Node,
    stream: Box<dyn AsyncReadWrite>,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let service = node
        .transport()
        .unwrap()
        .grpc_service
        .as_deref()
        .unwrap_or("GunService");
    let path = format!("/{}/Tun", service);
    let authority = node.host().to_string();
    // gRPC servers (sing-box) reject :scheme http over a TLS connection.
    let scheme = if node.tls().unwrap().enabled {
        "https"
    } else {
        "http"
    };

    Ok(Box::new(
        GrpcStream::new(stream, &path, &authority, scheme).await?,
    ))
}

/// Minimal gRPC client that wraps a TCP/TLS stream with HTTP/2
/// framing and gRPC message framing.
///
/// On construction sends: HTTP/2 preface + SETTINGS + HEADERS frame
/// to open a gRPC stream. Every read/write payload is one gRPC message:
/// HTTP/2 DATA frames carry a length-prefixed block
/// (`[1 byte compressed] [4 bytes BE length] [message]`), and the message
/// itself is the protobuf single-bytes-field envelope (`0x0a` tag + varint
/// length + content) that gun-style transports (sing-box, Xray) put
/// inside it — verified byte-for-byte against a sing-box client capture.
struct GrpcStream {
    inner: Box<dyn AsyncReadWrite>,
    stream_id: u32,
    /// Decoded payload not yet consumed by the reader.
    read_buf: Vec<u8>,
    /// Raw undecoded bytes from `inner` awaiting frame parsing; short
    /// reads land here instead of corrupting frame alignment.
    undecoded: Vec<u8>,
    /// DATA-frame payloads awaiting message parsing; a message may span
    /// multiple DATA frames.
    msg_buf: Vec<u8>,
    /// Outbound frames owned until the inner transport consumes them.
    write_queue: VecDeque<u8>,
    /// Client→server flow-control windows (RFC 7540 §6.9): the server's
    /// advertised initial stream window plus WINDOW_UPDATE increments,
    /// minus queued DATA payload bytes.
    send_stream_window: i64,
    send_conn_window: i64,
    /// Server's SETTINGS_INITIAL_WINDOW_SIZE, tracked so its SETTINGS
    /// frame can adjust the live stream window by the delta.
    peer_initial_window: i64,
    /// Server's SETTINGS_MAX_FRAME_SIZE.
    peer_max_frame: usize,
    /// DATA payload bytes received since the last WINDOW_UPDATE top-up.
    recv_unacked: u32,
    /// SETTINGS ACKs / WINDOW_UPDATEs sit in `write_queue`; the read path
    /// flushes them while downloading so a pure receiver never stalls.
    control_pending: bool,
    /// The server closed its send side (DATA/HEADERS with END_STREAM).
    stream_eof: bool,
    /// poll_shutdown already queued the END_STREAM marker.
    end_stream_sent: bool,
}

impl std::fmt::Debug for GrpcStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcStream")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

const H2_DATA: u8 = 0x0;
const H2_HEADERS: u8 = 0x1;
const H2_SETTINGS: u8 = 0x4;
const H2_WINDOW_UPDATE: u8 = 0x8;

const H2_FLAG_END_STREAM: u8 = 0x01;
const H2_FLAG_ACK: u8 = 0x01;
const H2_FLAG_END_HEADERS: u8 = 0x04;

const H2_DEFAULT_WINDOW: i64 = 65535;
/// RFC 7540 caps a flow-control window at 2^31 - 1.
const H2_MAX_WINDOW: i64 = 0x7FFF_FFFF;
const H2_DEFAULT_MAX_FRAME: usize = 16384;
/// Top the peer's send windows up after this many received DATA bytes;
/// far below the advertised ~2 GiB window, so the top-up frames are
/// always flushed by ongoing reads long before the peer could stall.
const H2_WINDOW_REFRESH: u32 = 8 * 1024 * 1024;
/// gRPC prefix plus protobuf tag and the one-byte varint for one payload byte.
const GRPC_MESSAGE_OVERHEAD_MIN: usize = 7;

/// Encode an uncompressed HPACK string length (RFC 7541 §5.1).
fn push_hpack_string_length(hpack: &mut Vec<u8>, length: usize) {
    const PREFIX_MAX: usize = (1 << 7) - 1;
    if length < PREFIX_MAX {
        hpack.push(length as u8);
        return;
    }

    hpack.push(PREFIX_MAX as u8);
    let mut remainder = length - PREFIX_MAX;
    while remainder >= (1 << 7) {
        hpack.push(((remainder as u8) & 0x7f) | 0x80);
        remainder >>= 7;
    }
    hpack.push(remainder as u8);
}

impl GrpcStream {
    async fn new(
        inner: Box<dyn AsyncReadWrite>,
        path: &str,
        authority: &str,
        scheme: &str,
    ) -> anyhow::Result<Self> {
        let mut s = Self {
            inner,
            stream_id: 1,
            read_buf: Vec::new(),
            undecoded: Vec::new(),
            msg_buf: Vec::new(),
            write_queue: VecDeque::new(),
            send_stream_window: H2_DEFAULT_WINDOW,
            send_conn_window: H2_DEFAULT_WINDOW,
            peer_initial_window: H2_DEFAULT_WINDOW,
            peer_max_frame: H2_DEFAULT_MAX_FRAME,
            recv_unacked: 0,
            control_pending: false,
            stream_eof: false,
            end_stream_sent: false,
        };
        s.send_preface().await?;
        s.send_settings().await?;
        s.send_headers_frame(path, authority, scheme).await?;
        Ok(s)
    }

    /// Send the HTTP/2 connection preface.
    async fn send_preface(&mut self) -> anyhow::Result<()> {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        self.inner.write_all(PREFACE).await?;
        Ok(())
    }

    /// Send the SETTINGS frame: a maximal initial stream window, so the
    /// server is never stream-window limited before the first top-up.
    /// Followed by a connection-level WINDOW_UPDATE bringing the receive
    /// connection window to 2^31 - 1; both windows are topped up by the
    /// read path as DATA arrives (see `H2_WINDOW_REFRESH`).
    async fn send_settings(&mut self) -> anyhow::Result<()> {
        let mut frame = Vec::with_capacity(9 + 6 + 9 + 4);
        push_frame_header(&mut frame, 6, H2_SETTINGS, 0, 0);
        // SETTINGS_INITIAL_WINDOW_SIZE (0x4)
        frame.extend_from_slice(&[0, 4]);
        frame.extend_from_slice(&(H2_MAX_WINDOW as u32).to_be_bytes());
        push_frame_header(&mut frame, 4, H2_WINDOW_UPDATE, 0, 0);
        frame.extend_from_slice(&((H2_MAX_WINDOW - H2_DEFAULT_WINDOW) as u32).to_be_bytes());
        self.inner.write_all(&frame).await?;
        Ok(())
    }

    /// Send a HEADERS frame to open stream 1 with gRPC pseudo-headers.
    async fn send_headers_frame(
        &mut self,
        path: &str,
        authority: &str,
        scheme: &str,
    ) -> anyhow::Result<()> {
        let mut hpack = Vec::with_capacity(128);

        // :method: POST — literal header field with incremental indexing
        // 0x40 | 0x03 = 0x43 (indexed name, ref static table idx 3 = ":method")
        // value: "POST" = 4 bytes, huffman not used
        hpack.push(0x43);
        hpack.push(0x04);
        hpack.extend_from_slice(b"POST");

        // :scheme — same pattern, static idx 6 = ":scheme"
        hpack.push(0x46);
        push_hpack_string_length(&mut hpack, scheme.len());
        hpack.extend_from_slice(scheme.as_bytes());

        // :path: <path> — static idx 4 = ":path"
        hpack.push(0x44);
        push_hpack_string_length(&mut hpack, path.len());
        hpack.extend_from_slice(path.as_bytes());

        // :authority: <authority> — static idx 1 = ":authority"
        hpack.push(0x41);
        push_hpack_string_length(&mut hpack, authority.len());
        hpack.extend_from_slice(authority.as_bytes());

        // content-type: application/grpc — static idx 31 = "content-type"
        hpack.push(0x5f); // 0x40 | 31
        hpack.push(16); // "application/grpc" len
        hpack.extend_from_slice(b"application/grpc");

        // te: trailers — "te" is not in the HPACK static table (55 is
        // set-cookie), so encode it as a literal name without indexing.
        hpack.push(0x00);
        hpack.push(2);
        hpack.extend_from_slice(b"te");
        hpack.push(8); // "trailers" len
        hpack.extend_from_slice(b"trailers");

        // user-agent: honk — static idx 58 for the name
        hpack.push(0x40 | 58);
        hpack.push(4); // "honk" len
        hpack.extend_from_slice(b"honk");

        let mut frame = Vec::with_capacity(9 + hpack.len());
        push_frame_header(
            &mut frame,
            hpack.len() as u32,
            H2_HEADERS,
            H2_FLAG_END_HEADERS,
            self.stream_id,
        );
        frame.extend_from_slice(&hpack);
        self.inner.write_all(&frame).await?;
        self.inner.flush().await?;
        Ok(())
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let drain = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..drain]);
                self.read_buf.drain(..drain);
                return Poll::Ready(Ok(()));
            }
            while self.try_parse_message() {}
            if !self.read_buf.is_empty() {
                continue;
            }
            if self.stream_eof {
                return Poll::Ready(Ok(()));
            }
            if self.try_parse_frame() {
                if self.control_pending {
                    // A delayed top-up flushes on the next read; the
                    // advertised window is large enough that it can never
                    // stall the peer.
                    if let Poll::Ready(Ok(())) = self.drain_write_queue(cx) {
                        self.control_pending = false;
                    }
                }
                continue;
            }

            // Need more bytes from the inner stream.
            let mut chunk = [0u8; 4096];
            let mut rb = ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        // EOF: an empty read is the AsyncRead EOF signal.
                        return Poll::Ready(Ok(()));
                    }
                    self.undecoded.extend_from_slice(rb.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Append the 9-byte HTTP/2 frame header to `out`.
fn push_frame_header(
    out: &mut Vec<u8>,
    payload_len: u32,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
) {
    out.extend_from_slice(&[
        (payload_len >> 16) as u8,
        (payload_len >> 8) as u8,
        payload_len as u8,
        frame_type,
        flags,
        ((stream_id >> 24) & 0x7F) as u8,
        ((stream_id >> 16) & 0xFF) as u8,
        ((stream_id >> 8) & 0xFF) as u8,
        (stream_id & 0xFF) as u8,
    ]);
}

impl GrpcStream {
    /// Parse one complete HTTP/2 frame out of `self.undecoded` if fully
    /// present. DATA payloads append to `msg_buf`; SETTINGS and
    /// WINDOW_UPDATE drive the send-side flow control; DATA/HEADERS with
    /// END_STREAM on our stream mark `stream_eof`. Returns false when the
    /// next frame is incomplete.
    fn try_parse_frame(&mut self) -> bool {
        if self.undecoded.len() < 9 {
            return false;
        }
        let payload_len = ((self.undecoded[0] as usize) << 16)
            | ((self.undecoded[1] as usize) << 8)
            | self.undecoded[2] as usize;
        let frame_type = self.undecoded[3];
        let flags = self.undecoded[4];
        let stream_id = u32::from_be_bytes([
            self.undecoded[5] & 0x7F,
            self.undecoded[6],
            self.undecoded[7],
            self.undecoded[8],
        ]);
        let total = 9 + payload_len;
        if self.undecoded.len() < total {
            return false;
        }
        let payload = self.undecoded[9..total].to_vec();
        self.undecoded.drain(..total);
        match frame_type {
            H2_DATA => {
                self.recv_unacked = self.recv_unacked.saturating_add(payload_len as u32);
                if self.recv_unacked >= H2_WINDOW_REFRESH {
                    self.queue_window_updates();
                }
                self.msg_buf.extend_from_slice(&payload);
            }
            H2_SETTINGS if stream_id == 0 && flags & H2_FLAG_ACK == 0 => {
                self.apply_peer_settings(&payload);
                let mut ack = Vec::with_capacity(9);
                push_frame_header(&mut ack, 0, H2_SETTINGS, H2_FLAG_ACK, 0);
                self.write_queue.extend(ack);
                self.control_pending = true;
            }
            H2_WINDOW_UPDATE if payload.len() == 4 => {
                let inc = (u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                    & 0x7FFF_FFFF) as i64;
                if inc > 0 {
                    let window = if stream_id == 0 {
                        &mut self.send_conn_window
                    } else if stream_id == self.stream_id {
                        &mut self.send_stream_window
                    } else {
                        return true;
                    };
                    *window = (*window + inc).min(H2_MAX_WINDOW);
                }
            }
            _ => {}
        }
        if stream_id == self.stream_id && flags & H2_FLAG_END_STREAM != 0 {
            self.stream_eof = true;
        }
        true
    }

    /// Apply the server's SETTINGS: INITIAL_WINDOW_SIZE adjusts the live
    /// stream window by its delta (RFC 7540 §6.9.2), MAX_FRAME_SIZE caps
    /// the DATA frames poll_write emits.
    fn apply_peer_settings(&mut self, payload: &[u8]) {
        for entry in payload.as_chunks::<6>().0 {
            let id = u16::from_be_bytes([entry[0], entry[1]]);
            let value = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
            match id {
                0x4 => {
                    let new = (value & 0x7FFF_FFFF) as i64;
                    self.send_stream_window += new - self.peer_initial_window;
                    self.peer_initial_window = new;
                }
                0x5 => {
                    self.peer_max_frame = (value as usize).clamp(H2_DEFAULT_MAX_FRAME, 0xFF_FFFF);
                }
                _ => {}
            }
        }
    }

    /// Top up the stream and connection receive windows by the bytes
    /// consumed since the last update.
    fn queue_window_updates(&mut self) {
        let inc = self.recv_unacked;
        self.recv_unacked = 0;
        let mut frames = Vec::with_capacity(2 * (9 + 4));
        for stream_id in [self.stream_id, 0] {
            push_frame_header(&mut frames, 4, H2_WINDOW_UPDATE, 0, stream_id);
            frames.extend_from_slice(&inc.to_be_bytes());
        }
        self.write_queue.extend(frames);
        self.control_pending = true;
    }

    /// Drive inbound frames until the send window fits at least one application
    /// byte and its gRPC/protobuf envelope. Pending arms the read-side waker for
    /// the WINDOW_UPDATE or SETTINGS change that can make progress.
    fn poll_send_window(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.send_stream_window.min(self.send_conn_window) <= GRPC_MESSAGE_OVERHEAD_MIN as i64
        {
            if self.try_parse_frame() {
                continue;
            }
            let mut chunk = [0u8; 4096];
            let mut rb = ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "grpc: EOF while waiting for send window",
                        )));
                    }
                    self.undecoded.extend_from_slice(rb.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Parse one complete gRPC message out of `self.msg_buf`, appending
    /// its content to `self.read_buf`. The message envelope is the
    /// protobuf bytes field (`0x0a` + varint length) inside the
    /// length-prefixed block; anything else passes through raw so a
    /// non-gun framing still delivers its bytes.
    fn try_parse_message(&mut self) -> bool {
        if self.msg_buf.len() < 5 {
            return false;
        }
        let compressed = self.msg_buf[0];
        let msg_len = u32::from_be_bytes([
            self.msg_buf[1],
            self.msg_buf[2],
            self.msg_buf[3],
            self.msg_buf[4],
        ]) as usize;
        if self.msg_buf.len() < 5 + msg_len {
            return false;
        }
        let msg = &self.msg_buf[5..5 + msg_len];
        let content = if compressed == 0 && msg.first() == Some(&0x0a) {
            match parse_varint(&msg[1..]) {
                Some((len, used)) if 1 + used + len == msg.len() => &msg[1 + used..],
                _ => msg,
            }
        } else {
            msg
        };
        self.read_buf.extend_from_slice(content);
        self.msg_buf.drain(..5 + msg_len);
        true
    }
}

fn parse_varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut value: usize = 0;
    for (i, &b) in bytes.iter().enumerate().take(10) {
        value |= ((b & 0x7f) as usize) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
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

fn grpc_chunk_len(input_len: usize, max_data_frame: usize) -> usize {
    let mut chunk = input_len.min(max_data_frame.saturating_sub(GRPC_MESSAGE_OVERHEAD_MIN));
    while chunk != 0 && chunk + 6 + protobuf_varint_len(chunk) > max_data_frame {
        chunk -= 1;
    }
    chunk
}

fn protobuf_varint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

impl GrpcStream {
    /// Write as much of the queued frame as possible; Pending keeps the
    /// remainder queued for the next call.
    fn drain_write_queue(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.write_queue.is_empty() {
            let n = match Pin::new(&mut self.inner).poll_write(cx, self.write_queue.as_slices().0) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "grpc: inner transport accepted zero bytes",
                )));
            }
            self.write_queue.drain(..n);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.end_stream_sent {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "grpc: stream write side is closed",
            )));
        }
        match self.drain_write_queue(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        match self.poll_send_window(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let available = self.send_stream_window.min(self.send_conn_window) as usize;
        let chunk_len = grpc_chunk_len(buf.len(), self.peer_max_frame.min(available));
        debug_assert!(chunk_len != 0);
        let chunk = &buf[..chunk_len];
        // Message: [1B uncompressed] [4B BE length] [protobuf envelope]:
        // field 1 bytes content (0x0a tag + varint length + payload).
        let mut msg = Vec::with_capacity(5 + chunk.len());
        msg.push(0x0a);
        push_varint(&mut msg, chunk.len());
        msg.extend_from_slice(chunk);
        let h2_len = 5 + msg.len();
        let mut frame = Vec::with_capacity(9 + h2_len);
        push_frame_header(&mut frame, h2_len as u32, H2_DATA, 0x00, self.stream_id);
        frame.push(0x00); // uncompressed
        frame.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        frame.extend_from_slice(&msg);
        self.send_stream_window -= h2_len as i64;
        self.send_conn_window -= h2_len as i64;
        self.write_queue.extend(frame);
        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.drain_write_queue(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        // Half-close the gRPC stream with an empty END_STREAM DATA frame
        // before closing the transport: a bare TCP close would race the
        // server's in-flight response.
        if !self.end_stream_sent {
            self.end_stream_sent = true;
            let mut frame = Vec::with_capacity(9);
            push_frame_header(&mut frame, 0, H2_DATA, H2_FLAG_END_STREAM, self.stream_id);
            self.write_queue.extend(frame);
        }
        match self.drain_write_queue(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests;
