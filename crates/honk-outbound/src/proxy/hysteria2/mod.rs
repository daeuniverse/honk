//! Hysteria2 proxy handler over real QUIC (quinn), wire-compatible with the
//! official hysteria2 server and sing-box's hysteria2 outbound.
//!
//! Protocol summary, implemented against the sing-quic reference
//! (`sing-box/vendor/github.com/sagernet/sing-quic/hysteria2/`):
//!
//! - **Transport**: QUIC with ALPN `h3` (`client.go:100-102` — hysteria2
//!   speaks HTTP/3 for authentication; the hysteria1 ALPN `hysteria` does not
//!   apply here). Keep-alive every 10s (`hysteria/protocol.go:21`).
//! - **Authentication** (`internal/protocol/http.go`, `client.go:533-605`):
//!   an HTTP/3 `POST https://hysteria/auth` request on a client bi stream
//!   carrying the `Hysteria-Auth` (password), `Hysteria-CC-RX` (receive
//!   bandwidth, 0 = unset) and `Hysteria-Padding` headers. The server answers
//!   with status **233** on success plus `Hysteria-UDP` / `Hysteria-CC-RX`
//!   response headers; anything else means authentication failed.
//! - **TCP** (`internal/protocol/proxy.go:32-151`, `service.go:330-360`): one
//!   bi stream per connection starting with frame type `0x401`, then the
//!   target address (`varint len + "host:port"`) and random padding. The
//!   server replies with a status byte, a message string, and padding; the
//!   stream then becomes the raw data channel.
//! - **UDP** (`internal/protocol/proxy.go:153-221`, `packet.go`): QUIC
//!   datagrams (RFC 9221) carrying
//!   `[session u32 BE][packet u16 BE][frag u8][frag_total u8][vstring addr][data]`,
//!   fragmented at the datagram MTU (every fragment repeats the full header),
//!   max payload 4096 bytes. Sessions are client-allocated `u32` ids.
//! - **Salamander obfuscation** (`salamander.go`): when `hy2_obfs` is set,
//!   every UDP datagram on the wire gets an 8-byte random salt prefix and the
//!   payload XORed with `BLAKE2b-256(password ++ salt)` repeated. Implemented
//!   as a custom quinn `AsyncUdpSocket` (`Hy2UdpSocket`).
//! - **Congestion control**: without bandwidth hints the connection runs BBR
//!   and sends `Hysteria-CC-RX: 0`. `hy2_up_mbps` selects the fixed-rate
//!   Brutal sender. `hy2_down_mbps` is serialized as bytes/s in
//!   `Hysteria-CC-RX` so the server can pace its sender.
//!
//! ## HTTP/3 layer
//!
//! The workspace has no HTTP/3 crate, so this module implements the minimal
//! subset needed for the auth exchange: a client preface (control stream with
//! SETTINGS, empty QPACK encoder/decoder streams), HEADERS frames, and a
//! QPACK field-section codec (static table only, with HPACK Huffman decoding
//! since quic-go's server encoder Huffman-codes all literal strings). Request
//! headers are emitted without Huffman (valid QPACK; quic-go's decoder
//! accepts both forms).

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use honk_config::node::Node;
use quinn::{AsyncUdpSocket, Endpoint, UdpPoller};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::debug;

use crate::quic::defrag::Defragmenter;
use crate::quic::{QuicClient, QuicConnState, now_secs};

use super::{
    PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, QuicSendToken, TcpOutbound,
    WarmableOutbound,
};

/// QUIC keep-alive (`hysteria/protocol.go:21`).
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Close the shared QUIC connection after this long without open streams.
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

mod h3;
mod salamander;
#[cfg(test)]
mod tests;
mod wire;

use h3::*;
use salamander::*;
use wire::{
    AUTH_PADDING_MAX, AUTH_PADDING_MIN, HEADER_AUTH, HEADER_CC_RX, HEADER_PADDING, HEADER_UDP,
    MAX_ADDRESS_LENGTH, MAX_MESSAGE_LENGTH, MAX_PADDING_LENGTH, MAX_UDP_SIZE, STATUS_AUTH_OK,
    URL_HOST, URL_PATH, UdpInbound, decode_udp_message, encode_tcp_request, fragment_udp_message,
    random_padding,
};

/// Auth request: HEADERS frame for `POST https://hysteria/auth`
/// (`client.go:540-549`, `protocol/http.go:41-45`). The receive limit is
/// bytes/s; 0 asks the server to use its configured congestion controller.
fn auth_request_frame(password: &str, rx_bytes_per_second: u64) -> Vec<u8> {
    let padding = random_padding(AUTH_PADDING_MIN, AUTH_PADDING_MAX);
    let section = qpack_encode_request_fields(&[
        (":authority", URL_HOST),
        (":method", "POST"),
        (":path", URL_PATH),
        (":scheme", "https"),
        (HEADER_AUTH, password),
        (HEADER_CC_RX, &rx_bytes_per_second.to_string()),
        (HEADER_PADDING, padding.as_str()),
        ("content-length", "0"),
    ]);
    h3_headers_frame(&section)
}

type SessionMap = Arc<parking_lot::Mutex<HashMap<u32, mpsc::Sender<UdpInbound>>>>;

/// Per-session inbound queue depth. UDP semantics: a full queue drops the
/// datagram rather than queueing without bound.
const UDP_SESSION_QUEUE_CAP: usize = 256;

/// Per-QUIC-connection protocol state (demux maps, counters, reaper task).
struct Hy2ConnState {
    conn: quinn::Connection,
    udp_disabled: bool,
    sessions: SessionMap,
    next_session: AtomicU32,
    /// Number of open TCP streams + UDP bridges on this connection.
    open: Arc<AtomicUsize>,
    /// Last activity (unix seconds) for the idle-connection reaper.
    last_activity: Arc<AtomicU64>,
    path_health: Arc<crate::quic::QuicPathHealth>,
    metrics: OnceLock<crate::quic::QuicConnectionMonitor>,
    /// H3 client preface streams (control + QPACK encoder/decoder). Held
    /// open for the life of the connection: dropping the send half finishes
    /// the stream, and closing a critical H3 stream is a connection error.
    _preface: (quinn::SendStream, quinn::SendStream, quinn::SendStream),
}

impl QuicConnState for Hy2ConnState {
    fn touch(&self) {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
    }

    fn open_counter(&self) -> &Arc<AtomicUsize> {
        &self.open
    }
    fn install_metrics_monitor(&self, conn: quinn::Connection) {
        self.path_health.enable_telemetry();
        self.metrics
            .get_or_init(|| crate::quic::monitor_quic_connection(&conn));
    }
}

impl Hy2ConnState {
    fn new(
        conn: quinn::Connection,
        udp_disabled: bool,
        preface: (quinn::SendStream, quinn::SendStream, quinn::SendStream),
    ) -> Self {
        let path_health = crate::quic::QuicPathHealth::new(&conn);
        let sessions: SessionMap = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let state = Self {
            conn: conn.clone(),
            udp_disabled,
            sessions: Arc::clone(&sessions),
            next_session: AtomicU32::new(0),
            open: Arc::new(AtomicUsize::new(0)),
            last_activity: Arc::new(AtomicU64::new(now_secs())),
            path_health: Arc::clone(&path_health),
            metrics: OnceLock::new(),
            _preface: preface,
        };
        if !udp_disabled {
            // Inbound QUIC datagrams demultiplexed by session id
            // (`client_packet.go:5-19`).
            let recv_conn = conn.clone();
            let recv_sessions = Arc::clone(&sessions);
            let recv_health = Arc::clone(&path_health);
            tokio::spawn(async move {
                loop {
                    let Ok(data) = recv_conn.read_datagram().await else {
                        break;
                    };
                    let Some(msg) = decode_udp_message(&data) else {
                        continue;
                    };
                    let tx = recv_sessions.lock().get(&msg.session_id).cloned();
                    if let Some(tx) = tx {
                        if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                            tx.try_send(msg)
                        {
                            recv_health.record_session_rx_drop();
                        }
                    } else {
                        debug!(
                            session_id = msg.session_id,
                            "Hysteria2 UDP: datagram for unknown session dropped"
                        );
                    }
                }
                // Connection died: drop all session senders so bridges end.
                recv_sessions.lock().clear();
            });
        }
        if !udp_disabled {
            crate::quic::spawn_quic_path_watchdog(conn, path_health);
        }
        crate::quic::spawn_conn_reaper(
            state.conn.clone(),
            Arc::downgrade(&state.open),
            Arc::downgrade(&state.last_activity),
            KEEP_ALIVE_INTERVAL,
            CONN_IDLE_TIMEOUT,
            None,
        );
        state
    }

    fn alloc_session(&self) -> u32 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }
}

const MAX_TCP_RESPONSE_BUFFER: usize =
    1 + 8 + MAX_MESSAGE_LENGTH as usize + 8 + MAX_PADDING_LENGTH as usize;

#[derive(Debug)]
struct Hy2TcpStream {
    inner: crate::quic::QuicBiStream,
    request: Option<Bytes>,
    response: Vec<u8>,
    body_offset: Option<usize>,
}

impl Hy2TcpStream {
    fn new(inner: crate::quic::QuicBiStream, addr: &str) -> Self {
        Self {
            inner,
            request: Some(encode_tcp_request(addr).into()),
            response: Vec::new(),
            body_offset: None,
        }
    }

    fn parse_response(&self) -> io::Result<Option<usize>> {
        let input = self.response.as_slice();
        let Some(&status) = input.first() else {
            return Ok(None);
        };
        let mut offset = 1;
        let Some(message_len) = parse_varint(input, &mut offset) else {
            return Ok(None);
        };
        if message_len > MAX_MESSAGE_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Hysteria2: invalid TCP response message length",
            ));
        }
        let message_end = offset + message_len as usize;
        let Some(message) = input.get(offset..message_end) else {
            return Ok(None);
        };
        offset = message_end;
        let Some(padding_len) = parse_varint(input, &mut offset) else {
            return Ok(None);
        };
        if padding_len > MAX_PADDING_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Hysteria2: invalid TCP response padding length",
            ));
        }
        let header_end = offset + padding_len as usize;
        if input.get(offset..header_end).is_none() {
            return Ok(None);
        }
        if status != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "Hysteria2: remote error: {}",
                    String::from_utf8_lossy(message)
                ),
            ));
        }
        Ok(Some(header_end))
    }
}

fn parse_varint(input: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *input.get(*offset)?;
    let len = 1usize << (first >> 6);
    let bytes = input.get(*offset..*offset + len)?;
    *offset += len;
    Some(
        bytes[1..]
            .iter()
            .fold(u64::from(first & 0x3f), |value, byte| {
                (value << 8) | u64::from(*byte)
            }),
    )
}

impl AsyncRead for Hy2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.request.is_some() {
            std::task::ready!(self.as_mut().poll_flush(cx))?;
        }
        loop {
            if let Some(offset) = self.body_offset {
                if offset < self.response.len() {
                    let count = output.remaining().min(self.response.len() - offset);
                    output.put_slice(&self.response[offset..offset + count]);
                    self.body_offset = Some(offset + count);
                    return Poll::Ready(Ok(()));
                }
                self.response.clear();
                return AsyncRead::poll_read(Pin::new(&mut self.inner), cx, output);
            }
            if let Some(header_end) = self.parse_response()? {
                self.body_offset = Some(header_end);
                continue;
            }
            if self.response.len() == MAX_TCP_RESPONSE_BUFFER {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Hysteria2 TCP response header too large",
                )));
            }
            let mut chunk = [0; 1024];
            let mut input = ReadBuf::new(&mut chunk);
            match AsyncRead::poll_read(Pin::new(&mut self.inner), cx, &mut input) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if input.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Hysteria2 TCP response truncated",
                    )));
                }
                Poll::Ready(Ok(())) => self.response.extend_from_slice(input.filled()),
            }
        }
    }
}

impl AsyncWrite for Hy2TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(request) = self.request.take() {
            let request_len = request.len();
            let mut chunks = [request, Bytes::copy_from_slice(input)];
            match self.inner.poll_write_chunks(cx, &mut chunks) {
                Poll::Pending => {
                    self.request = Some(chunks[0].clone());
                    Poll::Pending
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(written)) if written <= request_len => {
                    if !chunks[0].is_empty() {
                        self.request = Some(chunks[0].clone());
                    }
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Ok(written)) => Poll::Ready(Ok(written - request_len)),
            }
        } else {
            AsyncWrite::poll_write(Pin::new(&mut self.inner), cx, input)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(request) = self.request.take() {
            let mut chunks = [request];
            match self.inner.poll_write_chunks(cx, &mut chunks) {
                Poll::Pending => {
                    self.request = Some(chunks[0].clone());
                    return Poll::Pending;
                }
                Poll::Ready(Ok(_)) if !chunks[0].is_empty() => {
                    self.request = Some(chunks[0].clone());
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        AsyncWrite::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        AsyncWrite::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}

struct Hy2Client {
    quic: QuicClient<Hy2ConnState>,
    password: String,
    /// Receive bandwidth advertised in the auth exchange, bytes/s (0 = unset).
    rx_bytes_per_second: u64,
}

#[async_trait]
impl crate::runtime::QuicRuntimeClient for Hy2Client {
    fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }

    async fn enable_metrics(&self) {
        self.quic.enable_metrics().await;
    }

    async fn force_close(&self) {
        self.quic.force_close().await;
    }

    async fn release_warm(&self) {
        self.quic.release_cached().await;
    }
}

impl Hy2Client {
    async fn connection(
        &self,
        connect_timeout: Duration,
    ) -> anyhow::Result<(quinn::Connection, Arc<Hy2ConnState>)> {
        let password = self.password.clone();
        let rx_bytes_per_second = self.rx_bytes_per_second;
        self.quic
            .connection_with_metrics(connect_timeout, move |conn| async move {
                authenticate(&conn, &password, rx_bytes_per_second, connect_timeout).await
            })
            .await
    }
}

/// Hysteria2 connection setup: send the H3 client preface, then authenticate
/// with the `POST https://hysteria/auth` exchange (`client.go:533-605`).
/// Runs inside the single-flight critical section of `QuicClient`.
async fn authenticate(
    conn: &quinn::Connection,
    password: &str,
    rx_bytes_per_second: u64,
    timeout: Duration,
) -> anyhow::Result<Hy2ConnState> {
    tokio::time::timeout(timeout, async {
        // Client preface: control stream + SETTINGS, QPACK encoder/decoder
        // streams (type byte only — no dynamic table instructions).
        let mut control = conn
            .open_uni()
            .await
            .context("Hysteria2: open control stream")?;
        control
            .write_all(&client_preface())
            .await
            .context("Hysteria2: send SETTINGS")?;
        let mut qpack_enc = conn
            .open_uni()
            .await
            .context("Hysteria2: open QPACK encoder stream")?;
        qpack_enc
            .write_all(&[H3_STREAM_QPACK_ENCODER as u8])
            .await
            .context("Hysteria2: QPACK encoder stream preface")?;
        let mut qpack_dec = conn
            .open_uni()
            .await
            .context("Hysteria2: open QPACK decoder stream")?;
        qpack_dec
            .write_all(&[H3_STREAM_QPACK_DECODER as u8])
            .await
            .context("Hysteria2: QPACK decoder stream preface")?;

        // Auth request on a bi stream; the response HEADERS carry the result.
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("Hysteria2: open auth stream")?;
        send.write_all(&auth_request_frame(password, rx_bytes_per_second))
            .await
            .context("Hysteria2: send auth request")?;
        send.finish().context("Hysteria2: finish auth request")?;
        let headers = read_h3_response_headers(&mut recv)
            .await
            .context("Hysteria2: read auth response")?;
        let header = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        let status: u16 = header(":status").and_then(|v| v.parse().ok()).unwrap_or(0);
        if status != STATUS_AUTH_OK {
            anyhow::bail!("Hysteria2: authentication failed, status code: {status}");
        }
        let udp_enabled = header(HEADER_UDP) == Some("true");
        // Dropping the receive half issues STOP_SENDING for the unread
        // response body — what quic-go's http3 client does on
        // `response.Body.Close()` after a successful auth.
        Ok(Hy2ConnState::new(
            conn.clone(),
            !udp_enabled,
            (control, qpack_enc, qpack_dec),
        ))
    })
    .await
    .map_err(|_| anyhow!("Hysteria2: authentication timed out"))?
}

/// `host:port` address string for the wire (domain preferred; IPv6 gets
/// brackets via `SocketAddr`'s `Display`).
fn target_string(target: SocketAddr, target_domain: Option<&str>) -> String {
    match target_domain {
        Some(domain) => format!("{domain}:{}", target.port()),
        None => target.to_string(),
    }
}

/// Hysteria2 proxy handler (QUIC). Stateless: the per-server client (and
/// its shared QUIC connection) lives in the node's generation runtime.
#[derive(Debug, Default, Clone)]
pub struct Hysteria2Handler;

impl Hysteria2Handler {
    pub fn new() -> Self {
        Self
    }

    fn resolve_password(node: &Node) -> &str {
        node.hysteria2().unwrap().auth.as_deref().unwrap_or("")
    }

    async fn build_client(&self, node: &Node) -> anyhow::Result<Arc<Hy2Client>> {
        let hy2 = node.hysteria2().unwrap();
        let password = Self::resolve_password(node);
        let obfs = hy2.obfs.as_deref().filter(|s| !s.is_empty());
        if let Some(obfs) = obfs
            && obfs.len() < SALAMANDER_MIN_PSK_LEN
        {
            anyhow::bail!(
                "Hysteria2: Salamander password must be at least {SALAMANDER_MIN_PSK_LEN} bytes"
            );
        }
        // Hysteria-CC-RX is bytes/s; configuration uses decimal Mbit/s.
        let rx_bytes_per_second = u64::from(hy2.down_mbps.unwrap_or(0)) * 125_000;
        // Port hopping (`mport`/`mhop`): destination port rotates among the
        // list every interval (default 30s, official client parity).
        let hop = hy2
            .port_hopping
            .as_deref()
            .map(|spec| {
                let ports = parse_port_hopping(spec)
                    .ok_or_else(|| anyhow!("Hysteria2: invalid port hopping list"))?;
                Ok::<_, anyhow::Error>((
                    ports,
                    Duration::from_secs(hy2.hop_interval.unwrap_or(30).max(5)),
                ))
            })
            .transpose()?;
        let server_name = hy2
            .quic
            .tls
            .sni
            .clone()
            .unwrap_or_else(|| node.host().to_string());
        // A positive upload hint selects the fixed-rate sender; no hint uses BBR.
        let factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> = match hy2.up_mbps
        {
            Some(mbps) if mbps > 0 => Arc::new(crate::quic::BrutalConfig::from_bps(
                u64::from(mbps) * 1_000_000,
            )),
            _ => crate::quic::congestion_factory(Some("bbr")),
        };
        let config = crate::quic::client_config(
            node,
            &[b"h3"],
            crate::quic::QuicClientOptions {
                congestion: Some(factory),
                keep_alive: Some(KEEP_ALIVE_INTERVAL),
                // Download throughput is capped by our advertised receive
                // windows (window/RTT): quinn's 1.25 MiB stream default
                // tops out around 2 Gbps on a LAN. Stream window keeps the
                // single-flow ceiling high; the conn window doubles as the
                // per-connection memory budget (slow consumers buffer up to
                // ~3x it), so it stays at 8 MiB — measured throughput-neutral
                // on a 75ms/15%-loss link.
                stream_receive_window: hy2.init_stream_recv_window.or(Some(8 << 20)),
                conn_receive_window: hy2.init_conn_recv_window.or(Some(8 << 20)),
                disable_mtu_discovery: hy2.disable_mtu_discovery == Some(true),
                max_udp_payload_size: hy2.quic.mtu,
            },
        )
        .await?;
        let quic = QuicClient::new(node.host().to_string(), node.port, server_name, config);
        let mtu = hy2.quic.mtu.unwrap_or(1252);
        let quic = quic.with_max_udp_payload_size(mtu);
        let quic = match (obfs, hop) {
            (None, None) => quic,
            (obfs, hop) => quic.with_endpoint_factory(hy2_endpoint_factory(
                obfs.map(|p| Arc::from(p.as_bytes())),
                hop,
                mtu,
            )),
        };
        Ok(Arc::new(Hy2Client {
            quic,
            password: password.to_string(),
            rx_bytes_per_second,
        }))
    }

    async fn client_for_runtime(
        &self,
        runtime: &crate::runtime::NodeRuntime,
    ) -> anyhow::Result<Arc<Hy2Client>> {
        runtime
            .quic_client(|| self.build_client(runtime.node.as_ref()))
            .await
    }
}

#[async_trait]
impl WarmableOutbound for Hysteria2Handler {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: Duration,
        requirement: super::WarmRequirement,
    ) -> anyhow::Result<()> {
        let client = self.client_for_runtime(&runtime).await?;
        let (_, state) = client.connection(connect_timeout).await?;
        if requirement == super::WarmRequirement::Udp && state.udp_disabled {
            anyhow::bail!("Hysteria2: UDP disabled by server");
        }
        Ok(())
    }
}

impl Hysteria2Handler {
    async fn dial_via_client(
        &self,
        client: Arc<Hy2Client>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = target_string(target, target_domain);
        if addr.len() as u64 > MAX_ADDRESS_LENGTH {
            anyhow::bail!("Hysteria2: target address too long");
        }
        let stream = crate::quic::dial_quic_stream(
            &client.quic,
            |timeout| {
                let client = Arc::clone(&client);
                async move { client.connection(timeout).await }
            },
            connect_timeout,
            move |conn| async move {
                conn.open_bi()
                    .await
                    .map_err(|error| anyhow!("Hysteria2: open stream: {error}"))
            },
            |_| true,
            "Hysteria2",
        )
        .await?;
        let stream = Hy2TcpStream::new(stream, &addr);
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }

    async fn udp_transport_via_client(
        &self,
        client: Arc<Hy2Client>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let (conn, state) = client.connection(connect_timeout).await?;
        if state.udp_disabled {
            anyhow::bail!("Hysteria2: UDP disabled by server");
        }
        let max_datagram = conn
            .max_datagram_size()
            .ok_or_else(|| anyhow!("Hysteria2: peer does not support QUIC datagrams"))?;
        state.touch();
        let session_id = state.alloc_session();
        let addr = target_string(target, target_domain);
        if addr.len() as u64 > MAX_ADDRESS_LENGTH {
            anyhow::bail!("Hysteria2: target address too long");
        }
        let (tx, rx) = mpsc::channel::<UdpInbound>(UDP_SESSION_QUEUE_CAP);
        state.sessions.lock().insert(session_id, tx);
        state.open.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(Hy2UdpTransport {
            state,
            session_id,
            packet_id: AtomicU16::new(0),
            rx: tokio::sync::Mutex::new(rx),
            defrag: tokio::sync::Mutex::new(Defragmenter::new(MAX_UDP_SIZE)),
            addr,
            max_datagram,
            target,
        }))
    }
}

#[async_trait]
impl TcpOutbound for Hysteria2Handler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let client = self.build_client(node).await?;
        self.dial_via_client(client, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let client = self.client_for_runtime(&runtime).await?;
        self.dial_via_client(client, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_with_tcp(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _tcp: tokio::net::TcpStream,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!("Hysteria2 runs over QUIC; a bare TCP connection cannot be reused")
    }
}

#[async_trait]
impl PacketOutbound for Hysteria2Handler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let client = self.build_client(node).await?;
        self.udp_transport_via_client(client, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let client = self.client_for_runtime(&runtime).await?;
        self.udp_transport_via_client(client, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<super::PreparedUdpTransport> {
        let client = self.build_client(runtime.node.as_ref()).await?;
        super::prepare_detached_quic_transport(runtime, client, |client| async move {
            self.udp_transport_via_client(client, target, target_domain, connect_timeout)
                .await
        })
        .await
    }
}

#[async_trait]
impl ProbeableOutbound for Hysteria2Handler {
    async fn test_connectivity(&self, node: &Node) -> bool {
        match self.build_client(node).await {
            Ok(client) => client.connection(Duration::from_secs(5)).await.is_ok(),
            Err(e) => {
                debug!(
                    "Hysteria2 connectivity test failed for {}: {}",
                    node.name, e
                );
                false
            }
        }
    }
}

/// Framed UDP transport over the shared Hysteria2 QUIC connection: UDP
/// message datagrams go straight onto the connection and inbound datagrams
/// arrive through the session demux queue.
struct Hy2UdpTransport {
    state: Arc<Hy2ConnState>,
    session_id: u32,
    packet_id: AtomicU16,
    rx: tokio::sync::Mutex<mpsc::Receiver<UdpInbound>>,
    defrag: tokio::sync::Mutex<Defragmenter>,
    addr: String,
    max_datagram: usize,
    target: SocketAddr,
}

impl std::fmt::Debug for Hy2UdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hy2UdpTransport")
            .field("session_id", &self.session_id)
            .field("target", &self.target)
            .finish()
    }
}

impl Drop for Hy2UdpTransport {
    fn drop(&mut self) {
        self.state.sessions.lock().remove(&self.session_id);
        self.state.open.fetch_sub(1, Ordering::Relaxed);
    }
}

#[async_trait]
impl PacketTransport for Hy2UdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }
    fn send_timeout(&self) -> Duration {
        self.state.path_health.send_timeout()
    }
    fn record_quic_send_started(&self) -> QuicSendToken {
        self.state.path_health.record_send_started(&self.state.conn)
    }
    fn record_quic_send_success(&self, token: QuicSendToken) {
        self.state
            .path_health
            .record_send_success(token, &self.state.conn);
    }
    fn record_quic_send_timeout(&self, token: QuicSendToken) {
        if self
            .state
            .path_health
            .record_send_timeout(token, &self.state.conn)
        {
            crate::quic::record_quic_send_timeout();
        }
    }
    fn record_quic_send_failure(&self, token: QuicSendToken) {
        self.state.path_health.record_send_failure(token);
    }

    fn quic_path_stalled(&self) -> bool {
        self.state.path_health.is_stalled()
    }
    fn send_timeout_is_congestion(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_UDP_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2 datagram too large",
            ));
        }
        self.state.touch();
        let packet_id = self
            .packet_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let packets = fragment_udp_message(
            self.session_id,
            packet_id,
            &self.addr,
            data,
            self.max_datagram,
        )
        .map_err(io::Error::other)?;
        for packet in packets {
            self.state
                .conn
                .send_datagram_wait(bytes::Bytes::from(packet))
                .await
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let msg = self.rx.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "hysteria2 connection closed",
                )
            })?;
            let complete =
                self.defrag
                    .lock()
                    .await
                    .feed(msg.packet_id, msg.frag_id, msg.frag_total, msg.data);
            if let Some(data) = complete {
                if data.len() > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "hysteria2 packet exceeds buffer",
                    ));
                }
                buf[..data.len()].copy_from_slice(&data);
                return Ok((data.len(), self.target));
            }
        }
    }
}
