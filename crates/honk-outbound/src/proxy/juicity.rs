//! Juicity proxy handler (QUIC), implemented against the daeuniverse

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use honk_config::node::Node;
use tracing::debug;

use crate::quic::{QuicClient, QuicConnState, now_secs, recv_read_exact as read_exact};

use super::addr::SocksAddr as JuiceAddr;
use super::{
    PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound, WarmableOutbound,
};

const JUICITY_VERSION: u8 = 0x00;

const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x03;

/// daeuniverse juicity client keep-alive (`dialer.go:58`).
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
/// Close the shared QUIC connection after this long without any open stream.
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Grace period after sending AUTHENTICATE for the server to reject bad
/// credentials by closing the connection. Zero (tuic parity): bad
/// credentials fail the first stream open an RTT later instead.
const AUTH_GRACE: Duration = Duration::ZERO;

/// Read one inbound UDP frame (`[metadata][len u16][payload]`) into the
/// caller's buffer. Oversized payloads are consumed before returning the
/// same buffer-size error as the previous allocating path.
async fn read_udp_frame(
    recv: &mut quinn::RecvStream,
    payload: &mut [u8],
) -> io::Result<(JuiceAddr, usize)> {
    let addr = JuiceAddr::read_from_stream(recv).await?;
    let mut len = [0u8; 2];
    read_exact(recv, &mut len).await?;
    let payload_len = u16::from_be_bytes(len) as usize;
    if payload_len > payload.len() {
        let mut discard = [0u8; 512];
        let mut remaining = payload_len;
        while remaining != 0 {
            let chunk = remaining.min(discard.len());
            read_exact(recv, &mut discard[..chunk]).await?;
            remaining -= chunk;
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "juicity datagram exceeds buffer",
        ));
    }
    read_exact(recv, &mut payload[..payload_len]).await?;
    Ok((addr, payload_len))
}

/// Per-QUIC-connection protocol state.
struct JuicityConnState {
    /// Owns the underlying connection for this protocol state’s lifetime.
    _conn: quinn::Connection,
    /// Kept open for the connection lifetime — dropping it would send FIN on
    /// the authenticate stream (see module docs).
    _auth_stream: quinn::SendStream,
    /// Number of open TCP streams + UDP bridges on this connection.
    open: Arc<AtomicUsize>,
    /// Last activity (unix seconds) for the idle-connection reaper.
    last_activity: Arc<AtomicU64>,
    path_health: Arc<crate::quic::QuicPathHealth>,
    metrics: OnceLock<crate::quic::QuicConnectionMonitor>,
}

impl QuicConnState for JuicityConnState {
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

impl JuicityConnState {
    fn new(conn: quinn::Connection, auth_stream: quinn::SendStream) -> Self {
        let path_health = crate::quic::QuicPathHealth::new(&conn);
        let state = Self {
            _conn: conn.clone(),
            _auth_stream: auth_stream,
            open: Arc::new(AtomicUsize::new(0)),
            last_activity: Arc::new(AtomicU64::new(now_secs())),
            path_health: Arc::clone(&path_health),
            metrics: OnceLock::new(),
        };
        crate::quic::spawn_quic_path_watchdog(conn.clone(), path_health);
        crate::quic::spawn_conn_reaper(
            conn,
            Arc::downgrade(&state.open),
            Arc::downgrade(&state.last_activity),
            KEEP_ALIVE_INTERVAL,
            CONN_IDLE_TIMEOUT,
            None,
        );
        state
    }
}

struct JuicityClient {
    quic: QuicClient<JuicityConnState>,
    uuid: [u8; 16],
    password: String,
}

#[async_trait]
impl crate::runtime::QuicRuntimeClient for JuicityClient {
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

impl JuicityClient {
    async fn connection(
        &self,
        connect_timeout: Duration,
    ) -> anyhow::Result<(quinn::Connection, Arc<JuicityConnState>)> {
        let uuid = self.uuid;
        let password = self.password.clone();
        self.quic
            .connection_with_metrics(connect_timeout, move |conn| async move {
                let auth_stream = crate::quic::exporter_auth(
                    &conn,
                    &uuid,
                    &password,
                    JUICITY_VERSION,
                    false,
                    AUTH_GRACE,
                )
                .await?;
                Ok(JuicityConnState::new(conn, auth_stream))
            })
            .await
    }
}

/// Juicity proxy handler. Stateless: the per-server client (and its shared
/// QUIC connection) lives in the node's generation runtime.
#[derive(Debug, Default, Clone)]
pub struct JuicityHandler;

impl JuicityHandler {
    pub fn new() -> Self {
        Self
    }

    async fn build_client(&self, node: &Node) -> anyhow::Result<Arc<JuicityClient>> {
        let juicity = node.juicity().unwrap();
        let uuid_str = juicity
            .uuid
            .as_deref()
            .ok_or_else(|| anyhow!("Juicity node '{}': missing juicity_uuid", node.name))?;
        let uuid = uuid::Uuid::parse_str(uuid_str)
            .with_context(|| format!("Juicity node '{}': invalid uuid", node.name))?;
        let password = juicity.password.as_deref().unwrap_or("").to_string();
        let server_name = juicity
            .quic
            .tls
            .sni
            .clone()
            .unwrap_or_else(|| node.host().to_string());
        // Upstream juicity (Go and juicity-rs) defaults to BBR on the client
        // when no congestion_control is configured.
        let config = crate::quic::client_config(
            node,
            &[b"h3"],
            crate::quic::QuicClientOptions {
                keep_alive: Some(KEEP_ALIVE_INTERVAL),
                max_udp_payload_size: juicity.quic.mtu,
                // Same receive-window rationale as hy2/tuic: quinn's
                // 1.25 MiB stream default caps downloads around 2 Gbps
                // on a LAN. Conn window doubles as the per-connection
                // memory budget (see hy2).
                stream_receive_window: Some(8 << 20),
                conn_receive_window: Some(8 << 20),
                ..crate::quic::QuicClientOptions::with_congestion(Some("bbr"))
            },
        )
        .await?;
        Ok(Arc::new(JuicityClient {
            quic: QuicClient::new(node.host().to_string(), node.port, server_name, config)
                .with_max_udp_payload_size(juicity.quic.mtu.unwrap_or(1252)),
            uuid: *uuid.as_bytes(),
            password,
        }))
    }

    /// Open a bi stream and write the juicity request header
    /// (`[network][metadata]`, `stream_conn.go:29-36`).
    async fn open_stream(
        conn: &quinn::Connection,
        network: u8,
        addr: &JuiceAddr,
    ) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, recv) = conn.open_bi().await.context("Juicity: open stream")?;
        let mut header = Vec::with_capacity(1 + addr.encoded_len());
        header.push(network);
        addr.encode(&mut header);
        send.write_all(&header)
            .await
            .context("Juicity: send request header")?;
        Ok((send, recv))
    }
    async fn client_for_runtime(
        &self,
        runtime: &crate::runtime::NodeRuntime,
    ) -> anyhow::Result<Arc<JuicityClient>> {
        runtime
            .quic_client(|| self.build_client(runtime.node.as_ref()))
            .await
    }

    async fn dial_via_client(
        &self,
        client: Arc<JuicityClient>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = JuiceAddr::new(target, target_domain);
        let stream = crate::quic::dial_quic_stream(
            &client.quic,
            |timeout| {
                let client = Arc::clone(&client);
                async move { client.connection(timeout).await }
            },
            connect_timeout,
            move |conn| {
                let addr = addr.clone();
                async move { Self::open_stream(&conn, NETWORK_TCP, &addr).await }
            },
            |_| true,
            "Juicity",
        )
        .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }

    async fn udp_transport_via_client(
        &self,
        client: Arc<JuicityClient>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let stream_addr = JuiceAddr::new(target, target_domain);
        let mut last_error = None;
        for _ in 0..2 {
            let (conn, state) = client.connection(connect_timeout).await?;
            state.touch();
            match Self::open_stream(&conn, NETWORK_UDP, &stream_addr).await {
                Ok((send, recv)) => {
                    state.open.fetch_add(1, Ordering::Relaxed);
                    let open = Arc::clone(&state.open);
                    let stream_state = Arc::clone(&state);
                    let stream =
                        crate::quic::QuicBiStream::new(send, recv).with_on_drop(move || {
                            open.fetch_sub(1, Ordering::Relaxed);
                            let _state_kept_alive_under_this_stream = &stream_state;
                        });
                    let (send, recv, guard) = stream.into_parts();
                    return Ok(Arc::new(JuicityUdpTransport {
                        state,
                        send: tokio::sync::Mutex::new(send),
                        recv: tokio::sync::Mutex::new(recv),
                        _guard: guard,
                        target_addr: stream_addr,
                        target,
                    }));
                }
                Err(error) => {
                    client.quic.invalidate(&conn).await;
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.expect("Juicity UDP stream attempts are non-empty"))
    }
}

#[async_trait]
impl WarmableOutbound for JuicityHandler {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: Duration,
        _requirement: super::WarmRequirement,
    ) -> anyhow::Result<()> {
        let client = self.client_for_runtime(&runtime).await?;
        client.connection(connect_timeout).await?;
        Ok(())
    }
}

#[async_trait]
impl TcpOutbound for JuicityHandler {
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
        anyhow::bail!("Juicity runs over QUIC; a bare TCP connection cannot be reused")
    }
}

#[async_trait]
impl PacketOutbound for JuicityHandler {
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
impl ProbeableOutbound for JuicityHandler {
    async fn test_connectivity(&self, node: &Node) -> bool {
        match self.build_client(node).await {
            Ok(client) => match client.connection(Duration::from_secs(5)).await {
                Ok((conn, _)) => crate::quic::survives_auth_close_window(&conn).await,
                Err(_) => false,
            },
            Err(e) => {
                debug!("Juicity connectivity test failed for {}: {}", node.name, e);
                false
            }
        }
    }
}

/// Framed UDP transport over a Juicity UDP bi stream: datagrams are framed
/// as `[metadata][len u16][payload]` directly on the QUIC stream.
struct JuicityUdpTransport {
    state: Arc<JuicityConnState>,
    send: tokio::sync::Mutex<quinn::SendStream>,
    recv: tokio::sync::Mutex<quinn::RecvStream>,
    /// Keeps the connection's open-stream accounting alive for the
    /// transport's lifetime (see `QuicBiStream::into_parts`).
    _guard: crate::quic::StreamDropGuard,
    target_addr: JuiceAddr,
    target: SocketAddr,
}

impl std::fmt::Debug for JuicityUdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JuicityUdpTransport")
            .field("target", &self.target)
            .finish()
    }
}

#[async_trait]
impl PacketTransport for JuicityUdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }
    fn send_timeout(&self) -> Duration {
        self.state.path_health.send_timeout()
    }

    fn record_quic_send_started(&self) -> super::QuicSendToken {
        self.state
            .path_health
            .record_send_started(&self.state._conn)
    }

    fn record_quic_send_success(&self, token: super::QuicSendToken) {
        self.state
            .path_health
            .record_send_success(token, &self.state._conn);
    }

    fn record_quic_send_timeout(&self, token: super::QuicSendToken) {
        if self
            .state
            .path_health
            .record_send_timeout(token, &self.state._conn)
        {
            crate::quic::record_quic_send_timeout();
        }
    }

    fn record_quic_send_failure(&self, token: super::QuicSendToken) {
        self.state.path_health.record_send_failure(token);
    }

    fn quic_path_stalled(&self) -> bool {
        self.state.path_health.is_stalled()
    }

    fn send_timeout_is_congestion(&self) -> bool {
        // write_chunk is not cancellation-safe; a timed-out write can leave a
        // partial frame on this long-lived stream, so retire the endpoint.
        false
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "juicity datagram too large",
            ));
        }
        self.state.touch();
        // SealUDP: `[metadata][len u16][payload]`
        // (`stream_packet_conn.go:83-90`).
        let mut frame = Vec::with_capacity(self.target_addr.encoded_len() + 2 + data.len());
        self.target_addr.encode(&mut frame);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        self.send
            .lock()
            .await
            .write_chunk(Bytes::from(frame))
            .await
            .map_err(io::Error::other)
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (_addr, payload_len) = read_udp_frame(&mut *self.recv.lock().await, buf).await?;
        Ok((payload_len, self.target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::testutil;
    use quinn::VarInt;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// AUTHENTICATE command byte (the shared `exporter_auth` writes it
    /// inline; only the test server decodes it).
    const CMD_AUTHENTICATE: u8 = 0x00;

    const TEST_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const TEST_PASSWORD: &str = "juicity-test-password";

    fn test_node(port: u16, password: &str) -> Node {
        Node {
            name: "juicity-test".to_string(),
            host: "127.0.0.1".to_string(),
            address: format!("127.0.0.1:{port}"),
            port,
            outbound: honk_config::node::OutboundConfig::Juicity(
                honk_config::node::JuicityConfig {
                    uuid: Some(TEST_UUID.to_string()),
                    password: Some(password.to_string()),
                    quic: honk_config::node::QuicOptions {
                        tls: honk_config::node::TlsOptions {
                            skip_cert_verify: true,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                },
            ),
            ..Default::default()
        }
    }

    /// Minimal in-process Juicity server: verifies the AUTHENTICATE token
    /// with the same TLS exporter, echoes TCP streams back, and echoes UDP
    /// stream frames (`[metadata][len][payload]`) back verbatim.
    async fn start_server(password: &'static str) -> SocketAddr {
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    handle_connection(conn, password).await;
                });
            }
        });
        addr
    }

    async fn handle_connection(conn: quinn::Connection, password: &'static str) {
        // Uni stream: authenticate (stays open; only the first 50 bytes are
        // the auth frame).
        let uni_conn = conn.clone();
        tokio::spawn(async move {
            loop {
                let Ok(mut recv) = uni_conn.accept_uni().await else {
                    break;
                };
                let conn = uni_conn.clone();
                tokio::spawn(async move {
                    let mut head = [0u8; 2];
                    if read_exact(&mut recv, &mut head).await.is_err() {
                        return;
                    }
                    if head != [JUICITY_VERSION, CMD_AUTHENTICATE] {
                        return;
                    }
                    let mut rest = [0u8; 48];
                    if read_exact(&mut recv, &mut rest).await.is_err() {
                        return;
                    }
                    let uuid: &[u8; 16] = rest[..16].try_into().unwrap();
                    let mut token = [0u8; 32];
                    if conn
                        .export_keying_material(&mut token, uuid, password.as_bytes())
                        .is_err()
                    {
                        return;
                    }
                    if token != rest[16..] {
                        conn.close(VarInt::from_u32(0xfffffff1), b"authentication failed");
                    }
                });
            }
        });
        // Bi streams: TCP echo / UDP frame echo.
        loop {
            let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                break;
            };
            tokio::spawn(async move {
                let mut network = [0u8; 1];
                if read_exact(&mut recv, &mut network).await.is_err() {
                    return;
                }
                match network[0] {
                    NETWORK_TCP => {
                        if JuiceAddr::read_from_stream(&mut recv).await.is_err() {
                            return;
                        }
                        let mut buf = [0u8; 8192];
                        loop {
                            match recv.read(&mut buf).await {
                                Ok(Some(n)) => {
                                    if send.write_all(&buf[..n]).await.is_err() {
                                        return;
                                    }
                                }
                                _ => return,
                            }
                        }
                    }
                    NETWORK_UDP => {
                        if JuiceAddr::read_from_stream(&mut recv).await.is_err() {
                            return;
                        }
                        let mut payload = vec![0u8; u16::MAX as usize];
                        loop {
                            let Ok((addr, payload_len)) =
                                read_udp_frame(&mut recv, &mut payload).await
                            else {
                                return;
                            };
                            let mut frame =
                                Vec::with_capacity(addr.encoded_len() + 2 + payload_len);
                            addr.encode(&mut frame);
                            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
                            frame.extend_from_slice(&payload[..payload_len]);
                            if send.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                    }
                    _ => {}
                }
            });
        }
    }

    #[tokio::test]
    async fn test_dial_tcp_echo() {
        let server_addr = start_server(TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = JuicityHandler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let mut stream = handler
            .dial(&node, target, None, Duration::from_secs(5))
            .await
            .expect("dial should succeed");
        stream.stream.write_all(b"hello juicity").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello juicity");
    }

    #[tokio::test]
    async fn test_wrong_password_rejected() {
        let server_addr = start_server(TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), "wrong-password");
        let handler = JuicityHandler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        // Optimistic auth (zero grace, tuic parity): the rejection surfaces
        // ~1 RTT later when the server closes the connection; the
        // connectivity probe (which waits for it) must say no.
        let _ = handler
            .dial(&node, target, None, Duration::from_secs(5))
            .await;
        assert!(!handler.test_connectivity(&node).await);
    }

    #[tokio::test]
    async fn test_udp_transport_echo() {
        let server_addr = start_server(TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = JuicityHandler::new();
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let transport = handler
            .dial_udp_transport(&node, target, None, Duration::from_secs(5))
            .await
            .expect("dial_udp_transport should succeed");
        assert_eq!(transport.relay_addr(), target);
        transport.send_packet(b"dns-query").await.unwrap();
        let mut small = [0u8; 4];
        let error = transport.recv_packet(&mut small).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let mut buf = [0u8; 256];
        transport.send_packet(b"dns-query").await.unwrap();
        let (n, src) =
            tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                .await
                .expect("reply timed out")
                .unwrap();
        assert_eq!(src, target);
        assert_eq!(&buf[..n], b"dns-query");

        // A second datagram on the same session must work too.
        transport.send_packet(b"second").await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
            .await
            .expect("reply timed out")
            .unwrap();
        assert_eq!(&buf[..n], b"second");
    }

    #[test]
    fn test_metadata_codec() {
        let mut buf = Vec::new();
        JuiceAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 80)).encode(&mut buf);
        assert_eq!(
            buf,
            vec![crate::proxy::addr::ATYP_IPV4, 93, 184, 216, 34, 0x00, 0x50]
        );

        let mut buf = Vec::new();
        JuiceAddr::Domain("example.com".to_string(), 443).encode(&mut buf);
        assert_eq!(buf[0], crate::proxy::addr::ATYP_DOMAIN);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(&buf[13..15], &[0x01, 0xbb]);

        let mut buf = Vec::new();
        JuiceAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0)).encode(&mut buf);
        assert_eq!(buf.len(), 19);
        assert_eq!(buf[0], crate::proxy::addr::ATYP_IPV6);
        assert_eq!(&buf[17..19], &[0x1f, 0x90]);
    }
}
