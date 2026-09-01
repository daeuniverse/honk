//! TUIC v5 proxy handler (QUIC)

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use honk_config::node::Node;
use tokio::sync::mpsc;
use tracing::debug;

use crate::quic::defrag::Defragmenter;
use crate::quic::{QuicClient, QuicConnState, now_secs, recv_read_exact as read_exact};

use super::addr::{self, SocksAddr};
use super::{
    PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, QuicSendToken, TcpOutbound,
    WarmableOutbound,
};

const TUIC_VERSION: u8 = 0x05;

const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
const CMD_DISSOCIATE: u8 = 0x03;
const CMD_HEARTBEAT: u8 = 0x04;

const ATYP_NONE: u8 = 0xff;

/// sing-quic default heartbeat interval (`client.go:55-57`).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// Close the shared QUIC connection after this long without any open stream.
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Grace period after sending AUTHENTICATE for the server to reject bad
/// credentials by closing the connection. Zero: a bad password fails the
/// first stream open an RTT later with the same clarity — every cold dial
/// otherwise pays a fixed 150ms (measured: 160ms cold TUIC connect vs
/// dae's 85ms).
const AUTH_GRACE: Duration = Duration::ZERO;

/// TUIC address: the shared SOCKS5-style address encoded under sing's
/// socksaddr ATYP numbering ([`addr::ATYP_SING`]), plus TUIC's own
/// ATYP_NONE (0xff) marker used on continuation fragments.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TuicAddr {
    None,
    Addr(SocksAddr),
}

impl TuicAddr {
    fn new(target: SocketAddr, target_domain: Option<&str>) -> Self {
        TuicAddr::Addr(SocksAddr::new(target, target_domain))
    }

    fn encoded_len(&self) -> usize {
        match self {
            TuicAddr::None => 1,
            TuicAddr::Addr(a) => a.encoded_len(),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            TuicAddr::None => out.push(ATYP_NONE),
            TuicAddr::Addr(a) => a.encode_with(out, addr::ATYP_SING),
        }
    }

    /// Decode from a byte slice, advancing the cursor past the address.
    fn decode(cursor: &mut &[u8]) -> io::Result<TuicAddr> {
        if cursor.first() == Some(&ATYP_NONE) {
            *cursor = &cursor[1..];
            return Ok(TuicAddr::None);
        }
        SocksAddr::decode_with(cursor, addr::ATYP_SING).map(TuicAddr::Addr)
    }

    /// Read an address from a QUIC stream (used for inbound UDP-over-stream
    /// packets).
    async fn read_from_stream(recv: &mut quinn::RecvStream) -> io::Result<TuicAddr> {
        let mut atyp = [0u8; 1];
        read_exact(recv, &mut atyp).await?;
        if atyp[0] == ATYP_NONE {
            return Ok(TuicAddr::None);
        }
        SocksAddr::read_body(atyp[0], recv, addr::ATYP_SING)
            .await
            .map(TuicAddr::Addr)
    }
}

/// An inbound UDP packet delivered to a session bridge.
#[derive(Debug)]
struct UdpInbound {
    session_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    #[cfg(test)]
    addr: TuicAddr,
    data: Vec<u8>,
}

/// Decode a PACKET frame body (everything after `[version, command]`).
fn decode_udp_message(data: &[u8]) -> io::Result<UdpInbound> {
    if data.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short UDP message",
        ));
    }
    let session_id = u16::from_be_bytes(data[0..2].try_into().expect("len checked"));
    let packet_id = u16::from_be_bytes(data[2..4].try_into().expect("len checked"));
    let frag_total = data[4];
    let frag_id = data[5];
    let size = u16::from_be_bytes(data[6..8].try_into().expect("len checked")) as usize;
    let mut cursor = &data[8..];
    let _addr = TuicAddr::decode(&mut cursor)?;
    if cursor.len() != size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "UDP message length mismatch",
        ));
    }
    Ok(UdpInbound {
        session_id,
        packet_id,
        frag_total,
        frag_id,
        #[cfg(test)]
        addr: _addr,
        data: cursor.to_vec(),
    })
}

/// Read a full PACKET frame (after `[version, command]`) from a uni stream.
async fn read_udp_message_stream(recv: &mut quinn::RecvStream) -> io::Result<UdpInbound> {
    let mut fixed = [0u8; 8];
    read_exact(recv, &mut fixed).await?;
    let session_id = u16::from_be_bytes(fixed[0..2].try_into().expect("array length"));
    let packet_id = u16::from_be_bytes(fixed[2..4].try_into().expect("array length"));
    let frag_total = fixed[4];
    let frag_id = fixed[5];
    let size = u16::from_be_bytes(fixed[6..8].try_into().expect("array length")) as usize;
    let _addr = TuicAddr::read_from_stream(recv).await?;
    let mut data = vec![0u8; size];
    read_exact(recv, &mut data).await?;
    Ok(UdpInbound {
        session_id,
        packet_id,
        frag_total,
        frag_id,
        #[cfg(test)]
        addr: _addr,
        data,
    })
}

/// Encode one PACKET frame (including the `[version, command]` head).
fn encode_udp_packet(
    session_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    addr: &TuicAddr,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + addr.encoded_len() + data.len());
    out.push(TUIC_VERSION);
    out.push(CMD_PACKET);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(frag_total);
    out.push(frag_id);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    addr.encode(&mut out);
    out.extend_from_slice(data);
    out
}

/// Build the datagram sequence for one UDP payload, fragmenting like sing's
/// `fragUDPMessage` when it exceeds the datagram MTU: the first fragment
/// carries the address, continuation fragments use ATYP 0xff.
fn fragment_udp_packets(
    session_id: u16,
    packet_id: u16,
    addr: &TuicAddr,
    data: &[u8],
    max_datagram: usize,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let first_header = 10 + addr.encoded_len();
    if first_header + data.len() <= max_datagram {
        return Ok(vec![encode_udp_packet(
            session_id, packet_id, 1, 0, addr, data,
        )]);
    }
    let cont_header = 10 + TuicAddr::None.encoded_len();
    let first_cap = max_datagram.saturating_sub(first_header);
    let cont_cap = max_datagram.saturating_sub(cont_header);
    if first_cap == 0 || cont_cap == 0 {
        anyhow::bail!("datagram MTU {max_datagram} too small for the packet header");
    }
    let frag_total = 1 + (data.len() - first_cap).div_ceil(cont_cap);
    if frag_total > u8::MAX as usize {
        anyhow::bail!("UDP payload {} bytes needs too many fragments", data.len());
    }
    let mut out = Vec::with_capacity(frag_total);
    let mut offset = 0;
    for frag_id in 0..frag_total {
        let cap = if frag_id == 0 { first_cap } else { cont_cap };
        let end = (offset + cap).min(data.len());
        let frag_addr = if frag_id == 0 {
            addr.clone()
        } else {
            TuicAddr::None
        };
        out.push(encode_udp_packet(
            session_id,
            packet_id,
            frag_total as u8,
            frag_id as u8,
            &frag_addr,
            &data[offset..end],
        ));
        offset = end;
    }
    Ok(out)
}

type SessionMap = Arc<parking_lot::Mutex<HashMap<u16, mpsc::Sender<UdpInbound>>>>;

/// Per-session inbound queue depth. UDP semantics: when the bridge falls
/// behind, excess datagrams are dropped (never queue unboundedly).
const UDP_SESSION_QUEUE_CAP: usize = 256;

/// Per-QUIC-connection protocol state (demux maps, counters, task set).
struct TuicConnState {
    conn: quinn::Connection,
    /// UDP-over-stream fallback: the peer did not negotiate QUIC datagrams.
    udp_over_stream: bool,
    sessions: SessionMap,
    next_session: AtomicU16,
    /// Number of open TCP streams + UDP bridges on this connection.
    open: Arc<AtomicUsize>,
    /// Last activity (unix seconds) for the idle-connection reaper.
    last_activity: Arc<AtomicU64>,
    path_health: Arc<crate::quic::QuicPathHealth>,
    metrics: OnceLock<crate::quic::QuicConnectionMonitor>,
}

impl QuicConnState for TuicConnState {
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

impl TuicConnState {
    fn new(conn: quinn::Connection) -> Self {
        let sessions: SessionMap = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let path_health = crate::quic::QuicPathHealth::new(&conn);
        let state = Self {
            udp_over_stream: conn.max_datagram_size().is_none(),
            conn: conn.clone(),
            sessions: Arc::clone(&sessions),
            next_session: AtomicU16::new(0),
            open: Arc::new(AtomicUsize::new(0)),
            last_activity: Arc::new(AtomicU64::new(now_secs())),
            path_health: Arc::clone(&path_health),
            metrics: OnceLock::new(),
        };
        tokio::spawn(Self::datagram_loop(
            conn.clone(),
            Arc::clone(&sessions),
            Arc::clone(&path_health),
        ));
        tokio::spawn(Self::uni_stream_loop(
            conn.clone(),
            Arc::clone(&sessions),
            Arc::clone(&path_health),
        ));
        crate::quic::spawn_quic_path_watchdog(conn.clone(), Arc::clone(&path_health));
        let open = Arc::downgrade(&state.open);
        let last_activity = Arc::downgrade(&state.last_activity);
        crate::quic::spawn_conn_reaper(
            conn,
            open,
            last_activity,
            HEARTBEAT_INTERVAL,
            CONN_IDLE_TIMEOUT,
            if state.udp_over_stream {
                None
            } else {
                Some(Box::new(|conn: &quinn::Connection| {
                    !matches!(
                        conn.send_datagram(bytes::Bytes::from_static(&[
                            TUIC_VERSION,
                            CMD_HEARTBEAT,
                        ])),
                        Err(quinn::SendDatagramError::ConnectionLost(_))
                    )
                }))
            },
        );
        state
    }

    fn alloc_session(&self) -> u16 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }

    /// Inbound QUIC datagrams: PACKET frames are demultiplexed by session id
    /// (sing `loopMessages`, `client_packet.go:12-50`).
    async fn datagram_loop(
        conn: quinn::Connection,
        sessions: SessionMap,
        path_health: Arc<crate::quic::QuicPathHealth>,
    ) {
        loop {
            let data = match conn.read_datagram().await {
                Ok(data) => data,
                Err(_) => break,
            };
            if data.len() < 2 || data[0] != TUIC_VERSION {
                continue;
            }
            match data[1] {
                CMD_PACKET => {
                    if let Ok(msg) = decode_udp_message(&data[2..]) {
                        let tx = sessions.lock().get(&msg.session_id).cloned();
                        if let Some(tx) = tx
                            && let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                                tx.try_send(msg)
                        {
                            path_health.record_session_rx_drop();
                        }
                    }
                }
                CMD_HEARTBEAT => {}
                other => debug!("TUIC: ignoring unknown datagram command {other:#x}"),
            }
        }
        // Connection died: drop all session senders so bridges terminate.
        sessions.lock().clear();
    }

    /// Inbound uni streams carry one PACKET frame each in UDP-over-stream
    /// mode (sing `loopUniStreams`, `client_packet.go:52-93`).
    async fn uni_stream_loop(
        conn: quinn::Connection,
        sessions: SessionMap,
        path_health: Arc<crate::quic::QuicPathHealth>,
    ) {
        loop {
            let mut recv = match conn.accept_uni().await {
                Ok(recv) => recv,
                Err(_) => break,
            };
            let sessions = Arc::clone(&sessions);
            let path_health = Arc::clone(&path_health);
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                if read_exact(&mut recv, &mut head).await.is_err() {
                    return;
                }
                if head[0] != TUIC_VERSION || head[1] != CMD_PACKET {
                    return;
                }
                if let Ok(msg) = read_udp_message_stream(&mut recv).await {
                    let tx = sessions.lock().get(&msg.session_id).cloned();
                    if let Some(tx) = tx
                        && let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                            tx.try_send(msg)
                    {
                        path_health.record_session_rx_drop();
                    }
                }
            });
        }
    }
}

struct TuicClient {
    quic: QuicClient<TuicConnState>,
    uuid: [u8; 16],
    password: String,
}

#[async_trait]
impl crate::runtime::QuicRuntimeClient for TuicClient {
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

impl TuicClient {
    async fn connection(
        &self,
        connect_timeout: Duration,
    ) -> anyhow::Result<(quinn::Connection, Arc<TuicConnState>)> {
        let uuid = self.uuid;
        let password = self.password.clone();
        self.quic
            .connection_with_metrics(connect_timeout, move |conn| async move {
                crate::quic::exporter_auth(&conn, &uuid, &password, TUIC_VERSION, true, AUTH_GRACE)
                    .await?;
                Ok(TuicConnState::new(conn))
            })
            .await
    }
}

/// TUIC proxy handler. Stateless: the per-server client (and its shared
/// QUIC connection) lives in the node's generation runtime.
#[derive(Debug, Default, Clone)]
pub struct TuicHandler;

impl TuicHandler {
    pub fn new() -> Self {
        Self
    }

    async fn build_client(&self, node: &Node) -> anyhow::Result<Arc<TuicClient>> {
        let tuic = node.tuic().unwrap();
        let uuid_str = tuic
            .uuid
            .as_deref()
            .ok_or_else(|| anyhow!("TUIC node '{}': missing tuic_uuid", node.name))?;
        let uuid = uuid::Uuid::parse_str(uuid_str)
            .with_context(|| format!("TUIC node '{}': invalid uuid", node.name))?;
        let password = tuic.password.as_deref().unwrap_or("").to_string();
        let server_name = tuic
            .quic
            .tls
            .sni
            .clone()
            .unwrap_or_else(|| node.host().to_string());
        // ALPN override from the share link (`alpn=h3`, comma-separated);
        // servers configured without `tuic` in their ALPN list reject the
        // handshake at the TLS layer otherwise.
        let alpn: Vec<Vec<u8>> = tuic
            .alpn
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(|p| p.as_bytes().to_vec())
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec![b"tuic".to_vec()]);
        let options = crate::quic::QuicClientOptions {
            congestion: Some(crate::quic::congestion_factory(tuic.congestion.as_deref())),
            // Keep both protocol and QUIC PING liveness in fallback mode.
            keep_alive: Some(HEARTBEAT_INTERVAL),
            stream_receive_window: Some(tuic.init_stream_recv_window.unwrap_or(8 << 20)),
            conn_receive_window: Some(tuic.init_conn_recv_window.unwrap_or(8 << 20)),
            max_udp_payload_size: tuic.quic.mtu,
            ..Default::default()
        };
        let alpn_refs: Vec<&[u8]> = alpn.iter().map(Vec::as_slice).collect();
        let config = crate::quic::client_config(node, &alpn_refs, options).await?;
        Ok(Arc::new(TuicClient {
            quic: QuicClient::new(node.host().to_string(), node.port, server_name, config)
                .with_max_udp_payload_size(tuic.quic.mtu.unwrap_or(1252)),
            uuid: *uuid.as_bytes(),
            password,
        }))
    }

    async fn client_for_runtime(
        &self,
        runtime: &crate::runtime::NodeRuntime,
    ) -> anyhow::Result<Arc<TuicClient>> {
        runtime
            .quic_client(|| self.build_client(runtime.node.as_ref()))
            .await
    }

    async fn dial_via_client(
        &self,
        client: Arc<TuicClient>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = TuicAddr::new(target, target_domain);
        let stream = crate::quic::dial_quic_stream(
            &client.quic,
            |timeout| {
                let client = Arc::clone(&client);
                async move { client.connection(timeout).await }
            },
            connect_timeout,
            move |conn| {
                let addr = addr.clone();
                async move {
                    let (mut send, recv) = conn.open_bi().await.context("TUIC: open stream")?;
                    let mut header = Vec::with_capacity(2 + addr.encoded_len());
                    header.push(TUIC_VERSION);
                    header.push(CMD_CONNECT);
                    addr.encode(&mut header);
                    send.write_all(&header)
                        .await
                        .context("TUIC: send CONNECT")?;
                    Ok((send, recv))
                }
            },
            |_| true,
            "TUIC",
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
        client: Arc<TuicClient>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let (_conn, state) = client.connection(connect_timeout).await?;
        state.touch();
        let session_id = state.alloc_session();
        let (tx, rx) = mpsc::channel::<UdpInbound>(UDP_SESSION_QUEUE_CAP);
        state.sessions.lock().insert(session_id, tx);
        state.open.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(TuicUdpTransport {
            state,
            session_id,
            packet_id: AtomicU16::new(0),
            rx: tokio::sync::Mutex::new(rx),
            defrag: tokio::sync::Mutex::new(Defragmenter::new(u16::MAX as usize)),
            target_addr: TuicAddr::new(target, target_domain),
            target,
        }))
    }

    async fn send_udp(
        state: &TuicConnState,
        session_id: u16,
        packet_id: u16,
        addr: &TuicAddr,
        data: &[u8],
    ) -> anyhow::Result<()> {
        if data.len() > u16::MAX as usize {
            anyhow::bail!("UDP payload too large: {} bytes", data.len());
        }
        state.touch();
        if state.udp_over_stream {
            // One uni stream per packet (sing `writePacket` udpStream branch).
            let pkt = encode_udp_packet(session_id, packet_id, 1, 0, addr, data);
            let mut stream = state.conn.open_uni().await?;
            stream.write_all(&pkt).await?;
            stream.finish()?;
            return Ok(());
        }
        let max_datagram = state.conn.max_datagram_size().unwrap_or(1200);
        for pkt in fragment_udp_packets(session_id, packet_id, addr, data, max_datagram)? {
            state
                .conn
                .send_datagram_wait(bytes::Bytes::from(pkt))
                .await
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    async fn send_dissociate(conn: &quinn::Connection, session_id: u16) {
        if let Ok(mut stream) = conn.open_uni().await {
            let mut buf = Vec::with_capacity(4);
            buf.push(TUIC_VERSION);
            buf.push(CMD_DISSOCIATE);
            buf.extend_from_slice(&session_id.to_be_bytes());
            let _ = stream.write_all(&buf).await;
            let _ = stream.finish();
        }
    }
}

#[async_trait]
impl WarmableOutbound for TuicHandler {
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
impl TcpOutbound for TuicHandler {
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
        anyhow::bail!("TUIC runs over QUIC; a bare TCP connection cannot be reused")
    }
}

#[async_trait]
impl PacketOutbound for TuicHandler {
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
impl ProbeableOutbound for TuicHandler {
    async fn test_connectivity(&self, node: &Node) -> bool {
        match self.build_client(node).await {
            Ok(client) => match client.connection(Duration::from_secs(5)).await {
                Ok((conn, _)) => crate::quic::survives_auth_close_window(&conn).await,
                Err(_) => false,
            },
            Err(e) => {
                debug!("TUIC connectivity test failed for {}: {}", node.name, e);
                false
            }
        }
    }
}

/// Framed UDP transport over a TUIC session: PACKET frames go straight onto
/// the shared QUIC connection (datagrams, or uni streams when datagrams were
/// not negotiated) and inbound frames arrive through the connection's
/// session demux queue.
struct TuicUdpTransport {
    state: Arc<TuicConnState>,
    session_id: u16,
    packet_id: AtomicU16,
    rx: tokio::sync::Mutex<mpsc::Receiver<UdpInbound>>,
    defrag: tokio::sync::Mutex<Defragmenter>,
    target_addr: TuicAddr,
    target: SocketAddr,
}

impl std::fmt::Debug for TuicUdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicUdpTransport")
            .field("session_id", &self.session_id)
            .field("target", &self.target)
            .finish()
    }
}

impl Drop for TuicUdpTransport {
    fn drop(&mut self) {
        self.state.sessions.lock().remove(&self.session_id);
        self.state.open.fetch_sub(1, Ordering::Relaxed);
        let conn = self.state.conn.clone();
        let session_id = self.session_id;
        tokio::spawn(async move {
            TuicHandler::send_dissociate(&conn, session_id).await;
        });
    }
}

#[async_trait]
impl PacketTransport for TuicUdpTransport {
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
        !self.state.udp_over_stream
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        let packet_id = self
            .packet_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        TuicHandler::send_udp(
            &self.state,
            self.session_id,
            packet_id,
            &self.target_addr,
            data,
        )
        .await
        .map_err(io::Error::other)
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let msg = self.rx.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionAborted, "TUIC connection closed")
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
                        "TUIC packet exceeds buffer",
                    ));
                }
                buf[..data.len()].copy_from_slice(&data);
                return Ok((data.len(), self.target));
            }
        }
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
    const TEST_PASSWORD: &str = "tuic-test-password";

    fn test_node(port: u16, password: &str) -> Node {
        Node {
            name: "tuic-test".to_string(),
            host: "127.0.0.1".to_string(),
            address: format!("127.0.0.1:{port}"),
            port,
            outbound: honk_config::node::OutboundConfig::Tuic(honk_config::node::TuicConfig {
                uuid: Some(TEST_UUID.to_string()),
                password: Some(password.to_string()),
                quic: honk_config::node::QuicOptions {
                    tls: honk_config::node::TlsOptions {
                        skip_cert_verify: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Minimal in-process TUIC v5 server: verifies the AUTHENTICATE token
    /// with the same TLS exporter, echoes CONNECT streams back, echoes UDP
    /// packets back on the path they arrived (datagram or uni stream).
    async fn start_server(datagrams: bool, password: &'static str) -> SocketAddr {
        start_server_with_alpn(&[b"tuic"], datagrams, password).await
    }

    async fn start_server_with_alpn(
        alpn: &[&[u8]],
        datagrams: bool,
        password: &'static str,
    ) -> SocketAddr {
        let (endpoint, addr) = testutil::server_endpoint(alpn, datagrams).unwrap();
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
        // Uni streams: authenticate + UDP-over-stream packets.
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
                    match (head[0], head[1]) {
                        (TUIC_VERSION, CMD_AUTHENTICATE) => {
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
                        }
                        (TUIC_VERSION, CMD_PACKET) => {
                            let Ok(msg) = read_udp_message_stream(&mut recv).await else {
                                return;
                            };
                            // Echo the packet back on a fresh uni stream.
                            let pkt = encode_udp_packet(
                                msg.session_id,
                                msg.packet_id,
                                msg.frag_total,
                                msg.frag_id,
                                &msg.addr,
                                &msg.data,
                            );
                            if let Ok(mut send) = conn.open_uni().await {
                                let _ = send.write_all(&pkt).await;
                                let _ = send.finish();
                            }
                        }
                        _ => {}
                    }
                });
            }
        });
        // Bi streams: CONNECT echo.
        let bi_conn = conn.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut send, mut recv)) = bi_conn.accept_bi().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut head = [0u8; 2];
                    if read_exact(&mut recv, &mut head).await.is_err() {
                        return;
                    }
                    if head != [TUIC_VERSION, CMD_CONNECT] {
                        return;
                    }
                    if TuicAddr::read_from_stream(&mut recv).await.is_err() {
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
                });
            }
        });
        // Datagrams: echo PACKET frames verbatim.
        loop {
            let Ok(data) = conn.read_datagram().await else {
                break;
            };
            if data.len() >= 2 && data[0] == TUIC_VERSION && data[1] == CMD_PACKET {
                let _ = conn.send_datagram(data);
            }
        }
    }

    #[tokio::test]
    async fn test_dial_tcp_echo() {
        let server_addr = start_server(true, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = TuicHandler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let mut stream = handler
            .dial(&node, target, None, Duration::from_secs(5))
            .await
            .expect("dial should succeed");
        stream.stream.write_all(b"hello tuic").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello tuic");
    }

    #[tokio::test]
    async fn test_dial_tcp_domain_echo() {
        let server_addr = start_server(true, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = TuicHandler::new();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let mut stream = handler
            .dial(&node, target, Some("example.com"), Duration::from_secs(5))
            .await
            .expect("dial should succeed");
        stream.stream.write_all(b"domain").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"domain");
    }

    #[tokio::test]
    async fn test_wrong_password_rejected() {
        let server_addr = start_server(true, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), "wrong-password");
        let handler = TuicHandler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        // TUIC has no auth response, so the dial proceeds optimistically
        // (zero auth grace, sing-quic/dae parity); the rejection surfaces
        // ~1 RTT later when the server closes the connection. The
        // connectivity probe (which waits for exactly that) must say no.
        let _ = handler
            .dial(&node, target, None, Duration::from_secs(5))
            .await;
        assert!(!handler.test_connectivity(&node).await);
    }

    #[tokio::test]
    async fn test_custom_alpn() {
        // Server only accepts `h3` (HTTP/3-camouflaged TUIC deployment).
        let server_addr = start_server_with_alpn(&[b"h3"], true, TEST_PASSWORD).await;
        let handler = TuicHandler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        // Share-link `alpn=h3` is honored: the handshake succeeds.
        let mut node = test_node(server_addr.port(), TEST_PASSWORD);
        node.tuic_mut().unwrap().alpn = Some("h3".to_string());
        let mut stream = handler
            .dial(&node, target, None, Duration::from_secs(5))
            .await
            .expect("matching custom ALPN should connect");
        stream.stream.write_all(b"alpn").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"alpn");

        // Default ALPN (`tuic`) is rejected at the TLS layer.
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let result = handler
            .dial(&node, target, None, Duration::from_secs(5))
            .await;
        assert!(result.is_err(), "mismatched ALPN must fail the handshake");
    }

    #[tokio::test]
    async fn test_udp_transport_native_datagram_echo() {
        let server_addr = start_server(true, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = TuicHandler::new();
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let transport = handler
            .dial_udp_transport(&node, target, None, Duration::from_secs(5))
            .await
            .expect("dial_udp_transport should succeed");
        assert_eq!(transport.relay_addr(), target);
        assert!(transport.send_timeout_is_congestion());
        transport.send_packet(b"dns-query").await.unwrap();
        let mut buf = [0u8; 256];
        let (n, src) =
            tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                .await
                .expect("reply timed out")
                .unwrap();
        assert_eq!(src, target);
        assert_eq!(&buf[..n], b"dns-query");
    }

    #[tokio::test]
    async fn test_udp_transport_over_stream_echo() {
        // Server without QUIC datagram support → UDP-over-stream fallback.
        let server_addr = start_server(false, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = TuicHandler::new();
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let transport = handler
            .dial_udp_transport(&node, target, None, Duration::from_secs(5))
            .await
            .expect("dial_udp_transport should succeed");
        assert!(!transport.send_timeout_is_congestion());
        transport.send_packet(b"stream-query").await.unwrap();
        let mut buf = [0u8; 256];
        let (n, src) =
            tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                .await
                .expect("reply timed out")
                .unwrap();
        assert_eq!(src, target);
        assert_eq!(&buf[..n], b"stream-query");
    }

    #[tokio::test]
    async fn test_connection_reuse_across_dials() {
        let server_addr = start_server(true, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = TuicHandler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        for i in 0..3 {
            let mut stream = handler
                .dial(&node, target, None, Duration::from_secs(5))
                .await
                .expect("dial should succeed");
            let payload = format!("req{i}");
            stream.stream.write_all(payload.as_bytes()).await.unwrap();
            let mut buf = [0u8; 16];
            let n = stream.stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], payload.as_bytes());
        }
    }

    #[test]
    fn test_addr_codec_roundtrip() {
        let cases = [
            TuicAddr::Addr(SocksAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(93, 184, 216, 34),
                80,
            ))),
            TuicAddr::Addr(SocksAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                443,
                0,
                0,
            ))),
            TuicAddr::Addr(SocksAddr::Domain("example.com".to_string(), 8080)),
            TuicAddr::None,
        ];
        for addr in cases {
            let mut buf = Vec::new();
            addr.encode(&mut buf);
            assert_eq!(buf.len(), addr.encoded_len());
            let mut cursor = &buf[..];
            let decoded = TuicAddr::decode(&mut cursor).unwrap();
            assert_eq!(decoded, addr);
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn test_udp_message_codec_roundtrip() {
        let addr = TuicAddr::Addr(SocksAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(8, 8, 8, 8),
            53,
        )));
        let pkt = encode_udp_packet(7, 42, 1, 0, &addr, b"payload");
        assert_eq!(pkt[0], TUIC_VERSION);
        assert_eq!(pkt[1], CMD_PACKET);
        let msg = decode_udp_message(&pkt[2..]).unwrap();
        assert_eq!(msg.session_id, 7);
        assert_eq!(msg.packet_id, 42);
        assert_eq!(msg.frag_total, 1);
        assert_eq!(msg.frag_id, 0);
        assert_eq!(msg.addr, addr);
        assert_eq!(msg.data, b"payload");
    }

    #[test]
    fn test_fragmentation_and_defrag() {
        let addr = TuicAddr::Addr(SocksAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(8, 8, 8, 8),
            53,
        )));
        let data = vec![0xabu8; 3000];
        let max = 1200;
        let frags = fragment_udp_packets(1, 99, &addr, &data, max).unwrap();
        assert_eq!(frags.len(), 3);
        assert!(frags.iter().all(|f| f.len() <= max));

        let mut defrag = Defragmenter::new(u16::MAX as usize);
        let mut out = None;
        // Feed out of order; only the last missing fragment completes it.
        for pkt in frags.iter().rev() {
            let msg = decode_udp_message(&pkt[2..]).unwrap();
            out = defrag
                .feed(msg.packet_id, msg.frag_id, msg.frag_total, msg.data)
                .or(out);
        }
        assert_eq!(out.expect("reassembled payload"), data);
    }

    #[test]
    fn test_fragmentation_small_packet_not_fragmented() {
        let addr = TuicAddr::Addr(SocksAddr::Domain("example.com".to_string(), 443));
        let data = b"tiny";
        let frags = fragment_udp_packets(1, 1, &addr, data, 1200).unwrap();
        assert_eq!(frags.len(), 1);
        let msg = decode_udp_message(&frags[0][2..]).unwrap();
        assert_eq!(msg.frag_total, 1);
        assert_eq!(msg.addr, addr);
        assert_eq!(msg.data, data);
    }
}
