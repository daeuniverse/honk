//! Juicity proxy handler (QUIC), implemented against the daeuniverse

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use honk_config::node::Node;
use tracing::debug;

use crate::quic::{QuicClient, QuicConnState, now_secs, recv_read_exact as read_exact};
use crate::transport_quality::TransportQuality;

use super::addr::SocksAddr as JuiceAddr;
use super::uot::{AddrFraming, MAX_PACKET_SIZE};
use super::{
    MultiTargetTransport, PacketOutbound, PacketTransport, PreparedUdpTransport, ProbeableOutbound,
    ProxyStream, SharedSourceOutbound, TcpOutbound, WarmableOutbound,
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
/// caller's buffer. An unprojectable source is consumed whole and returned
/// as `None`; an oversized deliverable payload is consumed before returning
/// a buffer-size error.
async fn read_udp_frame(
    recv: &mut quinn::RecvStream,
    payload: &mut [u8],
    target: SocketAddr,
    target_domain: Option<&str>,
) -> io::Result<Option<(SocketAddr, usize)>> {
    let peer = super::addr::read_reply_source(recv, target_domain, target).await?;
    let mut len = [0u8; 2];
    read_exact(recv, &mut len).await?;
    let payload_len = u16::from_be_bytes(len) as usize;
    let Some(peer) = peer.filter(|_| payload_len <= payload.len()) else {
        let mut discard = [0u8; 512];
        let mut remaining = payload_len;
        while remaining != 0 {
            let chunk = remaining.min(discard.len());
            read_exact(recv, &mut discard[..chunk]).await?;
            remaining -= chunk;
        }
        return if peer.is_some() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "juicity datagram exceeds buffer",
            ))
        } else {
            Ok(None)
        };
    };
    read_exact(recv, &mut payload[..payload_len]).await?;
    Ok(Some((peer, payload_len)))
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
}

impl QuicConnState for JuicityConnState {
    fn touch(&self) {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
    }

    fn open_counter(&self) -> &Arc<AtomicUsize> {
        &self.open
    }
    fn enable_telemetry(&self) {
        self.path_health.enable_telemetry();
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

    async fn enable_metrics(&self, quality: Arc<TransportQuality>) {
        self.quic.enable_metrics(quality).await;
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
        let password = &self.password;
        self.quic
            .connection_with_metrics(connect_timeout, move |conn| async move {
                let auth_stream = crate::quic::exporter_auth(
                    &conn,
                    &uuid,
                    password,
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

    async fn build_client(
        &self,
        node: &Node,
        profiles: Option<Arc<crate::quic::AdaptiveFlowProfiles>>,
    ) -> anyhow::Result<Arc<JuicityClient>> {
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
                congestion: Some(crate::quic::congestion_factory(Some("bbr"))),
                keep_alive: Some(KEEP_ALIVE_INTERVAL),
                disable_mtu_discovery: juicity.quic.disable_mtu_discovery,
                max_udp_payload_size: juicity.quic.mtu,
                // Same receive-window rationale as hy2/tuic: quinn's
                // 1.25 MiB stream default caps downloads around 2 Gbps
                // on a LAN. Conn window doubles as the per-connection
                // memory budget (see hy2).
                stream_receive_window: Some(8 << 20),
                conn_receive_window: Some(8 << 20),
            },
        )
        .await?;
        Ok(Arc::new(JuicityClient {
            quic: QuicClient::new(node.host().to_string(), node.port, server_name, config)
                .with_flow_control_profiles(profiles)
                .with_max_udp_payload_size(juicity.quic.mtu.unwrap_or(1252)),
            uuid: *uuid.as_bytes(),
            password,
        }))
    }

    /// Open a bi stream and write the juicity request header
    /// (`[network][metadata]`, `stream_conn.go:29-36`). `observe` publishes
    /// the opener's request milestone; a shared UDP stream's header names only
    /// its first destination, so its flows publish per datagram instead.
    async fn open_stream(
        conn: &quinn::Connection,
        network: u8,
        addr: &JuiceAddr,
        observe: bool,
    ) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|error| super::NodeFailure(error.into()))
            .context("Juicity: open stream")?;
        let mut header = Vec::with_capacity(1 + addr.encoded_len());
        header.push(network);
        addr.encode(&mut header);
        send.write_all(&header)
            .await
            .context("Juicity: send request header")
            .map_err(super::quic_carrier_error)?;
        if observe {
            publish_request_sent();
        }
        Ok((send, recv))
    }
    async fn client_for_runtime(
        &self,
        runtime: &crate::runtime::NodeRuntime,
    ) -> anyhow::Result<Arc<JuicityClient>> {
        let profiles = runtime.quic_flow_control_profiles()?;
        runtime
            .quic_client(|| self.build_client(runtime.node.as_ref(), Some(profiles)))
            .await
    }

    async fn dial_via_client(
        &self,
        client: Arc<JuicityClient>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = JuiceAddr::new(target, target_domain)?;
        let stream = crate::quic::dial_quic_stream(
            &client.quic,
            |timeout| {
                let client = Arc::clone(&client);
                async move { client.connection(timeout).await }
            },
            connect_timeout,
            move |conn| {
                let addr = addr.clone();
                async move { Self::open_stream(&conn, NETWORK_TCP, &addr, true).await }
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
        observe_open: bool,
    ) -> anyhow::Result<Arc<JuicityUdpTransport>> {
        let stream_addr = JuiceAddr::new(target, target_domain)?;
        let mut last_error = None;
        for _ in 0..2 {
            let (conn, state) = client.connection(connect_timeout).await?;
            state.touch();
            let observation = crate::session::ObservedSessionOpen::start();
            match Self::open_stream(&conn, NETWORK_UDP, &stream_addr, observe_open).await {
                Ok((send, recv)) => {
                    observation
                        .finish(crate::runtime::flow_observation::SessionEvent::OpenSucceeded);
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
                        poison: super::FramePoison::default(),
                        recv: tokio::sync::Mutex::new(recv),
                        _guard: guard,
                        target,
                        target_domain: target_domain.map(Box::from),
                    }));
                }
                Err(error) => {
                    observation.finish(crate::runtime::flow_observation::SessionEvent::OpenFailed);
                    client.quic.invalidate(&conn).await;
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.expect("Juicity UDP stream attempts are non-empty"))
    }

    /// One UDP stream carrying every destination of a client source.
    pub async fn prepare_udp_source(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        if !speculative {
            let client = self.client_for_runtime(&runtime).await?;
            let transport = self
                .udp_transport_via_client(client, target, target_domain, connect_timeout, false)
                .await?;
            return Ok(PreparedUdpTransport::ready(
                transport as Arc<dyn MultiTargetTransport>,
            ));
        }
        let profiles = runtime.quic_flow_control_profiles()?;
        let client = self
            .build_client(runtime.node.as_ref(), Some(profiles))
            .await?;
        super::prepare_detached_quic_transport(runtime, client, |client| async move {
            let transport = self
                .udp_transport_via_client(client, target, target_domain, connect_timeout, false)
                .await?;
            Ok(transport as Arc<dyn MultiTargetTransport>)
        })
        .await
    }
}

fn publish_request_sent() {
    if let Some(observer) = crate::runtime::flow_observation::current() {
        observer.milestone_once(crate::runtime::flow_observation::Milestone::TargetRequestSent);
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
        let warm = async {
            let client = self.client_for_runtime(&runtime).await?;
            client.connection(connect_timeout).await?;
            Ok(())
        };
        let warm = crate::runtime::flow_observation::without(warm);
        warm.await
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
        let client = self.build_client(node, None).await?;
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
impl SharedSourceOutbound for JuicityHandler {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        self.prepare_udp_source(runtime, target, target_domain, connect_timeout, speculative)
            .await
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
        let client = self.build_client(node, None).await?;
        Ok(self
            .udp_transport_via_client(client, target, target_domain, connect_timeout, true)
            .await?)
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let client = self.client_for_runtime(&runtime).await?;
        Ok(self
            .udp_transport_via_client(client, target, target_domain, connect_timeout, true)
            .await?)
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<super::PreparedUdpTransport> {
        let profiles = runtime.quic_flow_control_profiles()?;
        let client = self
            .build_client(runtime.node.as_ref(), Some(profiles))
            .await?;
        super::prepare_detached_quic_transport(runtime, client, |client| async move {
            let transport = self
                .udp_transport_via_client(client, target, target_domain, connect_timeout, true)
                .await?;
            Ok(transport as Arc<dyn PacketTransport>)
        })
        .await
    }
}

#[async_trait]
impl ProbeableOutbound for JuicityHandler {
    async fn test_connectivity(&self, node: &Node) -> bool {
        match self.build_client(node, None).await {
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
/// as `[metadata][len u16][payload]` directly on the QUIC stream, in both
/// directions and for any destination.
struct JuicityUdpTransport {
    state: Arc<JuicityConnState>,
    send: tokio::sync::Mutex<quinn::SendStream>,
    /// Set while a frame is being written, cleared once it is accepted:
    /// `write_chunk` is not cancellation safe, so a write cancelled halfway
    /// leaves it set and no sibling destination may extend the torn frame.
    poison: super::FramePoison,
    recv: tokio::sync::Mutex<quinn::RecvStream>,
    /// Keeps the connection's open-stream accounting alive for the
    /// transport's lifetime (see `QuicBiStream::into_parts`).
    _guard: crate::quic::StreamDropGuard,
    /// The destination and name the stream was opened for: ordinary sends go
    /// there, and a domain reply from it projects back to `target`.
    target: SocketAddr,
    target_domain: Option<Box<str>>,
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
    fn allows_full_cone_replies(&self) -> bool {
        true
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
        self.send_datagram(self.target, self.target_domain.as_deref(), data, None)
            .await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut recv = self.recv.lock().await;
        loop {
            let Some((peer, payload_len)) =
                read_udp_frame(&mut recv, buf, self.target, self.target_domain.as_deref())
                    .await
                    .map_err(super::quic_carrier_io_error)?
            else {
                continue;
            };
            return Ok((payload_len, peer));
        }
    }
}

#[async_trait]
impl MultiTargetTransport for JuicityUdpTransport {
    async fn send_to(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        _confirmed: bool,
        admitted: Option<&std::sync::atomic::AtomicBool>,
    ) -> io::Result<()> {
        self.send_datagram(target, domain, data, admitted).await?;
        publish_request_sent();
        Ok(())
    }

    fn carrier_addr(&self) -> Option<SocketAddr> {
        Some(self.state._conn.remote_address())
    }

    fn frame_stream_torn(&self) -> bool {
        self.poison.is_set()
    }
}

impl JuicityUdpTransport {
    /// SealUDP: `[metadata][len u16][payload]` (`stream_packet_conn.go:83-90`).
    async fn send_datagram(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        admitted: Option<&std::sync::atomic::AtomicBool>,
    ) -> io::Result<()> {
        let frame = AddrFraming::SOCKS5.encode(&[], target, domain, data, MAX_PACKET_SIZE)?;
        self.state.touch();
        let mut send = self.send.lock().await;
        let write = self.poison.begin(admitted)?;
        send.write_chunk(frame)
            .await
            .map_err(io::Error::other)
            .map_err(super::quic_carrier_io_error)?;
        write.complete();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
