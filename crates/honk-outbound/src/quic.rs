//! Shared QUIC client plumbing for QUIC-based proxy protocols.
//!
//! Used by the TUIC v5, Juicity, and Hysteria2 outbounds.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use parking_lot::Mutex as SyncMutex;
use quinn::congestion;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, TransportConfig, VarInt};
use tokio::sync::Mutex;
use tracing::warn;

use crate::transport_quality::TransportQuality;

pub mod boring;
mod client;
mod endpoint;
mod flow_control;
mod metrics;
mod path_health;
mod stream;

use endpoint::clamp_quic_payload_size;
use metrics::QuicClientConnectionMonitor;

pub(crate) use endpoint::endpoint_config_with_mtu;
pub use endpoint::{client_endpoint, client_endpoint_with_mtu, marked_udp_socket};
pub use metrics::{
    QuicConnectionMonitor, QuicStatsSnapshot, monitor_quic_connection, quic_stats_snapshot,
    record_quic_path_stall, record_quic_send_timeout,
};
pub(crate) use path_health::spawn_quic_path_watchdog;
pub use stream::QuicBiStream;
pub(crate) use stream::{
    QuicConnState, StreamDropGuard, dial_quic_stream, exporter_auth, spawn_conn_reaper,
};

/// Map a congestion-control name (`cubic` / `new_reno` / `bbr`, as used by
/// sing-box and dae node configs) to a quinn controller factory.
///
/// Unknown names fall back to cubic with a warning (all three algorithms are
/// provided by quinn-proto itself).
pub fn congestion_factory(
    name: Option<&str>,
) -> Arc<dyn congestion::ControllerFactory + Send + Sync> {
    match name.unwrap_or("cubic") {
        "cubic" => Arc::new(congestion::CubicConfig::default()),
        "new_reno" => Arc::new(congestion::NewRenoConfig::default()),
        "bbr" => Arc::new(congestion::BbrConfig::default()),
        other => {
            warn!("unknown QUIC congestion control '{other}', falling back to cubic");
            Arc::new(congestion::CubicConfig::default())
        }
    }
}

/// Fixed-rate "brutal" sender (hysteria2 parity): paces at a constant rate
/// and ignores loss entirely. quinn's token-bucket pacer refills at
/// window/RTT, so reporting a window of `rate × RTT` yields the target
/// pacing rate — the same shape as apernet's brutal sender, whose congestion
/// window is `SendBPS × RTT`.
#[derive(Debug)]
pub struct BrutalConfig {
    /// Target send rate in bytes per second.
    bytes_per_second: u64,
}

impl BrutalConfig {
    /// Build a factory for a target rate in bits per second (hysteria2
    /// bandwidth configs are in bps; 1 Mbps = 1e6 bps).
    pub fn from_bps(bps: u64) -> Self {
        Self {
            bytes_per_second: bps / 8,
        }
    }
}

impl congestion::ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn congestion::Controller> {
        Box::new(Brutal {
            rate: self.bytes_per_second,
            // RFC 9002 initial RTT; refined by the first ACK.
            rtt: Duration::from_millis(333),
            mtu: current_mtu,
        })
    }
}
struct Brutal {
    /// Target send rate, bytes per second.
    rate: u64,
    /// Latest smoothed RTT estimate.
    rtt: Duration,
    mtu: u16,
}

impl Brutal {
    fn bdp(&self) -> u64 {
        (u128::from(self.rate).saturating_mul(self.rtt.as_micros()) / 1_000_000)
            .min(u128::from(u64::MAX)) as u64
    }
}

impl congestion::Controller for Brutal {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.rtt = rtt.get();
    }

    /// Brutal never slows down for loss or ECN — that is its entire point.
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
    }

    fn window(&self) -> u64 {
        self.bdp().max(self.initial_window())
    }

    fn metrics(&self) -> congestion::ControllerMetrics {
        // ControllerMetrics is #[non_exhaustive]: no struct literals outside
        // the crate, mutate a default value instead.
        let mut metrics = congestion::ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some(self.rate.saturating_mul(8));
        metrics
    }

    fn clone_box(&self) -> Box<dyn congestion::Controller> {
        Box::new(Brutal {
            rate: self.rate,
            rtt: self.rtt,
            mtu: self.mtu,
        })
    }

    fn initial_window(&self) -> u64 {
        10 * u64::from(self.mtu)
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

const QUIC_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// Connection-wide QUIC delivery progress. Packet sends only read atomics;
/// Quinn statistics are sampled at most once per second, plus on a send
/// deadline and the watchdog's one-second tick.
#[derive(Debug)]
pub(crate) struct QuicPathHealth {
    ack_state: AtomicU64,
    last_acked_packets: AtomicU64,
    sampled_acked_packets: AtomicU64,
    sampled_sent_ack_eliciting_packets: AtomicU64,
    waiting_sent_baseline: AtomicU64,
    waiting_acked_baseline: AtomicU64,
    unacked_since_ms: AtomicU64,
    last_sample_ms: AtomicU64,
    timeout_state: AtomicU64,
    waiting_since_ms: AtomicU64,
    send_timeout_ms: AtomicU64,
    path_stall_timeout_ms: AtomicU64,
    path_stalled: AtomicBool,
    telemetry_enabled: AtomicBool,
}

enum SendCompletion {
    Success,
    Timeout,
    Failure,
}

#[derive(Debug, Default)]
struct AdaptiveFlowProfile {
    connection_receive_floor: u64,
    stream_receive_floor: u64,
    send_floor: u64,
    last_connection_receive_adjust_ms: Option<u64>,
    last_stream_receive_adjust_ms: Option<u64>,
    last_send_adjust_ms: Option<u64>,
}

#[derive(Debug, Default)]
pub(crate) struct AdaptiveFlowProfiles(SyncMutex<[AdaptiveFlowProfile; 2]>);

#[derive(Debug, Default)]
struct QuicMetricTotals {
    sent_packets: AtomicU64,
    ack_frames: AtomicU64,
    lost_packets: AtomicU64,
    sent_plpmtud_probes: AtomicU64,
    lost_plpmtud_probes: AtomicU64,
    black_holes: AtomicU64,
    congestion_events: AtomicU64,
    flow_received_bytes: AtomicU64,
    flow_sent_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_datagrams: AtomicU64,
    rx_datagrams: AtomicU64,
    tx_ios: AtomicU64,
    rx_ios: AtomicU64,
    transport_tx_would_block: AtomicU64,
    transport_rx_drops: AtomicU64,
    transport_tx_drops: AtomicU64,
    session_rx_drops: AtomicU64,
    send_timeouts: AtomicU64,
    path_stalls: AtomicU64,
}

#[derive(Debug)]
struct QuicMetricEntry {
    stats: quinn::ConnectionStats,
}

#[derive(Debug, Default)]
struct QuicMetrics {
    entries: SyncMutex<HashMap<u64, QuicMetricEntry>>,
    next_id: AtomicU64,
    totals: QuicMetricTotals,
}

#[derive(Debug, Default)]
struct QuicMetricTracker {
    id: Option<u64>,
    closed_received_bytes: Option<u64>,
    finished: bool,
}

/// Caller-tunable options for [`client_config`]. Everything defaults to the
/// quinn/cubic behavior; protocol handlers override only what they need.
#[derive(Clone, Default)]
pub struct QuicClientOptions {
    /// Congestion controller; `None` = cubic. Use [`congestion_factory`] for
    /// named algorithms or [`BrutalConfig`] for hysteria2's fixed-rate sender.
    pub congestion: Option<Arc<dyn congestion::ControllerFactory + Send + Sync>>,
    /// QUIC keep-alive interval.
    pub keep_alive: Option<Duration>,
    /// Initial per-stream receive window, bytes.
    pub stream_receive_window: Option<u64>,
    /// Initial connection-level receive window, bytes.
    pub conn_receive_window: Option<u64>,
    /// Disable QUIC path MTU discovery.
    pub disable_mtu_discovery: bool,
    /// UDP payload size (NOT link MTU): applied as the send-side
    /// `initial_mtu` and the PMTUD upper bound; the endpoint's
    /// `max_udp_payload_size` (receive advertisement) is set separately by
    /// the protocol handler from the same node field.
    pub max_udp_payload_size: Option<u16>,
}

impl QuicClientOptions {
    /// Options with a named congestion controller (`cubic`/`new_reno`/`bbr`).
    pub fn with_congestion(name: Option<&str>) -> Self {
        Self {
            congestion: Some(congestion_factory(name)),
            ..Default::default()
        }
    }
}

/// Assemble a quinn [`ClientConfig`] for a proxy protocol.
///
/// - `alpn`: ALPN protocol list required by the protocol (TUIC: `tuic`,
///   Juicity/Hysteria2: `h3`).
/// - `options`: transport tuning, see [`QuicClientOptions`].
///
/// TLS is the BoringSSL backend in [`crate::quic::boring`] (Chrome fingerprint
/// when `tls_implementation = "utls"`, ECH when the node carries one —
/// static config, or DNS HTTPS-RR discovery when only `ech_enabled` is set,
/// pinSHA256 when `tls_pin_sha256` is set).
pub async fn client_config(
    node: &honk_config::node::Node,
    alpn: &[&[u8]],
    options: QuicClientOptions,
) -> anyhow::Result<ClientConfig> {
    let tls = node.tls().ok_or_else(|| {
        anyhow!(
            "node '{}' protocol '{}' has no QUIC TLS configuration",
            node.name,
            node.protocol().as_str()
        )
    })?;
    if !tls.alpn.is_empty() {
        return Err(honk_config::ConfigError::Validation(
            "TCP TLS ALPN is unsupported for QUIC; use protocol-specific ALPN".into(),
        )
        .into());
    }
    let alpn_wire = alpn
        .iter()
        .flat_map(|p| std::iter::once(p.len() as u8).chain(p.iter().copied()))
        .collect::<Vec<u8>>();
    let ech = match crate::tls::load_ech_config_list(node)? {
        Some(list) => Some(Arc::new(list)),
        None if tls.ech_enabled => {
            let name = tls.sni.clone().unwrap_or_else(|| node.host().to_string());
            crate::tls::discover_ech_config(&name).await.map(Arc::new)
        }
        None => None,
    };
    let pin_sha256 = tls
        .pin_sha256
        .as_deref()
        .map(|pin| {
            crate::tls::parse_pin_sha256(pin).ok_or_else(|| {
                anyhow!(
                    "node '{}': invalid tls_pin_sha256 (expected 64 hex chars)",
                    node.name
                )
            })
        })
        .transpose()?;
    let crypto =
        crate::quic::boring::BoringQuicClientConfig::new(crate::quic::boring::BoringQuicOptions {
            alpn_wire,
            skip_cert_verify: tls.skip_cert_verify,
            chrome: crate::tls::chrome_mode(),
            ech_config_list: ech,
            pin_sha256,
            ticket_key: Some(format!(
                "{}|{}|{}|{}",
                node.host(),
                node.port,
                tls.sni.clone().unwrap_or_else(|| node.host().to_string()),
                alpn.iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect::<Vec<_>>()
                    .join(","),
            )),
        })?;
    let mut cfg = ClientConfig::new(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport
        .congestion_controller_factory(
            options
                .congestion
                .unwrap_or_else(|| congestion_factory(None)),
        )
        .max_concurrent_uni_streams(VarInt::from_u32(4096));
    if let Some(w) = options.stream_receive_window {
        transport.stream_receive_window(VarInt::from_u64(w)?);
    }
    if let Some(w) = options.conn_receive_window {
        transport.receive_window(VarInt::from_u64(w)?);
    }
    if let Some(mtu) = options.max_udp_payload_size {
        let mtu = clamp_quic_payload_size(mtu);
        transport.initial_mtu(mtu);
        if !options.disable_mtu_discovery {
            let mut mtud = quinn::MtuDiscoveryConfig::default();
            mtud.upper_bound(mtu);
            transport.mtu_discovery_config(Some(mtud));
        }
    }
    if options.disable_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    if let Some(ka) = options.keep_alive {
        transport.keep_alive_interval(Some(ka));
    }
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) async fn recv_read_exact(recv: &mut RecvStream, buf: &mut [u8]) -> io::Result<()> {
    recv.read_exact(buf)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))
}

pub(crate) async fn survives_auth_close_window(conn: &Connection) -> bool {
    let wait = (2 * conn.rtt()).max(Duration::from_millis(2));
    tokio::select! {
        _ = conn.closed() => false,
        _ = tokio::time::sleep(wait) => conn.close_reason().is_none(),
    }
}

/// UDP fragment reassembly shared by the TUIC and Hysteria2 session bridges
/// (sing `udpDefragger` parity).
pub(crate) mod defrag;
#[cfg(test)]
mod path_health_tests;

struct TrackedConnection<C> {
    id: u64,
    connection: Connection,
    _endpoint: crate::runtime::RuntimeEndpoint,
    state: Weak<C>,
    monitor: Arc<QuicClientConnectionMonitor>,
}

struct State<C> {
    /// Lazily created endpoint, tagged with its address family. Recreated when
    /// the family of the resolved server address changes.
    endpoint: Option<(bool, crate::runtime::RuntimeEndpoint)>,
    conn: Option<(Connection, Arc<C>)>,
    connections: Vec<TrackedConnection<C>>,
    next_connection_id: u64,
    quality: Option<Arc<TransportQuality>>,

    /// Set by [`QuicClient::force_close`]: future dials fail instead of
    /// re-dialing into a closed client.
    closed: bool,
}

/// Per-server QUIC connection holder.
///
/// Keeps at most one active QUIC connection to the server and re-dials on
/// demand (first use, connection loss, or explicit [`QuicClient::invalidate`]).
/// **Rotation overlaps by construction**: a flow owns its `(Connection,
/// Arc<C>)` pair, so when the holder detects the connection's close reason
/// and dials a fresh one, in-flight streams/datagram flows finish on the
/// old connection while new flows land on the new one — one Active plus
/// one draining, without a hard cut. The generic `C` is the
/// protocol-specific per-connection state (demux maps, background task
/// handles, ...), built by the `setup` closure inside the single-flight
/// critical section so concurrent dialers share exactly one handshake.
pub struct QuicClient<C> {
    server_host: String,
    server_port: u16,
    server_name: String,
    config: ClientConfig,
    /// Optional custom endpoint constructor, called with the address family
    /// (`true` = IPv6) of the resolved server address. Hysteria2 uses this to
    /// run QUIC over a salamander-obfuscated socket; when unset the plain
    /// marked socket from [`client_endpoint`] is used.
    endpoint_factory: Option<Arc<dyn Fn(bool) -> io::Result<Endpoint> + Send + Sync>>,
    /// Advertised `max_udp_payload_size` cap for the default endpoint (see
    /// [`client_endpoint`] for the safe 1252 default).
    mtu: u16,
    flow_control_profiles: Arc<AdaptiveFlowProfiles>,
    state: Arc<Mutex<State<C>>>,
    task_scope: crate::runtime::TaskScope,
}
#[cfg(test)]
pub(crate) mod testutil;

#[cfg(test)]
mod brutal_tests;

#[cfg(test)]
mod client_tests;

// ---------------------------------------------------------------------------
// QUIC over a proxied UDP tunnel
// ---------------------------------------------------------------------------

mod packet_transport;

pub use packet_transport::{
    PacketTransportEndpoint, packet_transport_endpoint, packet_transport_endpoint_with_metrics,
    quic_handshake_probe,
};
