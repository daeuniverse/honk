//! Shared QUIC client plumbing for QUIC-based proxy protocols.
//!
//! Used by the TUIC v5, Juicity, and Hysteria2 outbounds.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow};
use bytes::Bytes;
use parking_lot::Mutex as SyncMutex;
use quinn::congestion;
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, RecvStream, SendStream, TransportConfig,
    VarInt,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tracing::{debug, warn};

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
        let bdp = self.rate as u128 * self.rtt.as_micros() / 1_000_000;
        bdp as u64
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
        metrics.pacing_rate = Some(self.rate * 8);
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

/// Caller-tunable options for [`client_config`]. Everything defaults to the
/// quinn/cubic behavior; protocol handlers override only what they need.
#[derive(Clone, Default)]
pub struct QuicClientOptions {
    /// Congestion controller; `None` = cubic. Use [`congestion_factory`] for
    /// named algorithms or [`BrutalConfig`] for hysteria2's fixed-rate sender.
    pub congestion: Option<Arc<dyn congestion::ControllerFactory + Send + Sync>>,
    /// QUIC keep-alive interval (Juicity uses 5s per the daeuniverse
    /// reference client; TUIC relies on its own heartbeat datagrams instead).
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
/// TLS is the BoringSSL backend in [`crate::quic_boring`] (Chrome fingerprint
/// when `tls_implementation = "utls"`, ECH when the node carries one —
/// static config, or DNS HTTPS-RR discovery when only `ech_enabled` is set,
/// pinSHA256 when `tls_pin_sha256` is set).
pub async fn client_config(
    node: &honk_config::node::Node,
    alpn: &[&[u8]],
    options: QuicClientOptions,
) -> anyhow::Result<ClientConfig> {
    let alpn_wire = alpn
        .iter()
        .flat_map(|p| std::iter::once(p.len() as u8).chain(p.iter().copied()))
        .collect::<Vec<u8>>();
    let ech = match crate::tls::load_ech_config_list(node)? {
        Some(list) => Some(Arc::new(list)),
        None if node.ech_enabled => {
            let name = node.sni.clone().unwrap_or_else(|| node.host().to_string());
            crate::tls::discover_ech_config(&name).await.map(Arc::new)
        }
        None => None,
    };
    let pin_sha256 = node
        .tls_pin_sha256
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
        crate::quic_boring::BoringQuicClientConfig::new(crate::quic_boring::BoringQuicOptions {
            alpn_wire,
            skip_cert_verify: node.skip_cert_verify,
            chrome: crate::tls::chrome_mode(),
            ech_config_list: ech,
            pin_sha256,
            // Tickets belong to a specific service, not a hostname:
            // address|port|SNI|ALPN — different protocols, different
            // servers behind one certificate, and reloaded configs never
            // cross-resume into each other.
            ticket_key: Some(format!(
                "{}|{}|{}|{}",
                node.host(),
                node.port,
                node.sni.clone().unwrap_or_else(|| node.host().to_string()),
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
        // Protocols like TUIC deliver inbound UDP packets on server-initiated
        // uni streams (one stream per packet) — allow a generous number
        // (sing-quic sets MaxIncomingUniStreams to 1<<60).
        .max_concurrent_uni_streams(VarInt::from_u32(4096));
    if let Some(w) = options.stream_receive_window {
        transport.stream_receive_window(VarInt::from_u64(w)?);
    }
    if let Some(w) = options.conn_receive_window {
        transport.receive_window(VarInt::from_u64(w)?);
    }
    if let Some(mtu) = options.max_udp_payload_size {
        // UDP payload size, not link MTU. Valid range per RFC 9000 (initial
        // packets must carry 1200) and quinn's cap; invalid values are
        // clamped rather than failing the first dial later.
        let mtu = mtu.clamp(1200, 65527);
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

/// Current unix time in seconds (0 on clock skew); used for the idle
/// accounting of shared connections.
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `RecvStream::read_exact` with quinn's error mapped to
/// `io::ErrorKind::UnexpectedEof` (protocol framing helpers return
/// `io::Result`).
pub(crate) async fn recv_read_exact(recv: &mut RecvStream, buf: &mut [u8]) -> io::Result<()> {
    recv.read_exact(buf)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))
}
/// Wait long enough for a server to reject zero-grace authentication after
/// the handshake. The final close check covers a close racing the timer.
pub(crate) async fn survives_auth_close_window(conn: &Connection) -> bool {
    let wait = (2 * conn.rtt()).max(Duration::from_millis(2));
    tokio::select! {
        _ = conn.closed() => false,
        _ = tokio::time::sleep(wait) => conn.close_reason().is_none(),
    }
}

/// UDP fragment reassembly shared by the TUIC and Hysteria2 session bridges
/// (sing `udpDefragger` parity).
pub(crate) mod defrag {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    /// Maximum pending fragmented packets kept for reassembly per session.
    const DEFRAG_MAX_PENDING: usize = 64;
    /// Maximum age of a pending fragmented packet before it is dropped.
    const DEFRAG_MAX_AGE: Duration = Duration::from_secs(10);

    /// Reassembly state for one fragmented packet.
    struct DefragBuffer {
        frags: Vec<Option<Vec<u8>>>,
        count: usize,
        updated: Instant,
    }

    /// Reassembles fragmented UDP packets, bounding memory by capping the
    /// number of pending packets and expiring stale ones.
    #[derive(Default)]
    pub(crate) struct Defragmenter {
        map: HashMap<u16, DefragBuffer>,
    }

    impl Defragmenter {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// Feed one fragment; returns the reassembled payload when the last
        /// missing fragment arrives. Unfragmented packets (`frag_total <= 1`)
        /// pass through immediately; invalid or duplicate fragments are
        /// dropped (`None`).
        pub(crate) fn feed(
            &mut self,
            packet_id: u16,
            frag_id: u8,
            frag_total: u8,
            data: Vec<u8>,
        ) -> Option<Vec<u8>> {
            if frag_total <= 1 {
                return Some(data);
            }
            if frag_id >= frag_total {
                return None;
            }
            let map = &mut self.map;
            if map.len() >= DEFRAG_MAX_PENDING && !map.contains_key(&packet_id) {
                map.retain(|_, b| b.updated.elapsed() < DEFRAG_MAX_AGE);
                if map.len() >= DEFRAG_MAX_PENDING {
                    return None;
                }
            }
            let frag_total = frag_total as usize;
            let entry = map.entry(packet_id).or_insert_with(|| DefragBuffer {
                frags: (0..frag_total).map(|_| None).collect(),
                count: 0,
                updated: Instant::now(),
            });
            if entry.frags.len() != frag_total {
                entry.frags = (0..frag_total).map(|_| None).collect();
                entry.count = 0;
            }
            let frag_id = frag_id as usize;
            if entry.frags[frag_id].is_some() {
                return None;
            }
            entry.frags[frag_id] = Some(data);
            entry.count += 1;
            entry.updated = Instant::now();
            if entry.count != entry.frags.len() {
                return None;
            }
            let entry = map.remove(&packet_id).expect("entry just inserted");
            let mut data = Vec::new();
            for frag in entry.frags.into_iter().flatten() {
                data.extend_from_slice(&frag);
            }
            Some(data)
        }
    }
}

/// Bind a non-blocking UDP socket with `SO_MARK` set so the local eBPF
/// datapath treats QUIC packets to the proxy server as control-plane traffic
/// and does not re-route them (same bypass as `util::udp_marked_bind`; QUIC
/// needs ownership of the raw socket, so it cannot reuse that helper).
///
/// Public so protocol handlers that wrap the socket themselves (Hysteria2's
/// salamander obfuscation) can reuse the same marking logic.
pub fn marked_udp_socket(ipv6: bool) -> io::Result<std::net::UdpSocket> {
    let bind_addr: SocketAddr = if ipv6 {
        "[::]:0".parse().expect("hardcoded IPv6 bind address")
    } else {
        "0.0.0.0:0".parse().expect("hardcoded IPv4 bind address")
    };
    crate::util::marked_udp_socket(bind_addr)
}

/// Create a client-only quinn [`Endpoint`] on a marked UDP socket for the
/// given address family.
///
/// The endpoint advertises `max_udp_payload_size = 1252` instead of quinn's
/// 1472: on PPPoE/tunneled last miles, larger downlink UDP datagrams are
/// silently black-holed (measured on a CN PPPoE line: ≤1260B echoes pass,
/// 1280B all lost), which kills every QUIC handshake whose ServerHello
/// flight exceeds the threshold. 1252 matches quic-go's default; going
/// lower (e.g. the RFC minimum 1200) shrinks the server's flight allowance
/// below its anti-amplification budget (3× the client Initial) and can
/// deadlock handshakes against large certificate chains.
pub fn client_endpoint(ipv6: bool) -> io::Result<Endpoint> {
    client_endpoint_with_mtu(ipv6, 1252)
}

fn default_gso_enabled(max_udp_payload_size: u16) -> bool {
    max_udp_payload_size > 1252
}
const MAX_QUIC_GSO_SEGMENTS: usize = 16;

fn gso_transmit_segments(enabled: bool, kernel_max: usize) -> usize {
    if enabled {
        kernel_max.min(MAX_QUIC_GSO_SEGMENTS)
    } else {
        1
    }
}

/// [`client_endpoint`] with an explicit advertised `max_udp_payload_size`.
///
/// An explicit MTU above the conservative 1252 default opts into UDP GSO:
/// the operator has already declared that the path carries larger datagrams.
/// `HONK_QUIC_GSO=0|1` overrides that policy process-wide.
pub fn client_endpoint_with_mtu(ipv6: bool, max_udp_payload_size: u16) -> io::Result<Endpoint> {
    let socket = marked_udp_socket(ipv6)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
    let io = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
    let inner = quinn::udp::UdpSocketState::new((&*io).into())?;
    static GSO_OVERRIDE: std::sync::LazyLock<Option<bool>> = std::sync::LazyLock::new(|| {
        std::env::var("HONK_QUIC_GSO")
            .ok()
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    });
    let gso = (*GSO_OVERRIDE).unwrap_or_else(|| default_gso_enabled(max_udp_payload_size));
    let socket = Arc::new(NoGsoUdpSocket { io, inner, gso });
    Endpoint::new_with_abstract_socket(
        endpoint_config_with_mtu(max_udp_payload_size)?,
        None,
        socket,
        runtime,
    )
}

/// EndpointConfig advertising `max_udp_payload_size` (see `client_endpoint`
/// for why 1252 is the safe default on PMTU-black-holed last miles).
pub(crate) fn endpoint_config_with_mtu(mtu: u16) -> io::Result<EndpointConfig> {
    let mut config = EndpointConfig::default();
    config.max_udp_payload_size(mtu).map_err(io::Error::other)?;
    Ok(config)
}

/// GSO policy. The safe 1252-byte default sends one datagram per syscall,
/// dodging PPPoE uplinks that drop later segments of a GSO super-packet.
/// Explicit larger MTUs enable batches capped at 16 segments because those
/// paths have already opted out of the black-hole-safe default.
/// `HONK_QUIC_GSO=0|1` forces either mode.
///
/// This is quinn's own `runtime/tokio.rs` socket with only
/// [`max_transmit_segments`](quinn::AsyncUdpSocket::max_transmit_segments)
/// made policy-driven; ECN, GRO receives, and pktinfo stay unchanged.
#[derive(Debug)]
struct NoGsoUdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: quinn::udp::UdpSocketState,
    gso: bool,
}

impl quinn::AsyncUdpSocket for NoGsoUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(NoGsoUdpPoller {
            socket: Arc::clone(&self.io),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        self.io.try_io(tokio::io::Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            std::task::ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(tokio::io::Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                Ok(res) => return Poll::Ready(Ok(res)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        gso_transmit_segments(self.gso, self.inner.max_gso_segments())
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

#[derive(Debug)]
struct NoGsoUdpPoller {
    socket: Arc<tokio::net::UdpSocket>,
}

impl quinn::UdpPoller for NoGsoUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

struct State<C> {
    /// Lazily created endpoint, tagged with its address family. Recreated when
    /// the family of the resolved server address changes.
    endpoint: Option<(bool, Endpoint)>,
    conn: Option<(Connection, Arc<C>)>,
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
    state: Mutex<State<C>>,
}

impl<C> QuicClient<C> {
    pub fn new(
        server_host: impl Into<String>,
        server_port: u16,
        server_name: impl Into<String>,
        config: ClientConfig,
    ) -> Self {
        Self {
            server_host: server_host.into(),
            server_port,
            server_name: server_name.into(),
            config,
            endpoint_factory: None,
            mtu: 1252,
            state: Mutex::new(State {
                endpoint: None,
                conn: None,
                closed: false,
            }),
        }
    }

    /// Advertise a larger `max_udp_payload_size` on paths known to carry it
    /// (anything but PMTU-black-holed last miles — see [`client_endpoint`]).
    /// Larger datagrams directly lower the per-packet processing cost that
    /// caps single-connection QUIC throughput (~180k pps at 1252B).
    pub fn with_max_udp_payload_size(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Use a custom endpoint constructor instead of [`client_endpoint`] (see
    /// the field docs). The factory is called once per address family and the
    /// resulting endpoint is cached like the default one.
    pub fn with_endpoint_factory(
        mut self,
        factory: impl Fn(bool) -> io::Result<Endpoint> + Send + Sync + 'static,
    ) -> Self {
        self.endpoint_factory = Some(Arc::new(factory));
        self
    }

    /// Return the shared connection (plus its protocol state), dialing and
    /// running `setup` first when there is no live connection.
    ///
    /// Resolved server addresses are raced until one completes the QUIC
    /// handshake; protocol setup runs exactly once for that winner.
    pub async fn connection_with<F, Fut>(
        &self,
        connect_timeout: Duration,
        setup: F,
    ) -> anyhow::Result<(Connection, Arc<C>)>
    where
        F: FnOnce(Connection) -> Fut,
        Fut: Future<Output = anyhow::Result<C>>,
    {
        let mut state = self.state.lock().await;
        if state.closed {
            anyhow::bail!("QUIC client is closed");
        }
        if let Some((conn, ctx)) = &state.conn
            && conn.close_reason().is_none()
        {
            return Ok((conn.clone(), Arc::clone(ctx)));
        }
        state.conn = None;

        let host = format!("{}:{}", self.server_host, self.server_port);
        let addrs: Vec<SocketAddr> = crate::bootstrap::resolve(&self.server_host)
            .await
            .with_context(|| format!("resolve {host}"))?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.server_port))
            .collect();
        if addrs.is_empty() {
            anyhow::bail!("resolve {host}: no addresses");
        }

        let cached_endpoint = state
            .endpoint
            .as_ref()
            .map(|(ipv6, endpoint)| (*ipv6, endpoint.clone()));
        let raced = crate::address_race::race_resolved_addrs(&addrs, |server_addr| {
            let ipv6 = server_addr.is_ipv6();
            let endpoint = cached_endpoint
                .as_ref()
                .filter(|(cached_ipv6, _)| *cached_ipv6 == ipv6)
                .map(|(_, endpoint)| endpoint.clone());
            async move {
                let endpoint = match endpoint {
                    Some(endpoint) => endpoint,
                    None => match &self.endpoint_factory {
                        Some(factory) => factory(ipv6),
                        None => client_endpoint_with_mtu(ipv6, self.mtu),
                    }
                    .with_context(|| format!("create QUIC endpoint (ipv6={ipv6})"))?,
                };
                let mut last_error = None;
                // Keep retries inside one address job: the shared scheduler
                // races addresses for this node, never protocol attempts or nodes.
                for attempt in 1..=3u8 {
                    let connecting = match endpoint.connect_with(
                        self.config.clone(),
                        server_addr,
                        &self.server_name,
                    ) {
                        Ok(connecting) => connecting,
                        Err(error) => return Err(error.into()),
                    };
                    match tokio::time::timeout(connect_timeout, connecting).await {
                        Err(_) => {
                            last_error = Some(anyhow!(
                                "QUIC connect to {server_addr} timed out (attempt {attempt})"
                            ));
                        }
                        Ok(Err(error)) => {
                            last_error = Some(anyhow!(
                                "QUIC connect to {server_addr}: {error} (attempt {attempt})"
                            ));
                        }
                        Ok(Ok(connection)) => return Ok((connection, endpoint, ipv6)),
                    }
                }
                Err(last_error.unwrap_or_else(|| anyhow!("QUIC connect to {server_addr} failed")))
            }
        })
        .await;
        let (conn, endpoint, ipv6) = match raced {
            Some(result) => result?,
            None => anyhow::bail!("resolve {host}: no addresses"),
        };
        state.endpoint = Some((ipv6, endpoint));
        let ctx = setup(conn.clone()).await.inspect_err(|_| {
            conn.close(VarInt::from_u32(0), b"setup failed");
        })?;
        let ctx = Arc::new(ctx);
        // The single-flight mutex makes this unreachable today; the guard
        // keeps a freshly dialed connection out of a closed client if the
        // critical section is ever narrowed.
        if state.closed {
            conn.close(VarInt::from_u32(0), b"generation shutdown");
            anyhow::bail!("QUIC client closed during dial");
        }
        state.conn = Some((conn.clone(), Arc::clone(&ctx)));
        Ok((conn, ctx))
    }

    /// Drop the cached connection if it is `conn`, forcing the next
    /// [`connection_with`](Self::connection_with) call to re-dial. Used when a
    /// stream operation fails on a half-dead connection.
    pub async fn invalidate(&self, conn: &Connection) {
        let mut state = self.state.lock().await;
        if let Some((cached, _)) = &state.conn
            && cached.stable_id() == conn.stable_id()
        {
            state.conn = None;
        }
    }

    /// Release the reusable holder without closing flows that already own
    /// connection/state clones. A later dial may rebuild this client.
    pub async fn release_cached(&self) {
        let mut state = self.state.lock().await;
        state.conn = None;
        state.endpoint = None;
    }

    /// Close the cached connection and endpoint, terminating every flow that
    /// still owns a connection clone, and reject future dials. Awaits an
    /// in-flight dial's single-flight section so its late connection is also
    /// closed; a try-lock skip would leak that connection and endpoint driver.
    pub async fn force_close(&self) {
        let mut state = self.state.lock().await;
        state.closed = true;
        if let Some((conn, _)) = state.conn.take() {
            conn.close(VarInt::from_u32(0), b"generation shutdown");
        }
        if let Some((_, endpoint)) = state.endpoint.take() {
            endpoint.close(VarInt::from_u32(0), b"generation shutdown");
        }
    }
}

/// A QUIC bidirectional stream as a single `AsyncRead + AsyncWrite` object.
///
/// Dropping the send half finishes the stream (sends FIN), which is what the
/// relay's half-close semantics rely on. The [`StreamDropGuard`] lets the
/// owning protocol track open-stream counts (for idle connection reaping)
/// without wrapping the stream again.
pub struct QuicBiStream {
    send: SendStream,
    recv: RecvStream,
    guard: StreamDropGuard,
}

/// Fires the registered callback when dropped. Lives inside
/// [`QuicBiStream`]; users that split the stream into its raw quinn halves
/// ([`QuicBiStream::into_parts`]) keep the guard for the same lifetime
/// accounting.
pub(crate) struct StreamDropGuard(Option<Box<dyn Fn() + Send + Sync>>);

impl Drop for StreamDropGuard {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

impl std::fmt::Debug for QuicBiStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicBiStream")
            .field("send", &self.send)
            .field("recv", &self.recv)
            .finish_non_exhaustive()
    }
}

impl QuicBiStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            guard: StreamDropGuard(None),
        }
    }

    /// Register a callback fired when this stream object is dropped.
    pub fn with_on_drop(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.guard.0 = Some(Box::new(f));
        self
    }

    /// Poll one cancellation-safe scatter write. `chunks` retains exactly the
    /// unsent suffix when progress is made.
    pub(crate) fn poll_write_chunks(
        &mut self,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        use std::future::Future;

        let result = std::pin::pin!(self.send.write_chunks(chunks)).poll(cx);
        result.map(|result| {
            result
                .map(|written| written.bytes)
                .map_err(io::Error::other)
        })
    }

    /// Split into the raw quinn halves plus the drop guard (open-stream
    /// accounting) — for users that drive the halves separately, e.g. UDP
    /// session bridges.
    pub(crate) fn into_parts(self) -> (SendStream, RecvStream, StreamDropGuard) {
        (self.send, self.recv, self.guard)
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Fully-qualified calls: quinn's inherent `poll_read`/`poll_write`
        // methods (different error types) would shadow the trait methods.
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

// ---------------------------------------------------------------------------
// Shared skeletons for the TUIC / Juicity / Hysteria2 protocol handlers
// ---------------------------------------------------------------------------

/// Per-connection state shared by the QUIC proxy handlers: the activity
/// bookkeeping used by the dial retry skeleton and the idle reaper.
pub(crate) trait QuicConnState: Send + Sync + 'static {
    /// Record activity on the connection (resets the idle reaper).
    fn touch(&self);
    /// Counter of open streams/bridges on this connection.
    fn open_counter(&self) -> &Arc<AtomicUsize>;
}

/// TUIC-style exporter authentication (sing `clientHandshake`,
/// `client.go:197-214`): one uni stream carrying
/// `[version, 0x00, uuid(16), token(32)]` where
/// `token = TLS ExportKeyingMaterial(label = uuid, context = password, 32)`.
/// Juicity reuses the same frame with version 0x00 and keeps the stream
/// open (`finish = false`); TUIC finishes it right after the write.
///
/// There is no positive auth acknowledgement: a server that rejects the
/// credentials closes the connection, so the call waits a brief `grace`
/// period for that to surface as a dial error here instead of a stream
/// failure on the first proxied connection. Returns the auth stream.
pub(crate) async fn exporter_auth(
    conn: &Connection,
    uuid: &[u8; 16],
    password: &str,
    version: u8,
    finish: bool,
    grace: Duration,
) -> anyhow::Result<SendStream> {
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|e| anyhow!("QUIC exporter auth: TLS keying material export failed: {e:?}"))?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.push(version);
    auth.push(0x00); // CMD_AUTHENTICATE
    auth.extend_from_slice(uuid);
    auth.extend_from_slice(&token);
    let mut stream = conn
        .open_uni()
        .await
        .context("QUIC exporter auth: open authenticate stream")?;
    stream
        .write_all(&auth)
        .await
        .context("QUIC exporter auth: send authenticate")?;
    if finish {
        stream
            .finish()
            .context("QUIC exporter auth: finish authenticate stream")?;
    }
    tokio::select! {
        e = conn.closed() => Err(anyhow!("QUIC exporter auth: connection closed during authentication: {e}")),
        _ = tokio::time::sleep(grace) => Ok(stream),
    }
}

/// Per-tick callback for [`spawn_conn_reaper`] (TUIC's heartbeat datagram);
/// returning false ends the reaper loop.
type ReaperTick = Box<dyn Fn(&Connection) -> bool + Send + 'static>;

/// Spawn the idle-connection reaper shared by the QUIC protocol handlers:
/// every `interval`, close the connection when the owning protocol state was
/// dropped ("state dropped") or when it has had no open streams/bridges for
/// `idle_timeout` ("idle"). `on_tick` runs after the liveness checks (TUIC's
/// heartbeat datagram); returning false ends the loop.
pub(crate) fn spawn_conn_reaper(
    conn: Connection,
    open: Weak<AtomicUsize>,
    last_activity: Weak<AtomicU64>,
    interval: Duration,
    idle_timeout: Duration,
    on_tick: Option<ReaperTick>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if conn.close_reason().is_some() {
                break;
            }
            let (Some(open), Some(last)) = (open.upgrade(), last_activity.upgrade()) else {
                // Protocol state dropped: nothing can use this connection.
                conn.close(VarInt::from_u32(0), b"state dropped");
                break;
            };
            let idle = now_secs().saturating_sub(last.load(Ordering::Relaxed));
            if open.load(Ordering::Relaxed) == 0 && idle > idle_timeout.as_secs() {
                conn.close(VarInt::from_u32(0), b"idle");
                break;
            }
            if let Some(on_tick) = &on_tick
                && !on_tick(&conn)
            {
                break;
            }
        }
    });
}

/// Shared TCP-over-QUIC dial skeleton (TUIC/Juicity/Hysteria2): get the
/// shared connection via `connect` (re-dialing when needed), run the
/// protocol's stream handshake (`make`), and retry once with a fresh
/// connection when the handshake fails on a half-dead cached connection and
/// `retryable` allows it (Hysteria2's server-side refusals are not
/// retryable). The returned stream decrements the connection's open counter
/// on drop.
pub(crate) async fn dial_quic_stream<S, Connect, Fut, Make, MakeFut>(
    client: &QuicClient<S>,
    connect: Connect,
    connect_timeout: Duration,
    make: Make,
    retryable: impl Fn(&anyhow::Error) -> bool,
    proto: &'static str,
) -> anyhow::Result<QuicBiStream>
where
    S: QuicConnState,
    Connect: Fn(Duration) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<(Connection, Arc<S>)>>,
    Make: Fn(Connection) -> MakeFut,
    MakeFut: std::future::Future<Output = anyhow::Result<(SendStream, RecvStream)>>,
{
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..2 {
        let (conn, state) = connect(connect_timeout).await?;
        state.touch();
        match make(conn.clone()).await {
            Ok((send, recv)) => {
                let open = Arc::clone(state.open_counter());
                open.fetch_add(1, Ordering::Relaxed);
                // The flow owns its `(Connection, Arc<S>)` pair: the guard
                // must hold the state, not just the open counter — a
                // dropped state makes the connection reaper kill the live
                // connection ("state dropped") under the stream.
                let stream = QuicBiStream::new(send, recv).with_on_drop(move || {
                    open.fetch_sub(1, Ordering::Relaxed);
                    let _state_kept_alive_under_this_stream = &state;
                });
                return Ok(stream);
            }
            Err(e) if retryable(&e) => {
                debug!("{proto}: stream open failed (attempt {attempt}): {e}");
                client.invalidate(&conn).await;
                last_err = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.expect("loop runs at least once"))
}

#[cfg(test)]
pub(crate) mod testutil {
    //! In-process QUIC test servers: self-signed certs plus endpoint builders
    //! shared by the TUIC and Juicity handler tests.

    use std::sync::Arc;

    use anyhow::anyhow;
    use quinn::{ServerConfig, TransportConfig};

    /// Build a quinn server config with a freshly generated self-signed
    /// certificate (valid for `localhost`) and the given ALPN list.
    ///
    /// When `datagrams` is false the server does not advertise QUIC datagram
    /// support, which exercises the UDP-over-stream fallback of clients.
    pub fn server_config(alpn: &[&[u8]], datagrams: bool) -> anyhow::Result<ServerConfig> {
        server_config_with_cert(alpn, datagrams).map(|(config, _)| config)
    }

    /// [`server_config`] that also returns the leaf certificate DER (for
    /// pinSHA256 tests).
    pub fn server_config_with_cert(
        alpn: &[&[u8]],
        datagrams: bool,
    ) -> anyhow::Result<(ServerConfig, Vec<u8>)> {
        server_config_impl(alpn, datagrams, false)
    }

    /// [`server_config`] restricted to TLS 1.3 ChaCha20-Poly1305, forcing the
    /// peer onto the ChaCha20 header-protection path.
    pub fn server_config_chacha20(alpn: &[&[u8]], datagrams: bool) -> anyhow::Result<ServerConfig> {
        server_config_impl(alpn, datagrams, true).map(|(config, _)| config)
    }

    fn server_config_impl(
        alpn: &[&[u8]],
        datagrams: bool,
        chacha20_only: bool,
    ) -> anyhow::Result<(ServerConfig, Vec<u8>)> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;

        let mut provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
        if chacha20_only {
            // ChaCha20 first so the handshake negotiates it; AES-128 stays
            // because quinn derives QUIC initial keys from it.
            provider.cipher_suites = vec![
                tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ];
        }
        let mut tls_config =
            tokio_rustls::rustls::ServerConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(|e| anyhow!("TLS protocol versions: {e}"))?
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                        signing_key.serialize_der().into(),
                    ),
                )
                .map_err(|e| anyhow!("TLS server config: {e}"))?;
        if chacha20_only {
            // rustls defaults to client order; honk's BoringSSL client offers
            // AES first, so the suite restriction alone is not enough.
            tls_config.ignore_client_order = true;
        }
        tls_config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();

        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| anyhow!("rustls server config is not QUIC-compatible: {e}"))?;
        let mut config = ServerConfig::with_crypto(Arc::new(quic_crypto));
        if !datagrams {
            let mut transport = TransportConfig::default();
            transport.datagram_receive_buffer_size(None);
            config.transport_config(Arc::new(transport));
        }
        Ok((config, cert.der().to_vec()))
    }

    /// Start a QUIC server endpoint on a loopback ephemeral port.
    pub fn server_endpoint(
        alpn: &[&[u8]],
        datagrams: bool,
    ) -> anyhow::Result<(quinn::Endpoint, std::net::SocketAddr)> {
        let endpoint = quinn::Endpoint::server(
            server_config(alpn, datagrams)?,
            "127.0.0.1:0".parse().expect("hardcoded bind address"),
        )?;
        let addr = endpoint.local_addr()?;
        Ok((endpoint, addr))
    }

    /// [`server_endpoint`] restricted to ChaCha20-Poly1305.
    pub fn server_endpoint_chacha20(
        alpn: &[&[u8]],
        datagrams: bool,
    ) -> anyhow::Result<(quinn::Endpoint, std::net::SocketAddr)> {
        let endpoint = quinn::Endpoint::server(
            server_config_chacha20(alpn, datagrams)?,
            "127.0.0.1:0".parse().expect("hardcoded bind address"),
        )?;
        let addr = endpoint.local_addr()?;
        Ok((endpoint, addr))
    }
}

#[cfg(test)]
mod brutal_tests {
    use super::*;
    use congestion::ControllerFactory;

    fn controller(rate_bps: u64) -> Box<dyn congestion::Controller> {
        Arc::new(BrutalConfig::from_bps(rate_bps)).build(Instant::now(), 1200)
    }

    #[test]
    fn window_is_rate_times_rtt() {
        let cc = controller(100_000_000);
        // Initial RTT guess 333ms: BDP = 12.5e6 × 0.333 ≈ 4.16 MB.
        let w = cc.window();
        assert!((4_000_000..4_400_000).contains(&w), "window {w}");
    }

    #[test]
    fn loss_never_shrinks_window() {
        let mut cc = controller(50_000_000);
        let before = cc.window();
        cc.on_congestion_event(Instant::now(), Instant::now(), true, 12000);
        cc.on_congestion_event(Instant::now(), Instant::now(), false, 0);
        assert_eq!(cc.window(), before);
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;
    #[test]
    fn explicit_large_mtu_enables_gso_by_default() {
        assert!(!default_gso_enabled(1252));
        assert!(default_gso_enabled(1253));
        assert!(default_gso_enabled(1452));
    }

    #[test]
    fn gso_batches_are_bounded() {
        assert_eq!(gso_transmit_segments(false, 64), 1);
        assert_eq!(gso_transmit_segments(true, 8), 8);
        assert_eq!(gso_transmit_segments(true, 64), MAX_QUIC_GSO_SEGMENTS);
    }

    #[tokio::test]
    async fn client_config_rejects_invalid_pin() {
        let node = honk_config::node::Node {
            name: "bad-pin".to_string(),
            tls_pin_sha256: Some("not-a-pin".to_string()),
            ..Default::default()
        };
        let error = match client_config(&node, &[b"h3"], QuicClientOptions::default()).await {
            Ok(_) => panic!("invalid pin must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("invalid tls_pin_sha256"));
    }

    #[tokio::test]
    async fn real_quic_loser_connection_closes_when_fallback_wins() {
        let (first_server, first_addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let (second_server, second_addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let first_closed = tokio::spawn(async move {
            let connection = first_server.accept().await.unwrap().await.unwrap();
            connection.closed().await
        });
        let second_accepted =
            tokio::spawn(async move { second_server.accept().await.unwrap().await.unwrap() });
        let node = honk_config::node::Node {
            name: "quic-address-race".to_string(),
            skip_cert_verify: true,
            ..Default::default()
        };
        let config = client_config(&node, &[b"h3"], QuicClientOptions::default())
            .await
            .unwrap();
        let endpoint = client_endpoint(false).unwrap();
        let first_connection = endpoint
            .connect_with(config.clone(), first_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let mut first_connection = Some(first_connection);
        let addrs = [first_addr, second_addr];

        let winner = crate::address_race::race_resolved_addrs_with_stagger(
            &addrs,
            Duration::from_millis(20),
            |addr| {
                let held = (addr == first_addr).then(|| {
                    first_connection
                        .take()
                        .expect("first address launched once")
                });
                let endpoint = endpoint.clone();
                let config = config.clone();
                async move {
                    if let Some(connection) = held {
                        let _connection = connection;
                        return std::future::pending::<anyhow::Result<Connection>>().await;
                    }
                    Ok(endpoint.connect_with(config, addr, "localhost")?.await?)
                }
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(winner.remote_address(), second_addr);

        let second_connection = tokio::time::timeout(Duration::from_secs(1), second_accepted)
            .await
            .expect("winning QUIC handshake did not reach the server")
            .unwrap();
        let _closed = tokio::time::timeout(Duration::from_secs(1), first_closed)
            .await
            .expect("losing QUIC connection stayed open")
            .unwrap();
        winner.close(VarInt::from_u32(0), b"test complete");
        drop(second_connection);
        endpoint.close(VarInt::from_u32(0), b"test complete");
    }

    async fn test_client(port: u16) -> QuicClient<()> {
        let node = honk_config::node::Node {
            name: "quic-test".to_string(),
            host: "127.0.0.1".to_string(),
            address: format!("127.0.0.1:{port}"),
            port,
            skip_cert_verify: true,
            ..Default::default()
        };
        let config = client_config(&node, &[b"h3"], QuicClientOptions::default())
            .await
            .unwrap();
        QuicClient::new("127.0.0.1", port, "localhost", config)
    }

    fn spawn_accept_loop(endpoint: Endpoint) {
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let _ = incoming.await;
                });
            }
        });
    }

    #[tokio::test]
    async fn dead_warm_quic_reconnect_waits_for_limit_one() {
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let client = Arc::new(test_client(addr.port()).await);
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
                .unwrap()
                .0,
        );
        let first_accept = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { endpoint.accept().await.unwrap().await.unwrap() }
        });
        let (first, _) = generation
            .scope_dials(client.connection_with(Duration::from_secs(1), |_| async {
                Ok::<(), anyhow::Error>(())
            }))
            .await
            .unwrap();
        let first_server = first_accept.await.unwrap();
        first.close(VarInt::from_u32(0), b"replace");
        client.invalidate(&first).await;

        let held = generation.acquire_dial_permit().await;
        let reconnect = tokio::spawn({
            let client = Arc::clone(&client);
            let generation = Arc::clone(&generation);
            async move {
                generation
                    .scope_dials(client.connection_with(Duration::from_secs(1), |_| async {
                        Ok::<(), anyhow::Error>(())
                    }))
                    .await
            }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), endpoint.accept())
                .await
                .is_err(),
            "dead cached QUIC reconnect bypassed the physical dial limit"
        );

        drop(held);
        let incoming = tokio::time::timeout(Duration::from_secs(1), endpoint.accept())
            .await
            .expect("admitted QUIC reconnect sent no Initial")
            .expect("server endpoint closed");
        let second_accept = tokio::spawn(async move { incoming.await.unwrap() });
        let (second, _) = tokio::time::timeout(Duration::from_secs(1), reconnect)
            .await
            .expect("admitted QUIC reconnect did not finish")
            .unwrap()
            .unwrap();
        let second_server = second_accept.await.unwrap();

        second.close(VarInt::from_u32(0), b"test complete");
        client.force_close().await;
        endpoint.close(VarInt::from_u32(0), b"test complete");
        drop((first_server, second_server));
    }

    #[tokio::test]
    async fn force_close_covers_connection_cached_by_in_flight_dial() {
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        spawn_accept_loop(endpoint);
        let client = Arc::new(test_client(addr.port()).await);

        // Park the dial inside its setup closure: it holds the single-flight
        // state lock with the handshake already completed.
        let (setup_entered, entered) = tokio::sync::oneshot::channel::<()>();
        let (release_setup, release) = tokio::sync::oneshot::channel::<()>();
        let dial = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                client
                    .connection_with(Duration::from_secs(5), move |_conn| async move {
                        let _ = setup_entered.send(());
                        let _ = release.await;
                        Ok::<(), anyhow::Error>(())
                    })
                    .await
            }
        });
        entered.await.unwrap();

        let closer = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.force_close().await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !closer.is_finished(),
            "force_close must wait out the in-flight dial"
        );

        let _ = release_setup.send(());
        let (conn, _) = dial.await.unwrap().unwrap();
        closer.await.unwrap();
        assert!(
            conn.close_reason().is_some(),
            "a connection cached just before the close must still be closed"
        );
        assert!(
            client
                .connection_with(Duration::from_secs(1), |_conn| async {
                    Ok::<(), anyhow::Error>(())
                })
                .await
                .is_err(),
            "a closed client rejects new dials"
        );
    }

    #[tokio::test]
    async fn release_cached_keeps_client_reusable_for_a_fresh_connection() {
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        spawn_accept_loop(endpoint);
        let client = test_client(addr.port()).await;
        let (first, _) = client
            .connection_with(Duration::from_secs(5), |_conn| async {
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap();

        client.release_cached().await;
        let state = client.state.lock().await;
        assert!(state.conn.is_none());
        assert!(!state.closed);
        drop(state);

        let (second, _) = client
            .connection_with(Duration::from_secs(5), |_conn| async {
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap();
        assert_ne!(first.stable_id(), second.stable_id());
        client.force_close().await;
    }

    /// A cold-node health probe dials QUIC through an ephemeral runtime;
    /// closing it must deterministically close the cached connection and
    /// endpoint driver (drop-alone is not relied upon).
    struct ProbeClient(QuicClient<()>);
    #[async_trait::async_trait]
    impl crate::runtime::QuicRuntimeClient for ProbeClient {
        fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
            self
        }
        async fn force_close(&self) {
            self.0.force_close().await;
        }
        async fn release_warm(&self) {
            self.0.release_cached().await;
        }
    }

    fn tuic_ephemeral() -> Arc<crate::runtime::NodeRuntime> {
        crate::runtime::NodeRuntime::ephemeral(&honk_config::node::Node {
            protocol: honk_config::types::NodeProtocol::Tuic,
            ..Default::default()
        })
    }

    async fn probe_client(
        runtime: &crate::runtime::NodeRuntime,
        port: u16,
    ) -> (Arc<ProbeClient>, quinn::Connection) {
        let crate::runtime::ProtocolRuntime::Quic(quic) = &runtime.runtime else {
            panic!("tuic runtime expected");
        };
        let client: Arc<ProbeClient> = quic
            .client(|| async { Ok(Arc::new(ProbeClient(test_client(port).await))) })
            .await
            .unwrap();
        let (conn, _) = client
            .0
            .connection_with(Duration::from_secs(5), |_conn| async {
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap();
        (client, conn)
    }

    #[tokio::test]
    async fn ephemeral_runtime_close_shuts_quic_client() {
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        spawn_accept_loop(endpoint);
        let runtime = tuic_ephemeral();
        let (_client, conn) = probe_client(&runtime, addr.port()).await;
        assert!(conn.close_reason().is_none());
        assert!(runtime.is_warm_or_stateless());

        runtime.close().await;
        assert!(
            conn.close_reason().is_some(),
            "closing the ephemeral runtime must close the probe connection"
        );
        assert!(
            !runtime.is_warm_or_stateless(),
            "a closed runtime no longer reports warm clients"
        );
    }

    /// A probe future dropped mid-flight (outer timeout / task abort) never
    /// runs the explicit close; the guard's Drop must still close the cached
    /// connection and endpoint driver.
    #[tokio::test]
    async fn ephemeral_guard_releases_quic_client_when_probe_is_aborted() {
        use crate::runtime::NodeRuntime;

        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        spawn_accept_loop(endpoint);
        let (conn_tx, conn_rx) = tokio::sync::oneshot::channel();
        let probe = tokio::spawn(async move {
            let guard = NodeRuntime::ephemeral_guarded(&honk_config::node::Node {
                protocol: honk_config::types::NodeProtocol::Tuic,
                ..Default::default()
            });
            let runtime = guard.runtime();
            let (_client, conn) = probe_client(&runtime, addr.port()).await;
            let _ = conn_tx.send(conn);
            std::future::pending::<()>().await;
        });
        let conn = conn_rx.await.unwrap();
        probe.abort();
        let _ = probe.await;

        tokio::time::timeout(Duration::from_secs(5), async {
            while conn.close_reason().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the guard Drop must drive the QUIC close after abort");
    }
}

// ---------------------------------------------------------------------------
// QUIC over a proxied UDP tunnel
// ---------------------------------------------------------------------------

use crate::proxy::{PacketErrorClass, PacketTransport, packet_error_class};

/// quinn [`AsyncUdpSocket`] over a framed [`PacketTransport`]: outbound
/// datagrams ride a bounded channel drained by a forwarder task (the
/// transport's async send cannot run in a poll context), while inbound
/// datagrams are accepted only from the configured QUIC peer.
const TRANSPORT_QUEUE_CAP: usize = 64;

#[derive(Debug)]
struct TransportIoError {
    kind: io::ErrorKind,
    message: String,
}

impl TransportIoError {
    fn new(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn fatal(error: io::Error) -> Self {
        let mut error = Self::new(error);
        // Quinn deliberately ignores UDP ECONNRESET on its receive path, but
        // every worker error exposed here has already terminated the adapter.
        if error.kind == io::ErrorKind::ConnectionReset {
            error.kind = io::ErrorKind::ConnectionAborted;
        }
        error
    }

    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

type SharedRecvWaker = Arc<SyncMutex<Option<Waker>>>;

fn wake_recv(waker: &SharedRecvWaker) {
    let waker = waker.lock().take();
    if let Some(waker) = waker {
        waker.wake();
    }
}
type SharedTransportError = Arc<SyncMutex<Option<TransportIoError>>>;

#[derive(Debug)]
struct TransportQuinnSocket {
    remote: SocketAddr,
    outbound: tokio::sync::mpsc::Sender<Vec<u8>>,
    inbound: SyncMutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    send_error: SharedTransportError,
    recv_error: SharedTransportError,
    recv_waker: SharedRecvWaker,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl TransportQuinnSocket {
    fn new(transport: Arc<dyn PacketTransport>, remote: SocketAddr) -> Arc<Self> {
        let (outbound_tx, mut outbound_rx) =
            tokio::sync::mpsc::channel::<Vec<u8>>(TRANSPORT_QUEUE_CAP);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(TRANSPORT_QUEUE_CAP);
        let send_error = Arc::new(SyncMutex::new(None));
        let recv_error = Arc::new(SyncMutex::new(None));
        let recv_waker = Arc::new(SyncMutex::new(None));
        let sender = tokio::spawn({
            let transport = Arc::clone(&transport);
            let send_error = Arc::clone(&send_error);
            let recv_waker = Arc::clone(&recv_waker);
            async move {
                let mut first_datagram = true;
                while let Some(data) = outbound_rx.recv().await {
                    let result = if first_datagram {
                        transport.send_packet_confirmed(&data).await
                    } else {
                        transport.send_packet(&data).await
                    };
                    match result {
                        Ok(()) => first_datagram = false,
                        Err(error) => {
                            let congestion = packet_error_class(&error)
                                == PacketErrorClass::Congestion
                                || (error.kind() == io::ErrorKind::TimedOut
                                    && transport.send_timeout_is_congestion());
                            if congestion {
                                continue;
                            }
                            *send_error.lock() = Some(TransportIoError::fatal(error));
                            wake_recv(&recv_waker);
                            outbound_rx.close();
                            return;
                        }
                    }
                }
            }
        });
        let allows_full_cone_replies = transport.allows_full_cone_replies();
        let receiver = tokio::spawn({
            let recv_error = Arc::clone(&recv_error);
            let recv_waker = Arc::clone(&recv_waker);
            async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let (n, source) = match transport.recv_packet(&mut buf).await {
                        Ok(packet) => packet,
                        Err(error) => {
                            *recv_error.lock() = Some(TransportIoError::fatal(error));
                            wake_recv(&recv_waker);
                            return;
                        }
                    };
                    if n == 0 {
                        continue;
                    }
                    if source != remote && !allows_full_cone_replies {
                        continue;
                    }
                    if n > buf.len() {
                        *recv_error.lock() = Some(TransportIoError::fatal(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "PacketTransport returned a datagram larger than its receive buffer",
                        )));
                        wake_recv(&recv_waker);
                        return;
                    }
                    // A full queue drops the datagram (UDP semantics); the
                    // transport read must never backpressure or allocate for a drop.
                    if let Ok(permit) = inbound_tx.try_reserve() {
                        permit.send(buf[..n].to_vec());
                    }
                }
            }
        });
        Arc::new(Self {
            remote,
            outbound: outbound_tx,
            inbound: SyncMutex::new(inbound_rx),
            send_error,
            recv_error,
            recv_waker,
            tasks: Mutex::new(vec![sender, receiver]),
        })
    }

    fn send_error(&self) -> Option<io::Error> {
        self.send_error
            .lock()
            .as_ref()
            .map(TransportIoError::to_io_error)
    }

    fn recv_error(&self) -> Option<io::Error> {
        self.recv_error
            .lock()
            .as_ref()
            .map(TransportIoError::to_io_error)
    }

    fn terminal_error(&self) -> Option<io::Error> {
        self.recv_error().or_else(|| self.send_error())
    }

    async fn close_tasks(&self) {
        let mut tasks = self.tasks.lock().await;
        for task in tasks.iter() {
            task.abort();
        }
        for task in tasks.iter_mut() {
            let _ = task.await;
        }
        tasks.clear();
    }

    fn abort_tasks(&self) {
        if let Ok(tasks) = self.tasks.try_lock() {
            for task in tasks.iter() {
                task.abort();
            }
        }
    }
}

impl Drop for TransportQuinnSocket {
    fn drop(&mut self) {
        for task in self.tasks.get_mut().drain(..) {
            task.abort();
        }
    }
}

type TransportSendPermit =
    Result<tokio::sync::mpsc::OwnedPermit<Vec<u8>>, tokio::sync::mpsc::error::SendError<()>>;

struct TransportUdpPoller {
    socket: Arc<TransportQuinnSocket>,
    writable: SyncMutex<Option<Pin<Box<dyn Future<Output = TransportSendPermit> + Send>>>>,
}

impl std::fmt::Debug for TransportUdpPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportUdpPoller").finish_non_exhaustive()
    }
}

impl quinn::UdpPoller for TransportUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.socket.send_error() {
            *this.writable.lock() = None;
            return Poll::Ready(Err(error));
        }

        let mut writable = this.writable.lock();
        if writable.is_none() {
            *writable = Some(Box::pin(this.socket.outbound.clone().reserve_owned()));
        }
        match writable.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(permit)) => {
                drop(permit);
                *writable = None;
                Poll::Ready(this.socket.send_error().map_or(Ok(()), Err))
            }
            Poll::Ready(Err(_)) => {
                *writable = None;
                Poll::Ready(Err(this
                    .socket
                    .send_error()
                    .unwrap_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))))
            }
        }
    }
}

impl quinn::AsyncUdpSocket for TransportQuinnSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(TransportUdpPoller {
            socket: self,
            writable: SyncMutex::new(None),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        if transmit.destination != self.remote {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PacketTransport QUIC destination does not match its peer",
            ));
        }
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PacketTransport QUIC does not support segmented transmits",
            ));
        }
        if let Some(error) = self.send_error() {
            return Err(error);
        }

        match self.outbound.try_reserve() {
            Ok(permit) => {
                permit.send(transmit.contents.to_vec());
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(self
                .send_error()
                .unwrap_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.terminal_error() {
            return Poll::Ready(Err(error));
        }
        *self.recv_waker.lock() = Some(cx.waker().clone());
        if let Some(error) = self.terminal_error() {
            return Poll::Ready(Err(error));
        }

        let mut inbound = self.inbound.lock();
        let mut count = 0;
        for (buf, meta_slot) in bufs.iter_mut().zip(meta.iter_mut()) {
            match inbound.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    // quic-go may coalesce a 1280-byte first flight despite the
                    // 1252-byte advertisement. Preserve complete leading packets
                    // as a bounded native UDP receive would; Quinn discards a
                    // truncated tail and requests retransmission.
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    *meta_slot = quinn::udp::RecvMeta {
                        addr: self.remote,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    count += 1;
                }
                Poll::Ready(None) => {
                    return if count == 0 {
                        Poll::Ready(Err(self
                            .terminal_error()
                            .unwrap_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))))
                    } else {
                        Poll::Ready(Ok(count))
                    };
                }
                Poll::Pending => {
                    return if count == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(count))
                    };
                }
            }
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // There is no kernel socket; quinn uses this only to validate the
        // endpoint's address family.
        let ip: std::net::IpAddr = match self.remote {
            SocketAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
            SocketAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
        };
        Ok(SocketAddr::new(ip, 0))
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

/// Owns a client-only quinn endpoint and the bounded [`PacketTransport`]
/// adapter workers that drive it.
#[derive(Debug)]
pub struct PacketTransportEndpoint {
    endpoint: Endpoint,
    socket: Arc<TransportQuinnSocket>,
}

impl PacketTransportEndpoint {
    /// Borrow the Quinn endpoint. Keep this owner alive as long as any
    /// connection opened from it can still perform I/O.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Close the Quinn endpoint and wait up to `timeout` for it to drain.
    /// A zero timeout aborts the adapter workers without waiting; other closes
    /// abort and join them. Repeated and cancelled closes are safe.
    pub async fn close(&self, timeout: Duration) {
        self.endpoint.close(VarInt::from_u32(0), b"shutdown");
        if timeout.is_zero() {
            self.socket.abort_tasks();
            return;
        }
        let _ = tokio::time::timeout(timeout, self.endpoint.wait_idle()).await;
        self.socket.close_tasks().await;
    }
}

impl Drop for PacketTransportEndpoint {
    fn drop(&mut self) {
        self.socket.abort_tasks();
    }
}

/// Create a [`PacketTransportEndpoint`] pinned to `remote` with the safe
/// 1252-byte UDP payload cap.
pub fn packet_transport_endpoint(
    transport: Arc<dyn PacketTransport>,
    remote: SocketAddr,
) -> io::Result<PacketTransportEndpoint> {
    if transport.relay_addr() != remote {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PacketTransport relay address does not match the QUIC peer",
        ));
    }
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
    let socket = TransportQuinnSocket::new(transport, remote);
    let endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config_with_mtu(1252)?,
        None,
        socket.clone(),
        runtime,
    )?;
    Ok(PacketTransportEndpoint { endpoint, socket })
}

/// Establish a QUIC connection through a proxied UDP tunnel and time the
/// handshake.  This is the real QUIC liveness probe: unlike a bare
/// Version-Negotiation trigger (which many frontends ignore), it proves
/// TLS-in-QUIC reachability through the node's UDP path.  `config` comes from
/// [`client_config`] — pass a node with `skip_cert_verify` for pure liveness
/// probing.
pub async fn quic_handshake_probe(
    transport: Arc<dyn PacketTransport>,
    target: SocketAddr,
    server_name: &str,
    config: &ClientConfig,
    timeout: Duration,
) -> anyhow::Result<Duration> {
    let endpoint = packet_transport_endpoint(transport, target)?;

    let start = Instant::now();
    let connecting = endpoint
        .endpoint()
        .connect_with(config.clone(), target, server_name)
        .context("create QUIC connecting")?;
    let conn = tokio::time::timeout(timeout, connecting)
        .await
        .context("QUIC handshake timeout")??;
    let elapsed = start.elapsed();
    conn.close(quinn::VarInt::from_u32(0), b"probe");
    // `wait_idle` cannot complete while this handle is still alive.
    drop(conn);
    endpoint.close(Duration::ZERO).await;
    Ok(elapsed)
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    #[derive(Debug)]
    struct SendFailedPacketTransport;

    #[async_trait::async_trait]
    impl PacketTransport for SendFailedPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            "127.0.0.1:443".parse().unwrap()
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        }

        async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct ReceiveFailedPacketTransport;

    #[async_trait::async_trait]
    impl PacketTransport for ReceiveFailedPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            "127.0.0.1:443".parse().unwrap()
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }

        async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        }
    }

    #[derive(Debug)]
    struct AdmissionPacketTransport {
        confirmed: AtomicUsize,
        ordinary: AtomicUsize,
        ordinary_sent: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl PacketTransport for AdmissionPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            "127.0.0.1:443".parse().unwrap()
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            self.ordinary.fetch_add(1, Ordering::SeqCst);
            self.ordinary_sent.notify_one();
            Ok(())
        }

        async fn send_packet_confirmed(&self, _data: &[u8]) -> io::Result<()> {
            self.confirmed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct CongestedPacketTransport {
        sends: AtomicUsize,
        sent_after_congestion: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl PacketTransport for CongestedPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            "127.0.0.1:443".parse().unwrap()
        }

        fn send_timeout_is_congestion(&self) -> bool {
            true
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            if self.sends.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(io::Error::from(io::ErrorKind::TimedOut))
            } else {
                self.sent_after_congestion.notify_one();
                Ok(())
            }
        }

        async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct SequencePacketTransport {
        remote: SocketAddr,
        packets: Mutex<std::collections::VecDeque<(Vec<u8>, SocketAddr)>>,
        full_cone: bool,
    }

    #[async_trait::async_trait]
    impl PacketTransport for SequencePacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            self.remote
        }

        fn allows_full_cone_replies(&self) -> bool {
            self.full_cone
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }

        async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let Some((packet, source)) = self.packets.lock().await.pop_front() else {
                return std::future::pending().await;
            };
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok((len, source))
        }
    }

    #[derive(Debug)]
    struct UdpPacketTransport {
        socket: tokio::net::UdpSocket,
        remote: SocketAddr,
    }

    #[async_trait::async_trait]
    impl PacketTransport for UdpPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            self.remote
        }

        async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
            self.socket.send(data).await?;
            Ok(())
        }

        async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Ok((self.socket.recv(buf).await?, self.remote))
        }
    }

    #[tokio::test]
    async fn packet_transport_failures_surface() {
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let transmit = quinn::udp::Transmit {
            destination: remote,
            ecn: None,
            contents: b"initial",
            segment_size: None,
            src_ip: None,
        };
        let send_socket = TransportQuinnSocket::new(Arc::new(SendFailedPacketTransport), remote);
        quinn::AsyncUdpSocket::try_send(&*send_socket, &transmit).unwrap();

        let mut data = [0; 64];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let send_error = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                let mut bufs = [std::io::IoSliceMut::new(&mut data)];
                quinn::AsyncUdpSocket::poll_recv(&*send_socket, cx, &mut bufs, &mut meta)
            }),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(send_error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            quinn::AsyncUdpSocket::try_send(&*send_socket, &transmit)
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionAborted
        );

        let recv_socket = TransportQuinnSocket::new(Arc::new(ReceiveFailedPacketTransport), remote);
        let recv_error = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                let mut bufs = [std::io::IoSliceMut::new(&mut data)];
                quinn::AsyncUdpSocket::poll_recv(&*recv_socket, cx, &mut bufs, &mut meta)
            }),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(recv_error.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn packet_transport_congestion_drops_only_one_datagram() {
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let transport = Arc::new(CongestedPacketTransport {
            sends: AtomicUsize::new(0),
            sent_after_congestion: tokio::sync::Notify::new(),
        });
        let socket = TransportQuinnSocket::new(transport.clone(), remote);
        for contents in [b"dropped".as_slice(), b"forwarded".as_slice()] {
            quinn::AsyncUdpSocket::try_send(
                &*socket,
                &quinn::udp::Transmit {
                    destination: remote,
                    ecn: None,
                    contents,
                    segment_size: None,
                    src_ip: None,
                },
            )
            .unwrap();
        }

        tokio::time::timeout(
            Duration::from_secs(1),
            transport.sent_after_congestion.notified(),
        )
        .await
        .unwrap();
        assert_eq!(transport.sends.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn packet_transport_confirms_only_the_first_datagram() {
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let transport = Arc::new(AdmissionPacketTransport {
            confirmed: AtomicUsize::new(0),
            ordinary: AtomicUsize::new(0),
            ordinary_sent: tokio::sync::Notify::new(),
        });
        let socket = TransportQuinnSocket::new(transport.clone(), remote);
        for contents in [b"first".as_slice(), b"second".as_slice()] {
            quinn::AsyncUdpSocket::try_send(
                &*socket,
                &quinn::udp::Transmit {
                    destination: remote,
                    ecn: None,
                    contents,
                    segment_size: None,
                    src_ip: None,
                },
            )
            .unwrap();
        }

        tokio::time::timeout(Duration::from_secs(1), transport.ordinary_sent.notified())
            .await
            .unwrap();
        assert_eq!(transport.confirmed.load(Ordering::SeqCst), 1);
        assert_eq!(transport.ordinary.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn packet_transport_socket_is_peer_pinned_and_family_matched() {
        let remote: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let wrong: SocketAddr = "[2001:db8::3]:443".parse().unwrap();
        let socket = TransportQuinnSocket::new(
            Arc::new(SequencePacketTransport {
                remote,
                full_cone: false,
                packets: Mutex::new(std::collections::VecDeque::from([
                    (b"wrong".to_vec(), wrong),
                    (vec![0x5a; 65], remote),
                ])),
            }),
            remote,
        );
        assert!(
            quinn::AsyncUdpSocket::local_addr(&*socket)
                .unwrap()
                .is_ipv6()
        );

        let error = quinn::AsyncUdpSocket::try_send(
            &*socket,
            &quinn::udp::Transmit {
                destination: wrong,
                ecn: None,
                contents: b"wrong peer",
                segment_size: None,
                src_ip: None,
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let mut data = [0; 64];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let received = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                let mut bufs = [std::io::IoSliceMut::new(&mut data)];
                quinn::AsyncUdpSocket::poll_recv(&*socket, cx, &mut bufs, &mut meta)
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, 1);
        assert_eq!(meta[0].len, data.len());
        assert_eq!(data, [0x5a; 64]);
        assert_eq!(meta[0].addr, remote);
    }

    #[tokio::test]
    async fn packet_transport_socket_accepts_full_cone_reply_metadata() {
        let remote: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let reply_source: SocketAddr = "[2001:db8::3]:443".parse().unwrap();
        let socket = TransportQuinnSocket::new(
            Arc::new(SequencePacketTransport {
                remote,
                packets: Mutex::new(std::collections::VecDeque::from([(
                    b"accepted".to_vec(),
                    reply_source,
                )])),
                full_cone: true,
            }),
            remote,
        );
        let mut data = [0; 64];
        let mut meta = [quinn::udp::RecvMeta::default()];

        let received = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                let mut bufs = [std::io::IoSliceMut::new(&mut data)];
                quinn::AsyncUdpSocket::poll_recv(&*socket, cx, &mut bufs, &mut meta)
            }),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(received, 1);
        assert_eq!(&data[..meta[0].len], b"accepted");
        assert_eq!(meta[0].addr, remote);
    }

    #[tokio::test]
    async fn handshake_crosses_packet_transport_adapter() {
        let (server, remote) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let server_task = tokio::spawn(async move {
            server.accept().await.unwrap().await.unwrap();
        });
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(remote).await.unwrap();
        let node = honk_config::node::Node {
            sni: Some("localhost".into()),
            skip_cert_verify: true,
            ..Default::default()
        };
        let config = client_config(&node, &[b"h3"], QuicClientOptions::default())
            .await
            .unwrap();

        quic_handshake_probe(
            Arc::new(UdpPacketTransport { socket, remote }),
            remote,
            "localhost",
            &config,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }
}
