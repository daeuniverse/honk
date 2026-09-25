//! Outbound dialer management — alive detection and recovery state.

pub mod collection;
mod health;
pub mod latencies;
mod probe;
mod urltest;

#[cfg(test)]
mod tests;

use self::collection::DialerCollection;
use crate::group::{ScoreFeedback, ScoreSelectionContext};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

type ScoreFeedbackFactory =
    Arc<dyn Fn(Uuid, ScoreSelectionContext) -> Option<ScoreFeedback> + Send + Sync>;

/// Per-(node, check_url) probe state for URLTest groups with a custom
/// `check_url` (sing-box urltest `url` option). Deliberately simpler than
/// [`PerProtocolState`]: TCP-only, no traffic counters, no permanent stop
/// (deep backoff keeps probing on the max-cooldown cadence, same as the
/// global probe path).
#[derive(Debug, Clone)]
struct UrlProbeState {
    alive: bool,
    consecutive_failures: u32,
    consecutive_successes: u32,
    cooldown_until: Instant,
}

impl UrlProbeState {
    fn new() -> Self {
        Self {
            alive: true,
            consecutive_failures: 0,
            consecutive_successes: 0,
            cooldown_until: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeDomain {
    Tcp = 0,
    DnsUdp = 1,
    DataUdp = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    V4 = 0,
    V6 = 1,
}

impl ProbeDomain {
    pub const fn count() -> usize {
        3
    }
}
impl IpVersion {
    pub const fn count() -> usize {
        2
    }
}

pub const ALIVE_STATES_PER_NODE: usize = ProbeDomain::count() * IpVersion::count();

/// Maximum number of consecutive probe failures before permanent backoff stop.
/// Matches Go's `maxProbeBackoffFailures`.
const MAX_PROBE_BACKOFF_FAILURES: u32 = 10;

/// Number of consecutive successful probes needed to revive a dead node.
/// Prevents transient success (e.g. a TCP SYN accepted but proxy handshake
/// rejected) from immediately marking a dead node as alive.
const RECOVERY_SUCCESSES_NEEDED: u32 = 2;

/// Grace period for newly registered nodes. Probe failures during this
/// window don't count toward the death threshold, preventing new nodes
/// from being immediately marked dead before the first probe completes.
pub(crate) const GRACE_PERIOD: Duration = Duration::from_secs(60);

/// Cooldown between emergency probes to protect the health check pool.
/// Matches Go's 2-second cooldown for NotifyCheckTcp/NotifyCheckDnsUdp.
const EMERGENCY_PROBE_COOLDOWN: Duration = Duration::from_secs(2);

#[inline]
pub fn alive_index(domain: ProbeDomain, ipver: IpVersion) -> usize {
    domain as usize * IpVersion::count() + ipver as usize
}

/// Result of one HTTP health probe. Only a complete warm exchange is healthy
/// and contributes latency; setup and target-exchange failures stay distinct
/// for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpProbeResult {
    WarmSuccess(Duration),
    SetupFailure(String),
    ExchangeFailure(String),
    LocalRefusal(crate::proxy::PacketRejection),
}

/// Trait for HTTP-based health check probing through proxy nodes.
///
/// Implemented by `honk-core` to route HTTP requests through the proxy
/// registry, matching Go's `Dialer.HttpCheck`. `url` is the check target
/// (global `tcp_check_url`, or a group's custom `check_url`); `addr` is a
/// pre-resolved IP for that URL's host. Only [`HttpProbeResult::WarmSuccess`]
/// is healthy and carries a ranking RTT.
/// Implementations own timeout handling; callers do not wrap the future in a
/// competing deadline.
pub trait HttpProber: Send + Sync {
    fn probe_http(
        &self,
        node_name: &str,
        addr: SocketAddr,
        url: &str,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = HttpProbeResult> + Send + 'static>>;
}

/// Type-erased HTTP prober stored in `AliveDialerSet`.
pub type HttpProberRef = Arc<dyn HttpProber>;

/// Outcome of one node UDP health probe: two independent signals.
///
/// The DNS exchange against `udp_check_dns` and the Score data-path
/// handshake (a real TLS-in-QUIC handshake to the HTTPS check URL) can
/// disagree when the DNS target is blocked through the node — a common
/// anti-amplification rule on relay servers — while the UDP data path
/// itself works. Treating that as total UDP death excluded healthy nodes
/// from UDP selection permanently (no traffic left to revive them).
#[derive(Debug)]
pub struct UdpProbeOutcome {
    /// Round-trip of the minimal DNS query through the node's UDP transport;
    /// `None` when target policy skips it or local target initialization is still pending.
    pub dns: Option<anyhow::Result<Duration>>,
    /// Independent data-path handshake result; `None` when not run (no HTTPS
    /// check URL, no Score group, or target policy skips it).
    pub data_path: Option<anyhow::Result<Duration>>,
}

/// Trait for UDP-based health check probing through proxy nodes.
///
/// Implemented by `honk-core` to route a minimal DNS query through the
/// proxy handler's UDP data path (real UDP, UoT, QUIC datagrams — whatever
/// `dial_udp_transport` provides), matching Go's `Dialer.UdpCheck`, plus the
/// Score data-path handshake as an independent second signal.
///
/// This catches nodes whose TCP path works but whose UDP path is broken
/// (e.g. an AnyTLS server without UoT support) — a plain TCP probe can
/// never see that failure mode.
/// Implementations own timeout handling; callers do not wrap the future in a
/// competing deadline.
pub trait UdpProber: Send + Sync {
    fn probe_udp(
        &self,
        node_name: &str,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = UdpProbeOutcome> + Send + 'static>>;
}

/// Type-erased UDP prober stored in `AliveDialerSet`.
pub type UdpProberRef = Arc<dyn UdpProber>;

/// Returns the failure threshold for probe-based health checks.
///   TCP probe = 3 (Go dae uses 1; a single transient probe loss used to
///   eject the URLTest incumbent from the candidate set outright, forcing
///   an immediate switch that bypassed tolerance hysteresis — ranking
///   demotion now covers the fast path, liveness exclusion is the backstop)
///   UDP DNS probe = 3 (DNS queries more prone to transient loss)
///   UDP Data probe = 3 (same as DNS)
const fn probe_failure_threshold(domain: ProbeDomain) -> u32 {
    match domain {
        ProbeDomain::Tcp => 3,
        ProbeDomain::DnsUdp => 3,
        ProbeDomain::DataUdp => 3,
    }
}

/// Returns the failure threshold for traffic-based health checks.
/// Matches Go thresholds:
///   TCP traffic = 10 (balance fast discovery with noise resilience)
///   UDP Data traffic = 50 (protect long-lived UDP flows from transient flips)
///   DNS UDP traffic = 3 (DNS failures from real user traffic)
const fn traffic_failure_threshold(domain: ProbeDomain) -> u32 {
    match domain {
        ProbeDomain::Tcp => 10,
        ProbeDomain::DnsUdp => 3,
        ProbeDomain::DataUdp => 50,
    }
}

#[derive(Debug, Clone)]
struct PerProtocolState {
    alive: bool,
    /// Probe-based consecutive failures.
    consecutive_failures: u32,
    /// Probe-based consecutive successes (for recovery hysteresis).
    consecutive_successes: u32,
    /// Traffic-based consecutive failures (separate counter, higher thresholds).
    traffic_failures: u32,
    cooldown_until: Instant,
    /// When true, the node is in deep backoff: probes continue on the slow
    /// max_cooldown cadence until resuscitation.
    stopped: bool,
}

impl PerProtocolState {
    /// Mark the domain alive and clear every failure/backoff counter
    /// (shared by all probe/traffic success paths).
    fn reset_on_success(&mut self) {
        self.alive = true;
        self.consecutive_failures = 0;
        self.consecutive_successes = 0;
        self.traffic_failures = 0;
        self.stopped = false;
        self.cooldown_until = Instant::now();
    }

    fn is_clean_alive(&self) -> bool {
        self.alive
            && self.consecutive_failures == 0
            && self.consecutive_successes == 0
            && self.traffic_failures == 0
            && !self.stopped
    }

    fn new() -> Self {
        Self {
            alive: true,
            consecutive_failures: 0,
            consecutive_successes: 0,
            traffic_failures: 0,
            cooldown_until: Instant::now(),
            stopped: false,
        }
    }
}

impl Default for PerProtocolState {
    fn default() -> Self {
        Self::new()
    }
}

fn fresh_states() -> [PerProtocolState; ALIVE_STATES_PER_NODE] {
    std::array::from_fn(|_| PerProtocolState::new())
}

type EbpfAliveCallback = dyn Fn(Uuid, u8, u32, u32, bool) + Send + Sync;

/// Callback fired when a node's (domain, ip-version) state flips
/// alive→dead on the probe path (same trigger as the eBPF connectivity
/// push). Carries the NodeId plus the registered display name for logs.
/// honk-core purges pooled connections and UDP endpoints bound to the
/// node from it. Fires once per domain/ip-version flip — handlers
/// must be idempotent.
type DeathCallback = dyn Fn(Uuid, &str) + Send + Sync;

/// Resolves a custom-check-URL group's member tags to `(tag, current
/// leaf node)` pairs for probing (see `url_member_resolver`).
pub type UrlMemberResolver = Arc<dyn Fn(&str) -> Vec<(String, String)> + Send + Sync>;

/// Default URLTest group idle timeout when the group config has none
/// (sing-box default: 30 minutes). Periodic probing of a URLTest group's
/// members pauses while the group is idle and resumes on the next selection.
pub const DEFAULT_URLTEST_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);

/// Resolves a NodeId to its eBPF outbound index for
/// `OUTBOUND_CONNECTIVITY_MAP` writes (direct=0, block=1, group i → 2+i,
/// matching the control plane's routing push). Returns `None` for nodes
/// without an eBPF outbound id (not in any group) — those state changes
/// are not pushed to the kernel map.
pub type OutboundIdResolver = Arc<dyn Fn(Uuid) -> Option<u8> + Send + Sync>;

/// A node registered for health checking: the content-derived NodeId is
/// the map key; the name is kept for logs and the prober's node lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredNode {
    pub name: String,
    pub address: String,
}

/// A single probe record for history/API consumption.
#[derive(Debug, Clone)]
pub struct ProbeRecord {
    pub timestamp: Instant,
    pub success: bool,
    pub latency: Option<Duration>,
}

/// Maximum probe history entries per node per domain/IP version.
const MAX_PROBE_HISTORY: usize = 100;

/// Domain resolver for health-check targets: `(host, port) → Result<addrs>`.
/// honk-core installs the DNS-forwarder-backed resolver so all health-check
/// name resolution shares honk's own DNS stack (routing, cache, serve-stale)
/// instead of the raw system resolver; bootstrap DNS stays for node
/// hostnames and startup.
pub type ResolveHook = Arc<
    dyn Fn(String, u16) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<SocketAddr>>> + Send>>
        + Send
        + Sync,
>;

pub struct AliveDialerSet {
    /// Uses parking_lot RwLock/Mutex for synchronous, uncontended access on the
    /// async runtime (parking_lot blocks OS threads without runtime awareness).
    states: RwLock<HashMap<Uuid, [PerProtocolState; ALIVE_STATES_PER_NODE]>>,
    /// Per-node-per-domain latency collections (Go `collection` struct).
    collections: RwLock<HashMap<Uuid, [Arc<DialerCollection>; ALIVE_STATES_PER_NODE]>>,
    registered: RwLock<HashMap<Uuid, Arc<RegisteredNode>>>,
    ebpf_callback: RwLock<Option<Arc<EbpfAliveCallback>>>,
    death_callback: RwLock<Option<Arc<DeathCallback>>>,
    base_cooldown: Duration,
    max_cooldown: Duration,
    /// Bounded node-deduplicated emergency probe queue. A pending node owns
    /// at most one entry, so traffic failure storms cannot grow memory.
    trigger_tx: tokio::sync::mpsc::Sender<Uuid>,
    trigger_rx: Mutex<Option<tokio::sync::mpsc::Receiver<Uuid>>>,
    trigger_pending: Mutex<HashSet<Uuid>>,
    /// Optional `SO_MARK` value applied to probe sockets so the eBPF datapath
    /// treats them as control-plane traffic and does not re-route them.
    so_mark: Option<u32>,
    /// Last emergency probe timestamps per node for cooldown (Go: lastNotifyUdp/lastNotifyTcp).
    last_emergency_tcp: Mutex<HashMap<Uuid, Instant>>,
    last_emergency_udp: Mutex<HashMap<Uuid, Instant>>,
    /// HTTP health prober and URL from config (Go: TcpCheckOption).
    /// When set, probes use HTTP(S) through the proxy instead of raw TCP.
    http_prober: RwLock<Option<HttpProberRef>>,
    check_url: RwLock<String>,
    /// Probe target for the `direct` node (`host:port`): the proxy check URL
    /// is meaningless for direct egress, so direct is measured with a raw
    /// TCP connect against the bootstrap resolver instead. Defaults to
    /// [`DEFAULT_DIRECT_CHECK_ADDR`].
    direct_check_addr: RwLock<String>,
    /// Cached resolved IPs from the check URL hostname (Go: TcpCheckOption.Ip46).
    /// Resolved once at startup; refreshed on `refresh_check_ips()`.
    check_url_ips: RwLock<Vec<SocketAddr>>,
    /// UDP health check prober (Go: UdpCheckOption) installed by honk-core.
    /// When set, each periodic probe cycle runs a DNS-over-UDP exchange
    /// through the node's UDP data path after the TCP probe.
    udp_prober: RwLock<Option<UdpProberRef>>,
    score_feedback: RwLock<Option<ScoreFeedbackFactory>>,
    /// Timestamp when each node was first registered (for grace period).
    node_registered_at: RwLock<HashMap<Uuid, Instant>>,
    /// Per-node per-domain/IP-version probe history for API/UI.
    probe_history: RwLock<HashMap<(Uuid, usize), Vec<ProbeRecord>>>,
    /// NodeId → eBPF outbound index resolver for connectivity pushes.
    outbound_resolver: RwLock<Option<OutboundIdResolver>>,
    /// DNS resolver for check targets (system lookup when unset).
    resolver: RwLock<Option<ResolveHook>>,
    /// Last activity timestamp per URLTest group (lazy start: absent = idle).
    group_last_active: RwLock<HashMap<String, Instant>>,
    /// NodeId → URLTest groups it belongs to (for idle suspension).
    node_urltest_groups: RwLock<HashMap<Uuid, Vec<String>>>,
    /// URLTest group → member NodeIds (for wake-up probes).
    urltest_group_members: RwLock<HashMap<String, Vec<Uuid>>>,
    /// URLTest group → idle timeout (probing pauses past it).
    urltest_group_timeout: RwLock<HashMap<String, Duration>>,
    /// Group → custom check URL for per-group health check targets
    /// (sing-box urltest `url` option). Members are resolved dynamically
    /// each probe cycle through `url_member_resolver` — sub-group picks
    /// change over time, a static list would go stale.
    group_check_urls: RwLock<HashMap<String, String>>,
    /// Resolves a group's member tags to `(tag, current leaf node)` pairs
    /// for custom-URL probing (installed by honk-core via the group
    /// manager; direct members map to themselves).
    url_member_resolver: RwLock<Option<UrlMemberResolver>>,
    /// (member tag, check_url) → probe state (TCP-only, see [`UrlProbeState`]).
    /// Keyed by member TAG, not NodeId: a member may be a nested sub-group,
    /// which has no node identity (sing-box RealTag semantics).
    url_states: RwLock<HashMap<(String, String), UrlProbeState>>,
    /// (member tag, check_url) → latency collection for selection ranking.
    url_collections: RwLock<HashMap<(String, String), Arc<DialerCollection>>>,
    /// check_url → cached resolved IPs (same caching as `check_url_ips`).
    url_check_ips: RwLock<HashMap<String, Vec<SocketAddr>>>,
}

/// Default probe target for the `direct` node when no `bootstrap_resolver`
/// is configured: a directly-reachable, anycasted resolver.
pub const DEFAULT_DIRECT_CHECK_ADDR: &str = "223.5.5.5:53";

/// Exponential probe backoff: `base * 2^min(failures, 8)`, capped at `max`.
fn probe_backoff(base: Duration, max: Duration, consecutive_failures: u32) -> Duration {
    base.saturating_mul(2u32.pow(consecutive_failures.min(8)))
        .min(max)
}

impl AliveDialerSet {
    pub fn new() -> Self {
        const TRIGGER_QUEUE_CAPACITY: usize = 256;
        let (tx, rx) = tokio::sync::mpsc::channel(TRIGGER_QUEUE_CAPACITY);
        Self {
            states: RwLock::new(HashMap::new()),
            collections: RwLock::new(HashMap::new()),
            registered: RwLock::new(HashMap::new()),
            ebpf_callback: RwLock::new(None),
            death_callback: RwLock::new(None),
            resolver: RwLock::new(None),
            base_cooldown: Duration::from_secs(5),
            max_cooldown: Duration::from_secs(300),
            trigger_tx: tx,
            trigger_rx: Mutex::new(Some(rx)),
            trigger_pending: Mutex::new(HashSet::new()),
            so_mark: None,
            last_emergency_tcp: Mutex::new(HashMap::new()),
            last_emergency_udp: Mutex::new(HashMap::new()),
            http_prober: RwLock::new(None),
            check_url: RwLock::new(String::new()),
            direct_check_addr: RwLock::new(DEFAULT_DIRECT_CHECK_ADDR.to_string()),
            check_url_ips: RwLock::new(Vec::new()),
            udp_prober: RwLock::new(None),
            score_feedback: RwLock::new(None),
            node_registered_at: RwLock::new(HashMap::new()),
            probe_history: RwLock::new(HashMap::new()),
            outbound_resolver: RwLock::new(None),
            group_last_active: RwLock::new(HashMap::new()),
            node_urltest_groups: RwLock::new(HashMap::new()),
            urltest_group_members: RwLock::new(HashMap::new()),
            urltest_group_timeout: RwLock::new(HashMap::new()),
            group_check_urls: RwLock::new(HashMap::new()),
            url_member_resolver: RwLock::new(None),
            url_states: RwLock::new(HashMap::new()),
            url_collections: RwLock::new(HashMap::new()),
            url_check_ips: RwLock::new(HashMap::new()),
        }
    }

    /// Set the `SO_MARK` value for probe sockets and return `self` for chaining.
    pub fn with_so_mark(mut self, mark: u32) -> Self {
        self.so_mark = Some(mark);
        self
    }

    /// Override the `direct` node's probe target (`host:port`). honk-core
    /// installs the configured `bootstrap_resolver` here.
    pub fn set_direct_check_addr(&self, addr: String) {
        *self.direct_check_addr.write() = addr;
    }

    /// Configure HTTP-based health checks from config (Go: TcpCheckOption).
    ///
    /// Resolves the check URL's hostname once at startup and caches the IPs.
    /// Probes reuse the cached IPs without repeated DNS lookups, matching
    /// Go's `TcpCheckOptionRaw.Option()` pattern.
    pub async fn set_http_probe(
        &self,
        prober: HttpProberRef,
        check_url: String,
        check_method: String,
    ) {
        *self.http_prober.write() = Some(prober);

        let Ok(target) = honk_config::check::decode_health_http_target(&check_url) else {
            tracing::warn!("Invalid health check URL; falling back to TCP probe");
            *self.check_url.write() = String::new();
            self.check_url_ips.write().clear();
            return;
        };
        let (hostname, port) = (target.host(), target.port());
        *self.check_url.write() = check_url.clone();

        // Resolve the check URL hostname once at startup; dae-format literal
        // fallback IPs (comma-separated) are merged in so probes still have
        // targets even when DNS resolution fails.
        let addrs = self.resolve_host(hostname, port).await.unwrap_or_default();
        if addrs.is_empty() {
            tracing::warn!("Failed to resolve health check URL '{}'", hostname);
        }
        let ips = Self::merge_check_addrs(addrs, &check_url, port);
        tracing::debug!(
            "Health check DNS resolved '{}' → {} IPs",
            hostname,
            ips.len()
        );
        *self.check_url_ips.write() = ips;
        tracing::info!(
            "HTTP health check enabled (url={}, method={})",
            check_url,
            check_method
        );
    }

    /// Install the UDP health check prober (Go: UdpCheckOption).
    ///
    /// Once installed, the periodic health check cycle runs
    /// [`AliveDialerSet::probe_node_udp`] after each node's TCP probe.
    pub fn set_udp_probe(&self, prober: UdpProberRef) {
        *self.udp_prober.write() = Some(prober);
    }

    pub fn set_score_feedback_factory<F>(&self, factory: F)
    where
        F: Fn(Uuid, ScoreSelectionContext) -> Option<ScoreFeedback> + Send + Sync + 'static,
    {
        *self.score_feedback.write() = Some(Arc::new(factory));
    }

    /// Install the DNS resolver for health-check targets (see [`ResolveHook`]).
    pub fn set_resolver(&self, hook: ResolveHook) {
        *self.resolver.write() = Some(hook);
    }

    /// Resolve `host` via the installed hook. Typed local refusal is returned;
    /// ordinary empty or failed hook results retain marked bootstrap/system fallback.
    pub async fn resolve_host(&self, host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        let hook = self.resolver.read().clone();
        if let Some(hook) = hook {
            match hook(host.to_string(), port).await {
                Ok(out) if !out.is_empty() => return Ok(out),
                Err(error) if crate::proxy::is_packet_rejection(&error) => return Err(error),
                Ok(_) => {
                    tracing::debug!(
                        "health-check resolver found nothing for {host}; bootstrap/system fallback"
                    )
                }
                Err(_) => {
                    tracing::debug!(
                        "health-check resolver failed for {host}; bootstrap/system fallback"
                    )
                }
            }
        }
        Ok(crate::bootstrap::resolve(host)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    /// Refresh the cached check URL IPs.  Called at the start of each full
    /// health check cycle so DNS record changes are eventually picked up.
    /// Matches Go's `TcpCheckOptionRaw.Reset()`.
    pub async fn refresh_check_ips(&self) {
        let check_url = self.check_url.read().clone();
        if let Ok(target) = honk_config::check::decode_health_http_target(&check_url) {
            let port = target.port();
            let ips = match self.resolve_host(target.host(), port).await {
                Ok(addrs) => Self::merge_check_addrs(addrs, &check_url, port),
                Err(_) => {
                    *self.check_url_ips.write() =
                        Self::merge_check_addrs(Vec::new(), &check_url, port);
                    return;
                }
            };
            if !ips.is_empty() {
                *self.check_url_ips.write() = ips;
            }
        }
    }

    pub fn set_ebpf_callback(&self, cb: Box<EbpfAliveCallback>) {
        *self.ebpf_callback.write() = Some(cb.into());
    }

    /// Install the callback fired when a node's state flips alive→dead
    /// (see [`DeathCallback`]). Re-callable; pass `None` to remove.
    pub fn set_death_callback(&self, cb: Option<Box<DeathCallback>>) {
        *self.death_callback.write() = cb.map(Arc::from);
    }

    /// Install the node name → eBPF outbound index resolver used by
    /// `push_ebpf`. Re-callable: honk-core re-installs (or refreshes the
    /// captured map) on config reload. Pass `None` to restore the legacy
    /// fallback (outbound 0).
    pub fn set_outbound_resolver(&self, resolver: Option<OutboundIdResolver>) {
        *self.outbound_resolver.write() = resolver;
    }

    pub fn take_trigger_rx(&self) -> Option<tokio::sync::mpsc::Receiver<Uuid>> {
        self.trigger_rx.lock().take()
    }

    fn with_state<F, R>(&self, node_id: Uuid, idx: usize, f: F) -> R
    where
        F: FnOnce(&mut PerProtocolState) -> R,
    {
        let mut states = self.states.write();
        let entry = states.entry(node_id).or_insert_with(fresh_states);
        f(&mut entry[idx])
    }

    fn read_state(&self, node_id: Uuid, idx: usize) -> PerProtocolState {
        self.states
            .read()
            .get(&node_id)
            .map(|s| s[idx].clone())
            .unwrap_or_default()
    }

    pub fn is_alive_for(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) -> bool {
        let idx = alive_index(domain, ipver);
        self.states
            .read()
            .get(&node_id)
            .is_none_or(|s| s[idx].alive)
    }

    /// Get (or create) the `DialerCollection` for a given node and domain index.
    fn get_or_create_collection(&self, node_id: Uuid, idx: usize) -> Arc<DialerCollection> {
        let mut cols = self.collections.write();
        let arr = cols
            .entry(node_id)
            .or_insert_with(|| std::array::from_fn(|_| Arc::new(DialerCollection::new())));
        Arc::clone(&arr[idx])
    }

    pub fn register_node(&self, node_id: Uuid, name: String, address: String) {
        let mut registered = self.registered.write();
        registered.insert(node_id, Arc::new(RegisteredNode { name, address }));
        self.node_registered_at
            .write()
            .insert(node_id, Instant::now());
        let mut states = self.states.write();
        states.entry(node_id).or_insert_with(fresh_states);
    }

    /// Snapshot of currently registered nodes (NodeId → name/address), used
    /// by config reload to diff and re-register only what changed.
    pub fn registered_nodes(&self) -> HashMap<Uuid, RegisteredNode> {
        self.registered
            .read()
            .iter()
            .map(|(id, node)| (*id, node.as_ref().clone()))
            .collect()
    }

    /// Registered display name for logs and prober lookups; falls back to
    /// the ID itself for nodes driven without registration (tests).
    pub fn node_name(&self, node_id: Uuid) -> String {
        self.registered
            .read()
            .get(&node_id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| node_id.to_string())
    }

    pub fn remove_node(&self, node_id: Uuid) {
        let mut registered = self.registered.write();
        registered.remove(&node_id);
        self.states.write().remove(&node_id);
        self.collections.write().remove(&node_id);
        self.node_registered_at.write().remove(&node_id);
        self.node_urltest_groups.write().remove(&node_id);
        self.probe_history
            .write()
            .retain(|(id, _), _| *id != node_id);
        self.last_emergency_tcp.lock().remove(&node_id);
        self.last_emergency_udp.lock().remove(&node_id);
        self.trigger_pending.lock().remove(&node_id);
    }

    /// A link/address/route change invalidates probe backoff that may have
    /// been accumulated while the host had no usable uplink. Keep nodes
    /// fail-closed until a fresh probe succeeds, but let that verified
    /// success satisfy the recovery hysteresis immediately.
    pub fn notify_network_change(&self) {
        let node_ids: Vec<Uuid> = self.registered.read().keys().copied().collect();
        let now = Instant::now();
        {
            let mut states = self.states.write();
            for node_id in &node_ids {
                let Some(protocol_states) = states.get_mut(node_id) else {
                    continue;
                };
                for state in protocol_states {
                    state.cooldown_until = now;
                    if !state.alive {
                        state.consecutive_successes = RECOVERY_SUCCESSES_NEEDED - 1;
                    }
                }
            }
        }
        for node_id in node_ids {
            self.trigger_probe(node_id);
        }
    }

    pub fn trigger_probe(&self, node_id: Uuid) {
        let mut pending = self.trigger_pending.lock();
        if !pending.insert(node_id) {
            return;
        }
        if self.trigger_tx.try_send(node_id).is_err() {
            // Queue saturation drops this request (a later traffic failure or
            // periodic sweep retries it), and releases its dedup reservation.
            pending.remove(&node_id);
        }
    }

    pub(crate) fn finish_trigger_probe(&self, node_id: Uuid) {
        self.trigger_pending.lock().remove(&node_id);
    }

    pub fn should_probe(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) -> bool {
        let idx = alive_index(domain, ipver);
        let state = self.read_state(node_id, idx);
        // Stopped nodes (MAX_PROBE_BACKOFF_FAILURES consecutive failures)
        // still probe, just on the slow max_cooldown cadence their backoff
        // has grown to — never probing again would make the
        // 2-consecutive-success recovery path unreachable and permanently
        // kill single-member Selector groups (sing-box re-tests every
        // interval unconditionally). Emergency probes bypass this via
        // triggered checks.
        Instant::now() >= state.cooldown_until
    }

    /// Extract the comma-separated literal fallback IPs from a dae-format
    /// check URL (`http://host,ip4,ip6`) as socket addresses on the URL's
    /// port. Go: the non-URL entries of `TcpCheckOptionRaw.Raw`.
    fn parse_check_literals(check_url: &str, port: u16) -> Vec<SocketAddr> {
        check_url
            .split(',')
            .skip(1)
            .filter_map(|seg| {
                let ip = seg.trim().parse::<std::net::IpAddr>().ok();
                if ip.is_none() && !seg.trim().is_empty() {
                    tracing::debug!(
                        "ignoring unparseable check URL fallback segment '{}'",
                        seg.trim()
                    );
                }
                ip.map(|ip| SocketAddr::new(ip, port))
            })
            .collect()
    }

    /// Merge resolved and literal check-target addresses, deduplicated.
    fn merge_check_addrs(resolved: Vec<SocketAddr>, check_url: &str, port: u16) -> Vec<SocketAddr> {
        // Operator-declared literal fallbacks are the trusted anchors and
        // are tried first: resolved answers can be DNS-poisoned, and the
        // per-family probe window (first 3) would otherwise fill with
        // poisoned entries and starve the good literals out entirely.
        let mut ips = Self::parse_check_literals(check_url, port);
        for a in resolved {
            if !ips.contains(&a) {
                ips.push(a);
            }
        }
        ips
    }
}

impl Default for AliveDialerSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod trigger_tests {
    use super::*;

    #[test]
    fn trigger_queue_is_deduplicated_and_bounded() {
        let set = AliveDialerSet::new();
        let same = Uuid::from_u128(1);
        for _ in 0..1_000 {
            set.trigger_probe(same);
        }
        for index in 0..1_000u128 {
            set.trigger_probe(Uuid::from_u128(index + 2));
        }

        let mut receiver = set.take_trigger_rx().expect("first receiver ownership");
        let mut seen = std::collections::HashSet::new();
        while let Ok(id) = receiver.try_recv() {
            seen.insert(id);
        }
        assert!(seen.len() <= 256);
        assert_eq!(seen.iter().filter(|id| **id == same).count(), 1);
        for id in seen {
            set.finish_trigger_probe(id);
        }
        set.trigger_probe(same);
        assert_eq!(receiver.try_recv(), Ok(same));
    }
}

#[cfg(test)]
mod merge_check_addrs_tests {
    use super::*;

    #[test]
    fn literals_come_before_resolved_even_when_they_sort_later() {
        let literal: SocketAddr = "142.250.197.238:80".parse().unwrap();
        let poisoned: SocketAddr = "58.63.233.33:80".parse().unwrap();
        let merged = AliveDialerSet::merge_check_addrs(
            vec![poisoned],
            "http://www.google-analytics.com/generate_204,142.250.197.238",
            80,
        );
        assert_eq!(merged.first(), Some(&literal));
        assert!(merged.contains(&poisoned));
        assert_eq!(merged.len(), 2);
    }
}
