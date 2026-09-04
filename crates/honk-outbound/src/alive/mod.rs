//! Outbound dialer management — alive detection, sticky cache, recovery state.

pub mod collection;
pub mod latencies;
mod probe;

#[cfg(test)]
mod tests;

use self::collection::{DialerCollection, SLOW_DIAL_STREAK_MAX, TrafficVerdict};
use crate::group::{ScoreFeedback, ScoreSelectionContext};
use honk_config::config::{BLOCK_NODE_ID, DIRECT_NODE_ID};
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

pub type ProtocolDomain = ProbeDomain;

/// Result of one HTTP health probe. Only a complete warm exchange is healthy
/// and contributes latency; setup and target-exchange failures stay distinct
/// for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpProbeResult {
    WarmSuccess(Duration),
    SetupFailure(String),
    ExchangeFailure(String),
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
    /// Round-trip of the minimal DNS query through the node's UDP transport.
    pub dns: Result<Duration, String>,
    /// Independent data-path handshake result; `None` when not run (no HTTPS
    /// check URL, or the node belongs to no Score group).
    pub data_path: Option<Result<Duration, String>>,
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
    [
        PerProtocolState::new(),
        PerProtocolState::new(),
        PerProtocolState::new(),
        PerProtocolState::new(),
        PerProtocolState::new(),
        PerProtocolState::new(),
    ]
}

type EbpfAliveCallback = Box<dyn Fn(Uuid, u8, u32, u32, bool) + Send + Sync>;

/// Callback fired when a node's (domain, ip-version) state flips
/// alive→dead on the probe path (same trigger as the eBPF connectivity
/// push). Carries the NodeId plus the registered display name for logs.
/// honk-core purges pooled connections and UDP endpoints bound to the
/// node from it. Fires once per domain/ip-version flip — handlers
/// must be idempotent.
type DeathCallback = Box<dyn Fn(Uuid, &str) + Send + Sync>;

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

/// Domain resolver for health-check targets: `(host, port) → addrs`.
/// honk-core installs the DNS-forwarder-backed resolver so all health-check
/// name resolution shares honk's own DNS stack (routing, cache, serve-stale)
/// instead of the raw system resolver; bootstrap DNS stays for node
/// hostnames and startup.
pub type ResolveHook = Arc<
    dyn Fn(
            String,
            u16,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<SocketAddr>> + Send>>
        + Send
        + Sync,
>;

pub struct AliveDialerSet {
    /// Uses parking_lot RwLock/Mutex for synchronous, uncontended access on the
    /// async runtime (parking_lot blocks OS threads without runtime awareness).
    states: RwLock<HashMap<Uuid, [PerProtocolState; ALIVE_STATES_PER_NODE]>>,
    /// Per-node-per-domain latency collections (Go `collection` struct).
    collections: RwLock<HashMap<Uuid, [Arc<DialerCollection>; ALIVE_STATES_PER_NODE]>>,
    registered: RwLock<HashMap<Uuid, RegisteredNode>>,
    ebpf_callback: RwLock<Option<EbpfAliveCallback>>,
    death_callback: RwLock<Option<DeathCallback>>,
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
    /// HTTP health check URL and method from config (Go: TcpCheckOption).
    /// When set, the probe uses HTTP(S) requests through the proxy instead of
    /// raw TCP connect, matching Go's `HttpCheck` behaviour.
    http_prober: RwLock<Option<HttpProberRef>>,
    check_url: RwLock<String>,
    check_method: RwLock<String>,
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
            check_method: RwLock::new(String::new()),
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
        *self.check_method.write() = check_method.clone();

        let port = Self::parse_url_port(&check_url);
        let Some(hostname) = Self::parse_url_host(&check_url) else {
            tracing::warn!(
                "Invalid health check URL '{}'; falling back to TCP probe",
                check_url
            );
            *self.check_url.write() = String::new();
            self.check_url_ips.write().clear();
            return;
        };
        *self.check_url.write() = check_url.clone();

        // Resolve the check URL hostname once at startup; dae-format literal
        // fallback IPs (comma-separated) are merged in so probes still have
        // targets even when DNS resolution fails.
        let addrs = self.resolve_host(&hostname, port).await;
        if addrs.is_empty() {
            tracing::warn!("Failed to resolve health check URL '{}'[39m", hostname);
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

    /// Resolve `host` via the installed hook, falling back to the system
    /// resolver when no hook is set or the hook finds nothing.
    pub async fn resolve_host(&self, host: &str, port: u16) -> Vec<SocketAddr> {
        let hook = self.resolver.read().clone();
        if let Some(hook) = hook {
            let out = hook(host.to_string(), port).await;
            if !out.is_empty() {
                return out;
            }
            tracing::debug!("health-check resolver found nothing for {host}; system fallback");
        }
        tokio::net::lookup_host(format!("{host}:{port}"))
            .await
            .map(|it| it.collect())
            .unwrap_or_default()
    }

    /// Refresh the cached check URL IPs.  Called at the start of each full
    /// health check cycle so DNS record changes are eventually picked up.
    /// Matches Go's `TcpCheckOptionRaw.Reset()`.
    pub async fn refresh_check_ips(&self) {
        let check_url = self.check_url.read().clone();
        if let Some(hostname) = Self::parse_url_host(&check_url) {
            let port = Self::parse_url_port(&check_url);
            let addrs = self.resolve_host(&hostname, port).await;
            if !addrs.is_empty() {
                let ips = Self::merge_check_addrs(addrs, &check_url, port);
                *self.check_url_ips.write() = ips;
            }
        }
    }

    pub fn set_ebpf_callback(&self, cb: EbpfAliveCallback) {
        *self.ebpf_callback.write() = Some(cb);
    }

    /// Install the callback fired when a node's state flips alive→dead
    /// (see [`DeathCallback`]). Re-callable; pass `None` to remove.
    pub fn set_death_callback(&self, cb: Option<DeathCallback>) {
        *self.death_callback.write() = cb;
    }

    /// Install the node name → eBPF outbound index resolver used by
    /// `push_ebpf`. Re-callable: honk-core re-installs (or refreshes the
    /// captured map) on config reload. Pass `None` to restore the legacy
    /// fallback (outbound 0).
    pub fn set_outbound_resolver(&self, resolver: Option<OutboundIdResolver>) {
        *self.outbound_resolver.write() = resolver;
    }

    fn push_ebpf(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion, alive: bool) {
        let outbound = match *self.outbound_resolver.read() {
            Some(ref resolve) => match resolve(node_id) {
                Some(id) => id,
                // Node has no eBPF outbound id (not in any group) — skip.
                None => return,
            },
            // Legacy fallback when no resolver is installed (tests).
            None => 0,
        };
        if let Some(ref cb) = *self.ebpf_callback.read() {
            cb(node_id, outbound, domain as u32, ipver as u32, alive);
        }
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

    pub fn is_alive(&self, node_id: Uuid) -> bool {
        self.is_alive_for(node_id, ProbeDomain::Tcp, IpVersion::V4)
    }

    pub fn is_alive_udp(&self, node_id: Uuid) -> bool {
        self.is_alive_for(node_id, ProbeDomain::DataUdp, IpVersion::V4)
    }

    /// Whether any UDP-domain state (DataUdp or DnsUdp, either IP version)
    /// has ever been recorded for this node — i.e. it was UDP-probed or had
    /// UDP traffic reported. Group selection uses this to distinguish
    /// "never UDP-probed" (TCP liveness fallback applies) from "UDP-probed
    /// and dead" (excluded from UDP selection even when TCP is alive).
    pub fn has_udp_state(&self, node_id: Uuid) -> bool {
        let history = self.probe_history.read();
        [ProbeDomain::DataUdp, ProbeDomain::DnsUdp]
            .into_iter()
            .flat_map(|d| {
                [IpVersion::V4, IpVersion::V6]
                    .into_iter()
                    .map(move |v| (d, v))
            })
            .any(|(d, v)| {
                history
                    .get(&(node_id, alive_index(d, v)))
                    .is_some_and(|records| !records.is_empty())
            })
    }

    pub fn alive_nodes(&self) -> HashSet<Uuid> {
        let idx = alive_index(ProbeDomain::Tcp, IpVersion::V4);
        self.states
            .read()
            .iter()
            .filter(|(_, s)| s[idx].alive)
            .map(|(k, _)| *k)
            .collect()
    }

    pub fn count(&self) -> usize {
        let idx = alive_index(ProbeDomain::Tcp, IpVersion::V4);
        self.states.read().values().filter(|s| s[idx].alive).count()
    }

    #[cfg(test)]
    fn mark_alive_for(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        self.mark_alive_for_latency(node_id, domain, ipver, Duration::ZERO);
    }

    /// Mark a node as alive for a specific domain/IP version, recording the
    /// probe latency so `Latencies10` and `MovingAverage` are updated.
    fn mark_alive_for_latency(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
        latency: Duration,
    ) {
        let idx = alive_index(domain, ipver);
        let was_alive = self.with_state(node_id, idx, |e| {
            let was = e.alive;
            e.reset_on_success();
            was
        });
        if !was_alive {
            self.push_ebpf(node_id, domain, ipver, true);
        }
        if latency > Duration::ZERO {
            let coll = self.get_or_create_collection(node_id, idx);
            coll.mark_available(latency);
        }
        self.record_probe_history(node_id, idx, true, Some(latency));
    }

    /// Check if a node is within its grace period.
    fn is_in_grace_period(&self, node_id: Uuid) -> bool {
        self.node_registered_at
            .read()
            .get(&node_id)
            .map(|t| t.elapsed() < GRACE_PERIOD)
            .unwrap_or(false)
    }

    /// Append a probe record to history.
    fn record_probe_history(
        &self,
        node_id: Uuid,
        idx: usize,
        success: bool,
        latency: Option<Duration>,
    ) {
        let key = (node_id, idx);
        let mut history = self.probe_history.write();
        let entry = history.entry(key).or_default();
        entry.push(ProbeRecord {
            timestamp: Instant::now(),
            success,
            latency,
        });
        if entry.len() > MAX_PROBE_HISTORY {
            entry.remove(0);
        }
    }

    /// Internal: mark a node as unavailable using either probe or traffic counters.
    ///
    /// Matches Go's `markUnavailableInternal`:
    /// - `force` = true → force-dead immediately
    /// - `is_traffic` = true → use traffic_failure_threshold
    fn mark_unavailable_internal(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
        force: bool,
        is_traffic: bool,
    ) {
        let idx = alive_index(domain, ipver);

        // During the grace period (fresh registrations, e.g. right after a
        // restart) neither probe nor traffic failures count toward death:
        // a startup DNS/warm-up hiccup must not mass-mark every node dead
        // and cause a full proxy outage that then needs minutes of revival
        // cycles to recover from. Forced deaths always bypass grace.
        if !force && self.is_in_grace_period(node_id) {
            self.record_probe_history(node_id, idx, false, None);
            return;
        }

        let threshold = if is_traffic {
            traffic_failure_threshold(domain)
        } else {
            probe_failure_threshold(domain)
        };

        let (was_alive, _failures) = self.with_state(node_id, idx, |e| {
            let was = e.alive;
            e.consecutive_successes = 0;
            if force {
                // Forced death: set counters to threshold to match state.
                e.consecutive_failures = threshold;
                e.traffic_failures = threshold;
                e.alive = false;
            } else if is_traffic {
                e.traffic_failures += 1;
                let f = e.traffic_failures;
                if f >= threshold {
                    e.alive = false;
                }
                // Traffic failures don't advance probe backoff cooldown
            } else {
                e.consecutive_failures += 1;
                let f = e.consecutive_failures;
                let backoff = probe_backoff(self.base_cooldown, self.max_cooldown, f);
                e.cooldown_until = Instant::now() + backoff;
                if f >= MAX_PROBE_BACKOFF_FAILURES {
                    e.stopped = true;
                }
                if f >= threshold {
                    e.alive = false;
                }
            }
            (was, e.consecutive_failures + e.traffic_failures)
        });

        if was_alive && !force {
            let still_alive = self.read_state(node_id, idx).alive;
            if !still_alive {
                self.push_ebpf(node_id, domain, ipver, false);
                if let Some(ref cb) = *self.death_callback.read() {
                    cb(node_id, &self.node_name(node_id));
                }
            }
        }
        if !is_traffic {
            // Probe counters own liveness and cooldown; ranking strikes are
            // reserved for real dial failures.
            self.get_or_create_collection(node_id, idx)
                .mark_probe_unavailable();
        }

        self.record_probe_history(node_id, idx, false, None);
    }

    fn mark_dead_for(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        self.mark_unavailable_internal(node_id, domain, ipver, false, false);
    }

    /// Mark a TCP node as dead (public API for proxy dial failure callers).
    pub fn mark_dead(&self, node_id: Uuid) {
        self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V4);
        self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V6);
    }

    /// Report a node as unavailable due to real traffic failure.
    ///
    /// Uses the per-protocol traffic failure thresholds (TCP=10, UDP Data=50)
    /// so transient glitches don't immediately tear down the node's alive state.
    /// Matches Go's `Dialer.ReportUnavailable`.
    pub fn report_unavailable_traffic(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        // A blocked flow is policy working, not a health signal.
        if node_id == BLOCK_NODE_ID {
            return;
        }
        self.mark_unavailable_internal(node_id, domain, ipver, false, true);
    }

    /// Force-mark a node as dead immediately (used on fatal errors).
    /// Matches Go's `Dialer.ReportUnavailableForced`.
    pub fn report_unavailable_forced(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        if node_id == BLOCK_NODE_ID {
            return;
        }
        self.mark_unavailable_internal(node_id, domain, ipver, true, true);
    }

    /// Report successful traffic through a node, reviving its alive state.
    ///
    /// For DataUDP: a single successful real UDP flow can instantly revive
    /// the data-UDP health domain (Go: `ReportAvailableTraffic`).
    pub fn report_available_traffic(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        let idx = alive_index(domain, ipver);
        // A real dial success breaks the consecutive dial-failure streak —
        // even when the state is clean and nothing else needs updating.
        if let Some(arr) = self.collections.read().get(&node_id) {
            arr[idx].reset_dial_fail_streak();
        }
        if self
            .states
            .read()
            .get(&node_id)
            .is_some_and(|states| states[idx].is_clean_alive())
        {
            return;
        }
        let was_alive = self.with_state(node_id, idx, |e| {
            let was = e.alive;
            e.reset_on_success();
            was
        });
        if !was_alive {
            self.push_ebpf(node_id, domain, ipver, true);
            tracing::info!(
                "Node '{}' revived via traffic (domain={:?}, ipver={:?})",
                node_id,
                domain,
                ipver
            );
        }
    }

    /// Trigger an emergency TCP health check on this node.
    /// Rate-limited to once per EMERGENCY_PROBE_COOLDOWN to protect the worker pool.
    pub fn notify_check_tcp(&self, node_id: Uuid) {
        let now = Instant::now();
        let mut last = self.last_emergency_tcp.lock();
        if let Some(prev) = last.get(&node_id)
            && now.duration_since(*prev) < EMERGENCY_PROBE_COOLDOWN
        {
            return;
        }
        last.insert(node_id, now);
        drop(last);
        self.trigger_probe(node_id);
    }

    /// Trigger an emergency DNS UDP health check on this node.
    /// Rate-limited to once per EMERGENCY_PROBE_COOLDOWN.
    pub fn notify_check_dns_udp(&self, node_id: Uuid) {
        let now = Instant::now();
        let mut last = self.last_emergency_udp.lock();
        if let Some(prev) = last.get(&node_id)
            && now.duration_since(*prev) < EMERGENCY_PROBE_COOLDOWN
        {
            return;
        }
        last.insert(node_id, now);
        drop(last);
        self.trigger_probe(node_id);
    }

    /// Whether this node is in deep backoff (MAX_PROBE_BACKOFF_FAILURES
    /// consecutive failures). Such nodes still probe on the slow
    /// max_cooldown cadence; the flag is informational (API/diagnostics).
    /// Emergency probes can still be triggered via `notify_check_*`.
    pub fn is_probe_stopped(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) -> bool {
        let idx = alive_index(domain, ipver);
        self.states
            .read()
            .get(&node_id)
            .map(|s| s[idx].stopped)
            .unwrap_or(false)
    }

    /// Get (or create) the `DialerCollection` for a given node and domain index.
    fn get_or_create_collection(&self, node_id: Uuid, idx: usize) -> Arc<DialerCollection> {
        let mut cols = self.collections.write();
        let arr = cols.entry(node_id).or_insert_with(|| {
            [
                Arc::new(DialerCollection::new()),
                Arc::new(DialerCollection::new()),
                Arc::new(DialerCollection::new()),
                Arc::new(DialerCollection::new()),
                Arc::new(DialerCollection::new()),
                Arc::new(DialerCollection::new()),
            ]
        });
        Arc::clone(&arr[idx])
    }

    /// Record a successful probe latency for a node + domain + IP version.
    /// Applies recovery hysteresis and feeds the selection moving average.
    pub fn record_probe_latency(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
        latency: Duration,
    ) {
        let idx = alive_index(domain, ipver);
        let revived = self.with_state(node_id, idx, |e| {
            let was = e.alive;
            if was {
                e.reset_on_success();
                false
            } else {
                e.consecutive_successes += 1;
                e.consecutive_failures = 0;
                e.traffic_failures = 0;
                if e.consecutive_successes >= RECOVERY_SUCCESSES_NEEDED {
                    e.alive = true;
                    e.stopped = false;
                    e.cooldown_until = Instant::now();
                    e.consecutive_successes = 0;
                    true
                } else {
                    tracing::debug!(
                        "Node '{}' recovery progress: {}/{} consecutive successes (domain={:?}, ipver={:?})",
                        node_id,
                        e.consecutive_successes,
                        RECOVERY_SUCCESSES_NEEDED,
                        domain,
                        ipver,
                    );
                    false
                }
            }
        });
        if revived {
            self.push_ebpf(node_id, domain, ipver, true);
        }
        let coll = self.get_or_create_collection(node_id, idx);
        if revived || self.read_state(node_id, idx).alive {
            coll.mark_available(latency);
        }

        self.record_probe_history(node_id, idx, true, Some(latency));
    }

    /// Read the moving average latency for a node-domain pair.
    ///
    /// Used by `GroupManager`'s `MinLatency` / `MinMovingAverage` policies.
    pub fn get_moving_average(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<Duration> {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        let coll = cols.get(&node_id).map(|arr| &arr[idx])?;
        let ma = coll.moving_average_duration();
        if ma > Duration::ZERO { Some(ma) } else { None }
    }

    /// Whether the node carries pending failure strikes in this domain.
    /// Selection demotes such nodes below every non-demoted candidate; the
    /// demotion clears only after max(strikes, 2) consecutive real
    /// successes, so a fast-but-flaky node cannot reclaim rank with one
    /// lucky probe.
    pub fn is_failure_demoted(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) -> bool {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        cols.get(&node_id)
            .is_some_and(|arr| arr[idx].is_failure_demoted())
    }

    /// Read the last probe latency for a node-domain pair.
    pub fn get_last_latency(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<Duration> {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        let coll = cols.get(&node_id).map(|arr| &arr[idx])?;
        coll.latencies.last()
    }

    /// Read the most recent REAL (non-synthetic) probe sample and its
    /// measurement time — display semantics for the clash delay history.
    /// Synthetic failure placeholders (10s) are skipped so dashboards never
    /// show them as a measured delay.
    pub fn get_last_real_sample(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<(Duration, std::time::SystemTime)> {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        let coll = cols.get(&node_id).map(|arr| &arr[idx])?;
        coll.latencies.last_real_sample().map(|s| (s.latency, s.at))
    }

    /// Moving average of the recent probe samples for the same
    /// (domain, ipver) state — this is what dae's `min_moving_avg` /
    /// `min_avg10` group policies rank nodes by. Falls back to the latest
    /// sample when there is only one.
    pub fn get_avg_latency(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<Duration> {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        let coll = cols.get(&node_id).map(|arr| &arr[idx])?;
        coll.latencies.avg().or_else(|| coll.latencies.last())
    }

    /// Dial-failure handling: only DIAL_FAILURE_STRIKE_AT consecutive dial
    /// failures append the synthetic timeout sample and one failure strike —
    /// a lone transient failure (the retry race rescues that flow) leaves no
    /// selection state at all. The node's real history and moving average
    /// are retained so URLTest tolerance hysteresis keeps its baseline; the
    /// strike demotes the node in ranking until max(strikes, 2) consecutive
    /// real successes clear it, which is what stops a fast-but-flaky node
    /// from reclaiming the top rank with a single lucky probe.
    pub fn record_dial_failure(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        if node_id == BLOCK_NODE_ID {
            return;
        }
        self.get_or_create_collection(node_id, alive_index(domain, ipver))
            .record_dial_failure();
    }

    /// Feed one REAL proxied dial's wall-clock latency (network round trip
    /// only — pool-ready hits are excluded by the caller). Sudden
    /// degradation (3 consecutive dials slower than min(2×ema, ema+500ms),
    /// floored at 250ms so fast nodes under load don't trip it)
    /// appends a synthetic failure strike (strike demotion) and returns
    /// true so the caller fires an emergency probe. Gradual drift stays
    /// owned by the probe cycle. Returns true once per demotion.
    ///
    /// A false positive (target-mix shift, not node decay) self-heals: the
    /// emergency probe succeeds and consecutive probe successes clear the
    /// strike while the replacement node serves traffic meanwhile.
    pub fn report_dial_latency(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
        elapsed: Duration,
    ) -> bool {
        // Local-egress latency is not node quality.
        if node_id == DIRECT_NODE_ID || node_id == BLOCK_NODE_ID {
            return false;
        }
        let coll = self.get_or_create_collection(node_id, alive_index(domain, ipver));
        match coll.record_traffic_latency(elapsed) {
            TrafficVerdict::Slow => {
                if coll.bump_slow_streak() >= SLOW_DIAL_STREAK_MAX {
                    coll.reset_slow_streak();
                    coll.mark_unavailable();
                    true
                } else {
                    false
                }
            }
            TrafficVerdict::Fast | TrafficVerdict::Warmup => {
                coll.reset_slow_streak();
                false
            }
        }
    }

    /// Seed a persisted delay sample into the node's TCP-v4 latency
    /// history (cache.db warm start). Does NOT touch alive state — probes
    /// decide liveness; this only pre-seeds ranking data so URLTest groups
    /// don't start cold after a restart.
    pub fn restore_latency(&self, node_id: Uuid, latency: Duration, at: std::time::SystemTime) {
        let idx = alive_index(ProbeDomain::Tcp, IpVersion::V4);
        let coll = self.get_or_create_collection(node_id, idx);
        coll.restore_sample(latency, at);
    }

    /// Snapshot every node's last real TCP-v4 latency sample for
    /// persistence. Synthetic (failure) samples are excluded.
    pub fn latency_snapshot(&self) -> Vec<(Uuid, Duration, std::time::SystemTime)> {
        let idx = alive_index(ProbeDomain::Tcp, IpVersion::V4);
        let cols = self.collections.read();
        cols.iter()
            .filter_map(|(node, arr)| {
                arr[idx]
                    .latencies
                    .last_real_sample()
                    .map(|s| (*node, s.latency, s.at))
            })
            .collect()
    }

    pub fn register_node(&self, node_id: Uuid, name: String, address: String) {
        self.registered
            .write()
            .insert(node_id, RegisteredNode { name, address });
        self.node_registered_at
            .write()
            .insert(node_id, Instant::now());
        let mut states = self.states.write();
        states.entry(node_id).or_insert_with(fresh_states);
    }

    /// Snapshot of currently registered nodes (NodeId → name/address), used
    /// by config reload to diff and re-register only what changed.
    pub fn registered_nodes(&self) -> HashMap<Uuid, RegisteredNode> {
        self.registered.read().clone()
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
        self.registered.write().remove(&node_id);
        self.states.write().remove(&node_id);
        self.node_registered_at.write().remove(&node_id);
        self.node_urltest_groups.write().remove(&node_id);
        let mut history = self.probe_history.write();
        history.retain(|(id, _), _| *id != node_id);
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

    /// Register a URLTest group for idle-aware probe suspension.
    ///
    /// `members` are NodeIds; callers should exclude members that also
    /// belong to Selector groups (those are probed unconditionally).
    /// `idle_timeout` defaults to [`DEFAULT_URLTEST_IDLE_TIMEOUT`] when
    /// `None`. Re-callable on config reload.
    pub fn register_urltest_group(
        &self,
        group: &str,
        members: &[Uuid],
        idle_timeout: Option<Duration>,
    ) {
        let timeout = idle_timeout.unwrap_or(DEFAULT_URLTEST_IDLE_TIMEOUT);
        self.urltest_group_timeout
            .write()
            .insert(group.to_string(), timeout);
        self.urltest_group_members
            .write()
            .insert(group.to_string(), members.to_vec());
        let mut node_groups = self.node_urltest_groups.write();
        for member in members {
            node_groups
                .entry(*member)
                .or_default()
                .push(group.to_string());
        }
    }

    /// Replace the whole custom check-URL table (config reload), same
    /// shape as [`AliveDialerSet::sync_urltest_groups`]: `groups` is
    /// `(group name, check_url)` for every group that has a custom
    /// `check_url`. Entries for groups absent from `groups` are dropped;
    /// per-(tag, url) probe state and latency data survive as long as the
    /// URL itself is still in use by some group.
    pub fn sync_group_check_urls(&self, groups: &[(String, String)]) {
        {
            let mut map = self.group_check_urls.write();
            map.clear();
            for (group, url) in groups {
                map.insert(group.clone(), url.clone());
            }
        }
        let active_urls: HashSet<String> = self.group_check_urls.read().values().cloned().collect();
        self.url_check_ips
            .write()
            .retain(|url, _| active_urls.contains(url));
        self.url_states
            .write()
            .retain(|(_, url), _| active_urls.contains(url));
        self.url_collections
            .write()
            .retain(|(_, url), _| active_urls.contains(url));
    }

    /// Groups with a custom check URL: `(group name, url)`.
    pub fn group_check_urls(&self) -> Vec<(String, String)> {
        self.group_check_urls
            .read()
            .iter()
            .map(|(g, u)| (g.clone(), u.clone()))
            .collect()
    }

    /// Install the member-tag → leaf resolver used by custom-URL probing
    /// (see the `group_check_urls` field docs).
    pub fn set_url_member_resolver(&self, resolver: Option<UrlMemberResolver>) {
        *self.url_member_resolver.write() = resolver;
    }

    /// Resolve a custom-URL group's members to `(tag, leaf)` pairs through
    /// the installed resolver. Empty when no resolver is installed (tests
    /// drive the per-url state directly).
    pub fn url_members_for(&self, group: &str) -> Vec<(String, String)> {
        self.url_member_resolver
            .read()
            .as_ref()
            .map(|r| r(group))
            .unwrap_or_default()
    }

    /// Whether the member is alive for a custom check URL. The key is the
    /// member tag; members never probed default to alive.
    pub fn is_alive_for_url(&self, node_id: &str, url: &str) -> bool {
        self.url_states
            .read()
            .get(&(node_id.to_string(), url.to_string()))
            .map(|s| s.alive)
            .unwrap_or(true)
    }

    /// Whether any probe result has been recorded for (member tag, url).
    pub fn has_url_state(&self, node_id: &str, url: &str) -> bool {
        self.url_states
            .read()
            .contains_key(&(node_id.to_string(), url.to_string()))
    }

    /// Moving-average latency for (member tag, check_url) — the ranking
    /// metric for URLTest groups with a custom check URL.
    pub fn get_avg_latency_for_url(&self, node_id: &str, url: &str) -> Option<Duration> {
        let cols = self.url_collections.read();
        let coll = cols.get(&(node_id.to_string(), url.to_string()))?;
        let ma = coll.moving_average_duration();
        if ma > Duration::ZERO { Some(ma) } else { None }
    }

    /// Record a successful custom-URL probe (recovery hysteresis mirrors
    /// the global path: a dead node needs RECOVERY_SUCCESSES_NEEDED
    /// consecutive successes to revive).
    pub(crate) fn record_url_probe_success(&self, node_id: &str, url: &str, latency: Duration) {
        let key = (node_id.to_string(), url.to_string());
        {
            let mut states = self.url_states.write();
            let e = states.entry(key.clone()).or_insert_with(UrlProbeState::new);
            if e.alive {
                e.consecutive_failures = 0;
                e.consecutive_successes = 0;
                e.cooldown_until = Instant::now();
            } else {
                e.consecutive_successes += 1;
                e.consecutive_failures = 0;
                if e.consecutive_successes >= RECOVERY_SUCCESSES_NEEDED {
                    e.alive = true;
                    e.consecutive_successes = 0;
                    e.cooldown_until = Instant::now();
                }
            }
        }
        let coll = {
            let mut cols = self.url_collections.write();
            cols.entry(key)
                .or_insert_with(|| Arc::new(DialerCollection::new()))
                .clone()
        };
        if self.is_alive_for_url(node_id, url) {
            coll.mark_available(latency);
        }
    }

    /// Record a failed custom-URL probe: TCP-probe parity — three
    /// consecutive failures kill the node for this URL; backoff 5s→300s
    /// with no permanent stop.
    pub(crate) fn record_url_probe_failure(&self, node_id: &str, url: &str) {
        let key = (node_id.to_string(), url.to_string());
        let mut states = self.url_states.write();
        let e = states.entry(key).or_insert_with(UrlProbeState::new);
        e.consecutive_successes = 0;
        e.consecutive_failures += 1;
        let backoff = probe_backoff(
            self.base_cooldown,
            self.max_cooldown,
            e.consecutive_failures,
        );
        e.cooldown_until = Instant::now() + backoff;
        if e.consecutive_failures >= probe_failure_threshold(ProbeDomain::Tcp) {
            e.alive = false;
        }
    }

    /// Whether a (node, url) probe is due (deep backoff still probes on
    /// the slow cadence, matching the global path).
    fn should_probe_url(&self, node_id: &str, url: &str) -> bool {
        self.url_states
            .read()
            .get(&(node_id.to_string(), url.to_string()))
            .map(|s| Instant::now() >= s.cooldown_until)
            .unwrap_or(true)
    }

    /// Cached resolved IPs for a custom check URL, resolving on first use
    /// (same caching + literal-fallback semantics as the global check URL).
    async fn check_ips_for_url(&self, url: &str) -> Vec<SocketAddr> {
        if let Some(ips) = self.url_check_ips.read().get(url) {
            return ips.clone();
        }
        let ips = match Self::parse_url_host(url) {
            Some(hostname) => {
                let port = Self::parse_url_port(url);
                let addrs = self.resolve_host(&hostname, port).await;
                Self::merge_check_addrs(addrs, url, port)
            }
            None => Self::merge_check_addrs(Vec::new(), url, Self::parse_url_port(url)),
        };
        self.url_check_ips
            .write()
            .insert(url.to_string(), ips.clone());
        ips
    }

    /// Replace the whole URLTest group table (config reload).
    ///
    /// `groups` is `(group name, member NodeIds, idle timeout)` per
    /// URLTest group — the same shape [`register_urltest_group`] takes.
    /// Entries for groups absent from `groups` are dropped, and the
    /// node → groups index is rebuilt from scratch (so stale memberships
    /// and duplicate entries from repeated registration disappear).
    /// `group_last_active` timestamps survive for groups that still exist,
    /// keeping the idle-suspension state across the reload.
    pub fn sync_urltest_groups(&self, groups: &[(String, Vec<Uuid>, Option<Duration>)]) {
        {
            let mut timeouts = self.urltest_group_timeout.write();
            let mut members_map = self.urltest_group_members.write();
            let mut node_groups = self.node_urltest_groups.write();
            timeouts.clear();
            members_map.clear();
            node_groups.clear();
            for (group, members, idle_timeout) in groups {
                timeouts.insert(
                    group.clone(),
                    idle_timeout.unwrap_or(DEFAULT_URLTEST_IDLE_TIMEOUT),
                );
                members_map.insert(group.clone(), members.clone());
                for member in members {
                    node_groups.entry(*member).or_default().push(group.clone());
                }
            }
        }
        let surviving: HashSet<String> =
            self.urltest_group_timeout.read().keys().cloned().collect();
        self.group_last_active
            .write()
            .retain(|group, _| surviving.contains(group));
    }

    /// Record activity for a group (called from group selection paths).
    ///
    /// When a suspended URLTest group becomes active again, health checks
    /// resume and member probes are kicked off immediately so latency data
    /// is fresh for the next selection.
    pub fn mark_group_active(&self, group: &str) {
        let Some(timeout) = self.urltest_group_timeout.read().get(group).copied() else {
            return;
        };
        let was_idle = {
            let mut active = self.group_last_active.write();
            let now = Instant::now();
            let was_idle = active
                .get(group)
                .is_none_or(|last| now.duration_since(*last) >= timeout);
            if let Some(last) = active.get_mut(group) {
                *last = now;
            } else {
                active.insert(group.to_owned(), now);
            }
            was_idle
        };
        if was_idle {
            let members = self
                .urltest_group_members
                .read()
                .get(group)
                .cloned()
                .unwrap_or_default();
            if !members.is_empty() {
                tracing::debug!(
                    "URLTest group '{}' active again — resuming member probes",
                    group
                );
                for member in members {
                    self.trigger_probe(member);
                }
            }
        }
    }

    /// Whether a registered URLTest group has been inactive for longer than
    /// its idle timeout. A never-active group counts as idle (lazy start:
    /// no probes run before the first selection). Unregistered groups are
    /// never idle.
    pub fn is_urltest_group_idle(&self, group: &str) -> bool {
        let timeout = match self.urltest_group_timeout.read().get(group) {
            Some(t) => *t,
            None => return false,
        };
        self.group_last_active
            .read()
            .get(group)
            .map(|t| t.elapsed() >= timeout)
            .unwrap_or(true)
    }

    /// Whether periodic probing of this node is suspended because every
    /// URLTest group it belongs to is idle. Nodes outside URLTest groups
    /// are never suspended.
    pub fn is_probe_suspended(&self, node_id: Uuid) -> bool {
        let groups = self.node_urltest_groups.read();
        match groups.get(&node_id) {
            Some(gs) if !gs.is_empty() => gs.iter().all(|g| self.is_urltest_group_idle(g)),
            _ => false,
        }
    }

    /// Number of consecutive TCP failures for this node.
    /// Used by `GroupManager` to add a backoff penalty to latency-based
    /// selection, deprioritising recently-flapping nodes.
    pub fn consecutive_failures(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> u32 {
        let idx = alive_index(domain, ipver);
        self.states
            .read()
            .get(&node_id)
            .map(|s| s[idx].consecutive_failures)
            .unwrap_or(0)
    }

    /// Extract hostname from a URL string like "http://cp.cloudflare.com".
    ///
    /// The dae config format allows comma-separated fallback IPs after the
    /// URL (`http://host,ip4,ip6`, Go: `TcpCheckOptionRaw.Raw`); only the
    /// first segment is the URL.
    fn parse_url_host(url: &str) -> Option<String> {
        let s = url.trim();
        // The scheme is optional: dae check URLs are usually written with
        // one, but bare `host/path` forms also appear.
        let s = s
            .strip_prefix("http://")
            .or_else(|| s.strip_prefix("https://"))
            .unwrap_or(s);
        // dae comma-separated fallback list: first segment is the URL.
        let s = s.split(',').next().unwrap_or(s).trim();
        // Drop any path/query/fragment — only the authority is resolved.
        // (Previously only a single trailing '/' was stripped, so a URL like
        // `http://www.google-analytics.com/generate_204` was looked up as the
        // hostname "www.google-analytics.com/generate_204" and DNS failed.)
        let s = s.split(['/', '?', '#']).next().unwrap_or(s);
        // Strip the port, keeping bracketed IPv6 literals intact.
        let host = if let Some(rest) = s.strip_prefix('[') {
            rest.split(']').next().unwrap_or(s)
        } else {
            s.split(':').next().unwrap_or(s)
        };
        if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        }
    }

    /// Port of a check URL: the explicit `:port` of the first (URL) segment
    /// wins; otherwise the scheme default (https 443, http/bare 80).
    fn parse_url_port(url: &str) -> u16 {
        let s = url.trim();
        let (default_port, rest) = if let Some(rest) = s.strip_prefix("https://") {
            (443, rest)
        } else if let Some(rest) = s.strip_prefix("http://") {
            (80, rest)
        } else {
            (80, s)
        };
        let authority = rest
            .split(',')
            .next()
            .unwrap_or(rest)
            .trim()
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("");
        let port_str = if let Some(rest) = authority.strip_prefix('[') {
            // [v6]:port — only a port after the closing bracket counts.
            rest.split(']')
                .nth(1)
                .and_then(|tail| tail.strip_prefix(':'))
        } else {
            authority.rsplit_once(':').map(|(_, port)| port)
        };
        port_str
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port)
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

#[derive(Debug, Clone)]
pub struct StickyTarget {
    pub addr: String,
    pub protocol: String,
}

pub struct StickyCache {
    cache: Mutex<HashMap<String, (StickyTarget, Instant)>>,
    ttl: Duration,
}

impl StickyCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            ttl,
        }
    }
    pub fn get_sticky(&self, id: &str) -> Option<StickyTarget> {
        self.cache
            .lock()
            .get(id)
            .filter(|(_, exp)| Instant::now() < *exp)
            .map(|(t, _)| t.clone())
    }
    pub fn set_sticky(&self, id: String, target: StickyTarget) {
        self.cache
            .lock()
            .insert(id, (target, Instant::now() + self.ttl));
    }
    pub fn remove_sticky(&self, id: &str) {
        self.cache.lock().remove(id);
    }
    pub fn prune_expired(&self) -> usize {
        let mut c = self.cache.lock();
        let n = c.len();
        c.retain(|_, (_, e)| Instant::now() < *e);
        n - c.len()
    }
}
