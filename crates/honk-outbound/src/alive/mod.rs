//! Outbound dialer management — alive detection and recovery state.

pub mod collection;
mod health;
pub mod latencies;
mod observations;
mod probe;
pub(crate) mod route_health;
mod runner;
mod urltest;

#[cfg(test)]
mod tests;

use self::collection::DialerCollection;
use crate::group::{ScoreFeedback, ScoreSelectionContext};
pub use observations::{
    GroupHealthObservation, GroupProbeContext, HealthAverages, HealthMeasurement,
    HealthObservation, HealthPurpose, HealthState, HealthTransport, HealthWarmth, ProbeMeasurement,
    ProbeTicket, UrlProbeMember,
};
use parking_lot::{Mutex, RwLock};
pub use probe::RouteHttpProber;
pub use route_health::{
    RouteHealthRevision, RouteHealthStamp, RouteProbeTicket, UdpBareReply, UdpHealthNotifications,
    UdpHopRole, UdpRouteAdmission,
};
pub use runner::{HealthCheckError, HealthProbePermit, ProbeCancellation};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
pub use urltest::{IdleActivitySlot, IdleGroupKind, IdleGroupRegistration};
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
    Cancelled,
}

#[derive(Debug)]
pub struct HttpProbeOutcome {
    pub result: HttpProbeResult,
    pub observation: Option<HealthObservation>,
}

impl From<HttpProbeResult> for HttpProbeOutcome {
    fn from(result: HttpProbeResult) -> Self {
        Self {
            result,
            observation: None,
        }
    }
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
/// Cancellation must stop network work and join owned children before returning.
pub trait HttpProber: Send + Sync {
    fn probe_http(
        &self,
        node_id: Uuid,
        addr: SocketAddr,
        url: &str,
        timeout: Duration,
        cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = HttpProbeOutcome> + Send + 'static>>;
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
    /// Legacy setup-inclusive DNS attempt timing; qualified exchange-only
    /// timing is retained separately in `observations`. `None` means no attempt.
    pub dns: Option<anyhow::Result<Duration>>,
    /// Independent data-path handshake result; `None` when not run (no HTTPS
    /// check URL, no Score group, or target policy skips it).
    pub data_path: Option<anyhow::Result<Duration>>,
    /// Qualified DNS and data measurements, captured before legacy family fanout.
    pub observations: [Option<HealthObservation>; 2],
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
/// Cancellation preserves completed measurements and joins owned children.
pub trait UdpProber: Send + Sync {
    fn probe_udp(
        &self,
        node_id: Uuid,
        timeout: Duration,
        cancel: ProbeCancellation,
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
    /// A probe or traffic outcome has reached this state; a fresh state's
    /// `alive: true` is only the optimistic default.
    measured: bool,
    /// Probe-based consecutive failures.
    consecutive_failures: u32,
    /// Probe-based consecutive successes (for recovery hysteresis).
    consecutive_successes: u32,
    /// Traffic-based consecutive failures (separate counter, higher thresholds).
    traffic_failures: u32,
    /// A TCP traffic down edge confirmed by the routed outcome owner; zero otherwise.
    route_down_at: u64,
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
        self.measured = true;
        self.consecutive_failures = 0;
        self.consecutive_successes = 0;
        self.traffic_failures = 0;
        self.route_down_at = 0;
        self.stopped = false;
        self.cooldown_until = Instant::now();
    }

    /// A fresh, never-measured state is not clean, so the first success
    /// still records `measured`.
    fn is_clean_alive(&self) -> bool {
        self.measured
            && self.alive
            && self.consecutive_failures == 0
            && self.consecutive_successes == 0
            && self.traffic_failures == 0
            && !self.stopped
    }

    fn new() -> Self {
        Self {
            alive: true,
            measured: false,
            consecutive_failures: 0,
            consecutive_successes: 0,
            traffic_failures: 0,
            route_down_at: 0,
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

fn fresh_states() -> NodeStates {
    NodeStates {
        protocols: std::array::from_fn(|_| PerProtocolState::new()),
        route_tcp: Default::default(),
        route_udp: None,
    }
}

struct NodeStates {
    protocols: [PerProtocolState; ALIVE_STATES_PER_NODE],
    route_tcp: [route_health::Evidence; IpVersion::count()],
    route_udp: Option<
        Box<[route_health::RoutedUdpNode; (ALIVE_STATES_PER_NODE - IpVersion::count()) * 2]>,
    >,
}

impl std::ops::Index<usize> for NodeStates {
    type Output = PerProtocolState;

    fn index(&self, index: usize) -> &Self::Output {
        &self.protocols[index]
    }
}

impl std::ops::IndexMut<usize> for NodeStates {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.protocols[index]
    }
}

type EbpfAliveCallback = dyn Fn(Uuid, u8, u32, u32, bool) + Send + Sync;

/// Callback fired when a node's (domain, ip-version) state flips
/// alive→dead on the probe path (same trigger as the eBPF connectivity
/// push). Carries the NodeId plus the registered display name for logs.
/// honk-core purges pooled connections and UDP endpoints bound to the
/// node from it. Fires once per domain/ip-version flip — handlers
/// must be idempotent.
type DeathCallback = dyn Fn(Uuid, &str) + Send + Sync;
type RoutedUdpConnectivityCallback = dyn Fn(Uuid, ProbeDomain, IpVersion) + Send + Sync;
type RoutedUdpDeathCallback = dyn Fn(Uuid, ProbeDomain, IpVersion, UdpHopRole) + Send + Sync;

/// Resolves custom-check members with concrete leaf IDs and optional captured
/// native group/member identities; display tags are not node lookup keys.
pub type UrlMemberResolver = Arc<dyn Fn(&str) -> Vec<UrlProbeMember> + Send + Sync>;

/// Default group idle timeout when the group config has none (sing-box
/// default: 30 minutes). Periodic probing of an automatic group's direct
/// members pauses while the group is idle and resumes on the next selection.
pub const DEFAULT_GROUP_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);

/// Resolves a NodeId to its eBPF outbound index for
/// `OUTBOUND_CONNECTIVITY_MAP` writes (direct=0, block=1, group i → 2+i,
/// matching the control plane's routing push). Returns `None` for nodes
/// without an eBPF outbound id (not in any group) — those state changes
/// are not pushed to the kernel map.
pub type OutboundIdResolver = Arc<dyn Fn(Uuid) -> Option<u8> + Send + Sync>;

/// A node registered for health checking: the content-derived NodeId is
/// the map key; the name is kept only for display and logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredNode {
    pub name: String,
    /// Configured raw TCP endpoint. Virtual chains have no endpoint of their own.
    pub raw_probe_address: Option<String>,
}

#[derive(Default)]
struct Registrations {
    nodes: HashMap<Uuid, Arc<RegisteredNode>>,
    manual_delays: std::collections::BTreeMap<Uuid, ManualDelay>,
}

struct ManualDelay {
    owner: std::sync::Weak<crate::runtime::NodeRuntime>,
    ticket: Arc<()>,
    sample: Option<ProbeMeasurement>,
    /// A legacy sample this slot superseded when the wall clock stepped back.
    superseded_legacy: Option<(Duration, std::time::SystemTime)>,
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

/// Isolates hot lock words and atomics onto dedicated 64-byte cache lines so
/// concurrent readers do not self-invalidate adjacent map metadata or atomics.
#[repr(align(64))]
struct CachePadded<T>(T);

type PaddedRwLock<T> = CachePadded<RwLock<CachePadded<T>>>;
type NodeCollections = HashMap<Uuid, [Arc<DialerCollection>; ALIVE_STATES_PER_NODE]>;

impl<T> std::ops::Deref for CachePadded<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> std::ops::DerefMut for CachePadded<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

pub struct AliveDialerSet {
    /// Uses parking_lot RwLock/Mutex for synchronous, uncontended access on the
    /// async runtime (parking_lot blocks OS threads without runtime awareness).
    states: PaddedRwLock<HashMap<Uuid, NodeStates>>,
    /// Per-node-per-domain latency collections (Go `collection` struct).
    collections: PaddedRwLock<NodeCollections>,
    registered: RwLock<Registrations>,
    route_health: RwLock<route_health::RouteHealth>,
    /// Fast negative hint; exact domain/family/operation evidence remains in `NodeStates`.
    udp_faults: AtomicBool,
    route_http_prober: RwLock<Option<Arc<dyn RouteHttpProber>>>,
    connectivity_callback: RwLock<Option<Arc<health::ConnectivityCallback>>>,
    /// DIRECT also accepts delay evidence without a periodic registration.
    /// Removing its history invalidates those tickets under the registration lock.
    direct_removals: AtomicU64,
    health_observations: RwLock<Option<observations::HealthHistory>>,
    ebpf_callback: RwLock<Option<Arc<EbpfAliveCallback>>>,
    death_callback: RwLock<Option<Arc<DeathCallback>>>,
    routed_udp_death_callback: RwLock<Option<Arc<RoutedUdpDeathCallback>>>,
    routed_udp_connectivity_callback: RwLock<Option<Arc<RoutedUdpConnectivityCallback>>>,
    base_cooldown: Duration,
    max_cooldown: Duration,
    /// Bounded node-deduplicated emergency probe queue. A pending node owns
    /// at most one entry, so traffic failure storms cannot grow memory. The
    /// value records whether custom `check_url` probing should also run after
    /// the global TCP probe (coalesced via `|=` when a failure trigger arrives
    /// alongside a node-only wake).
    trigger_tx: tokio::sync::mpsc::Sender<Uuid>,
    trigger_rx: Mutex<Option<tokio::sync::mpsc::Receiver<Uuid>>>,
    trigger_pending: Mutex<HashMap<Uuid, bool>>,
    health_control: Mutex<runner::HealthControl>,
    health_mode: tokio::sync::watch::Sender<runner::HealthMode>,
    health_changed: tokio::sync::Notify,
    external_probes: Mutex<tokio::task::JoinSet<()>>,
    #[cfg(feature = "owned-tasks")]
    health_resolver_tasks: Mutex<Option<Arc<crate::runtime::TaskOwner>>>,
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
    /// Monotonic origin for exact sub-second per-group activity timestamps.
    started_at: Instant,
    /// Monotonic coarse origin (Linux `CLOCK_MONOTONIC_COARSE`, ns) for `>= 1s`
    /// per-group activity timestamps.
    #[cfg(target_os = "linux")]
    started_at_coarse_ns: u64,
    /// Bumped on every idle-group table mutation to invalidate cached
    /// [`IdleActivitySlot`] handles.
    idle_generation: CachePadded<AtomicU64>,
    /// Idle-group membership, timeouts, and per-group activity timestamps.
    idle_groups: RwLock<urltest::IdleGroups>,
    /// Nodes a group holds fixed (manual selection or non-builtin node `final`);
    /// they keep periodic probing while their groups are idle.
    selected_nodes: RwLock<HashSet<Uuid>>,
    /// Automatic group name → pinned member tags that keep custom-`check_url`
    /// probing while the group is idle.
    pinned_url_members: RwLock<HashMap<String, HashSet<String>>>,
    /// Custom-`check_url` groups queued for asynchronous member-probe wakeup
    /// (resolved on the health loop, off caller locks such as `SharedGroupManager`).
    pending_url_group_wakes: Mutex<HashSet<String>>,
    url_group_wake_notify: tokio::sync::Notify,
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

const _: () = {
    assert!(std::mem::align_of::<PaddedRwLock<HashMap<Uuid, NodeStates>>>() >= 64);
    assert!(std::mem::size_of::<PaddedRwLock<HashMap<Uuid, NodeStates>>>() >= 128);
    assert!(std::mem::size_of::<PaddedRwLock<NodeCollections>>() >= 128);
    assert!(std::mem::align_of::<CachePadded<AtomicU64>>() >= 64);
};

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
        let (health_mode, _) = tokio::sync::watch::channel(runner::HealthMode::Running);
        Self {
            states: CachePadded(RwLock::new(CachePadded(HashMap::new()))),
            collections: CachePadded(RwLock::new(CachePadded(HashMap::new()))),
            registered: RwLock::default(),
            route_health: RwLock::default(),
            udp_faults: AtomicBool::new(false),
            route_http_prober: RwLock::default(),
            connectivity_callback: RwLock::default(),
            direct_removals: AtomicU64::new(0),
            health_observations: RwLock::new(None),
            ebpf_callback: RwLock::new(None),
            death_callback: RwLock::new(None),
            routed_udp_death_callback: RwLock::default(),
            routed_udp_connectivity_callback: RwLock::default(),
            resolver: RwLock::new(None),
            base_cooldown: Duration::from_secs(5),
            max_cooldown: Duration::from_secs(300),
            trigger_tx: tx,
            trigger_rx: Mutex::new(Some(rx)),
            trigger_pending: Mutex::new(HashMap::new()),
            health_control: Mutex::new(runner::HealthControl::default()),
            health_mode,
            health_changed: tokio::sync::Notify::new(),
            external_probes: Mutex::new(tokio::task::JoinSet::new()),
            #[cfg(feature = "owned-tasks")]
            health_resolver_tasks: Mutex::new(None),
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
            started_at: Instant::now(),
            #[cfg(target_os = "linux")]
            started_at_coarse_ns: urltest::monotonic_coarse_ns(),
            idle_generation: CachePadded(AtomicU64::new(0)),
            idle_groups: RwLock::default(),
            selected_nodes: RwLock::new(HashSet::new()),
            pinned_url_members: RwLock::new(HashMap::new()),
            pending_url_group_wakes: Mutex::new(HashSet::new()),
            url_group_wake_notify: tokio::sync::Notify::new(),
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
        let permit = self.acquire_health_probe()?;
        let cancel = permit.cancellation();
        // Boxed: unboxed, this future is large enough in debug builds to overflow
        // the worker stack when the check URL resolves through a proxied upstream.
        let operation = Box::pin(self.resolve_host_inner(host, port));
        cancel
            .run(cancel.scope_resolution(operation))
            .await
            .ok_or(HealthCheckError::Stopped)?
    }

    async fn resolve_host_inner(&self, host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
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

    /// Retire endpoints and source associations bound to this hop operation, domain and family.
    pub fn set_routed_udp_death_callback(&self, cb: Option<Box<RoutedUdpDeathCallback>>) {
        *self.routed_udp_death_callback.write() = cb.map(Arc::from);
    }

    pub fn set_routed_udp_connectivity_callback(
        &self,
        callback: impl Fn(Uuid, ProbeDomain, IpVersion) + Send + Sync + 'static,
    ) {
        *self.routed_udp_connectivity_callback.write() = Some(Arc::new(callback));
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
            .is_none_or(|s| s[idx].alive && s.routed_udp_available(domain, idx))
    }

    /// TCP liveness across address families: alive when any family with a
    /// probe or traffic outcome is alive, or when no family has one yet.
    pub fn tcp_alive_any_measured(&self, node_id: Uuid) -> bool {
        let states = self.states.read();
        let Some(states) = states.get(&node_id) else {
            return true;
        };
        let mut measured = [IpVersion::V4, IpVersion::V6]
            .into_iter()
            .map(|ipver| &states[alive_index(ProbeDomain::Tcp, ipver)])
            .filter(|state| state.measured)
            .peekable();
        measured.peek().is_none() || measured.any(|state| state.alive)
    }

    /// Get (or create) the `DialerCollection` for a given node and domain index.
    fn get_or_create_collection(&self, node_id: Uuid, idx: usize) -> Arc<DialerCollection> {
        let mut cols = self.collections.write();
        let arr = cols
            .entry(node_id)
            .or_insert_with(|| std::array::from_fn(|_| Arc::new(DialerCollection::new())));
        Arc::clone(&arr[idx])
    }

    pub fn register_node(&self, node_id: Uuid, name: String, raw_probe_address: Option<String>) {
        let mut registered = self.registered.write();
        self.register_node_locked(&mut registered, node_id, name, raw_probe_address);
    }

    fn register_node_locked(
        &self,
        registered: &mut Registrations,
        node_id: Uuid,
        name: String,
        raw_probe_address: Option<String>,
    ) {
        registered.manual_delays.remove(&node_id);
        registered.nodes.insert(
            node_id,
            Arc::new(RegisteredNode {
                name,
                raw_probe_address,
            }),
        );
        self.node_registered_at
            .write()
            .insert(node_id, Instant::now());
        let mut states = self.states.write();
        states.entry(node_id).or_insert_with(fresh_states);
    }

    /// Temporary registration lookup for group-exit selection and traffic reporting.
    pub fn is_registered(&self, node_id: Uuid) -> bool {
        self.registered.read().nodes.contains_key(&node_id)
    }

    /// Install the accepted health targets, preserving the exact registration
    /// and grace period of each unchanged node. Returns `(added, removed)`.
    pub fn sync_registrations(
        &self,
        targets: HashMap<Uuid, (&str, Option<&str>)>,
    ) -> (usize, usize) {
        self.sync_registrations_retaining_delays(targets, |_| true)
    }

    /// Publish registrations and invalidate manual delays whose ordinary leaf was replaced.
    /// `retain` uses the caller's immutable publication data under the registration lock.
    pub fn sync_registrations_retaining_delays(
        &self,
        targets: HashMap<Uuid, (&str, Option<&str>)>,
        retain: impl FnMut(&Uuid) -> bool,
    ) -> (usize, usize) {
        self.sync_registrations_inner(targets, retain, |id| {
            self.states.write().remove(&id);
        })
    }

    /// Stage proven routed hop failures while dropping old probe registrations.
    /// The accepted manager revalidates their ordered paths at route publication.
    pub fn sync_registrations_retaining_routes(
        &self,
        targets: HashMap<Uuid, (&str, Option<&str>)>,
        retain: impl FnMut(&Uuid) -> bool,
        mut routed: impl FnMut(&Uuid) -> bool,
    ) -> (usize, usize) {
        let mut route_health = self.route_health.write();
        route_health.retire_owner();
        let changes = self.sync_registrations_inner(targets, retain, |id| {
            self.clear_registered_route_health(&mut route_health, id, routed(&id));
        });
        self.prune_unrouted_uuids(routed);
        changes
    }

    fn sync_registrations_inner(
        &self,
        targets: HashMap<Uuid, (&str, Option<&str>)>,
        mut retain: impl FnMut(&Uuid) -> bool,
        mut remove_state: impl FnMut(Uuid),
    ) -> (usize, usize) {
        let mut registered = self.registered.write();
        registered.manual_delays.retain(|id, _| retain(id));
        let before = registered.nodes.len();
        if registered.nodes.keys().any(|id| !targets.contains_key(id)) {
            if let Some(observations) = self.health_observations.write().as_mut() {
                // DIRECT can have samples even if it was never registered.
                observations.remove_nodes(|id| {
                    registered.nodes.contains_key(id) && !targets.contains_key(id)
                });
            }
            registered.nodes.retain(|id, _| {
                if targets.contains_key(id) {
                    return true;
                }
                remove_state(*id);
                self.clear_legacy_node_state(*id);
                false
            });
        }
        let removed = before - registered.nodes.len();
        let mut added = 0;
        for (id, (name, raw_address)) in targets {
            if registered.nodes.get(&id).is_some_and(|node| {
                node.name == name && node.raw_probe_address.as_deref() == raw_address
            }) {
                continue;
            }
            self.register_node_locked(
                &mut registered,
                id,
                name.to_owned(),
                raw_address.map(str::to_owned),
            );
            added += 1;
        }
        (added, removed)
    }

    /// Snapshot of current health-check registrations.
    pub fn registered_nodes(&self) -> HashMap<Uuid, RegisteredNode> {
        self.registered
            .read()
            .nodes
            .iter()
            .map(|(id, node)| (*id, node.as_ref().clone()))
            .collect()
    }

    /// Registered display name for logs; falls back to
    /// the ID itself for nodes driven without registration (tests).
    pub fn node_name(&self, node_id: Uuid) -> String {
        self.registered
            .read()
            .nodes
            .get(&node_id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| node_id.to_string())
    }

    pub fn remove_node(&self, node_id: Uuid) {
        let mut registered = self.registered.write();
        registered.manual_delays.remove(&node_id);
        registered.nodes.remove(&node_id);
        if let Some(observations) = self.health_observations.write().as_mut() {
            observations.remove_node(node_id);
        }
        self.states.write().remove(&node_id);
        self.clear_legacy_node_state(node_id);
    }

    fn clear_legacy_node_state(&self, node_id: Uuid) {
        if node_id == honk_config::config::DIRECT_NODE_ID {
            self.direct_removals.fetch_add(1, Ordering::Relaxed);
        }
        self.collections.write().remove(&node_id);
        self.node_registered_at.write().remove(&node_id);
        self.idle_groups.write().remove_node(node_id);
        self.selected_nodes.write().remove(&node_id);
        {
            let mut history = self.probe_history.write();
            for index in 0..ALIVE_STATES_PER_NODE {
                history.remove(&(node_id, index));
            }
        }
        self.last_emergency_tcp.lock().remove(&node_id);
        self.last_emergency_udp.lock().remove(&node_id);
        self.trigger_pending.lock().remove(&node_id);
    }

    /// A link/address/route change invalidates probe backoff that may have
    /// been accumulated while the host had no usable uplink. Keep nodes
    /// fail-closed until a fresh probe succeeds, but let that verified
    /// success satisfy the recovery hysteresis immediately.
    pub fn notify_network_change(&self) {
        let node_ids: Vec<Uuid> = self.registered.read().nodes.keys().copied().collect();
        let now = Instant::now();
        {
            let mut states = self.states.write();
            for node_id in &node_ids {
                let Some(protocol_states) = states.get_mut(node_id) else {
                    continue;
                };
                for state in &mut protocol_states.protocols {
                    state.cooldown_until = now;
                    if !state.alive {
                        state.consecutive_successes = RECOVERY_SUCCESSES_NEEDED - 1;
                    }
                }
            }
        }
        let mut dead_urls = HashSet::new();
        {
            let mut url_states = self.url_states.write();
            for ((_, url), state) in url_states.iter_mut() {
                state.cooldown_until = now;
                if !state.alive {
                    state.consecutive_successes = RECOVERY_SUCCESSES_NEEDED - 1;
                    dead_urls.insert(url.clone());
                }
            }
        }
        for node_id in node_ids {
            if !self.is_probe_suspended(node_id)
                || self.needs_idle_recovery(node_id, ProbeDomain::Tcp)
            {
                self.trigger_probe_node_only(node_id);
            }
        }
        for (group, url) in self.group_check_urls() {
            if !self.is_group_idle(&group)
                || !self.pinned_url_members_for(&group).is_empty()
                || dead_urls.contains(&url)
            {
                self.enqueue_url_group_wake(&group);
            }
        }
    }

    pub(super) fn enqueue_url_group_wake(&self, group: &str) {
        let _control = self.health_control.lock();
        if *self.health_mode.borrow() != runner::HealthMode::Running {
            return;
        }
        if self.pending_url_group_wakes.lock().insert(group.to_owned()) {
            self.url_group_wake_notify.notify_one();
        }
    }

    pub(super) fn take_pending_url_group_wake(&self) -> Option<String> {
        let mut pending = self.pending_url_group_wakes.lock();
        let group = pending.iter().next()?.clone();
        pending.remove(&group);
        Some(group)
    }

    pub fn trigger_probe(&self, node_id: Uuid) {
        self.enqueue_trigger_probe(node_id, true);
    }

    pub(super) fn trigger_probe_node_only(&self, node_id: Uuid) {
        self.enqueue_trigger_probe(node_id, false);
    }

    fn enqueue_trigger_probe(&self, node_id: Uuid, probe_custom_urls: bool) {
        let _control = self.health_control.lock();
        if *self.health_mode.borrow() != runner::HealthMode::Running {
            return;
        }
        let mut pending = self.trigger_pending.lock();
        if let Some(existing) = pending.get_mut(&node_id) {
            *existing |= probe_custom_urls;
            return;
        }
        pending.insert(node_id, probe_custom_urls);
        if self.trigger_tx.try_send(node_id).is_err() {
            // Queue saturation drops this request (a later traffic failure or
            // periodic sweep retries it), and releases its dedup reservation.
            pending.remove(&node_id);
        }
    }

    pub(super) fn take_trigger_custom_urls(&self, node_id: Uuid) -> bool {
        self.trigger_pending
            .lock()
            .get_mut(&node_id)
            .map(|flag| std::mem::replace(flag, false))
            .unwrap_or(false)
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
        assert!(set.take_trigger_custom_urls(same));
        assert!(!set.take_trigger_custom_urls(same));
        set.finish_trigger_probe(same);

        // A failure trigger coalesces custom-URL probing onto a queued node-only wake.
        set.trigger_probe_node_only(same);
        assert_eq!(receiver.try_recv(), Ok(same));
        set.trigger_probe(same);
        assert!(receiver.try_recv().is_err());
        assert!(set.take_trigger_custom_urls(same));
        set.finish_trigger_probe(same);
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
