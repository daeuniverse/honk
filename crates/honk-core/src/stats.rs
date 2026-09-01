//! Statistics tracking for honk-core.

use dashmap::DashMap;
use honk_ebpf_common::OutboundStats;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

pub(crate) mod dns;
#[cfg(test)]
pub(crate) use dns::dns_snapshot;
pub(crate) use dns::{DnsStatEvent, record_dns_event};

/// Per-outbound statistics tracked in user-space.
#[derive(Debug, Clone, Default)]
pub struct OutboundTracker {
    /// Total connections through this outbound
    pub total_connections: Arc<AtomicU64>,
    /// Active connections currently open
    pub active_connections: Arc<AtomicU64>,
    /// Total bytes transferred (client → proxy)
    pub tx_bytes: Arc<AtomicU64>,
    /// Total bytes transferred (proxy → client)
    pub rx_bytes: Arc<AtomicU64>,
    /// Failed connection attempts
    pub errors: Arc<AtomicU64>,
}

impl OutboundTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_connections(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, tx: u64, rx: u64) {
        if tx != 0 {
            self.tx_bytes.fetch_add(tx, Ordering::Relaxed);
        }
        if rx != 0 {
            self.rx_bytes.fetch_add(rx, Ordering::Relaxed);
        }
    }

    pub fn increment_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> OutboundStats {
        OutboundStats {
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: 0, // Not tracked at user-space level
            rx_packets: 0,
            active_conns: self.active_connections.load(Ordering::Relaxed) as u32,
            total_conns: self.total_connections.load(Ordering::Relaxed) as u32,
            errors: self.errors.load(Ordering::Relaxed) as u32,
            _pad: 0,
        }
    }
}

/// Fixed number of log2 latency buckets for UDP metrics. Bucket `n` covers
/// values from `2^n` through `2^(n+1)-1` nanoseconds (except bucket 0,
/// which also includes zero); the final bucket saturates at `u64::MAX`.
pub const UDP_LOG2_BUCKETS: usize = 64;

#[derive(Debug)]
struct Log2Histogram {
    count: AtomicU64,
    sum_nanos: AtomicU64,
    buckets: [AtomicU64; UDP_LOG2_BUCKETS],
}

impl Default for Log2Histogram {
    fn default() -> Self {
        Self {
            count: AtomicU64::new(0),
            sum_nanos: AtomicU64::new(0),
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl Log2Histogram {
    fn record(&self, elapsed: std::time::Duration) {
        let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        let bucket = nanos.max(1).ilog2() as usize;
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> UdpLatencyHistogramSnapshot {
        UdpLatencyHistogramSnapshot {
            count: self.count.load(Ordering::Relaxed),
            sum_nanos: self.sum_nanos.load(Ordering::Relaxed),
            buckets: std::array::from_fn(|index| self.buckets[index].load(Ordering::Relaxed)),
        }
    }
}

/// Immutable copy of one fixed-size UDP latency histogram.
#[derive(Debug, Clone)]
pub struct UdpLatencyHistogramSnapshot {
    pub count: u64,
    pub sum_nanos: u64,
    pub buckets: [u64; UDP_LOG2_BUCKETS],
}

impl UdpLatencyHistogramSnapshot {
    /// Inclusive upper bound, in nanoseconds, of a log2 bucket.
    pub const fn bucket_upper_bound_ns(bucket: usize) -> u64 {
        if bucket >= UDP_LOG2_BUCKETS - 1 {
            u64::MAX
        } else {
            (1u64 << (bucket + 1)) - 1
        }
    }

    /// Return the inclusive bucket upper bound containing the requested
    /// quantile. This remains bounded and needs no labels or dynamic storage.
    pub fn quantile_upper_bound_ns(&self, quantile: f64) -> Option<u64> {
        if self.count == 0 || !(0.0..=1.0).contains(&quantile) {
            return None;
        }
        let target = ((self.count as f64 * quantile).ceil() as u64).max(1);
        let mut seen: u64 = 0;
        for (index, count) in self.buckets.iter().enumerate() {
            seen = seen.saturating_add(*count);
            if seen >= target {
                return Some(Self::bucket_upper_bound_ns(index));
            }
        }
        Some(Self::bucket_upper_bound_ns(UDP_LOG2_BUCKETS - 1))
    }
}

#[derive(Debug, Default)]
struct TcpStats {
    limit: AtomicU64,
    active_flows: AtomicU64,
    /// Admission-loop attempts that found all TCP permits occupied.
    capacity_rejections: AtomicU64,
}

#[cfg(any(feature = "clash-api", test))]
/// Fixed TCP admission metrics exposed by `/stats`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpStatsSnapshot {
    pub limit: u64,
    pub active_flows: u64,
    pub capacity_rejections: u64,
}

#[derive(Debug, Default)]
struct UdpNfqueueStats {
    received: AtomicU64,
    active_flows: AtomicU64,
    kernel_queue_depth: AtomicU64,
    kernel_stats_available: AtomicU64,
    kernel_stats_read_errors: AtomicU64,
    kernel_dropped: AtomicU64,
    kernel_user_dropped: AtomicU64,
    held_packets: AtomicU64,
    held_peak: AtomicU64,
    socket_receive_buffer_bytes: AtomicU64,
    actor_queue_full: AtomicU64,
    correlator_full: AtomicU64,
    actor_queue_depth: AtomicU64,
    actor_queued_bytes: AtomicU64,
    actor_oldest_age_nanos: AtomicU64,
    direct_accepted: AtomicU64,
    proxy_copied: AtomicU64,
    proxy_dropped: AtomicU64,
    block: AtomicU64,
    cancel: AtomicU64,
    drop: AtomicU64,
    token_mismatch: AtomicU64,
    token_exhaustion: AtomicU64,
    token_rollovers: AtomicU64,
    verdict_errors: AtomicU64,
    receipt_to_verdict_latency: Log2Histogram,
}

impl UdpNfqueueStats {
    fn record_verdict(&self, counter: &AtomicU64, elapsed: std::time::Duration) {
        counter.fetch_add(1, Ordering::Relaxed);
        self.receipt_to_verdict_latency.record(elapsed);
    }

    fn snapshot(&self) -> UdpNfqueueStatsSnapshot {
        UdpNfqueueStatsSnapshot {
            received: self.received.load(Ordering::Relaxed),
            active_flows: self.active_flows.load(Ordering::Relaxed),
            kernel_queue_depth: self.kernel_queue_depth.load(Ordering::Relaxed),
            kernel_stats_available: self.kernel_stats_available.load(Ordering::Relaxed) != 0,
            kernel_stats_read_errors: self.kernel_stats_read_errors.load(Ordering::Relaxed),
            kernel_dropped: self.kernel_dropped.load(Ordering::Relaxed),
            kernel_user_dropped: self.kernel_user_dropped.load(Ordering::Relaxed),
            held_packets: self.held_packets.load(Ordering::Relaxed),
            held_peak: self.held_peak.load(Ordering::Relaxed),
            socket_receive_buffer_bytes: self.socket_receive_buffer_bytes.load(Ordering::Relaxed),
            actor_queue_full: self.actor_queue_full.load(Ordering::Relaxed),
            correlator_full: self.correlator_full.load(Ordering::Relaxed),
            actor_queue_depth: self.actor_queue_depth.load(Ordering::Relaxed),
            actor_queued_bytes: self.actor_queued_bytes.load(Ordering::Relaxed),
            actor_oldest_age_nanos: self.actor_oldest_age_nanos.load(Ordering::Relaxed),
            direct_accepted: self.direct_accepted.load(Ordering::Relaxed),
            proxy_copied: self.proxy_copied.load(Ordering::Relaxed),
            proxy_dropped: self.proxy_dropped.load(Ordering::Relaxed),
            block: self.block.load(Ordering::Relaxed),
            cancel: self.cancel.load(Ordering::Relaxed),
            drop: self.drop.load(Ordering::Relaxed),
            token_mismatch: self.token_mismatch.load(Ordering::Relaxed),
            token_exhaustion: self.token_exhaustion.load(Ordering::Relaxed),
            token_rollovers: self.token_rollovers.load(Ordering::Relaxed),
            verdict_errors: self.verdict_errors.load(Ordering::Relaxed),
            receipt_to_verdict_latency: self.receipt_to_verdict_latency.snapshot(),
        }
    }
}

/// Immutable snapshot of the fixed NFQUEUE UDP metrics schema.
#[derive(Debug, Clone)]
pub struct UdpNfqueueStatsSnapshot {
    pub received: u64,
    pub active_flows: u64,
    pub kernel_queue_depth: u64,
    pub kernel_stats_available: bool,
    pub kernel_stats_read_errors: u64,
    pub kernel_dropped: u64,
    pub kernel_user_dropped: u64,
    pub held_packets: u64,
    pub held_peak: u64,
    pub socket_receive_buffer_bytes: u64,
    pub actor_queue_full: u64,
    pub correlator_full: u64,
    pub actor_queue_depth: u64,
    pub actor_queued_bytes: u64,
    pub actor_oldest_age_nanos: u64,
    pub direct_accepted: u64,
    pub proxy_copied: u64,
    pub proxy_dropped: u64,
    pub block: u64,
    pub cancel: u64,
    pub drop: u64,
    pub token_mismatch: u64,
    pub token_exhaustion: u64,
    pub token_rollovers: u64,
    pub verdict_errors: u64,
    pub receipt_to_verdict_latency: UdpLatencyHistogramSnapshot,
}

/// Fixed, allocation-free UDP pipeline metrics for the current control-plane
/// path. The schema is intentionally stable while each recorder is wired to
/// its corresponding production event.
#[derive(Debug, Default)]
struct UdpStats {
    endpoint_hits: AtomicU64,
    endpoint_misses: AtomicU64,
    route_latency: Log2Histogram,
    dial_latency: Log2Histogram,
    reply_ready_latency: Log2Histogram,
    first_send_latency: Log2Histogram,
    first_reply_latency: Log2Histogram,
    capacity_rejections: AtomicU64,
    slow_permit_accepted: AtomicU64,
    slow_permit_rejected: AtomicU64,
    slow_permit_closed: AtomicU64,
    queue_accepted: AtomicU64,
    /// Drop-newest because this flow's packet-slot bound was exhausted.
    flow_queue_full: AtomicU64,
    /// Drop-newest because the global retained-payload-byte bound was exhausted.
    global_payload_full: AtomicU64,
    /// Aggregate retained-queue drops retained for the stable API schema.
    queue_full: AtomicU64,
    queue_closed: AtomicU64,
    first_send_failures: AtomicU64,
    stagger_attempts: AtomicU64,
    stagger_winners: AtomicU64,
    stagger_cancellations: AtomicU64,
    warm_attempts: AtomicU64,
    warm_successes: AtomicU64,
    warm_failures: AtomicU64,
    nfqueue: UdpNfqueueStats,
}

/// Immutable snapshot of the fixed UDP metrics schema exposed by `/stats`.
#[derive(Debug, Clone)]
pub struct UdpStatsSnapshot {
    pub endpoint_hits: u64,
    pub endpoint_misses: u64,
    pub route_latency: UdpLatencyHistogramSnapshot,
    pub dial_latency: UdpLatencyHistogramSnapshot,
    pub reply_ready_latency: UdpLatencyHistogramSnapshot,
    pub first_send_latency: UdpLatencyHistogramSnapshot,
    pub first_reply_latency: UdpLatencyHistogramSnapshot,
    pub capacity_rejections: u64,
    pub slow_permit_accepted: u64,
    pub slow_permit_rejected: u64,
    pub slow_permit_closed: u64,
    pub queue_accepted: u64,
    pub flow_queue_full: u64,
    pub global_payload_full: u64,
    pub queue_full: u64,
    pub queue_closed: u64,
    pub first_send_failures: u64,
    pub stagger_attempts: u64,
    pub stagger_winners: u64,
    pub stagger_cancellations: u64,
    pub warm_attempts: u64,
    pub warm_successes: u64,
    pub warm_failures: u64,
    pub nfqueue: UdpNfqueueStatsSnapshot,
}

impl UdpStats {
    fn snapshot(&self) -> UdpStatsSnapshot {
        UdpStatsSnapshot {
            endpoint_hits: self.endpoint_hits.load(Ordering::Relaxed),
            endpoint_misses: self.endpoint_misses.load(Ordering::Relaxed),
            route_latency: self.route_latency.snapshot(),
            dial_latency: self.dial_latency.snapshot(),
            reply_ready_latency: self.reply_ready_latency.snapshot(),
            first_send_latency: self.first_send_latency.snapshot(),
            first_reply_latency: self.first_reply_latency.snapshot(),
            capacity_rejections: self.capacity_rejections.load(Ordering::Relaxed),
            slow_permit_accepted: self.slow_permit_accepted.load(Ordering::Relaxed),
            slow_permit_rejected: self.slow_permit_rejected.load(Ordering::Relaxed),
            slow_permit_closed: self.slow_permit_closed.load(Ordering::Relaxed),
            queue_accepted: self.queue_accepted.load(Ordering::Relaxed),
            flow_queue_full: self.flow_queue_full.load(Ordering::Relaxed),
            global_payload_full: self.global_payload_full.load(Ordering::Relaxed),
            queue_closed: self.queue_closed.load(Ordering::Relaxed),
            queue_full: self.queue_full.load(Ordering::Relaxed),
            first_send_failures: self.first_send_failures.load(Ordering::Relaxed),
            stagger_attempts: self.stagger_attempts.load(Ordering::Relaxed),
            stagger_winners: self.stagger_winners.load(Ordering::Relaxed),
            stagger_cancellations: self.stagger_cancellations.load(Ordering::Relaxed),
            warm_attempts: self.warm_attempts.load(Ordering::Relaxed),
            warm_successes: self.warm_successes.load(Ordering::Relaxed),
            warm_failures: self.warm_failures.load(Ordering::Relaxed),
            nfqueue: self.nfqueue.snapshot(),
        }
    }
}

/// Keeps exactly one per-outbound active-connection increment live. Dropping
/// the guard only balances `active_connections`; explicit error paths remain
/// responsible for recording errors themselves.
pub struct ActiveConnectionGuard {
    tracker: OutboundTracker,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.tracker.decrement_connections();
    }
}

pub(crate) struct TcpFlowGuard {
    stats: Arc<StatsManager>,
}

impl Drop for TcpFlowGuard {
    fn drop(&mut self) {
        let _ = self.stats.tcp.active_flows.try_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |active| Some(active.saturating_sub(1)),
        );
    }
}

/// Statistics manager that tracks per-outbound metrics.
#[derive(Debug)]
pub struct StatsManager {
    trackers: DashMap<String, OutboundTracker>,
    udp: UdpStats,
    tcp: TcpStats,
    /// Warm-reason attribution bits per node id, pruned at snapshot time to
    /// nodes that still hold warm resources.
    warm_marks: DashMap<uuid::Uuid, AtomicU8>,
}

/// Why a node's warm resources were established. Several reasons can mark
/// the same node; a warm node with no marks is reported as traffic-warmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmReason {
    /// Startup bare-TCP preconnect deposit.
    Preconnect,
    /// A health probe reused an already-warm generation resource. Throwaway
    /// probe warm-up is closed after measurement and is never attributed.
    Health,
    /// The UDP warm coordinator established the session/client.
    Udp,
    /// The node is the configured leaf of at least one Selector group.
    Selector,
}

impl WarmReason {
    fn bit(self) -> u8 {
        match self {
            WarmReason::Preconnect => 1,
            WarmReason::Health => 1 << 1,
            WarmReason::Udp => 1 << 2,
            WarmReason::Selector => 1 << 3,
        }
    }
}

/// Point-in-time warm-resource gauges behind `/stats`: warm nodes by reason
/// and retained sessions/clients per session protocol.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WarmSnapshot {
    pub preconnect_nodes: u64,
    pub health_nodes: u64,
    pub udp_nodes: u64,
    pub selector_nodes: u64,
    pub traffic_nodes: u64,
    pub anytls_sessions: u64,
    pub vless_sessions: u64,
    pub tuic_clients: u64,
    pub juicity_clients: u64,
    pub hysteria2_clients: u64,
}

impl WarmSnapshot {
    fn add_protocol_counts(
        &mut self,
        protocol: honk_config::types::NodeProtocol,
        counts: honk_outbound::runtime::WarmCounts,
    ) {
        use honk_config::types::NodeProtocol;
        match protocol {
            NodeProtocol::AnyTLS => self.anytls_sessions += counts.sessions as u64,
            NodeProtocol::VLess => self.vless_sessions += counts.sessions as u64,
            NodeProtocol::Tuic => self.tuic_clients += counts.clients.unwrap_or(0) as u64,
            NodeProtocol::Juicity => self.juicity_clients += counts.clients.unwrap_or(0) as u64,
            NodeProtocol::Hysteria2 => {
                self.hysteria2_clients += counts.clients.unwrap_or(0) as u64;
            }
            _ => {}
        }
    }
}

impl StatsManager {
    pub fn new() -> Self {
        Self {
            trackers: DashMap::new(),
            udp: UdpStats::default(),
            tcp: TcpStats::default(),
            warm_marks: DashMap::new(),
        }
    }

    pub(crate) fn with_tcp_flow_limit(limit: usize) -> Self {
        let stats = Self::new();
        stats.set_tcp_flow_limit(limit);
        stats
    }

    pub(crate) fn set_tcp_flow_limit(&self, limit: usize) {
        self.tcp.limit.store(limit as u64, Ordering::Relaxed);
    }

    pub(crate) fn track_tcp_flow(self: &Arc<Self>) -> TcpFlowGuard {
        self.tcp.active_flows.fetch_add(1, Ordering::Relaxed);
        TcpFlowGuard {
            stats: Arc::clone(self),
        }
    }

    pub(crate) fn record_tcp_capacity_rejection(&self) {
        self.tcp.capacity_rejections.fetch_add(1, Ordering::Relaxed);
    }

    /// Attribute a node's current warm resources to a reason.
    pub fn mark_warm(&self, node: uuid::Uuid, reason: WarmReason) {
        self.warm_marks
            .entry(node)
            .or_default()
            .fetch_or(reason.bit(), Ordering::Relaxed);
    }

    /// Remove one attribution without disturbing other owners of the same
    /// live resource. Zero-valued entries are pruned by the next snapshot.
    pub fn clear_warm(&self, node: uuid::Uuid, reason: WarmReason) {
        if let Some(mark) = self.warm_marks.get(&node) {
            mark.fetch_and(!reason.bit(), Ordering::Relaxed);
        }
    }

    /// Current warm-resource gauges: warm nodes counted per reason (an
    /// unmarked warm node counts as traffic-warmed) plus retained
    /// sessions/clients per session protocol. Marks of nodes that went
    /// cold are dropped here, so attribution never outlives the resource.
    pub fn warm_snapshot(
        &self,
        generation: &honk_outbound::runtime::OutboundRuntimeRegistry,
        pool: &crate::pool::ConnectionPool,
    ) -> WarmSnapshot {
        let mut snap = WarmSnapshot::default();
        let mut warm_ids = std::collections::HashSet::new();
        for runtime in generation.values() {
            let counts = runtime.warm_counts();
            snap.add_protocol_counts(runtime.node.protocol(), counts);
            let bare =
                pool.has_live_bare_entry(&format!("{}:{}", runtime.node.host(), runtime.node.port));
            // An unknown QUIC client count (map locked by an in-flight
            // build) is warm, not cold: pruning here would drop the node's
            // attribution and re-report it as traffic next sample.
            let session_warm = counts.sessions > 0 || counts.clients.unwrap_or(1) > 0;
            if !session_warm && !bare {
                continue;
            }
            warm_ids.insert(runtime.node.id);
            let marks = self
                .warm_marks
                .get(&runtime.node.id)
                .map(|m| m.load(Ordering::Relaxed))
                .unwrap_or(0);
            if marks == 0 {
                snap.traffic_nodes += 1;
                continue;
            }
            if marks & WarmReason::Preconnect.bit() != 0 {
                snap.preconnect_nodes += 1;
            }
            if marks & WarmReason::Health.bit() != 0 {
                snap.health_nodes += 1;
            }
            if marks & WarmReason::Udp.bit() != 0 {
                snap.udp_nodes += 1;
            }
            if marks & WarmReason::Selector.bit() != 0 {
                snap.selector_nodes += 1;
            }
        }
        self.warm_marks.retain(|id, _| warm_ids.contains(id));
        snap
    }

    /// Record a new connection on an outbound.
    pub fn record_connection(&self, outbound: &str) {
        if let Some(tracker) = self.trackers.get(outbound) {
            tracker.increment_connections();
            return;
        }
        self.trackers
            .entry(outbound.to_owned())
            .or_default()
            .increment_connections();
    }

    /// Track one connection with an exactly-once active counter balance.
    pub fn track_connection(self: &Arc<Self>, outbound: &str) -> ActiveConnectionGuard {
        let tracker = if let Some(tracker) = self.trackers.get(outbound) {
            tracker.clone()
        } else {
            self.trackers
                .entry(outbound.to_owned())
                .or_default()
                .clone()
        };
        tracker.increment_connections();
        ActiveConnectionGuard { tracker }
    }

    /// Resolve an outbound tracker once for a long-lived data path. Callers
    /// that already retain the returned value avoid allocating an outbound
    /// name and taking a DashMap shard lock for every packet.
    pub fn outbound_tracker(&self, outbound: &str) -> OutboundTracker {
        self.trackers
            .entry(outbound.to_owned())
            .or_default()
            .clone()
    }

    /// Track one connection using an already-resolved tracker.
    pub fn track_outbound(&self, tracker: OutboundTracker) -> ActiveConnectionGuard {
        tracker.increment_connections();
        ActiveConnectionGuard { tracker }
    }

    /// Record a real established-endpoint fast-path hit. This is deliberately
    /// separate from the slow-path endpoint lookup so one receive event is
    /// never counted twice.
    pub fn record_udp_endpoint_hit(&self) {
        self.udp.endpoint_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a real cold-flow endpoint lookup miss.
    pub fn record_udp_endpoint_miss(&self) {
        self.udp.endpoint_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record cold route selection latency.
    pub fn record_udp_route_latency(&self, elapsed: std::time::Duration) {
        self.udp.route_latency.record(elapsed);
    }

    /// Record one cold UDP dial attempt latency.
    pub fn record_udp_dial_latency(&self, elapsed: std::time::Duration) {
        self.udp.dial_latency.record(elapsed);
    }

    /// Record a transport-preparation attempt from the fixed cold URLTest
    /// stagger scheduler. The schema is fixed; callers never attach labels.
    pub fn record_udp_stagger_attempt(&self) {
        self.udp.stagger_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one started generation-owned UDP warm dispatch. These counters
    /// remain fixed, aggregate-only recorder fields: no per-node labels or
    /// outbound health/error state is created for warm-up work.
    pub fn record_udp_warm_attempt(&self) {
        self.udp.warm_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a warm dispatch that found or established a usable session.
    pub fn record_udp_warm_success(&self) {
        self.udp.warm_successes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a true warm failure while its generation remains live.
    pub fn record_udp_warm_failure(&self) {
        self.udp.warm_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the first eligible successful staggered preparation.
    pub fn record_udp_stagger_winner(&self) {
        self.udp.stagger_winners.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one started speculative preparation aborted after a winner.
    pub fn record_udp_stagger_cancellation(&self) {
        self.udp
            .stagger_cancellations
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record admission into the active UDP slow path.
    pub fn record_udp_slow_permit_accepted(&self) {
        self.udp
            .slow_permit_accepted
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record rejection of a UDP slow-path admission because the shared
    /// connection semaphore is full.
    pub fn record_udp_slow_permit_rejected(&self) {
        self.udp
            .slow_permit_rejected
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record an exact endpoint-capacity reservation rejection.
    pub fn record_udp_capacity_rejection(&self) {
        self.udp.capacity_rejections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a bounded endpoint-driver queue admission.
    pub fn record_udp_queue_accepted(&self) {
        self.udp.queue_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record drop-newest because a per-flow queue bound was full.
    pub fn record_udp_flow_queue_full(&self) {
        self.udp.flow_queue_full.fetch_add(1, Ordering::Relaxed);
        self.udp.queue_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Record drop-newest because the global retained-payload-byte bound was full.
    pub fn record_udp_global_payload_full(&self) {
        self.udp.global_payload_full.fetch_add(1, Ordering::Relaxed);
        self.udp.queue_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a queue attempt against a closing/closed endpoint driver.
    pub fn record_udp_queue_closed(&self) {
        self.udp.queue_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record synchronous anyfrom preparation latency before driver commit.
    pub fn record_udp_reply_ready_latency(&self, elapsed: std::time::Duration) {
        self.udp.reply_ready_latency.record(elapsed);
    }

    /// Record latency for a first-send transport attempt.
    pub fn record_udp_first_send_latency(&self, elapsed: std::time::Duration) {
        self.udp.first_send_latency.record(elapsed);
    }

    /// Record a first-send failure; the packet is never replayed.
    pub fn record_udp_first_send_failure(&self) {
        self.udp.first_send_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the first reply successfully reinjected to the client.
    pub fn record_udp_first_reply_latency(&self, elapsed: std::time::Duration) {
        self.udp.first_reply_latency.record(elapsed);
    }

    /// Record rejection of a UDP slow-path admission while draining.
    pub fn record_udp_slow_permit_closed(&self) {
        self.udp.slow_permit_closed.fetch_add(1, Ordering::Relaxed);
    }
    #[cfg(feature = "ebpf")]
    pub fn update_udp_nfqueue_local_stats(&self, stats: honk_nfqueue::QueueLocalStats) {
        self.udp
            .nfqueue
            .held_packets
            .store(stats.held_packets as u64, Ordering::Relaxed);
        self.udp
            .nfqueue
            .held_peak
            .store(stats.held_peak as u64, Ordering::Relaxed);
        self.udp
            .nfqueue
            .socket_receive_buffer_bytes
            .store(stats.socket_receive_buffer_bytes as u64, Ordering::Relaxed);
    }

    #[cfg(feature = "ebpf")]
    pub fn update_udp_nfqueue_service_stats(&self, stats: honk_nfqueue::QueueStats) {
        self.udp
            .nfqueue
            .kernel_stats_available
            .store(1, Ordering::Relaxed);
        self.udp
            .nfqueue
            .kernel_queue_depth
            .store(stats.kernel_queue_depth, Ordering::Relaxed);
        self.udp
            .nfqueue
            .kernel_dropped
            .store(stats.kernel_dropped, Ordering::Relaxed);
        self.udp
            .nfqueue
            .kernel_user_dropped
            .store(stats.kernel_user_dropped, Ordering::Relaxed);
        self.update_udp_nfqueue_local_stats(honk_nfqueue::QueueLocalStats {
            held_packets: stats.held_packets,
            held_peak: stats.held_peak,
            socket_receive_buffer_bytes: stats.socket_receive_buffer_bytes,
        });
    }

    #[cfg(feature = "ebpf")]
    pub fn record_udp_nfqueue_service_stats_error(&self) {
        self.udp
            .nfqueue
            .kernel_stats_available
            .store(0, Ordering::Relaxed);
        self.udp
            .nfqueue
            .kernel_stats_read_errors
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "ebpf")]
    pub fn update_udp_nfqueue_actor_queue(
        &self,
        depth: usize,
        queued_bytes: usize,
        oldest_age: std::time::Duration,
    ) {
        self.udp
            .nfqueue
            .actor_queue_depth
            .store(depth as u64, Ordering::Relaxed);
        self.udp
            .nfqueue
            .actor_queued_bytes
            .store(queued_bytes as u64, Ordering::Relaxed);
        self.udp.nfqueue.actor_oldest_age_nanos.store(
            oldest_age.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    #[cfg(feature = "ebpf")]
    pub fn record_udp_nfqueue_actor_queue_full(&self) {
        self.udp
            .nfqueue
            .actor_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "ebpf")]
    pub fn record_udp_nfqueue_correlator_full(&self) {
        self.udp
            .nfqueue
            .correlator_full
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record one packet delivered by the NFQUEUE listener.
    pub fn record_udp_nfqueue_received(&self) {
        self.udp.nfqueue.received.fetch_add(1, Ordering::Relaxed);
    }

    /// Add one flow owned by the pending-verdict correlator.
    pub fn increment_udp_nfqueue_active_flows(&self) {
        self.udp
            .nfqueue
            .active_flows
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Remove one flow from the pending-verdict correlator.
    pub fn decrement_udp_nfqueue_active_flows(&self) {
        let _ = self.udp.nfqueue.active_flows.try_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |active| Some(active.saturating_sub(1)),
        );
    }

    /// Record a successful direct accept and its receipt-to-verdict latency.
    pub fn record_udp_nfqueue_direct_accepted(&self, elapsed: std::time::Duration) {
        self.udp
            .nfqueue
            .record_verdict(&self.udp.nfqueue.direct_accepted, elapsed);
    }

    /// Record one NFQUEUE payload transferred to the canonical UDP pool.
    pub fn record_udp_nfqueue_proxy_copied(&self) {
        self.udp
            .nfqueue
            .proxy_copied
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful original-skb drop and its receipt-to-verdict latency.
    pub fn record_udp_nfqueue_proxy_dropped(&self, elapsed: std::time::Duration) {
        self.udp
            .nfqueue
            .record_verdict(&self.udp.nfqueue.proxy_dropped, elapsed);
    }

    /// Record a successful policy-block drop verdict.
    pub fn record_udp_nfqueue_block(&self, elapsed: std::time::Duration) {
        self.udp
            .nfqueue
            .record_verdict(&self.udp.nfqueue.block, elapsed);
    }

    /// Record a successful cancellation drop verdict.
    pub fn record_udp_nfqueue_cancel(&self, elapsed: std::time::Duration) {
        self.udp
            .nfqueue
            .record_verdict(&self.udp.nfqueue.cancel, elapsed);
    }

    pub fn record_udp_nfqueue_token_rollover(&self) {
        self.udp
            .nfqueue
            .token_rollovers
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record another successful fail-closed drop verdict.
    pub fn record_udp_nfqueue_drop(&self, elapsed: std::time::Duration) {
        self.udp
            .nfqueue
            .record_verdict(&self.udp.nfqueue.drop, elapsed);
    }

    pub fn record_udp_nfqueue_token_mismatch(&self) {
        self.udp
            .nfqueue
            .token_mismatch
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_udp_nfqueue_token_exhaustion(&self) {
        self.udp
            .nfqueue
            .token_exhaustion
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_udp_nfqueue_verdict_error(&self) {
        self.udp
            .nfqueue
            .verdict_errors
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a closed connection on an outbound.
    pub fn record_close(&self, outbound: &str) {
        if let Some(tracker) = self.trackers.get(outbound) {
            tracker.decrement_connections();
        }
    }

    /// Record bytes transferred through an outbound.
    pub fn record_bytes(&self, outbound: &str, tx: u64, rx: u64) {
        if let Some(tracker) = self.trackers.get(outbound) {
            tracker.add_bytes(tx, rx);
            return;
        }
        self.trackers
            .entry(outbound.to_owned())
            .or_default()
            .add_bytes(tx, rx);
    }

    /// Record an error on an outbound.
    pub fn record_error(&self, outbound: &str) {
        if let Some(tracker) = self.trackers.get(outbound) {
            tracker.increment_errors();
            return;
        }
        self.trackers
            .entry(outbound.to_owned())
            .or_default()
            .increment_errors();
    }

    /// Get a snapshot of all per-outbound statistics.
    pub fn snapshot(&self) -> std::collections::HashMap<String, OutboundStats> {
        self.trackers
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().snapshot()))
            .collect()
    }

    /// Get the complete fixed UDP metrics schema.
    pub fn udp_snapshot(&self) -> UdpStatsSnapshot {
        self.udp.snapshot()
    }
    #[cfg(any(feature = "clash-api", test))]
    pub(crate) fn tcp_snapshot(&self) -> TcpStatsSnapshot {
        TcpStatsSnapshot {
            limit: self.tcp.limit.load(Ordering::Relaxed),
            active_flows: self.tcp.active_flows.load(Ordering::Relaxed),
            capacity_rejections: self.tcp.capacity_rejections.load(Ordering::Relaxed),
        }
    }
}

impl Default for StatsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outbound_tracker() {
        let tracker = OutboundTracker::new();

        tracker.increment_connections();
        tracker.increment_connections();
        assert_eq!(tracker.total_connections.load(Ordering::Relaxed), 2);
        assert_eq!(tracker.active_connections.load(Ordering::Relaxed), 2);

        tracker.decrement_connections();
        assert_eq!(tracker.active_connections.load(Ordering::Relaxed), 1);

        tracker.add_bytes(100, 200);
        assert_eq!(tracker.tx_bytes.load(Ordering::Relaxed), 100);
        assert_eq!(tracker.rx_bytes.load(Ordering::Relaxed), 200);
        tracker.add_bytes(0, 50);
        tracker.add_bytes(25, 0);
        assert_eq!(tracker.tx_bytes.load(Ordering::Relaxed), 125);
        assert_eq!(tracker.rx_bytes.load(Ordering::Relaxed), 250);

        let snap = tracker.snapshot();
        assert_eq!(snap.total_conns, 2);
        assert_eq!(snap.active_conns, 1);
    }

    #[test]
    fn test_stats_manager() {
        let mgr = StatsManager::new();

        mgr.record_connection("proxy1");
        mgr.record_connection("proxy1");
        mgr.record_connection("proxy2");
        mgr.record_bytes("proxy1", 1000, 2000);
        mgr.record_error("proxy2");

        let snap = mgr.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get("proxy1").unwrap().total_conns, 2);
        assert_eq!(snap.get("proxy2").unwrap().total_conns, 1);
        assert_eq!(snap.get("proxy2").unwrap().errors, 1);
    }

    #[test]
    fn warmed_stats_methods_reuse_one_tracker() {
        let manager = Arc::new(StatsManager::new());
        manager.record_connection("proxy");
        let guard = manager.track_connection("proxy");
        manager.record_bytes("proxy", 100, 200);
        manager.record_error("proxy");

        assert_eq!(manager.trackers.len(), 1);
        let snapshot = manager.snapshot();
        let tracker = snapshot.get("proxy").unwrap();
        assert_eq!(tracker.total_conns, 2);
        assert_eq!(tracker.active_conns, 2);
        assert_eq!(tracker.tx_bytes, 100);
        assert_eq!(tracker.rx_bytes, 200);
        assert_eq!(tracker.errors, 1);

        drop(guard);
        manager.record_close("proxy");
        assert_eq!(manager.snapshot()["proxy"].active_conns, 0);
    }

    #[test]
    fn active_connection_guard_decrements_active_exactly_once() {
        let manager = Arc::new(StatsManager::new());
        let guard = manager.track_connection("udp-test");

        let snapshot = manager.snapshot();
        let tracker = snapshot.get("udp-test").unwrap();
        assert_eq!(tracker.total_conns, 1);
        assert_eq!(tracker.active_conns, 1);
        assert_eq!(tracker.errors, 0);

        drop(guard);
        let snapshot = manager.snapshot();
        let tracker = snapshot.get("udp-test").unwrap();
        assert_eq!(tracker.total_conns, 1);
        assert_eq!(tracker.active_conns, 0);
        assert_eq!(tracker.errors, 0);
    }

    #[test]
    fn tcp_admission_stats_track_active_flows_and_capacity_waits() {
        let manager = Arc::new(StatsManager::with_tcp_flow_limit(3));
        manager.record_tcp_capacity_rejection();
        let guard = manager.track_tcp_flow();

        assert_eq!(
            manager.tcp_snapshot(),
            TcpStatsSnapshot {
                limit: 3,
                active_flows: 1,
                capacity_rejections: 1,
            }
        );

        drop(guard);
        assert_eq!(manager.tcp_snapshot().active_flows, 0);
    }

    #[test]
    fn udp_latency_histogram_uses_fixed_log2_bounds_and_quantiles() {
        let manager = StatsManager::new();
        manager.record_udp_route_latency(std::time::Duration::from_nanos(1));
        manager.record_udp_route_latency(std::time::Duration::from_nanos(3));
        manager.record_udp_route_latency(std::time::Duration::from_nanos(4));

        let route = manager.udp_snapshot().route_latency;
        assert_eq!(route.count, 3);
        assert_eq!(route.sum_nanos, 8);
        assert_eq!(route.buckets[0], 1);
        assert_eq!(route.buckets[1], 1);
        assert_eq!(route.buckets[2], 1);
        assert_eq!(UdpLatencyHistogramSnapshot::bucket_upper_bound_ns(0), 1);
        assert_eq!(UdpLatencyHistogramSnapshot::bucket_upper_bound_ns(1), 3);
        assert_eq!(route.quantile_upper_bound_ns(0.5), Some(3));
    }

    #[test]
    fn udp_nfqueue_counters_and_verdict_latency_are_fixed_and_aggregate() {
        let manager = StatsManager::new();
        manager.record_udp_nfqueue_received();
        manager.increment_udp_nfqueue_active_flows();
        manager.increment_udp_nfqueue_active_flows();
        manager.decrement_udp_nfqueue_active_flows();
        manager.record_udp_nfqueue_direct_accepted(std::time::Duration::from_nanos(1));
        manager.record_udp_nfqueue_proxy_copied();
        manager.record_udp_nfqueue_proxy_dropped(std::time::Duration::from_nanos(2));
        manager.record_udp_nfqueue_block(std::time::Duration::from_nanos(4));
        manager.record_udp_nfqueue_cancel(std::time::Duration::from_nanos(8));
        manager.record_udp_nfqueue_drop(std::time::Duration::from_nanos(16));
        manager.record_udp_nfqueue_token_mismatch();
        manager.record_udp_nfqueue_token_exhaustion();
        manager.record_udp_nfqueue_token_rollover();
        manager.record_udp_nfqueue_verdict_error();

        let nfqueue = manager.udp_snapshot().nfqueue;
        assert_eq!(nfqueue.received, 1);
        assert_eq!(nfqueue.active_flows, 1);
        assert_eq!(nfqueue.direct_accepted, 1);
        assert_eq!(nfqueue.proxy_copied, 1);
        assert_eq!(nfqueue.proxy_dropped, 1);
        assert_eq!(nfqueue.block, 1);
        assert_eq!(nfqueue.cancel, 1);
        assert_eq!(nfqueue.drop, 1);
        assert_eq!(nfqueue.token_mismatch, 1);
        assert_eq!(nfqueue.token_exhaustion, 1);
        assert_eq!(nfqueue.token_rollovers, 1);
        assert_eq!(nfqueue.kernel_queue_depth, 0);
        assert_eq!(nfqueue.kernel_dropped, 0);
        assert_eq!(nfqueue.kernel_user_dropped, 0);
        assert_eq!(nfqueue.held_packets, 0);
        assert_eq!(nfqueue.held_peak, 0);
        assert_eq!(nfqueue.socket_receive_buffer_bytes, 0);
        assert_eq!(nfqueue.actor_queue_full, 0);
        assert_eq!(nfqueue.correlator_full, 0);
        assert_eq!(nfqueue.verdict_errors, 1);
        assert_eq!(nfqueue.receipt_to_verdict_latency.count, 5);
        assert_eq!(nfqueue.receipt_to_verdict_latency.sum_nanos, 31);
    }

    #[test]
    fn config_reserved_mark_mask_matches_the_datapath() {
        assert_eq!(
            honk_config::routing::DATAPATH_RESERVED_MARK_MASK,
            honk_ebpf_common::SKB_MARK_RESERVED_MASK
        );
    }

    #[test]
    fn warm_snapshot_routes_vless_sessions() {
        let mut snapshot = WarmSnapshot::default();
        snapshot.add_protocol_counts(
            honk_config::types::NodeProtocol::VLess,
            honk_outbound::runtime::WarmCounts {
                sessions: 2,
                clients: Some(0),
            },
        );
        assert_eq!(snapshot.vless_sessions, 2);
    }

    #[tokio::test]
    async fn warm_snapshot_attributes_reasons_and_prunes_cold_nodes() {
        let stats = StatsManager::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let node = honk_config::node::Node {
            id: uuid::Uuid::new_v4(),
            name: "ss".into(),
            address: addr.to_string(),
            port: addr.port(),
            outbound: honk_config::node::OutboundConfig::Shadowsocks(Default::default()),
            ..Default::default()
        };
        let generation =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
                .unwrap();
        let pool = crate::pool::ConnectionPool::new();

        let cold = stats.warm_snapshot(&generation, &pool);
        assert_eq!(cold, WarmSnapshot::default());

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _accepted = listener.accept().await.unwrap();
        pool.deposit_tcp(&addr.to_string(), stream).await;

        let unmarked = stats.warm_snapshot(&generation, &pool);
        assert_eq!(unmarked.traffic_nodes, 1);
        assert_eq!(unmarked.preconnect_nodes, 0);

        stats.mark_warm(node.id, WarmReason::Preconnect);
        let marked = stats.warm_snapshot(&generation, &pool);
        assert_eq!(marked.preconnect_nodes, 1);
        assert_eq!(marked.traffic_nodes, 0);

        // Once the resource is gone, its marks go with it: re-warming
        // without a mark counts as traffic again.
        let pool = crate::pool::ConnectionPool::new();
        assert_eq!(
            stats.warm_snapshot(&generation, &pool),
            WarmSnapshot::default()
        );
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        pool.deposit_tcp(&addr.to_string(), stream).await;
        let rewarmed = stats.warm_snapshot(&generation, &pool);
        assert_eq!(rewarmed.traffic_nodes, 1);
        assert_eq!(rewarmed.preconnect_nodes, 0);
    }

    #[tokio::test]
    async fn warm_snapshot_keeps_marks_while_quic_client_count_is_unknown() {
        use honk_outbound::runtime::{ProtocolRuntime, QuicRuntimeClient};

        struct ParkedClient;
        #[async_trait::async_trait]
        impl QuicRuntimeClient for ParkedClient {
            fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
                self
            }
            async fn force_close(&self) {}
            async fn release_warm(&self) {}
        }

        let stats = StatsManager::new();
        let node = honk_config::node::Node {
            id: uuid::Uuid::new_v4(),
            name: "tuic".into(),
            address: "127.0.0.1:443".into(),
            port: 443,
            outbound: honk_config::node::OutboundConfig::Tuic(Default::default()),
            ..Default::default()
        };
        let generation =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
                .unwrap();
        let runtime = generation.get(&node.id).unwrap();
        let pool = crate::pool::ConnectionPool::new();

        // Cold node: the mark is pruned with the missing resource.
        stats.mark_warm(node.id, WarmReason::Udp);
        assert_eq!(
            stats.warm_snapshot(&generation, &pool),
            WarmSnapshot::default()
        );

        // Hold the client map with an in-flight build: the count is
        // unknown, which must read as warm — the mark and its attribution
        // survive the contended snapshot.
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let build = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            async move {
                let ProtocolRuntime::Quic(quic) = &runtime.runtime else {
                    panic!("tuic runtime expected")
                };
                quic.client::<ParkedClient, _, _>(|| async move {
                    let _ = entered_tx.send(());
                    let _ = release_rx.await;
                    Ok(Arc::new(ParkedClient))
                })
                .await
            }
        });
        entered_rx.await.unwrap();
        stats.mark_warm(node.id, WarmReason::Udp);
        let contended = stats.warm_snapshot(&generation, &pool);
        assert_eq!(contended.udp_nodes, 1);
        assert_eq!(contended.traffic_nodes, 0);
        assert_eq!(
            contended.tuic_clients, 0,
            "an unknown count adds nothing to the gauge"
        );

        drop(release_tx);
        build.await.unwrap().unwrap();
        let settled = stats.warm_snapshot(&generation, &pool);
        assert_eq!(settled.udp_nodes, 1);
        assert_eq!(settled.tuic_clients, 1);
        generation.shutdown().await;
    }
    #[cfg(feature = "ebpf")]
    #[test]
    fn nfqueue_kernel_stats_failures_are_visible() {
        let stats = StatsManager::new();
        stats.update_udp_nfqueue_service_stats(honk_nfqueue::QueueStats {
            kernel_queue_depth: 7,
            kernel_dropped: 2,
            kernel_user_dropped: 3,
            held_packets: 4,
            held_peak: 5,
            socket_receive_buffer_bytes: 6,
        });
        let available = stats.udp_snapshot().nfqueue;
        assert!(available.kernel_stats_available);
        assert_eq!(available.kernel_queue_depth, 7);
        assert_eq!(available.kernel_stats_read_errors, 0);

        stats.update_udp_nfqueue_local_stats(honk_nfqueue::QueueLocalStats {
            held_packets: 1,
            held_peak: 6,
            socket_receive_buffer_bytes: 8192,
        });
        stats.record_udp_nfqueue_service_stats_error();
        let unavailable = stats.udp_snapshot().nfqueue;
        assert!(!unavailable.kernel_stats_available);
        assert_eq!(unavailable.kernel_stats_read_errors, 1);
        assert_eq!(unavailable.kernel_queue_depth, 7);
        assert_eq!(unavailable.held_packets, 1);
        assert_eq!(unavailable.held_peak, 6);
        assert_eq!(unavailable.socket_receive_buffer_bytes, 8192);
    }
}
