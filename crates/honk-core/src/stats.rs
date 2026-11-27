//! Statistics tracking for honk-core.

use dashmap::DashMap;
use honk_ebpf_common::OutboundStats;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

pub(crate) mod dns;
#[cfg(test)]
pub(crate) use dns::dns_snapshot;
pub(crate) use dns::{DnsStatEvent, record_dns_event};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKind {
    Builtin,
    Node,
    Group,
}

impl OutboundKind {
    /// Validated configs reject unknown outbounds and group/node name clashes,
    /// so a routed name that is neither builtin nor group is a node.
    pub(crate) fn routed(groups: &crate::group::GroupManager, name: &str) -> Self {
        match name {
            "direct" | "block" => Self::Builtin,
            // Internal handoff verdicts are neither node nor group; stats file them under groups.
            "must_rules" | "control_plane_routing" => Self::Group,
            _ if groups.get_group_policy(name).is_some() => Self::Group,
            _ => Self::Node,
        }
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Node => "node",
            Self::Group => "group",
        }
    }
}

#[cfg(feature = "native-api")]
pub(crate) struct NativeOutboundCounters {
    pub(crate) name: String,
    pub(crate) kind: OutboundKind,
    pub(crate) active_connections: u64,
    pub(crate) total_connections: u64,
    pub(crate) upload_bytes: u64,
    pub(crate) download_bytes: u64,
    pub(crate) errors: u64,
}

/// Per-outbound statistics tracked in user-space.
#[repr(align(64))]
#[derive(Debug, Default)]
pub struct OutboundTracker {
    /// Total connections through this outbound
    pub total_connections: AtomicU64,
    /// Active connections currently open
    pub active_connections: AtomicU64,
    /// Total bytes transferred (client → proxy)
    pub tx_bytes: AtomicU64,
    /// Total bytes transferred (proxy → client)
    pub rx_bytes: AtomicU64,
    /// Failed connection attempts
    pub errors: AtomicU64,
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
            active_conns: self
                .active_connections
                .load(Ordering::Relaxed)
                .min(u32::MAX as u64) as u32,
            total_conns: self
                .total_connections
                .load(Ordering::Relaxed)
                .min(u32::MAX as u64) as u32,
            errors: self.errors.load(Ordering::Relaxed).min(u32::MAX as u64) as u32,
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

#[cfg(feature = "legacy-tc")]
pub struct NfqueueServiceSample {
    pub kernel_queue_depth: u64,
    pub kernel_dropped: u64,
    pub kernel_user_dropped: u64,
    pub held_packets: usize,
    pub held_peak: usize,
    pub socket_receive_buffer_bytes: usize,
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
    tracker: Arc<OutboundTracker>,
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

#[cfg(target_os = "linux")]
#[cfg_attr(
    not(any(feature = "native-api", feature = "clash-api", test)),
    allow(dead_code)
)]
pub(crate) mod xdp {
    use honk_ebpf_common::xdp_gateway::GatewayReason;
    use honk_netstack::{MemoryBudget, MemoryReservation};
    use honk_xsk::{GatewayMaps, RingSnapshot, SocketStats};
    use parking_lot::Mutex;
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::{io, sync::Arc, time::SystemTime};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Lifecycle {
        Starting,
        Active,
        Closing,
        Closed,
        FailedRetained,
    }

    impl Lifecycle {
        fn as_str(self) -> &'static str {
            match self {
                Self::Starting => "starting",
                Self::Active => "active",
                Self::Closing => "closing",
                Self::Closed => "closed",
                Self::FailedRetained => "failed_retained",
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct QueueObservation {
        pub(crate) namespace: u64,
        pub(crate) attachment: u64,
        pub(crate) ifindex: u32,
        pub(crate) queue: u32,
        pub(crate) zero_copy: bool,
        pub(crate) ring_capacity: u32,
        pub(crate) rx_frames: usize,
        pub(crate) control_frames: usize,
        pub(crate) bulk_frames: usize,
        pub(crate) sequence: u64,
        pub(crate) attempted_at: Option<SystemTime>,
        pub(crate) succeeded_at: Option<SystemTime>,
        pub(crate) socket: Option<SocketStats>,
        pub(crate) errno: Option<i32>,
        pub(crate) read_errors: u64,
        pub(crate) rings: Option<RingSnapshot>,
    }

    impl QueueObservation {
        fn sample(&mut self, at: SystemTime, socket: io::Result<SocketStats>, rings: RingSnapshot) {
            self.sequence = self.sequence.saturating_add(1);
            self.attempted_at = Some(at);
            self.rings = Some(rings);
            match socket {
                Ok(socket) => {
                    self.socket = Some(socket);
                    self.errno = None;
                    self.succeeded_at = Some(at);
                }
                Err(error) => {
                    self.socket = None;
                    self.errno = error.raw_os_error();
                    self.read_errors = self.read_errors.saturating_add(1);
                }
            }
        }

        fn json(self) -> Value {
            let millis = |at: Option<SystemTime>| {
                at.and_then(|at| at.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map(|elapsed| elapsed.as_millis().to_string())
            };
            json!({
                "namespace_cookie": self.namespace.to_string(),
                "attachment_generation": self.attachment.to_string(),
                "ifindex": self.ifindex, "queue_id": self.queue,
                "mode": if self.zero_copy { "zerocopy" } else { "copy" },
                "ring_capacity": self.ring_capacity,
                "frames": {"rx": self.rx_frames, "control": self.control_frames, "bulk": self.bulk_frames},
                "sequence": self.sequence.to_string(),
                "attempted_at_unix_ms": millis(self.attempted_at),
                "last_success_at_unix_ms": millis(self.succeeded_at),
                "socket_available": self.socket.is_some(),
                "socket_error": (self.attempted_at.is_some() && self.socket.is_none()).then_some("statistics_unavailable"),
                "socket_errno": self.errno,
                "socket_read_errors": self.read_errors.to_string(),
                "socket": self.socket.map(|socket| json!({
                    "rx_dropped": socket.rx_dropped.to_string(),
                    "rx_invalid_descs": socket.rx_invalid_descs.to_string(),
                    "tx_invalid_descs": socket.tx_invalid_descs.to_string(),
                    "rx_ring_full": socket.rx_ring_full.to_string(),
                    "rx_fill_ring_empty_descs": socket.rx_fill_ring_empty_descs.to_string(),
                    "tx_ring_empty_descs": socket.tx_ring_empty_descs.to_string(),
                })),
                "rings": self.rings.map(|rings| json!({
                    "rx": {"producer": rings.rx_producer, "consumer": rings.rx_consumer},
                    "tx": {"producer": rings.tx_producer, "consumer": rings.tx_consumer},
                    "fill": {"producer": rings.fill_producer, "consumer": rings.fill_consumer},
                    "cq": {"producer": rings.cq_producer, "consumer": rings.cq_consumer},
                })),
            })
        }
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) enum DnsProjectionState {
        #[default]
        Disabled,
        NoDomainRules,
        Staged,
        Active,
        Closed,
        Fallback(&'static str),
    }

    impl DnsProjectionState {
        fn label(self) -> &'static str {
            match self {
                Self::Disabled => "disabled_by_config",
                Self::NoDomainRules => "inactive_no_domain_rules",
                Self::Staged => "staged_closed",
                Self::Active => "active_tcp_udp",
                Self::Closed => "closed",
                Self::Fallback(_) => "degraded_fallback",
            }
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct DnsObservation {
        state: DnsProjectionState,
        counters: Option<crate::xdp::gateway::dns::GatewayDnsCounters>,
        would_pass: Option<u64>,
    }

    const DNS_DECISIONS: [(&str, GatewayReason); 12] = [
        ("pass_dns_d1", GatewayReason::PassDnsD1),
        (
            "pass_dns_d1_pending_retry",
            GatewayReason::PassDnsD1PendingRetry,
        ),
        (
            "drop_native_pending_conflict",
            GatewayReason::DropNativePendingConflict,
        ),
        (
            "dns_native_pending_capped",
            GatewayReason::DnsNativePendingCapped,
        ),
        ("drop_hold_contention", GatewayReason::DropHoldContention),
        ("drop_hold_unavailable", GatewayReason::DropHoldUnavailable),
        (
            "hold_guard_release_failed",
            GatewayReason::HoldGuardReleaseFailed,
        ),
        ("hold_retire_failed", GatewayReason::HoldRetireFailed),
        (
            "host_meta_insert_failed",
            GatewayReason::HostMetaInsertFailed,
        ),
        (
            "host_direct_unrecorded",
            GatewayReason::HostDirectUnrecorded,
        ),
        ("host_late_packet", GatewayReason::HostLatePacket),
        (
            "host_direct_tcp_insert_failed",
            GatewayReason::HostDirectTcpInsertFailed,
        ),
    ];

    #[derive(Debug)]
    struct State {
        lifecycle: Lifecycle,
        changed_at: SystemTime,
        queues: Box<[QueueObservation]>,
        dns: DnsObservation,
        dns_decisions: Option<[Option<u64>; DNS_DECISIONS.len()]>,
        dns_bank: std::sync::Weak<crate::xdp::gateway::dns::GatewayDnsBank>,
    }

    #[derive(Debug)]
    pub(crate) struct Diagnostics {
        state: Mutex<State>,
        count: usize,
        cross_worker_handoffs: AtomicU64,
        _memory: MemoryReservation,
    }

    impl Diagnostics {
        pub(crate) fn new(
            budget: &Arc<MemoryBudget>,
            count: usize,
            queues: impl Iterator<Item = QueueObservation>,
        ) -> io::Result<Arc<Self>> {
            let bytes = count
                .checked_mul(size_of::<QueueObservation>())
                .and_then(|bytes| bytes.checked_add(size_of::<Self>() + 2 * size_of::<usize>()))
                .ok_or_else(|| io::Error::other("XDP diagnostics extent overflow"))?;
            let memory = budget
                .reserve(bytes)
                .ok_or_else(|| io::Error::other("XDP diagnostics memory capacity"))?;
            let mut storage = Vec::with_capacity(count);
            for queue in queues {
                if storage.len() == count {
                    return Err(io::Error::other("XDP diagnostic queue count mismatch"));
                }
                storage.push(queue);
            }
            if storage.len() != count {
                return Err(io::Error::other("XDP diagnostic queue count mismatch"));
            }
            Ok(Arc::new(Self {
                state: Mutex::new(State {
                    lifecycle: Lifecycle::Starting,
                    changed_at: SystemTime::now(),
                    queues: storage.into_boxed_slice(),
                    dns: DnsObservation::default(),
                    dns_decisions: None,
                    dns_bank: std::sync::Weak::new(),
                }),
                count,
                cross_worker_handoffs: AtomicU64::new(0),
                _memory: memory,
            }))
        }

        pub(crate) fn dns_state(&self, status: DnsProjectionState) {
            let mut state = self.state.lock();
            if state.dns.state != status && state.dns.state != DnsProjectionState::Closed {
                state.dns = DnsObservation {
                    state: status,
                    ..Default::default()
                };
                state.dns_bank = std::sync::Weak::new();
                if let DnsProjectionState::Fallback(reason) = status {
                    tracing::warn!(
                        reason,
                        "XDP DNS direct routing unavailable; using static D1 and Endpoint"
                    );
                }
            }
        }

        pub(crate) fn sample_dns(
            &self,
            bank: &Arc<crate::xdp::gateway::dns::GatewayDnsBank>,
            would_pass: Option<u64>,
        ) {
            let counters = bank.stats();
            let mut state = self.state.lock();
            if state.dns.state == DnsProjectionState::Active {
                state.dns.counters = Some(counters);
                if !std::ptr::eq(state.dns_bank.as_ptr(), Arc::as_ptr(bank)) {
                    state.dns_bank = Arc::downgrade(bank);
                }
                state.dns.would_pass = would_pass;
            }
        }

        pub(crate) fn sample_dns_decisions(&self, maps: &GatewayMaps) {
            let counts = DNS_DECISIONS.map(|(_, reason)| maps.reason_count(reason).ok());
            self.state.lock().dns_decisions = Some(counts);
        }

        pub(crate) fn sample(
            &self,
            index: usize,
            at: SystemTime,
            socket: io::Result<SocketStats>,
            rings: RingSnapshot,
        ) {
            self.state.lock().queues[index].sample(at, socket, rings);
        }

        pub(crate) fn record_worker_handoff(&self) {
            let _ =
                self.cross_worker_handoffs
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1));
        }

        pub(crate) fn lifecycle(&self, lifecycle: Lifecycle) {
            let mut state = self.state.lock();
            if !matches!(
                state.lifecycle,
                Lifecycle::Closed | Lifecycle::FailedRetained
            ) {
                state.lifecycle = lifecycle;
                state.changed_at = SystemTime::now();
            }
        }

        pub(crate) fn json(&self, full: bool) -> Value {
            let (lifecycle, changed_at, dns, decisions, bank) = {
                let state = self.state.lock();
                (
                    state.lifecycle,
                    state.changed_at,
                    state.dns,
                    state.dns_decisions,
                    full.then(|| state.dns_bank.upgrade()).flatten(),
                )
            };
            let mut rows = Vec::new();
            let mut remaining = 64 * 1024
                - if bank.is_some() || decisions.is_some() {
                    4096
                } else {
                    1024
                };
            if full {
                let mut encoded = Vec::new();
                for index in 0..self.count {
                    let queue = self.state.lock().queues[index];
                    let row = queue.json();
                    encoded.clear();
                    serde_json::to_writer(&mut encoded, &row)
                        .expect("XDP numeric observation JSON");
                    let bytes = encoded.len() + 1;
                    if bytes > remaining {
                        break;
                    }
                    remaining -= bytes;
                    rows.push(row);
                }
            }
            let mut value = json!({
                "state": lifecycle.as_str(), "queue_count": self.count,
                "cross_worker_handoffs": self.cross_worker_handoffs.load(Ordering::Relaxed).to_string(),
                "dns_projection_state": dns.state.label(),
                "dns_projection_reason": if let DnsProjectionState::Fallback(reason) = dns.state { Some(reason) } else { None },
                "dns_projection_counters": dns.counters,
                "would_pass_dns": dns.would_pass.map(|v| v.to_string()),
                "dns_decisions": decisions.map(|counts| DNS_DECISIONS.into_iter().zip(counts).map(|((name, _), n)| {
                    (name.to_owned(), n.map_or(Value::Null, |n| Value::String(n.to_string())))
                }).collect::<serde_json::Map<_, _>>()),
                "state_changed_at_unix_ms": changed_at.duration_since(SystemTime::UNIX_EPOCH).ok().map(|at| at.as_millis().to_string()),
            });
            if full {
                if let Some(bank) = bank {
                    let mut realms = [(0u32, 0u64); 64];
                    let count = bank.realm_revocations(&mut realms);
                    value["dns_realm_revocations"] = json!(&realms[..count]);
                }
                value["truncated"] = json!(rows.len() != self.count);
                value["queues"] = json!(rows);
            }
            value
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::stats::StatsManager;

        fn queue() -> QueueObservation {
            QueueObservation {
                namespace: u64::MAX,
                attachment: 7,
                ifindex: 3,
                queue: 1,
                zero_copy: false,
                ring_capacity: 256,
                rx_frames: 256,
                control_frames: 32,
                bulk_frames: 256,
                sequence: 0,
                attempted_at: None,
                succeeded_at: None,
                socket: None,
                errno: None,
                read_errors: 0,
                rings: None,
            }
        }

        #[test]
        fn error_recovery_passive_reads_and_terminal_state_preserve_evidence() {
            let budget = MemoryBudget::new(1 << 20);
            let diagnostics = Diagnostics::new(&budget, 1, std::iter::once(queue())).unwrap();
            let stats = StatsManager::new();
            assert!(stats.xdp_json(true).is_null());
            stats.install_xdp(Arc::clone(&diagnostics));
            assert_eq!(stats.xdp_json(false)["state"], "starting");
            let first = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1);
            let second = first + std::time::Duration::from_secs(1);
            let socket = SocketStats {
                rx_dropped: u64::MAX,
                ..SocketStats::default()
            };
            let rings = RingSnapshot {
                rx_producer: 0,
                rx_consumer: u32::MAX,
                ..RingSnapshot::default()
            };
            diagnostics.lifecycle(Lifecycle::Active);
            diagnostics.sample(0, first, Ok(socket), rings);
            let good = stats.xdp_json(true);
            assert_eq!(
                good["queues"][0]["socket"]["rx_dropped"],
                u64::MAX.to_string()
            );
            assert_eq!(good["queues"][0]["namespace_cookie"], u64::MAX.to_string());
            assert_eq!(good["queues"][0]["rings"]["rx"]["consumer"], u32::MAX);
            diagnostics.sample(0, second, Err(io::Error::other("private failure")), rings);
            let failed = stats.xdp_json(true);
            let row = &failed["queues"][0];
            assert_eq!(row["socket_available"], false);
            assert!(row["socket"].is_null());
            assert!(row["socket_errno"].is_null());
            assert_eq!(row["socket_error"], "statistics_unavailable");
            assert_eq!(row["socket_read_errors"], "1");
            assert_eq!(row["last_success_at_unix_ms"], "1000");
            assert_eq!(row["attempted_at_unix_ms"], "2000");
            assert_eq!(failed, stats.xdp_json(true));
            assert!(!failed.to_string().contains("private failure"));
            diagnostics.sample(0, second, Ok(socket), rings);
            let recovered = stats.xdp_json(true);
            assert_eq!(recovered["queues"][0]["socket_available"], true);
            assert!(recovered["queues"][0]["socket_error"].is_null());
            assert_eq!(recovered["queues"][0]["socket_read_errors"], "1");
            assert_eq!(recovered["queues"][0]["sequence"], "3");
            diagnostics.lifecycle(Lifecycle::Closing);
            assert_eq!(stats.xdp_json(false)["state"], "closing");
            diagnostics.lifecycle(Lifecycle::FailedRetained);
            diagnostics.lifecycle(Lifecycle::Active);
            diagnostics.lifecycle(Lifecycle::Closed);
            assert_eq!(stats.xdp_json(false)["state"], "failed_retained");
            drop(stats);
            assert!(budget.used() > 0, "the reader still funds the observation");
            drop(diagnostics);
            assert_eq!(budget.used(), 0);
        }

        #[test]
        fn allocation_admission_saturation_and_projection_are_bounded() {
            let empty = MemoryBudget::new(0);
            let mut consumed = 0;
            assert!(
                Diagnostics::new(
                    &empty,
                    1,
                    std::iter::once_with(|| {
                        consumed += 1;
                        queue()
                    })
                )
                .is_err()
            );
            assert_eq!(consumed, 0);
            let budget = MemoryBudget::new(1 << 24);
            let mut observation = queue();
            observation.sequence = u64::MAX;
            observation.read_errors = u64::MAX;
            let diagnostics =
                Diagnostics::new(&budget, 4096, std::iter::repeat_n(observation, 4096)).unwrap();
            diagnostics.sample(
                0,
                SystemTime::UNIX_EPOCH,
                Err(io::Error::from_raw_os_error(libc::EIO)),
                RingSnapshot::default(),
            );
            let full = diagnostics.json(true);
            assert_eq!(full["queues"][0]["sequence"], u64::MAX.to_string());
            assert_eq!(
                full["queues"][0]["socket_read_errors"],
                u64::MAX.to_string()
            );
            assert_eq!(full["queues"][0]["socket_errno"], libc::EIO);
            assert_eq!(full["truncated"], true);
            assert_eq!(full["queue_count"], 4096);
            assert!(serde_json::to_vec(&full).unwrap().len() <= 64 * 1024);
            assert!(diagnostics.json(false).get("queues").is_none());
            diagnostics.lifecycle(Lifecycle::Closed);
            diagnostics.lifecycle(Lifecycle::FailedRetained);
            assert_eq!(diagnostics.json(false)["state"], "closed");
        }
    }
}

/// Statistics manager that tracks per-outbound metrics.
#[derive(Debug)]
pub struct StatsManager {
    trackers: [DashMap<String, Arc<OutboundTracker>>; 3],
    udp: UdpStats,
    tcp: TcpStats,
    #[cfg(target_os = "linux")]
    xdp: parking_lot::RwLock<Option<Arc<xdp::Diagnostics>>>,
    #[cfg(feature = "native-api")]
    counter_since: std::time::SystemTime,
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
            trackers: std::array::from_fn(|_| DashMap::new()),
            udp: UdpStats::default(),
            tcp: TcpStats::default(),
            #[cfg(target_os = "linux")]
            xdp: parking_lot::RwLock::new(None),
            #[cfg(feature = "native-api")]
            counter_since: std::time::SystemTime::now(),
            warm_marks: DashMap::new(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn install_xdp(&self, diagnostics: Arc<xdp::Diagnostics>) {
        *self.xdp.write() = Some(diagnostics);
    }

    #[cfg(any(feature = "native-api", feature = "clash-api", test))]
    pub(crate) fn xdp_json(&self, full: bool) -> serde_json::Value {
        #[cfg(target_os = "linux")]
        {
            let diagnostics = self.xdp.read().clone();
            diagnostics.map_or(serde_json::Value::Null, |diagnostics| {
                diagnostics.json(full)
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = full;
            serde_json::Value::Null
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

    /// Track one connection with an exactly-once active counter balance.
    pub fn track_connection(
        self: &Arc<Self>,
        outbound: &str,
        kind: OutboundKind,
    ) -> ActiveConnectionGuard {
        self.track_outbound(self.outbound_tracker(outbound, kind))
    }

    /// Resolve an outbound tracker once for a long-lived data path. Callers
    /// that already retain the returned value avoid allocating an outbound
    /// name and taking a DashMap shard lock for every packet.
    pub fn outbound_tracker(&self, outbound: &str, kind: OutboundKind) -> Arc<OutboundTracker> {
        let trackers = &self.trackers[kind as usize];
        if let Some(tracker) = trackers.get(outbound) {
            return tracker.clone();
        }
        trackers.entry(outbound.to_owned()).or_default().clone()
    }

    /// Track one connection using an already-resolved tracker.
    pub fn track_outbound(&self, tracker: Arc<OutboundTracker>) -> ActiveConnectionGuard {
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
    #[cfg(feature = "legacy-tc")]
    pub fn update_udp_nfqueue_local_stats(
        &self,
        held_packets: usize,
        held_peak: usize,
        socket_receive_buffer_bytes: usize,
    ) {
        self.udp
            .nfqueue
            .held_packets
            .store(held_packets as u64, Ordering::Relaxed);
        self.udp
            .nfqueue
            .held_peak
            .store(held_peak as u64, Ordering::Relaxed);
        self.udp
            .nfqueue
            .socket_receive_buffer_bytes
            .store(socket_receive_buffer_bytes as u64, Ordering::Relaxed);
    }

    #[cfg(feature = "legacy-tc")]
    pub fn update_udp_nfqueue_service_stats(&self, stats: NfqueueServiceSample) {
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
        self.update_udp_nfqueue_local_stats(
            stats.held_packets,
            stats.held_peak,
            stats.socket_receive_buffer_bytes,
        );
    }

    #[cfg(feature = "legacy-tc")]
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

    #[cfg(feature = "legacy-tc")]
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

    #[cfg(feature = "legacy-tc")]
    pub fn record_udp_nfqueue_actor_queue_full(&self) {
        self.udp
            .nfqueue
            .actor_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "legacy-tc")]
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

    /// Record bytes transferred through an outbound.
    pub fn record_bytes(&self, outbound: &str, kind: OutboundKind, tx: u64, rx: u64) {
        let trackers = &self.trackers[kind as usize];
        if let Some(tracker) = trackers.get(outbound) {
            tracker.add_bytes(tx, rx);
            return;
        }
        trackers
            .entry(outbound.to_owned())
            .or_default()
            .add_bytes(tx, rx);
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn traffic_totals(&self) -> Option<(u64, u64)> {
        self.trackers
            .iter()
            .flat_map(|trackers| trackers.iter())
            .try_fold((0u64, 0u64), |(tx, rx), tracker| {
                Some((
                    tx.checked_add(tracker.tx_bytes.load(Ordering::Relaxed))?,
                    rx.checked_add(tracker.rx_bytes.load(Ordering::Relaxed))?,
                ))
            })
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn counter_since(&self) -> std::time::SystemTime {
        self.counter_since
    }

    /// Record an error on an outbound.
    pub fn record_error(&self, outbound: &str, kind: OutboundKind) {
        let trackers = &self.trackers[kind as usize];
        if let Some(tracker) = trackers.get(outbound) {
            tracker.increment_errors();
            return;
        }
        trackers
            .entry(outbound.to_owned())
            .or_default()
            .increment_errors();
    }

    /// Get a snapshot of all per-outbound statistics.
    pub fn snapshot(&self) -> std::collections::HashMap<String, OutboundStats> {
        let mut snapshot = std::collections::HashMap::<String, OutboundStats>::new();
        for entry in self.trackers.iter().flat_map(|trackers| trackers.iter()) {
            let value = entry.value().snapshot();
            let merged = snapshot.entry(entry.key().clone()).or_default();
            merged.tx_bytes = merged.tx_bytes.saturating_add(value.tx_bytes);
            merged.rx_bytes = merged.rx_bytes.saturating_add(value.rx_bytes);
            merged.active_conns = merged.active_conns.saturating_add(value.active_conns);
            merged.total_conns = merged.total_conns.saturating_add(value.total_conns);
            merged.errors = merged.errors.saturating_add(value.errors);
        }
        snapshot
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn native_snapshot(&self) -> Vec<NativeOutboundCounters> {
        let mut snapshot = Vec::new();
        for kind in [
            OutboundKind::Builtin,
            OutboundKind::Node,
            OutboundKind::Group,
        ] {
            for entry in &self.trackers[kind as usize] {
                snapshot.push(NativeOutboundCounters {
                    name: entry.key().clone(),
                    kind,
                    active_connections: entry.active_connections.load(Ordering::Relaxed),
                    total_connections: entry.total_connections.load(Ordering::Relaxed),
                    upload_bytes: entry.tx_bytes.load(Ordering::Relaxed),
                    download_bytes: entry.rx_bytes.load(Ordering::Relaxed),
                    errors: entry.errors.load(Ordering::Relaxed),
                });
            }
        }
        snapshot.sort_unstable_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.kind.as_str().cmp(b.kind.as_str()))
        });
        snapshot
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
        let mgr = Arc::new(StatsManager::new());

        let _first = mgr.track_connection("proxy1", crate::stats::OutboundKind::Node);
        let _second = mgr.track_connection("proxy1", crate::stats::OutboundKind::Node);
        let _third = mgr.track_connection("proxy2", crate::stats::OutboundKind::Node);
        mgr.record_bytes("proxy1", crate::stats::OutboundKind::Node, 1000, 2000);
        mgr.record_error("proxy2", crate::stats::OutboundKind::Node);

        let snap = mgr.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get("proxy1").unwrap().total_conns, 2);
        assert_eq!(snap.get("proxy2").unwrap().total_conns, 1);
        assert_eq!(snap.get("proxy2").unwrap().errors, 1);
    }

    #[test]
    fn warmed_stats_methods_reuse_one_tracker() {
        let manager = Arc::new(StatsManager::new());
        let first = manager.track_connection("proxy", crate::stats::OutboundKind::Node);
        let guard = manager.track_connection("proxy", crate::stats::OutboundKind::Node);
        manager.record_bytes("proxy", crate::stats::OutboundKind::Node, 100, 200);
        manager.record_error("proxy", crate::stats::OutboundKind::Node);

        let snapshot = manager.snapshot();
        let tracker = snapshot.get("proxy").unwrap();
        assert_eq!(tracker.total_conns, 2);
        assert_eq!(tracker.active_conns, 2);
        assert_eq!(tracker.tx_bytes, 100);
        assert_eq!(tracker.rx_bytes, 200);
        assert_eq!(tracker.errors, 1);

        drop(guard);
        drop(first);
        assert_eq!(manager.snapshot()["proxy"].active_conns, 0);
    }

    #[test]
    fn active_connection_guard_decrements_active_exactly_once() {
        let manager = Arc::new(StatsManager::new());
        let guard = manager.track_connection("udp-test", crate::stats::OutboundKind::Node);

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
        let mut node = honk_config::node::Node {
            name: "ss".into(),
            address: addr.to_string(),
            port: addr.port(),
            outbound: honk_config::node::OutboundConfig::Shadowsocks(Default::default()),
            ..Default::default()
        };
        node.id = node.derive_id();
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
        let mut node = honk_config::node::Node {
            name: "tuic".into(),
            address: "127.0.0.1:443".into(),
            port: 443,
            outbound: honk_config::node::OutboundConfig::Tuic(honk_config::node::TuicConfig {
                uuid: Some("00000000-0000-4000-8000-000000000001".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        node.id = node.derive_id();
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
    #[cfg(feature = "legacy-tc")]
    #[test]
    fn nfqueue_kernel_stats_failures_are_visible() {
        let stats = StatsManager::new();
        stats.update_udp_nfqueue_service_stats(NfqueueServiceSample {
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
        assert_eq!(available.kernel_dropped, 2);
        assert_eq!(available.kernel_user_dropped, 3);
        assert_eq!(available.held_packets, 4);
        assert_eq!(available.held_peak, 5);
        assert_eq!(available.socket_receive_buffer_bytes, 6);
        assert_eq!(available.kernel_stats_read_errors, 0);

        stats.update_udp_nfqueue_local_stats(1, 6, 8192);
        stats.record_udp_nfqueue_service_stats_error();
        let unavailable = stats.udp_snapshot().nfqueue;
        assert!(!unavailable.kernel_stats_available);
        assert_eq!(unavailable.kernel_stats_read_errors, 1);
        assert_eq!(unavailable.kernel_queue_depth, 7);
        assert_eq!(unavailable.held_packets, 1);
        assert_eq!(unavailable.held_peak, 6);
        assert_eq!(unavailable.socket_receive_buffer_bytes, 8192);
    }

    #[cfg(feature = "native-api")]
    #[test]
    fn native_traffic_overflow_is_unknown_not_wrapped() {
        let stats = StatsManager::new();
        stats.record_bytes("first", crate::stats::OutboundKind::Node, u64::MAX, 1);
        assert_eq!(stats.traffic_totals(), Some((u64::MAX, 1)));
        stats.record_bytes("second", crate::stats::OutboundKind::Node, 1, 0);
        assert_eq!(stats.traffic_totals(), None);
    }

    #[cfg(feature = "native-api")]
    #[test]
    fn native_counters_retain_kind_and_full_width_across_config_changes() {
        let stats = StatsManager::new();
        let old_groups = crate::group::GroupManager::new(
            &[honk_config::group::Group {
                name: "shared".into(),
                ..Default::default()
            }],
            &[],
        );
        let old_kind = OutboundKind::routed(&old_groups, "shared");
        assert_eq!(old_kind, OutboundKind::Group);
        let old = stats.outbound_tracker("shared", old_kind);
        let wide = u32::MAX as u64 + 17;
        old.total_connections.store(wide, Ordering::Relaxed);
        old.active_connections.store(wide, Ordering::Relaxed);
        old.errors.store(wide, Ordering::Relaxed);
        old.add_bytes(wide, wide + 1);
        let new_groups = crate::group::GroupManager::new(
            &[],
            &[honk_config::node::Node {
                name: "shared".into(),
                ..Default::default()
            }],
        );
        let new_kind = OutboundKind::routed(&new_groups, "shared");
        assert_eq!(new_kind, OutboundKind::Node);
        let guard = stats.track_outbound(stats.outbound_tracker("shared", new_kind));
        stats.record_bytes("shared", new_kind, 3, 5);
        old.add_bytes(7, 11);
        drop(guard);
        let snapshot = stats.native_snapshot();
        assert_eq!(snapshot.len(), 2);
        let group = snapshot
            .iter()
            .find(|row| row.kind == OutboundKind::Group)
            .unwrap();
        assert_eq!(
            (
                group.active_connections,
                group.total_connections,
                group.errors
            ),
            (wide, wide, wide)
        );
        assert_eq!(
            (group.upload_bytes, group.download_bytes),
            (wide + 7, wide + 12)
        );
        let node = snapshot
            .iter()
            .find(|row| row.kind == OutboundKind::Node)
            .unwrap();
        assert_eq!(
            (
                node.active_connections,
                node.total_connections,
                node.upload_bytes,
                node.download_bytes
            ),
            (0, 1, 3, 5)
        );
        assert_eq!(stats.traffic_totals(), Some((wide + 10, wide + 17)));
        let legacy = stats.snapshot();
        assert_eq!(legacy["shared"].total_conns, u32::MAX);
        assert_eq!(legacy["shared"].tx_bytes, wide + 10);
        assert_eq!(
            OutboundKind::routed(&new_groups, "direct"),
            OutboundKind::Builtin
        );
        assert_eq!(
            OutboundKind::routed(&new_groups, "must_rules"),
            OutboundKind::Group
        );
    }
}
