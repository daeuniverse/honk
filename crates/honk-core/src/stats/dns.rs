use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

mod snapshot;
pub(crate) use snapshot::DnsStatsSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsStatEvent {
    CacheHit,
    CacheMiss,
    CacheStale,
    SingleflightCancel,
    SingleflightRetry,
    SingleflightRejected,
    SingleflightAmplificationAvoided,
    PersistenceDrop,
    PersistenceFlushFailure,
    RuntimeRetirementTimeout,
    RuntimeForcedClose,
    TransportInit,
    TransportReset,
    SocketAdmissionRefused,
    SocketAdmissionTimeout,
    ProxyAdmissionTimeout,
    PressureRetiredUdpPool,
    PressureRetiredTransport,
    ProjectionStaleGeneration,
    ProjectionWriteFailure,
    ProjectionRetry,
    OutcomePositive,
    OutcomeNodata,
    OutcomeNxdomain,
    OutcomeServfail,
    OutcomeRejected,
    OutcomeError,
}

#[derive(Default)]
struct DnsStats {
    cache_hit: AtomicU64,
    cache_miss: AtomicU64,
    cache_stale: AtomicU64,
    singleflight_key_saturation: AtomicU64,
    singleflight_waiter_saturation: AtomicU64,
    singleflight_cancel: AtomicU64,
    singleflight_retry: AtomicU64,
    singleflight_rejected: AtomicU64,
    singleflight_amplification_avoided: AtomicU64,
    persistence_drop: AtomicU64,
    persistence_flush_failure: AtomicU64,
    runtime_retirement_timeout: AtomicU64,
    runtime_forced_close: AtomicU64,
    transport_init: AtomicU64,
    transport_reset: AtomicU64,
    socket_admission_refused: AtomicU64,
    socket_admission_timeout: AtomicU64,
    proxy_admission_timeout: AtomicU64,
    pressure_retired_udp_pool: AtomicU64,
    pressure_retired_transport: AtomicU64,
    projection_stale_generation: AtomicU64,
    projection_write_failure: AtomicU64,
    projection_retry: AtomicU64,
    outcome_positive: AtomicU64,
    outcome_nodata: AtomicU64,
    outcome_nxdomain: AtomicU64,
    outcome_servfail: AtomicU64,
    outcome_rejected: AtomicU64,
    outcome_error: AtomicU64,
}

static DNS_STATS: LazyLock<DnsStats> = LazyLock::new(DnsStats::default);

impl DnsStats {
    fn record(&self, event: DnsStatEvent) {
        self.counter(event).fetch_add(1, Ordering::Relaxed);
    }

    fn counter(&self, event: DnsStatEvent) -> &AtomicU64 {
        match event {
            DnsStatEvent::CacheHit => &self.cache_hit,
            DnsStatEvent::CacheMiss => &self.cache_miss,
            DnsStatEvent::CacheStale => &self.cache_stale,
            DnsStatEvent::SingleflightCancel => &self.singleflight_cancel,
            DnsStatEvent::SingleflightRetry => &self.singleflight_retry,
            DnsStatEvent::SingleflightRejected => &self.singleflight_rejected,
            DnsStatEvent::SingleflightAmplificationAvoided => {
                &self.singleflight_amplification_avoided
            }
            DnsStatEvent::PersistenceDrop => &self.persistence_drop,
            DnsStatEvent::PersistenceFlushFailure => &self.persistence_flush_failure,
            DnsStatEvent::RuntimeRetirementTimeout => &self.runtime_retirement_timeout,
            DnsStatEvent::RuntimeForcedClose => &self.runtime_forced_close,
            DnsStatEvent::TransportInit => &self.transport_init,
            DnsStatEvent::TransportReset => &self.transport_reset,
            DnsStatEvent::SocketAdmissionRefused => &self.socket_admission_refused,
            DnsStatEvent::SocketAdmissionTimeout => &self.socket_admission_timeout,
            DnsStatEvent::ProxyAdmissionTimeout => &self.proxy_admission_timeout,
            DnsStatEvent::PressureRetiredUdpPool => &self.pressure_retired_udp_pool,
            DnsStatEvent::PressureRetiredTransport => &self.pressure_retired_transport,
            DnsStatEvent::ProjectionStaleGeneration => &self.projection_stale_generation,
            DnsStatEvent::ProjectionWriteFailure => &self.projection_write_failure,
            DnsStatEvent::ProjectionRetry => &self.projection_retry,
            DnsStatEvent::OutcomePositive => &self.outcome_positive,
            DnsStatEvent::OutcomeNodata => &self.outcome_nodata,
            DnsStatEvent::OutcomeNxdomain => &self.outcome_nxdomain,
            DnsStatEvent::OutcomeServfail => &self.outcome_servfail,
            DnsStatEvent::OutcomeRejected => &self.outcome_rejected,
            DnsStatEvent::OutcomeError => &self.outcome_error,
        }
    }

    fn snapshot(&self) -> DnsStatsSnapshot {
        // Each field is an independent monotonic event counter. This scrape is
        // best-effort: concurrent records may become visible between loads, so
        // callers must not infer cross-counter invariants from one snapshot.
        DnsStatsSnapshot {
            cache_hit: self.cache_hit.load(Ordering::Relaxed),
            cache_miss: self.cache_miss.load(Ordering::Relaxed),
            cache_stale: self.cache_stale.load(Ordering::Relaxed),
            singleflight_key_saturation: self.singleflight_key_saturation.load(Ordering::Relaxed),
            singleflight_waiter_saturation: self
                .singleflight_waiter_saturation
                .load(Ordering::Relaxed),
            singleflight_cancel: self.singleflight_cancel.load(Ordering::Relaxed),
            singleflight_retry: self.singleflight_retry.load(Ordering::Relaxed),
            singleflight_rejected: self.singleflight_rejected.load(Ordering::Relaxed),
            singleflight_amplification_avoided: self
                .singleflight_amplification_avoided
                .load(Ordering::Relaxed),
            persistence_drop: self.persistence_drop.load(Ordering::Relaxed),
            persistence_flush_failure: self.persistence_flush_failure.load(Ordering::Relaxed),
            runtime_retirement_timeout: self.runtime_retirement_timeout.load(Ordering::Relaxed),
            runtime_forced_close: self.runtime_forced_close.load(Ordering::Relaxed),
            transport_init: self.transport_init.load(Ordering::Relaxed),
            transport_reset: self.transport_reset.load(Ordering::Relaxed),
            socket_admission_refused: self.socket_admission_refused.load(Ordering::Relaxed),
            socket_admission_timeout: self.socket_admission_timeout.load(Ordering::Relaxed),
            proxy_admission_timeout: self.proxy_admission_timeout.load(Ordering::Relaxed),
            pressure_retired_udp_pool: self.pressure_retired_udp_pool.load(Ordering::Relaxed),
            pressure_retired_transport: self.pressure_retired_transport.load(Ordering::Relaxed),
            projection_stale_generation: self.projection_stale_generation.load(Ordering::Relaxed),
            projection_write_failure: self.projection_write_failure.load(Ordering::Relaxed),
            projection_retry: self.projection_retry.load(Ordering::Relaxed),
            outcome_positive: self.outcome_positive.load(Ordering::Relaxed),
            outcome_nodata: self.outcome_nodata.load(Ordering::Relaxed),
            outcome_nxdomain: self.outcome_nxdomain.load(Ordering::Relaxed),
            outcome_servfail: self.outcome_servfail.load(Ordering::Relaxed),
            outcome_rejected: self.outcome_rejected.load(Ordering::Relaxed),
            outcome_error: self.outcome_error.load(Ordering::Relaxed),
        }
    }
}

pub(crate) fn record_dns_event(event: DnsStatEvent) {
    DNS_STATS.record(event);
}

#[cfg_attr(
    all(not(test), not(feature = "dns-bench"), not(feature = "clash-api")),
    expect(
        dead_code,
        reason = "DNS statistics are exposed only with the Clash API"
    )
)]
pub(crate) fn dns_snapshot() -> DnsStatsSnapshot {
    DNS_STATS.snapshot()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{DnsStatEvent, DnsStats};

    #[test]
    fn record_increments_only_the_selected_counter() {
        let stats = DnsStats::default();
        let before = stats.snapshot();

        stats.record(DnsStatEvent::CacheHit);

        let delta = stats.snapshot().delta(before);
        assert_eq!(delta.cache_hit, 1);
        assert_eq!(delta.cache_miss, 0);
    }

    #[test]
    fn concurrent_records_are_monotonic_without_cross_counter_coherence() {
        const WRITERS: u64 = 4;
        const WRITES_PER_THREAD: u64 = 25_000;

        let stats = Arc::new(DnsStats::default());
        let writers: Vec<_> = (0..WRITERS)
            .map(|_| {
                let stats = Arc::clone(&stats);
                std::thread::spawn(move || {
                    for _ in 0..WRITES_PER_THREAD {
                        stats.record(DnsStatEvent::CacheHit);
                    }
                })
            })
            .collect();

        let mut earlier = stats.snapshot().cache_hit;
        for _ in 0..100 {
            let current = stats.snapshot().cache_hit;
            assert!(current >= earlier);
            earlier = current;
        }
        for writer in writers {
            writer.join().expect("writer");
        }

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.cache_hit, WRITERS * WRITES_PER_THREAD);
        assert_eq!(snapshot.cache_miss, 0);
    }
}
