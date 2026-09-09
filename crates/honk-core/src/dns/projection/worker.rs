use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};
use tokio::time::Instant;

use super::{ProjectionCounters, RoutingProjection};
use crate::ebpf::{EbpfBackend, maps};

const WARN_INTERVAL: Duration = Duration::from_secs(5);

pub(super) async fn run(
    projection: std::sync::Weak<RoutingProjection>,
    mut receiver: mpsc::Receiver<()>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    counters: Arc<ProjectionCounters>,
) {
    let mut last_warning = None;
    loop {
        let Some(active) = projection.upgrade() else {
            return;
        };
        let deadline = active.state.lock().next_deadline();
        drop(active);
        let received_wake = match deadline {
            Some(deadline) => {
                tokio::select! {
                    wake = receiver.recv() => {
                        if wake.is_none() {
                            return;
                        }
                        true
                    },
                    () = tokio::time::sleep_until(deadline) => false,
                }
            }
            None => {
                if receiver.recv().await.is_none() {
                    return;
                }
                true
            }
        };
        let Some(active) = projection.upgrade() else {
            return;
        };
        if received_wake {
            active.clear_worker_wake();
        }
        flush(&active, &ebpf, &counters, &mut last_warning).await;
    }
}

async fn flush(
    projection: &RoutingProjection,
    ebpf: &RwLock<Box<dyn EbpfBackend>>,
    counters: &ProjectionCounters,
    last_warning: &mut Option<Instant>,
) {
    flush_after_snapshot(projection, ebpf, counters, last_warning, || {}).await;
}

async fn flush_after_snapshot(
    projection: &RoutingProjection,
    ebpf: &RwLock<Box<dyn EbpfBackend>>,
    counters: &ProjectionCounters,
    last_warning: &mut Option<Instant>,
    after_snapshot: impl FnOnce(),
) {
    let now = Instant::now();
    let batch = {
        let mut state = projection.state.lock();
        state.expire(now);
        state.batch(now)
    };
    after_snapshot();
    if batch.sets.is_empty() && batch.removes.is_empty() {
        return;
    }

    let mut successful_sets = Vec::new();
    let mut successful_removes = Vec::new();
    let mut failures = Vec::new();
    let writes_current = {
        let mut backend = ebpf.write().await;
        let publication = projection.publication_fence.read();
        if batch.generation != projection.state.lock().snapshot.generation() {
            drop(publication);
            drop(backend);
            counters.generation_rebuilds.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::ProjectionStaleGeneration);
            tracing::debug!(
                reason = "generation_changed_before_write",
                "DNS routing projection skipped stale write"
            );
            projection.notify_worker();
            return;
        }
        for set in &batch.sets {
            let key = maps::ip_addr_to_lpm_key(set.ip);
            match backend.set_domain_ip_bitmap(&key, &set.bitmap) {
                Ok(()) => successful_sets.push(*set),
                Err(error) => failures.push((set.ip, error)),
            }
        }
        for remove in &batch.removes {
            let key = maps::ip_addr_to_lpm_key(*remove);
            match backend.remove_domain_ip_bitmap(&key) {
                Ok(()) => successful_removes.push(*remove),
                Err(error) => failures.push((*remove, error)),
            }
        }

        // Keep map writes and their applied accounting under the same generation fence.
        let mut state = projection.state.lock();
        for (ip, _) in &failures {
            state.record_failure(*ip, now);
        }
        state.commit_success(&successful_sets, &successful_removes)
    };
    if !writes_current {
        crate::stats::record_dns_event(crate::stats::DnsStatEvent::ProjectionRetry);
        projection.notify_worker();
    }
    for (_, error) in failures {
        counters.write_failures.fetch_add(1, Ordering::Relaxed);
        crate::stats::record_dns_event(crate::stats::DnsStatEvent::ProjectionWriteFailure);
        crate::stats::record_dns_event(crate::stats::DnsStatEvent::ProjectionRetry);
        if error.is_map_full() {
            counters.map_full.fetch_add(1, Ordering::Relaxed);
        }
        let should_warn = last_warning.is_none_or(|last| now.duration_since(last) >= WARN_INTERVAL);
        if should_warn {
            let error_kind = if error.is_map_full() {
                "map_full"
            } else {
                "backend_write"
            };
            tracing::warn!(error_kind, "DNS routing projection write failed");
            *last_warning = Some(now);
        }
    }
}

#[cfg(test)]
pub(super) async fn flush_for_test(
    projection: &RoutingProjection,
    ebpf: &RwLock<Box<dyn EbpfBackend>>,
) {
    let mut last_warning = None;
    flush(projection, ebpf, &projection.counters, &mut last_warning).await;
}

#[cfg(test)]
pub(super) async fn flush_for_test_after_snapshot(
    projection: &RoutingProjection,
    ebpf: &RwLock<Box<dyn EbpfBackend>>,
    after_snapshot: impl FnOnce(),
) {
    let mut last_warning = None;
    flush_after_snapshot(
        projection,
        ebpf,
        &projection.counters,
        &mut last_warning,
        after_snapshot,
    )
    .await;
}
