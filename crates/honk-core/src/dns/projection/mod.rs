use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use honk_ebpf_common::DomainRouting;
use honk_outbound::alive::IpVersion;

use crate::ebpf::EbpfBackend;
use crate::routing::Router;

mod lifecycle {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub(super) struct ProjectionLifecycle {
        terminated: AtomicBool,
        termination: tokio::sync::Notify,
    }

    impl ProjectionLifecycle {
        pub(super) fn running() -> Arc<Self> {
            Arc::new(Self {
                terminated: AtomicBool::new(false),
                termination: tokio::sync::Notify::new(),
            })
        }

        pub(super) fn finish(&self) {
            self.terminated.store(true, Ordering::Release);
            self.termination.notify_waiters();
        }

        pub(super) async fn wait(&self) {
            loop {
                let terminated = self.termination.notified();
                if self.terminated.load(Ordering::Acquire) {
                    return;
                }
                terminated.await;
            }
        }
    }

    pub(super) struct TerminationGuard(Arc<ProjectionLifecycle>);

    impl TerminationGuard {
        pub(super) fn new(lifecycle: Arc<ProjectionLifecycle>) -> Self {
            Self(lifecycle)
        }
    }

    impl Drop for TerminationGuard {
        fn drop(&mut self) {
            self.0.finish();
        }
    }

    #[cfg(test)]
    pub(super) struct ProjectionTerminationProbe(Arc<ProjectionLifecycle>);

    #[cfg(test)]
    impl ProjectionTerminationProbe {
        pub(super) fn new(lifecycle: Arc<ProjectionLifecycle>) -> Self {
            Self(lifecycle)
        }

        pub(super) fn is_terminated(&self) -> bool {
            self.0.terminated.load(Ordering::Acquire)
        }

        pub(super) async fn wait(&self) {
            self.0.wait().await;
        }
    }
}
mod reconcile;
mod state;
mod worker;

#[cfg(test)]
use lifecycle::ProjectionTerminationProbe;
use lifecycle::{ProjectionLifecycle, TerminationGuard};
use state::DesiredState;

const DEFAULT_DOMAIN_CAPACITY: usize = 10_000;
/// Cache-hit refreshes of an unchanged owner within this window skip the
/// projection fence and state lock. Bounds stale LRU recency and how late a
/// skipped TTL shortening is applied.
const CACHE_HIT_COALESCE: Duration = Duration::from_secs(1);

/// Owner state last applied under the projection fence and state lock.
struct CacheHitHint {
    structure: u64,
    generation: u64,
    ips: Box<[IpAddr]>,
    expires_at: tokio::time::Instant,
    applied_at: tokio::time::Instant,
}

#[derive(Debug, Clone)]
pub(crate) struct RoutingProjectionSnapshot {
    generation: u64,
    matcher: Arc<Router>,
}

impl RoutingProjectionSnapshot {
    pub(crate) fn new(generation: u64, matcher: Arc<Router>) -> Self {
        Self {
            generation,
            matcher,
        }
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn bitmap_for(&self, domain: &str) -> Option<DomainRouting> {
        self.matcher.domain_bitmap(domain)
    }
}

/// A/AAAA results own only their address family; NXDOMAIN clears the name.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ProjectionObservation<'a> {
    Positive {
        domain: &'a str,
        family: IpVersion,
        ips: &'a [IpAddr],
        expires_at: tokio::time::Instant,
    },
    Clear {
        domain: &'a str,
        family: IpVersion,
    },
    ClearName {
        domain: &'a str,
    },
    Retain,
}

#[derive(Debug, Default)]
pub(crate) struct ProjectionCounters {
    write_failures: AtomicU64,
    map_full: AtomicU64,
    wake_coalesced: AtomicU64,
    evictions: AtomicU64,
    generation_rebuilds: AtomicU64,
}

impl ProjectionCounters {
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> ProjectionCounterSnapshot {
        ProjectionCounterSnapshot {
            write_failures: self.write_failures.load(Ordering::Relaxed),
            map_full: self.map_full.load(Ordering::Relaxed),
            wake_coalesced: self.wake_coalesced.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            generation_rebuilds: self.generation_rebuilds.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProjectionCounterSnapshot {
    pub(crate) write_failures: u64,
    pub(crate) map_full: u64,
    pub(crate) wake_coalesced: u64,
    pub(crate) evictions: u64,
    pub(crate) generation_rebuilds: u64,
}

pub(crate) struct RoutingProjection {
    state: parking_lot::Mutex<DesiredState>,
    publication_fence: parking_lot::RwLock<()>,
    wake: parking_lot::Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
    wake_pending: AtomicBool,
    counters: Arc<ProjectionCounters>,
    worker: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    lifecycle: Arc<ProjectionLifecycle>,
    /// Per-family cache-hit hints, dropped wholesale whenever the owner
    /// structure changes so the store never outgrows the owner set.
    hints: [dashmap::DashMap<Arc<str>, CacheHitHint>; 2],
    structure: Arc<std::sync::atomic::AtomicU64>,
    /// Structure epoch the hint store was last cleared for; written under the
    /// state lock only.
    hints_epoch: AtomicU64,
    /// Woken after every exclusive fence release so contended submissions
    /// wait asynchronously instead of blocking a thread.
    publication_released: tokio::sync::Notify,
}

pub(crate) struct PreparedProjectionPublication<'a> {
    projection: &'a RoutingProjection,
    fence: Option<parking_lot::RwLockWriteGuard<'a, ()>>,
}

impl Drop for PreparedProjectionPublication<'_> {
    fn drop(&mut self) {
        // Release before waking so woken submissions can take the fence.
        drop(self.fence.take());
        self.projection.publication_released.notify_waiters();
    }
}

impl PreparedProjectionPublication<'_> {
    pub(crate) fn project(
        &self,
        snapshot: &RoutingProjectionSnapshot,
    ) -> BTreeMap<IpAddr, DomainRouting> {
        self.projection.state.lock().project(snapshot)
    }

    pub(crate) fn commit(
        self,
        snapshot: Arc<RoutingProjectionSnapshot>,
        published: Option<BTreeMap<IpAddr, DomainRouting>>,
    ) {
        let mut state = self.projection.state.lock();
        if let Some(published) = published {
            // A reload pre-fills the map outside the incremental worker. Record
            // that exact set, including owners that expired while it loaded.
            state.applied = published;
            state.dirty_ips.clear();
            state.retries.clear();
        }
        state.update_snapshot(&snapshot);
        drop(state);
        self.projection.notify_worker();
    }
}

impl RoutingProjection {
    pub(crate) fn spawn(
        ebpf: Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>>,
        snapshot: Arc<RoutingProjectionSnapshot>,
    ) -> Arc<Self> {
        let (wake, receiver) = tokio::sync::mpsc::channel(1);
        let counters = Arc::new(ProjectionCounters::default());
        let lifecycle = ProjectionLifecycle::running();
        let state = DesiredState::new(snapshot, DEFAULT_DOMAIN_CAPACITY);
        let structure = Arc::clone(&state.structure);
        let projection = Arc::new(Self {
            state: parking_lot::Mutex::new(state),
            publication_fence: parking_lot::RwLock::new(()),
            wake: parking_lot::Mutex::new(Some(wake)),
            wake_pending: AtomicBool::new(false),
            counters: Arc::clone(&counters),
            worker: parking_lot::Mutex::new(None),
            lifecycle: Arc::clone(&lifecycle),
            hints: Default::default(),
            structure,
            hints_epoch: AtomicU64::new(0),
            publication_released: tokio::sync::Notify::new(),
        });
        let guard = TerminationGuard::new(lifecycle);
        let projection_worker = Arc::downgrade(&projection);
        let handle = tokio::spawn(async move {
            let _guard = guard;
            worker::run(projection_worker, receiver, ebpf, counters).await;
        });
        projection.worker.lock().replace(handle);
        projection
    }
    pub(crate) fn prepare_snapshot_publication(&self) -> PreparedProjectionPublication<'_> {
        PreparedProjectionPublication {
            projection: self,
            fence: Some(self.publication_fence.write()),
        }
    }

    #[cfg(test)]
    pub(crate) fn update_snapshot(&self, snapshot: Arc<RoutingProjectionSnapshot>) {
        assert!(self.try_mutate(snapshot.generation(), |state| {
            state.update_snapshot(&snapshot);
            0
        }));
    }

    #[cfg(test)]
    pub(crate) fn submit(
        &self,
        snapshot: Arc<RoutingProjectionSnapshot>,
        observation: ProjectionObservation<'_>,
    ) {
        assert!(
            self.try_submit(&snapshot, observation),
            "test submission met a held publication fence"
        );
    }

    #[cfg(test)]
    pub(crate) fn project(
        &self,
        snapshot: &RoutingProjectionSnapshot,
    ) -> Vec<(IpAddr, DomainRouting)> {
        self.state.lock().project(snapshot).into_iter().collect()
    }

    /// Applies `observation`, or returns `false` while a publication holds
    /// the fence; see [`Self::submit_after_publication`].
    pub(crate) fn try_submit(
        &self,
        snapshot: &Arc<RoutingProjectionSnapshot>,
        observation: ProjectionObservation<'_>,
    ) -> bool {
        self.try_mutate(snapshot.generation(), |state| {
            if !state.update_snapshot(snapshot) {
                crate::stats::record_dns_event(
                    crate::stats::DnsStatEvent::ProjectionStaleGeneration,
                );
                tracing::debug!(
                    reason = "older_snapshot",
                    "DNS routing projection update ignored"
                );
                return 0;
            }
            // A same-set positive changes expiry without a structure bump;
            // drop the hint so it cannot coalesce against the old expiry.
            if let ProjectionObservation::Positive { domain, family, .. } = observation {
                self.hints[family as usize].remove(domain);
            }
            state.observe(observation, tokio::time::Instant::now())
        })
    }

    /// Submits a DNS-cache observation. A refresh identical to one applied within
    /// `CACHE_HIT_COALESCE`, shortening expiry by at most that window, is coalesced
    /// without taking the projection fence or state lock.
    /// Returns `false` while a publication holds the fence.
    pub(crate) fn try_submit_cache_hit(
        &self,
        snapshot: &Arc<RoutingProjectionSnapshot>,
        domain: &str,
        family: IpVersion,
        ips: &[IpAddr],
        expires_at: tokio::time::Instant,
    ) -> bool {
        let now = tokio::time::Instant::now();
        let hints = &self.hints[family as usize];
        let structure = self.structure.load(Ordering::Acquire);
        let coalesced = hints.get(domain).is_some_and(|hint| {
            hint.structure == structure
                && hint.generation == snapshot.generation()
                && now < expires_at
                && now < hint.expires_at
                && now.saturating_duration_since(hint.applied_at) < CACHE_HIT_COALESCE
                && expires_at <= hint.expires_at
                && expires_at + CACHE_HIT_COALESCE >= hint.expires_at
                && state::same_address_set(hint.ips.iter(), ips)
        });
        if coalesced {
            return true;
        }
        self.try_mutate(snapshot.generation(), |state| {
            if !state.update_snapshot(snapshot) {
                crate::stats::record_dns_event(
                    crate::stats::DnsStatEvent::ProjectionStaleGeneration,
                );
                return 0;
            }
            let applied_at = tokio::time::Instant::now();
            let evicted = state.observe(
                ProjectionObservation::Positive {
                    domain,
                    family,
                    ips,
                    expires_at,
                },
                applied_at,
            );
            let structure = state.structure.load(Ordering::Acquire);
            if self.hints_epoch.swap(structure, Ordering::Relaxed) != structure {
                for family_hints in &self.hints {
                    family_hints.clear();
                }
            }
            if let Some((key, ips, expires_at)) = state.cache_hit_hint(family as usize, domain) {
                hints.insert(
                    key,
                    CacheHitHint {
                        structure,
                        generation: state.snapshot.generation(),
                        ips,
                        expires_at,
                        applied_at,
                    },
                );
            }
            evicted
        })
    }

    /// Retries a `try_submit*` closure that met a held publication fence,
    /// awaiting each release instead of blocking the thread.
    pub(crate) async fn submit_after_publication(&self, mut submit: impl FnMut() -> bool) {
        loop {
            let released = self.publication_released.notified();
            tokio::pin!(released);
            // Registered before retrying, so a release in between still wakes it.
            released.as_mut().enable();
            if submit() {
                return;
            }
            released.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn counters(&self) -> ProjectionCounterSnapshot {
        self.counters.snapshot()
    }

    pub(crate) async fn shutdown(&self, timeout: Duration) {
        self.wake.lock().take();
        let handle = self.worker.lock().take();
        if let Some(mut handle) = handle {
            // A wedged worker must be aborted, never detached: shutdown
            // continues into backend cleanup, and a live worker would keep
            // pushing map writes into the backend being torn down.
            if tokio::time::timeout(timeout, &mut handle).await.is_err() {
                handle.abort();
                let _ = (&mut handle).await;
            }
        } else {
            let _ = tokio::time::timeout(timeout, self.lifecycle.wait()).await;
        }
    }

    /// Applies `operation` under the shared publication fence, which worker
    /// map writes also share, or returns `false` while a publication holds or
    /// awaits it. Only a newer snapshot needs the fence exclusively.
    fn try_mutate(
        &self,
        generation: u64,
        operation: impl FnOnce(&mut DesiredState) -> u64,
    ) -> bool {
        let Some(shared) = self.publication_fence.try_read() else {
            return false;
        };
        let mut state = self.state.lock();
        let counter_delta = if generation > state.snapshot.generation() {
            drop(state);
            drop(shared);
            // Rebuilding under a newer snapshot must not interleave with a
            // worker batch. Reload commits snapshots under its own fence, so
            // a submission only gets here outside one, briefly.
            let exclusive = self.publication_fence.write();
            let delta = operation(&mut self.state.lock());
            drop(exclusive);
            self.publication_released.notify_waiters();
            delta
        } else {
            let delta = operation(&mut state);
            drop(state);
            drop(shared);
            delta
        };
        self.counters
            .evictions
            .fetch_add(counter_delta, Ordering::Relaxed);
        self.notify_worker();
        true
    }

    fn notify_worker(&self) {
        if self.wake_pending.swap(true, Ordering::AcqRel) {
            self.counters.wake_coalesced.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some(wake) = self.wake.lock().as_ref().cloned() else {
            self.wake_pending.store(false, Ordering::Release);
            return;
        };
        match wake.try_send(()) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(())) => {
                self.counters.wake_coalesced.fetch_add(1, Ordering::Relaxed);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                self.wake_pending.store(false, Ordering::Release);
            }
        }
    }

    fn clear_worker_wake(&self) {
        self.wake_pending.store(false, Ordering::Release);
    }

    #[cfg(test)]
    fn termination_probe_for_test(&self) -> ProjectionTerminationProbe {
        ProjectionTerminationProbe::new(Arc::clone(&self.lifecycle))
    }
}

#[cfg(feature = "dns-bench")]
pub(crate) struct ProjectionReplacementBenchmark {
    state: DesiredState,
    domains: Vec<Arc<str>>,
    next: usize,
    ip: IpAddr,
    now: tokio::time::Instant,
}

#[cfg(feature = "dns-bench")]
impl ProjectionReplacementBenchmark {
    /// Observes `domains` round-robin on one shared IP; more names than the
    /// owner capacity make every observation insert one owner and evict another.
    pub(crate) fn new(
        snapshot: Arc<RoutingProjectionSnapshot>,
        domains: Vec<Arc<str>>,
        ip: IpAddr,
    ) -> Self {
        let mut replacement = Self {
            state: DesiredState::new(snapshot, DEFAULT_DOMAIN_CAPACITY),
            domains,
            next: 0,
            ip,
            now: tokio::time::Instant::now(),
        };
        for _ in 0..replacement.domains.len().min(DEFAULT_DOMAIN_CAPACITY) {
            replacement.replace();
        }
        replacement
    }

    pub(crate) fn replace(&mut self) -> u64 {
        self.now += Duration::from_millis(1);
        let domain = &self.domains[self.next];
        self.next = (self.next + 1) % self.domains.len();
        self.state.observe(
            ProjectionObservation::Positive {
                domain,
                family: state::family_of(self.ip),
                ips: std::slice::from_ref(&self.ip),
                expires_at: self.now + Duration::from_secs(300),
            },
            self.now,
        );
        self.state.sequence
    }
}

impl Drop for RoutingProjection {
    fn drop(&mut self) {
        self.wake.get_mut().take();
        if let Some(handle) = self.worker.get_mut().take() {
            handle.abort();
        }
    }
}

fn or_bitmap(target: &mut DomainRouting, source: &DomainRouting) {
    for (target, source) in target.bitmap.iter_mut().zip(source.bitmap) {
        *target |= source;
    }
}

#[cfg(test)]
mod tests;
