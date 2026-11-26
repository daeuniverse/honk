use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use honk_datapath::ScopeId;
use honk_ebpf_common::DomainRouting;
use honk_outbound::alive::IpVersion;

use crate::dns::outcome::ProjectionSource;
use crate::ebpf::DomainProjectionSink;
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
#[cfg(target_os = "linux")]
mod gateway;
#[cfg(target_os = "linux")]
use crate::xdp::gateway::dns::GatewayDnsBank;
#[cfg(target_os = "linux")]
pub(crate) use gateway::GatewayDnsFill;
mod reconcile;
mod state;
mod worker;

#[cfg(test)]
use lifecycle::ProjectionTerminationProbe;
use lifecycle::{ProjectionLifecycle, TerminationGuard};
use state::DesiredState;

const DEFAULT_DOMAIN_CAPACITY: usize = 10_000;
/// HOST cache-hit refreshes of an unchanged owner within this window skip the
/// projection fence and state lock, bounding stale recency and TTL shortening.
const CACHE_HIT_COALESCE: Duration = Duration::from_secs(1);

/// Owner state last applied under its committed generation and state lock.
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
        source: ProjectionSource,
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

/// The fact destination and its originating authority, retained through publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QueryScope {
    fact_scope: ScopeId,
    origin: QueryOrigin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryOrigin {
    Permanent,
    Packet {
        execution: ScopeId,
        stamp: u64,
    },
    #[cfg(target_os = "linux")]
    HostListener {
        stamp: u64,
    },
}

impl QueryScope {
    pub(crate) const HOST: Self = Self::permanent(ScopeId::HOST);

    const fn permanent(fact_scope: ScopeId) -> Self {
        Self {
            fact_scope,
            origin: QueryOrigin::Permanent,
        }
    }

    fn packet(fact_scope: ScopeId, execution: ScopeId, stamp: u64) -> Self {
        Self {
            fact_scope,
            origin: QueryOrigin::Packet { execution, stamp },
        }
    }

    pub(crate) fn is_host_listener(self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self.origin, QueryOrigin::HostListener { .. })
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    #[cfg(target_os = "linux")]
    fn is_shared_host(self) -> bool {
        match self.origin {
            QueryOrigin::Permanent => false,
            QueryOrigin::Packet { execution, .. } => execution != self.fact_scope,
            QueryOrigin::HostListener { .. } => true,
        }
    }
}

/// One scope's withdrawal identity and original applicable expiry in tokio time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FactStamp {
    scope: ScopeId,
    revision: u64,
    expires_at: Option<tokio::time::Instant>,
}

impl FactStamp {
    pub(crate) fn is_unexpired_at(self, now: tokio::time::Instant) -> bool {
        self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

#[derive(Default)]
pub(crate) struct PacketDomainBitmap {
    pub(crate) bitmap: Option<DomainRouting>,
    #[cfg(target_os = "linux")]
    fill: Option<(Arc<GatewayDnsBank>, GatewayDnsFill)>,
}

/// Synchronous fact mutation serialization; never held across an await.
pub(crate) struct PacketFacts<'a>(parking_lot::MutexGuard<'a, DesiredState>);

impl PacketFacts<'_> {
    pub(crate) fn lookup(
        &mut self,
        scope: ScopeId,
        ip: IpAddr,
        router: &Router,
        generation: u64,
    ) -> anyhow::Result<(Option<DomainRouting>, FactStamp)> {
        check_packet_authority(&self.0, router, generation)?;
        self.0.packet_fact(scope, ip, tokio::time::Instant::now())
    }

    pub(crate) fn is_current(&mut self, stamp: FactStamp) -> bool {
        self.0.fact_is_current(stamp, tokio::time::Instant::now())
    }
}

fn check_packet_authority(
    state: &DesiredState,
    router: &Router,
    generation: u64,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        state.snapshot.generation() == generation
            && state.snapshot.matcher.policy_fingerprint() == router.policy_fingerprint(),
        "packet DNS projection generation does not match routing authority"
    );
    Ok(())
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
        if snapshot.generation() < state.snapshot.generation() {
            return;
        }
        if let Some(published) = published {
            // A reload pre-fills the map outside the incremental worker. Record
            // that exact set, including owners that expired while it loaded.
            state.applied = published;
            state.dirty_ips.clear();
            state.retries.clear();
        }
        #[cfg(target_os = "linux")]
        let previous = state.close_gateway_dns();
        state.update_snapshot(&snapshot);
        drop(state);
        #[cfg(target_os = "linux")]
        drop(previous);
        self.projection.notify_worker();
    }
}

impl RoutingProjection {
    pub(crate) fn spawn<S: DomainProjectionSink + ?Sized + 'static>(
        ebpf: Arc<tokio::sync::RwLock<Box<S>>>,
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
        assert!(
            self.try_mutate(QueryScope::HOST, snapshot.generation(), |state| {
                state.update_snapshot(&snapshot);
                0
            })
        );
    }

    #[cfg(test)]
    pub(crate) fn submit(
        &self,
        scope: ScopeId,
        snapshot: Arc<RoutingProjectionSnapshot>,
        observation: ProjectionObservation<'_>,
    ) {
        let query = if self.owns_packet_scope(scope) {
            self.packet_query_scope(scope)
                .expect("test DNS scope is offline")
        } else {
            QueryScope::permanent(scope)
        };
        assert!(
            self.try_submit(query, &snapshot, observation),
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

    pub(crate) fn register_packet_scopes(
        &self,
        scopes: impl ExactSizeIterator<Item = ScopeId> + Clone,
        budget: &Arc<honk_netstack::MemoryBudget>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            scopes.len() != 0
                && scopes.clone().enumerate().all(|(index, scope)| {
                    scope != ScopeId::HOST
                        && !scopes.clone().take(index).any(|other| other == scope)
                }),
            "packet DNS scopes must be distinct non-HOST scopes"
        );
        self.state.lock().register_packet_scopes(scopes, budget)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn register_aux_scopes(
        &self,
        scopes: &[ScopeId],
        budget: &Arc<honk_netstack::MemoryBudget>,
    ) -> std::io::Result<()> {
        self.state.lock().register_aux_scopes(scopes, budget)
    }

    /// Reserve the fact-only scopes before registering the endpoint's packet scopes.
    #[cfg(target_os = "linux")]
    pub(crate) fn register_host_scopes(
        &self,
        shared: ScopeId,
        standalone: ScopeId,
        ports: &[crate::control::netstack::PacketScope],
        budget: &Arc<honk_netstack::MemoryBudget>,
    ) -> std::io::Result<()> {
        self.state
            .lock()
            .register_host_scopes(shared, standalone, ports, budget)
    }

    /// Publish or withdraw one port's actual driver stamp under the projection lock.
    #[cfg(all(target_os = "linux", any(feature = "ebpf", test)))]
    pub(crate) fn set_host_binding(
        &self,
        scope: ScopeId,
        stamp: u64,
        active: bool,
    ) -> std::io::Result<()> {
        self.state.lock().set_host_binding(scope, stamp, active)?;
        self.publication_released.notify_waiters();
        self.notify_worker();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn set_aux_binding(&self, scope: ScopeId, active: bool) -> std::io::Result<()> {
        self.state.lock().set_aux_binding(scope, active)?;
        self.publication_released.notify_waiters();
        self.notify_worker();
        Ok(())
    }

    pub(crate) fn packet_query_scope(&self, scope: ScopeId) -> Option<QueryScope> {
        self.state.lock().packet_query_scope(scope)
    }

    pub(crate) fn query_scope_is_current(&self, query: QueryScope) -> bool {
        query.origin == QueryOrigin::Permanent || self.state.lock().query_scope_is_current(query)
    }

    pub(crate) fn listener_query_scopes(
        &self,
        standalone: ScopeId,
    ) -> (Option<QueryScope>, Option<QueryScope>) {
        if standalone == ScopeId::HOST {
            return (Some(QueryScope::HOST), None);
        }
        let state = self.state.lock();
        #[cfg(target_os = "linux")]
        let loopback = state.host_listener_query_scope(standalone);
        #[cfg(not(target_os = "linux"))]
        let loopback = None;
        (state.packet_query_scope(standalone), loopback)
    }

    // Each bound TCP frame has its own activity stamp even on a persistent socket.
    pub(crate) fn refresh_listener_query_scope(&self, query: QueryScope) -> QueryScope {
        #[cfg(target_os = "linux")]
        if query.is_host_listener() {
            return self.state.lock().host_listener_scope(query.fact_scope);
        }
        query
    }

    pub(crate) fn owns_packet_scope(&self, scope: ScopeId) -> bool {
        self.state.lock().owns_packet_scope(scope)
    }

    pub(crate) fn packet_facts(&self) -> PacketFacts<'_> {
        PacketFacts(self.state.lock())
    }

    pub(crate) fn try_packet_facts(&self) -> Option<PacketFacts<'_>> {
        self.state.try_lock().map(PacketFacts)
    }

    pub(crate) fn packet_domain_bitmap(
        &self,
        scope: ScopeId,
        ip: IpAddr,
        router: &Router,
        generation: u64,
    ) -> anyhow::Result<PacketDomainBitmap> {
        let mut state = self.state.lock();
        let query = state.packet_query_scope(scope);
        if query.is_none() && !state.owns_packet_scope(scope) {
            return Ok(PacketDomainBitmap::default());
        }
        check_packet_authority(&state, router, generation)?;
        let scope = query
            .map(|query| query.fact_scope)
            .or_else(|| state.packet_fact_destination(scope));
        let bitmap = if let Some(scope) = scope {
            state.try_bitmap(scope, ip)?
        } else {
            None
        };
        Ok(PacketDomainBitmap {
            bitmap,
            #[cfg(target_os = "linux")]
            fill: query.and_then(|query| state.gateway_packet_fill(query, ip, bitmap)),
        })
    }

    #[cfg(test)]
    pub(crate) fn packet_bitmap(
        &self,
        scope: ScopeId,
        ip: IpAddr,
        router: &Router,
        generation: u64,
    ) -> anyhow::Result<Option<DomainRouting>> {
        let mut state = self.state.lock();
        check_packet_authority(&state, router, generation)?;
        state.try_bitmap(scope, ip)
    }

    /// Defers HOST writes behind publication; packet observations also defer
    /// until their exact snapshot is committed, without taking the HOST fence.
    pub(crate) fn try_submit(
        &self,
        query: QueryScope,
        snapshot: &Arc<RoutingProjectionSnapshot>,
        observation: ProjectionObservation<'_>,
    ) -> bool {
        self.submit_observation(query, snapshot, observation, false)
    }

    fn submit_observation(
        &self,
        query: QueryScope,
        snapshot: &Arc<RoutingProjectionSnapshot>,
        observation: ProjectionObservation<'_>,
        cache_hit: bool,
    ) -> bool {
        #[cfg(target_os = "linux")]
        let mut export = None;
        let scope = query.fact_scope;
        let submitted = self.try_mutate(query, snapshot.generation(), |state| {
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
            let now = tokio::time::Instant::now();
            // A delayed waiter may outlive both its template and the flight that replaced it.
            if matches!(observation, ProjectionObservation::Positive { source: ProjectionSource::SharedFlight, expires_at, .. } if expires_at <= now) {
                return state.observe(scope, ProjectionObservation::Retain, now);
            }
            // A same-set positive changes expiry without a structure bump;
            // drop the hint so it cannot coalesce against the old expiry.
            if let ProjectionObservation::Positive { domain, family, .. } = observation {
                self.hints[family as usize].remove(domain);
            }
            let evictions = if cache_hit {
                state.observe_cache_hit(scope, observation, now)
            } else {
                state.observe(scope, observation, now)
            };
            #[cfg(target_os = "linux")]
            if let ProjectionObservation::Positive { domain, family, .. } = observation {
                export = state.gateway_answer_fills(query, domain, family, now);
            }
            evictions
        });
        #[cfg(target_os = "linux")]
        if let Some((bank, rows)) = export {
            for row in rows.into_iter().flatten() {
                self.write_gateway_dns(&bank, row);
            }
        }
        submitted
    }

    /// Submits a DNS-cache observation. Only HOST refreshes may coalesce within
    /// `CACHE_HIT_COALESCE`; packet-scope shortening must revoke old permissions.
    /// Returns `false` until the matching publication can accept the observation.
    pub(crate) fn try_submit_cache_hit(
        &self,
        query: QueryScope,
        snapshot: &Arc<RoutingProjectionSnapshot>,
        observation: ProjectionObservation<'_>,
    ) -> bool {
        let scope = query.fact_scope;
        if scope != ScopeId::HOST {
            return self.submit_observation(query, snapshot, observation, true);
        }
        let ProjectionObservation::Positive {
            domain,
            family,
            ips,
            expires_at,
            ..
        } = observation
        else {
            return self.try_submit(query, snapshot, observation);
        };
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
                && hint.ips.len() == ips.len()
                && state::same_address_set(hint.ips.iter(), ips)
        });
        if coalesced {
            return true;
        }
        self.try_mutate(query, snapshot.generation(), |state| {
            if !state.update_snapshot(snapshot) {
                crate::stats::record_dns_event(
                    crate::stats::DnsStatEvent::ProjectionStaleGeneration,
                );
                return 0;
            }
            let applied_at = tokio::time::Instant::now();
            let evicted = state.observe(scope, observation, applied_at);
            let structure = state.structure.load(Ordering::Acquire);
            if self.hints_epoch.swap(structure, Ordering::Relaxed) != structure {
                for family_hints in &self.hints {
                    family_hints.clear();
                }
            }
            if let Some((key, ips, expires_at)) =
                state.cache_hit_hint(scope, family as usize, domain)
            {
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
        #[cfg(target_os = "linux")]
        self.close_gateway_dns();
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

    /// HOST mutations share the worker's publication fence. Packet mutations
    /// use the committed snapshot under the state lock and cannot advance it.
    fn try_mutate(
        &self,
        query: QueryScope,
        generation: u64,
        operation: impl FnOnce(&mut DesiredState) -> u64,
    ) -> bool {
        if query.fact_scope != ScopeId::HOST {
            let mut state = self.state.lock();
            if !state.query_scope_is_current(query) {
                return true;
            }
            if generation > state.snapshot.generation() {
                return false;
            }
            let counter_delta = operation(&mut state);
            drop(state);
            self.counters
                .evictions
                .fetch_add(counter_delta, Ordering::Relaxed);
            self.notify_worker();
            return true;
        }
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
            let mut state = self.state.lock();
            #[cfg(target_os = "linux")]
            let retired = if generation > state.snapshot.generation() {
                state.close_gateway_dns()
            } else {
                None
            };
            let delta = operation(&mut state);
            drop(state);
            #[cfg(target_os = "linux")]
            drop(retired);
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
            ScopeId::HOST,
            ProjectionObservation::Positive {
                domain,
                family: state::family_of(self.ip),
                ips: std::slice::from_ref(&self.ip),
                expires_at: self.now + Duration::from_secs(300),
                source: ProjectionSource::Fresh,
            },
            self.now,
        );
        self.state.sequence
    }
}

impl Drop for RoutingProjection {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        self.state.get_mut().close_gateway_dns();
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
