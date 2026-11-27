use std::future::Future;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use honk_outbound::SharedError;
use parking_lot::Mutex;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::dns::endpoint::ResolvedEndpointAddrs;

const MIN_BOOTSTRAP_TTL: Duration = Duration::from_secs(30);
const MAX_BOOTSTRAP_TTL: Duration = Duration::from_secs(300);
const DEFAULT_BOOTSTRAP_TTL: Duration = Duration::from_secs(60);
const STALE_RETENTION: Duration = Duration::from_secs(600);
const STALE_RETRY_COOLDOWN: Duration = Duration::from_secs(5);
const FORCED_INVALIDATE_COOLDOWN: Duration = Duration::from_secs(5);

/// Resolved upstream candidates with zero heap allocation on static literals and
/// cached domain hits.
#[derive(Clone)]
pub(super) enum ResolvedAddrs {
    Single(SocketAddr),
    Shared(Arc<[SocketAddr]>),
}

impl Deref for ResolvedAddrs {
    type Target = [SocketAddr];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Single(addr) => std::slice::from_ref(addr),
            Self::Shared(addrs) => addrs,
        }
    }
}

#[derive(Clone)]
pub(super) struct ResolvedCandidates {
    pub(super) addresses: ResolvedAddrs,
    pub(super) cache_generation: Option<u64>,
    pub(super) invalidation_epoch: u64,
}

#[derive(Clone)]
enum FlightOutcome {
    Resolved(ResolvedCandidates),
    Failed(SharedError),
    Cancelled,
}

type FlightSender = Arc<watch::Sender<Option<FlightOutcome>>>;

struct CachedAddrs {
    addresses: Arc<[SocketAddr]>,
    refresh_after: Instant,
    stale_until: Instant,
    generation: u64,
    retry_after: Option<Instant>,
}

#[derive(Default)]
struct CacheState {
    cached: Option<CachedAddrs>,
    preferred: [Option<SocketAddr>; 2],
    last_forced_invalidate: Option<Instant>,
    in_flight: Option<FlightSender>,
    invalidation_epoch: u64,
}

impl CacheState {
    fn try_hit(&self, now: Instant) -> Option<ResolvedCandidates> {
        let cached = self.cached.as_ref()?;
        let fresh = now < cached.refresh_after;
        let cooldown_stale =
            cached.retry_after.is_some_and(|retry| now < retry) && now < cached.stale_until;
        (fresh || cooldown_stale).then(|| ResolvedCandidates {
            addresses: ResolvedAddrs::Shared(Arc::clone(&cached.addresses)),
            cache_generation: Some(cached.generation),
            invalidation_epoch: self.invalidation_epoch,
        })
    }
}

/// Endpoint resolution returns strictly partitioned `[primary..., secondary...]`
/// addresses, so affinity promotion operates within each family slice in place
/// without repeating `DnsStrategy` matching.
fn promote_preferred(addresses: &mut [SocketAddr], preferred: [Option<SocketAddr>; 2]) {
    let Some(first) = addresses.first() else {
        return;
    };
    let first_is_v6 = first.is_ipv6();
    let split = addresses.partition_point(|addr| addr.is_ipv6() == first_is_v6);
    promote_in_slice(&mut addresses[..split], preferred[usize::from(first_is_v6)]);
    promote_in_slice(
        &mut addresses[split..],
        preferred[usize::from(!first_is_v6)],
    );
}

fn promote_in_slice(slice: &mut [SocketAddr], preferred: Option<SocketAddr>) {
    if let Some(target) = preferred
        && let Some(pos) = slice.iter().position(|addr| *addr == target)
        && pos > 0
    {
        slice[..=pos].rotate_right(1);
    }
}

enum FlightAction {
    Lead {
        flight: FlightSender,
        invalidation_epoch: u64,
    },
    Wait(watch::Receiver<Option<FlightOutcome>>),
}

struct ResolveGuard<'a> {
    cache: &'a UpstreamAddrCache,
    flight: Option<FlightSender>,
    invalidation_epoch: u64,
}

impl<'a> ResolveGuard<'a> {
    fn new(cache: &'a UpstreamAddrCache, flight: FlightSender, invalidation_epoch: u64) -> Self {
        Self {
            cache,
            flight: Some(flight),
            invalidation_epoch,
        }
    }

    fn clear_in_flight(state: &mut CacheState, flight: &FlightSender) {
        if state
            .in_flight
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, flight))
        {
            state.in_flight = None;
        }
    }

    fn publish(
        mut self,
        mut addresses: Vec<SocketAddr>,
        min_ttl: Option<u32>,
        now: Instant,
    ) -> ResolvedCandidates {
        let flight = self
            .flight
            .take()
            .expect("resolve guard finished more than once");
        let ttl = min_ttl.map_or(DEFAULT_BOOTSTRAP_TTL, |secs| {
            Duration::from_secs(u64::from(secs)).clamp(MIN_BOOTSTRAP_TTL, MAX_BOOTSTRAP_TTL)
        });
        let (shared, generation) = {
            let mut state = self.cache.state.lock();
            promote_preferred(&mut addresses, state.preferred);
            let shared: Arc<[SocketAddr]> = Arc::from(addresses);
            let generation = state
                .cached
                .as_ref()
                .map_or(0, |cached| cached.generation)
                .wrapping_add(1);
            let refresh_after = if state.invalidation_epoch == self.invalidation_epoch {
                now + ttl
            } else {
                now
            };
            let stale_until = refresh_after + STALE_RETENTION;
            state.cached = Some(CachedAddrs {
                addresses: Arc::clone(&shared),
                refresh_after,
                stale_until,
                generation,
                retry_after: None,
            });
            Self::clear_in_flight(&mut state, &flight);
            (shared, generation)
        };
        let candidates = ResolvedCandidates {
            addresses: ResolvedAddrs::Shared(shared),
            cache_generation: Some(generation),
            invalidation_epoch: self.invalidation_epoch,
        };
        flight.send_replace(Some(FlightOutcome::Resolved(candidates.clone())));
        candidates
    }

    fn fail(
        mut self,
        upstream: &str,
        error: anyhow::Error,
        now: Instant,
    ) -> anyhow::Result<ResolvedCandidates> {
        let flight = self
            .flight
            .take()
            .expect("resolve guard finished more than once");
        let is_rejection = honk_outbound::proxy::is_packet_rejection(&error);
        let outcome = {
            let mut state = self.cache.state.lock();
            Self::clear_in_flight(&mut state, &flight);
            let current_epoch = state.invalidation_epoch;
            if !is_rejection
                && let Some(cached) = state.cached.as_mut()
                && now < cached.stale_until
            {
                if current_epoch == self.invalidation_epoch {
                    cached.retry_after = Some(now + STALE_RETRY_COOLDOWN);
                }
                let candidates = ResolvedCandidates {
                    addresses: ResolvedAddrs::Shared(Arc::clone(&cached.addresses)),
                    cache_generation: Some(cached.generation),
                    invalidation_epoch: self.invalidation_epoch,
                };
                Ok((candidates, error))
            } else {
                Err(SharedError::fanout(error))
            }
        };
        match &outcome {
            Ok((candidates, _)) => {
                flight.send_replace(Some(FlightOutcome::Resolved(candidates.clone())));
            }
            Err(shared) => {
                flight.send_replace(Some(FlightOutcome::Failed(shared.clone())));
            }
        }
        match outcome {
            Ok((candidates, error)) => {
                crate::logging::warn_throttled!(
                    upstream,
                    error = %error,
                    "DNS upstream bootstrap refresh failed; serving stale cached addresses"
                );
                Ok(candidates)
            }
            Err(shared) => Err(anyhow::Error::new(shared)),
        }
    }
}

impl Drop for ResolveGuard<'_> {
    fn drop(&mut self) {
        let Some(flight) = self.flight.take() else {
            return;
        };
        {
            let mut state = self.cache.state.lock();
            Self::clear_in_flight(&mut state, &flight);
        }
        flight.send_replace(Some(FlightOutcome::Cancelled));
    }
}

/// Per-generation domain-upstream address cache with pure inline singleflight.
#[derive(Default)]
pub(super) struct UpstreamAddrCache {
    state: Mutex<CacheState>,
}

impl UpstreamAddrCache {
    pub(super) fn try_hit(&self, now: Instant) -> Option<ResolvedCandidates> {
        self.state.lock().try_hit(now)
    }

    pub(super) fn record_preferred(&self, address: SocketAddr) {
        let mut state = self.state.lock();
        let slot = &mut state.preferred[usize::from(address.is_ipv6())];
        if *slot == Some(address) {
            return;
        }
        *slot = Some(address);
        let preferred = state.preferred;
        if let Some(cached) = state.cached.as_mut() {
            let mut reordered = cached.addresses.to_vec();
            promote_preferred(&mut reordered, preferred);
            cached.addresses = Arc::from(reordered);
        }
    }

    pub(super) fn mark_dirty_on_all_failed(&self, observed_generation: Option<u64>, now: Instant) {
        let Some(observed_generation) = observed_generation else {
            return;
        };
        let mut state = self.state.lock();
        if state
            .last_forced_invalidate
            .is_some_and(|last| now.saturating_duration_since(last) < FORCED_INVALIDATE_COOLDOWN)
        {
            return;
        }
        let Some(cached) = state.cached.as_mut() else {
            return;
        };
        if cached.generation != observed_generation {
            return;
        }
        cached.refresh_after = now;
        cached.retry_after = None;
        state.last_forced_invalidate = Some(now);
    }

    pub(super) fn invalidate(&self, now: Instant) -> u64 {
        let mut state = self.state.lock();
        state.invalidation_epoch = state.invalidation_epoch.wrapping_add(1);
        state.last_forced_invalidate = None;
        if let Some(cached) = state.cached.as_mut() {
            cached.refresh_after = now;
            cached.retry_after = None;
        }
        state.invalidation_epoch
    }

    pub(super) async fn resolve_or_wait<F, Fut, W>(
        &self,
        upstream: &str,
        host: &str,
        deadline: Instant,
        is_open: impl Fn() -> bool,
        mut resolve: F,
    ) -> (anyhow::Result<ResolvedCandidates>, Option<W>)
    where
        F: FnMut(Instant) -> Fut,
        Fut: Future<Output = (anyhow::Result<ResolvedEndpointAddrs>, Option<W>)>,
    {
        loop {
            let action = {
                let now = Instant::now();
                let mut state = self.state.lock();
                if !is_open() {
                    return (Err(super::pool_closed_error().into()), None);
                }
                if let Some(hit) = state.try_hit(now) {
                    return (Ok(hit), None);
                }
                if let Some(flight) = state.in_flight.as_ref() {
                    FlightAction::Wait(flight.subscribe())
                } else {
                    if now >= deadline {
                        return (
                            Err(anyhow::anyhow!("bootstrap resolve '{host}' timed out")),
                            None,
                        );
                    }
                    let (tx, _rx) = watch::channel(None);
                    let flight = Arc::new(tx);
                    state.in_flight = Some(Arc::clone(&flight));
                    FlightAction::Lead {
                        flight,
                        invalidation_epoch: state.invalidation_epoch,
                    }
                }
            };

            match action {
                FlightAction::Lead {
                    flight,
                    invalidation_epoch,
                } => {
                    // Declare guard before awaiting `resolve` so cancellation drops
                    // the bootstrap future (and its socket credits) before
                    // ResolveGuard wakes surviving waiters.
                    let guard = ResolveGuard::new(self, flight, invalidation_epoch);
                    let (result, witness) = resolve(deadline).await;
                    let now = Instant::now();
                    return match result {
                        Ok(resolved) => (
                            Ok(guard.publish(resolved.addresses, resolved.min_ttl, now)),
                            witness,
                        ),
                        Err(error) => (guard.fail(upstream, error, now), None),
                    };
                }
                FlightAction::Wait(mut rx) => {
                    let outcome = match tokio::time::timeout_at(
                        deadline,
                        rx.wait_for(|outcome| outcome.is_some()),
                    )
                    .await
                    {
                        Ok(Ok(outcome)) => outcome
                            .as_ref()
                            .expect("wait_for matched Some outcome")
                            .clone(),
                        Ok(Err(_)) => FlightOutcome::Cancelled,
                        Err(_) => {
                            return (
                                Err(anyhow::anyhow!(
                                    "bootstrap resolve '{host}' timed out waiting for in-flight lookup"
                                )),
                                None,
                            );
                        }
                    };
                    match outcome {
                        FlightOutcome::Resolved(candidates) => return (Ok(candidates), None),
                        FlightOutcome::Failed(shared) => {
                            return (Err(anyhow::Error::new(shared)), None);
                        }
                        FlightOutcome::Cancelled => continue,
                    }
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn is_in_flight(&self) -> bool {
        self.state.lock().in_flight.is_some()
    }

    #[cfg(test)]
    pub(super) fn cache_timestamps(
        &self,
    ) -> Option<(Instant, Instant, Option<Instant>, Option<Instant>)> {
        let state = self.state.lock();
        let cached = state.cached.as_ref()?;
        Some((
            cached.refresh_after,
            cached.stale_until,
            cached.retry_after,
            state.last_forced_invalidate,
        ))
    }

    #[cfg(test)]
    pub(super) fn expire_for_test(&self, now: Instant, retry_after: Option<Instant>) {
        let mut state = self.state.lock();
        if let Some(cached) = state.cached.as_mut() {
            cached.refresh_after = now;
            cached.retry_after = retry_after;
        }
    }
}
