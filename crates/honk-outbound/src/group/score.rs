mod selection;
#[cfg(test)]
mod tests;

use super::{
    Candidate, GroupManager, IpVersion, MAX_GROUP_DEPTH, ProbeDomain, ScoreSelectionEntry,
    ScoreSelectionPlan, SelectionEffects, SelectionNetwork, SelectionPlanMode,
    removed_unique_candidate_count, unique_candidate_ids,
};
use honk_config::node::Node;
use lru::LruCache;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

const EXACT_CAPACITY: usize = 4096;
const AGGREGATE_CAPACITY: usize = 4096;
const RELIABILITY_CLOSE: f64 = 0.05;
const RELIABILITY_CONFIDENCE_Z: f64 = 1.64;
const SCORE_EVIDENCE_HALF_LIFE: Duration = Duration::from_secs(30 * 60);
const MIN_TRAINED_EVIDENCE: f64 = 0.5;
const SCORE_SWITCH_MARGIN: f64 = 0.01;
const SCORE_SWITCH_FULL_EVIDENCE: f64 = 8.0;
const SCORE_SWITCH_FLAP_WINDOW: u64 = 8;
const SELECTION_HISTORY_CAPACITY: usize = 4096;
const SCORE_FAILURE_FORGIVENESS_THRESHOLD: f64 = 0.01;
const SCORE_EXPLORATION_MIN_PERIOD: u64 = 16;
const SCORE_EXPLORATION_MAX_PERIOD: u64 = 64;
const SCORE_EXPLORE_BACKOFF_BASE: Duration = Duration::from_secs(5 * 60);
const SCORE_EXPLORE_BACKOFF_MAX: Duration = Duration::from_secs(6 * 3600);
/// Consecutive fresh failures that drop a leaf out of the reliability band
/// while any healthier candidate exists. Decayed history must not shield a
/// leaf that is failing right now.
const SCORE_FAIL_STREAK_EXCLUDE: u32 = 3;
const MIN_THROUGHPUT_DURATION: Duration = Duration::from_secs(1);
const MIN_THROUGHPUT_BYTES: u64 = 64 * 1024;

/// Exploration retry delay for a consecutive-failure streak, tracked outside
/// the decaying evidence so a dead leaf is not rediscovered as cold.
fn explore_backoff(streak: u32) -> Duration {
    SCORE_EXPLORE_BACKOFF_BASE
        .saturating_mul(2u32.saturating_pow(streak.saturating_sub(1).min(7)))
        .min(SCORE_EXPLORE_BACKOFF_MAX)
}

fn exploration_target(candidate_count: usize) -> usize {
    if candidate_count <= 4 {
        candidate_count
    } else {
        (((candidate_count as f64).sqrt().ceil() as usize) + 1).min(candidate_count)
    }
}

fn exploration_period(candidate_count: usize) -> u64 {
    (candidate_count as u64)
        .saturating_mul(2)
        .clamp(SCORE_EXPLORATION_MIN_PERIOD, SCORE_EXPLORATION_MAX_PERIOD)
}

fn exploration_attempts(score: &ScoreSnapshot) -> f64 {
    if score.targeted {
        score.target_attempts
    } else {
        score.attempts
    }
}

fn exploration_completed(score: &ScoreSnapshot) -> f64 {
    if score.targeted {
        score.target_completed
    } else {
        score.completed
    }
}

/// A normalized business target used only as an in-memory score key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScoreTarget {
    Domain { host: String, port: u16 },
    Socket(SocketAddr),
}

impl ScoreTarget {
    pub fn domain(host: &str, port: u16) -> Self {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        Self::Domain { host, port }
    }
}

impl From<SocketAddr> for ScoreTarget {
    fn from(value: SocketAddr) -> Self {
        Self::Socket(value)
    }
}

/// Business-target scoring dimensions plus the independent proxy-health
/// dimensions used to form the alive candidate set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreSelectionContext {
    pub network: SelectionNetwork,
    pub probe_domain: ProbeDomain,
    pub target_family: Option<IpVersion>,
    pub health_family: IpVersion,
    pub target: Option<ScoreTarget>,
}

impl ScoreSelectionContext {
    /// Context for traffic without a trustworthy business target (warm-up
    /// and preconnect). Feedback updates aggregate state only.
    pub fn aggregate(
        network: SelectionNetwork,
        probe_domain: ProbeDomain,
        health_family: IpVersion,
    ) -> Self {
        Self {
            network,
            probe_domain,
            target_family: None,
            health_family,
            target: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreAttribution {
    pub group: String,
    pub node_id: Uuid,
}

/// Compact terminal result; formatted error strings never enter score state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreOutcome {
    Success,
    Timeout,
    Io(io::ErrorKind),
    Cancelled,
    Shutdown,
    Other,
}

impl ScoreOutcome {
    pub fn from_error(error: &anyhow::Error) -> Self {
        error
            .chain()
            .find_map(|source| source.downcast_ref::<io::Error>())
            .map_or(Self::Other, |error| {
                if error.kind() == io::ErrorKind::TimedOut {
                    Self::Timeout
                } else {
                    Self::Io(error.kind())
                }
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExactKey {
    group: String,
    network: SelectionNetwork,
    family: IpVersion,
    target: ScoreTarget,
    node_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AggregateKey {
    group: String,
    network: SelectionNetwork,
    family: Option<IpVersion>,
    node_id: Uuid,
}

#[derive(Debug, Clone, Default)]
struct WeightedMean {
    sum: f64,
    weight: f64,
}

impl WeightedMean {
    fn decay(&mut self, factor: f64) {
        self.sum *= factor;
        self.weight *= factor;
    }

    fn record(&mut self, sample: f64) {
        self.sum += sample;
        self.weight += 1.0;
    }

    fn mean(&self) -> Option<f64> {
        (self.weight > 0.0).then(|| self.sum / self.weight)
    }
}

#[derive(Debug, Clone, Default)]
struct Stats {
    incarnation: u64,
    attempts: f64,
    setup_success: f64,
    setup_failure: f64,
    useful_success: f64,
    useful_failure: f64,
    setup_ms: WeightedMean,
    first_response_ms: WeightedMean,
    throughput_bytes: f64,
    throughput_seconds: f64,
    throughput_windows: f64,
    fail_streak: u32,
    explore_not_before: Option<Instant>,
    last_used: u64,
    updated_at: Option<Instant>,
    selected_at: u64,
}

impl Stats {
    fn completed(&self) -> f64 {
        self.setup_success + self.setup_failure
    }

    fn useful_completed(&self) -> f64 {
        self.useful_success + self.useful_failure
    }

    fn reliability_bounds(&self, factor: f64) -> (f64, f64) {
        // Setup failure is already a useful failure. Counting two additional
        // failures makes it the strongest negative signal without a knob.
        let successes = self.useful_success * factor;
        let failures = (self.useful_failure + self.setup_failure * 2.0) * factor;
        let a = successes + 1.0;
        let b = failures + 1.0;
        let sum = a + b;
        let mean = a / sum;
        let deviation = (a * b / (sum * sum * (sum + 1.0))).sqrt();
        (
            (mean - RELIABILITY_CONFIDENCE_Z * deviation).clamp(0.0, 1.0),
            (mean + RELIABILITY_CONFIDENCE_Z * deviation).clamp(0.0, 1.0),
        )
    }

    fn decay_to(&mut self, now: Instant) {
        let Some(updated_at) = self.updated_at.replace(now) else {
            return;
        };
        let factor = evidence_decay(now.saturating_duration_since(updated_at));
        self.attempts *= factor;
        self.setup_success *= factor;
        self.setup_failure *= factor;
        self.useful_success *= factor;
        self.useful_failure *= factor;
        self.setup_ms.decay(factor);
        self.first_response_ms.decay(factor);
        self.throughput_bytes *= factor;
        self.throughput_seconds *= factor;
        self.throughput_windows *= factor;
    }

    fn record_start(&mut self, now: Instant, tick: u64) {
        self.decay_to(now);
        self.attempts += 1.0;
        self.last_used = tick;
    }

    fn record_finish(
        &mut self,
        now: Instant,
        sample: &FlowSample,
        count_usefulness: bool,
        tick: u64,
    ) {
        self.decay_to(now);
        if matches!(
            sample.outcome,
            ScoreOutcome::Cancelled | ScoreOutcome::Shutdown
        ) {
            self.attempts = (self.attempts - evidence_decay(sample.elapsed)).max(0.0);
            self.last_used = tick;
            return;
        }
        if !sample.streak_neutral {
            if sample.outcome == ScoreOutcome::Success {
                // Liveness is proven, but the streak steps down one at a
                // time: a flapping leaf earns the fast cadence back.
                self.fail_streak = self.fail_streak.saturating_sub(1);
                self.explore_not_before = None;
            } else {
                self.fail_streak = self.fail_streak.saturating_add(1);
                self.explore_not_before = Some(now + explore_backoff(self.fail_streak));
            }
        }
        if let Some(setup) = sample.setup {
            self.setup_success += 1.0;
            self.setup_ms.record(setup.as_secs_f64() * 1000.0);
        } else {
            self.setup_failure += 1.0;
        }
        if let Some(first_response) = sample.first_response {
            self.first_response_ms
                .record(first_response.as_secs_f64() * 1000.0);
        }
        if count_usefulness {
            let useful = sample.outcome == ScoreOutcome::Success && sample.tx > 0 && sample.rx > 0;
            if useful {
                self.useful_success += 1.0;
                if sample.elapsed >= MIN_THROUGHPUT_DURATION
                    && sample.tx.max(sample.rx) >= MIN_THROUGHPUT_BYTES
                {
                    self.throughput_bytes += sample.tx.max(sample.rx) as f64;
                    self.throughput_seconds += sample.elapsed.as_secs_f64();
                    self.throughput_windows += 1.0;
                }
            } else {
                self.useful_failure += 1.0;
            }
        }
        self.last_used = tick;
    }
}

fn evidence_decay(elapsed: Duration) -> f64 {
    (-elapsed.as_secs_f64() / SCORE_EVIDENCE_HALF_LIFE.as_secs_f64()).exp2()
}

fn record_cell_start<K>(
    cache: &mut LruCache<K, Stats>,
    key: K,
    now: Instant,
    tick: u64,
    evictions: &mut u64,
) -> u64
where
    K: std::hash::Hash + Eq,
{
    if let Some(stats) = cache.get_mut(&key) {
        stats.record_start(now, tick);
        return stats.incarnation;
    }
    let mut stats = Stats {
        incarnation: tick,
        ..Default::default()
    };
    stats.record_start(now, tick);
    // A full cache means this put evicts the LRU tail.
    if cache.len() == cache.cap().get() {
        *evictions = evictions.saturating_add(1);
    }
    cache.put(key, stats);
    tick
}

fn record_cell_finish<K>(
    cache: &mut LruCache<K, Stats>,
    key: &K,
    incarnation: Option<u64>,
    now: Instant,
    sample: &FlowSample,
    count_usefulness: bool,
    tick: u64,
) where
    K: std::hash::Hash + Eq,
{
    let Some(incarnation) = incarnation else {
        return;
    };
    let remove_empty = match cache.get_mut(key) {
        Some(stats) if stats.incarnation == incarnation => {
            stats.record_finish(now, sample, count_usefulness, tick);
            stats.attempts == 0.0 && stats.completed() == 0.0
        }
        _ => false,
    };
    if remove_empty {
        cache.pop(key);
    }
}

#[derive(Clone, Copy, Default)]
struct StartedCells {
    aggregate: [Option<u64>; 2],
    exact: Option<u64>,
}

#[derive(Debug)]
pub(super) struct ScoreAuthority;

#[derive(Clone, PartialEq, Eq, Hash)]
struct SelectionCadenceKey {
    group: String,
    network: SelectionNetwork,
    family: Option<IpVersion>,
}

impl SelectionCadenceKey {
    fn new(group: &str, context: &ScoreSelectionContext) -> Self {
        Self {
            group: group.to_owned(),
            network: context.network,
            family: context.target_family,
        }
    }
}

/// Flap history is scoped to the same target the pick was ranked for:
/// unrelated targets interleaving their own winners is not a flap. The
/// exploration cadence keeps the coarser [`SelectionCadenceKey`].
#[derive(Clone, PartialEq, Eq, Hash)]
struct SelectionHistoryKey {
    group: String,
    network: SelectionNetwork,
    family: Option<IpVersion>,
    target: Option<ScoreTarget>,
}

impl SelectionHistoryKey {
    fn new(group: &str, context: &ScoreSelectionContext) -> Self {
        Self {
            group: group.to_owned(),
            network: context.network,
            family: context.target_family,
            target: context.target.clone(),
        }
    }
}

#[derive(Clone, Copy)]
struct SelectionHistory {
    current: Uuid,
    previous: Option<Uuid>,
    /// Committed non-exploration selections seen by this target scope.
    selections: u64,
    switched_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectionReason {
    ColdExplore,
    PeriodicExplore,
    ReliabilityWinner,
    PerformanceWinner,
    IncumbentHeld,
    FreshFailureBypass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HoldDecision {
    Held,
    FreshFailureBypass,
    UseBest,
}

impl SelectionReason {
    fn is_exploration(self) -> bool {
        matches!(self, Self::ColdExplore | Self::PeriodicExplore)
    }
}

#[derive(Clone, Copy)]
struct RankedSelection {
    index: usize,
    reason: SelectionReason,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct SelectionReasonKey {
    group: String,
    network: SelectionNetwork,
}

impl SelectionReasonKey {
    pub(super) fn new(group: &str, network: SelectionNetwork) -> Self {
        Self {
            group: group.to_owned(),
            network,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SelectionReasonCounts {
    cold_explore: u64,
    periodic_explore: u64,
    reliability_winner: u64,
    performance_winner: u64,
    incumbent_held: u64,
    fresh_failure_bypass: u64,
    dead_filtered: u64,
    switch_flap: u64,
    fail_streak_excluded: u64,
    explore_backed_off: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScoreReasonCounters {
    pub cold_explore: u64,
    pub periodic_explore: u64,
    pub reliability_winner: u64,
    pub performance_winner: u64,
    pub incumbent_held: u64,
    pub fresh_failure_bypass: u64,
    pub dead_filtered: u64,
    pub switch_flap: u64,
    pub fail_streak_excluded: u64,
    pub explore_backed_off: u64,
}

impl ScoreReasonCounters {
    const fn from_private(counts: SelectionReasonCounts) -> Self {
        Self {
            cold_explore: counts.cold_explore,
            periodic_explore: counts.periodic_explore,
            reliability_winner: counts.reliability_winner,
            performance_winner: counts.performance_winner,
            incumbent_held: counts.incumbent_held,
            fresh_failure_bypass: counts.fresh_failure_bypass,
            dead_filtered: counts.dead_filtered,
            switch_flap: counts.switch_flap,
            fail_streak_excluded: counts.fail_streak_excluded,
            explore_backed_off: counts.explore_backed_off,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScoreReasonGroupSnapshot {
    pub name: String,
    pub tcp: ScoreReasonCounters,
    pub udp: ScoreReasonCounters,
}

/// Occupancy and eviction totals of the two bounded evidence LRUs; carries no
/// group, node, or target identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScoreCacheSnapshot {
    pub exact_cells: usize,
    pub aggregate_cells: usize,
    pub exact_evictions: u64,
    pub aggregate_evictions: u64,
}

struct StateInner {
    exact: LruCache<ExactKey, Stats>,
    aggregate: LruCache<AggregateKey, Stats>,
    valid: HashSet<(String, Uuid)>,
    valid_groups: HashSet<String>,
    selection_counts: HashMap<SelectionCadenceKey, u64>,
    selection_history: LruCache<SelectionHistoryKey, SelectionHistory>,
    selection_reasons: HashMap<SelectionReasonKey, SelectionReasonCounts>,
    active_authority: Option<Arc<ScoreAuthority>>,
    tick: u64,
    exact_evictions: u64,
    aggregate_evictions: u64,
}

impl Default for StateInner {
    fn default() -> Self {
        Self {
            // SAFE-EXPECT: both cache capacities are positive compile-time constants.
            exact: LruCache::new(NonZeroUsize::new(EXACT_CAPACITY).expect("non-zero capacity")),
            aggregate: LruCache::new(
                // SAFE-EXPECT: both cache capacities are positive compile-time constants.
                NonZeroUsize::new(AGGREGATE_CAPACITY).expect("non-zero capacity"),
            ),
            valid: HashSet::new(),
            valid_groups: HashSet::new(),
            selection_counts: HashMap::new(),
            selection_history: LruCache::new(
                // SAFE-EXPECT: the capacity is a positive compile-time constant.
                NonZeroUsize::new(SELECTION_HISTORY_CAPACITY).expect("non-zero capacity"),
            ),
            selection_reasons: HashMap::new(),
            active_authority: None,
            tick: 0,
            exact_evictions: 0,
            aggregate_evictions: 0,
        }
    }
}

/// Process-memory-only score state shared by old and replacement managers.
#[derive(Default)]
pub struct ScorePolicyState {
    inner: Mutex<StateInner>,
}

impl ScorePolicyState {
    pub(super) fn reason_snapshot(
        &self,
        group_names: Vec<String>,
    ) -> Vec<ScoreReasonGroupSnapshot> {
        let mut groups: Vec<_> = group_names
            .into_iter()
            .map(|name| ScoreReasonGroupSnapshot {
                name,
                tcp: ScoreReasonCounters::default(),
                udp: ScoreReasonCounters::default(),
            })
            .collect();
        let inner = self.inner.lock();
        for (key, counts) in &inner.selection_reasons {
            let Ok(index) = groups.binary_search_by(|group| group.name.cmp(&key.group)) else {
                continue;
            };
            let destination = match key.network {
                SelectionNetwork::Tcp => &mut groups[index].tcp,
                SelectionNetwork::Udp => &mut groups[index].udp,
            };
            *destination = ScoreReasonCounters::from_private(*counts);
        }
        groups
    }

    pub(super) fn cache_snapshot(&self) -> ScoreCacheSnapshot {
        let inner = self.inner.lock();
        ScoreCacheSnapshot {
            exact_cells: inner.exact.len(),
            aggregate_cells: inner.aggregate.len(),
            exact_evictions: inner.exact_evictions,
            aggregate_evictions: inner.aggregate_evictions,
        }
    }

    /// Atomically publish committed Score group/leaf membership and prune
    /// removed cells. Construction with a reused state never calls this.
    pub(super) fn publish_generation<I, G>(
        &self,
        authority: Arc<ScoreAuthority>,
        groups: G,
        membership: I,
    ) where
        I: IntoIterator<Item = (String, Uuid)>,
        G: IntoIterator<Item = String>,
    {
        let mut inner = self.inner.lock();
        inner.active_authority = Some(authority);
        inner.valid = membership.into_iter().collect();
        inner.valid_groups = groups.into_iter().collect();
        let StateInner {
            selection_counts,
            selection_reasons,
            selection_history,
            valid,
            valid_groups,
            ..
        } = &mut *inner;
        selection_counts.retain(|key, _| valid_groups.contains(&key.group));
        selection_reasons.retain(|key, _| valid_groups.contains(&key.group));
        let invalid_history: Vec<_> = selection_history
            .iter()
            .filter(|(key, history)| {
                !valid_groups.contains(&key.group)
                    || !valid.contains(&(key.group.clone(), history.current))
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in invalid_history {
            selection_history.pop(&key);
        }
        let stale_previous: Vec<_> = selection_history
            .iter()
            .filter(|(key, history)| {
                history
                    .previous
                    .is_some_and(|node_id| !valid.contains(&(key.group.clone(), node_id)))
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in stale_previous {
            if let Some(history) = selection_history.get_mut(&key) {
                history.previous = None;
            }
        }
        let invalid_exact: Vec<_> = inner
            .exact
            .iter()
            .filter(|(key, _)| !inner.valid.contains(&(key.group.clone(), key.node_id)))
            .map(|(key, _)| key.clone())
            .collect();
        for key in invalid_exact {
            inner.exact.pop(&key);
        }
        let invalid_aggregate: Vec<_> = inner
            .aggregate
            .iter()
            .filter(|(key, _)| !inner.valid.contains(&(key.group.clone(), key.node_id)))
            .map(|(key, _)| key.clone())
            .collect();
        for key in invalid_aggregate {
            inner.aggregate.pop(&key);
        }
    }

    #[cfg(test)]
    fn publish_membership<I>(&self, membership: I)
    where
        I: IntoIterator<Item = (String, Uuid)>,
    {
        let membership: Vec<_> = membership.into_iter().collect();
        let groups = membership.iter().map(|(group, _)| group.clone());
        self.publish_generation(Arc::new(ScoreAuthority), groups, membership.clone());
    }

    pub(super) fn is_current_authority(&self, authority: &Arc<ScoreAuthority>) -> bool {
        self.inner
            .lock()
            .active_authority
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, authority))
    }

    fn record_selection_reason(
        inner: &mut StateInner,
        group: &str,
        network: SelectionNetwork,
        selection: RankedSelection,
    ) {
        let counts = inner
            .selection_reasons
            .entry(SelectionReasonKey::new(group, network))
            .or_default();
        let counter = match selection.reason {
            SelectionReason::ColdExplore => &mut counts.cold_explore,
            SelectionReason::PeriodicExplore => &mut counts.periodic_explore,
            SelectionReason::ReliabilityWinner => &mut counts.reliability_winner,
            SelectionReason::PerformanceWinner => &mut counts.performance_winner,
            SelectionReason::IncumbentHeld => &mut counts.incumbent_held,
            SelectionReason::FreshFailureBypass => &mut counts.fresh_failure_bypass,
        };
        *counter = counter.saturating_add(1);
    }

    fn record_switch_flap(
        inner: &mut StateInner,
        history_key: &SelectionHistoryKey,
        node_id: Uuid,
        reason: SelectionReason,
    ) {
        if reason.is_exploration() {
            return;
        }
        let Some(history) = inner.selection_history.get_mut(history_key) else {
            inner.selection_history.push(
                history_key.clone(),
                SelectionHistory {
                    current: node_id,
                    previous: None,
                    selections: 1,
                    switched_at: 0,
                },
            );
            return;
        };
        history.selections = history.selections.saturating_add(1);
        if history.current == node_id {
            return;
        }
        let switch_flap = history.previous == Some(node_id)
            && history.selections.saturating_sub(history.switched_at) <= SCORE_SWITCH_FLAP_WINDOW;
        history.previous = Some(history.current);
        history.current = node_id;
        history.switched_at = history.selections;
        if switch_flap {
            let counter = &mut inner
                .selection_reasons
                .entry(SelectionReasonKey::new(
                    &history_key.group,
                    history_key.network,
                ))
                .or_default()
                .switch_flap;
            *counter = counter.saturating_add(1);
        }
    }

    pub(super) fn record_dead_filtered(
        &self,
        authority: &Arc<ScoreAuthority>,
        key: SelectionReasonKey,
        removed: u64,
    ) {
        if removed == 0 {
            return;
        }
        let mut inner = self.inner.lock();
        let authorized = inner
            .active_authority
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, authority))
            && inner.valid_groups.contains(&key.group);
        if !authorized {
            return;
        }
        let counter = &mut inner
            .selection_reasons
            .entry(key)
            .or_default()
            .dead_filtered;
        *counter = counter.saturating_add(removed);
    }

    #[cfg(test)]
    fn selection_reason_counts(
        &self,
        group: &str,
        network: SelectionNetwork,
    ) -> SelectionReasonCounts {
        self.inner
            .lock()
            .selection_reasons
            .get(&SelectionReasonKey::new(group, network))
            .copied()
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn start(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
    ) -> Vec<StartedCells> {
        self.start_at(context, attributions, Instant::now())
    }

    #[cfg(test)]
    fn start_at(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        now: Instant,
    ) -> Vec<StartedCells> {
        let authority = self
            .inner
            .lock()
            .active_authority
            .clone()
            .unwrap_or_else(|| Arc::new(ScoreAuthority));
        self.start_at_with_authority(&authority, context, attributions, now)
    }

    fn start_at_with_authority(
        &self,
        authority: &Arc<ScoreAuthority>,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        now: Instant,
    ) -> Vec<StartedCells> {
        let mut inner = self.inner.lock();
        if !inner
            .active_authority
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, authority))
        {
            return vec![StartedCells::default(); attributions.len()];
        }
        inner.tick = inner.tick.saturating_add(1);
        let tick = inner.tick;
        let mut cells = Vec::with_capacity(attributions.len());
        for attribution in attributions {
            let mut started = StartedCells::default();
            if inner
                .valid
                .contains(&(attribution.group.clone(), attribution.node_id))
            {
                started.aggregate =
                    record_aggregate_start(&mut inner, attribution, context, now, tick);
                if let (Some(family), Some(target)) =
                    (context.target_family, context.target.as_ref())
                {
                    let key = ExactKey {
                        group: attribution.group.clone(),
                        network: context.network,
                        family,
                        target: target.clone(),
                        node_id: attribution.node_id,
                    };
                    let StateInner {
                        exact,
                        exact_evictions,
                        ..
                    } = &mut *inner;
                    started.exact = Some(record_cell_start(exact, key, now, tick, exact_evictions));
                }
            }
            cells.push(started);
        }
        cells
    }

    fn finish(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &[StartedCells],
        sample: &FlowSample,
    ) {
        self.finish_at(context, attributions, cells, sample, Instant::now());
    }

    fn finish_at(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &[StartedCells],
        sample: &FlowSample,
        now: Instant,
    ) {
        let mut inner = self.inner.lock();
        if !cells
            .iter()
            .any(|started| started.exact.is_some() || started.aggregate.iter().any(Option::is_some))
        {
            return;
        }
        inner.tick = inner.tick.saturating_add(1);
        let tick = inner.tick;
        for (index, attribution) in attributions.iter().enumerate() {
            if !inner
                .valid
                .contains(&(attribution.group.clone(), attribution.node_id))
            {
                continue;
            }
            let started = cells.get(index).copied().unwrap_or_default();
            record_aggregate_finish(
                &mut inner,
                attribution,
                context,
                started.aggregate,
                now,
                sample,
                tick,
            );
            if let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) {
                let key = ExactKey {
                    group: attribution.group.clone(),
                    network: context.network,
                    family,
                    target: target.clone(),
                    node_id: attribution.node_id,
                };
                record_cell_finish(
                    &mut inner.exact,
                    &key,
                    started.exact,
                    now,
                    sample,
                    sample.count_usefulness,
                    tick,
                );
            }
        }
    }

    pub(super) fn rank(
        &self,
        authority: &Arc<ScoreAuthority>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
    ) -> usize {
        self.rank_at_with_authority(authority, group, context, nodes, Instant::now())
    }

    pub(super) fn peek_rank(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
    ) -> usize {
        self.rank_inner(None, group, context, nodes, Instant::now(), false)
    }

    #[cfg(test)]
    fn rank_at(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
    ) -> usize {
        let authority = self
            .inner
            .lock()
            .active_authority
            .clone()
            .unwrap_or_else(|| Arc::new(ScoreAuthority));
        self.rank_at_with_authority(&authority, group, context, nodes, now)
    }

    fn rank_at_with_authority(
        &self,
        authority: &Arc<ScoreAuthority>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
    ) -> usize {
        self.rank_inner(Some(authority), group, context, nodes, now, true)
    }

    fn rank_inner(
        &self,
        authority: Option<&Arc<ScoreAuthority>>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
        apply: bool,
    ) -> usize {
        if nodes.len() < 2 {
            return 0;
        }
        let mut inner = self.inner.lock();
        let authorized = apply
            && authority.is_some_and(|authority| {
                inner
                    .active_authority
                    .as_ref()
                    .is_some_and(|active| Arc::ptr_eq(active, authority))
            })
            && inner.valid_groups.contains(group);
        let snapshots: Vec<_> = nodes
            .iter()
            .map(|node| score_snapshot(&inner, group, context, node.id, now))
            .collect();
        let performance = performance_baseline(&snapshots);
        let cadence_key = SelectionCadenceKey::new(group, context);
        let selection_count = if authorized {
            let count = inner
                .selection_counts
                .entry(cadence_key.clone())
                .or_default();
            *count = count.saturating_add(1);
            *count
        } else {
            let count = inner
                .selection_counts
                .get(&cadence_key)
                .copied()
                .unwrap_or(0);
            if apply {
                count.saturating_add(1)
            } else {
                count
            }
        };
        let best = best_index(&snapshots, nodes, selection_count, apply, performance);
        let incumbent = snapshots
            .iter()
            .enumerate()
            .filter(|(_, score)| score.selected_at != 0)
            .max_by(|(left_index, left), (right_index, right)| {
                left.selected_at
                    .cmp(&right.selected_at)
                    .then_with(|| left_index.cmp(right_index))
            })
            .map(|(index, _)| index);
        let selection = if best.reason.is_exploration() {
            best
        } else {
            match incumbent.filter(|&index| index != best.index) {
                Some(index) => {
                    match hold_decision(&snapshots[index], &snapshots[best.index], performance) {
                        HoldDecision::Held => RankedSelection {
                            index,
                            reason: SelectionReason::IncumbentHeld,
                        },
                        HoldDecision::FreshFailureBypass => RankedSelection {
                            index: best.index,
                            reason: SelectionReason::FreshFailureBypass,
                        },
                        HoldDecision::UseBest => best,
                    }
                }
                None => best,
            }
        };
        if authorized {
            let any_healthy = snapshots
                .iter()
                .any(|score| score.fail_streak < SCORE_FAIL_STREAK_EXCLUDE);
            let streak_excluded = snapshots
                .iter()
                .filter(|score| any_healthy && score.fail_streak >= SCORE_FAIL_STREAK_EXCLUDE)
                .count() as u64;
            let backed_off = snapshots
                .iter()
                .filter(|score| score.explore_backed_off)
                .count() as u64;
            if streak_excluded > 0 || backed_off > 0 {
                let counts = inner
                    .selection_reasons
                    .entry(SelectionReasonKey::new(group, context.network))
                    .or_default();
                counts.fail_streak_excluded =
                    counts.fail_streak_excluded.saturating_add(streak_excluded);
                counts.explore_backed_off = counts.explore_backed_off.saturating_add(backed_off);
            }
            Self::record_selection_reason(&mut inner, group, context.network, selection);
            Self::record_switch_flap(
                &mut inner,
                &SelectionHistoryKey::new(group, context),
                nodes[selection.index].id,
                selection.reason,
            );
            inner.tick = inner.tick.saturating_add(1);
            let selection_tick = inner.tick;
            mark_selected(
                &mut inner,
                group,
                context,
                nodes[selection.index].id,
                selection_tick,
            );
        }
        selection.index
    }

    #[cfg(test)]
    pub(super) fn exact_len(&self) -> usize {
        self.inner.lock().exact.len()
    }

    #[cfg(test)]
    pub(super) fn has_exact(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        node_id: Uuid,
    ) -> bool {
        let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) else {
            return false;
        };
        self.inner.lock().exact.contains(&ExactKey {
            group: group.to_string(),
            network: context.network,
            family,
            target: target.clone(),
            node_id,
        })
    }
    #[cfg(test)]
    fn exact_stats(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        node_id: Uuid,
    ) -> Option<(u64, u64, u64)> {
        let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) else {
            return None;
        };
        self.inner
            .lock()
            .exact
            .peek(&ExactKey {
                group: group.to_string(),
                network: context.network,
                family,
                target: target.clone(),
                node_id,
            })
            .map(|stats| {
                (
                    stats.attempts.round() as u64,
                    stats.setup_success.round() as u64,
                    stats.setup_failure.round() as u64,
                )
            })
    }

    #[cfg(test)]
    fn exact_useful_failures(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        node_id: Uuid,
    ) -> Option<u64> {
        let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) else {
            return None;
        };
        self.inner
            .lock()
            .exact
            .peek(&ExactKey {
                group: group.to_string(),
                network: context.network,
                family,
                target: target.clone(),
                node_id,
            })
            .map(|stats| stats.useful_failure.round() as u64)
    }

    #[cfg(test)]
    pub(super) fn aggregate_stats(
        &self,
        group: &str,
        network: SelectionNetwork,
        node_id: Uuid,
    ) -> Option<(u64, u64, u64)> {
        self.inner
            .lock()
            .aggregate
            .peek(&AggregateKey {
                group: group.to_string(),
                network,
                family: None,
                node_id,
            })
            .map(|stats| {
                (
                    stats.attempts.round() as u64,
                    stats.setup_success.round() as u64,
                    stats.setup_failure.round() as u64,
                )
            })
    }
}

fn best_index(
    snapshots: &[ScoreSnapshot],
    nodes: &[&Node],
    selection_count: u64,
    explore: bool,
    performance: PerformanceBaseline,
) -> RankedSelection {
    if explore {
        let candidate_count = snapshots.len();
        let target = exploration_target(candidate_count);
        let explored = snapshots
            .iter()
            .filter(|score| exploration_attempts(score) >= MIN_TRAINED_EVIDENCE)
            .count();
        let cold = snapshots
            .iter()
            .enumerate()
            .filter(|(_, score)| {
                exploration_completed(score) < MIN_TRAINED_EVIDENCE && !score.explore_backed_off
            })
            .min_by(|(left_index, left), (right_index, right)| {
                exploration_attempts(left)
                    .total_cmp(&exploration_attempts(right))
                    .then_with(|| left_index.cmp(right_index))
                    .then_with(|| nodes[*left_index].id.cmp(&nodes[*right_index].id))
            })
            .map(|(index, _)| index);
        let periodic = candidate_count > target
            && selection_count != 0
            && selection_count.is_multiple_of(exploration_period(candidate_count));
        if let Some(index) = cold
            && (explored < target || candidate_count <= target)
        {
            return RankedSelection {
                index,
                reason: SelectionReason::ColdExplore,
            };
        }
        if periodic {
            let incumbent = snapshots
                .iter()
                .enumerate()
                .filter(|(_, score)| score.selected_at != 0)
                .max_by_key(|(_, score)| score.selected_at)
                .map(|(index, _)| index);
            if let Some((index, _)) = snapshots
                .iter()
                .enumerate()
                .filter(|(index, score)| Some(*index) != incumbent && !score.explore_backed_off)
                .max_by(|(left_index, left), (right_index, right)| {
                    left.reliability_upper
                        .total_cmp(&right.reliability_upper)
                        .then_with(|| {
                            exploration_attempts(right).total_cmp(&exploration_attempts(left))
                        })
                        .then_with(|| right_index.cmp(left_index))
                        .then_with(|| nodes[*right_index].id.cmp(&nodes[*left_index].id))
                })
            {
                return RankedSelection {
                    index,
                    reason: SelectionReason::PeriodicExplore,
                };
            }
        }
    }
    // Fresh consecutive failures outweigh decayed success history.
    let any_healthy = snapshots
        .iter()
        .any(|score| score.fail_streak < SCORE_FAIL_STREAK_EXCLUDE);
    let rankable =
        |score: &&ScoreSnapshot| !any_healthy || score.fail_streak < SCORE_FAIL_STREAK_EXCLUDE;
    let best_reliability = snapshots
        .iter()
        .filter(rankable)
        .map(|score| score.reliability)
        .fold(0.0_f64, f64::max);
    let index = snapshots
        .iter()
        .enumerate()
        .filter(|(_, score)| {
            rankable(score) && best_reliability - score.reliability <= RELIABILITY_CLOSE
        })
        .max_by(|(left_index, left), (right_index, right)| {
            utility(left, performance)
                .total_cmp(&utility(right, performance))
                .then_with(|| right_index.cmp(left_index))
                .then_with(|| nodes[*right_index].id.cmp(&nodes[*left_index].id))
        })
        .map(|(index, _)| index)
        .unwrap_or(0);
    let reason = if snapshots
        .iter()
        .enumerate()
        .filter(|(candidate, _)| *candidate != index)
        .all(|(_, alternative)| {
            snapshots[index].reliability - alternative.reliability > RELIABILITY_CLOSE
        }) {
        SelectionReason::ReliabilityWinner
    } else {
        SelectionReason::PerformanceWinner
    };
    RankedSelection { index, reason }
}

fn switch_margin(completed: f64) -> f64 {
    SCORE_SWITCH_MARGIN * (completed / SCORE_SWITCH_FULL_EVIDENCE).clamp(0.0, 1.0)
}

fn hold_decision(
    incumbent: &ScoreSnapshot,
    best: &ScoreSnapshot,
    performance: PerformanceBaseline,
) -> HoldDecision {
    let trained =
        incumbent.completed >= MIN_TRAINED_EVIDENCE && best.completed >= MIN_TRAINED_EVIDENCE;
    let margin = switch_margin(incumbent.hysteresis_completed);
    let within_switch_margin =
        utility(best, performance) - utility(incumbent, performance) < margin;
    if !trained || !within_switch_margin {
        HoldDecision::UseBest
    } else if incumbent.failures < SCORE_FAILURE_FORGIVENESS_THRESHOLD {
        HoldDecision::Held
    } else {
        HoldDecision::FreshFailureBypass
    }
}

fn mark_selected(
    inner: &mut StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    node_id: Uuid,
    tick: u64,
) {
    let key = AggregateKey {
        group: group.to_string(),
        network: context.network,
        family: context.target_family,
        node_id,
    };
    if let Some(stats) = inner.aggregate.get_mut(&key) {
        stats.selected_at = tick;
    } else {
        // A full cache means this put evicts the LRU tail.
        if inner.aggregate.len() == inner.aggregate.cap().get() {
            inner.aggregate_evictions = inner.aggregate_evictions.saturating_add(1);
        }
        inner.aggregate.put(
            key,
            Stats {
                incarnation: tick,
                selected_at: tick,
                ..Default::default()
            },
        );
    }
    if let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) {
        let key = ExactKey {
            group: group.to_string(),
            network: context.network,
            family,
            target: target.clone(),
            node_id,
        };
        if let Some(stats) = inner.exact.get_mut(&key) {
            stats.selected_at = tick;
        }
    }
}
fn aggregate_families(context: &ScoreSelectionContext) -> [Option<IpVersion>; 2] {
    [None, context.target_family]
}

fn record_aggregate_start(
    inner: &mut StateInner,
    attribution: &ScoreAttribution,
    context: &ScoreSelectionContext,
    now: Instant,
    tick: u64,
) -> [Option<u64>; 2] {
    let mut cells = [None; 2];
    for (index, family) in aggregate_families(context).into_iter().enumerate() {
        if index == 1 && family.is_none() {
            break;
        }
        let key = AggregateKey {
            group: attribution.group.clone(),
            network: context.network,
            family,
            node_id: attribution.node_id,
        };
        cells[index] = Some(record_cell_start(
            &mut inner.aggregate,
            key,
            now,
            tick,
            &mut inner.aggregate_evictions,
        ));
    }
    cells
}

fn record_aggregate_finish(
    inner: &mut StateInner,
    attribution: &ScoreAttribution,
    context: &ScoreSelectionContext,
    cells: [Option<u64>; 2],
    now: Instant,
    sample: &FlowSample,
    tick: u64,
) {
    for (index, family) in aggregate_families(context).into_iter().enumerate() {
        if index == 1 && family.is_none() {
            break;
        }
        let key = AggregateKey {
            group: attribution.group.clone(),
            network: context.network,
            family,
            node_id: attribution.node_id,
        };
        record_cell_finish(
            &mut inner.aggregate,
            &key,
            cells[index],
            now,
            sample,
            sample.count_usefulness && context.target.is_some(),
            tick,
        );
    }
}

#[derive(Clone, Copy)]
struct ScoreSnapshot {
    attempts: f64,
    completed: f64,
    hysteresis_completed: f64,
    reliability: f64,
    reliability_upper: f64,
    useful_completed: f64,
    latency_ms: Option<f64>,
    latency_confidence: f64,
    throughput: Option<f64>,
    throughput_confidence: f64,
    failures: f64,
    explore_backed_off: bool,
    fail_streak: u32,
    selected_at: u64,
    targeted: bool,
    target_attempts: f64,
    target_completed: f64,
}

fn score_snapshot(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    node_id: Uuid,
    now: Instant,
) -> ScoreSnapshot {
    let family_score = context.target_family.and_then(|family| {
        inner
            .aggregate
            .peek(&AggregateKey {
                group: group.to_string(),
                network: context.network,
                family: Some(family),
                node_id,
            })
            .map(|stats| snapshot(stats, now))
    });
    let global_score = inner
        .aggregate
        .peek(&AggregateKey {
            group: group.to_string(),
            network: context.network,
            family: None,
            node_id,
        })
        .map_or_else(
            || snapshot(&Stats::default(), now),
            |stats| snapshot(stats, now),
        );
    let aggregate_score = family_score.map_or(global_score, |family| {
        let reliability_weight = (family.useful_completed / 8.0).clamp(0.0, 1.0);
        let setup_weight = (family.completed / 8.0).clamp(0.0, 1.0);
        ScoreSnapshot {
            attempts: family.attempts,
            completed: global_score.completed + family.completed,
            hysteresis_completed: if family.completed > 0.0 {
                family.hysteresis_completed
            } else {
                global_score.hysteresis_completed
            },
            useful_completed: global_score.useful_completed + family.useful_completed,
            reliability: blend(
                global_score.reliability,
                family.reliability,
                reliability_weight,
            ),
            reliability_upper: blend(
                global_score.reliability_upper,
                family.reliability_upper,
                reliability_weight,
            ),
            latency_ms: blend_option(global_score.latency_ms, family.latency_ms, setup_weight),
            latency_confidence: blend(
                global_score.latency_confidence,
                family.latency_confidence,
                setup_weight,
            ),
            throughput: blend_option(
                global_score.throughput,
                family.throughput,
                reliability_weight,
            ),
            throughput_confidence: blend(
                global_score.throughput_confidence,
                family.throughput_confidence,
                reliability_weight,
            ),
            failures: global_score.failures.max(family.failures),
            explore_backed_off: global_score.explore_backed_off,
            fail_streak: global_score.fail_streak,
            selected_at: global_score.selected_at.max(family.selected_at),
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        }
    });
    let exact_score = match (context.target_family, context.target.as_ref()) {
        (Some(family), Some(target)) => inner
            .exact
            .peek(&ExactKey {
                group: group.to_string(),
                network: context.network,
                family,
                target: target.clone(),
                node_id,
            })
            .map(|stats| snapshot(stats, now)),
        _ => None,
    };
    let Some(exact) = exact_score else {
        return aggregate_score;
    };
    let reliability_weight = (exact.useful_completed / 8.0).clamp(0.0, 1.0);
    let setup_weight = (exact.completed / 8.0).clamp(0.0, 1.0);
    ScoreSnapshot {
        attempts: exact.attempts,
        completed: aggregate_score.completed + exact.completed,
        hysteresis_completed: if exact.completed > 0.0 {
            exact.hysteresis_completed
        } else {
            aggregate_score.hysteresis_completed
        },
        useful_completed: aggregate_score.useful_completed + exact.useful_completed,
        reliability: blend(
            aggregate_score.reliability,
            exact.reliability,
            reliability_weight,
        ),
        reliability_upper: blend(
            aggregate_score.reliability_upper,
            exact.reliability_upper,
            reliability_weight,
        ),
        latency_ms: blend_option(aggregate_score.latency_ms, exact.latency_ms, setup_weight),
        latency_confidence: blend(
            aggregate_score.latency_confidence,
            exact.latency_confidence,
            setup_weight,
        ),
        throughput: blend_option(
            aggregate_score.throughput,
            exact.throughput,
            reliability_weight,
        ),
        throughput_confidence: blend(
            aggregate_score.throughput_confidence,
            exact.throughput_confidence,
            reliability_weight,
        ),
        failures: aggregate_score.failures.max(exact.failures),
        explore_backed_off: aggregate_score.explore_backed_off,
        fail_streak: aggregate_score.fail_streak,
        selected_at: aggregate_score.selected_at.max(exact.selected_at),
        targeted: exact.completed >= MIN_TRAINED_EVIDENCE
            || aggregate_score.completed < MIN_TRAINED_EVIDENCE,
        target_attempts: exact.attempts,
        target_completed: exact.completed,
    }
}
fn snapshot(stats: &Stats, now: Instant) -> ScoreSnapshot {
    let factor = stats.updated_at.map_or(1.0, |updated_at| {
        evidence_decay(now.saturating_duration_since(updated_at))
    });
    let (latency_ms, latency_weight) = stats
        .first_response_ms
        .mean()
        .map(|mean| (Some(mean), stats.first_response_ms.weight))
        .unwrap_or_else(|| (stats.setup_ms.mean(), stats.setup_ms.weight));
    // Dominant-direction bytes per second; utility normalizes this within the group.
    let throughput =
        (stats.throughput_seconds > 0.0).then(|| stats.throughput_bytes / stats.throughput_seconds);
    let (reliability, reliability_upper) = stats.reliability_bounds(factor);
    ScoreSnapshot {
        attempts: stats.attempts * factor,
        completed: stats.completed() * factor,
        hysteresis_completed: stats.completed() * factor,
        useful_completed: stats.useful_completed() * factor,
        reliability,
        reliability_upper,
        latency_ms,
        latency_confidence: (latency_weight * factor / 8.0).clamp(0.0, 1.0),
        throughput,
        throughput_confidence: (stats.throughput_windows * factor / 8.0).clamp(0.0, 1.0),
        failures: (stats.setup_failure + stats.useful_failure) * factor,
        explore_backed_off: stats.explore_not_before.is_some_and(|until| until > now),
        fail_streak: stats.fail_streak,
        selected_at: stats.selected_at,
        targeted: false,
        target_attempts: 0.0,
        target_completed: 0.0,
    }
}
fn blend(base: f64, exact: f64, exact_weight: f64) -> f64 {
    base * (1.0 - exact_weight) + exact * exact_weight
}

fn blend_option(base: Option<f64>, exact: Option<f64>, exact_weight: f64) -> Option<f64> {
    match (base, exact) {
        (Some(base), Some(exact)) => Some(blend(base, exact, exact_weight)),
        (None, exact) => exact,
        (base, None) => base,
    }
}

#[derive(Clone, Copy)]
struct PerformanceBaseline {
    latency_ms: Option<f64>,
    throughput: Option<f64>,
}

fn performance_baseline(snapshots: &[ScoreSnapshot]) -> PerformanceBaseline {
    let best_reliability = snapshots
        .iter()
        .map(|score| score.reliability)
        .fold(0.0_f64, f64::max);
    let eligible = || {
        snapshots
            .iter()
            .filter(|score| best_reliability - score.reliability <= RELIABILITY_CLOSE)
    };
    PerformanceBaseline {
        latency_ms: eligible()
            .filter_map(|score| score.latency_ms)
            .map(|latency| latency.max(1.0))
            .min_by(f64::total_cmp),
        throughput: eligible()
            .filter_map(|score| score.throughput)
            .max_by(f64::total_cmp),
    }
}

fn utility(score: &ScoreSnapshot, baseline: PerformanceBaseline) -> f64 {
    let latency_penalty = match (score.latency_ms, baseline.latency_ms) {
        (Some(latency), Some(best)) => {
            (1.0 - best / latency.max(1.0)).clamp(0.0, 1.0) * 0.03 * score.latency_confidence
        }
        _ => 0.0,
    };
    let throughput_bonus = match (score.throughput, baseline.throughput) {
        (Some(throughput), Some(best)) if best > 0.0 => {
            (throughput / best).clamp(0.0, 1.0) * 0.02 * score.throughput_confidence
        }
        _ => 0.0,
    };
    score.reliability + throughput_bonus - latency_penalty
}

#[derive(Clone)]
pub struct ScoreFeedback {
    state: Arc<ScorePolicyState>,
    authority: Arc<ScoreAuthority>,
    context: ScoreSelectionContext,
    attributions: Arc<[ScoreAttribution]>,
    streak_neutral: bool,
}

impl std::fmt::Debug for ScoreFeedback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScoreFeedback")
            .finish_non_exhaustive()
    }
}
impl ScoreFeedback {
    pub(super) fn new(
        state: Arc<ScorePolicyState>,
        authority: Arc<ScoreAuthority>,
        context: ScoreSelectionContext,
        attributions: Vec<ScoreAttribution>,
    ) -> Self {
        Self {
            state,
            authority,
            context,
            attributions: attributions.into(),
            streak_neutral: false,
        }
    }

    /// Probe, urltest, and warm-up outcomes must not touch the failure
    /// streak: a probe succeeding through a half-dead leaf must not wash out
    /// consecutive real-flow failures (and vice versa).
    pub fn streak_neutral(mut self) -> Self {
        self.streak_neutral = true;
        self
    }

    pub fn attributions(&self) -> &[ScoreAttribution] {
        &self.attributions
    }
    pub fn context(&self) -> &ScoreSelectionContext {
        &self.context
    }

    /// Add an outer Score group when a terminal `final` outbound supplies the
    /// leaf. Existing nested attribution order remains outer-to-inner.
    pub fn prepend_attribution(mut self, group: String, node_id: Uuid) -> Self {
        if !self
            .attributions
            .iter()
            .any(|attribution| attribution.group == group)
        {
            let mut attributions = Vec::with_capacity(self.attributions.len() + 1);
            attributions.push(ScoreAttribution { group, node_id });
            attributions.extend(self.attributions.iter().cloned());
            self.attributions = attributions.into();
        }
        self
    }
    /// Reuse the selected group chain for a related attempt with different
    /// transport dimensions, such as a UDP DNS reply retried over TCP.
    pub fn with_context(mut self, context: ScoreSelectionContext) -> Self {
        self.context = context;
        self
    }

    /// Call only when the physical dial or logical stream actually starts.
    pub fn start(&self) -> ScoreReporter {
        let started = Instant::now();
        let cells = self.state.start_at_with_authority(
            &self.authority,
            &self.context,
            &self.attributions,
            started,
        );
        ScoreReporter {
            shared: Arc::new(ReporterShared {
                state: Arc::clone(&self.state),
                authority: Arc::clone(&self.authority),
                context: self.context.clone(),
                attributions: Arc::clone(&self.attributions),
                cells: cells.into(),
                started,
                finished: AtomicBool::new(false),
                handles: AtomicUsize::new(1),
                tx: AtomicU64::new(0),
                rx: AtomicU64::new(0),
                progress: Mutex::new(ReporterProgress::default()),
                streak_neutral: self.streak_neutral,
            }),
        }
    }
}

#[derive(Default)]
struct ReporterProgress {
    setup: Option<Duration>,
    first_response: Option<Duration>,
}

struct ReporterShared {
    state: Arc<ScorePolicyState>,
    authority: Arc<ScoreAuthority>,
    context: ScoreSelectionContext,
    attributions: Arc<[ScoreAttribution]>,
    cells: Arc<[StartedCells]>,
    started: Instant,
    finished: AtomicBool,
    handles: AtomicUsize,
    tx: AtomicU64,
    rx: AtomicU64,
    progress: Mutex<ReporterProgress>,
    streak_neutral: bool,
}

/// Cloneable exact-once flow reporter. The first terminal call wins; dropping
/// the final unfinished handle reports cancellation.
pub struct ScoreReporter {
    shared: Arc<ReporterShared>,
}

impl Clone for ScoreReporter {
    fn clone(&self) -> Self {
        self.shared.handles.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl ScoreReporter {
    pub fn setup_succeeded(&self) {
        let mut progress = self.shared.progress.lock();
        progress
            .setup
            .get_or_insert_with(|| self.shared.started.elapsed());
    }

    pub fn setup_failed(&self, outcome: ScoreOutcome) {
        self.finish(outcome);
    }

    pub fn first_response(&self) {
        let mut progress = self.shared.progress.lock();
        progress
            .first_response
            .get_or_insert_with(|| self.shared.started.elapsed());
    }

    pub fn tx(&self, bytes: u64) {
        saturating_add(&self.shared.tx, bytes);
    }

    pub fn rx(&self, bytes: u64) {
        saturating_add(&self.shared.rx, bytes);
    }

    /// Recover the immutable attribution plan for a related physical attempt.
    pub fn feedback(&self) -> ScoreFeedback {
        ScoreFeedback {
            state: Arc::clone(&self.shared.state),
            authority: Arc::clone(&self.shared.authority),
            context: self.shared.context.clone(),
            attributions: Arc::clone(&self.shared.attributions),
            streak_neutral: self.shared.streak_neutral,
        }
    }

    /// Complete a successful preparation that carried no application payload.
    pub fn finish_setup_only(&self) {
        self.finish_inner(ScoreOutcome::Success, false);
    }

    pub fn finish(&self, outcome: ScoreOutcome) {
        self.finish_inner(outcome, true);
    }

    fn finish_inner(&self, outcome: ScoreOutcome, count_usefulness: bool) {
        if self
            .shared
            .finished
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let progress = self.shared.progress.lock();
        let sample = FlowSample {
            outcome,
            setup: progress.setup,
            first_response: progress.first_response,
            tx: self.shared.tx.load(Ordering::Relaxed),
            rx: self.shared.rx.load(Ordering::Relaxed),
            elapsed: self.shared.started.elapsed(),
            count_usefulness,
            streak_neutral: self.shared.streak_neutral,
        };
        self.shared.state.finish(
            &self.shared.context,
            &self.shared.attributions,
            &self.shared.cells,
            &sample,
        );
    }
}

impl Drop for ScoreReporter {
    fn drop(&mut self) {
        if self.shared.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.finish_inner(ScoreOutcome::Cancelled, false);
        }
    }
}

fn saturating_add(value: &AtomicU64, amount: u64) {
    let _ = value.try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(amount))
    });
}

struct FlowSample {
    outcome: ScoreOutcome,
    setup: Option<Duration>,
    first_response: Option<Duration>,
    tx: u64,
    rx: u64,
    elapsed: Duration,
    count_usefulness: bool,
    streak_neutral: bool,
}
