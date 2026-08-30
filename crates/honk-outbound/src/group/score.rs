use super::{IpVersion, ProbeDomain, SelectionNetwork};
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

impl super::GroupManager {
    /// Shared scorer handle for fallible reload construction.
    pub fn score_state(&self) -> Arc<ScorePolicyState> {
        Arc::clone(&self.score_state)
    }

    /// Publish committed group/leaf membership and prune only removed pairs.
    /// Extant non-Score groups remain valid for reporters started before a
    /// policy change; new selection creates feedback only for Score groups.
    pub fn publish_score_membership(&self) {
        let groups = self.groups.keys().cloned().collect::<Vec<_>>();
        let membership = self.groups.values().flat_map(|group| {
            let mut node_ids: HashSet<_> = self
                .leaf_nodes_in_group(&group.name)
                .into_iter()
                .map(|node| node.id)
                .collect();
            let mut visited = HashSet::new();
            self.collect_final_outbound_node_ids(group, &mut visited, &mut node_ids);
            node_ids
                .into_iter()
                .map(move |node_id| (group.name.clone(), node_id))
        });
        self.score_state
            .publish_generation(Arc::clone(&self.score_authority), groups, membership);
    }

    fn collect_final_outbound_node_ids(
        &self,
        group: &honk_config::group::Group,
        visited: &mut HashSet<String>,
        node_ids: &mut HashSet<Uuid>,
    ) {
        if !visited.insert(group.name.clone()) {
            return;
        }
        let Some(final_name) = group.final_outbound.as_deref() else {
            return;
        };
        match final_name {
            honk_config::Config::BUILTIN_DIRECT_NODE => {
                node_ids.insert(honk_config::config::DIRECT_NODE_ID);
            }
            honk_config::Config::BUILTIN_BLOCK_NODE => {
                node_ids.insert(honk_config::config::BLOCK_NODE_ID);
            }
            _ => {
                if let Some(node) = self.node_by_name(final_name) {
                    node_ids.insert(node.id);
                } else if let Some(final_group) = self.groups.get(final_name) {
                    node_ids.extend(
                        self.leaf_nodes_in_group(final_name)
                            .into_iter()
                            .map(|node| node.id),
                    );
                    self.collect_final_outbound_node_ids(final_group, visited, node_ids);
                }
            }
        }
    }

    /// Aggregate scorer feedback for concrete work scheduled by leaf ID.
    /// Every Score group that recursively contains the leaf is attributed
    /// once, regardless of how many nested paths reach it.
    pub fn feedback_for_node(
        &self,
        node_id: Uuid,
        context: ScoreSelectionContext,
    ) -> Option<ScoreFeedback> {
        let attributions: Vec<_> = self
            .groups
            .values()
            .filter(|group| group.policy == honk_config::group::GroupPolicy::Score)
            .filter(|group| {
                self.leaf_nodes_in_group(&group.name)
                    .iter()
                    .any(|node| node.id == node_id)
            })
            .map(|group| ScoreAttribution {
                group: group.name.clone(),
                node_id,
            })
            .collect();
        (!attributions.is_empty() && self.score_state.is_current_authority(&self.score_authority))
            .then(|| {
                ScoreFeedback::new(
                    Arc::clone(&self.score_state),
                    Arc::clone(&self.score_authority),
                    context,
                    attributions,
                )
            })
    }

    /// Feedback for a terminal `final` leaf attributed to one outer Honk
    /// group. Ordinary selected leaves should use their plan-carried feedback.
    pub fn feedback_for_group_node(
        &self,
        group_name: &str,
        node_id: Uuid,
        context: ScoreSelectionContext,
    ) -> Option<ScoreFeedback> {
        self.groups
            .get(group_name)
            .filter(|group| group.policy == honk_config::group::GroupPolicy::Score)
            .filter(|_| self.score_state.is_current_authority(&self.score_authority))
            .map(|group| {
                ScoreFeedback::new(
                    Arc::clone(&self.score_state),
                    Arc::clone(&self.score_authority),
                    context,
                    vec![ScoreAttribution {
                        group: group.name.clone(),
                        node_id,
                    }],
                )
            })
    }

    /// Target-aware selection with IPv6-target/IPv4-proxy health fallback.
    /// The target family remains unchanged in feedback keys; only the
    /// candidate health filter retries with IPv4.
    pub fn selection_plan_for_target_with_health_fallback(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
    ) -> super::ScoreSelectionPlan<'_> {
        let plan = self.selection_plan_for_target(group_name, context);
        if !plan.entries.is_empty() || context.health_family != IpVersion::V6 {
            return plan;
        }
        let mut fallback = context.clone();
        fallback.health_family = IpVersion::V4;
        self.selection_plan_for_target(group_name, &fallback)
    }
    /// Return the latency-ordered URLTest alternatives for one target without
    /// changing selection state. Each entry keeps the same Honk attribution
    /// and selection chain as an ordinary target-aware plan.
    pub fn urltest_retry_plan_for_target(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
    ) -> super::ScoreSelectionPlan<'_> {
        let Some(group) = self.groups.get(group_name) else {
            return super::ScoreSelectionPlan {
                mode: super::SelectionPlanMode::Authoritative,
                health_family: context.health_family,
                entries: Vec::new(),
            };
        };
        if group.policy != honk_config::group::GroupPolicy::URLTest {
            return super::ScoreSelectionPlan {
                mode: super::SelectionPlanMode::Authoritative,
                health_family: context.health_family,
                entries: Vec::new(),
            };
        }
        let mut visited = Vec::new();
        let candidates = self.flatten_candidates_for_target(
            group,
            context,
            &mut visited,
            0,
            super::SelectionEffects::Peek,
        );
        let candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        let mut seen = std::collections::HashSet::new();
        let candidates = self
            .order_by_latency(
                candidates,
                context.network,
                context.health_family,
                group.check_url.as_deref(),
            )
            .into_iter()
            .filter(|candidate| seen.insert(candidate.node.id))
            .take(3)
            .collect();
        self.score_selection_plan(candidates, super::SelectionPlanMode::Authoritative, context)
    }

    fn score_selection_plan<'a>(
        &'a self,
        candidates: Vec<super::Candidate<'a>>,
        mode: super::SelectionPlanMode,
        context: &ScoreSelectionContext,
    ) -> super::ScoreSelectionPlan<'a> {
        super::ScoreSelectionPlan {
            mode,
            health_family: context.health_family,
            entries: candidates
                .into_iter()
                .map(|candidate| {
                    let attributions: Vec<_> = candidate
                        .attribution
                        .into_iter()
                        .map(|group| ScoreAttribution {
                            group: group.to_string(),
                            node_id: candidate.node.id,
                        })
                        .collect();
                    let selection_chain = candidate
                        .selection_chain
                        .into_iter()
                        .map(str::to_owned)
                        .collect();
                    let feedback = (!attributions.is_empty())
                        .then(|| {
                            ScoreFeedback::new(
                                Arc::clone(&self.score_state),
                                Arc::clone(&self.score_authority),
                                context.clone(),
                                attributions,
                            )
                        })
                        .filter(|_| self.score_state.is_current_authority(&self.score_authority));
                    super::ScoreSelectionEntry {
                        node: candidate.node,
                        feedback,
                        selection_chain,
                    }
                })
                .collect(),
        }
    }

    /// Target-aware, candidate-safe plan with attribution captured during
    /// recursive selection rather than recovered from the selected NodeId.
    pub fn selection_plan_for_target(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
    ) -> super::ScoreSelectionPlan<'_> {
        let Some(group) = self.groups.get(group_name) else {
            return super::ScoreSelectionPlan {
                mode: super::SelectionPlanMode::Authoritative,
                health_family: context.health_family,
                entries: Vec::new(),
            };
        };
        self.mark_used(group_name);
        let mut visited = Vec::new();
        let mut candidates = self.flatten_candidates_for_target(
            group,
            context,
            &mut visited,
            0,
            super::SelectionEffects::Apply,
        );
        let before_filter = (group.policy == honk_config::group::GroupPolicy::Score
            && self.score_state.is_current_authority(&self.score_authority))
        .then(|| super::unique_candidate_ids(&candidates))
        .flatten();
        candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        if let Some(before_filter) = before_filter {
            self.score_state.record_dead_filtered(
                &self.score_authority,
                SelectionReasonKey::new(&group.name, context.network),
                super::removed_unique_candidate_count(before_filter, &candidates),
            );
        }
        let (mode, candidates) = if candidates.is_empty() {
            let candidate = self.last_resort_candidate_for_target(
                group,
                context,
                &mut visited,
                0,
                super::SelectionEffects::Apply,
            );
            (
                super::SelectionPlanMode::Authoritative,
                candidate.into_iter().collect(),
            )
        } else if group.policy == honk_config::group::GroupPolicy::URLTest
            && !candidates.iter().any(|candidate| {
                self.node_latency(
                    candidate.node,
                    context.network,
                    context.health_family,
                    group.check_url.as_deref(),
                    candidate.tag,
                ) != Duration::MAX
            })
        {
            (
                super::SelectionPlanMode::ColdUrlTest,
                self.order_by_latency(
                    candidates,
                    context.network,
                    context.health_family,
                    group.check_url.as_deref(),
                ),
            )
        } else {
            let candidate = match group.policy {
                honk_config::group::GroupPolicy::Selector => self.pick_selector(&candidates, group),
                honk_config::group::GroupPolicy::URLTest => self.pick_urltest(
                    &candidates,
                    group,
                    context.network,
                    context.health_family,
                    super::SelectionEffects::Apply,
                ),
                honk_config::group::GroupPolicy::LoadBalance => self.pick_load_balance(
                    &candidates,
                    group,
                    context.network,
                    super::SelectionEffects::Apply,
                ),
                honk_config::group::GroupPolicy::Fallback => self.pick_fallback(
                    &candidates,
                    group,
                    context.network,
                    super::SelectionEffects::Apply,
                ),
                honk_config::group::GroupPolicy::Score => {
                    self.pick_score(&candidates, group, context, super::SelectionEffects::Apply)
                }
            };
            (super::SelectionPlanMode::Authoritative, vec![candidate])
        };
        let candidates = candidates
            .into_iter()
            .map(|mut candidate| {
                if group.policy == honk_config::group::GroupPolicy::Score {
                    candidate.attribution.insert(0, group.name.as_str());
                }
                candidate.selection_chain.insert(0, group.name.as_str());
                candidate
            })
            .collect();
        self.score_selection_plan(candidates, mode, context)
    }

    fn last_resort_candidate_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Option<super::Candidate<'a>> {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return None;
        }
        let node = self.last_resort_tcp_leaf(group, context.probe_domain)?;
        if group.nodes.contains(&node.id) {
            return Some(super::Candidate {
                tag: node.name.as_str(),
                node,
                attribution: Vec::new(),
                selection_chain: vec![node.name.as_str()],
            });
        }

        visited.push(group.name.as_str());
        let candidate = group.groups.iter().find_map(|tag| {
            let subgroup = self.groups.get(tag)?;
            self.pick_candidate_for_target(subgroup, context, visited, depth + 1, effects)
                .filter(|candidate| candidate.node.id == node.id)
                .map(|mut candidate| {
                    candidate.tag = tag.as_str();
                    candidate
                })
        });
        visited.pop();
        candidate
    }

    fn pick_candidate_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Option<super::Candidate<'a>> {
        let mut candidates =
            self.flatten_candidates_for_target(group, context, visited, depth, effects);
        let before_filter = (effects.applies()
            && group.policy == honk_config::group::GroupPolicy::Score
            && self.score_state.is_current_authority(&self.score_authority))
        .then(|| super::unique_candidate_ids(&candidates))
        .flatten();
        candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        if let Some(before_filter) = before_filter {
            self.score_state.record_dead_filtered(
                &self.score_authority,
                SelectionReasonKey::new(&group.name, context.network),
                super::removed_unique_candidate_count(before_filter, &candidates),
            );
        }
        let mut candidate = if candidates.is_empty() {
            self.last_resort_candidate_for_target(group, context, visited, depth, effects)
        } else {
            Some(match group.policy {
                honk_config::group::GroupPolicy::Selector => self.pick_selector(&candidates, group),
                honk_config::group::GroupPolicy::URLTest => self.pick_urltest(
                    &candidates,
                    group,
                    context.network,
                    context.health_family,
                    effects,
                ),
                honk_config::group::GroupPolicy::LoadBalance => {
                    self.pick_load_balance(&candidates, group, context.network, effects)
                }
                honk_config::group::GroupPolicy::Fallback => {
                    self.pick_fallback(&candidates, group, context.network, effects)
                }
                honk_config::group::GroupPolicy::Score => {
                    self.pick_score(&candidates, group, context, effects)
                }
            })
        }?;
        if group.policy == honk_config::group::GroupPolicy::Score {
            candidate.attribution.insert(0, group.name.as_str());
        }
        candidate.selection_chain.insert(0, group.name.as_str());
        Some(candidate)
    }

    fn flatten_candidates_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Vec<super::Candidate<'a>> {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return Vec::new();
        }
        visited.push(group.name.as_str());
        let mut candidates: Vec<_> = group
            .nodes
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .map(|node| super::Candidate {
                tag: node.name.as_str(),
                node,
                attribution: Vec::new(),
                selection_chain: vec![node.name.as_str()],
            })
            .collect();
        for tag in &group.groups {
            let Some(subgroup) = self.groups.get(tag.as_str()) else {
                continue;
            };
            if effects.applies() {
                self.mark_used(tag);
            }
            if let Some(mut candidate) =
                self.pick_candidate_for_target(subgroup, context, visited, depth + 1, effects)
            {
                candidate.tag = tag.as_str();
                candidates.push(candidate);
            }
        }
        visited.pop();
        candidates
    }

    /// Aggregate winner used by display/control surfaces.
    pub fn get_score_selection_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<String> {
        let group = self.groups.get(group_name)?;
        let context = ScoreSelectionContext::aggregate(
            network,
            match network {
                SelectionNetwork::Tcp => ProbeDomain::Tcp,
                SelectionNetwork::Udp => ProbeDomain::DataUdp,
            },
            IpVersion::V4,
        );
        let mut visited = Vec::new();
        let mut candidates = self.flatten_candidates_for_target(
            group,
            &context,
            &mut visited,
            0,
            super::SelectionEffects::Peek,
        );
        candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        (!candidates.is_empty()).then(|| {
            self.pick_score(&candidates, group, &context, super::SelectionEffects::Peek)
                .tag
                .to_string()
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::group::{Group, GroupPolicy};

    fn assert_close(actual: f64, expected: f64) {
        assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
    }

    #[test]
    fn latency_samples_use_a_decayed_weighted_mean() {
        let mut latency = WeightedMean::default();
        latency.record(10.0);
        latency.record(20.0);
        latency.record(30.0);

        assert_close(latency.mean().unwrap(), 20.0);
        assert_close(latency.weight, 3.0);
    }

    #[test]
    fn trained_utility_does_not_trade_latency_for_attempt_balance() {
        let candidate = |attempts, latency_ms| ScoreSnapshot {
            attempts,
            completed: 8.0,
            hysteresis_completed: 8.0,
            reliability: 0.9,
            reliability_upper: 0.9,
            useful_completed: 8.0,
            latency_ms: Some(latency_ms),
            latency_confidence: 1.0,
            throughput: None,
            throughput_confidence: 0.0,
            failures: 0.0,
            selected_at: 0,
            explore_backed_off: false,
            fail_streak: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };

        let scores = [candidate(100.0, 50.0), candidate(8.0, 500.0)];
        let baseline = performance_baseline(&scores);
        assert!(utility(&scores[0], baseline) > utility(&scores[1], baseline));
    }

    #[test]
    fn relative_performance_is_scale_invariant() {
        let candidate = |latency_ms, throughput| ScoreSnapshot {
            attempts: 8.0,
            completed: 8.0,
            hysteresis_completed: 8.0,
            reliability: 0.9,
            reliability_upper: 0.9,
            useful_completed: 8.0,
            latency_ms: Some(latency_ms),
            latency_confidence: 1.0,
            throughput: Some(throughput),
            throughput_confidence: 1.0,
            failures: 0.0,
            selected_at: 0,
            explore_backed_off: false,
            fail_streak: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };
        let local = [candidate(30.0, 20_000_000.0), candidate(60.0, 10_000_000.0)];
        let remote = [
            candidate(300.0, 200_000_000.0),
            candidate(600.0, 100_000_000.0),
        ];
        let local_baseline = performance_baseline(&local);
        let remote_baseline = performance_baseline(&remote);

        assert_close(
            utility(&local[0], local_baseline) - utility(&local[1], local_baseline),
            utility(&remote[0], remote_baseline) - utility(&remote[1], remote_baseline),
        );
    }

    #[test]
    fn hold_decision_scales_margin_with_incumbent_evidence() {
        let candidate = |completed, reliability, latency_ms, failures| ScoreSnapshot {
            attempts: completed,
            completed,
            hysteresis_completed: completed,
            reliability,
            reliability_upper: reliability,
            useful_completed: completed,
            latency_ms,
            latency_confidence: f64::from(latency_ms.is_some()),
            throughput: None,
            throughput_confidence: 0.0,
            failures,
            selected_at: 0,
            explore_backed_off: false,
            fail_streak: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };
        let decision = |incumbent: ScoreSnapshot, best: ScoreSnapshot| {
            let performance = performance_baseline(&[incumbent, best]);
            hold_decision(&incumbent, &best, performance)
        };
        let trained = MIN_TRAINED_EVIDENCE;
        let low_margin = switch_margin(trained);
        let incumbent = candidate(trained, 0.0, None, 0.0);
        let proven = candidate(SCORE_SWITCH_FULL_EVIDENCE, 0.0, None, 0.0);

        assert_eq!(
            decision(
                candidate(trained - f64::EPSILON, 0.0, None, 0.0),
                candidate(trained, low_margin / 2.0, None, 0.0),
            ),
            HoldDecision::UseBest,
        );
        assert_eq!(
            decision(incumbent, candidate(trained, low_margin * 1.01, None, 0.0),),
            HoldDecision::UseBest,
        );
        assert_eq!(
            decision(incumbent, candidate(trained, low_margin / 2.0, None, 0.0),),
            HoldDecision::Held,
        );
        assert_eq!(
            decision(
                proven,
                candidate(
                    SCORE_SWITCH_FULL_EVIDENCE,
                    SCORE_SWITCH_MARGIN / 2.0,
                    None,
                    0.0,
                ),
            ),
            HoldDecision::Held,
        );
        assert_eq!(
            decision(
                proven,
                candidate(
                    SCORE_SWITCH_FULL_EVIDENCE,
                    SCORE_SWITCH_MARGIN * 1.01,
                    None,
                    0.0,
                ),
            ),
            HoldDecision::UseBest,
        );
        assert_eq!(
            decision(
                candidate(trained, 0.0, Some(1_048_576.0), 0.0),
                candidate(trained, 0.0, Some(1.0), 0.0),
            ),
            HoldDecision::UseBest,
        );
        assert_eq!(
            decision(
                candidate(trained, 0.0, None, SCORE_FAILURE_FORGIVENESS_THRESHOLD,),
                candidate(trained, low_margin / 2.0, None, 0.0),
            ),
            HoldDecision::FreshFailureBypass,
        );
    }

    #[test]
    fn hysteresis_evidence_counts_each_reporter_completion_once() {
        let assert_near = |actual: f64, expected: f64| {
            assert!((actual - expected).abs() < 1e-4, "{actual} != {expected}");
        };
        let node = node("only");
        let manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&node))],
            std::slice::from_ref(&node),
        );
        let context = context("evidence.example", IpVersion::V4);
        for _ in 0..3 {
            finish_success(&manager.selection_plan_for_target("score", &context));
        }
        let score = {
            let state = manager.score_state();
            let inner = state.inner.lock();
            score_snapshot(&inner, "score", &context, node.id, Instant::now())
        };
        assert_near(score.completed, 9.0);
        assert_near(score.hysteresis_completed, 3.0);
        assert_near(
            switch_margin(score.hysteresis_completed),
            SCORE_SWITCH_MARGIN * 3.0 / SCORE_SWITCH_FULL_EVIDENCE,
        );

        for _ in 3..8 {
            finish_success(&manager.selection_plan_for_target("score", &context));
        }
        let score = {
            let state = manager.score_state();
            let inner = state.inner.lock();
            score_snapshot(&inner, "score", &context, node.id, Instant::now())
        };
        assert_near(score.completed, 24.0);
        assert_near(score.hysteresis_completed, 8.0);
        assert_near(
            switch_margin(score.hysteresis_completed),
            SCORE_SWITCH_MARGIN,
        );
    }

    #[test]
    fn exploration_budget_scales_with_candidate_count() {
        assert_eq!(exploration_target(3), 3);
        assert_eq!(exploration_target(4), 4);
        assert_eq!(exploration_target(14), 5);
        assert_eq!(exploration_target(28), 7);
        assert_eq!(exploration_period(3), SCORE_EXPLORATION_MIN_PERIOD);
        assert_eq!(exploration_period(28), 56);
        assert_eq!(exploration_period(128), SCORE_EXPLORATION_MAX_PERIOD);
    }

    #[test]
    fn cold_exploration_skips_backed_off_candidates() {
        let nodes = [node("a"), node("b")];
        let node_refs: Vec<_> = nodes.iter().collect();
        let cold = |backed_off| ScoreSnapshot {
            attempts: 0.0,
            completed: 0.0,
            hysteresis_completed: 0.0,
            reliability: 0.0,
            reliability_upper: 0.5,
            useful_completed: 0.0,
            latency_ms: None,
            latency_confidence: 0.0,
            throughput: None,
            throughput_confidence: 0.0,
            failures: 0.0,
            explore_backed_off: backed_off,
            fail_streak: 0,
            selected_at: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };
        let snapshots = [cold(true), cold(false)];
        let performance = performance_baseline(&snapshots);
        let selection = best_index(&snapshots, &node_refs, 1, true, performance);
        assert_eq!(selection.index, 1);
        assert_eq!(selection.reason, SelectionReason::ColdExplore);

        let snapshots = [cold(false), cold(false)];
        let performance = performance_baseline(&snapshots);
        assert_eq!(
            best_index(&snapshots, &node_refs, 1, true, performance).index,
            0
        );

        // All backed off: exploration skips, ranking still returns a leaf.
        let snapshots = [cold(true), cold(true)];
        let performance = performance_baseline(&snapshots);
        let selection = best_index(&snapshots, &node_refs, 1, true, performance);
        assert!(!selection.reason.is_exploration());
        assert_eq!(selection.reason, SelectionReason::PerformanceWinner);
    }

    #[test]
    fn consecutive_failures_exclude_leaf_from_ranking() {
        let nodes = [node("a"), node("b")];
        let node_refs: Vec<_> = nodes.iter().collect();
        let trained = |reliability, fail_streak| ScoreSnapshot {
            attempts: 8.0,
            completed: 8.0,
            hysteresis_completed: 8.0,
            reliability,
            reliability_upper: reliability,
            useful_completed: 8.0,
            latency_ms: None,
            latency_confidence: 0.0,
            throughput: None,
            throughput_confidence: 0.0,
            failures: 0.0,
            explore_backed_off: false,
            fail_streak,
            selected_at: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };
        let snapshots = [trained(0.9, SCORE_FAIL_STREAK_EXCLUDE), trained(0.8, 0)];
        let performance = performance_baseline(&snapshots);
        assert_eq!(
            best_index(&snapshots, &node_refs, 1, false, performance).index,
            1
        );
        // Pinned fallback: with every candidate excluded, rank the full set.
        let snapshots = [
            trained(0.9, SCORE_FAIL_STREAK_EXCLUDE),
            trained(0.8, SCORE_FAIL_STREAK_EXCLUDE),
        ];
        let performance = performance_baseline(&snapshots);
        assert_eq!(
            best_index(&snapshots, &node_refs, 1, false, performance).index,
            0
        );
    }

    #[test]
    fn rank_counts_fail_streak_excluded_candidates() {
        let state = ScorePolicyState::default();
        let nodes = [node("a"), node("b")];
        let node_refs: Vec<_> = nodes.iter().collect();
        state.publish_membership([("score".into(), nodes[0].id), ("score".into(), nodes[1].id)]);
        let context = context("example.com", IpVersion::V4);
        let attributions = [ScoreAttribution {
            group: "score".into(),
            node_id: nodes[0].id,
        }];
        let now = Instant::now();
        let sample = FlowSample {
            outcome: ScoreOutcome::Timeout,
            setup: None,
            first_response: None,
            tx: 0,
            rx: 0,
            elapsed: Duration::ZERO,
            count_usefulness: true,
            streak_neutral: false,
        };
        for _ in 0..SCORE_FAIL_STREAK_EXCLUDE {
            let cells = state.start_at(&context, &attributions, now);
            state.finish_at(&context, &attributions, &cells, &sample, now);
        }
        let _ = state.rank_at("score", &context, &node_refs, now);
        let counts = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        assert_eq!(counts.fail_streak_excluded, 1);
        assert_eq!(counts.explore_backed_off, 1);

        let _ = state.peek_rank("score", &context, &node_refs);
        let counts = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        assert_eq!(counts.fail_streak_excluded, 1);
        assert_eq!(counts.explore_backed_off, 1);
    }

    #[test]
    fn rank_counts_explore_backed_off_candidates() {
        let state = ScorePolicyState::default();
        let nodes = [node("a"), node("b")];
        let node_refs: Vec<_> = nodes.iter().collect();
        state.publish_membership([("score".into(), nodes[0].id), ("score".into(), nodes[1].id)]);
        let context = context("backoff.example", IpVersion::V4);
        let attributions = [ScoreAttribution {
            group: "score".into(),
            node_id: nodes[0].id,
        }];
        let now = Instant::now();
        let sample = FlowSample {
            outcome: ScoreOutcome::Timeout,
            setup: None,
            first_response: None,
            tx: 0,
            rx: 0,
            elapsed: Duration::ZERO,
            count_usefulness: true,
            streak_neutral: false,
        };
        let cells = state.start_at(&context, &attributions, now);
        state.finish_at(&context, &attributions, &cells, &sample, now);
        let _ = state.rank_at("score", &context, &node_refs, now);
        let counts = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        assert_eq!(counts.explore_backed_off, 1);
        assert_eq!(counts.fail_streak_excluded, 0);
    }

    #[test]
    fn exploration_backoff_grows_with_failures_and_shrinks_with_success() {
        let state = ScorePolicyState::default();
        let leaf = node("leaf");
        state.publish_membership([("score".into(), leaf.id)]);
        let context = context("example.com", IpVersion::V4);
        let attributions = [ScoreAttribution {
            group: "score".into(),
            node_id: leaf.id,
        }];
        let now = Instant::now();
        let sample = |outcome, setup| FlowSample {
            outcome,
            setup,
            first_response: None,
            tx: 0,
            rx: 0,
            elapsed: Duration::ZERO,
            count_usefulness: true,
            streak_neutral: false,
        };
        let backed_off = |at: Instant| {
            let inner = state.inner.lock();
            score_snapshot(&inner, "score", &context, leaf.id, at).explore_backed_off
        };
        let fail = |at: Instant| {
            let cells = state.start_at(&context, &attributions, at);
            state.finish_at(
                &context,
                &attributions,
                &cells,
                &sample(ScoreOutcome::Timeout, None),
                at,
            );
        };
        let neutral = |outcome, at: Instant| {
            let cells = state.start_at(&context, &attributions, at);
            let mut neutral_sample = sample(outcome, None);
            neutral_sample.streak_neutral = true;
            state.finish_at(&context, &attributions, &cells, &neutral_sample, at);
        };
        let streak = |at: Instant| {
            let inner = state.inner.lock();
            score_snapshot(&inner, "score", &context, leaf.id, at).fail_streak
        };

        fail(now);
        // Probe/urltest/warm outcomes never move the streak or the backoff.
        neutral(ScoreOutcome::Success, now);
        neutral(ScoreOutcome::Timeout, now);
        assert_eq!(streak(now), 1);
        assert!(backed_off(now + Duration::from_secs(1)));
        assert!(!backed_off(
            now + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(1)
        ));

        let second = now + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(2);
        fail(second);
        assert!(backed_off(
            second + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(1)
        ));
        assert!(!backed_off(
            second + SCORE_EXPLORE_BACKOFF_BASE * 2 + Duration::from_secs(1)
        ));

        let cells = state.start_at(&context, &attributions, second);
        state.finish_at(
            &context,
            &attributions,
            &cells,
            &sample(ScoreOutcome::Success, Some(Duration::from_millis(10))),
            second,
        );
        // Success steps the streak down (2 → 1), so the next failure lands
        // back on the doubled cadence rather than the base one.
        assert!(!backed_off(second + Duration::from_secs(1)));
        let third = second + Duration::from_secs(2);
        fail(third);
        assert!(backed_off(
            third + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(1)
        ));
        assert!(!backed_off(
            third + SCORE_EXPLORE_BACKOFF_BASE * 2 + Duration::from_secs(1)
        ));
    }

    #[test]
    fn large_score_groups_periodically_try_non_incumbent() {
        let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
        let node_refs: Vec<_> = nodes.iter().collect();
        let context = context("example.com", IpVersion::V4);
        let state = ScorePolicyState::default();
        state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
        let now = Instant::now();
        {
            let mut inner = state.inner.lock();
            for (index, node) in nodes.iter().enumerate() {
                inner.aggregate.put(
                    AggregateKey {
                        group: "score".into(),
                        network: SelectionNetwork::Tcp,
                        family: None,
                        node_id: node.id,
                    },
                    Stats {
                        setup_success: 8.0,
                        useful_success: 8.0,
                        first_response_ms: WeightedMean {
                            sum: 800.0,
                            weight: 8.0,
                        },
                        updated_at: Some(now),
                        selected_at: u64::from(index == 0),
                        ..Default::default()
                    },
                );
            }
            inner.selection_counts.insert(
                SelectionCadenceKey::new("score", &context),
                exploration_period(nodes.len()) - 1,
            );
        }

        assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);
    }

    #[test]
    fn periodic_exploration_prefers_reliability_upper_bound() {
        let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
        let node_refs: Vec<_> = nodes.iter().collect();
        let candidate = |attempts, reliability_upper, selected_at| ScoreSnapshot {
            attempts,
            completed: 8.0,
            hysteresis_completed: 8.0,
            reliability: 0.2,
            reliability_upper,
            useful_completed: 8.0,
            latency_ms: None,
            latency_confidence: 0.0,
            throughput: None,
            throughput_confidence: 0.0,
            failures: 0.0,
            selected_at,
            explore_backed_off: false,
            fail_streak: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };
        let mut snapshots = vec![candidate(8.0, 0.2, 0); nodes.len()];
        snapshots[0] = candidate(8.0, 0.9, 1);
        snapshots[1] = candidate(1.0, 0.3, 0);
        snapshots[2] = candidate(8.0, 0.8, 0);
        let performance = performance_baseline(&snapshots);

        let selected = best_index(
            &snapshots,
            &node_refs,
            exploration_period(nodes.len()),
            true,
            performance,
        );

        assert_eq!(selected.index, 2);
        assert_eq!(selected.reason, SelectionReason::PeriodicExplore);
    }

    #[test]
    fn large_score_groups_cap_initial_target_exploration() {
        let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("example.com", IpVersion::V4);
        let mut seen = std::collections::HashSet::new();

        for _ in 0..exploration_target(nodes.len()) {
            let plan = manager.selection_plan_for_target("score", &context);
            seen.insert(plan.entries[0].node.id);
            finish_success(&plan);
        }

        assert_eq!(seen.len(), exploration_target(nodes.len()));
    }

    #[test]
    fn score_peek_does_not_consume_group_exploration_budget() {
        let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
        let node_refs: Vec<_> = nodes.iter().collect();
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let state = ScorePolicyState::default();
        state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
        let now = Instant::now();
        {
            let mut inner = state.inner.lock();
            for (index, node) in nodes.iter().enumerate() {
                inner.aggregate.put(
                    AggregateKey {
                        group: "score".into(),
                        network: SelectionNetwork::Tcp,
                        family: None,
                        node_id: node.id,
                    },
                    Stats {
                        setup_success: 8.0,
                        useful_success: 8.0,
                        first_response_ms: WeightedMean {
                            sum: 800.0,
                            weight: 8.0,
                        },
                        updated_at: Some(now),
                        selected_at: u64::from(index == 0),
                        ..Default::default()
                    },
                );
            }
            inner.selection_counts.insert(
                SelectionCadenceKey::new("score", &context),
                exploration_period(nodes.len()) - 1,
            );
        }

        let selected = state.rank_at("score", &context, &node_refs, now);
        assert_eq!(selected, 1);
        let key = SelectionCadenceKey::new("score", &context);
        let count = state.inner.lock().selection_counts[&key];
        assert_eq!(state.peek_rank("score", &context, &node_refs), selected);
        assert_eq!(state.inner.lock().selection_counts[&key], count);
    }

    #[test]
    fn same_scope_exploration_period_and_peek_are_unchanged() {
        let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
        let node_refs: Vec<_> = nodes.iter().collect();
        let context = context("example.com", IpVersion::V4);
        let state = ScorePolicyState::default();
        state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
        let now = Instant::now();
        {
            let mut inner = state.inner.lock();
            for (index, node) in nodes.iter().enumerate() {
                inner.aggregate.put(
                    AggregateKey {
                        group: "score".into(),
                        network: SelectionNetwork::Tcp,
                        family: None,
                        node_id: node.id,
                    },
                    Stats {
                        setup_success: 8.0,
                        useful_success: 8.0,
                        first_response_ms: WeightedMean {
                            sum: 800.0,
                            weight: 8.0,
                        },
                        updated_at: Some(now),
                        selected_at: u64::from(index == 0),
                        ..Default::default()
                    },
                );
            }
            inner.selection_counts.insert(
                SelectionCadenceKey::new("score", &context),
                exploration_period(nodes.len()) - 1,
            );
        }

        let selected = state.rank_at("score", &context, &node_refs, now);
        assert_eq!(selected, 1);
        assert_eq!(
            state.inner.lock().selection_counts[&SelectionCadenceKey::new("score", &context)],
            exploration_period(nodes.len())
        );
        assert_eq!(state.peek_rank("score", &context, &node_refs), selected);
        assert_eq!(
            state.inner.lock().selection_counts[&SelectionCadenceKey::new("score", &context)],
            exploration_period(nodes.len())
        );
    }

    #[test]
    fn periodic_exploration_is_scoped_by_network_and_family() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let targeted = |network, family| ScoreSelectionContext {
            network,
            probe_domain: if network == SelectionNetwork::Tcp {
                ProbeDomain::Tcp
            } else {
                ProbeDomain::DataUdp
            },
            target_family: Some(family),
            health_family: family,
            target: Some(ScoreTarget::domain("target.example", 443)),
        };
        let aggregate = |network| {
            ScoreSelectionContext::aggregate(
                network,
                if network == SelectionNetwork::Tcp {
                    ProbeDomain::Tcp
                } else {
                    ProbeDomain::DataUdp
                },
                IpVersion::V4,
            )
        };
        let contexts = [
            targeted(SelectionNetwork::Tcp, IpVersion::V4),
            targeted(SelectionNetwork::Tcp, IpVersion::V6),
            targeted(SelectionNetwork::Udp, IpVersion::V4),
            targeted(SelectionNetwork::Udp, IpVersion::V6),
            aggregate(SelectionNetwork::Tcp),
            aggregate(SelectionNetwork::Udp),
        ];
        for context in &contexts {
            let _ = manager.selection_plan_for_target("score", context);
        }
        let state = manager.score_state();
        assert_eq!(state.inner.lock().selection_counts.len(), 6);
        println!(
            "cadence scope cardinality={}",
            state.inner.lock().selection_counts.len()
        );

        let tcp_v4_key = SelectionCadenceKey::new("score", &contexts[0]);
        state
            .inner
            .lock()
            .selection_counts
            .insert(tcp_v4_key.clone(), exploration_period(nodes.len()) - 1);
        let _ = manager.selection_plan_for_target("score", &contexts[2]);
        assert_eq!(
            state.inner.lock().selection_counts[&tcp_v4_key],
            exploration_period(nodes.len()) - 1,
            "UDP-V4 must not consume TCP-V4 cadence"
        );
        let _ = manager.selection_plan_for_target("score", &contexts[0]);
        assert_eq!(
            state.inner.lock().selection_counts[&tcp_v4_key],
            exploration_period(nodes.len())
        );

        let different_target = context("other.example", IpVersion::V4);
        let _ = manager.selection_plan_for_target("score", &different_target);
        assert_eq!(state.inner.lock().selection_counts.len(), 6);
    }

    #[test]
    fn selection_count_reload_lifecycle_matches_group_name() {
        let nodes = [node("a"), node("b")];
        let old = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("reload.example", IpVersion::V4);
        let _ = old.selection_plan_for_target("score", &context);
        let state = old.score_state();
        let before: u64 = state.inner.lock().selection_counts.values().copied().sum();

        let empty = super::super::GroupManager::with_alive_set_and_score_state(
            &[group("score", &[])],
            &[],
            None,
            Arc::clone(&state),
        );
        empty.publish_score_membership();
        assert_eq!(
            state
                .inner
                .lock()
                .selection_counts
                .values()
                .copied()
                .sum::<u64>(),
            before,
            "a committed group name retains cadence through zero leaves"
        );

        let mut selector = group("score", &nodes);
        selector.policy = GroupPolicy::Selector;
        let non_score = super::super::GroupManager::with_alive_set_and_score_state(
            &[selector],
            &nodes,
            None,
            Arc::clone(&state),
        );
        non_score.publish_score_membership();
        assert_eq!(
            state
                .inner
                .lock()
                .selection_counts
                .values()
                .copied()
                .sum::<u64>(),
            before,
            "a surviving name retains cadence through Score to non-Score"
        );

        let removed = super::super::GroupManager::with_alive_set_and_score_state(
            &[],
            &[],
            None,
            Arc::clone(&state),
        );
        removed.publish_score_membership();
        assert!(state.inner.lock().selection_counts.is_empty());
    }

    #[test]
    fn stale_manager_authority_stays_revoked_after_same_name_recreation() {
        let survivor = node("survivor");
        let removed = node("removed");
        let replacement_node = node("replacement");
        let old_nodes = [survivor.clone(), removed.clone()];
        let old = super::super::GroupManager::new(&[group("score", &old_nodes)], &old_nodes);
        let state = old.score_state();
        let seeded_context = context("seeded.example", IpVersion::V4);
        finish_success(&old.selection_plan_for_target("score", &seeded_context));

        let deleted = super::super::GroupManager::with_alive_set_and_score_state(
            &[],
            &[],
            None,
            Arc::clone(&state),
        );
        deleted.publish_score_membership();
        let replacement_nodes = [survivor.clone(), replacement_node];
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
            &[group("score", &replacement_nodes)],
            &replacement_nodes,
            None,
            Arc::clone(&state),
        );
        replacement.publish_score_membership();
        let before = {
            let inner = state.inner.lock();
            (
                inner.tick,
                inner.selection_counts.len(),
                inner.aggregate.len(),
                inner.exact.len(),
            )
        };
        assert_eq!((before.1, before.2, before.3), (0, 0, 0));

        let stale =
            old.selection_plan_for_target("score", &context("stale.example", IpVersion::V4));
        assert!(stale.entries[0].feedback.is_none());
        assert!(
            old.feedback_for_group_node("score", survivor.id, seeded_context.clone())
                .is_none(),
            "the surviving ID must not restore old-manager feedback authority"
        );
        assert!(
            old.feedback_for_group_node("score", removed.id, seeded_context)
                .is_none(),
            "the replaced ID must not restore old-manager feedback authority"
        );
        let after_stale = {
            let inner = state.inner.lock();
            (
                inner.tick,
                inner.selection_counts.len(),
                inner.aggregate.len(),
                inner.exact.len(),
            )
        };
        assert_eq!(after_stale, before);

        let current = replacement
            .selection_plan_for_target("score", &context("current.example", IpVersion::V4));
        assert!(current.entries[0].feedback.is_some());
        let after_current = state.inner.lock();
        assert_eq!(after_current.selection_counts.len(), 1);
        assert_eq!(after_current.aggregate.len(), 1);
        assert!(after_current.tick > before.0);
    }

    #[test]
    fn captured_feedback_requires_current_authority_at_start() {
        let nodes = [node("a"), node("b")];
        let old = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("captured.example", IpVersion::V4);
        let feedback = old
            .feedback_for_group_node("score", nodes[0].id, context.clone())
            .unwrap();
        let state = old.score_state();
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
            &[group("score", &nodes)],
            &nodes,
            None,
            Arc::clone(&state),
        );
        replacement.publish_score_membership();
        let before_tick = state.inner.lock().tick;

        let reporter = feedback.start();
        reporter.setup_succeeded();
        reporter.first_response();
        reporter.tx(123);
        reporter.rx(456);
        reporter.finish(ScoreOutcome::Timeout);
        drop(reporter);

        assert!(!state.has_exact("score", &context, nodes[0].id));
        assert_eq!(state.inner.lock().tick, before_tick);
    }

    #[test]
    fn trained_score_holds_incumbent_against_small_gain() {
        let nodes = [node("a"), node("b")];
        let node_refs = [&nodes[0], &nodes[1]];
        let context = context("example.com", IpVersion::V4);
        let state = ScorePolicyState::default();
        state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
        let now = Instant::now();
        let key = |node_id| AggregateKey {
            group: "score".into(),
            network: SelectionNetwork::Tcp,
            family: Some(IpVersion::V4),
            node_id,
        };
        {
            let mut inner = state.inner.lock();
            for (node, latency_ms) in [(&nodes[0], 1_000.0), (&nodes[1], 1_200.0)] {
                inner.aggregate.put(
                    key(node.id),
                    Stats {
                        setup_success: 8.0,
                        useful_success: 8.0,
                        first_response_ms: WeightedMean {
                            sum: latency_ms * 8.0,
                            weight: 8.0,
                        },
                        updated_at: Some(now),
                        ..Default::default()
                    },
                );
            }
        }

        assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);
        inner_update_response(&state, key(nodes[1].id), 900.0);
        assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);
        inner_update_response(&state, key(nodes[1].id), 1.0);
        assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);
    }

    #[test]
    fn single_failure_layer_freshness_is_unchanged() {
        // Given: one aggregate failure cell with exactly one half-life of age.
        let node = node("leaf");
        let context = context("example.com", IpVersion::V4);
        let start = Instant::now();
        let mut inner = StateInner::default();
        inner.aggregate.put(
            AggregateKey {
                group: "score".into(),
                network: SelectionNetwork::Tcp,
                family: None,
                node_id: node.id,
            },
            Stats {
                setup_failure: 2.0,
                updated_at: Some(start),
                ..Default::default()
            },
        );

        // When: the scorer snapshots the single layer after one half-life.
        let score = score_snapshot(
            &inner,
            "score",
            &context,
            node.id,
            start + SCORE_EVIDENCE_HALF_LIFE,
        );

        // Then: existing decay remains unchanged and no absent layer contributes.
        println!("single failure layer envelope={:.12}", score.failures);
        assert_close(score.failures, 1.0);
    }

    fn layered_failure_value(ages: [Option<Duration>; 3]) -> f64 {
        let node = node("leaf");
        let context = context("example.com", IpVersion::V4);
        let start = Instant::now();
        let now = start + Duration::from_secs(60);
        let mut inner = StateInner::default();
        for (index, age) in ages.into_iter().enumerate() {
            let Some(age) = age else {
                continue;
            };
            let stats = Stats {
                setup_failure: 1.0,
                updated_at: Some(now - age),
                ..Default::default()
            };
            match index {
                0 | 1 => {
                    inner.aggregate.put(
                        AggregateKey {
                            group: "score".into(),
                            network: SelectionNetwork::Tcp,
                            family: (index == 1).then_some(IpVersion::V4),
                            node_id: node.id,
                        },
                        stats,
                    );
                }
                2 => {
                    inner.exact.put(
                        ExactKey {
                            group: "score".into(),
                            network: SelectionNetwork::Tcp,
                            family: IpVersion::V4,
                            target: context.target.clone().unwrap(),
                            node_id: node.id,
                        },
                        stats,
                    );
                }
                _ => unreachable!(),
            }
        }
        score_snapshot(&inner, "score", &context, node.id, now).failures
    }

    fn assert_aged_failure_layers_count_once() {
        // Given: the same 30-second-old failure appears in overlapping layers.
        let age = Some(Duration::from_secs(30));

        // When: one, two, and three layers are independently snapshotted.
        let global_only = layered_failure_value([age, None, None]);
        let global_family = layered_failure_value([age, age, None]);
        let global_family_exact = layered_failure_value([age, age, age]);
        println!(
            "layered failure envelope: global_only={global_only:.12} global_family={global_family:.12} global_family_exact={global_family_exact:.12}"
        );

        // Then: replication does not increase the effective failure envelope.
        assert_close(global_family, global_only);
        assert_close(global_family_exact, global_only);
        let aged = layered_failure_value([
            Some(Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 8)),
            Some(Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 8)),
            Some(Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 8)),
        ]);
        let incumbent = ScoreSnapshot {
            attempts: 1.0,
            completed: 1.0,
            hysteresis_completed: 1.0,
            reliability: 0.8,
            reliability_upper: 0.8,
            useful_completed: 1.0,
            latency_ms: None,
            latency_confidence: 0.0,
            throughput: None,
            throughput_confidence: 0.0,
            failures: aged,
            explore_backed_off: false,
            fail_streak: 0,
            selected_at: 1,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };
        let challenger = ScoreSnapshot {
            reliability: 0.8005,
            reliability_upper: 0.8005,
            failures: 0.0,
            selected_at: 0,
            ..incumbent
        };
        let retained = hold_decision(
            &incumbent,
            &challenger,
            performance_baseline(&[incumbent, challenger]),
        ) == HoldDecision::Held;
        println!("aged layered envelope={aged:.12} retained_incumbent={retained}");
        assert!(aged < SCORE_FAILURE_FORGIVENESS_THRESHOLD);
        assert!(retained);
    }

    #[test]
    fn layered_failure_freshness_uses_one_envelope() {
        assert_aged_failure_layers_count_once();
    }

    fn assert_larger_specific_failure_layer_still_wins() {
        // Given: global, family, and exact evidence are respectively 30, 20, and 10 seconds old.
        let global = evidence_decay(Duration::from_secs(30));
        let family = evidence_decay(Duration::from_secs(20));
        let exact = evidence_decay(Duration::from_secs(10));

        // When: all three overlapping layers are snapshotted together.
        let effective = layered_failure_value([
            Some(Duration::from_secs(30)),
            Some(Duration::from_secs(20)),
            Some(Duration::from_secs(10)),
        ]);
        println!(
            "specific failure envelope: global_30s={global:.12} family_20s={family:.12} exact_10s={exact:.12} effective={effective:.12}"
        );

        // Then: the freshest specific layer is the effective envelope.
        assert_close(effective, exact);
    }

    #[test]
    fn specific_failure_freshness_is_not_hidden() {
        assert_larger_specific_failure_layer_still_wins();
    }

    #[test]
    fn aged_failure_restores_incumbent_margin() {
        // Given: two trained nodes and negligible failure evidence on the incumbent.
        let nodes = [node("a"), node("b")];
        let node_refs = [&nodes[0], &nodes[1]];
        let context = context("example.com", IpVersion::V4);
        let state = ScorePolicyState::default();
        state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
        let start = Instant::now();
        let now = start + Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 8);
        {
            let mut inner = state.inner.lock();
            for (index, node) in nodes.iter().enumerate() {
                let incumbent = index == 0;
                inner.aggregate.put(
                    AggregateKey {
                        group: "score".into(),
                        network: SelectionNetwork::Tcp,
                        family: Some(IpVersion::V4),
                        node_id: node.id,
                    },
                    Stats {
                        attempts: 256.0 + f64::from(incumbent),
                        setup_success: 256.0,
                        setup_failure: f64::from(incumbent),
                        useful_success: 256.0,
                        useful_failure: f64::from(incumbent),
                        first_response_ms: WeightedMean {
                            sum: 256_000.0,
                            weight: 256.0,
                        },
                        updated_at: Some(start),
                        selected_at: u64::from(incumbent),
                        ..Default::default()
                    },
                );
            }
        }
        let snapshots: Vec<_> = {
            let inner = state.inner.lock();
            nodes
                .iter()
                .map(|node| score_snapshot(&inner, "score", &context, node.id, now))
                .collect()
        };
        assert!(
            snapshots[0].failures > 0.0
                && snapshots[0].failures < SCORE_FAILURE_FORGIVENESS_THRESHOLD
        );
        assert!(
            snapshots
                .iter()
                .all(|score| score.completed >= MIN_TRAINED_EVIDENCE)
        );
        let performance = performance_baseline(&snapshots);
        assert!(utility(&snapshots[1], performance) > utility(&snapshots[0], performance));
        assert!(
            utility(&snapshots[1], performance) - utility(&snapshots[0], performance)
                < switch_margin(snapshots[0].completed)
        );

        // When: the scorer ranks the candidates.
        let selected = state.rank_at("score", &context, &node_refs, now);

        // Then: the normal small-gain protection retains the incumbent.
        assert_eq!(selected, 0);
    }

    fn inner_update_response(state: &ScorePolicyState, key: AggregateKey, latency_ms: f64) {
        state
            .inner
            .lock()
            .aggregate
            .get_mut(&key)
            .unwrap()
            .first_response_ms
            .sum = latency_ms * 8.0;
    }

    #[test]
    fn throughput_ignores_bursts_and_pools_dominant_direction() {
        let now = Instant::now();
        let mut stats = Stats::default();
        let sample = |tx, rx, elapsed| FlowSample {
            outcome: ScoreOutcome::Success,
            setup: Some(Duration::from_millis(10)),
            first_response: None,
            tx,
            rx,
            elapsed,
            count_usefulness: true,
            streak_neutral: false,
        };

        stats.record_finish(
            now,
            &sample(10_000_000, 1, Duration::from_millis(999)),
            true,
            1,
        );
        stats.record_finish(now, &sample(65_535, 1, Duration::from_secs(2)), true, 2);
        assert_close(stats.throughput_windows, 0.0);

        stats.record_finish(now, &sample(65_536, 1, Duration::from_secs(1)), true, 3);
        stats.record_finish(now, &sample(1, 131_072, Duration::from_secs(3)), true, 4);

        assert_close(stats.throughput_bytes, 196_608.0);
        assert_close(stats.throughput_seconds, 4.0);
        assert_close(stats.throughput_windows, 2.0);
        let score = snapshot(&stats, now);
        assert_close(score.throughput.unwrap(), 49_152.0);
        assert_close(score.throughput_confidence, 0.25);
    }

    #[test]
    fn stale_exact_metrics_yield_back_to_aggregate_evidence() {
        let now = Instant::now();
        let context = context("example.com", IpVersion::V4);
        let node = node("leaf");
        let mut inner = StateInner::default();
        inner.aggregate.put(
            AggregateKey {
                group: "score".into(),
                network: SelectionNetwork::Tcp,
                family: None,
                node_id: node.id,
            },
            Stats {
                setup_success: 8.0,
                useful_success: 8.0,
                first_response_ms: WeightedMean {
                    sum: 800.0,
                    weight: 8.0,
                },
                updated_at: Some(now),
                ..Default::default()
            },
        );
        inner.exact.put(
            ExactKey {
                group: "score".into(),
                network: SelectionNetwork::Tcp,
                family: IpVersion::V4,
                target: context.target.clone().unwrap(),
                node_id: node.id,
            },
            Stats {
                setup_success: 8.0,
                useful_success: 8.0,
                first_response_ms: WeightedMean {
                    sum: 8_000.0,
                    weight: 8.0,
                },
                updated_at: Some(now),
                ..Default::default()
            },
        );

        let fresh = score_snapshot(&inner, "score", &context, node.id, now);
        assert_close(fresh.latency_ms.unwrap(), 1_000.0);
        assert_close(fresh.latency_confidence, 1.0);

        let aged = score_snapshot(
            &inner,
            "score",
            &context,
            node.id,
            now + Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 3),
        );
        assert_close(aged.latency_ms.unwrap(), 212.5);
        assert_close(aged.latency_confidence, 0.125);
    }

    #[test]
    fn evidence_half_life_decays_every_historical_field() {
        let start = Instant::now();
        let mut stats = Stats {
            incarnation: 7,
            attempts: 8.0,
            setup_success: 6.0,
            setup_failure: 2.0,
            useful_success: 4.0,
            useful_failure: 2.0,
            setup_ms: WeightedMean {
                sum: 800.0,
                weight: 8.0,
            },
            first_response_ms: WeightedMean {
                sum: 600.0,
                weight: 6.0,
            },
            throughput_bytes: 1_000_000.0,
            throughput_seconds: 10.0,
            throughput_windows: 4.0,
            fail_streak: 0,
            explore_not_before: None,
            last_used: 9,
            updated_at: Some(start),
            selected_at: 0,
        };

        stats.decay_to(start + SCORE_EVIDENCE_HALF_LIFE);

        assert_close(stats.attempts, 4.0);
        assert_close(stats.setup_success, 3.0);
        assert_close(stats.setup_failure, 1.0);
        assert_close(stats.useful_success, 2.0);
        assert_close(stats.useful_failure, 1.0);
        assert_close(stats.setup_ms.sum, 400.0);
        assert_close(stats.setup_ms.weight, 4.0);
        assert_close(stats.first_response_ms.sum, 300.0);
        assert_close(stats.first_response_ms.weight, 3.0);
        assert_close(stats.throughput_bytes, 500_000.0);
        assert_close(stats.throughput_seconds, 5.0);
        assert_close(stats.throughput_windows, 2.0);
        assert_eq!(stats.incarnation, 7);
        assert_eq!(stats.last_used, 9);
    }

    #[test]
    fn aged_evidence_reenters_deterministic_cold_exploration() {
        let nodes = [node("a"), node("b")];
        let node_refs = [&nodes[0], &nodes[1]];
        let context = context("example.com", IpVersion::V4);
        let state = ScorePolicyState::default();
        state.publish_membership(nodes.iter().map(|node| ("score".to_string(), node.id)));
        let now = Instant::now();

        for (index, node) in nodes.iter().enumerate() {
            let attributions = [ScoreAttribution {
                group: "score".into(),
                node_id: node.id,
            }];
            let cells = state.start_at(&context, &attributions, now);
            let success = index == 1;
            state.finish_at(
                &context,
                &attributions,
                &cells,
                &FlowSample {
                    outcome: if success {
                        ScoreOutcome::Success
                    } else {
                        ScoreOutcome::Timeout
                    },
                    setup: success.then_some(Duration::from_millis(10)),
                    first_response: success.then_some(Duration::from_millis(20)),
                    tx: u64::from(success),
                    rx: u64::from(success),
                    elapsed: Duration::from_secs(1),
                    count_usefulness: true,
                    streak_neutral: false,
                },
                now,
            );
        }

        assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);
        assert_eq!(
            state.rank_at(
                "score",
                &context,
                &node_refs,
                now + Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 3),
            ),
            0
        );
    }

    #[test]
    fn parsed_score_policy_learns_without_a_feature_flag() {
        let config = honk_config::parser::parse_dae_config(
            r#"
node {
    a: 'socks5://127.0.0.1:10001'
    b: 'socks5://127.0.0.1:10002'
}
group {
    scored {
        policy: score
        filter: name('a', 'b')
    }
}
"#,
        )
        .unwrap();
        let manager = super::super::GroupManager::new(&config.groups, &config.nodes);
        let context = context("example.com", IpVersion::V4);

        let first = manager.selection_plan_for_target("scored", &context);
        assert_eq!(first.entries[0].node.name, "a");
        finish_failure(&first);

        let second = manager.selection_plan_for_target("scored", &context);
        assert_eq!(second.entries[0].node.name, "b");
        finish_success(&second);
        assert_eq!(
            manager
                .selection_plan_for_target("scored", &context)
                .entries[0]
                .node
                .id,
            config.nodes[1].id
        );
    }
    fn node(name: &str) -> Node {
        Node {
            id: Uuid::new_v5(&honk_config::node::NODE_ID_NAMESPACE, name.as_bytes()),
            name: name.into(),
            ..Default::default()
        }
    }

    fn group(name: &str, nodes: &[Node]) -> Group {
        Group {
            id: Uuid::new_v4(),
            name: name.into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        }
    }

    fn group_with_children(name: &str, nodes: &[Node], groups: &[&str]) -> Group {
        Group {
            id: Uuid::new_v4(),
            name: name.into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            groups: groups.iter().map(|group| (*group).to_owned()).collect(),
            ..Default::default()
        }
    }

    fn selector_with_children(name: &str, nodes: &[Node], groups: &[&str]) -> Group {
        Group {
            policy: GroupPolicy::Selector,
            ..group_with_children(name, nodes, groups)
        }
    }

    fn context(host: &str, family: IpVersion) -> ScoreSelectionContext {
        ScoreSelectionContext {
            network: SelectionNetwork::Tcp,
            probe_domain: ProbeDomain::Tcp,
            target_family: Some(family),
            health_family: IpVersion::V4,
            target: Some(ScoreTarget::domain(host, 443)),
        }
    }

    fn trained_stats(successes: f64, latency_ms: f64, now: Instant) -> Stats {
        Stats {
            attempts: successes,
            setup_success: successes,
            useful_success: successes,
            first_response_ms: WeightedMean {
                sum: latency_ms * successes,
                weight: successes,
            },
            updated_at: Some(now),
            ..Default::default()
        }
    }

    fn finish_success(plan: &super::super::ScoreSelectionPlan<'_>) {
        let reporter = plan.entries[0]
            .feedback
            .as_ref()
            .expect("Score candidate must carry feedback")
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);
    }
    fn finish_failure(plan: &super::super::ScoreSelectionPlan<'_>) {
        plan.entries[0]
            .feedback
            .as_ref()
            .expect("Score candidate must carry feedback")
            .start()
            .setup_failed(ScoreOutcome::Timeout);
    }

    fn selected(manager: &super::super::GroupManager, context: &ScoreSelectionContext) -> Uuid {
        manager.selection_plan_for_target("score", context).entries[0]
            .node
            .id
    }

    #[test]
    fn selection_reason_instrumentation_preserves_existing_winners() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("baseline.example", IpVersion::V4);
        let apply = selected(&manager, &target);
        let peek = manager
            .get_score_selection_for_network("score", SelectionNetwork::Tcp)
            .expect("Score group has candidates");

        let singleton = node("singleton");
        let singleton_manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&singleton))],
            std::slice::from_ref(&singleton),
        );
        let singleton_selected = selected(&singleton_manager, &target);

        let last_resort = node("last-resort");
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(last_resort.id, ProbeDomain::Tcp, IpVersion::V4);
        let last_resort_manager = super::super::GroupManager::with_alive_set(
            &[group("score", std::slice::from_ref(&last_resort))],
            std::slice::from_ref(&last_resort),
            Some(alive),
        );
        let last_resort_selected = selected(&last_resort_manager, &target);

        println!(
            "winner baseline apply={apply} peek={peek} singleton={singleton_selected} last_resort={last_resort_selected}"
        );
        assert_eq!(apply, nodes[0].id);
        assert_eq!(peek, nodes[0].name);
        assert_eq!(singleton_selected, singleton.id);
        assert_eq!(last_resort_selected, last_resort.id);
    }

    #[test]
    fn switch_flap_counts_only_quick_committed_reversals() {
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let key = SelectionHistoryKey::new("score", &context);
        let first = node("first").id;
        let second = node("second").id;
        let mut inner = StateInner::default();

        let record = |inner: &mut StateInner, node_id, reason| {
            ScorePolicyState::record_switch_flap(inner, &key, node_id, reason);
        };
        record(&mut inner, first, SelectionReason::PerformanceWinner);
        // Exploration never touches flap history.
        record(&mut inner, second, SelectionReason::PeriodicExplore);
        record(&mut inner, second, SelectionReason::PerformanceWinner);
        // Same-winner selections push the next reversal out of the window.
        for _ in 0..SCORE_SWITCH_FLAP_WINDOW {
            record(&mut inner, second, SelectionReason::PerformanceWinner);
        }
        record(&mut inner, first, SelectionReason::ReliabilityWinner);
        record(&mut inner, second, SelectionReason::PerformanceWinner);

        assert_eq!(
            inner
                .selection_reasons
                .get(&SelectionReasonKey::new("score", SelectionNetwork::Tcp))
                .unwrap()
                .switch_flap,
            1
        );
    }

    #[test]
    fn switch_flap_ignores_cross_target_interleaving() {
        let first = node("first").id;
        let second = node("second").id;
        let mut inner = StateInner::default();
        let key_a = SelectionHistoryKey::new("score", &context("a.example", IpVersion::V4));
        let key_b = SelectionHistoryKey::new("score", &context("b.example", IpVersion::V4));
        let flap_count = |inner: &StateInner| {
            inner
                .selection_reasons
                .get(&SelectionReasonKey::new("score", SelectionNetwork::Tcp))
                .map_or(0, |counts| counts.switch_flap)
        };

        // A→first, B→second, A→first: neither target reversed its own winner.
        for (key, node_id) in [(&key_a, first), (&key_b, second), (&key_a, first)] {
            ScorePolicyState::record_switch_flap(
                &mut inner,
                key,
                node_id,
                SelectionReason::PerformanceWinner,
            );
        }
        assert_eq!(flap_count(&inner), 0);

        // A same-target reversal within the window still counts.
        ScorePolicyState::record_switch_flap(
            &mut inner,
            &key_a,
            second,
            SelectionReason::PerformanceWinner,
        );
        ScorePolicyState::record_switch_flap(
            &mut inner,
            &key_a,
            first,
            SelectionReason::PerformanceWinner,
        );
        assert_eq!(flap_count(&inner), 1);
    }

    #[test]
    fn applied_score_selection_records_switch_flap() {
        let nodes = [node("first"), node("second")];
        let node_refs = [&nodes[0], &nodes[1]];
        let state = ScorePolicyState::default();
        state.publish_membership(nodes.iter().map(|node| ("score".to_owned(), node.id)));
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let now = Instant::now();
        let keys = nodes.each_ref().map(|node| AggregateKey {
            group: "score".to_owned(),
            network: SelectionNetwork::Tcp,
            family: None,
            node_id: node.id,
        });
        {
            let mut inner = state.inner.lock();
            inner
                .aggregate
                .put(keys[0].clone(), trained_stats(8.0, 50.0, now));
            inner
                .aggregate
                .put(keys[1].clone(), trained_stats(8.0, 200.0, now));
        }
        assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);

        inner_update_response(&state, keys[0].clone(), 200.0);
        inner_update_response(&state, keys[1].clone(), 50.0);
        assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);

        inner_update_response(&state, keys[0].clone(), 50.0);
        inner_update_response(&state, keys[1].clone(), 200.0);
        assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);
        assert_eq!(
            state
                .selection_reason_counts("score", SelectionNetwork::Tcp)
                .switch_flap,
            1
        );
    }

    #[test]
    fn score_reload_prunes_removed_switch_history_members() {
        let state = ScorePolicyState::default();
        let first = node("first").id;
        let second = node("second").id;
        state.publish_membership([("score".to_owned(), first), ("score".to_owned(), second)]);
        let removed_key =
            SelectionHistoryKey::new("score", &context("removed.example", IpVersion::V4));
        let retained_key =
            SelectionHistoryKey::new("score", &context("retained.example", IpVersion::V6));
        {
            let mut inner = state.inner.lock();
            inner.selection_history.push(
                removed_key.clone(),
                SelectionHistory {
                    current: first,
                    previous: Some(second),
                    selections: 1,
                    switched_at: 1,
                },
            );
            inner.selection_history.push(
                retained_key.clone(),
                SelectionHistory {
                    current: second,
                    previous: Some(first),
                    selections: 1,
                    switched_at: 1,
                },
            );
        }

        state.publish_membership([("score".to_owned(), second)]);

        let inner = state.inner.lock();
        assert!(!inner.selection_history.contains(&removed_key));
        assert_eq!(
            inner
                .selection_history
                .peek(&retained_key)
                .unwrap()
                .previous,
            None
        );
    }

    #[test]
    fn selection_reason_precedence_is_stable() {
        let state = ScorePolicyState::default();
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let now = Instant::now();
        let cold = [node("cold-a"), node("cold-b")];
        let periodic: Vec<_> = (0..8)
            .map(|index| node(&format!("periodic-{index}")))
            .collect();
        let held = [node("held-a"), node("held-b")];
        let bypass = [node("bypass-a"), node("bypass-b")];
        let reliable = [node("reliable-a"), node("reliable-b")];
        let performance = [node("performance-a"), node("performance-b")];
        let memberships = [
            ("cold", cold.as_slice()),
            ("periodic", periodic.as_slice()),
            ("held", held.as_slice()),
            ("bypass", bypass.as_slice()),
            ("reliable", reliable.as_slice()),
            ("performance", performance.as_slice()),
        ];
        state.publish_membership(
            memberships
                .iter()
                .flat_map(|(group, nodes)| nodes.iter().map(|node| ((*group).to_owned(), node.id))),
        );
        {
            let mut inner = state.inner.lock();
            for (index, node) in periodic.iter().enumerate() {
                inner.aggregate.put(
                    AggregateKey {
                        group: "periodic".into(),
                        network: SelectionNetwork::Tcp,
                        family: None,
                        node_id: node.id,
                    },
                    Stats {
                        selected_at: u64::from(index == 0),
                        ..trained_stats(8.0, 100.0, now)
                    },
                );
            }
            inner.selection_counts.insert(
                SelectionCadenceKey::new("periodic", &context),
                exploration_period(periodic.len()) - 1,
            );
            for (group, nodes, stats) in [
                (
                    "held",
                    held.as_slice(),
                    [
                        Stats {
                            selected_at: 1,
                            ..trained_stats(8.0, 100.0, now)
                        },
                        trained_stats(8.0, 99.0, now),
                    ],
                ),
                (
                    "bypass",
                    bypass.as_slice(),
                    [
                        Stats {
                            attempts: 257.0,
                            useful_failure: 1.0,
                            selected_at: 1,
                            ..trained_stats(256.0, 100.0, now)
                        },
                        trained_stats(256.0, 100.0, now),
                    ],
                ),
                (
                    "reliable",
                    reliable.as_slice(),
                    [
                        trained_stats(8.0, 100.0, now),
                        Stats {
                            attempts: 8.0,
                            useful_failure: 4.0,
                            ..trained_stats(4.0, 50.0, now)
                        },
                    ],
                ),
                (
                    "performance",
                    performance.as_slice(),
                    [
                        trained_stats(8.0, 200.0, now),
                        trained_stats(8.0, 50.0, now),
                    ],
                ),
            ] {
                for (node, stats) in nodes.iter().zip(stats) {
                    inner.aggregate.put(
                        AggregateKey {
                            group: group.into(),
                            network: SelectionNetwork::Tcp,
                            family: None,
                            node_id: node.id,
                        },
                        stats,
                    );
                }
            }
        }

        let winners = [
            (
                "cold",
                state.rank_at("cold", &context, &cold.iter().collect::<Vec<_>>(), now),
            ),
            (
                "periodic",
                state.rank_at(
                    "periodic",
                    &context,
                    &periodic.iter().collect::<Vec<_>>(),
                    now,
                ),
            ),
            (
                "held",
                state.rank_at("held", &context, &held.iter().collect::<Vec<_>>(), now),
            ),
            (
                "bypass",
                state.rank_at("bypass", &context, &bypass.iter().collect::<Vec<_>>(), now),
            ),
            (
                "reliable",
                state.rank_at(
                    "reliable",
                    &context,
                    &reliable.iter().collect::<Vec<_>>(),
                    now,
                ),
            ),
            (
                "performance",
                state.rank_at(
                    "performance",
                    &context,
                    &performance.iter().collect::<Vec<_>>(),
                    now,
                ),
            ),
        ];
        assert_eq!(
            winners,
            [
                ("cold", 0),
                ("periodic", 1),
                ("held", 0),
                ("bypass", 1),
                ("reliable", 0),
                ("performance", 1)
            ]
        );

        let expected = [
            (
                "cold",
                SelectionReasonCounts {
                    cold_explore: 1,
                    ..Default::default()
                },
            ),
            (
                "periodic",
                SelectionReasonCounts {
                    periodic_explore: 1,
                    ..Default::default()
                },
            ),
            (
                "held",
                SelectionReasonCounts {
                    incumbent_held: 1,
                    ..Default::default()
                },
            ),
            (
                "bypass",
                SelectionReasonCounts {
                    fresh_failure_bypass: 1,
                    ..Default::default()
                },
            ),
            (
                "reliable",
                SelectionReasonCounts {
                    reliability_winner: 1,
                    ..Default::default()
                },
            ),
            (
                "performance",
                SelectionReasonCounts {
                    performance_winner: 1,
                    ..Default::default()
                },
            ),
        ];
        println!("winner table={winners:?}");
        for (group, counts) in expected {
            assert_eq!(
                state.selection_reason_counts(group, SelectionNetwork::Tcp),
                counts
            );
        }
    }

    #[test]
    fn selection_reason_counting_respects_apply_and_filter_boundaries() {
        let dead = node("dead");
        let live = [node("live-a"), node("live-b")];
        let all_nodes = [dead.clone(), live[0].clone(), live[1].clone()];
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(dead.id, ProbeDomain::Tcp, IpVersion::V4);
        let groups = [
            selector_with_children("dead-path", std::slice::from_ref(&dead), &[]),
            group_with_children("target-top", &all_nodes, &["dead-path"]),
            group("target-child", &all_nodes),
            selector_with_children("target-parent", &[], &["target-child"]),
            group("aggregate-top", &all_nodes),
            group("aggregate-child", &all_nodes),
            selector_with_children("aggregate-parent", &[], &["aggregate-child"]),
            group("singleton", std::slice::from_ref(&live[0])),
            group("last-resort", std::slice::from_ref(&dead)),
        ];
        let manager = super::super::GroupManager::with_alive_set(
            &groups,
            &all_nodes,
            Some(Arc::clone(&alive)),
        );
        let target = context("boundaries.example", IpVersion::V4);

        let _ = manager.selection_plan_for_target("target-top", &target);
        let _ = manager.selection_plan_for_target("target-parent", &target);
        let _ = manager.selection_plan_for_domain("aggregate-top", ProbeDomain::Tcp, IpVersion::V4);
        let _ =
            manager.selection_plan_for_domain("aggregate-parent", ProbeDomain::Tcp, IpVersion::V4);
        let mut udp_target = target.clone();
        udp_target.network = SelectionNetwork::Udp;
        udp_target.probe_domain = ProbeDomain::DataUdp;
        let _ = manager.selection_plan_for_target("target-top", &udp_target);
        let _ = manager.selection_plan_for_domain(
            "aggregate-parent",
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
        let _ = manager.selection_plan_for_target("singleton", &target);
        let _ = manager.selection_plan_for_target("last-resort", &target);
        let state = manager.score_state();
        let applied = [
            ("target-top", 1, 1),
            ("target-child", 1, 1),
            ("aggregate-top", 1, 1),
            ("aggregate-child", 1, 1),
        ];
        for (group, cold_explore, dead_filtered) in applied {
            let counts = state.selection_reason_counts(group, SelectionNetwork::Tcp);
            assert_eq!(counts.cold_explore, cold_explore);
            assert_eq!(counts.dead_filtered, dead_filtered);
            assert_eq!(
                counts.periodic_explore
                    + counts.reliability_winner
                    + counts.performance_winner
                    + counts.incumbent_held
                    + counts.fresh_failure_bypass,
                0
            );
        }
        for group in ["target-top", "aggregate-child"] {
            assert_eq!(
                state.selection_reason_counts(group, SelectionNetwork::Udp),
                SelectionReasonCounts {
                    cold_explore: 1,
                    dead_filtered: 1,
                    ..Default::default()
                }
            );
        }
        assert_eq!(
            state.selection_reason_counts("singleton", SelectionNetwork::Tcp),
            SelectionReasonCounts::default()
        );
        assert_eq!(
            state.selection_reason_counts("last-resort", SelectionNetwork::Tcp),
            SelectionReasonCounts {
                dead_filtered: 1,
                ..Default::default()
            }
        );

        let before_peek = state.inner.lock().selection_reasons.clone();
        let _ = manager.get_score_selection_for_network("target-top", SelectionNetwork::Tcp);
        let _ = manager.get_score_selection_for_network("target-parent", SelectionNetwork::Tcp);
        let _ = manager.peek_selection_plan_for_domain(
            "aggregate-top",
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let _ = manager.peek_selection_plan_for_domain(
            "aggregate-parent",
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        assert_eq!(state.inner.lock().selection_reasons, before_peek);
        {
            let inner = state.inner.lock();
            assert!(inner.selection_reasons.len() <= inner.valid_groups.len() * 2);
        }

        let stale_group = group("stale", &all_nodes);
        let stale = super::super::GroupManager::with_alive_set(
            std::slice::from_ref(&stale_group),
            &all_nodes,
            Some(Arc::clone(&alive)),
        );
        let stale_state = stale.score_state();
        let deleted = super::super::GroupManager::with_alive_set_and_score_state(
            &[],
            &all_nodes,
            Some(Arc::clone(&alive)),
            Arc::clone(&stale_state),
        );
        deleted.publish_score_membership();
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&stale_group),
            &all_nodes,
            Some(alive),
            Arc::clone(&stale_state),
        );
        replacement.publish_score_membership();
        let _ = stale.selection_plan_for_target("stale", &target);
        assert_eq!(
            stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
            SelectionReasonCounts::default()
        );
        let _ = replacement.selection_plan_for_target("stale", &target);
        assert_eq!(
            stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
            SelectionReasonCounts {
                cold_explore: 1,
                dead_filtered: 1,
                ..Default::default()
            }
        );

        let saturated = SelectionReasonCounts {
            cold_explore: u64::MAX,
            periodic_explore: u64::MAX,
            reliability_winner: u64::MAX,
            performance_winner: u64::MAX,
            incumbent_held: u64::MAX,
            fresh_failure_bypass: u64::MAX,
            dead_filtered: u64::MAX,
            switch_flap: u64::MAX,
            fail_streak_excluded: u64::MAX,
            explore_backed_off: u64::MAX,
        };
        stale_state.inner.lock().selection_reasons.insert(
            SelectionReasonKey::new("stale", SelectionNetwork::Tcp),
            saturated,
        );
        let _ = replacement.selection_plan_for_target("stale", &target);
        assert_eq!(
            stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
            saturated
        );
        {
            let inner = stale_state.inner.lock();
            assert!(inner.selection_reasons.len() <= inner.valid_groups.len() * 2);
        }
        println!(
            "counter table target-top-tcp={:?} target-top-udp={:?} target-child-tcp={:?} aggregate-top-tcp={:?} aggregate-child-tcp={:?} aggregate-child-udp={:?} singleton={:?} last-resort={:?} stale={:?}",
            state.selection_reason_counts("target-top", SelectionNetwork::Tcp),
            state.selection_reason_counts("target-top", SelectionNetwork::Udp),
            state.selection_reason_counts("target-child", SelectionNetwork::Tcp),
            state.selection_reason_counts("aggregate-top", SelectionNetwork::Tcp),
            state.selection_reason_counts("aggregate-child", SelectionNetwork::Tcp),
            state.selection_reason_counts("aggregate-child", SelectionNetwork::Udp),
            state.selection_reason_counts("singleton", SelectionNetwork::Tcp),
            state.selection_reason_counts("last-resort", SelectionNetwork::Tcp),
            stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
        );
    }

    #[test]
    fn nested_score_groups_count_reasons_independently() {
        let nodes = [node("parent-direct"), node("child-a"), node("child-b")];
        let child = group("child", &nodes[1..]);
        let parent = group_with_children("parent", std::slice::from_ref(&nodes[0]), &["child"]);
        let manager = super::super::GroupManager::new(&[child, parent], &nodes);
        let target = context("nested-reasons.example", IpVersion::V4);

        let selected = manager.selection_plan_for_target("parent", &target).entries[0]
            .node
            .id;
        let state = manager.score_state();
        let child_counts = state.selection_reason_counts("child", SelectionNetwork::Tcp);
        let parent_counts = state.selection_reason_counts("parent", SelectionNetwork::Tcp);
        println!("nested winner={selected} child={child_counts:?} parent={parent_counts:?}");
        assert_eq!(selected, nodes[0].id);
        assert_eq!(child_counts.cold_explore, 1);
        assert_eq!(parent_counts.cold_explore, 1);
        assert_eq!(child_counts.dead_filtered, 0);
        assert_eq!(parent_counts.dead_filtered, 0);
    }

    #[test]
    fn private_reason_counts_follow_committed_name_lifecycle() {
        let nodes = [node("lifecycle-a"), node("lifecycle-b")];
        let score = group("lifecycle", &nodes);
        let manager = super::super::GroupManager::new(std::slice::from_ref(&score), &nodes);
        let state = manager.score_state();
        let target = context("private-lifecycle.example", IpVersion::V4);
        let _ = manager.selection_plan_for_target("lifecycle", &target);
        let recorded = state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp);
        assert_eq!(recorded.cold_explore, 1);

        let selector = Group {
            policy: GroupPolicy::Selector,
            ..score.clone()
        };
        let hidden = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&selector),
            &nodes,
            None,
            Arc::clone(&state),
        );
        hidden.publish_score_membership();
        assert_eq!(
            state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp),
            recorded
        );

        let restored = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&score),
            &nodes,
            None,
            Arc::clone(&state),
        );
        restored.publish_score_membership();
        assert_eq!(
            state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp),
            recorded
        );

        let deleted = super::super::GroupManager::with_alive_set_and_score_state(
            &[],
            &nodes,
            None,
            Arc::clone(&state),
        );
        deleted.publish_score_membership();
        let recreated = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&score),
            &nodes,
            None,
            Arc::clone(&state),
        );
        recreated.publish_score_membership();
        let reset = state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp);
        println!(
            "private lifecycle recorded={recorded:?} hidden={recorded:?} restored={recorded:?} recreated={reset:?}"
        );
        assert_eq!(reset, SelectionReasonCounts::default());
    }

    #[test]
    fn score_reason_snapshot_is_sorted_fixed_and_private() {
        let nodes = [node("private-node-alpha"), node("private-node-beta")];
        let groups = [
            group("z-score", &nodes),
            Group {
                name: "hidden-selector".into(),
                policy: GroupPolicy::Selector,
                nodes: nodes.iter().map(|node| node.id).collect(),
                ..Default::default()
            },
            group("a-score", &nodes),
        ];
        let manager = super::super::GroupManager::new(&groups, &nodes);
        let mut tcp_target = context("private-target.internal", IpVersion::V4);
        let _ = manager.selection_plan_for_target("z-score", &tcp_target);
        tcp_target.network = SelectionNetwork::Udp;
        tcp_target.probe_domain = ProbeDomain::DataUdp;
        let _ = manager.selection_plan_for_target("a-score", &tcp_target);

        let state = manager.score_state();
        let before_read = state.inner.lock().selection_reasons.clone();
        let snapshot = manager.score_reason_snapshot();
        assert_eq!(state.inner.lock().selection_reasons, before_read);
        assert_eq!(
            snapshot
                .iter()
                .map(|group| group.name.as_str())
                .collect::<Vec<_>>(),
            ["a-score", "z-score"]
        );
        assert_eq!(
            snapshot[0].udp,
            ScoreReasonCounters {
                cold_explore: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            snapshot[1].tcp,
            ScoreReasonCounters {
                cold_explore: 1,
                ..Default::default()
            }
        );
        assert_eq!(snapshot[0].tcp, ScoreReasonCounters::default());
        assert_eq!(snapshot[1].udp, ScoreReasonCounters::default());

        let debug = format!("{snapshot:?}");
        assert!(!debug.contains("private-node-alpha"));
        assert!(!debug.contains("private-node-beta"));
        assert!(!debug.contains("private-target.internal"));
        let ScoreReasonCounters {
            cold_explore: _,
            periodic_explore: _,
            reliability_winner: _,
            performance_winner: _,
            incumbent_held: _,
            fresh_failure_bypass: _,
            dead_filtered: _,
            switch_flap: _,
            fail_streak_excluded: _,
            explore_backed_off: _,
        } = snapshot[0].tcp;

        let _ = manager.selection_plan_for_target(
            "z-score",
            &context("private-target.internal", IpVersion::V4),
        );
        let later = manager.score_reason_snapshot();
        assert_eq!(snapshot[1].tcp.cold_explore, 1);
        assert_eq!(later[1].tcp.cold_explore, 2);

        let saturated = SelectionReasonCounts {
            cold_explore: u64::MAX,
            periodic_explore: u64::MAX,
            reliability_winner: u64::MAX,
            performance_winner: u64::MAX,
            incumbent_held: u64::MAX,
            fresh_failure_bypass: u64::MAX,
            dead_filtered: u64::MAX,
            switch_flap: u64::MAX,
            fail_streak_excluded: u64::MAX,
            explore_backed_off: u64::MAX,
        };
        state.inner.lock().selection_reasons.insert(
            SelectionReasonKey::new("z-score", SelectionNetwork::Udp),
            saturated,
        );
        let saturated_snapshot = manager.score_reason_snapshot();
        assert_eq!(
            saturated_snapshot[1].udp,
            ScoreReasonCounters::from_private(saturated)
        );
        println!(
            "owned score snapshot={snapshot:?} later={later:?} saturated={saturated_snapshot:?}"
        );
    }

    #[test]
    fn delay_test_members_do_not_record_score_selection() {
        let nodes = [node("delay-peek-alpha"), node("delay-peek-beta")];
        let sub = group("delay-peek-sub", &nodes);
        let parent = Group {
            id: Uuid::new_v4(),
            name: "delay-peek-parent".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![],
            groups: vec!["delay-peek-sub".into()],
            ..Default::default()
        };
        let manager = super::super::GroupManager::new(&[parent, sub], &nodes);

        let members = manager.delay_test_members("delay-peek-parent");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].0, "delay-peek-sub");

        let state = manager.score_state();
        assert_eq!(
            state.selection_reason_counts("delay-peek-sub", SelectionNetwork::Tcp),
            SelectionReasonCounts::default()
        );
        assert!(state.inner.lock().selection_history.is_empty());
    }

    #[test]
    fn score_reason_snapshot_reload_policy_is_name_based() {
        let nodes = [node("private-reload-alpha"), node("private-reload-beta")];
        let score = group("persist", &nodes);
        let manager = super::super::GroupManager::new(std::slice::from_ref(&score), &nodes);
        let state = manager.score_state();
        let target = context("private-reload-target.internal", IpVersion::V4);
        let _ = manager.selection_plan_for_target("persist", &target);
        let recorded = manager.score_reason_snapshot();
        assert_eq!(recorded[0].tcp.cold_explore, 1);

        let selector = Group {
            policy: GroupPolicy::Selector,
            ..score.clone()
        };
        let hidden = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&selector),
            &nodes,
            None,
            Arc::clone(&state),
        );
        hidden.publish_score_membership();
        assert!(hidden.score_reason_snapshot().is_empty());
        let _ = manager.selection_plan_for_target("persist", &target);
        assert_eq!(
            state.selection_reason_counts("persist", SelectionNetwork::Tcp),
            SelectionReasonCounts {
                cold_explore: 1,
                ..Default::default()
            }
        );

        let empty_score = group("persist", &[]);
        let restored = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&empty_score),
            &nodes,
            None,
            Arc::clone(&state),
        );
        restored.publish_score_membership();
        assert_eq!(restored.score_reason_snapshot(), recorded);

        let deleted = super::super::GroupManager::with_alive_set_and_score_state(
            &[],
            &nodes,
            None,
            Arc::clone(&state),
        );
        deleted.publish_score_membership();
        let recreated = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&score),
            &nodes,
            None,
            Arc::clone(&state),
        );
        recreated.publish_score_membership();
        let reset = recreated.score_reason_snapshot();
        assert_eq!(reset[0].tcp, ScoreReasonCounters::default());
        let _ = manager.selection_plan_for_target("persist", &target);
        assert_eq!(recreated.score_reason_snapshot(), reset);
        let _ = recreated.selection_plan_for_target("persist", &target);
        let current = recreated.score_reason_snapshot();
        assert_eq!(current[0].tcp.cold_explore, 1);

        let empty = super::super::GroupManager::new(&[], &nodes);
        assert!(empty.score_reason_snapshot().is_empty());
        println!(
            "snapshot lifecycle recorded={recorded:?} hidden=[] restored={recorded:?} recreated={reset:?} current={current:?}"
        );
    }

    #[test]
    fn normalizes_domain_key_and_keeps_target_dimensions_independent() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);

        let a = context("EXAMPLE.COM.", IpVersion::V4);
        finish_success(&manager.selection_plan_for_target("score", &a));
        let normalized = context("example.com", IpVersion::V4);
        assert!(
            manager
                .score_state()
                .has_exact("score", &normalized, nodes[0].id)
        );
        assert!(!manager.score_state().has_exact(
            "score",
            &context("example.com", IpVersion::V6),
            nodes[0].id,
        ));
        assert!(!manager.score_state().has_exact(
            "score",
            &context("other.example", IpVersion::V4),
            nodes[0].id,
        ));
    }

    #[test]
    fn cold_exploration_is_deterministic_and_cancelled_loser_is_neutral() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("example.com", IpVersion::V4);
        let first = manager.selection_plan_for_target("score", &context);
        assert_eq!(first.entries[0].node.id, nodes[0].id);
        drop(first.entries[0].feedback.as_ref().unwrap().start());
        assert_eq!(
            manager.selection_plan_for_target("score", &context).entries[0]
                .node
                .id,
            nodes[0].id
        );
        finish_success(&manager.selection_plan_for_target("score", &context));
        assert_eq!(
            manager.selection_plan_for_target("score", &context).entries[0]
                .node
                .id,
            nodes[1].id,
            "the first useful success must release the next cold candidate"
        );
    }

    #[test]
    fn cancelled_exact_attempt_does_not_hide_aggregate_failure() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        manager
            .feedback_for_group_node(
                "score",
                nodes[0].id,
                ScoreSelectionContext::aggregate(
                    SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .unwrap()
            .start()
            .setup_failed(ScoreOutcome::Timeout);

        let context = context("cancelled.example", IpVersion::V4);
        drop(
            manager
                .feedback_for_group_node("score", nodes[0].id, context.clone())
                .unwrap()
                .start(),
        );

        assert!(
            !manager
                .score_state()
                .has_exact("score", &context, nodes[0].id)
        );
        assert_eq!(selected(&manager, &context), nodes[1].id);
    }

    #[test]
    fn reload_reuses_state_and_prunes_removed_members() {
        let nodes = [node("a"), node("b")];
        let old = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("example.com", IpVersion::V4);
        finish_success(&old.selection_plan_for_target("score", &context));
        let state = old.score_state();
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
            &[group("score", &nodes[1..])],
            &nodes[1..],
            None,
            Arc::clone(&state),
        );
        replacement.publish_score_membership();
        assert!(!state.has_exact("score", &context, nodes[0].id));
    }

    #[test]
    fn nested_score_groups_keep_the_target_and_complete_attribution_path() {
        let nodes = [node("a"), node("b")];
        let child = group("child", &nodes);
        let mut parent = group("parent", &[]);
        parent.groups.push("child".into());
        let manager = super::super::GroupManager::new(&[child, parent], &nodes);
        let context = context("example.com", IpVersion::V6);

        let plan = manager.selection_plan_for_target("parent", &context);
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].selection_chain, ["parent", "child", "a"]);
        let feedback = plan.entries[0].feedback.as_ref().unwrap();
        assert_eq!(
            feedback
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["parent", "child"]
        );
        finish_success(&plan);
        for group in ["parent", "child"] {
            assert!(
                manager
                    .score_state()
                    .has_exact(group, &context, nodes[0].id)
            );
        }
    }

    #[test]
    fn feedback_for_node_merges_nested_score_memberships_once() {
        let leaf = node("leaf");
        let other = node("other");
        let child = group("child", std::slice::from_ref(&leaf));
        let mut bridge = group("bridge", std::slice::from_ref(&leaf));
        bridge.policy = GroupPolicy::Selector;
        let mut parent = group("parent", std::slice::from_ref(&leaf));
        parent.groups = vec!["child".into(), "bridge".into()];
        let manager = super::super::GroupManager::new(
            &[
                child,
                bridge,
                parent,
                group("unrelated", std::slice::from_ref(&other)),
            ],
            &[leaf.clone(), other],
        );

        let feedback = manager
            .feedback_for_node(
                leaf.id,
                ScoreSelectionContext::aggregate(
                    SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .expect("nested Honk memberships must produce feedback");
        let mut groups = feedback
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>();
        groups.sort_unstable();
        assert_eq!(groups, ["child", "parent"]);
    }
    #[test]
    fn nested_score_last_resort_keeps_child_attribution() {
        let leaf = node("leaf");
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
        let child = group("child", std::slice::from_ref(&leaf));
        let mut parent = group("parent", &[]);
        parent.groups.push(child.name.clone());
        let manager = super::super::GroupManager::with_alive_set(
            &[child, parent],
            std::slice::from_ref(&leaf),
            Some(alive),
        );
        let plan = manager
            .selection_plan_for_target("parent", &context("last-resort.example", IpVersion::V4));
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(
            plan.entries[0]
                .feedback
                .as_ref()
                .unwrap()
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["parent", "child"]
        );
    }

    #[test]
    fn deep_score_last_resort_keeps_every_attribution() {
        let leaf = node("leaf");
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
        let child = group("child", std::slice::from_ref(&leaf));
        let mut middle = group("middle", &[]);
        middle.groups.push(child.name.clone());
        let mut outer = group("outer", &[]);
        outer.groups.push(middle.name.clone());
        let manager = super::super::GroupManager::with_alive_set(
            &[child, middle, outer],
            std::slice::from_ref(&leaf),
            Some(alive),
        );

        let plan =
            manager.selection_plan_for_target("outer", &context("deep.example", IpVersion::V4));
        assert_eq!(
            plan.entries[0].selection_chain,
            ["outer", "middle", "child", "leaf"]
        );
        assert_eq!(
            plan.entries[0]
                .feedback
                .as_ref()
                .unwrap()
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["outer", "middle", "child"]
        );
    }

    #[test]
    fn duplicate_direct_leaf_stays_direct_on_last_resort() {
        let leaf = node("leaf");
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
        let child = group("child", std::slice::from_ref(&leaf));
        let mut parent = group("parent", std::slice::from_ref(&leaf));
        parent.groups.push(child.name.clone());
        let manager = super::super::GroupManager::with_alive_set(
            &[child, parent],
            std::slice::from_ref(&leaf),
            Some(alive),
        );

        let plan = manager
            .selection_plan_for_target("parent", &context("last-resort.example", IpVersion::V4));
        assert_eq!(plan.entries[0].selection_chain, ["parent", "leaf"]);
        assert_eq!(
            plan.entries[0]
                .feedback
                .as_ref()
                .unwrap()
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["parent"]
        );
    }

    #[test]
    fn duplicate_leaf_paths_do_not_change_score_rank() {
        let nodes = [node("a"), node("b")];
        let mut bridge = group("bridge", std::slice::from_ref(&nodes[0]));
        bridge.policy = GroupPolicy::Selector;
        let mut parent = group("score", &nodes);
        parent.groups.push(bridge.name.clone());
        let manager = super::super::GroupManager::new(&[parent, bridge], &nodes);
        let context = context("duplicate.example", IpVersion::V4);
        finish_failure(&manager.selection_plan_for_target("score", &context));
        assert_eq!(selected(&manager, &context), nodes[1].id);
    }

    #[test]
    fn aggregate_feedback_completion_and_cancellation_are_accounted_once() {
        let leaf = node("leaf");
        let manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&leaf))],
            std::slice::from_ref(&leaf),
        );
        let feedback = manager
            .feedback_for_node(
                leaf.id,
                ScoreSelectionContext::aggregate(
                    SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .unwrap();

        drop(feedback.start());
        assert_eq!(
            manager
                .score_state()
                .aggregate_stats("score", SelectionNetwork::Tcp, leaf.id),
            None
        );
        let reporter = feedback.start();
        reporter.setup_succeeded();
        reporter.finish(ScoreOutcome::Success);
        assert_eq!(
            manager
                .score_state()
                .aggregate_stats("score", SelectionNetwork::Tcp, leaf.id),
            Some((1, 1, 0))
        );
    }

    #[test]
    fn setup_only_success_does_not_become_usefulness_failure() {
        let leaf = node("leaf");
        let manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&leaf))],
            std::slice::from_ref(&leaf),
        );
        let context = context("prepared.example", IpVersion::V4);
        let feedback = manager.selection_plan_for_target("score", &context).entries[0]
            .feedback
            .clone()
            .unwrap();
        let reporter = feedback.start();
        reporter.setup_succeeded();
        reporter.finish_setup_only();
        assert_eq!(
            manager
                .score_state()
                .exact_useful_failures("score", &context, leaf.id),
            Some(0)
        );

        let related = reporter.feedback().start();
        related.setup_succeeded();
        related.finish_setup_only();

        assert_eq!(
            manager
                .score_state()
                .exact_useful_failures("score", &context, leaf.id),
            Some(0)
        );
    }

    #[test]
    fn setup_only_exact_samples_keep_aggregate_reliability() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        for index in 0..8 {
            let reporter = manager
                .feedback_for_group_node(
                    "score",
                    nodes[0].id,
                    context(&format!("a-{index}.example"), IpVersion::V4),
                )
                .unwrap()
                .start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }
        let reporter = manager
            .feedback_for_group_node("score", nodes[1].id, context("b.example", IpVersion::V4))
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);

        let target = context("prepared.example", IpVersion::V4);
        for _ in 0..8 {
            let reporter = manager
                .feedback_for_group_node("score", nodes[0].id, target.clone())
                .unwrap()
                .start();
            reporter.setup_succeeded();
            reporter.finish_setup_only();
        }

        assert_eq!(selected(&manager, &target), nodes[0].id);
    }

    #[test]
    fn setup_only_family_samples_keep_global_reliability() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        for index in 0..8 {
            let reporter = manager
                .feedback_for_group_node(
                    "score",
                    nodes[0].id,
                    context(&format!("a-{index}.example"), IpVersion::V6),
                )
                .unwrap()
                .start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }
        let reporter = manager
            .feedback_for_group_node("score", nodes[1].id, context("b.example", IpVersion::V6))
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);

        let reporter = manager
            .feedback_for_group_node(
                "score",
                nodes[0].id,
                context("prepared.example", IpVersion::V4),
            )
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.finish_setup_only();

        assert_eq!(
            selected(&manager, &context("fresh.example", IpVersion::V4)),
            nodes[0].id
        );
    }

    #[test]
    fn compact_outcome_finds_nested_io_errors() {
        let error = anyhow::Error::new(io::Error::new(io::ErrorKind::TimedOut, "secret target"))
            .context("outer context");
        assert_eq!(ScoreOutcome::from_error(&error), ScoreOutcome::Timeout);
    }

    #[test]
    fn exact_cache_has_a_hard_lru_bound() {
        let node = node("a");
        let manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&node))],
            std::slice::from_ref(&node),
        );
        for index in 0..=EXACT_CAPACITY {
            finish_success(&manager.selection_plan_for_target(
                "score",
                &context(&format!("{index}.example"), IpVersion::V4),
            ));
        }
        assert_eq!(manager.score_state().exact_len(), EXACT_CAPACITY);
    }

    #[test]
    fn setup_failure_switches_to_the_other_candidate() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("failure.example", IpVersion::V4);

        assert_eq!(selected(&manager, &context), nodes[0].id);
        finish_failure(&manager.selection_plan_for_target("score", &context));
        assert_eq!(selected(&manager, &context), nodes[1].id);
    }

    #[test]
    fn inflight_exact_attempt_does_not_mask_aggregate_reliability() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let aggregate = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        manager
            .feedback_for_group_node("score", nodes[0].id, aggregate.clone())
            .unwrap()
            .start()
            .setup_failed(ScoreOutcome::Other);
        let good = manager
            .feedback_for_group_node("score", nodes[1].id, aggregate)
            .unwrap()
            .start();
        good.setup_succeeded();
        good.finish_setup_only();
        let target = context("inflight.example", IpVersion::V4);
        let inflight = manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .start();

        assert_eq!(selected(&manager, &target), nodes[1].id);

        drop(inflight);
    }

    #[test]
    fn network_target_and_family_buckets_are_isolated() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let tcp_a_v4 = context("a.example", IpVersion::V4);
        finish_failure(&manager.selection_plan_for_target("score", &tcp_a_v4));

        let mut udp_a_v4 = tcp_a_v4.clone();
        udp_a_v4.network = SelectionNetwork::Udp;
        udp_a_v4.probe_domain = ProbeDomain::DataUdp;
        let tcp_b_v4 = context("b.example", IpVersion::V4);
        let tcp_a_v6 = context("a.example", IpVersion::V6);
        let state = manager.score_state();

        assert_eq!(
            state.exact_stats("score", &tcp_a_v4, nodes[0].id),
            Some((1, 0, 1))
        );
        for untouched in [&udp_a_v4, &tcp_b_v4, &tcp_a_v6] {
            assert_eq!(state.exact_stats("score", untouched, nodes[0].id), None);
        }
        finish_success(&manager.selection_plan_for_target("score", &tcp_b_v4));
        assert_eq!(
            state.exact_stats("score", &tcp_b_v4, nodes[1].id),
            Some((1, 1, 0))
        );
        assert_eq!(state.exact_stats("score", &tcp_a_v4, nodes[1].id), None);
    }

    #[test]
    fn dead_candidate_is_excluded_before_scoring() {
        let nodes = [node("a"), node("b")];
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(nodes[0].id, ProbeDomain::Tcp, IpVersion::V4);
        let manager = super::super::GroupManager::with_alive_set(
            &[group("score", &nodes)],
            &nodes,
            Some(alive),
        );

        assert_eq!(
            selected(&manager, &context("dead.example", IpVersion::V4)),
            nodes[1].id
        );
    }

    #[test]
    fn aggregate_cache_has_a_hard_lru_bound() {
        let state = ScorePolicyState::default();
        let node_id = node("a").id;
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let memberships: Vec<_> = (0..=AGGREGATE_CAPACITY)
            .map(|index| (format!("group-{index}"), node_id))
            .collect();
        state.publish_membership(memberships.iter().cloned());
        for (group, node_id) in memberships {
            drop(state.start(&context, &[ScoreAttribution { group, node_id }]));
        }
        assert_eq!(state.inner.lock().aggregate.len(), AGGREGATE_CAPACITY);
        assert_eq!(state.inner.lock().aggregate_evictions, 1);
        assert_eq!(state.inner.lock().exact_evictions, 0);
    }

    #[test]
    fn stale_exact_completion_does_not_mutate_recreated_cell() {
        let node = node("a");
        let manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&node))],
            std::slice::from_ref(&node),
        );
        let evicted = context("evicted.example", IpVersion::V4);
        let reporter = manager.selection_plan_for_target("score", &evicted).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        for index in 0..EXACT_CAPACITY {
            let context = context(&format!("{index}.example"), IpVersion::V4);
            finish_success(&manager.selection_plan_for_target("score", &context));
        }
        let replacement = manager.selection_plan_for_target("score", &evicted).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);
        assert_eq!(
            manager
                .score_state()
                .exact_stats("score", &evicted, node.id),
            Some((1, 0, 0))
        );
        replacement.setup_succeeded();
        replacement.tx(1);
        replacement.rx(1);
        replacement.finish(ScoreOutcome::Success);
        assert_eq!(
            manager
                .score_state()
                .exact_stats("score", &evicted, node.id),
            Some((1, 1, 0))
        );
    }

    #[test]
    fn stale_aggregate_completion_does_not_mutate_recreated_cell() {
        let state = ScorePolicyState::default();
        let node_id = node("a").id;
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let memberships: Vec<_> = (0..=AGGREGATE_CAPACITY)
            .map(|index| (format!("group-{index}"), node_id))
            .collect();
        state.publish_membership(memberships.iter().cloned());
        let evicted = ScoreAttribution {
            group: memberships[0].0.clone(),
            node_id,
        };
        let stale_cells = state.start(&context, std::slice::from_ref(&evicted));
        for (group, node_id) in memberships.iter().skip(1) {
            drop(state.start(
                &context,
                &[ScoreAttribution {
                    group: group.clone(),
                    node_id: *node_id,
                }],
            ));
        }
        let current_cells = state.start(&context, std::slice::from_ref(&evicted));
        let sample = FlowSample {
            outcome: ScoreOutcome::Success,
            setup: Some(Duration::ZERO),
            first_response: None,
            tx: 1,
            rx: 1,
            elapsed: Duration::from_millis(1),
            count_usefulness: true,
            streak_neutral: false,
        };
        state.finish(
            &context,
            std::slice::from_ref(&evicted),
            &stale_cells,
            &sample,
        );
        assert_eq!(state.inner.lock().aggregate.len(), AGGREGATE_CAPACITY);
        assert_eq!(
            state.aggregate_stats(&evicted.group, SelectionNetwork::Tcp, node_id),
            Some((1, 0, 0))
        );
        state.finish(
            &context,
            std::slice::from_ref(&evicted),
            &current_cells,
            &sample,
        );
        assert_eq!(
            state.aggregate_stats(&evicted.group, SelectionNetwork::Tcp, node_id),
            Some((1, 1, 0))
        );
    }

    #[test]
    fn builtin_direct_final_is_valid_feedback_membership() {
        let mut outer = group("outer", &[]);
        outer.final_outbound = Some(honk_config::Config::BUILTIN_DIRECT_NODE.into());
        let manager = super::super::GroupManager::new(&[outer], &[]);
        let context = context("final-direct.example", IpVersion::V4);
        let feedback = manager
            .feedback_for_group_node(
                "outer",
                honk_config::config::DIRECT_NODE_ID,
                context.clone(),
            )
            .unwrap();
        let reporter = feedback.start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);
        assert!(manager.score_state().has_exact(
            "outer",
            &context,
            honk_config::config::DIRECT_NODE_ID
        ));
    }

    #[test]
    fn aggregate_display_does_not_advance_nested_load_balance() {
        let nodes = [node("a"), node("b")];
        let mut child = group("child", &nodes);
        child.policy = GroupPolicy::LoadBalance;
        let mut parent = group("parent", &[]);
        parent.groups.push(child.name.clone());
        let manager = super::super::GroupManager::new(&[parent, child], &nodes);

        assert_eq!(
            manager.get_score_selection_for_network("parent", SelectionNetwork::Tcp),
            Some("child".into())
        );
        assert_eq!(manager.select_node("child").unwrap().id, nodes[0].id);
    }

    #[test]
    fn late_completion_keeps_extant_member_and_drops_deleted_member() {
        let nodes = [node("a"), node("b")];
        let old = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("reload.example", IpVersion::V4);
        let reporter_a = old.selection_plan_for_target("score", &context).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        finish_success(&old.selection_plan_for_target("score", &context));
        let reporter_b = old.selection_plan_for_target("score", &context).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        let state = old.score_state();
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
            &[group("score", &nodes[..1])],
            &nodes[..1],
            None,
            Arc::clone(&state),
        );
        replacement.publish_score_membership();

        for reporter in [&reporter_a, &reporter_b] {
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }
        assert!(state.has_exact("score", &context, nodes[0].id));
        assert!(!state.has_exact("score", &context, nodes[1].id));
    }

    #[test]
    fn final_outbound_late_completion_keeps_extant_leaf_and_drops_deleted_leaf() {
        let leaves = [node("final-a"), node("final-b")];
        let mut final_group = group("final-group", &leaves);
        final_group.policy = GroupPolicy::Selector;
        let mut outer = group("outer", &[]);
        outer.final_outbound = Some(final_group.name.clone());
        let old = super::super::GroupManager::new(&[outer.clone(), final_group.clone()], &leaves);
        let context = context("final.example", IpVersion::V4);
        let reporter_a = old
            .feedback_for_group_node("outer", leaves[0].id, context.clone())
            .unwrap()
            .start();
        let reporter_b = old
            .feedback_for_group_node("outer", leaves[1].id, context.clone())
            .unwrap()
            .start();
        let state = old.score_state();
        assert!(
            state
                .inner
                .lock()
                .valid
                .contains(&("outer".into(), leaves[0].id))
        );
        assert!(
            state
                .inner
                .lock()
                .valid
                .contains(&("outer".into(), leaves[1].id))
        );

        final_group.nodes.retain(|node_id| *node_id == leaves[0].id);
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
            &[outer, final_group],
            std::slice::from_ref(&leaves[0]),
            None,
            Arc::clone(&state),
        );
        replacement.publish_score_membership();
        for reporter in [&reporter_a, &reporter_b] {
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }

        assert!(state.has_exact("outer", &context, leaves[0].id));
        assert!(!state.has_exact("outer", &context, leaves[1].id));
    }
}
