use super::ranking::explore_backoff;
use super::{
    AggregateKey, Availability, ExactKey, FlowSample, LIVE_QUALIFICATION_TTL,
    MAX_THROUGHPUT_DURATION, MIN_THROUGHPUT_BYTES, MIN_THROUGHPUT_DURATION, PERFORMANCE_MAX_AGE,
    PERFORMANCE_VALIDATION_SAMPLES, RELIABILITY_CONFIDENCE_Z, SCORE_EVIDENCE_HALF_LIFE,
    ScoreAttribution, ScoreAuthority, ScoreOutcome, ScorePolicyState, ScoreSelectionContext,
    ScoreSource, StartedCells, Stats, WeightedMean,
};
use lru::LruCache;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub(super) struct Performance {
    pub setup: WeightedMean,
    pub response: WeightedMean,
    pub upload: WeightedMean,
    pub download: WeightedMean,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ProbeMetric {
    pub latency: WeightedMean,
    pub scope: u64,
}

pub(super) fn probe_slot(context: &ScoreSelectionContext) -> usize {
    context.probe_domain as usize * 2 + context.health_family as usize
}

#[derive(Clone, Copy, Default)]
pub(super) struct MetricSnapshot {
    pub value: Option<f64>,
    pub confidence: f64,
}

#[derive(Clone, Copy, Default)]
pub(super) struct PerformanceSnapshot {
    pub setup: MetricSnapshot,
    pub response: MetricSnapshot,
    pub upload: MetricSnapshot,
    pub download: MetricSnapshot,
}

impl Performance {
    pub(super) fn snapshot(&self, now: Instant) -> PerformanceSnapshot {
        PerformanceSnapshot {
            setup: self.setup.snapshot(now),
            response: self.response.snapshot(now),
            upload: self.upload.snapshot(now),
            download: self.download.snapshot(now),
        }
    }
}

impl WeightedMean {
    pub(super) fn record(&mut self, sample: f64, now: Instant) {
        if self
            .observed_at
            .is_none_or(|at| now.saturating_duration_since(at) >= PERFORMANCE_MAX_AGE)
        {
            self.sum = 0.0;
            self.weight = 0.0;
        }
        // Bound inertia as well as freshness: ten thousand old samples must
        // not outvote the next few observations of a degraded path.
        if self.weight >= PERFORMANCE_VALIDATION_SAMPLES {
            self.sum *= (PERFORMANCE_VALIDATION_SAMPLES - 1.0) / self.weight;
            self.weight = PERFORMANCE_VALIDATION_SAMPLES - 1.0;
        }
        self.sum += sample;
        self.weight += 1.0;
        self.observed_at = Some(now);
    }

    pub(super) fn snapshot(&self, now: Instant) -> MetricSnapshot {
        let Some(at) = self.observed_at else {
            return MetricSnapshot::default();
        };
        let age = now.saturating_duration_since(at);
        if age >= PERFORMANCE_MAX_AGE || self.weight <= 0.0 {
            return MetricSnapshot::default();
        }
        let freshness =
            (2.0 * (1.0 - age.as_secs_f64() / PERFORMANCE_MAX_AGE.as_secs_f64())).min(1.0);
        MetricSnapshot {
            value: Some(self.sum / self.weight),
            confidence: (self.weight / PERFORMANCE_VALIDATION_SAMPLES).min(1.0) * freshness,
        }
    }
}

impl Availability {
    fn invalidate(&mut self, at: Instant) {
        self.epoch = self.epoch.saturating_add(1);
        self.reporters = 0;
        self.latest_rx_at = None;
        self.valid_from = Some(self.valid_from.map_or(at, |old| old.max(at)));
    }

    fn record(&mut self, rx_at: Instant, now: Instant, credited: &mut Option<u64>) -> bool {
        let latest = self.latest_rx_at.map_or(now, |at| at.max(now));
        if let Some(at) = self.latest_rx_at
            && now.saturating_duration_since(at) >= LIVE_QUALIFICATION_TTL
        {
            // Delayed publication cannot bridge a cohort that has already expired.
            self.invalidate(at + LIVE_QUALIFICATION_TTL);
        }
        if rx_at > now
            || latest.saturating_duration_since(rx_at) >= LIVE_QUALIFICATION_TTL
            || self.valid_from.is_some_and(|start| rx_at < start)
        {
            return false;
        }
        if *credited != Some(self.epoch) {
            self.reporters = (self.reporters + 1).min(PERFORMANCE_VALIDATION_SAMPLES as u8);
            *credited = Some(self.epoch);
        }
        self.latest_rx_at = Some(self.latest_rx_at.map_or(rx_at, |at| at.max(rx_at)));
        true
    }
}

pub(super) enum Observation {
    Setup(Duration),
    Response(Duration),
    BusinessProgress {
        rx_at: Instant,
    },
    Probe {
        latency: Duration,
        scope: u64,
        slot: usize,
        interval: Option<Duration>,
    },
    Transfer {
        tx: u64,
        rx: u64,
        elapsed: Duration,
    },
}

impl Stats {
    pub(super) fn completed(&self) -> f64 {
        self.setup_success + self.setup_failure
    }

    pub(super) fn useful_completed(&self) -> f64 {
        self.useful_success + self.useful_failure
    }

    pub(super) fn reliability_bounds(&self, factor: f64) -> (f64, f64) {
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

    pub(super) fn decay_to(&mut self, now: Instant) {
        let Some(updated_at) = self.updated_at.replace(now) else {
            return;
        };
        let factor = evidence_decay(now.saturating_duration_since(updated_at));
        self.setup_success *= factor;
        self.setup_failure *= factor;
        self.useful_success *= factor;
        self.useful_failure *= factor;
    }

    fn record_start(&mut self, now: Instant, source: ScoreSource) {
        if source == ScoreSource::Traffic {
            self.decay_to(now);
        }
    }

    fn observe(
        &mut self,
        observation: &Observation,
        source: ScoreSource,
        now: Instant,
        credited: &mut Option<u64>,
        exact: bool,
    ) {
        match (source, observation) {
            (
                ScoreSource::Traffic,
                Observation::Setup(latency) | Observation::Response(latency),
            ) => {
                let metric = if matches!(observation, Observation::Setup(_)) {
                    &mut self.performance.setup
                } else {
                    &mut self.performance.response
                };
                let sample = latency.as_secs_f64() * 1000.0;
                let previous = metric.snapshot(now);
                // Aggregate means mix targets of unrelated latency; only the same target's
                // history can show that this node became slower.
                if exact
                    && previous.confidence == 1.0
                    && previous
                        .value
                        .is_some_and(|old| sample > old.max(1.0) * 1.5)
                {
                    self.degraded_at = Some(now);
                }
                metric.record(sample, now);
            }
            (ScoreSource::Warmup, Observation::Setup(latency)) => {
                self.warm_setup_ms
                    .record(latency.as_secs_f64() * 1000.0, now);
            }
            (
                ScoreSource::HealthProbe,
                Observation::Probe {
                    latency,
                    scope,
                    slot,
                    ..
                },
            ) => {
                let probe = &mut self.probes[*slot];
                if probe.scope != *scope {
                    probe.latency = WeightedMean::default();
                    probe.scope = *scope;
                }
                probe.latency.record(latency.as_secs_f64() * 1000.0, now);
            }
            (ScoreSource::Traffic, Observation::Transfer { tx, rx, elapsed })
                if *elapsed >= MIN_THROUGHPUT_DURATION && *elapsed <= MAX_THROUGHPUT_DURATION =>
            {
                // Directional rates are not summed: a request body and its
                // response are different workloads, not twice the capacity.
                if *tx >= MIN_THROUGHPUT_BYTES {
                    self.performance
                        .upload
                        .record(*tx as f64 / elapsed.as_secs_f64(), now);
                }
                if *rx >= MIN_THROUGHPUT_BYTES {
                    self.performance
                        .download
                        .record(*rx as f64 / elapsed.as_secs_f64(), now);
                }
            }
            (ScoreSource::Traffic, Observation::BusinessProgress { rx_at })
                if self
                    .business_invalidated_through
                    .is_none_or(|fence| *rx_at > fence) =>
            {
                if !self.availability.record(*rx_at, now, credited) {
                    return;
                }
                self.explore_not_before = None;
                if self.failed_at.is_some()
                    && self.availability.reporters >= PERFORMANCE_VALIDATION_SAMPLES as u8
                {
                    self.fail_streak = 0;
                    self.qualified_until = Some(*rx_at + LIVE_QUALIFICATION_TTL);
                }
                self.last_business_rx_at = Some(
                    self.last_business_rx_at
                        .map_or(*rx_at, |seen| seen.max(*rx_at)),
                );
                self.retain_qualification(*rx_at, now);
            }
            _ => {}
        }
    }

    fn retain_qualification(&mut self, rx_at: Instant, now: Instant) {
        let factor = self
            .updated_at
            .map_or(1.0, |at| evidence_decay(now.saturating_duration_since(at)));
        let qualified = self.useful_completed() * factor >= PERFORMANCE_VALIDATION_SAMPLES;
        let rx_at = if qualified {
            self.last_business_rx_at.unwrap_or(rx_at)
        } else {
            rx_at
        };
        if now.saturating_duration_since(rx_at) >= LIVE_QUALIFICATION_TTL
            || self
                .business_invalidated_through
                .is_some_and(|fence| rx_at <= fence)
        {
            return;
        }
        if qualified || self.qualified_until.is_some_and(|until| rx_at < until) {
            let until = rx_at + LIVE_QUALIFICATION_TTL;
            // A delayed terminal can bridge the lease to newer observed RX, but not across a silent gap.
            let latest = self
                .last_business_rx_at
                .filter(|at| *at < until)
                .unwrap_or(rx_at);
            let until = latest + LIVE_QUALIFICATION_TTL;
            self.qualified_until = Some(
                self.qualified_until
                    .map_or(until, |previous| previous.max(until)),
            );
        }
    }

    fn inherit_node(&mut self, node: NodeProvenance, now: Instant) {
        let replaced = self.node_incarnation != 0 && self.node_incarnation != node.incarnation;
        if replaced || node.invalidated_through > self.business_invalidated_through {
            self.invalidate_business(if replaced {
                node.invalidated_through.unwrap_or(now)
            } else {
                node.invalidated_through.unwrap()
            });
            self.performance = Performance::default();
            self.last_business_rx_at = None;
        }
        self.node_incarnation = node.incarnation;
        self.failed_at = self.failed_at.max(node.failed_at);
        self.last_node_failure_episode = self.last_node_failure_episode.max(node.failure_episode);
    }

    pub(super) fn invalidate_business(&mut self, now: Instant) {
        self.availability.invalidate(now);
        self.qualified_until = None;
        self.business_invalidated_through = Some(
            self.business_invalidated_through
                .map_or(now, |at| at.max(now)),
        );
    }

    pub(super) fn record_finish(
        &mut self,
        now: Instant,
        sample: &FlowSample,
        count_usefulness: bool,
        hard_failure: bool,
    ) {
        if sample.source != ScoreSource::Traffic {
            return;
        }
        self.decay_to(now);
        if matches!(
            sample.outcome,
            ScoreOutcome::Rejected | ScoreOutcome::Cancelled | ScoreOutcome::Shutdown
        ) {
            return;
        }
        let hard_failure = sample.outcome != ScoreOutcome::Success
            && hard_failure
            && match sample.outcome {
                ScoreOutcome::SharedNodeFailure(episode) => {
                    let fresh = episode > self.last_node_failure_episode;
                    self.last_node_failure_episode = self.last_node_failure_episode.max(episode);
                    fresh
                }
                _ => true,
            };
        if hard_failure {
            self.fail_streak = self.fail_streak.saturating_add(1);
            self.explore_not_before = Some(now + explore_backoff(self.fail_streak));
            self.invalidate_business(now);
            self.probes = Default::default();
            self.failed_at = Some(self.failed_at.map_or(now, |at| at.max(now)));
        }
        if sample.setup.is_some() {
            self.setup_success += 1.0;
        } else {
            self.setup_failure += 1.0;
        }
        if count_usefulness {
            if sample.outcome == ScoreOutcome::Success && sample.tx > 0 && sample.rx > 0 {
                self.useful_success += 1.0;
                if let Some(rx_at) = sample.eligible_rx_at {
                    self.retain_qualification(rx_at, now);
                }
            } else {
                self.useful_failure += 1.0;
            }
        }
    }
}

pub(super) fn evidence_decay(elapsed: Duration) -> f64 {
    (-elapsed.as_secs_f64() / SCORE_EVIDENCE_HALF_LIFE.as_secs_f64()).exp2()
}

#[derive(Clone, Copy)]
struct NodeProvenance {
    incarnation: u64,
    invalidated_through: Option<Instant>,
    failed_at: Option<Instant>,
    failure_episode: u64,
}

impl NodeProvenance {
    fn new(stats: &Stats) -> Self {
        Self {
            incarnation: stats.incarnation,
            invalidated_through: stats.business_invalidated_through,
            failed_at: stats.failed_at,
            failure_episode: stats.last_node_failure_episode,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct CellStamp<'a> {
    pub stats: &'a Stats,
    pub invalidated_through: Option<Instant>,
}

impl<'a> CellStamp<'a> {
    pub(super) fn own(stats: &'a Stats) -> Self {
        Self {
            stats,
            invalidated_through: stats.business_invalidated_through,
        }
    }

    pub(super) fn current(stats: &'a Stats, parent: Option<&Stats>) -> Option<Self> {
        let node = NodeProvenance::new(parent?);
        (stats.node_incarnation == node.incarnation).then_some(Self {
            stats,
            invalidated_through: stats
                .business_invalidated_through
                .max(node.invalidated_through),
        })
    }
}

fn record_cell_start<K: std::hash::Hash + Eq>(
    cache: &mut LruCache<K, Stats>,
    key: K,
    now: Instant,
    tick: u64,
    evictions: &mut u64,
    source: ScoreSource,
    node: Option<NodeProvenance>,
) -> NodeProvenance {
    if let Some(stats) = cache.get_mut(&key) {
        if let Some(node) = node {
            stats.inherit_node(node, now);
        }
        stats.record_start(now, source);
        return NodeProvenance::new(stats);
    }
    let mut stats = Stats {
        incarnation: tick,
        ..Default::default()
    };
    if let Some(node) = node {
        stats.inherit_node(node, now);
    }
    stats.record_start(now, source);
    if cache.len() == cache.cap().get() {
        *evictions = evictions.saturating_add(1);
    }
    let admitted = NodeProvenance::new(&stats);
    cache.put(key, stats);
    admitted
}

fn update_cell<K: std::hash::Hash + Eq>(
    cache: &mut LruCache<K, Stats>,
    key: &K,
    incarnation: Option<u64>,
    credited: &mut Option<u64>,
    update: &mut impl FnMut(&mut Stats, &mut Option<u64>, bool),
    exact: bool,
    node: Option<(NodeProvenance, Instant)>,
) {
    if let Some(stats) = cache.get_mut(key)
        && Some(stats.incarnation) == incarnation
    {
        if let Some((node, now)) = node {
            stats.inherit_node(node, now);
        }
        update(stats, credited, exact);
    }
}

impl ScorePolicyState {
    pub(super) fn fail_probe_at(
        &self,
        authority: &Arc<ScoreAuthority>,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &mut [StartedCells],
        scope: u64,
    ) {
        let mut inner = self.inner.lock();
        if !inner
            .active_authority
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, authority))
        {
            return;
        }
        let slot = probe_slot(context);
        for (attribution, started) in attributions.iter().zip(cells) {
            let key = AggregateKey {
                group: attribution.group.clone(),
                network: context.network,
                family: None,
                node_id: attribution.node_id,
            };
            if let Some(stats) = inner.aggregate.get_mut(&key)
                && Some(stats.incarnation) == started.aggregate[0]
                && stats.probes[slot].scope == scope
            {
                stats.probes[slot] = ProbeMetric::default();
                inner.comparisons.invalidate_probe(
                    &attribution.group,
                    context.network,
                    attribution.node_id,
                    scope,
                    slot,
                );
            }
        }
    }
    #[cfg(test)]
    pub(super) fn start(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
    ) -> Vec<StartedCells> {
        self.start_at(context, attributions, Instant::now())
    }

    #[cfg(test)]
    pub(super) fn start_at(
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
        self.start_at_with_authority(&authority, context, attributions, now, ScoreSource::Traffic)
    }

    pub(super) fn start_at_with_authority(
        &self,
        authority: &Arc<ScoreAuthority>,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        now: Instant,
        source: ScoreSource,
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
                let mut node = None;
                for (index, family) in [None, context.target_family].into_iter().enumerate() {
                    if index == 1 && (family.is_none() || source == ScoreSource::HealthProbe) {
                        break;
                    }
                    let key = AggregateKey {
                        group: attribution.group.clone(),
                        network: context.network,
                        family,
                        node_id: attribution.node_id,
                    };
                    let super::StateInner {
                        aggregate,
                        aggregate_evictions,
                        ..
                    } = &mut *inner;
                    let admitted = record_cell_start(
                        aggregate,
                        key,
                        now,
                        tick,
                        aggregate_evictions,
                        source,
                        node,
                    );
                    started.aggregate[index] = Some(admitted.incarnation);
                    if index == 0 {
                        node = Some(admitted);
                    }
                }
                if source != ScoreSource::HealthProbe
                    && let (Some(family), Some(target)) =
                        (context.target_family, context.target.as_ref())
                {
                    let key = ExactKey {
                        group: attribution.group.clone(),
                        network: context.network,
                        family,
                        target: target.clone(),
                        node_id: attribution.node_id,
                    };
                    let super::StateInner {
                        exact,
                        exact_evictions,
                        ..
                    } = &mut *inner;
                    started.exact = Some(
                        record_cell_start(exact, key, now, tick, exact_evictions, source, node)
                            .incarnation,
                    );
                }
            }
            cells.push(started);
        }
        cells
    }

    fn update_started(
        inner: &mut super::StateInner,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &mut [StartedCells],
        now: Instant,
        mut update: impl FnMut(&mut Stats, &mut Option<u64>, bool),
    ) {
        for (attribution, started) in attributions.iter().zip(cells) {
            if !inner
                .valid
                .contains(&(attribution.group.clone(), attribution.node_id))
            {
                continue;
            }
            let node_key = AggregateKey {
                group: attribution.group.clone(),
                network: context.network,
                family: None,
                node_id: attribution.node_id,
            };
            // Capture before updating the parent so the first shared failure reaches every cell once.
            let Some(node) = inner
                .aggregate
                .peek(&node_key)
                .filter(|stats| Some(stats.incarnation) == started.aggregate[0])
                .map(NodeProvenance::new)
            else {
                continue;
            };
            for (index, family) in [None, context.target_family].into_iter().enumerate() {
                if started.aggregate[index].is_none() {
                    continue;
                }
                if index == 1 && family.is_none() {
                    break;
                }
                let key = AggregateKey {
                    group: attribution.group.clone(),
                    network: context.network,
                    family,
                    node_id: attribution.node_id,
                };
                update_cell(
                    &mut inner.aggregate,
                    &key,
                    started.aggregate[index],
                    &mut started.credited_aggregate[index],
                    &mut update,
                    false,
                    (index != 0).then_some((node, now)),
                );
            }
            if started.exact.is_some()
                && let (Some(family), Some(target)) =
                    (context.target_family, context.target.as_ref())
            {
                let key = ExactKey {
                    group: attribution.group.clone(),
                    network: context.network,
                    family,
                    target: target.clone(),
                    node_id: attribution.node_id,
                };
                update_cell(
                    &mut inner.exact,
                    &key,
                    started.exact,
                    &mut started.credited_exact,
                    &mut update,
                    true,
                    Some((node, now)),
                );
            }
        }
    }

    pub(super) fn observe(
        inner: &mut super::StateInner,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &mut [StartedCells],
        source: ScoreSource,
        observation: Observation,
        now: Instant,
    ) {
        if matches!(observation, Observation::BusinessProgress { .. }) && context.target.is_none() {
            return;
        }
        Self::update_started(
            inner,
            context,
            attributions,
            cells,
            now,
            |stats, credited, exact| stats.observe(&observation, source, now, credited, exact),
        );
    }

    #[cfg(test)]
    pub(super) fn finish(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &mut [StartedCells],
        sample: &FlowSample,
    ) {
        self.finish_at(context, attributions, cells, sample, Instant::now());
    }

    pub(super) fn finish_at(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &mut [StartedCells],
        sample: &FlowSample,
        now: Instant,
    ) {
        let mut inner = self.inner.lock();
        for (attribution, cells) in attributions.iter().zip(cells) {
            Self::update_started(
                &mut inner,
                context,
                std::slice::from_ref(attribution),
                std::slice::from_mut(cells),
                now,
                |stats, credited, exact| {
                    if context.target.is_some()
                        && matches!(
                            sample.outcome,
                            ScoreOutcome::Success
                                | ScoreOutcome::Rejected
                                | ScoreOutcome::Cancelled
                                | ScoreOutcome::Shutdown
                        )
                        && let Some(rx_at) = sample.eligible_rx_at
                    {
                        stats.observe(
                            &Observation::BusinessProgress { rx_at },
                            sample.source,
                            now,
                            credited,
                            exact,
                        );
                    }
                    stats.record_finish(
                        now,
                        sample,
                        sample.count_usefulness && (exact || context.target.is_some()),
                        exact
                            || sample.outcome.is_node_failure()
                            || (sample.outcome != ScoreOutcome::TargetFailure
                                && (sample.setup.is_none() || context.target.is_none())),
                    );
                },
            );
        }
    }
}
