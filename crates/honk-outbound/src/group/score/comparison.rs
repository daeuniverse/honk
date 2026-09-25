use super::evidence::CellStamp;
use super::ranking::normal_eligible;
use super::verification::VerificationEvidence;
use super::{AggregateKey, ExactKey, ScoreSelectionContext, ScoreSnapshot, StateInner, Stats};
use honk_config::node::Node;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::Instant;
use uuid::Uuid;

mod store;
use store::{Bucket, Cell, Key, Timing};
pub(super) use store::{Store, observe};

pub(super) const MAX_CELLS: usize = 256;
pub(super) const MAX_TARGETS: usize = 8;
pub(super) const MAX_LOGICAL_BYTES: usize = 1024 * 1024;
pub(super) const MAX_KEY_BYTES: usize = 1024;
const BLOCKS: usize = 4;
const REPORTERS: usize = 4;

pub(super) fn next_reporter_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_update(AtomicOrdering::Relaxed, AtomicOrdering::Relaxed, |id| {
        id.checked_add(1)
    })
    .unwrap_or(0)
}

/// Inclusive symmetric 10% band: `high - low <= 0.1 × low`.
pub(super) fn equivalent(left: f64, right: f64) -> bool {
    let low = left.min(right);
    let high = left.max(right);
    // Averaging and unit conversion can round an inclusive boundary by a few ulps.
    high - low <= low * super::PERFORMANCE_SWITCH_MARGIN + high * f64::EPSILON * 8.0
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Basis {
    #[default]
    None,
    ExactTarget,
    CommonTargets,
    ConfiguredProbe,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct MetricPair {
    pub incumbent: f64,
    pub candidate: f64,
    pub reporters: u8,
    pub latest_at: Instant,
    pub expires_at: Instant,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PairEvidence {
    pub basis: Basis,
    pub response: Option<MetricPair>,
    pub upload: Option<MetricPair>,
    pub download: Option<MetricPair>,
    pub partial: bool,
    /// Challenger reporters sharing live blocks with the reference on the exact target, up to
    /// the four a pair needs, and the latest of their reports.
    pub progress: u8,
    pub progress_at: Option<Instant>,
}

/// Pairs indexed by node position; the reference and ineligible members have none.
pub(super) struct PairCohort {
    pub reference: usize,
    pub pairs: Vec<Option<PairEvidence>>,
}

impl PairCohort {
    pub fn get(&self, index: usize) -> Option<PairEvidence> {
        self.pairs.get(index).copied().flatten()
    }
}

#[derive(Default)]
struct Accumulator {
    sum: f64,
    count: u64,
    last: Option<Instant>,
    reporters: [u64; BLOCKS * REPORTERS],
    distinct: usize,
}

impl Accumulator {
    fn add(&mut self, bucket: &Bucket) {
        // Both nodes receive the same time-block weight despite different offered load.
        self.sum += bucket.sum / f64::from(bucket.count);
        self.count += 1;
        if let Some(at) = bucket.last {
            self.last = Some(self.last.map_or(at, |old| old.max(at)));
        }
        for id in bucket.reporters.into_iter().filter(|id| *id != 0) {
            if self.distinct < self.reporters.len()
                && !self.reporters[..self.distinct].contains(&id)
            {
                self.reporters[self.distinct] = id;
                self.distinct += 1;
            }
        }
    }
}

/// Same-block accumulation of both sides, with the earliest block deadline.
fn accumulate_common(
    left: &[Bucket; BLOCKS],
    right: &[Bucket; BLOCKS],
    origin: Instant,
    now: Instant,
    timing: Timing,
) -> Option<([Accumulator; 2], Option<Instant>)> {
    let mut sides = [Accumulator::default(), Accumulator::default()];
    let mut expires = None;
    for (left, right) in left.iter().zip(right) {
        if !timing.common(left, right, origin, now) {
            continue;
        }
        let until = timing.deadline(origin, left.block)?;
        sides[0].add(left);
        sides[1].add(right);
        expires = Some(expires.map_or(until, |old: Instant| old.min(until)));
    }
    Some((sides, expires))
}

fn metric_pair(
    ([a, b], expires): ([Accumulator; 2], Option<Instant>),
    now: Instant,
    timing: Timing,
) -> Option<MetricPair> {
    let reporters = a.distinct.min(b.distinct);
    if reporters < REPORTERS {
        return None;
    }
    let latest_at = a.last?.min(b.last?);
    let expires_at = expires?.min(latest_at.checked_add(timing.freshness)?);
    if now >= expires_at {
        return None;
    }
    Some(MetricPair {
        incumbent: a.sum / a.count as f64,
        candidate: b.sum / b.count as f64,
        reporters: reporters as u8,
        latest_at,
        expires_at,
    })
}

fn has_common_block(left: &Cell, right: &Cell, origin: Instant, now: Instant) -> bool {
    left.key.timing().is_some_and(|timing| {
        left.metrics
            .iter()
            .zip(&right.metrics)
            .any(|(left, right)| {
                left.iter()
                    .zip(right)
                    .any(|(a, b)| timing.common(a, b, origin, now))
            })
    })
}

fn merge_metric(acc: &mut Option<MetricPair>, next: Option<MetricPair>, count: usize) {
    *acc = match (*acc, next) {
        (_, Some(next)) if count == 0 => Some(next),
        (Some(old), Some(next)) => Some(MetricPair {
            incumbent: old.incumbent + next.incumbent,
            candidate: old.candidate + next.candidate,
            reporters: old.reporters.min(next.reporters),
            latest_at: old.latest_at.min(next.latest_at),
            expires_at: old.expires_at.min(next.expires_at),
        }),
        _ => None,
    };
}

fn paired_cell(
    left: &Cell,
    right: &Cell,
    origin: Instant,
    now: Instant,
    basis: Basis,
) -> PairEvidence {
    let mut result = PairEvidence {
        basis,
        ..PairEvidence::default()
    };
    let Some(timing) = left.key.timing() else {
        return result;
    };
    let [response, upload, download] = std::array::from_fn(|metric| {
        accumulate_common(
            &left.metrics[metric],
            &right.metrics[metric],
            origin,
            now,
            timing,
        )
    });
    if let Some(([_, challenger], _)) = &response {
        result.progress = challenger.distinct.min(REPORTERS) as u8;
        result.progress_at = challenger.last;
    }
    result.response = response.and_then(|sides| metric_pair(sides, now, timing));
    result.upload = upload.and_then(|sides| metric_pair(sides, now, timing));
    result.download = download.and_then(|sides| metric_pair(sides, now, timing));
    result
}

/// Positions of node ids within one evaluation; duplicates keep ascending positions.
struct NodeSlots(Vec<(Uuid, usize)>);

impl NodeSlots {
    fn new(ids: impl IntoIterator<Item = Uuid>) -> Self {
        let mut slots: Vec<_> = ids
            .into_iter()
            .enumerate()
            .map(|(slot, id)| (id, slot))
            .collect();
        slots.sort_unstable();
        Self(slots)
    }

    fn of(&self, node: Uuid) -> impl Iterator<Item = usize> + '_ {
        let first = self.0.partition_point(|(id, _)| *id < node);
        self.0[first..]
            .iter()
            .take_while(move |(id, _)| *id == node)
            .map(|(_, slot)| *slot)
    }
}

/// One challenger's accumulation against the reference, in store order.
#[derive(Default)]
struct PairScan {
    common: PairEvidence,
    count: usize,
    exact: Option<PairEvidence>,
    probe: Option<PairEvidence>,
}

impl PairScan {
    fn add(
        &mut self,
        context: &ScoreSelectionContext,
        (left, right): (&Cell, &Cell),
        origin: Instant,
        now: Instant,
    ) {
        if !has_common_block(left, right, origin, now) {
            return;
        }
        match &right.key {
            Key::Traffic(key)
                if context
                    .target_family
                    .is_none_or(|family| family == key.family) =>
            {
                if self.count == MAX_TARGETS && context.target.as_ref() != Some(&key.target) {
                    self.common.partial = true;
                    return;
                }
                let pair = paired_cell(left, right, origin, now, Basis::ExactTarget);
                if context.target.as_ref() == Some(&key.target) {
                    self.exact = Some(pair);
                }
                // Qualification, never magnitude, selects the canonical response cohort.
                if pair.response.is_some() && self.count < MAX_TARGETS {
                    merge_metric(&mut self.common.response, pair.response, self.count);
                    merge_metric(&mut self.common.upload, pair.upload, self.count);
                    merge_metric(&mut self.common.download, pair.download, self.count);
                    self.count += 1;
                } else {
                    self.common.partial = true;
                }
            }
            Key::Probe { slot, .. }
                if *slot == super::evidence::probe_slot(context) && self.probe.is_none() =>
            {
                self.probe = Some(paired_cell(
                    left,
                    right,
                    origin,
                    now,
                    Basis::ConfiguredProbe,
                ));
            }
            _ => {}
        }
    }

    fn finish(mut self) -> PairEvidence {
        self.common.basis = if self.count == 0 {
            Basis::None
        } else {
            Basis::CommonTargets
        };
        for metric in [
            &mut self.common.response,
            &mut self.common.upload,
            &mut self.common.download,
        ]
        .into_iter()
        .flatten()
        {
            metric.incumbent /= self.count as f64;
            metric.candidate /= self.count as f64;
        }
        let (progress, progress_at) = self
            .exact
            .map_or((0, None), |exact| (exact.progress, exact.progress_at));
        let mut result = self.exact.unwrap_or_default();
        if result.response.is_none() && result.upload.is_none() && result.download.is_none() {
            result = self.common;
        }
        if result.response.is_none()
            && let Some(pair) = self.probe
        {
            // Do not combine business rates with an unrelated proxy-probe response.
            result = pair;
        }
        (result.progress, result.progress_at) = (progress, progress_at);
        result
    }
}

/// One decision's borrowed view of comparison evidence. Node positions and their current global
/// parents are resolved once and shared by every reader of that decision.
pub(super) struct View<'a> {
    pub inner: &'a StateInner,
    pub group: &'a str,
    pub context: &'a ScoreSelectionContext,
    pub nodes: &'a [&'a Node],
    pub now: Instant,
    slots: NodeSlots,
    parents: Vec<Option<&'a Stats>>,
}

impl<'a> View<'a> {
    pub(super) fn new(
        inner: &'a StateInner,
        group: &'a str,
        context: &'a ScoreSelectionContext,
        nodes: &'a [&'a Node],
        now: Instant,
    ) -> Self {
        let mut key = AggregateKey {
            group: group.to_owned(),
            network: context.network,
            family: None,
            node_id: Uuid::nil(),
        };
        let parents = nodes
            .iter()
            .map(|node| {
                key.node_id = node.id;
                inner.aggregate.peek(&key)
            })
            .collect();
        Self {
            inner,
            group,
            context,
            nodes,
            now,
            slots: NodeSlots::new(nodes.iter().map(|node| node.id)),
            parents,
        }
    }

    /// Original pairs of evaluated eligible challengers against `reference`, as ordinary
    /// selection compares them.
    pub(super) fn pairs(
        &self,
        (snapshots, baseline): (&[ScoreSnapshot], super::PerformanceBaseline),
        (evaluated, reference): (&[bool], usize),
    ) -> PairCohort {
        let challengers: Vec<_> = (0..snapshots.len())
            .filter(|&index| {
                index != reference
                    && evaluated[index]
                    && normal_eligible(&snapshots[index], baseline)
            })
            .collect();
        let mut pairs = vec![None; self.nodes.len()];
        for (&index, pair) in challengers
            .iter()
            .zip(self.compare_all(reference, &challengers))
        {
            pairs[index] = Some(pair);
        }
        PairCohort { reference, pairs }
    }

    pub(super) fn node_evidence(&self, evaluated: &[bool]) -> Vec<VerificationEvidence> {
        let (inner, context, now) = (self.inner, self.context, self.now);
        let mut family_key = AggregateKey {
            group: self.group.to_owned(),
            network: context.network,
            family: context.target_family,
            node_id: Uuid::nil(),
        };
        let mut exact_key =
            context
                .target_family
                .zip(context.target.clone())
                .map(|(family, target)| ExactKey {
                    group: self.group.to_owned(),
                    network: context.network,
                    family,
                    target,
                    node_id: Uuid::nil(),
                });
        self.nodes
            .iter()
            .zip(evaluated)
            .zip(&self.parents)
            .map(|((node, evaluated), &parent)| {
                if !evaluated {
                    return VerificationEvidence::default();
                }
                let stamp = if let Some(key) = exact_key.as_mut() {
                    key.node_id = node.id;
                    inner
                        .exact
                        .peek(key)
                        .and_then(|stats| CellStamp::current(stats, parent))
                } else if context.target.is_none() {
                    family_key.node_id = node.id;
                    inner.aggregate.peek(&family_key).and_then(|stats| {
                        if context.target_family.is_none() {
                            Some(CellStamp::own(stats))
                        } else {
                            CellStamp::current(stats, parent)
                        }
                    })
                } else {
                    None
                };
                let mut evidence = stamp.map_or_else(VerificationEvidence::default, |stamp| {
                    let mut evidence = VerificationEvidence::new(stamp.stats, now);
                    evidence.business = evidence.business.filter(|metric| {
                        stamp
                            .invalidated_through
                            .is_none_or(|at| metric.latest_at > at)
                    });
                    evidence
                });
                evidence.failed_at = evidence
                    .failed_at
                    .max(parent.and_then(|parent| parent.failed_at));
                evidence
            })
            .collect()
    }

    /// Pairs every challenger with the reference; results follow `challengers`.
    fn compare_all(&self, reference: usize, challengers: &[usize]) -> Vec<PairEvidence> {
        let Some(origin) = self.inner.comparisons.origin else {
            return vec![PairEvidence::default(); challengers.len()];
        };
        let (context, now) = (self.context, self.now);
        let scan = |members: &[usize], wanted: &dyn Fn(&Key) -> bool| {
            let mut scans: Vec<_> = members.iter().map(|_| PairScan::default()).collect();
            self.for_each_pair(reference, members, wanted, |slot, pair| {
                scans[slot].add(context, pair, origin, now);
            });
            scans
        };
        let mut results = vec![None; challengers.len()];
        // A metric-bearing exact pair decides the result, so only the rest need common targets.
        if let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) {
            let slot = super::evidence::probe_slot(context);
            let exact_or_probe = |key: &Key| match key {
                Key::Traffic(key) => key.family == family && key.target == *target,
                Key::Probe { slot: probe, .. } => *probe == slot,
            };
            for (result, scan) in results.iter_mut().zip(scan(challengers, &exact_or_probe)) {
                if scan.exact.is_some_and(|pair| {
                    pair.response.is_some() || pair.upload.is_some() || pair.download.is_some()
                }) {
                    *result = Some(scan.finish());
                }
            }
        }
        let remaining: Vec<_> = (0..challengers.len())
            .filter(|slot| results[*slot].is_none())
            .collect();
        if !remaining.is_empty() {
            let members: Vec<_> = remaining.iter().map(|slot| challengers[*slot]).collect();
            for (slot, scan) in remaining.into_iter().zip(scan(&members, &|_| true)) {
                results[slot] = Some(scan.finish());
            }
        }
        results.into_iter().map(Option::unwrap_or_default).collect()
    }

    /// Visits valid reference/member cells of each wanted cohort in store order; `visit`
    /// receives each member's position within `members`, which lists positions without repeats.
    fn for_each_pair(
        &self,
        reference: usize,
        members: &[usize],
        wanted: &dyn Fn(&Key) -> bool,
        mut visit: impl FnMut(usize, (&'a Cell, &'a Cell)),
    ) {
        let mut member_slot = vec![None; self.nodes.len()];
        for (slot, &index) in members.iter().enumerate() {
            member_slot[index] = Some(slot);
        }
        let reference_id = self.nodes[reference].id;
        // Keys are unique per node within a sorted cohort, so each cohort pairs at most once.
        for cohort in self
            .inner
            .comparisons
            .cohorts(self.group, self.context.network)
        {
            if !wanted(&cohort[0].key) {
                continue;
            }
            let Some(left) = cohort.iter().find(|cell| {
                cell.key.node() == reference_id && cell.valid(self.inner, self.parents[reference])
            }) else {
                continue;
            };
            for right in cohort.iter().filter(|cell| cell.key.node() != reference_id) {
                for index in self.slots.of(right.key.node()) {
                    if let Some(slot) = member_slot[index]
                        && right.valid(self.inner, self.parents[index])
                    {
                        visit(slot, (left, right));
                    }
                }
            }
        }
    }
}
