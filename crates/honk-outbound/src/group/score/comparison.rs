use super::evidence::CellStamp;
use super::ranking::normal_eligible;
use super::verification::{TimedMetric, VerificationEvidence};
use super::{AggregateKey, ExactKey, ScoreSelectionContext, ScoreSnapshot, StateInner, Stats};
use honk_config::node::Node;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::Instant;
use uuid::Uuid;

mod store;
use store::{Bucket, Cell, Key, Timing};
pub(super) use store::{Store, observe, target_bytes};
mod summary;
pub(super) use summary::{Summary, failure_excluded, summarize};

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
    // Fingerprints describe selected keys/blocks, never measured values or raw API targets.
    pub support: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PairEvidence {
    pub basis: Basis,
    pub response: Option<MetricPair>,
    pub upload: Option<MetricPair>,
    pub download: Option<MetricPair>,
    pub partial: bool,
}

/// Pairs indexed by node position; the reference and ineligible members have none.
pub(super) struct PairCohort {
    pub reference: usize,
    pub pairs: Vec<Option<PairEvidence>>,
    /// Covered members' joint common-block projection, with the same indexing, when one applies.
    pub joint: Option<Vec<Option<PairEvidence>>>,
}

impl PairCohort {
    pub fn get(&self, index: usize) -> Option<PairEvidence> {
        self.pairs.get(index).copied().flatten()
    }

    pub fn summary_pair(&self, index: usize) -> Option<PairEvidence> {
        self.joint
            .as_ref()
            .and_then(|joint| joint.get(index).copied().flatten())
            .or_else(|| self.get(index))
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

/// Same-block accumulation shared by pair metrics and run progress; each caller keeps its scope.
fn accumulate_common(
    left: &[Bucket; BLOCKS],
    right: &[Bucket; BLOCKS],
    origin: Instant,
    now: Instant,
    timing: Timing,
    blocks: u8,
    mut on_block: impl FnMut(u64),
) -> Option<([Accumulator; 2], Option<Instant>)> {
    let mut sides = [Accumulator::default(), Accumulator::default()];
    let mut expires = None;
    for (index, (left, right)) in left.iter().zip(right).enumerate() {
        if blocks & (1 << index) == 0 || !timing.common(left, right, origin, now) {
            continue;
        }
        let until = timing.deadline(origin, left.block)?;
        on_block(left.block);
        sides[0].add(left);
        sides[1].add(right);
        expires = Some(expires.map_or(until, |old: Instant| old.min(until)));
    }
    Some((sides, expires))
}

fn metric_pair(
    left: &[Bucket; BLOCKS],
    right: &[Bucket; BLOCKS],
    origin: Instant,
    now: Instant,
    timing: Timing,
    blocks: u8,
    mut support: std::collections::hash_map::DefaultHasher,
) -> Option<MetricPair> {
    let ([a, b], expires) = accumulate_common(left, right, origin, now, timing, blocks, |block| {
        block.hash(&mut support)
    })?;
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
        support: support.finish(),
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
        (Some(old), Some(next)) => {
            let mut support = std::collections::hash_map::DefaultHasher::new();
            (old.support, next.support).hash(&mut support);
            Some(MetricPair {
                incumbent: old.incumbent + next.incumbent,
                candidate: old.candidate + next.candidate,
                reporters: old.reporters.min(next.reporters),
                latest_at: old.latest_at.min(next.latest_at),
                expires_at: old.expires_at.min(next.expires_at),
                support: support.finish(),
            })
        }
        _ => None,
    };
}

fn paired_cell(
    left: &Cell,
    right: &Cell,
    origin: Instant,
    now: Instant,
    basis: Basis,
    blocks: [u8; 3],
) -> PairEvidence {
    let mut result = PairEvidence {
        basis,
        ..PairEvidence::default()
    };
    let Some(timing) = left.key.timing() else {
        return result;
    };
    let mut support = std::collections::hash_map::DefaultHasher::new();
    match &left.key {
        Key::Traffic(key) => {
            key.target.hash(&mut support);
            (key.family as u8).hash(&mut support);
        }
        Key::Probe { scope, slot, .. } => {
            scope.hash(&mut support);
            slot.hash(&mut support);
        }
    }
    for (index, ((a, b), output)) in left
        .metrics
        .iter()
        .zip(&right.metrics)
        .zip([
            &mut result.response,
            &mut result.upload,
            &mut result.download,
        ])
        .enumerate()
    {
        *output = metric_pair(a, b, origin, now, timing, blocks[index], support.clone());
    }
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
                let pair = paired_cell(left, right, origin, now, Basis::ExactTarget, [u8::MAX; 3]);
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
                    [u8::MAX; 3],
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
        result
    }
}

fn global_stats<'a>(
    inner: &'a StateInner,
    group: &str,
    network: super::SelectionNetwork,
    node: Uuid,
) -> Option<&'a Stats> {
    inner.aggregate.peek(&AggregateKey {
        group: group.to_owned(),
        network,
        family: None,
        node_id: node,
    })
}

fn timed(
    buckets: &[Bucket; BLOCKS],
    origin: Instant,
    now: Instant,
    timing: Timing,
) -> Option<TimedMetric> {
    metric_pair(
        buckets,
        buckets,
        origin,
        now,
        timing,
        u8::MAX,
        std::collections::hash_map::DefaultHasher::new(),
    )
    .map(|pair| TimedMetric {
        value: pair.incumbent,
        reporters: pair.reporters,
        latest_at: pair.latest_at,
    })
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
    /// selection compares them; the joint projection is a separate verification step.
    pub(super) fn pairs(
        &self,
        (snapshots, baseline): (&[ScoreSnapshot], super::PerformanceBaseline),
        (membership, reference): (&super::evaluation::Membership, usize),
    ) -> PairCohort {
        let challengers: Vec<_> = (0..snapshots.len())
            .filter(|&index| {
                index != reference
                    && membership.evaluated[index]
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
        PairCohort {
            reference,
            pairs,
            joint: None,
        }
    }

    /// Adds covered members' joint common-block projection when their original pairs disagree.
    /// Optional evidence cannot constrain covered members' alignment.
    pub(super) fn join(&self, cohort: &mut PairCohort, membership: &super::evaluation::Membership) {
        let covered: Vec<_> = (0..cohort.pairs.len())
            .filter(|&index| membership.covered[index] && cohort.pairs[index].is_some())
            .collect();
        let original = |index: usize| cohort.pairs[index].expect("covered challengers are paired");
        let mut identity = None;
        let needs_joint = covered.len() > 1
            && covered.iter().any(|&index| {
                let pair = original(index);
                let Some(response) = pair.response else {
                    return true;
                };
                let next = (pair.basis, response.support);
                let differs = identity.is_some_and(|old| old != next);
                identity = Some(next);
                differs
            });
        if !needs_joint {
            return;
        }
        let business_response = covered.iter().any(|&index| {
            let pair = original(index);
            matches!(pair.basis, Basis::ExactTarget | Basis::CommonTargets)
                && pair.response.is_some()
        });
        let Some(joint) = [
            Basis::ExactTarget,
            Basis::CommonTargets,
            Basis::ConfiguredProbe,
        ]
        .into_iter()
        .filter(|basis| *basis != Basis::ConfiguredProbe || !business_response)
        .find_map(|basis| self.joint_pairs(cohort.reference, &covered, basis)) else {
            return;
        };
        let mut by_node = vec![None; cohort.pairs.len()];
        for (&index, pair) in covered.iter().zip(joint) {
            by_node[index] = Some(pair);
        }
        cohort.joint = Some(by_node);
    }

    pub(super) fn node_evidence(
        &self,
        snapshots: &[ScoreSnapshot],
        evaluated: &[bool],
    ) -> Vec<VerificationEvidence> {
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
        let mut evidence: Vec<_> = self
            .nodes
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
            .collect();
        let Some(origin) = inner.comparisons.origin else {
            return evidence;
        };
        let slot = super::evidence::probe_slot(context);
        // One scope pass; each node still sees its own cells in store order.
        for cell in inner.comparisons.scope(self.group, context.network) {
            let wanted = match &cell.key {
                Key::Traffic(key) => {
                    Some(key.family) == context.target_family
                        && Some(&key.target) == context.target.as_ref()
                }
                Key::Probe {
                    slot: cell_slot, ..
                } => *cell_slot == slot,
            };
            let Some(timing) = cell.key.timing().filter(|_| wanted) else {
                continue;
            };
            for index in self.slots.of(cell.key.node()) {
                if !evaluated[index] || !cell.valid(inner, self.parents[index]) {
                    continue;
                }
                let evidence = &mut evidence[index];
                match &cell.key {
                    Key::Traffic(_) => {
                        evidence.response = timed(&cell.metrics[0], origin, now, timing);
                    }
                    Key::Probe { scope, .. } if *scope == snapshots[index].probe_scope => {
                        evidence.probe = timed(&cell.metrics[0], origin, now, timing);
                    }
                    Key::Probe { .. } => {}
                }
            }
        }
        evidence
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

    /// Each node position's slot within `members`, which lists positions without repeats.
    fn member_slots(&self, members: &[usize]) -> Vec<Option<usize>> {
        let mut slots = vec![None; self.nodes.len()];
        for (slot, &index) in members.iter().enumerate() {
            slots[index] = Some(slot);
        }
        slots
    }

    /// Visits valid reference/member cells of each wanted cohort in store order; `visit`
    /// receives each member's position within `members`.
    fn for_each_pair(
        &self,
        reference: usize,
        members: &[usize],
        wanted: &dyn Fn(&Key) -> bool,
        mut visit: impl FnMut(usize, (&'a Cell, &'a Cell)),
    ) {
        let member_slot = self.member_slots(members);
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

    fn joint_pairs(
        &self,
        reference: usize,
        covered: &[usize],
        basis: Basis,
    ) -> Option<Vec<PairEvidence>> {
        let (inner, context, now) = (self.inner, self.context, self.now);
        let origin = inner.comparisons.origin?;
        let members: Vec<_> = std::iter::once(reference)
            .chain(covered.iter().copied())
            .collect();
        let count = covered.len();
        let mut result = vec![
            PairEvidence {
                basis,
                ..PairEvidence::default()
            };
            count
        ];
        let mut targets = 0;
        let mut partial = false;
        let member_slot = self.member_slots(&members);
        // A duplicated node id resolves to its first member slot.
        let slot_of = |cell: &Cell| {
            self.slots
                .of(cell.key.node())
                .filter_map(|index| member_slot[index])
                .min()
                .filter(|slot| cell.valid(inner, self.parents[members[*slot]]))
        };
        let reference_id = self.nodes[reference].id;
        let reference_parent = self.parents[reference];
        let mut selected = vec![None; members.len()];
        let mut next = vec![PairEvidence::default(); count];
        for current in inner.comparisons.cohorts(self.group, context.network) {
            let eligible = match (&current[0].key, basis) {
                (Key::Traffic(key), Basis::ExactTarget) => {
                    Some(key.family) == context.target_family
                        && Some(&key.target) == context.target.as_ref()
                }
                (Key::Traffic(key), Basis::CommonTargets) => context
                    .target_family
                    .is_none_or(|family| family == key.family),
                (Key::Probe { slot, .. }, Basis::ConfiguredProbe) => {
                    *slot == super::evidence::probe_slot(context)
                }
                _ => false,
            };
            if !eligible {
                continue;
            }
            // Keys are unique per node within a cohort: fewer cells than members cannot be complete.
            if current.len() < members.len() {
                partial |= current
                    .iter()
                    .find(|cell| {
                        cell.key.node() == reference_id && cell.valid(inner, reference_parent)
                    })
                    .is_some_and(|left| {
                        current.iter().any(|right| {
                            right.key.node() != reference_id
                                && slot_of(right).is_some()
                                && has_common_block(left, right, origin, now)
                        })
                    });
                continue;
            }
            selected.fill(None);
            for cell in current {
                if let Some(slot) = slot_of(cell) {
                    selected[slot] = Some(cell);
                }
            }
            if selected.iter().any(Option::is_none) {
                partial |= selected[0].is_some_and(|left| {
                    selected[1..]
                        .iter()
                        .flatten()
                        .any(|right| has_common_block(left, right, origin, now))
                });
                continue;
            }
            let left = selected[0]?;
            let timing = left.key.timing()?;
            let mut blocks = [0_u8; 3];
            for (metric, mask) in blocks.iter_mut().enumerate() {
                for block in 0..BLOCKS {
                    if selected.iter().flatten().all(|cell| {
                        timing.common(
                            &left.metrics[metric][block],
                            &cell.metrics[metric][block],
                            origin,
                            now,
                        )
                    }) {
                        *mask |= 1 << block;
                    }
                }
            }
            blocks[1] &= blocks[0];
            blocks[2] &= blocks[0];
            for (slot, pair) in next.iter_mut().enumerate() {
                *pair = paired_cell(left, selected[slot + 1]?, origin, now, basis, blocks);
            }
            if next.iter().any(|pair| pair.response.is_none()) {
                partial |= selected[1..]
                    .iter()
                    .flatten()
                    .any(|right| has_common_block(left, right, origin, now));
                continue;
            }
            if targets == MAX_TARGETS {
                partial = true;
                continue;
            }
            for (pair, next) in result.iter_mut().zip(&next) {
                merge_metric(&mut pair.response, next.response, targets);
                merge_metric(&mut pair.upload, next.upload, targets);
                merge_metric(&mut pair.download, next.download, targets);
            }
            targets += 1;
            if basis != Basis::CommonTargets {
                break;
            }
        }
        if targets == 0 {
            return None;
        }
        for pair in &mut result {
            pair.partial = basis == Basis::CommonTargets && partial;
            for metric in [&mut pair.response, &mut pair.upload, &mut pair.download]
                .into_iter()
                .flatten()
            {
                metric.incumbent /= targets as f64;
                metric.candidate /= targets as f64;
            }
        }
        Some(result)
    }
}

pub(super) fn response_progress(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    reference: Uuid,
    candidate: Uuid,
    now: Instant,
) -> Option<([u8; 2], u64)> {
    let family = context.target_family?;
    let target = context.target.as_ref()?;
    if group.len().saturating_add(target_bytes(target)) > MAX_KEY_BYTES {
        return None;
    }
    let mut key = ExactKey {
        group: group.to_owned(),
        network: context.network,
        family,
        target: target.clone(),
        node_id: reference,
    };
    let mut identity = std::collections::hash_map::DefaultHasher::new();
    let mut cells = [None; 2];
    for (side, node) in [reference, candidate].into_iter().enumerate() {
        let parent = global_stats(inner, group, context.network, node)?;
        key.node_id = node;
        let stats = inner.exact.peek(&key)?;
        let stamp = CellStamp::current(stats, Some(parent))?;
        (
            parent.incarnation,
            stats.incarnation,
            stamp.invalidated_through,
        )
            .hash(&mut identity);
        cells[side] = inner
            .comparisons
            .scope(group, context.network)
            .iter()
            .find(|cell| {
                matches!(&cell.key, Key::Traffic(current) if current == &key)
                    && cell.valid(inner, Some(parent))
            });
    }
    let mut counts = [0; 2];
    if let (Some(origin), [Some(left), Some(right)]) = (inner.comparisons.origin, cells) {
        let timing = left.key.timing()?;
        let (sides, _) = accumulate_common(
            &left.metrics[0],
            &right.metrics[0],
            origin,
            now,
            timing,
            u8::MAX,
            |_| {},
        )?;
        counts = sides.map(|side| side.distinct.min(REPORTERS) as u8);
    }
    Some((counts, identity.finish()))
}
