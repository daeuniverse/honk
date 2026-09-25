use super::super::evidence::{CellStamp, Observation};
use super::super::{
    AggregateKey, ExactKey, MAX_THROUGHPUT_DURATION, MIN_THROUGHPUT_BYTES, MIN_THROUGHPUT_DURATION,
    ScoreAttribution, ScoreSelectionContext, ScoreSource, ScoreTarget, SelectionNetwork,
    SelectionReasonKey, StartedCells, StateInner, Stats,
};
use super::{BLOCKS, MAX_CELLS, MAX_KEY_BYTES, MAX_LOGICAL_BYTES, REPORTERS};
use lru::LruCache;
use std::cmp::Ordering;
use std::mem::size_of;
use std::time::{Duration, Instant};
use uuid::Uuid;

const BLOCK_SECONDS: u64 = 15;
const LIFETIME: Duration = Duration::from_secs(BLOCK_SECONDS * BLOCKS as u64);

#[derive(Clone, Copy, Default)]
pub(super) struct Bucket {
    pub(super) block: u64,
    pub(super) count: u32,
    pub(super) sum: f64,
    pub(super) last: Option<Instant>,
    pub(super) reporters: [u64; REPORTERS],
}

impl Bucket {
    fn record(&mut self, block: u64, value: f64, reporter: u64, now: Instant) {
        if self.count == 0 || self.block != block {
            *self = Self {
                block,
                ..Self::default()
            };
        }
        if self.count == u32::MAX {
            return;
        }
        self.count += 1;
        self.sum += value;
        self.last = Some(self.last.map_or(now, |at| at.max(now)));
        if !self.reporters.contains(&reporter)
            && let Some(slot) = self.reporters.iter_mut().find(|id| **id == 0)
        {
            *slot = reporter;
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) enum Key {
    Traffic(ExactKey),
    Probe {
        key: AggregateKey,
        scope: u64,
        slot: usize,
        interval: Option<Duration>,
    },
}

impl Key {
    pub(super) fn group(&self) -> &str {
        match self {
            Self::Traffic(key) => &key.group,
            Self::Probe { key, .. } => &key.group,
        }
    }

    pub(super) fn node(&self) -> Uuid {
        match self {
            Self::Traffic(key) => key.node_id,
            Self::Probe { key, .. } => key.node_id,
        }
    }

    pub(super) fn network(&self) -> SelectionNetwork {
        match self {
            Self::Traffic(key) => key.network,
            Self::Probe { key, .. } => key.network,
        }
    }

    pub(super) fn timing(&self) -> Option<Timing> {
        let interval = match self {
            Self::Probe { interval, .. } => *interval,
            Self::Traffic(_) => None,
        };
        let doubled = match interval {
            Some(interval) if !interval.is_zero() => interval.checked_mul(2)?,
            Some(_) => return None,
            None => Duration::ZERO,
        };
        let width = Duration::from_secs(BLOCK_SECONDS).max(doubled);
        width.checked_mul(BLOCKS as u32)?;
        Some(Timing {
            width,
            freshness: LIFETIME.max(doubled),
        })
    }

    fn heap_bytes(&self) -> usize {
        match self {
            Self::Traffic(key) => key.group.capacity() + target_bytes(&key.target),
            Self::Probe { key, .. } => key.group.capacity(),
        }
    }

    pub(super) fn cohort_cmp(&self, other: &Self) -> Ordering {
        self.group()
            .cmp(other.group())
            .then_with(|| (self.network() as u8).cmp(&(other.network() as u8)))
            .then_with(|| match (self, other) {
                (Self::Traffic(left), Self::Traffic(right)) => (left.family as u8)
                    .cmp(&(right.family as u8))
                    .then_with(|| target_cmp(&left.target, &right.target)),
                (
                    Self::Probe {
                        scope: left,
                        slot: a,
                        interval: left_interval,
                        ..
                    },
                    Self::Probe {
                        scope: right,
                        slot: b,
                        interval: right_interval,
                        ..
                    },
                ) => a
                    .cmp(b)
                    .then_with(|| left.cmp(right))
                    .then_with(|| left_interval.cmp(right_interval)),
                (Self::Traffic(_), Self::Probe { .. }) => Ordering::Less,
                (Self::Probe { .. }, Self::Traffic(_)) => Ordering::Greater,
            })
    }

    fn cmp(&self, other: &Self) -> Ordering {
        self.cohort_cmp(other)
            .then_with(|| self.node().cmp(&other.node()))
    }

    fn stamp<'a>(
        &self,
        aggregate: &'a LruCache<AggregateKey, Stats>,
        exact: &'a LruCache<ExactKey, Stats>,
        node: Option<&Stats>,
    ) -> Option<CellStamp<'a>> {
        match self {
            Self::Traffic(key) => CellStamp::current(exact.peek(key)?, node),
            Self::Probe { key, .. } => aggregate.peek(key).map(CellStamp::own),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Timing {
    width: Duration,
    pub(super) freshness: Duration,
}

impl Timing {
    pub(super) fn deadline(self, origin: Instant, block: u64) -> Option<Instant> {
        let nanos = self
            .width
            .as_nanos()
            .checked_mul(u128::from(block.checked_add(BLOCKS as u64)?))?;
        let duration = Duration::new(
            u64::try_from(nanos / 1_000_000_000).ok()?,
            (nanos % 1_000_000_000) as u32,
        );
        origin.checked_add(duration)
    }

    pub(super) fn common(
        self,
        left: &Bucket,
        right: &Bucket,
        origin: Instant,
        now: Instant,
    ) -> bool {
        left.count > 0
            && right.count > 0
            && left.block == right.block
            && left.last.is_some_and(|at| at <= now)
            && right.last.is_some_and(|at| at <= now)
            && self
                .deadline(origin, left.block)
                .is_some_and(|until| now < until)
    }
}

fn target_bytes(target: &ScoreTarget) -> usize {
    match target {
        ScoreTarget::Domain { host, .. } => host.capacity(),
        ScoreTarget::Socket(_) => 0,
    }
}

fn target_cmp(left: &ScoreTarget, right: &ScoreTarget) -> Ordering {
    match (left, right) {
        (ScoreTarget::Domain { host: a, port: ap }, ScoreTarget::Domain { host: b, port: bp }) => {
            a.cmp(b).then_with(|| ap.cmp(bp))
        }
        (ScoreTarget::Socket(a), ScoreTarget::Socket(b)) => a.cmp(b),
        (ScoreTarget::Domain { .. }, ScoreTarget::Socket(_)) => Ordering::Less,
        (ScoreTarget::Socket(_), ScoreTarget::Domain { .. }) => Ordering::Greater,
    }
}

pub(super) struct Cell {
    pub(super) key: Key,
    incarnation: u64,
    invalidated_through: Option<Instant>,
    pub(super) metrics: [[Bucket; BLOCKS]; 3],
    touched: Instant,
}

impl Cell {
    pub(super) fn valid(&self, inner: &StateInner, node: Option<&Stats>) -> bool {
        self.key
            .stamp(&inner.aggregate, &inner.exact, node)
            .is_some_and(|stamp| {
                stamp.stats.incarnation == self.incarnation
                    && stamp.invalidated_through == self.invalidated_through
                    && match &self.key {
                        Key::Probe { scope, slot, .. } => stamp.stats.probes[*slot].scope == *scope,
                        Key::Traffic(_) => true,
                    }
            })
    }
}

#[derive(Default)]
pub(in crate::group::score) struct Store {
    pub(super) cells: Vec<Cell>,
    pub(super) origin: Option<Instant>,
    key_bytes: usize,
    pub(in crate::group::score) expired: u64,
    pub(in crate::group::score) evicted: u64,
    pub(in crate::group::score) rejected: u64,
}

// Vec has no hidden per-entry links/buckets. String capacities, the Vec's full
// allocation and the Store itself are all charged, including unused slots.
const _: () = assert!(
    size_of::<Store>() + MAX_CELLS * (size_of::<Cell>() + MAX_KEY_BYTES) <= MAX_LOGICAL_BYTES
);

impl Store {
    pub(in crate::group::score) fn clear(&mut self) {
        self.cells.clear();
        self.key_bytes = 0;
        self.origin = None;
    }

    pub(in crate::group::score) fn logical_bytes(&self) -> usize {
        size_of::<Self>() + self.cells.capacity() * size_of::<Cell>() + self.key_bytes
    }

    pub(in crate::group::score) fn cell_count(&self) -> usize {
        self.cells.len()
    }

    pub(in crate::group::score) fn logical_capacity_bound() -> usize {
        size_of::<Self>() + MAX_CELLS * (size_of::<Cell>() + MAX_KEY_BYTES)
    }

    /// Cells are ordered by group, then network.
    fn scope(&self, group: &str, network: SelectionNetwork) -> &[Cell] {
        fn key(cell: &Cell) -> (&str, u8) {
            (cell.key.group(), cell.key.network() as u8)
        }
        let wanted = (group, network as u8);
        let start = self.cells.partition_point(|cell| key(cell) < wanted);
        let len = self.cells[start..].partition_point(|cell| key(cell) == wanted);
        &self.cells[start..start + len]
    }

    /// Consecutive cells of one comparison cohort, in store order.
    pub(super) fn cohorts(
        &self,
        group: &str,
        network: SelectionNetwork,
    ) -> impl Iterator<Item = &[Cell]> {
        self.scope(group, network)
            .chunk_by(|left, right| left.key.cohort_cmp(&right.key) == Ordering::Equal)
    }

    fn remove(&mut self, index: usize) {
        self.key_bytes -= self.cells.remove(index).key.heap_bytes();
    }

    /// One order-preserving pass; returns how many cells were dropped.
    fn retain(&mut self, mut keep: impl FnMut(&Cell) -> bool) -> u64 {
        let (mut removed, mut bytes) = (0, 0);
        self.cells.retain(|cell| {
            let kept = keep(cell);
            if !kept {
                removed += 1;
                bytes += cell.key.heap_bytes();
            }
            kept
        });
        self.key_bytes -= bytes;
        removed
    }

    pub(in crate::group::score) fn invalidate_probe(
        &mut self,
        group: &str,
        network: SelectionNetwork,
        node: Uuid,
        scope: u64,
        slot: usize,
    ) {
        self.retain(|cell| {
            !matches!(&cell.key, Key::Probe { key, scope: old_scope, slot: old_slot, .. }
                if key.group == group && key.network == network && key.node_id == node
                    && *old_scope == scope && *old_slot == slot)
        });
    }

    fn record(
        &mut self,
        key: Key,
        CellStamp {
            stats,
            invalidated_through,
        }: CellStamp<'_>,
        values: [Option<f64>; 3],
        reporter: u64,
        now: Instant,
    ) {
        if let Key::Probe {
            key, scope, slot, ..
        } = &key
            && stats.probes[*slot].scope != *scope
        {
            // Stats still holds the previous scope until this observation is published.
            self.retain(|cell| {
                !matches!(&cell.key, Key::Probe { key: old, slot: old_slot, .. }
                    if old == key && old_slot == slot)
            });
        }
        if reporter == 0 || invalidated_through.is_some_and(|at| now <= at) {
            return;
        }
        let Some(timing) = key.timing() else {
            return;
        };
        let origin = *self.origin.get_or_insert(now);
        let Some(elapsed) = now.checked_duration_since(origin) else {
            return;
        };
        let Ok(block) = u64::try_from(elapsed.as_nanos() / timing.width.as_nanos()) else {
            return;
        };
        if timing.deadline(origin, block).is_none() {
            return;
        }
        let heap = key.heap_bytes();
        if heap > MAX_KEY_BYTES {
            self.rejected = self.rejected.saturating_add(1);
            return;
        }
        let mut index = self.cells.binary_search_by(|cell| cell.key.cmp(&key));
        if index.is_err() {
            let expired = self.retain(|cell| {
                cell.key.timing().is_some_and(|timing| {
                    now.saturating_duration_since(cell.touched) < timing.freshness
                })
            });
            self.expired = self.expired.saturating_add(expired);
            if self.cells.len() == MAX_CELLS
                && let Some((oldest, _)) = self
                    .cells
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, cell)| cell.touched)
            {
                self.remove(oldest);
                self.evicted = self.evicted.saturating_add(1);
            }
            if self.cells.capacity() == 0 {
                self.cells.reserve_exact(MAX_CELLS);
            }
            if self.logical_bytes().saturating_add(heap) > MAX_LOGICAL_BYTES {
                self.rejected = self.rejected.saturating_add(1);
                return;
            }
            index = self.cells.binary_search_by(|cell| cell.key.cmp(&key));
        }
        let index = match index {
            Ok(index) => index,
            Err(index) => {
                self.key_bytes += heap;
                self.cells.insert(
                    index,
                    Cell {
                        key,
                        incarnation: stats.incarnation,
                        invalidated_through,
                        metrics: [[Bucket::default(); BLOCKS]; 3],
                        touched: now,
                    },
                );
                index
            }
        };
        let cell = &mut self.cells[index];
        if cell.incarnation != stats.incarnation || cell.invalidated_through != invalidated_through
        {
            cell.metrics = [[Bucket::default(); BLOCKS]; 3];
            cell.incarnation = stats.incarnation;
            cell.invalidated_through = invalidated_through;
        }
        cell.touched = cell.touched.max(now);
        for (metric, value) in cell.metrics.iter_mut().zip(values) {
            if let Some(value) = value.filter(|value| value.is_finite() && *value >= 0.0) {
                let bucket = &mut metric[block as usize % BLOCKS];
                // A delayed callback cannot overwrite a newer block in the ring.
                if bucket.count == 0 || bucket.block <= block {
                    bucket.record(block, value, reporter, now);
                }
            }
        }
    }
}

pub(in crate::group::score) fn observe(
    inner: &mut StateInner,
    context: &ScoreSelectionContext,
    attributions: &[ScoreAttribution],
    (cells, reporter_id): (&[StartedCells], u64),
    source: ScoreSource,
    observation: &Observation,
    now: Instant,
) {
    if reporter_id == 0 && source != ScoreSource::HealthProbe {
        return;
    }
    let values = match (source, observation) {
        (ScoreSource::Traffic, Observation::Response(latency)) => {
            [Some(latency.as_secs_f64() * 1000.0), None, None]
        }
        (ScoreSource::Traffic, Observation::Transfer { tx, rx, elapsed })
            if *elapsed >= MIN_THROUGHPUT_DURATION && *elapsed <= MAX_THROUGHPUT_DURATION =>
        {
            [
                None,
                (*tx >= MIN_THROUGHPUT_BYTES).then(|| *tx as f64 / elapsed.as_secs_f64()),
                (*rx >= MIN_THROUGHPUT_BYTES).then(|| *rx as f64 / elapsed.as_secs_f64()),
            ]
        }
        (ScoreSource::HealthProbe, Observation::Probe { latency, .. }) => {
            [Some(latency.as_secs_f64() * 1000.0), None, None]
        }
        _ => return,
    };
    for (attribution, started) in attributions.iter().zip(cells) {
        if attribution.group.len() > MAX_KEY_BYTES {
            inner.comparisons.rejected = inner.comparisons.rejected.saturating_add(1);
            continue;
        }
        // Unevaluated members keep probe baselines in their stats, not bounded comparison cells.
        if matches!(observation, Observation::Probe { .. })
            && inner
                .evaluation
                .get(&SelectionReasonKey::new(
                    &attribution.group,
                    context.network,
                ))
                .is_some_and(|set| set.excludes(attribution.node_id))
        {
            continue;
        }
        let (key, captured) = match observation {
            Observation::Probe {
                scope,
                slot,
                interval,
                ..
            } => (
                Key::Probe {
                    key: AggregateKey {
                        group: attribution.group.clone(),
                        network: context.network,
                        family: None,
                        node_id: attribution.node_id,
                    },
                    scope: *scope,
                    slot: *slot,
                    interval: *interval,
                },
                started.aggregate[0],
            ),
            _ => {
                let (Some(family), Some(target)) = (context.target_family, context.target.as_ref())
                else {
                    continue;
                };
                if attribution.group.len().saturating_add(target_bytes(target)) > MAX_KEY_BYTES {
                    inner.comparisons.rejected = inner.comparisons.rejected.saturating_add(1);
                    continue;
                }
                (
                    Key::Traffic(ExactKey {
                        group: attribution.group.clone(),
                        network: context.network,
                        family,
                        target: target.clone(),
                        node_id: attribution.node_id,
                    }),
                    started.exact,
                )
            }
        };
        // Only the admitted incarnation may publish; evicted cells are not recreated here.
        let node = match &key {
            Key::Traffic(key) => inner.aggregate.peek(&AggregateKey {
                group: key.group.clone(),
                network: key.network,
                family: None,
                node_id: key.node_id,
            }),
            Key::Probe { key, .. } => inner.aggregate.peek(key),
        };
        let stamp =
            key.stamp(&inner.aggregate, &inner.exact, node)
                .filter(|stamp| {
                    captured == Some(stamp.stats.incarnation)
                        && match &key {
                            Key::Probe { .. } => true,
                            Key::Traffic(_) => node
                                .is_some_and(|node| started.aggregate[0] == Some(node.incarnation)),
                        }
                });
        if let Some(stamp) = stamp {
            inner
                .comparisons
                .record(key, stamp, values, reporter_id, now);
        }
    }
}
