//! Bounded evaluation set: which members receive comparisons and optional validation. Its size
//! follows the optional work earned from offered business, so a large group only evaluates as
//! many challengers as that business can fund.
use super::ranking::utility;
use super::*;
use honk_config::node::Node;

const REFRESH: Duration = Duration::from_secs(5 * 60);
const ROTATION_SLOT: Duration = Duration::from_secs(10 * 60);
const DEMAND_HALF_LIFE: Duration = Duration::from_secs(5 * 60);
const MIN_MEMBERS: usize = 3;
/// Bounds per-group evaluation work; comparison storage has its own independent limit.
const MAX_MEMBERS: usize = 25;
/// Share of earned optional work spent keeping members qualified; the rest funds response pairs.
const QUALIFICATION_SHARE: f64 = 0.5;
/// Ranked members keep their place until they fall this far below the cut, so ties cannot churn it.
const RANK_HYSTERESIS: usize = 2;
/// Recent Apply winners whose configured-probe cells stay admissible outside the ranked set.
const ANCHORS: usize = 4;

#[derive(Clone, Default)]
pub(super) struct EvaluationSet {
    /// Explicit ranked identities.
    ranked: Vec<Uuid>,
    rotation: Option<(Uuid, Instant)>,
    anchors: Vec<Uuid>,
    refreshed_at: Option<Instant>,
    limit: usize,
    demand: Option<(Instant, f64)>,
}

impl EvaluationSet {
    /// Counts an original business at the same deduplicated point as `business_starts`.
    pub(super) fn record_demand(&mut self, now: Instant) {
        self.demand = Some((now, self.demand_now(now) + 1.0));
    }

    fn demand_now(&self, now: Instant) -> f64 {
        self.demand.map_or(0.0, |(at, starts)| {
            starts
                * (-now.saturating_duration_since(at).as_secs_f64()
                    / DEMAND_HALF_LIFE.as_secs_f64())
                .exp2()
        })
    }

    /// Members the earned currency can keep qualified: each needs four effective completions under
    /// the evidence half-life, funded by one optional start per earning period.
    fn target_limit(&self, now: Instant) -> usize {
        let sustained = self.demand_now(now) * SCORE_EVIDENCE_HALF_LIFE.as_secs_f64()
            / DEMAND_HALF_LIFE.as_secs_f64();
        let challengers = QUALIFICATION_SHARE * sustained
            / (PERFORMANCE_VALIDATION_SAMPLES * SCORE_EXPLORATION_PERIOD as f64);
        (1 + challengers as usize).clamp(MIN_MEMBERS, MAX_MEMBERS)
    }

    /// Whether this member may receive comparisons and optional work under the stored set.
    pub(super) fn evaluates(&self, node: Uuid) -> bool {
        self.ranked.contains(&node) || self.rotation.is_some_and(|(id, _)| id == node)
    }

    /// Whether probe comparison cells for this member are outside the bounded store budget.
    pub(super) fn excludes(&self, node: Uuid) -> bool {
        self.refreshed_at.is_some() && !self.evaluates(node) && !self.anchors.contains(&node)
    }

    pub(super) fn anchor(&mut self, node: Uuid) {
        self.anchors.retain(|id| *id != node);
        self.anchors.insert(0, node);
        self.anchors.truncate(ANCHORS);
    }

    /// Membership changes keep only the decayed demand, which reflects offered business.
    pub(super) fn reset_members(&mut self) {
        *self = Self {
            demand: self.demand,
            ..Self::default()
        };
    }

    /// Evaluated flags aligned with `nodes`; the decision reference is evaluated even when it sits
    /// outside the stored set.
    pub(super) fn membership(&self, nodes: &[&Node], reference: usize) -> Vec<bool> {
        nodes
            .iter()
            .enumerate()
            .map(|(index, node)| index == reference || self.evaluates(node.id))
            .collect()
    }
}

/// Only Apply refreshes committed participants.
pub(super) fn derive<'a>(
    stored: Option<&'a EvaluationSet>,
    nodes: &[&Node],
    snapshots: &[ScoreSnapshot],
    baseline: PerformanceBaseline,
    now: Instant,
    apply: bool,
) -> std::borrow::Cow<'a, EvaluationSet> {
    if !apply && let Some(set) = stored.filter(|set| set.refreshed_at.is_some()) {
        return std::borrow::Cow::Borrowed(set);
    }
    let mut set = stored.cloned().unwrap_or_default();
    if set
        .refreshed_at
        .is_none_or(|at| now.saturating_duration_since(at) >= REFRESH)
    {
        let target = set.target_limit(now);
        // Growth waits for a refresh; shrinking also needs a two-member margin.
        if target > set.limit || target + 2 <= set.limit {
            set.limit = target;
        }
        let utilities: Vec<_> = snapshots
            .iter()
            .map(|score| utility(score, baseline))
            .collect();
        // Untried members tie on utility; the configured probe then hints the promising ones.
        // Only one measurement scope is comparable, so use the members' most common one.
        let mut scopes: Vec<_> = snapshots.iter().map(|score| score.probe_scope).collect();
        scopes.sort_unstable();
        let scope = scopes
            .chunk_by(|left, right| left == right)
            .max_by_key(|run| run.len())
            .map_or(0, |run| run[0]);
        let probe = |index: usize| {
            (snapshots[index].probe_scope == scope)
                .then_some(snapshots[index].probe.value)
                .flatten()
                .unwrap_or(f64::INFINITY)
        };
        let mut order: Vec<_> = (0..nodes.len()).collect();
        order.sort_by(|&left, &right| {
            utilities[right]
                .total_cmp(&utilities[left])
                .then_with(|| probe(left).total_cmp(&probe(right)))
                .then_with(|| nodes[left].id.cmp(&nodes[right].id))
        });
        let ranked_len = if nodes.len() > set.limit {
            set.limit - 1
        } else {
            set.limit
        };
        let rank = |id: &Uuid| order.iter().position(|&index| nodes[index].id == *id);
        // A member missing from this filtered or retry view keeps its place; absence is not removal.
        set.ranked
            .retain(|id| rank(id).is_none_or(|rank| rank < ranked_len + RANK_HYSTERESIS));
        set.ranked.sort_by_key(|id| rank(id).unwrap_or(usize::MAX));
        set.ranked.truncate(ranked_len);
        for &index in &order {
            if set.ranked.len() == ranked_len {
                break;
            }
            if !set.ranked.contains(&nodes[index].id) {
                set.ranked.push(nodes[index].id);
            }
        }
        set.refreshed_at = Some(now);
    }
    if set.ranked.len() == set.limit {
        set.rotation = None;
    } else if set.rotation.is_none_or(|(id, since)| {
        set.ranked.contains(&id) || now.saturating_duration_since(since) >= ROTATION_SLOT
    }) {
        let previous = set.rotation.map(|(id, _)| id);
        set.rotation = nodes
            .iter()
            .map(|node| node.id)
            .filter(|id| !set.ranked.contains(id))
            .min_by_key(|id| (previous.is_some_and(|old| *id <= old), *id))
            .map(|id| (id, now));
    }
    std::borrow::Cow::Owned(set)
}
