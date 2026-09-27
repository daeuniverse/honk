//! One bounded serving pool per Score group/network, shared by ordinary and optional work.
use super::evidence::decay;
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

#[derive(Clone)]
struct Member {
    node: Uuid,
    via: Option<Arc<str>>,
}

#[derive(Clone, Default)]
pub(super) struct EvaluationSet {
    /// Explicit ranked identities.
    ranked: Vec<Member>,
    rotation: Option<(Member, Instant)>,
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

    /// This group's recent offered original business in flows per second.
    pub(super) fn offered_rate(&self, now: Instant) -> f64 {
        // A decayed count with half-life h approximates rate × h / ln 2 under steady load.
        self.demand_now(now) * std::f64::consts::LN_2 / DEMAND_HALF_LIFE.as_secs_f64()
    }

    fn demand_now(&self, now: Instant) -> f64 {
        self.demand.map_or(0.0, |(at, starts)| {
            starts * decay(now.saturating_duration_since(at), DEMAND_HALF_LIFE)
        })
    }

    /// Members the earned currency can keep qualified: each needs four effective completions under
    /// the evidence half-life, funded by one optional start per base earning period. The group's
    /// exploration target (about √n) caps it, so trials concentrate on few enough members to
    /// reach comparisons.
    fn target_limit(&self, now: Instant, candidates: usize) -> usize {
        let sustained = self.demand_now(now) * SCORE_EVIDENCE_HALF_LIFE.as_secs_f64()
            / DEMAND_HALF_LIFE.as_secs_f64();
        let challengers = QUALIFICATION_SHARE * sustained
            / (PERFORMANCE_VALIDATION_SAMPLES * SCORE_EXPLORATION_PERIOD as f64);
        // A filtered view cannot reduce committed capacity; only falling demand or reload can.
        let cap = super::budget::exploration_target(candidates)
            .clamp(MIN_MEMBERS, MAX_MEMBERS)
            .max(self.limit);
        (1 + challengers as usize).clamp(MIN_MEMBERS, cap)
    }

    /// Whether this member belongs to the committed serving pool.
    pub(super) fn evaluates(&self, node: Uuid) -> bool {
        self.ranked.iter().any(|member| member.node == node)
            || self
                .rotation
                .as_ref()
                .is_some_and(|(member, _)| member.node == node)
    }

    pub(super) fn initialized(&self) -> bool {
        self.refreshed_at.is_some()
    }

    /// Whether probe comparison cells for this member are outside the bounded store budget.
    pub(super) fn excludes(&self, node: Uuid) -> bool {
        self.refreshed_at.is_some() && !self.evaluates(node) && !self.anchors.contains(&node)
    }

    pub(super) fn anchor(&mut self, node: Uuid, now: Instant) {
        self.anchors.retain(|id| *id != node);
        self.anchors.insert(0, node);
        self.anchors.truncate(ANCHORS);
        if self
            .rotation
            .as_ref()
            .is_some_and(|(member, _)| member.node == node)
        {
            // A serving winner trades places with a ranked member instead of expiring as a trial.
            let (mut winner, _) = self.rotation.take().expect("matching rotation member");
            if let Some(last) = self.ranked.last_mut() {
                std::mem::swap(last, &mut winner);
                self.rotation = Some((winner, now));
            } else {
                self.ranked.push(winner);
            }
        }
    }

    /// Membership changes keep only the decayed demand, which reflects offered business.
    pub(super) fn reset_members(&mut self) {
        *self = Self {
            demand: self.demand,
            ..Self::default()
        };
    }

    pub(super) fn membership(&self, nodes: &[&Node]) -> Vec<bool> {
        nodes.iter().map(|node| self.evaluates(node.id)).collect()
    }
}

/// Prepare membership; the caller commits it only for authorized Apply.
pub(super) fn derive<'a, 'view>(
    stored: Option<&'a EvaluationSet>,
    nodes: &[&Node],
    snapshots: &[ScoreSnapshot],
    now: Instant,
    apply: bool,
    representatives: impl Clone + Iterator<Item = (Uuid, Option<&'view str>)>,
    mut replaceable: impl FnMut((Uuid, Option<&str>)) -> bool,
) -> std::borrow::Cow<'a, EvaluationSet> {
    if !apply && let Some(set) = stored.filter(|set| set.refreshed_at.is_some()) {
        return std::borrow::Cow::Borrowed(set);
    }
    let mut set = stored.cloned().unwrap_or_default();
    let member = |node| Member {
        node,
        via: representatives
            .clone()
            .find(|(id, _)| *id == node)
            .and_then(|(_, via)| via)
            .map(Arc::from),
    };
    let mut replaced = false;
    for slot in set
        .ranked
        .iter_mut()
        .chain(set.rotation.iter_mut().map(|(slot, _)| slot))
    {
        if let Some(via) = slot.via.as_deref()
            && let Some((node, _)) = representatives
                .clone()
                .find(|(_, owner)| *owner == Some(via))
            && slot.node != node
        {
            slot.node = node;
            replaced = true;
        }
    }
    if replaced {
        // Subgroups can converge on one leaf; at most 25 slots need in-place deduplication.
        let mut index = 0;
        while index < set.ranked.len() {
            if set.ranked[..index]
                .iter()
                .any(|member| member.node == set.ranked[index].node)
            {
                set.ranked.remove(index);
            } else {
                index += 1;
            }
        }
    }
    let failing = |score: &ScoreSnapshot| score.node_fail_streak >= SCORE_FAIL_STREAK_EXCLUDE;
    // A failed or health-unavailable owner can already be absent from the current view.
    let mut failing_member = |member: &Member| replaceable((member.node, member.via.as_deref()));
    let substitute = set.ranked.iter().any(&mut failing_member)
        && nodes.iter().zip(snapshots).any(|(node, score)| {
            !failing(score) && !set.ranked.iter().any(|member| member.node == node.id)
        });
    let due = set
        .refreshed_at
        .is_none_or(|at| now.saturating_duration_since(at) >= REFRESH);
    if due || substitute || replaced {
        let target = set.target_limit(now, nodes.len());
        // Growth waits for a refresh; shrinking also needs a two-member margin.
        if due && (target > set.limit || target + 2 <= set.limit) {
            set.limit = target;
        }
        let baseline = super::ranking::performance_baseline(snapshots.iter());
        let utilities: Vec<_> = snapshots
            .iter()
            .map(|score| {
                (
                    super::ranking::normal_eligible(score, baseline),
                    utility(score, baseline),
                )
            })
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
                .0
                .cmp(&utilities[left].0)
                .then_with(|| utilities[right].1.total_cmp(&utilities[left].1))
                .then_with(|| probe(left).total_cmp(&probe(right)))
                .then_with(|| nodes[left].id.cmp(&nodes[right].id))
        });
        if !set.initialized() && !nodes.is_empty() {
            // The first ordinary winner occupies a ranked slot, never an extra member slot.
            let first = super::ranking::best_index(snapshots, nodes, baseline, |_| true).index;
            let position = order
                .iter()
                .position(|index| *index == first)
                .expect("winner in candidate order");
            order[..=position].rotate_right(1);
        }
        let ranked_len = if nodes.len() > set.limit {
            set.limit - 1
        } else {
            set.limit
        };
        let rank = |member: &Member| {
            order
                .iter()
                .position(|&index| nodes[index].id == member.node)
        };
        // A member missing from this filtered or retry view keeps its place; absence is not removal.
        set.ranked
            .retain(|id| rank(id).is_none_or(|rank| rank < ranked_len + RANK_HYSTERESIS));
        set.ranked
            .sort_by_key(|id| (failing_member(id), rank(id).unwrap_or(usize::MAX)));
        set.ranked.truncate(ranked_len);
        let mut healthy = set.ranked.partition_point(|id| !failing_member(id));
        for &index in &order {
            if healthy == ranked_len {
                break;
            }
            if !failing(&snapshots[index])
                && !set
                    .ranked
                    .iter()
                    .any(|member| member.node == nodes[index].id)
            {
                if set.ranked.len() == ranked_len {
                    set.ranked.pop();
                }
                set.ranked.insert(healthy, member(nodes[index].id));
                healthy += 1;
            }
        }
        // Without enough replacements, failing members retain access to funded recovery.
        for &index in &order {
            if set.ranked.len() == ranked_len {
                break;
            }
            if !set
                .ranked
                .iter()
                .any(|member| member.node == nodes[index].id)
            {
                set.ranked.push(member(nodes[index].id));
            }
        }
        if due {
            set.refreshed_at = Some(now);
        }
    }
    let replace_rotation = set
        .rotation
        .as_ref()
        .is_some_and(|(slot, _)| failing_member(slot))
        && nodes.iter().zip(snapshots).any(|(node, score)| {
            !failing(score) && !set.ranked.iter().any(|member| member.node == node.id)
        });
    if set.ranked.len() == set.limit {
        set.rotation = None;
    } else if set.rotation.as_ref().is_none_or(|(slot, since)| {
        replace_rotation
            || set.ranked.iter().any(|member| member.node == slot.node)
            || now.saturating_duration_since(*since) >= ROTATION_SLOT
    }) {
        let previous = set.rotation.as_ref().map(|(member, _)| member.node);
        set.rotation = nodes
            .iter()
            .zip(snapshots)
            .filter(|(node, score)| {
                (!replace_rotation || !failing(score))
                    && !set.ranked.iter().any(|member| member.node == node.id)
            })
            .map(|(node, _)| node.id)
            .min_by_key(|id| (previous.is_some_and(|old| *id <= old), *id))
            .map(|id| (member(id), now));
    }
    for slot in set
        .ranked
        .iter_mut()
        .chain(set.rotation.iter_mut().map(|(slot, _)| slot))
    {
        if let Some((_, via)) = representatives.clone().find(|(node, _)| *node == slot.node)
            && slot.via.as_deref() != via
        {
            slot.via = via.map(Arc::from);
        }
    }
    std::borrow::Cow::Owned(set)
}
