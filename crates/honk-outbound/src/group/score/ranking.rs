use super::evidence::{CellStamp, evidence_decay};
use super::{
    AggregateKey, ExactKey, MIN_TRAINED_EVIDENCE, MetricSnapshot, PERFORMANCE_SWITCH_MARGIN,
    PerformanceBaseline, PerformanceSnapshot, RELIABILITY_CLOSE, RankedSelection,
    SCORE_EXPLORE_BACKOFF_BASE, SCORE_EXPLORE_BACKOFF_MAX, SCORE_FAIL_STREAK_EXCLUDE,
    SCORE_SWITCH_FULL_EVIDENCE, ScoreAuthority, ScorePolicyState, ScoreSelectionContext,
    ScoreSnapshot, SelectionCadenceKey, SelectionHistoryKey, SelectionReason, SelectionReasonKey,
    StateInner, Stats, budget, comparison,
};
use honk_config::node::Node;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub(super) fn explore_backoff(streak: u32) -> Duration {
    SCORE_EXPLORE_BACKOFF_BASE
        .saturating_mul(2u32.saturating_pow(streak.saturating_sub(1).min(7)))
        .min(SCORE_EXPLORE_BACKOFF_MAX)
}

pub(super) struct Decision {
    pub scores: Vec<ScoreSnapshot>,
    pub evidence: Vec<super::verification::VerificationEvidence>,
    pub pairs: comparison::PairCohort,
    pub baseline: PerformanceBaseline,
    pub ordinary: RankedSelection,
    pub evaluation: Option<super::evaluation::EvaluationSet>,
    /// Aligned with `scores`: members that may receive comparison pairs, evidence and optional
    /// work.
    pub membership: Vec<bool>,
}

pub(super) fn decision(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    nodes: &[&Node],
    now: Instant,
    apply: bool,
) -> Decision {
    let view = comparison::View::new(inner, group, context, nodes, now);
    let (mut decision, evaluation) = ordinary_decision(&view, apply);
    if decision.ordinary.index != decision.pairs.reference {
        // The winner is always evaluated, even when it was outside the stored set.
        decision.membership = evaluation.membership(nodes, decision.ordinary.index);
        decision.pairs = view.pairs(
            (&decision.scores, decision.baseline),
            (&decision.membership, decision.ordinary.index),
        );
    }
    decision.evidence = view.node_evidence(&decision.membership);
    decision.evaluation = apply.then(|| evaluation.into_owned());
    decision
}

/// The ordinary choice alone: no verification evidence, and pairs stay bound to the incumbent.
fn ordinary_decision<'a>(
    view: &comparison::View<'a>,
    apply: bool,
) -> (
    Decision,
    std::borrow::Cow<'a, super::evaluation::EvaluationSet>,
) {
    let (inner, group, context, nodes, now) =
        (view.inner, view.group, view.context, view.nodes, view.now);
    let scores = score_snapshots(inner, group, context, nodes.iter().map(|node| node.id), now);
    let baseline = performance_baseline(&scores);
    let incumbent = inner
        .selection_history
        .peek(&SelectionHistoryKey::new(group, context))
        .and_then(|history| nodes.iter().position(|node| node.id == history.current));
    let reference = incumbent.unwrap_or_else(|| best_index(&scores, nodes, baseline).index);
    let evaluation = super::evaluation::derive(
        inner
            .evaluation
            .get(&SelectionReasonKey::new(group, context.network)),
        nodes,
        &scores,
        baseline,
        now,
        apply,
    );
    let membership = evaluation.membership(nodes, reference);
    let pairs = view.pairs((&scores, baseline), (&membership, reference));
    let ordinary = ordinary_selection(&scores, nodes, incumbent, baseline, &pairs);
    (
        Decision {
            scores,
            evidence: Vec::new(),
            pairs,
            baseline,
            ordinary,
            evaluation: None,
            membership,
        },
        evaluation,
    )
}

impl ScorePolicyState {
    pub(in crate::group) fn rank(
        self: &Arc<Self>,
        authority: &Arc<ScoreAuthority>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        allow_trials: bool,
    ) -> (usize, Option<Arc<budget::Work>>) {
        self.rank_inner(
            Some(authority),
            group,
            context,
            nodes,
            Instant::now(),
            allow_trials,
        )
    }

    pub(in crate::group) fn peek_rank(
        self: &Arc<Self>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
    ) -> usize {
        self.rank_inner(None, group, context, nodes, Instant::now(), false)
            .0
    }

    #[cfg(test)]
    pub(super) fn peek_rank_at(
        self: &Arc<Self>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
    ) -> usize {
        self.rank_inner(None, group, context, nodes, now, false).0
    }

    #[cfg(test)]
    pub(super) fn rank_at(
        self: &Arc<Self>,
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
        self.rank_inner(Some(&authority), group, context, nodes, now, true)
            .0
    }

    #[cfg(test)]
    pub(super) fn rank_plan_at(
        self: &Arc<Self>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
    ) -> (usize, super::ScoreAttempt) {
        let authority = self
            .inner
            .lock()
            .active_authority
            .clone()
            .expect("published test membership");
        let (index, reservation) =
            self.rank_inner(Some(&authority), group, context, nodes, now, true);
        let feedback = super::ScoreAttempt::planned(
            super::ScoreFeedback::new(
                Arc::clone(self),
                authority,
                context.clone(),
                vec![super::ScoreAttribution {
                    group: group.to_owned(),
                    node_id: nodes[index].id,
                }],
            ),
            Arc::new(budget::Opportunity::default()),
            reservation.into_iter().collect(),
            super::ScoreTrialSource::None,
        );
        (index, feedback)
    }

    fn rank_inner(
        self: &Arc<Self>,
        authority: Option<&Arc<ScoreAuthority>>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
        allow_trials: bool,
    ) -> (usize, Option<Arc<budget::Work>>) {
        if nodes.is_empty() {
            return (0, None);
        }
        let mut inner = self.inner.lock();
        let authorized = authority.is_some_and(|authority| {
            inner
                .active_authority
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, authority))
        }) && inner.valid_groups.contains(group);
        if !authorized {
            let view = comparison::View::new(&inner, group, context, nodes, now);
            return (ordinary_decision(&view, false).0.ordinary.index, None);
        }
        let mut decision = decision(&inner, group, context, nodes, now, true);
        let mut set = decision
            .evaluation
            .take()
            .expect("Apply prepares membership");
        let snapshots = &decision.scores;
        let performance = decision.baseline;
        let ordinary = decision.ordinary;
        let cadence_key = SelectionCadenceKey::new(group, context);
        set.anchor(nodes[ordinary.index].id);
        inner
            .evaluation
            .insert(SelectionReasonKey::new(group, context.network), set);
        let history_key = SelectionHistoryKey::new(group, context);
        inner
            .revalidated_at
            .entry(cadence_key.clone())
            .or_insert(now);
        let mut selection = ordinary;
        let mut reservation = None;
        // An ordinary escape to a different leaf serves the business instead of a trial; a
        // bypass label alone must not starve funded validation of alternatives.
        let escaping = matches!(
            ordinary.reason,
            SelectionReason::IncumbentIneligible | SelectionReason::FreshFailureBypass
        ) && inner
            .selection_history
            .peek(&history_key)
            .is_some_and(|history| history.current != nodes[ordinary.index].id);
        if allow_trials && context.target.is_some() && !escaping {
            (selection, reservation) = super::verification::plan(
                self,
                &mut inner,
                (group, context),
                &decision,
                nodes,
                now,
            );
        }
        if selection.reason.is_exploration() {
            if snapshots[ordinary.index]
                .carrier_pressure_at
                .is_some_and(|at| {
                    inner
                        .revalidated_at
                        .get(&cadence_key)
                        .is_some_and(|revalidated_at| at > *revalidated_at)
                })
            {
                let counts = inner
                    .selection_reasons
                    .entry(SelectionReasonKey::new(group, context.network))
                    .or_default();
                counts.carrier_validation = counts.carrier_validation.saturating_add(1);
            }
            if let Some(revalidated_at) = inner.revalidated_at.get_mut(&cadence_key) {
                *revalidated_at = now;
            }
        }
        Self::record_verification(
            &mut inner,
            &history_key,
            super::verification::usable(&decision.evidence[selection.index]),
            selection.reason.is_exploration(),
        );
        if nodes.len() > 1 {
            let streak_excluded = snapshots
                .iter()
                .filter(|score| {
                    performance.any_healthy && score.fail_streak >= SCORE_FAIL_STREAK_EXCLUDE
                })
                .count() as u64;
            let backed_off = snapshots
                .iter()
                .filter(|score| score.explore_backed_off)
                .count() as u64;
            let counts = inner
                .selection_reasons
                .entry(SelectionReasonKey::new(group, context.network))
                .or_default();
            counts.fail_streak_excluded =
                counts.fail_streak_excluded.saturating_add(streak_excluded);
            counts.explore_backed_off = counts.explore_backed_off.saturating_add(backed_off);
            Self::record_selection_reason(&mut inner, group, context.network, selection);
            Self::record_switch_flap(
                &mut inner,
                &history_key,
                nodes[selection.index].id,
                selection.reason,
            );
        }
        (selection.index, reservation)
    }
}

/// An admitted begin, not a plan, is a real opportunity; one tick covers every attribution.
pub(super) fn advance_rotation(
    inner: &mut StateInner,
    context: &ScoreSelectionContext,
    attributions: &[super::ScoreAttribution],
) {
    inner.tick = inner.tick.saturating_add(1);
    let tick = inner.tick;
    for attribution in attributions {
        mark_selected(
            inner,
            &attribution.group,
            context,
            attribution.node_id,
            tick,
        );
    }
}

pub(super) fn ordinary_selection(
    snapshots: &[ScoreSnapshot],
    nodes: &[&Node],
    incumbent: Option<usize>,
    performance: PerformanceBaseline,
    pairs: &comparison::PairCohort,
) -> RankedSelection {
    let best = best_index(snapshots, nodes, performance);
    let Some(index) = incumbent else {
        return best;
    };
    let current = &snapshots[index];
    if !normal_eligible(current, performance) {
        return RankedSelection {
            index: best.index,
            reason: SelectionReason::IncumbentIneligible,
        };
    }
    if current.unresolved_failure {
        return RankedSelection {
            index: best.index,
            reason: SelectionReason::FreshFailureBypass,
        };
    }
    if current.completed < MIN_TRAINED_EVIDENCE {
        return best;
    }
    let margin = switch_margin(current.completed);
    let mut promoted = None;
    let mut best_has_comparison = false;
    let mut directional_tradeoff = false;
    // Only pairs prepared against this fixed incumbent may compete.
    for (candidate_index, candidate) in snapshots.iter().enumerate() {
        if candidate_index == index
            || !normal_eligible(candidate, performance)
            || candidate.completed < MIN_TRAINED_EVIDENCE
            || pairs.reference != index
        {
            continue;
        }
        let Some(pair) = pairs.get(candidate_index) else {
            continue;
        };
        let result = promotion_result(
            pair,
            (current.qualified(), candidate.qualified()),
            (current.observed_reliability, candidate.observed_reliability),
        );
        let gain = result.gain;
        directional_tradeoff |= result.directional_tradeoff;
        if candidate_index == best.index || best.index == index {
            best_has_comparison |= result.comparable;
        }
        if gain >= margin
            && gain > 0.0
            && promoted.is_none_or(|(_, previous_gain)| gain > previous_gain)
        {
            promoted = Some((candidate_index, gain));
        }
    }
    if let Some((index, _)) = promoted {
        RankedSelection {
            index,
            reason: SelectionReason::PerformanceWinner,
        }
    } else {
        RankedSelection {
            index,
            reason: if directional_tradeoff {
                SelectionReason::DirectionalTradeoffHeld
            } else if best_has_comparison {
                SelectionReason::IncumbentHeld
            } else {
                SelectionReason::InsufficientEvidenceHeld
            },
        }
    }
}

pub(super) fn best_index(
    snapshots: &[ScoreSnapshot],
    nodes: &[&Node],
    performance: PerformanceBaseline,
) -> RankedSelection {
    let index = snapshots
        .iter()
        .enumerate()
        .filter(|(_, score)| normal_eligible(score, performance))
        .max_by(|(left_index, left), (right_index, right)| {
            utility(left, performance)
                .total_cmp(&utility(right, performance))
                .then_with(|| right_index.cmp(left_index))
                .then_with(|| nodes[*right_index].id.cmp(&nodes[*left_index].id))
        })
        .map(|(index, _)| index)
        .unwrap_or(0);
    let alternatives = snapshots
        .iter()
        .enumerate()
        .any(|(other, score)| other != index && normal_eligible(score, performance));
    RankedSelection {
        index,
        reason: if alternatives {
            SelectionReason::PerformanceWinner
        } else {
            SelectionReason::ReliabilityWinner
        },
    }
}

pub(super) fn normal_eligible(score: &ScoreSnapshot, baseline: PerformanceBaseline) -> bool {
    if baseline.any_healthy && score.fail_streak >= SCORE_FAIL_STREAK_EXCLUDE {
        return false;
    }
    if score.recovered_qualification && !score.unresolved_failure {
        return true;
    }
    if baseline.any_qualified {
        score.qualified()
            && score.reliability_upper + RELIABILITY_CLOSE >= baseline.best_reliability
            && score.observed_reliability + RELIABILITY_CLOSE >= baseline.best_observed_reliability
    } else {
        score.reliability + RELIABILITY_CLOSE >= baseline.best_reliability
    }
}

pub(super) fn switch_margin(completed: f64) -> f64 {
    // Ten percent of the available performance range: a 50% rate gain
    // clears this margin, while small latency jitter does not.
    0.05 * PERFORMANCE_SWITCH_MARGIN * (completed / SCORE_SWITCH_FULL_EVIDENCE).clamp(0.0, 1.0)
}

#[derive(Clone, Copy, Default)]
pub(super) struct PromotionResult {
    pub gain: f64,
    pub comparable: bool,
    pub directional_tradeoff: bool,
}

pub(super) fn promotion_result(
    pair: comparison::PairEvidence,
    qualified: (bool, bool),
    reliability: (f64, f64),
) -> PromotionResult {
    let latency_gain = pair.response.map_or(0.0, |metric| {
        let best = metric.incumbent.min(metric.candidate).max(1.0);
        (best / metric.candidate.max(1.0)).min(1.0) - (best / metric.incumbent.max(1.0)).min(1.0)
    });
    let mut improved = false;
    let mut regressed = false;
    let mut directional_gain = 0.0_f64;
    for metric in [pair.upload, pair.download].into_iter().flatten() {
        improved |=
            metric.candidate - metric.incumbent >= metric.incumbent * PERFORMANCE_SWITCH_MARGIN;
        regressed |=
            metric.incumbent - metric.candidate > metric.incumbent * PERFORMANCE_SWITCH_MARGIN;
        directional_gain = directional_gain.max(
            (metric.candidate - metric.incumbent) / metric.candidate.max(metric.incumbent).max(1.0),
        );
    }
    let qualified = qualified.0 && qualified.1;
    let response_guard = pair.response.is_some_and(|metric| {
        metric.candidate - metric.incumbent <= metric.incumbent * PERFORMANCE_SWITCH_MARGIN
    });
    let reliability_gain = if qualified {
        reliability.1 - reliability.0
    } else {
        0.0
    };
    let throughput_gain = if improved
        && !regressed
        && response_guard
        && qualified
        && reliability.1 >= reliability.0
    {
        directional_gain
    } else {
        0.0
    };
    PromotionResult {
        gain: reliability_gain + 0.03 * latency_gain + 0.02 * throughput_gain,
        comparable: pair.response.is_some() || pair.upload.is_some() || pair.download.is_some(),
        directional_tradeoff: improved && regressed,
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

#[cfg(test)]
pub(super) fn score_snapshot(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    node_id: Uuid,
    now: Instant,
) -> ScoreSnapshot {
    score_snapshots(inner, group, context, [node_id], now).remove(0)
}

pub(super) fn score_snapshots(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    nodes: impl IntoIterator<Item = Uuid>,
    now: Instant,
) -> Vec<ScoreSnapshot> {
    let mut layer = AggregateKey {
        group: group.to_owned(),
        network: context.network,
        family: None,
        node_id: Uuid::nil(),
    };
    let mut exact = context
        .target_family
        .zip(context.target.clone())
        .map(|(family, target)| ExactKey {
            group: group.to_owned(),
            network: context.network,
            family,
            target,
            node_id: Uuid::nil(),
        });
    let scoped = |stamp: CellStamp<'_>| {
        let stats = stamp.stats;
        let mut value = snapshot(stats, now);
        if stamp.invalidated_through > stats.business_invalidated_through {
            value.performance = PerformanceSnapshot::default();
            value.qualified_until = None;
            value.recovered_qualification = false;
        }
        value
    };
    nodes
        .into_iter()
        .map(|node_id| {
            layer.node_id = node_id;
            layer.family = None;
            let global_stats = inner.aggregate.peek(&layer);
            let mut score = global_stats.map_or_else(
                || snapshot(&Stats::default(), now),
                |stats| snapshot(stats, now),
            );
            let family_stats = context.target_family.and_then(|family| {
                layer.family = Some(family);
                inner.aggregate.peek(&layer)
            });
            if let Some(stamp) =
                family_stats.and_then(|stats| CellStamp::current(stats, global_stats))
            {
                let family = scoped(stamp);
                let weight = (family.useful_completed / SCORE_SWITCH_FULL_EVIDENCE).clamp(0.0, 1.0);
                score.reliability = blend(score.reliability, family.reliability, weight);
                score.reliability_upper =
                    blend(score.reliability_upper, family.reliability_upper, weight);
                score.observed_reliability = blend(
                    score.observed_reliability,
                    family.observed_reliability,
                    weight,
                );
                score.completed = score.completed.max(family.completed);
                score.useful_completed = score.useful_completed.max(family.useful_completed);
                score.qualified_until = score.qualified_until.max(family.qualified_until);
                score.recovered_qualification |= family.recovered_qualification;
                score.performance = prefer_specific(score.performance, family.performance);
                score.unresolved_failure |= family.unresolved_failure;
                score.fail_streak = score.fail_streak.max(family.fail_streak);
                score.explore_backed_off |= family.explore_backed_off;
                score.selected_at = score.selected_at.max(family.selected_at);
            }
            // Proxy health-family and probe protocol are independent of target family.
            if let Some(stats) = global_stats {
                let probe = &stats.probes[super::evidence::probe_slot(context)];
                score.probe = probe.latency.snapshot(now);
                score.probe_scope = probe.scope;
                // The filter family is not the socket selected by a dual-stack dial.
                // A carrier hint asks a node-wide question; it is not target performance.
                score.carrier_pressure_at = stats
                    .carrier_pressure
                    .iter()
                    .flatten()
                    .filter(|pressure| {
                        now.saturating_duration_since(pressure.observed_at)
                            < super::CARRIER_PRESSURE_TTL
                    })
                    .map(|pressure| pressure.observed_at)
                    .max();
            }
            if context.target.is_some() {
                score.recovered_qualification = false;
            }
            let exact_stats = exact.as_mut().and_then(|key| {
                key.node_id = node_id;
                inner.exact.peek(key)
            });
            if let Some(stats) = exact_stats
                && let Some(stamp) = CellStamp::current(stats, global_stats)
            {
                let exact = scoped(stamp);
                let weight = (exact.useful_completed / SCORE_SWITCH_FULL_EVIDENCE).clamp(0.0, 1.0);
                score.reliability = blend(score.reliability, exact.reliability, weight);
                score.reliability_upper =
                    blend(score.reliability_upper, exact.reliability_upper, weight);
                score.observed_reliability = blend(
                    score.observed_reliability,
                    exact.observed_reliability,
                    weight,
                );
                score.completed = score.completed.max(exact.completed);
                score.useful_completed = score.useful_completed.max(exact.useful_completed);
                score.qualified_until = score.qualified_until.max(exact.qualified_until);
                score.recovered_qualification = exact.recovered_qualification;
                score.target_performance = exact.performance;
                score.unresolved_failure |= exact.unresolved_failure;
                score.fail_streak = score.fail_streak.max(exact.fail_streak);
                score.explore_backed_off |= exact.explore_backed_off;
                score.selected_at = score.selected_at.max(exact.selected_at);
                score.degraded_at = score.degraded_at.max(exact.degraded_at);
            }
            score.degraded_at = score.degraded_at.max(score.carrier_pressure_at);
            score.recovered_qualification &= !score.unresolved_failure;
            score
        })
        .collect()
}

pub(super) fn snapshot(stats: &Stats, now: Instant) -> ScoreSnapshot {
    let factor = stats
        .updated_at
        .map_or(1.0, |at| evidence_decay(now.saturating_duration_since(at)));
    let (reliability, reliability_upper) = stats.reliability_bounds(factor);
    let failures = stats.useful_failure + stats.setup_failure * 2.0;
    let observations = stats.useful_success + failures;
    ScoreSnapshot {
        completed: stats.completed() * factor,
        useful_completed: stats.useful_completed() * factor,
        qualified_until: stats.qualified_until.filter(|until| now < *until),
        recovered_qualification: stats.failed_at.is_some()
            && stats.fail_streak == 0
            && stats.availability.reporters >= super::PERFORMANCE_VALIDATION_SAMPLES as u8
            && stats.qualified_until.is_some_and(|until| now < until),
        reliability,
        reliability_upper,
        observed_reliability: if observations > 0.0 {
            stats.useful_success / observations
        } else {
            0.5
        },
        performance: stats.performance.snapshot(now),
        warm_setup: stats.warm_setup_ms.snapshot(now),
        unresolved_failure: stats.fail_streak > 0,
        explore_backed_off: stats.explore_not_before.is_some_and(|until| until > now),
        degraded_at: stats
            .degraded_at
            .filter(|at| now.saturating_duration_since(*at) < super::PERFORMANCE_MAX_AGE),
        fail_streak: stats.fail_streak,
        selected_at: stats.selected_at,
        ..Default::default()
    }
}

fn blend(base: f64, specific: f64, weight: f64) -> f64 {
    base * (1.0 - weight) + specific * weight
}

fn prefer_specific(
    base: PerformanceSnapshot,
    specific: PerformanceSnapshot,
) -> PerformanceSnapshot {
    let pick = |base: MetricSnapshot, specific: MetricSnapshot| {
        if specific.value.is_some() {
            specific
        } else {
            base
        }
    };
    PerformanceSnapshot {
        setup: pick(base.setup, specific.setup),
        response: pick(base.response, specific.response),
        upload: pick(base.upload, specific.upload),
        download: pick(base.download, specific.download),
    }
}

pub(super) fn performance_baseline(snapshots: &[ScoreSnapshot]) -> PerformanceBaseline {
    let any_healthy = snapshots
        .iter()
        .any(|score| score.fail_streak < SCORE_FAIL_STREAK_EXCLUDE);
    let healthy =
        |score: &&ScoreSnapshot| !any_healthy || score.fail_streak < SCORE_FAIL_STREAK_EXCLUDE;
    let any_qualified = snapshots
        .iter()
        .filter(healthy)
        .any(|score| score.qualified());
    let best_reliability = snapshots
        .iter()
        .filter(healthy)
        .filter(|score| !any_qualified || score.qualified())
        .map(|score| score.reliability)
        .fold(0.0, f64::max);
    let best_observed_reliability = snapshots
        .iter()
        .filter(healthy)
        .filter(|score| !any_qualified || score.qualified())
        .map(|score| score.observed_reliability)
        .fold(0.0, f64::max);
    let mut baseline = PerformanceBaseline {
        performance: PerformanceSnapshot::default(),
        target_performance: PerformanceSnapshot::default(),
        probe: MetricSnapshot::default(),
        probe_scope: 0,
        warm_setup: MetricSnapshot::default(),
        best_reliability,
        best_observed_reliability,
        any_healthy,
        any_qualified,
    };
    let eligible = |score: &&ScoreSnapshot| normal_eligible(score, baseline);
    baseline.probe_scope = snapshots
        .iter()
        .filter(eligible)
        .find(|score| {
            score.probe.value.is_some()
                && snapshots
                    .iter()
                    .filter(eligible)
                    .filter(|other| {
                        other.probe.value.is_some() && other.probe_scope == score.probe_scope
                    })
                    .take(2)
                    .count()
                    == 2
        })
        .map_or(0, |score| score.probe_scope);
    let metric = |get: fn(&ScoreSnapshot) -> MetricSnapshot, larger: bool, scope: Option<u64>| {
        let mut values = snapshots
            .iter()
            .filter(|score| normal_eligible(score, baseline))
            .filter(|score| scope.is_none_or(|scope| score.probe_scope == scope))
            .filter_map(|score| get(score).value);
        let first = values.next();
        let second = values.next();
        match (first, second) {
            (Some(a), Some(b)) => MetricSnapshot {
                value: Some(values.fold(
                    if larger { a.max(b) } else { a.min(b) },
                    |best, value| {
                        if larger {
                            best.max(value)
                        } else {
                            best.min(value)
                        }
                    },
                )),
                confidence: 1.0,
            },
            _ => MetricSnapshot::default(),
        }
    };
    let performance = PerformanceSnapshot {
        setup: metric(|s| s.performance.setup, false, None),
        response: metric(|s| s.performance.response, false, None),
        upload: metric(|s| s.performance.upload, true, None),
        download: metric(|s| s.performance.download, true, None),
    };
    let target_performance = PerformanceSnapshot {
        setup: metric(|s| s.target_performance.setup, false, None),
        response: metric(|s| s.target_performance.response, false, None),
        upload: metric(|s| s.target_performance.upload, true, None),
        download: metric(|s| s.target_performance.download, true, None),
    };
    let probe = metric(|s| s.probe, false, Some(baseline.probe_scope));
    let warm_setup = metric(|s| s.warm_setup, false, None);
    baseline.performance = performance;
    baseline.target_performance = target_performance;
    baseline.probe = probe;
    baseline.warm_setup = warm_setup;
    baseline
}

fn relative(metric: MetricSnapshot, best: MetricSnapshot, larger: bool) -> Option<f64> {
    match (metric.value, best.value) {
        (Some(value), Some(best)) => Some(if larger {
            (value / best.max(1.0)).clamp(0.0, 1.0)
        } else {
            (best.max(1.0) / value.max(1.0)).clamp(0.0, 1.0)
        }),
        _ => None,
    }
}

fn correction(base: f64, metric: MetricSnapshot, best: MetricSnapshot, larger: bool) -> f64 {
    relative(metric, best, larger).map_or(base, |value| blend(base, value, metric.confidence))
}

fn scoped_correction(
    base: f64,
    aggregate: MetricSnapshot,
    aggregate_best: MetricSnapshot,
    exact: MetricSnapshot,
    exact_best: MetricSnapshot,
    larger: bool,
) -> f64 {
    if relative(exact, exact_best, larger).is_some() {
        correction(base, exact, exact_best, larger)
    } else {
        correction(base, aggregate, aggregate_best, larger)
    }
}

pub(super) fn utility(score: &ScoreSnapshot, baseline: PerformanceBaseline) -> f64 {
    let mut latency = if score.probe_scope == baseline.probe_scope {
        correction(0.0, score.probe, baseline.probe, false)
    } else {
        0.0
    };
    if baseline.probe.value.is_none() {
        if baseline.performance.setup.value.is_none() {
            latency = correction(latency, score.warm_setup, baseline.warm_setup, false);
        }
        latency = scoped_correction(
            latency,
            score.performance.setup,
            baseline.performance.setup,
            score.target_performance.setup,
            baseline.target_performance.setup,
            false,
        );
    }
    latency = scoped_correction(
        latency,
        score.performance.response,
        baseline.performance.response,
        score.target_performance.response,
        baseline.target_performance.response,
        false,
    );
    let upload = scoped_correction(
        0.0,
        score.performance.upload,
        baseline.performance.upload,
        score.target_performance.upload,
        baseline.target_performance.upload,
        true,
    );
    let download = scoped_correction(
        0.0,
        score.performance.download,
        baseline.performance.download,
        score.target_performance.download,
        baseline.target_performance.download,
        true,
    );
    // Uncertainty gates admission, not the payoff: zero observed failures
    // must not reward a thousand samples over twenty forever.
    score.observed_reliability + 0.03 * latency + 0.02 * upload.max(download)
}
