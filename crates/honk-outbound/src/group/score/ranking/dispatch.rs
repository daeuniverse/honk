//! Stateful selection entry points, optional-work ownership and committed reporting.
#[cfg(test)]
use super::super::{ScoreAttempt, ScoreAttribution, ScoreFeedback, ScoreTrialSource};
use super::super::{ScoreAuthority, ScorePolicyState, SelectionCadenceKey, budget, verification};
use super::*;
use crate::group::ScoreView;
use std::sync::Arc;

impl ScorePolicyState {
    pub(in crate::group) fn rank(
        self: &Arc<Self>,
        authority: &Arc<ScoreAuthority>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        origins: ScoreView<'_, '_>,
        allow_trials: bool,
    ) -> Option<(usize, Option<Arc<budget::Work>>)> {
        self.rank_inner(
            Some(authority),
            group,
            context,
            (nodes, origins),
            Instant::now(),
            allow_trials,
        )
    }

    pub(in crate::group) fn peek_rank(
        self: &Arc<Self>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        origins: ScoreView<'_, '_>,
    ) -> Option<usize> {
        self.rank_inner(
            None,
            group,
            context,
            (nodes, origins),
            Instant::now(),
            false,
        )
        .map(|(index, _)| index)
    }

    #[cfg(test)]
    pub(in crate::group::score) fn peek_rank_at(
        self: &Arc<Self>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
    ) -> usize {
        self.rank_inner(
            None,
            group,
            context,
            (nodes, Default::default()),
            now,
            false,
        )
        .expect("test view has a serving pool member")
        .0
    }

    #[cfg(test)]
    pub(in crate::group::score) fn rank_at(
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
        self.rank_inner(
            Some(&authority),
            group,
            context,
            (nodes, Default::default()),
            now,
            true,
        )
        .expect("test view has a serving pool member")
        .0
    }

    #[cfg(test)]
    pub(in crate::group::score) fn rank_plan_at(
        self: &Arc<Self>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
    ) -> (usize, ScoreAttempt) {
        let authority = self
            .inner
            .lock()
            .active_authority
            .clone()
            .expect("published test membership");
        let (index, reservation) = self
            .rank_inner(
                Some(&authority),
                group,
                context,
                (nodes, Default::default()),
                now,
                true,
            )
            .expect("test view has a serving pool member");
        let feedback = ScoreAttempt::planned(
            ScoreFeedback::new(
                Arc::clone(self),
                authority,
                context.clone(),
                vec![ScoreAttribution {
                    group: group.to_owned(),
                    node_id: nodes[index].id,
                }],
            )
            .with_pool_bound(1),
            Arc::new(budget::Opportunity::default()),
            reservation.into_iter().collect(),
            ScoreTrialSource::None,
        );
        (index, feedback)
    }

    fn rank_inner(
        self: &Arc<Self>,
        authority: Option<&Arc<ScoreAuthority>>,
        group: &str,
        context: &ScoreSelectionContext,
        view: (&[&Node], ScoreView<'_, '_>),
        now: Instant,
        allow_trials: bool,
    ) -> Option<(usize, Option<Arc<budget::Work>>)> {
        let (nodes, origins) = view;
        if nodes.is_empty() {
            return None;
        }
        let mut inner = self.inner.lock();
        observation::metric("score_utility", None);
        let authorized = authority.is_some_and(|authority| {
            inner
                .active_authority
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, authority))
        }) && inner.valid_groups.contains(group);
        if !authorized || origins.preview {
            let view = comparison::View::new(&inner, group, context, nodes, now);
            return ordinary_decision(&view, origins, authorized && origins.preview).map(
                |(decision, _)| {
                    observe_reason(decision.ordinary.reason);
                    (decision.ordinary.index, None)
                },
            );
        }
        let mut decision = decision(&inner, group, context, nodes, origins, now, true)?;
        let mut set = decision
            .evaluation
            .take()
            .expect("Apply prepares membership");
        let snapshots = &decision.scores;
        let performance = decision.baseline;
        let ordinary = decision.ordinary;
        let cadence_key = SelectionCadenceKey::new(group, context);
        set.anchor(nodes[ordinary.index].id, now);
        *inner.evaluation_mut(group, context.network) = set;
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
            (selection, reservation) =
                verification::plan(self, &mut inner, (group, context), &decision, nodes, now);
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
            verification::usable(&decision.evidence[selection.index]),
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
        observe_reason(selection.reason);
        Some((selection.index, reservation))
    }
}

fn observe_reason(reason: SelectionReason) {
    observation::reason(match reason {
        SelectionReason::ColdExplore => "cold_explore",
        SelectionReason::PeriodicExplore => "periodic_explore",
        SelectionReason::ReliabilityWinner => "reliability_winner",
        SelectionReason::PerformanceWinner => "performance_winner",
        SelectionReason::IncumbentHeld => "incumbent_held",
        SelectionReason::InsufficientEvidenceHeld => "insufficient_evidence_held",
        SelectionReason::DirectionalTradeoffHeld => "directional_tradeoff_held",
        SelectionReason::IncumbentIneligible => "incumbent_ineligible",
        SelectionReason::FreshFailureBypass => "fresh_failure_bypass",
    });
}
