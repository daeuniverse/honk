//! Each member's open evidence question, the dispatch walk that funds optional work for them,
//! and the readonly report of the ordinary selection's pairwise comparisons.
use super::super::comparison::{Basis, equivalent};
use super::super::ranking::{Decision, normal_eligible};
use super::*;

fn qualified(metric: Option<TimedMetric>) -> bool {
    metric.is_some_and(|metric| f64::from(metric.reporters) >= PERFORMANCE_VALIDATION_SAMPLES)
}

pub(in crate::group::score) fn usable(evidence: &VerificationEvidence) -> bool {
    qualified(evidence.business)
}

#[derive(Clone, Copy)]
pub(in crate::group::score) struct CandidateQuestion {
    question: ScoreEvidenceQuestion,
    /// A trial can still advance this question; otherwise it waits for ordinary traffic.
    fundable: bool,
    /// Evidence already gathered toward an unfinished question; finishing it first keeps its
    /// reporters inside the windows they expire from.
    partial: f64,
    excluded: bool,
    evaluated: bool,
    backed_off: bool,
}

impl CandidateQuestion {
    fn pending(&self) -> bool {
        self.evaluated && !self.excluded && self.question != ScoreEvidenceQuestion::None
    }

    fn actionable(&self) -> bool {
        self.pending() && !self.backed_off && self.fundable
    }
}

/// A recent failure excludes an ineligible member until its performance evidence expires.
fn failure_excluded(decision: &Decision, index: usize, now: Instant) -> bool {
    !normal_eligible(&decision.scores[index], decision.baseline)
        && decision.evidence[index]
            .failed_at
            .is_some_and(|at| now.saturating_duration_since(at) < PERFORMANCE_MAX_AGE)
}

/// The selection's original pair with this member holds fresh business response evidence of
/// this scope, newer than the selection's latest degradation. Probes never settle it.
fn paired(
    decision: &Decision,
    context: &ScoreSelectionContext,
    index: usize,
    now: Instant,
) -> bool {
    let wanted = if context.target.is_some() {
        Basis::ExactTarget
    } else {
        Basis::CommonTargets
    };
    let degraded_at = decision.scores[decision.pairs.reference].degraded_at;
    decision.pairs.get(index).is_some_and(|pair| {
        pair.basis == wanted
            && !pair.partial
            && pair.response.is_some_and(|metric| {
                now < metric.expires_at && degraded_at.is_none_or(|at| metric.latest_at >= at)
            })
    })
}

fn candidate_question(
    decision: &Decision,
    context: &ScoreSelectionContext,
    index: usize,
    now: Instant,
) -> CandidateQuestion {
    let score = &decision.scores[index];
    let evidence = &decision.evidence[index];
    let selected = decision.ordinary.index;
    let degraded_at = decision.scores[decision.pairs.reference].degraded_at;
    // Reporters from before the selection degraded cannot refresh the pair, so they are no progress.
    let progress = decision
        .pairs
        .get(index)
        .filter(|pair| degraded_at.is_none_or(|at| pair.progress_at.is_some_and(|last| last >= at)))
        .map_or(0, |pair| pair.progress);
    // Only members ordinary selection could compare can be asked for a pair.
    let unpaired = index != selected
        && normal_eligible(score, decision.baseline)
        && !paired(decision, context, index, now);
    let (question, gathered) = if score.fail_streak > 0 {
        (ScoreEvidenceQuestion::Recovery, None)
    } else if !usable(evidence) {
        (
            ScoreEvidenceQuestion::Availability,
            Some(
                evidence
                    .business
                    .map_or(0.0, |metric| f64::from(metric.reporters)),
            ),
        )
    } else if unpaired {
        (ScoreEvidenceQuestion::Response, Some(f64::from(progress)))
    } else if decision.baseline.any_qualified && !score.qualified() {
        (
            ScoreEvidenceQuestion::Qualification,
            Some(score.useful_completed),
        )
    } else {
        (ScoreEvidenceQuestion::None, None)
    };
    CandidateQuestion {
        question,
        fundable: gathered.is_none_or(|gathered| gathered < PERFORMANCE_VALIDATION_SAMPLES),
        partial: gathered
            .filter(|gathered| *gathered < PERFORMANCE_VALIDATION_SAMPLES)
            .unwrap_or(0.0),
        excluded: failure_excluded(decision, index, now),
        evaluated: decision.membership[index],
        backed_off: score.explore_backed_off,
    }
}

/// The ordinary selection's original pairs, as promotion reads them, with a fresh response.
fn challengers(decision: &Decision, names: &[&str], now: Instant) -> Vec<ScoreChallenger> {
    let pairs = &decision.pairs;
    (0..pairs.pairs.len())
        .filter(|index| *index != pairs.reference)
        .filter_map(|index| {
            let pair = pairs.get(index)?;
            let response = pair.response.filter(|metric| now < metric.expires_at)?;
            let basis = match pair.basis {
                Basis::ExactTarget => ScoreEvidenceBasis::TargetResponse,
                Basis::CommonTargets => ScoreEvidenceBasis::CommonTargets,
                Basis::ConfiguredProbe => ScoreEvidenceBasis::ConfiguredProbe,
                Basis::None => return None,
            };
            let relation = if equivalent(response.incumbent, response.candidate) {
                ScoreRelation::Equivalent
            } else if response.candidate < response.incumbent {
                ScoreRelation::ChallengerFaster
            } else {
                ScoreRelation::SelectedFaster
            };
            Some(ScoreChallenger {
                name: names[index].to_owned(),
                basis,
                relation,
                reporters: response.reporters,
                valid_for_ms: u64::try_from(
                    response
                        .expires_at
                        .saturating_duration_since(now)
                        .as_millis(),
                )
                .unwrap_or(u64::MAX),
            })
        })
        .collect()
}

/// Actionable challengers in the order optional work serves them: untrained members first, then
/// the most progress toward an unfinished question, so its reporters land inside the windows they
/// expire from, then the least recently selected. Never-selected members prefer a faster probe of
/// the selection's measurement scope. Except for recovery, a trial never lifts a challenger's
/// completions above the selection's, counting its unfinished work as completions already on
/// their way: first choice follows evidence, so trials that train a challenger first would
/// displace the probe-preferred selection.
fn dispatch_order(
    decision: &Decision,
    candidates: &[CandidateQuestion],
    unfinished: &[f64],
) -> Vec<usize> {
    let scores = &decision.scores;
    let selected = decision.ordinary.index;
    let ceiling = scores[selected].completed;
    let scope = scores[selected].probe_scope;
    let hint = |index: usize| {
        (scores[index].selected_at == 0 && scores[index].probe_scope == scope)
            .then_some(scores[index].probe.value)
            .flatten()
            .unwrap_or(f64::INFINITY)
    };
    let trained = |index: usize| scores[index].completed >= MIN_TRAINED_EVIDENCE;
    let mut order: Vec<_> = (0..candidates.len())
        .filter(|&index| {
            index != selected
                && candidates[index].actionable()
                && (candidates[index].question == ScoreEvidenceQuestion::Recovery
                    || scores[index].completed + unfinished[index] < ceiling)
        })
        .collect();
    order.sort_by(|&left, &right| {
        trained(left)
            .cmp(&trained(right))
            .then_with(|| {
                candidates[right]
                    .partial
                    .total_cmp(&candidates[left].partial)
            })
            .then_with(|| scores[left].selected_at.cmp(&scores[right].selected_at))
            .then_with(|| hint(left).total_cmp(&hint(right)))
            .then_with(|| left.cmp(&right))
    });
    order
}

fn next_step(
    candidates: &[CandidateQuestion],
    order: &[usize],
) -> (
    ScoreValidationAction,
    ScoreEvidenceQuestion,
    ScoreWaitReason,
) {
    let question_index = order
        .first()
        .copied()
        .or_else(|| candidates.iter().position(CandidateQuestion::pending));
    match question_index.map(|index| candidates[index]) {
        Some(candidate) if candidate.backed_off => (
            ScoreValidationAction::Backoff,
            candidate.question,
            ScoreWaitReason::Backoff,
        ),
        Some(candidate) => (
            ScoreValidationAction::NextBusinessFlow,
            candidate.question,
            ScoreWaitReason::ComparableTraffic,
        ),
        None => (
            ScoreValidationAction::None,
            ScoreEvidenceQuestion::None,
            ScoreWaitReason::None,
        ),
    }
}

/// Each member's open question, and the actionable members in dispatch order.
pub(in crate::group::score) fn questions(
    decision: &Decision,
    context: &ScoreSelectionContext,
    unfinished: &[f64],
    now: Instant,
) -> (Vec<CandidateQuestion>, Vec<usize>) {
    let candidates: Vec<_> = (0..decision.scores.len())
        .map(|index| candidate_question(decision, context, index, now))
        .collect();
    let order = dispatch_order(decision, &candidates, unfinished);
    (candidates, order)
}

/// Reserves one credit for the first member in dispatch order the ledger admits. A budget
/// refusal ends the walk; an in-flight refusal tries the next member.
pub(in crate::group::score) fn plan(
    state: &Arc<ScorePolicyState>,
    inner: &mut StateInner,
    (group, context): (&str, &ScoreSelectionContext),
    decision: &Decision,
    nodes: &[&Node],
    now: Instant,
) -> (RankedSelection, Option<Arc<budget::Work>>) {
    let unfinished = budget::unfinished(inner, group, context, nodes, now);
    let (candidates, order) = questions(decision, context, &unfinished, now);
    for index in order {
        let question = candidates[index].question;
        match budget::reserve(state, inner, group, context, nodes[index].id, question, now) {
            Ok(work) => {
                let reason = if work.is_cold() {
                    SelectionReason::ColdExplore
                } else {
                    SelectionReason::PeriodicExplore
                };
                return (RankedSelection { index, reason }, Some(work));
            }
            Err(ScoreWaitReason::Budget) => break,
            Err(_) => {}
        }
    }
    (decision.ordinary, None)
}

/// The readonly report: the question dispatch serves next with the ledger's wait for it, and the
/// ordinary selection's fresh response relations under the members' display `names`.
pub(in crate::group::score) fn report(
    inner: &StateInner,
    (group, context): (&str, &ScoreSelectionContext),
    decision: &Decision,
    (nodes, names): (&[&Node], &[&str]),
    now: Instant,
) -> ScoreVerificationSnapshot {
    let unfinished = budget::unfinished(inner, group, context, nodes, now);
    let (candidates, order) = questions(decision, context, &unfinished, now);
    let (next_action, question, mut wait_reason) = next_step(&candidates, &order);
    if let Some(&index) = order.first() {
        let question = candidates[index].question;
        let wait = budget::wait_reason(inner, group, context, nodes[index].id, question, now);
        if wait != ScoreWaitReason::None {
            wait_reason = wait;
        }
    }
    ScoreVerificationSnapshot {
        state: if usable(&decision.evidence[decision.ordinary.index]) {
            ScoreVerificationState::ObservedUsable
        } else {
            ScoreVerificationState::Provisional
        },
        next_action,
        question,
        wait_reason,
        challengers: challengers(decision, names, now),
        candidate_count: decision.scores.len(),
        evaluated_count: candidates
            .iter()
            .filter(|candidate| candidate.evaluated)
            .count(),
        pending_count: candidates
            .iter()
            .filter(|candidate| candidate.pending())
            .count(),
        network: context.network,
        target_family: context.target_family,
        health_family: context.health_family,
        target_specific: context.target.is_some(),
    }
}
