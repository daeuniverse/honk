//! Each member's open evidence question, the next optional validation target, and the readonly
//! pairwise comparisons of the ordinary selection.
use super::super::comparison::{Basis, Summary, equivalent};
use super::super::ranking::Decision;
use super::*;

fn qualified(metric: Option<TimedMetric>) -> bool {
    metric.is_some_and(|metric| f64::from(metric.reporters) >= PERFORMANCE_VALIDATION_SAMPLES)
}

pub(in crate::group::score) fn usable(evidence: &VerificationEvidence) -> bool {
    qualified(evidence.business)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseGap {
    None,
    Missing,
    Unpaired,
    Availability,
    ProbeScope,
    Degraded,
    Misaligned,
}

#[derive(Clone, Copy)]
pub(in crate::group::score) struct CandidateQuestion {
    pub question: ScoreEvidenceQuestion,
    pub required: usize,
    excluded: bool,
    evaluated: bool,
    backed_off: bool,
    response_gap: ResponseGap,
}

impl CandidateQuestion {
    fn pending(&self) -> bool {
        self.evaluated && !self.excluded && self.question != ScoreEvidenceQuestion::None
    }

    pub fn actionable(&self) -> bool {
        self.pending() && !self.backed_off
    }

    pub fn needs_alignment(&self) -> bool {
        self.response_gap == ResponseGap::Misaligned
    }
}

pub(super) fn milliseconds(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn untried_hint(decision: &Decision, left: usize, right: usize) -> std::cmp::Ordering {
    let scores = &decision.scores;
    if scores[left].selected_at != 0 || scores[right].selected_at != 0 {
        return std::cmp::Ordering::Equal;
    }
    let evidence = &decision.evidence;
    let (left_metric, right_metric) =
        if evidence[left].response.is_some() || evidence[right].response.is_some() {
            (evidence[left].response, evidence[right].response)
        } else if scores[left].probe_scope == scores[right].probe_scope {
            (evidence[left].probe, evidence[right].probe)
        } else {
            return std::cmp::Ordering::Equal;
        };
    left_metric
        .map_or(f64::INFINITY, |metric| metric.value)
        .total_cmp(&right_metric.map_or(f64::INFINITY, |metric| metric.value))
}

pub(in crate::group::score) fn startup_index(decision: &Decision) -> Option<usize> {
    (decision.scores.len() > 1)
        .then(|| {
            decision
                .scores
                .iter()
                .enumerate()
                .filter(|(index, score)| {
                    decision.membership.evaluated[*index]
                        && score.completed < MIN_TRAINED_EVIDENCE
                        && !score.explore_backed_off
                })
                .min_by(|(left_index, left), (right_index, right)| {
                    left.attempts
                        .total_cmp(&right.attempts)
                        .then_with(|| untried_hint(decision, *left_index, *right_index))
                        .then_with(|| left.selected_at.cmp(&right.selected_at))
                        .then_with(|| left_index.cmp(right_index))
                })
                .map(|(index, _)| index)
        })
        .flatten()
}

/// Which response metric validation reads: configured probes stand in only for targetless
/// scopes whose comparison has no business response basis.
#[derive(Clone, Copy)]
struct Responses<'a> {
    evidence: &'a [VerificationEvidence],
    probe: bool,
}

impl<'a> Responses<'a> {
    fn new(decision: &'a Decision, context: &ScoreSelectionContext, summary: &Summary) -> Self {
        let probe = context.target.is_none()
            && match summary.basis {
                Basis::ConfiguredProbe => true,
                Basis::None => qualified(decision.evidence[decision.ordinary.index].probe),
                Basis::ExactTarget | Basis::CommonTargets => false,
            };
        Self {
            evidence: &decision.evidence,
            probe,
        }
    }

    fn get(self, index: usize) -> Option<TimedMetric> {
        if self.probe {
            self.evidence[index].probe
        } else {
            self.evidence[index].response
        }
    }
}

/// One member's open question and why its response evidence cannot yet support a comparison.
fn candidate_question(
    decision: &Decision,
    context: &ScoreSelectionContext,
    summary: &Summary,
    responses: Responses<'_>,
    index: usize,
    now: Instant,
) -> CandidateQuestion {
    let snapshots = &decision.scores;
    let evidence = &decision.evidence;
    let selected = decision.ordinary.index;
    let winner = &snapshots[selected];
    let score = &snapshots[index];
    let excluded = super::comparison::failure_excluded(decision, index, now);
    let pair = decision.pairs.summary_pair(index);
    let paired_at = if context.target.is_none() && !responses.probe {
        pair.and_then(|pair| pair.response)
            .map(|metric| metric.latest_at)
            .or_else(|| {
                (index == selected)
                    .then_some(summary.response_latest_at)
                    .flatten()
            })
    } else {
        None
    };
    let availability_missing = !usable(&evidence[index]);
    let response_gap = if !qualified(responses.get(index)) && paired_at.is_none() {
        ResponseGap::Missing
    } else if pair.is_some_and(|pair| pair.partial || pair.response.is_none()) {
        ResponseGap::Unpaired
    } else if !responses.probe && availability_missing {
        ResponseGap::Availability
    } else if responses.probe && score.probe_scope != winner.probe_scope {
        ResponseGap::ProbeScope
    } else if winner.degraded_at.is_some_and(|at| {
        responses
            .get(index)
            .map(|metric| metric.latest_at)
            .or(paired_at)
            .is_none_or(|seen| seen < at)
    }) {
        ResponseGap::Degraded
    } else if summary.response_misaligned
        && !excluded
        && (index == selected
            || pair
                .and_then(|pair| pair.response)
                .is_some_and(|metric| now < metric.expires_at))
    {
        ResponseGap::Misaligned
    } else {
        ResponseGap::None
    };
    let question = if score.fail_streak > 0 {
        ScoreEvidenceQuestion::Recovery
    } else if availability_missing {
        ScoreEvidenceQuestion::Availability
    } else if response_gap != ResponseGap::None {
        ScoreEvidenceQuestion::Response
    } else if decision.baseline.any_qualified && !score.qualified() {
        ScoreEvidenceQuestion::Qualification
    } else {
        ScoreEvidenceQuestion::None
    };
    let supported = match question {
        ScoreEvidenceQuestion::Availability => evidence[index]
            .business
            .map_or(0.0, |metric| f64::from(metric.reporters)),
        ScoreEvidenceQuestion::Response
            if matches!(
                response_gap,
                ResponseGap::Missing
                    | ResponseGap::Unpaired
                    | ResponseGap::ProbeScope
                    | ResponseGap::Misaligned
            ) =>
        {
            0.0
        }
        ScoreEvidenceQuestion::Response => responses
            .get(index)
            .map_or(0.0, |metric| f64::from(metric.reporters)),
        ScoreEvidenceQuestion::Qualification => score.useful_completed,
        _ => PERFORMANCE_VALIDATION_SAMPLES,
    };
    CandidateQuestion {
        question,
        required: (PERFORMANCE_VALIDATION_SAMPLES - supported)
            .ceil()
            .clamp(1.0, 4.0) as usize,
        excluded,
        evaluated: decision.membership.evaluated[index],
        backed_off: score.explore_backed_off,
        response_gap,
    }
}

/// The ordinary selection's original pairs, as promotion reads them, with a fresh response.
fn challengers(decision: &Decision, now: Instant) -> Vec<ScoreChallenger> {
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
                name: String::new(),
                basis,
                relation,
                reporters: response.reporters,
                valid_for_ms: milliseconds(response.expires_at.saturating_duration_since(now)),
                index,
            })
        })
        .collect()
}

/// The member optional validation should serve next, if any is actionable.
fn validation_index(
    decision: &Decision,
    nodes: &[&Node],
    candidates: &[CandidateQuestion],
    focused: Option<Uuid>,
) -> Option<usize> {
    let selected = decision.ordinary.index;
    decision
        .scores
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != selected && candidates[*index].actionable())
        .min_by(|(left_index, left), (right_index, right)| {
            // A short run resolves one real question; no-progress/cancelled work
            // rotates by recency instead of pinning that run indefinitely.
            let focus = |index: usize| {
                focused == Some(nodes[index].id) && decision.evidence[index].business.is_some()
            };
            focus(*right_index)
                .cmp(&focus(*left_index))
                .then_with(|| untried_hint(decision, *left_index, *right_index))
                .then_with(|| left.selected_at.cmp(&right.selected_at))
                .then_with(|| left.last_attempt.cmp(&right.last_attempt))
                .then_with(|| right.reliability_upper.total_cmp(&left.reliability_upper))
                .then_with(|| left_index.cmp(right_index))
        })
        .map(|(index, _)| index)
}

fn next_step(
    candidates: &[CandidateQuestion],
    validation_index: Option<usize>,
) -> (
    ScoreValidationAction,
    ScoreEvidenceQuestion,
    ScoreWaitReason,
) {
    let question_index = validation_index
        .or_else(|| candidates.iter().position(CandidateQuestion::actionable))
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

pub(in crate::group::score) fn evaluate(
    decision: &Decision,
    nodes: &[&Node],
    context: &ScoreSelectionContext,
    cadence: Option<&SelectionCadence>,
    now: Instant,
) -> Evaluation {
    let selected = decision.ordinary.index;
    let summary = super::comparison::summarize(decision, now);
    let responses = Responses::new(decision, context, &summary);
    let candidates: Vec<_> = (0..decision.scores.len())
        .map(|index| candidate_question(decision, context, &summary, responses, index, now))
        .collect();
    let focused = cadence
        .and_then(|cadence| cadence.run.as_ref())
        .and_then(|run| run.focused(context, now));
    let validation_index = validation_index(decision, nodes, &candidates, focused);
    let (next_action, question, wait_reason) = next_step(&candidates, validation_index);
    Evaluation {
        snapshot: ScoreVerificationSnapshot {
            state: if usable(&decision.evidence[selected]) {
                ScoreVerificationState::ObservedUsable
            } else {
                ScoreVerificationState::Provisional
            },
            next_action,
            question,
            wait_reason,
            challengers: challengers(decision, now),
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
        },
        validation_index,
        candidates,
    }
}
