use super::super::ranking::{Decision, normal_eligible};
use super::super::{
    PERFORMANCE_MAX_AGE, PERFORMANCE_VALIDATION_SAMPLES, PerformanceBaseline, ScoreSnapshot,
};
use super::{Basis, PairEvidence};
use std::time::Instant;

/// Response basis and alignment across the evaluated members, as optional validation reads them.
#[derive(Clone, Copy, Debug, Default)]
pub(in crate::group::score) struct Summary {
    pub basis: Basis,
    pub response_misaligned: bool,
    pub response_latest_at: Option<Instant>,
}

/// Outside the eligibility band, yet completion-qualified with lower observed reliability than a
/// completion-qualified selection. Its unpaired metrics are not measured as equivalent.
pub(in crate::group::score) fn dominated(
    winner: &ScoreSnapshot,
    candidate: &ScoreSnapshot,
    baseline: PerformanceBaseline,
) -> bool {
    !normal_eligible(candidate, baseline)
        && winner.useful_completed.min(candidate.useful_completed) >= PERFORMANCE_VALIDATION_SAMPLES
        && candidate.observed_reliability < winner.observed_reliability
}

/// A recent failure excludes an ineligible member until its performance evidence expires.
pub(in crate::group::score) fn failure_excluded(
    decision: &Decision,
    index: usize,
    now: Instant,
) -> bool {
    !normal_eligible(&decision.scores[index], decision.baseline)
        && decision.evidence[index]
            .failed_at
            .is_some_and(|at| now.saturating_duration_since(at) < PERFORMANCE_MAX_AGE)
}

pub(in crate::group::score) fn summarize(decision: &Decision, now: Instant) -> Summary {
    let snapshots = &decision.scores;
    let selected = decision.pairs.reference;
    let Some(winner) = snapshots.get(selected) else {
        return Summary::default();
    };
    let mut summary = Summary::default();
    let covered = &decision.membership.covered;
    let mut response_support = None;
    let mut compared = false;
    for (index, candidate) in snapshots.iter().enumerate() {
        if index == selected || !decision.membership.evaluated[index] {
            continue;
        }
        if dominated(winner, candidate, decision.baseline) || failure_excluded(decision, index, now)
        {
            continue;
        }
        if decision.pairs.get(index).is_none() {
            continue;
        }
        let pair = decision
            .pairs
            .summary_pair(index)
            .expect("original pair exists");
        let pair = PairEvidence {
            response: pair.response.filter(|metric| now < metric.expires_at),
            upload: pair.upload.filter(|metric| now < metric.expires_at),
            download: pair.download.filter(|metric| now < metric.expires_at),
            ..pair
        };
        if pair.response.is_none() && pair.upload.is_none() && pair.download.is_none() {
            continue;
        }
        if covered[index]
            && let Some(response) = pair.response
        {
            // Optional pairs cannot lend their target/probe basis to the covered members.
            if response_support.is_none() {
                summary.basis = pair.basis;
            }
            let identity = (pair.basis, response.support);
            summary.response_misaligned |= response_support.is_some_and(|old| old != identity);
            response_support = Some(identity);
            summary.response_latest_at = Some(
                summary
                    .response_latest_at
                    .map_or(response.latest_at, |old| old.min(response.latest_at)),
            );
        }
        if !compared {
            summary.basis = pair.basis;
            compared = true;
        }
    }
    summary
}
