use super::ranking::decision;
use super::*;
use honk_config::node::Node;

mod question;
pub(super) use question::{plan, usable};
#[cfg(test)]
pub(super) use question::{questions, report};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreVerificationState {
    Provisional,
    ObservedUsable,
}

/// Which retained response evidence a pairwise comparison reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreEvidenceBasis {
    ConfiguredProbe,
    TargetResponse,
    CommonTargets,
}

/// Paired response values within 10% of each other are practically equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreRelation {
    SelectedFaster,
    Equivalent,
    ChallengerFaster,
}

/// One fresh qualified response pair between the ordinary selection and an evaluated challenger.
/// It describes measured response time only; it is not a promotion or reliability verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreChallenger {
    /// Member display tag, which need not be unique across nested paths.
    pub name: String,
    pub basis: ScoreEvidenceBasis,
    pub relation: ScoreRelation,
    /// Weaker side's distinct retained reporters.
    pub reporters: u8,
    pub valid_for_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreValidationAction {
    None,
    NextBusinessFlow,
    Backoff,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScoreEvidenceQuestion {
    #[default]
    None,
    Availability,
    Response,
    Qualification,
    Recovery,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScoreWaitReason {
    #[default]
    None,
    Budget,
    ComparableTraffic,
    InFlight,
    Backoff,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScoreTrialSource {
    #[default]
    None,
    Cold,
    Periodic,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreVerificationSnapshot {
    pub state: ScoreVerificationState,
    pub next_action: ScoreValidationAction,
    pub question: ScoreEvidenceQuestion,
    pub wait_reason: ScoreWaitReason,
    pub challengers: Vec<ScoreChallenger>,
    pub candidate_count: usize,
    /// Members receiving comparisons; smaller than `candidate_count` when the set is bounded.
    pub evaluated_count: usize,
    pub pending_count: usize,
    pub health_family: IpVersion,
    pub network: SelectionNetwork,
    pub target_family: Option<IpVersion>,
    pub target_specific: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScoreVerificationCounters {
    pub provisional_selections: u64,
    pub usable_selections: u64,
    pub validation_selections: u64,
}

#[derive(Clone, Copy)]
pub(super) struct TimedMetric {
    pub reporters: u8,
    pub latest_at: Instant,
}

#[derive(Clone, Copy, Default)]
pub(super) struct VerificationEvidence {
    pub business: Option<TimedMetric>,
    pub failed_at: Option<Instant>,
}

impl VerificationEvidence {
    pub(super) fn new(stats: &Stats, now: Instant) -> Self {
        let availability = &stats.availability;
        Self {
            business: availability
                .latest_rx_at
                .filter(|at| {
                    *at <= now && now < *at + LIVE_QUALIFICATION_TTL && availability.reporters > 0
                })
                .map(|latest_at| TimedMetric {
                    reporters: availability.reporters,
                    latest_at,
                }),
            failed_at: stats.failed_at,
        }
    }
}

impl ScorePolicyState {
    /// `names` are the members' display tags, aligned with `nodes`.
    pub(in crate::group) fn verification_selection(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        names: &[&str],
    ) -> Option<(usize, ScoreVerificationSnapshot)> {
        self.verification_selection_at(group, context, (nodes, names), Instant::now())
    }

    #[cfg(test)]
    pub(super) fn verification_snapshot_at(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
    ) -> Option<ScoreVerificationSnapshot> {
        let names: Vec<_> = nodes.iter().map(|node| node.name.as_str()).collect();
        self.verification_selection_at(group, context, (nodes, &names), now)
            .map(|(_, snapshot)| snapshot)
    }

    fn verification_selection_at(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        members: (&[&Node], &[&str]),
        now: Instant,
    ) -> Option<(usize, ScoreVerificationSnapshot)> {
        if members.0.is_empty() {
            return None;
        }
        let inner = self.inner.lock();
        let decision = decision(&inner, group, context, members.0, now, false);
        let report = question::report(&inner, (group, context), &decision, members, now);
        Some((decision.ordinary.index, report))
    }

    pub(in crate::group) fn verification_counters(
        &self,
        group: &str,
        network: SelectionNetwork,
    ) -> ScoreVerificationCounters {
        self.inner
            .lock()
            .verification_counters
            .get(&SelectionReasonKey::new(group, network))
            .copied()
            .unwrap_or_default()
    }

    pub(super) fn record_verification(
        inner: &mut StateInner,
        key: &SelectionHistoryKey,
        selected_usable: bool,
        validation: bool,
    ) {
        let counts = inner
            .verification_counters
            .entry(SelectionReasonKey::new(&key.group, key.network))
            .or_default();
        let selections = if selected_usable {
            &mut counts.usable_selections
        } else {
            &mut counts.provisional_selections
        };
        *selections = selections.saturating_add(1);
        if validation {
            counts.validation_selections = counts.validation_selections.saturating_add(1);
        }
        // Every authorized rank, including trials, keeps its target history resident in the LRU.
        inner.selection_history.promote(key);
    }
}
