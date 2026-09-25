use honk_outbound::alive::IpVersion;
use honk_outbound::group::{
    GroupManager, ScoreBudgetCounters, ScoreChallenger, ScoreEvidenceBasis, ScoreEvidenceQuestion,
    ScoreRelation, ScoreValidationAction, ScoreVerificationCounters, ScoreVerificationSnapshot,
    ScoreVerificationState, ScoreWaitReason, SelectionNetwork,
};

pub(super) fn verification(
    group_manager: &GroupManager,
    group: &str,
) -> (Option<String>, serde_json::Value) {
    let tcp = group_manager.score_verification_for_network(group, SelectionNetwork::Tcp);
    let selected = tcp.as_ref().map(|(name, _)| name.clone());
    (
        selected,
        serde_json::json!({
            "objective": "responseQualityWithAvailability",
            "scope": "aggregate",
            "tcp": snapshot(tcp, SelectionNetwork::Tcp),
            "udp": snapshot(group_manager.score_verification_for_network(group, SelectionNetwork::Udp), SelectionNetwork::Udp),
        }),
    )
}

fn snapshot(
    selection: Option<(String, ScoreVerificationSnapshot)>,
    network: SelectionNetwork,
) -> serde_json::Value {
    let (selected, snapshot) = match selection {
        Some((selected, snapshot)) => (Some(selected), Some(snapshot)),
        None => (None, None),
    };
    // No eligible ordinary candidate is not evidence about a final or last resort.
    let snapshot = snapshot.unwrap_or(ScoreVerificationSnapshot {
        state: ScoreVerificationState::Provisional,
        next_action: ScoreValidationAction::None,
        question: ScoreEvidenceQuestion::None,
        wait_reason: ScoreWaitReason::None,
        challengers: Vec::new(),
        candidate_count: 0,
        evaluated_count: 0,
        pending_count: 0,
        network,
        target_family: None,
        health_family: IpVersion::V4,
        target_specific: false,
    });
    serde_json::json!({
        "selected": selected,
        "state": match snapshot.state {
            ScoreVerificationState::Provisional => "provisional",
            ScoreVerificationState::ObservedUsable => "observedUsable",
        },
        "challengers": snapshot.challengers.iter().map(challenger).collect::<Vec<_>>(),
        "nextAction": match snapshot.next_action {
            ScoreValidationAction::None => "none",
            ScoreValidationAction::NextBusinessFlow => "nextBusinessFlow",
            ScoreValidationAction::Backoff => "backoff",
        },
        "question": match snapshot.question {
            ScoreEvidenceQuestion::None => "none",
            ScoreEvidenceQuestion::Availability => "availability",
            ScoreEvidenceQuestion::Response => "response",
            ScoreEvidenceQuestion::Qualification => "qualification",
            ScoreEvidenceQuestion::Recovery => "recovery",
        },
        "waitReason": match snapshot.wait_reason {
            ScoreWaitReason::None => "none",
            ScoreWaitReason::Budget => "budget",
            ScoreWaitReason::ComparableTraffic => "comparableTraffic",
            ScoreWaitReason::InFlight => "inFlight",
            ScoreWaitReason::Backoff => "backoff",
        },
        "coverage": {
            "scope": if snapshot.evaluated_count < snapshot.candidate_count { "bounded" } else { "all" },
            "candidates": snapshot.candidate_count,
            "evaluated": snapshot.evaluated_count,
            "unevaluated": snapshot.candidate_count - snapshot.evaluated_count,
            "pending": snapshot.pending_count,
        },
        "network": match snapshot.network {
            SelectionNetwork::Tcp => "tcp",
            SelectionNetwork::Udp => "udp",
        },
        "targetFamily": snapshot.target_family.map(|family| match family {
            IpVersion::V4 => "ipv4",
            IpVersion::V6 => "ipv6",
        }),
        "healthFamily": match snapshot.health_family {
            IpVersion::V4 => "ipv4",
            IpVersion::V6 => "ipv6",
        },
        "targetSpecific": snapshot.target_specific,
    })
}

pub(super) fn counters(counters: ScoreVerificationCounters) -> serde_json::Value {
    serde_json::json!({
        "provisionalSelections": counters.provisional_selections,
        "usableSelections": counters.usable_selections,
        "validationSelections": counters.validation_selections,
    })
}

fn challenger(value: &ScoreChallenger) -> serde_json::Value {
    serde_json::json!({
        "name": value.name,
        "basis": match value.basis {
            ScoreEvidenceBasis::ConfiguredProbe => "configuredProbe",
            ScoreEvidenceBasis::TargetResponse => "targetResponse",
            ScoreEvidenceBasis::CommonTargets => "commonTargets",
        },
        "relation": match value.relation {
            ScoreRelation::SelectedFaster => "selectedFaster",
            ScoreRelation::Equivalent => "equivalent",
            ScoreRelation::ChallengerFaster => "challengerFaster",
        },
        "reporters": value.reporters,
        "validForMs": value.valid_for_ms,
    })
}

pub(super) fn budget(value: ScoreBudgetCounters) -> serde_json::Value {
    serde_json::json!({
        "businessStarts": value.business_starts,
        "sources": { "cold": value.cold_trial_starts, "periodic": value.periodic_trial_starts, "recovery": value.recovery_starts },
        "trialStarts": value.trial_starts,
        "reserved": value.reserved,
        "spent": value.spent,
        "budgetBlocked": value.budget_blocked,
        "inFlightBlocked": value.in_flight_blocked,
        "refunded": value.refunded,
        "expired": value.expired,
        "coldAllowance": value.cold_allowance,
        "coldAvailable": value.cold_available,
        "earnedAvailable": value.earned_available,
        "earningPeriod": value.earning_period,
        "scopes": value.scopes,
        "trialSuccess": value.trial_success,
        "trialFailure": value.trial_failure,
        "trialCancelled": value.trial_cancelled,
        "trialSetupHistogram": value.trial_setup_histogram,
        "trialSetupMillis": value.trial_setup_millis,
        "trialElapsedMillis": value.trial_elapsed_millis,
    })
}
