use super::budget::complete_ordinary;
use super::*;

fn verification_at(
    manager: &GroupManager,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    now: Instant,
) -> ScoreVerificationSnapshot {
    manager
        .score_state()
        .verification_snapshot_at("score", target, &nodes.iter().collect::<Vec<_>>(), now)
        .unwrap()
}

/// Replies that establish availability without publishing response reporters.
fn replies_without_response_at(
    manager: &GroupManager,
    leaf: &Node,
    target: &ScoreSelectionContext,
    samples: usize,
    now: Instant,
) {
    for _ in 0..samples {
        let reporter = manager
            .feedback_for_group_node("score", leaf.id, target.clone())
            .unwrap()
            .start_at(now);
        reporter.setup_succeeded_at(now);
        reporter.transfer_at(1, 1, now);
        reporter.finish_at(ScoreOutcome::Success, true, now);
    }
}

#[test]
fn idle_terminal_does_not_refresh_old_business_evidence() {
    let nodes = [node("idle")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let mut target = context("business.example", IpVersion::V4);
    target.network = SelectionNetwork::Udp;
    target.probe_domain = ProbeDomain::DataUdp;
    let now = Instant::now();
    let reporters: Vec<_> = (0..5)
        .map(|_| {
            let reporter = manager
                .feedback_for_group_node("score", nodes[0].id, target.clone())
                .unwrap()
                .start_at(now);
            reporter.setup_succeeded_at(now);
            reporter.first_response_at(now);
            reporter.transfer_at(1, 1, now);
            reporter
        })
        .collect();
    for second in [20, 40, 60, 80, 100] {
        for reporter in &reporters {
            reporter.transfer_at(1, 0, now + Duration::from_secs(second));
        }
    }
    let expired = now + Duration::from_secs(120);
    for reporter in &reporters {
        reporter.finish_at(ScoreOutcome::Success, true, expired);
        reporter.finish_at(ScoreOutcome::Timeout, true, expired);
    }
    let report = verification_at(&manager, &nodes, &target, expired);
    assert_eq!(report.state, ScoreVerificationState::Provisional);
    let state = manager.score_state();
    let score = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, expired);
    assert_eq!(score.completed, 5.0);
    assert_eq!(score.useful_completed, 5.0);
    assert_eq!(score.fail_streak, 0);
}

#[test]
fn recent_business_uses_latest_rx_across_out_of_order_completions() {
    let nodes = [node("live")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..5)
        .map(|_| {
            let reporter = feedback.start_at(now);
            reporter.setup_succeeded_at(now);
            reporter.transfer_at(1, 1, now + Duration::from_secs(10));
            reporter
        })
        .collect();
    reporters[0].transfer_at(0, 1, now + Duration::from_secs(20));
    reporters[0].transfer_at(0, 1, now + Duration::from_secs(15));
    reporters[0].finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(30));
    let terminal = now + Duration::from_secs(31);
    for reporter in &reporters[1..] {
        reporter.finish_at(ScoreOutcome::Success, true, terminal);
    }
    let report = verification_at(&manager, &nodes, &target, terminal);
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_usable_until(&manager, &nodes, &target, now + Duration::from_secs(80));
    assert_eq!(
        verification_at(&manager, &nodes, &target, now + Duration::from_secs(81)).state,
        ScoreVerificationState::Provisional
    );
}

#[test]
fn delayed_settlement_preserves_fresh_live_availability_without_refreshing_old_rx() {
    let nodes = [node("delayed")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let replied = |rx_at| {
        let reporter = feedback.start_at(now);
        reporter.setup_succeeded_at(now);
        reporter.transfer_at(1, 1, rx_at);
        reporter
    };
    for _ in 0..5 {
        replied(now).finish_at(ScoreOutcome::Success, true, now);
    }
    let stale: Vec<_> = (0..3).map(|_| replied(now)).collect();
    let fresh: Vec<_> = (0..5)
        .map(|_| replied(now + Duration::from_secs(110)))
        .collect();
    let terminal = now + Duration::from_secs(130);
    fresh[0].finish_at(ScoreOutcome::Success, true, terminal);
    assert_eq!(
        verification_at(&manager, &nodes, &target, terminal).state,
        ScoreVerificationState::ObservedUsable
    );
    for reporter in &stale {
        reporter.finish_at(ScoreOutcome::Success, true, terminal);
    }
    assert_eq!(
        verification_at(&manager, &nodes, &target, terminal).state,
        ScoreVerificationState::ObservedUsable
    );
    for reporter in &fresh[1..] {
        reporter.finish_at(ScoreOutcome::Success, true, terminal);
    }
    let report = verification_at(&manager, &nodes, &target, terminal);
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_usable_until(&manager, &nodes, &target, now + Duration::from_secs(170));
}

#[test]
fn failure_requires_strictly_newer_rx_even_after_older_failure_completion() {
    let nodes = [node("recovering")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let fence = now + Duration::from_secs(10);
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let replied = |rx_at| {
        let reporter = feedback.start_at(now);
        reporter.setup_succeeded_at(now);
        reporter.transfer_at(1, 1, rx_at);
        reporter
    };
    let old: Vec<_> = (0..5).map(|_| replied(now)).collect();
    let tied: Vec<_> = (0..5).map(|_| replied(fence)).collect();
    let surviving: Vec<_> = (0..5).map(|_| replied(now)).collect();
    let older_failure = feedback.start_at(now);
    feedback
        .start_at(now)
        .finish_at(ScoreOutcome::Timeout, true, fence);
    older_failure.finish_at(ScoreOutcome::Timeout, true, fence - Duration::from_secs(1));
    let terminal = fence + Duration::from_secs(1);
    for batch in [&old, &tied] {
        for reporter in batch {
            reporter.finish_at(ScoreOutcome::Success, true, terminal);
        }
        let report = verification_at(&manager, &nodes, &target, terminal);
        assert_eq!(report.state, ScoreVerificationState::Provisional);
    }
    for reporter in &surviving {
        reporter.transfer_at(0, 1, terminal);
        reporter.finish_at(
            ScoreOutcome::Success,
            true,
            terminal + Duration::from_secs(1),
        );
    }
    let report = verification_at(&manager, &nodes, &target, terminal + Duration::from_secs(1));
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_usable_until(
        &manager,
        &nodes,
        &target,
        terminal + Duration::from_secs(60),
    );
}

#[test]
fn reload_rejects_old_rx_but_accepts_surviving_flow_progress() {
    let nodes = [node("survivor")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let before = Instant::now() - Duration::from_secs(1);
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..10)
        .map(|_| {
            let reporter = feedback.start_at(before);
            reporter.setup_succeeded_at(before);
            reporter.transfer_at(1, 1, before);
            reporter
        })
        .collect();
    let replacement = GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes)],
        &nodes,
        None,
        manager.score_state(),
    );
    replacement.publish_score_membership();
    let after = Instant::now() + Duration::from_secs(1);
    for reporter in &reporters[..5] {
        reporter.finish_at(ScoreOutcome::Success, true, after);
    }
    let report = verification_at(&replacement, &nodes, &target, after);
    assert_eq!(report.state, ScoreVerificationState::Provisional);
    for reporter in &reporters[5..] {
        reporter.transfer_at(0, 1, after);
        reporter.finish_at(ScoreOutcome::Success, true, after + Duration::from_secs(1));
    }
    let report = verification_at(
        &replacement,
        &nodes,
        &target,
        after + Duration::from_secs(1),
    );
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_usable_until(
        &replacement,
        &nodes,
        &target,
        after + Duration::from_secs(60),
    );
}

#[test]
fn real_flow_gaps_become_usable_and_compared_with_measured_exposure() {
    let nodes = [node("quick"), node("unvalidated")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let state = manager.score_state();
    let initial = verification_at(&manager, &nodes, &target, now);
    assert_eq!(initial.state, ScoreVerificationState::Provisional);
    assert_eq!(initial.pending_count, 2);
    let mut resolved = None;
    for step in 0..256 {
        let at = now + Duration::from_millis(step * 100);
        let (index, feedback) =
            state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at);
        respond_at(
            feedback,
            Duration::from_millis(if index == 0 { 1 } else { 60 }),
            at,
        );
        let counters = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert!(counters.trial_starts + counters.reserved <= 2 + counters.business_starts / 16);
        let snapshot = verification_at(&manager, &nodes, &target, at + Duration::from_millis(60));
        let compared = snapshot.challengers.len() == 1
            && snapshot.challengers[0].relation == ScoreRelation::SelectedFaster;
        if compared && snapshot.pending_count == 0 {
            resolved = Some(snapshot);
            break;
        }
    }
    let snapshot =
        resolved.expect("funded high-rate short flows must resolve the response dispute");
    assert_eq!(snapshot.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(
        snapshot.challengers[0].basis,
        ScoreEvidenceBasis::TargetResponse
    );
    assert_eq!(snapshot.next_action, ScoreValidationAction::None);
}

#[test]
fn funded_large_group_serves_promising_contender_until_graduation() {
    let nodes: Vec<_> = (0..32)
        .map(|index| node(&format!("leaf-{index}")))
        .collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let probe = context("health.example", IpVersion::V4);
    let now = Instant::now();
    train_at(&manager, &nodes[0], &target, 20, 60, 1, now);
    for (index, leaf) in nodes.iter().enumerate() {
        probe_at(
            &manager,
            leaf,
            &probe,
            if index == 31 { 1 } else { 60 },
            now + Duration::from_secs(1),
        );
    }
    let state = manager.score_state();
    let mut graduate = None;
    let mut contender_trials = 0;
    for step in 20..900 {
        let at = now + Duration::from_millis(step * 100);
        let before = state.verification_counters("score", SelectionNetwork::Tcp);
        let (index, feedback) =
            state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at);
        let after = state.verification_counters("score", SelectionNetwork::Tcp);
        if step == 20 {
            assert_eq!(
                index, 31,
                "same-cohort fresh hint should choose a promising question"
            );
        }
        let validation = after.validation_selections > before.validation_selections;
        if validation && index == 31 {
            contender_trials += 1;
        }
        if index == 31 && !validation {
            graduate = Some(step);
            break;
        }
        respond_at(
            feedback,
            Duration::from_millis(if index == 31 { 1 } else { 60 }),
            at,
        );
        let budget = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert!(
            budget.trial_starts + budget.reserved
                <= exploration_target(32) as u64
                    + budget.business_starts / SCORE_EXPLORATION_PERIOD
        );
    }
    let step = graduate.expect(
        "bounded validation must not strand a promising leaf under sufficient offered load",
    );
    assert!((5..=8).contains(&contender_trials));
    let snapshot = verification_at(
        &manager,
        &nodes,
        &target,
        now + Duration::from_millis(step * 100),
    );
    assert_eq!(snapshot.state, ScoreVerificationState::ObservedUsable);
    // Untried rivals are reported as unevaluated, never as compared challengers.
    assert!(snapshot.evaluated_count < snapshot.candidate_count);
    assert!(snapshot.challengers.len() < snapshot.evaluated_count);
}

#[test]
fn equivalent_response_stops_trials() {
    let nodes = [node("first"), node("equivalent")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for (leaf, latency) in nodes.iter().zip([100, 105]) {
        train_at(&manager, leaf, &target, 20, latency, 1, now);
    }
    for _ in 0..256 {
        assert_eq!(
            rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
            0
        );
    }
    let snapshot = verification_at(&manager, &nodes, &target, now + Duration::from_secs(2));
    let relations: Vec<_> = snapshot.challengers.iter().map(|c| c.relation).collect();
    assert_eq!(relations, [ScoreRelation::Equivalent]);
    assert_eq!(snapshot.pending_count, 0);
    assert_eq!(snapshot.next_action, ScoreValidationAction::None);
    assert_eq!(
        manager
            .score_state()
            .verification_counters("score", SelectionNetwork::Tcp)
            .validation_selections,
        0
    );
}

#[test]
fn old_history_cannot_refresh_availability_with_one_new_success() {
    let nodes = [node("historical")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let state = manager.score_state();
    train_at(&manager, &nodes[0], &target, 100, 100, 1, now);
    let now = now + Duration::from_secs(1);
    assert_eq!(
        verification_at(&manager, &nodes, &target, now).state,
        ScoreVerificationState::ObservedUsable
    );
    rank_at(&manager, &nodes, &target, now);
    let before = state.verification_counters("score", SelectionNetwork::Tcp);
    let expired = now + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
    let snapshot = verification_at(&manager, &nodes, &target, expired);
    assert_eq!(snapshot.state, ScoreVerificationState::Provisional);
    assert_eq!(
        state.verification_counters("score", SelectionNetwork::Tcp),
        before
    );
    rank_at(&manager, &nodes, &target, expired);
    train_at(&manager, &nodes[0], &target, 1, 10, 1, expired);
    assert_eq!(
        verification_at(&manager, &nodes, &target, expired + Duration::from_secs(2)).state,
        ScoreVerificationState::Provisional
    );
    train_at(
        &manager,
        &nodes[0],
        &target,
        4,
        10,
        1,
        expired + Duration::from_secs(3),
    );
    assert_eq!(
        verification_at(&manager, &nodes, &target, expired + Duration::from_secs(5)).state,
        ScoreVerificationState::ObservedUsable
    );
}

#[test]
fn probe_and_common_target_pairs_keep_their_basis() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("private-business.example", IpVersion::V4);
    let probe = context("health.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    for (leaf, latency) in nodes.iter().zip([10, 100]) {
        for _ in 0..8 {
            probe_at(&manager, leaf, &probe, latency, now);
        }
    }
    let aggregate_snapshot = verification_at(&manager, &nodes, &aggregate, now);
    assert_eq!(
        aggregate_snapshot.state,
        ScoreVerificationState::Provisional
    );
    let relations = |snapshot: &ScoreVerificationSnapshot| {
        snapshot
            .challengers
            .iter()
            .map(|c| (c.basis, c.relation))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        relations(&aggregate_snapshot),
        [(
            ScoreEvidenceBasis::ConfiguredProbe,
            ScoreRelation::SelectedFaster
        )]
    );
    let exact = verification_at(&manager, &nodes, &target, now);
    assert_eq!(exact.state, ScoreVerificationState::Provisional);
    assert!(
        exact
            .challengers
            .iter()
            .all(|c| c.basis == ScoreEvidenceBasis::ConfiguredProbe)
    );
    for leaf in &nodes {
        train_at(&manager, leaf, &target, 20, 100, 1, now);
    }
    let other = context("different-business.example", IpVersion::V4);
    assert_eq!(
        verification_at(&manager, &nodes, &other, now + Duration::from_secs(2)).state,
        ScoreVerificationState::Provisional
    );
    let fallback = verification_at(&manager, &nodes, &other, now + Duration::from_secs(2));
    assert_eq!(
        relations(&fallback),
        [(ScoreEvidenceBasis::CommonTargets, ScoreRelation::Equivalent)]
    );
    let singleton = verification_at(&manager, &nodes[..1], &target, now + Duration::from_secs(2));
    assert_eq!(singleton.state, ScoreVerificationState::ObservedUsable);
    assert!(singleton.challengers.is_empty());
    assert_eq!(singleton.candidate_count, 1);
}

#[test]
fn configured_probe_pairs_never_settle_the_response_question() {
    let nodes = [node("probe a"), node("probe b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        replies_without_response_at(&manager, leaf, &target, 4, now);
        probe_at(
            &manager,
            leaf,
            &context("health.example", IpVersion::V4),
            100,
            now,
        );
    }
    for read in [&target, &aggregate] {
        let snapshot = verification_at(&manager, &nodes, read, now);
        let bases: Vec<_> = snapshot.challengers.iter().map(|c| c.basis).collect();
        assert_eq!(bases, [ScoreEvidenceBasis::ConfiguredProbe]);
        assert_eq!(snapshot.question, ScoreEvidenceQuestion::Response);
    }
}

#[test]
fn one_unrelated_probe_cannot_suppress_comparable_http_pair() {
    let nodes = [node("raw-direct"), node("http-slow"), node("http-fast")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let probe = context("health.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    probe_at(&manager, &nodes[0], &probe, 1, now);
    let uri = "https://health.example/check";
    for (leaf, latency) in nodes[1..].iter().zip([600, 10]) {
        let feedback = manager
            .feedback_for_http_probe(leaf.id, probe.clone(), uri, uri)
            .unwrap()
            .with_probe_identity(uri, "HEAD");
        for _ in 0..4 {
            let reporter = feedback.start_at(now);
            reporter.probe_latency_at(Duration::from_millis(latency), now);
            reporter.finish_at(ScoreOutcome::Success, false, now);
        }
    }
    assert_eq!(
        manager
            .score_state()
            .peek_rank("score", &aggregate, &nodes.iter().collect::<Vec<_>>()),
        2
    );
    let snapshot = verification_at(&manager, &nodes, &aggregate, now);
    let relations: Vec<_> = snapshot
        .challengers
        .iter()
        .map(|c| (c.name.as_str(), c.basis, c.relation))
        .collect();
    assert_eq!(
        relations,
        [(
            "http-slow",
            ScoreEvidenceBasis::ConfiguredProbe,
            ScoreRelation::SelectedFaster
        )]
    );
    assert_eq!(snapshot.pending_count, 3);
}

#[test]
fn sparse_cancellations_rotate_without_unbounded_exposure() {
    let nodes = [node("working"), node("cancelled-a"), node("cancelled-b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    train_at(&manager, &nodes[0], &target, 20, 100, 1, now);
    let state = manager.score_state();
    let mut trials = [0u64; 3];
    for step in 0..16 {
        let at = now + Duration::from_secs(2) + REVALIDATION_INTERVAL * step;
        train_at(
            &manager,
            &nodes[0],
            &target,
            16,
            100,
            1,
            at - Duration::from_secs(1),
        );
        let before = state.verification_counters("score", SelectionNetwork::Tcp);
        for _ in 0..10 {
            verification_at(&manager, &nodes, &target, at);
        }
        assert_eq!(
            state.verification_counters("score", SelectionNetwork::Tcp),
            before
        );
        let (index, feedback) =
            state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at);
        assert_ne!(index, 0);
        trials[index] += 1;
        feedback
            .begin_at(at)
            .unwrap()
            .start_at(at)
            .finish_at(ScoreOutcome::Cancelled, true, at);
        let budget = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert!(budget.trial_starts + budget.reserved <= 3 + budget.business_starts / 16);
        let snapshot = verification_at(&manager, &nodes, &target, at);
        assert_eq!(snapshot.pending_count, 2);
        assert_eq!(
            snapshot.next_action,
            ScoreValidationAction::NextBusinessFlow
        );
    }
    assert_eq!(trials, [0, 8, 8]);
    let counts = state.verification_counters("score", SelectionNetwork::Tcp);
    assert_eq!(counts.validation_selections, 16);
    assert_eq!(counts.provisional_selections, 16);
}

#[test]
fn exhausted_budget_and_retired_authority_leave_counters_unchanged() {
    let nodes = [node("unknown-a"), node("unknown-b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    // Cancelled flows never complete, so the selection's seeded completion keeps trials offered.
    complete_ordinary(&manager, "score", &nodes[0], 1.0);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let state = manager.score_state();
    for _ in 0..64 {
        let (_, feedback) =
            state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), now);
        feedback
            .begin_at(now)
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::Cancelled, true, now);
    }
    let snapshot = verification_at(&manager, &nodes, &target, now);
    assert_eq!(snapshot.state, ScoreVerificationState::Provisional);
    assert_eq!(snapshot.pending_count, 2);
    assert_eq!(
        snapshot.next_action,
        ScoreValidationAction::NextBusinessFlow
    );
    let before = state.verification_counters("score", SelectionNetwork::Tcp);
    let budget = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(budget.business_starts, 64);
    assert_eq!(budget.trial_starts + budget.reserved, 2 + 63 / 16);
    let authority = state.inner.lock().active_authority.clone().unwrap();
    state.publish_membership(nodes.iter().map(|node| ("score".to_owned(), node.id)));
    state.rank(
        &authority,
        "score",
        &target,
        &nodes.iter().collect::<Vec<_>>(),
        true,
    );
    assert_eq!(
        state.verification_counters("score", SelectionNetwork::Tcp),
        before
    );
}

#[test]
fn stale_failure_keeps_recovery_work_outside_comparisons() {
    for history in [20, 0] {
        let nodes = [node("working"), node("slower"), node("failed")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("business.example", IpVersion::V4);
        let now = Instant::now();
        rank_at(&manager, &nodes, &target, now);
        for (leaf, (samples, latency)) in nodes.iter().zip([(20, 10), (20, 100), (history, 1)]) {
            train_at(&manager, leaf, &target, samples, latency, 1, now);
        }
        for _ in 0..3 {
            manager
                .feedback_for_group_node("score", nodes[2].id, target.clone())
                .unwrap()
                .start_at(now)
                .finish_at(ScoreOutcome::Timeout, true, now);
        }
        let snapshot = verification_at(&manager, &nodes, &target, now + Duration::from_secs(2));
        let relations = |snapshot: &ScoreVerificationSnapshot| {
            snapshot
                .challengers
                .iter()
                .map(|c| (c.name.clone(), c.relation))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            relations(&snapshot),
            [("slower".to_owned(), ScoreRelation::SelectedFaster)]
        );
        assert_eq!(snapshot.candidate_count, 3);
        assert_eq!(snapshot.pending_count, 0);
        let at = now + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
        for leaf in &nodes[..2] {
            train_at(&manager, leaf, &target, 5, 100, 1, at);
        }
        let snapshot = verification_at(&manager, &nodes, &target, at + Duration::from_secs(2));
        // Unknown history and a failed member never become comparisons.
        assert_eq!(
            relations(&snapshot),
            [("slower".to_owned(), ScoreRelation::Equivalent)],
            "history={history}"
        );
        // Stale failure never withdraws the failed member's recovery work.
        assert_eq!(snapshot.pending_count, 1);
        assert_eq!(snapshot.next_action, ScoreValidationAction::Backoff);
        assert_eq!(snapshot.question, ScoreEvidenceQuestion::Recovery);
        assert_eq!(snapshot.wait_reason, ScoreWaitReason::Backoff);
    }
}
#[test]
fn cross_target_latency_is_not_node_degradation() {
    let nodes = [node("fast"), node("slow")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let near = context("near.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    rank_at(&manager, &nodes, &near, now);
    for (leaf, latency) in nodes.iter().zip([10, 100]) {
        train_at(&manager, leaf, &near, 20, latency, 1, now);
    }
    let at = now + Duration::from_secs(2);
    let relations = |snapshot: &ScoreVerificationSnapshot| {
        snapshot
            .challengers
            .iter()
            .map(|c| c.relation)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        relations(&verification_at(&manager, &nodes, &aggregate, at)),
        [ScoreRelation::SelectedFaster]
    );
    // A farther target is slower through every path; it says nothing about this node.
    train_at(
        &manager,
        &nodes[0],
        &context("far.example", IpVersion::V4),
        1,
        100,
        1,
        at,
    );
    let later = at + Duration::from_secs(2);
    let report = verification_at(&manager, &nodes, &aggregate, later);
    assert_eq!(relations(&report), [ScoreRelation::SelectedFaster]);
    assert_ne!(report.question, ScoreEvidenceQuestion::Response);
    // The same target slowing down still reopens that target's comparison.
    train_at(&manager, &nodes[0], &near, 1, 100, 1, later);
    let report = verification_at(&manager, &nodes, &near, later + Duration::from_secs(2));
    assert_eq!(report.question, ScoreEvidenceQuestion::Response);
}
#[test]
fn partial_success_cannot_pin_cancelled_trials_forever() {
    let nodes = [node("working"), node("partial"), node("other")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    train_at(&manager, &nodes[0], &target, 20, 100, 1, now);
    let state = manager.score_state();
    let at = now + Duration::from_secs(2);
    let (index, feedback) =
        state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at);
    assert_eq!(index, 1);
    respond_at(feedback, Duration::from_millis(10), at);
    let mut trials = [0; 3];
    for _ in 0..SCORE_EXPLORATION_PERIOD * 12 {
        let before = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        let (index, feedback) =
            state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at);
        let after = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        if after.periodic_explore + after.cold_explore
            > before.periodic_explore + before.cold_explore
        {
            trials[index] += 1;
        }
        if index != 0 {
            feedback.begin_at(at).unwrap().start_at(at).finish_at(
                ScoreOutcome::Cancelled,
                true,
                at,
            );
        } else {
            respond_at(feedback, Duration::from_millis(100), at);
        }
    }
    // Partial progress never outranks a challenger without any completion.
    assert_eq!(trials[1], 0);
    assert!(trials[2] > 0);
}

#[test]
fn availability_validity_does_not_depend_on_decaying_terminal_completions() {
    let nodes = [node("barely-qualified")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for _ in 0..4 {
        let reporter = manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .start_at(now);
        reporter.setup_succeeded_at(now);
        reporter.transfer_at(1, 1, now);
        reporter.finish_at(ScoreOutcome::Success, true, now);
    }
    let snapshot = verification_at(&manager, &nodes, &target, now);
    assert_eq!(snapshot.state, ScoreVerificationState::ObservedUsable);
    assert_usable_until(&manager, &nodes, &target, now + Duration::from_secs(60));
}

#[test]
fn removed_winner_leaves_no_flap_history() {
    let nodes = [node("removed"), node("retained")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for (leaf, latency) in nodes.iter().zip([10, 100]) {
        train_at(&manager, leaf, &target, 20, latency, 1, now);
    }
    let at = now + Duration::from_secs(2);
    assert_eq!(rank_at(&manager, &nodes, &target, at), 0);
    let state = manager.score_state();
    let before = state.verification_counters("score", SelectionNetwork::Tcp);
    let remaining = &nodes[1..];
    let replacement = GroupManager::with_alive_set_and_score_state(
        &[group("score", remaining)],
        remaining,
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    assert_eq!(
        verification_at(&replacement, remaining, &target, at).state,
        ScoreVerificationState::Provisional
    );
    assert_eq!(
        state.verification_counters("score", SelectionNetwork::Tcp),
        before
    );
    rank_at(&replacement, remaining, &target, at);
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .switch_flap,
        0
    );
}
#[test]
fn response_pair_expires_with_its_support_block() {
    let nodes = [node("only"), node("peer")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("response.example", IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        train_at(&manager, leaf, &target, 8, 50, 1, now);
    }
    let later = now + Duration::from_secs(59);
    replies_without_response_at(&manager, &nodes[0], &target, 8, later);
    let response = |at| {
        decision_at(&manager.score_state().inner.lock(), &nodes, &target, 0, at)
            .pairs
            .get(1)
            .and_then(|pair| pair.response)
            .is_some()
    };
    let report = verification_at(&manager, &nodes, &target, later);
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(report.question, ScoreEvidenceQuestion::None);
    assert!(response(later));
    let expired = now + Duration::from_secs(61);
    let report = verification_at(&manager, &nodes, &target, expired);
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert!(!response(expired));
}

#[test]
fn partial_pair_progress_is_served_before_less_recently_selected_challengers() {
    let nodes = [node("selection"), node("progressing"), node("rival")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("progress.example", IpVersion::V4);
    let now = Instant::now();
    train_at(&manager, &nodes[0], &target, 20, 10, 1, now);
    // Replying first leaves the rival the less recently selected challenger.
    replies_without_response_at(
        &manager,
        &nodes[2],
        &target,
        5,
        now + Duration::from_secs(1),
    );
    let progress_at = now + Duration::from_secs(2);
    replies_without_response_at(&manager, &nodes[1], &target, 3, progress_at);
    // Two response reporters share the selection's block: progress, not yet a pair.
    train_at(&manager, &nodes[1], &target, 2, 100, 1, progress_at);
    let at = now + Duration::from_secs(4);
    assert_eq!(
        verification_at(&manager, &nodes, &target, at).question,
        ScoreEvidenceQuestion::Response
    );
    let refs = nodes.iter().collect::<Vec<_>>();
    assert_eq!(
        manager
            .score_state()
            .rank_plan_at("score", &target, &refs, at)
            .0,
        1
    );
}

#[test]
fn only_reporters_after_the_selection_degraded_count_as_pair_progress() {
    for after_degradation in [false, true] {
        let nodes = [node("degrading"), node("progressing"), node("rival")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("degraded.example", IpVersion::V4);
        let now = Instant::now();
        train_at(&manager, &nodes[0], &target, 20, 10, 1, now);
        replies_without_response_at(
            &manager,
            &nodes[2],
            &target,
            5,
            now + Duration::from_secs(1),
        );
        let replies_at = now + Duration::from_secs(2);
        replies_without_response_at(&manager, &nodes[1], &target, 3, replies_at);
        // A tenfold slower reply degrades the selection on this target.
        let degraded = now + Duration::from_secs(5);
        train_at(&manager, &nodes[0], &target, 1, 100, 1, degraded);
        let progress_at = if after_degradation {
            degraded + Duration::from_secs(1)
        } else {
            replies_at
        };
        train_at(&manager, &nodes[1], &target, 2, 100, 1, progress_at);
        let at = now + Duration::from_secs(8);
        let refs = nodes.iter().collect::<Vec<_>>();
        let (index, _) = manager
            .score_state()
            .rank_plan_at("score", &target, &refs, at);
        assert_eq!(
            index,
            if after_degradation { 1 } else { 2 },
            "after_degradation={after_degradation}"
        );
    }
}
