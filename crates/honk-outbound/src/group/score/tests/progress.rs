use super::super::ranking::{normal_eligible, ordinary_selection};
use super::*;

fn udp_context() -> ScoreSelectionContext {
    let mut target = context("active-udp.example", IpVersion::V4);
    target.network = SelectionNetwork::Udp;
    target.probe_domain = ProbeDomain::DataUdp;
    target
}

fn snapshots(
    manager: &GroupManager,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    at: Instant,
) -> super::super::ranking::Decision {
    let state = manager.score_state();
    let inner = state.inner.lock();
    decision_at(&inner, nodes, target, 0, at)
}

#[test]
fn active_udp_keeps_earned_qualification_without_inventing_completions() {
    let nodes = [node("incumbent"), node("challenger"), node("cold")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = udp_context();
    let now = Instant::now();
    for (index, samples) in [4, 5, 3].into_iter().enumerate() {
        train_at(
            &manager,
            &nodes[index],
            &target,
            samples,
            100 + index as u64 * 5,
            1,
            now,
        );
    }
    // A cold optional trial is not an ordinary incumbent switch.
    let _ = rank_at(&manager, &nodes, &target, now + Duration::from_secs(1));
    let active: Vec<_> = nodes
        .iter()
        .map(|leaf| {
            let reporter = manager
                .feedback_for_group_node("score", leaf.id, target.clone())
                .unwrap()
                .start_at(now + Duration::from_secs(1));
            reporter.setup_succeeded_at(now + Duration::from_secs(1));
            reporter
        })
        .collect();
    for second in (2..=662).step_by(30) {
        let at = now + Duration::from_secs(second);
        for reporter in &active {
            reporter.transfer_at(1, 1, at);
        }
        let scores = snapshots(&manager, &nodes, &target, at);
        let baseline = scores.baseline;
        assert!(scores.scores[0].useful_completed < 4.0);
        if second == 2 {
            assert!(scores.scores[1].useful_completed >= 4.0);
        }
        assert!(baseline.any_qualified);
        assert!(normal_eligible(&scores.scores[0], baseline));
        assert!(normal_eligible(&scores.scores[1], baseline));
        assert!(!normal_eligible(&scores.scores[2], baseline));
        for (score, samples) in scores.scores.iter().zip([4.0, 5.0, 3.0]) {
            let expected = samples * (-((second - 1) as f64) / 1800.0).exp2();
            assert_close(score.completed, expected);
            assert_close(score.useful_completed, expected);
            assert_eq!(score.fail_streak, 0);
            assert!(!score.unresolved_failure);
        }
        if second == 2 {
            let _ = rank_at(&manager, &nodes, &target, at);
        }
        let ordinary = ordinary_selection(
            &scores.scores,
            &nodes.iter().collect::<Vec<_>>(),
            Some(0),
            baseline,
            &scores.pairs,
        );
        assert_eq!(ordinary.index, 0);
    }
    let state = manager.score_state();
    let verification = state
        .verification_snapshot_at(
            "score",
            &target,
            &nodes.iter().collect::<Vec<_>>(),
            now + Duration::from_secs(662),
        )
        .unwrap();
    assert_eq!(verification.state, ScoreVerificationState::ObservedUsable);
    let reasons = state.selection_reason_counts("score", SelectionNetwork::Udp);
    assert_eq!(reasons.incumbent_ineligible, 0);
    assert_eq!(reasons.ordinary_switch, 0);

    train_at(
        &manager,
        &nodes[1],
        &target,
        5,
        105,
        1,
        now + Duration::from_secs(720),
    );
    let expiry = now + Duration::from_secs(722);
    let before = snapshots(&manager, &nodes, &target, expiry - Duration::from_nanos(1));
    assert!(normal_eligible(&before.scores[0], before.baseline));
    let expired = snapshots(&manager, &nodes, &target, expiry);
    assert!(!normal_eligible(&expired.scores[0], expired.baseline));
    let ordinary = ordinary_selection(
        &expired.scores,
        &nodes.iter().collect::<Vec<_>>(),
        Some(0),
        expired.baseline,
        &expired.pairs,
    );
    assert_eq!(ordinary.index, 1);
    assert_eq!(ordinary.reason, SelectionReason::IncumbentIneligible);
    active[0].transfer_at(1, 1, expiry + Duration::from_secs(1));
    let late = snapshots(&manager, &nodes, &target, expiry + Duration::from_secs(1));
    assert!(!normal_eligible(&late.scores[0], late.baseline));

    let settled_at = expiry + Duration::from_secs(2);
    let before = snapshots(&manager, &nodes, &target, settled_at);
    let clone = active[0].clone();
    active[0].finish_at(ScoreOutcome::Success, true, settled_at);
    clone.finish_at(ScoreOutcome::Timeout, true, settled_at);
    clone.transfer_at(1, 1, settled_at + Duration::from_secs(1));
    let settled = snapshots(&manager, &nodes, &target, settled_at);
    assert_close(
        settled.scores[0].completed,
        before.scores[0].completed + 1.0,
    );
    assert_close(
        settled.scores[0].useful_completed,
        before.scores[0].useful_completed + 1.0,
    );
    assert!(normal_eligible(&settled.scores[0], settled.baseline));
    assert!(!settled.scores[0].unresolved_failure);
    for reporter in &active[1..] {
        reporter.finish_at(ScoreOutcome::Cancelled, true, settled_at);
    }
    let terminal_expiry = expiry + Duration::from_secs(61);
    let before = snapshots(
        &manager,
        &nodes,
        &target,
        terminal_expiry - Duration::from_nanos(1),
    );
    assert!(before.scores[0].useful_completed < 4.0);
    assert!(normal_eligible(&before.scores[0], before.baseline));
    let expired = snapshots(&manager, &nodes, &target, terminal_expiry);
    assert!(!normal_eligible(&expired.scores[0], expired.baseline));
}

#[test]
fn publishable_business_rx_opens_recovery_without_settling_the_flow() {
    let nodes = [node("incumbent"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = udp_context();
    let now = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            1000,
            100 + index as u64 * 10,
            1,
            now + Duration::from_secs(index as u64 * 2),
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(4)),
        0
    );
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let failed_at = now + Duration::from_secs(6);
    let failure = feedback.start_at(failed_at);
    failure.setup_succeeded_at(failed_at);
    failure.finish_at(ScoreOutcome::Timeout, true, failed_at);
    train_at(
        &manager,
        &nodes[1],
        &target,
        1000,
        95,
        1,
        now + Duration::from_secs(7),
    );
    let at = now + Duration::from_secs(9);
    for source in [ScoreSource::HealthProbe, ScoreSource::Warmup] {
        let reporter = feedback.clone().with_source(source).start_at(at);
        reporter.setup_succeeded_at(at);
        reporter.transfer_at(1, 1, at);
        reporter.finish_at(ScoreOutcome::Success, true, at);
    }
    let mut untargeted = target.clone();
    untargeted.target = None;
    let unscoped = feedback
        .clone()
        .with_context(untargeted.clone())
        .start_at(at);
    unscoped.setup_succeeded_at(at);
    unscoped.transfer_at(1, 1, at);
    unscoped.finish_at(ScoreOutcome::Cancelled, true, at);
    let setup_only = feedback.start_at(at);
    setup_only.setup_succeeded_at(at);
    setup_only.finish_at(ScoreOutcome::Cancelled, false, at);
    let rx_only = feedback.start_at(at);
    rx_only.setup_succeeded_at(at);
    rx_only.transfer_at(0, 1, at);
    rx_only.finish_at(ScoreOutcome::Cancelled, true, at);
    let active = feedback.start_at(at);
    active.transfer_at(0, 1, at);
    active.setup_succeeded_at(at);
    active.transfer_at(1, 0, at);
    active.transfer_at(0, 0, at);
    let before = snapshots(&manager, &nodes, &target, at);
    assert!(before.scores[0].unresolved_failure);
    untargeted.target_family = None;
    assert!(!snapshots(&manager, &nodes, &untargeted, at).scores[0].unresolved_failure);
    let baseline = before.baseline;
    assert!(normal_eligible(&before.scores[0], baseline));
    let bypass = ordinary_selection(
        &before.scores,
        &nodes.iter().collect::<Vec<_>>(),
        Some(0),
        baseline,
        &before.pairs,
    );
    assert_eq!(bypass.index, 1);
    assert_eq!(bypass.reason, SelectionReason::FreshFailureBypass);

    active.transfer_at(0, 1, at);
    let recovered = snapshots(&manager, &nodes, &target, at);
    assert!(recovered.scores[0].unresolved_failure);
    assert_close(recovered.scores[0].completed, before.scores[0].completed);
    assert_close(
        recovered.scores[0].useful_completed,
        before.scores[0].useful_completed,
    );
    assert_close(
        recovered.scores[0].reliability,
        before.scores[0].reliability,
    );
    assert_close(
        recovered.scores[0].reliability_upper,
        before.scores[0].reliability_upper,
    );
    assert_close(
        recovered.scores[0].observed_reliability,
        before.scores[0].observed_reliability,
    );
    assert_eq!(recovered.scores[0].fail_streak, 1);
    assert!(!recovered.scores[0].explore_backed_off);
    assert!(!super::super::verification::usable(&recovered.evidence[0]));
    let held = ordinary_selection(
        &recovered.scores,
        &nodes.iter().collect::<Vec<_>>(),
        Some(0),
        recovered.baseline,
        &recovered.pairs,
    );
    assert_eq!(held.index, 1);
    assert_eq!(held.reason, SelectionReason::FreshFailureBypass);

    let next_failure = feedback.start_at(at + Duration::from_millis(100));
    next_failure.setup_succeeded_at(at + Duration::from_millis(100));
    next_failure.finish_at(ScoreOutcome::Timeout, true, at + Duration::from_millis(100));
    active.transfer_at(0, 1, at + Duration::from_millis(200));
    let throttled = snapshots(&manager, &nodes, &target, at + Duration::from_millis(200));
    assert!(throttled.scores[0].unresolved_failure);
    // No timer flushes throttled RX: only the next publishable RX or terminal can recover.
    let published_at = at + Duration::from_secs(1);
    let before = snapshots(&manager, &nodes, &target, published_at);
    active.transfer_at(0, 1, published_at);
    let published = snapshots(&manager, &nodes, &target, published_at);
    assert!(published.scores[0].unresolved_failure);
    assert_eq!(published.scores[0].fail_streak, 2);
    assert!(!published.scores[0].explore_backed_off);
    assert_close(published.scores[0].completed, before.scores[0].completed);
    assert_close(
        published.scores[0].useful_completed,
        before.scores[0].useful_completed,
    );
    let clone = active.clone();
    active.finish_at(ScoreOutcome::Cancelled, true, published_at);
    clone.finish_at(ScoreOutcome::Success, true, published_at);
    let cancelled = snapshots(&manager, &nodes, &target, published_at);
    assert!(cancelled.scores[0].unresolved_failure);
    assert_close(cancelled.scores[0].completed, published.scores[0].completed);
    assert_close(
        cancelled.scores[0].useful_completed,
        published.scores[0].useful_completed,
    );
    assert!(!super::super::verification::usable(&cancelled.evidence[0]));

    let last_failure_at = published_at + Duration::from_secs(1);
    let last_failure = feedback.start_at(last_failure_at);
    last_failure.setup_succeeded_at(last_failure_at);
    last_failure.finish_at(ScoreOutcome::Timeout, true, last_failure_at);
    let failed = snapshots(&manager, &nodes, &target, last_failure_at);
    clone.transfer_at(1, 1, last_failure_at + Duration::from_secs(1));
    clone.finish_at(
        ScoreOutcome::Timeout,
        true,
        last_failure_at + Duration::from_secs(1),
    );
    last_failure.finish_at(ScoreOutcome::Success, true, last_failure_at);
    let ignored = snapshots(&manager, &nodes, &target, last_failure_at);
    assert!(ignored.scores[0].unresolved_failure);
    assert_eq!(ignored.scores[0].fail_streak, 3);
    assert_close(ignored.scores[0].completed, failed.scores[0].completed);
    assert_close(
        ignored.scores[0].useful_completed,
        failed.scores[0].useful_completed,
    );
}

#[test]
fn stale_terminal_rx_preserves_failure_and_cannot_refresh_verification() {
    let nodes = [node("incumbent"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = udp_context();
    let now = Instant::now();
    // Two failures must stay below the mature margin to isolate recovery from risk-based promotion.
    for leaf in &nodes {
        train_at(&manager, leaf, &target, 512, 100, 1, now);
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
        0
    );
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let at = now + Duration::from_secs(3);
    let active = feedback.start_at(at);
    active.setup_succeeded_at(at);
    let failure = feedback.start_at(at);
    failure.setup_succeeded_at(at);
    failure.finish_at(ScoreOutcome::Timeout, true, at);
    active.transfer_at(1, 1, at + Duration::from_millis(100));
    assert!(
        snapshots(&manager, &nodes, &target, at + Duration::from_millis(100)).scores[0]
            .unresolved_failure
    );
    let next_failure = feedback.start_at(at + Duration::from_millis(200));
    next_failure.setup_succeeded_at(at + Duration::from_millis(200));
    next_failure.finish_at(ScoreOutcome::Timeout, true, at + Duration::from_millis(200));
    active.transfer_at(0, 1, at + Duration::from_millis(300));
    let finished_at = now + Duration::from_secs(124);
    let before = snapshots(&manager, &nodes, &target, finished_at);
    assert!(before.scores[0].unresolved_failure);
    active.finish_at(ScoreOutcome::Success, true, finished_at);
    let after = snapshots(&manager, &nodes, &target, finished_at);
    assert!(after.scores[0].unresolved_failure);
    assert_close(
        after.scores[0].useful_completed,
        before.scores[0].useful_completed + 1.0,
    );
    let baseline = after.baseline;
    assert!(normal_eligible(&after.scores[0], baseline));
    let ordinary = ordinary_selection(
        &after.scores,
        &nodes.iter().collect::<Vec<_>>(),
        Some(0),
        baseline,
        &after.pairs,
    );
    assert_eq!(ordinary.index, 1);
    assert_eq!(ordinary.reason, SelectionReason::FreshFailureBypass);
    assert_eq!(
        manager
            .score_state()
            .verification_snapshot_at(
                "score",
                &target,
                &nodes.iter().collect::<Vec<_>>(),
                finished_at,
            )
            .unwrap()
            .state,
        ScoreVerificationState::Provisional
    );
    assert!(after.evidence[0].business.is_none());
}

#[test]
fn reload_and_eviction_fence_progress_without_disabling_surviving_reporters() {
    let nodes = [node("survivor"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = udp_context();
    let before = Instant::now() - Duration::from_secs(10);
    for (index, samples) in [4, 5].into_iter().enumerate() {
        train_at(&manager, &nodes[index], &target, samples, 100, 1, before);
    }
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let active = feedback.start_at(before + Duration::from_secs(2));
    active.setup_succeeded_at(before + Duration::from_secs(2));
    active.transfer_at(1, 1, before + Duration::from_secs(2));
    let qualified = snapshots(&manager, &nodes, &target, before + Duration::from_secs(2));
    assert!(normal_eligible(&qualified.scores[0], qualified.baseline));
    let state = manager.score_state();
    let replacement = GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes)],
        &nodes,
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    let after = Instant::now() + Duration::from_secs(1);
    active.transfer_at(0, 1, before + Duration::from_secs(3));
    let stale = snapshots(&replacement, &nodes, &target, after);
    assert!(!normal_eligible(&stale.scores[0], stale.baseline));
    active.transfer_at(0, 1, after);
    let surviving = snapshots(&replacement, &nodes, &target, after);
    assert!(!normal_eligible(&surviving.scores[0], surviving.baseline));
    assert_close(
        surviving.scores[0].useful_completed,
        stale.scores[0].useful_completed,
    );
    assert!(!super::super::verification::usable(&surviving.evidence[0]));

    let new_feedback = replacement
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let failure = new_feedback.start_at(after + Duration::from_secs(1));
    failure.setup_succeeded_at(after + Duration::from_secs(1));
    failure.finish_at(ScoreOutcome::Timeout, true, after + Duration::from_secs(1));
    active.transfer_at(0, 1, after + Duration::from_secs(2));
    assert!(
        snapshots(
            &replacement,
            &nodes,
            &target,
            after + Duration::from_secs(2)
        )
        .scores[0]
            .unresolved_failure
    );

    {
        let mut inner = state.inner.lock();
        inner.exact.resize(NonZeroUsize::new(1).unwrap());
        inner.aggregate.resize(NonZeroUsize::new(2).unwrap());
    }
    let evicting = replacement
        .feedback_for_group_node("score", nodes[1].id, target.clone())
        .unwrap()
        .start_at(after + Duration::from_secs(3));
    let recreated = new_feedback.start_at(after + Duration::from_secs(3));
    recreated.setup_succeeded_at(after + Duration::from_secs(3));
    recreated.finish_at(ScoreOutcome::Timeout, true, after + Duration::from_secs(3));
    let before_late = snapshots(
        &replacement,
        &nodes[..1],
        &target,
        after + Duration::from_secs(4),
    );
    assert!(before_late.scores[0].unresolved_failure);
    active.transfer_at(0, 1, after + Duration::from_secs(4));
    active.finish_at(ScoreOutcome::Success, true, after + Duration::from_secs(4));
    let ignored = snapshots(
        &replacement,
        &nodes[..1],
        &target,
        after + Duration::from_secs(4),
    );
    assert!(ignored.scores[0].unresolved_failure);
    assert_close(ignored.scores[0].completed, before_late.scores[0].completed);
    assert_close(
        ignored.scores[0].useful_completed,
        before_late.scores[0].useful_completed,
    );
    assert_eq!(
        ignored.scores[0].fail_streak,
        before_late.scores[0].fail_streak
    );
    let fresh = new_feedback.start_at(after + Duration::from_secs(5));
    fresh.setup_succeeded_at(after + Duration::from_secs(5));
    fresh.transfer_at(1, 1, after + Duration::from_secs(5));
    assert!(
        snapshots(
            &replacement,
            &nodes[..1],
            &target,
            after + Duration::from_secs(5)
        )
        .scores[0]
            .unresolved_failure
    );
    fresh.finish_at(
        ScoreOutcome::Cancelled,
        true,
        after + Duration::from_secs(5),
    );
    evicting.finish_at(
        ScoreOutcome::Cancelled,
        true,
        after + Duration::from_secs(5),
    );
}

#[test]
fn delayed_terminal_bridges_qualification_to_already_observed_newer_rx() {
    let nodes = [node("delayed"), node("qualified")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = udp_context();
    let now = Instant::now();
    train_at(&manager, &nodes[0], &target, 4, 100, 1, now);
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let active = feedback.start_at(now + Duration::from_secs(1));
    active.setup_succeeded_at(now + Duration::from_secs(1));
    for second in (1..=1801).step_by(30) {
        active.transfer_at(1, 1, now + Duration::from_secs(second));
    }
    let state = manager.score_state();
    let started = now + Duration::from_secs(1802);
    let mut cells = state.start_at(&target, feedback.attributions(), started);
    train_at(
        &manager,
        &nodes[1],
        &target,
        5,
        105,
        1,
        now + Duration::from_secs(1869),
    );
    active.transfer_at(0, 1, now + Duration::from_secs(1871));
    let terminal_at = now + Duration::from_secs(1881);
    let before = snapshots(&manager, &nodes, &target, terminal_at);
    assert!(!normal_eligible(&before.scores[0], before.baseline));

    // RX at +50 was delivered late; RX at +70 alone could not bridge the +60 expiry.
    let sample = FlowSample {
        outcome: ScoreOutcome::Success,
        setup: Some(Duration::ZERO),
        source: ScoreSource::Traffic,
        tx: 1,
        rx: 1,
        eligible_rx_at: Some(now + Duration::from_secs(1851)),
        count_usefulness: true,
    };
    state.finish_at(
        &target,
        feedback.attributions(),
        &mut cells,
        &sample,
        terminal_at,
    );
    let bridged_at = now + Duration::from_secs(1921);
    let bridged = snapshots(&manager, &nodes, &target, bridged_at);
    assert!(bridged.scores[0].useful_completed < 4.0);
    assert!(normal_eligible(&bridged.scores[0], bridged.baseline));
    let ordinary = ordinary_selection(
        &bridged.scores,
        &nodes.iter().collect::<Vec<_>>(),
        Some(0),
        bridged.baseline,
        &bridged.pairs,
    );
    assert_eq!(ordinary.index, 0);
    let expires_at = now + Duration::from_secs(1931);
    let before_expiry = snapshots(
        &manager,
        &nodes,
        &target,
        expires_at - Duration::from_nanos(1),
    );
    assert!(normal_eligible(
        &before_expiry.scores[0],
        before_expiry.baseline
    ));
    let expired = snapshots(&manager, &nodes, &target, expires_at);
    assert!(!normal_eligible(&expired.scores[0], expired.baseline));
    active.transfer_at(0, 1, expires_at + Duration::from_secs(1));
    let gap = snapshots(
        &manager,
        &nodes,
        &target,
        expires_at + Duration::from_secs(1),
    );
    assert!(!normal_eligible(&gap.scores[0], gap.baseline));
    active.finish_at(
        ScoreOutcome::Cancelled,
        true,
        expires_at + Duration::from_secs(1),
    );
}

#[test]
fn four_distinct_live_replies_restore_eligibility_without_paying_terminal_debt() {
    let nodes = [node("recovered"), node("healthy rival")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = udp_context();
    let now = Instant::now();
    train_at(&manager, &nodes[1], &target, 200, 100, 1, now);
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let failed_at = now + Duration::from_secs(2);
    for _ in 0..9 {
        let reporter = feedback.start_at(failed_at);
        reporter.setup_succeeded_at(failed_at);
        reporter.finish_at(ScoreOutcome::TargetFailure, true, failed_at);
    }
    let at = now + Duration::from_secs(3);
    let open: Vec<_> = (0..4)
        .map(|_| {
            let reporter = feedback.start_at(at);
            reporter.setup_succeeded_at(at);
            reporter
        })
        .collect();
    let before = snapshots(&manager, &nodes, &target, at);
    assert!(!normal_eligible(&before.scores[0], before.baseline));
    for (index, reporter) in open.iter().enumerate() {
        reporter.transfer_at(1, 1, at);
        reporter.clone().transfer_at(0, 1, at);
        let current = snapshots(&manager, &nodes, &target, at);
        assert!(!current.scores[0].explore_backed_off);
        assert_eq!(current.scores[0].unresolved_failure, index != 3);
        assert_eq!(
            normal_eligible(&current.scores[0], current.baseline),
            index == 3
        );
        assert_close(current.scores[0].completed, before.scores[0].completed);
        assert_close(
            current.scores[0].useful_completed,
            before.scores[0].useful_completed,
        );
        assert_close(
            current.scores[0].observed_reliability,
            before.scores[0].observed_reliability,
        );
    }
    let recovered = snapshots(&manager, &nodes, &target, at);
    assert_eq!(recovered.scores[0].fail_streak, 0);
    assert!(recovered.scores[0].qualified());
    assert!(super::super::verification::usable(&recovered.evidence[0]));
    assert!(recovered.scores[0].observed_reliability < recovered.scores[1].observed_reliability);
    for reporter in open {
        reporter.finish_at(ScoreOutcome::Cancelled, true, at);
    }
}
