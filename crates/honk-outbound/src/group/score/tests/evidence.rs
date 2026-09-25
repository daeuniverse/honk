use super::*;

#[test]
fn recovered_historical_failure_holds_five_percent_latency_jitter() {
    let nodes = [node("incumbent"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let past = now - Duration::from_secs(3600);
    let failure = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap()
        .start_at(past);
    failure.setup_succeeded_at(past);
    failure.finish_at(ScoreOutcome::Io(io::ErrorKind::ConnectionReset), true, past);
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            200,
            100 + index as u64 * 10,
            1,
            now + Duration::from_secs(index as u64 * 2),
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(4)),
        0
    );
    train_at(
        &manager,
        &nodes[1],
        &target,
        200,
        95,
        1,
        now + Duration::from_secs(5),
    );
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(7)),
        0
    );
    let reasons = manager
        .score_state()
        .selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(reasons.incumbent_held, 1);
    assert_eq!(reasons.fresh_failure_bypass, 0);
}

#[test]
fn only_newer_business_rx_restores_incumbent_protection() {
    for recovery in [
        "none",
        "old-rx",
        "same-time-rx",
        "setup-only",
        "probe",
        "warmup",
        "neutral",
        "other-target",
        "business-rx",
        "new-rx-before-old-finish",
    ] {
        let nodes = [node("incumbent"), node("challenger")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("business.example", IpVersion::V4);
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
        let late = matches!(
            recovery,
            "old-rx" | "same-time-rx" | "new-rx-before-old-finish"
        )
        .then(|| {
            let at = if recovery == "same-time-rx" {
                failed_at
            } else {
                failed_at - Duration::from_secs(1)
            };
            let reporter = feedback.start_at(at);
            reporter.setup_succeeded_at(at);
            reporter.transfer_at(1, 1, at);
            reporter
        });
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
        match recovery {
            "business-rx" | "new-rx-before-old-finish" | "other-target" => {
                let recovered_target = if recovery == "other-target" {
                    context("other.example", IpVersion::V4)
                } else {
                    target.clone()
                };
                train_at(&manager, &nodes[0], &recovered_target, 20, 100, 1, at);
            }
            "setup-only" | "neutral" | "probe" | "warmup" => {
                let source = match recovery {
                    "probe" => ScoreSource::HealthProbe,
                    "warmup" => ScoreSource::Warmup,
                    _ => ScoreSource::Traffic,
                };
                let reporter = feedback.clone().with_source(source).start_at(at);
                reporter.setup_succeeded_at(at);
                if recovery != "setup-only" {
                    reporter.transfer_at(1, 1, at);
                }
                let outcome = if recovery == "neutral" {
                    ScoreOutcome::Cancelled
                } else {
                    ScoreOutcome::Success
                };
                reporter.finish_at(outcome, recovery != "setup-only", at);
            }
            _ => {}
        }
        let selected_at = now + Duration::from_secs(11);
        if let Some(late) = late {
            late.finish_at(ScoreOutcome::Success, true, selected_at);
        }
        let recovered = matches!(recovery, "business-rx" | "new-rx-before-old-finish");
        let state = manager.score_state();
        assert_eq!(
            state.peek_rank_at(
                "score",
                &target,
                &nodes.iter().collect::<Vec<_>>(),
                selected_at
            ),
            usize::from(!recovered),
            "{recovery}"
        );
    }
}

#[test]
fn stale_manager_authority_stays_revoked_after_same_name_recreation() {
    let survivor = node("survivor");
    let removed = node("removed");
    let replacement_node = node("replacement");
    let old_nodes = [survivor.clone(), removed.clone()];
    let old = super::super::super::GroupManager::new(&[group("score", &old_nodes)], &old_nodes);
    let state = old.score_state();
    let seeded_context = context("seeded.example", IpVersion::V4);
    finish_success(&old.selection_plan_for_target("score", &seeded_context));

    let deleted = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[],
        &[],
        None,
        Arc::clone(&state),
    );
    deleted.publish_score_membership();
    let replacement_nodes = [survivor.clone(), replacement_node];
    let replacement = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[group("score", &replacement_nodes)],
        &replacement_nodes,
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    let before = {
        let inner = state.inner.lock();
        (
            inner.tick,
            inner.revalidated_at.len(),
            inner.aggregate.len(),
            inner.exact.len(),
        )
    };
    assert_eq!((before.1, before.2, before.3), (0, 0, 0));

    let stale = old.selection_plan_for_target("score", &context("stale.example", IpVersion::V4));
    finish_success(&stale);
    assert!(
        old.feedback_for_group_node("score", survivor.id, seeded_context.clone())
            .is_none(),
        "the surviving ID must not restore old-manager feedback authority"
    );
    assert!(
        old.feedback_for_group_node("score", removed.id, seeded_context)
            .is_none(),
        "the replaced ID must not restore old-manager feedback authority"
    );
    let after_stale = {
        let inner = state.inner.lock();
        (
            inner.tick,
            inner.revalidated_at.len(),
            inner.aggregate.len(),
            inner.exact.len(),
        )
    };
    assert_eq!(after_stale, before);

    let current =
        replacement.selection_plan_for_target("score", &context("current.example", IpVersion::V4));
    assert!(current.entries[0].feedback.is_some());
    {
        let planned = state.inner.lock();
        assert_eq!(planned.revalidated_at.len(), 1);
        // An unbegun plan is not an opportunity: no discovery state or tick changes yet.
        assert_eq!((planned.tick, planned.aggregate.len()), (before.0, 0));
    }
    finish_success(&current);
    let after_current = state.inner.lock();
    assert!(!after_current.aggregate.is_empty());
    assert!(after_current.tick > before.0);
}

#[test]
fn captured_feedback_requires_current_authority_at_start() {
    let nodes = [node("a"), node("b")];
    let old = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let context = context("captured.example", IpVersion::V4);
    let feedback = old
        .feedback_for_group_node("score", nodes[0].id, context.clone())
        .unwrap();
    let state = old.score_state();
    let replacement = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes)],
        &nodes,
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    let before_tick = state.inner.lock().tick;

    let reporter = feedback.start();
    reporter.setup_succeeded();
    reporter.first_response();
    reporter.tx(123);
    reporter.rx(456);
    reporter.finish(ScoreOutcome::Timeout);
    drop(reporter);

    assert!(!state.has_exact("score", &context, nodes[0].id));
    assert_eq!(state.inner.lock().tick, before_tick);
}

#[test]
fn parsed_score_policy_learns_without_a_feature_flag() {
    let config = honk_config::parser::parse_dae_config(
        r#"
node {
    a: 'socks5://127.0.0.1:10001'
    b: 'socks5://127.0.0.1:10002'
}
group {
    scored {
        policy: score
        filter: name('a', 'b')
    }
}
"#,
    )
    .unwrap();
    let manager = super::super::super::GroupManager::new(&config.groups, &config.nodes);
    let context = context("example.com", IpVersion::V4);

    let first = manager.selection_plan_for_target("scored", &context);
    assert_eq!(first.entries[0].node.name, "a");
    finish_failure(&first);

    let second = manager.selection_plan_for_target("scored", &context);
    assert_eq!(second.entries[0].node.name, "b");
    finish_success(&second);
    assert_eq!(
        manager
            .selection_plan_for_target("scored", &context)
            .entries[0]
            .node
            .id,
        config.nodes[1].id
    );
}

#[test]
fn unrelated_target_failures_preserve_healthy_exact_selection_and_probe_support() {
    let nodes = [node("healthy scoped"), node("scoped rival")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let healthy = context("healthy.example", IpVersion::V4);
    let failing = context("unrelated.example", IpVersion::V6);
    let now = Instant::now();
    for leaf in &nodes {
        train_at(&manager, leaf, &healthy, 32, 100, 1, now);
        probe_at(&manager, leaf, &healthy, 50, now);
    }
    for outcome in [
        ScoreOutcome::TargetFailure,
        ScoreOutcome::Timeout,
        ScoreOutcome::Io(io::ErrorKind::ConnectionReset),
    ] {
        let reporter = manager
            .feedback_for_group_node("score", nodes[0].id, failing.clone())
            .unwrap()
            .start_at(now + Duration::from_secs(2));
        reporter.setup_succeeded_at(now + Duration::from_secs(2));
        reporter.finish_at(outcome, true, now + Duration::from_secs(3));
    }
    let state = manager.score_state();
    let at = now + Duration::from_secs(4);
    let scores = decision_at(&state.inner.lock(), &nodes, &healthy, 0, at);
    assert!(super::super::ranking::normal_eligible(
        &scores.scores[0],
        scores.baseline
    ));
    assert!(!scores.scores[0].unresolved_failure);
    assert!(!scores.scores[0].explore_backed_off);
    assert_eq!(scores.scores[0].probe.value, Some(50.0));
    assert_eq!(
        state.peek_rank_at("score", &healthy, &nodes.iter().collect::<Vec<_>>(), at),
        0
    );
    let failed = score_snapshot(&state.inner.lock(), "score", &failing, nodes[0].id, at);
    assert_eq!(failed.fail_streak, 3);
    assert!(failed.explore_backed_off);
    assert_eq!(
        state.exact_useful_failures("score", &failing, nodes[0].id),
        Some(3)
    );
}

#[test]
fn target_refusal_before_setup_or_without_family_never_opens_node_episode() {
    let leaf = node("refused target");
    let nodes = std::slice::from_ref(&leaf);
    let manager = GroupManager::new(&[group("score", nodes)], nodes);
    let mut target = context("refused.example", IpVersion::V4);
    let now = Instant::now();
    for known_family in [true, false] {
        if !known_family {
            target.target_family = None;
        }
        manager
            .feedback_for_group_node("score", leaf.id, target.clone())
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::TargetFailure, true, now);
    }
    let mut global = target.clone();
    global.target = None;
    let state = manager.score_state();
    let score = score_snapshot(&state.inner.lock(), "score", &global, leaf.id, now);
    assert_eq!(score.completed, 2.0);
    assert_eq!(score.fail_streak, 0);
    assert!(!score.explore_backed_off);
}

#[test]
fn shared_carrier_failure_counts_flows_but_only_one_hard_episode() {
    let leaf = node("shared carrier");
    let nodes = std::slice::from_ref(&leaf);
    let manager = GroupManager::new(&[group("score", nodes)], nodes);
    let target = context("shared.example", IpVersion::V4);
    let feedback = manager
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap();
    let now = Instant::now();
    let outcome = ScoreOutcome::shared_node_failure();
    let pending: Vec<_> = (0..8).map(|_| feedback.start_at(now)).collect();
    manager
        .feedback_for_group_node(
            "score",
            leaf.id,
            context("other-shared.example", IpVersion::V6),
        )
        .unwrap()
        .start_at(now)
        .finish_at(outcome, true, now);
    let recovered_at = now + Duration::from_secs(1);
    train_at(&manager, &leaf, &target, 4, 10, 1, recovered_at);
    for reporter in &pending {
        reporter.finish_at(outcome, true, now + Duration::from_secs(3));
    }
    let state = manager.score_state();
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(3),
    );
    assert_eq!(state.exact_stats("score", &target, leaf.id).unwrap().1, 8);
    assert_eq!(score.fail_streak, 0);
    assert!(!score.unresolved_failure);
    assert!(!score.explore_backed_off);
    feedback.start_at(now + Duration::from_secs(4)).finish_at(
        ScoreOutcome::shared_node_failure(),
        true,
        now + Duration::from_secs(4),
    );
    assert!(
        score_snapshot(
            &state.inner.lock(),
            "score",
            &target,
            leaf.id,
            now + Duration::from_secs(4)
        )
        .unresolved_failure
    );
}
