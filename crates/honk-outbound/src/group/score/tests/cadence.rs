use super::*;
#[test]
fn latency_samples_use_a_decayed_weighted_mean() {
    let mut latency = WeightedMean::default();
    latency.record(10.0);
    latency.record(20.0);
    latency.record(30.0);

    assert_close(latency.mean().unwrap(), 20.0);
    assert_close(latency.weight, 3.0);
}

#[test]
fn trained_utility_does_not_trade_latency_for_attempt_balance() {
    let candidate = |attempts, latency_ms| ScoreSnapshot {
        attempts,
        completed: 8.0,
        hysteresis_completed: 8.0,
        reliability: 0.9,
        reliability_upper: 0.9,
        useful_completed: 8.0,
        latency_ms: Some(latency_ms),
        latency_confidence: 1.0,
        throughput: None,
        throughput_confidence: 0.0,
        failures: 0.0,
        selected_at: 0,
        explore_backed_off: false,
        fail_streak: 0,
        targeted: false,
        target_attempts: 0.0,
        target_completed: 0.0,
    };

    let scores = [candidate(100.0, 50.0), candidate(8.0, 500.0)];
    let baseline = performance_baseline(&scores);
    assert!(utility(&scores[0], baseline) > utility(&scores[1], baseline));
}

#[test]
fn relative_performance_is_scale_invariant() {
    let candidate = |latency_ms, throughput| ScoreSnapshot {
        attempts: 8.0,
        completed: 8.0,
        hysteresis_completed: 8.0,
        reliability: 0.9,
        reliability_upper: 0.9,
        useful_completed: 8.0,
        latency_ms: Some(latency_ms),
        latency_confidence: 1.0,
        throughput: Some(throughput),
        throughput_confidence: 1.0,
        failures: 0.0,
        selected_at: 0,
        explore_backed_off: false,
        fail_streak: 0,
        targeted: false,
        target_attempts: 0.0,
        target_completed: 0.0,
    };
    let local = [candidate(30.0, 20_000_000.0), candidate(60.0, 10_000_000.0)];
    let remote = [
        candidate(300.0, 200_000_000.0),
        candidate(600.0, 100_000_000.0),
    ];
    let local_baseline = performance_baseline(&local);
    let remote_baseline = performance_baseline(&remote);

    assert_close(
        utility(&local[0], local_baseline) - utility(&local[1], local_baseline),
        utility(&remote[0], remote_baseline) - utility(&remote[1], remote_baseline),
    );
}

#[test]
fn hold_decision_scales_margin_with_incumbent_evidence() {
    let candidate = |completed, reliability, latency_ms, failures| ScoreSnapshot {
        attempts: completed,
        completed,
        hysteresis_completed: completed,
        reliability,
        reliability_upper: reliability,
        useful_completed: completed,
        latency_ms,
        latency_confidence: f64::from(latency_ms.is_some()),
        throughput: None,
        throughput_confidence: 0.0,
        failures,
        selected_at: 0,
        explore_backed_off: false,
        fail_streak: 0,
        targeted: false,
        target_attempts: 0.0,
        target_completed: 0.0,
    };
    let decision = |incumbent: ScoreSnapshot, best: ScoreSnapshot| {
        let performance = performance_baseline(&[incumbent, best]);
        hold_decision(&incumbent, &best, performance)
    };
    let trained = MIN_TRAINED_EVIDENCE;
    let low_margin = switch_margin(trained);
    let incumbent = candidate(trained, 0.0, None, 0.0);
    let proven = candidate(SCORE_SWITCH_FULL_EVIDENCE, 0.0, None, 0.0);

    assert_eq!(
        decision(
            candidate(trained - f64::EPSILON, 0.0, None, 0.0),
            candidate(trained, low_margin / 2.0, None, 0.0),
        ),
        HoldDecision::UseBest,
    );
    assert_eq!(
        decision(incumbent, candidate(trained, low_margin * 1.01, None, 0.0),),
        HoldDecision::UseBest,
    );
    assert_eq!(
        decision(incumbent, candidate(trained, low_margin / 2.0, None, 0.0),),
        HoldDecision::Held,
    );
    assert_eq!(
        decision(
            proven,
            candidate(
                SCORE_SWITCH_FULL_EVIDENCE,
                SCORE_SWITCH_MARGIN / 2.0,
                None,
                0.0,
            ),
        ),
        HoldDecision::Held,
    );
    assert_eq!(
        decision(
            proven,
            candidate(
                SCORE_SWITCH_FULL_EVIDENCE,
                SCORE_SWITCH_MARGIN * 1.01,
                None,
                0.0,
            ),
        ),
        HoldDecision::UseBest,
    );
    assert_eq!(
        decision(
            candidate(trained, 0.0, Some(1_048_576.0), 0.0),
            candidate(trained, 0.0, Some(1.0), 0.0),
        ),
        HoldDecision::UseBest,
    );
    assert_eq!(
        decision(
            candidate(trained, 0.0, None, SCORE_FAILURE_FORGIVENESS_THRESHOLD,),
            candidate(trained, low_margin / 2.0, None, 0.0),
        ),
        HoldDecision::FreshFailureBypass,
    );
}

#[test]
fn hysteresis_evidence_counts_each_reporter_completion_once() {
    let assert_near = |actual: f64, expected: f64| {
        assert!((actual - expected).abs() < 1e-4, "{actual} != {expected}");
    };
    let node = node("only");
    let manager = super::super::super::GroupManager::new(
        &[group("score", std::slice::from_ref(&node))],
        std::slice::from_ref(&node),
    );
    let context = context("evidence.example", IpVersion::V4);
    for _ in 0..3 {
        finish_success(&manager.selection_plan_for_target("score", &context));
    }
    let score = {
        let state = manager.score_state();
        let inner = state.inner.lock();
        score_snapshot(&inner, "score", &context, node.id, Instant::now())
    };
    assert_near(score.completed, 9.0);
    assert_near(score.hysteresis_completed, 3.0);
    assert_near(
        switch_margin(score.hysteresis_completed),
        SCORE_SWITCH_MARGIN * 3.0 / SCORE_SWITCH_FULL_EVIDENCE,
    );

    for _ in 3..8 {
        finish_success(&manager.selection_plan_for_target("score", &context));
    }
    let score = {
        let state = manager.score_state();
        let inner = state.inner.lock();
        score_snapshot(&inner, "score", &context, node.id, Instant::now())
    };
    assert_near(score.completed, 24.0);
    assert_near(score.hysteresis_completed, 8.0);
    assert_near(
        switch_margin(score.hysteresis_completed),
        SCORE_SWITCH_MARGIN,
    );
}

#[test]
fn exploration_budget_scales_with_candidate_count() {
    assert_eq!(exploration_target(3), 3);
    assert_eq!(exploration_target(4), 4);
    assert_eq!(exploration_target(14), 5);
    assert_eq!(exploration_target(28), 7);
    assert_eq!(exploration_period(3), SCORE_EXPLORATION_MIN_PERIOD);
    assert_eq!(exploration_period(28), 56);
    assert_eq!(exploration_period(128), SCORE_EXPLORATION_MAX_PERIOD);
}

#[test]
fn cold_exploration_skips_backed_off_candidates() {
    let nodes = [node("a"), node("b")];
    let node_refs: Vec<_> = nodes.iter().collect();
    let cold = |backed_off| ScoreSnapshot {
        attempts: 0.0,
        completed: 0.0,
        hysteresis_completed: 0.0,
        reliability: 0.0,
        reliability_upper: 0.5,
        useful_completed: 0.0,
        latency_ms: None,
        latency_confidence: 0.0,
        throughput: None,
        throughput_confidence: 0.0,
        failures: 0.0,
        explore_backed_off: backed_off,
        fail_streak: 0,
        selected_at: 0,
        targeted: false,
        target_attempts: 0.0,
        target_completed: 0.0,
    };
    let snapshots = [cold(true), cold(false)];
    let performance = performance_baseline(&snapshots);
    let selection = best_index(&snapshots, &node_refs, 1, true, performance);
    assert_eq!(selection.index, 1);
    assert_eq!(selection.reason, SelectionReason::ColdExplore);

    let snapshots = [cold(false), cold(false)];
    let performance = performance_baseline(&snapshots);
    assert_eq!(
        best_index(&snapshots, &node_refs, 1, true, performance).index,
        0
    );

    // All backed off: exploration skips, ranking still returns a leaf.
    let snapshots = [cold(true), cold(true)];
    let performance = performance_baseline(&snapshots);
    let selection = best_index(&snapshots, &node_refs, 1, true, performance);
    assert!(!selection.reason.is_exploration());
    assert_eq!(selection.reason, SelectionReason::PerformanceWinner);
}

#[test]
fn consecutive_failures_exclude_leaf_from_ranking() {
    let nodes = [node("a"), node("b")];
    let node_refs: Vec<_> = nodes.iter().collect();
    let trained = |reliability, fail_streak| ScoreSnapshot {
        attempts: 8.0,
        completed: 8.0,
        hysteresis_completed: 8.0,
        reliability,
        reliability_upper: reliability,
        useful_completed: 8.0,
        latency_ms: None,
        latency_confidence: 0.0,
        throughput: None,
        throughput_confidence: 0.0,
        failures: 0.0,
        explore_backed_off: false,
        fail_streak,
        selected_at: 0,
        targeted: false,
        target_attempts: 0.0,
        target_completed: 0.0,
    };
    let snapshots = [trained(0.9, SCORE_FAIL_STREAK_EXCLUDE), trained(0.8, 0)];
    let performance = performance_baseline(&snapshots);
    assert_eq!(
        best_index(&snapshots, &node_refs, 1, false, performance).index,
        1
    );
    // Pinned fallback: with every candidate excluded, rank the full set.
    let snapshots = [
        trained(0.9, SCORE_FAIL_STREAK_EXCLUDE),
        trained(0.8, SCORE_FAIL_STREAK_EXCLUDE),
    ];
    let performance = performance_baseline(&snapshots);
    assert_eq!(
        best_index(&snapshots, &node_refs, 1, false, performance).index,
        0
    );
}

#[test]
fn rank_counts_fail_streak_excluded_candidates() {
    let state = ScorePolicyState::default();
    let nodes = [node("a"), node("b")];
    let node_refs: Vec<_> = nodes.iter().collect();
    state.publish_membership([("score".into(), nodes[0].id), ("score".into(), nodes[1].id)]);
    let context = context("example.com", IpVersion::V4);
    let attributions = [ScoreAttribution {
        group: "score".into(),
        node_id: nodes[0].id,
    }];
    let now = Instant::now();
    let sample = FlowSample {
        outcome: ScoreOutcome::Timeout,
        setup: None,
        first_response: None,
        tx: 0,
        rx: 0,
        elapsed: Duration::ZERO,
        count_usefulness: true,
        streak_neutral: false,
    };
    for _ in 0..SCORE_FAIL_STREAK_EXCLUDE {
        let cells = state.start_at(&context, &attributions, now);
        state.finish_at(&context, &attributions, &cells, &sample, now);
    }
    let _ = state.rank_at("score", &context, &node_refs, now);
    let counts = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(counts.fail_streak_excluded, 1);
    assert_eq!(counts.explore_backed_off, 1);

    let _ = state.peek_rank("score", &context, &node_refs);
    let counts = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(counts.fail_streak_excluded, 1);
    assert_eq!(counts.explore_backed_off, 1);
}

#[test]
fn rank_counts_explore_backed_off_candidates() {
    let state = ScorePolicyState::default();
    let nodes = [node("a"), node("b")];
    let node_refs: Vec<_> = nodes.iter().collect();
    state.publish_membership([("score".into(), nodes[0].id), ("score".into(), nodes[1].id)]);
    let context = context("backoff.example", IpVersion::V4);
    let attributions = [ScoreAttribution {
        group: "score".into(),
        node_id: nodes[0].id,
    }];
    let now = Instant::now();
    let sample = FlowSample {
        outcome: ScoreOutcome::Timeout,
        setup: None,
        first_response: None,
        tx: 0,
        rx: 0,
        elapsed: Duration::ZERO,
        count_usefulness: true,
        streak_neutral: false,
    };
    let cells = state.start_at(&context, &attributions, now);
    state.finish_at(&context, &attributions, &cells, &sample, now);
    let _ = state.rank_at("score", &context, &node_refs, now);
    let counts = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(counts.explore_backed_off, 1);
    assert_eq!(counts.fail_streak_excluded, 0);
}

#[test]
fn exploration_backoff_grows_with_failures_and_shrinks_with_success() {
    let state = ScorePolicyState::default();
    let leaf = node("leaf");
    state.publish_membership([("score".into(), leaf.id)]);
    let context = context("example.com", IpVersion::V4);
    let attributions = [ScoreAttribution {
        group: "score".into(),
        node_id: leaf.id,
    }];
    let now = Instant::now();
    let sample = |outcome, setup| FlowSample {
        outcome,
        setup,
        first_response: None,
        tx: 0,
        rx: 0,
        elapsed: Duration::ZERO,
        count_usefulness: true,
        streak_neutral: false,
    };
    let backed_off = |at: Instant| {
        let inner = state.inner.lock();
        score_snapshot(&inner, "score", &context, leaf.id, at).explore_backed_off
    };
    let fail = |at: Instant| {
        let cells = state.start_at(&context, &attributions, at);
        state.finish_at(
            &context,
            &attributions,
            &cells,
            &sample(ScoreOutcome::Timeout, None),
            at,
        );
    };
    let neutral = |outcome, at: Instant| {
        let cells = state.start_at(&context, &attributions, at);
        let mut neutral_sample = sample(outcome, None);
        neutral_sample.streak_neutral = true;
        state.finish_at(&context, &attributions, &cells, &neutral_sample, at);
    };
    let streak = |at: Instant| {
        let inner = state.inner.lock();
        score_snapshot(&inner, "score", &context, leaf.id, at).fail_streak
    };

    fail(now);
    // Probe/urltest/warm outcomes never move the streak or the backoff.
    neutral(ScoreOutcome::Success, now);
    neutral(ScoreOutcome::Timeout, now);
    assert_eq!(streak(now), 1);
    assert!(backed_off(now + Duration::from_secs(1)));
    assert!(!backed_off(
        now + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(1)
    ));

    let second = now + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(2);
    fail(second);
    assert!(backed_off(
        second + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(1)
    ));
    assert!(!backed_off(
        second + SCORE_EXPLORE_BACKOFF_BASE * 2 + Duration::from_secs(1)
    ));

    let cells = state.start_at(&context, &attributions, second);
    state.finish_at(
        &context,
        &attributions,
        &cells,
        &sample(ScoreOutcome::Success, Some(Duration::from_millis(10))),
        second,
    );
    // Success steps the streak down (2 → 1), so the next failure lands
    // back on the doubled cadence rather than the base one.
    assert!(!backed_off(second + Duration::from_secs(1)));
    let third = second + Duration::from_secs(2);
    fail(third);
    assert!(backed_off(
        third + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(1)
    ));
    assert!(!backed_off(
        third + SCORE_EXPLORE_BACKOFF_BASE * 2 + Duration::from_secs(1)
    ));
}

#[test]
fn large_score_groups_periodically_try_non_incumbent() {
    let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
    let node_refs: Vec<_> = nodes.iter().collect();
    let context = context("example.com", IpVersion::V4);
    let state = ScorePolicyState::default();
    state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
    let now = Instant::now();
    {
        let mut inner = state.inner.lock();
        for (index, node) in nodes.iter().enumerate() {
            inner.aggregate.put(
                AggregateKey {
                    group: "score".into(),
                    network: SelectionNetwork::Tcp,
                    family: None,
                    node_id: node.id,
                },
                Stats {
                    setup_success: 8.0,
                    useful_success: 8.0,
                    first_response_ms: WeightedMean {
                        sum: 800.0,
                        weight: 8.0,
                    },
                    updated_at: Some(now),
                    selected_at: u64::from(index == 0),
                    ..Default::default()
                },
            );
        }
        inner.selection_counts.insert(
            SelectionCadenceKey::new("score", &context),
            exploration_period(nodes.len()) - 1,
        );
    }

    assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);
}

#[test]
fn periodic_exploration_prefers_reliability_upper_bound() {
    let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
    let node_refs: Vec<_> = nodes.iter().collect();
    let candidate = |attempts, reliability_upper, selected_at| ScoreSnapshot {
        attempts,
        completed: 8.0,
        hysteresis_completed: 8.0,
        reliability: 0.2,
        reliability_upper,
        useful_completed: 8.0,
        latency_ms: None,
        latency_confidence: 0.0,
        throughput: None,
        throughput_confidence: 0.0,
        failures: 0.0,
        selected_at,
        explore_backed_off: false,
        fail_streak: 0,
        targeted: false,
        target_attempts: 0.0,
        target_completed: 0.0,
    };
    let mut snapshots = vec![candidate(8.0, 0.2, 0); nodes.len()];
    snapshots[0] = candidate(8.0, 0.9, 1);
    snapshots[1] = candidate(1.0, 0.3, 0);
    snapshots[2] = candidate(8.0, 0.8, 0);
    let performance = performance_baseline(&snapshots);

    let selected = best_index(
        &snapshots,
        &node_refs,
        exploration_period(nodes.len()),
        true,
        performance,
    );

    assert_eq!(selected.index, 2);
    assert_eq!(selected.reason, SelectionReason::PeriodicExplore);
}

#[test]
fn large_score_groups_cap_initial_target_exploration() {
    let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let context = context("example.com", IpVersion::V4);
    let mut seen = std::collections::HashSet::new();

    for _ in 0..exploration_target(nodes.len()) {
        let plan = manager.selection_plan_for_target("score", &context);
        seen.insert(plan.entries[0].node.id);
        finish_success(&plan);
    }

    assert_eq!(seen.len(), exploration_target(nodes.len()));
}

#[test]
fn score_peek_does_not_consume_group_exploration_budget() {
    let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
    let node_refs: Vec<_> = nodes.iter().collect();
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let state = ScorePolicyState::default();
    state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
    let now = Instant::now();
    {
        let mut inner = state.inner.lock();
        for (index, node) in nodes.iter().enumerate() {
            inner.aggregate.put(
                AggregateKey {
                    group: "score".into(),
                    network: SelectionNetwork::Tcp,
                    family: None,
                    node_id: node.id,
                },
                Stats {
                    setup_success: 8.0,
                    useful_success: 8.0,
                    first_response_ms: WeightedMean {
                        sum: 800.0,
                        weight: 8.0,
                    },
                    updated_at: Some(now),
                    selected_at: u64::from(index == 0),
                    ..Default::default()
                },
            );
        }
        inner.selection_counts.insert(
            SelectionCadenceKey::new("score", &context),
            exploration_period(nodes.len()) - 1,
        );
    }

    let selected = state.rank_at("score", &context, &node_refs, now);
    assert_eq!(selected, 1);
    let key = SelectionCadenceKey::new("score", &context);
    let count = state.inner.lock().selection_counts[&key];
    assert_eq!(state.peek_rank("score", &context, &node_refs), selected);
    assert_eq!(state.inner.lock().selection_counts[&key], count);
}

#[test]
fn same_scope_exploration_period_and_peek_are_unchanged() {
    let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
    let node_refs: Vec<_> = nodes.iter().collect();
    let context = context("example.com", IpVersion::V4);
    let state = ScorePolicyState::default();
    state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
    let now = Instant::now();
    {
        let mut inner = state.inner.lock();
        for (index, node) in nodes.iter().enumerate() {
            inner.aggregate.put(
                AggregateKey {
                    group: "score".into(),
                    network: SelectionNetwork::Tcp,
                    family: None,
                    node_id: node.id,
                },
                Stats {
                    setup_success: 8.0,
                    useful_success: 8.0,
                    first_response_ms: WeightedMean {
                        sum: 800.0,
                        weight: 8.0,
                    },
                    updated_at: Some(now),
                    selected_at: u64::from(index == 0),
                    ..Default::default()
                },
            );
        }
        inner.selection_counts.insert(
            SelectionCadenceKey::new("score", &context),
            exploration_period(nodes.len()) - 1,
        );
    }

    let selected = state.rank_at("score", &context, &node_refs, now);
    assert_eq!(selected, 1);
    assert_eq!(
        state.inner.lock().selection_counts[&SelectionCadenceKey::new("score", &context)],
        exploration_period(nodes.len())
    );
    assert_eq!(state.peek_rank("score", &context, &node_refs), selected);
    assert_eq!(
        state.inner.lock().selection_counts[&SelectionCadenceKey::new("score", &context)],
        exploration_period(nodes.len())
    );
}

#[test]
fn periodic_exploration_is_scoped_by_network_and_family() {
    let nodes = [node("a"), node("b")];
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let targeted = |network, family| ScoreSelectionContext {
        network,
        probe_domain: if network == SelectionNetwork::Tcp {
            ProbeDomain::Tcp
        } else {
            ProbeDomain::DataUdp
        },
        target_family: Some(family),
        health_family: family,
        target: Some(ScoreTarget::domain("target.example", 443)),
    };
    let aggregate = |network| {
        ScoreSelectionContext::aggregate(
            network,
            if network == SelectionNetwork::Tcp {
                ProbeDomain::Tcp
            } else {
                ProbeDomain::DataUdp
            },
            IpVersion::V4,
        )
    };
    let contexts = [
        targeted(SelectionNetwork::Tcp, IpVersion::V4),
        targeted(SelectionNetwork::Tcp, IpVersion::V6),
        targeted(SelectionNetwork::Udp, IpVersion::V4),
        targeted(SelectionNetwork::Udp, IpVersion::V6),
        aggregate(SelectionNetwork::Tcp),
        aggregate(SelectionNetwork::Udp),
    ];
    for context in &contexts {
        let _ = manager.selection_plan_for_target("score", context);
    }
    let state = manager.score_state();
    assert_eq!(state.inner.lock().selection_counts.len(), 6);
    println!(
        "cadence scope cardinality={}",
        state.inner.lock().selection_counts.len()
    );

    let tcp_v4_key = SelectionCadenceKey::new("score", &contexts[0]);
    state
        .inner
        .lock()
        .selection_counts
        .insert(tcp_v4_key.clone(), exploration_period(nodes.len()) - 1);
    let _ = manager.selection_plan_for_target("score", &contexts[2]);
    assert_eq!(
        state.inner.lock().selection_counts[&tcp_v4_key],
        exploration_period(nodes.len()) - 1,
        "UDP-V4 must not consume TCP-V4 cadence"
    );
    let _ = manager.selection_plan_for_target("score", &contexts[0]);
    assert_eq!(
        state.inner.lock().selection_counts[&tcp_v4_key],
        exploration_period(nodes.len())
    );

    let different_target = context("other.example", IpVersion::V4);
    let _ = manager.selection_plan_for_target("score", &different_target);
    assert_eq!(state.inner.lock().selection_counts.len(), 6);
}

#[test]
fn selection_count_reload_lifecycle_matches_group_name() {
    let nodes = [node("a"), node("b")];
    let old = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let context = context("reload.example", IpVersion::V4);
    let _ = old.selection_plan_for_target("score", &context);
    let state = old.score_state();
    let before: u64 = state.inner.lock().selection_counts.values().copied().sum();

    let empty = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[group("score", &[])],
        &[],
        None,
        Arc::clone(&state),
    );
    empty.publish_score_membership();
    assert_eq!(
        state
            .inner
            .lock()
            .selection_counts
            .values()
            .copied()
            .sum::<u64>(),
        before,
        "a committed group name retains cadence through zero leaves"
    );

    let mut selector = group("score", &nodes);
    selector.policy = GroupPolicy::Selector;
    let non_score = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[selector],
        &nodes,
        None,
        Arc::clone(&state),
    );
    non_score.publish_score_membership();
    assert_eq!(
        state
            .inner
            .lock()
            .selection_counts
            .values()
            .copied()
            .sum::<u64>(),
        before,
        "a surviving name retains cadence through Score to non-Score"
    );

    let removed = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[],
        &[],
        None,
        Arc::clone(&state),
    );
    removed.publish_score_membership();
    assert!(state.inner.lock().selection_counts.is_empty());
}
