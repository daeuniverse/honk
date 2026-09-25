use super::*;

#[test]
fn selection_reason_instrumentation_preserves_existing_winners() {
    let nodes = [node("a"), node("b")];
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("baseline.example", IpVersion::V4);
    let apply = selected(&manager, &target);
    let peek = manager
        .get_score_selection_for_network("score", SelectionNetwork::Tcp)
        .expect("Score group has candidates");

    let singleton = node("singleton");
    let singleton_manager = super::super::super::GroupManager::new(
        &[group("score", std::slice::from_ref(&singleton))],
        std::slice::from_ref(&singleton),
    );
    let singleton_selected = selected(&singleton_manager, &target);

    let last_resort = node("last-resort");
    let alive = Arc::new(super::super::super::AliveDialerSet::new());
    alive.report_unavailable_forced(last_resort.id, ProbeDomain::Tcp, IpVersion::V4);
    let last_resort_manager = super::super::super::GroupManager::with_alive_set(
        &[group("score", std::slice::from_ref(&last_resort))],
        std::slice::from_ref(&last_resort),
        Some(alive),
    );
    let last_resort_selected = selected(&last_resort_manager, &target);

    assert_eq!(apply, nodes[0].id);
    assert_eq!(peek, nodes[0].name);
    assert_eq!(singleton_selected, singleton.id);
    assert_eq!(last_resort_selected, last_resort.id);
}

#[test]
fn switch_flap_counts_only_quick_committed_reversals() {
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let key = SelectionHistoryKey::new("score", &context);
    let first = node("first").id;
    let second = node("second").id;
    let mut inner = StateInner::default();

    let record = |inner: &mut StateInner, node_id, reason| {
        ScorePolicyState::record_switch_flap(inner, &key, node_id, reason);
    };
    record(&mut inner, first, SelectionReason::PerformanceWinner);
    // Exploration never touches flap history.
    record(&mut inner, second, SelectionReason::PeriodicExplore);
    record(&mut inner, second, SelectionReason::PerformanceWinner);
    // Same-winner selections push the next reversal out of the window.
    for _ in 0..SCORE_SWITCH_FLAP_WINDOW {
        record(&mut inner, second, SelectionReason::PerformanceWinner);
    }
    record(&mut inner, first, SelectionReason::ReliabilityWinner);
    record(&mut inner, second, SelectionReason::PerformanceWinner);

    assert_eq!(
        inner
            .selection_reasons
            .get(&SelectionReasonKey::new("score", SelectionNetwork::Tcp))
            .unwrap()
            .switch_flap,
        1
    );
}

#[test]
fn switch_flap_ignores_cross_target_interleaving() {
    let first = node("first").id;
    let second = node("second").id;
    let mut inner = StateInner::default();
    let key_a = SelectionHistoryKey::new("score", &context("a.example", IpVersion::V4));
    let key_b = SelectionHistoryKey::new("score", &context("b.example", IpVersion::V4));
    let flap_count = |inner: &StateInner| {
        inner
            .selection_reasons
            .get(&SelectionReasonKey::new("score", SelectionNetwork::Tcp))
            .map_or(0, |counts| counts.switch_flap)
    };

    // A→first, B→second, A→first: neither target reversed its own winner.
    for (key, node_id) in [(&key_a, first), (&key_b, second), (&key_a, first)] {
        ScorePolicyState::record_switch_flap(
            &mut inner,
            key,
            node_id,
            SelectionReason::PerformanceWinner,
        );
    }
    assert_eq!(flap_count(&inner), 0);

    // A same-target reversal within the window still counts.
    ScorePolicyState::record_switch_flap(
        &mut inner,
        &key_a,
        second,
        SelectionReason::PerformanceWinner,
    );
    ScorePolicyState::record_switch_flap(
        &mut inner,
        &key_a,
        first,
        SelectionReason::PerformanceWinner,
    );
    assert_eq!(flap_count(&inner), 1);
}

#[test]
fn ordinary_switch_counts_commits_but_not_first_choice_stay_peek_or_trial() {
    let nodes = [node("first"), node("second")];
    let node_refs = [&nodes[0], &nodes[1]];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let context = context("switch.example", IpVersion::V4);
    let now = Instant::now();
    let keys = nodes.each_ref().map(|node| AggregateKey {
        group: "score".to_owned(),
        network: SelectionNetwork::Tcp,
        family: None,
        node_id: node.id,
    });
    for (leaf, latency) in nodes.iter().zip([50, 200]) {
        train_at(&manager, leaf, &context, 8, latency, 1, now);
    }
    let now = now + Duration::from_secs(1);
    assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);
    assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .ordinary_switch,
        0
    );

    let now = now + PERFORMANCE_MAX_AGE;
    for (leaf, latency) in nodes.iter().zip([200, 50]) {
        train_at(&manager, leaf, &context, 8, latency, 1, now);
    }
    // The later trial needs the selection ahead of its challenger's evidence.
    train_at(&manager, &nodes[1], &context, 1, 50, 1, now);
    let now = now + Duration::from_secs(1);
    let before_peek = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(state.peek_rank_at("score", &context, &node_refs, now), 1);
    assert_eq!(
        state.selection_reason_counts("score", SelectionNetwork::Tcp),
        before_peek
    );
    assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);
    assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .ordinary_switch,
        1
    );

    for _ in 0..4 * SCORE_EXPLORATION_PERIOD {
        manager
            .feedback_for_group_node("score", nodes[1].id, context.clone())
            .unwrap()
            .business()
            .begin_at(now)
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::Cancelled, false, now);
    }
    let expired = now + PERFORMANCE_MAX_AGE + Duration::from_secs(1);
    let (index, feedback) = state.rank_plan_at("score", &context, &node_refs, expired);
    assert_eq!(index, 0);
    feedback
        .begin_at(expired)
        .unwrap()
        .start_at(expired)
        .finish_at(ScoreOutcome::Cancelled, false, expired);
    let trial = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .trial_starts,
        1
    );
    assert_eq!(trial.ordinary_switch, 1);
    assert_eq!(
        state.peek_rank_at("score", &context, &node_refs, expired),
        1
    );
    for (leaf, latency) in nodes.iter().zip([50, 200]) {
        train_at(&manager, leaf, &context, 8, latency, 1, expired);
    }
    let expired = expired + Duration::from_secs(1);
    assert_eq!(state.rank_at("score", &context, &node_refs, expired), 0);
    let switched = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(switched.ordinary_switch, 2);
    assert_eq!(switched.switch_flap, 1);

    {
        let mut inner = state.inner.lock();
        inner.aggregate.get_mut(&keys[0]).unwrap().fail_streak = SCORE_FAIL_STREAK_EXCLUDE;
        let counts = inner
            .selection_reasons
            .get_mut(&SelectionReasonKey::new("score", SelectionNetwork::Tcp))
            .unwrap();
        counts.ordinary_switch = u64::MAX;
    }
    assert_eq!(state.rank_at("score", &context, &node_refs, expired), 1);
    let saturated = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(saturated.ordinary_switch, u64::MAX);
    assert_eq!(saturated.incumbent_ineligible, 1);
    assert_eq!(saturated.fresh_failure_bypass, 0);
    {
        let mut inner = state.inner.lock();
        inner.aggregate.get_mut(&keys[0]).unwrap().fail_streak = 0;
        inner.aggregate.get_mut(&keys[1]).unwrap().fail_streak = SCORE_FAIL_STREAK_EXCLUDE;
        inner
            .selection_reasons
            .get_mut(&SelectionReasonKey::new("score", SelectionNetwork::Tcp))
            .unwrap()
            .incumbent_ineligible = u64::MAX;
    }
    assert_eq!(state.rank_at("score", &context, &node_refs, expired), 0);
    let saturated = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(saturated.incumbent_ineligible, u64::MAX);
    assert_eq!(saturated.ordinary_switch, u64::MAX);
}

#[test]
fn score_reload_prunes_removed_switch_history_members() {
    let state = ScorePolicyState::default();
    let first = node("first").id;
    let second = node("second").id;
    state.publish_membership([("score".to_owned(), first), ("score".to_owned(), second)]);
    let removed_key = SelectionHistoryKey::new("score", &context("removed.example", IpVersion::V4));
    let retained_key =
        SelectionHistoryKey::new("score", &context("retained.example", IpVersion::V6));
    {
        let mut inner = state.inner.lock();
        inner.selection_history.push(
            removed_key.clone(),
            SelectionHistory {
                current: first,
                previous: Some(second),
                selections: 1,
                switched_at: 1,
            },
        );
        inner.selection_history.push(
            retained_key.clone(),
            SelectionHistory {
                current: second,
                previous: Some(first),
                selections: 1,
                switched_at: 1,
            },
        );
    }

    state.publish_membership([("score".to_owned(), second)]);

    let inner = state.inner.lock();
    assert!(!inner.selection_history.contains(&removed_key));
    assert_eq!(
        inner
            .selection_history
            .peek(&retained_key)
            .unwrap()
            .previous,
        None
    );
}

#[test]
fn selection_reason_precedence_is_stable() {
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let traffic = super::context("precedence.example", IpVersion::V4);
    let now = Instant::now();
    let cold = [node("cold-a"), node("cold-b")];
    let periodic: Vec<_> = (0..8)
        .map(|index| node(&format!("periodic-{index}")))
        .collect();
    let held = [node("held-a"), node("held-b")];
    let bypass = [node("bypass-a"), node("bypass-b")];
    let reliable = [node("reliable-a"), node("reliable-b")];
    let performance = [node("performance-a"), node("performance-b")];
    let memberships = [
        ("cold", cold.as_slice()),
        ("periodic", periodic.as_slice()),
        ("held", held.as_slice()),
        ("bypass", bypass.as_slice()),
        ("reliable", reliable.as_slice()),
        ("performance", performance.as_slice()),
    ];
    let all_nodes: Vec<_> = memberships
        .iter()
        .flat_map(|(_, nodes)| nodes.iter().cloned())
        .collect();
    let groups: Vec<_> = memberships
        .iter()
        .map(|(name, nodes)| group(name, nodes))
        .collect();
    let manager = GroupManager::new(&groups, &all_nodes);
    let state = manager.score_state();
    {
        let mut inner = state.inner.lock();
        // Trials only go to challengers with less evidence than the selection.
        for (index, node) in periodic.iter().enumerate() {
            inner.aggregate.put(
                AggregateKey {
                    group: "periodic".into(),
                    network: SelectionNetwork::Tcp,
                    family: None,
                    node_id: node.id,
                },
                Stats {
                    selected_at: u64::from(index == 0),
                    availability: Availability::default(),
                    ..trained_stats(if index == 0 { 9.0 } else { 8.0 }, 100.0, now)
                },
            );
        }
        inner.aggregate.put(
            AggregateKey {
                group: "cold".into(),
                network: SelectionNetwork::Tcp,
                family: None,
                node_id: cold[0].id,
            },
            trained_stats(1.0, 100.0, now),
        );
    }
    for _ in 0..exploration_target(periodic.len()) {
        let (_, feedback) = state.rank_plan_at(
            "periodic",
            &traffic,
            &periodic.iter().collect::<Vec<_>>(),
            now,
        );
        feedback.begin_at(now).unwrap().start_at(now).finish_at(
            ScoreOutcome::Cancelled,
            false,
            now,
        );
    }
    for _ in 0..SCORE_EXPLORATION_PERIOD {
        manager
            .feedback_for_group_node("periodic", periodic[0].id, traffic.clone())
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::Cancelled, false, now);
    }
    {
        let mut inner = state.inner.lock();
        inner
            .selection_reasons
            .remove(&SelectionReasonKey::new("periodic", SelectionNetwork::Tcp));
        for (group, nodes, stats) in [
            (
                "held",
                held.as_slice(),
                [
                    Stats {
                        selected_at: 1,
                        ..trained_stats(8.0, 100.0, now)
                    },
                    trained_stats(8.0, 99.0, now),
                ],
            ),
            (
                "bypass",
                bypass.as_slice(),
                [
                    Stats {
                        useful_failure: 1.0,
                        failed_at: Some(now),
                        fail_streak: 1,
                        selected_at: 1,
                        ..trained_stats(256.0, 100.0, now)
                    },
                    trained_stats(256.0, 100.0, now),
                ],
            ),
            (
                "reliable",
                reliable.as_slice(),
                [
                    trained_stats(8.0, 100.0, now),
                    Stats {
                        useful_failure: 4.0,
                        ..trained_stats(4.0, 50.0, now)
                    },
                ],
            ),
            (
                "performance",
                performance.as_slice(),
                [
                    trained_stats(8.0, 200.0, now),
                    trained_stats(8.0, 50.0, now),
                ],
            ),
        ] {
            for (node, stats) in nodes.iter().zip(stats) {
                inner.aggregate.put(
                    AggregateKey {
                        group: group.into(),
                        network: SelectionNetwork::Tcp,
                        family: None,
                        node_id: node.id,
                    },
                    stats,
                );
            }
        }
        for (group, node) in [("held", &held[0]), ("bypass", &bypass[0])] {
            ScorePolicyState::record_switch_flap(
                &mut inner,
                &SelectionHistoryKey::new(group, &context),
                node.id,
                SelectionReason::PerformanceWinner,
            );
        }
    }
    for (leaf, latency) in held.iter().zip([100, 99]).rev() {
        for _ in 0..8 {
            let reporter = manager
                .feedback_for_group_node("held", leaf.id, traffic.clone())
                .unwrap()
                .start_at(now);
            reporter.setup_succeeded_at(now);
            reporter.first_response_at(now + Duration::from_millis(latency));
            reporter.transfer_at(1, 1, now + Duration::from_secs(1));
            reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(1));
        }
    }
    let now = now + Duration::from_secs(1);

    let winners = [
        (
            "cold",
            state.rank_at("cold", &traffic, &cold.iter().collect::<Vec<_>>(), now),
        ),
        (
            "periodic",
            state.rank_at(
                "periodic",
                &traffic,
                &periodic.iter().collect::<Vec<_>>(),
                now,
            ),
        ),
        (
            "held",
            state.rank_at("held", &context, &held.iter().collect::<Vec<_>>(), now),
        ),
        (
            "bypass",
            state.rank_at("bypass", &context, &bypass.iter().collect::<Vec<_>>(), now),
        ),
        (
            "reliable",
            state.rank_at(
                "reliable",
                &context,
                &reliable.iter().collect::<Vec<_>>(),
                now,
            ),
        ),
        (
            "performance",
            state.rank_at(
                "performance",
                &context,
                &performance.iter().collect::<Vec<_>>(),
                now,
            ),
        ),
    ];
    assert_eq!(
        winners.map(|(group, index)| (group, index == 0)),
        [
            ("cold", false),
            ("periodic", false),
            ("held", true),
            ("bypass", false),
            ("reliable", true),
            ("performance", false)
        ]
    );

    let expected = [
        (
            "cold",
            ScoreReasonCounters {
                cold_explore: 1,
                ..Default::default()
            },
        ),
        (
            "periodic",
            ScoreReasonCounters {
                periodic_explore: 1,
                ..Default::default()
            },
        ),
        (
            "held",
            ScoreReasonCounters {
                incumbent_held: 1,
                ..Default::default()
            },
        ),
        (
            "bypass",
            ScoreReasonCounters {
                fresh_failure_bypass: 1,
                ordinary_switch: 1,
                ..Default::default()
            },
        ),
        (
            "reliable",
            ScoreReasonCounters {
                reliability_winner: 1,
                ..Default::default()
            },
        ),
        (
            "performance",
            ScoreReasonCounters {
                performance_winner: 1,
                ..Default::default()
            },
        ),
    ];
    for (group, counts) in expected {
        assert_eq!(
            state.selection_reason_counts(group, SelectionNetwork::Tcp),
            counts
        );
    }
}

#[test]
fn selection_reason_counting_respects_apply_and_filter_boundaries() {
    let dead = node("dead");
    let live = [node("live-a"), node("live-b")];
    let all_nodes = [dead.clone(), live[0].clone(), live[1].clone()];
    let alive = Arc::new(super::super::super::AliveDialerSet::new());
    alive.report_unavailable_forced(dead.id, ProbeDomain::Tcp, IpVersion::V4);
    let groups = [
        selector_with_children("dead-path", std::slice::from_ref(&dead), &[]),
        group_with_children("target-top", &all_nodes, &["dead-path"]),
        group("target-child", &all_nodes),
        selector_with_children("target-parent", &[], &["target-child"]),
        group("aggregate-top", &all_nodes),
        group("aggregate-child", &all_nodes),
        selector_with_children("aggregate-parent", &[], &["aggregate-child"]),
        group("singleton", std::slice::from_ref(&live[0])),
        group("last-resort", std::slice::from_ref(&dead)),
    ];
    let manager = super::super::super::GroupManager::with_alive_set(
        &groups,
        &all_nodes,
        Some(Arc::clone(&alive)),
    );
    let target = context("boundaries.example", IpVersion::V4);

    let _ = manager.selection_plan_for_target("target-top", &target);
    let _ = manager.selection_plan_for_target("target-parent", &target);
    let _ = manager.selection_plan_for_domain("aggregate-top", ProbeDomain::Tcp, IpVersion::V4);
    let _ = manager.selection_plan_for_domain("aggregate-parent", ProbeDomain::Tcp, IpVersion::V4);
    let mut udp_target = target.clone();
    udp_target.network = SelectionNetwork::Udp;
    udp_target.probe_domain = ProbeDomain::DataUdp;
    let _ = manager.selection_plan_for_target("target-top", &udp_target);
    let _ =
        manager.selection_plan_for_domain("aggregate-parent", ProbeDomain::DataUdp, IpVersion::V4);
    let _ = manager.selection_plan_for_target("singleton", &target);
    let _ = manager.selection_plan_for_target("last-resort", &target);
    let state = manager.score_state();
    // Unfinished plans leave every group without evidence, so none of them can be explored.
    for group in [
        "target-top",
        "target-child",
        "aggregate-top",
        "aggregate-child",
    ] {
        assert_eq!(
            state.selection_reason_counts(group, SelectionNetwork::Tcp),
            ScoreReasonCounters {
                performance_winner: 1,
                dead_filtered: 1,
                ..Default::default()
            },
            "{group}"
        );
        let budget = manager.score_budget_counters(group, SelectionNetwork::Tcp);
        assert_eq!(
            (
                budget.business_starts,
                budget.trial_starts,
                budget.reserved,
                budget.refunded
            ),
            (0, 0, 0, 0)
        );
    }
    for group in ["target-top", "aggregate-child"] {
        assert_eq!(
            state.selection_reason_counts(group, SelectionNetwork::Udp),
            ScoreReasonCounters {
                performance_winner: 1,
                dead_filtered: 1,
                ..Default::default()
            }
        );
    }
    assert_eq!(
        state.selection_reason_counts("singleton", SelectionNetwork::Tcp),
        ScoreReasonCounters::default()
    );
    assert_eq!(
        state.selection_reason_counts("last-resort", SelectionNetwork::Tcp),
        ScoreReasonCounters {
            dead_filtered: 1,
            ..Default::default()
        }
    );

    let before_peek = state.inner.lock().selection_reasons.clone();
    let _ = manager.get_score_selection_for_network("target-top", SelectionNetwork::Tcp);
    let _ = manager.get_score_selection_for_network("target-parent", SelectionNetwork::Tcp);
    let _ =
        manager.peek_selection_plan_for_domain("aggregate-top", ProbeDomain::Tcp, IpVersion::V4);
    let _ =
        manager.peek_selection_plan_for_domain("aggregate-parent", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(state.inner.lock().selection_reasons, before_peek);
    {
        let inner = state.inner.lock();
        assert!(inner.selection_reasons.len() <= inner.valid_groups.len() * 2);
    }

    let stale_group = group("stale", &all_nodes);
    let stale = super::super::super::GroupManager::with_alive_set(
        std::slice::from_ref(&stale_group),
        &all_nodes,
        Some(Arc::clone(&alive)),
    );
    let stale_state = stale.score_state();
    let deleted = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[],
        &all_nodes,
        Some(Arc::clone(&alive)),
        Arc::clone(&stale_state),
    );
    deleted.publish_score_membership();
    let replacement = super::super::super::GroupManager::with_alive_set_and_score_state(
        std::slice::from_ref(&stale_group),
        &all_nodes,
        Some(alive),
        Arc::clone(&stale_state),
    );
    replacement.publish_score_membership();
    let _ = stale.selection_plan_for_target("stale", &target);
    assert_eq!(
        stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
        ScoreReasonCounters::default()
    );
    let _ = replacement.selection_plan_for_target("stale", &target);
    assert_eq!(
        stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
        ScoreReasonCounters {
            performance_winner: 1,
            dead_filtered: 1,
            ..Default::default()
        }
    );

    let saturated = ScoreReasonCounters {
        cold_explore: u64::MAX,
        periodic_explore: u64::MAX,
        reliability_winner: u64::MAX,
        performance_winner: u64::MAX,
        incumbent_held: u64::MAX,
        fresh_failure_bypass: u64::MAX,
        incumbent_ineligible: u64::MAX,
        insufficient_evidence_held: u64::MAX,
        directional_tradeoff_held: u64::MAX,
        ordinary_switch: u64::MAX,
        dead_filtered: u64::MAX,
        switch_flap: u64::MAX,
        fail_streak_excluded: u64::MAX,
        explore_backed_off: u64::MAX,
        carrier_pressure: u64::MAX,
        carrier_rtt_pressure: u64::MAX,
        carrier_loss_pressure: u64::MAX,
        carrier_validation: u64::MAX,
    };
    stale_state.inner.lock().selection_reasons.insert(
        SelectionReasonKey::new("stale", SelectionNetwork::Tcp),
        saturated,
    );
    for reason in [
        SelectionReason::ColdExplore,
        SelectionReason::PeriodicExplore,
        SelectionReason::ReliabilityWinner,
        SelectionReason::PerformanceWinner,
        SelectionReason::IncumbentHeld,
        SelectionReason::InsufficientEvidenceHeld,
        SelectionReason::DirectionalTradeoffHeld,
        SelectionReason::IncumbentIneligible,
        SelectionReason::FreshFailureBypass,
    ] {
        ScorePolicyState::record_selection_reason(
            &mut stale_state.inner.lock(),
            "stale",
            SelectionNetwork::Tcp,
            RankedSelection { index: 0, reason },
        );
    }
    let _ = replacement.selection_plan_for_target("stale", &target);
    assert_eq!(
        stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
        saturated
    );
    {
        let inner = stale_state.inner.lock();
        assert!(inner.selection_reasons.len() <= inner.valid_groups.len() * 2);
    }
}

#[test]
fn nested_score_groups_count_reasons_independently() {
    let nodes = [node("parent-direct"), node("child-a"), node("child-b")];
    let child = group("child", &nodes[1..]);
    let parent = group_with_children("parent", std::slice::from_ref(&nodes[0]), &["child"]);
    let manager = super::super::super::GroupManager::new(&[child, parent], &nodes);
    let target = context("nested-reasons.example", IpVersion::V4);

    let selected = manager.selection_plan_for_target("parent", &target).entries[0]
        .node
        .id;
    let state = manager.score_state();
    let child_counts = state.selection_reason_counts("child", SelectionNetwork::Tcp);
    let parent_counts = state.selection_reason_counts("parent", SelectionNetwork::Tcp);
    assert_eq!(selected, nodes[0].id);
    assert_eq!(child_counts.performance_winner, 1);
    assert_eq!(parent_counts.performance_winner, 1);
    assert_eq!(child_counts.dead_filtered, 0);
    assert_eq!(parent_counts.dead_filtered, 0);
}

#[test]
fn private_reason_counts_follow_committed_name_lifecycle() {
    let nodes = [node("lifecycle-a"), node("lifecycle-b")];
    let score = group("lifecycle", &nodes);
    let manager = super::super::super::GroupManager::new(std::slice::from_ref(&score), &nodes);
    let state = manager.score_state();
    let target = context("private-lifecycle.example", IpVersion::V4);
    let _ = manager.selection_plan_for_target("lifecycle", &target);
    let recorded = state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp);
    assert_eq!(recorded.performance_winner, 1);

    let selector = Group {
        policy: GroupPolicy::Selector,
        ..score.clone()
    };
    let hidden = super::super::super::GroupManager::with_alive_set_and_score_state(
        std::slice::from_ref(&selector),
        &nodes,
        None,
        Arc::clone(&state),
    );
    hidden.publish_score_membership();
    assert_eq!(
        state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp),
        recorded
    );

    let restored = super::super::super::GroupManager::with_alive_set_and_score_state(
        std::slice::from_ref(&score),
        &nodes,
        None,
        Arc::clone(&state),
    );
    restored.publish_score_membership();
    assert_eq!(
        state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp),
        recorded
    );

    let deleted = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[],
        &nodes,
        None,
        Arc::clone(&state),
    );
    deleted.publish_score_membership();
    let recreated = super::super::super::GroupManager::with_alive_set_and_score_state(
        std::slice::from_ref(&score),
        &nodes,
        None,
        Arc::clone(&state),
    );
    recreated.publish_score_membership();
    let reset = state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp);
    assert_eq!(reset, ScoreReasonCounters::default());
}

#[test]
fn score_reason_snapshot_is_sorted_fixed_and_private() {
    let nodes = [node("private-node-alpha"), node("private-node-beta")];
    let groups = [
        group("z-score", &nodes),
        Group {
            name: "hidden-selector".into(),
            policy: GroupPolicy::Selector,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        },
        group("a-score", &nodes),
    ];
    let manager = super::super::super::GroupManager::new(&groups, &nodes);
    let mut tcp_target = context("private-target.internal", IpVersion::V4);
    let _ = manager.selection_plan_for_target("z-score", &tcp_target);
    tcp_target.network = SelectionNetwork::Udp;
    tcp_target.probe_domain = ProbeDomain::DataUdp;
    let _ = manager.selection_plan_for_target("a-score", &tcp_target);

    let state = manager.score_state();
    let before_read = state.inner.lock().selection_reasons.clone();
    let snapshot = manager.score_reason_snapshot();
    assert_eq!(state.inner.lock().selection_reasons, before_read);
    assert_eq!(
        snapshot
            .iter()
            .map(|group| group.name.as_str())
            .collect::<Vec<_>>(),
        ["a-score", "z-score"]
    );
    assert_eq!(
        snapshot[0].udp,
        ScoreReasonCounters {
            performance_winner: 1,
            ..Default::default()
        }
    );
    assert_eq!(
        snapshot[1].tcp,
        ScoreReasonCounters {
            performance_winner: 1,
            ..Default::default()
        }
    );
    assert_eq!(snapshot[0].tcp, ScoreReasonCounters::default());
    assert_eq!(snapshot[1].udp, ScoreReasonCounters::default());

    let ScoreReasonCounters {
        cold_explore: _,
        periodic_explore: _,
        reliability_winner: _,
        performance_winner: _,
        incumbent_held: _,
        fresh_failure_bypass: _,
        incumbent_ineligible: _,
        insufficient_evidence_held: _,
        directional_tradeoff_held: _,
        ordinary_switch: _,
        dead_filtered: _,
        switch_flap: _,
        fail_streak_excluded: _,
        explore_backed_off: _,
        carrier_pressure: _,
        carrier_rtt_pressure: _,
        carrier_loss_pressure: _,
        carrier_validation: _,
    } = snapshot[0].tcp;

    let _ = manager.selection_plan_for_target(
        "z-score",
        &context("private-target.internal", IpVersion::V4),
    );
    let later = manager.score_reason_snapshot();
    assert_eq!(snapshot[1].tcp.performance_winner, 1);
    assert_eq!(later[1].tcp.performance_winner, 2);
}

#[test]
fn score_reason_snapshot_reload_policy_is_name_based() {
    let nodes = [node("private-reload-alpha"), node("private-reload-beta")];
    let score = group("persist", &nodes);
    let manager = super::super::super::GroupManager::new(std::slice::from_ref(&score), &nodes);
    let state = manager.score_state();
    let target = context("private-reload-target.internal", IpVersion::V4);
    let _ = manager.selection_plan_for_target("persist", &target);
    let recorded = manager.score_reason_snapshot();
    assert_eq!(recorded[0].tcp.performance_winner, 1);

    let selector = Group {
        policy: GroupPolicy::Selector,
        ..score.clone()
    };
    let hidden = super::super::super::GroupManager::with_alive_set_and_score_state(
        std::slice::from_ref(&selector),
        &nodes,
        None,
        Arc::clone(&state),
    );
    hidden.publish_score_membership();
    assert!(hidden.score_reason_snapshot().is_empty());
    let _ = manager.selection_plan_for_target("persist", &target);
    assert_eq!(
        state.selection_reason_counts("persist", SelectionNetwork::Tcp),
        ScoreReasonCounters {
            performance_winner: 1,
            ..Default::default()
        }
    );

    let empty_score = group("persist", &[]);
    let restored = super::super::super::GroupManager::with_alive_set_and_score_state(
        std::slice::from_ref(&empty_score),
        &nodes,
        None,
        Arc::clone(&state),
    );
    restored.publish_score_membership();
    assert_eq!(restored.score_reason_snapshot(), recorded);

    let deleted = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[],
        &nodes,
        None,
        Arc::clone(&state),
    );
    deleted.publish_score_membership();
    let recreated = super::super::super::GroupManager::with_alive_set_and_score_state(
        std::slice::from_ref(&score),
        &nodes,
        None,
        Arc::clone(&state),
    );
    recreated.publish_score_membership();
    let reset = recreated.score_reason_snapshot();
    assert_eq!(reset[0].tcp, ScoreReasonCounters::default());
    let _ = manager.selection_plan_for_target("persist", &target);
    assert_eq!(recreated.score_reason_snapshot(), reset);
    let _ = recreated.selection_plan_for_target("persist", &target);
    let current = recreated.score_reason_snapshot();
    assert_eq!(current[0].tcp.performance_winner, 1);

    let empty = super::super::super::GroupManager::new(&[], &nodes);
    assert!(empty.score_reason_snapshot().is_empty());
}
