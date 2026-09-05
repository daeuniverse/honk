use super::evidence::inner_update_response;
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

    println!(
        "winner baseline apply={apply} peek={peek} singleton={singleton_selected} last_resort={last_resort_selected}"
    );
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
fn applied_score_selection_records_switch_flap() {
    let nodes = [node("first"), node("second")];
    let node_refs = [&nodes[0], &nodes[1]];
    let state = ScorePolicyState::default();
    state.publish_membership(nodes.iter().map(|node| ("score".to_owned(), node.id)));
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    let keys = nodes.each_ref().map(|node| AggregateKey {
        group: "score".to_owned(),
        network: SelectionNetwork::Tcp,
        family: None,
        node_id: node.id,
    });
    {
        let mut inner = state.inner.lock();
        inner
            .aggregate
            .put(keys[0].clone(), trained_stats(8.0, 50.0, now));
        inner
            .aggregate
            .put(keys[1].clone(), trained_stats(8.0, 200.0, now));
    }
    assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);

    inner_update_response(&state, keys[0].clone(), 200.0);
    inner_update_response(&state, keys[1].clone(), 50.0);
    assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);

    inner_update_response(&state, keys[0].clone(), 50.0);
    inner_update_response(&state, keys[1].clone(), 200.0);
    assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .switch_flap,
        1
    );
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
    let state = ScorePolicyState::default();
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
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
    state.publish_membership(
        memberships
            .iter()
            .flat_map(|(group, nodes)| nodes.iter().map(|node| ((*group).to_owned(), node.id))),
    );
    {
        let mut inner = state.inner.lock();
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
                    ..trained_stats(8.0, 100.0, now)
                },
            );
        }
        inner.selection_counts.insert(
            SelectionCadenceKey::new("periodic", &context),
            exploration_period(periodic.len()) - 1,
        );
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
                        attempts: 257.0,
                        useful_failure: 1.0,
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
                        attempts: 8.0,
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
    }

    let winners = [
        (
            "cold",
            state.rank_at("cold", &context, &cold.iter().collect::<Vec<_>>(), now),
        ),
        (
            "periodic",
            state.rank_at(
                "periodic",
                &context,
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
        winners,
        [
            ("cold", 0),
            ("periodic", 1),
            ("held", 0),
            ("bypass", 1),
            ("reliable", 0),
            ("performance", 1)
        ]
    );

    let expected = [
        (
            "cold",
            SelectionReasonCounts {
                cold_explore: 1,
                ..Default::default()
            },
        ),
        (
            "periodic",
            SelectionReasonCounts {
                periodic_explore: 1,
                ..Default::default()
            },
        ),
        (
            "held",
            SelectionReasonCounts {
                incumbent_held: 1,
                ..Default::default()
            },
        ),
        (
            "bypass",
            SelectionReasonCounts {
                fresh_failure_bypass: 1,
                ..Default::default()
            },
        ),
        (
            "reliable",
            SelectionReasonCounts {
                reliability_winner: 1,
                ..Default::default()
            },
        ),
        (
            "performance",
            SelectionReasonCounts {
                performance_winner: 1,
                ..Default::default()
            },
        ),
    ];
    println!("winner table={winners:?}");
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
    let applied = [
        ("target-top", 1, 1),
        ("target-child", 1, 1),
        ("aggregate-top", 1, 1),
        ("aggregate-child", 1, 1),
    ];
    for (group, cold_explore, dead_filtered) in applied {
        let counts = state.selection_reason_counts(group, SelectionNetwork::Tcp);
        assert_eq!(counts.cold_explore, cold_explore, "{group} cold_explore");
        assert_eq!(counts.dead_filtered, dead_filtered, "{group} dead_filtered");
        assert_eq!(
            counts.periodic_explore
                + counts.reliability_winner
                + counts.performance_winner
                + counts.incumbent_held
                + counts.fresh_failure_bypass,
            0
        );
    }
    for group in ["target-top", "aggregate-child"] {
        assert_eq!(
            state.selection_reason_counts(group, SelectionNetwork::Udp),
            SelectionReasonCounts {
                cold_explore: 1,
                dead_filtered: 1,
                ..Default::default()
            }
        );
    }
    assert_eq!(
        state.selection_reason_counts("singleton", SelectionNetwork::Tcp),
        SelectionReasonCounts::default()
    );
    assert_eq!(
        state.selection_reason_counts("last-resort", SelectionNetwork::Tcp),
        SelectionReasonCounts {
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
        SelectionReasonCounts::default()
    );
    let _ = replacement.selection_plan_for_target("stale", &target);
    assert_eq!(
        stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
        SelectionReasonCounts {
            cold_explore: 1,
            dead_filtered: 1,
            ..Default::default()
        }
    );

    let saturated = SelectionReasonCounts {
        cold_explore: u64::MAX,
        periodic_explore: u64::MAX,
        reliability_winner: u64::MAX,
        performance_winner: u64::MAX,
        incumbent_held: u64::MAX,
        fresh_failure_bypass: u64::MAX,
        dead_filtered: u64::MAX,
        switch_flap: u64::MAX,
        fail_streak_excluded: u64::MAX,
        explore_backed_off: u64::MAX,
    };
    stale_state.inner.lock().selection_reasons.insert(
        SelectionReasonKey::new("stale", SelectionNetwork::Tcp),
        saturated,
    );
    let _ = replacement.selection_plan_for_target("stale", &target);
    assert_eq!(
        stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
        saturated
    );
    {
        let inner = stale_state.inner.lock();
        assert!(inner.selection_reasons.len() <= inner.valid_groups.len() * 2);
    }
    println!(
        "counter table target-top-tcp={:?} target-top-udp={:?} target-child-tcp={:?} aggregate-top-tcp={:?} aggregate-child-tcp={:?} aggregate-child-udp={:?} singleton={:?} last-resort={:?} stale={:?}",
        state.selection_reason_counts("target-top", SelectionNetwork::Tcp),
        state.selection_reason_counts("target-top", SelectionNetwork::Udp),
        state.selection_reason_counts("target-child", SelectionNetwork::Tcp),
        state.selection_reason_counts("aggregate-top", SelectionNetwork::Tcp),
        state.selection_reason_counts("aggregate-child", SelectionNetwork::Tcp),
        state.selection_reason_counts("aggregate-child", SelectionNetwork::Udp),
        state.selection_reason_counts("singleton", SelectionNetwork::Tcp),
        state.selection_reason_counts("last-resort", SelectionNetwork::Tcp),
        stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
    );
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
    println!("nested winner={selected} child={child_counts:?} parent={parent_counts:?}");
    assert_eq!(selected, nodes[0].id);
    assert_eq!(child_counts.cold_explore, 1);
    assert_eq!(parent_counts.cold_explore, 1);
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
    assert_eq!(recorded.cold_explore, 1);

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
    println!(
        "private lifecycle recorded={recorded:?} hidden={recorded:?} restored={recorded:?} recreated={reset:?}"
    );
    assert_eq!(reset, SelectionReasonCounts::default());
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
            cold_explore: 1,
            ..Default::default()
        }
    );
    assert_eq!(
        snapshot[1].tcp,
        ScoreReasonCounters {
            cold_explore: 1,
            ..Default::default()
        }
    );
    assert_eq!(snapshot[0].tcp, ScoreReasonCounters::default());
    assert_eq!(snapshot[1].udp, ScoreReasonCounters::default());

    let debug = format!("{snapshot:?}");
    assert!(!debug.contains("private-node-alpha"));
    assert!(!debug.contains("private-node-beta"));
    assert!(!debug.contains("private-target.internal"));
    let ScoreReasonCounters {
        cold_explore: _,
        periodic_explore: _,
        reliability_winner: _,
        performance_winner: _,
        incumbent_held: _,
        fresh_failure_bypass: _,
        dead_filtered: _,
        switch_flap: _,
        fail_streak_excluded: _,
        explore_backed_off: _,
    } = snapshot[0].tcp;

    let _ = manager.selection_plan_for_target(
        "z-score",
        &context("private-target.internal", IpVersion::V4),
    );
    let later = manager.score_reason_snapshot();
    assert_eq!(snapshot[1].tcp.cold_explore, 1);
    assert_eq!(later[1].tcp.cold_explore, 2);

    let saturated = SelectionReasonCounts {
        cold_explore: u64::MAX,
        periodic_explore: u64::MAX,
        reliability_winner: u64::MAX,
        performance_winner: u64::MAX,
        incumbent_held: u64::MAX,
        fresh_failure_bypass: u64::MAX,
        dead_filtered: u64::MAX,
        switch_flap: u64::MAX,
        fail_streak_excluded: u64::MAX,
        explore_backed_off: u64::MAX,
    };
    state.inner.lock().selection_reasons.insert(
        SelectionReasonKey::new("z-score", SelectionNetwork::Udp),
        saturated,
    );
    let saturated_snapshot = manager.score_reason_snapshot();
    assert_eq!(
        saturated_snapshot[1].udp,
        ScoreReasonCounters::from_private(saturated)
    );
    println!("owned score snapshot={snapshot:?} later={later:?} saturated={saturated_snapshot:?}");
}

#[test]
fn delay_test_members_do_not_record_score_selection() {
    let nodes = [node("delay-peek-alpha"), node("delay-peek-beta")];
    let sub = group("delay-peek-sub", &nodes);
    let parent = Group {
        id: Uuid::new_v4(),
        name: "delay-peek-parent".into(),
        policy: GroupPolicy::Selector,
        nodes: vec![],
        groups: vec!["delay-peek-sub".into()],
        ..Default::default()
    };
    let manager = super::super::super::GroupManager::new(&[parent, sub], &nodes);

    let members = manager.delay_test_members("delay-peek-parent");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].0, "delay-peek-sub");

    let state = manager.score_state();
    assert_eq!(
        state.selection_reason_counts("delay-peek-sub", SelectionNetwork::Tcp),
        SelectionReasonCounts::default()
    );
    assert!(state.inner.lock().selection_history.is_empty());
}

#[test]
fn selector_parent_peeks_unchosen_score_subgroups() {
    let nodes = [
        node("sel-sub-alpha-a"),
        node("sel-sub-alpha-b"),
        node("sel-sub-beta-a"),
        node("sel-sub-beta-b"),
    ];
    let sub_a = group("sel-sub-a", &nodes[..2]);
    let sub_b = group("sel-sub-b", &nodes[2..]);
    let parent = Group {
        id: Uuid::new_v4(),
        name: "sel-parent".into(),
        policy: GroupPolicy::Selector,
        nodes: vec![],
        groups: vec!["sel-sub-a".into(), "sel-sub-b".into()],
        ..Default::default()
    };
    let manager = super::super::super::GroupManager::new(&[sub_a, sub_b, parent], &nodes);
    let state = manager.score_state();

    // Default choice is the first member: only sub-a commits a rank.
    let _ = manager.selection_plan_for_domain("sel-parent", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        state
            .selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp)
            .cold_explore,
        1
    );
    assert_eq!(
        state.selection_reason_counts("sel-sub-b", SelectionNetwork::Tcp),
        SelectionReasonCounts::default()
    );
    assert!(state.inner.lock().selection_history.is_empty());

    // Switching the choice moves the committed rank to sub-b.
    manager.set_selector_choice("sel-parent", "sel-sub-b");
    let _ = manager.selection_plan_for_domain("sel-parent", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        state
            .selection_reason_counts("sel-sub-b", SelectionNetwork::Tcp)
            .cold_explore,
        1
    );
    assert_eq!(
        state
            .selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp)
            .cold_explore,
        1
    );

    // The target-aware dial path applies the same rule.
    manager.set_selector_choice("sel-parent", "sel-sub-a");
    let before_a = state.selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp);
    let before_b = state.selection_reason_counts("sel-sub-b", SelectionNetwork::Tcp);
    let _ = manager
        .selection_plan_for_target("sel-parent", &context("sel-target.internal", IpVersion::V4));
    assert_ne!(
        state.selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp),
        before_a
    );
    assert_eq!(
        state.selection_reason_counts("sel-sub-b", SelectionNetwork::Tcp),
        before_b
    );

    // A stale stored choice names no member: the fallback serving
    // sub-group still commits its rank instead of everything peeking.
    manager.set_selector_choice("sel-parent", "sel-sub-renamed-away");
    let before_a = state.selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp);
    let _ = manager.selection_plan_for_domain("sel-parent", ProbeDomain::Tcp, IpVersion::V4);
    assert_ne!(
        state.selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp),
        before_a
    );
}

#[test]
fn selector_commit_follows_non_first_default() {
    let nodes = [
        node("def-alpha-a"),
        node("def-alpha-b"),
        node("def-beta-a"),
        node("def-beta-b"),
    ];
    let sub_a = group("def-sub-a", &nodes[..2]);
    let sub_b = group("def-sub-b", &nodes[2..]);
    let mut parent = selector_with_children("def-parent", &[], &["def-sub-a", "def-sub-b"]);
    parent.default = Some("def-sub-b".into());
    let manager = super::super::super::GroupManager::new(&[sub_a, sub_b, parent], &nodes);
    let state = manager.score_state();

    // No stored choice: the default (non-first) member serves and must
    // be the one committing its rank.
    let _ = manager.selection_plan_for_domain("def-parent", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        state
            .selection_reason_counts("def-sub-b", SelectionNetwork::Tcp)
            .cold_explore,
        1
    );
    assert_eq!(
        state.selection_reason_counts("def-sub-a", SelectionNetwork::Tcp),
        SelectionReasonCounts::default()
    );
}

#[test]
fn selector_commit_follows_alive_fallback() {
    let dead = node("fallback-dead");
    let nodes = [dead.clone(), node("fallback-alpha"), node("fallback-beta")];
    let sub = group("fallback-sub", &nodes[1..]);
    let parent = Group {
        id: Uuid::new_v4(),
        name: "fallback-parent".into(),
        policy: GroupPolicy::Selector,
        nodes: vec![dead.id],
        groups: vec!["fallback-sub".into()],
        ..Default::default()
    };
    let alive = Arc::new(super::super::super::AliveDialerSet::new());
    alive.report_unavailable_forced(dead.id, ProbeDomain::Tcp, IpVersion::V4);
    let manager =
        super::super::super::GroupManager::with_alive_set(&[sub, parent], &nodes, Some(alive));
    let state = manager.score_state();

    // The chosen direct member is dead; the fallback serving sub-group
    // must be the one committing its rank.
    manager.set_selector_choice("fallback-parent", "fallback-dead");
    let _ = manager.selection_plan_for_domain("fallback-parent", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        state
            .selection_reason_counts("fallback-sub", SelectionNetwork::Tcp)
            .cold_explore,
        1
    );
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
    assert_eq!(recorded[0].tcp.cold_explore, 1);

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
        SelectionReasonCounts {
            cold_explore: 1,
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
    assert_eq!(current[0].tcp.cold_explore, 1);

    let empty = super::super::super::GroupManager::new(&[], &nodes);
    assert!(empty.score_reason_snapshot().is_empty());
    println!(
        "snapshot lifecycle recorded={recorded:?} hidden=[] restored={recorded:?} recreated={reset:?} current={current:?}"
    );
}
