use super::*;
#[test]
fn normalizes_domain_key_and_keeps_target_dimensions_independent() {
    let nodes = [node("a"), node("b")];
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);

    let a = context("EXAMPLE.COM.", IpVersion::V4);
    finish_success(&manager.selection_plan_for_target("score", &a));
    let normalized = context("example.com", IpVersion::V4);
    assert!(
        manager
            .score_state()
            .has_exact("score", &normalized, nodes[0].id)
    );
    assert!(!manager.score_state().has_exact(
        "score",
        &context("example.com", IpVersion::V6),
        nodes[0].id,
    ));
    assert!(!manager.score_state().has_exact(
        "score",
        &context("other.example", IpVersion::V4),
        nodes[0].id,
    ));
}

#[test]
fn cold_exploration_is_deterministic_and_cancelled_loser_is_neutral() {
    let nodes = [node("a"), node("b")];
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let context = context("example.com", IpVersion::V4);
    let first = manager.selection_plan_for_target("score", &context);
    assert_eq!(first.entries[0].node.id, nodes[0].id);
    drop(first.entries[0].feedback.as_ref().unwrap().start());
    assert_eq!(
        manager.selection_plan_for_target("score", &context).entries[0]
            .node
            .id,
        nodes[0].id
    );
    finish_success(&manager.selection_plan_for_target("score", &context));
    assert_eq!(
        manager.selection_plan_for_target("score", &context).entries[0]
            .node
            .id,
        nodes[1].id,
        "the first useful success must release the next cold candidate"
    );
}

#[test]
fn cancelled_exact_attempt_does_not_hide_aggregate_failure() {
    let nodes = [node("a"), node("b")];
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    manager
        .feedback_for_group_node(
            "score",
            nodes[0].id,
            ScoreSelectionContext::aggregate(
                SelectionNetwork::Tcp,
                ProbeDomain::Tcp,
                IpVersion::V4,
            ),
        )
        .unwrap()
        .start()
        .setup_failed(ScoreOutcome::Timeout);

    let context = context("cancelled.example", IpVersion::V4);
    drop(
        manager
            .feedback_for_group_node("score", nodes[0].id, context.clone())
            .unwrap()
            .start(),
    );

    assert!(
        !manager
            .score_state()
            .has_exact("score", &context, nodes[0].id)
    );
    assert_eq!(selected(&manager, &context), nodes[1].id);
}

#[test]
fn reload_reuses_state_and_prunes_removed_members() {
    let nodes = [node("a"), node("b")];
    let old = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let context = context("example.com", IpVersion::V4);
    finish_success(&old.selection_plan_for_target("score", &context));
    let state = old.score_state();
    let replacement = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes[1..])],
        &nodes[1..],
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    assert!(!state.has_exact("score", &context, nodes[0].id));
}

#[test]
fn nested_score_groups_keep_the_target_and_complete_attribution_path() {
    let nodes = [node("a"), node("b")];
    let child = group("child", &nodes);
    let mut parent = group("parent", &[]);
    parent.groups.push("child".into());
    let manager = super::super::super::GroupManager::new(&[child, parent], &nodes);
    let context = context("example.com", IpVersion::V6);

    let plan = manager.selection_plan_for_target("parent", &context);
    assert_eq!(plan.entries.len(), 1);
    assert_eq!(plan.entries[0].selection_chain, ["parent", "child", "a"]);
    let feedback = plan.entries[0].feedback.as_ref().unwrap();
    assert_eq!(
        feedback
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>(),
        ["parent", "child"]
    );
    finish_success(&plan);
    for group in ["parent", "child"] {
        assert!(
            manager
                .score_state()
                .has_exact(group, &context, nodes[0].id)
        );
    }
}

#[test]
fn feedback_for_node_merges_nested_score_memberships_once() {
    let leaf = node("leaf");
    let other = node("other");
    let child = group("child", std::slice::from_ref(&leaf));
    let mut bridge = group("bridge", std::slice::from_ref(&leaf));
    bridge.policy = GroupPolicy::Selector;
    let mut parent = group("parent", std::slice::from_ref(&leaf));
    parent.groups = vec!["child".into(), "bridge".into()];
    let manager = super::super::super::GroupManager::new(
        &[
            child,
            bridge,
            parent,
            group("unrelated", std::slice::from_ref(&other)),
        ],
        &[leaf.clone(), other],
    );

    let feedback = manager
        .feedback_for_node(
            leaf.id,
            ScoreSelectionContext::aggregate(
                SelectionNetwork::Tcp,
                ProbeDomain::Tcp,
                IpVersion::V4,
            ),
        )
        .expect("nested Honk memberships must produce feedback");
    let mut groups = feedback
        .attributions()
        .iter()
        .map(|attribution| attribution.group.as_str())
        .collect::<Vec<_>>();
    groups.sort_unstable();
    assert_eq!(groups, ["child", "parent"]);
}
#[test]
fn nested_score_last_resort_keeps_child_attribution() {
    let leaf = node("leaf");
    let alive = Arc::new(super::super::super::AliveDialerSet::new());
    alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
    let child = group("child", std::slice::from_ref(&leaf));
    let mut parent = group("parent", &[]);
    parent.groups.push(child.name.clone());
    let manager = super::super::super::GroupManager::with_alive_set(
        &[child, parent],
        std::slice::from_ref(&leaf),
        Some(alive),
    );
    let plan =
        manager.selection_plan_for_target("parent", &context("last-resort.example", IpVersion::V4));
    assert_eq!(plan.entries.len(), 1);
    assert_eq!(
        plan.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>(),
        ["parent", "child"]
    );
}

#[test]
fn deep_score_last_resort_keeps_every_attribution() {
    let leaf = node("leaf");
    let alive = Arc::new(super::super::super::AliveDialerSet::new());
    alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
    let child = group("child", std::slice::from_ref(&leaf));
    let mut middle = group("middle", &[]);
    middle.groups.push(child.name.clone());
    let mut outer = group("outer", &[]);
    outer.groups.push(middle.name.clone());
    let manager = super::super::super::GroupManager::with_alive_set(
        &[child, middle, outer],
        std::slice::from_ref(&leaf),
        Some(alive),
    );

    let plan = manager.selection_plan_for_target("outer", &context("deep.example", IpVersion::V4));
    assert_eq!(
        plan.entries[0].selection_chain,
        ["outer", "middle", "child", "leaf"]
    );
    assert_eq!(
        plan.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>(),
        ["outer", "middle", "child"]
    );
}

#[test]
fn duplicate_direct_leaf_stays_direct_on_last_resort() {
    let leaf = node("leaf");
    let alive = Arc::new(super::super::super::AliveDialerSet::new());
    alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
    let child = group("child", std::slice::from_ref(&leaf));
    let mut parent = group("parent", std::slice::from_ref(&leaf));
    parent.groups.push(child.name.clone());
    let manager = super::super::super::GroupManager::with_alive_set(
        &[child, parent],
        std::slice::from_ref(&leaf),
        Some(alive),
    );

    let plan =
        manager.selection_plan_for_target("parent", &context("last-resort.example", IpVersion::V4));
    assert_eq!(plan.entries[0].selection_chain, ["parent", "leaf"]);
    assert_eq!(
        plan.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>(),
        ["parent"]
    );
}

#[test]
fn duplicate_leaf_paths_do_not_change_score_rank() {
    let nodes = [node("a"), node("b")];
    let mut bridge = group("bridge", std::slice::from_ref(&nodes[0]));
    bridge.policy = GroupPolicy::Selector;
    let mut parent = group("score", &nodes);
    parent.groups.push(bridge.name.clone());
    let manager = super::super::super::GroupManager::new(&[parent, bridge], &nodes);
    let context = context("duplicate.example", IpVersion::V4);
    finish_failure(&manager.selection_plan_for_target("score", &context));
    assert_eq!(selected(&manager, &context), nodes[1].id);
}

#[test]
fn aggregate_feedback_completion_and_cancellation_are_accounted_once() {
    let leaf = node("leaf");
    let manager = super::super::super::GroupManager::new(
        &[group("score", std::slice::from_ref(&leaf))],
        std::slice::from_ref(&leaf),
    );
    let feedback = manager
        .feedback_for_node(
            leaf.id,
            ScoreSelectionContext::aggregate(
                SelectionNetwork::Tcp,
                ProbeDomain::Tcp,
                IpVersion::V4,
            ),
        )
        .unwrap();

    drop(feedback.start());
    assert_eq!(
        manager
            .score_state()
            .aggregate_stats("score", SelectionNetwork::Tcp, leaf.id),
        None
    );
    let reporter = feedback.start();
    reporter.setup_succeeded();
    reporter.finish(ScoreOutcome::Success);
    assert_eq!(
        manager
            .score_state()
            .aggregate_stats("score", SelectionNetwork::Tcp, leaf.id),
        Some((1, 1, 0))
    );
}

#[test]
fn setup_only_success_does_not_become_usefulness_failure() {
    let leaf = node("leaf");
    let manager = super::super::super::GroupManager::new(
        &[group("score", std::slice::from_ref(&leaf))],
        std::slice::from_ref(&leaf),
    );
    let context = context("prepared.example", IpVersion::V4);
    let feedback = manager.selection_plan_for_target("score", &context).entries[0]
        .feedback
        .clone()
        .unwrap();
    let reporter = feedback.start();
    reporter.setup_succeeded();
    reporter.finish_setup_only();
    assert_eq!(
        manager
            .score_state()
            .exact_useful_failures("score", &context, leaf.id),
        Some(0)
    );

    let related = reporter.feedback().start();
    related.setup_succeeded();
    related.finish_setup_only();

    assert_eq!(
        manager
            .score_state()
            .exact_useful_failures("score", &context, leaf.id),
        Some(0)
    );
}

#[test]
fn setup_only_exact_samples_keep_aggregate_reliability() {
    let nodes = [node("a"), node("b")];
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    for index in 0..8 {
        let reporter = manager
            .feedback_for_group_node(
                "score",
                nodes[0].id,
                context(&format!("a-{index}.example"), IpVersion::V4),
            )
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);
    }
    let reporter = manager
        .feedback_for_group_node("score", nodes[1].id, context("b.example", IpVersion::V4))
        .unwrap()
        .start();
    reporter.setup_succeeded();
    reporter.tx(1);
    reporter.rx(1);
    reporter.finish(ScoreOutcome::Success);

    let target = context("prepared.example", IpVersion::V4);
    for _ in 0..8 {
        let reporter = manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.finish_setup_only();
    }

    assert_eq!(selected(&manager, &target), nodes[0].id);
}

#[test]
fn setup_only_family_samples_keep_global_reliability() {
    let nodes = [node("a"), node("b")];
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    for index in 0..8 {
        let reporter = manager
            .feedback_for_group_node(
                "score",
                nodes[0].id,
                context(&format!("a-{index}.example"), IpVersion::V6),
            )
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);
    }
    let reporter = manager
        .feedback_for_group_node("score", nodes[1].id, context("b.example", IpVersion::V6))
        .unwrap()
        .start();
    reporter.setup_succeeded();
    reporter.tx(1);
    reporter.rx(1);
    reporter.finish(ScoreOutcome::Success);

    let reporter = manager
        .feedback_for_group_node(
            "score",
            nodes[0].id,
            context("prepared.example", IpVersion::V4),
        )
        .unwrap()
        .start();
    reporter.setup_succeeded();
    reporter.finish_setup_only();

    assert_eq!(
        selected(&manager, &context("fresh.example", IpVersion::V4)),
        nodes[0].id
    );
}

#[test]
fn compact_outcome_finds_nested_io_errors() {
    let error = anyhow::Error::new(io::Error::new(io::ErrorKind::TimedOut, "secret target"))
        .context("outer context");
    assert_eq!(ScoreOutcome::from_error(&error), ScoreOutcome::Timeout);
}

#[test]
fn exact_cache_has_a_hard_lru_bound() {
    let node = node("a");
    let manager = super::super::super::GroupManager::new(
        &[group("score", std::slice::from_ref(&node))],
        std::slice::from_ref(&node),
    );
    for index in 0..=EXACT_CAPACITY {
        finish_success(&manager.selection_plan_for_target(
            "score",
            &context(&format!("{index}.example"), IpVersion::V4),
        ));
    }
    assert_eq!(manager.score_state().exact_len(), EXACT_CAPACITY);
}

#[test]
fn setup_failure_switches_to_the_other_candidate() {
    let nodes = [node("a"), node("b")];
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let context = context("failure.example", IpVersion::V4);

    assert_eq!(selected(&manager, &context), nodes[0].id);
    finish_failure(&manager.selection_plan_for_target("score", &context));
    assert_eq!(selected(&manager, &context), nodes[1].id);
}

#[test]
fn inflight_exact_attempt_does_not_mask_aggregate_reliability() {
    let nodes = [node("a"), node("b")];
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    manager
        .feedback_for_group_node("score", nodes[0].id, aggregate.clone())
        .unwrap()
        .start()
        .setup_failed(ScoreOutcome::Other);
    let good = manager
        .feedback_for_group_node("score", nodes[1].id, aggregate)
        .unwrap()
        .start();
    good.setup_succeeded();
    good.finish_setup_only();
    let target = context("inflight.example", IpVersion::V4);
    let inflight = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap()
        .start();

    assert_eq!(selected(&manager, &target), nodes[1].id);

    drop(inflight);
}

#[test]
fn network_target_and_family_buckets_are_isolated() {
    let nodes = [node("a"), node("b")];
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let tcp_a_v4 = context("a.example", IpVersion::V4);
    finish_failure(&manager.selection_plan_for_target("score", &tcp_a_v4));

    let mut udp_a_v4 = tcp_a_v4.clone();
    udp_a_v4.network = SelectionNetwork::Udp;
    udp_a_v4.probe_domain = ProbeDomain::DataUdp;
    let tcp_b_v4 = context("b.example", IpVersion::V4);
    let tcp_a_v6 = context("a.example", IpVersion::V6);
    let state = manager.score_state();

    assert_eq!(
        state.exact_stats("score", &tcp_a_v4, nodes[0].id),
        Some((1, 0, 1))
    );
    for untouched in [&udp_a_v4, &tcp_b_v4, &tcp_a_v6] {
        assert_eq!(state.exact_stats("score", untouched, nodes[0].id), None);
    }
    finish_success(&manager.selection_plan_for_target("score", &tcp_b_v4));
    assert_eq!(
        state.exact_stats("score", &tcp_b_v4, nodes[1].id),
        Some((1, 1, 0))
    );
    assert_eq!(state.exact_stats("score", &tcp_a_v4, nodes[1].id), None);
}

#[test]
fn dead_candidate_is_excluded_before_scoring() {
    let nodes = [node("a"), node("b")];
    let alive = Arc::new(super::super::super::AliveDialerSet::new());
    alive.report_unavailable_forced(nodes[0].id, ProbeDomain::Tcp, IpVersion::V4);
    let manager = super::super::super::GroupManager::with_alive_set(
        &[group("score", &nodes)],
        &nodes,
        Some(alive),
    );

    assert_eq!(
        selected(&manager, &context("dead.example", IpVersion::V4)),
        nodes[1].id
    );
}

#[test]
fn aggregate_cache_has_a_hard_lru_bound() {
    let state = ScorePolicyState::default();
    let node_id = node("a").id;
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let memberships: Vec<_> = (0..=AGGREGATE_CAPACITY)
        .map(|index| (format!("group-{index}"), node_id))
        .collect();
    state.publish_membership(memberships.iter().cloned());
    for (group, node_id) in memberships {
        drop(state.start(&context, &[ScoreAttribution { group, node_id }]));
    }
    assert_eq!(state.inner.lock().aggregate.len(), AGGREGATE_CAPACITY);
    assert_eq!(state.inner.lock().aggregate_evictions, 1);
    assert_eq!(state.inner.lock().exact_evictions, 0);
}

#[test]
fn stale_exact_completion_does_not_mutate_recreated_cell() {
    let node = node("a");
    let manager = super::super::super::GroupManager::new(
        &[group("score", std::slice::from_ref(&node))],
        std::slice::from_ref(&node),
    );
    let evicted = context("evicted.example", IpVersion::V4);
    let reporter = manager.selection_plan_for_target("score", &evicted).entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .start();
    for index in 0..EXACT_CAPACITY {
        let context = context(&format!("{index}.example"), IpVersion::V4);
        finish_success(&manager.selection_plan_for_target("score", &context));
    }
    let replacement = manager.selection_plan_for_target("score", &evicted).entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .start();
    reporter.setup_succeeded();
    reporter.tx(1);
    reporter.rx(1);
    reporter.finish(ScoreOutcome::Success);
    assert_eq!(
        manager
            .score_state()
            .exact_stats("score", &evicted, node.id),
        Some((1, 0, 0))
    );
    replacement.setup_succeeded();
    replacement.tx(1);
    replacement.rx(1);
    replacement.finish(ScoreOutcome::Success);
    assert_eq!(
        manager
            .score_state()
            .exact_stats("score", &evicted, node.id),
        Some((1, 1, 0))
    );
}

#[test]
fn stale_aggregate_completion_does_not_mutate_recreated_cell() {
    let state = ScorePolicyState::default();
    let node_id = node("a").id;
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let memberships: Vec<_> = (0..=AGGREGATE_CAPACITY)
        .map(|index| (format!("group-{index}"), node_id))
        .collect();
    state.publish_membership(memberships.iter().cloned());
    let evicted = ScoreAttribution {
        group: memberships[0].0.clone(),
        node_id,
    };
    let stale_cells = state.start(&context, std::slice::from_ref(&evicted));
    for (group, node_id) in memberships.iter().skip(1) {
        drop(state.start(
            &context,
            &[ScoreAttribution {
                group: group.clone(),
                node_id: *node_id,
            }],
        ));
    }
    let current_cells = state.start(&context, std::slice::from_ref(&evicted));
    let sample = FlowSample {
        outcome: ScoreOutcome::Success,
        setup: Some(Duration::ZERO),
        first_response: None,
        tx: 1,
        rx: 1,
        elapsed: Duration::from_millis(1),
        count_usefulness: true,
        streak_neutral: false,
    };
    state.finish(
        &context,
        std::slice::from_ref(&evicted),
        &stale_cells,
        &sample,
    );
    assert_eq!(state.inner.lock().aggregate.len(), AGGREGATE_CAPACITY);
    assert_eq!(
        state.aggregate_stats(&evicted.group, SelectionNetwork::Tcp, node_id),
        Some((1, 0, 0))
    );
    state.finish(
        &context,
        std::slice::from_ref(&evicted),
        &current_cells,
        &sample,
    );
    assert_eq!(
        state.aggregate_stats(&evicted.group, SelectionNetwork::Tcp, node_id),
        Some((1, 1, 0))
    );
}

#[test]
fn builtin_direct_final_is_valid_feedback_membership() {
    let mut outer = group("outer", &[]);
    outer.final_outbound = Some(honk_config::Config::BUILTIN_DIRECT_NODE.into());
    let manager = super::super::super::GroupManager::new(&[outer], &[]);
    let context = context("final-direct.example", IpVersion::V4);
    let feedback = manager
        .feedback_for_group_node(
            "outer",
            honk_config::config::DIRECT_NODE_ID,
            context.clone(),
        )
        .unwrap();
    let reporter = feedback.start();
    reporter.setup_succeeded();
    reporter.tx(1);
    reporter.rx(1);
    reporter.finish(ScoreOutcome::Success);
    assert!(manager.score_state().has_exact(
        "outer",
        &context,
        honk_config::config::DIRECT_NODE_ID
    ));
}

#[test]
fn aggregate_display_does_not_advance_nested_load_balance() {
    let nodes = [node("a"), node("b")];
    let mut child = group("child", &nodes);
    child.policy = GroupPolicy::LoadBalance;
    let mut parent = group("parent", &[]);
    parent.groups.push(child.name.clone());
    let manager = super::super::super::GroupManager::new(&[parent, child], &nodes);

    assert_eq!(
        manager.get_score_selection_for_network("parent", SelectionNetwork::Tcp),
        Some("child".into())
    );
    assert_eq!(manager.select_node("child").unwrap().id, nodes[0].id);
}

#[test]
fn late_completion_keeps_extant_member_and_drops_deleted_member() {
    let nodes = [node("a"), node("b")];
    let old = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let context = context("reload.example", IpVersion::V4);
    let reporter_a = old.selection_plan_for_target("score", &context).entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .start();
    finish_success(&old.selection_plan_for_target("score", &context));
    let reporter_b = old.selection_plan_for_target("score", &context).entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .start();
    let state = old.score_state();
    let replacement = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes[..1])],
        &nodes[..1],
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();

    for reporter in [&reporter_a, &reporter_b] {
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);
    }
    assert!(state.has_exact("score", &context, nodes[0].id));
    assert!(!state.has_exact("score", &context, nodes[1].id));
}

#[test]
fn final_outbound_late_completion_keeps_extant_leaf_and_drops_deleted_leaf() {
    let leaves = [node("final-a"), node("final-b")];
    let mut final_group = group("final-group", &leaves);
    final_group.policy = GroupPolicy::Selector;
    let mut outer = group("outer", &[]);
    outer.final_outbound = Some(final_group.name.clone());
    let old =
        super::super::super::GroupManager::new(&[outer.clone(), final_group.clone()], &leaves);
    let context = context("final.example", IpVersion::V4);
    let reporter_a = old
        .feedback_for_group_node("outer", leaves[0].id, context.clone())
        .unwrap()
        .start();
    let reporter_b = old
        .feedback_for_group_node("outer", leaves[1].id, context.clone())
        .unwrap()
        .start();
    let state = old.score_state();
    assert!(
        state
            .inner
            .lock()
            .valid
            .contains(&("outer".into(), leaves[0].id))
    );
    assert!(
        state
            .inner
            .lock()
            .valid
            .contains(&("outer".into(), leaves[1].id))
    );

    final_group.nodes.retain(|node_id| *node_id == leaves[0].id);
    let replacement = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[outer, final_group],
        std::slice::from_ref(&leaves[0]),
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    for reporter in [&reporter_a, &reporter_b] {
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);
    }

    assert!(state.has_exact("outer", &context, leaves[0].id));
    assert!(!state.has_exact("outer", &context, leaves[1].id));
}
