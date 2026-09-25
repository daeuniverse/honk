use super::budget::complete_ordinary;
use super::*;

#[test]
fn configured_http_probe_quality_stays_in_its_url_cohort() {
    use honk_config::group::{Group, GroupPolicy};
    use honk_config::node::Node;
    let nodes = ["a", "b"].map(|name| Node {
        id: Uuid::new_v4(),
        name: name.into(),
        ..Default::default()
    });
    let groups = [
        ("default", None),
        ("explicit", Some("https://one.test")),
        ("custom", Some("https://two.test")),
    ]
    .map(|(name, url)| Group {
        name: name.into(),
        policy: GroupPolicy::Score,
        nodes: nodes.iter().map(|node| node.id).collect(),
        check_url: url.map(str::to_owned),
        ..Default::default()
    });
    let manager = GroupManager::new(&groups, &nodes);
    let context = ScoreSelectionContext {
        target: Some(ScoreTarget::domain("business.test", 443)),
        target_family: Some(IpVersion::V4),
        ..ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4)
    };
    for node in &nodes {
        let feedback = manager.feedback_for_node(node.id, context.clone()).unwrap();
        for _ in 0..20 {
            let reporter = feedback.start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }
    }
    for (url, latency) in [
        ("https://one.test", [1, 500]),
        ("https://two.test", [500, 1]),
    ] {
        for (node, latency) in nodes.iter().zip(latency) {
            let feedback = manager
                .feedback_for_http_probe(node.id, context.clone(), url, "https://one.test")
                .unwrap();
            for _ in 0..4 {
                let reporter = feedback.start();
                reporter.probe_latency(Duration::from_millis(latency));
                reporter.finish_setup_only();
            }
        }
    }
    assert_eq!(
        manager
            .get_score_selection_for_network("default", SelectionNetwork::Tcp)
            .as_deref(),
        Some("a")
    );
    assert_eq!(
        manager
            .get_score_selection_for_network("explicit", SelectionNetwork::Tcp)
            .as_deref(),
        Some("a")
    );
    assert_eq!(
        manager
            .get_score_selection_for_network("custom", SelectionNetwork::Tcp)
            .as_deref(),
        Some("b")
    );
    assert!(
        manager
            .feedback_for_http_probe(
                nodes[0].id,
                context,
                "https://manual.test",
                "https://one.test"
            )
            .is_none()
    );
}

#[test]
fn recovery_keeps_nested_selector_permissions_health_and_attribution() {
    use honk_config::group::{Group, GroupPolicy};
    use honk_config::node::Node;
    let nodes = ["a", "b", "outside"].map(|name| Node {
        id: Uuid::new_v4(),
        name: name.into(),
        ..Default::default()
    });
    let score = Group {
        name: "score".into(),
        policy: GroupPolicy::Score,
        nodes: vec![nodes[0].id, nodes[0].id, nodes[1].id],
        final_outbound: Some("direct".into()),
        ..Default::default()
    };
    let outer = Group {
        name: "outer".into(),
        policy: GroupPolicy::Selector,
        nodes: vec![nodes[2].id],
        groups: vec!["score".into()],
        default: Some("score".into()),
        ..Default::default()
    };
    let alive = Arc::new(crate::alive::AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(&[outer, score], &nodes, Some(Arc::clone(&alive)));
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let primary = manager.selection_plan_for_target("outer", &context);
    let failed_node = primary.entries[0].node.id;
    let final_owners = &primary.entries[0].final_owners;
    let business = primary.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap();
    let original = business.continuation();
    let recovery = manager.score_retry_plan_for_target(
        "outer",
        &context,
        failed_node,
        final_owners,
        &original,
    );
    assert_eq!(recovery.entries.len(), 1);
    assert_ne!(recovery.entries[0].node.id, failed_node);
    assert_eq!(
        recovery.entries[0].selection_chain,
        ["outer", "score", recovery.entries[0].node.name.as_str()]
    );
    let feedback = recovery.entries[0].feedback.as_ref().unwrap();
    assert_eq!(feedback.attributions().len(), 1);
    assert_eq!(feedback.attributions()[0].group, "score");
    alive.report_unavailable_forced(recovery.entries[0].node.id, ProbeDomain::Tcp, IpVersion::V4);
    assert!(
        manager
            .score_retry_plan_for_target("outer", &context, failed_node, final_owners, &original)
            .entries
            .is_empty()
    );
    manager.set_selector_choice("outer", "outside");
    assert!(
        manager
            .score_retry_plan_for_target("outer", &context, failed_node, final_owners, &original)
            .entries
            .is_empty()
    );
}

#[test]
fn recovery_does_not_open_node_final_with_duplicate_display_name() {
    let mut nodes = [node("outside"), node("ordinary")];
    for node in &mut nodes {
        node.name = "shared".into();
    }
    let mut score = group("score", &nodes[1..]);
    score.final_outbound = Some("shared".into());
    let manager = GroupManager::new(&[score], &nodes);
    let context = context("duplicate-final.example", IpVersion::V4);
    let primary = manager.selection_plan_for_target("score", &context);
    assert_eq!(primary.entries[0].node.id, nodes[1].id);
    let business = primary.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap();

    let recovery = manager.score_retry_plan_for_target(
        "score",
        &context,
        primary.entries[0].node.id,
        &primary.entries[0].final_owners,
        &business.continuation(),
    );
    assert!(
        recovery.entries.is_empty(),
        "the same display name cannot authorize the outside node's unused final edge"
    );
}

#[test]
fn recovery_does_not_turn_ordinary_child_into_final_after_parent_url_failure() {
    let nodes = [node("a"), node("b")];
    let mut child = group("child", &nodes);
    child.policy = GroupPolicy::Fallback;
    let mut parent = group_with_children("parent", &[], &["child"]);
    let url = "https://parent-check.example/health";
    parent.check_url = Some(url.into());
    parent.final_outbound = Some("child".into());
    let alive = Arc::new(crate::alive::AliveDialerSet::new());
    alive.sync_group_check_urls(&[("parent".into(), url.into())]);
    let manager = GroupManager::with_alive_set(&[parent, child], &nodes, Some(Arc::clone(&alive)));
    let context = context("parent-final.example", IpVersion::V4);
    let primary = manager.selection_plan_for_target("parent", &context);
    assert_eq!(primary.entries[0].node.id, nodes[0].id);
    let business = primary.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap();

    for _ in 0..3 {
        alive.record_url_probe_failure("child", url);
    }
    assert!(alive.is_alive_for(nodes[1].id, ProbeDomain::Tcp, IpVersion::V4));
    let recovery = manager.score_retry_plan_for_target(
        "parent",
        &context,
        primary.entries[0].node.id,
        &primary.entries[0].final_owners,
        &business.continuation(),
    );
    assert!(
        recovery.entries.is_empty(),
        "ordinary child membership cannot authorize its URL-filter-bypassing final edge"
    );
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
        ScoreReasonCounters::default()
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
    complete_ordinary(&manager, "sel-sub-a", &nodes[0], 1.0);
    complete_ordinary(&manager, "sel-sub-b", &nodes[2], 1.0);

    // Default choice is the first member: only sub-a commits a rank.
    let _ = manager.selection_plan_for_domain("sel-parent", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        state
            .selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp)
            .performance_winner,
        1
    );
    assert_eq!(
        state.selection_reason_counts("sel-sub-b", SelectionNetwork::Tcp),
        ScoreReasonCounters::default()
    );
    assert_eq!(
        state.verification_counters("sel-sub-b", SelectionNetwork::Tcp),
        ScoreVerificationCounters::default()
    );

    // Switching the choice moves the committed rank to sub-b.
    manager.set_selector_choice("sel-parent", "sel-sub-b");
    let _ = manager.selection_plan_for_domain("sel-parent", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        state
            .selection_reason_counts("sel-sub-b", SelectionNetwork::Tcp)
            .performance_winner,
        1
    );
    assert_eq!(
        state
            .selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp)
            .performance_winner,
        1
    );

    // The target-aware dial path applies the same rule.
    manager.set_selector_choice("sel-parent", "sel-sub-a");
    let before_a = state.selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp);
    let before_b = state.selection_reason_counts("sel-sub-b", SelectionNetwork::Tcp);
    let plan = manager
        .selection_plan_for_target("sel-parent", &context("sel-target.internal", IpVersion::V4));
    let pending = manager.score_budget_counters("sel-sub-a", SelectionNetwork::Tcp);
    assert_eq!(
        (
            pending.reserved,
            pending.business_starts,
            pending.trial_starts
        ),
        (1, 0, 0)
    );
    assert_eq!(
        manager
            .score_budget_counters("sel-sub-b", SelectionNetwork::Tcp)
            .reserved,
        0
    );
    drop(plan);
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
            .performance_winner,
        1
    );
    assert_eq!(
        state.selection_reason_counts("def-sub-a", SelectionNetwork::Tcp),
        ScoreReasonCounters::default()
    );
}

#[test]
fn selector_refusal_does_not_commit_a_sibling_score_group() {
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

    manager.set_selector_choice("fallback-parent", "fallback-dead");
    assert!(
        manager
            .selection_plan_for_domain("fallback-parent", ProbeDomain::Tcp, IpVersion::V4)
            .nodes
            .is_empty()
    );
    assert_eq!(
        state
            .selection_reason_counts("fallback-sub", SelectionNetwork::Tcp)
            .cold_explore,
        0
    );
}

#[test]
fn selector_commit_does_not_restore_a_stale_sibling() {
    use crate::alive::AliveDialerSet;
    use honk_config::group::{Group, GroupPolicy};
    use honk_config::node::Node;

    let nodes: Vec<_> = ["a", "b", "outside"]
        .into_iter()
        .enumerate()
        .map(|(index, name)| Node {
            id: Uuid::from_u128(index as u128 + 1),
            name: name.into(),
            ..Default::default()
        })
        .collect();
    let groups = [
        Group {
            name: "child".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![nodes[0].id, nodes[1].id],
            ..Default::default()
        },
        Group {
            name: "parent".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![nodes[2].id],
            groups: vec!["child".into()],
            ..Default::default()
        },
    ];
    let mut results = Vec::new();
    for target_aware in [false, true] {
        for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp] {
            let alive = Arc::new(AliveDialerSet::new());
            for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
                alive.report_unavailable_forced(nodes[1].id, domain, IpVersion::V4);
            }
            let manager = GroupManager::with_alive_set(&groups, &nodes, Some(alive));
            manager.set_selector_choice("parent", "child");
            manager.set_selector_choice("child", "a");
            let parent = &manager.groups["parent"];
            let selected_member = manager.selector_member(parent).unwrap();
            let context = ScoreSelectionContext {
                target: Some(ScoreTarget::domain("commit.example", 443)),
                ..ScoreSelectionContext::aggregate(
                    SelectionNetwork::from_probe_domain(domain),
                    domain,
                    IpVersion::V4,
                )
            };
            let mut visited = Vec::new();
            let candidates = if target_aware {
                manager.flatten_candidates_for_target(
                    parent,
                    &context,
                    &mut visited,
                    0,
                    SelectionEffects::Apply,
                    super::super::selection::ScoreSelectionRules::default(),
                )
            } else {
                manager.flatten_candidates(
                    parent,
                    context.probe_domain,
                    context.health_family,
                    &mut visited,
                    0,
                    SelectionEffects::Apply,
                )
            };

            // A failed serving commit must not resurrect the child's old leaf.
            manager.set_selector_choice("child", "b");
            let picked = GroupManager::pick_selector(&candidates, selected_member).unwrap();
            let committed = manager.commit_selector_pick_for_target(
                parent,
                picked,
                &context,
                &mut visited,
                0,
                SelectionEffects::Apply,
                super::super::selection::ScoreSelectionRules::default(),
            );
            results.push(committed.map(|candidate| candidate.node.id));
        }
    }
    assert_eq!(
        results, [None; 4],
        "ordinary and target-aware commits must refuse"
    );
}
