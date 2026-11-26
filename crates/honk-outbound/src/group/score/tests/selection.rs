use super::super::selection::ScoreSelectionRules;
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
    manager
        .set_selector_choice("outer", "outside", crate::group::SelectorNetworks::Both)
        .unwrap();
    assert!(
        manager
            .score_retry_plan_for_target("outer", &context, failed_node, final_owners, &original)
            .entries
            .is_empty()
    );
}

#[test]
fn score_replacement_uses_the_current_nested_selector_permission_and_revision() {
    use crate::group::{SelectorNetworks, Target};

    let nodes = [node("a"), node("b"), node("exit")];
    let score = group("score", &nodes[..2]);
    let outer = Group {
        exit: Some("exit".into()),
        default: Some("score".into()),
        ..selector_with_children("outer", &nodes[2..], &["score"])
    };
    let alive = Arc::new(crate::alive::AliveDialerSet::new());
    let manager = Arc::new(GroupManager::with_alive_set(
        &[outer, score],
        &nodes,
        Some(alive),
    ));
    manager.publish_route_health();
    let context = context("retry.example", IpVersion::V4);
    let (primary, original_revision) = manager.dial_plan_for_target("outer", &context, None);
    let first = &primary.entries[0];
    let business = first.feedback.as_ref().unwrap().begin().unwrap();
    let original = business.continuation();
    let retry = || {
        manager.score_retry_dial_plan(
            "outer",
            &context,
            first.node.id,
            &first.final_owners,
            &original,
        )
    };

    manager
        .set_selector_choice("outer", "exit", SelectorNetworks::Tcp)
        .unwrap();
    assert!(retry().0.entries.is_empty());
    manager
        .set_selector_choice("outer", "score", SelectorNetworks::Tcp)
        .unwrap();
    let (plan, revision) = retry();
    let family = plan.health_family;
    let replacement = plan.entries.into_iter().next().unwrap();
    assert_ne!(replacement.node.id, first.node.id);
    let target = manager.own_target(Target {
        node: replacement.node,
        route: replacement.route,
    });
    assert_eq!(
        target.route().unwrap().hops(),
        [replacement.node.id, nodes[2].id]
    );
    let refusal = crate::proxy::test_prefix_refusal(1);
    assert!(!manager.report_route_failure(
        "outer",
        &target,
        family,
        original_revision.admit(),
        refusal.as_ref(),
    ));
    assert!(manager.report_route_failure(
        "outer",
        &target,
        family,
        revision.admit(),
        refusal.as_ref(),
    ));
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
    manager
        .set_selector_choice(
            "sel-parent",
            "sel-sub-b",
            crate::group::SelectorNetworks::Both,
        )
        .unwrap();
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
    manager
        .set_selector_choice(
            "sel-parent",
            "sel-sub-a",
            crate::group::SelectorNetworks::Both,
        )
        .unwrap();
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

    assert_eq!(
        manager.set_selector_choice(
            "sel-parent",
            "sel-sub-renamed-away",
            crate::group::SelectorNetworks::Both
        ),
        Err(crate::group::SelectorError::NotMember),
    );
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

    manager
        .set_selector_choice(
            "fallback-parent",
            "fallback-dead",
            crate::group::SelectorNetworks::Both,
        )
        .unwrap();
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
            manager
                .set_selector_choice("parent", "child", crate::group::SelectorNetworks::Both)
                .unwrap();
            manager
                .set_selector_choice("child", "a", crate::group::SelectorNetworks::Both)
                .unwrap();
            let context = ScoreSelectionContext {
                target: Some(ScoreTarget::domain("commit.example", 443)),
                ..ScoreSelectionContext::aggregate(
                    SelectionNetwork::from_probe_domain(domain),
                    domain,
                    IpVersion::V4,
                )
            };
            assert_eq!(
                manager
                    .peek_selection_plan_for_domain("parent", domain, IpVersion::V4)
                    .nodes[0]
                    .id,
                nodes[0].id
            );
            manager
                .set_selector_choice("child", "b", crate::group::SelectorNetworks::Both)
                .unwrap();
            let committed = if target_aware {
                manager
                    .selection_plan_for_target("parent", &context)
                    .entries
                    .first()
                    .map(|entry| entry.node.id)
            } else {
                manager
                    .selection_plan_for_domain("parent", domain, IpVersion::V4)
                    .nodes
                    .first()
                    .map(|node| node.id)
            };
            results.push(committed);
        }
    }
    assert_eq!(
        results, [None; 4],
        "ordinary and target-aware commits must refuse"
    );
}

#[test]
fn publication_between_ranking_and_plan_construction_refuses_node_work() {
    let nodes = ["a", "b"].map(|name| Node {
        id: Uuid::new_v5(&honk_config::node::NODE_ID_NAMESPACE, name.as_bytes()),
        name: name.into(),
        ..Default::default()
    });
    let group = Group {
        id: Uuid::new_v4(),
        name: "score".into(),
        policy: GroupPolicy::Score,
        nodes: nodes.iter().map(|node| node.id).collect(),
        ..Default::default()
    };
    let manager = GroupManager::new(std::slice::from_ref(&group), &nodes);
    // Trials only serve challengers with fewer completions than the ordinary selection.
    manager.score_state().inner.lock().aggregate.put(
        AggregateKey {
            group: "score".into(),
            network: SelectionNetwork::Tcp,
            family: None,
            node_id: nodes[0].id,
        },
        Stats {
            setup_success: 1.0,
            updated_at: Some(Instant::now()),
            ..Default::default()
        },
    );
    let context = ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(IpVersion::V4),
        health_family: IpVersion::V4,
        target: Some(ScoreTarget::domain("reload.example", 443)),
    };
    let (mode, candidates) = manager.selection_candidates_for_target(
        &group,
        &context,
        &mut Vec::new(),
        0,
        SelectionEffects::Apply,
        ScoreSelectionRules {
            cold_urltest: true,
            ..Default::default()
        },
    );
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .reserved,
        1
    );
    let replacement = GroupManager::with_alive_set_and_score_state(
        std::slice::from_ref(&group),
        &nodes,
        None,
        manager.score_state(),
    );
    replacement.publish_score_membership();
    let published = replacement.score_budget_counters("score", SelectionNetwork::Tcp);
    let plan = manager.score_selection_plan(candidates, mode, &context, None, manager.has_exits());
    assert!(
        !plan.entries[0]
            .feedback
            .as_ref()
            .is_none_or(|attempt| attempt.begin().is_ok())
    );
    assert_eq!(
        replacement.score_budget_counters("score", SelectionNetwork::Tcp),
        published
    );
    assert_eq!(replacement.score_state().root_business_starts(), 0);
    assert_eq!(
        (published.reserved, published.spent, published.refunded),
        (0, 0, 1)
    );
}

#[test]
fn urltest_and_fallback_parents_peek_unchosen_score_subgroups() {
    use crate::alive::{AliveDialerSet, IdleGroupKind, IdleGroupRegistration};

    for policy in [GroupPolicy::URLTest, GroupPolicy::Fallback] {
        let nodes = [
            node("auto-sub-alpha-a"),
            node("auto-sub-alpha-b"),
            node("auto-sub-beta-a"),
            node("auto-sub-beta-b"),
            node("auto-sub-alpha-final"),
            node("auto-sub-dead-sole"),
        ];
        let sub_a = group("auto-sub-a", &nodes[..2]);
        let mut sub_b = group("auto-sub-b", &nodes[2..4]);
        sub_b.final_outbound = Some(nodes[4].name.clone());
        let sub_dead_sole = group("auto-sub-dead", &nodes[5..6]);
        let parent = Group {
            policy,
            ..group_with_children(
                "auto-parent",
                &[],
                &["auto-sub-a", "auto-sub-b", "auto-sub-dead"],
            )
        };
        let alive = Arc::new(AliveDialerSet::new());
        alive.report_unavailable_forced(nodes[5].id, ProbeDomain::Tcp, IpVersion::V4);
        alive.report_unavailable_forced(nodes[5].id, ProbeDomain::Tcp, IpVersion::V6);
        alive.sync_idle_groups(&[
            IdleGroupRegistration {
                name: "auto-parent".into(),
                members: Vec::new(),
                idle_timeout: Some(Duration::from_secs(3600)),
                kind: IdleGroupKind::Automatic,
                tcp_recovery_members: nodes.iter().map(|node| node.id).collect(),
                udp_recovery_members: nodes.iter().map(|node| node.id).collect(),
            },
            IdleGroupRegistration {
                name: "auto-sub-a".into(),
                members: nodes[..2].iter().map(|node| node.id).collect(),
                idle_timeout: Some(Duration::from_secs(3600)),
                kind: IdleGroupKind::Automatic,
                tcp_recovery_members: nodes[..2].iter().map(|node| node.id).collect(),
                udp_recovery_members: nodes[..2].iter().map(|node| node.id).collect(),
            },
            IdleGroupRegistration {
                name: "auto-sub-b".into(),
                members: vec![nodes[2].id, nodes[3].id, nodes[4].id],
                idle_timeout: Some(Duration::from_secs(3600)),
                kind: IdleGroupKind::Automatic,
                tcp_recovery_members: vec![nodes[2].id, nodes[3].id, nodes[4].id],
                udp_recovery_members: vec![nodes[2].id, nodes[3].id, nodes[4].id],
            },
            IdleGroupRegistration {
                name: "auto-sub-dead".into(),
                members: vec![nodes[5].id],
                idle_timeout: Some(Duration::from_secs(3600)),
                kind: IdleGroupKind::Automatic,
                tcp_recovery_members: vec![nodes[5].id],
                udp_recovery_members: vec![nodes[5].id],
            },
        ]);
        for (leaf, ms) in [
            (&nodes[0], 10),
            (&nodes[1], 20),
            (&nodes[2], 80),
            (&nodes[3], 90),
        ] {
            alive.record_probe_latency(
                leaf.id,
                ProbeDomain::Tcp,
                IpVersion::V4,
                Duration::from_millis(ms),
            );
            alive.record_probe_latency(
                leaf.id,
                ProbeDomain::DataUdp,
                IpVersion::V4,
                Duration::from_millis(ms),
            );
            alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V6);
        }
        let manager = GroupManager::with_alive_set(
            &[sub_a, sub_b, sub_dead_sole, parent],
            &nodes,
            Some(Arc::clone(&alive)),
        );
        let state = manager.score_state();
        complete_ordinary(&manager, "auto-sub-a", &nodes[0], 1.0);
        complete_ordinary(&manager, "auto-sub-b", &nodes[2], 1.0);

        assert!(alive.is_group_idle("auto-sub-a"));
        assert!(alive.is_group_idle("auto-sub-b"));

        let picked = manager
            .select_node_for_domain("auto-parent", ProbeDomain::Tcp, IpVersion::V4)
            .unwrap();
        assert!(nodes[..2].iter().any(|node| node.id == picked.id));
        assert!(!alive.is_group_idle("auto-sub-a"), "{policy:?}");
        assert!(!alive.is_group_idle("auto-sub-b"), "{policy:?}");

        let _ = manager.selection_plan_for_domain("auto-parent", ProbeDomain::Tcp, IpVersion::V4);
        assert_eq!(
            state.selection_reason_counts("auto-sub-a", SelectionNetwork::Tcp),
            ScoreReasonCounters {
                performance_winner: 1,
                insufficient_evidence_held: 1,
                ..Default::default()
            },
            "{policy:?}"
        );
        assert_eq!(
            state.selection_reason_counts("auto-sub-b", SelectionNetwork::Tcp),
            ScoreReasonCounters::default(),
            "{policy:?}"
        );
        assert_eq!(
            state.verification_counters("auto-sub-b", SelectionNetwork::Tcp),
            ScoreVerificationCounters::default(),
            "{policy:?}"
        );
        assert!(
            !state.score_pool_initialized("auto-sub-b", SelectionNetwork::Tcp),
            "{policy:?}"
        );
        assert!(
            !state.score_pool_initialized("auto-sub-dead", SelectionNetwork::Tcp),
            "{policy:?}"
        );

        let target = context("auto-target.internal", IpVersion::V4);
        let plan = manager.selection_plan_for_target("auto-parent", &target);
        let pending_a = manager.score_budget_counters("auto-sub-a", SelectionNetwork::Tcp);
        assert_eq!(pending_a.reserved, 1, "{policy:?}");
        assert_eq!(
            manager.score_budget_counters("auto-sub-b", SelectionNetwork::Tcp),
            ScoreBudgetCounters::default(),
            "{policy:?}"
        );
        plan.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);

        let v6_target = ScoreSelectionContext {
            health_family: IpVersion::V6,
            ..context("auto-v6.internal", IpVersion::V6)
        };
        let (v6_plan, _) = manager.dial_plan_for_target("auto-parent", &v6_target, None);
        assert_eq!(v6_plan.health_family, IpVersion::V4, "{policy:?}");
        assert!(
            nodes[..2]
                .iter()
                .any(|node| node.id == v6_plan.entries[0].node.id),
            "{policy:?}"
        );
        v6_plan.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
        assert_eq!(
            state.selection_reason_counts("auto-sub-b", SelectionNetwork::Tcp),
            ScoreReasonCounters::default(),
            "{policy:?}"
        );

        let packet_ctx = ScoreSelectionContext {
            network: SelectionNetwork::Udp,
            probe_domain: ProbeDomain::DataUdp,
            target_family: Some(IpVersion::V4),
            health_family: IpVersion::V4,
            target: Some(ScoreTarget::domain("dns.internal", 853)),
        };
        let (packet_plan, _) = manager.node_packet_dial_plan("auto-parent", &packet_ctx, None);
        assert!(
            state.score_pool_initialized("auto-sub-a", SelectionNetwork::Udp),
            "{policy:?}"
        );
        assert!(
            !state.score_pool_initialized("auto-sub-b", SelectionNetwork::Udp),
            "{policy:?}"
        );
        packet_plan.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);

        if policy == GroupPolicy::URLTest {
            for leaf in &nodes[..2] {
                for _ in 0..4 {
                    alive.record_probe_latency(
                        leaf.id,
                        ProbeDomain::Tcp,
                        IpVersion::V4,
                        Duration::from_millis(500),
                    );
                }
            }
        } else {
            for leaf in &nodes[..2] {
                alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
            }
        }
        let before_a_reasons = state.selection_reason_counts("auto-sub-a", SelectionNetwork::Tcp);
        let before_a_budget = manager.score_budget_counters("auto-sub-a", SelectionNetwork::Tcp);
        let switched = manager.selection_plan_for_target("auto-parent", &target);
        assert!(
            nodes[2..4]
                .iter()
                .any(|node| node.id == switched.entries[0].node.id),
            "{policy:?}"
        );
        switched.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
        assert!(
            state.score_pool_initialized("auto-sub-b", SelectionNetwork::Tcp),
            "{policy:?}"
        );
        assert_ne!(
            state.selection_reason_counts("auto-sub-b", SelectionNetwork::Tcp),
            ScoreReasonCounters::default(),
            "{policy:?}"
        );
        assert_eq!(
            state.selection_reason_counts("auto-sub-a", SelectionNetwork::Tcp),
            before_a_reasons,
            "{policy:?}"
        );
        assert_eq!(
            manager.score_budget_counters("auto-sub-a", SelectionNetwork::Tcp),
            before_a_budget,
            "{policy:?}"
        );
    }
}

#[test]
fn depth_three_automatic_trees_commit_only_winning_branch() {
    use crate::alive::AliveDialerSet;

    let nodes: Vec<_> = (0..10).map(|i| node(&format!("d3-{i}"))).collect();
    let s_l1 = group("s-l1", &nodes[0..2]);
    let s_l2 = group("s-l2", &nodes[2..4]);
    let s_r1 = group("s-r1", &nodes[4..6]);
    let s_r2 = group("s-r2", &nodes[6..8]);
    let lb_unused = Group {
        policy: GroupPolicy::LoadBalance,
        ..group("lb-unused", &nodes[8..10])
    };
    let fb_left = Group {
        policy: GroupPolicy::Fallback,
        ..group_with_children("fb-left", &[], &["s-l1", "s-l2"])
    };
    let ut_right = Group {
        policy: GroupPolicy::URLTest,
        ..group_with_children("ut-right", &[], &["s-r1", "s-r2", "lb-unused"])
    };
    let top = Group {
        policy: GroupPolicy::URLTest,
        ..group_with_children("top", &[], &["fb-left", "ut-right"])
    };
    let alive = Arc::new(AliveDialerSet::new());
    for (idx, leaf) in nodes.iter().enumerate() {
        let ms = if idx < 4 { 10 } else { 120 };
        alive.record_probe_latency(
            leaf.id,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(ms),
        );
    }
    let manager = GroupManager::with_alive_set(
        &[s_l1, s_l2, s_r1, s_r2, lb_unused, fb_left, ut_right, top],
        &nodes,
        Some(alive),
    );
    for (grp, leaf) in [
        ("s-l1", &nodes[0]),
        ("s-l2", &nodes[2]),
        ("s-r1", &nodes[4]),
        ("s-r2", &nodes[6]),
    ] {
        complete_ordinary(&manager, grp, leaf, 1.0);
    }

    let target = context("depth3.internal", IpVersion::V4);
    let (plan, _) = manager.dial_plan_for_target("top", &target, None);
    assert_eq!(
        plan.entries[0].selection_chain,
        ["top", "fb-left", "s-l1", plan.entries[0].node.name.as_str()]
    );
    plan.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);

    let state = manager.score_state();
    assert!(state.score_pool_initialized("s-l1", SelectionNetwork::Tcp));
    for untouched in ["s-l2", "s-r1", "s-r2"] {
        assert!(
            !state.score_pool_initialized(untouched, SelectionNetwork::Tcp),
            "{untouched}"
        );
        assert_eq!(
            state.selection_reason_counts(untouched, SelectionNetwork::Tcp),
            ScoreReasonCounters::default(),
            "{untouched}"
        );
        assert_eq!(
            state.verification_counters(untouched, SelectionNetwork::Tcp),
            ScoreVerificationCounters::default(),
            "{untouched}"
        );
        assert_eq!(
            manager.score_budget_counters(untouched, SelectionNetwork::Tcp),
            ScoreBudgetCounters::default(),
            "{untouched}"
        );
    }
    assert_eq!(manager.get_urltest_selection("ut-right"), None);
    assert_eq!(manager.select_node("lb-unused").unwrap().id, nodes[8].id);
}

#[test]
fn urltest_and_fallback_parents_replace_exhausted_committed_score_pool() {
    use crate::alive::AliveDialerSet;

    for policy in [GroupPolicy::URLTest, GroupPolicy::Fallback] {
        let nodes: Vec<_> = (0..10).map(|i| node(&format!("pool-rep-{i}"))).collect();
        let sub_a = group("sub-a", &nodes[..8]);
        let sub_b = group("sub-b", &nodes[8..]);
        let parent = Group {
            policy,
            ..group_with_children("parent", &[], &["sub-a", "sub-b"])
        };
        let alive = Arc::new(AliveDialerSet::new());
        for (idx, leaf) in nodes.iter().enumerate() {
            let ms = if idx < 8 { 10 } else { 150 };
            alive.record_probe_latency(
                leaf.id,
                ProbeDomain::Tcp,
                IpVersion::V4,
                Duration::from_millis(ms),
            );
        }
        let manager =
            GroupManager::with_alive_set(&[sub_a, sub_b, parent], &nodes, Some(Arc::clone(&alive)));
        let target = context("pool-replace.internal", IpVersion::V4);
        let first = manager.selection_plan_for_target("parent", &target);
        first.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);

        let initial_pool: Vec<Uuid> = {
            let state = manager.score_state();
            let inner = state.inner.lock();
            let set = inner.evaluation("sub-a", SelectionNetwork::Tcp).unwrap();
            nodes[..8]
                .iter()
                .filter(|n| set.evaluates(n.id))
                .map(|n| n.id)
                .collect()
        };
        assert_eq!(initial_pool.len(), 3);
        for id in &initial_pool {
            alive.report_unavailable_forced(*id, ProbeDomain::Tcp, IpVersion::V4);
        }
        assert_eq!(
            manager.get_score_selection_for_network("sub-a", SelectionNetwork::Tcp),
            None,
            "public Peek stays committed-only"
        );

        let recovered = manager.selection_plan_for_target("parent", &target);
        assert_eq!(
            recovered.entries[0].selection_chain[1], "sub-a",
            "{policy:?} must preview sub-a's replacement pool rather than ejecting sub-a"
        );
        assert!(!initial_pool.contains(&recovered.entries[0].node.id));
        recovered.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
        assert!(
            !manager
                .score_state()
                .score_pool_initialized("sub-b", SelectionNetwork::Tcp),
            "{policy:?}"
        );
    }
}

#[test]
fn cold_urltest_and_urltest_retry_admit_nested_score_subgroups() {
    use crate::alive::AliveDialerSet;

    let cold_nodes = [
        node("cold-a1"),
        node("cold-a2"),
        node("cold-b1"),
        node("cold-b2"),
    ];
    let cold_a = group("cold-sub-a", &cold_nodes[..2]);
    let cold_b = group("cold-sub-b", &cold_nodes[2..]);
    let cold_parent = Group {
        policy: GroupPolicy::URLTest,
        ..group_with_children("cold-parent", &[], &["cold-sub-a", "cold-sub-b"])
    };
    let cold_mgr = GroupManager::new(&[cold_a, cold_b, cold_parent], &cold_nodes);
    complete_ordinary(&cold_mgr, "cold-sub-a", &cold_nodes[0], 1.0);
    complete_ordinary(&cold_mgr, "cold-sub-b", &cold_nodes[2], 1.0);

    let target = context("cold-race.internal", IpVersion::V4);
    let (cold_plan, _) = cold_mgr.dial_plan_for_target("cold-parent", &target, None);
    assert_eq!(cold_plan.mode, crate::group::SelectionPlanMode::ColdUrlTest);
    assert_eq!(cold_plan.entries.len(), 2);
    for sub in ["cold-sub-a", "cold-sub-b"] {
        let budget = cold_mgr.score_budget_counters(sub, SelectionNetwork::Tcp);
        assert_eq!((budget.reserved, budget.refunded), (1, 0), "{sub}");
    }
    for entry in &cold_plan.entries {
        entry
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
    }

    let retry_nodes: Vec<_> = (0..11).map(|i| node(&format!("retry-s-{i}"))).collect();
    let s1 = group("s1", &retry_nodes[0..2]);
    let s_overlap = group(
        "s-overlap",
        &[retry_nodes[0].clone(), retry_nodes[10].clone()],
    );
    let s2 = group("s2", &retry_nodes[2..7]);
    let s3 = group("s3", &retry_nodes[7..9]);
    let s4 = group("s4", &retry_nodes[9..11]);
    let warm_parent = Group {
        policy: GroupPolicy::URLTest,
        ..group_with_children("warm-parent", &[], &["s1", "s-overlap", "s2", "s3", "s4"])
    };
    let alive = Arc::new(AliveDialerSet::new());
    for (idx, leaf) in retry_nodes.iter().enumerate() {
        let ms = if idx < 2 {
            15
        } else if idx < 7 {
            30
        } else if idx < 9 {
            45
        } else {
            60
        };
        alive.record_probe_latency(
            leaf.id,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(ms),
        );
    }
    let warm_mgr = GroupManager::with_alive_set(
        &[s1, s_overlap, s2, s3, s4, warm_parent],
        &retry_nodes,
        Some(Arc::clone(&alive)),
    );
    for (grp, leaf) in [
        ("s1", &retry_nodes[0]),
        ("s-overlap", &retry_nodes[0]),
        ("s2", &retry_nodes[2]),
        ("s3", &retry_nodes[7]),
        ("s4", &retry_nodes[9]),
    ] {
        complete_ordinary(&warm_mgr, grp, leaf, 1.0);
    }
    drop(warm_mgr.selection_plan_for_target("s2", &target));
    let s2_old_pool: Vec<Uuid> = {
        let state = warm_mgr.score_state();
        let inner = state.inner.lock();
        let set = inner.evaluation("s2", SelectionNetwork::Tcp).unwrap();
        retry_nodes[2..7]
            .iter()
            .filter(|n| set.evaluates(n.id))
            .map(|n| n.id)
            .collect()
    };
    assert_eq!(s2_old_pool.len(), 3);
    for id in &s2_old_pool {
        alive.report_unavailable_forced(*id, ProbeDomain::Tcp, IpVersion::V4);
    }
    assert_eq!(
        warm_mgr.get_score_selection_for_network("s2", SelectionNetwork::Tcp),
        None
    );

    let (primary, _) = warm_mgr.dial_plan_for_target("warm-parent", &target, None);
    assert_eq!(primary.entries.len(), 1);
    let guard = primary.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap();
    let original = guard.continuation();
    guard.finish(ScoreOutcome::Timeout);

    use crate::alive::{IdleGroupKind, IdleGroupRegistration};
    alive.sync_idle_groups(&[
        IdleGroupRegistration {
            name: "s-overlap".into(),
            members: vec![retry_nodes[0].id, retry_nodes[10].id],
            idle_timeout: Some(Duration::from_secs(3600)),
            kind: IdleGroupKind::Automatic,
            tcp_recovery_members: vec![retry_nodes[0].id, retry_nodes[10].id],
            udp_recovery_members: vec![retry_nodes[0].id, retry_nodes[10].id],
        },
        IdleGroupRegistration {
            name: "s4".into(),
            members: vec![retry_nodes[9].id, retry_nodes[10].id],
            idle_timeout: Some(Duration::from_secs(3600)),
            kind: IdleGroupKind::Automatic,
            tcp_recovery_members: vec![retry_nodes[9].id, retry_nodes[10].id],
            udp_recovery_members: vec![retry_nodes[9].id, retry_nodes[10].id],
        },
    ]);

    let state = warm_mgr.score_state();
    assert!(state.score_pool_initialized("s1", SelectionNetwork::Tcp));
    for untouched in ["s-overlap", "s3", "s4"] {
        assert!(!state.score_pool_initialized(untouched, SelectionNetwork::Tcp));
        assert_eq!(
            state.selection_reason_counts(untouched, SelectionNetwork::Tcp),
            ScoreReasonCounters::default()
        );
    }
    let s1_reasons_before_retry = state.selection_reason_counts("s1", SelectionNetwork::Tcp);
    let s2_reasons_before_retry = state.selection_reason_counts("s2", SelectionNetwork::Tcp);

    let (retry, _) = warm_mgr.urltest_retry_dial_plan("warm-parent", &target, Some(&original));
    assert_eq!(retry.entries.len(), 3);
    assert!(
        !state
            .inner
            .lock()
            .selection_history
            .iter()
            .any(|(key, _)| key.group == "s-overlap")
    );
    assert!(!state.score_pool_initialized("s-overlap", SelectionNetwork::Tcp));
    assert_eq!(
        state.selection_reason_counts("s-overlap", SelectionNetwork::Tcp),
        ScoreReasonCounters::default()
    );
    assert!(alive.is_group_idle("s-overlap"));
    assert!(alive.is_group_idle("s4"));
    assert_eq!(
        warm_mgr.score_budget_counters("s3", SelectionNetwork::Tcp),
        ScoreBudgetCounters::default()
    );
    assert_eq!(
        state.selection_reason_counts("s1", SelectionNetwork::Tcp),
        s1_reasons_before_retry,
        "already-admitted primary subgroup must not double-count on retry"
    );
    assert_ne!(
        state.selection_reason_counts("s2", SelectionNetwork::Tcp),
        s2_reasons_before_retry
    );
    for entry in &retry.entries {
        entry
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
    }
    assert!(state.score_pool_initialized("s3", SelectionNetwork::Tcp));
    assert!(!state.score_pool_initialized("s4", SelectionNetwork::Tcp));
    assert_eq!(
        state.selection_reason_counts("s4", SelectionNetwork::Tcp),
        ScoreReasonCounters::default()
    );
}

#[test]
fn routed_udp_subgroup_through_parent_exit_commits_only_winner() {
    use crate::alive::{AliveDialerSet, IdleGroupKind, IdleGroupRegistration};

    let tcp_only_a = Node {
        outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            network: Some("tcp".into()),
            ..Default::default()
        }),
        ..node("tcp-only-a")
    };
    let tcp_only_b = Node {
        outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            network: Some("tcp".into()),
            ..Default::default()
        }),
        ..node("tcp-only-b")
    };
    let trojan_exit = Node {
        outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
        ..node("trojan-exit")
    };
    let nodes = [tcp_only_a.clone(), tcp_only_b.clone(), trojan_exit.clone()];
    let sub_a = group("routed-sub-a", std::slice::from_ref(&tcp_only_a));
    let sub_b = group("routed-sub-b", std::slice::from_ref(&tcp_only_b));
    let parent = Group {
        policy: GroupPolicy::Fallback,
        exit: Some(trojan_exit.name.clone()),
        ..group_with_children("routed-parent", &[], &["routed-sub-a", "routed-sub-b"])
    };
    let selector_parent = Group {
        policy: GroupPolicy::Selector,
        exit: Some(trojan_exit.name.clone()),
        ..group_with_children("sel-routed-parent", &[], &["routed-sub-a", "routed-sub-b"])
    };
    let alive = Arc::new(AliveDialerSet::new());
    alive.sync_idle_groups(&[
        IdleGroupRegistration {
            name: "routed-sub-a".into(),
            members: vec![tcp_only_a.id],
            idle_timeout: Some(Duration::from_secs(3600)),
            kind: IdleGroupKind::Automatic,
            tcp_recovery_members: vec![tcp_only_a.id],
            udp_recovery_members: vec![tcp_only_a.id],
        },
        IdleGroupRegistration {
            name: "routed-sub-b".into(),
            members: vec![tcp_only_b.id],
            idle_timeout: Some(Duration::from_secs(3600)),
            kind: IdleGroupKind::Automatic,
            tcp_recovery_members: vec![tcp_only_b.id],
            udp_recovery_members: vec![tcp_only_b.id],
        },
    ]);
    let manager = GroupManager::with_alive_set(
        &[sub_a, sub_b, parent, selector_parent],
        &nodes,
        Some(Arc::clone(&alive)),
    );
    assert!(!manager.is_node_selectable_for_domain(
        tcp_only_a.id,
        ProbeDomain::DataUdp,
        IpVersion::V4
    ));
    let udp_ctx = ScoreSelectionContext {
        network: SelectionNetwork::Udp,
        probe_domain: ProbeDomain::DataUdp,
        target_family: Some(IpVersion::V4),
        health_family: IpVersion::V4,
        target: Some(ScoreTarget::domain("udp-exit.internal", 443)),
    };
    let (sel_plan, _) = manager.dial_plan_for_target("sel-routed-parent", &udp_ctx, None);
    assert_eq!(sel_plan.entries.len(), 1);
    assert!(!alive.is_group_idle("routed-sub-a"));
    assert!(alive.is_group_idle("routed-sub-b"));
    sel_plan.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);

    let (plan, _) = manager.dial_plan_for_target("routed-parent", &udp_ctx, None);
    assert_eq!(plan.entries.len(), 1);
    assert_eq!(plan.entries[0].node.id, tcp_only_a.id);
    assert!(!alive.is_group_idle("routed-sub-b"));
    plan.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    let state = manager.score_state();
    assert!(state.score_pool_initialized("routed-sub-a", SelectionNetwork::Udp));
    assert!(!state.score_pool_initialized("routed-sub-b", SelectionNetwork::Udp));
}

#[cfg(feature = "flow-observation")]
#[test]
fn observed_urltest_and_fallback_track_committed_trial_leaf_without_applying_siblings() {
    use crate::alive::AliveDialerSet;
    use crate::group::observation::ObservedMember;
    use crate::runtime::flow_observation::{FlowContext, FlowObserver};

    for policy in [GroupPolicy::URLTest, GroupPolicy::Fallback] {
        let nodes = [
            node("obs-a1"),
            node("obs-a2"),
            node("obs-b1"),
            node("obs-b2"),
        ];
        let sub_a = group("obs-sub-a", &nodes[..2]);
        let sub_b = group("obs-sub-b", &nodes[2..]);
        let parent = Group {
            policy,
            ..group_with_children("obs-parent", &[], &["obs-sub-a", "obs-sub-b"])
        };
        let alive = Arc::new(AliveDialerSet::new());
        for (leaf, ms) in [
            (&nodes[0], 10),
            (&nodes[1], 20),
            (&nodes[2], 90),
            (&nodes[3], 95),
        ] {
            alive.record_probe_latency(
                leaf.id,
                ProbeDomain::Tcp,
                IpVersion::V4,
                Duration::from_millis(ms),
            );
        }
        let manager = GroupManager::with_alive_set(&[sub_a, sub_b, parent], &nodes, Some(alive));
        complete_ordinary(&manager, "obs-sub-a", &nodes[0], 1.0);
        complete_ordinary(&manager, "obs-sub-b", &nodes[2], 1.0);

        let observer = FlowObserver::new(
            FlowContext {
                flow_id: Uuid::new_v4(),
                generation: 1,
                attempt_id: None,
                lookup_id: None,
                dns_purpose: "business",
            },
            Arc::new(|_, _| {}),
        );
        let target = context("obs-trial.internal", IpVersion::V4);
        let plan = observer.sync_scope(|| manager.selection_plan_for_target("obs-parent", &target));
        assert_eq!(
            plan.entries[0].node.id, nodes[1].id,
            "{policy:?} must dispatch sub-a's cold trial leaf on commit"
        );
        let facts = plan.observation.as_ref().unwrap();
        let root_decision = &facts.decisions[0];
        assert!(root_decision.applied);
        assert_eq!(
            root_decision.selected_member,
            Some(ObservedMember::Group {
                name: "obs-sub-a".into()
            }),
            "{policy:?}"
        );
        let selected_rows: Vec<_> = root_decision
            .candidates
            .iter()
            .filter(|row| row.selected)
            .collect();
        assert_eq!(selected_rows.len(), 1, "{policy:?}");
        assert_eq!(
            selected_rows[0].leaf_node_id,
            Some(nodes[1].id),
            "{policy:?}"
        );
        assert!(
            facts
                .decisions
                .iter()
                .filter(|d| d.group_name == "obs-sub-b")
                .all(|d| !d.applied),
            "{policy:?}"
        );
        assert!(
            facts
                .decisions
                .iter()
                .any(|d| d.group_name == "obs-sub-a" && d.applied),
            "{policy:?}"
        );
    }

    let cold_nodes = [
        node("cold-obs-a1"),
        node("cold-obs-a2"),
        node("cold-obs-b1"),
        node("cold-obs-b2"),
    ];
    let cold_sub_a = group("cold-obs-sub-a", &cold_nodes[..2]);
    let cold_sub_b = group("cold-obs-sub-b", &cold_nodes[2..]);
    let cold_parent = Group {
        policy: GroupPolicy::URLTest,
        ..group_with_children("cold-obs-parent", &[], &["cold-obs-sub-a"])
    };
    let cold_mid = Group {
        policy: GroupPolicy::URLTest,
        ..group_with_children("cold-obs-mid", &[], &["cold-obs-sub-b"])
    };
    let sel_top = Group {
        policy: GroupPolicy::Selector,
        ..group_with_children("sel-obs-top", &[], &["cold-obs-mid"])
    };
    let cold_mgr = GroupManager::new(
        &[cold_sub_a, cold_sub_b, cold_parent, cold_mid, sel_top],
        &cold_nodes,
    );
    complete_ordinary(&cold_mgr, "cold-obs-sub-a", &cold_nodes[0], 1.0);
    complete_ordinary(&cold_mgr, "cold-obs-sub-b", &cold_nodes[2], 1.0);

    let observer = FlowObserver::new(
        FlowContext {
            flow_id: Uuid::new_v4(),
            generation: 1,
            attempt_id: None,
            lookup_id: None,
            dns_purpose: "business",
        },
        Arc::new(|_, _| {}),
    );
    let target = context("cold-obs-trial.internal", IpVersion::V4);
    let cold_plan =
        observer.sync_scope(|| cold_mgr.selection_plan_for_target("cold-obs-parent", &target));
    assert_eq!(cold_plan.mode, crate::group::SelectionPlanMode::ColdUrlTest);
    assert_eq!(cold_plan.entries[0].node.id, cold_nodes[1].id);
    let cold_facts = cold_plan.observation.as_ref().unwrap();
    assert_eq!(
        cold_facts.decisions[0].candidates[0].leaf_node_id,
        Some(cold_nodes[1].id)
    );

    let nested_cold_plan =
        observer.sync_scope(|| cold_mgr.selection_plan_for_target("sel-obs-top", &target));
    assert_eq!(nested_cold_plan.entries[0].node.id, cold_nodes[3].id);
    let mid_decision = nested_cold_plan
        .observation
        .as_ref()
        .unwrap()
        .decisions
        .iter()
        .find(|d| d.group_name == "cold-obs-mid")
        .unwrap();
    assert_eq!(
        mid_decision.candidates[0].leaf_node_id,
        Some(cold_nodes[3].id)
    );
    assert!(mid_decision.candidates[0].selected);
}

#[test]
fn concurrent_subgroup_death_on_commit_leaves_parent_unselected_and_uncached() {
    use crate::alive::AliveDialerSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for (policy, cold, use_url, nested_empty) in [
        (GroupPolicy::URLTest, false, false, false),
        (GroupPolicy::Fallback, false, false, false),
        (GroupPolicy::Fallback, false, true, false),
        (GroupPolicy::URLTest, true, false, false),
        (GroupPolicy::URLTest, false, false, true),
    ] {
        let prev = node("race-prev");
        let mid_first = node("race-mid-first");
        let mid_score_leaf = node("race-mid-score");
        let nodes = [prev.clone(), mid_first.clone(), mid_score_leaf.clone()];
        let score_sub = group("race-score", std::slice::from_ref(&mid_score_leaf));
        let mid_fb = Group {
            policy: GroupPolicy::Fallback,
            interrupt_connections: true,
            ..group_with_children(
                "race-mid",
                std::slice::from_ref(&mid_first),
                &["race-score"],
            )
        };
        let outer_fb = Group {
            policy: GroupPolicy::Fallback,
            ..group_with_children("race-outer", &[], &["race-mid"])
        };
        let url = "http://race-check.internal/health";
        let child_tag = if nested_empty {
            "race-outer"
        } else {
            "race-mid"
        };
        let parent = Group {
            policy,
            interrupt_connections: true,
            check_url: use_url.then(|| url.into()),
            ..group_with_children(
                "race-parent",
                if cold {
                    &[][..]
                } else {
                    std::slice::from_ref(&prev)
                },
                &[child_tag],
            )
        };
        let alive = Arc::new(AliveDialerSet::new());
        if use_url {
            alive.sync_group_check_urls(&[("race-parent".into(), url.into())]);
        }
        if !cold {
            alive.record_probe_latency(
                prev.id,
                ProbeDomain::Tcp,
                IpVersion::V4,
                Duration::from_millis(5),
            );
            alive.record_probe_latency(
                mid_score_leaf.id,
                ProbeDomain::Tcp,
                IpVersion::V4,
                Duration::from_millis(20),
            );
        }
        let manager = GroupManager::with_alive_set(
            &[score_sub, mid_fb, outer_fb, parent],
            &nodes,
            Some(Arc::clone(&alive)),
        );
        assert_eq!(manager.select_node("race-mid").unwrap().id, mid_first.id);
        if !cold {
            assert_eq!(manager.select_node("race-parent").unwrap().id, prev.id);
            alive.report_unavailable_forced(prev.id, ProbeDomain::Tcp, IpVersion::V4);
            if use_url {
                for _ in 0..3 {
                    alive.record_url_probe_failure("race-prev", url);
                }
            }
        }
        alive.report_unavailable_forced(mid_first.id, ProbeDomain::Tcp, IpVersion::V4);

        let parent_interrupts = Arc::new(AtomicUsize::new(0));
        let interrupts_ref = Arc::clone(&parent_interrupts);
        let alive_cb = Arc::clone(&alive);
        manager.set_interrupt_callback(Some(Arc::new(move |grp, _| {
            if grp == "race-mid" {
                if use_url {
                    for _ in 0..3 {
                        alive_cb.record_url_probe_failure("race-mid", url);
                    }
                } else {
                    alive_cb.report_unavailable_forced(
                        mid_score_leaf.id,
                        ProbeDomain::Tcp,
                        IpVersion::V4,
                    );
                }
            } else if grp == "race-parent" {
                interrupts_ref.fetch_add(1, Ordering::SeqCst);
            }
        })));

        let target = context("race.internal", IpVersion::V4);
        #[cfg(feature = "flow-observation")]
        let plan = {
            use crate::runtime::flow_observation::{FlowContext, FlowObserver};
            let observer = FlowObserver::new(
                FlowContext {
                    flow_id: Uuid::new_v4(),
                    generation: 1,
                    attempt_id: None,
                    lookup_id: None,
                    dns_purpose: "business",
                },
                Arc::new(|_, _| {}),
            );
            observer.sync_scope(|| manager.selection_plan_for_target("race-parent", &target))
        };
        #[cfg(not(feature = "flow-observation"))]
        let plan = manager.selection_plan_for_target("race-parent", &target);

        assert!(
            plan.entries.is_empty(),
            "{policy:?} cold={cold} url={use_url}"
        );
        assert_eq!(
            plan.mode,
            crate::group::SelectionPlanMode::Authoritative,
            "{policy:?} cold={cold} url={use_url}"
        );
        if cold {
            assert_eq!(manager.get_urltest_selection("race-parent"), None);
        } else if policy == GroupPolicy::URLTest {
            assert_eq!(
                manager.get_urltest_selection("race-parent").as_deref(),
                Some("race-prev")
            );
        } else {
            assert_eq!(
                manager.get_fallback_selection("race-parent").as_deref(),
                Some("race-prev")
            );
        }
        assert_eq!(parent_interrupts.load(Ordering::SeqCst), 0);

        #[cfg(feature = "flow-observation")]
        {
            use crate::group::observation::ObservedMember;
            let root = &plan.observation.as_ref().unwrap().decisions[0];
            assert!(root.selected_member.is_none());
            assert!(root.candidates.iter().all(|row| !row.selected));
            assert_eq!(
                root.reason,
                if cold {
                    "no_eligible_candidate"
                } else {
                    "selected_member_unavailable"
                }
            );
            let sub_row = root
                .candidates
                .iter()
                .find(|row| {
                    row.member
                        == ObservedMember::Group {
                            name: child_tag.into(),
                        }
                })
                .unwrap();
            assert_eq!(sub_row.eligible, Some(false));
            assert_eq!(
                sub_row.reason,
                if nested_empty {
                    "selected_member_unavailable"
                } else if use_url {
                    "custom_url_unavailable"
                } else {
                    "capability_or_health_unavailable"
                }
            );
        }
    }
}

#[test]
fn parent_rejects_committed_trial_and_selects_healthy_sibling() {
    use crate::alive::AliveDialerSet;

    for (policy, final_outbound, cold_sibling) in [
        (GroupPolicy::Fallback, None, false),
        (GroupPolicy::Fallback, Some("direct"), false),
        (GroupPolicy::URLTest, None, false),
        (GroupPolicy::URLTest, Some("direct"), false),
        (GroupPolicy::URLTest, Some("direct"), true),
    ] {
        let leaf_a = node("trial-rej-a");
        let leaf_b = node("trial-rej-b");
        let leaf_t = node("trial-rej-t");
        let nodes = [leaf_a.clone(), leaf_b.clone(), leaf_t.clone()];
        let child_url = "http://child-score.internal/health";
        let sub_s = Group {
            policy: GroupPolicy::Score,
            check_url: Some(child_url.into()),
            ..group("trial-sub-s", &[leaf_a.clone(), leaf_b.clone()])
        };
        let sub_t = Group {
            policy: GroupPolicy::Score,
            ..group("trial-sub-t", std::slice::from_ref(&leaf_t))
        };
        let parent = Group {
            policy,
            final_outbound: final_outbound.map(str::to_owned),
            ..group_with_children("trial-parent", &[], &["trial-sub-s", "trial-sub-t"])
        };
        let alive = Arc::new(AliveDialerSet::new());
        alive.sync_group_check_urls(&[("trial-sub-s".into(), child_url.into())]);
        alive.record_probe_latency(
            leaf_a.id,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(10),
        );
        if !cold_sibling {
            alive.record_probe_latency(
                leaf_t.id,
                ProbeDomain::Tcp,
                IpVersion::V4,
                Duration::from_millis(25),
            );
        }
        alive.report_unavailable_forced(leaf_b.id, ProbeDomain::Tcp, IpVersion::V4);
        let manager =
            GroupManager::with_alive_set(&[sub_s, sub_t, parent], &nodes, Some(Arc::clone(&alive)));
        complete_ordinary(&manager, "trial-sub-s", &leaf_a, 1.0);

        let target = context("trial-reject.internal", IpVersion::V4);
        #[cfg(feature = "flow-observation")]
        let (plan, _) = {
            use crate::runtime::flow_observation::{FlowContext, FlowObserver};
            let observer = FlowObserver::new(
                FlowContext {
                    flow_id: Uuid::new_v4(),
                    generation: 1,
                    attempt_id: None,
                    lookup_id: None,
                    dns_purpose: "business",
                },
                Arc::new(|_, _| {}),
            );
            observer.sync_scope(|| manager.dial_plan_for_target("trial-parent", &target, None))
        };
        #[cfg(not(feature = "flow-observation"))]
        let (plan, _) = manager.dial_plan_for_target("trial-parent", &target, None);

        assert_eq!(
            plan.entries.len(),
            1,
            "{policy:?} final={final_outbound:?} cold={cold_sibling}"
        );
        assert_eq!(
            plan.entries[0].node.id, leaf_t.id,
            "{policy:?} final={final_outbound:?} cold={cold_sibling}"
        );
        assert_eq!(
            plan.entries[0].selection_chain,
            ["trial-parent", "trial-sub-t", "trial-rej-t"],
            "{policy:?} final={final_outbound:?} cold={cold_sibling}"
        );
        assert!(plan.entries[0].final_owners.is_empty());
        assert_eq!(
            plan.mode,
            if cold_sibling {
                crate::group::SelectionPlanMode::ColdUrlTest
            } else {
                crate::group::SelectionPlanMode::Authoritative
            }
        );
        assert_eq!(
            manager.score_budget_counters("trial-sub-s", SelectionNetwork::Tcp),
            ScoreBudgetCounters {
                cold_allowance: 2,
                cold_available: 2,
                earning_period: 16,
                refunded: 1,
                scopes: 1,
                ..Default::default()
            }
        );
        if cold_sibling {
            assert_eq!(manager.get_urltest_selection("trial-parent"), None);
        } else if policy == GroupPolicy::URLTest {
            assert_eq!(
                manager.get_urltest_selection("trial-parent").as_deref(),
                Some("trial-sub-t")
            );
        } else {
            assert_eq!(
                manager.get_fallback_selection("trial-parent").as_deref(),
                Some("trial-sub-t")
            );
        }

        #[cfg(feature = "flow-observation")]
        {
            use crate::group::observation::ObservedMember;
            let root = &plan.observation.as_ref().unwrap().decisions[0];
            let s_row = root
                .candidates
                .iter()
                .find(|row| {
                    row.member
                        == ObservedMember::Group {
                            name: "trial-sub-s".into(),
                        }
                })
                .unwrap();
            assert_eq!(s_row.eligible, Some(false));
            assert!(!s_row.selected);
            assert_eq!(s_row.reason, "capability_or_health_unavailable");
            if !cold_sibling {
                assert_eq!(
                    root.selected_member,
                    Some(ObservedMember::Group {
                        name: "trial-sub-t".into()
                    })
                );
            }
        }
        plan.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
    }
}
