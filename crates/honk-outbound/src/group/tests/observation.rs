use super::*;
use crate::group::observation::ObservedMember;
use crate::runtime::flow_observation::{FlowContext, FlowObserver};

fn observer() -> FlowObserver {
    FlowObserver::new(
        FlowContext {
            flow_id: uuid::Uuid::new_v4(),
            generation: 1,
            attempt_id: None,
            lookup_id: None,
            dns_purpose: "business",
        },
        Arc::new(|_, _| {}),
    )
}

fn context(network: SelectionNetwork, family: IpVersion) -> ScoreSelectionContext {
    ScoreSelectionContext::aggregate(
        network,
        match network {
            SelectionNetwork::Tcp => ProbeDomain::Tcp,
            SelectionNetwork::Udp => ProbeDomain::DataUdp,
        },
        family,
    )
}

fn member_id(member: &Option<ObservedMember>) -> Option<uuid::Uuid> {
    match member {
        Some(ObservedMember::Node { id, .. }) => Some(*id),
        _ => None,
    }
}

#[test]
fn capture_preserves_policy_choices_and_score_budgets() {
    let nodes = [make_node(nid("a"), "a"), make_node(nid("b"), "b")];
    let context = context(SelectionNetwork::Tcp, IpVersion::V4);
    for policy in [
        GroupPolicy::Selector,
        GroupPolicy::URLTest,
        GroupPolicy::LoadBalance,
        GroupPolicy::Fallback,
        GroupPolicy::Score,
    ] {
        let group = make_group("g", policy, nodes.iter().map(|node| node.id).collect());
        let plain = GroupManager::new(std::slice::from_ref(&group), &nodes);
        let recorded = GroupManager::new(&[group], &nodes);
        plain.publish_score_membership();
        recorded.publish_score_membership();
        for _ in 0..12 {
            let expected = plain.selection_plan_for_target("g", &context);
            let actual =
                observer().sync_scope(|| recorded.selection_plan_for_target("g", &context));
            assert!(expected.observation.is_none());
            assert_eq!(actual.mode, expected.mode);
            assert_eq!(
                actual
                    .entries
                    .iter()
                    .map(|entry| entry.node.id)
                    .collect::<Vec<_>>(),
                expected
                    .entries
                    .iter()
                    .map(|entry| entry.node.id)
                    .collect::<Vec<_>>()
            );
            let facts = actual.observation.unwrap();
            let decision = &facts.decisions[0];
            assert_eq!(
                decision
                    .candidates
                    .iter()
                    .map(|row| row.leaf_node_id)
                    .collect::<Vec<_>>(),
                [Some(nodes[0].id), Some(nodes[1].id)]
            );
            if actual.mode == SelectionPlanMode::ColdUrlTest {
                assert!(decision.selected_member.is_none());
                assert!(decision.candidates.iter().all(|row| !row.selected));
            } else {
                assert_eq!(
                    member_id(&decision.selected_member),
                    Some(actual.entries[0].node.id)
                );
                assert_eq!(
                    decision
                        .candidates
                        .iter()
                        .filter(|row| row.selected)
                        .count(),
                    1
                );
            }
            if policy == GroupPolicy::Score {
                assert!(
                    decision
                        .candidates
                        .iter()
                        .all(|row| row.score.is_some_and(f64::is_finite))
                );
            }
        }
        assert_eq!(
            plain.score_reason_snapshot(),
            recorded.score_reason_snapshot()
        );
        assert_eq!(
            plain.score_verification_counters("g", SelectionNetwork::Tcp),
            recorded.score_verification_counters("g", SelectionNetwork::Tcp)
        );
    }
}

#[test]
fn urltest_freezes_actual_latency_tolerance_and_previous_member() {
    let nodes = [make_node(nid("a"), "a"), make_node(nid("b"), "b")];
    let group = make_group(
        "g",
        GroupPolicy::URLTest,
        nodes.iter().map(|node| node.id).collect(),
    );
    let alive = Arc::new(AliveDialerSet::new());
    alive.record_probe_latency(
        nodes[0].id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    alive.record_probe_latency(
        nodes[1].id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(80),
    );
    let manager = GroupManager::with_alive_set(&[group], &nodes, Some(Arc::clone(&alive)));
    let context = context(SelectionNetwork::Tcp, IpVersion::V4);
    assert_eq!(
        manager.selection_plan_for_target("g", &context).entries[0]
            .node
            .id,
        nodes[0].id
    );
    alive.record_probe_latency(
        nodes[0].id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(190),
    );
    let plan = observer().sync_scope(|| manager.selection_plan_for_target("g", &context));
    let facts = plan.observation.unwrap();
    let decision = &facts.decisions[0];
    assert_eq!(decision.reason, "tolerance_held");
    assert_eq!(decision.tolerance_ms, Some(50.0));
    assert_eq!(member_id(&decision.previous_member), Some(nodes[0].id));
    assert_eq!(
        decision
            .candidates
            .iter()
            .map(|row| row.sorting_latency_ms)
            .collect::<Vec<_>>(),
        [Some(100.0), Some(80.0)]
    );
    alive.report_unavailable_forced(nodes[0].id, ProbeDomain::Tcp, IpVersion::V4);
    let replacement = observer().sync_scope(|| manager.selection_plan_for_target("g", &context));
    assert_eq!(replacement.entries[0].node.id, nodes[1].id);
    assert_eq!(
        member_id(&replacement.observation.unwrap().decisions[0].previous_member),
        Some(nodes[0].id)
    );
    assert_eq!(member_id(&decision.selected_member), Some(nodes[0].id));
    assert_eq!(decision.candidates[0].eligible, Some(true));
    assert_eq!(decision.candidates[0].sorting_latency_ms, Some(100.0));
}

#[test]
fn score_previous_leaf_is_not_reconstructed_as_a_subgroup_member() {
    let nodes = [make_node(nid("a"), "a"), make_node(nid("b"), "b")];
    let left = make_group("left", GroupPolicy::Selector, vec![nodes[0].id]);
    let right = make_group("right", GroupPolicy::Selector, vec![nodes[1].id]);
    let shared_left = make_group("shared-left", GroupPolicy::Selector, vec![nodes[0].id]);
    let shared_right = make_group("shared-right", GroupPolicy::Selector, vec![nodes[1].id]);
    for members in [
        vec!["left", "right"],
        vec!["left", "shared-left", "right", "shared-right"],
    ] {
        let root = make_subgroup("root", GroupPolicy::Score, &members);
        let manager = GroupManager::new(
            &[
                left.clone(),
                right.clone(),
                shared_left.clone(),
                shared_right.clone(),
                root,
            ],
            &nodes,
        );
        manager.publish_score_membership();
        let context = ScoreSelectionContext {
            target: Some(ScoreTarget::domain("business.test", 443)),
            target_family: Some(IpVersion::V4),
            ..context(SelectionNetwork::Tcp, IpVersion::V4)
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
        let previous = manager.selection_plan_for_target("root", &context).entries[0]
            .node
            .id;
        let plan = observer().sync_scope(|| manager.selection_plan_for_target("root", &context));
        let facts = plan.observation.unwrap();
        let decision = facts
            .decisions
            .iter()
            .find(|decision| decision.group_name == "root" && decision.applied)
            .unwrap();
        assert_eq!(decision.previous_leaf_node_id, Some(previous));
        assert!(decision.previous_member.is_none());
        assert!(
            decision
                .candidates
                .iter()
                .all(|candidate| matches!(candidate.member, ObservedMember::Group { .. }))
        );
    }
}

#[test]
fn score_does_not_attach_utility_to_a_health_filtered_alias() {
    let node = make_node(nid("shared"), "shared");
    let blocked = make_group("blocked", GroupPolicy::Selector, vec![node.id]);
    let serving = make_group("serving", GroupPolicy::Selector, vec![node.id]);
    let mut root = make_subgroup("root", GroupPolicy::Score, &["blocked", "serving"]);
    let url = "http://probe.example/";
    root.check_url = Some(url.into());
    let alive = Arc::new(AliveDialerSet::new());
    alive.sync_group_check_urls(&[("root".into(), url.into())]);
    for _ in 0..3 {
        alive.record_url_probe_failure("blocked", url);
    }
    let manager = GroupManager::with_alive_set(&[blocked, serving, root], &[node], Some(alive));
    manager.publish_score_membership();
    let plan = observer().sync_scope(|| {
        manager.selection_plan_for_target("root", &context(SelectionNetwork::Tcp, IpVersion::V4))
    });
    let facts = plan.observation.unwrap();
    let decision = facts
        .decisions
        .iter()
        .find(|decision| decision.group_name == "root")
        .unwrap();
    assert_eq!(
        decision.selected_member,
        Some(ObservedMember::Group {
            name: "serving".into()
        })
    );
    let excluded = decision
        .candidates
        .iter()
        .find(|row| {
            row.member
                == ObservedMember::Group {
                    name: "blocked".into(),
                }
        })
        .unwrap();
    assert_eq!(excluded.eligible, Some(false));
    assert!(!excluded.selected);
    assert_eq!(excluded.score, None);
    assert_eq!(excluded.reason, "custom_url_unavailable");
    let selected = decision.candidates.iter().find(|row| row.selected).unwrap();
    assert_eq!(selected.eligible, Some(true));
    assert!(selected.score.is_some_and(f64::is_finite));
}

#[test]
fn selected_subgroup_empty_members_and_final_selection_remain_distinct() {
    let nodes = [make_node(nid("a"), "a"), make_node(nid("b"), "b")];
    let chosen = make_group("chosen", GroupPolicy::Score, vec![nodes[0].id, nodes[1].id]);
    let unused = make_group("unused", GroupPolicy::Score, vec![nodes[1].id]);
    let empty = make_group("empty", GroupPolicy::Selector, vec![]);
    let mut root = make_subgroup(
        "root",
        GroupPolicy::Selector,
        &["empty", "chosen", "unused"],
    );
    root.default = Some("chosen".into());
    let mut final_root = make_subgroup("final-root", GroupPolicy::Selector, &["empty"]);
    final_root.final_outbound = Some("chosen".into());
    let manager = GroupManager::new(&[chosen, unused, empty, root, final_root], &nodes);
    let context = context(SelectionNetwork::Tcp, IpVersion::V4);
    let plan = observer().sync_scope(|| manager.selection_plan_for_target("root", &context));
    let facts = plan.observation.unwrap();
    assert!(
        facts
            .decisions
            .iter()
            .all(|decision| decision.group_name != "chosen" || decision.applied)
    );
    assert!(
        facts
            .decisions
            .iter()
            .any(|decision| decision.group_name == "chosen" && decision.applied)
    );
    assert!(
        facts
            .decisions
            .iter()
            .all(|decision| !matches!(decision.group_name.as_str(), "unused" | "empty"))
    );
    assert_eq!(
        facts.decisions[0].selected_member,
        Some(ObservedMember::Group {
            name: "chosen".into()
        })
    );
    let plan = observer().sync_scope(|| manager.selection_plan_for_target("empty", &context));
    assert!(plan.entries.is_empty());
    assert_eq!(
        plan.observation.unwrap().decisions[0].reason,
        "no_eligible_candidate"
    );
    let plan = observer().sync_scope(|| manager.selection_plan_for_target("final-root", &context));
    assert_eq!(plan.entries[0].final_owners, ["final-root"]);
    let facts = plan.observation.unwrap();
    assert_eq!(facts.decisions[0].reason, "final_selected");
    assert!(
        facts.decisions[0]
            .candidates
            .iter()
            .any(|row| row.reason == "empty_member"
                && row.eligible == Some(false)
                && row.leaf_node_id.is_none())
    );
    assert_eq!(
        facts.decisions[0].selected_member,
        Some(ObservedMember::Group {
            name: "chosen".into()
        })
    );
}

#[test]
fn rejected_family_and_final_preflight_survive_ipv4_fallback() {
    let nodes = [make_node(nid("a"), "a"), make_node(nid("b"), "b")];
    let mut group = make_group("g", GroupPolicy::Selector, vec![nodes[0].id, nodes[1].id]);
    group.final_outbound = Some("block".into());
    let alive = Arc::new(AliveDialerSet::new());
    for node in &nodes {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_unavailable_forced(node.id, domain, IpVersion::V6);
        }
    }
    let manager = GroupManager::with_alive_set(&[group], &nodes, Some(alive));
    let context = context(SelectionNetwork::Udp, IpVersion::V6);
    let plan = observer()
        .sync_scope(|| manager.selection_plan_for_target_with_health_fallback("g", &context, None));
    assert_eq!(plan.health_family, IpVersion::V4);
    assert_eq!(plan.entries[0].node.id, nodes[0].id);
    let facts = plan.observation.unwrap();
    assert_eq!(
        facts
            .decisions
            .iter()
            .map(|decision| (decision.health_family, decision.applied))
            .collect::<Vec<_>>(),
        [
            (IpVersion::V6, true),
            (IpVersion::V4, false),
            (IpVersion::V4, true)
        ]
    );
    assert_eq!(facts.decisions[0].reason, "health_family_fallback");
    assert!(
        facts.decisions[0]
            .candidates
            .iter()
            .all(|row| row.eligible == Some(false))
    );
    assert!(facts.decisions[0].selected_member.is_none());
    assert_eq!(
        member_id(&facts.decisions[2].selected_member),
        Some(nodes[0].id)
    );
}

#[test]
fn fallback_reports_dead_incumbent_without_reconstructing_it_after_mutation() {
    let nodes = [make_node(nid("a"), "a"), make_node(nid("b"), "b")];
    let group = make_group(
        "g",
        GroupPolicy::Fallback,
        nodes.iter().map(|node| node.id).collect(),
    );
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(&[group], &nodes, Some(Arc::clone(&alive)));
    let context = context(SelectionNetwork::Tcp, IpVersion::V4);
    assert_eq!(
        manager.selection_plan_for_target("g", &context).entries[0]
            .node
            .id,
        nodes[0].id
    );
    alive.report_unavailable_forced(nodes[0].id, ProbeDomain::Tcp, IpVersion::V4);
    let plan = observer().sync_scope(|| manager.selection_plan_for_target("g", &context));
    let facts = plan.observation.unwrap();
    let decision = &facts.decisions[0];
    assert_eq!(member_id(&decision.previous_member), Some(nodes[0].id));
    assert_eq!(member_id(&decision.selected_member), Some(nodes[1].id));
    assert_eq!(decision.candidates[0].eligible, Some(false));
    assert_eq!(decision.reason, "first_alive");
    let later = observer().sync_scope(|| manager.selection_plan_for_target("g", &context));
    assert_eq!(
        later.observation.unwrap().decisions[0].reason,
        "pinned_alive"
    );
    assert_eq!(member_id(&decision.previous_member), Some(nodes[0].id));
}

#[test]
fn whole_plan_capture_caps_do_not_change_uncaptured_winner() {
    let nodes: Vec<_> = (0..350)
        .map(|index| {
            let name = format!("node-{index}");
            make_node(nid(&name), &name)
        })
        .collect();
    let mut groups: Vec<_> = (0..70)
        .map(|index| {
            make_group(
                &format!("child-{index}"),
                GroupPolicy::Selector,
                nodes[index * 5..index * 5 + 5]
                    .iter()
                    .map(|node| node.id)
                    .collect(),
            )
        })
        .collect();
    let mut root = make_group("root", GroupPolicy::Fallback, vec![]);
    root.groups = groups
        .iter()
        .rev()
        .map(|group| group.name.clone())
        .collect();
    groups.push(root);
    let manager = GroupManager::new(&groups, &nodes);
    let context = context(SelectionNetwork::Tcp, IpVersion::V4);
    let plain = manager.selection_plan_for_target("root", &context);
    let plan = observer().sync_scope(|| manager.selection_plan_for_target("root", &context));
    assert_eq!(plan.entries[0].node.id, nodes[345].id);
    assert_eq!(
        plan.entries[0].selection_chain,
        plain.entries[0].selection_chain
    );
    let facts = plan.observation.unwrap();
    assert!(facts.truncated);
    assert_eq!(facts.decisions.len(), 64);
    assert_eq!(
        facts
            .decisions
            .iter()
            .map(|decision| decision.candidates.len())
            .sum::<usize>(),
        256
    );
    assert_eq!(
        facts.decisions[0].selected_member,
        Some(ObservedMember::Group {
            name: "child-69".into()
        })
    );
}

#[test]
fn unsafe_display_names_are_omitted_without_changing_node_identity() {
    let nodes = [
        make_node(nid("long"), &"x".repeat(513)),
        make_node(nid("unsafe"), "private/user@host"),
    ];
    let group = make_group(
        "g",
        GroupPolicy::Selector,
        nodes.iter().map(|node| node.id).collect(),
    );
    let manager = GroupManager::new(&[group], &nodes);
    let context = context(SelectionNetwork::Tcp, IpVersion::V4);
    let plan = observer().sync_scope(|| manager.selection_plan_for_target("g", &context));
    let facts = plan.observation.unwrap();
    assert_eq!(
        facts.decisions[0].selected_member,
        Some(ObservedMember::Node {
            id: nodes[0].id,
            name: None
        })
    );
    assert!(
        facts.decisions[0]
            .candidates
            .iter()
            .all(|row| row.leaf_node_name.is_none()
                && matches!(row.member, ObservedMember::Node { name: None, .. }))
    );
    assert_eq!(plan.entries[0].node.id, nodes[0].id);
}

#[test]
fn retry_plan_keeps_evaluated_candidates_beyond_the_attempt_limit() {
    let nodes: Vec<_> = (0..4)
        .map(|index| {
            let name = format!("retry-{index}");
            make_node(nid(&name), &name)
        })
        .collect();
    let group = make_group(
        "g",
        GroupPolicy::URLTest,
        nodes.iter().map(|node| node.id).collect(),
    );
    let alive = Arc::new(AliveDialerSet::new());
    for (index, node) in nodes.iter().enumerate() {
        alive.record_probe_latency(
            node.id,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis((4 - index) as u64),
        );
    }
    let manager = GroupManager::with_alive_set(&[group], &nodes, Some(alive));
    let context = context(SelectionNetwork::Tcp, IpVersion::V4);
    let plan = observer().sync_scope(|| manager.urltest_retry_plan_for_target("g", &context, None));
    assert_eq!(
        plan.entries
            .iter()
            .map(|entry| entry.node.id)
            .collect::<Vec<_>>(),
        [nodes[3].id, nodes[2].id, nodes[1].id]
    );
    let facts = plan.observation.unwrap();
    let decision = &facts.decisions[0];
    assert!(!decision.applied);
    assert!(decision.selected_member.is_none());
    assert!(decision.candidates.iter().all(|row| !row.selected));
    assert_eq!(
        decision
            .candidates
            .iter()
            .map(|row| row.leaf_node_id)
            .collect::<Vec<_>>(),
        [
            Some(nodes[3].id),
            Some(nodes[2].id),
            Some(nodes[1].id),
            Some(nodes[0].id)
        ]
    );
    assert_eq!(
        decision
            .candidates
            .iter()
            .map(|row| row.sorting_latency_ms)
            .collect::<Vec<_>>(),
        [Some(1.0), Some(2.0), Some(3.0), Some(4.0)]
    );
}

#[test]
fn cold_final_reports_candidates_without_inventing_a_winner() {
    let nodes = [make_node(nid("a"), "a"), make_node(nid("b"), "b")];
    let cold = make_group(
        "cold",
        GroupPolicy::URLTest,
        nodes.iter().map(|node| node.id).collect(),
    );
    let mut root = make_group("root", GroupPolicy::Selector, vec![]);
    root.final_outbound = Some("cold".into());
    let manager = GroupManager::new(&[cold, root], &nodes);
    let context = context(SelectionNetwork::Udp, IpVersion::V4);
    let plan = observer().sync_scope(|| manager.selection_plan_for_target("root", &context));
    assert_eq!(plan.mode, SelectionPlanMode::ColdUrlTest);
    assert_eq!(
        plan.entries
            .iter()
            .map(|entry| entry.node.id)
            .collect::<Vec<_>>(),
        [nodes[0].id, nodes[1].id]
    );
    let facts = plan.observation.unwrap();
    assert_eq!(facts.decisions[0].reason, "final_candidates_pending");
    assert_eq!(facts.decisions[1].reason, "cold_candidates_pending");
    assert!(
        facts
            .decisions
            .iter()
            .all(|decision| decision.selected_member.is_none()
                && decision.candidates.iter().all(|row| !row.selected))
    );
}

#[test]
fn cached_tag_ambiguity_does_not_fabricate_a_previous_member_identity() {
    let nodes = [
        make_node(nid("left"), "same"),
        make_node(nid("right"), "same"),
    ];
    let group = make_group(
        "g",
        GroupPolicy::Fallback,
        nodes.iter().map(|node| node.id).collect(),
    );
    let manager = GroupManager::new(&[group], &nodes);
    let context = context(SelectionNetwork::Tcp, IpVersion::V4);
    let original = manager.selection_plan_for_target("g", &context);
    let plan = observer().sync_scope(|| manager.selection_plan_for_target("g", &context));
    assert_eq!(plan.entries[0].node.id, original.entries[0].node.id);
    let facts = plan.observation.unwrap();
    assert!(facts.truncated);
    assert!(facts.decisions[0].previous_member.is_none());
    assert_eq!(
        member_id(&facts.decisions[0].selected_member),
        Some(nodes[0].id)
    );
}
