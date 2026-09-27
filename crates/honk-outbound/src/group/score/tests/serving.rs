use super::*;
use std::collections::BTreeSet;

fn members(count: usize) -> Vec<Node> {
    let mut nodes: Vec<_> = (0..count)
        .map(|index| node(&format!("serving-{index}")))
        .collect();
    nodes.sort_by_key(|node| node.id);
    nodes
}

fn committed_ids(manager: &GroupManager, group: &str, nodes: &[Node]) -> BTreeSet<Uuid> {
    let state = manager.score_state();
    let inner = state.inner.lock();
    let set = inner.evaluation(group, SelectionNetwork::Tcp).unwrap();
    nodes
        .iter()
        .filter(|node| set.evaluates(node.id))
        .map(|node| node.id)
        .collect()
}

fn seed_target(
    manager: &GroupManager,
    group: &str,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    preferred: Option<Uuid>,
    now: Instant,
) {
    let state = manager.score_state();
    let mut inner = state.inner.lock();
    for node in nodes {
        inner.aggregate.put(
            AggregateKey {
                group: group.into(),
                network: target.network,
                family: None,
                node_id: node.id,
            },
            trained_stats(16.0, 200.0, now),
        );
        inner.exact.put(
            ExactKey {
                group: group.into(),
                network: target.network,
                family: target.target_family.unwrap(),
                target: target.target.clone().unwrap(),
                node_id: node.id,
            },
            trained_stats(
                16.0,
                if preferred == Some(node.id) {
                    1.0
                } else {
                    200.0
                },
                now,
            ),
        );
    }
}

#[test]
fn selector_routes_and_target_favorites_share_one_serving_pool() {
    let nodes = members(12);
    let manager = GroupManager::new(
        &[
            group("wind", &nodes),
            selector_with_children("proxy", &[], &["wind"]),
            selector_with_children("google", &[], &["proxy"]),
            selector_with_children("final", &[], &["proxy"]),
        ],
        &nodes,
    );
    let target = context("initialize.example", IpVersion::V4);
    seed_target(&manager, "wind", &nodes, &target, None, Instant::now());
    drop(manager.selection_plan_for_target("google", &target));
    let pool = committed_ids(&manager, "wind", &nodes);
    assert_eq!(pool.len(), 3);
    let outside: Vec<_> = nodes
        .iter()
        .filter(|node| !pool.contains(&node.id))
        .collect();
    let mut served = BTreeSet::new();
    for index in 0..24 {
        let route = if index % 2 == 0 { "google" } else { "final" };
        let target = context(&format!("target-{index}.example"), IpVersion::V4);
        seed_target(
            &manager,
            "wind",
            &nodes,
            &target,
            Some(outside[index % outside.len()].id),
            Instant::now(),
        );
        let plan = manager.selection_plan_for_target(route, &target);
        let entry = &plan.entries[0];
        assert!(
            pool.contains(&entry.node.id),
            "{route} escaped the shared pool"
        );
        assert_eq!(
            entry.selection_chain,
            [route, "proxy", "wind", entry.node.name.as_str()]
        );
        entry
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
        served.insert(entry.node.id);
        assert_eq!(committed_ids(&manager, "wind", &nodes), pool);
    }
    assert!(served.len() <= pool.len());
    let counts = manager.score_budget_counters("wind", SelectionNetwork::Tcp);
    assert_eq!(
        (counts.business_starts, counts.trial_starts, counts.reserved),
        (24, 0, 0)
    );
    assert_eq!(manager.score_state().root_business_starts(), 24);
}

#[test]
fn cold_first_selection_cannot_escape_the_committed_pool() {
    let mut nodes = members(8);
    nodes.reverse();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("cold.example", IpVersion::V4);
    let plan = manager.selection_plan_for_target("score", &target);
    let pool = committed_ids(&manager, "score", &nodes);
    assert_eq!(pool.len(), 3);
    assert!(pool.contains(&plan.entries[0].node.id));
    assert_eq!(
        plan.entries[0].node.id, nodes[0].id,
        "bootstrap keeps the ordinary first choice inside its pool"
    );
    plan.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(
        (counts.business_starts, counts.trial_starts, counts.reserved),
        (1, 0, 0)
    );
    assert_eq!(manager.score_state().root_business_starts(), 1);
}

#[test]
fn failed_and_ineligible_incumbents_escape_only_within_the_pool() {
    let nodes = members(8);
    for fail_streak in [1, SCORE_FAIL_STREAK_EXCLUDE] {
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("escape.example", IpVersion::V4);
        seed_target(&manager, "score", &nodes, &target, None, Instant::now());
        let first = manager.selection_plan_for_target("score", &target);
        let incumbent = first.entries[0].node.id;
        first.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
        let pool = committed_ids(&manager, "score", &nodes);
        let outside = nodes.iter().find(|node| !pool.contains(&node.id)).unwrap();
        seed_target(
            &manager,
            "score",
            &nodes,
            &target,
            Some(outside.id),
            Instant::now(),
        );
        let alternative = pool
            .iter()
            .copied()
            .find(|node| *node != incumbent)
            .unwrap();
        manager.score_state().inner.lock().exact.put(
            ExactKey {
                group: "score".into(),
                network: target.network,
                family: target.target_family.unwrap(),
                target: target.target.clone().unwrap(),
                node_id: alternative,
            },
            trained_stats(16.0, 50.0, Instant::now()),
        );
        manager
            .score_state()
            .inner
            .lock()
            .exact
            .get_mut(&ExactKey {
                group: "score".into(),
                network: target.network,
                family: target.target_family.unwrap(),
                target: target.target.clone().unwrap(),
                node_id: incumbent,
            })
            .unwrap()
            .fail_streak = fail_streak;
        let escaped = manager.selection_plan_for_target("score", &target);
        assert_ne!(escaped.entries[0].node.id, incumbent);
        assert!(
            pool.contains(&escaped.entries[0].node.id),
            "streak {fail_streak}"
        );
        escaped.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
        assert_eq!(committed_ids(&manager, "score", &nodes), pool);
        let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(
            (counts.business_starts, counts.trial_starts, counts.reserved),
            (2, 0, 0)
        );
        assert_eq!(manager.score_state().root_business_starts(), 2);
    }
}

#[test]
fn readonly_evaluated_count_cannot_add_an_outside_target_winner() {
    let nodes = members(8);
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let initial = context("initialize.example", IpVersion::V4);
    seed_target(&manager, "score", &nodes, &initial, None, Instant::now());
    drop(manager.selection_plan_for_target("score", &initial));
    let pool = committed_ids(&manager, "score", &nodes);
    let outside = nodes.iter().find(|node| !pool.contains(&node.id)).unwrap();
    let target = context("readonly.example", IpVersion::V4);
    let now = Instant::now();
    seed_target(&manager, "score", &nodes, &target, Some(outside.id), now);
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    let snapshot = manager
        .score_state()
        .verification_snapshot_at("score", &target, &nodes.iter().collect::<Vec<_>>(), now)
        .unwrap();
    assert_eq!(snapshot.candidate_count, nodes.len());
    assert_eq!(snapshot.evaluated_count, pool.len());
    assert_eq!(committed_ids(&manager, "score", &nodes), pool);
    assert_eq!(
        manager.score_budget_counters("score", SelectionNetwork::Tcp),
        before
    );
    assert_eq!(manager.score_state().root_business_starts(), 0);
}

#[test]
fn nested_score_trials_replace_representatives_without_refund_starvation() {
    let nodes = members(6);
    let manager = GroupManager::new(
        &[
            group("child", &nodes),
            group_with_children("score", &[], &["child"]),
        ],
        &nodes,
    );
    let mut served = BTreeSet::new();
    for index in 0..8 {
        let target = context(&format!("nested-{index}.example"), IpVersion::V4);
        let plan = manager.selection_plan_for_target("score", &target);
        let entry = plan
            .entries
            .first()
            .expect("a changed child still serves its parent");
        let parent_pool = committed_ids(&manager, "score", &nodes);
        assert_eq!(parent_pool, BTreeSet::from([entry.node.id]));
        let child_pool = committed_ids(&manager, "child", &nodes);
        assert_eq!(child_pool.len(), 3);
        assert!(child_pool.contains(&entry.node.id));
        served.insert(entry.node.id);
        finish_success(&plan);
        for group in ["score", "child"] {
            let counts = manager.score_budget_counters(group, SelectionNetwork::Tcp);
            assert_eq!(counts.business_starts, index + 1);
            assert_eq!((counts.reserved, counts.refunded), (0, 0));
        }
        assert_eq!(manager.score_state().root_business_starts(), index + 1);
    }
    let child = manager.score_budget_counters("child", SelectionNetwork::Tcp);
    assert!(child.cold_trial_starts > 0);
    assert!(
        served.len() > 1,
        "the child must actually change its representative"
    );
    assert!(served.len() <= 3);
    assert_eq!(child.spent, child.trial_starts);
}

#[test]
fn selector_applies_its_chosen_subgroup_when_committed_peek_is_empty() {
    let nodes = [node("first"), node("second"), node("outside")];
    let mut outer = selector_with_children("outer", &nodes[2..], &["score"]);
    outer.default = Some("score".into());
    let manager = GroupManager::new(
        &[
            selector_with_children("choice", &nodes[..2], &[]),
            group_with_children("score", &[], &["choice"]),
            outer,
        ],
        &nodes,
    );
    let target = context("selector.example", IpVersion::V4);
    let first = manager.selection_plan_for_target("outer", &target);
    assert_eq!(first.entries[0].node.id, nodes[0].id);
    first.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    manager.set_selector_choice("choice", &nodes[1].name);
    assert!(
        manager
            .get_score_selection_for_network("score", SelectionNetwork::Tcp)
            .is_none()
    );
    assert_eq!(
        committed_ids(&manager, "score", &nodes),
        BTreeSet::from([nodes[0].id])
    );
    let next = manager.selection_plan_for_target("outer", &target);
    let entry = next
        .entries
        .first()
        .expect("Selector must reach the chosen group's Apply");
    assert_eq!(entry.node.id, nodes[1].id);
    assert_eq!(
        entry.selection_chain,
        ["outer", "score", "choice", nodes[1].name.as_str()]
    );
    entry
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    assert_eq!(
        committed_ids(&manager, "score", &nodes),
        BTreeSet::from([nodes[1].id])
    );
    assert_eq!(manager.score_state().root_business_starts(), 2);
    let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(
        (counts.business_starts, counts.reserved, counts.refunded),
        (2, 0, 0)
    );
}

#[test]
fn representative_reconciliation_preserves_a_health_filtered_direct_leaf() {
    let nodes = [node("direct-leaf"), node("old-child"), node("new-child")];
    let alive = Arc::new(crate::alive::AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(
        &[
            selector_with_children("choice", &nodes[1..], &[]),
            group_with_children("score", &nodes[..1], &["choice"]),
        ],
        &nodes,
        Some(Arc::clone(&alive)),
    );
    let target = context("mixed.example", IpVersion::V4);
    drop(manager.selection_plan_for_target("score", &target));
    assert_eq!(
        committed_ids(&manager, "score", &nodes),
        BTreeSet::from([nodes[0].id, nodes[1].id])
    );
    alive.report_unavailable_forced(nodes[0].id, ProbeDomain::Tcp, IpVersion::V4);
    manager.set_selector_choice("choice", &nodes[2].name);
    let changed = manager.selection_plan_for_target("score", &target);
    assert_eq!(changed.entries[0].node.id, nodes[2].id);
    assert_eq!(
        committed_ids(&manager, "score", &nodes),
        BTreeSet::from([nodes[0].id, nodes[2].id]),
        "only the replaced subgroup representative leaves the pool"
    );
    changed.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    alive.report_available_traffic(nodes[0].id, ProbeDomain::Tcp, IpVersion::V4);
    alive.report_unavailable_forced(nodes[2].id, ProbeDomain::Tcp, IpVersion::V4);
    let restored = manager.selection_plan_for_target("score", &target);
    assert_eq!(restored.entries[0].node.id, nodes[0].id);
    restored.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(
        (counts.business_starts, counts.reserved, counts.refunded),
        (2, 0, 0)
    );
    assert_eq!(manager.score_state().root_business_starts(), 2);
}

#[test]
fn health_filtering_replaces_an_unavailable_pool_without_extra_slots() {
    let nodes = members(8);
    let alive = Arc::new(crate::alive::AliveDialerSet::new());
    let manager =
        GroupManager::with_alive_set(&[group("score", &nodes)], &nodes, Some(Arc::clone(&alive)));
    let target = context("health-recovery.example", IpVersion::V4);
    drop(manager.selection_plan_for_target("score", &target));
    let before = committed_ids(&manager, "score", &nodes);
    assert_eq!(before.len(), 3);
    for node in &before {
        alive.report_unavailable_forced(*node, ProbeDomain::Tcp, IpVersion::V4);
    }
    let plan = manager.selection_plan_for_target("score", &target);
    let entry = plan
        .entries
        .first()
        .expect("available replacements must keep serving");
    let after = committed_ids(&manager, "score", &nodes);
    assert_eq!(after.len(), before.len());
    assert!(after.is_disjoint(&before));
    assert!(after.contains(&entry.node.id));
    entry
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    assert_eq!(manager.score_state().root_business_starts(), 1);
}

#[test]
fn duplicate_group_uuids_do_not_alias_serving_slots() {
    let nodes = members(8);
    let kept = selector_with_children("kept", &nodes[..1], &[]);
    let mut outside = selector_with_children("outside", &nodes[6..], &[]);
    outside.id = kept.id;
    let manager = GroupManager::new(
        &[
            outside,
            kept,
            selector_with_children("second", &nodes[1..2], &[]),
            selector_with_children("third", &nodes[2..3], &[]),
            group_with_children("score", &[], &["outside", "kept", "second", "third"]),
        ],
        &nodes,
    );
    let target = context("member-identity.example", IpVersion::V4);
    seed_target(
        &manager,
        "score",
        &nodes,
        &target,
        Some(nodes[0].id),
        Instant::now(),
    );
    let pending = manager.selection_plan_for_target("score", &target);
    let before = committed_ids(&manager, "score", &nodes);
    assert_eq!(before, nodes[..3].iter().map(|node| node.id).collect());
    manager.set_selector_choice("outside", &nodes[7].name);
    drop(manager.selection_plan_for_target("score", &target));
    assert_eq!(committed_ids(&manager, "score", &nodes), before);
    pending.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    assert_eq!(manager.score_state().root_business_starts(), 1);
}

#[test]
fn an_ordinary_winner_survives_rotation_and_comparison_expiry() {
    let nodes = members(8);
    let refs: Vec<_> = nodes.iter().collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let start = Instant::now();
    let initial = context("initial.example", IpVersion::V4);
    seed_target(&manager, "score", &nodes, &initial, None, start);
    let (_, first) = state.rank_plan_at("score", &initial, &refs, start);
    first
        .begin_at(start)
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    let target = context("rotation-winner.example", IpVersion::V4);
    let selected_at = start + Duration::from_secs(1);
    seed_target(
        &manager,
        "score",
        &nodes,
        &target,
        Some(nodes[2].id),
        selected_at,
    );
    let (winner, attempt) = state.rank_plan_at("score", &target, &refs, selected_at);
    assert_eq!(nodes[winner].id, nodes[2].id);
    attempt
        .begin_at(selected_at)
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    let later = start + Duration::from_secs(602);
    let (winner, attempt) = state.rank_plan_at("score", &target, &refs, later);
    assert_eq!(
        nodes[winner].id, nodes[2].id,
        "rotation must not evict the ordinary winner"
    );
    attempt
        .begin_at(later)
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    assert_eq!(committed_ids(&manager, "score", &nodes).len(), 3);
}

fn withdrawn_children_are_replaced(change_choice: bool) {
    let nodes = members(8);
    let children: Vec<_> = (0..4)
        .map(|index| {
            selector_with_children(
                &format!("child-{index}"),
                &nodes[index * 2..index * 2 + 2],
                &[],
            )
        })
        .collect();
    let mut groups = vec![group_with_children(
        "score",
        &[],
        &children
            .iter()
            .map(|child| child.name.as_str())
            .collect::<Vec<_>>(),
    )];
    groups.extend(children);
    let alive = Arc::new(crate::alive::AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(&groups, &nodes, Some(Arc::clone(&alive)));
    let target = ScoreSelectionContext {
        network: SelectionNetwork::Udp,
        probe_domain: ProbeDomain::DataUdp,
        ..context("withdrawn.example", IpVersion::V4)
    };
    let pool = || {
        let state = manager.score_state();
        let inner = state.inner.lock();
        let set = inner.evaluation("score", target.network).unwrap();
        nodes
            .iter()
            .filter(|node| set.evaluates(node.id))
            .map(|node| node.id)
            .collect::<BTreeSet<_>>()
    };
    drop(manager.selection_plan_for_target("score", &target));
    let before = pool();
    assert_eq!(before.len(), 3);
    let mut survivor = None;
    for (index, pair) in nodes.as_chunks::<2>().0.iter().enumerate() {
        if before.contains(&pair[0].id) {
            let unavailable = &pair[usize::from(change_choice)];
            for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
                alive.report_unavailable_forced(unavailable.id, domain, IpVersion::V4);
            }
            if change_choice {
                manager.set_selector_choice(&format!("child-{index}"), &unavailable.name);
                assert!(manager.is_node_selectable_for_domain(
                    pair[0].id,
                    ProbeDomain::DataUdp,
                    IpVersion::V4
                ));
            }
        } else {
            survivor = Some(pair[0].id);
        }
    }
    let plan = manager.selection_plan_for_target("score", &target);
    let entry = plan
        .entries
        .first()
        .expect("a healthy child must replace withdrawn slots");
    assert_eq!(Some(entry.node.id), survivor);
    assert!(pool().contains(&entry.node.id));
    assert!(pool().len() <= before.len());
    entry
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    assert_eq!(manager.score_state().root_business_starts(), 1);
}

#[test]
fn nested_udp_health_withdrawal_replaces_serving_slots() {
    withdrawn_children_are_replaced(false);
}

#[test]
fn nested_selector_withdrawal_replaces_still_healthy_old_leaves() {
    withdrawn_children_are_replaced(true);
}

#[test]
fn ipv4_pool_reconciliation_precedes_explicit_final() {
    let nodes = members(8);
    let mut score = group("score", &nodes);
    score.final_outbound = Some("direct".into());
    let alive = Arc::new(crate::alive::AliveDialerSet::new());
    for (index, node) in nodes.iter().enumerate() {
        alive.report_unavailable_forced(
            node.id,
            ProbeDomain::Tcp,
            if index < 3 {
                IpVersion::V4
            } else {
                IpVersion::V6
            },
        );
    }
    let manager = GroupManager::with_alive_set(
        &[score, selector_with_children("outer", &[], &["score"])],
        &nodes,
        Some(Arc::clone(&alive)),
    );
    let target = ScoreSelectionContext {
        health_family: IpVersion::V6,
        ..context("ipv6.example", IpVersion::V6)
    };
    let first = manager.selection_plan_for_target_with_health_fallback("outer", &target, None);
    first.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    let before = committed_ids(&manager, "score", &nodes);
    assert_eq!(before.len(), 3);
    for id in &before {
        alive.report_unavailable_forced(*id, ProbeDomain::Tcp, IpVersion::V6);
    }
    let plan = manager.selection_plan_for_target_with_health_fallback("outer", &target, None);
    assert_eq!(
        plan.health_family,
        IpVersion::V4,
        "ordinary IPv4 proxies must precede final"
    );
    let entry = &plan.entries[0];
    assert!(nodes[3..].iter().any(|node| node.id == entry.node.id));
    assert_eq!(
        entry.selection_chain,
        ["outer", "score", entry.node.name.as_str()]
    );
    entry
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    let after = committed_ids(&manager, "score", &nodes);
    assert_eq!(after.len(), 3);
    assert!(after.is_disjoint(&before));
    let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(
        (counts.business_starts, counts.reserved, counts.trial_starts),
        (2, 0, 0)
    );
}

#[test]
fn pool_preflight_is_readonly_and_rejects_stale_authority() {
    use crate::group::SelectionEffects;
    let nodes = members(8);
    let groups = [group("score", &nodes)];
    let alive = Arc::new(crate::alive::AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(&groups, &nodes, Some(Arc::clone(&alive)));
    let target = context("preflight.example", IpVersion::V4);
    drop(manager.selection_plan_for_target("score", &target));
    let before = committed_ids(&manager, "score", &nodes);
    for id in &before {
        alive.report_unavailable_forced(*id, ProbeDomain::Tcp, IpVersion::V4);
    }
    let pick = |manager: &GroupManager, effects| {
        manager
            .pick_candidate_for_target(
                &manager.groups["score"],
                &target,
                &mut Vec::new(),
                0,
                effects,
                super::super::selection::ScoreSelectionRules::default(),
            )
            .map(|candidate| candidate.node.id)
    };
    let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    let reasons = manager.score_reason_snapshot();
    assert_eq!(pick(&manager, SelectionEffects::Peek), None);
    let prospective = pick(&manager, SelectionEffects::Preview).unwrap();
    assert!(!before.contains(&prospective));
    assert_eq!(committed_ids(&manager, "score", &nodes), before);
    assert_eq!(
        manager.score_budget_counters("score", SelectionNetwork::Tcp),
        counts
    );
    assert_eq!(manager.score_reason_snapshot(), reasons);
    assert_eq!(manager.score_state().root_business_starts(), 0);
    let replacement =
        GroupManager::with_alive_set_and_score_state(&groups, &nodes, None, manager.score_state());
    replacement.publish_score_membership();
    drop(replacement.selection_plan_for_target("score", &target));
    assert_eq!(committed_ids(&replacement, "score", &nodes), before);
    assert_eq!(pick(&manager, SelectionEffects::Preview), None);
    assert_eq!(committed_ids(&replacement, "score", &nodes), before);
    assert_eq!(replacement.score_state().root_business_starts(), 0);
}
