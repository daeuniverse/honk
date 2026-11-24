use super::super::evaluation::{self, EvaluationSet};
use super::*;

fn replace_pool(manager: &GroupManager, nodes: &[Node], departed: Uuid) {
    let refs: Vec<_> = nodes.iter().filter(|node| node.id != departed).collect();
    let scores = vec![ScoreSnapshot::default(); refs.len()];
    let set = evaluation::derive(
        None,
        &refs,
        &scores,
        Instant::now(),
        true,
        std::iter::empty(),
        |_| false,
    )
    .into_owned();
    assert!(!set.evaluates(departed));
    *manager
        .score_state()
        .inner
        .lock()
        .evaluation_mut("score", SelectionNetwork::Tcp) = set;
}

#[test]
fn pending_pool_departure_cancels_ordinary_and_refunds_trial_without_business() {
    for trial in [false, true] {
        let nodes = [node("a"), node("b")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        if trial {
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
        }
        let target = context("departure.example", IpVersion::V4);
        let plan = manager.selection_plan_for_target("score", &target);
        let attempt = plan.entries[0].feedback.as_ref().unwrap().clone();
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(before.reserved, u64::from(trial));
        replace_pool(&manager, &nodes, plan.entries[0].node.id);
        for pending in [attempt.clone(), attempt] {
            assert!(matches!(
                pending.begin(),
                Err(crate::proxy::PacketRejection::Cancelled)
            ));
            assert!(pending.continuation().is_err());
        }
        let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(
            (after.business_starts, after.spent, after.reserved),
            (0, 0, 0)
        );
        assert_eq!(after.refunded - before.refunded, u64::from(trial));
        assert_eq!(
            after.cold_available,
            before.cold_available + u64::from(trial)
        );
        assert_eq!(manager.score_state().root_business_starts(), 0);
        assert!(
            !manager
                .score_state()
                .has_exact("score", &target, plan.entries[0].node.id)
        );
    }
}

#[test]
fn pending_ordinary_requires_initialized_pool_even_after_reload() {
    for reload in [false, true] {
        let nodes = [node("a"), node("b")];
        let config = group("score", &nodes);
        let manager = GroupManager::new(std::slice::from_ref(&config), &nodes);
        let target = context("uninitialized.example", IpVersion::V4);
        let plan = manager.selection_plan_for_target("score", &target);
        let state = manager.score_state();
        let _replacement = reload.then(|| {
            let replacement = GroupManager::with_alive_set_and_score_state(
                std::slice::from_ref(&config),
                &nodes,
                None,
                Arc::clone(&state),
            );
            replacement.publish_score_membership();
            replacement
        });
        *state
            .inner
            .lock()
            .evaluation_mut("score", SelectionNetwork::Tcp) = EvaluationSet::default();
        assert!(matches!(
            plan.entries[0].feedback.as_ref().unwrap().begin(),
            Err(crate::proxy::PacketRejection::Cancelled)
        ));
        assert_eq!(state.root_business_starts(), 0);
    }
}

#[test]
fn begun_flow_settles_after_pool_departure_and_reload() {
    for reload in [false, true] {
        let nodes = [node("a"), node("b")];
        let config = group("score", &nodes);
        let manager = GroupManager::new(std::slice::from_ref(&config), &nodes);
        let target = context("begun.example", IpVersion::V4);
        let plan = manager.selection_plan_for_target("score", &target);
        let leaf = plan.entries[0].node.id;
        let pending = manager.selection_plan_for_target("score", &target);
        assert_eq!(pending.entries[0].node.id, leaf);
        let attempt = plan.entries[0].feedback.as_ref().unwrap();
        let now = Instant::now();
        let guard = attempt.begin_at(now).unwrap();
        replace_pool(&manager, &nodes, leaf);
        assert!(matches!(
            pending.entries[0].feedback.as_ref().unwrap().begin(),
            Err(crate::proxy::PacketRejection::Cancelled)
        ));
        let reporter = guard.start_at(now);
        let state = manager.score_state();
        let _replacement = reload.then(|| {
            let replacement = GroupManager::with_alive_set_and_score_state(
                std::slice::from_ref(&config),
                &nodes,
                None,
                Arc::clone(&state),
            );
            replacement.publish_score_membership();
            replacement
        });
        reporter.setup_succeeded_at(now);
        reporter.transfer_at(1, 1, now + Duration::from_millis(1));
        reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_millis(2));
        assert_eq!(state.exact_stats("score", &target, leaf), Some((1, 0)));
        assert_eq!(state.root_business_starts(), 1);
    }
}

#[test]
fn final_owner_is_exempt_but_ordinary_score_ancestor_is_not() {
    let nodes = [node("backup")];
    let mut child = group("child", &[]);
    child.final_outbound = Some("backup".into());
    let outer = group_with_children("score", &[], &["child"]);
    let manager = GroupManager::new(&[outer, child], &nodes);
    let target = context("final.example", IpVersion::V4);
    let direct = manager.selection_plan_for_target("child", &target);
    assert_eq!(direct.entries[0].node.id, nodes[0].id);
    let owner_key = SelectionReasonKey::new("child", SelectionNetwork::Tcp);
    *manager
        .score_state()
        .inner
        .lock()
        .evaluation_mut(&owner_key.group, owner_key.network) = EvaluationSet::default();
    direct.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);

    let nested = manager.selection_plan_for_target("score", &target);
    assert_eq!(nested.entries[0].node.id, nodes[0].id);
    *manager
        .score_state()
        .inner
        .lock()
        .evaluation_mut(&owner_key.group, owner_key.network) = EvaluationSet::default();
    nested.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);

    let pending = manager.selection_plan_for_target("score", &target);
    *manager
        .score_state()
        .inner
        .lock()
        .evaluation_mut("score", SelectionNetwork::Tcp) = EvaluationSet::default();
    let before = manager.score_state().root_business_starts();
    assert!(matches!(
        pending.entries[0].feedback.as_ref().unwrap().begin(),
        Err(crate::proxy::PacketRejection::Cancelled)
    ));
    assert_eq!(manager.score_state().root_business_starts(), before);
}

#[test]
fn related_context_requires_its_networks_committed_pool() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("network.example", IpVersion::V4);
    let plan = manager.selection_plan_for_target("score", &target);
    let attempt = plan.entries[0].feedback.as_ref().unwrap().clone();
    attempt.begin().unwrap().finish(ScoreOutcome::Cancelled);
    let mut udp = target;
    udp.network = SelectionNetwork::Udp;
    udp.probe_domain = ProbeDomain::DataUdp;
    let related = attempt.clone().with_context(udp.clone()).unwrap();
    assert!(matches!(
        related.begin(),
        Err(crate::proxy::PacketRejection::Cancelled)
    ));
    assert_eq!(manager.score_state().root_business_starts(), 1);
    let udp_plan = manager.selection_plan_for_target("score", &udp);
    drop(udp_plan);
    attempt
        .with_context(udp)
        .unwrap()
        .begin()
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    assert_eq!(manager.score_state().root_business_starts(), 1);
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Udp)
            .recovery_starts,
        1
    );
}

fn packet_score_fixture() -> (Node, Node) {
    (
        node("front"),
        Node {
            outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
            ..node("land")
        },
    )
}

#[test]
fn packet_dns_cannot_replace_an_ordinary_subgroup_representative() {
    let (front, land) = packet_score_fixture();
    let child = Group {
        policy: GroupPolicy::Fallback,
        exit: Some(land.name.clone()),
        ..group("child", &[front.clone(), land.clone()])
    };
    let parent = Group {
        final_outbound: Some("block".into()),
        ..group_with_children("score", &[], &["child"])
    };
    let manager = GroupManager::new(&[child, parent], &[front.clone(), land.clone()]);
    let ordinary = ScoreSelectionContext::aggregate(
        SelectionNetwork::Udp,
        ProbeDomain::DataUdp,
        IpVersion::V4,
    );
    let ordinary_plan = manager.selection_plan_for_target("score", &ordinary);
    assert_eq!(ordinary_plan.entries[0].node.id, front.id);
    let held = ordinary_plan.entries[0].feedback.as_ref().unwrap();
    let reasons = manager.score_reason_snapshot();
    let budget = manager.score_budget_counters("score", SelectionNetwork::Udp);
    let packet = ScoreSelectionContext {
        target: Some(ScoreTarget::domain("dns.example", 853)),
        target_family: Some(IpVersion::V4),
        ..ordinary
    };
    let (plan, _) = manager.node_packet_dial_plan("score", &packet, None);
    assert_eq!(plan.entries[0].node.id, honk_config::config::BLOCK_NODE_ID);
    assert_eq!(manager.score_reason_snapshot(), reasons);
    assert_eq!(
        manager.score_budget_counters("score", SelectionNetwork::Udp),
        budget
    );
    held.begin().unwrap().finish(ScoreOutcome::Cancelled);
    let state = manager.score_state();
    let inner = state.inner.lock();
    let pool = inner.evaluation("score", SelectionNetwork::Udp).unwrap();
    assert!(pool.evaluates(front.id));
    assert!(!pool.evaluates(land.id));
}

#[test]
fn cold_packet_dns_uses_the_bounded_unrestricted_pool_and_keeps_begin_fenced() {
    for in_pool in [true, false] {
        let (front, mut land) = packet_score_fixture();
        land.id = Uuid::from_u128(if in_pool { 1 } else { u128::MAX });
        let (front_id, land_id) = (front.id, land.id);
        let mut nodes = vec![front, land];
        nodes.extend((0..6).map(|index| node(&format!("other-{index}"))));
        let routed = Group {
            exit: Some("land".into()),
            ..group("score", &nodes)
        };
        let ordinary = ScoreSelectionContext::aggregate(
            SelectionNetwork::Udp,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
        let packet = ScoreSelectionContext {
            target: Some(ScoreTarget::domain("dns.example", 853)),
            target_family: Some(IpVersion::V4),
            ..ordinary.clone()
        };
        let ordinary_manager = GroupManager::new(std::slice::from_ref(&routed), &nodes);
        let ordinary_plan = ordinary_manager.selection_plan_for_target("score", &ordinary);
        assert_eq!(ordinary_plan.entries[0].node.id, front_id);
        let members = |manager: &GroupManager| {
            let state = manager.score_state();
            let inner = state.inner.lock();
            let pool = inner.evaluation("score", SelectionNetwork::Udp).unwrap();
            nodes
                .iter()
                .filter(|node| pool.evaluates(node.id))
                .map(|node| node.id)
                .collect::<Vec<_>>()
        };
        let expected = members(&ordinary_manager);
        assert_eq!(expected.len(), 3);
        assert_eq!(expected.contains(&land_id), in_pool);
        let manager = GroupManager::new(&[routed], &nodes);
        let (plan, _) = manager.node_packet_dial_plan("score", &packet, None);
        assert_eq!(members(&manager), expected);
        assert_eq!(
            manager
                .score_budget_counters("score", SelectionNetwork::Udp)
                .reserved,
            0
        );
        if in_pool {
            let attempt = plan.entries[0].feedback.as_ref().unwrap();
            assert_eq!(plan.entries[0].node.id, land_id);
            attempt.begin().unwrap().finish(ScoreOutcome::Cancelled);
            *manager
                .score_state()
                .inner
                .lock()
                .evaluation_mut("score", SelectionNetwork::Udp) = EvaluationSet::default();
            assert!(matches!(
                attempt.begin(),
                Err(crate::proxy::PacketRejection::Cancelled)
            ));
        } else {
            assert!(plan.entries.is_empty());
        }
    }
}

#[test]
fn packet_ipv4_fallback_cannot_seed_a_pool_that_ordinary_ipv6_would_not_use() {
    let (front, land) = packet_score_fixture();
    let safe = node("safe");
    let child = Group {
        policy: GroupPolicy::Selector,
        exit: Some(land.name.clone()),
        ..group("route", std::slice::from_ref(&front))
    };
    let parent = Group {
        final_outbound: Some("block".into()),
        ..group_with_children("score", std::slice::from_ref(&safe), &["route"])
    };
    let packet = ScoreSelectionContext::aggregate(
        SelectionNetwork::Udp,
        ProbeDomain::DataUdp,
        IpVersion::V6,
    );
    let safe_id = safe.id;
    for ordinary_has_v6 in [true, false] {
        let alive = Arc::new(crate::alive::AliveDialerSet::new());
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_unavailable_forced(safe_id, domain, IpVersion::V6);
            if !ordinary_has_v6 {
                alive.report_unavailable_forced(front.id, domain, IpVersion::V6);
            }
        }
        let manager = GroupManager::with_alive_set(
            &[child.clone(), parent.clone()],
            &[front.clone(), land.clone(), safe.clone()],
            Some(alive),
        );
        let (plan, _) = manager.node_packet_dial_plan("score", &packet, None);
        let entry = &plan.entries[0];
        if ordinary_has_v6 {
            assert_eq!(entry.node.id, honk_config::config::BLOCK_NODE_ID);
            assert!(
                !manager
                    .score_state()
                    .score_pool_initialized("score", SelectionNetwork::Udp)
            );
        } else {
            assert_eq!(entry.node.id, safe_id);
            assert_eq!(plan.health_family, IpVersion::V4);
            entry
                .feedback
                .as_ref()
                .unwrap()
                .begin()
                .unwrap()
                .finish(ScoreOutcome::Cancelled);
        }
    }
}
