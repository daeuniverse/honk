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
