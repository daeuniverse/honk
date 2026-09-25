use super::*;
use crate::transport_quality::{PressureReason, TransportPressure};

fn pressure_at(manager: &GroupManager, node_id: Uuid, family: IpVersion, at: Instant) {
    let mut observations = [None; 2];
    observations[family as usize] = Some(TransportPressure {
        observed_at: at,
        reason: PressureReason::Both,
    });
    manager.score_state.observe_carrier_pressure(
        &manager.score_authority,
        node_id,
        &["score".into()],
        true,
        observations,
        at,
    );
}

#[test]
fn carrier_pressure_reopens_only_budgeted_comparison_without_penalizing_business() {
    for network in [SelectionNetwork::Tcp, SelectionNetwork::Udp] {
        let nodes = [node("incumbent"), node("alternative")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let mut target = context("business.example", IpVersion::V4);
        target.network = network;
        target.probe_domain = if network == SelectionNetwork::Tcp {
            ProbeDomain::Tcp
        } else {
            ProbeDomain::DataUdp
        };
        let start = Instant::now();
        let state = manager.score_state();
        let refs = nodes.iter().collect::<Vec<_>>();
        train_at(&manager, &nodes[0], &target, 20, 100, 1, start);
        for _ in 0..exploration_target(nodes.len()) {
            let (_, feedback) = state.rank_plan_at("score", &target, &refs, start);
            let guard = feedback.begin_at(start).unwrap();
            guard
                .start_at(start)
                .finish_at(ScoreOutcome::Cancelled, false, start);
        }
        // Trailing the selection's completions keeps the challenger under the trial ceiling.
        train_at(&manager, &nodes[1], &target, 16, 100, 1, start);
        let ready = start + Duration::from_secs(2);
        for _ in 0..16 {
            assert_eq!(rank_at(&manager, &nodes, &target, ready), 0);
        }
        let funded = state.budget_counters("score", network);
        assert_eq!(funded.cold_available, 0);
        assert!(funded.earned_available > 0);
        let at = ready + Duration::from_secs(1);
        let before = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, at);
        assert_eq!(
            state
                .selection_reason_counts("score", network)
                .periodic_explore,
            0
        );
        pressure_at(&manager, nodes[0].id, IpVersion::V4, at);
        pressure_at(&manager, nodes[0].id, IpVersion::V4, at);
        let after = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, at);
        assert_close(after.completed, before.completed);
        assert_close(after.useful_completed, before.useful_completed);
        assert_close(after.reliability, before.reliability);
        assert_eq!(after.fail_streak, before.fail_streak);
        assert_eq!(after.explore_backed_off, before.explore_backed_off);
        assert_eq!(after.qualified(), before.qualified());
        let counters = state.selection_reason_counts("score", network);
        for _ in 0..10 {
            assert_eq!(state.peek_rank_at("score", &target, &refs, at), 0);
        }
        assert_eq!(state.selection_reason_counts("score", network), counters);
        assert_eq!(counters.carrier_pressure, 1);
        assert_eq!(counters.carrier_rtt_pressure, 1);
        assert_eq!(counters.carrier_loss_pressure, 1);
        let (index, feedback) = state.rank_plan_at("score", &target, &refs, at);
        assert_eq!(index, 1);
        let validation = feedback.begin_at(at).unwrap().start_at(at);
        validation.setup_succeeded_at(at);
        let spent = state.budget_counters("score", network);
        assert_eq!(
            spent.periodic_trial_starts,
            funded.periodic_trial_starts + 1
        );
        assert!(
            spent.trial_starts + spent.reserved
                <= spent.cold_allowance + spent.business_starts / spent.earning_period
        );
        let validated = state.selection_reason_counts("score", network);
        assert_eq!(validated.periodic_explore, 1);
        assert_eq!(validated.carrier_validation, 1);
        assert_eq!(validated.ordinary_switch, 0);
        for _ in 0..15 {
            pressure_at(&manager, nodes[0].id, IpVersion::V4, at);
            assert_eq!(rank_at(&manager, &nodes, &target, at), 0);
        }
        let bounded = state.selection_reason_counts("score", network);
        assert_eq!(bounded.periodic_explore, 1);
        assert_eq!(bounded.carrier_pressure, 1);
        assert_eq!(bounded.carrier_rtt_pressure, 1);
        assert_eq!(bounded.carrier_loss_pressure, 1);
        assert_eq!(bounded.ordinary_switch, 0);
        let after = state.budget_counters("score", network);
        assert_eq!(after.business_starts, spent.business_starts);
        assert_eq!(after.trial_starts, spent.trial_starts);
        validation.finish_at(ScoreOutcome::Cancelled, false, at);
        for _ in 1..funded.earned_available {
            let available = state.budget_counters("score", network);
            if available.earned_available == 1 {
                let snapshot = state
                    .verification_snapshot_at("score", &target, &refs, at)
                    .unwrap();
                assert_eq!(snapshot.wait_reason, ScoreWaitReason::ComparableTraffic);
                assert_eq!(state.budget_counters("score", network), available);
            }
            let (index, feedback) = state.rank_plan_at("score", &target, &refs, at);
            assert_eq!(index, 1);
            feedback.begin_at(at).unwrap().start_at(at).finish_at(
                ScoreOutcome::Cancelled,
                false,
                at,
            );
        }
        let exhausted = state.budget_counters("score", network);
        assert_eq!(exhausted.earned_available, 0);
        assert_eq!(exhausted.periodic_trial_starts, funded.earned_available);
        assert_eq!(
            rank_at(&manager, &nodes, &target, at + Duration::from_secs(1)),
            0
        );
        assert_eq!(
            state.budget_counters("score", network).business_starts,
            exhausted.business_starts
        );
        assert_eq!(
            state.budget_counters("score", network).trial_starts,
            exhausted.trial_starts
        );
        // A successful measurement, not the hint, earns ordinary promotion.
        train_at(&manager, &nodes[1], &target, 20, 10, 1, at);
        assert_eq!(
            state.peek_rank_at("score", &target, &refs, at + Duration::from_secs(2)),
            1
        );
        assert_eq!(
            state
                .selection_reason_counts("score", network)
                .ordinary_switch,
            0
        );
    }
}

#[test]
fn answered_open_response_does_not_block_the_next_pressure_episode() {
    for download in [1, 128 * 1024] {
        let nodes = [node("refresh incumbent"), node("refresh challenger")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("refresh.example", IpVersion::V4);
        let start = Instant::now();
        let state = manager.score_state();
        let refs: Vec<_> = nodes.iter().collect();
        train_at(&manager, &nodes[0], &target, 64, 100, download, start);
        for _ in 0..exploration_target(nodes.len()) {
            let (_, attempt) = state.rank_plan_at("score", &target, &refs, start);
            attempt.begin_at(start).unwrap().start_at(start).finish_at(
                ScoreOutcome::Cancelled,
                false,
                start,
            );
        }
        // Trailing the selection's completions keeps the challenger under the trial ceiling.
        train_at(&manager, &nodes[1], &target, 60, 100, download, start);
        let at = start + Duration::from_secs(3);
        assert_eq!(state.rank_at("score", &target, &refs, at), 0);
        pressure_at(&manager, nodes[0].id, IpVersion::V4, at);
        let snapshot = state
            .verification_snapshot_at("score", &target, &refs, at)
            .unwrap();
        assert_eq!(snapshot.question, ScoreEvidenceQuestion::Response);
        let funded = state.budget_counters("score", target.network);
        assert!(funded.earned_available >= 2);
        let mut open = Vec::new();
        for episode in 0..2 {
            let began = at + Duration::from_secs(episode * 2);
            pressure_at(&manager, nodes[0].id, IpVersion::V4, began);
            let (index, attempt) = state.rank_plan_at("score", &target, &refs, began);
            assert_eq!(
                index, 1,
                "an answered open reporter cannot answer a new episode"
            );
            let reporter = attempt.begin_at(began).unwrap().start_at(began);
            reporter.setup_succeeded_at(began);
            let waiting = state
                .verification_snapshot_at("score", &target, &refs, began)
                .unwrap();
            assert_eq!(waiting.question, ScoreEvidenceQuestion::Response);
            assert_eq!(waiting.wait_reason, ScoreWaitReason::InFlight);
            assert_eq!(state.rank_at("score", &target, &refs, began), 0);
            reporter.first_response_at(began + Duration::from_millis(100));
            reporter.transfer_at(1, 1, began + Duration::from_millis(100));
            open.push(reporter);
            assert_eq!(
                state
                    .budget_counters("score", target.network)
                    .periodic_trial_starts,
                funded.periodic_trial_starts + episode + 1
            );
        }
        let now = at + Duration::from_secs(3);
        for reporter in open {
            reporter.finish_at(ScoreOutcome::Cancelled, true, now);
        }
    }
}

#[test]
fn pressure_reopens_responses_until_every_common_target_refreshes() {
    let nodes = [node("refresh winner"), node("refresh peer")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let targets = [
        context("first.example", IpVersion::V4),
        context("second.example", IpVersion::V4),
    ];
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let start = Instant::now();
    rank_at(&manager, &nodes, &targets[0], start);
    for target in &targets {
        for leaf in &nodes {
            train_at(&manager, leaf, target, 8, 100, 1, start);
        }
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let snapshot = |scope: &ScoreSelectionContext, at| {
        state
            .verification_snapshot_at("score", scope, &refs, at)
            .unwrap()
    };
    let equivalent = |snapshot: ScoreVerificationSnapshot| {
        snapshot
            .challengers
            .iter()
            .map(|c| c.relation)
            .collect::<Vec<_>>()
            == [ScoreRelation::Equivalent]
    };
    let reopened =
        |snapshot: ScoreVerificationSnapshot| snapshot.question == ScoreEvidenceQuestion::Response;
    assert!(equivalent(snapshot(
        &aggregate,
        start + Duration::from_secs(2)
    )));
    pressure_at(
        &manager,
        nodes[0].id,
        IpVersion::V4,
        start + Duration::from_secs(3),
    );
    let fresh = start + Duration::from_millis(3200);
    for leaf in &nodes {
        train_at(&manager, leaf, &targets[0], 4, 100, 1, fresh);
    }
    let partially_refreshed = start + Duration::from_millis(4300);
    assert!(!reopened(snapshot(&targets[0], partially_refreshed)));
    assert!(reopened(snapshot(&aggregate, partially_refreshed)));
    let fresh = start + Duration::from_secs(4);
    let now = start + Duration::from_secs(5);
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(&manager, leaf, &targets[1], 4, 100, 1, fresh);
        if index == 0 {
            assert!(reopened(snapshot(&aggregate, now)));
        }
    }
    let funded = state.budget_counters("score", SelectionNetwork::Tcp);
    assert!(funded.cold_available + funded.earned_available > 0);
    for scope in [&targets[0], &targets[1], &aggregate] {
        let refreshed = snapshot(scope, now);
        assert_eq!(refreshed.question, ScoreEvidenceQuestion::None);
        assert!(equivalent(refreshed));
        let (_, attempt) = state.rank_plan_at("score", scope, &refs, now);
        attempt
            .begin_at(now)
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::Cancelled, false, now);
        assert!(reopened(snapshot(scope, start + Duration::from_secs(61))));
    }
    assert_eq!(
        state
            .budget_counters("score", SelectionNetwork::Tcp)
            .trial_starts,
        funded.trial_starts
    );
}

#[test]
fn carrier_pressure_is_owner_scoped_expiring_and_cannot_create_flow_evidence() {
    let nodes = [node("one"), node("two")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let start = Instant::now();
    pressure_at(&manager, nodes[0].id, IpVersion::V4, start);
    assert_eq!(manager.score_cache_snapshot().aggregate_cells, 0);
    let target = context("family.example", IpVersion::V6);
    for leaf in &nodes {
        train_at(&manager, leaf, &target, 20, 100, 1, start);
    }
    let at = start + Duration::from_secs(2);
    manager.score_state.observe_carrier_pressure(
        &manager.score_authority,
        nodes[0].id,
        &["score".into()],
        true,
        [
            Some(TransportPressure {
                observed_at: at,
                reason: PressureReason::Rtt,
            }),
            None,
        ],
        at,
    );
    let state = manager.score_state();
    let score = |context: &ScoreSelectionContext, now| {
        score_snapshot(&state.inner.lock(), "score", context, nodes[0].id, now)
    };
    assert_eq!(score(&target, at).carrier_pressure_at, Some(at));
    let mut other_carrier_family = target.clone();
    other_carrier_family.health_family = IpVersion::V6;
    assert_eq!(
        score(&other_carrier_family, at).carrier_pressure_at,
        Some(at)
    );
    let expired = at + CARRIER_PRESSURE_TTL;
    assert!(score(&target, expired).carrier_pressure_at.is_none());
    let reasons = state.selection_reason_counts("score", target.network);
    assert_eq!(reasons.carrier_rtt_pressure, 1);
    assert_eq!(reasons.carrier_loss_pressure, 0);
    let late = [
        Some(TransportPressure {
            observed_at: at,
            reason: PressureReason::Loss,
        }),
        None,
    ];
    state.observe_carrier_pressure(
        &manager.score_authority,
        nodes[0].id,
        &["score".into()],
        true,
        late,
        at,
    );
    assert_eq!(
        state.selection_reason_counts("score", target.network),
        reasons
    );
    state.observe_carrier_pressure(
        &manager.score_authority,
        nodes[0].id,
        &["score".into()],
        true,
        late,
        expired,
    );
    assert_eq!(
        state.selection_reason_counts("score", target.network),
        reasons
    );
}

#[test]
fn replaced_runtime_and_retired_manager_cannot_publish_carrier_pressure() {
    let leaf = Node::from_share_link("socks5://127.0.0.1:1080#old").unwrap();
    let groups = [group("score", std::slice::from_ref(&leaf))];
    let old_runtimes =
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&leaf)).unwrap();
    let old = GroupManager::new(&groups, std::slice::from_ref(&leaf));
    old.bind_transport_quality(&old_runtimes);
    let target = context("reload.example", IpVersion::V4);
    train_at(
        &old,
        &leaf,
        &target,
        20,
        1,
        1,
        Instant::now() - Duration::from_secs(2),
    );
    let mut renamed = leaf.clone();
    renamed.name = "replacement".into();
    let (new_runtimes, reused) = crate::runtime::OutboundRuntimeRegistry::build_reusing(
        std::slice::from_ref(&renamed),
        64,
        Some(&old_runtimes),
    )
    .unwrap();
    assert!(reused.is_empty());
    let replacement =
        GroupManager::with_alive_set_and_score_state(&groups, &[renamed], None, old.score_state());
    replacement.bind_transport_quality(&new_runtimes);
    replacement.publish_score_membership();
    let old_quality = old_runtimes.get(&leaf.id).unwrap().transport_quality();
    old_quality.report(false, PressureReason::Loss, Instant::now());
    old.observe_transport_quality();
    replacement.observe_transport_quality();
    assert_eq!(
        replacement
            .score_state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .carrier_pressure,
        0
    );
    new_runtimes
        .get(&leaf.id)
        .unwrap()
        .transport_quality()
        .report(false, PressureReason::Loss, Instant::now());
    replacement.observe_transport_quality();
    assert_eq!(
        replacement
            .score_state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .carrier_pressure,
        1
    );
    let successor = GroupManager::with_alive_set_and_score_state(
        &groups,
        std::slice::from_ref(&leaf),
        None,
        old.score_state(),
    );
    successor.bind_transport_quality(&new_runtimes);
    successor.publish_score_membership();
    successor.observe_transport_quality();
    assert_eq!(
        successor
            .score_state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .carrier_pressure,
        1
    );
    assert!(
        score_snapshot(
            &successor.score_state.inner.lock(),
            "score",
            &target,
            leaf.id,
            Instant::now()
        )
        .carrier_pressure_at
        .is_none()
    );
}

#[test]
fn shadowsocks_tcp_pressure_does_not_spend_native_udp_validation() {
    let leaf = Node::from_share_link("ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:8388#carrier").unwrap();
    let nodes = std::slice::from_ref(&leaf);
    let manager = GroupManager::new(&[group("score", nodes)], nodes);
    let runtimes = crate::runtime::OutboundRuntimeRegistry::build(nodes).unwrap();
    manager.bind_transport_quality(&runtimes);
    let tcp = context("same-node.example", IpVersion::V4);
    let mut udp = tcp.clone();
    udp.network = SelectionNetwork::Udp;
    udp.probe_domain = ProbeDomain::DataUdp;
    for target in [&tcp, &udp] {
        train_at(
            &manager,
            &leaf,
            target,
            20,
            10,
            1,
            Instant::now() - Duration::from_secs(2),
        );
    }
    runtimes.get(&leaf.id).unwrap().transport_quality().report(
        false,
        PressureReason::Loss,
        Instant::now(),
    );
    manager.observe_transport_quality();
    let state = manager.score_state();
    let inner = state.inner.lock();
    assert!(
        score_snapshot(&inner, "score", &tcp, leaf.id, Instant::now())
            .carrier_pressure_at
            .is_some()
    );
    assert!(
        score_snapshot(&inner, "score", &udp, leaf.id, Instant::now())
            .carrier_pressure_at
            .is_none()
    );
    drop(inner);
    let tcp_counts = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(tcp_counts.carrier_pressure, 1);
    assert_eq!(tcp_counts.carrier_rtt_pressure, 0);
    assert_eq!(tcp_counts.carrier_loss_pressure, 1);
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Udp)
            .carrier_pressure,
        0
    );
}
