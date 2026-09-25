use super::*;

#[test]
fn unbegun_run_plans_expire_refund_and_do_not_advance_control() {
    let nodes = [node("pending control"), node("pending challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("pending-run.example", IpVersion::V4);
    let other = context("different-run.example", IpVersion::V4);
    let start = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            128,
            100 + 15 * index as u64,
            1,
            start,
        );
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    assert_eq!(
        state
            .rank_plan_at("score", &target, &refs, start + Duration::from_secs(2))
            .0,
        0
    );
    let at = start + Duration::from_secs(75);
    let (index, unbegun) = state.rank_plan_at("score", &target, &refs, at);
    assert_eq!(index, 0);
    drop(unbegun);
    let (index, control) = state.rank_plan_at("score", &target, &refs, at);
    assert_eq!(index, 0);
    let reporter = control.begin_at(at).unwrap().start_at(at);
    reporter.setup_succeeded_at(at);
    reporter.first_response_at(at + Duration::from_millis(100));
    reporter.transfer_at(1, 1, at + Duration::from_millis(100));
    reporter.finish_at(ScoreOutcome::Success, true, at + Duration::from_millis(100));
    let (index, pending) = state.rank_plan_at("score", &target, &refs, at + Duration::from_secs(1));
    assert_eq!(index, 1);
    let reserved = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(reserved.reserved, 1);
    for _ in 0..8 {
        let (_, ordinary) = state.rank_plan_at("score", &other, &refs, at + Duration::from_secs(2));
        ordinary
            .begin_at(at + Duration::from_secs(2))
            .unwrap()
            .start_at(at + Duration::from_secs(2))
            .finish_at(ScoreOutcome::Cancelled, true, at + Duration::from_secs(2));
    }
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .trial_starts,
        reserved.trial_starts
    );
    assert!(pending.begin_at(at + Duration::from_secs(45)).is_err());
    let expired = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(expired.reserved, 0);
    assert_eq!(expired.refunded, reserved.refunded + 1);
    assert_eq!(expired.spent, reserved.spent);
}

#[test]
fn node_failure_between_run_plan_and_begin_cancels_unstarted_exposure() {
    let nodes = [node("fenced control"), node("fenced challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("fenced-run.example", IpVersion::V4);
    let start = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            128,
            100 + 15 * index as u64,
            1,
            start,
        );
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let at = start + Duration::from_secs(75);
    let (_, pending) = state.rank_plan_at("score", &target, &refs, at);
    let failure = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap()
        .start_at(at);
    failure.finish_at(
        ScoreOutcome::NodeFailure,
        true,
        at + Duration::from_millis(1),
    );
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert!(pending.begin_at(at + Duration::from_millis(2)).is_err());
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(after.business_starts, before.business_starts);
    assert_eq!(after.spent, before.spent);
}

#[test]
fn other_target_reference_and_escape_preserve_pending_validation() {
    for escape in [false, true] {
        let nodes = [node("isolated control"), node("isolated challenger")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("active-run.example", IpVersion::V4);
        let other = context("other-run.example", IpVersion::V4);
        let start = Instant::now();
        for (index, leaf) in nodes.iter().enumerate() {
            train_at(
                &manager,
                leaf,
                &target,
                128,
                100 + 15 * index as u64,
                1,
                start,
            );
            train_at(
                &manager,
                leaf,
                &other,
                128,
                if (index == 0) == escape { 100 } else { 200 },
                1,
                start,
            );
        }
        let state = manager.score_state();
        let refs: Vec<_> = nodes.iter().collect();
        let at = start + Duration::from_secs(75);
        if escape {
            assert_eq!(
                state
                    .rank_plan_at("score", &other, &refs, start + Duration::from_secs(2))
                    .0,
                0
            );
        }
        let (index, pending) = state.rank_plan_at("score", &target, &refs, at);
        assert_eq!(index, 0);
        if escape {
            manager
                .feedback_for_group_node("score", nodes[0].id, other.clone())
                .unwrap()
                .start_at(at)
                .finish_at(
                    ScoreOutcome::TargetFailure,
                    true,
                    at + Duration::from_millis(1),
                );
        }
        let (index, unrelated) =
            state.rank_plan_at("score", &other, &refs, at + Duration::from_secs(1));
        assert_eq!(index, 1);
        respond_at(
            unrelated,
            Duration::from_millis(100),
            at + Duration::from_secs(1),
        );
        respond_at(
            pending,
            Duration::from_millis(100),
            at + Duration::from_secs(2),
        );
    }
}

#[test]
fn binding_a_staged_run_fences_its_original_unbegun_plan() {
    let nodes = [node("staged control"), node("staged challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("staged.example", IpVersion::V4);
    let start = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            if index == 0 { 8 } else { 1 },
            100,
            1,
            start,
        );
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let at = start + Duration::from_secs(2);
    let (index, pending) = state.rank_plan_at("score", &target, &refs, at);
    assert_eq!(index, 1);
    let (index, ordinary) = state.rank_plan_at("score", &target, &refs, at);
    assert_eq!(index, 0);
    drop(ordinary);
    manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap()
        .start_at(at)
        .finish_at(
            ScoreOutcome::NodeFailure,
            true,
            at + Duration::from_millis(1),
        );
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert!(pending.begin_at(at + Duration::from_millis(2)).is_err());
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(after.business_starts, before.business_starts);
    assert_eq!(after.spent, before.spent);
    assert_eq!(after.refunded, before.refunded + 1);
}

#[test]
fn staged_run_releases_unanswered_focus_after_sixteen_matching_offers() {
    let nodes = [node("known control"), node("unanswered challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let start = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &context("old.example", IpVersion::V4),
        20,
        100,
        1,
        start,
    );
    let target = context("unanswered.example", IpVersion::V4);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let at = start + Duration::from_secs(2);
    let (index, pending) = state.rank_plan_at("score", &target, &refs, at);
    assert_eq!(index, 1);
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    for _ in 0..16 {
        let (index, ordinary) = state.rank_plan_at("score", &target, &refs, at);
        assert_eq!(index, 0);
        ordinary
            .begin_at(at)
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
    }
    assert!(pending.begin_at(at).is_err());
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(after.spent, before.spent);
    assert_eq!(after.business_starts, before.business_starts + 16);
    assert_eq!(after.refunded, before.refunded + 1);
}

#[test]
fn promising_cold_target_run_waits_for_ordinary_reference_observation() {
    let nodes = [
        node("known control"),
        node("first cold challenger"),
        node("other cold challenger"),
    ];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let start = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &context("old.example", IpVersion::V4),
        20,
        100,
        1,
        start,
    );
    let target = context("new.example", IpVersion::V4);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let mut challenger_replies = 0;
    for step in 0..12 {
        let at = start + Duration::from_secs(2 + step);
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        assert!(
            index <= 1,
            "a new target must not scatter a promising staged challenger"
        );
        if step == 0 {
            assert_eq!(index, 1);
        }
        challenger_replies += usize::from(index == 1);
        respond_at(attempt, Duration::from_millis(100), at);
        if challenger_replies == 4 {
            break;
        }
    }
    assert_eq!(challenger_replies, 4);
}

#[test]
fn terminal_staged_runs_release_other_target_trials() {
    for outcome in [
        None,
        Some(ScoreOutcome::Cancelled),
        Some(ScoreOutcome::Success),
    ] {
        let nodes = [node("known control"), node("cold challenger")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let start = Instant::now();
        train_at(
            &manager,
            &nodes[0],
            &context("old.example", IpVersion::V4),
            20,
            100,
            1,
            start,
        );
        let target = context("staged.example", IpVersion::V4);
        let other = context("offered.example", IpVersion::V4);
        let state = manager.score_state();
        let refs: Vec<_> = nodes.iter().collect();
        let at = start + Duration::from_secs(2);
        let (index, pending) = state.rank_plan_at("score", &target, &refs, at);
        assert_eq!(index, 1);
        let reporter = outcome.map(|_| pending.begin_at(at).unwrap().start_at(at));
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let (index, ordinary) =
            state.rank_plan_at("score", &other, &refs, at + Duration::from_secs(1));
        assert_eq!(index, 0, "live staged work must retain its target");
        drop(ordinary);
        assert_eq!(
            manager
                .score_budget_counters("score", SelectionNetwork::Tcp)
                .reserved,
            before.reserved,
        );
        if let Some(reporter) = reporter {
            let finished = at + Duration::from_secs(2);
            if outcome == Some(ScoreOutcome::Success) {
                reporter.setup_succeeded_at(at);
                reporter.first_response_at(finished);
                reporter.transfer_at(1, 1, finished);
            }
            reporter.finish_at(outcome.unwrap(), true, finished);
        }
        drop(pending);
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let at = at + Duration::from_secs(3);
        let (index, next) = state.rank_plan_at("score", &other, &refs, at);
        assert_eq!(
            index, 1,
            "terminal staged outcome {outcome:?} retained focus"
        );
        respond_at(next, Duration::from_millis(100), at);
        let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(after.trial_starts, before.trial_starts + 1);
        assert_eq!(after.spent, before.spent + 1);
    }
}

#[test]
fn bound_run_keeps_unfinished_pair_but_releases_completed_pair() {
    let nodes = [node("paired control"), node("paired challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("paired.example", IpVersion::V4);
    let other = context("offered.example", IpVersion::V4);
    let start = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            128,
            100 + 15 * index as u64,
            1,
            start,
        );
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    assert_eq!(
        state
            .rank_plan_at("score", &target, &refs, start + Duration::from_secs(2))
            .0,
        0
    );
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    let mut allocated = [0; 2];
    let mut live_last = None;
    for step in 0..8 {
        let at = start + Duration::from_secs(75 + step * 5);
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        allocated[index] += 1;
        let latency = Duration::from_millis(100 + 15 * index as u64);
        if step == 7 {
            let reporter = attempt.begin_at(at).unwrap().start_at(at);
            reporter.setup_succeeded_at(at);
            reporter.first_response_at(at + latency);
            reporter.transfer_at(1, 1, at + latency);
            live_last = Some(reporter);
        } else {
            respond_at(attempt, latency, at);
        }
        let counters = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert!(
            counters.spent + counters.reserved
                <= counters.cold_allowance + counters.business_starts / counters.earning_period
        );
        if step == 0 {
            let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
            let (_, unrelated) =
                state.rank_plan_at("score", &other, &refs, at + Duration::from_secs(1));
            drop(unrelated);
            let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
            assert_eq!(after.refunded, before.refunded);
            assert_eq!(after.reserved, before.reserved);
        }
    }
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(allocated, [4, 4]);
    assert_eq!(after.business_starts - before.business_starts, 8);
    assert_eq!(after.trial_starts - before.trial_starts, 4);
    let at = start + Duration::from_secs(111);
    let (_, next) = state.rank_plan_at("score", &other, &refs, at);
    respond_at(next, Duration::from_millis(100), at);
    let released = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(released.trial_starts, after.trial_starts + 1);
    live_last
        .unwrap()
        .finish_at(ScoreOutcome::Success, true, at);
    let snapshot = state
        .verification_snapshot_at("score", &target, &refs, at)
        .unwrap();
    let relations: Vec<_> = snapshot.challengers.iter().map(|c| c.relation).collect();
    assert_eq!(relations, [ScoreRelation::SelectedFaster]);
    assert_eq!(snapshot.pending_count, 0);
}

#[test]
fn pending_bound_work_releases_focus_after_cell_replacement() {
    for parent in [false, true] {
        let nodes = [node("fenced control"), node("fenced challenger")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("fenced.example", IpVersion::V4);
        let other = context("new-offer.example", IpVersion::V4);
        let start = Instant::now();
        for leaf in &nodes {
            train_at(&manager, leaf, &target, 128, 100, 1, start);
        }
        let state = manager.score_state();
        let refs: Vec<_> = nodes.iter().collect();
        let first = start + Duration::from_secs(75);
        let (_, control) = state.rank_plan_at("score", &target, &refs, first);
        respond_at(control, Duration::from_millis(100), first);
        let at = start + Duration::from_secs(80);
        let (_, pending) = state.rank_plan_at("score", &target, &refs, at);
        {
            let mut inner = state.inner.lock();
            if parent {
                inner
                    .aggregate
                    .pop(&AggregateKey {
                        group: "score".into(),
                        network: target.network,
                        family: None,
                        node_id: nodes[0].id,
                    })
                    .unwrap();
            } else {
                inner
                    .exact
                    .pop(&ExactKey {
                        group: "score".into(),
                        network: target.network,
                        family: IpVersion::V4,
                        target: target.target.clone().unwrap(),
                        node_id: nodes[0].id,
                    })
                    .unwrap();
            }
        }
        drop(
            manager
                .feedback_for_group_node("score", nodes[0].id, target.clone())
                .unwrap()
                .start_at(at),
        );
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let (_, offered) = state.rank_plan_at("score", &other, &refs, at + Duration::from_secs(1));
        respond_at(
            offered,
            Duration::from_millis(100),
            at + Duration::from_secs(1),
        );
        let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(
            after.trial_starts,
            before.trial_starts + 1,
            "parent={parent}"
        );
        assert!(pending.begin_at(at + Duration::from_secs(2)).is_err());
        assert_eq!(
            manager
                .score_budget_counters("score", SelectionNetwork::Tcp)
                .refunded,
            after.refunded + 1
        );
    }
}

#[test]
fn staged_failure_invalidates_pending_work_without_another_rank() {
    for (failed_index, outcome, unrelated, admitted) in [
        (0, ScoreOutcome::TargetFailure, false, false),
        (1, ScoreOutcome::TargetFailure, false, false),
        (0, ScoreOutcome::TargetFailure, true, true),
        (1, ScoreOutcome::TargetFailure, true, true),
        (0, ScoreOutcome::NodeFailure, true, false),
        (1, ScoreOutcome::NodeFailure, true, false),
        (0, ScoreOutcome::shared_node_failure(), false, true),
    ] {
        let nodes = [node("staged control"), node("staged challenger")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("staged.example", IpVersion::V4);
        let failed_target = if unrelated {
            context("other.example", IpVersion::V6)
        } else {
            target.clone()
        };
        let feedback = manager
            .feedback_for_group_node("score", nodes[failed_index].id, failed_target)
            .unwrap();
        let start = Instant::now();
        let delayed = if matches!(outcome, ScoreOutcome::SharedNodeFailure(_)) {
            let delayed = feedback.start_at(start);
            feedback.start_at(start).finish_at(outcome, true, start);
            Some(delayed)
        } else {
            None
        };
        for (index, leaf) in nodes.iter().enumerate() {
            train_at(
                &manager,
                leaf,
                &target,
                if index == 0 { 8 } else { 1 },
                100,
                1,
                start + Duration::from_secs(1),
            );
        }
        let state = manager.score_state();
        let refs: Vec<_> = nodes.iter().collect();
        let at = start + Duration::from_secs(3);
        let (index, pending) = state.rank_plan_at("score", &target, &refs, at);
        assert_eq!(index, 1);
        delayed.unwrap_or_else(|| feedback.start_at(at)).finish_at(
            outcome,
            true,
            at + Duration::from_millis(1),
        );
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let guard = pending.begin_at(at + Duration::from_millis(2));
        assert_eq!(
            guard.is_ok(),
            admitted,
            "failed_index={failed_index}, outcome={outcome:?}, unrelated={unrelated}"
        );
        drop(guard);
        let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(
            after.business_starts,
            before.business_starts + u64::from(admitted)
        );
        assert_eq!(after.spent, before.spent + u64::from(admitted));
        assert_eq!(after.refunded, before.refunded + u64::from(!admitted));
    }
}
