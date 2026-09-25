use super::super::verification;
use super::budget::complete_ordinary;
use super::*;

#[test]
fn overlapping_layers_count_each_terminal_completion_once() {
    let leaf = node("only");
    let manager = GroupManager::new(
        &[group("score", std::slice::from_ref(&leaf))],
        std::slice::from_ref(&leaf),
    );
    let target = context("counts.example", IpVersion::V4);
    for _ in 0..3 {
        finish_success(&manager.selection_plan_for_target("score", &target));
    }
    let state = manager.score_state();
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        Instant::now(),
    );
    assert!((score.completed - 3.0).abs() < 0.001);
    assert!((score.useful_completed - 3.0).abs() < 0.001);
}

#[test]
fn settled_cohorts_stop_sampling_and_expiry_spends_only_business_funding() {
    let nodes: Vec<_> = (0..8).map(|i| node(&format!("node-{i}"))).collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    // Challengers hold less evidence than the selection, so expiry reopens trials for them.
    for (index, leaf) in nodes.iter().enumerate() {
        let (samples, response_ms) = if index == 0 { (24, 10) } else { (20, 600) };
        train_at(&manager, leaf, &target, samples, response_ms, 1, now);
    }
    let state = manager.score_state();
    for _ in 0..32 {
        let (index, feedback) = state.rank_plan_at(
            "score",
            &target,
            &nodes.iter().collect::<Vec<_>>(),
            now + Duration::from_secs(2),
        );
        assert_eq!(index, 0);
        feedback
            .begin_at(now + Duration::from_secs(2))
            .unwrap()
            .start_at(now + Duration::from_secs(2))
            .finish_at(ScoreOutcome::Cancelled, false, now + Duration::from_secs(2));
    }
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .trial_starts,
        0
    );
    let expired = now + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
    let mut sampled = std::collections::HashSet::new();
    for _ in 0..128 {
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let (index, feedback) =
            state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), expired);
        feedback
            .begin_at(expired)
            .unwrap()
            .start_at(expired)
            .finish_at(ScoreOutcome::Cancelled, false, expired);
        let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        if after.trial_starts > before.trial_starts {
            sampled.insert(index);
        }
        assert!(
            after.spent + after.reserved
                <= after.cold_allowance + after.business_starts / after.earning_period
        );
    }
    assert!(
        sampled.len() > 1,
        "unfinished questions rotate across real business offers"
    );
}

#[test]
fn new_targets_cannot_mint_exploration_and_peek_cannot_spend_it() {
    let nodes: Vec<_> = (0..8).map(|i| node(&format!("node-{i}"))).collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    // Cancelled flows never complete, so the selection's seeded completion keeps trials offered.
    complete_ordinary(&manager, "score", &nodes[0], 1.0);
    let now = Instant::now();
    let state = manager.score_state();
    for request in 0..64 {
        let target = context(&format!("{request}.example"), IpVersion::V4);
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        for _ in 0..10 {
            state.peek_rank("score", &target, &nodes.iter().collect::<Vec<_>>());
        }
        assert_eq!(
            manager.score_budget_counters("score", SelectionNetwork::Tcp),
            before
        );
        let (_, feedback) =
            state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), now);
        feedback.begin_at(now).unwrap().start_at(now).finish_at(
            ScoreOutcome::Cancelled,
            false,
            now,
        );
    }
    let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(counts.business_starts, 64);
    assert_eq!(counts.scopes, 1);
    assert_eq!(
        counts.spent,
        exploration_target(nodes.len()) as u64 + 63 / SCORE_EXPLORATION_PERIOD
    );
}

#[test]
fn answered_unfinished_trial_holds_the_challenger_at_the_selection_ceiling() {
    let nodes = [node("selection"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    complete_ordinary(&manager, "score", &nodes[0], 1.0);
    let target = context("ceiling.example", IpVersion::V4);
    let state = manager.score_state();
    let refs = nodes.iter().collect::<Vec<_>>();
    let now = Instant::now();
    let (index, attempt) = state.rank_plan_at("score", &target, &refs, now);
    assert_eq!(index, 1);
    let reporter = attempt.begin_at(now).unwrap().start_at(now);
    reporter.setup_succeeded_at(now);
    // The reply answers the availability question, so the in-flight gate would admit another.
    reporter.transfer_at(1, 1, now);
    assert_eq!(state.rank_plan_at("score", &target, &refs, now).0, 0);
    reporter.finish_at(ScoreOutcome::Cancelled, true, now);
    assert_eq!(state.rank_plan_at("score", &target, &refs, now).0, 1);
}

#[test]
fn sparse_selection_without_started_business_cannot_earn_currency() {
    let nodes: Vec<_> = (0..32).map(|i| node(&format!("node-{i}"))).collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    // Selection evidence makes every rank offer a trial to the ledger.
    manager.score_state().inner.lock().aggregate.put(
        AggregateKey {
            group: "score".into(),
            network: SelectionNetwork::Tcp,
            family: None,
            node_id: nodes[0].id,
        },
        trained_stats(1.0, 100.0, now),
    );
    for hour in 0..128 {
        rank_at(
            &manager,
            &nodes,
            &target,
            now + Duration::from_secs(hour * 3600),
        );
        let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(
            (
                counts.business_starts,
                counts.spent,
                counts.reserved,
                counts.earned_available
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(
            counts.cold_available,
            exploration_target(nodes.len()) as u64
        );
    }
}

#[test]
fn expired_backoff_gets_bounded_recovery_despite_normal_exclusion() {
    let nodes = [node("working"), node("failed")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let aggregate = ScoreSelectionContext {
        target: None,
        target_family: None,
        ..target.clone()
    };
    let now = Instant::now();
    for leaf in &nodes {
        train_at(&manager, leaf, &target, 20, 100, 1, now);
    }
    for _ in 0..3 {
        manager
            .feedback_for_group_node("score", nodes[1].id, target.clone())
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::Timeout, true, now);
    }
    let state = manager.score_state();
    let node_refs = [&nodes[0], &nodes[1]];
    for _ in 0..32 {
        let (index, feedback) = state.rank_plan_at("score", &target, &node_refs, now);
        assert_eq!(index, 0);
        feedback.begin_at(now).unwrap().start_at(now).finish_at(
            ScoreOutcome::Cancelled,
            false,
            now,
        );
        assert_eq!(rank_at(&manager, &nodes, &aggregate, now), 0);
    }
    let expired = now + SCORE_EXPLORE_BACKOFF_BASE * 4 + Duration::from_secs(1);
    let mut active = Vec::new();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    for _ in 0..4 {
        let reporter = feedback.start_at(expired);
        reporter.setup_succeeded_at(expired);
        reporter.transfer_at(1, 1, expired);
        active.push(reporter);
    }
    for leaf in &nodes {
        probe_at(&manager, leaf, &target, 100, expired);
    }
    let decision = ranking::decision(
        &state.inner.lock(),
        "score",
        &target,
        &node_refs,
        expired,
        false,
    );
    assert_eq!(decision.scores[1].fail_streak, 3);
    assert!(!decision.scores[1].explore_backed_off);
    assert!(!ranking::normal_eligible(
        &decision.scores[1],
        decision.baseline
    ));
    for reporter in active {
        reporter.finish_at(ScoreOutcome::Cancelled, true, expired);
    }
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    let (index, feedback) = state.rank_plan_at("score", &target, &node_refs, expired);
    assert_eq!(index, 1);
    let reporter = feedback.begin_at(expired).unwrap().start_at(expired);
    assert_eq!(rank_at(&manager, &nodes, &target, expired), 0);
    assert_eq!(rank_at(&manager, &nodes, &aggregate, expired), 0);
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(after.trial_starts, before.trial_starts + 1);
    assert!(
        after.trial_starts + after.reserved
            <= after.cold_allowance + after.business_starts / after.earning_period
    );
    reporter.finish_at(ScoreOutcome::Cancelled, false, expired);
}

#[test]
fn unchanged_failed_incumbent_allows_funded_recovery_without_free_trials() {
    let nodes = [node("recovery incumbent"), node("recovery challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    train_at(&manager, &nodes[0], &target, 100, 10, 1, now);
    train_at(&manager, &nodes[1], &target, 80, 100, 1, now);
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
        0
    );
    let failed_at = now + Duration::from_secs(3);
    for leaf in &nodes {
        let reporter = manager
            .feedback_for_group_node("score", leaf.id, target.clone())
            .unwrap()
            .start_at(failed_at);
        reporter.setup_succeeded_at(failed_at);
        reporter.transfer_at(1, 0, failed_at);
        reporter.finish_at(ScoreOutcome::Timeout, true, failed_at);
    }
    let backed_off = failed_at + Duration::from_secs(1);
    for _ in 0..128 {
        manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .business()
            .begin_at(backed_off)
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
    }
    let state = manager.score_state();
    let refs = [&nodes[0], &nodes[1]];
    let (index, attempt) = state.rank_plan_at("score", &target, &refs, backed_off);
    assert_eq!(index, 0, "backed-off alternatives must not become trials");
    attempt
        .begin_at(backed_off)
        .unwrap()
        .start_at(backed_off)
        .finish_at(ScoreOutcome::Cancelled, false, backed_off);
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!((before.earned_available, before.trial_starts), (8, 0));

    let later = now + Duration::from_secs(304);
    {
        let inner = state.inner.lock();
        let decision = ranking::decision(&inner, "score", &target, &refs, later, false);
        assert_eq!(decision.ordinary.index, 0);
        assert_eq!(
            decision.ordinary.reason,
            SelectionReason::FreshFailureBypass
        );
        let (_, order) = verification::questions(&decision, &target, &[0.0; 2], later);
        assert_eq!(order.first(), Some(&1));
    }
    let mut challenger_trials = 0;
    let mut total_trials = 0;
    let mut exhausted = false;
    for second in 0..32 {
        let at = later + Duration::from_secs(second);
        let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let ordinary = ranking::decision(&state.inner.lock(), "score", &target, &refs, at, false)
            .ordinary
            .index;
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        let reserved = manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .reserved
            > counts.reserved;
        if counts.cold_available + counts.earned_available == 0 {
            exhausted = true;
            assert_eq!(
                index, ordinary,
                "an exhausted budget must keep the ordinary choice"
            );
            assert!(!reserved, "an exhausted budget cannot reserve a free trial");
        }
        challenger_trials += u64::from(reserved && index == 1);
        total_trials += u64::from(reserved);
        let reporter = attempt.begin_at(at).unwrap().start_at(at);
        reporter.setup_succeeded_at(at);
        reporter.transfer_at(1, 0, at);
        reporter.finish_at(ScoreOutcome::Cancelled, true, at + Duration::from_millis(1));
        let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(
            after.trial_starts - counts.trial_starts,
            u64::from(reserved)
        );
        assert!(
            after.spent + after.reserved
                <= after.cold_allowance + after.business_starts / after.earning_period
        );
    }
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert!(
        challenger_trials > 0,
        "funded actionable recovery must remain reachable"
    );
    assert!(exhausted);
    assert_eq!(after.trial_cancelled - before.trial_cancelled, total_trials);
    assert_eq!(after.refunded, before.refunded);
    let escape_at = later + Duration::from_secs(32);
    for leaf in &nodes {
        assert!(
            score_snapshot(&state.inner.lock(), "score", &target, leaf.id, escape_at)
                .unresolved_failure
        );
    }

    let failure = manager
        .feedback_for_group_node("score", nodes[1].id, target.clone())
        .unwrap()
        .start_at(escape_at);
    failure.finish_at(ScoreOutcome::Timeout, false, escape_at);
    let (index, attempt) = state.rank_plan_at("score", &target, &refs, escape_at);
    assert_eq!(index, 0);
    attempt
        .begin_at(escape_at)
        .unwrap()
        .finish(ScoreOutcome::Cancelled);

    train_at(&manager, &nodes[1], &target, 100, 10, 1, escape_at);
    let escape_at = escape_at + Duration::from_secs(2);
    for _ in 0..before.earning_period {
        manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .business()
            .begin_at(escape_at)
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
    }
    assert!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .earned_available
            > 0
    );
    {
        let inner = state.inner.lock();
        let decision = ranking::decision(&inner, "score", &target, &refs, escape_at, false);
        assert_eq!(decision.ordinary.index, 1);
        assert_eq!(
            decision.ordinary.reason,
            SelectionReason::FreshFailureBypass
        );
        let (_, order) = verification::questions(&decision, &target, &[0.0; 2], escape_at);
        assert_eq!(order.first(), Some(&0));
    }
    let (index, attempt) = state.rank_plan_at("score", &target, &refs, escape_at);
    assert_eq!(
        index, 1,
        "ordinary escape takes priority over optional recovery"
    );
    attempt
        .begin_at(escape_at)
        .unwrap()
        .start_at(escape_at)
        .finish_at(ScoreOutcome::Cancelled, false, escape_at);
    let escaped = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(escaped.spent, after.spent);
    assert_eq!(escaped.trial_starts, after.trial_starts);
    assert_eq!(escaped.reserved, 0);
}

#[test]
fn all_failing_fallback_remains_selectable() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        for _ in 0..3 {
            manager
                .feedback_for_group_node("score", leaf.id, target.clone())
                .unwrap()
                .start_at(now)
                .finish_at(ScoreOutcome::Timeout, true, now);
        }
    }
    assert_eq!(rank_at(&manager, &nodes, &target, now), 0);
}

#[test]
fn source_outcomes_do_not_forgive_traffic_backoff() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for _ in 0..2 {
        manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::Timeout, true, now);
    }
    for source in [ScoreSource::HealthProbe, ScoreSource::Warmup] {
        probe_source_at(
            &manager,
            &nodes[0],
            &target,
            source,
            Duration::from_millis(1),
            now,
        );
        manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .with_source(source)
            .start_at(now)
            .finish_at(ScoreOutcome::Timeout, true, now);
    }
    let state = manager.score_state();
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        nodes[0].id,
        now + SCORE_EXPLORE_BACKOFF_BASE,
    );
    assert_eq!(score.fail_streak, 2);
    assert!(score.explore_backed_off);
}

#[test]
fn latency_degradation_revalidation_cannot_bypass_exposure_budget() {
    let nodes: Vec<_> = (0..32).map(|i| node(&format!("node-{i}"))).collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            20,
            if index == 0 { 10 } else { 600 },
            1,
            now,
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
        0
    );
    train_at(
        &manager,
        &nodes[0],
        &target,
        1,
        100,
        1,
        now + Duration::from_secs(3),
    );
    let state = manager.score_state();
    let node_refs = nodes.iter().collect::<Vec<_>>();
    let at = now + Duration::from_secs(4);
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    for _ in 0..128 {
        let (_, feedback) = state.rank_plan_at("score", &target, &node_refs, at);
        feedback
            .begin_at(at)
            .unwrap()
            .start_at(at)
            .finish_at(ScoreOutcome::Cancelled, false, at);
        let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert!(
            counts.trial_starts + counts.reserved
                <= counts.cold_allowance + counts.business_starts / counts.earning_period
        );
    }
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(after.business_starts, before.business_starts + 128);
    assert!(after.trial_starts > before.trial_starts);
    assert_eq!(after.trial_cancelled, after.trial_starts);
    assert_eq!(after.refunded, before.refunded);
}

#[test]
fn cancelled_cold_trials_keep_alternative_coverage() {
    let nodes = [node("winner"), node("cold-b"), node("cold-c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    train_at(&manager, &nodes[0], &target, 20, 100, 1, now);
    let state = manager.score_state();
    let mut trials = std::collections::HashSet::new();
    let requests = exploration_target(nodes.len()) as u64 + SCORE_EXPLORATION_PERIOD * 2;
    let node_refs = nodes.iter().collect::<Vec<_>>();
    let at = now + Duration::from_secs(2);
    for _ in 0..requests {
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let (index, feedback) = state.rank_plan_at("score", &target, &node_refs, at);
        feedback
            .begin_at(at)
            .unwrap()
            .start_at(at)
            .finish_at(ScoreOutcome::Cancelled, true, at);
        let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        if after.trial_starts > before.trial_starts {
            trials.insert(index);
        }
        assert!(
            after.trial_starts + after.reserved
                <= after.cold_allowance + after.business_starts / after.earning_period
        );
    }
    assert_eq!(trials, std::collections::HashSet::from([1, 2]));
    let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(counts.trial_cancelled, counts.trial_starts);
    assert_eq!(counts.refunded, 0);
    for leaf in &nodes[1..] {
        let score = score_snapshot(&state.inner.lock(), "score", &target, leaf.id, now);
        assert_eq!((score.completed, score.unresolved_failure), (0.0, false));
    }
}

#[test]
fn qualified_trial_does_not_replace_committed_incumbent_without_new_evidence() {
    let nodes = [node("incumbent"), node("near-equal-trial")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    // The trial needs the incumbent ahead of the challenger's evidence.
    for (leaf, samples, latency) in [(&nodes[0], 21, 100), (&nodes[1], 20, 105)] {
        train_at(&manager, leaf, &target, samples, latency, 1, now);
    }
    let state = manager.score_state();
    let node_refs = [&nodes[0], &nodes[1]];
    let mut at = now + Duration::from_secs(2);
    let (index, feedback) = state.rank_plan_at("score", &target, &node_refs, at);
    assert_eq!(index, 0);
    feedback
        .begin_at(at)
        .unwrap()
        .start_at(at)
        .finish_at(ScoreOutcome::Cancelled, false, at);
    for _ in 0..4 * SCORE_EXPLORATION_PERIOD {
        manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .business()
            .begin_at(at)
            .unwrap()
            .start_at(at)
            .finish_at(ScoreOutcome::Cancelled, false, at);
    }
    at += PERFORMANCE_MAX_AGE;
    let (index, feedback) = state.rank_plan_at("score", &target, &node_refs, at);
    assert_eq!(index, 1);
    feedback
        .begin_at(at)
        .unwrap()
        .start_at(at)
        .finish_at(ScoreOutcome::Cancelled, true, at);
    assert_eq!(state.peek_rank_at("score", &target, &node_refs, at), 0);
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .trial_starts,
        1
    );
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .ordinary_switch,
        0
    );
    train_at(&manager, &nodes[0], &target, 20, 100, 1, at);
    train_at(&manager, &nodes[1], &target, 20, 50, 1, at);
    assert_eq!(
        rank_at(&manager, &nodes, &target, at + Duration::from_secs(1)),
        1
    );
    assert_eq!(
        manager
            .score_state()
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .ordinary_switch,
        1
    );
}

#[test]
fn first_normal_selection_uses_quality_not_the_last_startup_trial() {
    let nodes = [node("better"), node("last-trial")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("startup.example", IpVersion::V4);
    let now = Instant::now();
    for (index, latency) in [100, 105].into_iter().enumerate() {
        assert_eq!(rank_at(&manager, &nodes, &target, now), index);
        train_at(&manager, &nodes[index], &target, 20, latency, 1, now);
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
        0
    );
}

#[test]
fn terminal_success_with_same_time_rx_does_not_clear_failure_backoff() {
    let leaf = node("recovering");
    let nodes = std::slice::from_ref(&leaf);
    let manager = GroupManager::new(&[group("score", nodes)], nodes);
    let target = context("recovery.example", IpVersion::V4);
    let feedback = manager
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap();
    let now = Instant::now();
    for _ in 0..2 {
        feedback
            .start_at(now)
            .finish_at(ScoreOutcome::Timeout, true, now);
    }
    let success = feedback.start_at(now);
    success.setup_succeeded_at(now);
    success.transfer_at(1, 1, now);
    success.finish_at(ScoreOutcome::Success, true, now);
    let state = manager.score_state();
    let recovered = score_snapshot(&state.inner.lock(), "score", &target, leaf.id, now);
    assert_eq!(recovered.fail_streak, 2);
    assert!(recovered.explore_backed_off);

    feedback
        .start_at(now)
        .finish_at(ScoreOutcome::Timeout, true, now);
    let until = now + SCORE_EXPLORE_BACKOFF_BASE * 4;
    let before = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        until - Duration::from_nanos(1),
    );
    let expired = score_snapshot(&state.inner.lock(), "score", &target, leaf.id, until);
    assert_eq!(expired.fail_streak, 3);
    assert!(before.explore_backed_off);
    assert!(!expired.explore_backed_off);
}

#[test]
fn unbegun_plans_do_not_rotate_discovery() {
    let nodes = [node("rotation a"), node("rotation b"), node("rotation c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("rotation.example", IpVersion::V4);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let now = Instant::now();
    // Rotation state is only visible once each member has begun real work.
    for leaf in &nodes {
        train_at(&manager, leaf, &target, 1, 10, 1, now);
    }
    let at = now + Duration::from_secs(2);
    let rotation = |index: usize| {
        score_snapshot(&state.inner.lock(), "score", &target, nodes[index].id, at).selected_at
    };
    let before: Vec<_> = (0..nodes.len()).map(rotation).collect();
    let (index, dropped) = state.rank_plan_at("score", &target, &refs, at);
    drop(dropped);
    assert_eq!(
        rotation(index),
        before[index],
        "an unbegun plan is not an opportunity"
    );
    let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
    attempt
        .begin_at(at)
        .unwrap()
        .start_at(at)
        .finish_at(ScoreOutcome::Success, true, at);
    assert!(
        rotation(index) > before[index],
        "an admitted begin advances rotation"
    );
}
