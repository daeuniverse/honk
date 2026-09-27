use super::super::budget;
use super::*;

/// Runs one business start through the ledger; a reserved trial settles with `outcome`.
fn run_business(
    manager: &GroupManager,
    target: &ScoreSelectionContext,
    node: &Node,
    work: Arc<budget::Work>,
    outcome: ScoreOutcome,
    now: Instant,
) {
    let state = manager.score_state();
    let attributions = [ScoreAttribution {
        group: "score".into(),
        node_id: node.id,
    }];
    assert!(budget::begin(
        &mut state.inner.lock(),
        &manager.score_authority,
        target,
        &attributions,
        &budget::Opportunity::default(),
        std::slice::from_ref(&work),
        now
    ));
    budget::finish(&state, std::slice::from_ref(&work), outcome, now);
}

fn seed_demand(manager: &GroupManager, starts: usize, at: Instant) {
    let state = manager.score_state();
    let mut inner = state.inner.lock();
    let set = inner.evaluation_mut("score", SelectionNetwork::Tcp);
    for _ in 0..starts {
        set.record_demand(at);
    }
}

/// One cold trial per outcome, one per member and a second apart, then `ordinary` untracked
/// business starts at the last trial's time.
fn trials_then_business(
    seeded_demand: usize,
    outcomes: &[ScoreOutcome],
    ordinary: usize,
    now: Instant,
) -> (GroupManager, [Node; 4], ScoreSelectionContext) {
    let nodes = [node("a"), node("b"), node("c"), node("d")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    seed_demand(&manager, seeded_demand, now);
    let target = context("yield.example", IpVersion::V4);
    let mut at = now;
    for (node, &outcome) in nodes.iter().zip(outcomes) {
        let work = budget::reserve(
            &state,
            &mut state.inner.lock(),
            ("score", &target),
            node.id,
            ScoreEvidenceQuestion::Availability,
            false,
            at,
        );
        run_business(
            &manager,
            &target,
            node,
            work.expect("cold trial"),
            outcome,
            at,
        );
        at += Duration::from_secs(1);
    }
    for _ in 0..ordinary {
        let work = budget::Work::new(
            &state,
            "score",
            &target,
            nodes[0].id,
            ScoreTrialSource::None,
        );
        run_business(
            &manager,
            &target,
            &nodes[0],
            work,
            ScoreOutcome::Cancelled,
            at,
        );
    }
    (manager, nodes, target)
}

#[test]
fn busy_scopes_with_productive_trials_earn_twice_as_fast() {
    // 1000 recent starts is about 2.3 flows per second; none is quiet. Trials settle after their
    // own start, so the business after the third success earns at the busy rate.
    let success = [ScoreOutcome::Success; 3];
    let failure = [ScoreOutcome::Timeout; 3];
    for (demand, outcomes, earned, period) in [
        (0, &success[..], 1, 16),
        (1000, &failure[..], 1, 16),
        (1000, &success[..2], 1, 16),
        (1000, &success[..], 2, 8),
    ] {
        let (manager, _, _) = trials_then_business(demand, outcomes, 17, Instant::now());
        let c = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(
            (c.trial_starts, c.earned_available, c.earning_period),
            (outcomes.len() as u64, earned, period),
            "demand {demand}, trials {outcomes:?}"
        );
    }
}

/// Exercise pause and half-open recovery while only the ordinary incumbent succeeds.
fn run_failing_trials(live: bool) -> (u32, u64, bool) {
    let nodes: Vec<_> = (0..8).map(|index| node(&format!("m{index}"))).collect();
    let refs: Vec<_> = nodes.iter().collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let target = context("pause.example", IpVersion::V4);
    let start = Instant::now();
    let (mut trials, mut budget_reads, mut resumed) = (0, 0, false);
    // The first plan has no completed selection to explore against, so it is ordinary.
    let mut incumbent = None;
    for step in 0..1800 {
        let at = start + Duration::from_secs(step);
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        let reporter = attempt.begin_at(at).unwrap().start_at(at);
        let started = manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .trial_starts;
        if *incumbent.get_or_insert(index) == index {
            reporter.setup_succeeded_at(at);
            // Live replies keep the selection usable; completions alone do not.
            if live {
                reporter.transfer_at(1, 1, at);
            }
            reporter.finish_at(ScoreOutcome::Success, true, at);
        } else {
            assert!(
                started > trials,
                "healthy incumbent lost ordinary service at step {step}, live={live}"
            );
            reporter.finish_at(ScoreOutcome::Timeout, false, at);
        }
        resumed |= budget_reads > 0 && started > trials;
        trials = started;
        let report = state.verification_snapshot_at("score", &target, &refs, at);
        budget_reads +=
            u32::from(report.is_some_and(|report| report.wait_reason == ScoreWaitReason::Budget));
    }
    let counters = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    (budget_reads, counters.budget_blocked, resumed)
}

#[test]
fn failing_trials_pause_only_behind_a_usable_selection() {
    // Backoff alone retries each failed member later; the pause also waits for the scope's
    // failures to decay.
    let (live_paused, live_blocked, resumed) = run_failing_trials(true);
    let (dead_paused, dead_blocked, _) = run_failing_trials(false);
    assert!(live_paused > 0);
    assert!(
        resumed,
        "decayed failures must reopen funded trials after pausing"
    );
    // Credit never runs out here, so only the pause reads and counts as a budget refusal.
    assert_eq!((dead_paused, dead_blocked), (0, 0));
    assert!(live_blocked > 0);
}

#[test]
fn a_failing_scope_tests_one_trial_at_a_time_below_the_pause() {
    let nodes: Vec<_> = (0..8).map(|index| node(&format!("m{index}"))).collect();
    let refs: Vec<_> = nodes.iter().collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let target = context("half-open.example", IpVersion::V4);
    let start = Instant::now();
    // Enough recent demand to evaluate every member, so more than two challengers could be tried.
    seed_demand(&manager, 1000, start);
    // A usable selection before any trial, so the pause rules apply from the first failure.
    train_at(&manager, &nodes[0], &target, 20, 50, 1, start);
    let (mut failed, mut held) = (false, Vec::new());
    for step in 1..30 {
        let at = start + Duration::from_secs(step);
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        let reporter = attempt.begin_at(at).unwrap().start_at(at);
        if index == 0 {
            reporter.setup_succeeded_at(at);
            reporter.transfer_at(1, 1, at);
            reporter.finish_at(ScoreOutcome::Success, true, at);
        } else if !failed {
            // The first trial fails; its failure alone weighs one, below the pause.
            reporter.finish_at(ScoreOutcome::Timeout, false, at);
            failed = true;
        } else {
            held.push(reporter);
        }
    }
    assert!(
        failed && held.len() == 1,
        "only one trial may test a failing scope at a time: failed {failed}, held {}",
        held.len()
    );
}

#[test]
fn a_pause_counts_only_candidates_the_ledger_refuses() {
    let nodes = [node("a"), node("b"), node("c")];
    let refs: Vec<_> = nodes.iter().collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let target = context("refused.example", IpVersion::V4);
    let start = Instant::now();
    train_at(&manager, &nodes[0], &target, 20, 50, 1, start);
    let mut trials = 0;
    for step in 1..60 {
        let at = start + Duration::from_secs(step);
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        let reporter = attempt.begin_at(at).unwrap().start_at(at);
        if index == 0 {
            reporter.setup_succeeded_at(at);
            reporter.transfer_at(1, 1, at);
            reporter.finish_at(ScoreOutcome::Success, true, at);
        } else {
            trials += 1;
            reporter.finish_at(ScoreOutcome::Timeout, false, at);
        }
    }
    let counters = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    // Both failed challengers back off, so no later plan reaches the paused ledger.
    assert_eq!((trials, counters.budget_blocked), (2, 0));
}

#[test]
fn trial_yield_ignores_refusing_targets_and_resets_on_reload() {
    let now = Instant::now();
    let wait = |manager: &GroupManager, node: &Node, target: &ScoreSelectionContext| {
        budget::wait_reason(
            &manager.score_state().inner.lock(),
            ("score", target),
            node.id,
            ScoreEvidenceQuestion::Availability,
            true,
            now + Duration::from_secs(3),
        )
    };
    let (refused, nodes, target) =
        trials_then_business(0, &[ScoreOutcome::TargetFailure; 3], 0, now);
    assert_eq!(wait(&refused, &nodes[0], &target), ScoreWaitReason::None);
    let (failed, nodes, target) = trials_then_business(0, &[ScoreOutcome::Timeout; 3], 0, now);
    assert_eq!(wait(&failed, &nodes[0], &target), ScoreWaitReason::Budget);
    failed
        .score_state()
        .publish_membership(nodes.iter().map(|node| ("score".to_owned(), node.id)));
    assert_eq!(wait(&failed, &nodes[0], &target), ScoreWaitReason::None);
}
