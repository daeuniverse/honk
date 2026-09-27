use super::super::evaluation::{self, EvaluationSet};
use super::*;

fn members(count: usize) -> Vec<Node> {
    (0..count)
        .map(|index| node(&format!("member-{index}")))
        .collect()
}

fn idle_scores(count: usize) -> Vec<ScoreSnapshot> {
    vec![ScoreSnapshot::default(); count]
}

#[test]
fn evaluation_limit_follows_offered_business_only_at_refresh() {
    let nodes = members(400);
    let refs: Vec<_> = nodes.iter().collect();
    let scores = idle_scores(nodes.len());
    let now = Instant::now();
    let idle = evaluation::derive(None, &refs, &scores, now, true, std::iter::empty(), |_| {
        false
    })
    .into_owned();
    let idle_membership = idle.membership(&refs);
    assert_eq!(idle_membership.iter().filter(|v| **v).count(), 3);
    let mut busy = idle;
    for second in 0..240 {
        busy.record_demand(now + Duration::from_secs(second));
    }
    let before_refresh = evaluation::derive(
        Some(&busy),
        &refs,
        &scores,
        now + Duration::from_secs(240),
        true,
        std::iter::empty(),
        |_| false,
    )
    .into_owned();
    assert_eq!(
        before_refresh
            .membership(&refs)
            .iter()
            .filter(|v| **v)
            .count(),
        3,
        "growth waits for the refresh period"
    );
    for second in 240..600 {
        busy.record_demand(now + Duration::from_secs(second));
    }
    let refreshed = evaluation::derive(
        Some(&busy),
        &refs,
        &scores,
        now + Duration::from_secs(600),
        true,
        std::iter::empty(),
        |_| false,
    )
    .into_owned();
    let evaluated = refreshed.membership(&refs).iter().filter(|v| **v).count();
    // 600 one-per-second starts decay to 324 under the five-minute half-life, sizing 16
    // members below this group's √n cap; undecayed demand would reach the 25-member cap.
    assert_eq!(evaluated, 16);
}

#[test]
fn members_missing_from_one_view_keep_their_place() {
    let nodes = members(12);
    let refs: Vec<_> = nodes.iter().collect();
    let scores = idle_scores(nodes.len());
    let now = Instant::now();
    let set = evaluation::derive(None, &refs, &scores, now, true, std::iter::empty(), |_| {
        false
    })
    .into_owned();
    let ranked = set
        .membership(&refs)
        .iter()
        .position(|evaluated| *evaluated)
        .unwrap();
    let absent = refs[ranked].id;
    let view: Vec<_> = refs
        .iter()
        .copied()
        .filter(|node| node.id != absent)
        .collect();
    let view_scores = idle_scores(view.len());
    let later = evaluation::derive(
        Some(&set),
        &view,
        &view_scores,
        now + Duration::from_secs(600),
        true,
        std::iter::empty(),
        |_| false,
    )
    .into_owned();
    assert!(
        later.evaluates(absent),
        "a retry or filtered view is not a membership removal"
    );
}

#[test]
fn rotation_visits_every_member_outside_the_ranked_set() {
    let nodes = members(10);
    let refs: Vec<_> = nodes.iter().collect();
    let scores = idle_scores(nodes.len());
    let start = Instant::now();
    let mut set: Option<EvaluationSet> = None;
    let mut visited = std::collections::HashSet::new();
    for slot in 0..10 {
        let derived = evaluation::derive(
            set.as_ref(),
            &refs,
            &scores,
            start + Duration::from_secs(600 * slot),
            true,
            std::iter::empty(),
            |_| false,
        )
        .into_owned();
        let membership = derived.membership(&refs);
        assert_eq!(membership.iter().filter(|v| **v).count(), 3);
        for (index, node) in refs.iter().enumerate() {
            if membership[index] {
                visited.insert(node.id);
            }
        }
        set = Some(derived);
    }
    // Two ranked members plus one ten-minute rotation slot reach all ten in ten slots.
    assert_eq!(visited.len(), 10);
}

#[test]
fn readonly_reads_never_store_an_evaluation_set() {
    let nodes = members(10);
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let state = manager.score_state();
    state
        .verification_snapshot_at("score", &target, &nodes.iter().collect::<Vec<_>>(), now)
        .unwrap();
    state.peek_rank_at("score", &target, &nodes.iter().collect::<Vec<_>>(), now);
    assert!(state.inner.lock().evaluation.is_empty());
    rank_at(&manager, &nodes, &target, now);
    assert_eq!(state.inner.lock().evaluation.len(), 1);
}

#[test]
fn unevaluated_members_keep_probes_out_of_comparison_cells() {
    let nodes = members(10);
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let probe = context("health.example", IpVersion::V4);
    let now = Instant::now();
    rank_at(&manager, &nodes, &target, now);
    let state = manager.score_state();
    let key = SelectionReasonKey::new("score", SelectionNetwork::Tcp);
    let (inside, outside) = {
        let inner = state.inner.lock();
        let set = inner.evaluation(&key.group, key.network).unwrap();
        (
            nodes
                .iter()
                .find(|node| set.evaluates(node.id))
                .unwrap()
                .clone(),
            nodes
                .iter()
                .find(|node| set.excludes(node.id))
                .unwrap()
                .clone(),
        )
    };
    let cells = || state.inner.lock().comparisons.cell_count();
    let before = cells();
    probe_at(&manager, &outside, &probe, 10, now);
    assert_eq!(cells(), before);
    probe_at(&manager, &inside, &probe, 10, now);
    assert_eq!(cells(), before + 1);
}

#[test]
fn a_hundred_members_reach_bounded_comparisons_at_moderate_traffic() {
    let nodes = members(100);
    let refs: Vec<_> = nodes.iter().collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let target = context("business.example", IpVersion::V4);
    let probe = context("health.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let latency = |index: usize| 40 + (index as u64 * 37) % 400;
    let start = Instant::now();
    let mut compared = None;
    let mut widest = 0;
    // About 1.5 business flows per second for 25 minutes, with 30-second configured probes.
    for step in 0..2250u64 {
        let at = start + Duration::from_millis(step * 667);
        if step % 45 == 0 {
            for (index, leaf) in nodes.iter().enumerate() {
                let reporter = manager
                    .feedback_for_group_node("score", leaf.id, probe.clone())
                    .unwrap()
                    .with_source(ScoreSource::HealthProbe)
                    .with_probe_interval(Duration::from_secs(30))
                    .start_at(at);
                reporter.probe_latency_at(Duration::from_millis(latency(index)), at);
                reporter.finish_at(ScoreOutcome::Success, false, at);
            }
        }
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        respond_at(attempt, Duration::from_millis(latency(index)), at);
        if step % 15 == 0 {
            let snapshot = state
                .verification_snapshot_at(
                    "score",
                    &aggregate,
                    &refs,
                    at + Duration::from_millis(latency(index)),
                )
                .unwrap();
            widest = widest.max(snapshot.evaluated_count);
            assert!(snapshot.pending_count <= snapshot.evaluated_count);
            if !snapshot.challengers.is_empty() {
                compared.get_or_insert(snapshot);
            }
        }
    }
    let snapshot = compared.expect("a bounded evaluation set must be able to compare");
    assert!(snapshot.evaluated_count < snapshot.candidate_count);
    assert!(widest <= 26, "{widest}");
    let budget = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert!(
        budget.trial_starts
            <= exploration_target(100) as u64 + budget.business_starts / SCORE_EXPLORATION_PERIOD
    );
}

#[test]
fn filtered_views_cannot_disable_evaluation_bounds() {
    let nodes = members(100);
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let target = context("filtered.example", IpVersion::V4);
    let now = Instant::now();
    let short: Vec<_> = nodes[..2].iter().collect();
    state.rank_at("score", &target, &short, now);
    let all: Vec<_> = nodes.iter().collect();
    let report = state
        .verification_snapshot_at("score", &target, &all, now + Duration::from_secs(1))
        .unwrap();
    assert_eq!(report.candidate_count, 100);
    assert!(report.evaluated_count <= 4);
}

#[test]
fn readonly_refresh_does_not_replace_committed_participants() {
    let nodes = members(100);
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let target = context("readonly.example", IpVersion::V4);
    let refs: Vec<_> = nodes.iter().collect();
    let now = Instant::now();
    rank_at(&manager, &nodes, &target, now);
    let key = SelectionReasonKey::new("score", SelectionNetwork::Tcp);
    for second in 0..600 {
        state
            .inner
            .lock()
            .evaluation_mut(&key.group, key.network)
            .record_demand(now + Duration::from_secs(second));
    }
    let at = now + Duration::from_secs(600);
    let report = state
        .verification_snapshot_at("score", &target, &refs, at)
        .unwrap();
    assert!(
        report.evaluated_count <= 3,
        "GET cannot expand committed coverage"
    );
    rank_at(&manager, &nodes, &target, at);
    let applied = state
        .verification_snapshot_at("score", &target, &refs, at)
        .unwrap();
    // Demand sizes 16 members, but a hundred-member group caps at ⌈√100⌉ + 1 = 11.
    assert_eq!(applied.evaluated_count, 11);
}

#[test]
fn only_node_failure_streaks_replace_shared_evaluation_members() {
    let mut nodes = members(12);
    nodes.sort_by_key(|node| node.id);
    let refs: Vec<_> = nodes.iter().collect();
    let good = context("healthy.example", IpVersion::V4);
    let bad = context("failing.example", IpVersion::V6);
    let start = Instant::now();
    let key = SelectionReasonKey::new("score", SelectionNetwork::Tcp);
    for outcome in [ScoreOutcome::TargetFailure, ScoreOutcome::NodeFailure] {
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let state = manager.score_state();
        state.rank_at("score", &good, &refs, start);
        let retained = || {
            state
                .inner
                .lock()
                .evaluation(&key.group, key.network)
                .unwrap()
                .evaluates(nodes[1].id)
        };
        assert!(retained());
        for streak in 1..=SCORE_FAIL_STREAK_EXCLUDE {
            let at = start + Duration::from_secs(u64::from(streak));
            let reporter = manager
                .feedback_for_group_node("score", nodes[1].id, bad.clone())
                .unwrap()
                .start_at(at);
            reporter.setup_succeeded_at(at);
            reporter.finish_at(outcome, true, at);
            state.peek_rank_at("score", &bad, &refs, at);
            assert!(retained(), "readonly cannot commit failure substitution");
            state.rank_at("score", &bad, &refs, at);
            assert_eq!(
                retained(),
                outcome == ScoreOutcome::TargetFailure || streak < SCORE_FAIL_STREAK_EXCLUDE,
                "{outcome:?}, streak {streak}"
            );
        }
    }
}

#[test]
fn a_short_retry_view_cannot_reduce_funded_capacity() {
    let nodes = members(100);
    let refs: Vec<_> = nodes.iter().collect();
    let scores = idle_scores(nodes.len());
    let start = Instant::now();
    let mut set = EvaluationSet::default();
    for _ in 0..4096 {
        set.record_demand(start);
    }
    let set = evaluation::derive(
        Some(&set),
        &refs,
        &scores,
        start,
        true,
        std::iter::empty(),
        |_| false,
    )
    .into_owned();
    let retry_scores = idle_scores(1);
    let retry = evaluation::derive(
        Some(&set),
        &refs[..1],
        &retry_scores,
        start + Duration::from_secs(300),
        true,
        std::iter::empty(),
        |_| false,
    )
    .into_owned();
    // The funded hundred-member view retains ten ranked members plus its rotation slot.
    // A one-member retry cannot remove those ranked identities merely by hiding them.
    assert!(
        retry
            .membership(&refs)
            .iter()
            .filter(|&&value| value)
            .count()
            >= 10
    );
}
