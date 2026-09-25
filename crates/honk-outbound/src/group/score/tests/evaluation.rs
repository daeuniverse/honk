use super::super::evaluation::{self, EvaluationSet};
use super::super::ranking::performance_baseline;
use super::*;

fn members(count: usize) -> Vec<Node> {
    (0..count)
        .map(|index| node(&format!("member-{index}")))
        .collect()
}

fn idle_scores(count: usize) -> (Vec<ScoreSnapshot>, PerformanceBaseline) {
    let scores = vec![ScoreSnapshot::default(); count];
    let baseline = performance_baseline(&scores);
    (scores, baseline)
}

#[test]
fn evaluation_limit_follows_offered_business_only_at_refresh() {
    let nodes = members(40);
    let refs: Vec<_> = nodes.iter().collect();
    let (scores, baseline) = idle_scores(nodes.len());
    let now = Instant::now();
    let idle = evaluation::derive(None, &refs, &scores, baseline, now, true).into_owned();
    let idle_membership = idle.membership(&refs, 0, baseline.any_qualified);
    assert_eq!(idle_membership.evaluated.iter().filter(|v| **v).count(), 4);
    let mut busy = idle;
    for second in 0..240 {
        busy.record_demand(now + Duration::from_secs(second));
    }
    let before_refresh = evaluation::derive(
        Some(&busy),
        &refs,
        &scores,
        baseline,
        now + Duration::from_secs(240),
        true,
    )
    .into_owned();
    assert_eq!(
        before_refresh
            .membership(&refs, 0, baseline.any_qualified)
            .evaluated
            .iter()
            .filter(|v| **v)
            .count(),
        4,
        "growth waits for the refresh period"
    );
    for second in 240..600 {
        busy.record_demand(now + Duration::from_secs(second));
    }
    let refreshed = evaluation::derive(
        Some(&busy),
        &refs,
        &scores,
        baseline,
        now + Duration::from_secs(600),
        true,
    )
    .into_owned();
    let evaluated = refreshed
        .membership(&refs, 0, baseline.any_qualified)
        .evaluated
        .iter()
        .filter(|v| **v)
        .count();
    // 600 one-per-second starts decay to 324 under the five-minute half-life, sizing 16
    // members; undecayed demand would reach the 25-member cap.
    assert_eq!(evaluated, 16);
}

#[test]
fn members_missing_from_one_view_keep_their_place() {
    let nodes = members(12);
    let refs: Vec<_> = nodes.iter().collect();
    let (scores, baseline) = idle_scores(nodes.len());
    let now = Instant::now();
    let set = evaluation::derive(None, &refs, &scores, baseline, now, true).into_owned();
    let ranked = set
        .membership(&refs, usize::MAX, baseline.any_qualified)
        .covered
        .iter()
        .position(|covered| *covered)
        .unwrap();
    let absent = refs[ranked].id;
    let view: Vec<_> = refs
        .iter()
        .copied()
        .filter(|node| node.id != absent)
        .collect();
    let (view_scores, view_baseline) = idle_scores(view.len());
    let later = evaluation::derive(
        Some(&set),
        &view,
        &view_scores,
        view_baseline,
        now + Duration::from_secs(600),
        true,
    )
    .into_owned();
    assert!(
        later.evaluates(absent),
        "a retry or filtered view is not a membership removal"
    );
}

#[test]
fn ranked_members_join_coverage_at_their_first_qualification() {
    let nodes = members(3);
    let refs: Vec<_> = nodes.iter().collect();
    let now = Instant::now();
    let (idle, _) = idle_scores(3);
    let qualified = ScoreSnapshot {
        useful_completed: PERFORMANCE_VALIDATION_SAMPLES,
        ..Default::default()
    };
    let unknown = ScoreSnapshot::default();
    let derive = |stored: Option<&EvaluationSet>, scores: &[ScoreSnapshot]| {
        evaluation::derive(
            stored,
            &refs,
            scores,
            performance_baseline(scores),
            now,
            true,
        )
        .into_owned()
    };
    let covered = |set: &EvaluationSet, qualified| set.membership(&refs, 0, qualified).covered;
    // Qualification cannot gate coverage before any member is qualified.
    let cold = derive(None, &idle);
    assert_eq!(covered(&cold, false), [true, true, true]);
    // Once one is, members still acquiring evidence are evaluated but cannot stall alignment.
    let first = derive(Some(&cold), &[qualified, qualified, unknown]);
    assert_eq!(covered(&first, true), [true, true, false]);
    assert!(first.membership(&refs, 0, true).evaluated[2]);
    // Admission outlives a later lapse, so coverage does not shrink with it.
    let lapsed = derive(Some(&first), &[qualified, unknown, unknown]);
    assert_eq!(covered(&lapsed, true), [true, true, false]);
}

#[test]
fn rotation_visits_every_member_outside_the_ranked_set() {
    let nodes = members(10);
    let refs: Vec<_> = nodes.iter().collect();
    let (scores, baseline) = idle_scores(nodes.len());
    let start = Instant::now();
    let mut set: Option<EvaluationSet> = None;
    let mut visited = std::collections::HashSet::new();
    for slot in 0..10 {
        let derived = evaluation::derive(
            set.as_ref(),
            &refs,
            &scores,
            baseline,
            start + Duration::from_secs(600 * slot),
            true,
        )
        .into_owned();
        let membership = derived.membership(&refs, usize::MAX, baseline.any_qualified);
        for (index, node) in refs.iter().enumerate() {
            if membership.evaluated[index] && !membership.covered[index] {
                visited.insert(node.id);
            }
        }
        set = Some(derived);
    }
    let final_set = set.unwrap();
    let outside = refs
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            !final_set
                .membership(&refs, usize::MAX, baseline.any_qualified)
                .covered[*index]
        })
        .count();
    assert_eq!(outside, 8);
    assert_eq!(visited.len(), outside);
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
        let set = &inner.evaluation[&key];
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
    assert!(covered(&state, &target, &all, now + Duration::from_secs(1)) <= report.evaluated_count);
}

fn covered(
    state: &ScorePolicyState,
    target: &ScoreSelectionContext,
    refs: &[&Node],
    at: Instant,
) -> usize {
    let inner = state.inner.lock();
    super::super::ranking::decision(&inner, "score", target, refs, at, false)
        .membership
        .covered
        .iter()
        .filter(|covered| **covered)
        .count()
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
            .evaluation
            .get_mut(&key)
            .unwrap()
            .record_demand(now + Duration::from_secs(second));
    }
    let at = now + Duration::from_secs(600);
    let report = state
        .verification_snapshot_at("score", &target, &refs, at)
        .unwrap();
    assert!(
        report.evaluated_count <= 4,
        "GET cannot expand committed coverage"
    );
    rank_at(&manager, &nodes, &target, at);
    let applied = state
        .verification_snapshot_at("score", &target, &refs, at)
        .unwrap();
    assert_eq!(applied.evaluated_count, 17);
}

#[test]
fn qualified_readonly_bootstrap_waits_for_committed_participants() {
    let nodes = members(2);
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("bootstrap.example", IpVersion::V4);
    let refs: Vec<_> = nodes.iter().collect();
    let now = Instant::now();
    for leaf in &nodes {
        train_at(&manager, leaf, &target, 8, 100, 1, now);
    }
    let state = manager.score_state();
    let at = now + Duration::from_secs(2);
    assert_eq!(covered(&state, &target, &refs, at), 1);
    rank_at(&manager, &nodes, &target, at);
    assert_eq!(covered(&state, &target, &refs, at), 2);
    let committed = state
        .verification_snapshot_at("score", &target, &refs, at)
        .unwrap();
    let relations: Vec<_> = committed.challengers.iter().map(|c| c.relation).collect();
    assert_eq!(relations, [ScoreRelation::Equivalent]);
}

#[test]
fn live_recovery_admits_coverage_before_settlement() {
    let nodes = members(3);
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("live-admission.example", IpVersion::V4);
    let refs: Vec<_> = nodes.iter().collect();
    let now = Instant::now();
    rank_at(&manager, &nodes, &target, now);
    for leaf in &nodes[..2] {
        train_at(&manager, leaf, &target, 8, 100, 1, now);
    }
    let feedback = manager
        .feedback_for_group_node("score", nodes[2].id, target.clone())
        .unwrap();
    for _ in 0..3 {
        let reporter = feedback.start_at(now + Duration::from_secs(2));
        reporter.setup_succeeded_at(now + Duration::from_secs(2));
        reporter.finish_at(
            ScoreOutcome::TargetFailure,
            true,
            now + Duration::from_secs(2),
        );
    }
    let state = manager.score_state();
    let at = now + Duration::from_secs(3);
    assert_eq!(covered(&state, &target, &refs, at), 2);
    let reporters: Vec<_> = (0..4).map(|_| feedback.start_at(at)).collect();
    for reporter in &reporters {
        reporter.setup_succeeded_at(at);
        reporter.first_response_at(at);
        reporter.transfer_at(1, 1, at);
    }
    assert_eq!(covered(&state, &target, &refs, at), 3);
    let expired = at + PERFORMANCE_MAX_AGE + Duration::from_secs(1);
    assert_eq!(covered(&state, &target, &refs, expired), 3);
    let lapsed = score_snapshot(&state.inner.lock(), "score", &target, nodes[2].id, expired);
    assert!(!lapsed.qualified());
    for reporter in reporters {
        reporter.finish_at(ScoreOutcome::Cancelled, false, expired);
    }
}
