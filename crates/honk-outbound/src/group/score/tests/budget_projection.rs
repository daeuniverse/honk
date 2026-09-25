use super::budget::complete_ordinary;
use super::*;

fn assert_readonly_wait(manager: &GroupManager, expected: ScoreWaitReason) {
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    let root_before = manager.score_state().root_business_starts();
    for _ in 0..16 {
        let (_, snapshot) = manager
            .score_verification_for_network("score", SelectionNetwork::Tcp)
            .unwrap();
        assert_eq!(snapshot.wait_reason, expected);
    }
    assert_eq!(
        manager.score_budget_counters("score", SelectionNetwork::Tcp),
        before
    );
    assert_eq!(manager.score_state().root_business_starts(), root_before);
}

#[test]
fn aggregate_budget_wait_requires_both_target_families_exhausted_and_is_readonly() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    // Unfinished flows count as a challenger's completions; the selection must stay ahead of the
    // four that fill a challenger's in-flight slots, or dispatch never reaches the ledger's wait.
    complete_ordinary(&manager, "score", &nodes[0], 5.0);
    assert_readonly_wait(&manager, ScoreWaitReason::ComparableTraffic);
    for family in [IpVersion::V4, IpVersion::V6] {
        let target = context("budget.example", family);
        for _ in 0..2 {
            assert_readonly_wait(&manager, ScoreWaitReason::ComparableTraffic);
            let plan = manager.selection_plan_for_target("score", &target);
            let feedback = plan.entries[0].feedback.as_ref().unwrap();
            feedback.begin().unwrap().finish(ScoreOutcome::Cancelled);
        }
    }
    let exhausted = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(
        (
            exhausted.spent,
            exhausted.cold_available,
            exhausted.earned_available
        ),
        (4, 0, 0)
    );
    assert_readonly_wait(&manager, ScoreWaitReason::Budget);

    let mut pending = Vec::new();
    for leaf in &nodes {
        for _ in 0..4 {
            let feedback = manager
                .feedback_for_group_node(
                    "score",
                    leaf.id,
                    context("pending.example", IpVersion::V4),
                )
                .unwrap();
            pending.push(feedback.business().begin().unwrap());
        }
    }
    assert_readonly_wait(&manager, ScoreWaitReason::InFlight);
    for feedback in pending {
        feedback.finish(ScoreOutcome::Cancelled);
    }
    assert_readonly_wait(&manager, ScoreWaitReason::Budget);
}

#[test]
fn aggregate_inflight_wait_keeps_missing_or_free_target_family_available() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    // An aggregate read counts unfinished flows of both target families; the selection must stay
    // ahead of the eight that fill a challenger's in-flight slots in both.
    complete_ordinary(&manager, "score", &nodes[0], 9.0);
    let mut pending = Vec::new();
    for family in [IpVersion::V4, IpVersion::V6] {
        assert_readonly_wait(&manager, ScoreWaitReason::ComparableTraffic);
        for leaf in &nodes {
            for _ in 0..4 {
                let feedback = manager
                    .feedback_for_group_node("score", leaf.id, context("pending.example", family))
                    .unwrap();
                pending.push(feedback.business().begin().unwrap());
            }
        }
    }
    assert_readonly_wait(&manager, ScoreWaitReason::InFlight);
    for feedback in pending.drain(8..) {
        feedback.finish(ScoreOutcome::Cancelled);
    }
    assert_readonly_wait(&manager, ScoreWaitReason::ComparableTraffic);
    for feedback in pending {
        feedback.finish(ScoreOutcome::Cancelled);
    }
}

#[test]
fn unrelated_inflight_work_cannot_fill_a_target_availability_gap() {
    let nodes = [node("working"), node("partial")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("gap.example", IpVersion::V4);
    let now = Instant::now();
    train_at(&manager, &nodes[0], &target, 8, 10, 1, now);
    train_at(&manager, &nodes[1], &target, 3, 100, 1, now);
    let at = now + Duration::from_secs(2);
    let unrelated = manager
        .feedback_for_group_node(
            "score",
            nodes[1].id,
            context("unrelated.example", IpVersion::V4),
        )
        .unwrap()
        .start_at(at);
    let state = manager.score_state();
    let (index, feedback) =
        state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at);
    assert_eq!(
        index, 1,
        "one unrelated flow cannot replace the one missing target witness"
    );
    feedback
        .begin_at(at)
        .unwrap()
        .start_at(at)
        .finish_at(ScoreOutcome::Cancelled, true, at);
    unrelated.finish_at(ScoreOutcome::Cancelled, true, at);
}

#[test]
fn expired_pending_credit_is_visible_without_refunding_on_read() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    // Pending trials count as the challenger's completions, so two selection completions let
    // it hold one unanswered trial per target; the second target exhausts each family.
    complete_ordinary(&manager, "score", &nodes[0], 2.0);
    let state = manager.score_state();
    let refs = nodes.iter().collect::<Vec<_>>();
    let now = Instant::now();
    let mut pending = Vec::new();
    for family in [IpVersion::V4, IpVersion::V6] {
        for host in ["pending.example", "queued.example"] {
            pending.push(
                state
                    .rank_plan_at("score", &context(host, family), &refs, now)
                    .1,
            );
        }
    }
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(before.reserved, 4);
    let later = now + Duration::from_secs(61);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    for _ in 0..4 {
        let snapshot = state
            .verification_snapshot_at("score", &aggregate, &refs, later)
            .unwrap();
        assert_eq!(snapshot.wait_reason, ScoreWaitReason::ComparableTraffic);
    }
    assert_eq!(
        manager.score_budget_counters("score", SelectionNetwork::Tcp),
        before
    );
    assert_eq!(state.root_business_starts(), 0);
    let reasons = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    let (_, attempt) = state.rank_plan_at(
        "score",
        &context("pending.example", IpVersion::V4),
        &refs,
        later,
    );
    attempt
        .begin_at(later)
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .cold_explore,
        reasons.cold_explore + 1
    );
    assert!(pending[0].begin_at(later).is_err());
}

#[test]
fn expired_earned_reservation_is_available_but_started_work_never_refunds() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    complete_ordinary(&manager, "score", &nodes[0], 1.0);
    let state = manager.score_state();
    let refs = nodes.iter().collect::<Vec<_>>();
    let target = context("earned.example", IpVersion::V4);
    let now = Instant::now();
    for _ in 0..2 {
        state
            .rank_plan_at("score", &target, &refs, now)
            .1
            .begin_at(now)
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
    }
    let factory = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    for _ in 0..14 {
        factory
            .business()
            .begin_at(now)
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
    }
    let pending = state.rank_plan_at("score", &target, &refs, now).1;
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(
        (
            before.business_starts,
            before.spent,
            before.reserved,
            before.earned_available
        ),
        (16, 2, 1, 0)
    );
    let later = now + Duration::from_secs(61);
    assert_eq!(
        state
            .verification_snapshot_at("score", &target, &refs, later)
            .unwrap()
            .wait_reason,
        ScoreWaitReason::ComparableTraffic
    );
    assert_eq!(
        manager.score_budget_counters("score", SelectionNetwork::Tcp),
        before
    );
    let attempt = state.rank_plan_at("score", &target, &refs, later).1;
    let started = attempt.begin_at(later).unwrap();
    assert!(pending.begin_at(later).is_err());
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!((after.spent, after.refunded), (3, 1));
    assert_eq!(
        state
            .verification_snapshot_at("score", &target, &refs, later + Duration::from_secs(61))
            .unwrap()
            .wait_reason,
        ScoreWaitReason::Budget
    );
    assert_eq!(
        manager.score_budget_counters("score", SelectionNetwork::Tcp),
        after
    );
    drop(started);
}

#[test]
fn targeted_unknown_family_uses_its_own_budget_and_inflight_scope() {
    let nodes = [node("a"), node("b"), node("c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    // Unfinished flows count as a challenger's completions; the selection must stay ahead of the
    // four that fill a challenger's in-flight slots, or dispatch never reaches the ledger's wait.
    complete_ordinary(&manager, "score", &nodes[0], 5.0);
    let state = manager.score_state();
    let refs = nodes.iter().collect::<Vec<_>>();
    let now = Instant::now();
    for family in [IpVersion::V4, IpVersion::V6] {
        for _ in 0..3 {
            state
                .rank_plan_at("score", &context("known.example", family), &refs, now)
                .1
                .begin_at(now)
                .unwrap()
                .finish(ScoreOutcome::Cancelled);
        }
    }
    let mut target = context("remote-resolution.example", IpVersion::V4);
    target.target_family = None;
    assert_eq!(
        state
            .verification_snapshot_at("score", &target, &refs, now)
            .unwrap()
            .wait_reason,
        ScoreWaitReason::ComparableTraffic
    );
    let mut active = Vec::new();
    for leaf in &nodes {
        for _ in 0..4 {
            active.push(
                manager
                    .feedback_for_group_node("score", leaf.id, target.clone())
                    .unwrap()
                    .business()
                    .begin_at(now)
                    .unwrap(),
            );
        }
    }
    assert_eq!(
        state
            .verification_snapshot_at("score", &target, &refs, now)
            .unwrap()
            .wait_reason,
        ScoreWaitReason::InFlight
    );
    for work in active.drain(8..) {
        work.finish(ScoreOutcome::Cancelled);
    }
    assert_eq!(
        state
            .verification_snapshot_at("score", &target, &refs, now)
            .unwrap()
            .wait_reason,
        ScoreWaitReason::InFlight
    );
    let (index, attempt) = state.rank_plan_at("score", &target, &refs, now);
    assert_eq!(
        index, 2,
        "a blocked unknown-family candidate must not hide a reservable sibling"
    );
    attempt
        .begin_at(now)
        .unwrap()
        .finish(ScoreOutcome::Cancelled);
}

#[test]
fn aggregate_read_skips_a_challenger_its_begun_trial_holds_at_the_selection() {
    let nodes = [node("selection"), node("progressing"), node("behind")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let refs = nodes.iter().collect::<Vec<_>>();
    let now = Instant::now();
    // The progressing member is further along its availability question than the usable member
    // behind is on its response pair, so progress alone would serve it first.
    for (leaf, completed, reporters) in [(0, 4.0, 4), (1, 3.0, 3), (2, 1.0, 4)] {
        state.inner.lock().aggregate.put(
            AggregateKey {
                group: "score".into(),
                network: SelectionNetwork::Tcp,
                family: None,
                node_id: nodes[leaf].id,
            },
            Stats {
                setup_success: completed,
                availability: Availability {
                    reporters,
                    latest_rx_at: Some(now),
                    ..Default::default()
                },
                updated_at: Some(now),
                ..Default::default()
            },
        );
    }
    let target = context("ceiling.example", IpVersion::V4);
    let (index, attempt) = state.rank_plan_at("score", &target, &refs, now);
    assert_eq!(index, 1);
    let _begun = attempt.begin_at(now).unwrap();
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let snapshot = state
        .verification_snapshot_at("score", &aggregate, &refs, now)
        .unwrap();
    assert_eq!(
        (snapshot.question, snapshot.next_action),
        (
            ScoreEvidenceQuestion::Response,
            ScoreValidationAction::NextBusinessFlow
        ),
        "three completions and one begun trial already match the selection's four"
    );
    assert_eq!(state.rank_plan_at("score", &target, &refs, now).0, 2);
}
