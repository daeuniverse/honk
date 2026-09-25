use super::*;

fn train_cross_pair_responses(
    manager: &GroupManager,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    now: Instant,
    aligned: bool,
) {
    let later = now + Duration::from_secs(16);
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            manager,
            leaf,
            target,
            4,
            100 * (index as u64 + 1),
            1,
            if aligned || index == 0 || index % 2 == 1 {
                now
            } else {
                later
            },
        );
    }
    train_at(manager, &nodes[0], target, 4, 100, 1, later);
}

#[test]
fn healthy_three_leaf_comparison_renews_after_expiry() {
    let nodes = [node("slow"), node("medium"), node("fast")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("renewal.example", IpVersion::V4);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let start = Instant::now();
    let mut renewed = [false; 3];
    for step in 0..1200 {
        let at = start + Duration::from_millis(step * 250);
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        let reporter = attempt.begin_at(at).unwrap().start_at(at);
        reporter.setup_succeeded_at(at + Duration::from_millis(1));
        let response = at + Duration::from_millis([200, 100, 40][index]);
        reporter.first_response_at(response);
        reporter.transfer_at(128, 512, response);
        reporter.finish_at(ScoreOutcome::Success, true, response);
        let budget = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(budget.business_starts, step + 1);
        assert!(
            budget.spent + budget.reserved
                <= budget.cold_allowance + budget.business_starts / budget.earning_period
        );
        if step >= 480 && step % 4 == 3 {
            let snapshot = state
                .verification_snapshot_at("score", &target, &refs, response)
                .unwrap();
            renewed[(step / 240 - 2) as usize] |= snapshot.challengers.len() == 2
                && snapshot
                    .challengers
                    .iter()
                    .all(|c| c.relation == ScoreRelation::SelectedFaster);
        }
    }
    assert!(renewed.into_iter().all(|supported| supported));
    assert_eq!(
        state.peek_rank_at("score", &target, &refs, start + Duration::from_secs(300)),
        2
    );
}

#[test]
fn cross_pair_response_misalignment_requests_funded_validation_for_control_and_challengers() {
    for aligned in [true, false] {
        let nodes = [node("timing a"), node("timing b"), node("timing c")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("timing.example", IpVersion::V4);
        let now = Instant::now();
        rank_at(&manager, &nodes, &target, now);
        train_cross_pair_responses(&manager, &nodes, &target, now, aligned);
        let state = manager.score_state();
        let refs: Vec<_> = nodes.iter().collect();
        let at = now + Duration::from_secs(19);
        let decision = decision_at(&state.inner.lock(), &nodes, &target, 0, at);
        assert_eq!(decision.ordinary.index, 0);
        assert!(decision.scores.iter().all(ScoreSnapshot::qualified));
        for index in [1, 2] {
            let pair = decision.pairs.get(index).unwrap();
            assert!(pair.response.is_some());
            assert!(pair.upload.is_none() && pair.download.is_none());
        }
        let evaluation = verification_engine::evaluate(&decision, &refs, &target, None, at);
        let budget_before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let verification_before = state.verification_counters("score", SelectionNetwork::Tcp);
        for _ in 0..4 {
            let snapshot = state
                .verification_snapshot_at("score", &target, &refs, at)
                .unwrap();
            assert_eq!(snapshot, evaluation.snapshot);
            assert_eq!(snapshot.challengers.len(), 2);
            assert_eq!(
                snapshot.question,
                if aligned {
                    ScoreEvidenceQuestion::None
                } else {
                    ScoreEvidenceQuestion::Response
                }
            );
        }
        assert_eq!(
            manager.score_budget_counters("score", SelectionNetwork::Tcp),
            budget_before
        );
        assert_eq!(
            state.verification_counters("score", SelectionNetwork::Tcp),
            verification_before
        );
        if aligned {
            assert_eq!(evaluation.snapshot.next_action, ScoreValidationAction::None);
            assert!(
                evaluation
                    .candidates
                    .iter()
                    .all(|candidate| { candidate.question == ScoreEvidenceQuestion::None })
            );
            continue;
        }
        assert_eq!(
            evaluation.snapshot.question,
            ScoreEvidenceQuestion::Response
        );
        assert_eq!(
            evaluation.snapshot.next_action,
            ScoreValidationAction::NextBusinessFlow
        );
        assert_eq!(
            evaluation.snapshot.wait_reason,
            ScoreWaitReason::ComparableTraffic
        );
        assert_eq!(evaluation.snapshot.pending_count, 3);
        for candidate in &evaluation.candidates {
            assert_eq!(candidate.question, ScoreEvidenceQuestion::Response);
            assert_eq!(candidate.required, 4);
        }
        let mut reporters = Vec::new();
        let mut assigned = [0_usize; 3];
        for turn in 0..8 {
            if turn == 3 {
                let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
                assert_eq!((before.cold_available, before.earned_available), (0, 1));
                assert_eq!(
                    state
                        .verification_snapshot_at("score", &target, &refs, at)
                        .unwrap()
                        .wait_reason,
                    ScoreWaitReason::ComparableTraffic
                );
                assert_eq!(
                    manager.score_budget_counters("score", SelectionNetwork::Tcp),
                    before
                );
            }
            let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
            assigned[index] += 1;
            reporters.push(attempt.begin_at(at).unwrap().start_at(at));
        }
        assert!(assigned.into_iter().all(|count| count > 0));
        for reporter in reporters {
            reporter.finish_at(ScoreOutcome::Cancelled, true, at);
        }
        let spent = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(spent.trial_starts, 4);
        assert_eq!(spent.cold_trial_starts, 3);
        assert_eq!(spent.periodic_trial_starts, 1);
        assert_eq!(spent.reserved, 0);
        assert_eq!(spent.cold_available, 0);
        assert_eq!(spent.earned_available, 0);
        assert!(spent.spent <= spent.cold_allowance + spent.business_starts / spent.earning_period);
        let exhausted = state
            .verification_snapshot_at("score", &target, &refs, at)
            .unwrap();
        assert_eq!(exhausted.question, ScoreEvidenceQuestion::Response);
        assert_eq!(exhausted.wait_reason, ScoreWaitReason::Budget);
        assert_eq!(
            manager.score_budget_counters("score", SelectionNetwork::Tcp),
            spent
        );
        for step in 0..56 {
            let control_at = at + Duration::from_secs(46) + Duration::from_millis(step * 200);
            let (index, attempt) = state.rank_plan_at("score", &target, &refs, control_at);
            assert_eq!(index, 0);
            let reporter = attempt.begin_at(control_at).unwrap().start_at(control_at);
            reporter.setup_succeeded_at(control_at);
            let response_at = control_at + Duration::from_millis(100);
            reporter.first_response_at(response_at);
            reporter.transfer_at(1, 1, response_at);
            reporter.finish_at(ScoreOutcome::Success, true, response_at);
        }
        let earned = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(earned.business_starts, 80);
        assert_eq!(earned.trial_starts, 4);
        assert_eq!(earned.earned_available, 4);
        let control_at = at + Duration::from_secs(58);
        let (index, control) = state.rank_plan_at("score", &target, &refs, control_at);
        assert_eq!(index, 0);
        respond_at(control, Duration::from_millis(100), control_at);
        let funded_at = at + Duration::from_secs(59);
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, funded_at);
        assert_ne!(index, 0);
        attempt
            .begin_at(funded_at)
            .unwrap()
            .start_at(funded_at)
            .finish_at(ScoreOutcome::Cancelled, true, funded_at);
        let funded = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(funded.trial_starts, 5);
        assert_eq!(funded.periodic_trial_starts, 2);
        assert_eq!(funded.earned_available, 3);
        assert!(
            funded.spent + funded.reserved
                <= funded.cold_allowance + funded.business_starts / funded.earning_period
        );
    }
}

#[test]
fn cross_pair_response_repair_requires_shared_fresh_reporters_after_old_blocks_expire() {
    let nodes = [node("timing a"), node("timing b"), node("timing c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("timing.example", IpVersion::V4);
    let now = Instant::now();
    rank_at(&manager, &nodes, &target, now);
    train_cross_pair_responses(&manager, &nodes, &target, now, false);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    for (offset, samples) in [(32, 1), (96, 1), (98, 3)] {
        let at = now + Duration::from_secs(offset);
        for (index, leaf) in nodes.iter().enumerate() {
            train_at(
                &manager,
                leaf,
                &target,
                samples,
                100 * (index as u64 + 1),
                1,
                at,
            );
        }
        let snapshot = state
            .verification_snapshot_at("score", &target, &refs, at + Duration::from_secs(2))
            .unwrap();
        if offset == 98 {
            assert_eq!(snapshot.challengers.len(), 2);
            assert_eq!(snapshot.question, ScoreEvidenceQuestion::None);
            assert_eq!(snapshot.pending_count, 0);
            assert_eq!(snapshot.next_action, ScoreValidationAction::None);
        } else if offset == 32 {
            assert_eq!(snapshot.question, ScoreEvidenceQuestion::Response);
        } else {
            let decision = decision_at(
                &state.inner.lock(),
                &nodes,
                &target,
                0,
                at + Duration::from_secs(2),
            );
            for index in [1, 2] {
                assert!(decision.pairs.get(index).unwrap().response.is_none());
            }
        }
    }
}

#[test]
fn disjoint_response_support_schedules_comparable_business_not_bulk_transfer() {
    let nodes = [node("incumbent"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("shared.example", IpVersion::V4);
    let now = Instant::now();
    train_at(&manager, &nodes[1], &target, 8, 100, 1, now);
    let later = now + Duration::from_secs(16);
    train_at(&manager, &nodes[0], &target, 8, 10, 1, later);
    let at = later + Duration::from_secs(2);
    let state = manager.score_state();
    let snapshot = state
        .verification_snapshot_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at)
        .unwrap();
    assert!(snapshot.challengers.is_empty());
    assert_eq!(snapshot.question, ScoreEvidenceQuestion::Response);
    assert_eq!(
        snapshot.next_action,
        ScoreValidationAction::NextBusinessFlow
    );
    assert_eq!(snapshot.wait_reason, ScoreWaitReason::ComparableTraffic);
    let (index, feedback) =
        state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at);
    assert_eq!(index, 1);
    feedback
        .begin_at(at)
        .unwrap()
        .start_at(at)
        .finish_at(ScoreOutcome::Cancelled, true, at);
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .trial_starts,
        1
    );
}

#[test]
fn winner_only_probe_does_not_replace_common_business_response_evidence() {
    let nodes = [node("business winner"), node("business peer")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("shared.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    rank_at(&manager, &nodes, &target, now);
    for leaf in &nodes {
        train_at(&manager, leaf, &target, 4, 100, 1, now);
    }
    let at = now + Duration::from_secs(2);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let before = state
        .verification_snapshot_at("score", &aggregate, &refs, at)
        .unwrap();
    let relations: Vec<_> = before
        .challengers
        .iter()
        .map(|c| (c.basis, c.relation))
        .collect();
    assert_eq!(
        relations,
        [(ScoreEvidenceBasis::CommonTargets, ScoreRelation::Equivalent)]
    );
    let winner = state.peek_rank_at("score", &aggregate, &refs, at);
    probe_at(
        &manager,
        &nodes[winner],
        &context("health.example", IpVersion::V4),
        100,
        at,
    );
    let after = state
        .verification_snapshot_at("score", &aggregate, &refs, at)
        .unwrap();
    assert_eq!(after, before);
}
#[test]
fn response_validity_uses_the_support_block_not_event_time() {
    let nodes = [node("timed evidence")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let start = Instant::now();
    let seed = manager
        .feedback_for_group_node(
            "score",
            nodes[0].id,
            context("block-origin.example", IpVersion::V4),
        )
        .unwrap()
        .start_at(start);
    seed.setup_succeeded_at(start);
    seed.first_response_at(start);
    seed.finish_at(ScoreOutcome::Cancelled, false, start);
    let target = context("observed-later.example", IpVersion::V4);
    let observed = start + Duration::from_secs(7);
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    for _ in 0..4 {
        let reporter = feedback.start_at(observed);
        reporter.setup_succeeded_at(observed);
        reporter.first_response_at(observed);
        reporter.transfer_at(1, 1, observed);
        reporter.finish_at(ScoreOutcome::Success, true, observed);
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let snapshot = state
        .verification_snapshot_at("score", &target, &refs, start + Duration::from_secs(9))
        .unwrap();
    assert_eq!(snapshot.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(snapshot.question, ScoreEvidenceQuestion::None);
    let block_end = start + Duration::from_secs(60);
    let last = state
        .verification_snapshot_at(
            "score",
            &target,
            &refs,
            block_end - Duration::from_millis(1),
        )
        .unwrap();
    assert_eq!(last.question, ScoreEvidenceQuestion::None);
    let expired = state
        .verification_snapshot_at("score", &target, &refs, block_end)
        .unwrap();
    assert_eq!(expired.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(expired.question, ScoreEvidenceQuestion::Response);
}

#[test]
fn sparse_common_support_stays_pending_until_every_common_target_qualifies() {
    let nodes = [node("partial a"), node("partial b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let dense = context("a.dense.example", IpVersion::V4);
    let sparse = context("b.sparse.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    rank_at(&manager, &nodes, &dense, now);
    for leaf in &nodes {
        train_at(&manager, leaf, &sparse, 1, 100, 1, now);
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let unknown = state
        .verification_snapshot_at("score", &aggregate, &refs, now + Duration::from_secs(2))
        .unwrap();
    assert!(unknown.challengers.is_empty());
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &dense,
            4,
            100,
            1,
            now + Duration::from_secs(2),
        );
    }
    let partial = state
        .verification_snapshot_at("score", &aggregate, &refs, now + Duration::from_secs(4))
        .unwrap();
    let relations = |snapshot: &ScoreVerificationSnapshot| {
        snapshot
            .challengers
            .iter()
            .map(|c| (c.basis, c.relation))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        relations(&partial),
        [(ScoreEvidenceBasis::CommonTargets, ScoreRelation::Equivalent)]
    );
    assert_eq!(partial.question, ScoreEvidenceQuestion::Response);
    let exact = state
        .verification_snapshot_at("score", &dense, &refs, now + Duration::from_secs(4))
        .unwrap();
    assert_eq!(
        relations(&exact),
        [(
            ScoreEvidenceBasis::TargetResponse,
            ScoreRelation::Equivalent
        )]
    );
    assert_ne!(exact.question, ScoreEvidenceQuestion::Response);
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &sparse,
            3,
            100,
            1,
            now + Duration::from_secs(4),
        );
    }
    let complete = state
        .verification_snapshot_at("score", &aggregate, &refs, now + Duration::from_secs(6))
        .unwrap();
    assert_eq!(
        relations(&complete),
        [(ScoreEvidenceBasis::CommonTargets, ScoreRelation::Equivalent)]
    );
    assert_ne!(complete.question, ScoreEvidenceQuestion::Response);
}
