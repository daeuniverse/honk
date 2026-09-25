use super::*;

fn train_cross_pair_responses(
    manager: &GroupManager,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    now: Instant,
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
            if index == 2 { later } else { now },
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
fn cross_pair_responses_require_shared_fresh_reporters_after_old_blocks_expire() {
    let nodes = [node("timing a"), node("timing b"), node("timing c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("timing.example", IpVersion::V4);
    let now = Instant::now();
    rank_at(&manager, &nodes, &target, now);
    train_cross_pair_responses(&manager, &nodes, &target, now);
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
            // Each pair still stands on its own shared blocks until they expire.
            assert_eq!(snapshot.challengers.len(), 2);
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
fn disjoint_response_support_schedules_comparable_business() {
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
    let nodes = [node("timed evidence"), node("timed peer")];
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
    for leaf in &nodes {
        let feedback = manager
            .feedback_for_group_node("score", leaf.id, target.clone())
            .unwrap();
        for _ in 0..4 {
            let reporter = feedback.start_at(observed);
            reporter.setup_succeeded_at(observed);
            reporter.first_response_at(observed);
            reporter.transfer_at(1, 1, observed);
            reporter.finish_at(ScoreOutcome::Success, true, observed);
        }
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let response = |at| {
        decision_at(&state.inner.lock(), &nodes, &target, 0, at)
            .pairs
            .get(1)
            .and_then(|pair| pair.response)
            .is_some()
    };
    let snapshot = state
        .verification_snapshot_at("score", &target, &refs, start + Duration::from_secs(9))
        .unwrap();
    assert_eq!(snapshot.state, ScoreVerificationState::ObservedUsable);
    assert!(response(start + Duration::from_secs(9)));
    let block_end = start + Duration::from_secs(60);
    assert!(response(block_end - Duration::from_millis(1)));
    let expired = state
        .verification_snapshot_at("score", &target, &refs, block_end)
        .unwrap();
    assert_eq!(expired.state, ScoreVerificationState::ObservedUsable);
    assert!(!response(block_end));
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
