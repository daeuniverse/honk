use super::*;

#[test]
fn common_targets_do_not_promote_a_simpson_mixture() {
    let now = Instant::now();
    let nodes = [node("mixture incumbent"), node("mixture candidate")];
    let fast = context("a.fast", IpVersion::V4);
    let slow = context("b.slow", IpVersion::V4);
    let unseen = context("unseen", IpVersion::V4);
    let mut inner = StateInner::default();
    response(&mut inner, &nodes[0], &fast, 4, 100, now);
    response(&mut inner, &nodes[0], &slow, 36, 1000, now);
    response(&mut inner, &nodes[1], &slow, 4, 1100, now);
    response(&mut inner, &nodes[1], &fast, 36, 110, now);
    let mut snapshots = scores(&inner, &nodes, &unseen, now);
    // Heuristic proposals may prefer the candidate's lighter mix; proof may not.
    for (score, ms) in snapshots.scores.iter_mut().zip([1000.0, 110.0]) {
        score.completed = 8.0;
        score.useful_completed = 8.0;
        score.performance.response = MetricSnapshot {
            value: Some(ms),
            confidence: 1.0,
        };
    }
    let evidence = snapshots.pairs.get(1).unwrap();
    assert_eq!(evidence.basis, Basis::CommonTargets);
    assert_close(evidence.response.unwrap().incumbent, 550.0);
    assert_close(evidence.response.unwrap().candidate, 605.0);
    let chosen = ordinary_selection(
        &snapshots.scores,
        &nodes.iter().collect::<Vec<_>>(),
        Some(0),
        performance_baseline(&snapshots.scores),
        &snapshots.pairs,
    );
    assert_eq!(chosen.index, 0);
}

#[test]
fn common_target_cap_follows_qualification_and_directional_metrics_keep_that_cohort() {
    let nodes: Vec<_> = (0..10)
        .map(|index| node(&format!("bounded {index}")))
        .collect();
    let now = Instant::now();
    let mut inner = StateInner::default();
    let unseen = context("unseen", IpVersion::V4);
    for index in (0..17).rev() {
        let target = context(&format!("{index:02}.target"), IpVersion::V4);
        for (side, leaf) in nodes.iter().enumerate() {
            response(
                &mut inner,
                leaf,
                &target,
                if index < 8 { 1 } else { 4 },
                if index == 16 && side > 0 { 1 } else { 100 },
                now,
            );
            if index != 8 {
                for _ in 0..4 {
                    publish(
                        &mut inner,
                        leaf,
                        &target,
                        comparison::next_reporter_id(),
                        now,
                        Observation::Transfer {
                            tx: 1_048_576,
                            rx: 1_048_576,
                            elapsed: Duration::from_secs(1),
                        },
                    );
                }
            }
        }
    }
    for reference in [0, 1] {
        let decision = decision_at(&inner, &nodes, &unseen, reference, now);
        assert_eq!(
            decision.pairs.pairs.iter().flatten().count(),
            nodes.len() - 1
        );
        for pair in decision.pairs.pairs.iter().flatten() {
            assert_close(pair.response.unwrap().incumbent, 100.0);
            assert_close(pair.response.unwrap().candidate, 100.0);
            assert!(pair.upload.is_none() && pair.download.is_none());
            assert!(
                pair.partial,
                "capped common targets keep the response gap pending"
            );
        }
    }
    let exact = pair(&inner, &nodes, &context("16.target", IpVersion::V4), now);
    assert_eq!(exact.basis, Basis::ExactTarget);
    assert_close(exact.response.unwrap().candidate, 1.0);
    assert!(!exact.partial);
}

#[test]
fn response_equivalence_uses_actual_symmetric_tolerance_including_zero() {
    for (left, right, equivalent) in [
        (100_000_000, 109_999_000, true),
        (100_000_000, 110_000_000, true),
        (100_000_000, 110_001_000, false),
        (100_000, 109_999, true),
        (100_000, 110_000, true),
        (100_000, 110_001, false),
        (0, 0, true),
        (0, 1, false),
    ] {
        let nodes = [node("lower"), node("higher")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("boundary.example", IpVersion::V4);
        let now = Instant::now();
        for (leaf, nanos) in nodes.iter().zip([left, right]) {
            train_response_at(
                &manager,
                leaf,
                &target,
                8,
                Duration::from_nanos(nanos),
                1,
                now,
            );
        }
        let at = now + Duration::from_secs(2);
        let state = manager.score_state();
        for reference in [0, 1] {
            let inner = state.inner.lock();
            let decision = decision_at(&inner, &nodes, &target, reference, at);
            assert_eq!(decision.ordinary.index, reference);
            let report = report(&inner, &nodes, &target, &decision, at);
            let expected = match (equivalent, reference) {
                (true, _) => ScoreRelation::Equivalent,
                (false, 0) => ScoreRelation::SelectedFaster,
                _ => ScoreRelation::ChallengerFaster,
            };
            let relations: Vec<_> = report.challengers.iter().map(|c| c.relation).collect();
            assert_eq!(
                relations,
                [expected],
                "{left}/{right} reference={reference}"
            );
        }
    }
}

#[test]
fn a_held_incumbent_reports_a_materially_faster_rival() {
    let nodes = [node("held"), node("faster"), node("slower")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("held.example", IpVersion::V4);
    let now = Instant::now();
    for (index, latency) in [(1, 100), (0, 115), (2, 200)] {
        train_at(&manager, &nodes[index], &target, 8, latency, 1, now);
    }
    let at = now + Duration::from_secs(2);
    let state = manager.score_state();
    let inner = state.inner.lock();
    let decision = scores(&inner, &nodes, &target, at);
    assert_eq!(decision.ordinary.index, 0);
    let report = report(&inner, &nodes, &target, &decision, at);
    let relations: Vec<_> = report
        .challengers
        .iter()
        .map(|c| (c.name.as_str(), c.relation))
        .collect();
    assert_eq!(
        relations,
        [
            ("faster", ScoreRelation::ChallengerFaster),
            ("slower", ScoreRelation::SelectedFaster),
        ]
    );
}

#[test]
fn common_target_aggregation_discards_lost_direction_identity() {
    for noise in [false, true] {
        let nodes = [node("selected"), node("second"), node("third")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let now = Instant::now();
        let targets = [
            context("a.example", IpVersion::V4),
            context("b.example", IpVersion::V4),
        ];
        for (target_index, target) in targets.iter().enumerate() {
            for (index, (leaf, latency)) in nodes.iter().zip([100, 200, 300]).enumerate() {
                let uploads = if noise && target_index == 0 && index < 2 {
                    4
                } else {
                    0
                };
                train_transfers(
                    &manager,
                    leaf,
                    target,
                    (4, uploads),
                    Duration::from_millis(latency),
                    (MIN_THROUGHPUT_BYTES, 1),
                    now,
                );
            }
        }
        let at = now + Duration::from_secs(3);
        let aggregate = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let state = manager.score_state();
        let inner = state.inner.lock();
        assert_eq!(
            pair(&inner, &nodes, &targets[0], at).upload.is_some(),
            noise
        );
        let decision = scores(&inner, &nodes, &aggregate, at);
        for index in [1, 2] {
            let pair = decision.pairs.get(index).unwrap();
            assert!(pair.upload.is_none() && pair.download.is_none());
        }
    }
}
