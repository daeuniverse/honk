use super::*;

#[test]
fn common_time_blocks_receive_equal_weights_not_reporter_mix_weights() {
    let now = Instant::now();
    let nodes = [node("block incumbent"), node("block candidate")];
    let target = context("blocks", IpVersion::V4);
    let mut inner = StateInner::default();
    response(&mut inner, &nodes[0], &target, 4, 100, now);
    response(&mut inner, &nodes[1], &target, 36, 110, now);
    response(
        &mut inner,
        &nodes[0],
        &target,
        36,
        1000,
        now + Duration::from_secs(15),
    );
    response(
        &mut inner,
        &nodes[1],
        &target,
        4,
        1100,
        now + Duration::from_secs(15),
    );
    let metric = pair(&inner, &nodes, &target, now + Duration::from_secs(16))
        .response
        .unwrap();
    assert_close(metric.incumbent, 550.0);
    assert_close(metric.candidate, 605.0);
}

#[test]
fn a_fresh_sample_does_not_rejuvenate_old_blocks_or_diversity() {
    let now = Instant::now();
    let nodes = [node("age incumbent"), node("age candidate")];
    let target = context("independent-expiry", IpVersion::V4);
    let mut inner = StateInner::default();
    for leaf in &nodes {
        response(&mut inner, leaf, &target, 4, 100, now);
        response(
            &mut inner,
            leaf,
            &target,
            1,
            100,
            now + Duration::from_secs(45),
        );
    }
    let before = pair(&inner, &nodes, &target, now + Duration::from_secs(59))
        .response
        .unwrap();
    assert_eq!(before.expires_at, now + Duration::from_secs(60));
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(60))
            .response
            .is_none()
    );
    let expired = scores(&inner, &nodes, &target, now + Duration::from_secs(60));
    assert_eq!(expired.pairs.get(1).unwrap().progress, 1);
    assert!(
        expired.scores[0]
            .target_performance
            .response
            .value
            .is_some()
    );
}

#[test]
fn reporter_diversity_is_a_union_not_a_sum_of_bucket_counts() {
    let now = Instant::now();
    let nodes = [node("union incumbent"), node("union candidate")];
    let target = context("union", IpVersion::V4);
    let mut inner = StateInner::default();
    for leaf in &nodes {
        let reporters: Vec<_> = (0..3).map(|_| comparison::next_reporter_id()).collect();
        for block in 0..4 {
            for id in &reporters {
                publish(
                    &mut inner,
                    leaf,
                    &target,
                    *id,
                    now + Duration::from_secs(block * 15),
                    Observation::Response(Duration::from_millis(100)),
                );
            }
        }
    }
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(46))
            .response
            .is_none()
    );
    for leaf in &nodes {
        response(
            &mut inner,
            leaf,
            &target,
            1,
            100,
            now + Duration::from_secs(47),
        );
    }
    assert_eq!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(48))
            .response
            .unwrap()
            .reporters,
        4
    );
}

#[test]
fn failures_delayed_events_and_recreated_incarnations_cannot_revive_proof() {
    let now = Instant::now();
    let nodes = [node("fence incumbent"), node("fence candidate")];
    let target = context("fence", IpVersion::V4);
    let mut inner = StateInner::default();
    for leaf in &nodes {
        response(&mut inner, leaf, &target, 4, 100, now);
    }
    assert!(pair(&inner, &nodes, &target, now).response.is_some());
    let key = exact(&nodes[1], &target);
    inner
        .exact
        .get_mut(&key)
        .unwrap()
        .invalidate_business(now + Duration::from_secs(10));
    response(
        &mut inner,
        &nodes[1],
        &target,
        4,
        1,
        now + Duration::from_secs(5),
    );
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(11))
            .response
            .is_none()
    );
    response(
        &mut inner,
        &nodes[1],
        &target,
        4,
        100,
        now + Duration::from_secs(12),
    );
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(13))
            .response
            .is_some()
    );
    let old = StartedCells {
        exact: Some(inner.exact.peek(&key).unwrap().incarnation),
        aggregate: [Some(inner.exact.peek(&key).unwrap().node_incarnation), None],
        ..StartedCells::default()
    };
    inner.exact.get_mut(&key).unwrap().incarnation += 100;
    comparison::observe(
        &mut inner,
        &target,
        &[ScoreAttribution {
            group: "score".into(),
            node_id: nodes[1].id,
        }],
        (&[old], comparison::next_reporter_id()),
        ScoreSource::Traffic,
        &Observation::Response(Duration::from_millis(1)),
        now + Duration::from_secs(14),
    );
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(14))
            .response
            .is_none()
    );
    response(
        &mut inner,
        &nodes[1],
        &target,
        1,
        1,
        now + Duration::from_secs(14),
    );
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(14))
            .response
            .is_none()
    );
}

#[test]
fn comparison_memory_cap_counts_keys_and_container_capacity_and_eviction_loses_support() {
    let now = Instant::now();
    let leaf = node("capacity");
    let mut inner = StateInner::default();
    let first = context(&format!("{:04}{}", 0, "x".repeat(1015)), IpVersion::V4);
    response(&mut inner, &leaf, &first, 4, 100, now);
    for index in 1..=MAX_CELLS {
        let target = context(&format!("{index:04}{}", "x".repeat(1015)), IpVersion::V4);
        response(
            &mut inner,
            &leaf,
            &target,
            1,
            100,
            now + Duration::from_millis(index as u64),
        );
    }
    let store = &inner.comparisons;
    assert_eq!(store.cell_count(), MAX_CELLS);
    assert_eq!(store.evicted, 1);
    assert!(store.logical_bytes() <= comparison::Store::logical_capacity_bound());
    assert!(store.logical_bytes() >= MAX_CELLS * 1024);
    let nodes = [node("capacity reference"), leaf.clone()];
    let at = now + Duration::from_secs(1);
    response(&mut inner, &nodes[0], &first, 4, 100, at);
    response(&mut inner, &leaf, &first, 1, 100, at);
    let evicted = pair(&inner, &nodes, &first, at);
    assert!(evicted.response.is_none());
    assert_eq!(evicted.progress, 1);
    let oversize = context(&"z".repeat(MAX_KEY_BYTES), IpVersion::V4);
    let before = inner.comparisons.logical_bytes();
    response(
        &mut inner,
        &leaf,
        &oversize,
        1,
        100,
        now + Duration::from_secs(2),
    );
    assert_eq!(inner.comparisons.logical_bytes(), before);
    assert_eq!(inner.comparisons.rejected, 1);
    assert!(inner.exact.peek(&exact(&leaf, &oversize)).is_some());
}

#[test]
fn disjoint_time_blocks_do_not_compare_even_when_both_nodes_are_fresh() {
    let now = Instant::now();
    let nodes = [node("early"), node("late")];
    let target = context("disjoint", IpVersion::V4);
    let mut inner = StateInner::default();
    response(&mut inner, &nodes[0], &target, 4, 100, now);
    response(
        &mut inner,
        &nodes[1],
        &target,
        4,
        1,
        now + Duration::from_secs(15),
    );
    let scores = scores(&inner, &nodes, &target, now + Duration::from_secs(16));
    assert!(
        scores
            .scores
            .iter()
            .all(|score| score.target_performance.response.value.is_some())
    );
    assert_eq!(scores.pairs.get(1).unwrap().progress, 0);
    assert!(scores.pairs.get(1).unwrap().response.is_none());
}

#[test]
fn ordinary_probe_streams_qualify_through_block_rotation_and_expire_on_weaker_support() {
    for seconds in [30, 60] {
        let nodes = [node("periodic a"), node("periodic b")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let interval = Duration::from_secs(seconds);
        let feedback: Vec<_> = nodes
            .iter()
            .map(|leaf| {
                manager
                    .feedback_for_group_node("score", leaf.id, target.clone())
                    .unwrap()
                    .with_source(ScoreSource::HealthProbe)
                    .with_probe_interval(interval)
                    .with_probe_identity("https://periodic.example/check", "HEAD")
            })
            .collect();
        let publish = |index: usize, at| {
            let reporter = feedback[index].clone().start_at(at);
            reporter.probe_latency_at(Duration::from_millis(100), at);
            reporter.finish_at(ScoreOutcome::Success, false, at);
        };
        let now = Instant::now();
        let state = manager.score_state();
        for cycle in 0..12 {
            let phase = cycle % 2;
            let at = now + Duration::from_secs(cycle * seconds + phase);
            publish(0, at);
            publish(1, at + Duration::from_secs(2));
            let decision = scores(
                &state.inner.lock(),
                &nodes,
                &target,
                at + Duration::from_secs(3),
            );
            let response = decision.pairs.get(1).unwrap().response;
            assert_eq!(
                response.is_some(),
                cycle >= 3,
                "interval={seconds} cycle={cycle}"
            );
            if cycle >= 3 {
                let response = response.unwrap();
                assert!(comparison::equivalent(
                    response.incumbent,
                    response.candidate
                ));
            }
        }
        let last = now + Duration::from_secs(11 * seconds + 1);
        // Only the stronger side continues; it cannot renew the weaker side's proof.
        publish(1, last + interval);
        let expires = last + interval * 2;
        let metric = pair(
            &state.inner.lock(),
            &nodes,
            &target,
            expires - Duration::from_nanos(1),
        )
        .response
        .unwrap();
        assert_eq!(metric.expires_at, expires);
        assert!(
            pair(&state.inner.lock(), &nodes, &target, expires)
                .response
                .is_none()
        );
    }
}

#[test]
fn changed_probe_cohorts_and_invalid_cadences_cannot_inherit_comparison_support() {
    let nodes = [node("cadence a"), node("cadence b")];
    let target =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let uri = "https://periodic.example/check";
    let old = Duration::from_secs(30);
    // The request scope and the cadence are both part of the cohort key.
    for (changed_uri, changed_interval) in [
        ("https://periodic.example/other", old),
        (uri, Duration::from_secs(60)),
    ] {
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let publish = |index: usize, uri: &str, interval: Duration, count: usize, at: Instant| {
            let feedback = manager
                .feedback_for_group_node("score", nodes[index].id, target.clone())
                .unwrap()
                .with_source(ScoreSource::HealthProbe)
                .with_probe_identity(uri, "HEAD")
                .with_probe_interval(interval);
            for _ in 0..count {
                let reporter = feedback.clone().start_at(at);
                reporter.probe_latency_at(Duration::from_millis(100), at);
                reporter.finish_at(ScoreOutcome::Success, false, at);
            }
        };
        let now = Instant::now();
        let state = manager.score_state();
        for index in 0..2 {
            publish(index, uri, old, 4, now);
        }
        assert!(
            pair(&state.inner.lock(), &nodes, &target, now)
                .response
                .is_some()
        );
        let later = now + Duration::from_secs(1);
        publish(1, changed_uri, changed_interval, 4, later);
        assert!(
            pair(&state.inner.lock(), &nodes, &target, later)
                .response
                .is_none()
        );
        publish(1, uri, old, 1, later);
        assert!(
            pair(&state.inner.lock(), &nodes, &target, later)
                .response
                .is_none()
        );
        publish(1, uri, old, 3, later);
        assert!(
            pair(&state.inner.lock(), &nodes, &target, later)
                .response
                .is_some()
        );
        for invalid in [Duration::ZERO, Duration::MAX] {
            for index in 0..2 {
                publish(index, uri, invalid, 4, later);
            }
            let pair = pair(&state.inner.lock(), &nodes, &target, later);
            assert!(pair.response.is_none());
            assert_eq!(pair.basis, Basis::None);
        }
    }
}

#[test]
fn parent_eviction_and_recreation_cannot_revive_exact_proof_or_old_reporters() {
    let nodes = [node("parent a"), node("parent b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("parent.example", IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        train_at(&manager, leaf, &target, 4, 100, 1, now);
    }
    let feedback = manager
        .feedback_for_group_node("score", nodes[1].id, target.clone())
        .unwrap();
    let old: Vec<_> = (0..4)
        .map(|_| feedback.start_at(now + Duration::from_secs(2)))
        .collect();
    let state = manager.score_state();
    let parent = AggregateKey {
        group: "score".into(),
        network: target.network,
        family: None,
        node_id: nodes[1].id,
    };
    state.inner.lock().aggregate.pop(&parent).unwrap();
    let assert_missing = |at| {
        let inner = state.inner.lock();
        let decision = scores(&inner, &nodes, &target, at);
        assert!(decision.evidence[1].business.is_none());
        assert!(
            decision
                .pairs
                .get(1)
                .and_then(|pair| pair.response)
                .is_none()
        );
        assert_eq!(decision.pairs.get(1).map_or(0, |pair| pair.progress), 0);
    };
    assert_missing(now + Duration::from_secs(3));
    let replacement = manager
        .feedback_for_group_node(
            "score",
            nodes[1].id,
            context("unrelated.example", IpVersion::V4),
        )
        .unwrap()
        .start_at(now + Duration::from_secs(3));
    replacement.finish_at(ScoreOutcome::Cancelled, false, now + Duration::from_secs(3));
    assert_missing(now + Duration::from_secs(3));
    for reporter in old {
        reporter.setup_succeeded_at(now + Duration::from_secs(4));
        reporter.first_response_at(now + Duration::from_millis(4100));
        reporter.transfer_at(1, 1, now + Duration::from_secs(5));
        reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(5));
    }
    assert_missing(now + Duration::from_secs(6));
    train_at(
        &manager,
        &nodes[1],
        &target,
        4,
        100,
        1,
        now + Duration::from_secs(7),
    );
    let decision = scores(
        &state.inner.lock(),
        &nodes,
        &target,
        now + Duration::from_secs(9),
    );
    assert!(decision.evidence[1].business.is_some());
    assert!(
        decision
            .pairs
            .get(1)
            .and_then(|pair| pair.response)
            .is_some()
    );
}

#[test]
fn target_failure_preserves_other_targets_and_probe_but_node_failure_invalidates_them() {
    for outcome in [ScoreOutcome::TargetFailure, ScoreOutcome::NodeFailure] {
        let nodes = [node("scope a"), node("scope b")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let good = context("good.example", IpVersion::V4);
        let bad = context("bad.example", IpVersion::V4);
        let probe = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let now = Instant::now();
        for leaf in &nodes {
            probe_at(&manager, leaf, &probe, 100, now);
            for target in [&good, &bad] {
                train_at(&manager, leaf, target, 4, 100, 1, now);
            }
        }
        let state = manager.score_state();
        let before = scores(
            &state.inner.lock(),
            &nodes,
            &good,
            now + Duration::from_secs(2),
        );
        assert_eq!(before.pairs.get(1).map_or(0, |pair| pair.progress), 4);
        let failed = manager
            .feedback_for_group_node("score", nodes[1].id, bad.clone())
            .unwrap()
            .start_at(now + Duration::from_secs(3));
        failed.setup_succeeded_at(now + Duration::from_secs(3));
        failed.finish_at(outcome, true, now + Duration::from_secs(3));
        let inner = state.inner.lock();
        let at = now + Duration::from_secs(4);
        let survives = outcome == ScoreOutcome::TargetFailure;
        // The failed member leaves normal eligibility, so its cells are read as the reference.
        let against_failed = |target: &ScoreSelectionContext| {
            decision_at(&inner, &nodes, target, 1, at)
                .pairs
                .get(0)
                .unwrap()
        };
        assert_eq!(
            against_failed(&good)
                .response
                .map(|metric| metric.reporters),
            survives.then(|| before.pairs.get(1).unwrap().response.unwrap().reporters)
        );
        // Another target family shares the probe slot but none of the traffic cohorts.
        let probe_only = against_failed(&context("probe-only.example", IpVersion::V6));
        assert_eq!(probe_only.basis == Basis::ConfiguredProbe, survives);
        assert_eq!(probe_only.response.is_some(), survives);
        assert_ne!(against_failed(&bad).basis, Basis::ExactTarget);
        let good = scores(&inner, &nodes, &good, at);
        assert_eq!(good.evidence[1].business.is_some(), survives);
        // Either failure drops the challenger's observed reliability out of normal eligibility,
        // so ordinary selection holds no pair to report progress on.
        assert!(good.pairs.get(1).is_none());
    }
}

#[test]
fn failed_probe_cannot_requalify_from_its_prior_samples() {
    let nodes = [node("probe fault a"), node("probe fault b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        probe_at(&manager, leaf, &context, 100, now);
    }
    let feedback = manager
        .feedback_for_group_node("score", nodes[1].id, context.clone())
        .unwrap()
        .with_source(ScoreSource::HealthProbe);
    let failed = feedback.clone().start_at(now + Duration::from_secs(1));
    failed.finish_at(
        ScoreOutcome::NodeFailure,
        false,
        now + Duration::from_secs(1),
    );
    let fresh = feedback.start_at(now + Duration::from_secs(2));
    fresh.probe_latency_at(Duration::from_millis(100), now + Duration::from_secs(2));
    fresh.finish_at(ScoreOutcome::Success, false, now + Duration::from_secs(2));
    let state = manager.score_state();
    // The failed member leaves normal eligibility, so its probe cell is read as the reference.
    let pair = decision_at(
        &state.inner.lock(),
        &nodes,
        &context,
        1,
        now + Duration::from_secs(3),
    )
    .pairs
    .get(0)
    .unwrap();
    assert_eq!(pair.basis, Basis::ConfiguredProbe);
    assert!(pair.response.is_none());
}
