use super::*;

#[test]
fn joint_response_uses_qualified_common_blocks_without_more_traffic() {
    for shared in [3, 4] {
        let nodes = [node("joint a"), node("joint b"), node("joint c")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("joint.example", IpVersion::V4);
        let now = Instant::now();
        for (leaf, latency) in nodes[..2].iter().zip([100, 200]) {
            train_at(&manager, leaf, &target, 4, latency, 1, now);
            train_at(
                &manager,
                leaf,
                &target,
                shared,
                latency,
                1,
                now + Duration::from_secs(16),
            );
        }
        train_at(
            &manager,
            &nodes[2],
            &target,
            4,
            300,
            1,
            now + Duration::from_secs(16),
        );
        let at = now + Duration::from_secs(18);
        let state = manager.score_state();
        let decision = scores(&state.inner.lock(), &nodes, &target, at);
        let progress = comparison::response_progress(
            &state.inner.lock(),
            "score",
            &target,
            nodes[0].id,
            nodes[2].id,
            at,
        )
        .unwrap();
        assert_eq!(progress.0, [shared as u8, 4]);
        let summary = comparison::summarize(&decision, at);
        let report = evaluate(
            &decision,
            &nodes.iter().collect::<Vec<_>>(),
            &target,
            None,
            at,
        )
        .snapshot;
        if shared == 4 {
            assert_ne!(
                decision.pairs.get(1).unwrap().response.unwrap().support,
                decision.pairs.get(2).unwrap().response.unwrap().support
            );
            assert!(!summary.response_misaligned);
            assert_ne!(report.question, ScoreEvidenceQuestion::Response);
            let original = decision.pairs.get(1).unwrap().response.unwrap();
            let narrowed = decision.pairs.summary_pair(1).unwrap().response.unwrap();
            assert!(original.expires_at < narrowed.expires_at);
            let renewed = scores(&state.inner.lock(), &nodes, &target, original.expires_at);
            assert_eq!(
                renewed
                    .pairs
                    .summary_pair(1)
                    .unwrap()
                    .response
                    .unwrap()
                    .support,
                narrowed.support
            );
            assert!(!comparison::summarize(&renewed, original.expires_at).response_misaligned);
        } else {
            assert!(
                decision
                    .pairs
                    .get(2)
                    .and_then(|pair| pair.response)
                    .is_none()
            );
            assert_eq!(report.question, ScoreEvidenceQuestion::Response);
        }
    }
}

#[test]
fn disjoint_pair_blocks_leave_responses_misaligned() {
    let nodes = [node("split a"), node("split b"), node("split c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("split.example", IpVersion::V4);
    let now = Instant::now();
    let probe =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    for leaf in &nodes {
        probe_at(&manager, leaf, &probe, 50, now);
    }
    for (index, seconds) in [(0, 0), (1, 0), (0, 16), (2, 16)] {
        train_at(
            &manager,
            &nodes[index],
            &target,
            4,
            100 + index as u64 * 100,
            1,
            now + Duration::from_secs(seconds),
        );
    }
    let at = now + Duration::from_secs(18);
    let state = manager.score_state();
    let decision = scores(&state.inner.lock(), &nodes, &target, at);
    assert_eq!(
        comparison::response_progress(
            &state.inner.lock(),
            "score",
            &target,
            nodes[1].id,
            nodes[2].id,
            at
        )
        .unwrap()
        .0,
        [0, 0]
    );
    assert!(comparison::summarize(&decision, at).response_misaligned);
    let report = evaluate(
        &decision,
        &nodes.iter().collect::<Vec<_>>(),
        &target,
        None,
        at,
    )
    .snapshot;
    assert_eq!(report.question, ScoreEvidenceQuestion::Response);
}

#[test]
fn joint_common_targets_keep_partial_coverage_and_response_bound_directions() {
    let nodes = [node("targets a"), node("targets b"), node("targets c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let now = Instant::now();
    let common = context("a.common", IpVersion::V4);
    let extra = context("b.extra", IpVersion::V4);
    for (leaf, latency) in nodes.iter().zip([100, 200, 300]) {
        train_transfers(
            &manager,
            leaf,
            &common,
            (4, 4),
            Duration::from_millis(latency),
            (MIN_THROUGHPUT_BYTES, 1),
            now + Duration::from_secs(16),
        );
    }
    for (leaf, latency) in nodes[..2].iter().zip([100, 200]) {
        train_transfers(
            &manager,
            leaf,
            &extra,
            (4, 4),
            Duration::from_millis(latency),
            (MIN_THROUGHPUT_BYTES * 8, 1),
            now + Duration::from_secs(16),
        );
    }
    let at = now + Duration::from_secs(19);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let state = manager.score_state();
    let decision = scores(&state.inner.lock(), &nodes, &aggregate, at);
    assert!(!comparison::summarize(&decision, at).response_misaligned);
    for index in [1, 2] {
        let pair = decision.pairs.summary_pair(index).unwrap();
        assert_close(
            pair.upload.unwrap().incumbent,
            MIN_THROUGHPUT_BYTES as f64 / 2.0,
        );
        assert_close(
            pair.upload.unwrap().candidate,
            MIN_THROUGHPUT_BYTES as f64 / 2.0,
        );
    }
}

#[test]
fn joint_narrowing_keeps_the_original_directional_pair() {
    let nodes = [
        node("direction veto a"),
        node("direction veto b"),
        node("direction veto c"),
    ];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("direction-veto.example", IpVersion::V4);
    let now = Instant::now();
    for (leaf, upload) in nodes[..2]
        .iter()
        .zip([MIN_THROUGHPUT_BYTES, MIN_THROUGHPUT_BYTES * 4])
    {
        train_transfers(
            &manager,
            leaf,
            &target,
            (4, 4),
            Duration::from_millis(100),
            (upload, 1),
            now,
        );
    }
    for (leaf, latency) in nodes.iter().zip([100, 100, 200]) {
        train_transfers(
            &manager,
            leaf,
            &target,
            (4, 4),
            Duration::from_millis(latency),
            (MIN_THROUGHPUT_BYTES, 1),
            now + Duration::from_secs(16),
        );
    }
    let at = now + Duration::from_secs(19);
    let state = manager.score_state();
    let decision = scores(&state.inner.lock(), &nodes, &target, at);
    let narrowed = decision.pairs.summary_pair(1).unwrap().upload.unwrap();
    assert_close(narrowed.incumbent, narrowed.candidate);
    let original = decision.pairs.get(1).unwrap().upload.unwrap();
    assert!(original.candidate > original.incumbent * 1.1);
    assert!(!comparison::summarize(&decision, at).response_misaligned);
}
