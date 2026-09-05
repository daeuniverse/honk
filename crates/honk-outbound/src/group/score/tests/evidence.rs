use super::*;
#[test]
fn stale_manager_authority_stays_revoked_after_same_name_recreation() {
    let survivor = node("survivor");
    let removed = node("removed");
    let replacement_node = node("replacement");
    let old_nodes = [survivor.clone(), removed.clone()];
    let old = super::super::super::GroupManager::new(&[group("score", &old_nodes)], &old_nodes);
    let state = old.score_state();
    let seeded_context = context("seeded.example", IpVersion::V4);
    finish_success(&old.selection_plan_for_target("score", &seeded_context));

    let deleted = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[],
        &[],
        None,
        Arc::clone(&state),
    );
    deleted.publish_score_membership();
    let replacement_nodes = [survivor.clone(), replacement_node];
    let replacement = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[group("score", &replacement_nodes)],
        &replacement_nodes,
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    let before = {
        let inner = state.inner.lock();
        (
            inner.tick,
            inner.selection_counts.len(),
            inner.aggregate.len(),
            inner.exact.len(),
        )
    };
    assert_eq!((before.1, before.2, before.3), (0, 0, 0));

    let stale = old.selection_plan_for_target("score", &context("stale.example", IpVersion::V4));
    assert!(stale.entries[0].feedback.is_none());
    assert!(
        old.feedback_for_group_node("score", survivor.id, seeded_context.clone())
            .is_none(),
        "the surviving ID must not restore old-manager feedback authority"
    );
    assert!(
        old.feedback_for_group_node("score", removed.id, seeded_context)
            .is_none(),
        "the replaced ID must not restore old-manager feedback authority"
    );
    let after_stale = {
        let inner = state.inner.lock();
        (
            inner.tick,
            inner.selection_counts.len(),
            inner.aggregate.len(),
            inner.exact.len(),
        )
    };
    assert_eq!(after_stale, before);

    let current =
        replacement.selection_plan_for_target("score", &context("current.example", IpVersion::V4));
    assert!(current.entries[0].feedback.is_some());
    let after_current = state.inner.lock();
    assert_eq!(after_current.selection_counts.len(), 1);
    assert_eq!(after_current.aggregate.len(), 1);
    assert!(after_current.tick > before.0);
}

#[test]
fn captured_feedback_requires_current_authority_at_start() {
    let nodes = [node("a"), node("b")];
    let old = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let context = context("captured.example", IpVersion::V4);
    let feedback = old
        .feedback_for_group_node("score", nodes[0].id, context.clone())
        .unwrap();
    let state = old.score_state();
    let replacement = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes)],
        &nodes,
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    let before_tick = state.inner.lock().tick;

    let reporter = feedback.start();
    reporter.setup_succeeded();
    reporter.first_response();
    reporter.tx(123);
    reporter.rx(456);
    reporter.finish(ScoreOutcome::Timeout);
    drop(reporter);

    assert!(!state.has_exact("score", &context, nodes[0].id));
    assert_eq!(state.inner.lock().tick, before_tick);
}

#[test]
fn trained_score_holds_incumbent_against_small_gain() {
    let nodes = [node("a"), node("b")];
    let node_refs = [&nodes[0], &nodes[1]];
    let context = context("example.com", IpVersion::V4);
    let state = ScorePolicyState::default();
    state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
    let now = Instant::now();
    let key = |node_id| AggregateKey {
        group: "score".into(),
        network: SelectionNetwork::Tcp,
        family: Some(IpVersion::V4),
        node_id,
    };
    {
        let mut inner = state.inner.lock();
        for (node, latency_ms) in [(&nodes[0], 1_000.0), (&nodes[1], 1_200.0)] {
            inner.aggregate.put(
                key(node.id),
                Stats {
                    setup_success: 8.0,
                    useful_success: 8.0,
                    first_response_ms: WeightedMean {
                        sum: latency_ms * 8.0,
                        weight: 8.0,
                    },
                    updated_at: Some(now),
                    ..Default::default()
                },
            );
        }
    }

    assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);
    inner_update_response(&state, key(nodes[1].id), 900.0);
    assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);
    inner_update_response(&state, key(nodes[1].id), 1.0);
    assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);
}

#[test]
fn single_failure_layer_freshness_is_unchanged() {
    // Given: one aggregate failure cell with exactly one half-life of age.
    let node = node("leaf");
    let context = context("example.com", IpVersion::V4);
    let start = Instant::now();
    let mut inner = StateInner::default();
    inner.aggregate.put(
        AggregateKey {
            group: "score".into(),
            network: SelectionNetwork::Tcp,
            family: None,
            node_id: node.id,
        },
        Stats {
            setup_failure: 2.0,
            updated_at: Some(start),
            ..Default::default()
        },
    );

    // When: the scorer snapshots the single layer after one half-life.
    let score = score_snapshot(
        &inner,
        "score",
        &context,
        node.id,
        start + SCORE_EVIDENCE_HALF_LIFE,
    );

    // Then: existing decay remains unchanged and no absent layer contributes.
    println!("single failure layer envelope={:.12}", score.failures);
    assert_close(score.failures, 1.0);
}

fn layered_failure_value(ages: [Option<Duration>; 3]) -> f64 {
    let node = node("leaf");
    let context = context("example.com", IpVersion::V4);
    let start = Instant::now();
    let now = start + Duration::from_secs(60);
    let mut inner = StateInner::default();
    for (index, age) in ages.into_iter().enumerate() {
        let Some(age) = age else {
            continue;
        };
        let stats = Stats {
            setup_failure: 1.0,
            updated_at: Some(now - age),
            ..Default::default()
        };
        match index {
            0 | 1 => {
                inner.aggregate.put(
                    AggregateKey {
                        group: "score".into(),
                        network: SelectionNetwork::Tcp,
                        family: (index == 1).then_some(IpVersion::V4),
                        node_id: node.id,
                    },
                    stats,
                );
            }
            2 => {
                inner.exact.put(
                    ExactKey {
                        group: "score".into(),
                        network: SelectionNetwork::Tcp,
                        family: IpVersion::V4,
                        target: context.target.clone().unwrap(),
                        node_id: node.id,
                    },
                    stats,
                );
            }
            _ => unreachable!(),
        }
    }
    score_snapshot(&inner, "score", &context, node.id, now).failures
}

fn assert_aged_failure_layers_count_once() {
    // Given: the same 30-second-old failure appears in overlapping layers.
    let age = Some(Duration::from_secs(30));

    // When: one, two, and three layers are independently snapshotted.
    let global_only = layered_failure_value([age, None, None]);
    let global_family = layered_failure_value([age, age, None]);
    let global_family_exact = layered_failure_value([age, age, age]);
    println!(
        "layered failure envelope: global_only={global_only:.12} global_family={global_family:.12} global_family_exact={global_family_exact:.12}"
    );

    // Then: replication does not increase the effective failure envelope.
    assert_close(global_family, global_only);
    assert_close(global_family_exact, global_only);
    let aged = layered_failure_value([
        Some(Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 8)),
        Some(Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 8)),
        Some(Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 8)),
    ]);
    let incumbent = ScoreSnapshot {
        attempts: 1.0,
        completed: 1.0,
        hysteresis_completed: 1.0,
        reliability: 0.8,
        reliability_upper: 0.8,
        useful_completed: 1.0,
        latency_ms: None,
        latency_confidence: 0.0,
        throughput: None,
        throughput_confidence: 0.0,
        failures: aged,
        explore_backed_off: false,
        fail_streak: 0,
        selected_at: 1,
        targeted: false,
        target_attempts: 0.0,
        target_completed: 0.0,
    };
    let challenger = ScoreSnapshot {
        reliability: 0.8005,
        reliability_upper: 0.8005,
        failures: 0.0,
        selected_at: 0,
        ..incumbent
    };
    let retained = hold_decision(
        &incumbent,
        &challenger,
        performance_baseline(&[incumbent, challenger]),
    ) == HoldDecision::Held;
    println!("aged layered envelope={aged:.12} retained_incumbent={retained}");
    assert!(aged < SCORE_FAILURE_FORGIVENESS_THRESHOLD);
    assert!(retained);
}

#[test]
fn layered_failure_freshness_uses_one_envelope() {
    assert_aged_failure_layers_count_once();
}

fn assert_larger_specific_failure_layer_still_wins() {
    // Given: global, family, and exact evidence are respectively 30, 20, and 10 seconds old.
    let global = evidence_decay(Duration::from_secs(30));
    let family = evidence_decay(Duration::from_secs(20));
    let exact = evidence_decay(Duration::from_secs(10));

    // When: all three overlapping layers are snapshotted together.
    let effective = layered_failure_value([
        Some(Duration::from_secs(30)),
        Some(Duration::from_secs(20)),
        Some(Duration::from_secs(10)),
    ]);
    println!(
        "specific failure envelope: global_30s={global:.12} family_20s={family:.12} exact_10s={exact:.12} effective={effective:.12}"
    );

    // Then: the freshest specific layer is the effective envelope.
    assert_close(effective, exact);
}

#[test]
fn specific_failure_freshness_is_not_hidden() {
    assert_larger_specific_failure_layer_still_wins();
}

#[test]
fn aged_failure_restores_incumbent_margin() {
    // Given: two trained nodes and negligible failure evidence on the incumbent.
    let nodes = [node("a"), node("b")];
    let node_refs = [&nodes[0], &nodes[1]];
    let context = context("example.com", IpVersion::V4);
    let state = ScorePolicyState::default();
    state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
    let start = Instant::now();
    let now = start + Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 8);
    {
        let mut inner = state.inner.lock();
        for (index, node) in nodes.iter().enumerate() {
            let incumbent = index == 0;
            inner.aggregate.put(
                AggregateKey {
                    group: "score".into(),
                    network: SelectionNetwork::Tcp,
                    family: Some(IpVersion::V4),
                    node_id: node.id,
                },
                Stats {
                    attempts: 256.0 + f64::from(incumbent),
                    setup_success: 256.0,
                    setup_failure: f64::from(incumbent),
                    useful_success: 256.0,
                    useful_failure: f64::from(incumbent),
                    first_response_ms: WeightedMean {
                        sum: 256_000.0,
                        weight: 256.0,
                    },
                    updated_at: Some(start),
                    selected_at: u64::from(incumbent),
                    ..Default::default()
                },
            );
        }
    }
    let snapshots: Vec<_> = {
        let inner = state.inner.lock();
        nodes
            .iter()
            .map(|node| score_snapshot(&inner, "score", &context, node.id, now))
            .collect()
    };
    assert!(
        snapshots[0].failures > 0.0 && snapshots[0].failures < SCORE_FAILURE_FORGIVENESS_THRESHOLD
    );
    assert!(
        snapshots
            .iter()
            .all(|score| score.completed >= MIN_TRAINED_EVIDENCE)
    );
    let performance = performance_baseline(&snapshots);
    assert!(utility(&snapshots[1], performance) > utility(&snapshots[0], performance));
    assert!(
        utility(&snapshots[1], performance) - utility(&snapshots[0], performance)
            < switch_margin(snapshots[0].completed)
    );

    // When: the scorer ranks the candidates.
    let selected = state.rank_at("score", &context, &node_refs, now);

    // Then: the normal small-gain protection retains the incumbent.
    assert_eq!(selected, 0);
}

pub(super) fn inner_update_response(state: &ScorePolicyState, key: AggregateKey, latency_ms: f64) {
    state
        .inner
        .lock()
        .aggregate
        .get_mut(&key)
        .unwrap()
        .first_response_ms
        .sum = latency_ms * 8.0;
}

#[test]
fn throughput_ignores_bursts_and_pools_dominant_direction() {
    let now = Instant::now();
    let mut stats = Stats::default();
    let sample = |tx, rx, elapsed| FlowSample {
        outcome: ScoreOutcome::Success,
        setup: Some(Duration::from_millis(10)),
        first_response: None,
        tx,
        rx,
        elapsed,
        count_usefulness: true,
        streak_neutral: false,
    };

    stats.record_finish(
        now,
        &sample(10_000_000, 1, Duration::from_millis(999)),
        true,
        1,
    );
    stats.record_finish(now, &sample(65_535, 1, Duration::from_secs(2)), true, 2);
    assert_close(stats.throughput_windows, 0.0);

    stats.record_finish(now, &sample(65_536, 1, Duration::from_secs(1)), true, 3);
    stats.record_finish(now, &sample(1, 131_072, Duration::from_secs(3)), true, 4);

    assert_close(stats.throughput_bytes, 196_608.0);
    assert_close(stats.throughput_seconds, 4.0);
    assert_close(stats.throughput_windows, 2.0);
    let score = snapshot(&stats, now);
    assert_close(score.throughput.unwrap(), 49_152.0);
    assert_close(score.throughput_confidence, 0.25);
}

#[test]
fn stale_exact_metrics_yield_back_to_aggregate_evidence() {
    let now = Instant::now();
    let context = context("example.com", IpVersion::V4);
    let node = node("leaf");
    let mut inner = StateInner::default();
    inner.aggregate.put(
        AggregateKey {
            group: "score".into(),
            network: SelectionNetwork::Tcp,
            family: None,
            node_id: node.id,
        },
        Stats {
            setup_success: 8.0,
            useful_success: 8.0,
            first_response_ms: WeightedMean {
                sum: 800.0,
                weight: 8.0,
            },
            updated_at: Some(now),
            ..Default::default()
        },
    );
    inner.exact.put(
        ExactKey {
            group: "score".into(),
            network: SelectionNetwork::Tcp,
            family: IpVersion::V4,
            target: context.target.clone().unwrap(),
            node_id: node.id,
        },
        Stats {
            setup_success: 8.0,
            useful_success: 8.0,
            first_response_ms: WeightedMean {
                sum: 8_000.0,
                weight: 8.0,
            },
            updated_at: Some(now),
            ..Default::default()
        },
    );

    let fresh = score_snapshot(&inner, "score", &context, node.id, now);
    assert_close(fresh.latency_ms.unwrap(), 1_000.0);
    assert_close(fresh.latency_confidence, 1.0);

    let aged = score_snapshot(
        &inner,
        "score",
        &context,
        node.id,
        now + Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 3),
    );
    assert_close(aged.latency_ms.unwrap(), 212.5);
    assert_close(aged.latency_confidence, 0.125);
}

#[test]
fn evidence_half_life_decays_every_historical_field() {
    let start = Instant::now();
    let mut stats = Stats {
        incarnation: 7,
        attempts: 8.0,
        setup_success: 6.0,
        setup_failure: 2.0,
        useful_success: 4.0,
        useful_failure: 2.0,
        setup_ms: WeightedMean {
            sum: 800.0,
            weight: 8.0,
        },
        first_response_ms: WeightedMean {
            sum: 600.0,
            weight: 6.0,
        },
        throughput_bytes: 1_000_000.0,
        throughput_seconds: 10.0,
        throughput_windows: 4.0,
        fail_streak: 0,
        explore_not_before: None,
        last_used: 9,
        updated_at: Some(start),
        selected_at: 0,
    };

    stats.decay_to(start + SCORE_EVIDENCE_HALF_LIFE);

    assert_close(stats.attempts, 4.0);
    assert_close(stats.setup_success, 3.0);
    assert_close(stats.setup_failure, 1.0);
    assert_close(stats.useful_success, 2.0);
    assert_close(stats.useful_failure, 1.0);
    assert_close(stats.setup_ms.sum, 400.0);
    assert_close(stats.setup_ms.weight, 4.0);
    assert_close(stats.first_response_ms.sum, 300.0);
    assert_close(stats.first_response_ms.weight, 3.0);
    assert_close(stats.throughput_bytes, 500_000.0);
    assert_close(stats.throughput_seconds, 5.0);
    assert_close(stats.throughput_windows, 2.0);
    assert_eq!(stats.incarnation, 7);
    assert_eq!(stats.last_used, 9);
}

#[test]
fn aged_evidence_reenters_deterministic_cold_exploration() {
    let nodes = [node("a"), node("b")];
    let node_refs = [&nodes[0], &nodes[1]];
    let context = context("example.com", IpVersion::V4);
    let state = ScorePolicyState::default();
    state.publish_membership(nodes.iter().map(|node| ("score".to_string(), node.id)));
    let now = Instant::now();

    for (index, node) in nodes.iter().enumerate() {
        let attributions = [ScoreAttribution {
            group: "score".into(),
            node_id: node.id,
        }];
        let cells = state.start_at(&context, &attributions, now);
        let success = index == 1;
        state.finish_at(
            &context,
            &attributions,
            &cells,
            &FlowSample {
                outcome: if success {
                    ScoreOutcome::Success
                } else {
                    ScoreOutcome::Timeout
                },
                setup: success.then_some(Duration::from_millis(10)),
                first_response: success.then_some(Duration::from_millis(20)),
                tx: u64::from(success),
                rx: u64::from(success),
                elapsed: Duration::from_secs(1),
                count_usefulness: true,
                streak_neutral: false,
            },
            now,
        );
    }

    assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);
    assert_eq!(
        state.rank_at(
            "score",
            &context,
            &node_refs,
            now + Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 3),
        ),
        0
    );
}

#[test]
fn parsed_score_policy_learns_without_a_feature_flag() {
    let config = honk_config::parser::parse_dae_config(
        r#"
node {
    a: 'socks5://127.0.0.1:10001'
    b: 'socks5://127.0.0.1:10002'
}
group {
    scored {
        policy: score
        filter: name('a', 'b')
    }
}
"#,
    )
    .unwrap();
    let manager = super::super::super::GroupManager::new(&config.groups, &config.nodes);
    let context = context("example.com", IpVersion::V4);

    let first = manager.selection_plan_for_target("scored", &context);
    assert_eq!(first.entries[0].node.name, "a");
    finish_failure(&first);

    let second = manager.selection_plan_for_target("scored", &context);
    assert_eq!(second.entries[0].node.name, "b");
    finish_success(&second);
    assert_eq!(
        manager
            .selection_plan_for_target("scored", &context)
            .entries[0]
            .node
            .id,
        config.nodes[1].id
    );
}
