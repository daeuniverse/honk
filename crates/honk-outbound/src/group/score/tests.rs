    use super::*;
    use honk_config::group::{Group, GroupPolicy};

    fn assert_close(actual: f64, expected: f64) {
        assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
    }

    #[test]
    fn latency_samples_use_a_decayed_weighted_mean() {
        let mut latency = WeightedMean::default();
        latency.record(10.0);
        latency.record(20.0);
        latency.record(30.0);

        assert_close(latency.mean().unwrap(), 20.0);
        assert_close(latency.weight, 3.0);
    }

    #[test]
    fn trained_utility_does_not_trade_latency_for_attempt_balance() {
        let candidate = |attempts, latency_ms| ScoreSnapshot {
            attempts,
            completed: 8.0,
            hysteresis_completed: 8.0,
            reliability: 0.9,
            reliability_upper: 0.9,
            useful_completed: 8.0,
            latency_ms: Some(latency_ms),
            latency_confidence: 1.0,
            throughput: None,
            throughput_confidence: 0.0,
            failures: 0.0,
            selected_at: 0,
            explore_backed_off: false,
            fail_streak: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };

        let scores = [candidate(100.0, 50.0), candidate(8.0, 500.0)];
        let baseline = performance_baseline(&scores);
        assert!(utility(&scores[0], baseline) > utility(&scores[1], baseline));
    }

    #[test]
    fn relative_performance_is_scale_invariant() {
        let candidate = |latency_ms, throughput| ScoreSnapshot {
            attempts: 8.0,
            completed: 8.0,
            hysteresis_completed: 8.0,
            reliability: 0.9,
            reliability_upper: 0.9,
            useful_completed: 8.0,
            latency_ms: Some(latency_ms),
            latency_confidence: 1.0,
            throughput: Some(throughput),
            throughput_confidence: 1.0,
            failures: 0.0,
            selected_at: 0,
            explore_backed_off: false,
            fail_streak: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };
        let local = [candidate(30.0, 20_000_000.0), candidate(60.0, 10_000_000.0)];
        let remote = [
            candidate(300.0, 200_000_000.0),
            candidate(600.0, 100_000_000.0),
        ];
        let local_baseline = performance_baseline(&local);
        let remote_baseline = performance_baseline(&remote);

        assert_close(
            utility(&local[0], local_baseline) - utility(&local[1], local_baseline),
            utility(&remote[0], remote_baseline) - utility(&remote[1], remote_baseline),
        );
    }

    #[test]
    fn hold_decision_scales_margin_with_incumbent_evidence() {
        let candidate = |completed, reliability, latency_ms, failures| ScoreSnapshot {
            attempts: completed,
            completed,
            hysteresis_completed: completed,
            reliability,
            reliability_upper: reliability,
            useful_completed: completed,
            latency_ms,
            latency_confidence: f64::from(latency_ms.is_some()),
            throughput: None,
            throughput_confidence: 0.0,
            failures,
            selected_at: 0,
            explore_backed_off: false,
            fail_streak: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };
        let decision = |incumbent: ScoreSnapshot, best: ScoreSnapshot| {
            let performance = performance_baseline(&[incumbent, best]);
            hold_decision(&incumbent, &best, performance)
        };
        let trained = MIN_TRAINED_EVIDENCE;
        let low_margin = switch_margin(trained);
        let incumbent = candidate(trained, 0.0, None, 0.0);
        let proven = candidate(SCORE_SWITCH_FULL_EVIDENCE, 0.0, None, 0.0);

        assert_eq!(
            decision(
                candidate(trained - f64::EPSILON, 0.0, None, 0.0),
                candidate(trained, low_margin / 2.0, None, 0.0),
            ),
            HoldDecision::UseBest,
        );
        assert_eq!(
            decision(incumbent, candidate(trained, low_margin * 1.01, None, 0.0),),
            HoldDecision::UseBest,
        );
        assert_eq!(
            decision(incumbent, candidate(trained, low_margin / 2.0, None, 0.0),),
            HoldDecision::Held,
        );
        assert_eq!(
            decision(
                proven,
                candidate(
                    SCORE_SWITCH_FULL_EVIDENCE,
                    SCORE_SWITCH_MARGIN / 2.0,
                    None,
                    0.0,
                ),
            ),
            HoldDecision::Held,
        );
        assert_eq!(
            decision(
                proven,
                candidate(
                    SCORE_SWITCH_FULL_EVIDENCE,
                    SCORE_SWITCH_MARGIN * 1.01,
                    None,
                    0.0,
                ),
            ),
            HoldDecision::UseBest,
        );
        assert_eq!(
            decision(
                candidate(trained, 0.0, Some(1_048_576.0), 0.0),
                candidate(trained, 0.0, Some(1.0), 0.0),
            ),
            HoldDecision::UseBest,
        );
        assert_eq!(
            decision(
                candidate(trained, 0.0, None, SCORE_FAILURE_FORGIVENESS_THRESHOLD,),
                candidate(trained, low_margin / 2.0, None, 0.0),
            ),
            HoldDecision::FreshFailureBypass,
        );
    }

    #[test]
    fn hysteresis_evidence_counts_each_reporter_completion_once() {
        let assert_near = |actual: f64, expected: f64| {
            assert!((actual - expected).abs() < 1e-4, "{actual} != {expected}");
        };
        let node = node("only");
        let manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&node))],
            std::slice::from_ref(&node),
        );
        let context = context("evidence.example", IpVersion::V4);
        for _ in 0..3 {
            finish_success(&manager.selection_plan_for_target("score", &context));
        }
        let score = {
            let state = manager.score_state();
            let inner = state.inner.lock();
            score_snapshot(&inner, "score", &context, node.id, Instant::now())
        };
        assert_near(score.completed, 9.0);
        assert_near(score.hysteresis_completed, 3.0);
        assert_near(
            switch_margin(score.hysteresis_completed),
            SCORE_SWITCH_MARGIN * 3.0 / SCORE_SWITCH_FULL_EVIDENCE,
        );

        for _ in 3..8 {
            finish_success(&manager.selection_plan_for_target("score", &context));
        }
        let score = {
            let state = manager.score_state();
            let inner = state.inner.lock();
            score_snapshot(&inner, "score", &context, node.id, Instant::now())
        };
        assert_near(score.completed, 24.0);
        assert_near(score.hysteresis_completed, 8.0);
        assert_near(
            switch_margin(score.hysteresis_completed),
            SCORE_SWITCH_MARGIN,
        );
    }

    #[test]
    fn exploration_budget_scales_with_candidate_count() {
        assert_eq!(exploration_target(3), 3);
        assert_eq!(exploration_target(4), 4);
        assert_eq!(exploration_target(14), 5);
        assert_eq!(exploration_target(28), 7);
        assert_eq!(exploration_period(3), SCORE_EXPLORATION_MIN_PERIOD);
        assert_eq!(exploration_period(28), 56);
        assert_eq!(exploration_period(128), SCORE_EXPLORATION_MAX_PERIOD);
    }

    #[test]
    fn cold_exploration_skips_backed_off_candidates() {
        let nodes = [node("a"), node("b")];
        let node_refs: Vec<_> = nodes.iter().collect();
        let cold = |backed_off| ScoreSnapshot {
            attempts: 0.0,
            completed: 0.0,
            hysteresis_completed: 0.0,
            reliability: 0.0,
            reliability_upper: 0.5,
            useful_completed: 0.0,
            latency_ms: None,
            latency_confidence: 0.0,
            throughput: None,
            throughput_confidence: 0.0,
            failures: 0.0,
            explore_backed_off: backed_off,
            fail_streak: 0,
            selected_at: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };
        let snapshots = [cold(true), cold(false)];
        let performance = performance_baseline(&snapshots);
        let selection = best_index(&snapshots, &node_refs, 1, true, performance);
        assert_eq!(selection.index, 1);
        assert_eq!(selection.reason, SelectionReason::ColdExplore);

        let snapshots = [cold(false), cold(false)];
        let performance = performance_baseline(&snapshots);
        assert_eq!(
            best_index(&snapshots, &node_refs, 1, true, performance).index,
            0
        );

        // All backed off: exploration skips, ranking still returns a leaf.
        let snapshots = [cold(true), cold(true)];
        let performance = performance_baseline(&snapshots);
        let selection = best_index(&snapshots, &node_refs, 1, true, performance);
        assert!(!selection.reason.is_exploration());
        assert_eq!(selection.reason, SelectionReason::PerformanceWinner);
    }

    #[test]
    fn consecutive_failures_exclude_leaf_from_ranking() {
        let nodes = [node("a"), node("b")];
        let node_refs: Vec<_> = nodes.iter().collect();
        let trained = |reliability, fail_streak| ScoreSnapshot {
            attempts: 8.0,
            completed: 8.0,
            hysteresis_completed: 8.0,
            reliability,
            reliability_upper: reliability,
            useful_completed: 8.0,
            latency_ms: None,
            latency_confidence: 0.0,
            throughput: None,
            throughput_confidence: 0.0,
            failures: 0.0,
            explore_backed_off: false,
            fail_streak,
            selected_at: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };
        let snapshots = [trained(0.9, SCORE_FAIL_STREAK_EXCLUDE), trained(0.8, 0)];
        let performance = performance_baseline(&snapshots);
        assert_eq!(
            best_index(&snapshots, &node_refs, 1, false, performance).index,
            1
        );
        // Pinned fallback: with every candidate excluded, rank the full set.
        let snapshots = [
            trained(0.9, SCORE_FAIL_STREAK_EXCLUDE),
            trained(0.8, SCORE_FAIL_STREAK_EXCLUDE),
        ];
        let performance = performance_baseline(&snapshots);
        assert_eq!(
            best_index(&snapshots, &node_refs, 1, false, performance).index,
            0
        );
    }

    #[test]
    fn rank_counts_fail_streak_excluded_candidates() {
        let state = ScorePolicyState::default();
        let nodes = [node("a"), node("b")];
        let node_refs: Vec<_> = nodes.iter().collect();
        state.publish_membership([("score".into(), nodes[0].id), ("score".into(), nodes[1].id)]);
        let context = context("example.com", IpVersion::V4);
        let attributions = [ScoreAttribution {
            group: "score".into(),
            node_id: nodes[0].id,
        }];
        let now = Instant::now();
        let sample = FlowSample {
            outcome: ScoreOutcome::Timeout,
            setup: None,
            first_response: None,
            tx: 0,
            rx: 0,
            elapsed: Duration::ZERO,
            count_usefulness: true,
            streak_neutral: false,
        };
        for _ in 0..SCORE_FAIL_STREAK_EXCLUDE {
            let cells = state.start_at(&context, &attributions, now);
            state.finish_at(&context, &attributions, &cells, &sample, now);
        }
        let _ = state.rank_at("score", &context, &node_refs, now);
        let counts = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        assert_eq!(counts.fail_streak_excluded, 1);
        assert_eq!(counts.explore_backed_off, 1);

        let _ = state.peek_rank("score", &context, &node_refs);
        let counts = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        assert_eq!(counts.fail_streak_excluded, 1);
        assert_eq!(counts.explore_backed_off, 1);
    }

    #[test]
    fn rank_counts_explore_backed_off_candidates() {
        let state = ScorePolicyState::default();
        let nodes = [node("a"), node("b")];
        let node_refs: Vec<_> = nodes.iter().collect();
        state.publish_membership([("score".into(), nodes[0].id), ("score".into(), nodes[1].id)]);
        let context = context("backoff.example", IpVersion::V4);
        let attributions = [ScoreAttribution {
            group: "score".into(),
            node_id: nodes[0].id,
        }];
        let now = Instant::now();
        let sample = FlowSample {
            outcome: ScoreOutcome::Timeout,
            setup: None,
            first_response: None,
            tx: 0,
            rx: 0,
            elapsed: Duration::ZERO,
            count_usefulness: true,
            streak_neutral: false,
        };
        let cells = state.start_at(&context, &attributions, now);
        state.finish_at(&context, &attributions, &cells, &sample, now);
        let _ = state.rank_at("score", &context, &node_refs, now);
        let counts = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        assert_eq!(counts.explore_backed_off, 1);
        assert_eq!(counts.fail_streak_excluded, 0);
    }

    #[test]
    fn exploration_backoff_grows_with_failures_and_shrinks_with_success() {
        let state = ScorePolicyState::default();
        let leaf = node("leaf");
        state.publish_membership([("score".into(), leaf.id)]);
        let context = context("example.com", IpVersion::V4);
        let attributions = [ScoreAttribution {
            group: "score".into(),
            node_id: leaf.id,
        }];
        let now = Instant::now();
        let sample = |outcome, setup| FlowSample {
            outcome,
            setup,
            first_response: None,
            tx: 0,
            rx: 0,
            elapsed: Duration::ZERO,
            count_usefulness: true,
            streak_neutral: false,
        };
        let backed_off = |at: Instant| {
            let inner = state.inner.lock();
            score_snapshot(&inner, "score", &context, leaf.id, at).explore_backed_off
        };
        let fail = |at: Instant| {
            let cells = state.start_at(&context, &attributions, at);
            state.finish_at(
                &context,
                &attributions,
                &cells,
                &sample(ScoreOutcome::Timeout, None),
                at,
            );
        };
        let neutral = |outcome, at: Instant| {
            let cells = state.start_at(&context, &attributions, at);
            let mut neutral_sample = sample(outcome, None);
            neutral_sample.streak_neutral = true;
            state.finish_at(&context, &attributions, &cells, &neutral_sample, at);
        };
        let streak = |at: Instant| {
            let inner = state.inner.lock();
            score_snapshot(&inner, "score", &context, leaf.id, at).fail_streak
        };

        fail(now);
        // Probe/urltest/warm outcomes never move the streak or the backoff.
        neutral(ScoreOutcome::Success, now);
        neutral(ScoreOutcome::Timeout, now);
        assert_eq!(streak(now), 1);
        assert!(backed_off(now + Duration::from_secs(1)));
        assert!(!backed_off(
            now + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(1)
        ));

        let second = now + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(2);
        fail(second);
        assert!(backed_off(
            second + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(1)
        ));
        assert!(!backed_off(
            second + SCORE_EXPLORE_BACKOFF_BASE * 2 + Duration::from_secs(1)
        ));

        let cells = state.start_at(&context, &attributions, second);
        state.finish_at(
            &context,
            &attributions,
            &cells,
            &sample(ScoreOutcome::Success, Some(Duration::from_millis(10))),
            second,
        );
        // Success steps the streak down (2 → 1), so the next failure lands
        // back on the doubled cadence rather than the base one.
        assert!(!backed_off(second + Duration::from_secs(1)));
        let third = second + Duration::from_secs(2);
        fail(third);
        assert!(backed_off(
            third + SCORE_EXPLORE_BACKOFF_BASE + Duration::from_secs(1)
        ));
        assert!(!backed_off(
            third + SCORE_EXPLORE_BACKOFF_BASE * 2 + Duration::from_secs(1)
        ));
    }

    #[test]
    fn large_score_groups_periodically_try_non_incumbent() {
        let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
        let node_refs: Vec<_> = nodes.iter().collect();
        let context = context("example.com", IpVersion::V4);
        let state = ScorePolicyState::default();
        state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
        let now = Instant::now();
        {
            let mut inner = state.inner.lock();
            for (index, node) in nodes.iter().enumerate() {
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
                        selected_at: u64::from(index == 0),
                        ..Default::default()
                    },
                );
            }
            inner.selection_counts.insert(
                SelectionCadenceKey::new("score", &context),
                exploration_period(nodes.len()) - 1,
            );
        }

        assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);
    }

    #[test]
    fn periodic_exploration_prefers_reliability_upper_bound() {
        let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
        let node_refs: Vec<_> = nodes.iter().collect();
        let candidate = |attempts, reliability_upper, selected_at| ScoreSnapshot {
            attempts,
            completed: 8.0,
            hysteresis_completed: 8.0,
            reliability: 0.2,
            reliability_upper,
            useful_completed: 8.0,
            latency_ms: None,
            latency_confidence: 0.0,
            throughput: None,
            throughput_confidence: 0.0,
            failures: 0.0,
            selected_at,
            explore_backed_off: false,
            fail_streak: 0,
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        };
        let mut snapshots = vec![candidate(8.0, 0.2, 0); nodes.len()];
        snapshots[0] = candidate(8.0, 0.9, 1);
        snapshots[1] = candidate(1.0, 0.3, 0);
        snapshots[2] = candidate(8.0, 0.8, 0);
        let performance = performance_baseline(&snapshots);

        let selected = best_index(
            &snapshots,
            &node_refs,
            exploration_period(nodes.len()),
            true,
            performance,
        );

        assert_eq!(selected.index, 2);
        assert_eq!(selected.reason, SelectionReason::PeriodicExplore);
    }

    #[test]
    fn large_score_groups_cap_initial_target_exploration() {
        let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("example.com", IpVersion::V4);
        let mut seen = std::collections::HashSet::new();

        for _ in 0..exploration_target(nodes.len()) {
            let plan = manager.selection_plan_for_target("score", &context);
            seen.insert(plan.entries[0].node.id);
            finish_success(&plan);
        }

        assert_eq!(seen.len(), exploration_target(nodes.len()));
    }

    #[test]
    fn score_peek_does_not_consume_group_exploration_budget() {
        let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
        let node_refs: Vec<_> = nodes.iter().collect();
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let state = ScorePolicyState::default();
        state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
        let now = Instant::now();
        {
            let mut inner = state.inner.lock();
            for (index, node) in nodes.iter().enumerate() {
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
                        selected_at: u64::from(index == 0),
                        ..Default::default()
                    },
                );
            }
            inner.selection_counts.insert(
                SelectionCadenceKey::new("score", &context),
                exploration_period(nodes.len()) - 1,
            );
        }

        let selected = state.rank_at("score", &context, &node_refs, now);
        assert_eq!(selected, 1);
        let key = SelectionCadenceKey::new("score", &context);
        let count = state.inner.lock().selection_counts[&key];
        assert_eq!(state.peek_rank("score", &context, &node_refs), selected);
        assert_eq!(state.inner.lock().selection_counts[&key], count);
    }

    #[test]
    fn same_scope_exploration_period_and_peek_are_unchanged() {
        let nodes: Vec<_> = (0..8).map(|index| node(&format!("node-{index}"))).collect();
        let node_refs: Vec<_> = nodes.iter().collect();
        let context = context("example.com", IpVersion::V4);
        let state = ScorePolicyState::default();
        state.publish_membership(nodes.iter().map(|node| ("score".into(), node.id)));
        let now = Instant::now();
        {
            let mut inner = state.inner.lock();
            for (index, node) in nodes.iter().enumerate() {
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
                        selected_at: u64::from(index == 0),
                        ..Default::default()
                    },
                );
            }
            inner.selection_counts.insert(
                SelectionCadenceKey::new("score", &context),
                exploration_period(nodes.len()) - 1,
            );
        }

        let selected = state.rank_at("score", &context, &node_refs, now);
        assert_eq!(selected, 1);
        assert_eq!(
            state.inner.lock().selection_counts[&SelectionCadenceKey::new("score", &context)],
            exploration_period(nodes.len())
        );
        assert_eq!(state.peek_rank("score", &context, &node_refs), selected);
        assert_eq!(
            state.inner.lock().selection_counts[&SelectionCadenceKey::new("score", &context)],
            exploration_period(nodes.len())
        );
    }

    #[test]
    fn periodic_exploration_is_scoped_by_network_and_family() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let targeted = |network, family| ScoreSelectionContext {
            network,
            probe_domain: if network == SelectionNetwork::Tcp {
                ProbeDomain::Tcp
            } else {
                ProbeDomain::DataUdp
            },
            target_family: Some(family),
            health_family: family,
            target: Some(ScoreTarget::domain("target.example", 443)),
        };
        let aggregate = |network| {
            ScoreSelectionContext::aggregate(
                network,
                if network == SelectionNetwork::Tcp {
                    ProbeDomain::Tcp
                } else {
                    ProbeDomain::DataUdp
                },
                IpVersion::V4,
            )
        };
        let contexts = [
            targeted(SelectionNetwork::Tcp, IpVersion::V4),
            targeted(SelectionNetwork::Tcp, IpVersion::V6),
            targeted(SelectionNetwork::Udp, IpVersion::V4),
            targeted(SelectionNetwork::Udp, IpVersion::V6),
            aggregate(SelectionNetwork::Tcp),
            aggregate(SelectionNetwork::Udp),
        ];
        for context in &contexts {
            let _ = manager.selection_plan_for_target("score", context);
        }
        let state = manager.score_state();
        assert_eq!(state.inner.lock().selection_counts.len(), 6);
        println!(
            "cadence scope cardinality={}",
            state.inner.lock().selection_counts.len()
        );

        let tcp_v4_key = SelectionCadenceKey::new("score", &contexts[0]);
        state
            .inner
            .lock()
            .selection_counts
            .insert(tcp_v4_key.clone(), exploration_period(nodes.len()) - 1);
        let _ = manager.selection_plan_for_target("score", &contexts[2]);
        assert_eq!(
            state.inner.lock().selection_counts[&tcp_v4_key],
            exploration_period(nodes.len()) - 1,
            "UDP-V4 must not consume TCP-V4 cadence"
        );
        let _ = manager.selection_plan_for_target("score", &contexts[0]);
        assert_eq!(
            state.inner.lock().selection_counts[&tcp_v4_key],
            exploration_period(nodes.len())
        );

        let different_target = context("other.example", IpVersion::V4);
        let _ = manager.selection_plan_for_target("score", &different_target);
        assert_eq!(state.inner.lock().selection_counts.len(), 6);
    }

    #[test]
    fn selection_count_reload_lifecycle_matches_group_name() {
        let nodes = [node("a"), node("b")];
        let old = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("reload.example", IpVersion::V4);
        let _ = old.selection_plan_for_target("score", &context);
        let state = old.score_state();
        let before: u64 = state.inner.lock().selection_counts.values().copied().sum();

        let empty = super::super::GroupManager::with_alive_set_and_score_state(
            &[group("score", &[])],
            &[],
            None,
            Arc::clone(&state),
        );
        empty.publish_score_membership();
        assert_eq!(
            state
                .inner
                .lock()
                .selection_counts
                .values()
                .copied()
                .sum::<u64>(),
            before,
            "a committed group name retains cadence through zero leaves"
        );

        let mut selector = group("score", &nodes);
        selector.policy = GroupPolicy::Selector;
        let non_score = super::super::GroupManager::with_alive_set_and_score_state(
            &[selector],
            &nodes,
            None,
            Arc::clone(&state),
        );
        non_score.publish_score_membership();
        assert_eq!(
            state
                .inner
                .lock()
                .selection_counts
                .values()
                .copied()
                .sum::<u64>(),
            before,
            "a surviving name retains cadence through Score to non-Score"
        );

        let removed = super::super::GroupManager::with_alive_set_and_score_state(
            &[],
            &[],
            None,
            Arc::clone(&state),
        );
        removed.publish_score_membership();
        assert!(state.inner.lock().selection_counts.is_empty());
    }

    #[test]
    fn stale_manager_authority_stays_revoked_after_same_name_recreation() {
        let survivor = node("survivor");
        let removed = node("removed");
        let replacement_node = node("replacement");
        let old_nodes = [survivor.clone(), removed.clone()];
        let old = super::super::GroupManager::new(&[group("score", &old_nodes)], &old_nodes);
        let state = old.score_state();
        let seeded_context = context("seeded.example", IpVersion::V4);
        finish_success(&old.selection_plan_for_target("score", &seeded_context));

        let deleted = super::super::GroupManager::with_alive_set_and_score_state(
            &[],
            &[],
            None,
            Arc::clone(&state),
        );
        deleted.publish_score_membership();
        let replacement_nodes = [survivor.clone(), replacement_node];
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
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

        let stale =
            old.selection_plan_for_target("score", &context("stale.example", IpVersion::V4));
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

        let current = replacement
            .selection_plan_for_target("score", &context("current.example", IpVersion::V4));
        assert!(current.entries[0].feedback.is_some());
        let after_current = state.inner.lock();
        assert_eq!(after_current.selection_counts.len(), 1);
        assert_eq!(after_current.aggregate.len(), 1);
        assert!(after_current.tick > before.0);
    }

    #[test]
    fn captured_feedback_requires_current_authority_at_start() {
        let nodes = [node("a"), node("b")];
        let old = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("captured.example", IpVersion::V4);
        let feedback = old
            .feedback_for_group_node("score", nodes[0].id, context.clone())
            .unwrap();
        let state = old.score_state();
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
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
            snapshots[0].failures > 0.0
                && snapshots[0].failures < SCORE_FAILURE_FORGIVENESS_THRESHOLD
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

    fn inner_update_response(state: &ScorePolicyState, key: AggregateKey, latency_ms: f64) {
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
        let manager = super::super::GroupManager::new(&config.groups, &config.nodes);
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
    fn node(name: &str) -> Node {
        Node {
            id: Uuid::new_v5(&honk_config::node::NODE_ID_NAMESPACE, name.as_bytes()),
            name: name.into(),
            ..Default::default()
        }
    }

    fn group(name: &str, nodes: &[Node]) -> Group {
        Group {
            id: Uuid::new_v4(),
            name: name.into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        }
    }

    fn group_with_children(name: &str, nodes: &[Node], groups: &[&str]) -> Group {
        Group {
            id: Uuid::new_v4(),
            name: name.into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            groups: groups.iter().map(|group| (*group).to_owned()).collect(),
            ..Default::default()
        }
    }

    fn selector_with_children(name: &str, nodes: &[Node], groups: &[&str]) -> Group {
        Group {
            policy: GroupPolicy::Selector,
            ..group_with_children(name, nodes, groups)
        }
    }

    fn context(host: &str, family: IpVersion) -> ScoreSelectionContext {
        ScoreSelectionContext {
            network: SelectionNetwork::Tcp,
            probe_domain: ProbeDomain::Tcp,
            target_family: Some(family),
            health_family: IpVersion::V4,
            target: Some(ScoreTarget::domain(host, 443)),
        }
    }

    fn trained_stats(successes: f64, latency_ms: f64, now: Instant) -> Stats {
        Stats {
            attempts: successes,
            setup_success: successes,
            useful_success: successes,
            first_response_ms: WeightedMean {
                sum: latency_ms * successes,
                weight: successes,
            },
            updated_at: Some(now),
            ..Default::default()
        }
    }

    fn finish_success(plan: &super::super::ScoreSelectionPlan<'_>) {
        let reporter = plan.entries[0]
            .feedback
            .as_ref()
            .expect("Score candidate must carry feedback")
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);
    }
    fn finish_failure(plan: &super::super::ScoreSelectionPlan<'_>) {
        plan.entries[0]
            .feedback
            .as_ref()
            .expect("Score candidate must carry feedback")
            .start()
            .setup_failed(ScoreOutcome::Timeout);
    }

    fn selected(manager: &super::super::GroupManager, context: &ScoreSelectionContext) -> Uuid {
        manager.selection_plan_for_target("score", context).entries[0]
            .node
            .id
    }

    #[test]
    fn selection_reason_instrumentation_preserves_existing_winners() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("baseline.example", IpVersion::V4);
        let apply = selected(&manager, &target);
        let peek = manager
            .get_score_selection_for_network("score", SelectionNetwork::Tcp)
            .expect("Score group has candidates");

        let singleton = node("singleton");
        let singleton_manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&singleton))],
            std::slice::from_ref(&singleton),
        );
        let singleton_selected = selected(&singleton_manager, &target);

        let last_resort = node("last-resort");
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(last_resort.id, ProbeDomain::Tcp, IpVersion::V4);
        let last_resort_manager = super::super::GroupManager::with_alive_set(
            &[group("score", std::slice::from_ref(&last_resort))],
            std::slice::from_ref(&last_resort),
            Some(alive),
        );
        let last_resort_selected = selected(&last_resort_manager, &target);

        println!(
            "winner baseline apply={apply} peek={peek} singleton={singleton_selected} last_resort={last_resort_selected}"
        );
        assert_eq!(apply, nodes[0].id);
        assert_eq!(peek, nodes[0].name);
        assert_eq!(singleton_selected, singleton.id);
        assert_eq!(last_resort_selected, last_resort.id);
    }

    #[test]
    fn switch_flap_counts_only_quick_committed_reversals() {
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let key = SelectionHistoryKey::new("score", &context);
        let first = node("first").id;
        let second = node("second").id;
        let mut inner = StateInner::default();

        let record = |inner: &mut StateInner, node_id, reason| {
            ScorePolicyState::record_switch_flap(inner, &key, node_id, reason);
        };
        record(&mut inner, first, SelectionReason::PerformanceWinner);
        // Exploration never touches flap history.
        record(&mut inner, second, SelectionReason::PeriodicExplore);
        record(&mut inner, second, SelectionReason::PerformanceWinner);
        // Same-winner selections push the next reversal out of the window.
        for _ in 0..SCORE_SWITCH_FLAP_WINDOW {
            record(&mut inner, second, SelectionReason::PerformanceWinner);
        }
        record(&mut inner, first, SelectionReason::ReliabilityWinner);
        record(&mut inner, second, SelectionReason::PerformanceWinner);

        assert_eq!(
            inner
                .selection_reasons
                .get(&SelectionReasonKey::new("score", SelectionNetwork::Tcp))
                .unwrap()
                .switch_flap,
            1
        );
    }

    #[test]
    fn switch_flap_ignores_cross_target_interleaving() {
        let first = node("first").id;
        let second = node("second").id;
        let mut inner = StateInner::default();
        let key_a = SelectionHistoryKey::new("score", &context("a.example", IpVersion::V4));
        let key_b = SelectionHistoryKey::new("score", &context("b.example", IpVersion::V4));
        let flap_count = |inner: &StateInner| {
            inner
                .selection_reasons
                .get(&SelectionReasonKey::new("score", SelectionNetwork::Tcp))
                .map_or(0, |counts| counts.switch_flap)
        };

        // A→first, B→second, A→first: neither target reversed its own winner.
        for (key, node_id) in [(&key_a, first), (&key_b, second), (&key_a, first)] {
            ScorePolicyState::record_switch_flap(
                &mut inner,
                key,
                node_id,
                SelectionReason::PerformanceWinner,
            );
        }
        assert_eq!(flap_count(&inner), 0);

        // A same-target reversal within the window still counts.
        ScorePolicyState::record_switch_flap(
            &mut inner,
            &key_a,
            second,
            SelectionReason::PerformanceWinner,
        );
        ScorePolicyState::record_switch_flap(
            &mut inner,
            &key_a,
            first,
            SelectionReason::PerformanceWinner,
        );
        assert_eq!(flap_count(&inner), 1);
    }

    #[test]
    fn applied_score_selection_records_switch_flap() {
        let nodes = [node("first"), node("second")];
        let node_refs = [&nodes[0], &nodes[1]];
        let state = ScorePolicyState::default();
        state.publish_membership(nodes.iter().map(|node| ("score".to_owned(), node.id)));
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let now = Instant::now();
        let keys = nodes.each_ref().map(|node| AggregateKey {
            group: "score".to_owned(),
            network: SelectionNetwork::Tcp,
            family: None,
            node_id: node.id,
        });
        {
            let mut inner = state.inner.lock();
            inner
                .aggregate
                .put(keys[0].clone(), trained_stats(8.0, 50.0, now));
            inner
                .aggregate
                .put(keys[1].clone(), trained_stats(8.0, 200.0, now));
        }
        assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);

        inner_update_response(&state, keys[0].clone(), 200.0);
        inner_update_response(&state, keys[1].clone(), 50.0);
        assert_eq!(state.rank_at("score", &context, &node_refs, now), 1);

        inner_update_response(&state, keys[0].clone(), 50.0);
        inner_update_response(&state, keys[1].clone(), 200.0);
        assert_eq!(state.rank_at("score", &context, &node_refs, now), 0);
        assert_eq!(
            state
                .selection_reason_counts("score", SelectionNetwork::Tcp)
                .switch_flap,
            1
        );
    }

    #[test]
    fn score_reload_prunes_removed_switch_history_members() {
        let state = ScorePolicyState::default();
        let first = node("first").id;
        let second = node("second").id;
        state.publish_membership([("score".to_owned(), first), ("score".to_owned(), second)]);
        let removed_key =
            SelectionHistoryKey::new("score", &context("removed.example", IpVersion::V4));
        let retained_key =
            SelectionHistoryKey::new("score", &context("retained.example", IpVersion::V6));
        {
            let mut inner = state.inner.lock();
            inner.selection_history.push(
                removed_key.clone(),
                SelectionHistory {
                    current: first,
                    previous: Some(second),
                    selections: 1,
                    switched_at: 1,
                },
            );
            inner.selection_history.push(
                retained_key.clone(),
                SelectionHistory {
                    current: second,
                    previous: Some(first),
                    selections: 1,
                    switched_at: 1,
                },
            );
        }

        state.publish_membership([("score".to_owned(), second)]);

        let inner = state.inner.lock();
        assert!(!inner.selection_history.contains(&removed_key));
        assert_eq!(
            inner
                .selection_history
                .peek(&retained_key)
                .unwrap()
                .previous,
            None
        );
    }

    #[test]
    fn selection_reason_precedence_is_stable() {
        let state = ScorePolicyState::default();
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let now = Instant::now();
        let cold = [node("cold-a"), node("cold-b")];
        let periodic: Vec<_> = (0..8)
            .map(|index| node(&format!("periodic-{index}")))
            .collect();
        let held = [node("held-a"), node("held-b")];
        let bypass = [node("bypass-a"), node("bypass-b")];
        let reliable = [node("reliable-a"), node("reliable-b")];
        let performance = [node("performance-a"), node("performance-b")];
        let memberships = [
            ("cold", cold.as_slice()),
            ("periodic", periodic.as_slice()),
            ("held", held.as_slice()),
            ("bypass", bypass.as_slice()),
            ("reliable", reliable.as_slice()),
            ("performance", performance.as_slice()),
        ];
        state.publish_membership(
            memberships
                .iter()
                .flat_map(|(group, nodes)| nodes.iter().map(|node| ((*group).to_owned(), node.id))),
        );
        {
            let mut inner = state.inner.lock();
            for (index, node) in periodic.iter().enumerate() {
                inner.aggregate.put(
                    AggregateKey {
                        group: "periodic".into(),
                        network: SelectionNetwork::Tcp,
                        family: None,
                        node_id: node.id,
                    },
                    Stats {
                        selected_at: u64::from(index == 0),
                        ..trained_stats(8.0, 100.0, now)
                    },
                );
            }
            inner.selection_counts.insert(
                SelectionCadenceKey::new("periodic", &context),
                exploration_period(periodic.len()) - 1,
            );
            for (group, nodes, stats) in [
                (
                    "held",
                    held.as_slice(),
                    [
                        Stats {
                            selected_at: 1,
                            ..trained_stats(8.0, 100.0, now)
                        },
                        trained_stats(8.0, 99.0, now),
                    ],
                ),
                (
                    "bypass",
                    bypass.as_slice(),
                    [
                        Stats {
                            attempts: 257.0,
                            useful_failure: 1.0,
                            selected_at: 1,
                            ..trained_stats(256.0, 100.0, now)
                        },
                        trained_stats(256.0, 100.0, now),
                    ],
                ),
                (
                    "reliable",
                    reliable.as_slice(),
                    [
                        trained_stats(8.0, 100.0, now),
                        Stats {
                            attempts: 8.0,
                            useful_failure: 4.0,
                            ..trained_stats(4.0, 50.0, now)
                        },
                    ],
                ),
                (
                    "performance",
                    performance.as_slice(),
                    [
                        trained_stats(8.0, 200.0, now),
                        trained_stats(8.0, 50.0, now),
                    ],
                ),
            ] {
                for (node, stats) in nodes.iter().zip(stats) {
                    inner.aggregate.put(
                        AggregateKey {
                            group: group.into(),
                            network: SelectionNetwork::Tcp,
                            family: None,
                            node_id: node.id,
                        },
                        stats,
                    );
                }
            }
        }

        let winners = [
            (
                "cold",
                state.rank_at("cold", &context, &cold.iter().collect::<Vec<_>>(), now),
            ),
            (
                "periodic",
                state.rank_at(
                    "periodic",
                    &context,
                    &periodic.iter().collect::<Vec<_>>(),
                    now,
                ),
            ),
            (
                "held",
                state.rank_at("held", &context, &held.iter().collect::<Vec<_>>(), now),
            ),
            (
                "bypass",
                state.rank_at("bypass", &context, &bypass.iter().collect::<Vec<_>>(), now),
            ),
            (
                "reliable",
                state.rank_at(
                    "reliable",
                    &context,
                    &reliable.iter().collect::<Vec<_>>(),
                    now,
                ),
            ),
            (
                "performance",
                state.rank_at(
                    "performance",
                    &context,
                    &performance.iter().collect::<Vec<_>>(),
                    now,
                ),
            ),
        ];
        assert_eq!(
            winners,
            [
                ("cold", 0),
                ("periodic", 1),
                ("held", 0),
                ("bypass", 1),
                ("reliable", 0),
                ("performance", 1)
            ]
        );

        let expected = [
            (
                "cold",
                SelectionReasonCounts {
                    cold_explore: 1,
                    ..Default::default()
                },
            ),
            (
                "periodic",
                SelectionReasonCounts {
                    periodic_explore: 1,
                    ..Default::default()
                },
            ),
            (
                "held",
                SelectionReasonCounts {
                    incumbent_held: 1,
                    ..Default::default()
                },
            ),
            (
                "bypass",
                SelectionReasonCounts {
                    fresh_failure_bypass: 1,
                    ..Default::default()
                },
            ),
            (
                "reliable",
                SelectionReasonCounts {
                    reliability_winner: 1,
                    ..Default::default()
                },
            ),
            (
                "performance",
                SelectionReasonCounts {
                    performance_winner: 1,
                    ..Default::default()
                },
            ),
        ];
        println!("winner table={winners:?}");
        for (group, counts) in expected {
            assert_eq!(
                state.selection_reason_counts(group, SelectionNetwork::Tcp),
                counts
            );
        }
    }

    #[test]
    fn selection_reason_counting_respects_apply_and_filter_boundaries() {
        let dead = node("dead");
        let live = [node("live-a"), node("live-b")];
        let all_nodes = [dead.clone(), live[0].clone(), live[1].clone()];
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(dead.id, ProbeDomain::Tcp, IpVersion::V4);
        let groups = [
            selector_with_children("dead-path", std::slice::from_ref(&dead), &[]),
            group_with_children("target-top", &all_nodes, &["dead-path"]),
            group("target-child", &all_nodes),
            selector_with_children("target-parent", &[], &["target-child"]),
            group("aggregate-top", &all_nodes),
            group("aggregate-child", &all_nodes),
            selector_with_children("aggregate-parent", &[], &["aggregate-child"]),
            group("singleton", std::slice::from_ref(&live[0])),
            group("last-resort", std::slice::from_ref(&dead)),
        ];
        let manager = super::super::GroupManager::with_alive_set(
            &groups,
            &all_nodes,
            Some(Arc::clone(&alive)),
        );
        let target = context("boundaries.example", IpVersion::V4);

        let _ = manager.selection_plan_for_target("target-top", &target);
        let _ = manager.selection_plan_for_target("target-parent", &target);
        let _ = manager.selection_plan_for_domain("aggregate-top", ProbeDomain::Tcp, IpVersion::V4);
        let _ =
            manager.selection_plan_for_domain("aggregate-parent", ProbeDomain::Tcp, IpVersion::V4);
        let mut udp_target = target.clone();
        udp_target.network = SelectionNetwork::Udp;
        udp_target.probe_domain = ProbeDomain::DataUdp;
        let _ = manager.selection_plan_for_target("target-top", &udp_target);
        let _ = manager.selection_plan_for_domain(
            "aggregate-parent",
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
        let _ = manager.selection_plan_for_target("singleton", &target);
        let _ = manager.selection_plan_for_target("last-resort", &target);
        let state = manager.score_state();
        let applied = [
            ("target-top", 1, 1),
            ("target-child", 1, 1),
            ("aggregate-top", 1, 1),
            ("aggregate-child", 1, 1),
        ];
        for (group, cold_explore, dead_filtered) in applied {
            let counts = state.selection_reason_counts(group, SelectionNetwork::Tcp);
            assert_eq!(counts.cold_explore, cold_explore, "{group} cold_explore");
            assert_eq!(counts.dead_filtered, dead_filtered, "{group} dead_filtered");
            assert_eq!(
                counts.periodic_explore
                    + counts.reliability_winner
                    + counts.performance_winner
                    + counts.incumbent_held
                    + counts.fresh_failure_bypass,
                0
            );
        }
        for group in ["target-top", "aggregate-child"] {
            assert_eq!(
                state.selection_reason_counts(group, SelectionNetwork::Udp),
                SelectionReasonCounts {
                    cold_explore: 1,
                    dead_filtered: 1,
                    ..Default::default()
                }
            );
        }
        assert_eq!(
            state.selection_reason_counts("singleton", SelectionNetwork::Tcp),
            SelectionReasonCounts::default()
        );
        assert_eq!(
            state.selection_reason_counts("last-resort", SelectionNetwork::Tcp),
            SelectionReasonCounts {
                dead_filtered: 1,
                ..Default::default()
            }
        );

        let before_peek = state.inner.lock().selection_reasons.clone();
        let _ = manager.get_score_selection_for_network("target-top", SelectionNetwork::Tcp);
        let _ = manager.get_score_selection_for_network("target-parent", SelectionNetwork::Tcp);
        let _ = manager.peek_selection_plan_for_domain(
            "aggregate-top",
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let _ = manager.peek_selection_plan_for_domain(
            "aggregate-parent",
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        assert_eq!(state.inner.lock().selection_reasons, before_peek);
        {
            let inner = state.inner.lock();
            assert!(inner.selection_reasons.len() <= inner.valid_groups.len() * 2);
        }

        let stale_group = group("stale", &all_nodes);
        let stale = super::super::GroupManager::with_alive_set(
            std::slice::from_ref(&stale_group),
            &all_nodes,
            Some(Arc::clone(&alive)),
        );
        let stale_state = stale.score_state();
        let deleted = super::super::GroupManager::with_alive_set_and_score_state(
            &[],
            &all_nodes,
            Some(Arc::clone(&alive)),
            Arc::clone(&stale_state),
        );
        deleted.publish_score_membership();
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&stale_group),
            &all_nodes,
            Some(alive),
            Arc::clone(&stale_state),
        );
        replacement.publish_score_membership();
        let _ = stale.selection_plan_for_target("stale", &target);
        assert_eq!(
            stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
            SelectionReasonCounts::default()
        );
        let _ = replacement.selection_plan_for_target("stale", &target);
        assert_eq!(
            stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
            SelectionReasonCounts {
                cold_explore: 1,
                dead_filtered: 1,
                ..Default::default()
            }
        );

        let saturated = SelectionReasonCounts {
            cold_explore: u64::MAX,
            periodic_explore: u64::MAX,
            reliability_winner: u64::MAX,
            performance_winner: u64::MAX,
            incumbent_held: u64::MAX,
            fresh_failure_bypass: u64::MAX,
            dead_filtered: u64::MAX,
            switch_flap: u64::MAX,
            fail_streak_excluded: u64::MAX,
            explore_backed_off: u64::MAX,
        };
        stale_state.inner.lock().selection_reasons.insert(
            SelectionReasonKey::new("stale", SelectionNetwork::Tcp),
            saturated,
        );
        let _ = replacement.selection_plan_for_target("stale", &target);
        assert_eq!(
            stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
            saturated
        );
        {
            let inner = stale_state.inner.lock();
            assert!(inner.selection_reasons.len() <= inner.valid_groups.len() * 2);
        }
        println!(
            "counter table target-top-tcp={:?} target-top-udp={:?} target-child-tcp={:?} aggregate-top-tcp={:?} aggregate-child-tcp={:?} aggregate-child-udp={:?} singleton={:?} last-resort={:?} stale={:?}",
            state.selection_reason_counts("target-top", SelectionNetwork::Tcp),
            state.selection_reason_counts("target-top", SelectionNetwork::Udp),
            state.selection_reason_counts("target-child", SelectionNetwork::Tcp),
            state.selection_reason_counts("aggregate-top", SelectionNetwork::Tcp),
            state.selection_reason_counts("aggregate-child", SelectionNetwork::Tcp),
            state.selection_reason_counts("aggregate-child", SelectionNetwork::Udp),
            state.selection_reason_counts("singleton", SelectionNetwork::Tcp),
            state.selection_reason_counts("last-resort", SelectionNetwork::Tcp),
            stale_state.selection_reason_counts("stale", SelectionNetwork::Tcp),
        );
    }

    #[test]
    fn nested_score_groups_count_reasons_independently() {
        let nodes = [node("parent-direct"), node("child-a"), node("child-b")];
        let child = group("child", &nodes[1..]);
        let parent = group_with_children("parent", std::slice::from_ref(&nodes[0]), &["child"]);
        let manager = super::super::GroupManager::new(&[child, parent], &nodes);
        let target = context("nested-reasons.example", IpVersion::V4);

        let selected = manager.selection_plan_for_target("parent", &target).entries[0]
            .node
            .id;
        let state = manager.score_state();
        let child_counts = state.selection_reason_counts("child", SelectionNetwork::Tcp);
        let parent_counts = state.selection_reason_counts("parent", SelectionNetwork::Tcp);
        println!("nested winner={selected} child={child_counts:?} parent={parent_counts:?}");
        assert_eq!(selected, nodes[0].id);
        assert_eq!(child_counts.cold_explore, 1);
        assert_eq!(parent_counts.cold_explore, 1);
        assert_eq!(child_counts.dead_filtered, 0);
        assert_eq!(parent_counts.dead_filtered, 0);
    }

    #[test]
    fn private_reason_counts_follow_committed_name_lifecycle() {
        let nodes = [node("lifecycle-a"), node("lifecycle-b")];
        let score = group("lifecycle", &nodes);
        let manager = super::super::GroupManager::new(std::slice::from_ref(&score), &nodes);
        let state = manager.score_state();
        let target = context("private-lifecycle.example", IpVersion::V4);
        let _ = manager.selection_plan_for_target("lifecycle", &target);
        let recorded = state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp);
        assert_eq!(recorded.cold_explore, 1);

        let selector = Group {
            policy: GroupPolicy::Selector,
            ..score.clone()
        };
        let hidden = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&selector),
            &nodes,
            None,
            Arc::clone(&state),
        );
        hidden.publish_score_membership();
        assert_eq!(
            state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp),
            recorded
        );

        let restored = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&score),
            &nodes,
            None,
            Arc::clone(&state),
        );
        restored.publish_score_membership();
        assert_eq!(
            state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp),
            recorded
        );

        let deleted = super::super::GroupManager::with_alive_set_and_score_state(
            &[],
            &nodes,
            None,
            Arc::clone(&state),
        );
        deleted.publish_score_membership();
        let recreated = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&score),
            &nodes,
            None,
            Arc::clone(&state),
        );
        recreated.publish_score_membership();
        let reset = state.selection_reason_counts("lifecycle", SelectionNetwork::Tcp);
        println!(
            "private lifecycle recorded={recorded:?} hidden={recorded:?} restored={recorded:?} recreated={reset:?}"
        );
        assert_eq!(reset, SelectionReasonCounts::default());
    }

    #[test]
    fn score_reason_snapshot_is_sorted_fixed_and_private() {
        let nodes = [node("private-node-alpha"), node("private-node-beta")];
        let groups = [
            group("z-score", &nodes),
            Group {
                name: "hidden-selector".into(),
                policy: GroupPolicy::Selector,
                nodes: nodes.iter().map(|node| node.id).collect(),
                ..Default::default()
            },
            group("a-score", &nodes),
        ];
        let manager = super::super::GroupManager::new(&groups, &nodes);
        let mut tcp_target = context("private-target.internal", IpVersion::V4);
        let _ = manager.selection_plan_for_target("z-score", &tcp_target);
        tcp_target.network = SelectionNetwork::Udp;
        tcp_target.probe_domain = ProbeDomain::DataUdp;
        let _ = manager.selection_plan_for_target("a-score", &tcp_target);

        let state = manager.score_state();
        let before_read = state.inner.lock().selection_reasons.clone();
        let snapshot = manager.score_reason_snapshot();
        assert_eq!(state.inner.lock().selection_reasons, before_read);
        assert_eq!(
            snapshot
                .iter()
                .map(|group| group.name.as_str())
                .collect::<Vec<_>>(),
            ["a-score", "z-score"]
        );
        assert_eq!(
            snapshot[0].udp,
            ScoreReasonCounters {
                cold_explore: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            snapshot[1].tcp,
            ScoreReasonCounters {
                cold_explore: 1,
                ..Default::default()
            }
        );
        assert_eq!(snapshot[0].tcp, ScoreReasonCounters::default());
        assert_eq!(snapshot[1].udp, ScoreReasonCounters::default());

        let debug = format!("{snapshot:?}");
        assert!(!debug.contains("private-node-alpha"));
        assert!(!debug.contains("private-node-beta"));
        assert!(!debug.contains("private-target.internal"));
        let ScoreReasonCounters {
            cold_explore: _,
            periodic_explore: _,
            reliability_winner: _,
            performance_winner: _,
            incumbent_held: _,
            fresh_failure_bypass: _,
            dead_filtered: _,
            switch_flap: _,
            fail_streak_excluded: _,
            explore_backed_off: _,
        } = snapshot[0].tcp;

        let _ = manager.selection_plan_for_target(
            "z-score",
            &context("private-target.internal", IpVersion::V4),
        );
        let later = manager.score_reason_snapshot();
        assert_eq!(snapshot[1].tcp.cold_explore, 1);
        assert_eq!(later[1].tcp.cold_explore, 2);

        let saturated = SelectionReasonCounts {
            cold_explore: u64::MAX,
            periodic_explore: u64::MAX,
            reliability_winner: u64::MAX,
            performance_winner: u64::MAX,
            incumbent_held: u64::MAX,
            fresh_failure_bypass: u64::MAX,
            dead_filtered: u64::MAX,
            switch_flap: u64::MAX,
            fail_streak_excluded: u64::MAX,
            explore_backed_off: u64::MAX,
        };
        state.inner.lock().selection_reasons.insert(
            SelectionReasonKey::new("z-score", SelectionNetwork::Udp),
            saturated,
        );
        let saturated_snapshot = manager.score_reason_snapshot();
        assert_eq!(
            saturated_snapshot[1].udp,
            ScoreReasonCounters::from_private(saturated)
        );
        println!(
            "owned score snapshot={snapshot:?} later={later:?} saturated={saturated_snapshot:?}"
        );
    }

    #[test]
    fn delay_test_members_do_not_record_score_selection() {
        let nodes = [node("delay-peek-alpha"), node("delay-peek-beta")];
        let sub = group("delay-peek-sub", &nodes);
        let parent = Group {
            id: Uuid::new_v4(),
            name: "delay-peek-parent".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![],
            groups: vec!["delay-peek-sub".into()],
            ..Default::default()
        };
        let manager = super::super::GroupManager::new(&[parent, sub], &nodes);

        let members = manager.delay_test_members("delay-peek-parent");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].0, "delay-peek-sub");

        let state = manager.score_state();
        assert_eq!(
            state.selection_reason_counts("delay-peek-sub", SelectionNetwork::Tcp),
            SelectionReasonCounts::default()
        );
        assert!(state.inner.lock().selection_history.is_empty());
    }

    #[test]
    fn selector_parent_peeks_unchosen_score_subgroups() {
        let nodes = [
            node("sel-sub-alpha-a"),
            node("sel-sub-alpha-b"),
            node("sel-sub-beta-a"),
            node("sel-sub-beta-b"),
        ];
        let sub_a = group("sel-sub-a", &nodes[..2]);
        let sub_b = group("sel-sub-b", &nodes[2..]);
        let parent = Group {
            id: Uuid::new_v4(),
            name: "sel-parent".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![],
            groups: vec!["sel-sub-a".into(), "sel-sub-b".into()],
            ..Default::default()
        };
        let manager = super::super::GroupManager::new(&[sub_a, sub_b, parent], &nodes);
        let state = manager.score_state();

        // Default choice is the first member: only sub-a commits a rank.
        let _ = manager.selection_plan_for_domain("sel-parent", ProbeDomain::Tcp, IpVersion::V4);
        assert_eq!(
            state
                .selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp)
                .cold_explore,
            1
        );
        assert_eq!(
            state.selection_reason_counts("sel-sub-b", SelectionNetwork::Tcp),
            SelectionReasonCounts::default()
        );
        assert!(state.inner.lock().selection_history.is_empty());

        // Switching the choice moves the committed rank to sub-b.
        manager.set_selector_choice("sel-parent", "sel-sub-b");
        let _ = manager.selection_plan_for_domain("sel-parent", ProbeDomain::Tcp, IpVersion::V4);
        assert_eq!(
            state
                .selection_reason_counts("sel-sub-b", SelectionNetwork::Tcp)
                .cold_explore,
            1
        );
        assert_eq!(
            state
                .selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp)
                .cold_explore,
            1
        );

        // The target-aware dial path applies the same rule.
        manager.set_selector_choice("sel-parent", "sel-sub-a");
        let before_a = state.selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp);
        let before_b = state.selection_reason_counts("sel-sub-b", SelectionNetwork::Tcp);
        let _ = manager.selection_plan_for_target(
            "sel-parent",
            &context("sel-target.internal", IpVersion::V4),
        );
        assert_ne!(
            state.selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp),
            before_a
        );
        assert_eq!(
            state.selection_reason_counts("sel-sub-b", SelectionNetwork::Tcp),
            before_b
        );

        // A stale stored choice names no member: the fallback serving
        // sub-group still commits its rank instead of everything peeking.
        manager.set_selector_choice("sel-parent", "sel-sub-renamed-away");
        let before_a = state.selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp);
        let _ = manager.selection_plan_for_domain("sel-parent", ProbeDomain::Tcp, IpVersion::V4);
        assert_ne!(
            state.selection_reason_counts("sel-sub-a", SelectionNetwork::Tcp),
            before_a
        );
    }

    #[test]
    fn selector_commit_follows_non_first_default() {
        let nodes = [
            node("def-alpha-a"),
            node("def-alpha-b"),
            node("def-beta-a"),
            node("def-beta-b"),
        ];
        let sub_a = group("def-sub-a", &nodes[..2]);
        let sub_b = group("def-sub-b", &nodes[2..]);
        let mut parent = selector_with_children("def-parent", &[], &["def-sub-a", "def-sub-b"]);
        parent.default = Some("def-sub-b".into());
        let manager = super::super::GroupManager::new(&[sub_a, sub_b, parent], &nodes);
        let state = manager.score_state();

        // No stored choice: the default (non-first) member serves and must
        // be the one committing its rank.
        let _ = manager.selection_plan_for_domain("def-parent", ProbeDomain::Tcp, IpVersion::V4);
        assert_eq!(
            state
                .selection_reason_counts("def-sub-b", SelectionNetwork::Tcp)
                .cold_explore,
            1
        );
        assert_eq!(
            state.selection_reason_counts("def-sub-a", SelectionNetwork::Tcp),
            SelectionReasonCounts::default()
        );
    }

    #[test]
    fn selector_commit_follows_alive_fallback() {
        let dead = node("fallback-dead");
        let nodes = [dead.clone(), node("fallback-alpha"), node("fallback-beta")];
        let sub = group("fallback-sub", &nodes[1..]);
        let parent = Group {
            id: Uuid::new_v4(),
            name: "fallback-parent".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![dead.id],
            groups: vec!["fallback-sub".into()],
            ..Default::default()
        };
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(dead.id, ProbeDomain::Tcp, IpVersion::V4);
        let manager =
            super::super::GroupManager::with_alive_set(&[sub, parent], &nodes, Some(alive));
        let state = manager.score_state();

        // The chosen direct member is dead; the fallback serving sub-group
        // must be the one committing its rank.
        manager.set_selector_choice("fallback-parent", "fallback-dead");
        let _ =
            manager.selection_plan_for_domain("fallback-parent", ProbeDomain::Tcp, IpVersion::V4);
        assert_eq!(
            state
                .selection_reason_counts("fallback-sub", SelectionNetwork::Tcp)
                .cold_explore,
            1
        );
    }

    #[test]
    fn score_reason_snapshot_reload_policy_is_name_based() {
        let nodes = [node("private-reload-alpha"), node("private-reload-beta")];
        let score = group("persist", &nodes);
        let manager = super::super::GroupManager::new(std::slice::from_ref(&score), &nodes);
        let state = manager.score_state();
        let target = context("private-reload-target.internal", IpVersion::V4);
        let _ = manager.selection_plan_for_target("persist", &target);
        let recorded = manager.score_reason_snapshot();
        assert_eq!(recorded[0].tcp.cold_explore, 1);

        let selector = Group {
            policy: GroupPolicy::Selector,
            ..score.clone()
        };
        let hidden = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&selector),
            &nodes,
            None,
            Arc::clone(&state),
        );
        hidden.publish_score_membership();
        assert!(hidden.score_reason_snapshot().is_empty());
        let _ = manager.selection_plan_for_target("persist", &target);
        assert_eq!(
            state.selection_reason_counts("persist", SelectionNetwork::Tcp),
            SelectionReasonCounts {
                cold_explore: 1,
                ..Default::default()
            }
        );

        let empty_score = group("persist", &[]);
        let restored = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&empty_score),
            &nodes,
            None,
            Arc::clone(&state),
        );
        restored.publish_score_membership();
        assert_eq!(restored.score_reason_snapshot(), recorded);

        let deleted = super::super::GroupManager::with_alive_set_and_score_state(
            &[],
            &nodes,
            None,
            Arc::clone(&state),
        );
        deleted.publish_score_membership();
        let recreated = super::super::GroupManager::with_alive_set_and_score_state(
            std::slice::from_ref(&score),
            &nodes,
            None,
            Arc::clone(&state),
        );
        recreated.publish_score_membership();
        let reset = recreated.score_reason_snapshot();
        assert_eq!(reset[0].tcp, ScoreReasonCounters::default());
        let _ = manager.selection_plan_for_target("persist", &target);
        assert_eq!(recreated.score_reason_snapshot(), reset);
        let _ = recreated.selection_plan_for_target("persist", &target);
        let current = recreated.score_reason_snapshot();
        assert_eq!(current[0].tcp.cold_explore, 1);

        let empty = super::super::GroupManager::new(&[], &nodes);
        assert!(empty.score_reason_snapshot().is_empty());
        println!(
            "snapshot lifecycle recorded={recorded:?} hidden=[] restored={recorded:?} recreated={reset:?} current={current:?}"
        );
    }

    #[test]
    fn normalizes_domain_key_and_keeps_target_dimensions_independent() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);

        let a = context("EXAMPLE.COM.", IpVersion::V4);
        finish_success(&manager.selection_plan_for_target("score", &a));
        let normalized = context("example.com", IpVersion::V4);
        assert!(
            manager
                .score_state()
                .has_exact("score", &normalized, nodes[0].id)
        );
        assert!(!manager.score_state().has_exact(
            "score",
            &context("example.com", IpVersion::V6),
            nodes[0].id,
        ));
        assert!(!manager.score_state().has_exact(
            "score",
            &context("other.example", IpVersion::V4),
            nodes[0].id,
        ));
    }

    #[test]
    fn cold_exploration_is_deterministic_and_cancelled_loser_is_neutral() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("example.com", IpVersion::V4);
        let first = manager.selection_plan_for_target("score", &context);
        assert_eq!(first.entries[0].node.id, nodes[0].id);
        drop(first.entries[0].feedback.as_ref().unwrap().start());
        assert_eq!(
            manager.selection_plan_for_target("score", &context).entries[0]
                .node
                .id,
            nodes[0].id
        );
        finish_success(&manager.selection_plan_for_target("score", &context));
        assert_eq!(
            manager.selection_plan_for_target("score", &context).entries[0]
                .node
                .id,
            nodes[1].id,
            "the first useful success must release the next cold candidate"
        );
    }

    #[test]
    fn cancelled_exact_attempt_does_not_hide_aggregate_failure() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        manager
            .feedback_for_group_node(
                "score",
                nodes[0].id,
                ScoreSelectionContext::aggregate(
                    SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .unwrap()
            .start()
            .setup_failed(ScoreOutcome::Timeout);

        let context = context("cancelled.example", IpVersion::V4);
        drop(
            manager
                .feedback_for_group_node("score", nodes[0].id, context.clone())
                .unwrap()
                .start(),
        );

        assert!(
            !manager
                .score_state()
                .has_exact("score", &context, nodes[0].id)
        );
        assert_eq!(selected(&manager, &context), nodes[1].id);
    }

    #[test]
    fn reload_reuses_state_and_prunes_removed_members() {
        let nodes = [node("a"), node("b")];
        let old = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("example.com", IpVersion::V4);
        finish_success(&old.selection_plan_for_target("score", &context));
        let state = old.score_state();
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
            &[group("score", &nodes[1..])],
            &nodes[1..],
            None,
            Arc::clone(&state),
        );
        replacement.publish_score_membership();
        assert!(!state.has_exact("score", &context, nodes[0].id));
    }

    #[test]
    fn nested_score_groups_keep_the_target_and_complete_attribution_path() {
        let nodes = [node("a"), node("b")];
        let child = group("child", &nodes);
        let mut parent = group("parent", &[]);
        parent.groups.push("child".into());
        let manager = super::super::GroupManager::new(&[child, parent], &nodes);
        let context = context("example.com", IpVersion::V6);

        let plan = manager.selection_plan_for_target("parent", &context);
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].selection_chain, ["parent", "child", "a"]);
        let feedback = plan.entries[0].feedback.as_ref().unwrap();
        assert_eq!(
            feedback
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["parent", "child"]
        );
        finish_success(&plan);
        for group in ["parent", "child"] {
            assert!(
                manager
                    .score_state()
                    .has_exact(group, &context, nodes[0].id)
            );
        }
    }

    #[test]
    fn feedback_for_node_merges_nested_score_memberships_once() {
        let leaf = node("leaf");
        let other = node("other");
        let child = group("child", std::slice::from_ref(&leaf));
        let mut bridge = group("bridge", std::slice::from_ref(&leaf));
        bridge.policy = GroupPolicy::Selector;
        let mut parent = group("parent", std::slice::from_ref(&leaf));
        parent.groups = vec!["child".into(), "bridge".into()];
        let manager = super::super::GroupManager::new(
            &[
                child,
                bridge,
                parent,
                group("unrelated", std::slice::from_ref(&other)),
            ],
            &[leaf.clone(), other],
        );

        let feedback = manager
            .feedback_for_node(
                leaf.id,
                ScoreSelectionContext::aggregate(
                    SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .expect("nested Honk memberships must produce feedback");
        let mut groups = feedback
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>();
        groups.sort_unstable();
        assert_eq!(groups, ["child", "parent"]);
    }
    #[test]
    fn nested_score_last_resort_keeps_child_attribution() {
        let leaf = node("leaf");
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
        let child = group("child", std::slice::from_ref(&leaf));
        let mut parent = group("parent", &[]);
        parent.groups.push(child.name.clone());
        let manager = super::super::GroupManager::with_alive_set(
            &[child, parent],
            std::slice::from_ref(&leaf),
            Some(alive),
        );
        let plan = manager
            .selection_plan_for_target("parent", &context("last-resort.example", IpVersion::V4));
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(
            plan.entries[0]
                .feedback
                .as_ref()
                .unwrap()
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["parent", "child"]
        );
    }

    #[test]
    fn deep_score_last_resort_keeps_every_attribution() {
        let leaf = node("leaf");
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
        let child = group("child", std::slice::from_ref(&leaf));
        let mut middle = group("middle", &[]);
        middle.groups.push(child.name.clone());
        let mut outer = group("outer", &[]);
        outer.groups.push(middle.name.clone());
        let manager = super::super::GroupManager::with_alive_set(
            &[child, middle, outer],
            std::slice::from_ref(&leaf),
            Some(alive),
        );

        let plan =
            manager.selection_plan_for_target("outer", &context("deep.example", IpVersion::V4));
        assert_eq!(
            plan.entries[0].selection_chain,
            ["outer", "middle", "child", "leaf"]
        );
        assert_eq!(
            plan.entries[0]
                .feedback
                .as_ref()
                .unwrap()
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["outer", "middle", "child"]
        );
    }

    #[test]
    fn duplicate_direct_leaf_stays_direct_on_last_resort() {
        let leaf = node("leaf");
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
        let child = group("child", std::slice::from_ref(&leaf));
        let mut parent = group("parent", std::slice::from_ref(&leaf));
        parent.groups.push(child.name.clone());
        let manager = super::super::GroupManager::with_alive_set(
            &[child, parent],
            std::slice::from_ref(&leaf),
            Some(alive),
        );

        let plan = manager
            .selection_plan_for_target("parent", &context("last-resort.example", IpVersion::V4));
        assert_eq!(plan.entries[0].selection_chain, ["parent", "leaf"]);
        assert_eq!(
            plan.entries[0]
                .feedback
                .as_ref()
                .unwrap()
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["parent"]
        );
    }

    #[test]
    fn duplicate_leaf_paths_do_not_change_score_rank() {
        let nodes = [node("a"), node("b")];
        let mut bridge = group("bridge", std::slice::from_ref(&nodes[0]));
        bridge.policy = GroupPolicy::Selector;
        let mut parent = group("score", &nodes);
        parent.groups.push(bridge.name.clone());
        let manager = super::super::GroupManager::new(&[parent, bridge], &nodes);
        let context = context("duplicate.example", IpVersion::V4);
        finish_failure(&manager.selection_plan_for_target("score", &context));
        assert_eq!(selected(&manager, &context), nodes[1].id);
    }

    #[test]
    fn aggregate_feedback_completion_and_cancellation_are_accounted_once() {
        let leaf = node("leaf");
        let manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&leaf))],
            std::slice::from_ref(&leaf),
        );
        let feedback = manager
            .feedback_for_node(
                leaf.id,
                ScoreSelectionContext::aggregate(
                    SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .unwrap();

        drop(feedback.start());
        assert_eq!(
            manager
                .score_state()
                .aggregate_stats("score", SelectionNetwork::Tcp, leaf.id),
            None
        );
        let reporter = feedback.start();
        reporter.setup_succeeded();
        reporter.finish(ScoreOutcome::Success);
        assert_eq!(
            manager
                .score_state()
                .aggregate_stats("score", SelectionNetwork::Tcp, leaf.id),
            Some((1, 1, 0))
        );
    }

    #[test]
    fn setup_only_success_does_not_become_usefulness_failure() {
        let leaf = node("leaf");
        let manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&leaf))],
            std::slice::from_ref(&leaf),
        );
        let context = context("prepared.example", IpVersion::V4);
        let feedback = manager.selection_plan_for_target("score", &context).entries[0]
            .feedback
            .clone()
            .unwrap();
        let reporter = feedback.start();
        reporter.setup_succeeded();
        reporter.finish_setup_only();
        assert_eq!(
            manager
                .score_state()
                .exact_useful_failures("score", &context, leaf.id),
            Some(0)
        );

        let related = reporter.feedback().start();
        related.setup_succeeded();
        related.finish_setup_only();

        assert_eq!(
            manager
                .score_state()
                .exact_useful_failures("score", &context, leaf.id),
            Some(0)
        );
    }

    #[test]
    fn setup_only_exact_samples_keep_aggregate_reliability() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        for index in 0..8 {
            let reporter = manager
                .feedback_for_group_node(
                    "score",
                    nodes[0].id,
                    context(&format!("a-{index}.example"), IpVersion::V4),
                )
                .unwrap()
                .start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }
        let reporter = manager
            .feedback_for_group_node("score", nodes[1].id, context("b.example", IpVersion::V4))
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);

        let target = context("prepared.example", IpVersion::V4);
        for _ in 0..8 {
            let reporter = manager
                .feedback_for_group_node("score", nodes[0].id, target.clone())
                .unwrap()
                .start();
            reporter.setup_succeeded();
            reporter.finish_setup_only();
        }

        assert_eq!(selected(&manager, &target), nodes[0].id);
    }

    #[test]
    fn setup_only_family_samples_keep_global_reliability() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        for index in 0..8 {
            let reporter = manager
                .feedback_for_group_node(
                    "score",
                    nodes[0].id,
                    context(&format!("a-{index}.example"), IpVersion::V6),
                )
                .unwrap()
                .start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }
        let reporter = manager
            .feedback_for_group_node("score", nodes[1].id, context("b.example", IpVersion::V6))
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);

        let reporter = manager
            .feedback_for_group_node(
                "score",
                nodes[0].id,
                context("prepared.example", IpVersion::V4),
            )
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.finish_setup_only();

        assert_eq!(
            selected(&manager, &context("fresh.example", IpVersion::V4)),
            nodes[0].id
        );
    }

    #[test]
    fn compact_outcome_finds_nested_io_errors() {
        let error = anyhow::Error::new(io::Error::new(io::ErrorKind::TimedOut, "secret target"))
            .context("outer context");
        assert_eq!(ScoreOutcome::from_error(&error), ScoreOutcome::Timeout);
    }

    #[test]
    fn exact_cache_has_a_hard_lru_bound() {
        let node = node("a");
        let manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&node))],
            std::slice::from_ref(&node),
        );
        for index in 0..=EXACT_CAPACITY {
            finish_success(&manager.selection_plan_for_target(
                "score",
                &context(&format!("{index}.example"), IpVersion::V4),
            ));
        }
        assert_eq!(manager.score_state().exact_len(), EXACT_CAPACITY);
    }

    #[test]
    fn setup_failure_switches_to_the_other_candidate() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("failure.example", IpVersion::V4);

        assert_eq!(selected(&manager, &context), nodes[0].id);
        finish_failure(&manager.selection_plan_for_target("score", &context));
        assert_eq!(selected(&manager, &context), nodes[1].id);
    }

    #[test]
    fn inflight_exact_attempt_does_not_mask_aggregate_reliability() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let aggregate = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        manager
            .feedback_for_group_node("score", nodes[0].id, aggregate.clone())
            .unwrap()
            .start()
            .setup_failed(ScoreOutcome::Other);
        let good = manager
            .feedback_for_group_node("score", nodes[1].id, aggregate)
            .unwrap()
            .start();
        good.setup_succeeded();
        good.finish_setup_only();
        let target = context("inflight.example", IpVersion::V4);
        let inflight = manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .start();

        assert_eq!(selected(&manager, &target), nodes[1].id);

        drop(inflight);
    }

    #[test]
    fn network_target_and_family_buckets_are_isolated() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let tcp_a_v4 = context("a.example", IpVersion::V4);
        finish_failure(&manager.selection_plan_for_target("score", &tcp_a_v4));

        let mut udp_a_v4 = tcp_a_v4.clone();
        udp_a_v4.network = SelectionNetwork::Udp;
        udp_a_v4.probe_domain = ProbeDomain::DataUdp;
        let tcp_b_v4 = context("b.example", IpVersion::V4);
        let tcp_a_v6 = context("a.example", IpVersion::V6);
        let state = manager.score_state();

        assert_eq!(
            state.exact_stats("score", &tcp_a_v4, nodes[0].id),
            Some((1, 0, 1))
        );
        for untouched in [&udp_a_v4, &tcp_b_v4, &tcp_a_v6] {
            assert_eq!(state.exact_stats("score", untouched, nodes[0].id), None);
        }
        finish_success(&manager.selection_plan_for_target("score", &tcp_b_v4));
        assert_eq!(
            state.exact_stats("score", &tcp_b_v4, nodes[1].id),
            Some((1, 1, 0))
        );
        assert_eq!(state.exact_stats("score", &tcp_a_v4, nodes[1].id), None);
    }

    #[test]
    fn dead_candidate_is_excluded_before_scoring() {
        let nodes = [node("a"), node("b")];
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(nodes[0].id, ProbeDomain::Tcp, IpVersion::V4);
        let manager = super::super::GroupManager::with_alive_set(
            &[group("score", &nodes)],
            &nodes,
            Some(alive),
        );

        assert_eq!(
            selected(&manager, &context("dead.example", IpVersion::V4)),
            nodes[1].id
        );
    }

    #[test]
    fn aggregate_cache_has_a_hard_lru_bound() {
        let state = ScorePolicyState::default();
        let node_id = node("a").id;
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let memberships: Vec<_> = (0..=AGGREGATE_CAPACITY)
            .map(|index| (format!("group-{index}"), node_id))
            .collect();
        state.publish_membership(memberships.iter().cloned());
        for (group, node_id) in memberships {
            drop(state.start(&context, &[ScoreAttribution { group, node_id }]));
        }
        assert_eq!(state.inner.lock().aggregate.len(), AGGREGATE_CAPACITY);
        assert_eq!(state.inner.lock().aggregate_evictions, 1);
        assert_eq!(state.inner.lock().exact_evictions, 0);
    }

    #[test]
    fn stale_exact_completion_does_not_mutate_recreated_cell() {
        let node = node("a");
        let manager = super::super::GroupManager::new(
            &[group("score", std::slice::from_ref(&node))],
            std::slice::from_ref(&node),
        );
        let evicted = context("evicted.example", IpVersion::V4);
        let reporter = manager.selection_plan_for_target("score", &evicted).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        for index in 0..EXACT_CAPACITY {
            let context = context(&format!("{index}.example"), IpVersion::V4);
            finish_success(&manager.selection_plan_for_target("score", &context));
        }
        let replacement = manager.selection_plan_for_target("score", &evicted).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);
        assert_eq!(
            manager
                .score_state()
                .exact_stats("score", &evicted, node.id),
            Some((1, 0, 0))
        );
        replacement.setup_succeeded();
        replacement.tx(1);
        replacement.rx(1);
        replacement.finish(ScoreOutcome::Success);
        assert_eq!(
            manager
                .score_state()
                .exact_stats("score", &evicted, node.id),
            Some((1, 1, 0))
        );
    }

    #[test]
    fn stale_aggregate_completion_does_not_mutate_recreated_cell() {
        let state = ScorePolicyState::default();
        let node_id = node("a").id;
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let memberships: Vec<_> = (0..=AGGREGATE_CAPACITY)
            .map(|index| (format!("group-{index}"), node_id))
            .collect();
        state.publish_membership(memberships.iter().cloned());
        let evicted = ScoreAttribution {
            group: memberships[0].0.clone(),
            node_id,
        };
        let stale_cells = state.start(&context, std::slice::from_ref(&evicted));
        for (group, node_id) in memberships.iter().skip(1) {
            drop(state.start(
                &context,
                &[ScoreAttribution {
                    group: group.clone(),
                    node_id: *node_id,
                }],
            ));
        }
        let current_cells = state.start(&context, std::slice::from_ref(&evicted));
        let sample = FlowSample {
            outcome: ScoreOutcome::Success,
            setup: Some(Duration::ZERO),
            first_response: None,
            tx: 1,
            rx: 1,
            elapsed: Duration::from_millis(1),
            count_usefulness: true,
            streak_neutral: false,
        };
        state.finish(
            &context,
            std::slice::from_ref(&evicted),
            &stale_cells,
            &sample,
        );
        assert_eq!(state.inner.lock().aggregate.len(), AGGREGATE_CAPACITY);
        assert_eq!(
            state.aggregate_stats(&evicted.group, SelectionNetwork::Tcp, node_id),
            Some((1, 0, 0))
        );
        state.finish(
            &context,
            std::slice::from_ref(&evicted),
            &current_cells,
            &sample,
        );
        assert_eq!(
            state.aggregate_stats(&evicted.group, SelectionNetwork::Tcp, node_id),
            Some((1, 1, 0))
        );
    }

    #[test]
    fn builtin_direct_final_is_valid_feedback_membership() {
        let mut outer = group("outer", &[]);
        outer.final_outbound = Some(honk_config::Config::BUILTIN_DIRECT_NODE.into());
        let manager = super::super::GroupManager::new(&[outer], &[]);
        let context = context("final-direct.example", IpVersion::V4);
        let feedback = manager
            .feedback_for_group_node(
                "outer",
                honk_config::config::DIRECT_NODE_ID,
                context.clone(),
            )
            .unwrap();
        let reporter = feedback.start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);
        assert!(manager.score_state().has_exact(
            "outer",
            &context,
            honk_config::config::DIRECT_NODE_ID
        ));
    }

    #[test]
    fn aggregate_display_does_not_advance_nested_load_balance() {
        let nodes = [node("a"), node("b")];
        let mut child = group("child", &nodes);
        child.policy = GroupPolicy::LoadBalance;
        let mut parent = group("parent", &[]);
        parent.groups.push(child.name.clone());
        let manager = super::super::GroupManager::new(&[parent, child], &nodes);

        assert_eq!(
            manager.get_score_selection_for_network("parent", SelectionNetwork::Tcp),
            Some("child".into())
        );
        assert_eq!(manager.select_node("child").unwrap().id, nodes[0].id);
    }

    #[test]
    fn late_completion_keeps_extant_member_and_drops_deleted_member() {
        let nodes = [node("a"), node("b")];
        let old = super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
        let context = context("reload.example", IpVersion::V4);
        let reporter_a = old.selection_plan_for_target("score", &context).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        finish_success(&old.selection_plan_for_target("score", &context));
        let reporter_b = old.selection_plan_for_target("score", &context).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        let state = old.score_state();
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
            &[group("score", &nodes[..1])],
            &nodes[..1],
            None,
            Arc::clone(&state),
        );
        replacement.publish_score_membership();

        for reporter in [&reporter_a, &reporter_b] {
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }
        assert!(state.has_exact("score", &context, nodes[0].id));
        assert!(!state.has_exact("score", &context, nodes[1].id));
    }

    #[test]
    fn final_outbound_late_completion_keeps_extant_leaf_and_drops_deleted_leaf() {
        let leaves = [node("final-a"), node("final-b")];
        let mut final_group = group("final-group", &leaves);
        final_group.policy = GroupPolicy::Selector;
        let mut outer = group("outer", &[]);
        outer.final_outbound = Some(final_group.name.clone());
        let old = super::super::GroupManager::new(&[outer.clone(), final_group.clone()], &leaves);
        let context = context("final.example", IpVersion::V4);
        let reporter_a = old
            .feedback_for_group_node("outer", leaves[0].id, context.clone())
            .unwrap()
            .start();
        let reporter_b = old
            .feedback_for_group_node("outer", leaves[1].id, context.clone())
            .unwrap()
            .start();
        let state = old.score_state();
        assert!(
            state
                .inner
                .lock()
                .valid
                .contains(&("outer".into(), leaves[0].id))
        );
        assert!(
            state
                .inner
                .lock()
                .valid
                .contains(&("outer".into(), leaves[1].id))
        );

        final_group.nodes.retain(|node_id| *node_id == leaves[0].id);
        let replacement = super::super::GroupManager::with_alive_set_and_score_state(
            &[outer, final_group],
            std::slice::from_ref(&leaves[0]),
            None,
            Arc::clone(&state),
        );
        replacement.publish_score_membership();
        for reporter in [&reporter_a, &reporter_b] {
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }

        assert!(state.has_exact("outer", &context, leaves[0].id));
        assert!(!state.has_exact("outer", &context, leaves[1].id));
    }
