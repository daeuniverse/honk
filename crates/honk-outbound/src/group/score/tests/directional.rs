use super::super::comparison::{self, Basis, MetricPair, PairEvidence};
use super::super::ranking::{
    ordinary_selection, performance_baseline, promotion_result, switch_margin,
};
use super::*;

fn metric(left: f64, right: f64, now: Instant) -> MetricPair {
    MetricPair {
        incumbent: left,
        candidate: right,
        reporters: 4,
        latest_at: now,
        expires_at: now + Duration::from_secs(60),
    }
}

fn trained_pair(now: Instant) -> (ScoreSnapshot, ScoreSnapshot, PairEvidence) {
    let score = ScoreSnapshot {
        completed: 8.0,
        useful_completed: 8.0,
        observed_reliability: 1.0,
        reliability: 0.8,
        reliability_upper: 1.0,
        ..ScoreSnapshot::default()
    };
    let pair = PairEvidence {
        basis: Basis::ExactTarget,
        response: Some(metric(100.0, 100.0, now)),
        ..PairEvidence::default()
    };
    (score, score, pair)
}

#[test]
fn unilateral_upload_and_download_gains_promote_without_max_direction_masking() {
    for upload in [true, false] {
        let nodes = [node("direction incumbent"), node("direction candidate")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("directional", IpVersion::V4);
        let now = Instant::now();
        for (index, leaf) in nodes.iter().enumerate() {
            for _ in 0..8 {
                let reporter = manager
                    .feedback_for_group_node("score", leaf.id, target.clone())
                    .unwrap()
                    .start_at(now);
                reporter.setup_succeeded_at(now);
                reporter.first_response_at(now + Duration::from_millis(100));
                let improved = if index == 0 { 512 * 1024 } else { 768 * 1024 };
                let (tx, rx) = if upload {
                    (improved, 8 * 1024 * 1024)
                } else {
                    (8 * 1024 * 1024, improved)
                };
                reporter.transfer_at(tx, rx, now + Duration::from_secs(1));
                reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(1));
            }
        }
        let state = manager.score_state();
        let inner = state.inner.lock();
        let refs: Vec<_> = nodes.iter().collect();
        let at = now + Duration::from_secs(1);
        let decision = decision_at(&inner, &nodes, &target, 0, at);
        let scores = &decision.scores;
        let baseline = decision.baseline;
        assert_eq!(
            ordinary_selection(scores, &refs, None, baseline, &decision.pairs).index,
            0
        );
        let result = promotion_result(
            decision.pairs.get(1).unwrap(),
            (scores[0].qualified(), scores[1].qualified()),
            (
                scores[0].observed_reliability,
                scores[1].observed_reliability,
            ),
        );
        assert!(result.gain > switch_margin(scores[0].completed));
        assert_eq!(
            ordinary_selection(scores, &refs, Some(0), baseline, &decision.pairs).index,
            1
        );
    }
}

#[test]
fn unknown_direction_stays_unknown_but_does_not_veto_a_supported_gain() {
    let now = Instant::now();
    let (incumbent, candidate, mut pair) = trained_pair(now);
    pair.upload = Some(metric(100.0, 150.0, now));
    let result = promotion_result(
        pair,
        (incumbent.qualified(), candidate.qualified()),
        (
            incumbent.observed_reliability,
            candidate.observed_reliability,
        ),
    );
    assert!(!result.directional_tradeoff);
    assert!(result.gain > switch_margin(incumbent.completed));
    pair.response = None;
    assert_eq!(
        promotion_result(
            pair,
            (incumbent.qualified(), candidate.qualified()),
            (
                incumbent.observed_reliability,
                candidate.observed_reliability
            )
        )
        .gain,
        0.0
    );
}

#[test]
fn throughput_needs_response_and_same_unit_qualified_reliability() {
    let now = Instant::now();
    let (incumbent, mut candidate, mut pair) = trained_pair(now);
    pair.download = Some(metric(100.0, 10000.0, now));
    candidate.observed_reliability = 0.999;
    assert!(
        promotion_result(
            pair,
            (incumbent.qualified(), candidate.qualified()),
            (
                incumbent.observed_reliability,
                candidate.observed_reliability
            )
        )
        .gain
            < 0.0
    );
    candidate.observed_reliability = 1.0;
    candidate.useful_completed = 3.0;
    assert_eq!(
        promotion_result(
            pair,
            (incumbent.qualified(), candidate.qualified()),
            (
                incumbent.observed_reliability,
                candidate.observed_reliability
            )
        )
        .gain,
        0.0
    );
    candidate.useful_completed = 8.0;
    pair.response = Some(metric(100.0, 111.0, now));
    assert!(
        promotion_result(
            pair,
            (incumbent.qualified(), candidate.qualified()),
            (
                incumbent.observed_reliability,
                candidate.observed_reliability
            )
        )
        .gain
            < 0.0
    );
}

#[test]
fn direction_tolerance_boundaries_are_inclusive_but_do_not_reduce_hold_margin() {
    let now = Instant::now();
    let (incumbent, candidate, mut pair) = trained_pair(now);
    pair.upload = Some(metric(100.0, 110.0, now));
    pair.download = Some(metric(100.0, 90.0, now));
    let result = promotion_result(
        pair,
        (incumbent.qualified(), candidate.qualified()),
        (
            incumbent.observed_reliability,
            candidate.observed_reliability,
        ),
    );
    assert!(!result.directional_tradeoff);
    assert!(result.gain > 0.0);
    assert!(result.gain < switch_margin(incumbent.completed));
    pair.download = Some(metric(100.0, 89.999, now));
    assert!(
        promotion_result(
            pair,
            (incumbent.qualified(), candidate.qualified()),
            (
                incumbent.observed_reliability,
                candidate.observed_reliability
            )
        )
        .directional_tradeoff
    );
    pair.upload = Some(metric(100.0, 10000.0, now));
    pair.download = Some(metric(100.0, 100.0, now));
    pair.response = Some(metric(100.0, 110.0, now));
    assert!(
        promotion_result(
            pair,
            (incumbent.qualified(), candidate.qualified()),
            (
                incumbent.observed_reliability,
                candidate.observed_reliability
            )
        )
        .gain
            > switch_margin(incumbent.completed)
    );
}

#[test]
fn first_choice_and_real_failure_escape_need_no_comparison_evidence() {
    let now = Instant::now();
    let nodes = [node("escape incumbent"), node("escape candidate")];
    let (mut incumbent, mut candidate, _) = trained_pair(now);
    candidate.performance.response = MetricSnapshot {
        value: Some(10.0),
        confidence: 1.0,
    };
    incumbent.performance.response = MetricSnapshot {
        value: Some(1000.0),
        confidence: 1.0,
    };
    let pairs = comparison::PairCohort {
        reference: 0,
        pairs: vec![None; 2],
    };
    let mut scores = [incumbent, candidate];
    let baseline = performance_baseline(&scores);
    assert_eq!(
        ordinary_selection(
            &scores,
            &nodes.iter().collect::<Vec<_>>(),
            None,
            baseline,
            &pairs
        )
        .index,
        1
    );
    assert_eq!(
        ordinary_selection(
            &scores,
            &nodes.iter().collect::<Vec<_>>(),
            Some(0),
            baseline,
            &pairs,
        )
        .index,
        0
    );
    scores[0].unresolved_failure = true;
    let escaped = ordinary_selection(
        &scores,
        &nodes.iter().collect::<Vec<_>>(),
        Some(0),
        baseline,
        &pairs,
    );
    assert_eq!(escaped.index, 1);
    assert_eq!(escaped.reason, SelectionReason::FreshFailureBypass);
}
