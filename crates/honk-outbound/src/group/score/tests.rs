use super::budget::exploration_target;
use super::ranking::score_snapshot;
use super::*;
use honk_config::group::{Group, GroupPolicy};
use honk_config::node::Node;
mod attribution;
mod availability;
mod budget;
mod budget_projection;
mod cadence;
mod comparison;
mod directional;
mod evaluation;
mod evidence;
mod live;
mod performance;
mod pressure;
mod progress;
mod reasons;
mod selection;
mod verification;
mod verification_boundaries;

fn assert_close(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
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
        setup_success: successes,
        useful_success: successes,
        availability: Availability {
            reporters: successes.min(PERFORMANCE_VALIDATION_SAMPLES) as u8,
            latest_rx_at: Some(now),
            ..Default::default()
        },
        performance: Performance {
            response: WeightedMean {
                sum: latency_ms * successes,
                weight: successes,
                observed_at: Some(now),
            },
            ..Default::default()
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
        .begin()
        .expect("current Score plan must admit work")
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
        .begin()
        .expect("current Score plan must admit work")
        .start()
        .setup_failed(ScoreOutcome::Timeout);
}

fn respond_at(attempt: ScoreAttempt, latency: Duration, now: Instant) {
    let reporter = attempt.begin_at(now).unwrap().start_at(now);
    reporter.setup_succeeded_at(now);
    reporter.first_response_at(now + latency);
    reporter.transfer_at(1, 1, now + latency);
    reporter.finish_at(ScoreOutcome::Success, true, now + latency);
}

fn selected(manager: &super::super::GroupManager, context: &ScoreSelectionContext) -> Uuid {
    manager.selection_plan_for_target("score", context).entries[0]
        .node
        .id
}

fn train_at(
    manager: &GroupManager,
    leaf: &Node,
    target: &ScoreSelectionContext,
    samples: usize,
    response_ms: u64,
    download: u64,
    now: Instant,
) {
    let response = Duration::from_millis(response_ms);
    train_response_at(manager, leaf, target, samples, response, download, now);
}

fn train_response_at(
    manager: &GroupManager,
    leaf: &Node,
    target: &ScoreSelectionContext,
    samples: usize,
    response: Duration,
    download: u64,
    now: Instant,
) {
    let feedback = manager
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..samples).map(|_| feedback.start_at(now)).collect();
    for reporter in &reporters {
        reporter.setup_succeeded_at(now);
    }
    for reporter in &reporters {
        reporter.first_response_at(now + response);
    }
    let finished = now + Duration::from_secs(1).max(response);
    for reporter in &reporters {
        reporter.transfer_at(1, download.max(1), finished);
    }
    for reporter in reporters {
        reporter.finish_at(ScoreOutcome::Success, true, finished);
    }
}

fn probe_at(
    manager: &GroupManager,
    leaf: &Node,
    probe_context: &ScoreSelectionContext,
    latency_ms: u64,
    now: Instant,
) {
    let latency = Duration::from_millis(latency_ms);
    probe_source_at(
        manager,
        leaf,
        probe_context,
        ScoreSource::HealthProbe,
        latency,
        now,
    );
}

fn probe_source_at(
    manager: &GroupManager,
    leaf: &Node,
    probe_context: &ScoreSelectionContext,
    source: ScoreSource,
    latency: Duration,
    now: Instant,
) {
    for _ in 0..4 {
        let reporter = manager
            .feedback_for_group_node("score", leaf.id, probe_context.clone())
            .unwrap()
            .with_source(source)
            .start_at(now);
        reporter.setup_succeeded_at(now);
        reporter.probe_latency_at(latency, now);
        reporter.finish_at(ScoreOutcome::Success, false, now);
    }
}

fn rank_at(
    manager: &GroupManager,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    now: Instant,
) -> usize {
    manager
        .score_state()
        .rank_at("score", target, &nodes.iter().collect::<Vec<_>>(), now)
}

/// Usability ends exactly sixty seconds after the cohort's latest eligible receive.
fn assert_usable_until(
    manager: &GroupManager,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    expires: Instant,
) {
    let refs = nodes.iter().collect::<Vec<_>>();
    let state = |at| {
        manager
            .score_state()
            .verification_snapshot_at("score", target, &refs, at)
            .unwrap()
            .state
    };
    assert_eq!(
        state(expires - Duration::from_millis(1)),
        ScoreVerificationState::ObservedUsable
    );
    assert_eq!(state(expires), ScoreVerificationState::Provisional);
}

/// A decision's original pairs, as `ranking::decision` builds them.
fn pairs_at(
    inner: &StateInner,
    target: &ScoreSelectionContext,
    refs: &[&Node],
    scores: (&[ScoreSnapshot], PerformanceBaseline),
    membership: (&[bool], usize),
    now: Instant,
) -> super::comparison::PairCohort {
    super::comparison::View::new(inner, "score", target, refs, now).pairs(scores, membership)
}

fn decision_at(
    inner: &StateInner,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    reference: usize,
    now: Instant,
) -> ranking::Decision {
    let refs = nodes.iter().collect::<Vec<_>>();
    let scores = nodes
        .iter()
        .map(|node| score_snapshot(inner, "score", target, node.id, now))
        .collect::<Vec<_>>();
    let baseline = ranking::performance_baseline(&scores);
    // Comparison unit tests exercise every member; bounding is covered by evaluation tests.
    let membership = vec![true; nodes.len()];
    let evidence =
        super::comparison::View::new(inner, "score", target, &refs, now).node_evidence(&membership);
    let pairs = pairs_at(
        inner,
        target,
        &refs,
        (&scores, baseline),
        (&membership, reference),
        now,
    );
    let ordinary = ranking::ordinary_selection(&scores, &refs, Some(reference), baseline, &pairs);
    ranking::Decision {
        scores,
        evidence,
        pairs,
        baseline,
        ordinary,
        evaluation: Default::default(),
        membership,
    }
}
