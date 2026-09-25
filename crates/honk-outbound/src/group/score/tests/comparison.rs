use super::super::comparison::{self, Basis, MAX_CELLS, MAX_KEY_BYTES, PairEvidence};
use super::super::evidence::Observation;
use super::super::ranking::{ordinary_selection, performance_baseline};
use super::*;

mod relations;
mod storage_timing;

fn exact(leaf: &Node, target: &ScoreSelectionContext) -> ExactKey {
    ExactKey {
        group: "score".into(),
        network: target.network,
        family: target.target_family.unwrap(),
        target: target.target.clone().unwrap(),
        node_id: leaf.id,
    }
}

fn publish(
    inner: &mut StateInner,
    leaf: &Node,
    target: &ScoreSelectionContext,
    id: u64,
    at: Instant,
    observation: Observation,
) {
    let key = exact(leaf, target);
    let parent = AggregateKey {
        group: "score".into(),
        network: target.network,
        family: None,
        node_id: leaf.id,
    };
    if inner.aggregate.peek(&parent).is_none() {
        inner.tick += 1;
        inner.aggregate.put(
            parent.clone(),
            Stats {
                incarnation: inner.tick,
                ..Stats::default()
            },
        );
    }
    let node_incarnation = inner.aggregate.peek(&parent).unwrap().incarnation;
    if inner.exact.peek(&key).is_none() {
        inner.tick += 1;
        inner.exact.put(
            key.clone(),
            Stats {
                incarnation: inner.tick,
                node_incarnation,
                useful_success: 8.0,
                setup_success: 8.0,
                updated_at: Some(at),
                ..Stats::default()
            },
        );
    }
    let incarnation = inner.exact.peek(&key).unwrap().incarnation;
    let mut cells = [StartedCells {
        exact: Some(incarnation),
        aggregate: [Some(node_incarnation), None],
        ..StartedCells::default()
    }];
    let attribution = [ScoreAttribution {
        group: "score".into(),
        node_id: leaf.id,
    }];
    comparison::observe(
        inner,
        target,
        &attribution,
        (&cells, id),
        ScoreSource::Traffic,
        &observation,
        at,
    );
    inner.valid.insert(("score".into(), leaf.id));
    ScorePolicyState::observe(
        inner,
        target,
        &attribution,
        &mut cells,
        ScoreSource::Traffic,
        observation,
        at,
    );
}

fn response(
    inner: &mut StateInner,
    leaf: &Node,
    target: &ScoreSelectionContext,
    count: usize,
    ms: u64,
    at: Instant,
) {
    for _ in 0..count {
        publish(
            inner,
            leaf,
            target,
            comparison::next_reporter_id(),
            at,
            Observation::Response(Duration::from_millis(ms)),
        );
    }
}

fn train_transfers(
    manager: &GroupManager,
    leaf: &Node,
    target: &ScoreSelectionContext,
    (samples, transfer_samples): (usize, usize),
    response: Duration,
    (tx, rx): (u64, u64),
    now: Instant,
) {
    let feedback = manager
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..samples).map(|_| feedback.start_at(now)).collect();
    for reporter in &reporters {
        reporter.setup_succeeded_at(now);
        reporter.first_response_at(now + response);
    }
    for (index, reporter) in reporters.iter().enumerate() {
        let (tx, rx) = if index < transfer_samples {
            (tx, rx)
        } else {
            (1, 1)
        };
        reporter.transfer_at(tx, rx, now + Duration::from_secs(2));
    }
    for reporter in reporters {
        reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(2));
    }
}

fn scores(
    inner: &StateInner,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    now: Instant,
) -> super::super::ranking::Decision {
    decision_at(inner, nodes, target, 0, now)
}

/// The readonly report of `decision`, with members named by node.
fn report(
    inner: &StateInner,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    decision: &super::super::ranking::Decision,
    now: Instant,
) -> ScoreVerificationSnapshot {
    let refs: Vec<_> = nodes.iter().collect();
    let names: Vec<_> = nodes.iter().map(|node| node.name.as_str()).collect();
    super::super::verification::report(inner, ("score", target), decision, (&refs, &names), now)
}

fn pair(
    inner: &StateInner,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    now: Instant,
) -> PairEvidence {
    scores(inner, nodes, target, now).pairs.get(1).unwrap()
}
