use super::*;
use honk_config::group::{Group, GroupPolicy};
mod attribution;
mod cadence;
mod evidence;
mod reasons;

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
