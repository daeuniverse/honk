use std::hint::black_box;
use std::sync::Arc;

use chrono::Utc;
use criterion::{Criterion, criterion_group, criterion_main};
use honk_config::node::{Group, GroupPolicy, NODE_ID_NAMESPACE, Node};
use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use honk_outbound::group::{
    GroupManager, ScoreOutcome, ScoreSelectionContext, ScoreTarget, SelectionNetwork,
};
use uuid::Uuid;
fn node(name: &str) -> Node {
    Node {
        id: Uuid::new_v5(&NODE_ID_NAMESPACE, name.as_bytes()),
        name: name.to_owned(),
        ..Default::default()
    }
}

fn group(name: &str, policy: GroupPolicy, nodes: &[Node]) -> Group {
    Group {
        id: Uuid::new_v5(&NODE_ID_NAMESPACE, name.as_bytes()),
        name: name.to_owned(),
        policy,
        nodes: nodes.iter().map(|node| node.id).collect(),
        filters: Vec::new(),
        groups: Vec::new(),
        default: None,
        final_outbound: None,
        check_url: None,
        check_interval: None,
        tolerance: 50,
        idle_timeout: None,
        interrupt_connections: false,
        created_at: Utc::now(),
    }
}

fn bench_group_selection(c: &mut Criterion) {
    let nodes = vec![node("a"), node("b"), node("c")];
    let groups = vec![
        group("selector", GroupPolicy::Selector, &nodes),
        group("load-balance", GroupPolicy::LoadBalance, &nodes),
        group("fallback", GroupPolicy::Fallback, &nodes),
        group("score", GroupPolicy::Score, &nodes),
    ];
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(&groups, &nodes, Some(Arc::clone(&alive)));
    alive.report_available_traffic(nodes[0].id, ProbeDomain::DataUdp, IpVersion::V4);
    let score_context = ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(IpVersion::V4),
        health_family: IpVersion::V4,
        target: Some(ScoreTarget::domain("example.com", 443)),
    };

    let score_nodes: Vec<_> = (0..64)
        .map(|index| node(&format!("score-{index}")))
        .collect();
    let score_manager = GroupManager::new(
        &[group("score", GroupPolicy::Score, &score_nodes)],
        &score_nodes,
    );
    let mut group = c.benchmark_group("group_selection");
    group.bench_function("direct_selector_plan", |b| {
        b.iter(|| {
            let plan = manager.selection_plan_for_domain(
                black_box("selector"),
                ProbeDomain::DataUdp,
                IpVersion::V4,
            );
            black_box(plan.nodes[0].id)
        });
    });
    group.bench_function("score_cold_target_plan", |b| {
        b.iter(|| {
            let plan =
                manager.selection_plan_for_target(black_box("score"), black_box(&score_context));
            black_box(plan.entries[0].node.id)
        });
    });
    for _ in 0..8 {
        let plan = manager.selection_plan_for_target("score", &score_context);
        let reporter = plan.entries[0]
            .feedback
            .as_ref()
            .expect("score feedback")
            .start();
        reporter.setup_succeeded();
        reporter.rx(1);
        reporter.finish(ScoreOutcome::Success);
    }
    group.bench_function("score_trained_target_plan", |b| {
        b.iter(|| {
            let plan =
                manager.selection_plan_for_target(black_box("score"), black_box(&score_context));
            black_box(plan.entries[0].node.id)
        });
    });
    group.bench_function("load_balance_tcp", |b| {
        b.iter(|| {
            black_box(
                manager
                    .select_node_for_domain(
                        black_box("load-balance"),
                        ProbeDomain::Tcp,
                        IpVersion::V4,
                    )
                    .expect("load-balance node")
                    .id,
            )
        });
    });
    group.bench_function("fallback_tcp", |b| {
        b.iter(|| {
            black_box(
                manager
                    .select_node_for_domain(black_box("fallback"), ProbeDomain::Tcp, IpVersion::V4)
                    .expect("fallback node")
                    .id,
            )
        });
    });
    group.bench_function("score_peek_64", |b| {
        b.iter(|| {
            black_box(
                score_manager
                    .get_score_selection_for_network(black_box("score"), SelectionNetwork::Tcp)
                    .expect("score node"),
            )
        });
    });
    group.bench_function("clean_health_success", |b| {
        b.iter(|| {
            alive.report_available_traffic(
                black_box(nodes[0].id),
                ProbeDomain::DataUdp,
                IpVersion::V4,
            );
        });
    });
    group.finish();
}

criterion_group!(benches, bench_group_selection);
criterion_main!(benches);
