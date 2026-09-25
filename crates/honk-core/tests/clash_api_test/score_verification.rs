use super::*;
use honk_config::group::GroupPolicy;
use honk_outbound::group::{
    ScoreOutcome, ScoreSelectionContext, ScoreSource, ScoreTarget, SelectionNetwork,
};

async fn get_json(app: &TestApp, path: &str) -> serde_json::Value {
    let response = http_client().get(app.url(path)).send().await.unwrap();
    assert_eq!(response.status(), 200);
    response.json().await.unwrap()
}

fn context(network: SelectionNetwork) -> ScoreSelectionContext {
    ScoreSelectionContext::aggregate(
        network,
        match network {
            SelectionNetwork::Tcp => ProbeDomain::Tcp,
            SelectionNetwork::Udp => ProbeDomain::DataUdp,
        },
        IpVersion::V4,
    )
}

fn business_success(
    manager: &GroupManager,
    node: &Node,
    context: &ScoreSelectionContext,
    response: bool,
) {
    let reporter = manager
        .feedback_for_node(node.id, context.clone())
        .unwrap()
        .start();
    reporter.setup_succeeded();
    reporter.tx(1);
    if response {
        reporter.first_response();
    }
    reporter.rx(1);
    reporter.finish(ScoreOutcome::Success);
}

#[tokio::test]
async fn score_stats_count_only_committed_switches_and_distinguish_ineligible_incumbents() {
    let nodes = [make_node("private-a"), make_node("private-b")];
    let app = spawn_app_with_config(
        Config {
            nodes: nodes.to_vec(),
            groups: vec![
                Group {
                    name: "auto".into(),
                    policy: GroupPolicy::Score,
                    nodes: nodes.iter().map(|node| node.id).collect(),
                    ..Default::default()
                },
                Group {
                    name: "empty".into(),
                    policy: GroupPolicy::Score,
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    let manager = app.state.group_manager.read().clone();
    let initial = get_json(&app, "/stats").await;
    let groups = initial["score"]["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0]["name"], "auto");
    assert_eq!(groups[1]["name"], "empty");
    for group in groups {
        for network in ["tcp", "udp"] {
            assert_eq!(group[network]["ordinarySwitch"], 0);
        }
    }

    for (network, label) in [
        (SelectionNetwork::Tcp, "tcp"),
        (SelectionNetwork::Udp, "udp"),
    ] {
        let context = ScoreSelectionContext {
            target: Some(ScoreTarget::domain("private-switch.example", 6543)),
            target_family: Some(IpVersion::V4),
            ..context(network)
        };
        for (index, node) in nodes.iter().enumerate() {
            let plan = manager.selection_plan_for_target("auto", &context);
            assert_eq!(plan.entries[0].node.id, node.id);
            let reporter = plan.entries[0]
                .feedback
                .as_ref()
                .unwrap()
                .begin()
                .unwrap()
                .start();
            // Cold exploration reaches the challenger only once the selection has evidence.
            if index == 0 {
                reporter.setup_succeeded();
                reporter.tx(1);
                reporter.first_response();
                reporter.rx(1);
                reporter.finish(ScoreOutcome::Success);
            } else {
                reporter.finish(ScoreOutcome::Cancelled);
            }
            assert_eq!(
                get_json(&app, "/stats").await["score"]["groups"][0][label]["ordinarySwitch"],
                0
            );
        }
        for node in &nodes {
            for _ in 0..16 {
                business_success(&manager, node, &context, true);
            }
        }

        let first = manager.selection_plan_for_target("auto", &context);
        let incumbent = first.entries[0].node.id;
        let first_stats = get_json(&app, "/stats").await;
        assert_eq!(
            first_stats["score"]["groups"][0][label]["ordinarySwitch"],
            0
        );
        let stay = manager.selection_plan_for_target("auto", &context);
        assert_eq!(stay.entries[0].node.id, incumbent);
        let before = get_json(&app, "/stats").await;
        let before_counts = &before["score"]["groups"][0][label];
        assert_eq!(before_counts["ordinarySwitch"], 0);
        assert_eq!(before_counts["incumbentIneligible"], 0);

        for _ in 0..3 {
            manager
                .feedback_for_node(incumbent, context.clone())
                .unwrap()
                .start()
                .setup_failed(ScoreOutcome::Timeout);
        }
        let switched = manager.selection_plan_for_target("auto", &context);
        let challenger = nodes.iter().find(|node| node.id != incumbent).unwrap();
        assert_eq!(switched.entries[0].node.id, challenger.id);
        let after = get_json(&app, "/stats").await;
        let after_counts = &after["score"]["groups"][0][label];
        assert_eq!(after_counts["ordinarySwitch"], 1);
        assert_eq!(after_counts["incumbentIneligible"], 1);
        assert_eq!(after_counts["freshFailureBypass"], 0);
        for reason in [
            "coldExplore",
            "periodicExplore",
            "reliabilityWinner",
            "performanceWinner",
            "incumbentHeld",
            "insufficientEvidenceHeld",
            "freshFailureBypass",
        ] {
            assert_eq!(
                after_counts[reason], before_counts[reason],
                "{label}: {reason}"
            );
        }
        for path in ["/proxies", "/proxies/auto", "/stats"] {
            get_json(&app, path).await;
        }
        assert_eq!(get_json(&app, "/stats").await["score"], after["score"]);
    }

    let final_stats = get_json(&app, "/stats").await;
    for network in ["tcp", "udp"] {
        assert_eq!(
            final_stats["score"]["groups"][0][network]["ordinarySwitch"],
            1
        );
        assert_eq!(
            final_stats["score"]["groups"][1][network]["ordinarySwitch"],
            0
        );
    }
    let encoded = final_stats["score"].to_string();
    assert!(!encoded.contains("private-switch.example"));
    assert!(!encoded.contains("6543"));
    for node in &nodes {
        assert!(!encoded.contains(&node.name));
        assert!(!encoded.contains(&node.id.to_string()));
    }
}

#[tokio::test]
async fn score_verification_is_private_readonly_and_uses_canonical_candidates() {
    let (a, b, dead, unchosen) = (
        make_node("private-a"),
        make_node("private-b"),
        make_node("private-dead"),
        make_node("private-unchosen"),
    );
    let nodes = vec![a.clone(), b.clone(), dead.clone(), unchosen.clone()];
    let app = spawn_app_with_config(
        Config {
            nodes: nodes.clone(),
            groups: vec![
                Group {
                    name: "auto".into(),
                    policy: GroupPolicy::Score,
                    nodes: vec![a.id, a.id, dead.id],
                    groups: vec!["selected".into(), "alias".into()],
                    ..Default::default()
                },
                Group {
                    name: "selected".into(),
                    policy: GroupPolicy::Selector,
                    nodes: vec![b.id, unchosen.id],
                    ..Default::default()
                },
                Group {
                    name: "alias".into(),
                    policy: GroupPolicy::Selector,
                    nodes: vec![b.id],
                    ..Default::default()
                },
                Group {
                    name: "empty".into(),
                    policy: GroupPolicy::Score,
                    final_outbound: Some(unchosen.name.clone()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        app.state
            .alive_set
            .report_unavailable_forced(dead.id, domain, IpVersion::V4);
    }
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        app.state
            .alive_set
            .report_unavailable_forced(b.id, domain, IpVersion::V4);
    }
    let manager = app.state.group_manager.read().clone();
    let private_context = ScoreSelectionContext {
        target: Some(ScoreTarget::domain("private-target.example", 6543)),
        target_family: Some(IpVersion::V6),
        ..context(SelectionNetwork::Tcp)
    };
    drop(
        manager
            .feedback_for_node(a.id, private_context)
            .unwrap()
            .start(),
    );
    let before = get_json(&app, "/stats").await;
    for path in ["/proxies", "/proxies/auto"] {
        let body = get_json(&app, path).await;
        let proxy = if path == "/proxies" {
            &body["proxies"]["auto"]
        } else {
            &body
        };
        let verification = &proxy["scoreVerification"];
        assert_eq!(proxy["type"], "url_test");
        assert_eq!(verification["objective"], "responseQualityWithAvailability");
        assert_eq!(verification["scope"], "aggregate");
        for (network, candidates) in [("tcp", 2), ("udp", 1)] {
            let summary = &verification[network];
            assert_eq!(summary["state"], "provisional");
            assert_eq!(summary["challengers"], serde_json::json!([]));
            assert_eq!(summary["coverage"]["candidates"], candidates);
            assert_eq!(summary["coverage"]["pending"], candidates);
            assert_eq!(summary["question"], "availability");
            assert_eq!(summary["nextAction"], "nextBusinessFlow");
            assert_eq!(summary["network"], network);
            assert_eq!(summary["targetSpecific"], false);
            assert!(summary["targetFamily"].is_null());
        }
        let encoded = verification.to_string();
        assert!(!encoded.contains("private-target.example"));
        assert!(!encoded.contains("6543"));
        for node in &nodes {
            assert!(!encoded.contains(&node.id.to_string()));
        }
        assert!(!encoded.contains(&dead.name));
        assert!(!encoded.contains(&unchosen.name));
        assert_eq!(verification["tcp"]["selected"], proxy["now"]);
        if path == "/proxies" {
            assert!(
                body["proxies"]["selected"]
                    .get("scoreVerification")
                    .is_none()
            );
            let empty = &body["proxies"]["empty"];
            assert_eq!(empty["now"], unchosen.name);
            for network in ["tcp", "udp"] {
                let summary = &empty["scoreVerification"][network];
                assert_eq!(summary["state"], "provisional");
                assert_eq!(summary["challengers"], serde_json::json!([]));
                assert_eq!(summary["nextAction"], "none");
                assert_eq!(
                    summary["coverage"],
                    serde_json::json!({
                        "scope": "all", "candidates": 0, "evaluated": 0, "unevaluated": 0,
                        "pending": 0,
                    })
                );
            }
        }
    }
    let after = get_json(&app, "/stats").await;
    assert_eq!(before["score"], after["score"]);
}

#[tokio::test]
async fn score_verification_separates_probe_comparison_from_business_usability() {
    let nodes = [make_node("fast"), make_node("slow")];
    let group = Group {
        name: "auto".into(),
        policy: GroupPolicy::Score,
        nodes: nodes.iter().map(|node| node.id).collect(),
        ..Default::default()
    };
    let config = Config {
        nodes: nodes.to_vec(),
        groups: vec![group],
        ..Default::default()
    };
    let app = spawn_app_with_config(config.clone(), "", "").await;
    let manager = app.state.group_manager.read().clone();
    let context = ScoreSelectionContext {
        target: Some(ScoreTarget::domain("business-private.example", 443)),
        target_family: Some(IpVersion::V4),
        ..context(SelectionNetwork::Tcp)
    };
    for (node, latency) in nodes.iter().zip([10, 100]) {
        for _ in 0..16 {
            let reporter = manager
                .feedback_for_node(node.id, context.clone())
                .unwrap()
                .with_source(ScoreSource::HealthProbe)
                .start();
            reporter.probe_latency(Duration::from_millis(latency));
            reporter.finish(ScoreOutcome::Success);
        }
    }
    let probes = get_json(&app, "/proxies/auto").await;
    let verification = &probes["scoreVerification"]["tcp"];
    assert_eq!(verification["state"], "provisional");
    let challenger = &verification["challengers"][0];
    assert_eq!(challenger["name"], "slow");
    assert_eq!(challenger["basis"], "configuredProbe");
    assert_eq!(challenger["relation"], "selectedFaster");
    assert_eq!(verification["question"], "availability");
    assert_eq!(verification["nextAction"], "nextBusinessFlow");

    for node in &nodes {
        for _ in 0..16 {
            business_success(&manager, node, &context, false);
        }
    }
    manager.selection_plan_for_target("auto", &context);
    let observed = get_json(&app, "/proxies/auto").await;
    let verification = &observed["scoreVerification"]["tcp"];
    assert_eq!(observed["now"], "fast");
    assert_eq!(verification["state"], "observedUsable");
    assert_eq!(
        verification["challengers"],
        serde_json::json!([{
            "name": "slow", "basis": "configuredProbe", "relation": "selectedFaster",
            "reporters": 4, "validForMs": verification["challengers"][0]["validForMs"],
        }])
    );
    // Configured probes never settle a pair question, so the slower member stays pending.
    assert_eq!(
        verification["coverage"],
        serde_json::json!({
            "scope": "all", "candidates": 2, "evaluated": 2, "unevaluated": 0, "pending": 1,
        })
    );
    assert_eq!(verification["question"], "response");
    assert_eq!(verification["nextAction"], "nextBusinessFlow");
    let validity = verification["challengers"][0]["validForMs"]
        .as_u64()
        .unwrap();
    assert!(validity > 0 && validity <= 120_000);
    assert_eq!(observed["scoreVerification"]["udp"]["state"], "provisional");

    let before = get_json(&app, "/stats").await;
    assert_eq!(
        before["score"]["groups"][0]["verification"]["tcp"]["usableSelections"],
        1
    );
    for path in ["/proxies", "/proxies/auto", "/stats"] {
        get_json(&app, path).await;
    }
    assert_eq!(get_json(&app, "/stats").await["score"], before["score"]);

    let replacement = GroupManager::with_alive_set_and_score_state(
        &config.groups,
        &config.nodes,
        Some(app.state.alive_set.clone()),
        manager.score_state(),
    );
    replacement.publish_score_membership();
    *app.state.group_manager.write() = Arc::new(replacement);
    let reloaded = get_json(&app, "/proxies/auto").await;
    let verification = &reloaded["scoreVerification"]["tcp"];
    assert_eq!(verification["state"], "provisional");
    assert_eq!(verification["challengers"], serde_json::json!([]));
    assert_eq!(verification["question"], "availability");
    assert_eq!(verification["nextAction"], "nextBusinessFlow");

    let manager = app.state.group_manager.read().clone();
    for node in &nodes {
        manager
            .feedback_for_node(node.id, context.clone())
            .unwrap()
            .start()
            .finish(ScoreOutcome::Timeout);
    }
    let failed = get_json(&app, "/proxies/auto").await;
    assert_eq!(failed["scoreVerification"]["tcp"]["state"], "provisional");
    assert_eq!(failed["scoreVerification"]["tcp"]["question"], "recovery");
}

#[tokio::test]
async fn score_verification_keeps_singleton_aggregate_availability_separate_from_target_response() {
    let node = make_node("single");
    let app = spawn_app_with_config(
        Config {
            nodes: vec![node.clone()],
            groups: vec![Group {
                name: "auto".into(),
                policy: GroupPolicy::Score,
                nodes: vec![node.id],
                ..Default::default()
            }],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    let manager = app.state.group_manager.read().clone();
    let mut reporters = Vec::new();
    for network in [SelectionNetwork::Tcp, SelectionNetwork::Udp] {
        let context = ScoreSelectionContext {
            target: Some(ScoreTarget::domain("business-private.example", 443)),
            target_family: Some(IpVersion::V6),
            ..context(network)
        };
        for _ in 0..4 {
            let reporter = manager
                .feedback_for_node(node.id, context.clone())
                .unwrap()
                .start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.first_response();
            reporter.rx(1);
            reporters.push(reporter);
        }
    }
    let observed = get_json(&app, "/proxies/auto").await;
    for network in ["tcp", "udp"] {
        let verification = &observed["scoreVerification"][network];
        assert_eq!(verification["state"], "observedUsable");
        assert_eq!(verification["challengers"], serde_json::json!([]));
        assert_eq!(verification["coverage"]["candidates"], 1);
        assert_eq!(verification["question"], "none");
        assert_eq!(verification["nextAction"], "none");
        assert_eq!(verification["targetSpecific"], false);
        assert!(verification["targetFamily"].is_null());
    }
    assert!(
        !observed["scoreVerification"]
            .to_string()
            .contains("business-private.example")
    );
    for reporter in reporters {
        reporter.finish(ScoreOutcome::Cancelled);
    }
    let cancelled = get_json(&app, "/proxies/auto").await;
    for network in ["tcp", "udp"] {
        assert_eq!(
            cancelled["scoreVerification"][network]["state"],
            "observedUsable"
        );
    }
}
