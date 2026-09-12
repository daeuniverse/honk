use super::*;
use std::time::Duration;

fn nid(name: &str) -> uuid::Uuid {
    uuid::Uuid::new_v5(&honk_config::node::NODE_ID_NAMESPACE, name.as_bytes())
}

fn make_node(id: uuid::Uuid, name: &str) -> Node {
    Node {
        id,
        name: name.into(),
        ..Default::default()
    }
}
fn make_group(name: &str, policy: GroupPolicy, ids: Vec<uuid::Uuid>) -> Group {
    Group {
        name: name.into(),
        policy,
        nodes: ids,
        ..Default::default()
    }
}

/// Repro of the gateway scenario: urltest group where one node has a
/// good UDP latency (trojan) and another (anytls, UoT-blackhole) has
/// none. The UDP pick must choose the trojan node, not mirror TCP.
#[test]
fn udp_pick_prefers_node_with_udp_latency_over_mirror() {
    let (t, a) = (nid("trojan"), nid("anytls"));
    let nodes = vec![make_node(t, "trojan"), make_node(a, "anytls")];
    let alive = std::sync::Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("japan", GroupPolicy::URLTest, vec![t, a])],
        &nodes,
        Some(alive.clone()),
    );
    // anytls: great TCP latency (best TCP), no UDP latency.
    alive.record_probe_latency(
        nid("anytls"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(50),
    );
    // trojan: worse TCP, but has real UDP latency.
    alive.record_probe_latency(
        nid("trojan"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(200),
    );
    alive.record_probe_latency(
        nid("trojan"),
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(283),
    );

    let udp = m.select_node_for_domain("japan", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(
        udp.unwrap().name,
        "trojan",
        "UDP pick must prefer the node with real UDP latency"
    );
}

#[test]
fn udp_pick_keeps_tcp_mirror_with_only_synthetic_failures() {
    let (a, b) = (nid("udp-mirror-a"), nid("udp-mirror-b"));
    let nodes = vec![make_node(a, "a"), make_node(b, "b")];
    let child = make_group("udp-mirror-child", GroupPolicy::URLTest, vec![b]);
    let mut parent = make_group("udp-mirror-parent", GroupPolicy::URLTest, vec![a]);
    parent.groups = vec![child.name.clone()];
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(&[child, parent], &nodes, Some(alive.clone()));

    alive.record_probe_latency(
        a,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    alive.record_probe_latency(
        b,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    assert_eq!(
        manager
            .select_node_for_domain("udp-mirror-parent", ProbeDomain::Tcp, IpVersion::V4)
            .map(|node| node.name.as_str()),
        Some("b")
    );

    for _ in 0..2 {
        alive.record_dial_failure(b, ProbeDomain::DataUdp, IpVersion::V4);
    }
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        assert_eq!(
            manager
                .select_node_for_domain("udp-mirror-parent", domain, IpVersion::V4)
                .map(|node| node.name.as_str()),
            Some("b"),
            "synthetic {domain:?} evidence must not disable the nested TCP mirror"
        );
    }
}

#[test]
fn udp_pick_switches_after_real_evidence_survives_ring_eviction() {
    let (a, b) = (nid("udp-ring-a"), nid("udp-ring-b"));
    let nodes = vec![make_node(a, "a"), make_node(b, "b")];
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(
        &[make_group("udp-ring", GroupPolicy::URLTest, vec![a, b])],
        &nodes,
        Some(alive.clone()),
    );

    alive.record_probe_latency(
        a,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    alive.record_probe_latency(
        b,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    assert_eq!(
        manager
            .select_node_for_domain("udp-ring", ProbeDomain::Tcp, IpVersion::V4)
            .map(|node| node.name.as_str()),
        Some("b")
    );
    for _ in 0..2 {
        alive.record_dial_failure(b, ProbeDomain::DataUdp, IpVersion::V4);
    }
    let synthetic_choice = manager
        .select_node_for_domain("udp-ring", ProbeDomain::DataUdp, IpVersion::V4)
        .map(|node| node.name.as_str());

    alive.record_probe_latency(
        b,
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(20),
    );
    for _ in 0..11 {
        alive.record_dial_failure(b, ProbeDomain::DataUdp, IpVersion::V4);
    }
    assert!(
        alive
            .get_last_real_sample(b, ProbeDomain::DataUdp, IpVersion::V4)
            .is_none(),
        "the real sample must be evicted from the ten-entry display ring"
    );
    assert!(alive.is_failure_demoted(b, ProbeDomain::DataUdp, IpVersion::V4));
    let retained_choice = manager
        .select_node_for_domain("udp-ring", ProbeDomain::DataUdp, IpVersion::V4)
        .map(|node| node.name.as_str());

    assert_eq!(
        (synthetic_choice, retained_choice),
        (Some("b"), Some("a")),
        "UDP should mirror TCP before real evidence, then demote b after it is retained"
    );
}

fn assert_udp_selection(manager: &GroupManager, group: &str, expected: Option<&str>) {
    for ipver in [IpVersion::V4, IpVersion::V6] {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            assert_eq!(
                manager
                    .select_node_for_domain(group, domain, ipver)
                    .map(|node| node.name.as_str()),
                expected,
                "{group}: {domain:?}/{ipver:?}"
            );
            let expected_nodes: Vec<_> = expected.into_iter().collect();
            for plan in [
                manager.selection_plan_for_domain(group, domain, ipver),
                manager.peek_selection_plan_for_domain(group, domain, ipver),
            ] {
                assert_eq!(
                    plan.nodes
                        .iter()
                        .map(|node| node.name.as_str())
                        .collect::<Vec<_>>(),
                    expected_nodes,
                    "{group}: {domain:?}/{ipver:?}"
                );
            }
            let context = ScoreSelectionContext {
                target: Some(ScoreTarget::domain("selector.example", 443)),
                ..ScoreSelectionContext::aggregate(SelectionNetwork::Udp, domain, ipver)
            };
            let plan = manager.selection_plan_for_target_with_health_fallback(group, &context);
            assert_eq!(
                plan.entries
                    .iter()
                    .map(|entry| entry.node.name.as_str())
                    .collect::<Vec<_>>(),
                expected_nodes,
                "{group}: target-aware {domain:?}/{ipver:?}"
            );
        }
    }
}

#[test]
fn selector_udp_choice_does_not_fall_back_to_default_or_sibling() {
    let nodes = [make_node(nid("a"), "a"), make_node(nid("b"), "b")];
    let mut group = make_group(
        "selector",
        GroupPolicy::Selector,
        vec![nodes[0].id, nodes[1].id],
    );
    group.default = Some("b".into());
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(&[group], &nodes, Some(alive.clone()));

    for ipver in [IpVersion::V4, IpVersion::V6] {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_unavailable_forced(nodes[1].id, domain, ipver);
        }
    }
    assert_udp_selection(&manager, "selector", None);
    manager.set_selector_choice("selector", "a");
    assert_udp_selection(&manager, "selector", Some("a"));
    manager.set_selector_choice("selector", "b");
    assert_udp_selection(&manager, "selector", None);
    assert_eq!(manager.select_node("selector").unwrap().name, "b");

    for ipver in [IpVersion::V4, IpVersion::V6] {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_available_traffic(nodes[1].id, domain, ipver);
            alive.report_unavailable_forced(nodes[0].id, domain, ipver);
        }
    }
    assert_udp_selection(&manager, "selector", Some("b"));
    manager.set_selector_choice("selector", "a");
    assert_udp_selection(&manager, "selector", None);

    manager.set_selector_choice("selector", "removed");
    assert_udp_selection(&manager, "selector", Some("b"));
}

#[test]
fn selector_udp_nested_choice_preserves_subgroup_policy_boundary() {
    let nodes = [
        make_node(nid("a"), "a"),
        make_node(nid("b"), "b"),
        make_node(nid("outside"), "outside"),
    ];
    let child = make_group(
        "child",
        GroupPolicy::Selector,
        vec![nodes[0].id, nodes[1].id],
    );
    let automatic = make_group("automatic", GroupPolicy::URLTest, child.nodes.clone());
    let mut parent = make_group("parent", GroupPolicy::Selector, vec![nodes[2].id]);
    parent.groups = vec!["child".into(), "automatic".into()];
    parent.default = Some("child".into());
    let alive = Arc::new(AliveDialerSet::new());
    let manager =
        GroupManager::with_alive_set(&[child, automatic, parent], &nodes, Some(alive.clone()));

    for ipver in [IpVersion::V4, IpVersion::V6] {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_unavailable_forced(nodes[0].id, domain, ipver);
        }
    }
    assert_udp_selection(&manager, "parent", None);
    manager.set_selector_choice("child", "b");
    assert_udp_selection(&manager, "parent", Some("b"));
    manager.set_selector_choice("child", "a");
    manager.set_selector_choice("parent", "automatic");
    assert_udp_selection(&manager, "parent", Some("b"));

    for ipver in [IpVersion::V4, IpVersion::V6] {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_unavailable_forced(nodes[1].id, domain, ipver);
        }
    }
    assert_udp_selection(&manager, "parent", None);
    manager.set_selector_choice("parent", "outside");
    assert_udp_selection(&manager, "parent", Some("outside"));
}

#[test]
fn selector_udp_health_family_fallback_keeps_the_selected_member() {
    let nodes = [make_node(nid("a"), "a"), make_node(nid("b"), "b")];
    let group = make_group(
        "selector",
        GroupPolicy::Selector,
        vec![nodes[0].id, nodes[1].id],
    );
    let alive = Arc::new(AliveDialerSet::new());
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(nodes[0].id, domain, IpVersion::V6);
    }
    let manager = GroupManager::with_alive_set(&[group], &nodes, Some(alive));
    manager.set_selector_choice("selector", "a");
    let context = ScoreSelectionContext {
        target_family: Some(IpVersion::V6),
        target: Some(ScoreTarget::domain("ipv6.example", 443)),
        ..ScoreSelectionContext::aggregate(
            SelectionNetwork::Udp,
            ProbeDomain::DataUdp,
            IpVersion::V6,
        )
    };
    assert!(
        manager
            .selection_plan_for_domain("selector", ProbeDomain::DataUdp, IpVersion::V6)
            .nodes
            .is_empty()
    );
    assert!(
        manager
            .selection_plan_for_target("selector", &context)
            .entries
            .is_empty()
    );
    let plan = manager.selection_plan_for_target_with_health_fallback("selector", &context);
    assert_eq!(plan.health_family, IpVersion::V4);
    assert_eq!(
        plan.entries
            .iter()
            .map(|entry| entry.node.id)
            .collect::<Vec<_>>(),
        [nodes[0].id]
    );
}

#[test]
fn selector_duplicate_names_keep_one_identity_across_entrypoints() {
    let first = Node::from_share_link("socks5://127.0.0.1:1080#shared").unwrap();
    let second = Node::from_share_link("socks5://127.0.0.1:1081#shared").unwrap();
    let ids = vec![first.id, second.id];
    let mut direct = make_group("direct-members", GroupPolicy::Selector, ids.clone());
    direct.default = Some("shared".into());
    let mut mixed = make_group("mixed-members", GroupPolicy::Selector, ids);
    mixed.default = Some("shared".into());
    mixed.groups.push("unused".into());
    let mut parent = make_group("parent", GroupPolicy::Selector, vec![]);
    parent.groups.push(mixed.name.clone());
    let config = honk_config::Config {
        nodes: vec![first, second],
        groups: vec![
            direct,
            mixed,
            parent,
            make_group("unused", GroupPolicy::Selector, vec![]),
        ],
        ..Default::default()
    };
    config.validate().unwrap();
    let first_id = config.nodes[0].id;
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive.clone()));
    let picks = |name: &str, domain| {
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::from_probe_domain(domain),
            domain,
            IpVersion::V4,
        );
        [
            manager
                .select_node_for_domain(name, domain, IpVersion::V4)
                .into_iter()
                .map(|node| node.id)
                .collect::<Vec<_>>(),
            manager
                .selection_plan_for_domain(name, domain, IpVersion::V4)
                .nodes
                .into_iter()
                .map(|node| node.id)
                .collect(),
            manager
                .peek_selection_plan_for_domain(name, domain, IpVersion::V4)
                .nodes
                .into_iter()
                .map(|node| node.id)
                .collect(),
            manager
                .selection_plan_for_target(name, &context)
                .entries
                .into_iter()
                .map(|entry| entry.node.id)
                .collect(),
        ]
    };
    let healthy: [Vec<_>; 4] = std::array::from_fn(|_| vec![first_id]);
    for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp] {
        for name in ["direct-members", "mixed-members", "parent"] {
            assert_eq!(picks(name, domain), healthy, "{name}/{domain:?}");
        }
    }
    for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(first_id, domain, IpVersion::V4);
    }
    let mut refused = Vec::new();
    for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp] {
        for name in ["direct-members", "mixed-members", "parent"] {
            refused.push(picks(name, domain));
        }
    }
    assert!(refused.iter().flatten().all(Vec::is_empty), "{refused:?}");
    for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_available_traffic(first_id, domain, IpVersion::V4);
    }
    for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp] {
        for name in ["direct-members", "mixed-members", "parent"] {
            assert_eq!(
                picks(name, domain),
                healthy,
                "{name}/{domain:?} after recovery"
            );
        }
    }
}
