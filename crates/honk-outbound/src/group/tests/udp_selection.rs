use super::*;
use std::time::Duration;

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
            let plan =
                manager.selection_plan_for_target_with_health_fallback(group, &context, None);
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

fn udp_incapable_nodes() -> [Node; 2] {
    use honk_config::node::{OutboundConfig, VlessConfig, VmessConfig};

    let uuid = "00000000-0000-0000-0000-000000000001";
    [
        (
            "vmess",
            OutboundConfig::Vmess(VmessConfig {
                uuid: Some(uuid.into()),
                ..Default::default()
            }),
        ),
        (
            "vless-tcp",
            OutboundConfig::Vless(VlessConfig {
                uuid: Some(uuid.into()),
                network: Some("tcp".into()),
                ..Default::default()
            }),
        ),
    ]
    .map(|(name, outbound)| {
        let mut node = Node {
            name: name.into(),
            address: "127.0.0.1:443".into(),
            host: "127.0.0.1".into(),
            port: 443,
            outbound,
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    })
}

#[test]
fn score_udp_capability_filters_selection_verification_and_nested_finals() {
    use honk_config::node::{Udp443Policy, VlessMultiplex};

    let mut capable =
        Node::from_share_link("vless://00000000-0000-0000-0000-000000000002@127.0.0.1:443#udp")
            .unwrap();
    capable.vless_mut().unwrap().multiplex = VlessMultiplex::xray(8, 0, Udp443Policy::Reject);
    capable.id = capable.derive_id();
    let mut nodes = udp_incapable_nodes().to_vec();
    let incapable_ids: Vec<_> = nodes.iter().map(|node| node.id).collect();
    nodes.push(capable);
    let score = make_group(
        "score",
        GroupPolicy::Score,
        nodes.iter().map(|node| node.id).collect(),
    );
    let mut incapable = make_group("incapable", GroupPolicy::Score, incapable_ids);
    incapable.final_outbound = Some("terminal".into());
    let mut terminal = make_group("terminal", GroupPolicy::Score, vec![nodes[1].id]);
    terminal.final_outbound = Some("block".into());
    let parent = make_subgroup("parent", GroupPolicy::Selector, &["incapable"]);
    let groups = [score, incapable, terminal, parent];
    let alive = Arc::new(AliveDialerSet::new());
    for node in &nodes {
        alive.register_node(node.id, node.name.clone(), node.address.clone());
    }

    for alive_set in [Some(alive), None] {
        let manager = GroupManager::with_alive_set(&groups, &nodes, alive_set);
        let counters = manager.score_verification_counters("score", SelectionNetwork::Udp);
        let (selected, verification) = manager
            .score_verification_for_network("score", SelectionNetwork::Udp)
            .unwrap();
        assert_eq!(
            (selected.as_str(), verification.candidate_count),
            ("udp", 1)
        );
        assert_eq!(
            manager
                .get_score_selection_for_network("score", SelectionNetwork::Udp)
                .as_deref(),
            Some("udp")
        );
        assert_eq!(
            manager.score_verification_counters("score", SelectionNetwork::Udp),
            counters
        );
        assert!(
            manager
                .score_verification_for_network("incapable", SelectionNetwork::Udp)
                .is_none()
        );
        assert_eq!(
            manager
                .score_verification_for_network("score", SelectionNetwork::Tcp)
                .unwrap()
                .1
                .candidate_count,
            3
        );
        // Port-443 policy refusal belongs to dispatch, not capability filtering.
        assert_udp_selection(&manager, "score", Some("udp"));
        assert_udp_selection(&manager, "parent", Some("block"));
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Udp,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
        assert_eq!(
            manager
                .selection_plan_for_target("parent", &context)
                .entries[0]
                .selection_chain,
            ["parent", "incapable", "terminal", "block"]
        );
        assert_eq!(
            manager
                .ranked_udp_leaves("score", IpVersion::V4, 3)
                .iter()
                .map(|node| node.id)
                .collect::<Vec<_>>(),
            [nodes[2].id]
        );
    }
}

#[test]
fn selector_udp_capability_keeps_the_pin_and_terminal_members() {
    let mut nodes = udp_incapable_nodes().to_vec();
    nodes.extend([
        Node::from_share_link("socks5://127.0.0.1:1080#udp").unwrap(),
        honk_config::Config::builtin_block_node(),
        honk_config::Config::builtin_direct_node(),
    ]);
    let mut selector = make_group(
        "selector",
        GroupPolicy::Selector,
        nodes.iter().map(|node| node.id).collect(),
    );
    selector.default = Some("udp".into());
    let parent = make_subgroup("parent", GroupPolicy::Selector, &["selector"]);
    let alive = Arc::new(AliveDialerSet::new());
    for node in &nodes {
        alive.register_node(node.id, node.name.clone(), node.address.clone());
    }
    for alive_set in [Some(alive), None] {
        let manager =
            GroupManager::with_alive_set(&[selector.clone(), parent.clone()], &nodes, alive_set);
        for node in &nodes[..2] {
            manager
                .set_selector_choice("selector", &node.name, SelectorNetworks::Both)
                .unwrap();
            assert_udp_selection(&manager, "selector", None);
            assert_udp_selection(&manager, "parent", None);
            assert_eq!(manager.select_node("selector").unwrap().id, node.id);
        }
        for selected in ["udp", "block", "direct"] {
            manager
                .set_selector_choice("selector", selected, SelectorNetworks::Both)
                .unwrap();
            assert_udp_selection(&manager, "selector", Some(selected));
            assert_udp_selection(&manager, "parent", Some(selected));
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
    manager
        .set_selector_choice("selector", "a", crate::group::SelectorNetworks::Both)
        .unwrap();
    assert_udp_selection(&manager, "selector", Some("a"));
    manager
        .set_selector_choice("selector", "b", crate::group::SelectorNetworks::Both)
        .unwrap();
    assert_udp_selection(&manager, "selector", None);
    assert_eq!(manager.select_node("selector").unwrap().name, "b");

    for ipver in [IpVersion::V4, IpVersion::V6] {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_available_traffic(nodes[1].id, domain, ipver);
            alive.report_unavailable_forced(nodes[0].id, domain, ipver);
        }
    }
    assert_udp_selection(&manager, "selector", Some("b"));
    manager
        .set_selector_choice("selector", "a", crate::group::SelectorNetworks::Both)
        .unwrap();
    assert_udp_selection(&manager, "selector", None);

    assert_eq!(
        manager.set_selector_choice("selector", "removed", SelectorNetworks::Both),
        Err(SelectorError::NotMember)
    );
    assert_udp_selection(&manager, "selector", None);
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
    manager
        .set_selector_choice("child", "b", crate::group::SelectorNetworks::Both)
        .unwrap();
    assert_udp_selection(&manager, "parent", Some("b"));
    manager
        .set_selector_choice("child", "a", crate::group::SelectorNetworks::Both)
        .unwrap();
    manager
        .set_selector_choice("parent", "automatic", crate::group::SelectorNetworks::Both)
        .unwrap();
    assert_udp_selection(&manager, "parent", Some("b"));

    for ipver in [IpVersion::V4, IpVersion::V6] {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_unavailable_forced(nodes[1].id, domain, ipver);
        }
    }
    assert_udp_selection(&manager, "parent", None);
    manager
        .set_selector_choice("parent", "outside", crate::group::SelectorNetworks::Both)
        .unwrap();
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
    manager
        .set_selector_choice("selector", "a", crate::group::SelectorNetworks::Both)
        .unwrap();
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
    let plan = manager.selection_plan_for_target_with_health_fallback("selector", &context, None);
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

#[test]
fn named_final_uses_first_declaration_not_hash_order_or_health() {
    let nodes = [
        Node::from_share_link("socks5://127.0.0.1:1080#shared").unwrap(),
        Node::from_share_link("socks5://127.0.0.1:1081#shared").unwrap(),
    ];
    let mut child = make_group("child", GroupPolicy::Selector, vec![]);
    child.final_outbound = Some("shared".into());
    let parent = make_subgroup("parent", GroupPolicy::Selector, &["child"]);
    let groups = [parent, child];
    let alive = Arc::new(AliveDialerSet::new());
    let forward = GroupManager::with_alive_set(&groups, &nodes, Some(alive.clone()));
    let mut reverse = GroupManager::with_alive_set(
        &groups,
        &[nodes[1].clone(), nodes[0].clone()],
        Some(alive.clone()),
    );
    // Identical hash iteration makes opposite declaration orders a deterministic control.
    reverse.nodes = forward.nodes.clone();
    let context = ScoreSelectionContext::aggregate(
        SelectionNetwork::Udp,
        ProbeDomain::DataUdp,
        IpVersion::V4,
    );
    for (manager, first, second) in [(&forward, 0, 1), (&reverse, 1, 0)] {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_available_traffic(nodes[first].id, domain, IpVersion::V4);
            alive.report_unavailable_forced(nodes[second].id, domain, IpVersion::V4);
        }
        let plan = manager.selection_plan_for_target("parent", &context);
        assert_eq!(
            plan.entries
                .iter()
                .map(|entry| entry.node.id)
                .collect::<Vec<_>>(),
            [nodes[first].id]
        );
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_unavailable_forced(nodes[first].id, domain, IpVersion::V4);
            alive.report_available_traffic(nodes[second].id, domain, IpVersion::V4);
        }
        assert!(
            manager
                .selection_plan_for_target("parent", &context)
                .entries
                .is_empty()
        );
    }
}

#[test]
fn nested_score_udp_final_is_explicit_and_health_checked() {
    let nodes = [
        make_node(nid("dead"), "dead"),
        make_node(nid("backup"), "backup"),
        make_node(nid("outside"), "outside"),
    ];
    let mut child = make_group("child", GroupPolicy::Score, vec![nodes[0].id]);
    child.final_outbound = Some("backup".into());
    let mut parent = make_subgroup("parent", GroupPolicy::Selector, &["child", "empty"]);
    parent.nodes.push(nodes[2].id);
    parent.default = Some("child".into());
    let alive = Arc::new(AliveDialerSet::new());
    for family in [IpVersion::V4, IpVersion::V6] {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_unavailable_forced(nodes[0].id, domain, family);
        }
    }
    let manager = GroupManager::with_alive_set(
        &[
            parent,
            child,
            make_group("empty", GroupPolicy::Selector, vec![]),
        ],
        &nodes,
        Some(alive.clone()),
    );
    assert_udp_selection(&manager, "parent", Some("backup"));
    assert_eq!(manager.node_names_in_group("child"), ["dead"]);
    assert_eq!(
        manager.leaf_node_names_in_group("parent"),
        ["outside", "dead"]
    );
    let context = ScoreSelectionContext::aggregate(
        SelectionNetwork::Udp,
        ProbeDomain::DataUdp,
        IpVersion::V4,
    );
    let plan = manager.selection_plan_for_target("parent", &context);
    assert_eq!(
        plan.entries[0].selection_chain,
        ["parent", "child", "backup"]
    );
    assert_eq!(
        manager.selection_chain_for_network("parent", SelectionNetwork::Udp),
        ["parent", "child", "backup"]
    );
    assert_eq!(
        manager
            .ranked_udp_leaves("child", IpVersion::V4, 3)
            .iter()
            .map(|node| node.id)
            .collect::<Vec<_>>(),
        [nodes[1].id]
    );

    manager
        .set_selector_choice("parent", "empty", crate::group::SelectorNetworks::Both)
        .unwrap();
    assert_udp_selection(&manager, "parent", None);
    manager
        .set_selector_choice("parent", "child", crate::group::SelectorNetworks::Both)
        .unwrap();
    for family in [IpVersion::V4, IpVersion::V6] {
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_unavailable_forced(nodes[1].id, domain, family);
        }
    }
    assert_udp_selection(&manager, "parent", None);
}

#[test]
fn nested_final_waits_for_ipv4_proxy_health_before_direct() {
    let nodes = [make_node(nid("proxy"), "proxy")];
    let mut child = make_group("child", GroupPolicy::Score, vec![nodes[0].id]);
    child.final_outbound = Some("direct".into());
    let mut parent = make_subgroup("parent", GroupPolicy::Selector, &["child"]);
    parent.final_outbound = Some("block".into());
    let alive = Arc::new(AliveDialerSet::new());
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(nodes[0].id, domain, IpVersion::V6);
    }
    let manager = GroupManager::with_alive_set(&[child, parent], &nodes, Some(alive.clone()));
    let context = ScoreSelectionContext {
        target_family: Some(IpVersion::V6),
        target: Some(ScoreTarget::domain("ipv6.example", 443)),
        ..ScoreSelectionContext::aggregate(
            SelectionNetwork::Udp,
            ProbeDomain::DataUdp,
            IpVersion::V6,
        )
    };
    let plan = manager.selection_plan_for_target_with_health_fallback("parent", &context, None);
    assert_eq!(plan.health_family, IpVersion::V4);
    assert_eq!(plan.entries[0].node.id, nodes[0].id);
    assert_eq!(
        plan.entries[0].selection_chain,
        ["parent", "child", "proxy"]
    );
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(nodes[0].id, domain, IpVersion::V4);
    }
    let plan = manager.selection_plan_for_target_with_health_fallback("parent", &context, None);
    assert_eq!(plan.entries[0].node.id, honk_config::config::DIRECT_NODE_ID);
    assert_eq!(
        plan.entries[0].selection_chain,
        ["parent", "child", "direct"]
    );
}

#[test]
fn final_peek_and_unselected_subgroups_do_not_advance_rotation() {
    let nodes = [
        make_node(nid("a"), "a"),
        make_node(nid("b"), "b"),
        make_node(nid("outside"), "outside"),
    ];
    let final_group = make_group(
        "rotation",
        GroupPolicy::LoadBalance,
        vec![nodes[0].id, nodes[1].id],
    );
    let mut child = make_group("child", GroupPolicy::Score, vec![]);
    child.final_outbound = Some("rotation".into());
    let mut parent = make_subgroup("parent", GroupPolicy::Selector, &["child"]);
    parent.nodes.push(nodes[2].id);
    let manager = GroupManager::new(&[parent, child, final_group], &nodes);
    assert_eq!(manager.select_node("parent").unwrap().id, nodes[2].id);
    manager
        .set_selector_choice("parent", "child", crate::group::SelectorNetworks::Both)
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            manager
                .peek_selection_plan_for_domain("parent", ProbeDomain::DataUdp, IpVersion::V4)
                .nodes[0]
                .id,
            nodes[0].id
        );
    }
    let warmed = manager.ranked_udp_leaves("child", IpVersion::V4, 2);
    assert_eq!(
        warmed.iter().map(|node| node.id).collect::<Vec<_>>(),
        [nodes[0].id, nodes[1].id]
    );
    assert_eq!(
        manager
            .select_node_for_domain("parent", ProbeDomain::DataUdp, IpVersion::V4)
            .unwrap()
            .id,
        nodes[0].id
    );
    assert_eq!(
        manager
            .select_node_for_domain("parent", ProbeDomain::DataUdp, IpVersion::V4)
            .unwrap()
            .id,
        nodes[1].id
    );
}

#[test]
fn final_chains_preserve_cold_provenance_and_bound_mixed_cycles() {
    let nodes = [make_node(nid("a"), "a"), make_node(nid("b"), "b")];
    let terminal = make_group(
        "terminal",
        GroupPolicy::URLTest,
        vec![nodes[0].id, nodes[1].id],
    );
    let mut bridge = make_group("bridge", GroupPolicy::Selector, vec![]);
    bridge.final_outbound = Some("terminal".into());
    let mut root = make_group("root", GroupPolicy::Score, vec![]);
    root.final_outbound = Some("bridge".into());
    let member = make_subgroup("member", GroupPolicy::Selector, &["root"]);
    let manager = GroupManager::new(&[root, bridge, terminal, member], &nodes);
    let context = ScoreSelectionContext::aggregate(
        SelectionNetwork::Udp,
        ProbeDomain::DataUdp,
        IpVersion::V4,
    );
    let plan = manager.selection_plan_for_target("root", &context);
    assert_eq!(plan.mode, SelectionPlanMode::ColdUrlTest);
    assert_eq!(
        plan.entries
            .iter()
            .map(|entry| entry.node.id)
            .collect::<Vec<_>>(),
        [nodes[0].id, nodes[1].id]
    );
    assert_eq!(
        plan.entries[0].selection_chain,
        ["root", "bridge", "terminal", "a"]
    );
    let nested = manager.selection_plan_for_target("member", &context);
    assert_eq!(nested.mode, SelectionPlanMode::Authoritative);
    assert_eq!(
        nested
            .entries
            .iter()
            .map(|entry| entry.node.id)
            .collect::<Vec<_>>(),
        [nodes[0].id]
    );

    let mut cycle = make_subgroup("cycle", GroupPolicy::Selector, &["back"]);
    let mut back = make_group("back", GroupPolicy::Score, vec![]);
    back.final_outbound = Some("cycle".into());
    let manager = GroupManager::new(&[cycle.clone(), back.clone()], &[]);
    assert_udp_selection(&manager, "cycle", None);
    assert!(
        manager
            .ranked_udp_leaves("cycle", IpVersion::V4, 3)
            .is_empty()
    );
    for (name, id) in [
        ("direct", honk_config::config::DIRECT_NODE_ID),
        ("block", honk_config::config::BLOCK_NODE_ID),
    ] {
        cycle.final_outbound = Some(name.into());
        let manager = GroupManager::new(&[cycle.clone(), back.clone()], &[]);
        let plan = manager.selection_plan_for_target("cycle", &context);
        assert_eq!(plan.entries[0].node.id, id);
        assert_eq!(plan.entries[0].selection_chain, ["cycle", name]);
        assert_udp_selection(&manager, "cycle", Some(name));
    }

    let mut chain: Vec<_> = (0..=MAX_GROUP_DEPTH)
        .map(|index| {
            let mut group = make_group(&format!("level-{index}"), GroupPolicy::Score, vec![]);
            group.final_outbound = Some(format!("level-{}", index + 1));
            group
        })
        .collect();
    chain[MAX_GROUP_DEPTH].final_outbound = Some("direct".into());
    let manager = GroupManager::new(&chain, &[]);
    assert_udp_selection(&manager, "level-0", None);
    assert_udp_selection(&manager, "level-1", Some("direct"));
}
