use super::*;
use honk_config::types::NodeProtocol;

fn exit_group(name: &str, ids: Vec<uuid::Uuid>, exit: &str) -> Group {
    Group {
        exit: Some(exit.into()),
        ..make_group(name, GroupPolicy::Selector, ids)
    }
}

fn nodes(names: &[&str]) -> Vec<Node> {
    names
        .iter()
        .map(|name| make_node(nid(name), name))
        .collect()
}

fn chain_node(name: &str, hops: &[&str]) -> Node {
    Node::chain(name, hops.iter().map(|hop| (*hop).to_owned()).collect())
}

fn bound_nodes(physical: &[&str], name: &str, hops: &[&str]) -> Vec<Node> {
    let mut nodes: Vec<_> = physical
        .iter()
        .enumerate()
        .map(|(index, name)| {
            Node::from_share_link(&format!("socks5://127.0.0.1:{}#{name}", 1080 + index)).unwrap()
        })
        .collect();
    nodes.push(chain_node(name, hops));
    honk_config::Config {
        nodes,
        ..Default::default()
    }
    .assemble(|_, _, _| {})
    .unwrap()
    .nodes
}

fn node_id(nodes: &[Node], name: &str) -> uuid::Uuid {
    nodes.iter().find(|node| node.name == name).unwrap().id
}

fn tcp_context() -> ScoreSelectionContext {
    ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4)
}

/// Each dialing target of `group`'s TCP plan: the node's name and, for a
/// route, its hop names.
fn tcp_plan(manager: &GroupManager, group: &str) -> Vec<(String, Option<Vec<String>>)> {
    manager
        .selection_plan_for_target(group, &tcp_context())
        .entries
        .into_iter()
        .map(|entry| {
            let owned = manager.own_target(Target {
                node: entry.node,
                route: entry.route,
            });
            (
                owned.node.name.clone(),
                owned.route.map(|routed| routed.hop_names.into_vec()),
            )
        })
        .collect()
}

fn routed(leaf: &str, hops: &[&str]) -> (String, Option<Vec<String>>) {
    (
        leaf.to_owned(),
        Some(hops.iter().map(|hop| hop.to_string()).collect()),
    )
}

fn direct(node: &str) -> (String, Option<Vec<String>>) {
    (node.to_owned(), None)
}

#[test]
fn target_layout_stays_two_words() {
    assert_eq!(size_of::<Target<'_>>(), 2 * size_of::<usize>());
    assert_eq!(
        std::mem::size_of::<Option<Box<crate::group::exit::Exits>>>(),
        std::mem::size_of::<usize>()
    );
}

#[test]
fn a_leaf_selected_through_an_exit_group_dials_as_a_route() {
    let manager = GroupManager::new(
        &[exit_group("g", vec![nid("a")], "land")],
        &nodes(&["a", "land"]),
    );
    let plan = manager.selection_plan_for_target("g", &tcp_context());
    let route = plan.entries[0].route.as_deref().unwrap();
    assert_eq!(plan.entries[0].node.id, nid("a"));
    assert_eq!(
        (route.leaf(), route.hops()),
        (nid("a"), &[nid("a"), nid("land")][..])
    );
    assert_eq!(plan.entries[0].selection_chain, ["g", "a"]);
    assert_eq!(tcp_plan(&manager, "g"), [routed("a", &["a", "land"])]);
    assert_eq!(manager.select_node("g").unwrap().id, nid("a"));
    assert_eq!(
        manager
            .selector_warm_node("g", SelectionNetwork::Tcp)
            .unwrap()
            .id,
        nid("a")
    );
}

#[test]
fn nested_exits_chain_from_the_innermost_group_out() {
    let mut outer = exit_group("outer", vec![], "far");
    outer.groups = vec!["inner".into()];
    let manager = GroupManager::new(
        &[outer, exit_group("inner", vec![nid("a")], "near")],
        &nodes(&["a", "near", "far"]),
    );
    assert_eq!(
        tcp_plan(&manager, "outer"),
        [routed("a", &["a", "near", "far"])]
    );
    assert_eq!(tcp_plan(&manager, "inner"), [routed("a", &["a", "near"])]);
}

#[test]
fn a_final_back_to_an_exit_ancestor_keeps_the_routes_below_it() {
    let mut proxy = exit_group("proxy", vec![], "land");
    proxy.groups = vec!["hk".into(), "us".into()];
    let mut hk = make_group("hk", GroupPolicy::Selector, vec![nid("a")]);
    hk.final_outbound = Some("proxy".into());
    let us = make_group("us", GroupPolicy::Selector, vec![nid("b")]);
    let alive = Arc::new(AliveDialerSet::new());
    alive.register_node(nid("a"), "a".into(), Some("127.0.0.1:1080".into()));
    let manager = GroupManager::with_alive_set(
        &[proxy, hk, us],
        &nodes(&["a", "b", "land"]),
        Some(Arc::clone(&alive)),
    );
    manager
        .set_selector_choice("proxy", "hk", SelectorNetworks::Tcp)
        .unwrap();
    assert_eq!(tcp_plan(&manager, "proxy"), [routed("a", &["a", "land"])]);

    alive.report_unavailable_forced(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert!(tcp_plan(&manager, "proxy").is_empty());
    manager
        .set_selector_choice("proxy", "us", SelectorNetworks::Tcp)
        .unwrap();
    assert_eq!(tcp_plan(&manager, "proxy"), [routed("b", &["b", "land"])]);
}

#[test]
fn a_selector_write_during_selection_keeps_each_route_with_its_own_revision() {
    let switch = Group {
        interrupt_connections: true,
        ..make_group(
            "switch",
            GroupPolicy::Fallback,
            vec![nid("first"), nid("second")],
        )
    };
    let pin = make_group("pin", GroupPolicy::Selector, vec![nid("a"), nid("b")]);
    let root = Group {
        exit: Some("land".into()),
        ..make_subgroup("root", GroupPolicy::URLTest, &["switch", "pin"])
    };
    let alive = Arc::new(AliveDialerSet::new());
    let manager = Arc::new(GroupManager::with_alive_set(
        &[root, switch, pin],
        &nodes(&["first", "second", "a", "b", "land"]),
        Some(Arc::clone(&alive)),
    ));
    manager.publish_route_health();
    manager
        .set_selector_choice("pin", "a", SelectorNetworks::Tcp)
        .unwrap();
    assert_eq!(manager.select_node("switch").unwrap().name, "first");
    alive.report_unavailable_forced(nid("first"), ProbeDomain::Tcp, IpVersion::V4);
    for name in ["first", "second", "a", "b"] {
        alive.report_unavailable_forced(nid(name), ProbeDomain::Tcp, IpVersion::V6);
    }

    // Switching the first subgroup's fallback commits B before the same walk visits `pin`.
    let owner = Arc::downgrade(&manager);
    manager.set_interrupt_callback(Some(Arc::new(move |group, network| {
        assert_eq!((group, network), ("switch", SelectionNetwork::Tcp));
        owner
            .upgrade()
            .unwrap()
            .set_selector_choice("pin", "b", SelectorNetworks::Tcp)
            .unwrap();
    })));
    let from_pin = |plan: ScoreSelectionPlan<'_>| {
        let mut entries = plan.entries.into_iter();
        assert_eq!(entries.next().unwrap().node.name, "second");
        let entry = entries.next().unwrap();
        assert_eq!(entry.selection_chain[1], "pin");
        assert!(entries.next().is_none());
        manager.own_target(Target {
            node: entry.node,
            route: entry.route,
        })
    };
    let v6 =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V6);
    let (cold, old_revision) = manager.dial_plan_for_target("root", &v6, None);
    assert_eq!(cold.mode, SelectionPlanMode::ColdUrlTest);
    assert_eq!(cold.health_family, IpVersion::V4);
    assert_eq!(
        manager
            .get_selector_choice("pin", SelectionNetwork::Tcp)
            .as_deref(),
        Some("b"),
    );
    let old = from_pin(cold);
    assert_eq!(old.route().unwrap().hops(), [nid("a"), nid("land")]);
    let refusal = crate::proxy::test_prefix_refusal(1);
    assert!(!manager.report_route_failure(
        "root",
        &old,
        IpVersion::V4,
        old_revision.admit(),
        refusal.as_ref(),
    ));

    let (retry, new_revision) = manager.urltest_retry_dial_plan("root", &tcp_context(), None);
    let current = from_pin(retry);
    let path = current.route().unwrap();
    assert_eq!(path.hops(), [nid("b"), nid("land")]);
    let (_, plain_revision) = manager.dial_plan_for_target("switch", &tcp_context(), None);
    assert!(!manager.report_route_failure(
        "root",
        &current,
        IpVersion::V4,
        plain_revision.admit(),
        refusal.as_ref(),
    ));
    for _ in 0..10 {
        assert!(manager.report_route_failure(
            "root",
            &current,
            IpVersion::V4,
            new_revision.admit(),
            refusal.as_ref(),
        ));
    }
    assert!(!manager.route_prefix_available(path, IpVersion::V4));
    manager.report_route_response(
        "root",
        current.key(),
        IpVersion::V4,
        new_revision.admit(),
        None,
    );
    assert!(manager.route_prefix_available(path, IpVersion::V4));

    manager
        .set_selector_choice("pin", "a", SelectorNetworks::Tcp)
        .unwrap();
    let (again, _) = manager.dial_plan_for_target("root", &v6, None);
    assert_eq!(from_pin(again).key(), old.key());
}

#[test]
fn a_parent_without_exit_keeps_its_own_leaves_direct() {
    let mut parent = make_group("parent", GroupPolicy::LoadBalance, vec![nid("b")]);
    parent.groups = vec!["g".into()];
    let manager = GroupManager::new(
        &[parent, exit_group("g", vec![nid("a")], "land")],
        &nodes(&["a", "b", "land"]),
    );
    // Round-robin: two picks cover both members.
    let mut plan = tcp_plan(&manager, "parent");
    plan.extend(tcp_plan(&manager, "parent"));
    assert!(plan.contains(&direct("b")), "{plan:?}");
    assert!(plan.contains(&routed("a", &["a", "land"])), "{plan:?}");
}

#[test]
fn a_chain_leaf_with_unknown_hops_stays_out_of_a_plan_beside_an_exit() {
    let mut all = nodes(&["land"]);
    all.push(Node {
        id: nid("chain"),
        ..chain_node("chain", &["missing", "land"])
    });
    let manager = GroupManager::new(
        &[
            make_group("plain", GroupPolicy::Selector, vec![nid("chain")]),
            exit_group("g", vec![nid("land")], "land"),
        ],
        &all,
    );
    assert!(tcp_plan(&manager, "plain").is_empty());
}

#[test]
fn a_plan_with_a_leaf_direct_and_routed_keeps_both_entries() {
    let mut parent = Group {
        groups: vec!["g".into()],
        ..make_group("parent", GroupPolicy::URLTest, vec![nid("a")])
    };
    parent.check_url = None;
    let manager = GroupManager::new(
        &[parent, exit_group("g", vec![nid("a")], "land")],
        &nodes(&["a", "land"]),
    );
    let plan = manager.selection_plan_for_target("parent", &tcp_context());
    let keys: Vec<_> = plan
        .entries
        .into_iter()
        .map(|entry| {
            manager
                .own_target(Target {
                    node: entry.node,
                    route: entry.route,
                })
                .key()
        })
        .collect();
    assert_eq!(keys.len(), 2, "{:?}", plan.mode);
    assert!(keys.contains(&DialKey::Node(nid("a"))));
    assert!(keys.iter().any(|key| matches!(key, DialKey::Route(_))));
}

#[test]
fn final_goes_through_the_exit_except_block() {
    let mut to_node = exit_group("to-node", vec![], "land");
    to_node.final_outbound = Some("b".into());
    let mut to_direct = exit_group("to-direct", vec![], "land");
    to_direct.final_outbound = Some("direct".into());
    let mut to_block = exit_group("to-block", vec![], "land");
    to_block.final_outbound = Some("block".into());
    let manager = GroupManager::new(&[to_node, to_direct, to_block], &nodes(&["b", "land"]));
    assert_eq!(tcp_plan(&manager, "to-node"), [routed("b", &["b", "land"])]);
    // Direct through the exit is the exit itself.
    assert_eq!(tcp_plan(&manager, "to-direct"), [direct("land")]);
    let plan = manager.selection_plan_for_target("to-block", &tcp_context());
    assert_eq!(plan.entries[0].node.protocol(), NodeProtocol::Block);
    assert!(plan.entries[0].route.is_none());
}

#[test]
fn an_exit_group_offers_no_udp_candidates() {
    let mut parent = make_group("parent", GroupPolicy::LoadBalance, vec![nid("b")]);
    parent.groups = vec!["g".into()];
    for policy in [GroupPolicy::Selector, GroupPolicy::Fallback] {
        let child = Group {
            policy,
            ..exit_group("g", vec![nid("a")], "land")
        };
        let groups = [parent.clone(), child];
        let nodes = nodes(&["a", "b", "land"]);
        let manager = GroupManager::with_alive_set(
            &groups,
            &nodes,
            (groups[1].policy == GroupPolicy::Fallback).then(|| Arc::new(AliveDialerSet::new())),
        );
        for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            let udp =
                ScoreSelectionContext::aggregate(SelectionNetwork::Udp, domain, IpVersion::V4);
            assert!(
                manager
                    .selection_plan_for_target("g", &udp)
                    .entries
                    .is_empty()
            );
            assert!(
                manager
                    .peek_selection_plan_for_domain("g", domain, IpVersion::V4)
                    .nodes
                    .is_empty()
            );
            assert_eq!(
                parent_picks(&manager, domain),
                vec![vec!["b".to_owned()]; 4]
            );
        }
        assert!(manager.ranked_udp_leaves("g", IpVersion::V4, 4).is_empty());
        let ranked: Vec<_> = manager
            .ranked_udp_leaves("parent", IpVersion::V4, 4)
            .iter()
            .map(|node| node.id)
            .collect();
        assert_eq!(ranked, [nid("b")]);
    }
}

#[test]
fn an_exit_allows_selected_block_without_allowing_a_udp_proxy() {
    let block = honk_config::Config::builtin_block_node();
    let mut nodes = nodes(&["a", "land"]);
    nodes.push(block.clone());
    let mut group = exit_group("g", vec![nid("a"), block.id], "land");
    group.policy = GroupPolicy::Fallback;
    let manager = GroupManager::new(&[group], &nodes);
    manager
        .publish_override(
            "g",
            &crate::group::SelectorMember::Node(nid("a")),
            crate::group::SelectorNetworks::Udp,
        )
        .unwrap()
        .run_callbacks();
    assert!(
        manager
            .select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4)
            .is_none()
    );
    assert_eq!(
        manager.routed_group_available("g", ProbeDomain::DataUdp, IpVersion::V4),
        Some(false),
    );
    manager
        .publish_override(
            "g",
            &crate::group::SelectorMember::Node(block.id),
            crate::group::SelectorNetworks::Udp,
        )
        .unwrap()
        .run_callbacks();
    assert_eq!(
        manager
            .select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4)
            .map(|node| node.id),
        Some(block.id),
    );
    assert_eq!(
        manager.routed_group_available("g", ProbeDomain::DataUdp, IpVersion::V4),
        Some(true),
    );
}

#[test]
fn routed_score_preflight_obeys_custom_health_without_spending() {
    let alive = Arc::new(AliveDialerSet::new());
    let url = "http://health.example/check";
    let group = Group {
        policy: GroupPolicy::Score,
        check_url: Some(url.into()),
        ..exit_group("score", vec![nid("a"), nid("b")], "land")
    };
    let manager =
        GroupManager::with_alive_set(&[group], &nodes(&["a", "b", "land"]), Some(alive.clone()));
    let eligible = || manager.routed_group_available("score", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(eligible(), Some(true));
    for tag in ["a", "b"] {
        for _ in 0..3 {
            alive.record_url_probe_failure(tag, url);
        }
    }
    assert_eq!(eligible(), Some(false));
    for _ in 0..2 {
        alive.record_url_probe_success("a", url, Duration::from_millis(1));
    }
    assert_eq!(eligible(), Some(true));
    assert_eq!(
        manager.score_budget_counters("score", SelectionNetwork::Tcp),
        Default::default(),
    );
}

#[test]
fn an_unresolved_exit_offers_no_candidates() {
    let manager = GroupManager::new(
        &[exit_group("g", vec![nid("a")], "missing")],
        &nodes(&["a"]),
    );
    assert!(tcp_plan(&manager, "g").is_empty());
}

#[test]
fn url_test_and_fallback_groups_route_through_their_exit() {
    for policy in [GroupPolicy::URLTest, GroupPolicy::Fallback] {
        let group = Group {
            exit: Some("land".into()),
            ..make_group("g", policy, vec![nid("a"), nid("b")])
        };
        let manager = GroupManager::new(&[group], &nodes(&["a", "b", "land"]));
        let plan = tcp_plan(&manager, "g");
        assert!(!plan.is_empty(), "{policy:?}");
        for (leaf, hops) in plan {
            assert_eq!(hops.unwrap(), [leaf, "land".to_owned()], "{policy:?}");
        }
    }
}

#[test]
fn urltest_retry_caps_distinct_executable_routes_after_composition() {
    let group = Group {
        exit: Some("far".into()),
        ..make_subgroup(
            "g",
            GroupPolicy::URLTest,
            &["invalid", "first", "duplicate", "second", "third", "fourth"],
        )
    };
    let groups = [
        group,
        exit_group("invalid", vec![nid("a")], "missing"),
        exit_group("first", vec![nid("a")], "near"),
        exit_group("duplicate", vec![nid("a")], "near"),
        exit_group("second", vec![nid("a")], "far"),
        exit_group("third", vec![nid("b")], "far"),
        exit_group("fourth", vec![nid("c")], "far"),
    ];
    let manager = GroupManager::new(&groups, &nodes(&["a", "b", "c", "near", "far"]));
    let plan = manager.urltest_retry_plan_for_target("g", &tcp_context(), None);
    let expected = [
        ("first", &["a", "near", "far"][..]),
        ("second", &["a", "far"][..]),
        ("third", &["b", "far"][..]),
    ];
    assert_eq!(plan.entries.len(), expected.len());
    for (entry, (via, hops)) in plan.entries.iter().zip(expected) {
        assert_eq!(entry.selection_chain, ["g", via, hops[0]]);
        assert_eq!(entry.node.id, nid(hops[0]));
        let route = entry.route.as_deref().unwrap();
        let expected_hops: Vec<_> = hops.iter().map(|hop| nid(hop)).collect();
        assert_eq!(route.hops(), expected_hops);
    }
}

#[test]
fn readonly_score_udp_excludes_exits_without_spending_selection_state() {
    let routed_score = Group {
        policy: GroupPolicy::Score,
        ..exit_group("routed", vec![nid("a")], "land")
    };
    let round = make_group("round", GroupPolicy::LoadBalance, vec![nid("b"), nid("c")]);
    let parent = make_subgroup("parent", GroupPolicy::Score, &["routed", "round"]);
    let terminal = Group {
        final_outbound: Some("block".into()),
        ..make_subgroup("terminal", GroupPolicy::Score, &["routed"])
    };
    let manager = GroupManager::new(
        &[routed_score, round, parent, terminal],
        &nodes(&["a", "b", "c", "land"]),
    );
    let udp = SelectionNetwork::Udp;
    let budget = manager.score_budget_counters("parent", udp);
    let counters = manager.score_verification_counters("parent", udp);
    assert!(
        manager
            .score_verification_for_network("routed", udp)
            .is_none()
    );
    assert_eq!(manager.get_score_selection_for_network("routed", udp), None);
    assert!(
        manager
            .score_verification_for_network("routed", SelectionNetwork::Tcp)
            .is_some()
    );
    let (selected, snapshot) = manager
        .score_verification_for_network("parent", udp)
        .unwrap();
    assert_eq!((selected.as_str(), snapshot.candidate_count), ("round", 1));
    assert_eq!(
        manager
            .get_score_selection_for_network("parent", udp)
            .as_deref(),
        Some("round")
    );
    assert_eq!(manager.score_budget_counters("parent", udp), budget);
    assert_eq!(manager.score_verification_counters("parent", udp), counters);
    assert_eq!(
        manager.lb_counters["round"][udp.slot()].load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    let context = ScoreSelectionContext::aggregate(udp, ProbeDomain::DataUdp, IpVersion::V4);
    let parent = manager.selection_plan_for_target("parent", &context);
    assert_eq!(parent.entries[0].node.id, nid("b"));
    assert!(
        manager
            .score_verification_for_network("terminal", udp)
            .is_none()
    );
    assert_eq!(
        manager
            .get_score_selection_for_network("terminal", udp)
            .as_deref(),
        Some("block")
    );
    let terminal = manager.selection_plan_for_target("terminal", &context);
    assert_eq!(terminal.entries[0].node.protocol(), NodeProtocol::Block);
    assert!(terminal.entries[0].route.is_none());
}

#[test]
fn a_dead_exit_makes_the_group_fall_back_to_its_final() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut group = exit_group("g", vec![nid("a"), nid("b")], "land");
    group.final_outbound = Some("block".into());
    let manager = GroupManager::with_alive_set(
        &[group],
        &nodes(&["a", "b", "land"]),
        Some(Arc::clone(&alive)),
    );
    alive.report_unavailable_forced(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(tcp_plan(&manager, "g"), [direct("block")]);
    // Registering keeps the state reported before it.
    alive.register_node(nid("land"), "land".into(), Some("192.0.2.1:443".into()));
    assert_eq!(tcp_plan(&manager, "g"), [direct("block")]);
    alive.report_available_traffic(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(tcp_plan(&manager, "g"), [routed("a", &["a", "land"])]);
}

/// A `final` goes through the exit, so a dead exit drops it too, `block`
/// excepted, also in a root group that no parent filters.
#[test]
fn a_dead_exit_drops_a_final_through_it() {
    let alive = Arc::new(AliveDialerSet::new());
    let with_final = |name: &str, final_outbound: &str| Group {
        final_outbound: Some(final_outbound.into()),
        ..exit_group(name, vec![], "land")
    };
    let manager = GroupManager::with_alive_set(
        &[
            with_final("to-node", "f"),
            with_final("to-group", "fg"),
            with_final("to-direct", "direct"),
            make_group("fg", GroupPolicy::Selector, vec![nid("f")]),
        ],
        &nodes(&["f", "land"]),
        Some(Arc::clone(&alive)),
    );
    let plans = || ["to-node", "to-group", "to-direct"].map(|group| tcp_plan(&manager, group));
    alive.register_node(nid("land"), "land".into(), Some("192.0.2.1:443".into()));
    alive.report_available_traffic(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        plans(),
        [
            vec![routed("f", &["f", "land"])],
            vec![routed("f", &["f", "land"])],
            vec![direct("land")],
        ]
    );
    alive.report_unavailable_forced(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(plans(), [vec![], vec![], vec![]]);
}

/// The `final` makes a dead exit visible: without one, the sole leaf is the
/// group's last resort and stays in the plan whatever its exit's state.
#[test]
fn an_unprobed_exit_marked_dead_activates_the_explicit_final() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut group = exit_group("g", vec![nid("a")], "land");
    group.final_outbound = Some("block".into());
    let manager =
        GroupManager::with_alive_set(&[group], &nodes(&["a", "land"]), Some(Arc::clone(&alive)));
    for _ in 0..64 {
        alive.report_unavailable_forced(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
    }
    assert!(!alive.is_registered(nid("land")));
    assert_eq!(tcp_plan(&manager, "g"), [direct("block")]);
}

/// `block` never goes through an exit, so a dead exit keeps a `block` member
/// the selector chose.
#[test]
fn a_dead_exit_keeps_a_block_member() {
    let alive = Arc::new(AliveDialerSet::new());
    let block = honk_config::Config::builtin_block_node();
    let mut nodes = nodes(&["a", "land"]);
    nodes.push(block.clone());
    let manager = GroupManager::with_alive_set(
        &[exit_group("g", vec![block.id, nid("a")], "land")],
        &nodes,
        Some(Arc::clone(&alive)),
    );
    alive.register_node(nid("land"), "land".into(), Some("192.0.2.1:443".into()));
    alive.report_unavailable_forced(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(tcp_plan(&manager, "g"), [direct("block")]);
}

/// A root group's sole TCP leaf with no `final` stays its last resort and is
/// dialed through its exit even while a probe holds that exit dead.
#[test]
fn a_root_sole_leaf_stays_its_last_resort_through_a_dead_exit() {
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(
        &[exit_group("g", vec![nid("a")], "land")],
        &nodes(&["a", "land"]),
        Some(Arc::clone(&alive)),
    );
    alive.register_node(nid("land"), "land".into(), Some("192.0.2.1:443".into()));
    alive.report_unavailable_forced(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
    assert!(!alive.is_alive_for(nid("land"), ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(tcp_plan(&manager, "g"), [routed("a", &["a", "land"])]);
}

#[test]
fn only_the_authorized_root_can_use_a_nested_sole_leaf_with_its_exits() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut root = exit_group("root", vec![], "far");
    root.groups.push("child".into());
    let through_final = Group {
        final_outbound: Some("root".into()),
        ..make_group("via-final", GroupPolicy::Fallback, vec![])
    };
    let manager = GroupManager::with_alive_set(
        &[
            root,
            exit_group("child", vec![nid("a")], "near"),
            through_final,
        ],
        &nodes(&["a", "near", "far"]),
        Some(alive.clone()),
    );
    alive.report_unavailable_forced(nid("near"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        tcp_plan(&manager, "root"),
        [routed("a", &["a", "near", "far"])]
    );
    assert_eq!(tcp_plan(&manager, "child"), [routed("a", &["a", "near"])]);
    assert!(tcp_plan(&manager, "via-final").is_empty());
    assert_eq!(
        manager.routed_group_available("via-final", ProbeDomain::Tcp, IpVersion::V4),
        Some(false),
    );
    for other_has_exit in [false, true] {
        let mut groups = vec![
            make_group("plain-child", GroupPolicy::Fallback, vec![nid("a")]),
            Group {
                final_outbound: Some("plain-child".into()),
                ..make_group("plain-root", GroupPolicy::Fallback, vec![])
            },
        ];
        if other_has_exit {
            groups.push(exit_group("other", vec![nid("a")], "far"));
        }
        let gm =
            GroupManager::with_alive_set(&groups, &nodes(&["a", "far"]), Some(Arc::clone(&alive)));
        alive.report_unavailable_forced(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
        assert_eq!(
            tcp_plan(&gm, "plain-root"),
            [direct("a")],
            "unrelated exit present: {other_has_exit}"
        );
    }
}

#[test]
fn a_leaf_or_hop_equal_to_the_exit_is_entered_once() {
    let all = bound_nodes(&["a", "land"], "via", &["a", "land"]);
    let [via, land] = ["via", "land"].map(|name| node_id(&all, name));
    let manager = GroupManager::new(
        &[
            exit_group("to-exit", vec![land], "land"),
            exit_group("to-via", vec![via], "land"),
        ],
        &all,
    );
    assert_eq!(tcp_plan(&manager, "to-exit"), [direct("land")]);
    assert_eq!(
        tcp_plan(&manager, "to-via"),
        [routed("via", &["a", "land"])]
    );
    // The chain leaf proves its own hops; the exit it ends at takes the latency.
    let target = owned_tcp_target(&manager, "to-via").key();
    assert_eq!(target.proven().collect::<Vec<_>>(), [via]);
    assert_eq!(target.success_owner(), land);
}

#[test]
fn routes_over_the_same_hops_from_different_leaves_stay_apart() {
    let all = bound_nodes(&["a", "b", "land"], "via", &["a", "b"]);
    let [a, via] = ["a", "via"].map(|name| node_id(&all, name));
    let mut outer = exit_group("outer", vec![], "land");
    outer.groups = vec!["inner".into()];
    let manager = GroupManager::new(
        &[
            exit_group("inner", vec![a], "b"),
            outer,
            exit_group("chained", vec![via], "land"),
        ],
        &all,
    );
    let route = |group| {
        *manager
            .selection_plan_for_target(group, &tcp_context())
            .entries[0]
            .route
            .clone()
            .unwrap()
    };
    let (nested, chained) = (route("outer"), route("chained"));
    assert_eq!(nested.hops(), chained.hops());
    assert_ne!(nested, chained);
    assert_eq!((nested.leaf(), chained.leaf()), (a, via));
}

#[test]
fn exit_reach_follows_selection() {
    let parent = Group {
        groups: vec!["exit".into()],
        ..make_group("parent", GroupPolicy::Selector, vec![])
    };
    let mut all = bound_nodes(&["a", "b", "land"], "resolved-chain", &["a", "b"]);
    // Existing hop names alone do not bind a manually supplied chain.
    all.push(Node {
        id: nid("unresolved-chain"),
        ..chain_node("unresolved-chain", &["a", "b"])
    });
    let a = node_id(&all, "a");
    let with_final = |name: &str, final_outbound: &str| Group {
        final_outbound: Some(final_outbound.into()),
        ..make_group(name, GroupPolicy::Selector, vec![a])
    };
    // g0 reaches g8 at depth 8, which selection does not enter; g1 does.
    let depth: Vec<Group> = (0..=8)
        .map(|level| match level {
            8 => exit_group("g8", vec![a], "land"),
            _ => Group {
                groups: vec![format!("g{}", level + 1)],
                ..make_group(&format!("g{level}"), GroupPolicy::Selector, vec![])
            },
        })
        .collect();
    let mut groups = vec![
        make_group("plain", GroupPolicy::Selector, vec![a]),
        exit_group("exit", vec![a], "land"),
        parent,
        with_final("to-exit", "exit"),
        with_final("to-node", "b"),
        with_final("to-direct", "direct"),
        make_group(
            "resolved",
            GroupPolicy::Selector,
            vec![node_id(&all, "resolved-chain")],
        ),
        make_group(
            "unresolved",
            GroupPolicy::Selector,
            vec![nid("unresolved-chain")],
        ),
        exit_group("unresolved-exit", vec![a], "missing"),
        exit_group("shadowed", vec![a], "land"),
        make_group("shadowed", GroupPolicy::Selector, vec![a]),
    ];
    groups.extend(depth);
    let manager = GroupManager::new(&groups, &all);
    for (group, routes) in [
        ("plain", false),
        ("parent", true),
        ("to-exit", true),
        ("to-node", false),
        ("to-direct", false),
        ("resolved", false),
        ("unresolved", true),
        ("unresolved-exit", true),
        ("shadowed", false),
        ("g0", false),
        ("g1", true),
    ] {
        assert_eq!(manager.groups[group].routes, routes, "{group}");
    }
    assert_eq!(tcp_plan(&manager, "resolved"), [direct("resolved-chain")]);
    assert!(tcp_plan(&manager, "unresolved").is_empty());
}

/// The manager selects through the last of two namesake groups, so the
/// first one's exit must not route a chain leaf the second one selects.
#[test]
fn a_shadowed_group_exit_routes_nothing() {
    let all = bound_nodes(&["a", "b", "land"], "c", &["a", "b"]);
    let c = node_id(&all, "c");
    let manager = GroupManager::new(
        &[
            exit_group("g", vec![c], "land"),
            make_group("g", GroupPolicy::Selector, vec![c]),
        ],
        &all,
    );
    assert!(!manager.groups["g"].routes);
    assert_eq!(tcp_plan(&manager, "g"), [direct("c")]);
    assert_eq!(manager.group_exit("g"), None);
}

/// `hk` has no exit and reaches one only through its `final`.
#[test]
fn a_final_into_an_exit_group_routes_a_dead_member() {
    let alive = Arc::new(AliveDialerSet::new());
    let hk = Group {
        final_outbound: Some("proxy".into()),
        ..make_group("hk", GroupPolicy::Selector, vec![nid("a")])
    };
    let manager = GroupManager::with_alive_set(
        &[hk, exit_group("proxy", vec![nid("b")], "land")],
        &nodes(&["a", "b", "land"]),
        Some(Arc::clone(&alive)),
    );
    alive.register_node(nid("a"), "a".into(), Some("192.0.2.1:443".into()));
    alive.report_unavailable_forced(nid("a"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(tcp_plan(&manager, "hk"), [routed("b", &["b", "land"])]);
}

/// `parent` balances its own `h` against `children[0]`, behind exit `land`.
fn balanced_parent(children: Vec<Group>) -> (Arc<AliveDialerSet>, GroupManager) {
    let alive = Arc::new(AliveDialerSet::new());
    let mut parent = make_group("parent", GroupPolicy::LoadBalance, vec![nid("h")]);
    parent.groups = vec![children[0].name.clone()];
    let mut groups = vec![parent];
    groups.extend(children);
    let manager = GroupManager::with_alive_set(
        &groups,
        &nodes(&["a", "h", "f", "land"]),
        Some(Arc::clone(&alive)),
    );
    (alive, manager)
}

fn parent_picks(manager: &GroupManager, domain: ProbeDomain) -> Vec<Vec<String>> {
    let context = ScoreSelectionContext::aggregate(
        SelectionNetwork::from_probe_domain(domain),
        domain,
        IpVersion::V4,
    );
    (0..4)
        .map(|_| {
            manager
                .selection_plan_for_target("parent", &context)
                .entries
                .iter()
                .map(|entry| entry.node.name.clone())
                .collect()
        })
        .collect()
}

#[test]
fn a_parent_never_picks_a_route_through_a_dead_exit_over_a_healthy_sibling() {
    let behind_exit = |final_outbound: Option<&str>| Group {
        exit: Some("land".into()),
        final_outbound: final_outbound.map(Into::into),
        ..make_group("g", GroupPolicy::Fallback, vec![nid("a")])
    };
    let final_group = make_group("fg", GroupPolicy::Fallback, vec![nid("f")]);
    for (case, children) in [
        ("final node", vec![behind_exit(Some("f"))]),
        ("final group", vec![behind_exit(Some("fg")), final_group]),
        ("sole leaf", vec![behind_exit(None)]),
    ] {
        let (alive, manager) = balanced_parent(children);
        alive.register_node(nid("land"), "land".into(), Some("192.0.2.1:443".into()));
        alive.report_unavailable_forced(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
        assert_eq!(
            parent_picks(&manager, ProbeDomain::Tcp),
            vec![vec!["h".to_owned()]; 4],
            "{case}"
        );
    }
}

fn owned_tcp_target(manager: &GroupManager, group: &str) -> OwnedTarget {
    let plan = manager.selection_plan_for_target(group, &tcp_context());
    let entry = plan.entries.into_iter().next().unwrap();
    manager.own_target(Target {
        node: entry.node,
        route: entry.route,
    })
}

fn hop_failure(hop: usize, node: uuid::Uuid, error: anyhow::Error) -> anyhow::Error {
    crate::proxy::ChainHopFailure { hop, node, error }.into()
}

/// `chain` = [a, b] behind `inner` (exit near) behind `outer` (exit land).
fn chain_behind_two_exits() -> GroupManager {
    let all = bound_nodes(&["a", "b", "near", "land"], "chain", &["a", "b"]);
    let mut outer = exit_group("outer", vec![], "land");
    outer.groups = vec!["inner".into()];
    GroupManager::new(
        &[
            outer,
            exit_group("inner", vec![node_id(&all, "chain")], "near"),
        ],
        &all,
    )
}

#[test]
fn a_route_charges_each_hop_to_its_chain_or_exit() {
    let manager = chain_behind_two_exits();
    let target = owned_tcp_target(&manager, "outer");
    assert_eq!(
        target.route.as_deref().unwrap().hop_names[..],
        ["a", "b", "near", "land"]
    );
    for (hop, node, owner) in [
        (0, "a", "chain"),
        (1, "b", "chain"),
        (2, "near", "near"),
        (3, "land", "land"),
    ] {
        let id = manager.node_by_name(node).unwrap().id;
        let cause = crate::proxy::NodeFailure(anyhow::anyhow!("failed carrier"));
        assert_eq!(
            target.failure_owner(&hop_failure(hop, id, cause.into())),
            Some(manager.node_by_name(owner).unwrap().id),
            "hop {hop}"
        );
    }
}

#[test]
fn a_later_hop_locator_alone_cannot_charge_a_node() {
    let manager = chain_behind_two_exits();
    let target = owned_tcp_target(&manager, "outer");
    let near = manager.node_by_name("near").unwrap().id;
    let error = hop_failure(2, near, anyhow::anyhow!("unlocalized failure"));
    assert_eq!(target.failure_owner(&error), None);
}

#[test]
fn a_final_target_refusal_cannot_charge_the_exit() {
    let manager = chain_behind_two_exits();
    let target = owned_tcp_target(&manager, "outer");
    let land = manager.node_by_name("land").unwrap().id;
    let cause = crate::proxy::TargetFailure(anyhow::anyhow!("target refused"));
    let error = hop_failure(3, land, cause.into());
    assert_eq!(target.failure_owner(&error), None);
}

#[test]
fn a_chain_deadline_charges_no_hop() {
    let manager = chain_behind_two_exits();
    let target = owned_tcp_target(&manager, "outer");
    let deadline = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "proxy chain setup timeout",
    ));
    assert_eq!(target.failure_owner(&deadline), None);
    // Outside a route, a configured chain answers for itself as before.
    let chain = manager.node_by_name("chain").unwrap();
    let target = OwnedTarget::node(chain.clone());
    assert_eq!(target.failure_owner(&deadline), Some(chain.id));
}

#[test]
fn route_latency_counts_against_the_last_exit_only() {
    let manager = chain_behind_two_exits();
    let target = owned_tcp_target(&manager, "outer").key();
    let id = |name| manager.node_by_name(name).unwrap().id;
    assert_eq!(target.success_owner(), id("land"));
    assert_eq!(
        target.proven().collect::<Vec<_>>(),
        [id("chain"), id("near")]
    );
    let manager = GroupManager::new(
        &[exit_group("g", vec![nid("a")], "land")],
        &nodes(&["a", "land"]),
    );
    let plain = owned_tcp_target(&manager, "g").key();
    assert_eq!(plain.success_owner(), nid("land"));
    assert_eq!(plain.proven().collect::<Vec<_>>(), [nid("a")]);
}

#[test]
fn a_one_hop_route_reports_health_on_the_exit() {
    let mut to_direct = exit_group("to-direct", vec![], "land");
    to_direct.final_outbound = Some("direct".into());
    let manager = GroupManager::new(
        &[to_direct, exit_group("to-exit", vec![nid("land")], "land")],
        &nodes(&["land"]),
    );
    for group in ["to-direct", "to-exit"] {
        let target = owned_tcp_target(&manager, group);
        assert!(target.route.is_none(), "{group}");
        assert_eq!(target.node.id, nid("land"), "{group}");
        let key = target.key();
        assert_eq!(key.success_owner(), nid("land"), "{group}");
        assert_eq!(key.proven().count(), 0, "{group}");
        assert_eq!(
            target.failure_owner(&anyhow::anyhow!("refused")),
            Some(nid("land")),
            "{group}"
        );
    }
}

#[cfg(feature = "rprx")]
const TARGET_ALLOCATION_CHILD: &str = "HONK_GROUP_TARGET_ALLOCATION_CHILD";

/// An unrelated exit adds no allocations to target-aware plans for groups
/// that cannot reach it. The `rprx` encryption tests install the counting allocator.
#[cfg(feature = "rprx")]
#[test]
fn unrelated_exits_do_not_add_allocations_to_plain_dial_plans() {
    if std::env::var_os(TARGET_ALLOCATION_CHILD).is_some() {
        use stats_alloc::{INSTRUMENTED_SYSTEM, Region};

        let ids = vec![nid("a"), nid("b"), nid("c")];
        let mut nested = make_group("nested", GroupPolicy::Selector, vec![nid("a")]);
        nested.groups = vec!["load-balance".into()];
        let groups = [
            make_group("selector", GroupPolicy::Selector, ids.clone()),
            make_group("load-balance", GroupPolicy::LoadBalance, ids.clone()),
            make_group("fallback", GroupPolicy::Fallback, ids.clone()),
            make_group("url-test", GroupPolicy::URLTest, ids.clone()),
            make_group("score", GroupPolicy::Score, ids),
            nested,
        ];
        let mixed: Vec<_> = groups
            .iter()
            .cloned()
            .chain([exit_group("exit", vec![nid("a")], "land")])
            .collect();
        let plain = GroupManager::new(&groups, &nodes(&["a", "b", "c"]));
        let mixed = GroupManager::new(&mixed, &nodes(&["a", "b", "c", "land"]));
        let context = tcp_context();
        for group in &groups {
            let measure = |manager: &GroupManager| {
                let region = Region::new(&INSTRUMENTED_SYSTEM);
                let (plan, _) = manager.dial_plan_for_target(&group.name, &context, None);
                let stats = region.change();
                assert!(!plan.entries.is_empty());
                assert!(plan.entries.iter().all(|entry| entry.route.is_none()));
                (plan.entries.len(), stats.allocations, stats.reallocations)
            };
            let expected = measure(&plain);
            assert_ne!(
                expected.1, 0,
                "counting allocator must record plan allocations"
            );
            assert_eq!(measure(&mixed), expected, "{}", group.name);
        }
        return;
    }
    let output =
        std::process::Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "group::tests::exit::unrelated_exits_do_not_add_allocations_to_plain_dial_plans",
                "--nocapture",
            ])
            .env(TARGET_ALLOCATION_CHILD, "1")
            .output()
            .expect("isolated allocation test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
