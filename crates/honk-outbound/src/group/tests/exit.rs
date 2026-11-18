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
    let mut node = make_node(nid(name), name);
    node.outbound = honk_config::node::OutboundConfig::Chain {
        hops: hops.iter().map(|hop| hop.to_string()).collect(),
    };
    node
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
    assert_eq!(std::mem::size_of::<Target<'_>>(), 16);
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
    // Legacy dialing callers get the same route; leaf-facing callers the leaf.
    let targets = manager.select_targets_in_order_for_domain("g", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(targets[0].key(), DialKey::Route(*route));
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
    let manager = GroupManager::new(&[proxy, hk, us], &nodes(&["a", "b", "land"]));
    manager
        .set_selector_choice("proxy", "hk", SelectorNetworks::Tcp)
        .unwrap();
    assert_eq!(tcp_plan(&manager, "proxy"), [routed("a", &["a", "land"])]);
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
    all.push(chain_node("chain", &["missing"]));
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
        .iter()
        .map(|entry| {
            Target {
                node: entry.node,
                route: entry.route.clone(),
            }
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
    let manager = GroupManager::new(
        &[parent, exit_group("g", vec![nid("a")], "land")],
        &nodes(&["a", "b", "land"]),
    );
    let udp = ScoreSelectionContext::aggregate(
        SelectionNetwork::Udp,
        ProbeDomain::DataUdp,
        IpVersion::V4,
    );
    assert!(
        manager
            .selection_plan_for_target("g", &udp)
            .entries
            .is_empty()
    );
    assert!(manager.ranked_udp_leaves("g", IpVersion::V4, 4).is_empty());
    for _ in 0..2 {
        let parent_udp: Vec<_> = manager
            .selection_plan_for_target("parent", &udp)
            .entries
            .iter()
            .map(|entry| entry.node.id)
            .collect();
        assert_eq!(parent_udp, [nid("b")]);
    }
    let ranked: Vec<_> = manager
        .ranked_udp_leaves("parent", IpVersion::V4, 4)
        .iter()
        .map(|node| node.id)
        .collect();
    assert_eq!(ranked, [nid("b")]);
}

#[test]
fn an_unresolved_exit_offers_no_candidates() {
    let manager = GroupManager::new(
        &[exit_group("g", vec![nid("a")], "missing")],
        &nodes(&["a"]),
    );
    assert!(tcp_plan(&manager, "g").is_empty());
    assert!(
        manager
            .select_targets_in_order_for_domain("g", ProbeDomain::Tcp, IpVersion::V4)
            .is_empty()
    );
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
fn a_url_test_retry_plan_routes_through_the_exit() {
    let group = Group {
        exit: Some("land".into()),
        ..make_group("g", GroupPolicy::URLTest, vec![nid("a"), nid("b")])
    };
    let manager = GroupManager::new(&[group], &nodes(&["a", "b", "land"]));
    let plan = manager.urltest_retry_plan_for_target("g", &tcp_context(), None);
    assert_eq!(plan.entries.len(), 2);
    for entry in &plan.entries {
        let route = entry.route.as_deref().expect("a route through the exit");
        assert_eq!(route.hops(), &[entry.node.id, nid("land")][..]);
    }
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
    // Nothing probes an unregistered exit, so traffic alone cannot hold it dead.
    assert_eq!(tcp_plan(&manager, "g"), [routed("a", &["a", "land"])]);
    // Registering keeps the state reported before it.
    alive.register_node(nid("land"), "land".into(), "192.0.2.1:443".into());
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
    alive.register_node(nid("land"), "land".into(), "192.0.2.1:443".into());
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
fn an_unprobed_exit_marked_dead_stays_selectable() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut group = exit_group("g", vec![nid("a")], "land");
    group.final_outbound = Some("block".into());
    let manager =
        GroupManager::with_alive_set(&[group], &nodes(&["a", "land"]), Some(Arc::clone(&alive)));
    for _ in 0..64 {
        alive.report_unavailable_forced(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
    }
    assert!(!alive.is_registered(nid("land")));
    assert_eq!(tcp_plan(&manager, "g"), [routed("a", &["a", "land"])]);
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
    alive.register_node(nid("land"), "land".into(), "192.0.2.1:443".into());
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
    alive.register_node(nid("land"), "land".into(), "192.0.2.1:443".into());
    alive.report_unavailable_forced(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
    assert!(!alive.is_alive_for(nid("land"), ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(tcp_plan(&manager, "g"), [routed("a", &["a", "land"])]);
}

#[test]
fn a_leaf_or_hop_equal_to_the_exit_is_entered_once() {
    let mut all = nodes(&["a", "land"]);
    all.push(chain_node("via", &["a", "land"]));
    let manager = GroupManager::new(
        &[
            exit_group("to-exit", vec![nid("land")], "land"),
            exit_group("to-via", vec![nid("via")], "land"),
        ],
        &all,
    );
    assert_eq!(tcp_plan(&manager, "to-exit"), [direct("land")]);
    assert_eq!(
        tcp_plan(&manager, "to-via"),
        [routed("via", &["a", "land"])]
    );
    // The chain leaf proves its own hops; the exit it ends at takes the latency.
    let via = owned_tcp_target(&manager, "to-via");
    assert_eq!(via.proven().collect::<Vec<_>>(), [nid("via")]);
    assert_eq!(via.success_owner(), nid("land"));
}

#[test]
fn routes_over_the_same_hops_from_different_leaves_stay_apart() {
    let mut all = nodes(&["a", "b", "land"]);
    all.push(chain_node("via", &["a", "b"]));
    let mut outer = exit_group("outer", vec![], "land");
    outer.groups = vec!["inner".into()];
    let manager = GroupManager::new(
        &[
            exit_group("inner", vec![nid("a")], "b"),
            outer,
            exit_group("chained", vec![nid("via")], "land"),
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
    assert_eq!((nested.leaf(), chained.leaf()), (nid("a"), nid("via")));
}

#[test]
fn exit_reach_follows_selection() {
    let parent = Group {
        groups: vec!["exit".into()],
        ..make_group("parent", GroupPolicy::Selector, vec![])
    };
    let with_final = |name: &str, final_outbound: &str| Group {
        final_outbound: Some(final_outbound.into()),
        ..make_group(name, GroupPolicy::Selector, vec![nid("a")])
    };
    // g0 reaches g8 at depth 8, which selection does not enter; g1 does.
    let depth: Vec<Group> = (0..=8)
        .map(|level| match level {
            8 => exit_group("g8", vec![nid("a")], "land"),
            _ => Group {
                groups: vec![format!("g{}", level + 1)],
                ..make_group(&format!("g{level}"), GroupPolicy::Selector, vec![])
            },
        })
        .collect();
    let mut groups = vec![
        make_group("plain", GroupPolicy::Selector, vec![nid("a")]),
        exit_group("exit", vec![nid("a")], "land"),
        parent,
        with_final("to-exit", "exit"),
        with_final("to-node", "b"),
        with_final("to-direct", "direct"),
        make_group(
            "resolved",
            GroupPolicy::Selector,
            vec![nid("resolved-chain")],
        ),
        make_group(
            "unresolved",
            GroupPolicy::Selector,
            vec![nid("unresolved-chain")],
        ),
        exit_group("unresolved-exit", vec![nid("a")], "missing"),
        exit_group("shadowed", vec![nid("a")], "land"),
        make_group("shadowed", GroupPolicy::Selector, vec![nid("a")]),
    ];
    groups.extend(depth);
    let mut all = nodes(&["a", "b", "land"]);
    all.push(chain_node("resolved-chain", &["a", "b"]));
    all.push(chain_node("unresolved-chain", &["missing"]));
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
}

/// The manager selects through the last of two namesake groups, so the
/// first one's exit must not route a chain leaf the second one selects.
#[test]
fn a_shadowed_group_exit_routes_nothing() {
    let mut all = nodes(&["a", "b", "land"]);
    all.push(chain_node("c", &["a", "b"]));
    let manager = GroupManager::new(
        &[
            exit_group("g", vec![nid("c")], "land"),
            make_group("g", GroupPolicy::Selector, vec![nid("c")]),
        ],
        &all,
    );
    assert!(!manager.groups["g"].routes);
    assert_eq!(tcp_plan(&manager, "g"), [direct("c")]);
    assert_eq!(manager.group_exit("g"), None);
    let targets = manager.select_targets_in_order_for_domain("g", ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(targets.len(), 1);
    assert!(targets[0].route.is_none());
    assert_eq!(targets[0].node.id, nid("c"));
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
    alive.register_node(nid("a"), "a".into(), "192.0.2.1:443".into());
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
fn a_udp_parent_skips_a_child_behind_an_exit_before_its_policy_runs() {
    let child = Group {
        exit: Some("land".into()),
        ..make_group("g", GroupPolicy::Fallback, vec![nid("a")])
    };
    let (_alive, manager) = balanced_parent(vec![child]);
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        assert_eq!(
            parent_picks(&manager, domain),
            vec![vec!["h".to_owned()]; 4],
            "{domain:?}"
        );
    }
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
        alive.register_node(nid("land"), "land".into(), "192.0.2.1:443".into());
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

fn hop_failure(hop: usize, node: uuid::Uuid) -> anyhow::Error {
    crate::proxy::ChainHopFailure {
        hop,
        node,
        error: anyhow::anyhow!("refused"),
    }
    .into()
}

/// `chain` = [a, b] behind `inner` (exit near) behind `outer` (exit land).
fn chain_behind_two_exits() -> GroupManager {
    let mut all = nodes(&["a", "b", "near", "land"]);
    all.push(chain_node("chain", &["a", "b"]));
    let mut outer = exit_group("outer", vec![], "land");
    outer.groups = vec!["inner".into()];
    GroupManager::new(
        &[outer, exit_group("inner", vec![nid("chain")], "near")],
        &all,
    )
}

#[test]
fn a_hop_inside_a_chain_leaf_counts_against_the_chain() {
    let target = owned_tcp_target(&chain_behind_two_exits(), "outer");
    assert_eq!(
        target.route.as_deref().unwrap().hop_names[..],
        ["a", "b", "near", "land"]
    );
    for (hop, node) in [(0, "a"), (1, "b")] {
        assert_eq!(
            target.failure_owner(&hop_failure(hop, nid(node))),
            Some(nid("chain")),
            "hop {hop}"
        );
    }
}

#[test]
fn an_inner_exit_failure_counts_against_that_exit() {
    let target = owned_tcp_target(&chain_behind_two_exits(), "outer");
    for (hop, node) in [(2, "near"), (3, "land")] {
        assert_eq!(
            target.failure_owner(&hop_failure(hop, nid(node))),
            Some(nid(node)),
            "hop {hop}"
        );
    }
}

#[test]
fn a_chain_deadline_charges_no_hop() {
    let target = owned_tcp_target(&chain_behind_two_exits(), "outer");
    let deadline = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "proxy chain setup timeout",
    ));
    assert_eq!(target.failure_owner(&deadline), None);
    // Outside a route, a configured chain answers for itself as before.
    let manager = chain_behind_two_exits();
    let chain = OwnedTarget::node(manager.nodes[&nid("chain")].clone());
    assert_eq!(chain.failure_owner(&deadline), Some(nid("chain")));
}

#[test]
fn route_latency_counts_against_the_last_exit_only() {
    let target = owned_tcp_target(&chain_behind_two_exits(), "outer");
    assert_eq!(target.success_owner(), nid("land"));
    assert_eq!(
        target.proven().collect::<Vec<_>>(),
        [nid("chain"), nid("near")]
    );
    let manager = GroupManager::new(
        &[exit_group("g", vec![nid("a")], "land")],
        &nodes(&["a", "land"]),
    );
    let plain = owned_tcp_target(&manager, "g");
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
        assert_eq!(target.success_owner(), nid("land"), "{group}");
        assert_eq!(target.proven().count(), 0, "{group}");
        assert_eq!(
            target.failure_owner(&anyhow::anyhow!("refused")),
            Some(nid("land")),
            "{group}"
        );
    }
}

const TARGET_ALLOCATION_CHILD: &str = "HONK_GROUP_TARGET_ALLOCATION_CHILD";

/// For a group without an exit on its path, owned dialing targets in order
/// allocate exactly what owning the leaf plan they mirror does, for every
/// policy and the nested path, also beside an unrelated exit group: no
/// borrowed target list is built on the way. Counted by
/// `test_support::ALLOCATOR`.
#[test]
fn in_order_targets_without_exits_allocate_as_owned_leaves() {
    if std::env::var_os(TARGET_ALLOCATION_CHILD).is_some() {
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
        for (manager, config) in [
            (
                GroupManager::new(&groups, &nodes(&["a", "b", "c"])),
                "no exit",
            ),
            (
                GroupManager::new(&mixed, &nodes(&["a", "b", "c", "land"])),
                "mixed",
            ),
        ] {
            allocations_match(&manager, &groups, config);
        }
        return;
    }
    let output =
        std::process::Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "group::tests::exit::in_order_targets_without_exits_allocate_as_owned_leaves",
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

fn allocations_match(manager: &GroupManager, groups: &[Group], config: &str) {
    use stats_alloc::{INSTRUMENTED_SYSTEM, Region};
    for group in groups {
        let name = group.name.as_str();
        let leaves = || {
            manager
                .select_nodes_in_order_for_domain(name, ProbeDomain::Tcp, IpVersion::V4)
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        let targets =
            || manager.select_targets_in_order_for_domain(name, ProbeDomain::Tcp, IpVersion::V4);
        assert_eq!(leaves().len(), targets().len(), "{config}: {name}");
        let region = Region::new(&INSTRUMENTED_SYSTEM);
        drop(leaves());
        let leaves = region.change();
        let region = Region::new(&INSTRUMENTED_SYSTEM);
        drop(targets());
        let targets = region.change();
        assert_ne!(leaves.allocations, 0, "{config}: {name}");
        assert_eq!(
            (targets.allocations, targets.reallocations),
            (leaves.allocations, leaves.reallocations),
            "{config}: {name}"
        );
    }
}

fn trojan(name: &str) -> Node {
    Node {
        outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
        ..make_node(nid(name), name)
    }
}

fn udp_context() -> ScoreSelectionContext {
    ScoreSelectionContext::aggregate(SelectionNetwork::Udp, ProbeDomain::DataUdp, IpVersion::V4)
}

/// Each dialing target of `group`'s UDP plan, as [`tcp_plan`] lists them.
fn udp_plan(manager: &GroupManager, group: &str) -> Vec<(String, Option<Vec<String>>)> {
    manager
        .selection_plan_for_target(group, &udp_context())
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

#[test]
fn an_exit_that_carries_udp_gives_route_udp_candidates() {
    let mut all = nodes(&["a"]);
    all.push(trojan("land"));
    let manager = GroupManager::new(&[exit_group("g", vec![nid("a")], "land")], &all);
    assert_eq!(udp_plan(&manager, "g"), [routed("a", &["a", "land"])]);
    // UDP warm-up keeps skipping exit groups: a route has no state to warm.
    assert!(manager.ranked_udp_leaves("g", IpVersion::V4, 4).is_empty());
}

#[test]
fn a_udp_parent_picks_a_child_behind_an_exit_that_carries_udp() {
    let mut parent = make_group("parent", GroupPolicy::Fallback, vec![]);
    parent.groups = vec!["g".into()];
    let mut all = nodes(&["a"]);
    all.push(trojan("land"));
    let manager = GroupManager::new(&[parent, exit_group("g", vec![nid("a")], "land")], &all);
    assert_eq!(udp_plan(&manager, "parent"), [routed("a", &["a", "land"])]);
    // Warm-up dials leaves as themselves, so it skips the route below.
    assert!(
        manager
            .ranked_udp_leaves("parent", IpVersion::V4, 4)
            .is_empty()
    );
}

/// `final: direct` behind an exit dials the exit itself, so its UDP is the
/// exit's own, not what the exit could carry through a tunnel.
#[test]
fn a_one_hop_route_offers_the_exit_own_udp() {
    let mut group = exit_group("g", vec![], "land");
    group.final_outbound = Some("direct".into());
    let manager = GroupManager::new(&[group], &nodes(&["land"]));
    assert_eq!(udp_plan(&manager, "g"), [direct("land")]);
}

/// A group without an exit under an ancestor whose exit cannot tunnel UDP
/// drops the members whose route lacks it before its own policy picks, so
/// Fallback passes over its first member to the one that carries UDP.
#[test]
fn a_child_under_an_exit_drops_udp_less_members_before_its_policy_picks() {
    let child = make_group("child", GroupPolicy::Fallback, vec![nid("a"), nid("land")]);
    let mut outer = exit_group("outer", vec![], "land");
    outer.groups = vec!["child".into()];
    let manager = GroupManager::new(&[outer, child], &nodes(&["a", "land"]));
    assert_eq!(udp_plan(&manager, "outer"), [direct("land")]);
}

/// A member whose route through the exit has no UDP is dropped before the
/// policy runs, so UDP falls to `final: direct`, the exit's own UDP.
#[test]
fn a_member_route_without_udp_falls_to_the_final() {
    let mut group = exit_group("g", vec![nid("a")], "land");
    group.final_outbound = Some("direct".into());
    let manager = GroupManager::new(&[group], &nodes(&["a", "land"]));
    assert_eq!(udp_plan(&manager, "g"), [direct("land")]);
    assert_eq!(tcp_plan(&manager, "g"), [routed("a", &["a", "land"])]);
}

/// A child whose UDP routes are dropped offers its parent nothing, so the
/// parent's policy picks a sibling instead of losing its pick. An outer
/// group's exit gives the child a UDP route, past the up-front check.
#[test]
fn a_udp_parent_skips_a_child_whose_routes_lack_udp() {
    for final_outbound in [None, Some("c")] {
        let mut child = exit_group("g", vec![nid("a")], "land");
        child.final_outbound = final_outbound.map(Into::into);
        let mut outer = exit_group("outer", vec![], "tunnel");
        outer.groups = vec!["g".into()];
        let mut parent = make_group("parent", GroupPolicy::Fallback, vec![]);
        parent.groups = vec!["g".into(), "h".into()];
        let mut all = nodes(&["a", "b", "c", "land"]);
        all.push(trojan("tunnel"));
        let manager = GroupManager::new(
            &[
                parent,
                outer,
                child,
                make_group("h", GroupPolicy::Selector, vec![nid("b")]),
            ],
            &all,
        );
        assert_eq!(
            udp_plan(&manager, "outer")[0],
            routed("a", &["a", "land", "tunnel"])
        );
        assert_eq!(
            udp_plan(&manager, "parent"),
            [direct("b")],
            "{final_outbound:?}"
        );
    }
}

#[test]
fn a_final_back_to_an_exit_ancestor_keeps_its_udp_routes() {
    let mut proxy = exit_group("proxy", vec![], "land");
    proxy.groups = vec!["hk".into()];
    let mut hk = make_group("hk", GroupPolicy::Selector, vec![nid("a")]);
    hk.final_outbound = Some("proxy".into());
    let mut all = nodes(&["a"]);
    all.push(trojan("land"));
    let manager = GroupManager::new(&[proxy, hk], &all);
    assert_eq!(udp_plan(&manager, "proxy"), [routed("a", &["a", "land"])]);
}

/// The datapath reads the leaf's UDP liveness, so a route needs it although
/// the leaf carries only the stream.
#[test]
fn a_route_needs_the_leaf_udp_alive() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut all = nodes(&["a"]);
    all.push(trojan("land"));
    let manager = GroupManager::with_alive_set(
        &[exit_group("g", vec![nid("a")], "land")],
        &all,
        Some(Arc::clone(&alive)),
    );
    assert_eq!(udp_plan(&manager, "g"), [routed("a", &["a", "land"])]);
    alive.report_unavailable_forced(nid("a"), ProbeDomain::DataUdp, IpVersion::V4);
    alive.report_unavailable_forced(nid("a"), ProbeDomain::DnsUdp, IpVersion::V4);
    assert!(udp_plan(&manager, "g").is_empty());
}

/// A dead exit sends UDP to `final`, judged by its UDP state when it has one
/// and by its TCP state otherwise.
#[test]
fn a_dead_exit_sends_udp_to_the_final() {
    for udp_state in [false, true] {
        let alive = Arc::new(AliveDialerSet::new());
        let mut group = exit_group("g", vec![nid("a")], "land");
        group.final_outbound = Some("block".into());
        let mut all = nodes(&["a"]);
        all.push(trojan("land"));
        let manager = GroupManager::with_alive_set(&[group], &all, Some(Arc::clone(&alive)));
        alive.register_node(nid("land"), "land".into(), "192.0.2.1:443".into());
        assert_eq!(udp_plan(&manager, "g"), [routed("a", &["a", "land"])]);
        if udp_state {
            alive.report_unavailable_forced(nid("land"), ProbeDomain::DataUdp, IpVersion::V4);
            alive.report_unavailable_forced(nid("land"), ProbeDomain::DnsUdp, IpVersion::V4);
        } else {
            alive.report_unavailable_forced(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
        }
        assert_eq!(udp_plan(&manager, "g"), [direct("block")], "{udp_state}");
    }
}

/// A dead exit drops a `final` that goes through it from a UDP plan as from
/// a TCP one; only `block` stays.
#[test]
fn a_dead_exit_drops_a_udp_final_through_it() {
    let alive = Arc::new(AliveDialerSet::new());
    let with_final = |name: &str, final_outbound: &str| Group {
        final_outbound: Some(final_outbound.into()),
        ..exit_group(name, vec![], "land")
    };
    let mut all = nodes(&["f"]);
    all.push(trojan("land"));
    let manager = GroupManager::with_alive_set(
        &[
            with_final("to-node", "f"),
            with_final("to-group", "fg"),
            with_final("to-direct", "direct"),
            with_final("to-block", "block"),
            make_group("fg", GroupPolicy::Selector, vec![nid("f")]),
        ],
        &all,
        Some(Arc::clone(&alive)),
    );
    let plans =
        || ["to-node", "to-group", "to-direct", "to-block"].map(|group| udp_plan(&manager, group));
    alive.register_node(nid("land"), "land".into(), "192.0.2.1:443".into());
    alive.report_available_traffic(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        plans(),
        [
            vec![routed("f", &["f", "land"])],
            vec![routed("f", &["f", "land"])],
            vec![direct("land")],
            vec![direct("block")],
        ]
    );
    alive.report_unavailable_forced(nid("land"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(plans(), [vec![], vec![], vec![], vec![direct("block")]]);
}

fn vmess(name: &str) -> Node {
    Node {
        outbound: honk_config::node::OutboundConfig::Vmess(Default::default()),
        ..make_node(nid(name), name)
    }
}

/// A leaf whose own protocol has no UDP carries the stream to an exit that
/// tunnels UDP, so it is a UDP candidate there, as a member, a `final`, or a
/// target checked before its flow binds; without the exit it is none.
#[test]
fn a_tcp_only_leaf_carries_udp_through_an_exit_that_tunnels_it() {
    let alive = Arc::new(AliveDialerSet::new());
    let all = [vmess("m"), trojan("land")];
    let mut final_only = exit_group("final-only", vec![], "land");
    final_only.final_outbound = Some("m".into());
    let mut plain_final = make_group("plain-final", GroupPolicy::Selector, vec![]);
    plain_final.final_outbound = Some("m".into());
    let manager = GroupManager::with_alive_set(
        &[
            exit_group("member", vec![nid("m")], "land"),
            final_only,
            make_group("plain", GroupPolicy::Selector, vec![nid("m")]),
            plain_final,
        ],
        &all,
        Some(Arc::clone(&alive)),
    );
    alive.register_node(nid("m"), "m".into(), "192.0.2.2:443".into());
    alive.report_available_traffic(nid("m"), ProbeDomain::Tcp, IpVersion::V4);
    for group in ["member", "final-only"] {
        assert_eq!(
            udp_plan(&manager, group),
            [routed("m", &["m", "land"])],
            "{group}"
        );
    }
    for group in ["plain", "plain-final"] {
        assert!(udp_plan(&manager, group).is_empty(), "{group}");
    }
    let target = |group: &str| {
        let plan = manager.selection_plan_for_target(group, &tcp_context());
        let entry = plan.entries.into_iter().next().unwrap();
        manager.own_target(Target {
            node: entry.node,
            route: entry.route,
        })
    };
    let selectable = |group: &str| {
        manager.target_selectable(&target(group), ProbeDomain::DataUdp, IpVersion::V4)
    };
    assert!(selectable("member"));
    assert!(!selectable("plain"));
    // Health stays on the leaf.
    alive.report_unavailable_forced(nid("m"), ProbeDomain::Tcp, IpVersion::V4);
    assert!(udp_plan(&manager, "member").is_empty());
    assert!(!selectable("member"));
}

/// Beside routes, a leaf without UDP of its own is still dropped where its
/// path crosses no exit: in a group none of whose paths do, before that
/// group's policy picks, and among a parent's own members.
#[test]
fn a_udp_less_leaf_beside_routes_is_dropped() {
    let mut all = nodes(&["a", "b"]);
    all.extend([vmess("m"), trojan("land")]);
    let mut root = make_group("root", GroupPolicy::Fallback, vec![nid("m")]);
    root.groups = vec!["plain".into(), "routed".into()];
    let manager = GroupManager::new(
        &[
            root,
            make_group("plain", GroupPolicy::Fallback, vec![nid("m"), nid("a")]),
            exit_group("routed", vec![nid("b")], "land"),
        ],
        &all,
    );
    let plan = udp_plan(&manager, "root");
    assert!(plan.iter().all(|(node, _)| node != "m"), "{plan:?}");
    assert_eq!(plan.first(), Some(&direct("a")), "{plan:?}");
}

/// An exit before the outermost carries only the stream, so UDP needs its
/// health, not its own UDP.
#[test]
fn an_inner_exit_needs_only_the_stream_for_udp() {
    let alive = Arc::new(AliveDialerSet::new());
    let mut outer = exit_group("outer", vec![], "land");
    outer.groups = vec!["inner".into()];
    let mut all = nodes(&["a"]);
    all.extend([vmess("mid"), trojan("land")]);
    let manager = GroupManager::with_alive_set(
        &[outer, exit_group("inner", vec![nid("a")], "mid")],
        &all,
        Some(Arc::clone(&alive)),
    );
    alive.register_node(nid("mid"), "mid".into(), "192.0.2.3:443".into());
    alive.report_available_traffic(nid("mid"), ProbeDomain::Tcp, IpVersion::V4);
    assert_eq!(
        udp_plan(&manager, "outer"),
        [routed("a", &["a", "mid", "land"])]
    );
    alive.report_unavailable_forced(nid("mid"), ProbeDomain::Tcp, IpVersion::V4);
    assert!(udp_plan(&manager, "outer").is_empty());
}

/// An exit that neither tunnels UDP nor can be the one node a route
/// collapses to offers no UDP before any candidate is built.
#[test]
fn an_exit_without_udp_for_its_members_offers_none_up_front() {
    let mut all = nodes(&["a", "b"]);
    all.push(Node {
        outbound: honk_config::node::OutboundConfig::Socks5(Default::default()),
        ..make_node(nid("socks"), "socks")
    });
    let manager = GroupManager::new(&[exit_group("g", vec![nid("a"), nid("b")], "socks")], &all);
    let group = &manager.groups.get("g").unwrap().group;
    assert!(!manager.exit_offers_udp(group, &[]));
    assert!(udp_plan(&manager, "g").is_empty());
    let with_exit_member = Group {
        exit: Some("socks".into()),
        ..make_group("h", GroupPolicy::Fallback, vec![nid("a"), nid("socks")])
    };
    let manager = GroupManager::new(&[with_exit_member], &all);
    let group = &manager.groups.get("h").unwrap().group;
    assert!(manager.exit_offers_udp(group, &[]));
    assert_eq!(udp_plan(&manager, "h"), [direct("socks")]);
}

const UDP_FILTER_ALLOCATION_CHILD: &str = "HONK_UDP_FILTER_ALLOCATION_CHILD";

/// With exits configured elsewhere, filtering UDP candidates whose path
/// crosses no exit allocates nothing, and judging one whose path does
/// composes its route without collecting the path. Measured in a child
/// process, so other tests' threads stay out of the process-wide allocation
/// counters.
#[test]
fn udp_filtering_allocates_nothing_without_an_exit_on_the_path() {
    if std::env::var_os(UDP_FILTER_ALLOCATION_CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "group::tests::exit::udp_filtering_allocates_nothing_without_an_exit_on_the_path",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(UDP_FILTER_ALLOCATION_CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let mut all = nodes(&["a", "b", "c"]);
    all.push(trojan("land"));
    let manager = GroupManager::new(
        &[
            make_group("plain", GroupPolicy::Selector, vec![nid("a"), nid("b")]),
            exit_group("routed", vec![nid("c")], "land"),
        ],
        &all,
    );
    let candidate = |name: &'static str, node| Candidate {
        via: None,
        node,
        attribution: Vec::new(),
        pool_bound: 0,
        selection_chain: vec![name],
        exit_on_path: false,
        final_owners: Vec::new(),
        score_work: Vec::new(),
    };
    for (group, members, ancestors) in [
        (
            "plain",
            vec![candidate("a", &all[0]), candidate("b", &all[1])],
            &["outer"][..],
        ),
        ("routed", vec![candidate("c", &all[2])], &[][..]),
    ] {
        let group = &manager.groups.get(group).unwrap().group;
        let count = members.len();
        let region = stats_alloc::Region::new(crate::test_support::ALLOCATOR);
        let kept = manager.retain_exit_selectable(
            members,
            ancestors,
            group,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
        let change = region.change();
        assert_eq!(kept.len(), count, "{}", group.name);
        assert_eq!(
            (change.allocations, change.reallocations),
            (0, 0),
            "{}",
            group.name
        );
    }
}
