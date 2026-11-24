use super::*;

fn ids<const N: usize>() -> [Uuid; N] {
    std::array::from_fn(|index| Uuid::from_u128(index as u128 + 1))
}

fn routed(composed: Composed) -> (Vec<Uuid>, usize) {
    match composed {
        Composed::Routed(route) => (route.hops().to_vec(), route.leaf_hops()),
        other => panic!("expected a route, got {other:?}"),
    }
}

#[test]
fn compose_dedups_only_adjacent_hops() {
    let [m, x, y, a, e] = ids();
    assert_eq!(routed(compose(m, &[m], [x])), (vec![m, x], 1));
    assert_eq!(routed(compose(m, &[m], [x, x])), (vec![m, x], 1));
    assert_eq!(routed(compose(m, &[m], [x, y, x])), (vec![m, x, y, x], 1));
    // A configured chain dials its own hops as configured.
    assert_eq!(routed(compose(m, &[a, a], [e])), (vec![a, a, e], 2));
    assert_eq!(routed(compose(m, &[a, e], [e])), (vec![a, e], 2));
}

#[test]
fn compose_tells_direct_collapsed_routed_and_too_long_apart() {
    let [m, a, b, c, d, e] = ids();
    let direct = crate::config::DIRECT_NODE_ID;
    assert_eq!(compose(m, &[m], []), Composed::Direct);
    assert_eq!(compose(m, &[a, b], []), Composed::Direct);
    assert_eq!(compose(e, &[e], [e]), Composed::Collapsed(e));
    assert_eq!(compose(direct, &[], [e]), Composed::Collapsed(e));
    assert_eq!(routed(compose(direct, &[], [a, e])), (vec![a, e], 0));
    assert_eq!(routed(compose(m, &[a, b, c], [e])), (vec![a, b, c, e], 3));
    assert_eq!(compose(m, &[a, b, c, d], [e]), Composed::TooLong);
    assert_eq!(compose(m, &[m], [a, b, c, d]), Composed::TooLong);
    let Composed::Routed(route) = compose(m, &[a, b], [e]) else {
        panic!("expected a route");
    };
    assert_eq!((route.leaf(), route.exit()), (m, e));
}

fn config(groups: &str) -> Config {
    crate::parser::parse_dae_config(&format!(
        "node {{\n m: 'socks5://127.0.0.1:1081'\n m: 'socks5://127.0.0.1:1082'\n e1: 'socks5://127.0.0.1:1083'\n e2: 'socks5://127.0.0.1:1084'\n}}\ngroup {{\n{groups}\n}}\nrouting {{\n fallback: direct\n}}\n"
    ))
    .unwrap()
}

fn set_exit(config: &mut Config, group: &str, exit: &str) {
    config
        .groups
        .iter_mut()
        .find(|candidate| candidate.name == group)
        .unwrap()
        .exit = Some(exit.to_owned());
}

fn node_id(config: &Config, name: &str) -> Uuid {
    config
        .nodes
        .iter()
        .find(|node| node.name == name)
        .unwrap()
        .id
}

#[derive(Default)]
struct Leaves(Vec<(Leaf, Vec<Uuid>)>);

impl Visitor for Leaves {
    fn leaf(&mut self, leaf: Leaf, exits: &[Uuid]) -> ControlFlow<()> {
        self.0.push((leaf, exits.to_vec()));
        ControlFlow::Continue(())
    }
}

fn leaves(graph: &GroupGraph<'_>, root: &str) -> Vec<(Leaf, Vec<Uuid>)> {
    let mut leaves = Leaves::default();
    let _ = graph.visit(graph.group(root).unwrap(), &mut leaves);
    leaves.0
}

#[test]
fn reparsing_the_same_config_preserves_the_route_key() {
    let text = " outer {\n  filter: group(inner)\n }\n inner {\n  filter: name(e1)\n }";
    let route = || {
        let mut config = config(text);
        set_exit(&mut config, "outer", "e2");
        let graph = GroupGraph::new(&config.groups, &config.nodes);
        let leaves = leaves(&graph, "outer");
        let [(Leaf::Node(leaf), exits)] = leaves.as_slice() else {
            panic!("expected one node leaf");
        };
        compose(
            *leaf,
            std::slice::from_ref(leaf),
            exits.iter().rev().copied(),
        )
    };
    let first = route();
    assert!(matches!(first, Composed::Routed(_)));
    assert_eq!(first, route());
}

#[test]
fn exits_reach_the_visitor_outermost_first() {
    let mut config = config(
        " outer {\n  filter: group(inner)\n }\n inner {\n  filter: name(e1)\n  final: direct\n }",
    );
    set_exit(&mut config, "outer", "e2");
    set_exit(&mut config, "inner", "e1");
    let graph = GroupGraph::new(&config.groups, &config.nodes);
    let [e1, e2] = [node_id(&config, "e1"), node_id(&config, "e2")];
    assert_eq!(
        leaves(&graph, "outer"),
        [(Leaf::Node(e1), vec![e2, e1]), (Leaf::Direct, vec![e2, e1]),]
    );
}

#[test]
fn an_exit_that_does_not_name_one_tunnel_node_is_unresolved() {
    let mut config = config(" g {\n  filter: name(e1)\n }");
    for exit in ["m", "nowhere", "direct"] {
        set_exit(&mut config, "g", exit);
        let graph = GroupGraph::new(&config.groups, &config.nodes);
        assert_eq!(graph.exit(0), Some(ExitEdge::Unresolved), "{exit}");
    }
    set_exit(&mut config, "g", "e1");
    let graph = GroupGraph::new(&config.groups, &config.nodes);
    assert_eq!(graph.exit(0), Some(ExitEdge::Node(node_id(&config, "e1"))));
}

#[test]
fn a_final_reaches_its_first_namesake() {
    let config = config(" g {\n  filter: name(e1)\n  final: m\n }\n m {\n  filter: name(e2)\n }");
    let graph = GroupGraph::new(&config.groups, &config.nodes);
    let namesakes: Vec<Uuid> = config
        .nodes
        .iter()
        .filter(|node| node.name == "m")
        .map(|node| node.id)
        .collect();
    assert_eq!(namesakes.len(), 2);
    // A node of the final's name wins over a group of that name.
    assert_eq!(
        leaves(&graph, "g")
            .into_iter()
            .skip(1)
            .map(|(leaf, _)| leaf)
            .collect::<Vec<_>>(),
        [Leaf::Node(namesakes[0])]
    );
}

fn nested(levels: usize) -> Config {
    let groups: String = (0..levels)
        .map(|level| match level + 1 < levels {
            true => format!(
                " g{level} {{\n  filter: name(e1)\n  filter: group(g{})\n }}\n",
                level + 1
            ),
            false => format!(" g{level} {{\n  filter: name(e1)\n }}\n"),
        })
        .collect();
    config(&groups)
}

#[test]
fn the_depth_limit_counts_groups_from_the_root() {
    let config = nested(10);
    let graph = GroupGraph::new(&config.groups, &config.nodes);
    assert_eq!(leaves(&graph, "g0").len(), MAX_GROUP_DEPTH);
}

#[derive(Default)]
struct Completeness(Vec<(usize, bool)>);

impl Visitor for Completeness {
    fn leaf(&mut self, _: Leaf, _: &[Uuid]) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }

    fn leave(&mut self, group: usize, _: usize, _: &[Uuid], complete: bool) {
        self.0.push((group, complete));
    }
}

#[test]
fn a_cycle_stops_at_the_path_guard() {
    let config = config(
        " a {\n  filter: name(e1)\n  filter: group(b)\n }\n b {\n  filter: name(e2)\n  filter: group(a)\n }",
    );
    let graph = GroupGraph::new(&config.groups, &config.nodes);
    assert_eq!(leaves(&graph, "a").len(), 2);
    let mut completeness = Completeness::default();
    let _ = graph.visit(0, &mut completeness);
    assert_eq!(completeness.0, [(1, false), (0, false)]);
}

#[test]
fn cut_cycles_drops_the_back_edge_in_name_order() {
    let config = config(" b {\n  filter: group(a)\n }\n a {\n  filter: group(b)\n }");
    let mut groups: HashMap<String, Group> = config
        .groups
        .iter()
        .map(|group| (group.name.clone(), group.clone()))
        .collect();
    cut_cycles(&mut groups);
    assert_eq!(groups["a"].groups, ["b"]);
    assert!(groups["b"].groups.is_empty());
}
