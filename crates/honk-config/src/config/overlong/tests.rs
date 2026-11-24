use uuid::Uuid;

use crate::Config;
use crate::node::Node;
use crate::parser::{parse_dae_config, resolve_group_filters};

// Build the same canonical nodes and members as runtime admission. Restore
// the exits afterward so the length checker can see invalid routes too.
fn bind_members(mut config: Config) -> Config {
    let exits: Vec<_> = config
        .groups
        .iter_mut()
        .map(|group| group.exit.take())
        .collect();
    let mut bound = config.assemble(resolve_group_filters).unwrap();
    for (group, exit) in bound.groups.iter_mut().zip(exits) {
        group.exit = exit;
    }
    bound
}

/// The validator's route-length walk before the group graph, narrowed to
/// selection's reach: eight groups on a path, no group twice on one path,
/// and the first node a `final` names.
fn oracle(config: &Config) -> Option<usize> {
    use std::collections::HashMap;

    struct Walk<'a> {
        by_id: HashMap<Uuid, &'a Node>,
        by_name: HashMap<&'a str, Vec<&'a Node>>,
        groups: HashMap<&'a str, &'a crate::group::Group>,
    }
    impl<'a> Walk<'a> {
        fn leaf(node: &Node, next: Option<Uuid>) -> usize {
            let hops = match node.protocol() {
                crate::types::NodeProtocol::Block | crate::types::NodeProtocol::Direct => {
                    return 0;
                }
                crate::types::NodeProtocol::Chain => node.resolved_chain_hops().unwrap(),
                _ => std::slice::from_ref(&node.id),
            };
            hops.len() - usize::from(hops.last().copied() == next)
        }

        fn longest(
            &self,
            group: &'a crate::group::Group,
            path: &[&'a str],
            next: Option<Uuid>,
        ) -> usize {
            let depth = path.len();
            let path = [path, &[group.name.as_str()]].concat();
            let enter = |name: &str| {
                (depth + 1 < crate::group::MAX_GROUP_DEPTH && !path.contains(&name))
                    .then(|| self.groups.get(name))
                    .flatten()
            };
            let exit = group.exit.as_deref().map(|name| self.by_name[name][0].id);
            let inner_next = exit.or(next);
            let leaves = group
                .nodes
                .iter()
                .filter_map(|id| self.by_id.get(id))
                .map(|node| Self::leaf(node, inner_next));
            let nested = group.groups.iter().filter_map(|name| {
                enter(name.as_str()).map(|nested| self.longest(nested, &path, inner_next))
            });
            let fallback =
                group
                    .final_outbound
                    .as_deref()
                    .and_then(|name| match self.by_name.get(name) {
                        Some(namesakes) => {
                            namesakes.first().map(|node| Self::leaf(node, inner_next))
                        }
                        None => enter(name).map(|nested| self.longest(nested, &path, inner_next)),
                    });
            let inner = leaves.chain(nested).chain(fallback).max().unwrap_or(0);
            inner + usize::from(exit.is_some() && exit != next)
        }
    }
    if config.groups.iter().all(|group| group.exit.is_none()) {
        return None;
    }
    let mut by_name: HashMap<&str, Vec<&Node>> = HashMap::new();
    for node in &config.nodes {
        by_name.entry(node.name.as_str()).or_default().push(node);
    }
    let walk = Walk {
        by_id: config.nodes.iter().map(|node| (node.id, node)).collect(),
        by_name,
        groups: config
            .groups
            .iter()
            .map(|group| (group.name.as_str(), group))
            .collect(),
    };
    config
        .groups
        .iter()
        .position(|group| walk.longest(group, &[], None) > crate::node::MAX_CHAIN_HOPS)
}

/// A small deterministic generator, so a failure names its seed.
struct Rng(u64);

impl Rng {
    fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % bound as u64) as usize
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

const PLAIN: [&str; 6] = ["a", "b", "c", "d", "twin", "twin"];
const UNIQUE: [&str; 4] = ["a", "b", "c", "d"];

fn random_config(rng: &mut Rng) -> String {
    let mut nodes = String::new();
    for (index, name) in PLAIN.iter().enumerate() {
        nodes.push_str(&format!(" {name}: 'socks5://127.0.0.1:{}'\n", 1000 + index));
    }
    let mut chains = Vec::new();
    for _ in 0..rng.below(4) {
        let hops: Vec<&str> = (0..2 + rng.below(3))
            .map(|_| UNIQUE[rng.below(UNIQUE.len())])
            .collect();
        if !chains.contains(&hops) {
            chains.push(hops);
        }
    }
    let leaves: Vec<String> = PLAIN[..5]
        .iter()
        .map(|name| name.to_string())
        .chain(chains.into_iter().enumerate().map(|(index, hops)| {
            let name = format!("chain{index}");
            nodes.push_str(&format!(" {name}: {}\n", hops.join(" -> ")));
            name
        }))
        .collect();
    let groups = 1 + rng.below(6);
    let mut text = String::new();
    for group in 0..groups {
        text.push_str(&format!(" g{group} {{\n"));
        let mut filtered = false;
        for _ in 0..rng.below(3) {
            text.push_str(&format!(
                "  filter: name({})\n",
                leaves[rng.below(leaves.len())]
            ));
            filtered = true;
        }
        for _ in 0..rng.below(3) {
            text.push_str(&format!("  filter: group(g{})\n", rng.below(groups)));
            filtered = true;
        }
        if !filtered {
            text.push_str("  filter: name(nothing)\n");
        }
        match rng.below(6) {
            0 => text.push_str("  final: direct\n"),
            1 => text.push_str("  final: block\n"),
            2 => text.push_str(&format!("  final: {}\n", leaves[rng.below(leaves.len())])),
            3 => text.push_str(&format!("  final: g{}\n", rng.below(groups))),
            _ => {}
        }
        if rng.chance(60) {
            text.push_str(&format!("  exit: {}\n", UNIQUE[rng.below(UNIQUE.len())]));
        }
        text.push_str(" }\n");
    }
    format!("node {{\n{nodes}}}\ngroup {{\n{text}}}\nrouting {{\n fallback: direct\n}}\n")
}

#[test]
fn route_length_validation_matches_the_walk_at_selection_reach() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let (mut overlong, mut within) = (0, 0);
    for case in 0..4000 {
        let text = random_config(&mut rng);
        let partial = parse_dae_config(&text).unwrap_or_else(|error| panic!("{error}\n{text}"));
        let config = bind_members(partial);
        let expected = oracle(&config);
        assert_eq!(
            config.overlong_group_route(),
            expected,
            "case {case}:\n{text}"
        );
        match expected {
            Some(_) => overlong += 1,
            None => within += 1,
        }
    }
    assert!(
        overlong > 200 && within > 200,
        "{overlong} overlong, {within} within"
    );
}

fn two_level(exits: [&str; 9], leaf_group: usize) -> Config {
    let groups: String = (0..9)
        .map(|level| {
            let nested = match level < 8 {
                true => format!("  filter: group(g{})\n", level + 1),
                false => String::new(),
            };
            let member = match level == leaf_group {
                true => "  filter: name(m)\n",
                false => "",
            };
            let exit = match exits[level] {
                "" => String::new(),
                exit => format!("  exit: {exit}\n"),
            };
            let filler = match nested.is_empty() && member.is_empty() {
                true => "  filter: name(nothing)\n",
                false => "",
            };
            format!(" g{level} {{\n{nested}{member}{exit}{filler} }}\n")
        })
        .collect();
    parse_dae_config(&format!(
        "node {{\n m: 'socks5://127.0.0.1:1000'\n x: 'socks5://127.0.0.1:1001'\n y: 'socks5://127.0.0.1:1002'\n}}\ngroup {{\n{groups}}}\nrouting {{\n fallback: direct\n}}\n"
    ))
    .unwrap()
}

#[test]
fn validation_and_selection_cut_at_the_same_depth() {
    // From g0 the route through the ninth group, m-x-y-x-y, is five hops,
    // but selection never reaches that group from g0; from g1, which does,
    // it is four. One group up, g0 reaches it and the route counts.
    let config = two_level(["y", "x", "y", "", "", "", "", "", "x"], 8);
    assert_eq!(config.overlong_group_route(), None);
    let config = two_level(["y", "x", "y", "", "", "", "", "x", ""], 7);
    assert_eq!(config.overlong_group_route(), Some(0));
}

#[test]
fn a_final_names_the_first_declared_namesake_everywhere() {
    let config = |long_first: bool| {
        let (first, second) = match long_first {
            true => ("a -> b -> c -> d", "'socks5://127.0.0.1:1005'"),
            false => ("'socks5://127.0.0.1:1005'", "a -> b -> c -> d"),
        };
        parse_dae_config(&format!(
            "node {{\n a: 'socks5://127.0.0.1:1000'\n b: 'socks5://127.0.0.1:1001'\n c: 'socks5://127.0.0.1:1002'\n d: 'socks5://127.0.0.1:1003'\n x: 'socks5://127.0.0.1:1004'\n twin: {first}\n twin: {second}\n}}\ngroup {{\n g {{\n  filter: name(a)\n  final: twin\n  exit: x\n }}\n}}\nrouting {{\n fallback: direct\n}}\n"
        ))
        .unwrap()
    };
    assert_eq!(bind_members(config(true)).overlong_group_route(), Some(0));
    // Selection dials the first namesake, so the later one no longer counts.
    assert_eq!(bind_members(config(false)).overlong_group_route(), None);
}

#[test]
fn a_cycle_through_exit_groups_counts_each_group_once() {
    // Followed to the depth limit, g0 -> g1 -> g0 -> ... would put m behind
    // x-y-x-y-x; selection enters each group once per path, so the longest
    // route is m-x-y, from g1.
    let config = parse_dae_config(
        "node {\n m: 'socks5://127.0.0.1:1000'\n x: 'socks5://127.0.0.1:1001'\n y: 'socks5://127.0.0.1:1002'\n}\ngroup {\n g0 {\n  filter: name(m)\n  filter: group(g1)\n  exit: x\n }\n g1 {\n  filter: group(g0)\n  exit: y\n }\n}\nrouting {\n fallback: direct\n}\n",
    )
    .unwrap();
    assert_eq!(config.overlong_group_route(), None);
}
