//! Group `exit`: a leaf selected through groups with an exit dials as a
//! route, its own hops first and then each group's exit from the innermost
//! group out. Selection itself is unchanged; only the target a dialing plan
//! hands out carries the route, so policies, health filtering and Score
//! feedback keep working on the leaf.
//!
//! The manager keeps only each group's exit edge and each configured
//! chain's hop IDs. A route is composed when a candidate is selected, so
//! the number of routes the configuration could produce, which can grow
//! with the product of nested exit groups, costs nothing until one is
//! dialed. Routes carry TCP only: UDP through an exit is not offered.

use honk_config::group::Group;
use honk_config::group_graph::{
    Composed, ExitEdge, GroupGraph, Leaf, Limits, Step, Visitor, compose,
};
use honk_config::node::Node;
use honk_config::route::Route;
use honk_config::types::NodeProtocol;
use std::collections::HashMap;
use std::ops::ControlFlow;
use uuid::Uuid;

use super::target::{OwnedTarget, RoutedTarget, Target};
use super::{GroupManager, ManagedGroup, SelectionNetwork, observation};

/// Exit edges by group name and configured chain hops by chain ID, built
/// only when some group has an exit.
#[derive(Debug)]
pub(super) struct Exits {
    by_group: HashMap<String, ExitEdge>,
    chains: HashMap<Uuid, Box<[Uuid]>>,
}

impl Exits {
    /// Also sets each managed group's `routes`, which stays false without
    /// exits.
    pub(super) fn build(
        groups: &[Group],
        nodes: &[Node],
        managed: &mut HashMap<String, ManagedGroup>,
    ) -> Option<Box<Self>> {
        if groups.iter().all(|group| group.exit.is_none()) {
            return None;
        }
        let graph = GroupGraph::new(groups, nodes);
        // The raw graph reaches at least what selection reaches through the
        // cycle-cut copy, so `false` is sound there.
        let mut reach = Reach {
            graph: &graph,
            clear: vec![false; graph.len()],
        };
        let routes: Vec<bool> = (0..graph.len())
            .map(|group| graph.visit(group, Limits::SELECTION, &mut reach).is_break())
            .collect();
        for (name, entry) in managed.iter_mut() {
            entry.routes = graph.group(name).is_some_and(|group| routes[group]);
        }
        // A later namesake shadows a group, here as in the manager and the
        // graph, so a shadowed group's exit routes nothing.
        let named = |group: usize| graph.group(graph.name(group)) == Some(group);
        Some(Box::new(Self {
            by_group: (0..graph.len())
                .filter(|group| named(*group))
                .filter_map(|group| Some((graph.name(group).to_owned(), graph.exit(group)?)))
                .collect(),
            chains: graph.chains().map(|(id, hops)| (id, hops.into())).collect(),
        }))
    }
}

/// Breaks when selection can produce a route: a group with an exit, or a
/// chain leaf whose hops are unknown, which [`GroupManager::routed`] drops.
struct Reach<'g, 'a> {
    graph: &'g GroupGraph<'a>,
    /// Groups whose complete subtree has neither.
    clear: Vec<bool>,
}

impl Visitor for Reach<'_, '_> {
    fn enter(&mut self, group: usize, _: usize, _: &[Uuid]) -> ControlFlow<(), Step> {
        if self.graph.exit(group).is_some() {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(if self.clear[group] {
            Step::Skip
        } else {
            Step::Descend
        })
    }

    fn leaf(&mut self, leaf: Leaf, _: &[Uuid]) -> ControlFlow<()> {
        match leaf {
            Leaf::Node(id)
                if self.graph.chain_hops(id).is_none()
                    && self
                        .graph
                        .node(id)
                        .is_some_and(|node| node.protocol() == NodeProtocol::Chain) =>
            {
                ControlFlow::Break(())
            }
            _ => ControlFlow::Continue(()),
        }
    }

    fn leave(&mut self, group: usize, _: usize, _: &[Uuid], complete: bool) {
        self.clear[group] |= complete;
    }
}

impl GroupManager {
    /// The target a candidate dials: its leaf, or the route through the
    /// exits of the groups on `path`. `None` drops the candidate: UDP
    /// through an exit, an exit this manager could not resolve, a chain leaf
    /// whose hops it could not resolve, or a route over `MAX_CHAIN_HOPS`.
    #[inline(never)]
    pub(super) fn routed<'a>(
        &'a self,
        leaf: &'a Node,
        path: &[&str],
        network: SelectionNetwork,
    ) -> Option<Target<'a>> {
        let Some(exits) = self.exits.as_deref() else {
            return Some(Target::node(leaf));
        };
        if leaf.protocol() == NodeProtocol::Block {
            return Some(Target::node(leaf));
        }
        let edges = || {
            path.iter()
                .rev()
                .filter_map(|group| exits.by_group.get(*group))
        };
        if edges().any(|edge| *edge == ExitEdge::Unresolved) {
            return None;
        }
        let leaf_hops = match leaf.protocol() {
            NodeProtocol::Direct => &[][..],
            NodeProtocol::Chain => exits.chains.get(&leaf.id)?,
            _ => std::slice::from_ref(&leaf.id),
        };
        let composed = compose(
            leaf.id,
            leaf_hops,
            edges().filter_map(|edge| match edge {
                ExitEdge::Node(exit) => Some(*exit),
                ExitEdge::Unresolved => None,
            }),
        );
        match composed {
            Composed::Direct => Some(Target::node(leaf)),
            _ if network == SelectionNetwork::Udp => None,
            Composed::Collapsed(node) => self.nodes.get(&node).map(Target::node),
            Composed::Routed(route) => Some(Target {
                node: leaf,
                route: Some(Box::new(route)),
            }),
            Composed::TooLong => None,
        }
    }

    /// [`Self::routed`] for a candidate, whose selection chain ends with its
    /// leaf. Inline, with [`Self::routed`] out of line, so a candidate with
    /// no exit on its path pays only these tests. A chain leaf still goes
    /// through [`Self::routed`], which drops it when its hops are unknown.
    #[inline]
    pub(super) fn routed_chain<'a>(
        &'a self,
        candidate: &super::Candidate<'a>,
        network: SelectionNetwork,
    ) -> Option<Target<'a>> {
        let leaf = candidate.node;
        if !self.has_exits() || (!candidate.exit_on_path && leaf.protocol() != NodeProtocol::Chain)
        {
            return Some(Target::node(leaf));
        }
        let path = candidate
            .selection_chain
            .split_last()
            .map_or(&[][..], |(_, path)| path);
        self.routed(leaf, path, network)
    }

    /// Whether a candidate dials its own leaf, which every candidate under a
    /// root whose `routes` is false must.
    pub(super) fn dials_its_leaf(
        &self,
        candidate: &super::Candidate<'_>,
        network: SelectionNetwork,
    ) -> bool {
        !candidate.exit_on_path
            && self.routed_chain(candidate, network).is_some_and(|target| {
                std::ptr::eq(target.node, candidate.node) && target.route.is_none()
            })
    }

    /// Own a target with the hop names this manager knows, for a dial and
    /// its observation outliving the manager. Inline, with the route half
    /// out of line, so owning a plain node costs its clone and no call.
    #[inline]
    pub fn own_target(&self, target: Target<'_>) -> OwnedTarget {
        match target.route {
            None => OwnedTarget::node(target.node.clone()),
            Some(route) => OwnedTarget {
                node: target.node.clone(),
                route: Some(self.own_route(*route)),
            },
        }
    }

    #[inline(never)]
    fn own_route(&self, route: Route) -> Box<RoutedTarget> {
        Box::new(RoutedTarget {
            hop_names: route
                .hops()
                .iter()
                .map(|hop| {
                    self.nodes
                        .get(hop)
                        .map_or_else(|| hop.to_string(), |node| node.name.clone())
                })
                .collect(),
            route,
        })
    }

    /// Drop the candidates whose routes cross a dead exit, `group`'s own
    /// included; `block` never goes through an exit and stays. Out of line, like [`Self::routed`], so the health filter
    /// inlined into every selection path stays its exit-free size.
    #[inline(never)]
    pub(super) fn retain_exit_selectable<'a>(
        &self,
        mut candidates: Vec<super::Candidate<'a>>,
        group: &Group,
        domain: super::ProbeDomain,
        ipver: super::IpVersion,
    ) -> Vec<super::Candidate<'a>> {
        if group.exit.is_none() && !candidates.iter().any(|c| c.exit_on_path) {
            return candidates;
        }
        if !self.exit_alive(&group.name, domain, ipver) {
            candidates.retain(|candidate| {
                let block = candidate.node.protocol() == NodeProtocol::Block;
                if !block {
                    observation::candidate(candidate, false, "exit_unavailable");
                }
                block
            });
            return candidates;
        }
        candidates.retain(|candidate| {
            let selectable = self.candidate_exits_selectable(candidate, domain, ipver);
            if !selectable {
                observation::candidate(candidate, false, "exit_unavailable");
            }
            selectable
        });
        candidates
    }

    /// Drop the candidates `group`'s `final` offers while `group`'s own exit
    /// is dead: the final goes through that exit too, except `block`. A root
    /// group has no parent to drop them, so it would dial the dead exit.
    #[inline(never)]
    pub(super) fn retain_final_exit_selectable<'a>(
        &self,
        mut candidates: Vec<super::Candidate<'a>>,
        group: &Group,
        domain: super::ProbeDomain,
        ipver: super::IpVersion,
    ) -> Vec<super::Candidate<'a>> {
        if self.exit_alive(&group.name, domain, ipver) {
            return candidates;
        }
        candidates.retain(|candidate| {
            let block = candidate.node.protocol() == NodeProtocol::Block;
            if !block {
                observation::candidate(candidate, false, "exit_unavailable");
            }
            block
        });
        candidates
    }

    /// Whether the exits of the groups a candidate was selected through are
    /// alive. A nested group's last-resort leaf bypasses that group's own
    /// exit check, so without this a parent would keep choosing a route
    /// through a dead exit over a healthy sibling.
    fn candidate_exits_selectable(
        &self,
        candidate: &super::Candidate<'_>,
        domain: super::ProbeDomain,
        ipver: super::IpVersion,
    ) -> bool {
        candidate.node.protocol() == NodeProtocol::Block
            || candidate
                .selection_chain
                .split_last()
                .is_none_or(|(_, groups)| {
                    groups
                        .iter()
                        .all(|group| self.exit_alive(group, domain, ipver))
                })
    }

    /// The resolved exit of `group`, for callers that probe it.
    pub fn group_exit(&self, group: &str) -> Option<Uuid> {
        match self.exits.as_deref()?.by_group.get(group)? {
            ExitEdge::Node(exit) => Some(*exit),
            ExitEdge::Unresolved => None,
        }
    }

    /// Whether any group has an exit. Every exit check tests this first, so
    /// a configuration without exits pays no lookup or allocation for them.
    #[inline]
    pub(super) fn has_exits(&self) -> bool {
        self.exits.is_some()
    }

    /// A route through `group` counts as alive only while its exit is. An
    /// exit the alive set does not register is never probed, so traffic
    /// alone could hold it dead; it counts as alive.
    fn exit_alive(&self, group: &str, domain: super::ProbeDomain, ipver: super::IpVersion) -> bool {
        let Some(exit) = self.group_exit(group) else {
            return true;
        };
        self.alive_set
            .as_ref()
            .is_none_or(|alive| !alive.is_registered(exit))
            || self.is_node_selectable_for_domain(exit, domain, ipver)
    }

    /// Owned dialing targets of a group in plan order, the legacy
    /// counterpart of [`Self::select_nodes_in_order_for_domain`] for callers
    /// that dial. Owned here, as those callers keep every target, so no
    /// borrowed target list is built on the way.
    pub fn select_targets_in_order_for_domain(
        &self,
        group_name: &str,
        domain: super::ProbeDomain,
        ipver: super::IpVersion,
    ) -> Vec<OwnedTarget> {
        let Some(entry) = self.groups.get(group_name) else {
            return Vec::new();
        };
        if !entry.routes {
            return self
                .selection_plan_for_group(
                    &entry.group,
                    false,
                    domain,
                    ipver,
                    super::SelectionEffects::Apply,
                )
                .nodes
                .into_iter()
                .map(|node| OwnedTarget::node(node.clone()))
                .collect();
        }
        let group = &entry.group;
        self.mark_used(group_name);
        let context = super::ScoreSelectionContext::aggregate(
            SelectionNetwork::from_probe_domain(domain),
            domain,
            ipver,
        );
        let (_, candidates) = self.selection_candidates_for_target(
            group,
            &context,
            &mut Vec::new(),
            0,
            super::SelectionEffects::Apply,
            super::score::selection::ScoreSelectionRules {
                cold_urltest: true,
                routes: true,
                ..Default::default()
            },
        );
        candidates
            .into_iter()
            .filter_map(|candidate| self.routed_chain(&candidate, context.network))
            .map(|target| self.own_target(target))
            .collect()
    }
}
