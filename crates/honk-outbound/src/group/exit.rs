//! Group `exit`: a leaf selected through groups with an exit dials as a
//! route, its own hops first and then each group's exit from the innermost
//! group out. Eligibility includes the full composed path before a policy
//! reduces its candidates. Ranking and Score attribution use the selected leaf.
//!
//! The manager keeps each group's exit edge and uses the configured chain's
//! bound hop IDs. A route is composed when a candidate is selected, so the
//! number of possible routes costs nothing until one is selected. Routes
//! carry TCP only: UDP through an exit is not offered.

mod health;

use honk_config::group::Group;
use honk_config::group_graph::{Composed, ExitEdge, GroupGraph, Leaf, Step, Visitor, compose};
use honk_config::node::Node;
use honk_config::route::Route;
use honk_config::types::NodeProtocol;
use std::collections::HashMap;
use std::ops::ControlFlow;
use uuid::Uuid;

use super::target::{OwnedTarget, RoutedTarget, Target};
use super::{GroupManager, ManagedGroup, SelectionNetwork};

/// Exit edges by group name, built only when some group has an exit.
#[derive(Debug)]
pub(super) struct Exits {
    by_group: HashMap<String, ExitEdge>,
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
            .map(|group| graph.visit(group, &mut reach).is_break())
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
        }))
    }
}

/// Breaks when selection can produce a route: a group with an exit, or a
/// chain leaf whose hops are unknown, which [`GroupManager::compose_route`] drops.
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
                if self.graph.node(id).is_some_and(|node| {
                    node.protocol() == NodeProtocol::Chain && node.resolved_chain_hops().is_none()
                }) =>
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
    fn compose_route<'a>(
        &'a self,
        leaf: &'a Node,
        path: &[&str],
        network: SelectionNetwork,
    ) -> Option<(&'a Node, Option<Route>)> {
        let composed = self.compose_path(leaf, path.iter().rev().copied(), |_| true)?;
        match composed {
            Composed::Direct => Some((leaf, None)),
            _ if network == SelectionNetwork::Udp => None,
            Composed::Collapsed(node) => self.nodes.get(&node).map(|node| (node, None)),
            Composed::Routed(route) => Some((leaf, Some(route))),
            Composed::TooLong => None,
        }
    }

    #[inline]
    pub(super) fn compose_candidate_route<'a>(
        &'a self,
        candidate: &super::Candidate<'a>,
        network: SelectionNetwork,
    ) -> Option<(&'a Node, Option<Route>)> {
        let leaf = candidate.node;
        if !self.has_exits() || (!candidate.exit_on_path && leaf.protocol() != NodeProtocol::Chain)
        {
            return Some((leaf, None));
        }
        let path = candidate
            .selection_chain
            .split_last()
            .map_or(&[][..], |(_, path)| path);
        self.compose_route(leaf, path, network)
    }

    /// A known route is boxed only when it is included in a dial plan.
    #[inline]
    pub(super) fn routed_chain<'a>(
        &'a self,
        candidate: &super::Candidate<'a>,
        network: SelectionNetwork,
    ) -> Option<Target<'a>> {
        let (node, route) = self.compose_candidate_route(candidate, network)?;
        Some(Target {
            node,
            route: route.map(Box::new),
        })
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
                collapse: super::ExitCollapse::None,
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

    pub(super) fn compose_path<'a>(
        &self,
        leaf: &Node,
        groups: impl Iterator<Item = &'a str>,
        mut exit_available: impl FnMut(Uuid) -> bool,
    ) -> Option<Composed> {
        let Some(exits) = self.exits.as_deref() else {
            return Some(Composed::Direct);
        };
        if leaf.protocol() == NodeProtocol::Block {
            return Some(Composed::Direct);
        }
        let leaf_hops = match leaf.protocol() {
            NodeProtocol::Direct => &[][..],
            NodeProtocol::Chain => leaf.resolved_chain_hops()?,
            _ => std::slice::from_ref(&leaf.id),
        };
        let mut available = true;
        let edges = groups.filter_map(|group| match exits.by_group.get(group)? {
            ExitEdge::Node(id) => {
                available &= exit_available(*id);
                Some(*id)
            }
            ExitEdge::Unresolved => {
                available = false;
                None
            }
        });
        let route = compose(leaf.id, leaf_hops, edges);
        available.then_some(route)
    }

    /// Validate a direct member against the exits along its complete selection path.
    /// The root-only sole TCP retry passes no health family, but still needs a valid route.
    pub(super) fn leaf_route_available(
        &self,
        leaf: &Node,
        group: &Group,
        ancestors: &[&str],
        domain: super::ProbeDomain,
        family: Option<super::IpVersion>,
    ) -> bool {
        if leaf.protocol() == NodeProtocol::Block {
            return true;
        }
        let Some(exits) = self.exits.as_deref() else {
            return true;
        };
        if group.exit.is_none()
            && ancestors
                .iter()
                .all(|name| !exits.by_group.contains_key(*name))
        {
            return leaf.protocol() != NodeProtocol::Chain || leaf.resolved_chain_hops().is_some();
        }
        if domain != super::ProbeDomain::Tcp {
            return false;
        }
        let groups = std::iter::once(group.name.as_str()).chain(ancestors.iter().rev().copied());
        let path = self.compose_path(leaf, groups, |id| {
            family.is_none_or(|ipver| self.is_node_selectable_for_domain(id, domain, ipver))
        });
        match path {
            Some(Composed::Direct | Composed::Collapsed(_)) => true,
            Some(Composed::Routed(route)) => {
                family.is_none_or(|ipver| self.route_prefix_available(&route, ipver))
            }
            Some(Composed::TooLong) | None => false,
        }
    }

    /// The resolved exit of `group`, for callers that probe it.
    pub fn group_exit(&self, group: &str) -> Option<Uuid> {
        match self.exits.as_deref()?.by_group.get(group)? {
            ExitEdge::Node(exit) => Some(*exit),
            ExitEdge::Unresolved => None,
        }
    }

    /// Whether the published group graph contains a configured exit.
    #[inline]
    pub fn has_exits(&self) -> bool {
        self.exits.is_some()
    }
}
