//! Group `exit`: a leaf selected through groups with an exit dials as a
//! route, its own hops first and then each group's exit from the innermost
//! group out. Eligibility includes the full composed path before a policy
//! reduces its candidates. Ranking and Score attribution use the selected leaf.
//!
//! The manager keeps each group's exit edge and uses the configured chain's
//! bound hop IDs. UDP capability belongs to the terminal hop of a composed
//! route. A collapsed route uses the actual node's own UDP transport.

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
use super::{
    GroupManager, GroupMember, IpVersion, MAX_GROUP_DEPTH, ManagedGroup, ProbeDomain,
    SelectionNetwork,
};
use crate::descriptor::{UdpPath, builtin_tunneled_udp_available, builtin_udp_available};

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
    /// Whether membership or a final can dial a UDP chain, route, or exit collapse.
    /// This checks the compiled transport shape independently of current selection and health.
    pub fn group_can_compose_udp(&self, name: &str) -> bool {
        self.groups.get(name).is_some_and(|entry| {
            entry.udp_chain
                || (entry.routes
                    && self.exit_path_can_compose_udp(
                        &entry.group,
                        &mut [""; MAX_GROUP_DEPTH],
                        0,
                        false,
                    ))
        })
    }

    fn exit_path_can_compose_udp<'a>(
        &'a self,
        group: &'a Group,
        path: &mut [&'a str; MAX_GROUP_DEPTH],
        depth: usize,
        exit_on_path: bool,
    ) -> bool {
        if depth == path.len() || path[..depth].contains(&group.name.as_str()) {
            return false;
        }
        let exit_on_path = if group.exit.is_some() {
            let Some(exit_id) = self.group_exit(&group.name) else {
                return false;
            };
            // The outermost exit remains terminal even when composition collapses it.
            exit_on_path
                || self
                    .nodes
                    .get(&exit_id)
                    .is_some_and(|exit| builtin_udp_available(UdpPath::Own(exit)))
        } else {
            exit_on_path
        };
        path[depth] = &group.name;
        let mut can_compose = |member| match member {
            GroupMember::Group(child) => {
                self.exit_path_can_compose_udp(child, path, depth + 1, exit_on_path)
            }
            GroupMember::Node(leaf) => {
                exit_on_path
                    && leaf.protocol() != NodeProtocol::Block
                    && self
                        .compose_route(leaf, &path[..=depth], SelectionNetwork::Udp)
                        .is_some()
            }
        };
        self.members(group).any(&mut can_compose)
            || self.final_member(group).is_some_and(can_compose)
    }

    /// The target a candidate dials: its leaf, or the route through the
    /// exits of the groups on `path`, outermost first. `None` drops the
    /// candidate: UDP over a route that cannot carry it, an exit this
    /// manager could not resolve, a chain leaf whose hops it could not
    /// resolve, or a route over `MAX_CHAIN_HOPS`.
    #[inline(never)]
    fn compose_route<'a>(
        &'a self,
        leaf: &'a Node,
        path: &[&str],
        network: SelectionNetwork,
    ) -> Option<(&'a Node, Option<Route>)> {
        let composed = self.compose_path(leaf, path.iter().rev().copied(), |_| true)?;
        let udp = network == SelectionNetwork::Udp;
        match composed {
            Composed::Direct => Some((leaf, None)),
            Composed::Collapsed(id) => self
                .nodes
                .get(&id)
                .filter(|node| !udp || builtin_udp_available(UdpPath::Own(node)))
                .map(|node| (node, None)),
            Composed::Routed(route) if !udp || self.route_carries_udp(&route) => {
                Some((leaf, Some(route)))
            }
            Composed::Routed(_) | Composed::TooLong => None,
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
        node_targets_only: bool,
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
            return if domain == ProbeDomain::Tcp {
                leaf.protocol() != NodeProtocol::Chain || leaf.resolved_chain_hops().is_some()
            } else {
                self.udp_leaf_available(leaf, domain, family)
            };
        }
        let groups = std::iter::once(group.name.as_str()).chain(ancestors.iter().rev().copied());
        if domain != ProbeDomain::Tcp {
            return match self.compose_path(leaf, groups, |_| true) {
                Some(Composed::Direct) => self.udp_leaf_available(leaf, domain, family),
                Some(Composed::Collapsed(id)) => self.nodes.get(&id).is_some_and(|node| {
                    builtin_udp_available(UdpPath::Own(node))
                        && family
                            .is_none_or(|ipver| self.is_node_alive_for_domain(id, domain, ipver))
                }),
                Some(Composed::Routed(route)) => {
                    !node_targets_only && self.udp_route_available(&route, domain, family)
                }
                Some(Composed::TooLong) | None => false,
            };
        }
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

    fn udp_leaf_available(
        &self,
        leaf: &Node,
        domain: super::ProbeDomain,
        family: Option<super::IpVersion>,
    ) -> bool {
        family.map_or_else(
            || self.node_carries_udp(leaf),
            |ipver| self.is_node_selectable_for_domain(leaf.id, domain, ipver),
        )
    }

    /// Whether the captured UDP target is still eligible before its flow binds.
    pub fn target_selectable(
        &self,
        target: &OwnedTarget,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> bool {
        target.node.protocol() == NodeProtocol::Block
            || target.route().map_or_else(
                || self.is_node_selectable_for_domain(target.node.id, domain, ipver),
                |route| self.udp_route_available(route, domain, Some(ipver)),
            )
    }

    fn route_carries_udp(&self, route: &Route) -> bool {
        builtin_tunneled_udp_available(route.hops(), |id| self.nodes.get(id))
    }

    fn udp_route_available(
        &self,
        route: &Route,
        domain: ProbeDomain,
        family: Option<IpVersion>,
    ) -> bool {
        self.route_carries_udp(route)
            && family.is_none_or(|ipver| {
                self.udp_route_path_available(route.leaf(), route.hops(), domain, ipver)
            })
    }

    /// Skip building candidates when a simple exit group cannot offer UDP.
    pub(super) fn exit_offers_udp(&self, group: &Group, ancestors: &[&str]) -> bool {
        if !group.groups.is_empty() || group.final_outbound.is_some() {
            return true;
        }
        let Some(exits) = self.exits.as_deref() else {
            return true;
        };
        if ancestors
            .iter()
            .any(|name| exits.by_group.contains_key(*name))
        {
            return true;
        }
        let exit = self
            .group_exit(&group.name)
            .and_then(|id| self.nodes.get(&id));
        exit.is_some_and(|exit| builtin_udp_available(UdpPath::Tunneled { exit }))
            || group
                .nodes
                .iter()
                .filter_map(|id| self.nodes.get(id))
                .any(|node| {
                    node.protocol() == NodeProtocol::Block
                        || exit.is_some_and(|exit| {
                            builtin_udp_available(UdpPath::Own(exit))
                                && (node.id == exit.id || node.protocol() == NodeProtocol::Direct)
                        })
                })
    }

    /// Warm-up opens the leaf runtime directly. A collapse may reuse that
    /// runtime when the leaf itself is the node the route dials.
    pub(super) fn udp_warm_dials_leaf<'g>(
        &self,
        leaf: &Node,
        groups: impl Iterator<Item = &'g str>,
    ) -> bool {
        match self.compose_path(leaf, groups, |_| true) {
            Some(Composed::Direct) => true,
            Some(Composed::Collapsed(id)) => id == leaf.id,
            _ => false,
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
