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
//! dialed. A route is a UDP candidate only when it can carry UDP: a route
//! collapsed to one node through that node's own UDP, a longer one through
//! its exit tunneling UDP over the stream to it. Candidates that cannot are
//! dropped before any group policy runs, never refused after a pick.

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
use crate::descriptor::{UdpPath, carries_udp};

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
    /// exits of the groups on `path`, outermost first. `None` drops the
    /// candidate: UDP over a route that cannot carry it, an exit this
    /// manager could not resolve, a chain leaf whose hops it could not
    /// resolve, or a route over `MAX_CHAIN_HOPS`.
    #[inline(never)]
    pub(super) fn routed<'a, 'p>(
        &'a self,
        leaf: &'a Node,
        path: impl DoubleEndedIterator<Item = &'p str> + Clone,
        network: SelectionNetwork,
    ) -> Option<Target<'a>> {
        let Some(exits) = self.exits.as_deref() else {
            return Some(Target::node(leaf));
        };
        let udp = network == SelectionNetwork::Udp;
        match self.compose_path(exits, leaf, path)? {
            Composed::Direct => Some(Target::node(leaf)),
            Composed::Collapsed(node) => self
                .nodes
                .get(&node)
                .filter(|node| !udp || carries_udp(UdpPath::Own(node)))
                .map(Target::node),
            Composed::Routed(route) => (!udp || self.route_carries_udp(&route)).then(|| Target {
                node: leaf,
                route: Some(Box::new(route)),
            }),
            Composed::TooLong => None,
        }
    }

    /// What `leaf` dials through the exits of the groups on `path`,
    /// outermost first. `None` for an exit or chain hops this manager could
    /// not resolve. Builds no target, so filters can ask it per candidate.
    /// Inlined into each caller: called, it measured about a hundred more
    /// instructions per TCP selection through an exit.
    #[inline(always)]
    fn compose_path<'p>(
        &self,
        exits: &Exits,
        leaf: &Node,
        path: impl DoubleEndedIterator<Item = &'p str> + Clone,
    ) -> Option<Composed> {
        if leaf.protocol() == NodeProtocol::Block {
            return Some(Composed::Direct);
        }
        let edges = || {
            path.clone()
                .rev()
                .filter_map(|group| exits.by_group.get(group))
        };
        if edges().any(|edge| *edge == ExitEdge::Unresolved) {
            return None;
        }
        let leaf_hops = match leaf.protocol() {
            NodeProtocol::Direct => &[][..],
            NodeProtocol::Chain => exits.chains.get(&leaf.id)?,
            _ => std::slice::from_ref(&leaf.id),
        };
        Some(compose(
            leaf.id,
            leaf_hops,
            edges().filter_map(|edge| match edge {
                ExitEdge::Node(exit) => Some(*exit),
                ExitEdge::Unresolved => None,
            }),
        ))
    }

    /// A route frames UDP at its outermost exit, over the stream to it.
    fn route_carries_udp(&self, route: &honk_config::route::Route) -> bool {
        self.nodes
            .get(&route.exit())
            .is_some_and(|exit| carries_udp(UdpPath::Tunneled { exit }))
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
        self.routed(leaf, path.iter().copied(), network)
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
    /// included (`block` never goes through an exit and stays), and for UDP
    /// those whose leaf or route cannot carry it, so the caller checks only
    /// the leaf's health. Dropping them before any policy runs leaves `final`
    /// and a parent's other members to serve. `ancestors` are the groups
    /// above `group`, outermost first. Out of line, like [`Self::routed`], so
    /// the health filter inlined into every selection path stays its
    /// exit-free size.
    #[inline(never)]
    pub(super) fn retain_exit_selectable<'a>(
        &self,
        mut candidates: Vec<super::Candidate<'a>>,
        ancestors: &[&str],
        group: &Group,
        domain: super::ProbeDomain,
        ipver: super::IpVersion,
    ) -> Vec<super::Candidate<'a>> {
        let udp = matches!(
            domain,
            super::ProbeDomain::DataUdp | super::ProbeDomain::DnsUdp
        );
        if group.exit.is_none()
            && !candidates.iter().any(|c| c.exit_on_path)
            && !(udp && ancestors.iter().any(|group| self.group_has_exit(group)))
        {
            if udp {
                candidates.retain(|candidate| {
                    let capable = self.leaf_carries_udp(candidate.node);
                    if !capable {
                        observation::candidate(
                            candidate,
                            false,
                            "capability_or_health_unavailable",
                        );
                    }
                    capable
                });
            }
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
        let outer_exit = udp
            && ancestors
                .iter()
                .copied()
                .chain(std::iter::once(group.name.as_str()))
                .any(|group| self.group_has_exit(group));
        candidates.retain(|candidate| {
            let reason = if !self.candidate_exits_selectable(candidate, domain, ipver) {
                "exit_unavailable"
            } else if let Some(reason) = udp
                .then(|| self.candidate_udp_unavailable(candidate, outer_exit, ancestors, group))
                .flatten()
            {
                reason
            } else {
                return true;
            };
            observation::candidate(candidate, false, reason);
            false
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

    /// Whether a UDP target is still selectable before its flow binds: the
    /// node itself, or a route that carries UDP with its leaf and its
    /// outermost exit alive, the same reach as selection's exit check.
    pub fn target_selectable(
        &self,
        target: &OwnedTarget,
        domain: super::ProbeDomain,
        ipver: super::IpVersion,
    ) -> bool {
        let Some(route) = target.route() else {
            return self.is_node_selectable_for_domain(target.node.id, domain, ipver);
        };
        (domain == super::ProbeDomain::Tcp || self.route_carries_udp(route))
            && self.is_node_alive_for_domain(route.leaf(), domain, ipver)
            && self.node_exit_alive(route.exit(), domain, ipver)
    }

    /// Why a candidate cannot carry UDP, or `None` when it can: its route
    /// judged on the whole path from the outermost ancestor down to its
    /// leaf without collecting it, or the leaf's own UDP when the path
    /// crosses no exit, which under `outer_exit == false` costs no compose.
    #[inline(never)]
    fn candidate_udp_unavailable(
        &self,
        candidate: &super::Candidate<'_>,
        outer_exit: bool,
        ancestors: &[&str],
        group: &Group,
    ) -> Option<&'static str> {
        let leaf = || {
            (!self.leaf_carries_udp(candidate.node)).then_some("capability_or_health_unavailable")
        };
        let Some(exits) = self.exits.as_deref() else {
            return leaf();
        };
        let below = candidate
            .selection_chain
            .split_last()
            .map_or(&[][..], |(_, groups)| groups);
        if !outer_exit
            && !below
                .iter()
                .any(|group| exits.by_group.contains_key(*group))
        {
            return leaf();
        }
        let path = ancestors
            .iter()
            .copied()
            .chain(std::iter::once(group.name.as_str()))
            .chain(below.iter().copied());
        (!self.path_carries_udp(exits, candidate.node, path)).then_some("exit_without_udp")
    }

    /// Whether what `leaf` dials through the exits of the groups on `path`,
    /// outermost first, carries UDP: the leaf itself without an exit, the
    /// one node a route collapses to, or the exit tunneling it otherwise.
    #[inline(always)]
    fn path_carries_udp<'p>(
        &self,
        exits: &Exits,
        leaf: &Node,
        path: impl DoubleEndedIterator<Item = &'p str> + Clone,
    ) -> bool {
        match self.compose_path(exits, leaf, path) {
            Some(Composed::Direct) => self.leaf_carries_udp(leaf),
            Some(Composed::Collapsed(node)) => self
                .nodes
                .get(&node)
                .is_some_and(|node| carries_udp(UdpPath::Own(node))),
            Some(Composed::Routed(route)) => self.route_carries_udp(&route),
            Some(Composed::TooLong) | None => false,
        }
    }

    /// Whether `group`'s `final` node is selectable, judged like a member:
    /// UDP capability from what it dials through the exits of `ancestors`
    /// and `group`, health on the node itself.
    pub(super) fn final_node_selectable(
        &self,
        node: &Node,
        ancestors: &[&str],
        group: &Group,
        domain: super::ProbeDomain,
        ipver: super::IpVersion,
    ) -> bool {
        match self.exits.as_deref() {
            Some(exits)
                if matches!(
                    domain,
                    super::ProbeDomain::DataUdp | super::ProbeDomain::DnsUdp
                ) =>
            {
                let path = ancestors
                    .iter()
                    .copied()
                    .chain(std::iter::once(group.name.as_str()));
                self.path_carries_udp(exits, node, path)
                    && self.is_node_alive_for_domain(node.id, domain, ipver)
            }
            _ => self.is_node_selectable_for_domain(node.id, domain, ipver),
        }
    }

    /// Whether a leaf reached through `selection_chain` dials as itself:
    /// no exit on the path, or one that collapses to the leaf.
    pub(super) fn dials_as_itself(&self, leaf: &Node, selection_chain: &[&str]) -> bool {
        let Some(exits) = self.exits.as_deref() else {
            return true;
        };
        let path = selection_chain
            .split_last()
            .map_or(&[][..], |(_, path)| path);
        match self.compose_path(exits, leaf, path.iter().copied()) {
            Some(Composed::Direct) => true,
            Some(Composed::Collapsed(node)) => node == leaf.id,
            _ => false,
        }
    }

    fn group_has_exit(&self, group: &str) -> bool {
        self.exits
            .as_deref()
            .is_some_and(|exits| exits.by_group.contains_key(group))
    }

    /// Whether UDP through `group` can be offered at all: the outermost
    /// exit on the path frames it, so only when no ancestor has an exit
    /// does `group`'s own exit need to carry UDP, tunneled or, for a route
    /// that may collapse to it, its own.
    pub(super) fn exit_offers_udp(&self, group: &Group, ancestors: &[&str]) -> bool {
        let Some(exits) = self.exits.as_deref() else {
            return true;
        };
        if ancestors
            .iter()
            .any(|ancestor| self.group_has_exit(ancestor))
        {
            return true;
        }
        match exits.by_group.get(&group.name) {
            None => true,
            Some(ExitEdge::Unresolved) => false,
            Some(ExitEdge::Node(exit)) => self.nodes.get(exit).is_some_and(|node| {
                carries_udp(UdpPath::Tunneled { exit: node })
                    || (carries_udp(UdpPath::Own(node)) && self.may_collapse_to(group, *exit))
            }),
        }
    }

    /// Whether a route through `group` may collapse to `exit`, judged
    /// without building candidates: a direct, `block` or chain member, the
    /// exit itself, any subgroup or any `final` may.
    fn may_collapse_to(&self, group: &Group, exit: Uuid) -> bool {
        !group.groups.is_empty()
            || group.final_outbound.is_some()
            || group.nodes.iter().any(|id| {
                *id == exit
                    || self.nodes.get(id).is_none_or(|node| {
                        matches!(
                            node.protocol(),
                            NodeProtocol::Direct | NodeProtocol::Block | NodeProtocol::Chain
                        )
                    })
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
    /// alone could hold it dead; it counts as alive. Health only: whether
    /// the route carries UDP is the route's answer, and an exit before the
    /// outermost carries only the stream.
    fn exit_alive(&self, group: &str, domain: super::ProbeDomain, ipver: super::IpVersion) -> bool {
        self.group_exit(group)
            .is_none_or(|exit| self.node_exit_alive(exit, domain, ipver))
    }

    fn node_exit_alive(
        &self,
        exit: Uuid,
        domain: super::ProbeDomain,
        ipver: super::IpVersion,
    ) -> bool {
        self.alive_set
            .as_ref()
            .is_none_or(|alive| !alive.is_registered(exit))
            || self.is_node_alive_for_domain(exit, domain, ipver)
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
