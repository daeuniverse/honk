use crate::alive::route_health::{
    Failure, RouteHealth, RouteScope, UdpEdges, UdpWitness, physical_hops,
};
use crate::alive::{
    IpVersion, ProbeDomain, RouteHealthRevision, RouteHealthStamp, UdpBareReply,
    UdpHealthNotifications, UdpHopRole, UdpRouteAdmission,
};
use crate::group::{
    DialKey, GroupManager, GroupMember, MAX_GROUP_DEPTH, OwnedTarget, SelectionNetwork,
    SelectorState, SelectorStorage,
};
use crate::proxy::{
    DialFailureScope, dial_failure_scope, node_failure_cause, shared_failure_cause,
};
use honk_config::group::{Group, GroupPolicy};
use honk_config::group_graph::Composed;
use honk_config::node::Node;
use honk_config::route::Route;
use std::error::Error;
use std::sync::Arc;
use uuid::Uuid;

fn custom_url(group: &Group) -> Option<&str> {
    group
        .check_url
        .as_deref()
        .filter(|url| group.policy != GroupPolicy::Selector && !url.is_empty())
}

impl GroupManager {
    /// Publish only after admission, under the same writer as health registrations.
    pub fn publish_route_health(self: &Arc<Self>) {
        self.publish_route_health_with_udp(None);
    }

    /// The caller supplies only settings explicitly present in the accepted configuration.
    pub fn publish_route_health_with_udp(self: &Arc<Self>, explicit_dns: Option<&[String]>) {
        self.publish_route_authority(|target| *target = explicit_dns.map(Arc::from));
    }

    /// A manager-only rebind cannot admit configuration changes to the probe destination.
    pub fn republish_route_health(self: &Arc<Self>) {
        self.publish_route_authority(|_| {});
    }

    fn publish_route_authority(
        self: &Arc<Self>,
        publish_dns: impl FnOnce(&mut Option<Arc<[String]>>),
    ) {
        if let Some(alive) = &self.alive_set {
            let selector = self.selector_choice.read();
            alive.publish_routes(
                self,
                selector.revision,
                publish_dns,
                |id| self.nodes.contains_key(id),
                |state| self.attach_witnesses(state, &selector),
            );
        }
    }

    pub(crate) fn with_route_revision<T>(&self, run: impl FnOnce(u64) -> T) -> T {
        run(self.selector_choice.read().revision)
    }

    pub(crate) fn refresh_route_choices(&self) {
        if let Some(alive) = &self.alive_set {
            let selector = self.selector_choice.read();
            alive.refresh_route_choices(self, selector.revision, |state| {
                self.attach_witnesses(state, &selector)
            });
        }
    }

    fn attach_witnesses(&self, state: &mut RouteHealth, selector: &SelectorState) {
        state.refresh_udp(
            |origin, target| self.current_udp_witness(origin, target, selector),
            |id| self.nodes.contains_key(id),
        );
        if !state.has_tcp_rows() {
            return;
        }
        for entry in self.groups.values().filter(|entry| entry.routes) {
            let root = &entry.group;
            self.visit_health_routes(
                root,
                selector,
                &mut [""; MAX_GROUP_DEPTH],
                0,
                true,
                &mut |target, authorized| {
                    state.admit(&root.name, target, custom_url(root), authorized);
                    false
                },
            );
        }
    }

    /// Visit potential final edges even while their ordinary siblings are healthy. The
    /// recovery exchange needs a policy-authorized path that ordinary health now gates.
    fn visit_health_routes<'a>(
        &'a self,
        group: &'a Group,
        selector: &SelectorState,
        path: &mut [&'a str; MAX_GROUP_DEPTH],
        depth: usize,
        authorized: bool,
        visit: &mut impl FnMut(DialKey, bool) -> bool,
    ) -> bool {
        if depth >= path.len() || path[..depth].contains(&group.name.as_str()) {
            return false;
        }
        path[depth] = &group.name;
        let pin = self.selector_member_in(group, SelectionNetwork::Tcp, selector);
        let mut visit_member = |member, active| match member {
            GroupMember::Group(child) => {
                self.visit_health_routes(child, selector, path, depth + 1, active, visit)
            }
            GroupMember::Node(node) => {
                match self.compose_path(node, path[..=depth].iter().rev().copied(), |_| true) {
                    Some(Composed::Routed(route)) => visit(DialKey::Route(route), active),
                    Some(Composed::Collapsed(id)) => visit(DialKey::Node(id), active),
                    _ => false,
                }
            }
        };
        self.members(group).any(|member| {
            let active = authorized
                && pin.map_or(group.policy != GroupPolicy::Selector, |pin| {
                    Self::same_member(pin, member)
                });
            visit_member(member, active)
        }) || self
            .final_member(group)
            .is_some_and(|member| visit_member(member, authorized))
    }

    fn admits_route(&self, group: &Group, selector: &SelectorState, target: DialKey) -> bool {
        self.visit_health_routes(
            group,
            selector,
            &mut [""; MAX_GROUP_DEPTH],
            0,
            true,
            &mut |key, active| active && key == target,
        )
    }

    pub fn route_prefix_available(&self, route: &Route, family: IpVersion) -> bool {
        self.alive_set
            .as_ref()
            .is_none_or(|alive| alive.prefix_available(route, family))
    }

    /// Current route authority. Business callers use the revision returned with their dial plan.
    pub fn route_health_revision(&self, root: &str) -> RouteHealthRevision {
        self.with_routed_selector(root, SelectionNetwork::Tcp, |_, revision| revision)
    }

    pub(in crate::group) fn route_plan_snapshot(
        &self,
        root: &str,
        network: SelectionNetwork,
    ) -> (Option<Arc<SelectorState>>, RouteHealthRevision) {
        self.with_routed_selector(root, network, |state, revision| {
            (Some(Arc::clone(state)), revision)
        })
    }

    fn with_routed_selector<T: Default>(
        &self,
        root: &str,
        network: SelectionNetwork,
        capture: impl FnOnce(&Arc<SelectorState>, RouteHealthRevision) -> T,
    ) -> T {
        if !self.has_exits() && self.udp_evidence_nodes.is_empty() {
            return T::default();
        }
        if self.groups.get(root).is_none_or(|entry| {
            !entry.routes && !(network == SelectionNetwork::Udp && entry.udp_chain)
        }) {
            return T::default();
        }
        let selector = self.selector_choice.read();
        let SelectorStorage::Shared(state) = &*selector else {
            unreachable!("a manager with routed plans publishes shared selector state");
        };
        let revision = self
            .alive_set
            .as_ref()
            .map_or_else(RouteHealthRevision::default, |alive| {
                alive.route_revision(self, state.revision)
            });
        capture(state, revision)
    }

    /// Report whether the current health owner accepted a UUID or ordered-prefix strike.
    pub fn report_route_failure(
        &self,
        root_group: &str,
        target: &OwnedTarget,
        family: IpVersion,
        stamp: RouteHealthStamp,
        error: &(dyn Error + 'static),
    ) -> bool {
        if !target.uses_route_evidence() {
            return false;
        }
        let (Some(alive), Some(entry)) = (&self.alive_set, self.groups.get(root_group)) else {
            return false;
        };
        let root = &entry.group;
        let key = target.key();
        let typed = node_failure_cause(error);
        let (end, node, prefix) = match (dial_failure_scope(error), key) {
            (DialFailureScope::Prefix(j), DialKey::Route(route))
                if j > 0 && j < route.hops().len() =>
            {
                (j, (j < route.leaf_hops()).then_some(route.leaf()), true)
            }
            (DialFailureScope::Hop(j), DialKey::Route(route)) => {
                let Some(&id) = route.hops().get(j) else {
                    return false;
                };
                (
                    j,
                    Some(if j < route.leaf_hops() {
                        route.leaf()
                    } else {
                        id
                    }),
                    false,
                )
            }
            (DialFailureScope::Hop(0), DialKey::Node(id)) => (0, Some(id), false),
            (DialFailureScope::Unattributed, DialKey::Node(id)) if typed.is_some() => {
                (0, Some(id), false)
            }
            _ => return false,
        };
        let shared = typed.flatten().or_else(|| shared_failure_cause(error));
        let selector = self.selector_choice.read();
        // An internal refusal in a configured chain also belongs to its virtual leaf.
        // Settle both scopes under one publication fence.
        let failure = Failure {
            manager: self,
            selector: selector.revision,
            witness: (Some(root_group), key, custom_url(root)),
            udp: None,
            hops: physical_hops(&key),
            scope: RouteScope::new(ProbeDomain::Tcp, family),
            stamp,
            end,
            node,
            prefix,
            shared,
        };
        let Some((counted, node_changed, prefix_changed)) =
            alive.route_failed(failure, || self.admits_route(root, &selector, key))
        else {
            return false;
        };
        drop(selector);
        let hop = physical_hops(&key)[end];
        if node_changed {
            alive.notify_route_failure(self, stamp, counted, hop, family);
        }
        if prefix_changed {
            alive.notify_route_failure(self, stamp, None, hop, family);
        }
        true
    }

    /// Report a validated protocol or application response using the root, target and
    /// family captured by the actual dial. The stream alone supplies no evidence.
    pub fn report_route_response(
        &self,
        root_group: &str,
        key: DialKey,
        family: IpVersion,
        stamp: RouteHealthStamp,
        dial_latency: Option<std::time::Duration>,
    ) {
        let Some(alive) = &self.alive_set else { return };
        if !self.groups.contains_key(root_group) {
            return;
        }
        let selector = self.selector_choice.read();
        let changes =
            alive.route_response(self, key, family, selector.revision, stamp, dial_latency);
        drop(selector);
        alive.notify_route_response(self, stamp, family, changes);
    }
}

impl GroupManager {
    pub fn group_has_udp_chain(&self, root: &str) -> bool {
        self.groups.get(root).is_some_and(|entry| entry.udp_chain)
    }

    pub fn has_udp_route_health(&self) -> bool {
        !self.udp_evidence_nodes.is_empty()
            || self
                .alive_set
                .as_ref()
                .is_some_and(|alive| alive.may_have_udp_faults())
    }

    pub fn retains_udp_route_health_node(&self, id: Uuid) -> bool {
        self.udp_evidence_nodes.binary_search(&id).is_ok()
    }

    pub fn udp_hop_down(
        &self,
        id: Uuid,
        domain: ProbeDomain,
        family: IpVersion,
        role: UdpHopRole,
    ) -> bool {
        self.alive_set
            .as_ref()
            .is_some_and(|alive| alive.udp_hop_down(self, id, domain, family, role))
    }

    pub fn capture_udp_bare_reply(&self, id: Uuid, family: IpVersion) -> Option<UdpBareReply> {
        let alive = self.alive_set.as_ref()?;
        if !(self.retains_udp_route_health_node(id)
            || (alive.has_bare_udp_fault(id, family) && self.nodes.contains_key(&id)))
        {
            return None;
        }
        Some(UdpBareReply::new(
            id,
            family,
            alive.route_revision(self, 0).admit(),
        ))
    }

    pub fn report_udp_bare_reply(&self, proof: &UdpBareReply) {
        if let Some(notifications) = self.settle_udp_bare_reply(proof) {
            notifications.notify();
        }
    }

    /// Settles the physical proof and legacy state once for this source.
    /// `None` leaves ordinary traffic accounting to the caller.
    pub fn settle_udp_bare_reply<'a>(
        &'a self,
        proof: &'a UdpBareReply,
    ) -> Option<UdpHealthNotifications<'a>> {
        proof.settle(self.alive_set.as_deref()?, self)
    }

    /// Explicit node resolution has no group Selector. Its bound hops still belong to a generation.
    pub fn udp_node_revision(&self, node: &Node) -> RouteHealthRevision {
        if node.resolved_chain_hops().is_none() {
            return RouteHealthRevision::default();
        }
        self.alive_set
            .as_ref()
            .map_or_else(RouteHealthRevision::default, |alive| {
                alive.route_revision(self, 0)
            })
    }

    /// Check capability when binding the plan. Only immutable hop IDs and authority survive setup.
    pub fn capture_udp_route(
        &self,
        target: &OwnedTarget,
        selection_chain: &[String],
        final_owners: &[String],
        revision: RouteHealthRevision,
        domain: ProbeDomain,
        family: IpVersion,
    ) -> Option<UdpRouteAdmission> {
        if domain == ProbeDomain::Tcp {
            return None;
        }
        let (selected, groups) = selection_chain.split_last()?;
        if groups.len() > MAX_GROUP_DEPTH || final_owners.len() > groups.len() {
            return None;
        }
        let key = target.key();
        let hops = match &key {
            DialKey::Route(route) if self.route_carries_udp(route) => route.hops(),
            DialKey::Node(id) => {
                let node = self.nodes.get(id)?;
                if !self.node_carries_udp(node) {
                    return None;
                }
                node.resolved_chain_hops()
                    .unwrap_or_else(|| std::slice::from_ref(id))
            }
            _ => return None,
        };
        let selector = self.selector_choice.read();
        let (leaf, leaf_name) = target.selected_member();
        let mut edges = UdpEdges {
            depth: groups.len() as u8,
            leaf,
            ..Default::default()
        };
        if groups.is_empty() {
            if target.uses_route_evidence()
                || target.node.resolved_chain_hops().is_none()
                || selected != &target.node.name
                || !final_owners.is_empty()
            {
                return None;
            }
        } else {
            let mut finals = final_owners.iter().peekable();
            for (depth, name) in groups.iter().enumerate() {
                if finals.next_if(|owner| *owner == name).is_some() {
                    edges.finals |= 1 << depth;
                } else if let Some(child) = groups.get(depth + 1) {
                    let group = &self.groups.get(name)?.group;
                    edges.children[depth] = group
                        .groups
                        .iter()
                        .position(|tag| tag == child)?
                        .try_into()
                        .ok()?;
                }
            }
            if selected != leaf_name
                || finals.next().is_some()
                || self.udp_path_status(
                    groups.iter().map(String::as_str),
                    edges.finals,
                    leaf,
                    key,
                    &selector,
                ) != Some(true)
            {
                return None;
            }
        }
        let root = match groups.first() {
            Some(root) => Some(Arc::clone(self.groups.get(root)?.udp_root.as_ref()?)),
            None => None,
        };
        let token =
            UdpRouteAdmission::new(key, hops, domain, family, revision.admit(), root, edges);
        let attempt = token.attempt(self, token.root.as_ref().map(|_| selector.revision));
        self.current_udp_attempt(token.leaf(), &attempt)
            .then_some(token)
    }

    pub(crate) fn own_udp_witness(&self, token: &UdpRouteAdmission) -> UdpWitness {
        let edges = &token.edges;
        let mut groups = Vec::with_capacity(usize::from(edges.depth));
        let mut next = token.root.as_deref();
        for depth in 0..usize::from(edges.depth) {
            let name = next.expect("captured group edge");
            groups.push((name.to_owned(), self.group_exit(name)));
            if depth + 1 < usize::from(edges.depth) {
                let group = &self.groups[name].group;
                next = if edges.finals & (1 << depth) != 0 {
                    group.final_outbound.as_deref()
                } else {
                    Some(&group.groups[edges.children[depth] as usize])
                };
            }
        }
        let explicit_name = groups
            .is_empty()
            .then(|| Box::from(self.nodes[&edges.leaf].name.as_str()));
        UdpWitness {
            groups: groups.into_boxed_slice(),
            explicit_name,
            leaf: edges.leaf,
            finals: edges.finals,
        }
    }

    fn current_udp_witness(
        &self,
        origin: &UdpWitness,
        key: DialKey,
        selector: &SelectorState,
    ) -> Option<bool> {
        match &key {
            DialKey::Node(id) if self.node_carries_udp(self.nodes.get(id)?) => (),
            DialKey::Route(route) if self.route_carries_udp(route) => (),
            _ => return None,
        }
        if let Some(name) = &origin.explicit_name {
            let node = self.nodes.get(&origin.leaf)?;
            return (key == DialKey::Node(origin.leaf)
                && node.name == name.as_ref()
                && node.resolved_chain_hops().is_some())
            .then_some(true);
        }
        // Deduplication can hide removal or replacement of a configured exit.
        if origin
            .groups
            .iter()
            .any(|(name, exit)| self.group_exit(name) != *exit)
        {
            return None;
        }
        self.udp_path_status(
            origin.groups.iter().map(|(name, _)| name.as_str()),
            origin.finals,
            origin.leaf,
            key,
            selector,
        )
    }

    // None removes this witness. A still-configured path can await its own UDP Selector.
    fn udp_path_status<'a>(
        &self,
        groups: impl Iterator<Item = &'a str>,
        finals: u8,
        leaf: Uuid,
        key: DialKey,
        selector: &SelectorState,
    ) -> Option<bool> {
        let mut active = true;
        let mut seen = [""; MAX_GROUP_DEPTH];
        let mut path = groups.enumerate().peekable();
        while let Some((depth, name)) = path.next() {
            if depth >= seen.len() || seen[..depth].contains(&name) {
                return None;
            }
            let group = &self.groups.get(name)?.group;
            seen[depth] = group.name.as_str();
            let child = path.peek().map(|&(_, name)| name);
            let matches = |member: GroupMember<'_>| match (member, child) {
                (GroupMember::Group(group), Some(child)) => group.name == child,
                (GroupMember::Node(node), None) => node.id == leaf,
                _ => false,
            };
            let member = if finals & (1 << depth) != 0 {
                let member = self.final_member(group).filter(|&m| matches(m))?;
                active &= !self.udp_blocks(group, selector, &mut seen, depth, false);
                member
            } else {
                let member = self.members(group).find(|&m| matches(m))?;
                active &= self
                    .selector_member_in(group, SelectionNetwork::Udp, selector)
                    .map_or(group.policy != GroupPolicy::Selector, |pin| {
                        Self::same_member(pin, member)
                    });
                member
            };
            if let GroupMember::Node(node) = member {
                let ancestors = seen[..=depth].iter().rev().copied();
                let expected = match self.compose_path(node, ancestors, |_| true)? {
                    Composed::Direct if node.resolved_chain_hops().is_some() => {
                        DialKey::Node(node.id)
                    }
                    Composed::Direct => return None,
                    Composed::Collapsed(id) => DialKey::Node(id),
                    Composed::Routed(route) => DialKey::Route(route),
                    Composed::TooLong => return None,
                };
                return (expected == key).then_some(active);
            }
        }
        None
    }

    fn udp_blocks<'a>(
        &'a self,
        group: &'a Group,
        selector: &SelectorState,
        seen: &mut [&'a str; MAX_GROUP_DEPTH],
        depth: usize,
        include_final: bool,
    ) -> bool {
        if depth == seen.len() || seen[..depth].contains(&group.name.as_str()) {
            return false;
        }
        seen[depth] = &group.name;
        let mut blocks = |member: GroupMember<'a>| match member {
            GroupMember::Node(node) => node.id == honk_config::config::BLOCK_NODE_ID,
            GroupMember::Group(child) => self.udp_blocks(child, selector, seen, depth + 1, true),
        };
        let ordinary = match self.selector_member_in(group, SelectionNetwork::Udp, selector) {
            Some(pin) => blocks(pin),
            None => self.members(group).any(&mut blocks),
        };
        ordinary || (include_final && self.final_member(group).is_some_and(blocks))
    }

    /// Eligibility of the complete bound path, also used by selection and TC publication.
    pub fn udp_route_path_available(
        &self,
        leaf: Uuid,
        hops: &[Uuid],
        domain: ProbeDomain,
        family: IpVersion,
    ) -> bool {
        domain != ProbeDomain::Tcp
            && !hops.is_empty()
            && self.alive_set.as_ref().is_none_or(|alive| {
                alive.hops_available(hops, RouteScope::new(domain, family))
                    && self.udp_nodes_available(alive, leaf, hops, domain, family)
            })
    }

    fn udp_nodes_available(
        &self,
        alive: &crate::alive::AliveDialerSet,
        leaf: Uuid,
        hops: &[Uuid],
        domain: ProbeDomain,
        family: IpVersion,
    ) -> bool {
        let Some((exit, prefix)) = hops.split_last() else {
            return false;
        };
        (leaf == *exit || alive.udp_carrier_leaf_available(leaf, domain, family))
            && self.is_node_alive_for_domain(*exit, domain, family)
            && prefix.iter().all(|&id| {
                alive.udp_carrier_available(id, domain, family)
                    && alive.is_alive_for(id, ProbeDomain::Tcp, family)
            })
    }

    /// Only synchronous Score reporter operations belong inside this fence.
    pub fn with_udp_score_authority<R>(
        &self,
        token: &UdpRouteAdmission,
        publish: impl FnOnce(bool) -> R,
    ) -> R {
        let Some(alive) = &self.alive_set else {
            return publish(false);
        };
        let selector = token.root.as_ref().map(|_| self.selector_choice.read());
        let attempt = token.attempt(self, selector.as_ref().map(|s| s.revision));
        alive.with_route_authority(&attempt, publish)
    }

    /// Called at admission, bind and the first send, after any asynchronous gate wait.
    pub fn udp_route_current(&self, token: &UdpRouteAdmission) -> bool {
        let selector = token.root.as_ref().map(|_| self.selector_choice.read());
        let attempt = token.attempt(self, selector.as_ref().map(|s| s.revision));
        self.current_udp_attempt(token.leaf(), &attempt)
    }

    fn current_udp_attempt(
        &self,
        leaf: Uuid,
        attempt: &crate::alive::route_health::RouteAttempt<'_>,
    ) -> bool {
        self.alive_set.as_ref().is_some_and(|alive| {
            alive.current_route_eligible(attempt, || {
                self.udp_nodes_available(
                    alive,
                    leaf,
                    attempt.hops,
                    attempt.scope.domain(),
                    attempt.scope.family(),
                )
            })
        })
    }

    pub fn report_udp_route_failure(
        &self,
        token: &UdpRouteAdmission,
        error: &(dyn Error + 'static),
    ) -> bool {
        let Some(alive) = &self.alive_set else {
            return false;
        };
        let selector = token.root.as_ref().map(|_| self.selector_choice.read());
        let attempt = token.attempt(self, selector.as_ref().map(|s| s.revision));
        let (end, prefix) = match dial_failure_scope(error) {
            DialFailureScope::Hop(i) => (i, false),
            DialFailureScope::Prefix(i) if i > 0 => (i, true),
            DialFailureScope::Unattributed
                if attempt.hops.len() == 1 && node_failure_cause(error).is_some() =>
            {
                (0, false)
            }
            _ => return false,
        };
        let Some(&hop) = attempt.hops.get(end) else {
            return false;
        };
        if !token.claim_failure() {
            return false;
        }
        let failure = Failure {
            manager: self,
            scope: attempt.scope,
            selector: attempt.selector,
            stamp: attempt.stamp,
            hops: attempt.hops,
            witness: (token.root.as_deref(), token.key(), None),
            udp: Some(token),
            end,
            prefix,
            node: (!prefix).then_some(hop),
            shared: node_failure_cause(error)
                .flatten()
                .or_else(|| shared_failure_cause(error)),
        };
        let Some((_, node_changed, prefix_changed)) = alive.route_failed(failure, || true) else {
            return false;
        };
        drop(selector);
        if node_changed || prefix_changed {
            alive.notify_udp_route_change(
                &attempt,
                hop,
                node_changed,
                UdpHopRole::at(end, attempt.hops.len()),
                false,
            );
        }
        true
    }

    /// Only a delivered packet proves this path, including the physical hops of a configured chain.
    pub fn report_udp_route_reply(&self, token: &UdpRouteAdmission) {
        if let Some(notifications) = self.settle_udp_route_reply(token) {
            notifications.notify();
        }
    }

    /// Apply the route reply before the caller publishes its notifications.
    pub fn settle_udp_route_reply<'a>(
        &'a self,
        token: &'a UdpRouteAdmission,
    ) -> Option<UdpHealthNotifications<'a>> {
        if !token.claim_reply() {
            return None;
        }
        let alive = self.alive_set.as_deref()?;
        let selector = token.root.as_ref().map(|_| self.selector_choice.read());
        let attempt = token.attempt(self, selector.as_ref().map(|s| s.revision));
        let (exit, carriers) = attempt.hops.split_last().expect("admitted UDP path");
        let owners = carriers
            .iter()
            .enumerate()
            .filter_map(|(index, &id)| {
                (!carriers[..index].contains(&id)).then_some((id, UdpHopRole::Carrier))
            })
            .chain(std::iter::once((*exit, UdpHopRole::Framing)));
        let leaf = token.leaf();
        // A chain used only as the TCP prefix of another exit did not run its own UDP framing.
        let whole_chain =
            self.nodes.get(&leaf).and_then(Node::resolved_chain_hops) == Some(attempt.hops);
        let owners = owners.chain(whole_chain.then_some((leaf, UdpHopRole::Framing)));
        let changes = alive.confirm_route(&attempt, owners, None);
        drop(selector);
        Some(UdpHealthNotifications::new(alive, attempt, changes))
    }
}
