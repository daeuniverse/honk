use super::{
    Evidence, Prefix, RouteAttempt, RouteFailureScope, RouteHealthStamp, RouteScope,
    UdpHealthNotifications,
};
use crate::SharedError;
use crate::alive::{AliveDialerSet, IpVersion, NodeStates, ProbeDomain, alive_index, fresh_states};
use crate::group::{DialKey, GroupManager};
use honk_config::config::{BLOCK_NODE_ID, DIRECT_NODE_ID};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

/// Physical operation performed by this node on the admitted packet path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpHopRole {
    Carrier,
    Framing,
}

impl UdpHopRole {
    pub(crate) fn at(index: usize, len: usize) -> Self {
        if index + 1 == len {
            Self::Framing
        } else {
            Self::Carrier
        }
    }
}

/// The creator of one bare association may prove its DataUdp framing operation once.
#[derive(Debug)]
pub struct UdpBareReply {
    node: Uuid,
    family: IpVersion,
    stamp: RouteHealthStamp,
    replied: AtomicBool,
}

impl UdpBareReply {
    pub(crate) fn new(node: Uuid, family: IpVersion, stamp: RouteHealthStamp) -> Self {
        Self {
            node,
            family,
            stamp,
            replied: AtomicBool::new(false),
        }
    }

    pub fn depends_on(
        &self,
        id: Uuid,
        domain: ProbeDomain,
        family: IpVersion,
        role: UdpHopRole,
    ) -> bool {
        self.node == id
            && self.family == family
            && domain == ProbeDomain::DataUdp
            && role == UdpHopRole::Framing
    }

    pub(crate) fn settle<'a>(
        &'a self,
        alive: &'a AliveDialerSet,
        manager: &'a GroupManager,
    ) -> Option<UdpHealthNotifications<'a>> {
        if self.replied.load(Ordering::Relaxed) || self.replied.swap(true, Ordering::Relaxed) {
            return None;
        }
        let attempt = RouteAttempt {
            manager,
            hops: std::slice::from_ref(&self.node),
            scope: RouteScope::new(ProbeDomain::DataUdp, self.family),
            selector: self.stamp.selector,
            stamp: self.stamp,
            grouped: false,
        };
        // A bare reply proves one physical node. Order its watermark with
        // other route settlements while also resetting the legacy slot.
        let state = alive.route_health.write();
        if !state.accepts(manager, attempt.selector, self.stamp) {
            return None;
        }
        let (flipped, first) = alive.recover_routed_udp_node(
            self.node,
            attempt.scope,
            self.stamp,
            super::next_episode(),
        )?;
        drop(state);
        let mut changes = Vec::new();
        if flipped || first {
            changes.push((self.node, true));
        }
        Some(UdpHealthNotifications::new(alive, attempt, changes))
    }
}

/// Indexes refer only to the immutable manager that issued the attempt.
#[derive(Default, Debug)]
pub(crate) struct UdpEdges {
    pub children: [u32; crate::group::MAX_GROUP_DEPTH - 1],
    pub depth: u8,
    pub finals: u8,
    pub leaf: Uuid,
}

/// Stable names are copied only when a counted fault first installs a witness.
#[derive(Debug)]
pub(crate) struct UdpWitness {
    pub groups: Box<[(String, Option<Uuid>)]>,
    pub explicit_name: Option<Box<str>>,
    pub finals: u8,
    pub leaf: Uuid,
}

/// Authority and bound physical order of one UDP attempt, captured before setup.
#[derive(Debug)]
pub struct UdpRouteAdmission {
    path: UdpPath,
    scope: RouteScope,
    stamp: RouteHealthStamp,
    pub(crate) root: Option<Arc<str>>,
    pub(crate) edges: UdpEdges,
    failed: AtomicBool,
    replied: AtomicBool,
}

#[derive(Clone, Copy, Debug)]
enum UdpPath {
    Routed(honk_config::route::Route),
    Node { id: Uuid, path: Prefix },
}

impl UdpRouteAdmission {
    pub(crate) fn new(
        key: DialKey,
        hops: &[Uuid],
        domain: ProbeDomain,
        family: IpVersion,
        stamp: RouteHealthStamp,
        root: Option<Arc<str>>,
        edges: UdpEdges,
    ) -> Self {
        let scope = RouteScope::new(domain, family);
        let path = match key {
            DialKey::Route(route) => UdpPath::Routed(route),
            DialKey::Node(id) => UdpPath::Node {
                id,
                path: Prefix::new(hops, scope),
            },
        };
        Self {
            path,
            scope,
            stamp,
            root,
            edges,
            failed: AtomicBool::new(false),
            replied: AtomicBool::new(false),
        }
    }

    pub fn depends_on(
        &self,
        id: Uuid,
        domain: ProbeDomain,
        family: IpVersion,
        role: UdpHopRole,
    ) -> bool {
        let hops = self.hops();
        self.scope == RouteScope::new(domain, family)
            && hops
                .iter()
                .enumerate()
                .any(|(index, hop)| *hop == id && UdpHopRole::at(index, hops.len()) == role)
    }

    /// A single flow/association can close once even when both sides observe its termination.
    pub(crate) fn claim_failure(&self) -> bool {
        !self.failed.swap(true, Ordering::Relaxed)
    }

    pub(crate) fn claim_reply(&self) -> bool {
        !self.replied.load(Ordering::Relaxed) && !self.replied.swap(true, Ordering::Relaxed)
    }

    pub(crate) fn leaf(&self) -> Uuid {
        match self.path {
            UdpPath::Routed(route) => route.leaf(),
            UdpPath::Node { id, .. } => id,
        }
    }

    pub(crate) fn key(&self) -> DialKey {
        match self.path {
            UdpPath::Routed(route) => DialKey::Route(route),
            UdpPath::Node { id, .. } => DialKey::Node(id),
        }
    }

    fn hops(&self) -> &[Uuid] {
        match &self.path {
            UdpPath::Routed(route) => route.hops(),
            UdpPath::Node { path, .. } => path.hops(),
        }
    }

    pub(crate) fn attempt<'a>(
        &'a self,
        manager: &'a GroupManager,
        selector: Option<u64>,
    ) -> RouteAttempt<'a> {
        RouteAttempt {
            manager,
            hops: self.hops(),
            scope: self.scope,
            selector: selector.unwrap_or(self.stamp.selector),
            stamp: self.stamp,
            grouped: self.root.is_some(),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct RoutedUdpNode {
    evidence: Evidence,
    // Legacy node probes may sample a different path, target or family. They
    // cannot reset this streak or supply a recovery watermark.
    failures: u32,
    down_at: u64,
}

impl NodeStates {
    pub(super) fn has_udp_faults(&self) -> bool {
        self.route_udp
            .as_ref()
            .is_some_and(|rows| rows.iter().any(|row| row.failures != 0))
    }

    pub(super) fn udp_hop_episode(&self, scope: RouteScope, started: u64) -> Option<u64> {
        let node = &self.route_udp.as_ref()?[scope.udp_index()];
        (node.down_at != 0 && node.evidence.failure <= started).then_some(node.down_at)
    }

    pub(in crate::alive) fn routed_udp_available(&self, domain: ProbeDomain, index: usize) -> bool {
        domain == ProbeDomain::Tcp
            || self.route_udp.as_ref().is_none_or(|slots| {
                slots[(index - IpVersion::count()) * 2].failures
                    < super::traffic_failure_threshold(domain)
            })
    }
}

impl AliveDialerSet {
    pub(crate) fn may_have_udp_faults(&self) -> bool {
        self.udp_faults.load(Ordering::Acquire)
    }

    pub(crate) fn has_bare_udp_fault(&self, id: Uuid, family: IpVersion) -> bool {
        let index = RouteScope::new(ProbeDomain::DataUdp, family).udp_index();
        self.may_have_udp_faults()
            && self
                .states
                .read()
                .get(&id)
                .and_then(|node| node.route_udp.as_ref())
                .is_some_and(|rows| rows[index].failures != 0)
    }

    /// Selection reads the UDP domain history and UUID slots once, including on ordinary managers.
    pub(crate) fn data_udp_available(&self, id: Uuid, family: IpVersion) -> bool {
        let sampled = self.has_udp_state(id);
        let states = self.states.read();
        let Some(node) = states.get(&id) else {
            return true;
        };
        let scope = RouteScope::new(ProbeDomain::DataUdp, family);
        let row = node.route_udp.as_ref().map(|rows| &rows[scope.udp_index()]);
        if row.is_some_and(|row| row.down_at != 0) {
            return false;
        }
        if sampled || row.is_some_and(|row| row.evidence.recovered != 0) {
            let dns = alive_index(ProbeDomain::DnsUdp, family);
            node[scope.index()].alive
                || (node[dns].alive && node.routed_udp_available(ProbeDomain::DnsUdp, dns))
        } else {
            node[alive_index(ProbeDomain::Tcp, family)].alive
        }
    }

    /// Exact routed evidence must gate even a bare node with DNS-UDP history.
    pub fn routed_udp_node_available(
        &self,
        node: Uuid,
        domain: ProbeDomain,
        family: IpVersion,
    ) -> bool {
        let index = alive_index(domain, family);
        self.states
            .read()
            .get(&node)
            .is_none_or(|slots| slots.routed_udp_available(domain, index))
    }

    /// Legacy leaf eligibility still applies to the logical member. A routed framing fault
    /// is irrelevant when this member is used only to carry another node's packet stream.
    pub(crate) fn udp_carrier_leaf_available(
        &self,
        id: Uuid,
        domain: ProbeDomain,
        family: IpVersion,
    ) -> bool {
        let inherit_tcp = domain == ProbeDomain::DataUdp && !self.has_udp_state(id);
        let states = self.states.read();
        let Some(node) = states.get(&id) else {
            return true;
        };
        if inherit_tcp {
            node[alive_index(ProbeDomain::Tcp, family)].alive
        } else if domain == ProbeDomain::DataUdp {
            node[alive_index(domain, family)].alive
                || node[alive_index(ProbeDomain::DnsUdp, family)].alive
        } else {
            node[alive_index(domain, family)].alive
        }
    }

    pub(crate) fn udp_carrier_available(
        &self,
        node: Uuid,
        domain: ProbeDomain,
        family: IpVersion,
    ) -> bool {
        let index = RouteScope::new(domain, family)
            .with_role(UdpHopRole::Carrier)
            .udp_index();
        self.states
            .read()
            .get(&node)
            .and_then(|slots| slots.route_udp.as_ref())
            .is_none_or(|rows| rows[index].down_at == 0)
    }

    pub fn routed_udp_node_proven(
        &self,
        node: Uuid,
        domain: ProbeDomain,
        family: IpVersion,
    ) -> bool {
        self.routed_udp_hop_proven(node, domain, family, UdpHopRole::Framing)
    }

    pub(in crate::alive) fn routed_udp_hop_proven(
        &self,
        node: Uuid,
        domain: ProbeDomain,
        family: IpVersion,
        role: UdpHopRole,
    ) -> bool {
        if domain == ProbeDomain::Tcp {
            return false;
        }
        let index = RouteScope::new(domain, family).with_role(role).udp_index();
        self.states
            .read()
            .get(&node)
            .and_then(|slots| slots.route_udp.as_ref())
            .is_some_and(|slots| slots[index].evidence.recovered != 0)
    }

    pub(super) fn fail_routed_udp_node(
        &self,
        node: Uuid,
        scope: RouteScope,
        stamp: RouteHealthStamp,
        event: u64,
        shared: Option<(&SharedError, RouteFailureScope)>,
    ) -> Option<bool> {
        if matches!(node, DIRECT_NODE_ID | BLOCK_NODE_ID) {
            return None;
        }
        let grace = self.is_in_grace_period(node);
        let mut states = self.states.write();
        let row = &mut states
            .entry(node)
            .or_insert_with(fresh_states)
            .route_udp
            .get_or_insert_with(Box::default)[scope.udp_index()];
        if !row.evidence.fail(stamp, event, shared) {
            return None;
        }
        if grace {
            return Some(false);
        }
        let threshold = super::traffic_failure_threshold(scope.domain());
        row.failures = row.failures.saturating_add(1);
        if row.failures == 1 {
            self.udp_faults.store(true, Ordering::Release);
        }
        if row.failures == threshold {
            row.down_at = event;
            Some(true)
        } else {
            Some(false)
        }
    }

    pub(super) fn recover_routed_udp_node(
        &self,
        node: Uuid,
        scope: RouteScope,
        stamp: RouteHealthStamp,
        event: u64,
    ) -> Option<(bool, bool)> {
        if matches!(node, DIRECT_NODE_ID | BLOCK_NODE_ID) {
            return None;
        }
        let index = scope.index();
        let result = {
            let mut states = self.states.write();
            let slots = states.entry(node).or_insert_with(fresh_states);
            let framing = scope.role() == UdpHopRole::Framing;
            let legacy_down = framing && !slots[index].alive;
            let row = &mut slots.route_udp.get_or_insert_with(Box::default)[scope.udp_index()];
            let was_alive = row.down_at == 0 && !legacy_down;
            let first = row.evidence.recovered == 0;
            if !row.evidence.recover(stamp, event) {
                return None;
            }
            row.failures = 0;
            row.down_at = 0;
            if framing && !slots[index].is_clean_alive() {
                slots[index].reset_on_success();
            }
            (!was_alive, first)
        };
        if scope.role() == UdpHopRole::Framing
            && let Some(collections) = self.collections.read().get(&node)
        {
            collections[index].reset_dial_fail_streak();
        }
        Some(result)
    }
}

impl AliveDialerSet {
    pub(crate) fn notify_udp_route_change(
        &self,
        attempt: &RouteAttempt<'_>,
        id: Uuid,
        node: bool,
        role: UdpHopRole,
        available: bool,
    ) {
        let current = || {
            let accepts =
                |selector| selector == attempt.selector && self.accepts_route_attempt(attempt);
            if attempt.grouped {
                attempt.manager.with_route_revision(accepts)
            } else {
                accepts(attempt.selector)
            }
        };
        let family = attempt.scope.family();
        if node {
            self.notify_routed_udp_change(
                id,
                attempt.scope.domain(),
                family,
                role,
                available,
                current,
            );
        } else if current() {
            self.notify_route_change(id, family);
        }
    }
}
