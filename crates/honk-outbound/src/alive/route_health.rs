use super::{
    AliveDialerSet, IpVersion, ProbeDomain, alive_index, probe_backoff, traffic_failure_threshold,
};
use crate::SharedError;
use crate::group::{DialKey, GroupManager};
use crate::shared_error::next_episode;
use honk_config::node::MAX_CHAIN_HOPS;
use honk_config::route::Route;
use std::collections::{BTreeMap, btree_map::Entry};
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use uuid::Uuid;

const TCP: ProbeDomain = ProbeDomain::Tcp;

mod udp;
pub(super) use udp::RoutedUdpNode;
pub use udp::{UdpBareReply, UdpHopRole, UdpRouteAdmission};
pub(crate) use udp::{UdpEdges, UdpWitness};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
// Two operation slots per (domain, family); the low bit selects interior carrier work.
pub(crate) struct RouteScope(u8);

impl RouteScope {
    pub(crate) fn new(domain: ProbeDomain, family: IpVersion) -> Self {
        Self((alive_index(domain, family) * 2) as u8)
    }

    fn with_role(self, role: UdpHopRole) -> Self {
        Self((self.0 & !1) | u8::from(role == UdpHopRole::Carrier))
    }

    fn role(self) -> UdpHopRole {
        if self.0 & 1 == 0 {
            UdpHopRole::Framing
        } else {
            UdpHopRole::Carrier
        }
    }

    fn udp_index(self) -> usize {
        usize::from(self.0) - IpVersion::count() * 2
    }

    fn index(self) -> usize {
        usize::from(self.0) / 2
    }

    pub(crate) fn domain(self) -> ProbeDomain {
        [TCP, ProbeDomain::DnsUdp, ProbeDomain::DataUdp][self.index() / IpVersion::count()]
    }

    pub(crate) fn family(self) -> IpVersion {
        [IpVersion::V4, IpVersion::V6][self.index() % IpVersion::count()]
    }
}

pub(crate) struct RouteAttempt<'a> {
    pub manager: &'a GroupManager,
    pub hops: &'a [Uuid],
    pub scope: RouteScope,
    pub selector: u64,
    pub stamp: RouteHealthStamp,
    pub grouped: bool,
}

/// The health generation and Selector revision captured before candidate selection.
#[derive(Clone, Copy, Debug, Default)]
pub struct RouteHealthRevision {
    generation: u64,
    selector: u64,
}

impl RouteHealthRevision {
    /// Allocate an attempt identity while preserving the plan's revision.
    pub fn admit(self) -> RouteHealthStamp {
        RouteHealthStamp {
            generation: self.generation,
            selector: self.selector,
            clock: next_episode(),
        }
    }
}

/// Captured at attempt admission, before any bytes are sent.
#[derive(Clone, Copy, Debug, Default)]
pub struct RouteHealthStamp {
    generation: u64,
    selector: u64,
    /// Unique attempt identity, from the same sequence as shared carrier faults.
    clock: u64,
}

#[derive(Default, Debug, Clone, Copy)]
pub(super) struct Evidence {
    failure: u64,
    /// An older attempt cannot replace a newer proof, except for the proving flow itself.
    recovered: u64,
    proven_attempt: u64,
}

impl Evidence {
    // A proving flow can subsequently fail once, but cannot replay a carrier episode
    // that was already superseded by recovery.
    fn fail(
        &mut self,
        stamp: RouteHealthStamp,
        event: u64,
        shared: Option<(&SharedError, RouteFailureScope)>,
    ) -> bool {
        if (stamp.clock < self.recovered && stamp.clock != self.proven_attempt)
            || shared
                .is_some_and(|(cause, scope)| !cause.claim_route_failure(scope, self.recovered))
        {
            return false;
        }
        if stamp.clock == self.proven_attempt {
            self.proven_attempt = 0;
        }
        self.failure = event;
        true
    }

    fn recover(&mut self, stamp: RouteHealthStamp, event: u64) -> bool {
        if self.failure > stamp.clock {
            return false;
        }
        self.recovered = event;
        self.proven_attempt = stamp.clock;
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Prefix {
    hops: [Uuid; MAX_CHAIN_HOPS],
    len: u8,
    scope: RouteScope,
    // Zero is an ordered-prefix row. A UDP hop witness carries its whole original path
    // and the one-based position of the physical operation which failed.
    hop: u8,
}

impl Prefix {
    fn new(hops: &[Uuid], scope: RouteScope) -> Self {
        let mut slots = [Uuid::nil(); MAX_CHAIN_HOPS];
        slots[..hops.len()].copy_from_slice(hops);
        Self {
            hops: slots,
            len: hops.len() as u8,
            scope,
            hop: 0,
        }
    }

    fn udp_hop(hops: &[Uuid], index: usize, scope: RouteScope) -> Self {
        let scope = scope.with_role(UdpHopRole::at(index, hops.len()));
        Self {
            hop: (index + 1) as u8,
            ..Self::new(hops, scope)
        }
    }

    fn hops(&self) -> &[Uuid] {
        &self.hops[..usize::from(self.len)]
    }

    fn last(self) -> Uuid {
        self.hops[usize::from(if self.hop == 0 { self.len } else { self.hop }) - 1]
    }

    fn family(self) -> IpVersion {
        self.scope.family()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RouteFailureScope {
    health: u64,
    // A single UUID key denotes node evidence. Ordered-prefix refusals have two or more hops.
    prefix: Prefix,
}

pub(crate) fn physical_hops(key: &DialKey) -> &[Uuid] {
    match key {
        DialKey::Route(route) => route.hops(),
        DialKey::Node(id) => std::slice::from_ref(id),
    }
}

struct Witness {
    root: Option<Arc<str>>,
    target: DialKey,
    custom_url: Option<Arc<str>>,
    udp: Option<UdpWitness>,
    active: bool,
}

impl Witness {
    fn new(root: Option<&str>, target: DialKey, custom_url: Option<&str>) -> Box<Self> {
        Box::new(Self {
            root: root.map(Arc::from),
            target,
            custom_url: custom_url.map(Arc::from),
            udp: None,
            active: true,
        })
    }
}

struct Row {
    // Recovery fences still apply to old attempts and shared causes that settle later.
    evidence: Evidence,
    failures: u32,
    // A node-wide failure still belongs to the UUID slot. This only supplies its witness.
    hop_failure: Option<u64>,
    // Set by accepted deregistration, whose cleanup removes the old UUID slot.
    retained_hop: Option<Evidence>,
    witness: Option<Box<Witness>>,
    /// Moved out only during synchronous publication so the original authorized route wins.
    previous: Option<Box<Witness>>,
    admitted: bool,
    claim: Option<u64>,
    due: Instant,
    misses: u32,
}

impl Row {
    fn new(evidence: Evidence) -> Self {
        Self {
            evidence,
            failures: 0,
            hop_failure: None,
            witness: None,
            retained_hop: None,
            previous: None,
            admitted: true,
            claim: None,
            due: Instant::now(),
            misses: 0,
        }
    }

    fn down(&self, key: Prefix) -> bool {
        self.failures >= traffic_failure_threshold(key.scope.domain())
    }

    fn needs_probe(&self, alive: &AliveDialerSet, key: Prefix, started: u64) -> bool {
        self.down(key)
            || self.hop_failure.is_some_and(|event| {
                alive.hop_episode(key, started) == Some(event)
                    && (key.scope.domain() != TCP || !alive.is_registered(key.last()))
            })
    }

    fn discard_stale_hop(&mut self, alive: &AliveDialerSet, key: Prefix) {
        // Between deregistration and publication the episode lives in this row.
        if self.retained_hop.is_none()
            && self.hop_failure.is_some()
            && self.hop_failure != alive.hop_episode(key, u64::MAX)
        {
            self.hop_failure = None;
        }
    }
}

#[derive(Default)]
pub(crate) struct RouteHealth {
    owner: Weak<GroupManager>,
    /// Stable across publications that share the same UUID and prefix health owner.
    id: u64,
    generation: u64,
    selector: u64,
    rows: BTreeMap<Prefix, Row>,
    /// A confirmed-only prefix needs an ordering fence, not a failure row or probe witness.
    positive: BTreeMap<Prefix, (u64, u64)>,
    cursor: Option<Prefix>,
    explicit_udp_dns: Option<Arc<[String]>>,
}

impl RouteHealth {
    fn owner_is(&self, manager: &GroupManager) -> bool {
        std::ptr::eq(self.owner.as_ptr(), manager)
    }

    pub(super) fn retire_owner(&mut self) {
        self.owner = Weak::new();
    }

    fn accepts(&self, manager: &GroupManager, selector: u64, stamp: RouteHealthStamp) -> bool {
        self.owner_is(manager) && self.generation == stamp.generation && selector == stamp.selector
    }

    fn hops_available(&self, hops: &[Uuid], scope: RouteScope) -> bool {
        self.rows.is_empty()
            || (2..=hops.len()).all(|end| {
                let key = Prefix::new(&hops[..end], scope);
                !self.rows.get(&key).is_some_and(|row| row.down(key))
            })
    }

    pub(crate) fn has_tcp_rows(&self) -> bool {
        self.rows.keys().any(|key| key.scope.domain() == TCP)
    }

    pub(crate) fn refresh_udp(
        &mut self,
        mut validate: impl FnMut(&UdpWitness, DialKey) -> Option<bool>,
        mut contains: impl FnMut(&Uuid) -> bool,
    ) {
        for (key, row) in self
            .rows
            .iter_mut()
            .filter(|(key, _)| key.scope.domain() != TCP)
        {
            // A shared prefix can remain down after the selecting root disappears. Its
            // replacement may receive business evidence but cannot inherit probe authority.
            row.admitted = key.hop == 0 && key.hops().iter().all(&mut contains);
            if let Some(mut witness) = row.previous.take()
                && let Some(active) = witness
                    .udp
                    .as_ref()
                    .and_then(|path| validate(path, witness.target))
            {
                row.admitted = true;
                witness.active = active;
                row.witness = Some(witness);
            }
        }
    }

    /// Reattach existing rows only. Keep structural membership even while a Selector pin
    /// is elsewhere, but only an authorized path can become the HTTP witness.
    pub(crate) fn admit(
        &mut self,
        root: &str,
        target: DialKey,
        custom_url: Option<&str>,
        authorized: bool,
    ) {
        let hops = physical_hops(&target);
        for end in 1..=hops.len() {
            for family in [IpVersion::V4, IpVersion::V6] {
                let scope = RouteScope::new(TCP, family);
                let Some(row) = self.rows.get_mut(&Prefix::new(&hops[..end], scope)) else {
                    continue;
                };
                row.admitted = true;
                if !authorized {
                    continue;
                }
                let same_path = |w: &Witness| {
                    row.previous
                        .as_ref()
                        .is_some_and(|prev| prev.root == w.root && prev.target == w.target)
                };
                let original = row.previous.as_ref().is_some_and(|prev| {
                    prev.root.as_deref() == Some(root) && prev.target == target
                });
                let preferred = row.witness.as_ref().is_none_or(|w| {
                    !same_path(w) && w.custom_url.is_none() && custom_url.is_some()
                });
                if original || preferred {
                    row.witness = Some(Witness::new(Some(root), target, custom_url));
                }
            }
        }
    }
}

impl AliveDialerSet {
    pub(super) fn clear_registered_route_health(
        &self,
        route_health: &mut RouteHealth,
        node: Uuid,
        retain: bool,
    ) {
        let mut states = self.states.write();
        let Some(slots) = states.remove(&node) else {
            return;
        };
        if retain {
            for (key, row) in &mut route_health.rows {
                if key.scope.domain() != TCP || key.last() != node {
                    continue;
                }
                let tcp = &slots[alive_index(TCP, key.family())];
                let evidence = slots.route_tcp[key.family() as usize];
                if row.hop_failure == Some(tcp.route_down_at) && !tcp.alive {
                    row.retained_hop = Some(evidence);
                }
            }
        } else if !slots.has_udp_faults() {
            return;
        }
        if let Some(udp) = slots.route_udp {
            states
                .entry(node)
                .or_insert_with(super::fresh_states)
                .route_udp = Some(udp);
        }
    }

    /// Exit-only UUIDs have no registration to retire when topology drops them.
    pub(super) fn prune_unrouted_uuids(&self, mut admitted: impl FnMut(&Uuid) -> bool) {
        let registered = self.registered.read();
        let mut removed = Vec::new();
        self.states.write().retain(|id, slots| {
            if (slots
                .route_tcp
                .iter()
                .any(|e| e.failure != 0 || e.recovered != 0)
                || slots.route_udp.is_some())
                && !registered.nodes.contains_key(id)
                && !admitted(id)
            {
                removed.push(*id);
                if slots.has_udp_faults() {
                    // The next published manager decides whether this UUID still exists as a bare node.
                    let udp = slots.route_udp.take();
                    *slots = super::fresh_states();
                    slots.route_udp = udp;
                    true
                } else {
                    false
                }
            } else {
                true
            }
        });
        for id in removed {
            self.clear_legacy_node_state(id);
        }
    }

    pub fn admitted_udp_check_dns(&self) -> Option<Arc<[String]>> {
        self.route_health.read().explicit_udp_dns.clone()
    }

    pub(crate) fn publish_routes(
        &self,
        manager: &Arc<GroupManager>,
        selector: u64,
        publish_dns: impl FnOnce(&mut Option<Arc<[String]>>),
        mut configured: impl FnMut(&Uuid) -> bool,
        walk: impl FnOnce(&mut RouteHealth),
    ) {
        let mut state = self.route_health.write();
        state.generation = next_episode();
        if state.id == 0 {
            state.id = state.generation;
        }
        if self.may_have_udp_faults() {
            let mut pending = false;
            self.states.write().retain(|id, slots| {
                if !slots.has_udp_faults() {
                    return true;
                }
                if !configured(id) {
                    return false;
                }
                pending = true;
                true
            });
            self.udp_faults
                .store(pending, std::sync::atomic::Ordering::Release);
        }
        state.owner = Arc::downgrade(manager);
        state.selector = selector;
        publish_dns(&mut state.explicit_udp_dns);
        state.positive.clear();
        // Publication fences every former dial; its recovery tombstones can now go.
        state.rows.retain(|key, row| {
            row.discard_stale_hop(self, *key);
            row.failures != 0 || row.hop_failure.is_some() || row.claim.is_some()
        });
        self.refresh_routes(&mut state, walk);
        for (key, row) in &mut state.rows {
            if let (Some(episode), Some(evidence)) = (row.hop_failure, row.retained_hop.take()) {
                let mut states = self.states.write();
                let slots = states.entry(key.last()).or_insert_with(super::fresh_states);
                let tcp = &mut slots[alive_index(TCP, key.family())];
                tcp.alive = false;
                tcp.measured = true;
                tcp.traffic_failures = traffic_failure_threshold(TCP);
                tcp.route_down_at = episode;
                slots.route_tcp[key.family() as usize] = evidence;
            }
        }
    }

    fn refresh_routes(&self, state: &mut RouteHealth, walk: impl FnOnce(&mut RouteHealth)) {
        if state.rows.is_empty() {
            return;
        }
        for row in state.rows.values_mut() {
            row.admitted = false;
            row.previous = row.witness.take();
            // A stale ticket may still own I/O. Its Drop releases the surviving claim.
        }
        walk(state);
        state.rows.retain(|_, row| {
            row.previous = None;
            row.admitted
        });
    }

    pub(crate) fn refresh_route_choices(
        &self,
        manager: &GroupManager,
        selector: u64,
        walk: impl FnOnce(&mut RouteHealth),
    ) {
        let mut state = self.route_health.write();
        if state.owner_is(manager) && state.selector != selector {
            state.selector = selector;
            self.refresh_routes(&mut state, walk);
        }
    }

    pub(crate) fn route_revision(
        &self,
        manager: &GroupManager,
        selector: u64,
    ) -> RouteHealthRevision {
        let state = self.route_health.read();
        if state.owner_is(manager) {
            RouteHealthRevision {
                generation: state.generation,
                selector,
            }
        } else {
            RouteHealthRevision::default()
        }
    }

    pub(crate) fn udp_hop_down(
        &self,
        manager: &GroupManager,
        id: Uuid,
        domain: ProbeDomain,
        family: IpVersion,
        role: UdpHopRole,
    ) -> bool {
        let owner = self.route_health.read();
        owner.owner_is(manager) && self.routed_udp_retirable(id, domain, family, role)
    }

    pub(crate) fn prefix_available(&self, route: &Route, family: IpVersion) -> bool {
        self.hops_available(route.hops(), RouteScope::new(TCP, family))
    }

    pub(crate) fn accepts_route_attempt(&self, attempt: &RouteAttempt<'_>) -> bool {
        self.with_route_authority(attempt, |current| current)
    }

    pub(crate) fn with_route_authority<R>(
        &self,
        attempt: &RouteAttempt<'_>,
        publish: impl FnOnce(bool) -> R,
    ) -> R {
        let state = self.route_health.read();
        publish(state.accepts(attempt.manager, attempt.selector, attempt.stamp))
    }

    pub(crate) fn hops_available(&self, hops: &[Uuid], scope: RouteScope) -> bool {
        self.route_health.read().hops_available(hops, scope)
    }

    pub(crate) fn current_route_eligible(
        &self,
        attempt: &RouteAttempt<'_>,
        nodes_eligible: impl FnOnce() -> bool,
    ) -> bool {
        let state = self.route_health.read();
        state.accepts(attempt.manager, attempt.selector, attempt.stamp)
            && state.hops_available(attempt.hops, attempt.scope)
            && nodes_eligible()
    }
}

pub(crate) struct Failure<'a> {
    pub manager: &'a GroupManager,
    pub witness: (Option<&'a str>, DialKey, Option<&'a str>),
    pub udp: Option<&'a UdpRouteAdmission>,
    pub scope: RouteScope,
    pub hops: &'a [Uuid],
    pub selector: u64,
    pub stamp: RouteHealthStamp,
    pub end: usize,
    pub node: Option<Uuid>,
    pub prefix: bool,
    pub shared: Option<&'a SharedError>,
}

impl AliveDialerSet {
    // Later faults fence in-flight probes without replacing the down edge
    // that owns the witness.
    fn hop_episode(&self, key: Prefix, started: u64) -> Option<u64> {
        let states = self.states.read();
        let slot = states.get(&key.last())?;
        if key.scope.domain() != TCP {
            return slot.udp_hop_episode(key.scope, started);
        }
        let tcp = &slot[alive_index(TCP, key.family())];
        (!tcp.alive
            && tcp.route_down_at != 0
            && slot.route_tcp[key.family() as usize].failure <= started)
            .then_some(tcp.route_down_at)
    }

    /// Return notifications after recording at least one accepted strike under the selector fence.
    pub(crate) fn route_failed(
        &self,
        f: Failure<'_>,
        admitted: impl FnOnce() -> bool,
    ) -> Option<(Option<Uuid>, bool, bool)> {
        let key = if f.scope.domain() != TCP && f.node.is_some() {
            Prefix::udp_hop(f.hops, f.end, f.scope)
        } else {
            Prefix::new(&f.hops[..=f.end], f.scope)
        };
        let mut state = self.route_health.write();
        if !state.accepts(f.manager, f.selector, f.stamp) {
            return None;
        }
        let known = state.selector == f.selector
            && state
                .rows
                .get(&key)
                .and_then(|r| r.witness.as_ref())
                .is_some_and(|w| w.root.as_deref() == f.witness.0 && w.target == f.witness.1);
        if !known && !admitted() {
            return None;
        }
        let event = next_episode();
        let health = state.id;
        let mut counted = None;
        let mut node_changed = false;
        if let Some(node) = f.node {
            let shared = f.shared.map(|cause| {
                (
                    cause,
                    RouteFailureScope {
                        health,
                        prefix: Prefix::new(std::slice::from_ref(&node), key.scope),
                    },
                )
            });
            let domain = f.scope.domain();
            let family = f.scope.family();
            if domain != TCP {
                if let Some(changed) =
                    self.fail_routed_udp_node(node, key.scope, f.stamp, event, shared)
                {
                    counted = Some(node);
                    node_changed = changed;
                    if key.scope.role() == UdpHopRole::Framing {
                        self.record_dial_failure(node, domain, family);
                    }
                }
            } else if self
                .states
                .write()
                .entry(node)
                .or_insert_with(super::fresh_states)
                .route_tcp[family as usize]
                .fail(f.stamp, event, shared)
            {
                counted = Some(node);
                node_changed = self.mark_routed_unavailable_state(node, family, event);
                self.record_dial_failure(node, TCP, family);
                if self.is_registered(node) {
                    self.notify_check_tcp(node);
                }
            }
        }
        let new_hop = node_changed && f.node == Some(key.last());
        if !new_hop && !f.prefix {
            return counted.map(|node| (Some(node), node_changed, false));
        }
        let fail_prefix = |evidence: &mut Evidence| {
            f.prefix
                && evidence.fail(
                    f.stamp,
                    event,
                    f.shared.map(|cause| {
                        (
                            cause,
                            RouteFailureScope {
                                health,
                                prefix: key,
                            },
                        )
                    }),
                )
        };
        let RouteHealth { rows, positive, .. } = &mut *state;
        let (row, prefix_failed) = match rows.entry(key) {
            Entry::Occupied(entry) => {
                let row = entry.into_mut();
                let failed = fail_prefix(&mut row.evidence);
                (row, failed)
            }
            Entry::Vacant(entry) => {
                let watermark = positive.entry(key);
                let (recovered, proven_attempt) = match &watermark {
                    Entry::Occupied(entry) => *entry.get(),
                    Entry::Vacant(_) => (0, 0),
                };
                let mut evidence = Evidence {
                    recovered,
                    proven_attempt,
                    ..Evidence::default()
                };
                let failed = fail_prefix(&mut evidence);
                if !new_hop && !failed {
                    return counted.map(|node| (Some(node), node_changed, false));
                }
                if let Entry::Occupied(watermark) = watermark {
                    watermark.remove();
                }
                (entry.insert(Row::new(evidence)), failed)
            }
        };
        if new_hop {
            row.hop_failure = Some(event);
        }
        let was_down = row.down(key);
        if prefix_failed {
            row.failures = row.failures.saturating_add(1);
        }
        let prefix_changed = prefix_failed && !was_down && row.down(key);
        if f.udp.is_some() && (new_hop || (prefix_failed && row.failures == 1)) {
            let mut witness = Witness::new(None, f.witness.1, None);
            witness.udp = f.udp.map(|admission| f.manager.own_udp_witness(admission));
            row.witness = Some(witness);
        } else if f.udp.is_none() && !known && (new_hop || (prefix_failed && !was_down)) {
            let (root, target, url) = f.witness;
            row.witness = Some(Witness::new(root, target, url));
        }
        (counted.is_some() || prefix_failed).then_some((counted, node_changed, prefix_changed))
    }

    pub(crate) fn notify_route_failure(
        &self,
        manager: &GroupManager,
        stamp: RouteHealthStamp,
        node: Option<Uuid>,
        hop: Uuid,
        family: IpVersion,
    ) {
        if let Some(id) = node {
            self.notify_health_change(id, TCP, family, false, || {
                let state = self.route_health.read();
                state.owner_is(manager) && state.generation == stamp.generation
            });
        } else {
            self.notify_route_change(hop, family);
        }
    }

    fn recover_node(
        &self,
        id: Uuid,
        family: IpVersion,
        stamp: RouteHealthStamp,
        event: u64,
        episode: Option<u64>,
    ) -> Option<bool> {
        let idx = alive_index(TCP, family);
        let changed = {
            let mut states = self.states.write();
            let slots = if let Some(epoch) = episode {
                let slots = states.get_mut(&id)?;
                if slots[idx].alive || slots[idx].route_down_at != epoch {
                    return None;
                }
                slots
            } else {
                states.entry(id).or_insert_with(super::fresh_states)
            };
            if !slots.route_tcp[family as usize].recover(stamp, event) {
                return None;
            }
            let tcp = &mut slots[idx];
            let changed = !tcp.alive;
            if !tcp.is_clean_alive() {
                tcp.reset_on_success();
            }
            changed
        };
        if let Some(collections) = self.collections.read().get(&id) {
            collections[idx].reset_dial_fail_streak();
        }
        Some(changed)
    }

    pub(crate) fn route_response(
        &self,
        manager: &GroupManager,
        key: DialKey,
        family: IpVersion,
        selector: u64,
        stamp: RouteHealthStamp,
        dial_latency: Option<Duration>,
    ) -> Vec<(Uuid, bool)> {
        let attempt = RouteAttempt {
            manager,
            hops: physical_hops(&key),
            scope: RouteScope::new(TCP, family),
            selector,
            stamp,
            grouped: true,
        };
        self.confirm_route(
            &attempt,
            std::iter::once(key.success_owner())
                .chain(key.proven())
                .map(|id| (id, UdpHopRole::Framing)),
            dial_latency.map(|elapsed| (key.success_owner(), elapsed)),
        )
    }

    pub(crate) fn confirm_route(
        &self,
        attempt: &RouteAttempt<'_>,
        owners: impl Iterator<Item = (Uuid, UdpHopRole)>,
        dial_latency: Option<(Uuid, Duration)>,
    ) -> Vec<(Uuid, bool)> {
        let RouteAttempt {
            manager,
            hops,
            scope,
            selector,
            stamp,
            ..
        } = *attempt;
        let family = scope.family();
        let mut state = self.route_health.write();
        let mut changes = Vec::new();
        if !state.accepts(manager, selector, stamp) {
            return changes;
        }
        let event = next_episode();
        for end in 1..=hops.len() {
            let prefix = Prefix::new(&hops[..end], scope);
            let Some(row) = state.rows.get_mut(&prefix) else {
                if end > 1 {
                    state.positive.insert(prefix, (event, stamp.clock));
                }
                continue;
            };
            if row.evidence.recover(stamp, event) {
                if row.down(prefix) {
                    changes.push((hops[end - 1], false));
                }
                row.failures = 0;
                row.misses = 0;
                row.due = Instant::now();
            }
            row.discard_stale_hop(self, prefix);
        }
        for (id, role) in owners {
            if scope.domain() != TCP {
                if let Some((flipped, first)) =
                    self.recover_routed_udp_node(id, scope.with_role(role), stamp, event)
                    && (flipped || (first && role == UdpHopRole::Framing))
                {
                    if let Some((_, physical)) = changes.iter_mut().find(|(node, _)| *node == id) {
                        *physical = true;
                    } else {
                        changes.push((id, true));
                    }
                }
                continue;
            }
            let Some(changed) = self.recover_node(id, family, stamp, event, None) else {
                continue;
            };
            if changed {
                changes.push((id, true));
                for (end, &hop) in hops.iter().enumerate() {
                    if hop == id
                        && let Some(row) = state.rows.get_mut(&Prefix::new(&hops[..=end], scope))
                    {
                        row.hop_failure = None;
                    }
                }
            }
            if let Some((_, elapsed)) = dial_latency.filter(|(exit, _)| *exit == id)
                && self.report_dial_latency(id, TCP, family, elapsed)
                && self.is_registered(id)
            {
                self.notify_check_tcp(id);
            }
        }
        changes
    }

    pub(crate) fn notify_route_response(
        &self,
        manager: &GroupManager,
        stamp: RouteHealthStamp,
        family: IpVersion,
        changes: Vec<(Uuid, bool)>,
    ) {
        for (id, node) in changes {
            if node {
                self.notify_health_change(id, TCP, family, true, || {
                    let state = self.route_health.read();
                    state.owner_is(manager) && state.generation == stamp.generation
                });
            } else {
                self.notify_route_change(id, family);
            }
        }
    }
}

/// One reservation in the existing recovery pool. Dropping it never changes liveness.
pub struct RouteProbeTicket {
    alive: Arc<AliveDialerSet>,
    manager: Arc<GroupManager>,
    key: Prefix,
    claim: u64,
    stamp: RouteHealthStamp,
    target: DialKey,
    family: IpVersion,
    destination: RouteProbeDestination,
}

enum RouteProbeDestination {
    Http(Arc<str>),
    Udp(Arc<[String]>),
}

/// Notify observers of settled UDP health changes after releasing the caller's guards.
#[must_use]
pub struct UdpHealthNotifications<'a> {
    alive: &'a AliveDialerSet,
    attempt: RouteAttempt<'a>,
    changes: Vec<(Uuid, bool)>,
}

impl<'a> UdpHealthNotifications<'a> {
    pub(crate) fn new(
        alive: &'a AliveDialerSet,
        attempt: RouteAttempt<'a>,
        changes: Vec<(Uuid, bool)>,
    ) -> Self {
        Self {
            alive,
            attempt,
            changes,
        }
    }

    pub fn notify(self) {
        for (id, node) in self.changes {
            self.alive.notify_udp_route_change(
                &self.attempt,
                id,
                node,
                self.attempt.scope.role(),
                true,
            );
        }
    }
}

impl AliveDialerSet {
    pub fn take_route_probe(self: &Arc<Self>) -> Option<RouteProbeTicket> {
        let manager = {
            let state = self.route_health.read();
            if state.rows.is_empty() {
                return None;
            }
            state.owner.upgrade()?
        };
        manager.refresh_route_choices();
        manager.with_route_revision(|selector| {
            let mut state = self.route_health.write();
            if !state.owner_is(&manager) || state.selector != selector {
                return None;
            }
            let mode = self.health_mode.borrow();
            if *mode != super::runner::HealthMode::Running {
                return None;
            }
            let now = Instant::now();
            let global = self.check_url.read();
            let bound = state.cursor.map_or(Unbounded, Excluded);
            let due = |(key, row): (&Prefix, &Row)| {
                let witness = row.witness.as_ref()?;
                (witness.active
                    && row.claim.is_none()
                    && row.due <= now
                    && row.needs_probe(self, *key, u64::MAX)
                    && if key.scope.domain() == TCP {
                        witness.custom_url.is_some() || !global.is_empty()
                    } else {
                        state
                            .explicit_udp_dns
                            .as_ref()
                            .is_some_and(|targets| !targets.is_empty())
                    })
                .then_some(*key)
            };
            let key = state
                .rows
                .range((bound, Unbounded))
                .find_map(due)
                .or_else(|| state.rows.range(..=state.cursor?).find_map(due))?;
            let claim = next_episode();
            let stamp = RouteHealthStamp {
                generation: state.generation,
                selector,
                clock: claim,
            };
            let dns = state.explicit_udp_dns.clone();
            state.cursor = Some(key);
            let row = state.rows.get_mut(&key)?;
            let witness = row.witness.as_ref()?;
            let destination = if key.scope.domain() == TCP {
                RouteProbeDestination::Http(
                    witness
                        .custom_url
                        .clone()
                        .unwrap_or_else(|| Arc::from(global.as_str())),
                )
            } else {
                RouteProbeDestination::Udp(dns?)
            };
            row.claim = Some(claim);
            row.due = now + self.base_cooldown;
            Some(RouteProbeTicket {
                alive: Arc::clone(self),
                manager: Arc::clone(&manager),
                key,
                claim,
                stamp,
                target: witness.target,
                family: key.family(),
                destination,
            })
        })
    }
}

impl RouteProbeTicket {
    pub fn target(&self) -> DialKey {
        self.target
    }

    pub fn family(&self) -> IpVersion {
        self.family
    }

    pub fn url(&self) -> &str {
        match &self.destination {
            RouteProbeDestination::Http(url) => url,
            RouteProbeDestination::Udp(_) => "",
        }
    }

    pub fn domain(&self) -> ProbeDomain {
        self.key.scope.domain()
    }

    pub fn udp_check_dns(&self) -> Option<&[String]> {
        match &self.destination {
            RouteProbeDestination::Udp(dns) => Some(dns),
            RouteProbeDestination::Http(_) => None,
        }
    }

    fn matches(&self, state: &RouteHealth, selector: u64) -> bool {
        state.accepts(&self.manager, selector, self.stamp)
            && state.rows.get(&self.key).is_some_and(|row| {
                row.claim == Some(self.claim)
                    && row.needs_probe(&self.alive, self.key, self.stamp.clock)
                    && row.evidence.failure <= self.stamp.clock
                    && row
                        .hop_failure
                        .is_none_or(|epoch| epoch <= self.stamp.clock)
            })
    }

    pub fn is_current(&self) -> bool {
        self.manager.with_route_revision(|selector| {
            let state = self.alive.route_health.read();
            self.matches(&state, selector)
                && *self.alive.health_mode.borrow() == super::runner::HealthMode::Running
        })
    }

    pub fn is_current_for(&self, manager: &Arc<GroupManager>) -> bool {
        Arc::ptr_eq(&self.manager, manager) && self.is_current()
    }

    pub fn finish(self, success: bool) {
        if self.domain() == TCP {
            let changes = self.settle(success, None);
            self.alive
                .notify_route_response(&self.manager, self.stamp, self.family, changes);
        }
    }

    /// Core verifies the matching live manager/runtime under its read guards for this call.
    pub fn settle_udp(
        &self,
        success: bool,
        deadline: tokio::time::Instant,
        cancel: &super::ProbeCancellation,
    ) -> UdpHealthNotifications<'_> {
        let changes = if self.domain() != TCP {
            self.settle(success, Some((deadline, cancel)))
        } else {
            Vec::new()
        };
        let attempt = RouteAttempt {
            manager: &self.manager,
            hops: self.key.hops(),
            scope: self.key.scope,
            selector: self.stamp.selector,
            stamp: self.stamp,
            grouped: true,
        };
        UdpHealthNotifications::new(&self.alive, attempt, changes)
    }

    fn settle(
        &self,
        success: bool,
        udp: Option<(tokio::time::Instant, &super::ProbeCancellation)>,
    ) -> Vec<(Uuid, bool)> {
        let mut changes = Vec::new();
        self.manager.with_route_revision(|selector| {
            let mut state = self.alive.route_health.write();
            if udp.is_some_and(|(_, cancel)| cancel.is_cancelled()) { return; }
            let mode = self.alive.health_mode.borrow();
            if *mode != super::runner::HealthMode::Running || !self.matches(&state, selector)
                // A silent, still-authorized exchange finishes at its deadline and backs off.
                // A reply first committed at or after that same instant cannot revive a path.
                || (success && udp.is_some_and(|(deadline, _)| tokio::time::Instant::now() >= deadline)) {
                return;
            }
            let event = next_episode();
            let row = state.rows.get_mut(&self.key).expect("matched claim");
            row.claim = None;
            if !success {
                row.misses = row.misses.saturating_add(1);
                row.due = Instant::now()
                    + probe_backoff(
                        self.alive.base_cooldown,
                        self.alive.max_cooldown,
                        row.misses,
                    );
                return;
            }
            let id = self.key.last();
            if row.down(self.key) && row.evidence.recover(self.stamp, event) {
                row.failures = 0;
                changes.push((id, false));
            }
            if self.domain() != TCP {
                if row.hop_failure.is_some_and(|epoch| self.alive.hop_episode(self.key, self.stamp.clock) == Some(epoch))
                    && let Some((changed, _)) = self.alive.recover_routed_udp_node(id, self.key.scope, self.stamp, event) {
                    row.hop_failure = None;
                    if changed { changes.push((id, true)); }
                }
            } else if let Some(epoch) = row.hop_failure
                && self.alive.recover_node(id, self.family, self.stamp, event, Some(epoch))
                    == Some(true)
            {
                row.hop_failure = None;
                changes.push((id, true));
            } else {
                row.discard_stale_hop(&self.alive, self.key);
            }
            row.misses = 0;
        });
        changes
    }
}

impl Drop for RouteProbeTicket {
    fn drop(&mut self) {
        let mut state = self.alive.route_health.write();
        if let Some(row) = state.rows.get_mut(&self.key)
            && row.claim == Some(self.claim)
        {
            row.claim = None;
            row.discard_stale_hop(&self.alive, self.key);
        }
    }
}

#[cfg(test)]
mod tests;
