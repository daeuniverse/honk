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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Prefix {
    hops: [Uuid; MAX_CHAIN_HOPS],
    len: u8,
    family: u8,
}

impl Prefix {
    fn new(hops: &[Uuid], family: IpVersion) -> Self {
        let mut slots = [Uuid::nil(); MAX_CHAIN_HOPS];
        slots[..hops.len()].copy_from_slice(hops);
        Self {
            hops: slots,
            len: hops.len() as u8,
            family: family as u8,
        }
    }

    fn last(self) -> Uuid {
        self.hops[self.len as usize - 1]
    }

    fn family(self) -> IpVersion {
        [IpVersion::V4, IpVersion::V6][self.family as usize]
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
    root: Arc<str>,
    target: DialKey,
    custom_url: Option<Arc<str>>,
}

impl Witness {
    fn new(root: &str, target: DialKey, custom_url: Option<&str>) -> Box<Self> {
        Box::new(Self {
            root: root.into(),
            target,
            custom_url: custom_url.map(Arc::from),
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

    fn down(&self) -> bool {
        self.failures >= traffic_failure_threshold(TCP)
    }

    fn needs_probe(&self, alive: &AliveDialerSet, key: Prefix, started: u64) -> bool {
        self.down()
            || self.hop_failure.is_some_and(|event| {
                alive.hop_episode(key, started) == Some(event) && !alive.is_registered(key.last())
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
                let Some(row) = self.rows.get_mut(&Prefix::new(&hops[..end], family)) else {
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
                let original = row
                    .previous
                    .as_ref()
                    .is_some_and(|prev| prev.root.as_ref() == root && prev.target == target);
                let preferred = row.witness.as_ref().is_none_or(|w| {
                    !same_path(w) && w.custom_url.is_none() && custom_url.is_some()
                });
                if original || preferred {
                    row.witness = Some(Witness::new(root, target, custom_url));
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
        if !retain {
            return;
        }
        for (key, row) in &mut route_health.rows {
            if key.last() != node {
                continue;
            }
            let tcp = &slots[alive_index(TCP, key.family())];
            let evidence = slots.route_tcp[key.family as usize];
            if row.hop_failure == Some(tcp.route_down_at) && !tcp.alive {
                row.retained_hop = Some(evidence);
            }
        }
    }

    /// Exit-only UUIDs have no registration to retire when topology drops them.
    pub(super) fn prune_unrouted_uuids(&self, mut admitted: impl FnMut(&Uuid) -> bool) {
        let registered = self.registered.read();
        let mut removed = Vec::new();
        self.states.write().retain(|id, slots| {
            if slots
                .route_tcp
                .iter()
                .any(|e| e.failure != 0 || e.recovered != 0)
                && !registered.nodes.contains_key(id)
                && !admitted(id)
            {
                removed.push(*id);
                false
            } else {
                true
            }
        });
        for id in removed {
            self.clear_legacy_node_state(id);
        }
    }

    pub(crate) fn publish_routes(
        &self,
        manager: &Arc<GroupManager>,
        selector: u64,
        walk: impl FnOnce(&mut RouteHealth),
    ) {
        let mut state = self.route_health.write();
        state.generation = next_episode();
        if state.id == 0 {
            state.id = state.generation;
        }
        state.owner = Arc::downgrade(manager);
        state.selector = selector;
        state.positive.clear();
        // Publication fences every former dial; its recovery tombstones can now go.
        state.rows.retain(|key, row| {
            row.discard_stale_hop(self, *key);
            row.failures != 0 || row.hop_failure.is_some() || row.claim.is_some()
        });
        Self::refresh_routes(&mut state, walk);
        for (key, row) in &mut state.rows {
            if let (Some(episode), Some(evidence)) = (row.hop_failure, row.retained_hop.take()) {
                let mut states = self.states.write();
                let slots = states.entry(key.last()).or_insert_with(super::fresh_states);
                let tcp = &mut slots[alive_index(TCP, key.family())];
                tcp.alive = false;
                tcp.traffic_failures = traffic_failure_threshold(TCP);
                tcp.route_down_at = episode;
                slots.route_tcp[key.family as usize] = evidence;
            }
        }
    }

    fn refresh_routes(state: &mut RouteHealth, walk: impl FnOnce(&mut RouteHealth)) {
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
            Self::refresh_routes(&mut state, walk);
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

    pub(crate) fn prefix_available(&self, route: &Route, family: IpVersion) -> bool {
        let state = self.route_health.read();
        state.rows.is_empty()
            || (2..=route.hops().len()).all(|end| {
                !state
                    .rows
                    .get(&Prefix::new(&route.hops()[..end], family))
                    .is_some_and(Row::down)
            })
    }
}

pub(crate) struct Failure<'a> {
    pub manager: &'a GroupManager,
    pub root: &'a str,
    pub target: DialKey,
    pub family: IpVersion,
    pub selector: u64,
    pub stamp: RouteHealthStamp,
    pub custom_url: Option<&'a str>,
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
        let tcp = &slot[alive_index(TCP, key.family())];
        (!tcp.alive
            && tcp.route_down_at != 0
            && slot.route_tcp[key.family as usize].failure <= started)
            .then_some(tcp.route_down_at)
    }

    /// Return notifications after recording at least one accepted strike under the selector fence.
    pub(crate) fn route_failed(
        &self,
        f: Failure<'_>,
        admitted: impl FnOnce() -> bool,
    ) -> Option<(Option<Uuid>, bool, bool)> {
        let key = Prefix::new(&physical_hops(&f.target)[..=f.end], f.family);
        let mut state = self.route_health.write();
        if !state.accepts(f.manager, f.selector, f.stamp) {
            return None;
        }
        let known = state.selector == f.selector
            && state
                .rows
                .get(&key)
                .and_then(|r| r.witness.as_ref())
                .is_some_and(|w| w.root.as_ref() == f.root && w.target == f.target);
        if !known && !admitted() {
            return None;
        }
        let event = next_episode();
        let health = state.id;
        let make_witness = || Witness::new(f.root, f.target, f.custom_url);
        let mut counted = None;
        let mut node_changed = false;
        if let Some(node) = f.node {
            let shared = f.shared.map(|cause| {
                (
                    cause,
                    RouteFailureScope {
                        health,
                        prefix: Prefix::new(std::slice::from_ref(&node), f.family),
                    },
                )
            });
            let accepted = self
                .states
                .write()
                .entry(node)
                .or_insert_with(super::fresh_states)
                .route_tcp[f.family as usize]
                .fail(f.stamp, event, shared);
            if accepted {
                counted = Some(node);
                node_changed = self.mark_routed_unavailable_state(node, f.family, event);
                self.record_dial_failure(node, TCP, f.family);
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
        let was_down = row.down();
        if prefix_failed {
            row.failures = row.failures.saturating_add(1);
        }
        let prefix_changed = prefix_failed && !was_down && row.down();
        if !known && (new_hop || (prefix_failed && !was_down)) {
            row.witness = Some(make_witness());
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
        let mut state = self.route_health.write();
        let mut changes = Vec::new();
        if !state.accepts(manager, selector, stamp) {
            return changes;
        }
        let event = next_episode();
        let hops = physical_hops(&key);
        for end in 1..=hops.len() {
            let prefix = Prefix::new(&hops[..end], family);
            let Some(row) = state.rows.get_mut(&prefix) else {
                if end > 1 {
                    state.positive.insert(prefix, (event, stamp.clock));
                }
                continue;
            };
            if row.evidence.recover(stamp, event) {
                if row.down() {
                    changes.push((hops[end - 1], false));
                }
                row.failures = 0;
                row.misses = 0;
                row.due = Instant::now();
            }
            row.discard_stale_hop(self, prefix);
        }
        let exit = key.success_owner();
        for id in std::iter::once(exit).chain(key.proven()) {
            let Some(changed) = self.recover_node(id, family, stamp, event, None) else {
                continue;
            };
            if changed {
                changes.push((id, true));
                for (end, &hop) in hops.iter().enumerate() {
                    if hop == id
                        && let Some(row) = state.rows.get_mut(&Prefix::new(&hops[..=end], family))
                    {
                        row.hop_failure = None;
                    }
                }
            }
            if id == exit
                && let Some(elapsed) = dial_latency
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
    url: Arc<str>,
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
                (row.claim.is_none()
                    && row.due <= now
                    && row.needs_probe(self, *key, u64::MAX)
                    && (witness.custom_url.is_some() || !global.is_empty()))
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
            state.cursor = Some(key);
            let row = state.rows.get_mut(&key)?;
            let witness = row.witness.as_ref()?;
            let url = witness
                .custom_url
                .clone()
                .unwrap_or_else(|| Arc::from(global.as_str()));
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
                url,
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
        &self.url
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
        let mut changes = Vec::new();
        self.manager.with_route_revision(|selector| {
            let mut state = self.alive.route_health.write();
            let mode = self.alive.health_mode.borrow();
            if *mode != super::runner::HealthMode::Running || !self.matches(&state, selector) {
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
            if row.down() && row.evidence.recover(self.stamp, event) {
                row.failures = 0;
                changes.push((id, false));
            }
            if let Some(epoch) = row.hop_failure
                && self
                    .alive
                    .recover_node(id, self.family, self.stamp, event, Some(epoch))
                    == Some(true)
            {
                row.hop_failure = None;
                changes.push((id, true));
            } else {
                row.discard_stale_hop(&self.alive, self.key);
            }
            row.misses = 0;
        });
        self.alive
            .notify_route_response(&self.manager, self.stamp, self.family, changes);
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
