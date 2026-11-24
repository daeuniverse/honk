use crate::alive::route_health::{Failure, RouteHealth, physical_hops};
use crate::alive::{IpVersion, RouteHealthRevision, RouteHealthStamp};
use crate::group::{
    DialKey, GroupManager, GroupMember, MAX_GROUP_DEPTH, OwnedTarget, SelectionNetwork,
    SelectorState, SelectorStorage,
};
use crate::proxy::{
    DialFailureScope, dial_failure_scope, node_failure_cause, shared_failure_cause,
};
use honk_config::group::{Group, GroupPolicy};
use honk_config::group_graph::Composed;
use honk_config::route::Route;
use std::error::Error;
use std::sync::Arc;

fn custom_url(group: &Group) -> Option<&str> {
    group
        .check_url
        .as_deref()
        .filter(|url| group.policy != GroupPolicy::Selector && !url.is_empty())
}

impl GroupManager {
    /// Publish only after admission, under the same writer as health registrations.
    pub fn publish_route_health(self: &Arc<Self>) {
        if let Some(alive) = &self.alive_set {
            let selector = self.selector_choice.read();
            alive.publish_routes(self, selector.revision, |state| {
                self.attach_witnesses(state, &selector)
            });
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
        self.with_routed_selector(root, |_, revision| revision)
    }

    pub(in crate::group) fn route_plan_snapshot(
        &self,
        root: &str,
        network: SelectionNetwork,
    ) -> (Option<Arc<SelectorState>>, RouteHealthRevision) {
        if network != SelectionNetwork::Tcp {
            return Default::default();
        }
        self.with_routed_selector(root, |state, revision| (Some(Arc::clone(state)), revision))
    }

    fn with_routed_selector<T: Default>(
        &self,
        root: &str,
        capture: impl FnOnce(&Arc<SelectorState>, RouteHealthRevision) -> T,
    ) -> T {
        if !self.has_exits() || self.groups.get(root).is_none_or(|entry| !entry.routes) {
            return T::default();
        }
        let selector = self.selector_choice.read();
        let SelectorStorage::Shared(state) = &*selector else {
            unreachable!("a manager with exits publishes shared selector state");
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
            root: root_group,
            target: key,
            family,
            selector: selector.revision,
            stamp,
            custom_url: custom_url(root),
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
