use std::collections::BTreeSet;
use std::ops::ControlFlow;

use honk_config::group_graph::{GroupGraph, Leaf, Step, Visitor};

use super::*;

/// Leaf ids `group` reaches through membership and explicit final edges.
/// This walks the configuration's graph, whose cycles GroupManager's copy
/// cuts, so the leaf sets (and the eBPF outbound ids built from them) do
/// not depend on which back edge that cut removed. Exits are not followed:
/// health is registered on leaves only.
fn group_leaf_ids(graph: &GroupGraph<'_>, group: usize) -> BTreeSet<uuid::Uuid> {
    struct Leaves<'g, 'a> {
        graph: &'g GroupGraph<'a>,
        path: Vec<&'a str>,
        ids: BTreeSet<uuid::Uuid>,
    }
    impl Visitor for Leaves<'_, '_> {
        // Groups of one name share a path entry, as when groups were
        // looked up by name.
        fn enter(&mut self, group: usize, depth: usize, _: &[uuid::Uuid]) -> ControlFlow<(), Step> {
            let name = self.graph.name(group);
            self.path.truncate(depth);
            if self.path.contains(&name) {
                return ControlFlow::Continue(Step::Skip);
            }
            self.path.push(name);
            ControlFlow::Continue(Step::Descend)
        }

        fn leaf(&mut self, leaf: Leaf, _: &[uuid::Uuid]) -> ControlFlow<()> {
            self.ids.insert(match leaf {
                Leaf::Node(id) => id,
                Leaf::Direct => honk_config::config::DIRECT_NODE_ID,
                Leaf::Block => honk_config::config::BLOCK_NODE_ID,
            });
            ControlFlow::Continue(())
        }
    }
    let mut leaves = Leaves {
        graph,
        path: Vec::with_capacity(honk_outbound::group::MAX_GROUP_DEPTH),
        ids: BTreeSet::new(),
    };
    let _ = graph.visit(group, &mut leaves);
    leaves.ids
}

/// Nodes reachable through group membership or explicit finals are probed
/// for alive display and recovery, including Selector leaves. Ungrouped
/// nodes are skipped unless no reachable leaves exist. An exit-only node
/// is never added to the raw probe set by that fallback.
pub(in crate::control) fn health_registrations<'a>(
    config: &'a Config,
    reachable: &OutboundHealthIndex,
) -> std::collections::HashMap<uuid::Uuid, (&'a str, Option<&'a str>)> {
    let exits: BTreeSet<_> = if reachable.is_empty() {
        config
            .groups
            .iter()
            .filter_map(|group| group.exit.as_deref())
            .collect()
    } else {
        BTreeSet::new()
    };
    config
        .nodes
        .iter()
        .filter(|node| {
            reachable.contains_key(&node.id)
                || (reachable.is_empty() && !exits.contains(node.name.as_str()))
        })
        .map(|node| {
            let address = (node.protocol() != NodeProtocol::Chain).then_some(node.address.as_str());
            (node.id, (node.name.as_str(), address))
        })
        .collect()
}

#[cfg(test)]
pub(in crate::control) fn sync_health_check_nodes(
    alive_set: &AliveDialerSet,
    config: &Config,
) -> (usize, usize) {
    let leaves = build_outbound_id_map(config);
    alive_set.sync_registrations(health_registrations(config, &leaves))
}

/// Direct idle-group registrations for the alive set, covering every policy.
///
/// Each entry lists only that group's direct node members and any direct-node
/// `final` edge so activating an automatic group wakes its own members while
/// chosen subgroups activate on traversal, and `Selector` groups stay isolated
/// to their fixed selections. Automatic groups also carry their reachable
/// non-builtin TCP and UDP recovery leaves for datapath-parity idle recovery.
pub(in crate::control) fn idle_group_registrations(
    config: &Config,
) -> Vec<honk_outbound::alive::IdleGroupRegistration> {
    let graph = GroupGraph::new(&config.groups, &config.nodes);
    let node_by_id: std::collections::HashMap<uuid::Uuid, &honk_config::node::Node> =
        config.nodes.iter().map(|node| (node.id, node)).collect();
    config
        .groups
        .iter()
        .enumerate()
        .map(|(index, group)| {
            let mut members: BTreeSet<uuid::Uuid> = group.nodes.iter().copied().collect();
            match group.final_outbound.as_deref() {
                None => {}
                Some(Config::BUILTIN_DIRECT_NODE) => {
                    members.insert(honk_config::config::DIRECT_NODE_ID);
                }
                Some(Config::BUILTIN_BLOCK_NODE) => {
                    members.insert(honk_config::config::BLOCK_NODE_ID);
                }
                Some(name) => {
                    if let Some(node) = config.nodes.iter().find(|node| node.name == name) {
                        members.insert(node.id);
                    }
                }
            }
            let (kind, tcp_recovery_members, udp_recovery_members) =
                if group.policy == GroupPolicy::Selector {
                    (
                        honk_outbound::alive::IdleGroupKind::Selector,
                        Vec::new(),
                        Vec::new(),
                    )
                } else {
                    let tcp: Vec<uuid::Uuid> = group_leaf_ids(&graph, index)
                        .into_iter()
                        .filter(|id| {
                            *id != honk_config::config::DIRECT_NODE_ID
                                && *id != honk_config::config::BLOCK_NODE_ID
                        })
                        .collect();
                    let udp: Vec<uuid::Uuid> = tcp
                        .iter()
                        .copied()
                        .filter(|id| {
                            node_by_id.get(id).is_some_and(|node| {
                                honk_outbound::descriptor::node_carries_udp(node, |hop| {
                                    node_by_id.get(hop).copied()
                                })
                            })
                        })
                        .collect();
                    (honk_outbound::alive::IdleGroupKind::Automatic, tcp, udp)
                };
            honk_outbound::alive::IdleGroupRegistration {
                name: group.name.clone(),
                members: members.into_iter().collect(),
                idle_timeout: group.idle_timeout.map(std::time::Duration::from_secs),
                kind,
                tcp_recovery_members,
                udp_recovery_members,
            }
        })
        .collect()
}

/// Build `(group name, check_url)` for every group with a custom
/// `check_url` (sing-box urltest `url` option) — the input to
/// [`AliveDialerSet::sync_group_check_urls`]. Selector groups are
/// excluded (their check_url is ignored, sing-box parity). Members are
/// resolved dynamically each probe cycle through the group manager (the
/// url member resolver installed in `ControlPlane`), so sub-group picks
/// never go stale here.
pub(in crate::control) fn group_check_url_registrations(config: &Config) -> Vec<(String, String)> {
    config
        .groups
        .iter()
        .filter(|g| g.policy != GroupPolicy::Selector && g.check_url.is_some())
        .map(|group| {
            (
                group.name.clone(),
                group.check_url.clone().unwrap_or_default(),
            )
        })
        .collect()
}

/// Publish idle-group membership, custom `check_url` targets, and fixed probe
/// selections under the caller's publication guards. Call `wake()` on the
/// returned token only after dropping those guards.
pub(in crate::control) fn publish_group_probe_state(
    alive_set: &AliveDialerSet,
    group_manager: &GroupManager,
    idle_groups: &[honk_outbound::alive::IdleGroupRegistration],
    check_urls: &[(String, String)],
) -> honk_outbound::group::SelectedProbeWake {
    alive_set.sync_idle_groups(idle_groups);
    alive_set.sync_group_check_urls(check_urls);
    group_manager.stage_selected_probe_wake()
}

/// Automatic policy changes cancel captured group/network owners without rebuilding provenance.
pub(in crate::control) fn install_interrupt_callback(
    group_manager: &GroupManager,
    groups: &[honk_config::group::Group],
    tracker: &Arc<ConnectionTracker>,
    diagnostics: &crate::config_diagnostics::SharedDiagnostics,
    generation: u64,
    #[cfg(feature = "native-api")] native: Option<&Arc<crate::observe::Observation>>,
) {
    if group_manager.has_interrupt_connections() {
        tracker.enable_for_interrupts();
    }
    let identities: std::collections::HashMap<_, _> = groups
        .iter()
        .map(|group| (group.name.clone(), group.id.to_string()))
        .collect();
    let tracker = Arc::clone(tracker);
    let diagnostics = Arc::clone(diagnostics);
    #[cfg(feature = "native-api")]
    let native = native.cloned();
    group_manager.set_interrupt_callback(Some(Arc::new(move |name, network| {
        if diagnostics.read().generation != generation {
            return;
        }
        let identity = identities.get(name).cloned();
        #[cfg(feature = "native-api")]
        let identity = if let Some(native) = &native {
            native.catalog.snapshot().groups.get(name).cloned()
        } else {
            identity
        };
        let Some(identity) = identity else {
            return;
        };
        let network = match network {
            honk_outbound::group::SelectionNetwork::Tcp => "tcp",
            honk_outbound::group::SelectionNetwork::Udp => "udp",
        };
        for selected in tracker.snapshot_group(&identity, Some(network)) {
            // The transport/removal owner, not this synchronous callback, owns completion.
            drop(tracker.start_close(selected));
        }
    })));
}

/// Wake Selector warming and route-aware connectivity publication after a
/// manual choice changes. Both tasks read current policy outside the callback.
pub(in crate::control) fn install_selector_warm_callback(
    group_manager: &GroupManager,
    notify: &Arc<tokio::sync::Notify>,
    alive: &Arc<AliveDialerSet>,
) {
    let alive = Arc::downgrade(alive);
    let notify = Arc::clone(notify);
    group_manager.set_selector_change_callback(Some(Arc::new(move || {
        notify.notify_waiters();
        if let Some(alive) = alive.upgrade() {
            alive.notify_policy_change();
        }
    })));
}

/// The first containing group supplies the raw callback's slot hint. Routed
/// publication resolves every affected group against the committed routing plan.
pub(in crate::control) fn build_outbound_id_map(config: &Config) -> OutboundHealthIndex {
    let graph = GroupGraph::new(&config.groups, &config.nodes);
    let mut map = std::collections::HashMap::new();
    for i in 0..config.groups.len() {
        let id = OutboundIndex::UserBase as u8 + i as u8;
        for node_id in group_leaf_ids(&graph, i) {
            map.entry(node_id).or_insert(id);
        }
    }
    map
}

pub(in crate::control) type OutboundHealthIndex = std::collections::HashMap<uuid::Uuid, u8>;

/// Extend only the callback dispatch map, after raw probe registrations were derived.
pub(in crate::control) fn extend_route_health_dependencies(
    config: &Config,
    manager: &GroupManager,
    map: &mut OutboundHealthIndex,
) {
    for (index, group) in config.groups.iter().enumerate() {
        let outbound = OutboundIndex::UserBase as u8 + index as u8;
        manager.visit_route_health_dependencies(&group.name, |node| {
            map.entry(node).or_insert(outbound);
            false
        });
    }
}

type GroupConnectivity = (u8, u32, u32, bool);

/// A sole TCP leaf with no configured fallback remains a userspace last resort:
/// suppressing it in TC would prevent real traffic from proving recovery.
pub(in crate::control) fn group_datapath_alive(
    group: &Group,
    group_manager: &GroupManager,
    alive_set: &AliveDialerSet,
    domain: ProbeDomain,
    ipver: IpVersion,
) -> bool {
    if let Some(alive) = group_manager.routed_group_available(&group.name, domain, ipver) {
        return alive;
    }
    if domain == ProbeDomain::Tcp {
        return (group.final_outbound.is_none()
            && group_manager.leaf_nodes_in_group(&group.name).len() == 1)
            || group_manager
                .reachable_leaf_nodes_in_group(&group.name)
                .iter()
                .any(|node| alive_set.is_alive_for(node.id, domain, ipver));
    }
    group_manager.any_udp_leaf_in_group(&group.name, |node| {
        (node.protocol() == NodeProtocol::Block || group_manager.node_carries_udp(node))
            && alive_set.is_alive_for(node.id, domain, ipver)
    })
}

pub(crate) fn group_connectivity_snapshot(
    config: &Config,
    group_manager: &GroupManager,
    alive_set: &AliveDialerSet,
) -> Vec<GroupConnectivity> {
    let groups = config
        .groups
        .iter()
        .enumerate()
        .map(|(index, group)| (OutboundIndex::UserBase as u8 + index as u8, group));
    connectivity_snapshot(groups, |group, domain, family| {
        Some(group_datapath_alive(
            group,
            group_manager,
            alive_set,
            domain,
            family,
        ))
    })
}

pub(in crate::control) fn initial_route_connectivity(
    plan: &routing_matcher::RoutingPushPlan,
    manager: &GroupManager,
) -> Vec<GroupConnectivity> {
    let groups = plan
        .group_slots
        .iter()
        .map(|(slot, name)| (*slot, name.as_str()));
    connectivity_snapshot(groups, |name, domain, family| {
        manager.routed_group_available(name, domain, family)
    })
}

fn connectivity_snapshot<G: Copy>(
    groups: impl ExactSizeIterator<Item = (u8, G)>,
    mut check: impl FnMut(G, ProbeDomain, IpVersion) -> Option<bool>,
) -> Vec<GroupConnectivity> {
    let mut snapshot = Vec::with_capacity(groups.len() * 6);
    for (outbound, group) in groups {
        for domain in [ProbeDomain::Tcp, ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
            for family in [IpVersion::V4, IpVersion::V6] {
                if let Some(alive) = check(group, domain, family) {
                    snapshot.push((outbound, domain as u32, family as u32, alive));
                }
            }
        }
    }
    snapshot
}

pub(super) fn installed_group_connectivity(
    ebpf: &dyn EbpfBackend,
    group_count: usize,
) -> anyhow::Result<Vec<GroupConnectivity>> {
    let mut snapshot = Vec::with_capacity(group_count * 6);
    visit_group_connectivity_slots(group_count, |outbound, domain, ipver| {
        let alive = ebpf.get_outbound_alive(outbound, domain, ipver)?;
        snapshot.push((outbound, domain, ipver, alive));
        Ok(())
    })?;
    Ok(snapshot)
}

pub(crate) fn publish_group_connectivity(
    ebpf: &mut dyn EbpfBackend,
    snapshot: &[GroupConnectivity],
) -> anyhow::Result<()> {
    for &(outbound, domain, ipver, alive) in snapshot {
        ebpf.set_outbound_alive(outbound, domain, ipver, alive)?;
    }
    Ok(())
}

pub(crate) fn open_group_connectivity(
    ebpf: &mut dyn EbpfBackend,
    group_count: usize,
) -> anyhow::Result<()> {
    visit_group_connectivity_slots(group_count, |outbound, domain, ipver| {
        ebpf.set_outbound_alive(outbound, domain, ipver, true)
    })
}

fn visit_group_connectivity_slots(
    group_count: usize,
    mut visit: impl FnMut(u8, u32, u32) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    for index in 0..group_count {
        let offset = u8::try_from(index)
            .map_err(|_| anyhow::anyhow!("too many outbound groups: {group_count}"))?;
        let outbound = (OutboundIndex::UserBase as u8)
            .checked_add(offset)
            .ok_or_else(|| anyhow::anyhow!("too many outbound groups: {group_count}"))?;
        for domain in 0..3 {
            for ipver in 0..2 {
                visit(outbound, domain, ipver)?;
            }
        }
    }
    Ok(())
}

impl ControlPlane {
    /// Rebuild ordinary groups without replacing the DNS generation. If either graph has an
    /// exit, submit the candidate to [`Self::reload_runtime_config`] without prewriting it.
    pub async fn reload_group_manager(&self) -> anyhow::Result<()> {
        let config = self.config.read().await;
        let score = {
            let current = self.group_manager.read();
            anyhow::ensure!(
                !current.has_exits() && config.groups.iter().all(|g| g.exit.is_none()),
                "group exits require a full configuration reload"
            );
            current.score_state()
        };
        let new_gm = Arc::new(GroupManager::with_alive_set_and_score_state(
            &config.groups,
            &config.nodes,
            Some(self.alive_set.clone()),
            score,
        ));
        let runtimes = self.runtime_registry.read().clone();
        new_gm.bind_transport_quality(&runtimes);
        // Migrate runtime choices before wiring callbacks: migration must
        // not fire persistence or connection interruption.
        new_gm.migrate_selector_choices_from(&self.group_manager.read());
        install_interrupt_callback(
            &new_gm,
            &config.groups,
            &self.connection_tracker,
            &self.diagnostics,
            self.diagnostics.read().generation,
            #[cfg(feature = "native-api")]
            self.native.as_ref(),
        );
        let owns_udp_routes = new_gm.has_udp_route_health();
        if owns_udp_routes {
            install_selector_warm_callback(&new_gm, &self.selector_warm_notify, &self.alive_set);
        }
        if let Some(ref db) = self.cache_db {
            let db_cb = db.clone();
            new_gm.set_persist_callback(Some(Arc::new(move |group, network, member| {
                db_cb.save_network_selector(group, network, member);
            })));
        }
        let targets = health_registrations(&config, &build_outbound_id_map(&config));
        let idle_groups = idle_group_registrations(&config);
        let check_urls = group_check_url_registrations(&config);
        let group_count = config.groups.len();
        let ((added, removed), probe_wake) = {
            #[cfg(all(test, feature = "clash-api"))]
            let _after_unlock = self.clash_publication_pause.lock().take();
            let mut group_manager = self.group_manager.write();
            new_gm.publish_score_membership();
            let probe_wake =
                publish_group_probe_state(&self.alive_set, &new_gm, &idle_groups, &check_urls);
            let retain_delay = |id: &uuid::Uuid| new_gm.retains_manual_delay(id, &runtimes);
            let changes = if owns_udp_routes || group_manager.has_udp_route_health() {
                let changes = self.alive_set.sync_registrations_retaining_routes(
                    targets,
                    retain_delay,
                    |id| new_gm.retains_udp_route_health_node(*id),
                );
                new_gm.republish_route_health();
                changes
            } else {
                self.alive_set
                    .sync_registrations_retaining_delays(targets, retain_delay)
            };
            self.active_routing_plan
                .write()
                .rebind_manager(&group_manager, &new_gm, &config);
            *group_manager = new_gm;
            (changes, probe_wake)
        };
        drop(config);
        probe_wake.wake();
        info!(
            "Group manager rebuilt: {} group(s), health checks +{}/-{} node(s)",
            group_count, added, removed,
        );
        Ok(())
    }
}
