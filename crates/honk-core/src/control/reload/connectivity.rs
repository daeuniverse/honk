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
    reachable: &std::collections::HashMap<uuid::Uuid, impl Sized>,
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
    let leaves = build_outbound_id_map(config, std::convert::identity);
    alive_set.sync_registrations(health_registrations(config, &leaves))
}

/// URLTest group registrations for the alive set's idle-suspension table:
/// `(group name, member NodeIds, idle timeout)` per URLTest group.
/// Leaves shared with any non-URLTest group are probed unconditionally.
/// Membership and explicit final edges both participate, since health state
/// lives on real nodes. Used identically at startup and on config reload.
pub(in crate::control) fn urltest_group_registrations(
    config: &Config,
) -> Vec<(String, Vec<uuid::Uuid>, Option<Duration>)> {
    let graph = GroupGraph::new(&config.groups, &config.nodes);
    let always_probed_node_ids: BTreeSet<uuid::Uuid> = config
        .groups
        .iter()
        .enumerate()
        .filter(|(_, g)| g.policy != GroupPolicy::URLTest)
        .flat_map(|(index, _)| group_leaf_ids(&graph, index))
        .collect();
    config
        .groups
        .iter()
        .enumerate()
        .filter(|(_, g)| g.policy == GroupPolicy::URLTest)
        .map(|(index, group)| {
            let members: Vec<uuid::Uuid> = group_leaf_ids(&graph, index)
                .into_iter()
                .filter(|id| !always_probed_node_ids.contains(id))
                .collect();
            (
                group.name.clone(),
                members,
                group.idle_timeout.map(std::time::Duration::from_secs),
            )
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

/// Build the NodeId → eBPF outbound id map used for
/// `OUTBOUND_CONNECTIVITY_MAP` pushes. Numbering matches
/// `push_routing_to_ebpf`: direct=0, block=1, group i → `UserBase + i`;
/// Reachable leaves inherit their group's id (first group wins), expanding
/// membership and explicit final edges so final-only health transitions also
/// update the containing group's slot. Unreachable nodes are absent.
pub(in crate::control) fn build_outbound_id_map<T>(
    config: &Config,
    value: impl Fn(u8) -> T,
) -> std::collections::HashMap<uuid::Uuid, T> {
    let graph = GroupGraph::new(&config.groups, &config.nodes);
    let mut map = std::collections::HashMap::new();
    for i in 0..config.groups.len() {
        let id = OutboundIndex::UserBase as u8 + i as u8;
        for node_id in group_leaf_ids(&graph, i) {
            map.entry(node_id).or_insert_with(|| value(id));
        }
    }
    map
}

#[derive(Clone, Copy)]
pub(in crate::control) struct OutboundHealthDependency {
    pub outbound: u8,
    pub routed: bool,
}

impl OutboundHealthDependency {
    pub fn leaf(outbound: u8) -> Self {
        Self {
            outbound,
            routed: false,
        }
    }
}

pub(in crate::control) type OutboundHealthIndex =
    std::collections::HashMap<uuid::Uuid, OutboundHealthDependency>;

/// Extend only the callback dispatch map, after raw probe registrations were derived.
pub(in crate::control) fn extend_route_health_dependencies(
    config: &Config,
    manager: &GroupManager,
    map: &mut OutboundHealthIndex,
) {
    for (index, group) in config.groups.iter().enumerate() {
        let outbound = OutboundIndex::UserBase as u8 + index as u8;
        manager.visit_route_health_dependencies(&group.name, |node| {
            map.entry(node)
                .or_insert_with(|| OutboundHealthDependency::leaf(outbound))
                .routed = true;
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
    alive_set: &crate::outbound::AliveDialerSet,
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
        (node.protocol() == NodeProtocol::Block
            || (honk_outbound::descriptor::descriptor(node.protocol()).supports_udp)(node))
            && alive_set.is_alive_for(node.id, domain, ipver)
    })
}

pub(crate) fn group_connectivity_snapshot(
    config: &Config,
    group_manager: &GroupManager,
    alive_set: &AliveDialerSet,
) -> Vec<GroupConnectivity> {
    connectivity_snapshot(config, |group, domain, family| {
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
    config: &Config,
    manager: &GroupManager,
) -> Vec<GroupConnectivity> {
    connectivity_snapshot(config, |group, domain, family| {
        manager.routed_group_available(&group.name, domain, family)
    })
}

fn connectivity_snapshot(
    config: &Config,
    mut check: impl FnMut(&Group, ProbeDomain, IpVersion) -> Option<bool>,
) -> Vec<GroupConnectivity> {
    let mut snapshot = Vec::with_capacity(config.groups.len() * 6);
    for (index, group) in config.groups.iter().enumerate() {
        let outbound = OutboundIndex::UserBase as u8 + index as u8;
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
    for index in 0..group_count {
        let offset = u8::try_from(index)
            .map_err(|_| anyhow::anyhow!("too many outbound groups: {group_count}"))?;
        let outbound = (OutboundIndex::UserBase as u8)
            .checked_add(offset)
            .ok_or_else(|| anyhow::anyhow!("too many outbound groups: {group_count}"))?;
        for domain in 0..3 {
            for ipver in 0..2 {
                ebpf.set_outbound_alive(outbound, domain, ipver, true)?;
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
        let new_gm = GroupManager::with_alive_set_and_score_state(
            &config.groups,
            &config.nodes,
            Some(self.alive_set.clone()),
            score,
        );
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
        if let Some(ref db) = self.cache_db {
            let db_cb = db.clone();
            new_gm.set_persist_callback(Some(Arc::new(move |group, network, member| {
                db_cb.save_network_selector(group, network, member);
            })));
        }
        let targets = health_registrations(
            &config,
            &build_outbound_id_map(&config, OutboundHealthDependency::leaf),
        );
        let (added, removed) = {
            #[cfg(all(test, feature = "clash-api"))]
            let _after_unlock = self.clash_publication_pause.lock().take();
            let mut group_manager = self.group_manager.write();
            new_gm.publish_score_membership();
            *group_manager = Arc::new(new_gm);
            self.alive_set
                .sync_registrations_retaining_delays(targets, |id| {
                    group_manager.retains_manual_delay(id, &runtimes)
                })
        };

        // Refresh the URLTest idle table to match the published membership.
        self.alive_set
            .sync_urltest_groups(&urltest_group_registrations(&config));
        self.alive_set
            .sync_group_check_urls(&group_check_url_registrations(&config));
        info!(
            "Group manager rebuilt: {} group(s), health checks +{}/-{} node(s)",
            config.groups.len(),
            added,
            removed,
        );
        Ok(())
    }
}
