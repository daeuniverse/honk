use std::cell::LazyCell;
use std::collections::BTreeSet;
use std::ops::ControlFlow;
use std::sync::LazyLock;

use honk_config::group_graph::{ExitEdge, GroupGraph, Leaf, Limits, Step, Visitor};

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
    let _ = graph.visit(group, Limits::SELECTION, &mut leaves);
    leaves.ids
}

/// Nodes reachable through group membership or explicit finals are probed
/// for alive display and recovery, including Selector leaves. Ungrouped
/// nodes are skipped unless no reachable leaves exist.
/// Returns `(NodeId, node name, address)` triples.
pub(in crate::control) fn health_check_targets(
    config: &Config,
) -> Vec<(uuid::Uuid, String, String)> {
    let graph = GroupGraph::new(&config.groups, &config.nodes);
    let group_node_ids: BTreeSet<uuid::Uuid> = (0..graph.len())
        .flat_map(|group| group_leaf_ids(&graph, group))
        .collect();
    config
        .nodes
        .iter()
        .filter(|n| group_node_ids.is_empty() || group_node_ids.contains(&n.id))
        .map(|n| (n.id, n.name.clone(), n.address.clone()))
        .collect()
}

/// Synchronize alive-set health-check registrations with the config's
/// group membership: register nodes that are new or whose name/address
/// changed, remove nodes that left the checked set. Unchanged
/// registrations keep their probe state and grace period. Returns
/// `(added, removed)` counts.
pub(in crate::control) fn sync_health_check_nodes(
    alive_set: &AliveDialerSet,
    config: &Config,
) -> (usize, usize) {
    let desired: std::collections::HashMap<uuid::Uuid, (String, String)> =
        health_check_targets(config)
            .into_iter()
            .map(|(id, name, addr)| (id, (name, addr)))
            .collect();
    let current = alive_set.registered_nodes();
    let mut added = 0usize;
    for (id, (name, addr)) in &desired {
        let unchanged = current
            .get(id)
            .is_some_and(|r| &r.name == name && &r.address == addr);
        if !unchanged {
            alive_set.register_node(*id, name.clone(), addr.clone());
            added += 1;
        }
    }
    let mut removed = 0usize;
    for id in current.keys() {
        if !desired.contains_key(id) {
            alive_set.remove_node(*id);
            removed += 1;
        }
    }
    (added, removed)
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

/// Wake the Selector warm coordinator after a manual choice changes. The
/// task re-resolves every Selector so shared/nested leaves stay reference
/// correct without putting async work in the synchronous group callback.
pub(in crate::control) fn install_selector_warm_callback(
    group_manager: &GroupManager,
    notify: &Arc<tokio::sync::Notify>,
) {
    let notify = Arc::clone(notify);
    group_manager.set_selector_change_callback(Some(Arc::new(move || {
        notify.notify_waiters();
    })));
}

/// Build the NodeId → eBPF outbound id map used for
/// `OUTBOUND_CONNECTIVITY_MAP` pushes. Numbering matches
/// `push_routing_to_ebpf`: direct=0, block=1, group i → `UserBase + i`;
/// Reachable leaves inherit their group's id (first group wins), expanding
/// membership and explicit final edges so final-only health transitions also
/// update the containing group's slot. Unreachable nodes are absent.
pub(in crate::control) fn build_outbound_id_map(
    config: &Config,
) -> std::collections::HashMap<uuid::Uuid, u8> {
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

type GroupConnectivity = (u8, u32, u32, bool);

/// One TC slot of `group`. The graph is forced only for a UDP slot.
pub(in crate::control) fn group_datapath_alive<'a>(
    graph: &LazyCell<GroupGraph<'a>, impl FnOnce() -> GroupGraph<'a>>,
    index: usize,
    group: &Group,
    group_manager: &GroupManager,
    alive_set: &crate::outbound::AliveDialerSet,
    domain: ProbeDomain,
    ipver: IpVersion,
) -> bool {
    if domain == ProbeDomain::Tcp {
        return group_tcp_alive(group, group_manager, alive_set, ipver);
    }
    group_udp_alive(
        LazyCell::force(graph),
        index,
        group_manager,
        alive_set,
        &[(domain, ipver)],
    ) != 0
}

/// A sole TCP leaf with no configured fallback remains a userspace last resort:
/// suppressing it in TC would prevent real traffic from proving recovery.
fn group_tcp_alive(
    group: &Group,
    group_manager: &GroupManager,
    alive_set: &crate::outbound::AliveDialerSet,
    ipver: IpVersion,
) -> bool {
    (group.final_outbound.is_none() && group_manager.leaf_nodes_in_group(&group.name).len() == 1)
        || group_manager
            .reachable_leaf_nodes_in_group(&group.name)
            .iter()
            .any(|node| alive_set.is_alive_for(node.id, ProbeDomain::Tcp, ipver))
}

/// One bit per entry of `slots` whose UDP is alive for `group`: some leaf
/// it reaches carries UDP over what it dials and is alive in that slot.
/// One walk answers every slot, asking each leaf's capability once.
fn group_udp_alive(
    graph: &GroupGraph<'_>,
    group: usize,
    group_manager: &GroupManager,
    alive_set: &crate::outbound::AliveDialerSet,
    slots: &[(ProbeDomain, IpVersion)],
) -> u8 {
    let all = (1u8 << slots.len()) - 1;
    let mut found = 0;
    let _ = walk_udp_leaves(graph, group, |node, exits| {
        // `block` reached from a group with an exit means no route there
        // carries UDP, so it counts only outside every exit.
        let carries = if node.protocol() == NodeProtocol::Block {
            exits.is_empty()
        } else {
            group_manager.carries_udp_via(node, exits)
        };
        if carries {
            for (bit, &(domain, ipver)) in slots.iter().enumerate() {
                if alive_set.is_alive_for(node.id, domain, ipver) {
                    found |= 1 << bit;
                }
            }
        }
        found == all
    });
    found
}

/// Breaks on the first leaf of `group` that `stop` accepts with the exits
/// on its path. Walks the configuration's graph, as [`group_leaf_ids`] does,
/// so a cycle GroupManager's copy cuts only widens what TC passes to
/// userspace. Nothing behind an exit the configuration cannot resolve is
/// selectable.
fn walk_udp_leaves(
    graph: &GroupGraph<'_>,
    group: usize,
    stop: impl FnMut(&Node, &[uuid::Uuid]) -> bool,
) -> ControlFlow<()> {
    struct UdpLeaves<'g, 'a, F> {
        graph: &'g GroupGraph<'a>,
        path: [&'a str; honk_outbound::group::MAX_GROUP_DEPTH],
        stop: F,
    }
    impl<F: FnMut(&Node, &[uuid::Uuid]) -> bool> Visitor for UdpLeaves<'_, '_, F> {
        fn enter(&mut self, group: usize, depth: usize, _: &[uuid::Uuid]) -> ControlFlow<(), Step> {
            let name = self.graph.name(group);
            if depth >= self.path.len()
                || self.path[..depth].contains(&name)
                || self.graph.exit(group) == Some(ExitEdge::Unresolved)
            {
                return ControlFlow::Continue(Step::Skip);
            }
            self.path[depth] = name;
            ControlFlow::Continue(Step::Descend)
        }

        fn leaf(&mut self, leaf: Leaf, exits: &[uuid::Uuid]) -> ControlFlow<()> {
            static DIRECT: LazyLock<Node> = LazyLock::new(Config::builtin_direct_node);
            static BLOCK: LazyLock<Node> = LazyLock::new(Config::builtin_block_node);
            let node = match leaf {
                Leaf::Node(id) => self.graph.node(id),
                Leaf::Direct => Some(&*DIRECT),
                Leaf::Block => Some(&*BLOCK),
            };
            if node.is_some_and(|node| (self.stop)(node, exits)) {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }
    }
    graph.visit(
        group,
        Limits::SELECTION,
        &mut UdpLeaves {
            graph,
            path: [""; honk_outbound::group::MAX_GROUP_DEPTH],
            stop,
        },
    )
}

/// The UDP slots of a snapshot, in its order.
const UDP_SLOTS: [(ProbeDomain, IpVersion); 4] = [
    (ProbeDomain::DnsUdp, IpVersion::V4),
    (ProbeDomain::DnsUdp, IpVersion::V6),
    (ProbeDomain::DataUdp, IpVersion::V4),
    (ProbeDomain::DataUdp, IpVersion::V6),
];

pub(crate) fn group_connectivity_snapshot(
    config: &Config,
    group_manager: &GroupManager,
    alive_set: &crate::outbound::AliveDialerSet,
) -> Vec<GroupConnectivity> {
    let graph = GroupGraph::new(&config.groups, &config.nodes);
    let mut snapshot = Vec::with_capacity(config.groups.len() * 6);
    for (index, group) in config.groups.iter().enumerate() {
        let outbound = OutboundIndex::UserBase as u8 + index as u8;
        for (ip_index, ipver) in [IpVersion::V4, IpVersion::V6].into_iter().enumerate() {
            snapshot.push((
                outbound,
                0,
                ip_index as u32,
                group_tcp_alive(group, group_manager, alive_set, ipver),
            ));
        }
        let udp = group_udp_alive(&graph, index, group_manager, alive_set, &UDP_SLOTS);
        for (bit, (domain, ipver)) in UDP_SLOTS.into_iter().enumerate() {
            snapshot.push((
                outbound,
                if domain == ProbeDomain::DnsUdp { 1 } else { 2 },
                ipver as u32,
                udp & (1 << bit) != 0,
            ));
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
    /// Rebuild the [`GroupManager`] from the current config after a reload.
    ///
    /// A fresh manager is installed into the shared cell so every holder
    /// (control plane, per-connection handles, clash API) picks up new or
    /// changed groups at once. Runtime selector choices migrate by group
    /// name (choices whose group or selected node vanished are dropped);
    /// choices kept in the state db survive because every change is persisted
    /// at set time, so no restore runs here. The alive set's
    /// health-check registrations and URLTest group table are refreshed to
    /// match the new group membership, and the node → eBPF outbound id map
    /// (`outbound_id_map`, already refreshed by the reload path) is built
    /// from the same config, keeping the two consistent.
    pub async fn reload_group_manager(&self) {
        let (groups, nodes) = {
            let config = self.config.read().await;
            (config.groups.clone(), config.nodes.clone())
        };
        let new_gm = GroupManager::with_alive_set_and_score_state(
            &groups,
            &nodes,
            Some(self.alive_set.clone()),
            self.group_manager.read().score_state(),
        );
        let runtimes = self.runtime_registry.read().clone();
        new_gm.bind_transport_quality(&runtimes);
        // Migrate runtime choices before wiring callbacks: migration must
        // not fire persistence or connection interruption.
        new_gm.migrate_selector_choices_from(&self.group_manager.read());
        install_interrupt_callback(
            &new_gm,
            &groups,
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
        {
            let mut group_manager = self.group_manager.write();
            new_gm.publish_score_membership();
            *group_manager = Arc::new(new_gm);
        }

        // Refresh health-check registrations and the URLTest idle table to
        // match the new group membership.
        let config = self.config.read().await;
        let (added, removed) = sync_health_check_nodes(&self.alive_set, &config);
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
    }
}
