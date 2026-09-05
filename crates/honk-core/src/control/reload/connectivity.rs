use super::*;

/// Recursively collect the member node ids of a group, expanding nested
/// sub-groups (`Group.groups`). Config-level twin of the GroupManager's
/// leaf expansion — the config may still contain group cycles (the
/// GroupManager cuts them on its own copy), so a visited guard and the
/// shared depth cap apply here too.
pub(in crate::control) fn collect_group_leaf_ids<'a>(
    group: &'a Group,
    groups_by_name: &std::collections::HashMap<&'a str, &'a Group>,
    depth: usize,
    visited: &mut Vec<&'a str>,
    out: &mut std::collections::BTreeSet<uuid::Uuid>,
) {
    if depth >= honk_outbound::group::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
        return;
    }
    visited.push(group.name.as_str());
    out.extend(group.nodes.iter().copied());
    for tag in &group.groups {
        if let Some(sub) = groups_by_name.get(tag.as_str()) {
            collect_group_leaf_ids(sub, groups_by_name, depth + 1, visited, out);
        }
    }
    visited.pop();
}

/// Group lookup by name for [`collect_group_leaf_ids`].
pub(in crate::control) fn groups_by_name(
    config: &Config,
) -> std::collections::HashMap<&str, &Group> {
    config.groups.iter().map(|g| (g.name.as_str(), g)).collect()
}

/// Nodes that should be health-checked: members of any group — with
/// nested sub-groups expanded to their leaf nodes (Selector members are
/// probed too — alive display + failure discovery — not just URLTest
/// members). Ungrouped nodes are skipped unless no groups exist at all.
/// Returns `(NodeId, node name, address)` triples.
pub(in crate::control) fn health_check_targets(
    config: &Config,
) -> Vec<(uuid::Uuid, String, String)> {
    let by_name = groups_by_name(config);
    let group_node_ids: std::collections::BTreeSet<uuid::Uuid> = config
        .groups
        .iter()
        .flat_map(|g| {
            let mut ids = std::collections::BTreeSet::new();
            collect_group_leaf_ids(g, &by_name, 0, &mut Vec::new(), &mut ids);
            ids
        })
        .collect();
    config
        .nodes
        .iter()
        .filter(|n| group_node_ids.is_empty() || group_node_ids.contains(&n.id))
        .map(|n| (n.id, n.name.clone(), n.address.clone()))
        .collect()
}

/// Synchronize the alive-set authority with every current config node, while
/// keeping scheduled health checks limited to the configured group targets.
/// Nodes that leave the checked set are unregistered from periodic probes but
/// remain eligible for traffic feedback while they stay in the config.
/// Returns `(added, removed)` scheduled-probe counts.
pub(in crate::control) fn sync_health_check_nodes(
    alive_set: &AliveDialerSet,
    config: &Config,
) -> (usize, usize) {
    let current = alive_set.registered_nodes();
    alive_set.sync_active_nodes(config.nodes.iter().map(|node| node.id).collect());

    let desired: std::collections::HashMap<uuid::Uuid, (String, String)> =
        health_check_targets(config)
            .into_iter()
            .map(|(id, name, addr)| (id, (name, addr)))
            .collect();
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
            alive_set.unregister_probe_node(*id);
            removed += 1;
        }
    }
    (added, removed)
}

/// URLTest group registrations for the alive set's idle-suspension table:
/// `(group name, member NodeIds, idle timeout)` per URLTest group.
/// Members shared with any non-URLTest group (Selector, LoadBalance,
/// Fallback) are excluded — those are probed unconditionally, same as
/// Selector members. Nested sub-groups are expanded to their leaf nodes
/// (health state lives on real nodes). Used identically at startup and on
/// config reload.
pub(in crate::control) fn urltest_group_registrations(
    config: &Config,
) -> Vec<(String, Vec<uuid::Uuid>, Option<Duration>)> {
    let by_name = groups_by_name(config);
    let leaf_ids = |g: &Group| {
        let mut ids = std::collections::BTreeSet::new();
        collect_group_leaf_ids(g, &by_name, 0, &mut Vec::new(), &mut ids);
        ids
    };
    let always_probed_node_ids: std::collections::BTreeSet<uuid::Uuid> = config
        .groups
        .iter()
        .filter(|g| g.policy != GroupPolicy::URLTest)
        .flat_map(&leaf_ids)
        .collect();
    config
        .groups
        .iter()
        .filter(|g| g.policy == GroupPolicy::URLTest)
        .map(|group| {
            let members: Vec<uuid::Uuid> = leaf_ids(group)
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

/// Wire the `interrupt_connections` callback into a group manager: when a
/// group's selected node changes, close its tracked connections so they
/// re-dial through the new node. The callback reads the *current* manager
/// through the shared cell, so it keeps working after a reload swaps the
/// manager out. Tracked connections record the dialed leaf node name, so
/// the target set covers the group name, its member tags, and every leaf
/// reachable through nested sub-groups.
pub(in crate::control) fn install_interrupt_callback(
    group_manager: &GroupManager,
    group_manager_cell: &SharedGroupManager,
    tracker: &Arc<ConnectionTracker>,
) {
    if group_manager.has_interrupt_connections() {
        tracker.enable_for_interrupts();
    }

    let cell = group_manager_cell.clone();
    let tracker = tracker.clone();
    group_manager.set_interrupt_callback(Some(Arc::new(move |group_name: &str| {
        let gm = cell.read().clone();
        let mut targets: std::collections::HashSet<String> =
            gm.node_names_in_group(group_name).into_iter().collect();
        targets.extend(gm.leaf_node_names_in_group(group_name));
        targets.insert(group_name.to_string());
        let mut closed = 0usize;
        for snap in tracker.snapshot() {
            if targets.contains(&snap.proxy) {
                tracker.remove(&snap.id);
                closed += 1;
            }
        }
        if closed > 0 {
            info!(
                "interrupt_connections: closed {} connection(s) for group '{}'",
                closed, group_name
            );
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
        notify.notify_one();
    })));
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
    let leaves = group_manager.leaf_nodes_in_group(&group.name);
    (domain == ProbeDomain::Tcp && group.final_outbound.is_none() && leaves.len() == 1)
        || leaves
            .iter()
            .any(|node| alive_set.is_alive_for(node.id, domain, ipver))
}

pub(crate) fn group_connectivity_snapshot(
    config: &Config,
    group_manager: &GroupManager,
    alive_set: &crate::outbound::AliveDialerSet,
) -> Vec<GroupConnectivity> {
    let mut snapshot = Vec::with_capacity(config.groups.len() * 6);
    for (index, group) in config.groups.iter().enumerate() {
        let outbound = OutboundIndex::UserBase as u8 + index as u8;
        for (domain_index, domain) in [ProbeDomain::Tcp, ProbeDomain::DnsUdp, ProbeDomain::DataUdp]
            .into_iter()
            .enumerate()
        {
            for (ip_index, ipver) in [IpVersion::V4, IpVersion::V6].into_iter().enumerate() {
                snapshot.push((
                    outbound,
                    domain_index as u32,
                    ip_index as u32,
                    group_datapath_alive(group, group_manager, alive_set, domain, ipver),
                ));
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
    /// The alive set is synchronized after publication so health checks use
    /// the same rebuilt manager and config generation as routing.
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
        // Migrate runtime choices before wiring callbacks: migration must
        // not fire persistence or connection interruption.
        new_gm.migrate_selector_choices_from(&self.group_manager.read());
        install_interrupt_callback(&new_gm, &self.group_manager, &self.connection_tracker);
        if let Some(ref db) = self.cache_db {
            let db_cb = db.clone();
            new_gm.set_persist_callback(Some(Arc::new(move |group, node| {
                db_cb.save_selector_choice(group, node);
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
