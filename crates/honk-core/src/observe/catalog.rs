//! Process-local group identities bound to a configuration revision.

use std::{collections::HashMap, sync::Arc};

use honk_config::{
    Config,
    group::{Group, GroupPolicy},
};
use honk_outbound::group::{GroupManager, GroupMember, SelectionNetwork};
use parking_lot::RwLock;
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) struct CatalogIdentity {
    pub(crate) revision: String,
    pub(crate) groups: HashMap<String, String>,
}

pub(crate) struct Catalog {
    identity: RwLock<Arc<CatalogIdentity>>,
}

impl Catalog {
    pub(crate) fn new(config: &Config) -> Self {
        let catalog = Self {
            identity: RwLock::new(Arc::new(CatalogIdentity {
                revision: String::new(),
                groups: HashMap::new(),
            })),
        };
        catalog.install(config);
        catalog
    }

    pub(crate) fn install(&self, config: &Config) {
        let mut identity = self.identity.write();
        *identity = Self::prepare_identity(config, &identity);
    }

    pub(crate) fn prepare(&self, config: &Config) -> Arc<CatalogIdentity> {
        Self::prepare_identity(config, &self.identity.read())
    }

    /// The configuration publisher installs the same identity bound to its DNS runtime.
    pub(crate) fn install_prepared(&self, identity: Arc<CatalogIdentity>) {
        *self.identity.write() = identity;
    }

    fn prepare_identity(config: &Config, identity: &Arc<CatalogIdentity>) -> Arc<CatalogIdentity> {
        let effective = GroupManager::effective_groups(&config.groups);
        let revision = config_revision(config, &effective);
        if identity.revision == revision {
            return Arc::clone(identity);
        }
        let groups = effective
            .keys()
            .map(|name| {
                let id = identity
                    .groups
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                (name.clone(), id)
            })
            .collect();
        Arc::new(CatalogIdentity { revision, groups })
    }

    pub(crate) fn snapshot(&self) -> Arc<CatalogIdentity> {
        self.identity.read().clone()
    }
}

/// The URL a group's health check probes; later comma entries are literal
/// fallback addresses, not part of the URL.
pub(crate) fn check_url(group: &Group) -> Option<String> {
    honk_config::check::decode_health_http_target(group.check_url.as_deref()?)
        .ok()
        .map(|target| probed_url(&target))
}

/// A single check URL in the form GET reports and PATCH writes.
pub(crate) fn normalized_check_url(value: &str) -> Option<String> {
    honk_config::check::decode_http_check_target(value, false)
        .ok()
        .map(|target| probed_url(&target))
}

fn probed_url(target: &honk_config::check::HttpCheckTarget) -> String {
    format!(
        "{}://{}{}",
        if target.is_https() { "https" } else { "http" },
        target.authority(),
        target.request_target()
    )
}

/// Only URLTest switches on latency; other policies have no tolerance to report,
/// and a URLTest group that sets none inherits `global.check_tolerance`.
pub(crate) fn tolerance(group: &Group) -> Option<u64> {
    (group.policy == honk_config::group::GroupPolicy::URLTest && group.own.tolerance)
        .then_some(group.tolerance)
}

/// Null when the group leaves it to the default.
pub(crate) fn interrupt_connections(group: &Group) -> Option<bool> {
    group
        .own
        .interrupt_connections
        .then_some(group.interrupt_connections)
}

pub(crate) fn revision_for(config: &Config) -> String {
    config_revision(config, &GroupManager::effective_groups(&config.groups))
}

fn config_revision(config: &Config, groups: &HashMap<String, Group>) -> String {
    let nodes: HashMap<_, _> = config.nodes.iter().map(|node| (node.id, node)).collect();
    let mut ordered: Vec<_> = groups.values().collect();
    ordered.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    let canonical: Vec<_> = ordered
        .into_iter()
        .map(|group| {
            let nodes: Vec<_> = group
                .nodes
                .iter()
                .filter_map(|id| nodes.get(id))
                .map(|node| (node.id, &node.name))
                .collect();
            let children: Vec<_> = group
                .groups
                .iter()
                .filter(|name| groups.contains_key(*name))
                .collect();
            let mut filters: Vec<_> = group.filters.iter().collect();
            filters.sort_unstable();
            filters.dedup();
            json!([
                group.name,
                group.icon,
                group.policy.as_str(),
                nodes,
                children,
                filters,
                group.default,
                group.final_outbound,
                check_url(group),
                group.check_interval,
                tolerance(group),
                group.idle_timeout,
                interrupt_connections(group)
            ])
        })
        .collect();
    crate::configuration::digest(&serde_json::to_vec(&canonical).expect("catalog values serialize"))
}

pub(crate) fn member_id(member: GroupMember<'_>, identity: &CatalogIdentity) -> Option<String> {
    match member {
        GroupMember::Node(node) => Some(node.id.to_string()),
        GroupMember::Group(group) => identity.groups.get(&group.name).cloned(),
    }
}

/// A group's current `{tcp, udp}` selections, `null` where none is formed.
pub(crate) fn runtime_selection(
    manager: &GroupManager,
    identity: &CatalogIdentity,
    group_name: &str,
) -> Value {
    let group = manager.group(group_name);
    let [tcp, udp] = [SelectionNetwork::Tcp, SelectionNetwork::Udp].map(|network| {
        group.map_or(Value::Null, |group| {
            selection(manager, group, network, identity)
        })
    });
    json!({ "tcp": tcp, "udp": udp })
}

pub(crate) fn selection(
    manager: &GroupManager,
    group: &Group,
    network: SelectionNetwork,
    identity: &CatalogIdentity,
) -> Value {
    let Some(selection) = manager.peek_selection(&group.name, network) else {
        return Value::Null;
    };
    let Some(member_id) = member_id(selection.member, identity) else {
        return Value::Null;
    };
    json!({
        "member_id": member_id,
        "resolved_leaf_node_id": selection.leaf.map(|node| node.id.to_string()),
        "source": match group.policy {
            _ if manager.has_override(&group.name, network) => "override",
            GroupPolicy::Selector => "runtime",
            GroupPolicy::URLTest => "health",
            _ => "policy",
        }
    })
}

#[cfg(test)]
pub(crate) mod tests;
