//! Native node and group projections, with bounded, immutable node pages.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    io::{self, Write},
    ops::Range,
    sync::Arc,
    time::SystemTime,
};

use axum::{
    Json,
    body::Body,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use honk_config::{
    Config,
    group::{Group, GroupPolicy},
};
use honk_outbound::{
    alive::{AliveDialerSet, HealthAverages, HealthObservation},
    group::{GroupManager, GroupMember, SelectionNetwork},
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::observe::{
    catalog::{CatalogIdentity, check_url, interrupt_connections, member_id, selection, tolerance},
    timestamp,
};

use super::{
    ApiError, ErrorCode, NativeState,
    config::ListenerSecrets,
    error, invalid_query,
    pages::{self, MAX_SNAPSHOT_BYTES, Pages, Snapshot},
    parse_query,
    types::RequestId,
};

/// Frozen node pages behind live cursors.
pub(crate) type NodePages = Pages<NodeSnapshot>;

pub(crate) struct NodeSnapshot {
    group_id: Option<String>,
    observed_at: String,
    nodes: Vec<Box<str>>,
    bytes: usize,
}

impl Snapshot for NodeSnapshot {
    fn len(&self) -> usize {
        self.nodes.len()
    }

    fn bytes(&self) -> usize {
        self.bytes
    }

    fn page(&self, rows: Range<usize>, next_cursor: Option<String>) -> Response {
        let mut body = format!("{{\"observed_at\":\"{}\",\"nodes\":[", self.observed_at);
        for (index, node) in self.nodes[rows].iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            body.push_str(node);
        }
        body.push_str("],\"next_cursor\":");
        body.push_str(&serde_json::to_string(&next_cursor).expect("cursor serializes"));
        body.push('}');
        (
            [(header::CONTENT_TYPE, "application/json")],
            Body::from(body),
        )
            .into_response()
    }
}

struct BoundedJson {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("snapshot capacity"));
        }
        let required = self.bytes.len() + bytes.len();
        if required > self.bytes.capacity() {
            let capacity = required
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.limit);
            self.bytes.reserve_exact(capacity - self.bytes.len());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn millis(duration: Option<std::time::Duration>) -> Option<f64> {
    duration.map(|duration| duration.as_secs_f64() * 1000.0)
}

fn health(observation: HealthObservation, averages: HealthAverages) -> Value {
    json!({
        "transport": observation.transport,
        "purpose": observation.purpose,
        "ip_version": crate::observe::flows::producer::ip_family(observation.ip_version),
        "warmth": observation.warmth,
        "measurement": observation.measurement,
        "sample_source": "probe",
        "state": observation.state,
        "latency_ms": millis(observation.latency),
        "moving_avg_ms": millis(averages.moving),
        "avg10_ms": millis(averages.avg10),
        "observed_at": timestamp(observation.observed_at),
        "error": observation.error,
    })
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum ProviderId {
    Subscription(Uuid),
    Inline(&'static str),
}

#[derive(serde::Serialize)]
struct NodeRow<'a> {
    id: Uuid,
    name: Cow<'a, str>,
    protocol: &'static str,
    stream_transport: Option<&'static str>,
    subscription_tag: Option<Cow<'a, str>>,
    provider_id: Option<ProviderId>,
    group_ids: Vec<&'a String>,
    health: Vec<Value>,
}

pub(super) fn is_inline_node(node: &honk_config::node::Node) -> bool {
    node.subscription_id.is_none()
        && !matches!(
            node.protocol(),
            honk_config::types::NodeProtocol::Direct | honk_config::types::NodeProtocol::Block
        )
}

fn node_row<'a>(
    node: &'a honk_config::node::Node,
    config: &'a Config,
    alive: &AliveDialerSet,
    group_ids: Vec<&'a String>,
    secrets: &ListenerSecrets,
) -> NodeRow<'a> {
    NodeRow {
        id: node.id,
        name: secrets.mask_borrowed(&node.name),
        protocol: node.protocol().as_str(),
        stream_transport: node
            .transport()
            .and_then(|t| honk_config::options::vocab::xhttp_stream_transport(&t.transport).ok()),
        subscription_tag: node
            .subscription_id
            .and_then(|id| {
                config
                    .subscriptions
                    .iter()
                    .find(|subscription| subscription.id == id)
            })
            .map(|subscription| secrets.mask_borrowed(&subscription.name)),
        provider_id: node
            .subscription_id
            .map(ProviderId::Subscription)
            .or_else(|| is_inline_node(node).then_some(ProviderId::Inline("inline"))),
        group_ids,
        health: alive
            .health_samples(node.id)
            .into_iter()
            .map(|(observation, averages)| health(observation, averages))
            .collect(),
    }
}

pub(super) fn node_value(
    config: &Config,
    identity: &CatalogIdentity,
    manager: &GroupManager,
    alive: &AliveDialerSet,
    node_id: Uuid,
    secrets: &ListenerSecrets,
) -> Option<Value> {
    let node = config.nodes.iter().find(|node| node.id == node_id)?;
    let mut groups: Vec<_> = identity
        .groups
        .iter()
        .filter_map(|(name, id)| {
            manager
                .group_members(name)
                .any(|member| matches!(member, GroupMember::Node(node) if node.id == node_id))
                .then_some(id)
        })
        .collect();
    groups.sort_unstable();
    groups.dedup();
    serde_json::to_value(node_row(node, config, alive, groups, secrets)).ok()
}

fn node_snapshot(
    config: &Config,
    manager: &GroupManager,
    identity: &CatalogIdentity,
    alive: &AliveDialerSet,
    group_id: Option<&str>,
    id: &RequestId,
    secrets: &ListenerSecrets,
) -> Result<NodeSnapshot, ApiError> {
    let filter = match group_id {
        Some(group_id) => Some(
            identity
                .groups
                .iter()
                .find(|(_, value)| value.as_str() == group_id)
                .map(|(name, _)| name.as_str())
                .ok_or_else(|| group_not_found(id))?,
        ),
        None => None,
    };
    let filter_nodes: Option<HashSet<_>> = filter.map(|name| {
        manager
            .group_members(name)
            .filter_map(|member| match member {
                GroupMember::Node(node) => Some(node.id),
                GroupMember::Group(_) => None,
            })
            .collect()
    });
    let mut nodes: Vec<_> = config
        .nodes
        .iter()
        .filter(|node| {
            filter_nodes
                .as_ref()
                .is_none_or(|filter| filter.contains(&node.id))
        })
        .collect();
    nodes.sort_unstable_by_key(|node| node.id);
    let mut snapshot = NodeSnapshot {
        group_id: group_id.map(str::to_owned),
        observed_at: timestamp(SystemTime::now()),
        nodes: Vec::new(),
        bytes: 0,
    };
    let overhead = std::mem::size_of::<NodeSnapshot>()
        + snapshot.group_id.as_ref().map_or(0, String::len)
        + snapshot.observed_at.len()
        + nodes.len().saturating_mul(std::mem::size_of::<Box<str>>());
    if overhead > MAX_SNAPSHOT_BYTES {
        return Err(snapshot_unavailable(id));
    }
    snapshot.nodes = Vec::with_capacity(nodes.len());
    snapshot.bytes = overhead;
    let mut membership: HashMap<Uuid, Vec<&String>> = HashMap::new();
    for (name, group_id) in &identity.groups {
        for member in manager.group_members(name) {
            if let GroupMember::Node(node) = member {
                membership.entry(node.id).or_default().push(group_id);
            }
        }
    }
    for node in nodes {
        let mut group_ids = membership.remove(&node.id).unwrap_or_default();
        group_ids.sort_unstable();
        group_ids.dedup();
        let value = node_row(node, config, alive, group_ids, secrets);
        let mut writer = BoundedJson {
            bytes: Vec::new(),
            limit: MAX_SNAPSHOT_BYTES - snapshot.bytes,
        };
        serde_json::to_writer(&mut writer, &value).map_err(|_| snapshot_unavailable(id))?;
        snapshot.bytes += writer.bytes.len();
        snapshot.nodes.push(
            String::from_utf8(writer.bytes)
                .expect("JSON is UTF-8")
                .into_boxed_str(),
        );
    }
    Ok(snapshot)
}

pub(super) async fn nodes(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let query = parse_query(uri, &["group_id", "limit", "cursor"], id)?;
    let limit = pages::limit(&query, id)?;
    if query.get("group_id").is_some_and(String::is_empty) {
        return Err(invalid_query(id));
    }
    let group_id = query.get("group_id").map(String::as_str);
    if let Some(cursor) = query.get("cursor") {
        return state.observation.node_pages.resume(
            cursor,
            limit,
            |snapshot| snapshot.group_id.as_deref() == group_id,
            id,
        );
    }
    let (config, identity, manager, secrets) = {
        let config = state.config.read().await;
        (
            Arc::clone(&config),
            state.observation.core.catalog.snapshot(),
            state.group_manager.read().clone(),
            listener_secrets(state),
        )
    };
    let snapshot = node_snapshot(
        &config,
        &manager,
        &identity,
        &state.alive_set,
        group_id,
        id,
        &secrets,
    )?;
    state.observation.node_pages.first(snapshot, limit, id)
}

pub(super) async fn node(
    state: &NativeState,
    node_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let config = state.config.read().await;
    let identity = state.observation.core.catalog.snapshot();
    let manager = state.group_manager.read().clone();
    Uuid::parse_str(node_id)
        .ok()
        .and_then(|node_id| {
            node_value(
                &config,
                &identity,
                &manager,
                &state.alive_set,
                node_id,
                &listener_secrets(state),
            )
        })
        .map(|value| Json(value).into_response())
        .ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                ErrorCode::ResourceNotFound,
                "Node not found",
                id,
            )
        })
}

fn listener_secrets(state: &NativeState) -> Arc<ListenerSecrets> {
    state.observation.configuration.current_secrets()
}

fn group_health(
    manager: &GroupManager,
    group: &Group,
    identity: &CatalogIdentity,
    alive: &AliveDialerSet,
) -> Vec<Value> {
    let group_id =
        Uuid::parse_str(&identity.groups[&group.name]).expect("catalog group IDs are UUIDs");
    // Accepted-epoch retention owns member/leaf associations, including explicit leaf probes.
    let samples = alive.group_health_observations(group_id);
    let mut result: Vec<_> = samples
        .iter()
        .map(|sample| {
            group_observation(
                sample.member_id.to_string(),
                sample.node_id,
                sample.observation,
                HealthAverages::default(),
            )
        })
        .collect();
    if group.check_url.is_none() {
        let mut seen = HashSet::new();
        for member in manager.group_members(&group.name) {
            let GroupMember::Node(node) = member else {
                continue;
            };
            if !seen.insert(node.id) {
                continue;
            }
            for (sample, averages) in alive.health_samples(node.id) {
                if samples.iter().any(|retained| {
                    retained.member_id == node.id
                        && retained.observation.transport == sample.transport
                        && retained.observation.purpose == sample.purpose
                        && retained.observation.measurement == sample.measurement
                        && retained.observation.ip_version == sample.ip_version
                        && retained.observation.warmth == sample.warmth
                }) {
                    continue;
                }
                result.push(group_observation(
                    node.id.to_string(),
                    node.id,
                    sample,
                    averages,
                ));
            }
        }
    }
    result
}

fn group_observation(
    member_id: String,
    node_id: Uuid,
    sample: HealthObservation,
    averages: HealthAverages,
) -> Value {
    let mut result = health(sample, averages);
    result["member_id"] = json!(member_id);
    result["resolved_leaf_node_id"] = json!(node_id.to_string());
    result["sorting_latency_ms"] = Value::Null;
    result["ranking"] = Value::Null;
    result
}

fn group_value(
    manager: &GroupManager,
    group: &Group,
    identity: &CatalogIdentity,
    alive: &AliveDialerSet,
    full: bool,
) -> Value {
    let tcp = selection(manager, group, SelectionNetwork::Tcp, identity);
    let udp = selection(manager, group, SelectionNetwork::Udp, identity);
    let mut result = json!({
        "id": identity.groups[&group.name], "name": group.name, "icon": group.icon,
        "config_revision": identity.revision,
        "policy": { "kind": group.policy.as_str(), "native": group.policy.as_str() }
    });
    if !full {
        result["member_count"] = json!(manager.group_members(&group.name).count());
        result["selection"] =
            json!({ "tcp_member_id": tcp["member_id"], "udp_member_id": udp["member_id"] });
        return result;
    }
    let members: Vec<_> = manager
        .group_members(&group.name)
        .filter_map(|member| {
            let id = member_id(member, identity)?;
            let (name, kind) = match member {
                GroupMember::Node(node) => (&node.name, "node"),
                GroupMember::Group(group) => (&group.name, "group"),
            };
            Some(json!({ "id": id, "name": name, "kind": kind }))
        })
        .collect();
    let default_id = group
        .default
        .as_ref()
        .and_then(|name| {
            members
                .iter()
                .find(|member| member["name"].as_str() == Some(name.as_str()))
        })
        .map(|member| member["id"].clone());
    result["members"] = json!(members);
    result["config"] = json!({
        "default_member_id": default_id, "final_outbound": group.final_outbound,
        "check_url": check_url(group), "check_interval": group.check_interval.filter(|value| *value > 0),
        "tolerance": tolerance(group), "idle_timeout": group.idle_timeout,
        "interrupt_connections": interrupt_connections(group)
    });
    result["runtime"] = json!({ "selection": { "tcp": tcp, "udp": udp }, "health": group_health(manager, group, identity, alive) });
    result["capabilities"] = json!({
        "can_select": group.policy == honk_config::group::GroupPolicy::Selector, "can_override": group.policy != honk_config::group::GroupPolicy::Selector, "supports_nested_groups": true,
        "mutable_config": [], "probe_transports": ["tcp", "udp"]
    });
    result
}

pub(super) async fn groups(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let config = state.config.read().await;
    let identity = state.observation.core.catalog.snapshot();
    let manager = state.group_manager.read().clone();
    // Declaration order; a redefined group sits where its winning last definition is.
    let mut seen = HashSet::new();
    let mut names: Vec<_> = config
        .groups
        .iter()
        .rev()
        .map(|group| &group.name)
        .filter(|name| identity.groups.contains_key(*name) && seen.insert(*name))
        .collect();
    names.reverse();
    let revision = state
        .observation
        .configuration
        .sources
        .revision()
        .unwrap_or_else(|| identity.revision.clone());
    let groups: Vec<_> = names
        .into_iter()
        .filter_map(|name| manager.group(name))
        .map(|group| {
            let mut value = group_value(&manager, group, &identity, &state.alive_set, false);
            value["config_revision"] = json!(revision);
            value
        })
        .collect();
    Ok(Json(super::config::administrative_projection(
        state,
        Value::Array(groups),
    )?)
    .into_response())
}

pub(super) async fn group(
    state: &NativeState,
    group_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let (value, _) = group_document(state, group_id, uri, id).await?;
    Ok(Json(value).into_response())
}

/// The group's `policy` and `config`, the target of `PATCH`, tagged with the
/// configuration revision that `If-Match` compares.
pub(super) async fn group_config(
    state: &NativeState,
    group_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let (value, revision) = group_document(state, group_id, uri, id).await?;
    let document = json!({"policy": value["policy"], "config": value["config"]});
    Ok(([(header::ETAG, format!("\"{revision}\""))], Json(document)).into_response())
}

async fn group_document(
    state: &NativeState,
    group_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<(Value, String), ApiError> {
    parse_query(uri, &[], id)?;
    let _config = state.config.read().await;
    let identity = state.observation.core.catalog.snapshot();
    let manager = state.group_manager.read().clone();
    let name = identity
        .groups
        .iter()
        .find(|(_, id)| id.as_str() == group_id)
        .map(|(name, _)| name)
        .ok_or_else(|| group_not_found(id))?;
    let group = manager.group(name).ok_or_else(|| group_not_found(id))?;
    let revision = state
        .observation
        .configuration
        .sources
        .revision()
        .unwrap_or_else(|| identity.revision.clone());
    let mut value = group_value(&manager, group, &identity, &state.alive_set, true);
    value["config_revision"] = json!(revision);
    if state.observation.configuration.group_writable(name) {
        let mutable: Vec<_> = super::groups::FIELDS
            .into_iter()
            .map(|(field, ..)| field)
            .filter(|field| *field != "tolerance" || group.policy == GroupPolicy::URLTest)
            .collect();
        value["capabilities"]["mutable_config"] = json!(mutable);
    }
    let value = super::config::administrative_projection(state, value)?;
    Ok((value, revision))
}

fn group_not_found(id: &RequestId) -> ApiError {
    error(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "Group not found",
        id,
    )
}

pub(super) fn snapshot_expired(id: &RequestId) -> ApiError {
    error(
        StatusCode::GONE,
        ErrorCode::SnapshotExpired,
        "Page cursor expired",
        id,
    )
}

pub(super) fn snapshot_unavailable(id: &RequestId) -> ApiError {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::SnapshotUnavailable,
        "A coherent snapshot is unavailable",
        id,
    )
}

#[cfg(test)]
mod tests;
