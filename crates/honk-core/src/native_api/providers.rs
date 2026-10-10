//! Provider observations and supervisor-owned refresh admission.

use std::{collections::HashMap, mem::size_of, ops::Range, sync::Arc};

use axum::{
    Json,
    extract::Request,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use honk_config::subscription::Subscription;
use parking_lot::RwLock;
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    ApiError, ErrorCode, NativeState,
    catalog::snapshot_unavailable,
    invalid_query,
    operations::{OperationKind, OperationResult, OperationStore, Reservation},
    pages::{self, MAX_PAGE_SIZE, MAX_SNAPSHOT_BYTES, Pages},
    parse_query, timestamp,
    types::RequestId,
};
use crate::{
    control::ReloadOutcome,
    subscription::{
        ProviderLoad, RefreshRefusal, RefreshReport, SubscriptionMergeReply,
        SubscriptionSupervisorHandle,
    },
};

#[derive(Clone, Serialize)]
pub(crate) struct Provider {
    id: String,
    name: String,
    kind: &'static str,
    url_redacted: Option<String>,
    node_count: usize,
    updated_at: Option<String>,
    expires_at: Option<String>,
    traffic: Option<()>,
    status: &'static str,
    last_error: Option<ProviderError>,
    download: Option<Value>,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Provider")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("node_count", &self.node_count)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Serialize)]
struct ProviderError {
    code: &'static str,
    message: &'static str,
    details: Option<Value>,
}

/// The message for a failure code that says more than the generic one.
fn error_message(code: &str) -> Option<&'static str> {
    match code {
        "route_unavailable" => Some(
            "The subscription's download route has no usable node yet, so it cannot carry the download. Set route to direct for this subscription.",
        ),
        _ => None,
    }
}

/// Names the configuration diagnostic that rejected a publication.
fn rejection_details(rejection: Option<&'static str>) -> Option<Value> {
    rejection.map(|code| json!({"diagnostic_code": code}))
}

impl Provider {
    fn inline(node_count: usize) -> Self {
        Self {
            id: "inline".into(),
            name: "inline".into(),
            kind: "inline",
            url_redacted: None,
            node_count,
            updated_at: None,
            expires_at: None,
            traffic: None,
            status: "ok",
            last_error: None,
            download: None,
        }
    }

    fn observed(subscription: &Subscription, load: ProviderLoad, node_count: usize) -> Self {
        Self {
            id: subscription.id.to_string(),
            name: subscription.name.clone(),
            kind: "subscription",
            url_redacted: Some(subscription.url.clone()),
            node_count,
            updated_at: load.updated_at.map(timestamp),
            expires_at: None,
            traffic: None,
            status: if load.error.is_some() && node_count == 0 {
                "error"
            } else if load.updated_at.is_none()
                || load.cached
                || load.error.is_some()
                || !subscription.enabled
                || node_count == 0
            {
                "stale"
            } else {
                "ok"
            },
            last_error: load.error.map(|code| ProviderError {
                code,
                message: error_message(code).unwrap_or(
                    "Provider loading or runtime publication did not complete successfully.",
                ),
                details: rejection_details(load.rejection),
            }),
            download: None,
        }
    }

    /// The subscription's download route, `{route, group_id}` as for geodata.
    fn routed(
        mut self,
        subscription: &Subscription,
        group_id: impl Fn(&str) -> Option<String>,
    ) -> Self {
        self.download = Some(
            super::geodata::Route::from_detour(&subscription.download_detour)
                .unwrap_or_default()
                .json(group_id),
        );
        self
    }

    fn mask_listener_secrets(
        mut self,
        config: &honk_config::Config,
        sources: Option<&super::config::ConfigService>,
    ) -> Self {
        let secrets = match sources {
            Some(sources) => sources.secrets_with(config),
            None => super::config::ListenerSecrets::from_config(config),
        };
        for value in std::iter::once(&mut self.name).chain(self.url_redacted.iter_mut()) {
            *value = secrets.mask(value).0;
        }
        self
    }

    fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + self.id.capacity()
            + self.name.capacity()
            + self.url_redacted.as_ref().map_or(0, String::capacity)
            + self.updated_at.as_ref().map_or(0, String::capacity)
    }
}

struct Snapshot {
    instance: String,
    rows: Vec<Provider>,
    bytes: usize,
}

impl pages::Snapshot for Snapshot {
    fn len(&self) -> usize {
        self.rows.len()
    }

    fn bytes(&self) -> usize {
        self.bytes
    }

    fn page(&self, rows: Range<usize>, next_cursor: Option<String>) -> Response {
        Json(json!({"providers": &self.rows[rows], "next_cursor": next_cursor})).into_response()
    }
}

pub(crate) struct ProviderApi {
    supervisor: RwLock<Option<SubscriptionSupervisorHandle>>,
    snapshots: Pages<Snapshot>,
}

impl ProviderApi {
    pub(crate) fn new() -> Self {
        Self {
            supervisor: RwLock::new(None),
            snapshots: Pages::default(),
        }
    }

    pub(crate) fn attach(&self, supervisor: SubscriptionSupervisorHandle) {
        *self.supervisor.write() = Some(supervisor);
    }

    /// `create_options` gives the value an omitted field takes, so it reports
    /// the `assets.subscription` defaults over the built-in ones.
    pub(crate) fn capability(&self, assets: &honk_config::assets::AssetsConfig) -> Value {
        let base = assets.subscription_base();
        let mut create_options = json!({
            "update_interval": base.update_interval,
            "user_agent": crate::subscription::effective_subscription_user_agent(&base),
        });
        if self.caches() {
            create_options["cache"] = json!(base.cache);
        }
        json!({"available": true, "can_refresh": self.supervisor.read().as_ref().is_some_and(SubscriptionSupervisorHandle::running), "create_options": create_options, "max_page_size": MAX_PAGE_SIZE})
    }

    /// Whether a subscription's `cache` setting has any effect in this run.
    pub(crate) fn caches(&self) -> bool {
        self.supervisor
            .read()
            .as_ref()
            .is_some_and(SubscriptionSupervisorHandle::caches)
    }
}

pub(super) async fn list(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let query = parse_query(uri, &["limit", "cursor"], id)?;
    let limit = pages::limit(&query, id)?;
    let service = &state.observation.providers;
    if let Some(cursor) = query.get("cursor") {
        let instance = &state.observation.core.instance_id;
        return service.snapshots.resume(
            cursor,
            limit,
            |snapshot| &snapshot.instance == instance,
            id,
        );
    }
    let (config, identity, supervisor) = {
        let config = state.config.read().await;
        (
            Arc::clone(&config),
            state.observation.core.catalog.snapshot(),
            service.supervisor.read().clone(),
        )
    };
    if config
        .subscriptions
        .iter()
        .fold(0usize, |bytes, subscription| {
            bytes
                .saturating_add(size_of::<Provider>() + 256)
                .saturating_add(subscription.name.len())
                .saturating_add(subscription.url.len())
        })
        >= MAX_SNAPSHOT_BYTES
    {
        return Err(snapshot_unavailable(id));
    }
    let mut counts: HashMap<_, usize> = config.subscriptions.iter().map(|s| (s.id, 0)).collect();
    let mut inline_count = 0;
    for node in &config.nodes {
        if let Some(count) = node.subscription_id.and_then(|id| counts.get_mut(&id)) {
            *count += 1;
        } else if super::catalog::is_inline_node(node) {
            inline_count += 1;
        }
    }
    let inline = Provider::inline(inline_count);
    let mut bytes =
        size_of::<Snapshot>() + state.observation.core.instance_id.len() + inline.retained_bytes();
    let mut rows = Vec::with_capacity(config.subscriptions.len() + 1);
    rows.push(inline);
    for subscription in &config.subscriptions {
        let load = supervisor
            .as_ref()
            .map(|owner| owner.observation(subscription))
            .unwrap_or_default();
        let row = Provider::observed(subscription, load, counts[&subscription.id])
            .routed(subscription, |name| identity.groups.get(name).cloned())
            .mask_listener_secrets(&config, Some(&state.observation.configuration));
        bytes += row.retained_bytes();
        if bytes > MAX_SNAPSHOT_BYTES {
            return Err(snapshot_unavailable(id));
        }
        rows.push(row);
    }
    rows[1..].sort_unstable_by(|a, b| a.id.cmp(&b.id));
    service.snapshots.first(
        Snapshot {
            instance: state.observation.core.instance_id.clone(),
            rows,
            bytes,
        },
        limit,
        id,
    )
}

pub(super) async fn detail(
    state: &NativeState,
    provider_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    if provider_id == "inline" {
        let config = state.config.read().await;
        let count = config
            .nodes
            .iter()
            .filter(|node| super::catalog::is_inline_node(node))
            .count();
        return Ok(Json(Provider::inline(count)).into_response());
    }
    let provider_id = Uuid::parse_str(provider_id).map_err(|_| not_found())?;
    let config = state.config.read().await;
    provider_value(
        &config,
        state.observation.providers.supervisor.read().as_ref(),
        provider_id,
        Some(&state.observation.configuration),
        |name| super::geodata::group_id(&state.observation.core.catalog, name),
    )
    .map(|value| Json(value).into_response())
    .ok_or_else(not_found)
}

pub(super) fn provider_value(
    config: &honk_config::Config,
    supervisor: Option<&SubscriptionSupervisorHandle>,
    provider_id: Uuid,
    sources: Option<&super::config::ConfigService>,
    group_id: impl Fn(&str) -> Option<String>,
) -> Option<Value> {
    let subscription = config.subscriptions.iter().find(|s| s.id == provider_id)?;
    let load = supervisor
        .map(|s| s.observation(subscription))
        .unwrap_or_default();
    let count = config
        .nodes
        .iter()
        .filter(|node| node.subscription_id == Some(provider_id))
        .count();
    serde_json::to_value(
        Provider::observed(subscription, load, count)
            .routed(subscription, group_id)
            .mask_listener_secrets(config, sources),
    )
    .ok()
}

pub(super) async fn refresh(
    state: &NativeState,
    provider_id: &str,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    if provider_id == "inline" {
        return Err(not_refreshable());
    }
    let key = super::config::request_header(&request, "idempotency-key")
        .map_err(|_| invalid_query(id))?
        .map(str::to_owned);
    let body = super::body::buffered(request.into_body()).await;
    if !body.is_empty() || key.as_deref() == Some("") {
        return Err(invalid_query(id));
    }
    let uuid = Uuid::parse_str(provider_id).map_err(|_| not_found())?;
    let subscription = state
        .config
        .read()
        .await
        .subscriptions
        .iter()
        .find(|subscription| subscription.id == uuid)
        .cloned();
    let operations = &state.observation.operations;
    let path = format!("/api/v1/providers/{provider_id}/refresh");
    let Some(subscription) = subscription else {
        if let Some(replay) =
            operations.replay(state.principal(), "POST", &path, key.as_deref(), &body)?
        {
            return Ok(replay.admission().await?.into_response());
        }
        return Err(not_found());
    };
    let reservation = operations.reserve(
        state.principal(),
        "POST",
        &path,
        key.as_deref(),
        &body,
        OperationKind::ProviderRefresh,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        let prepared = async {
            state.require_running()?;
            let config = state.config.read().await;
            state.require_running()?;
            if !subscription.enabled {
                return Err(not_refreshable());
            }
            let supervisor = state
                .observation
                .providers
                .supervisor
                .read()
                .clone()
                .ok_or_else(not_refreshable)?;
            let display = Provider::observed(&subscription, ProviderLoad::default(), 0)
                .routed(&subscription, |name| {
                    super::geodata::group_id(&state.observation.core.catalog, name)
                })
                .mask_listener_secrets(&config, Some(&state.observation.configuration));
            Ok((subscription, supervisor, display))
        }
        .await;
        match prepared {
            Ok((subscription, supervisor, display)) => supervisor.refresh(
                subscription,
                Box::new(RefreshOperation {
                    reservation,
                    operations: Arc::clone(operations),
                    instance: state.observation.core.instance_id.clone(),
                    display_name: display.name,
                    display_url: display.url_redacted.expect("subscription URL is present"),
                    display_download: display.download,
                }),
            )?,
            Err(error) => {
                operations.reject(&reservation.id, error.clone());
                return Err(error);
            }
        }
    }
    Ok(admission.await?.into_response())
}

pub(crate) struct RefreshOperation {
    pub(crate) reservation: Reservation,
    pub(crate) operations: Arc<OperationStore>,
    pub(crate) instance: String,
    pub(crate) display_name: String,
    pub(crate) display_url: String,
    pub(crate) display_download: Option<Value>,
}

impl RefreshReport for RefreshOperation {
    fn accept(&self) {
        self.operations.accept(&self.reservation.id);
    }
    fn running(&self) {
        self.operations.running(&self.reservation.id);
    }
    fn reject(self: Box<Self>, refusal: RefreshRefusal) {
        self.operations.reject(&self.reservation.id, refusal.into());
    }

    fn finish(
        self: Box<Self>,
        subscription: &Subscription,
        load: ProviderLoad,
        result: Result<SubscriptionMergeReply, &'static str>,
    ) {
        let id = &self.reservation.id;
        match result {
            Ok(reply) => {
                match reply.outcome {
                    ReloadOutcome::Noop { .. } | ReloadOutcome::Committed { .. } => {
                        let mut provider = Provider::observed(subscription, load, reply.node_count);
                        provider.name = self.display_name;
                        provider.url_redacted = Some(self.display_url);
                        provider.download = self.display_download;
                        self.operations
                            .succeed(id, OperationResult::ProviderRefresh(provider));
                    }
                    ReloadOutcome::CommittedDegraded { generation } => {
                        self.operations.fail(id, "publication_degraded", "Provider nodes were committed but the runtime is degraded.", Some(json!({"committed": true, "active_generation_id": format!("{}:{generation}", self.instance), "datapath_generation_id": null})));
                    }
                    ReloadOutcome::Rejected => {
                        self.operations.fail(id, "publication_rejected", "Provider runtime publication was rejected; active nodes were retained.", rejection_details(reply.rejection));
                    }
                }
            }
            Err(code) => {
                self.operations.fail(
                    id,
                    code,
                    error_message(code)
                        .unwrap_or("Provider refresh did not complete successfully."),
                    None,
                );
            }
        }
    }
}

impl From<RefreshRefusal> for ApiError {
    fn from(refusal: RefreshRefusal) -> Self {
        match refusal {
            RefreshRefusal::NotRefreshable => not_refreshable(),
            RefreshRefusal::Busy => busy(),
            RefreshRefusal::Unavailable => unavailable(),
        }
    }
}

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Provider refresh admission is temporarily unavailable.",
        None,
    )
    .with_retry_after(1)
}
fn busy() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::StateConflict,
        "A refresh for this provider is already in flight.",
        None,
    )
}
fn not_refreshable() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "This provider cannot be refreshed.",
        None,
    )
}
fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "Provider was not found.",
        None,
    )
}

#[cfg(test)]
mod tests;
