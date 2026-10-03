//! Synchronous managed-entry actions use the daemon-owned source coordinator.

use std::sync::Arc;

use axum::{
    Json,
    extract::Request,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::{ApiError, ErrorCode, NativeState, config, parse_query, types::RequestId};

/// One year, the contract's ceiling for `update_interval`.
const MAX_UPDATE_INTERVAL: u64 = 365 * 24 * 60 * 60;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NodeCreate {
    pub(super) name: String,
    pub(super) link: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderCreate {
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) url: String,
    pub(super) update_interval: Option<u64>,
    pub(super) user_agent: Option<String>,
    pub(super) cache: Option<bool>,
}

impl ProviderCreate {
    pub(super) fn options(&self) -> honk_config::parser::source_edit::SubscriptionOptions<'_> {
        honk_config::parser::source_edit::SubscriptionOptions {
            update_interval: self.update_interval,
            user_agent: self.user_agent.as_deref(),
            cache: self.cache,
        }
    }
}

pub(super) enum Action {
    CreateNode,
    CreateProvider,
    Delete(Mutation),
}

pub(super) enum Mutation {
    CreateNode(NodeCreate),
    CreateProvider(ProviderCreate),
    DeleteNode(String),
    DeleteProvider(String),
}

impl Mutation {
    pub(super) fn deleting(&self) -> bool {
        matches!(self, Self::DeleteNode(_) | Self::DeleteProvider(_))
    }
}

pub(super) enum Completion {
    Created {
        collection: &'static str,
        id: Uuid,
        value: serde_json::Value,
    },
    Deleted(u8),
}

impl Completion {
    pub(super) fn response(self) -> Response {
        match self {
            Self::Created {
                collection,
                id,
                value,
            } => (
                StatusCode::CREATED,
                [(header::LOCATION, format!("/api/v1/{collection}/{id}"))],
                Json(value),
            )
                .into_response(),
            Self::Deleted(deleted) => Json(json!({"deleted":deleted})).into_response(),
        }
    }
}

pub(super) fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "This resource is not managed by the writable main source",
        None,
    )
}

pub(super) fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid management request",
        None,
    )
}

fn invalid_value(message: &'static str, details: serde_json::Value) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        message,
        None,
    )
    .with_details(details)
}

/// Details name the resource path and the rejected fields; submitted names,
/// links and URLs can hold secrets and are never echoed.
pub(super) fn unsupported_value(message: &'static str, details: serde_json::Value) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::UnsupportedValue,
        message,
        None,
    )
    .with_details(details)
}

pub(super) fn conflict() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::StateConflict,
        "A resource with this name already exists",
        None,
    )
}

pub(super) fn referenced(groups: &[&String]) -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::StateConflict,
        "Groups still name this node as their final outbound",
        None,
    )
    .with_details(json!({"groups":groups}))
}

pub(super) fn activation_error(
    stage: &'static str,
    written: Option<bool>,
    durability: Option<bool>,
    committed: Option<bool>,
    active_generation_id: Option<String>,
) -> ApiError {
    let mut details = json!({"stage":stage,"committed":committed});
    if let Some(written) = written {
        details["written"] = json!(written);
    }
    if let Some(durability) = durability {
        details["durability_confirmed"] = json!(durability);
    }
    if committed == Some(true) {
        details["active_generation_id"] = json!(active_generation_id);
    }
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Managed configuration change did not complete successfully",
        None,
    )
    .with_details(details)
}

/// The management error contract: every failure carries activation details, and
/// anything but a conflict, a stale revision or a request-shaped rejection of a
/// create is retryable unavailability.
fn contract_error(mut error: ApiError, deleting: bool) -> ApiError {
    let stage = match error.status {
        StatusCode::PRECONDITION_FAILED => "revision_conflict",
        StatusCode::UNPROCESSABLE_ENTITY => "validation",
        StatusCode::CONFLICT => "state_conflict",
        StatusCode::NOT_FOUND => "capability",
        _ => "admission",
    };
    if !matches!(
        error.status,
        StatusCode::NOT_FOUND
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::CONFLICT
            | StatusCode::PRECONDITION_FAILED
    ) && (deleting
        || !matches!(
            error.status,
            StatusCode::UNPROCESSABLE_ENTITY
                | StatusCode::BAD_REQUEST
                | StatusCode::PAYLOAD_TOO_LARGE
                | StatusCode::UNSUPPORTED_MEDIA_TYPE
        ))
    {
        error.status = StatusCode::SERVICE_UNAVAILABLE;
        error.error.code = ErrorCode::TemporarilyUnavailable;
    }
    let details = error.error.details.get_or_insert_with(|| json!({}));
    if let Some(details) = details.as_object_mut() {
        details.entry("stage").or_insert(json!(stage));
        details.entry("written").or_insert(json!(false));
        details.entry("committed").or_insert(json!(false));
    }
    error
}

pub(super) async fn mutate(
    state: &Arc<NativeState>,
    action: Action,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    state.observation.configuration.manage_admission()?;
    let deleting = matches!(action, Action::Delete(_));
    parse_query(request.uri(), &[], id)?;
    if !deleting {
        config::json_type(&request)?;
    }
    let body = super::body::buffered(request.into_body()).await;
    if deleting && !body.is_empty() {
        return Err(invalid());
    }
    let result = async {
        let mutation = match action {
            Action::Delete(mutation) => mutation,
            Action::CreateNode => {
                let input: NodeCreate = super::body::decode(&body, invalid)?;
                if !(1..=64).contains(&input.name.chars().count()) {
                    return Err(invalid_value(
                        "Node name must be 1 to 64 characters",
                        json!({"resource":"/nodes","field":"name"}),
                    ));
                }
                if !(1..=8192).contains(&input.link.chars().count()) {
                    return Err(invalid_value(
                        "Node share link must be 1 to 8192 characters",
                        json!({"resource":"/nodes","field":"link"}),
                    ));
                }
                Mutation::CreateNode(input)
            }
            Action::CreateProvider => {
                let input: ProviderCreate = super::body::decode(&body, invalid)?;
                let rejected = |message, field: &str| {
                    Err(invalid_value(
                        message,
                        json!({"resource":"/providers","field":field}),
                    ))
                };
                if input.kind != "subscription" {
                    return Err(invalid_value(
                        "Provider kind must be subscription",
                        json!({"resource":"/providers","field":"kind","allowed":["subscription"]}),
                    ));
                }
                if !(1..=64).contains(&input.name.len())
                    || !input
                        .name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                {
                    return rejected(
                        "Provider name must be 1 to 64 ASCII letters, digits, '_', '.' or '-'",
                        "name",
                    );
                }
                if !(1..=4096).contains(&input.url.chars().count()) {
                    return rejected("Provider URL must be 1 to 4096 characters", "url");
                }
                if !(input.url.starts_with("http://") || input.url.starts_with("https://"))
                    || reqwest::Url::parse(&input.url)
                        .ok()
                        .is_none_or(|url| url.host_str().is_none())
                {
                    return Err(unsupported_value(
                        "Provider URL must be an HTTP(S) URL with a host",
                        json!({"resource":"/providers","field":"url"}),
                    ));
                }
                if input
                    .update_interval
                    .is_some_and(|seconds| seconds > MAX_UPDATE_INTERVAL)
                {
                    return rejected(
                        "Provider update interval must be at most one year in seconds",
                        "update_interval",
                    );
                }
                if input.user_agent.as_ref().is_some_and(|agent| {
                    !(1..=256).contains(&agent.len())
                        || !agent.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
                }) {
                    return rejected(
                        "Provider user agent must be 1 to 256 printable ASCII characters",
                        "user_agent",
                    );
                }
                if input.cache.is_some() && !state.observation.providers.caches() {
                    return Err(unsupported_value(
                        "Provider cache requires global.store_subscribe",
                        json!({"resource":"/providers","field":"cache"}),
                    ));
                }
                Mutation::CreateProvider(input)
            }
        };
        let completion = state
            .observation
            .configuration
            .manage(
                mutation,
                Arc::clone(&state.observation.core.catalog),
                Arc::clone(&state.group_manager),
                Arc::clone(&state.alive_set),
            )
            .await?;
        Ok(completion.response())
    }
    .await;
    result.map_err(|error| contract_error(error, deleting))
}
