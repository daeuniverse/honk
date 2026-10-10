//! Source-owned restricted RFC 6902 group edits; selection remains runtime state.

use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use honk_config::{group::Group, parser::source_edit::GroupField};
use honk_outbound::group::GroupMember;
use serde_json::{Value, json};

use super::{
    ApiError, ErrorCode, NativeState, config, operations::OperationKind, parse_query,
    types::RequestId,
};

pub(super) const MAX_PATCH_OPERATIONS: usize = 32;

/// Patchable settings: wire field name, JSON pointer and source edit, indexed by the constants below.
pub(super) const FIELDS: [(&str, &str, GroupField); 7] = [
    ("policy", "/policy", GroupField::Policy),
    (
        "default_member_id",
        "/config/default_member_id",
        GroupField::Default,
    ),
    (
        "final_outbound",
        "/config/final_outbound",
        GroupField::Final,
    ),
    ("tolerance", "/config/tolerance", GroupField::Tolerance),
    (
        "idle_timeout",
        "/config/idle_timeout",
        GroupField::IdleTimeout,
    ),
    (
        "interrupt_connections",
        "/config/interrupt_connections",
        GroupField::InterruptConnections,
    ),
    ("check_url", "/config/check_url", GroupField::CheckUrl),
];
const POLICY: usize = 0;
const DEFAULT: usize = 1;
const FINAL: usize = 2;
const TOLERANCE: usize = 3;
const IDLE_TIMEOUT: usize = 4;
const INTERRUPT: usize = 5;
const CHECK_URL: usize = 6;
const MAX_CHECK_URL_BYTES: usize = 2048;

fn paths() -> [&'static str; 7] {
    FIELDS.map(|(_, path, _)| path)
}

pub(super) struct GroupPatch {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) revision: String,
    pub(super) expected: Result<config::IfMatch, ApiError>,
    group: Group,
    members: Vec<(String, String)>,
    operations: Value,
}

fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid or unsupported group patch",
        None,
    )
}

pub(super) fn read_only() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "Group source is not writable",
        None,
    )
}

/// Details name schema fields and paths only; submitted pointers and values
/// and configured member names can hold secrets and are never echoed.
fn unsupported(message: &'static str, details: Value) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::UnsupportedValue,
        message,
        None,
    )
    .with_details(details)
}

fn unsupported_value(index: usize) -> ApiError {
    unsupported(
        "Group patch value is unsupported",
        json!({"field": FIELDS[index].0}),
    )
}

fn tolerance_not_urltest() -> ApiError {
    unsupported(
        "Group tolerance applies only to URLTest groups",
        json!({"field": FIELDS[TOLERANCE].0}),
    )
}

/// The index of the supported path held by the operation's `key` pointer.
fn field(operation: &serde_json::Map<String, Value>, key: &'static str) -> Result<usize, ApiError> {
    let pointer = operation
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let paths = paths();
    paths
        .iter()
        .position(|candidate| *candidate == pointer)
        .ok_or_else(|| {
            unsupported(
                "Group patch path is unsupported",
                json!({"field": key, "allowed": paths}),
            )
        })
}

fn integer(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .filter(|value| *value <= crate::observe::MAX_SAFE_UINT)
        .or_else(|| {
            value
                .as_f64()
                .filter(|value| {
                    *value >= 0.0
                        && *value <= crate::observe::MAX_SAFE_UINT as f64
                        && value.fract() == 0.0
                })
                .map(|value| value as u64)
        })
}

/// The stored form of a supported value, as GET reports it.
fn normalized(index: usize, value: &Value) -> Option<Value> {
    let valid = match index {
        POLICY => value.as_object().is_some_and(|policy| {
            policy.len() == 2
                && policy
                    .get("kind")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| {
                        ["selector", "urltest", "loadbalance", "fallback", "score"].contains(&kind)
                            && policy.get("native").and_then(Value::as_str) == Some(kind)
                    })
        }),
        DEFAULT | FINAL => value.is_null() || value.as_str().is_some_and(|value| !value.is_empty()),
        TOLERANCE | IDLE_TIMEOUT if !value.is_null() => return integer(value).map(Value::from),
        INTERRUPT => value.is_null() || value.is_boolean(),
        CHECK_URL if !value.is_null() => {
            return value.as_str().and_then(check_url).map(Value::from);
        }
        TOLERANCE | IDLE_TIMEOUT | CHECK_URL => true,
        _ => false,
    };
    valid.then(|| value.clone())
}

/// The contract's SafeHttpUrl in the normalized form the probe sends: health
/// checks split on commas and the source edit needs a usable quote.
fn check_url(value: &str) -> Option<String> {
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))?;
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if authority.contains('@')
        || value
            .chars()
            .any(|char| char.is_whitespace() || char.is_control())
    {
        return None;
    }
    crate::observe::catalog::normalized_check_url(value).filter(|url| {
        url.len() <= MAX_CHECK_URL_BYTES
            && !url.contains(',')
            && !(url.contains('\'') && url.contains('"'))
    })
}

/// The body checks that precede the `If-Match` comparison: a non-empty array
/// within the operation limit whose operations name a known `op`, their
/// required members and supported paths.
fn operation_list(value: &Value) -> Result<&Vec<Value>, ApiError> {
    let operations = value
        .as_array()
        .filter(|operations| !operations.is_empty())
        .ok_or_else(invalid)?;
    if operations.len() > MAX_PATCH_OPERATIONS {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::RequestTooLarge,
            "Group patch operation limit exceeded",
            None,
        ));
    }
    for operation in operations {
        let operation = operation.as_object().ok_or_else(invalid)?;
        let op = operation.get("op").and_then(Value::as_str);
        let complete = match op {
            Some("add" | "replace" | "test") => operation.contains_key("value"),
            Some("remove" | "copy" | "move") => true,
            _ => false,
        };
        if !complete {
            return Err(invalid());
        }
        field(operation, "path")?;
        if matches!(op, Some("copy" | "move")) {
            field(operation, "from")?;
        }
    }
    Ok(operations)
}

impl GroupPatch {
    /// Body checks that the coordinator runs before the revision comparison.
    pub(super) fn validate_shape(&self) -> Result<(), ApiError> {
        operation_list(&self.operations).map(drop)
    }

    pub(super) fn changes(&self) -> Result<Vec<(GroupField, Option<String>)>, ApiError> {
        let policy = serde_json::to_value(self.group.policy).map_err(|_| invalid())?;
        let default = self
            .group
            .default
            .as_ref()
            .and_then(|name| self.members.iter().find(|(_, member)| member == name))
            .map(|(id, _)| id);
        let initial = [
            json!({"kind":policy,"native":policy}),
            json!(default),
            json!(self.group.final_outbound),
            json!(crate::observe::catalog::tolerance(&self.group)),
            json!(self.group.idle_timeout),
            json!(crate::observe::catalog::interrupt_connections(&self.group)),
            json!(crate::observe::catalog::check_url(&self.group)),
        ];
        let mut values = initial.clone().map(Some);
        let operations = operation_list(&self.operations)?;
        let rejected = |op: &str, path: usize| {
            // Without a policy write the group cannot become URLTest, so any
            // tolerance write fails on the policy rule whatever its value.
            let never_urltest = || {
                initial[POLICY]["kind"] != "urltest"
                    && !operations.iter().any(|operation| {
                        operation.get("path").and_then(Value::as_str) == Some(FIELDS[POLICY].1)
                    })
            };
            if path == TOLERANCE && op != "test" && never_urltest() {
                tolerance_not_urltest()
            } else {
                unsupported_value(path)
            }
        };
        for operation in operations {
            let operation = operation.as_object().ok_or_else(invalid)?;
            let op = operation
                .get("op")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            let path = field(operation, "path")?;
            match op {
                "add" | "replace" | "test" => {
                    if !operation.contains_key("value") {
                        return Err(invalid());
                    }
                    let value =
                        normalized(path, &operation["value"]).ok_or_else(|| rejected(op, path))?;
                    if op != "add" && values[path].is_none() {
                        return Err(invalid());
                    }
                    if op == "test" {
                        if values[path].as_ref() != Some(&value) {
                            return Err(ApiError::new(
                                StatusCode::CONFLICT,
                                ErrorCode::StateConflict,
                                "Group patch test failed",
                                None,
                            ));
                        }
                    } else {
                        values[path] = Some(value);
                    }
                }
                "remove" => {
                    if values[path].take().is_none() {
                        return Err(invalid());
                    }
                }
                "copy" | "move" => {
                    let from = field(operation, "from")?;
                    let value = values[from].as_ref().ok_or_else(invalid)?;
                    let value = normalized(path, value).ok_or_else(|| rejected(op, path))?;
                    if op == "move" {
                        values[from] = None;
                    }
                    values[path] = Some(value);
                }
                _ => return Err(invalid()),
            }
        }
        let urltest = values[POLICY]
            .as_ref()
            .and_then(|policy| policy["kind"].as_str())
            == Some("urltest");
        if !urltest
            && values[TOLERANCE]
                .as_ref()
                .is_some_and(|value| !value.is_null() && *value != initial[TOLERANCE])
        {
            return Err(tolerance_not_urltest());
        }
        let mut changes = Vec::new();
        for (index, value) in values.iter().enumerate() {
            if value.as_ref() == Some(&initial[index]) {
                continue;
            }
            let value = match value.as_ref().filter(|value| !value.is_null()) {
                None => None,
                Some(value) if index == POLICY => {
                    Some(value["kind"].as_str().ok_or_else(invalid)?.to_owned())
                }
                Some(value) if index == DEFAULT => {
                    let id = value.as_str().ok_or_else(invalid)?;
                    let (_, name) = self
                        .members
                        .iter()
                        .find(|(member, _)| member == id)
                        .ok_or_else(|| {
                            unsupported(
                                "Group default member is not a direct member",
                                json!({"field": FIELDS[DEFAULT].0}),
                            )
                        })?;
                    // Dae defaults are names: reject identities shadowed by an earlier same-name member.
                    if self
                        .members
                        .iter()
                        .find(|(_, member)| member == name)
                        .map(|(member, _)| member.as_str())
                        != Some(id)
                    {
                        return Err(unsupported(
                            "Group default member shares its name with an earlier member",
                            json!({"field": FIELDS[DEFAULT].0}),
                        ));
                    }
                    Some(name.clone())
                }
                Some(value) => Some(
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string()),
                ),
            };
            changes.push((FIELDS[index].2, value));
        }
        Ok(changes)
    }
}

pub(super) async fn patch(
    state: &NativeState,
    group_id: &str,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    let service = &state.observation.configuration;
    if let Some(reason) = service.write_refusal() {
        return Err(read_only().with_reason(reason));
    }
    if config::request_header(&request, "content-type")?
        .and_then(|value| value.split(';').next())
        .is_none_or(|value| {
            !value
                .trim()
                .eq_ignore_ascii_case("application/json-patch+json")
        })
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            "Expected application/json-patch+json",
            None,
        ));
    }
    let expected = config::IfMatch::from_request(&request).and_then(|condition| {
        condition.ok_or_else(|| {
            ApiError::new(
                StatusCode::PRECONDITION_REQUIRED,
                ErrorCode::PreconditionRequired,
                "A strong group revision is required",
                None,
            )
        })
    });
    let key = config::request_header(&request, "idempotency-key")?.map(str::to_owned);
    let path = request.uri().path().to_owned();
    let bytes = super::body::buffered(request.into_body()).await;
    let operations = super::body::value(&bytes, invalid)?;
    let reservation = state.observation.operations.reserve(
        state.principal(),
        "PATCH",
        &path,
        key.as_deref(),
        &bytes,
        OperationKind::GroupUpdate,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        let captured = async {
            let _config = state.config.read().await;
            let identity = state.observation.core.catalog.snapshot();
            let name = identity
                .groups
                .iter()
                .find(|(_, value)| value.as_str() == group_id)
                .map(|(name, _)| name)
                .ok_or_else(|| {
                    ApiError::new(
                        StatusCode::NOT_FOUND,
                        ErrorCode::ResourceNotFound,
                        "Group was not found",
                        None,
                    )
                })?;
            let manager = state.group_manager.read().clone();
            let group = manager.group(name).ok_or_else(invalid)?.clone();
            let members = manager
                .group_members(name)
                .filter_map(|member| match member {
                    GroupMember::Node(node) => Some((node.id.to_string(), node.name.clone())),
                    GroupMember::Group(group) => identity
                        .groups
                        .get(&group.name)
                        .map(|id| (id.clone(), group.name.clone())),
                })
                .collect();
            Ok::<_, ApiError>(GroupPatch {
                id: group_id.to_owned(),
                name: name.clone(),
                revision: service.sources.revision().ok_or_else(invalid)?,
                expected,
                group,
                members,
                operations,
            })
        }
        .await;
        match captured {
            Ok(patch) => service.enqueue_group_patch(patch, reservation)?,
            Err(error) => {
                state.observation.operations.reject(&reservation.id, error);
            }
        }
    }
    Ok(admission.await?.into_response())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionBody {
    member_id: String,
    network: NetworkChoice,
}

#[derive(Clone, Copy, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum NetworkChoice {
    Tcp,
    Udp,
    Both,
}

pub(super) async fn select(
    state: &NativeState,
    group_id: &str,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    state.require_running()?;
    config::json_type(&request)?;
    if config::request_header(&request, "idempotency-key")?.is_some_and(str::is_empty) {
        return Err(invalid());
    }
    let bytes = super::body::buffered(request.into_body()).await;
    let body: SelectionBody = super::body::decode(&bytes, invalid)?;
    if body.member_id.is_empty() || body.member_id.len() > 256 {
        return Err(invalid());
    }
    let networks = body.network.into();
    let selected = apply_selection(
        state,
        crate::control::client::SelectionRequest::Native {
            group_id: group_id.to_owned(),
            member_id: body.member_id.clone(),
            networks,
        },
        id,
    )
    .await?;
    let source = if selected.overridden {
        "override"
    } else {
        "runtime"
    };
    Ok(axum::Json(json!({"group_id":group_id,"member_id":body.member_id,"network":body.network,"source":source,"selection_revision":format!("{}:selection:{}",state.instance_id,selected.revision),"connections_interrupted":selected.interrupted})).into_response())
}

/// Unpin an automatic group; a Selector has no override to clear.
pub(super) async fn clear_override(
    state: &NativeState,
    group_id: &str,
    uri: &axum::http::Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let query = parse_query(uri, &["network"], id)?;
    let network = match query.get("network").map(String::as_str) {
        None | Some("both") => NetworkChoice::Both,
        Some("tcp") => NetworkChoice::Tcp,
        Some("udp") => NetworkChoice::Udp,
        Some(_) => return Err(super::invalid_query(id)),
    };
    state.require_running()?;
    let cleared = apply_selection(
        state,
        crate::control::client::SelectionRequest::ClearOverride {
            group_id: group_id.to_owned(),
            networks: network.into(),
        },
        id,
    )
    .await?;
    Ok(axum::Json(json!({"group_id":group_id,"network":network,"selection_revision":format!("{}:selection:{}",state.instance_id,cleared.revision),"connections_interrupted":cleared.interrupted,"selection":cleared.selection})).into_response())
}

async fn apply_selection(
    state: &NativeState,
    request: crate::control::client::SelectionRequest,
    id: &RequestId,
) -> Result<crate::control::client::SelectionResult, ApiError> {
    crate::control::ControlClient::new(state.control_tx.clone())
        .select(request)
        .await
        .map_err(|reason| {
            let (status, code) = match reason {
                crate::control::client::ControlError::NotFound => {
                    (StatusCode::NOT_FOUND, ErrorCode::ResourceNotFound)
                }
                crate::control::client::ControlError::Unsupported => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    ErrorCode::UnsupportedValue,
                ),
                crate::control::client::ControlError::Conflict => {
                    (StatusCode::CONFLICT, ErrorCode::StateConflict)
                }
                _ => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::TemporarilyUnavailable,
                ),
            };
            super::error(
                status,
                code,
                "Selection transition could not be confirmed",
                id,
            )
        })
}

impl From<NetworkChoice> for honk_outbound::group::SelectorNetworks {
    fn from(network: NetworkChoice) -> Self {
        match network {
            NetworkChoice::Tcp => Self::Tcp,
            NetworkChoice::Udp => Self::Udp,
            NetworkChoice::Both => Self::Both,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operations: Value) -> GroupPatch {
        GroupPatch {
            id: "group".into(),
            name: "G".into(),
            revision: "r".into(),
            expected: Ok(config::IfMatch::Tags(vec!["r".into()])),
            group: Group {
                policy: honk_config::group::GroupPolicy::URLTest,
                own: honk_config::group::OwnOptions {
                    tolerance: true,
                    ..Default::default()
                },
                ..Group::default()
            },
            members: vec![("node".into(), "A".into())],
            operations,
        }
    }

    #[test]
    fn sequential_patch_move_copy_test_and_failure_are_atomic() {
        let patch = request(json!([
            {"op":"test","path":"/config/tolerance","value":50.0},
            {"op":"copy","from":"/config/tolerance","path":"/config/idle_timeout"},
            {"op":"move","from":"/config/idle_timeout","path":"/config/tolerance"},
            {"op":"add","path":"/config/default_member_id","value":"node"}
        ]));
        assert_eq!(
            patch.changes().unwrap(),
            vec![
                (GroupField::Default, Some("A".into())),
                (GroupField::IdleTimeout, None)
            ]
        );
        for operations in [
            json!([{"op":"replace","path":"/config/tolerance","value":9},{"op":"test","path":"/config/tolerance","value":50}]),
            json!([{"op":"remove","path":"/config/tolerance"},{"op":"replace","path":"/config/tolerance","value":1}]),
            json!([{"op":"copy","path":"/policy","from":"/config/tolerance"}]),
            json!([{"op":"replace","path":"/config/check_url","value":"localhost/"}]),
            json!([{"op":"replace","path":"/config/tolerance","value":0.5}]),
            json!(vec![
                json!({"op":"test","path":"/config/tolerance","value":50});
                33
            ]),
        ] {
            assert!(request(operations).changes().is_err());
        }
    }

    #[test]
    fn operation_members_outside_the_operation_are_ignored() {
        let patch = request(json!([
            {"op":"test","path":"/config/tolerance","value":50,"comment":"current"},
            {"op":"copy","from":"/config/tolerance","path":"/config/idle_timeout","value":1},
            {"op":"remove","path":"/config/final_outbound","from":"/policy"},
            {"op":"replace","path":"/config/tolerance","value":60,"x":null}
        ]));
        assert_eq!(
            patch.changes().unwrap(),
            vec![
                (GroupField::Final, None),
                (GroupField::Tolerance, Some("60".into())),
                (GroupField::IdleTimeout, Some("50".into()))
            ]
        );
        for operations in [
            json!([{"op":"replace","path":"/config/tolerance","comment":"no value"}]),
            json!([{"op":"copy","path":"/config/idle_timeout","value":1}]),
        ] {
            assert_eq!(
                request(operations).changes().unwrap_err().status,
                StatusCode::BAD_REQUEST
            );
        }
    }

    #[test]
    fn unsupported_errors_name_the_schema_field_but_not_submitted_or_configured_values() {
        let score = |operations: Value| {
            let mut patch = request(operations);
            patch.group.policy = honk_config::group::GroupPolicy::Score;
            patch
        };
        let mut shadowed =
            request(json!([{"op":"replace","path":"/config/default_member_id","value":"second"}]));
        shadowed.members = vec![
            ("first".into(), "PRIVATE".into()),
            ("second".into(), "PRIVATE".into()),
        ];
        let allowed = |field| json!({"field":field,"allowed":paths()});
        for (patch, message, details) in [
            (
                request(json!([{"op":"replace","path":"/config/PRIVATE","value":1}])),
                "Group patch path is unsupported",
                allowed("path"),
            ),
            (
                request(json!([{"op":"copy","from":"/PRIVATE","path":"/config/tolerance"}])),
                "Group patch path is unsupported",
                allowed("from"),
            ),
            (
                request(
                    json!([{"op":"replace","path":"/config/check_url","value":"https://u:PRIVATE@example.test/"}]),
                ),
                "Group patch value is unsupported",
                json!({"field":"check_url"}),
            ),
            (
                request(json!([{"op":"copy","path":"/policy","from":"/config/tolerance"}])),
                "Group patch value is unsupported",
                json!({"field":"policy"}),
            ),
            (
                score(json!([{"op":"replace","path":"/config/tolerance","value":100}])),
                "Group tolerance applies only to URLTest groups",
                json!({"field":"tolerance"}),
            ),
            (
                score(json!([{"op":"replace","path":"/config/tolerance","value":"PRIVATE"}])),
                "Group tolerance applies only to URLTest groups",
                json!({"field":"tolerance"}),
            ),
            (
                score(json!([{"op":"test","path":"/config/tolerance","value":"PRIVATE"}])),
                "Group patch value is unsupported",
                json!({"field":"tolerance"}),
            ),
            (
                score(json!([
                    {"op":"replace","path":"/config/tolerance","value":"PRIVATE"},
                    {"op":"replace","path":"/policy","value":{"kind":"urltest","native":"urltest"}}
                ])),
                "Group patch value is unsupported",
                json!({"field":"tolerance"}),
            ),
            (
                request(
                    json!([{"op":"replace","path":"/config/default_member_id","value":"PRIVATE"}]),
                ),
                "Group default member is not a direct member",
                json!({"field":"default_member_id"}),
            ),
            (
                shadowed,
                "Group default member shares its name with an earlier member",
                json!({"field":"default_member_id"}),
            ),
        ] {
            let error = serde_json::to_value(patch.changes().unwrap_err()).unwrap();
            assert_eq!(error["error"]["code"], "unsupported_value");
            assert_eq!(error["error"]["message"], message);
            assert_eq!(error["error"]["details"], details);
            assert!(!error.to_string().contains("PRIVATE"), "{error}");
        }
    }

    #[test]
    fn check_url_patch_accepts_safe_http_urls_and_null() {
        let change = |value: Value| {
            request(json!([{"op":"replace","path":"/config/check_url","value":value}])).changes()
        };
        for (url, written) in [
            ("https://www.gstatic.com/generate_204", None),
            ("http://127.0.0.1:8080/probe?x=1", None),
            ("https://[::1]/a@b", None),
            ("https://example.test/it's", None),
            ("http://example.test", Some("http://example.test/")),
            (
                "https://example.test/p#frag",
                Some("https://example.test/p"),
            ),
            ("http://Example.Test:80/x", Some("http://example.test/x")),
            ("http://example.test?x", Some("http://example.test/?x")),
        ] {
            assert_eq!(
                change(json!(url)).unwrap(),
                vec![(GroupField::CheckUrl, Some(written.unwrap_or(url).into()))]
            );
        }
        assert!(change(Value::Null).unwrap().is_empty());
        let long = format!("https://example.test/{}", "a".repeat(2048));
        for url in [
            "ftp://example.test/",
            "https://user:pass@example.test/",
            "https://user@example.test/",
            "example.test/generate_204",
            "HTTPS://example.test/",
            "https:///path",
            "https://a.test/,https://b.test/",
            " https://example.test/",
            "https://example.test/a\u{a0}b",
            "https://example.test/a\u{85}b",
            "https://example.test/'\"",
            long.as_str(),
        ] {
            assert!(change(json!(url)).is_err(), "{url}");
        }
        assert!(change(json!(204)).is_err());
    }

    #[test]
    fn check_url_test_compares_the_catalog_form() {
        let mut patch = request(json!([
            {"op":"test","path":"/config/check_url","value":"http://example.test/"},
            {"op":"remove","path":"/config/check_url"}
        ]));
        patch.group.check_url = Some("example.test".into());
        assert_eq!(patch.changes().unwrap(), vec![(GroupField::CheckUrl, None)]);
        patch.operations =
            json!([{"op":"replace","path":"/config/check_url","value":"http://example.test/"}]);
        assert!(patch.changes().unwrap().is_empty());
    }

    #[test]
    fn tolerance_patch_applies_only_to_urltest() {
        let score = |operations: Value| {
            let mut patch = request(operations);
            patch.group.policy = honk_config::group::GroupPolicy::Score;
            patch.changes()
        };
        let to_score =
            json!({"op":"replace","path":"/policy","value":{"kind":"score","native":"score"}});
        let to_urltest =
            json!({"op":"replace","path":"/policy","value":{"kind":"urltest","native":"urltest"}});
        assert!(
            score(json!([{"op":"test","path":"/config/tolerance","value":null}]))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            score(json!([{"op":"remove","path":"/config/tolerance"}])).unwrap(),
            vec![(GroupField::Tolerance, None)]
        );
        assert_eq!(
            request(json!([to_score, {"op":"remove","path":"/config/tolerance"}]))
                .changes()
                .unwrap(),
            vec![
                (GroupField::Policy, Some("score".into())),
                (GroupField::Tolerance, None)
            ]
        );
        assert_eq!(
            score(json!([to_urltest, {"op":"replace","path":"/config/tolerance","value":100}]))
                .unwrap(),
            vec![
                (GroupField::Policy, Some("urltest".into())),
                (GroupField::Tolerance, Some("100".into()))
            ]
        );
        for patch in [
            score(json!([{"op":"replace","path":"/config/tolerance","value":100}])),
            score(json!([{"op":"add","path":"/config/tolerance","value":0}])),
            request(json!([to_score, {"op":"replace","path":"/config/tolerance","value":100}]))
                .changes(),
        ] {
            assert!(patch.is_err());
        }
    }
}
