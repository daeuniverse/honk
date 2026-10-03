//! Bounded native DNS diagnostics and Exact cache control.

use std::{
    collections::{HashMap, VecDeque},
    io::{self, Write},
    sync::{Arc, Weak},
    time::{Duration, SystemTime},
};

use axum::{
    body::Body,
    extract::{Query, Request},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    ApiError, ErrorCode, NativeState, error, full_detail, invalid_query, timestamp,
    types::RequestId,
};
use crate::dns::{
    DiagnosticError, DiagnosticFailure,
    forwarder::{CacheAccess, ResolveOptions},
    outcome::RequestRoute,
    planner::UpstreamTag,
    query::IngressProfile,
};
use crate::observe::{DnsRecorder, flows::FlowStore};

mod cache;
pub(super) mod log;
mod records;
pub(super) mod rules;
#[cfg(test)]
mod tests;

pub(crate) use rules::capability as rules_capability;

pub(super) const MAX_RESPONSE_BYTES: usize = 262_144;
const MAX_QUERY_TYPES: usize = 8;
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const TYPES: &[u16] = &[1, 2, 5, 6, 12, 15, 16, 28, 33, 64, 65, 257];

pub(crate) struct DnsApi {
    rate: super::security::RequestRate,
    snapshots: tokio::sync::Mutex<VecDeque<cache::Snapshot>>,
    log: Arc<log::DnsHistory>,
    pub(crate) recorder: Arc<DnsRecorder>,
}

impl DnsApi {
    pub(crate) fn new(instance_id: String, recording: bool, flows: Weak<FlowStore>) -> Self {
        let log = Arc::new(log::DnsHistory::new(instance_id.clone(), recording));
        Self {
            recorder: Arc::new(DnsRecorder::new(instance_id, flows, log.clone())),
            log,
            rate: super::security::RequestRate::new(),
            snapshots: tokio::sync::Mutex::new(VecDeque::new()),
        }
    }

    pub(crate) fn set_log_limit(&self, limit: usize) {
        self.log.set_limit(limit);
    }
    pub(crate) fn set_recording(&self, recording: bool) {
        self.log.set_recording(recording);
    }
    pub(crate) fn query_capability(&self) -> Value {
        json!({"available":true,"record_types":TYPES.iter().map(|&value| records::record_type(value)).collect::<Vec<_>>(),
            "limits":{"max_types_per_request":MAX_QUERY_TYPES,"query_timeout_ms":QUERY_TIMEOUT.as_millis(),"max_response_bytes":MAX_RESPONSE_BYTES,
            "per_principal_requests_per_minute":super::security::REQUESTS_PER_MINUTE,"global_requests_per_minute":super::security::REQUESTS_PER_MINUTE}})
    }
    pub(crate) fn cache_capability(&self) -> Value {
        json!({"available":true,"read":true,"delete_entry":true,"delete_name":true,"flush":true,"entry_kinds":["positive","negative"]})
    }
    pub(crate) fn log_capability(&self) -> Value {
        self.log.capability()
    }
    #[cfg(test)]
    pub(crate) fn log_for_test(&self) -> &log::DnsHistory {
        &self.log
    }
}

pub(super) fn validate_name(name: &str) -> bool {
    if name == "." {
        return true;
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'_')
        })
}

fn canonical_name(name: &str, id: &RequestId) -> Result<String, ApiError> {
    if !validate_name(name) {
        return Err(invalid_query(id));
    }
    if name == "." {
        return Ok(name.to_owned());
    }
    Ok(format!(
        "{}.",
        name.trim_end_matches('.').to_ascii_lowercase()
    ))
}

fn parameters(
    uri: &Uri,
    allowed: &[&str],
    id: &RequestId,
) -> Result<(HashMap<String, String>, Vec<u16>), ApiError> {
    let Query(pairs) =
        Query::<Vec<(String, String)>>::try_from_uri(uri).map_err(|_| invalid_query(id))?;
    let mut values = HashMap::new();
    let mut types = Vec::new();
    for (key, value) in pairs {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid_query(id));
        }
        if key == "type" {
            let qtype = records::parse_type(&value).ok_or_else(|| invalid_query(id))?;
            if types.contains(&qtype) {
                return Err(invalid_query(id));
            }
            types.push(qtype);
        } else if values.insert(key, value).is_some() {
            return Err(invalid_query(id));
        }
    }
    Ok((values, types))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryBody {
    domain: String,
    #[serde(rename = "type")]
    types: Option<Vec<String>>,
    upstream: Option<String>,
    cache_mode: Option<String>,
}

pub(super) async fn query(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let (values, _) = parameters(request.uri(), &["detail"], id)?;
    let full = full_detail(&values, id)?;
    super::config::json_type(&request)?;
    let bytes = super::body::buffered(request.into_body()).await;
    if bytes.len() > 4096 {
        return Err(error(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::RequestTooLarge,
            "DNS query body is too large",
            id,
        ));
    }
    let invalid = || {
        error(
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidRequest,
            "Invalid DNS query body",
            id,
        )
    };
    let body: QueryBody = super::body::decode(&bytes, invalid)?;
    let domain = canonical_name(&body.domain, id).map_err(|_| invalid())?;
    let names = body.types.unwrap_or_else(|| vec!["A".into()]);
    let mut types = Vec::with_capacity(names.len());
    for name in &names {
        let qtype = records::parse_type(name).ok_or_else(invalid)?;
        if types.contains(&qtype) {
            return Err(invalid());
        }
        types.push(qtype);
    }
    if types.is_empty() {
        return Err(invalid());
    }
    if types.len() > MAX_QUERY_TYPES {
        return Err(error(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::RequestTooLarge,
            "Too many DNS record types",
            id,
        ));
    }
    if types.iter().any(|value| !TYPES.contains(value)) {
        return Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::UnsupportedValue,
            "Unsupported DNS record type",
            id,
        ));
    }
    let cache_mode = body.cache_mode.as_deref().unwrap_or("normal");
    let options = ResolveOptions {
        cache: match cache_mode {
            "normal" => CacheAccess::Normal,
            "bypass" => CacheAccess::Bypass,
            _ => return Err(invalid()),
        },
        forced_upstream: body
            .upstream
            .as_deref()
            .map(UpstreamTag::new)
            .transpose()
            .map_err(|_| invalid())?,
    };
    state.require_running().map_err(|_| unavailable(id))?;
    state.observation.dns.rate.admit(id)?;
    let query_time = timestamp(SystemTime::now());
    let results = state
        .dns
        .diagnostic(
            &domain,
            &types,
            &options,
            tokio::time::Instant::now() + QUERY_TIMEOUT,
        )
        .await
        .map_err(|error| match error {
            DiagnosticError::UnknownUpstream => error_response_upstream(id),
            DiagnosticError::Unavailable => unavailable(id),
        })?;
    let mut budget = MAX_RESPONSE_BYTES.saturating_sub(4096);
    let mut rows = Vec::with_capacity(results.len());
    for result in results {
        let question =
            records::question(&result.query, IngressProfile::Api).map_err(|_| unavailable(id))?;
        let mut row = json!({"type": question.rtype, "question": question, "elapsed_ms": result.elapsed.as_millis().min(u128::from(crate::observe::MAX_SAFE_UINT)) as u64});
        match result.outcome {
            Ok(outcome) => {
                let cached = outcome.is_cached();
                row["cached"] = json!(cached);
                row["cache_entry_id"] = json!(outcome.cache_entry_id());
                row["upstream"] = json!(if cached {
                    None
                } else {
                    outcome.final_upstream()
                });
                row["route"] = json!(outcome.request_route());
                row["status"] = json!(records::status(outcome.rendered()));
                if full {
                    row["answers"] = json!(
                        records::project(
                            &result.query,
                            outcome.rendered(),
                            IngressProfile::Api,
                            &mut budget
                        )
                        .map_err(|_| unavailable(id))?
                    );
                }
            }
            Err(failure) => {
                row["cached"] = json!(false);
                row["cache_entry_id"] = Value::Null;
                row["upstream"] = Value::Null;
                row["route"] = json!(RequestRoute {
                    source: result.route,
                    rule: None
                });
                row["status"] = json!(match failure {
                    DiagnosticFailure::Timeout => "TIMEOUT",
                    DiagnosticFailure::Refused => "REFUSED",
                    DiagnosticFailure::Error => "ERROR",
                });
                if full {
                    row["answers"] = json!([]);
                }
            }
        }
        rows.push(row);
    }
    bounded_response(
        &json!({"domain": domain, "cache_mode": cache_mode, "query_time": query_time, "results": rows}),
        id,
    )
}

fn error_response_upstream(id: &RequestId) -> ApiError {
    error(
        StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::UnsupportedValue,
        "Unknown configured DNS upstream",
        id,
    )
}

fn unavailable(id: &RequestId) -> ApiError {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "DNS observation is temporarily unavailable",
        id,
    )
    .with_retry_after(1)
}

struct BoundedJson(Vec<u8>, usize);
impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > self.1 {
            return Err(io::Error::other("DNS response budget exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn bounded_response(value: &impl Serialize, id: &RequestId) -> Result<Response, ApiError> {
    json_response(value, MAX_RESPONSE_BYTES, id)
}
fn json_response(value: &impl Serialize, cap: usize, id: &RequestId) -> Result<Response, ApiError> {
    let mut writer = BoundedJson(Vec::new(), cap);
    serde_json::to_writer(&mut writer, value).map_err(|_| unavailable(id))?;
    Ok((
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(writer.0),
    )
        .into_response())
}

pub(super) async fn cache(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    cache::serve(state, uri, id).await
}
pub(super) async fn log(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    log::serve(state, uri, id).await
}

async fn empty_body(request: Request, allow_object: bool, id: &RequestId) -> Result<(), ApiError> {
    let json_type = super::config::json_type(&request);
    let body = super::body::buffered(request.into_body()).await;
    if body.is_empty() {
        return Ok(());
    }
    if !allow_object {
        return Err(invalid_query(id));
    }
    json_type?;
    super::body::no_inputs(&body, || invalid_query(id))
}

pub(super) async fn delete_name(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let (values, types) = parameters(request.uri(), &["name", "type"], id)?;
    let name = canonical_name(values.get("name").ok_or_else(|| invalid_query(id))?, id)?;
    empty_body(request, false, id).await?;
    let result = state
        .dns
        .invalidate_cache(crate::dns::cache::CacheInvalidation::Name { name, types })
        .await
        .map_err(|_| unavailable(id))?;
    bounded_response(
        &json!({"matched":result.deleted,"deleted":result.deleted}),
        id,
    )
}

pub(super) async fn delete_entry(
    state: &NativeState,
    entry_id: &str,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parameters(request.uri(), &[], id)?;
    empty_body(request, false, id).await?;
    let result = state
        .dns
        .invalidate_cache(crate::dns::cache::CacheInvalidation::Id(
            entry_id.to_owned(),
        ))
        .await
        .map_err(|_| unavailable(id))?;
    bounded_response(&json!({"deleted":result.deleted}), id)
}

pub(super) async fn flush(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parameters(request.uri(), &[], id)?;
    empty_body(request, true, id).await?;
    let result = state
        .dns
        .invalidate_cache(crate::dns::cache::CacheInvalidation::All)
        .await
        .map_err(|_| unavailable(id))?;
    bounded_response(
        &json!({"matched":result.deleted,"deleted":result.deleted}),
        id,
    )
}
