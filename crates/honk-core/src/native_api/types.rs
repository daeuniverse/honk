//! Wire types for the pinned native API contract.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::{Map, Value, json};

#[derive(Clone, Copy, Debug)]
pub enum ErrorCode {
    InvalidRequest,
    AuthenticationRequired,
    PermissionDenied,
    ResourceNotFound,
    CapabilityNotSupported,
    MethodNotAllowed,
    StateConflict,
    IdempotencyConflict,
    EventCursorExpired,
    SnapshotUnavailable,
    SnapshotExpired,
    FlowExpired,
    StaleRevision,
    RequestTooLarge,
    UnsupportedMediaType,
    UnsupportedValue,
    PreconditionRequired,
    RateLimited,
    TemporarilyUnavailable,
    SetupRequired,
    SetupAlreadyCompleted,
    InvalidCredentials,
}

impl ErrorCode {
    /// The wire spelling, also used in errors embedded in operations.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::AuthenticationRequired => "authentication_required",
            Self::PermissionDenied => "permission_denied",
            Self::ResourceNotFound => "resource_not_found",
            Self::CapabilityNotSupported => "capability_not_supported",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::StateConflict => "state_conflict",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::EventCursorExpired => "event_cursor_expired",
            Self::SnapshotUnavailable => "snapshot_unavailable",
            Self::SnapshotExpired => "snapshot_expired",
            Self::FlowExpired => "flow_expired",
            Self::StaleRevision => "stale_revision",
            Self::RequestTooLarge => "request_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::UnsupportedValue => "unsupported_value",
            Self::PreconditionRequired => "precondition_required",
            Self::RateLimited => "rate_limited",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::SetupRequired => "setup_required",
            Self::SetupAlreadyCompleted => "setup_already_completed",
            Self::InvalidCredentials => "invalid_credentials",
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Why a configuration write was refused, sent as `details.reason`, or why a listed source is
/// read-only, sent as its `read_only_reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteRefusal {
    WritesDisabled,
    ConfigurationUnavailable,
    /// Only a source listing names it: a failed record blocks writes until the head is activated.
    StoreBlocked,
    ListenerSecretSource,
    ListenerSecretInContent,
    ListenerSettingsChanged,
    CredentialSourcesChanged,
    ImportEntryChanged,
    UnsafePath,
}

impl WriteRefusal {
    const ALL: [Self; 9] = [
        Self::WritesDisabled,
        Self::ConfigurationUnavailable,
        Self::StoreBlocked,
        Self::ListenerSecretSource,
        Self::ListenerSecretInContent,
        Self::ListenerSettingsChanged,
        Self::CredentialSourcesChanged,
        Self::ImportEntryChanged,
        Self::UnsafePath,
    ];

    /// The code spelled `text`, if it is one.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.as_str() == text)
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::WritesDisabled => "writes_disabled",
            Self::ConfigurationUnavailable => "configuration_unavailable",
            Self::StoreBlocked => "store_blocked",
            Self::ListenerSecretSource => "listener_secret_source",
            Self::ListenerSecretInContent => "listener_secret_in_content",
            Self::ListenerSettingsChanged => "listener_settings_changed",
            Self::CredentialSourcesChanged => "credential_sources_changed",
            Self::ImportEntryChanged => "import_entry_changed",
            Self::UnsafePath => "unsafe_path",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum RetryAfter {
    /// `1` on a 429 or 503, absent otherwise.
    Default,
    Seconds(u32),
    Never,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiError {
    #[serde(skip)]
    pub(super) status: StatusCode,
    #[serde(skip)]
    retry_after: RetryAfter,
    /// Travels to the request log as a response extension; the body carries it in `details`.
    #[serde(skip)]
    reason: Option<WriteRefusal>,
    pub(super) error: ErrorBody,
    request_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct ErrorBody {
    pub(super) code: ErrorCode,
    message: &'static str,
    pub(super) details: Option<Value>,
}

impl ApiError {
    pub fn new(
        status: StatusCode,
        code: ErrorCode,
        message: &'static str,
        request_id: Option<String>,
    ) -> Self {
        Self {
            status,
            retry_after: RetryAfter::Default,
            reason: None,
            error: ErrorBody {
                code,
                message,
                details: None,
            },
            request_id,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.error.details = Some(details);
        if let Some(reason) = self.reason {
            self = self.with_reason(reason);
        }
        self
    }

    /// Adds `reason`, preserving object fields or wrapping other details in `value`.
    pub(crate) fn with_reason(mut self, reason: WriteRefusal) -> Self {
        let mut details = match self.error.details.take() {
            Some(Value::Object(details)) => details,
            Some(value) => Map::from_iter([("value".into(), value)]),
            None => Map::new(),
        };
        details.insert("reason".into(), json!(reason.as_str()));
        self.error.details = Some(Value::Object(details));
        self.reason = Some(reason);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn with_retry_after(mut self, seconds: u32) -> Self {
        self.retry_after = RetryAfter::Seconds(seconds.max(1));
        self
    }

    /// For a 503 after a completed write, where repeating the request cannot succeed.
    pub(crate) fn without_retry_after(mut self) -> Self {
        self.retry_after = RetryAfter::Never;
        self
    }

    pub(crate) fn message(&self) -> &'static str {
        self.error.message
    }

    pub(crate) fn into_details(self) -> Option<Value> {
        self.error.details
    }

    /// Code, message and details for an operation that fails with this error.
    pub(crate) fn into_safe(self) -> (&'static str, &'static str, Option<Value>) {
        (
            self.error.code.as_str(),
            self.message(),
            self.into_details(),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let retry_after = match self.retry_after {
            RetryAfter::Seconds(seconds) => Some(seconds),
            RetryAfter::Never => None,
            RetryAfter::Default => matches!(
                status,
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
            )
            .then_some(1),
        };
        let reason = self.reason;
        let mut response = (
            self.status,
            [
                ("cache-control", "no-store"),
                ("x-content-type-options", "nosniff"),
            ],
            Json(self),
        )
            .into_response();
        if let Some(reason) = reason {
            response.extensions_mut().insert(reason);
        }
        if let Some(seconds) = retry_after {
            response
                .headers_mut()
                .insert("retry-after", axum::http::HeaderValue::from(seconds));
        }
        response
    }
}

#[derive(Clone)]
pub(super) struct RequestId(pub String);

/// Set on a request the listener authenticated, or admitted without a credential.
#[derive(Clone, Copy)]
pub(super) struct Admitted;

#[derive(Clone, Serialize)]
pub(super) struct Runtime {
    pub(super) observed_at: String,
    pub(super) instance_id: String,
    pub(super) lifecycle: Lifecycle,
    pub(super) generation: Generation,
    pub(super) datapath: DatapathSummary,
    pub(super) traffic: TrafficSummary,
    pub(super) process: Process,
    pub(super) last_reload: Option<Value>,
    pub(super) degradations: Vec<Degradation>,
}

/// A contract `SafeError` plus the reduced component and when it degraded.
#[derive(Clone, Serialize)]
pub(super) struct Degradation {
    pub(super) code: &'static str,
    pub(super) message: &'static str,
    pub(super) details: Value,
    pub(super) component: &'static str,
    pub(super) since: String,
}

#[derive(Clone, Serialize)]
pub(super) struct Lifecycle {
    pub(super) state: &'static str,
    pub(super) started_at: Option<String>,
    pub(super) uptime_seconds: Option<String>,
}

#[derive(Clone, Serialize)]
pub(super) struct Generation {
    pub(super) active_id: String,
    pub(super) config_revision: Option<String>,
    pub(super) state: &'static str,
    pub(super) activated_at: Option<String>,
}

#[derive(Clone, Serialize)]
pub(super) struct DatapathSummary {
    pub(super) kind: &'static str,
    pub(super) state: &'static str,
    pub(super) visibility: &'static str,
    pub(super) ebpf: Option<super::datapath::EbpfSummary>,
}

#[derive(Clone, Serialize)]
pub(super) struct Process {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) pid: Option<u32>,
    pub(super) cpu_percent: Option<f64>,
}

#[derive(Clone, Serialize)]
pub(super) struct TrafficSummary {
    pub(super) scope: &'static str,
    pub(super) observed_by: &'static str,
    pub(super) counter_since: Option<String>,
    pub(super) sampled_at: Option<String>,
    pub(super) connections: TrafficConnections,
    pub(super) bytes: TrafficBytes,
    pub(super) rates: Option<TrafficRates>,
}

#[derive(Clone, Serialize)]
pub(super) struct TrafficConnections {
    pub(super) tcp: Option<u64>,
    pub(super) udp: Option<u64>,
    pub(super) total: Option<u64>,
}

#[derive(Clone, Serialize)]
pub(super) struct TrafficBytes {
    pub(super) upload: Option<String>,
    pub(super) download: Option<String>,
}

#[derive(Clone, Serialize)]
pub(super) struct TrafficRates {
    pub(super) window_seconds: f64,
    pub(super) upload_bytes_per_second: Option<String>,
    pub(super) download_bytes_per_second: Option<String>,
}

#[derive(Clone, Serialize)]
pub(super) struct Connection {
    pub(super) id: String,
    pub(super) flow_id: Option<String>,
    pub(super) pname: Option<String>,
    pub(super) state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) src: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) dst: Option<String>,
    // Outer None omits summary data; Some(None) retains full-detail unknowns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) domain: Option<Option<String>>,
    pub(super) outbound: Option<String>,
    pub(super) chain: Vec<String>,
    pub(super) chain_source: &'static str,
    pub(super) rule_id: Option<String>,
    pub(super) rule_expression: Option<String>,
    pub(super) rule_source: crate::observe::vocab::RuleSource,
    pub(super) ingress: Option<&'static str>,
    pub(super) domain_source: Option<crate::observe::vocab::DomainSource>,
    pub(super) started_at: Option<String>,
    pub(super) observed_by: &'static str,
    pub(super) upload_bytes: Option<String>,
    pub(super) download_bytes: Option<String>,
    pub(super) upload_bytes_per_second: Option<String>,
    pub(super) download_bytes_per_second: Option<String>,
}

#[derive(Clone, Serialize)]
pub(super) struct ConnectionList {
    pub(super) observed_at: String,
    pub(super) instance_id: String,
    pub(super) visibility: &'static str,
    pub(super) truncated: bool,
    pub(super) tcp: Vec<Connection>,
    pub(super) udp: Vec<Connection>,
    pub(super) total_tcp: u64,
    pub(super) total_udp: u64,
}

/// What a client must do before it may call anything else.
pub(crate) struct AuthDiscovery {
    pub(crate) mode: &'static str,
    pub(crate) setup_required: bool,
    pub(crate) anonymous_loopback: bool,
}

pub(super) fn discovery(auth: AuthDiscovery, admitted: bool) -> Value {
    let password = auth.mode == "password";
    let link = |path: &'static str| {
        if password {
            Value::from(path)
        } else {
            Value::Null
        }
    };
    // Discovery is public; a caller that is not admitted learns only how to sign in.
    if !admitted {
        return json!({
            "name": "daeuniverse/native",
            "api_major": 1,
            "links": {
                "auth_setup": link("/api/v1/auth/setup"),
                "auth_login": link("/api/v1/auth/login"),
            },
            "auth": {
                "mode": auth.mode,
                "setup_required": auth.setup_required,
            },
        });
    }
    json!({
        "name": "daeuniverse/native",
        "status": "draft",
        "api_major": 1,
        "base_path": "/api/v1",
        "links": {
            "version": "/api/v1/version",
            "capabilities": "/api/v1/capabilities",
            "config": "/api/v1/config",
            "config_validate": "/api/v1/config/validate",
            "runtime": "/api/v1/runtime",
            "runtime_outbounds": "/api/v1/runtime/outbounds",
            "traffic_history": "/api/v1/runtime/traffic/history",
            "memory_history": "/api/v1/runtime/memory/history",
            "logs": "/api/v1/logs",
            "providers": "/api/v1/providers",
            "rules": "/api/v1/rules",
            "geodata": "/api/v1/geodata",
            "operations": "/api/v1/operations/{operation_id}",
            "auth_setup": link("/api/v1/auth/setup"),
            "auth_login": link("/api/v1/auth/login"),
            "auth_logout": link("/api/v1/auth/logout"),
            "x-honk": {
                "config_export": "/api/v1/x-honk/config/export",
                "config_import": "/api/v1/x-honk/config/import",
                "config_revisions": "/api/v1/x-honk/config/revisions",
            },
        },
        "auth": {
            "mode": auth.mode,
            "setup_required": auth.setup_required,
            "anonymous_loopback": auth.anonymous_loopback,
        },
    })
}

pub(super) fn version() -> Value {
    let optional = |value: &str| (!value.is_empty()).then(|| Value::from(value));
    json!({
        "api": {"name": "daeuniverse/native", "major": 1, "status": "draft"},
        "engine": {"name": "honk", "version": crate::VERSION},
        // No build timestamp: the binary carries none, and inventing one would mislead.
        "build": {"revision": optional(crate::REVISION), "target": optional(crate::TARGET), "built_at": null},
    })
}

pub(super) async fn capabilities(state: &super::NativeState) -> Value {
    let config = &state.observation.configuration;
    let telemetry = &state.observation.telemetry;
    let kinds = super::events::kind_names();
    let mut providers = state
        .observation
        .providers
        .capability(&state.config.read().await.assets);
    providers["can_manage"] = json!(config.can_manage());
    providers["create_unfetched"] = json!(true);
    let geodata = super::geodata::capability(state).await;
    let routing_trace = super::routing::trace_capability();
    let rules = super::routing::rules_capability(&*state.traffic_router.read().await);
    let dns_rules = super::dns::rules_capability(&state.config.read().await.dns.routing);
    json!({
        "observed_at": super::timestamp(std::time::SystemTime::now()),
        "profiles": ["base"],
        "limits": {
            "max_request_target_bytes": super::security::MAX_TARGET_BYTES,
            "max_header_bytes": super::security::MAX_HEADER_BYTES,
            "max_json_body_bytes": super::security::MAX_BODY_BYTES,
        },
        "resources": {
            "config": {"available":config.sources.available(),"writable":config.editable(),"create":config.editable(),"max_bytes":super::config::MAX_CONTENT_BYTES,"max_sources":crate::configuration::MAX_SOURCES,"x-honk":{"store":config.store_value()["kind"]}},
            "x-honk": {
                "config_export": {"available":config.sources.available()},
                "config_import": config.import_capability(),
                "config_revisions": config.revisions_capability(),
                "runtime_mode": {"available":false},
            },
            "config_validate": {"available":config.running(),"modes":["syntax","full"],"max_bytes":crate::configuration::MAX_SOURCE_BYTES,"max_sources":crate::configuration::MAX_SOURCES},
            "runtime": {"available": true},
            "runtime_memory": {"available":true,"metrics":telemetry.metrics()},
            "runtime_outbounds": {"available":true},
            "traffic_history": {"available":telemetry.record_traffic(),"max_window_seconds":super::telemetry::RETENTION.as_secs(),"max_points":super::telemetry::MAX_POINTS},
            "memory_history": {"available":telemetry.record_memory(),"max_window_seconds":super::telemetry::RETENTION.as_secs(),"max_points":super::telemetry::MAX_POINTS},
            "datapath": super::datapath::capability(),
            "nodes": {"available": true, "can_manage":config.can_manage()},
            "providers": providers,
            "geodata": geodata,
            "groups": {"available": true, "config_patch":config.editable(), "selection": true, "max_patch_operations":super::groups::MAX_PATCH_OPERATIONS},
            "probes": state.observation.probes.capability(),
            "connections": {
                "available": true,
                "can_close": true,
                "max_bulk_close": super::connections::MAX_BULK_CLOSE,
            },
            "flows": {"available": true, "recording": state.observation.settings.flow_recording_policy(), "scopes":["userspace_tcp","userspace_udp","dns_intercept"], "min_flows":super::settings::MIN_RECORDS, "max_flows":crate::observe::flows::MAX_RECORDS, "max_steps_per_flow":crate::observe::flows::MAX_STEPS, "retention_seconds":crate::observe::flows::TERMINAL_TTL.as_secs(), "snapshot_ttl_seconds":crate::observe::flows::SNAPSHOT_TTL.as_secs(), "max_page_size":super::pages::MAX_PAGE_SIZE},
            "routing_trace": routing_trace,
            "rules": rules,
            "events": {"available":true,"kinds":kinds,"retention_seconds":super::events::RETENTION.as_secs(),"max_buffered_events":super::events::MAX_EVENTS,"max_clients":super::events::MAX_CLIENTS,"heartbeat_seconds":super::events::HEARTBEAT.as_secs()},
            "logs": state.observation.logs.capability(),
            "dns_query": state.observation.dns.query_capability(),
            "dns_cache": state.observation.dns.cache_capability(),
            "dns_log": state.observation.dns.log_capability(),
            "dns_rules": dns_rules,
            "runtime_settings": super::settings::capability(&state.settings, state.geodata.as_ref().is_some()),
            "operations": {"available":true,"retention_seconds":super::operations::RETENTION.as_secs(),"max_replay_keys":super::operations::MAX_TOMBSTONES},
            "reload": {"available":config.running()},
            "suspend": {"available":false},
            "resume": {"available":false},
        },
    })
}

#[cfg(test)]
mod tests;
