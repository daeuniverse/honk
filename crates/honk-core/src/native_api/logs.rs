//! Structured native logs. Unreviewed messages and fields never reach a formatter.

use std::{
    fmt,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::SystemTime,
};

use axum::{extract::Request, http::StatusCode, response::Response};
use bytes::Bytes;
use parking_lot::RwLock;
use serde_json::{Map, Value, json};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    Layer,
    layer::{Context, Filter},
    registry::LookupSpan,
};

use super::{
    ApiError, ErrorCode, NativeState, error,
    events::{self, EventHub},
    parse_query, timestamp,
    types::RequestId,
};

const MAX_RECORDS: usize = 512;
const WITHHELD: &str = "[message withheld: not audited for native disclosure]";
const LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

#[derive(serde::Serialize)]
struct LogRecord {
    ts: String,
    level: &'static str,
    target: &'static str,
    message: &'static str,
    fields: Option<Map<String, Value>>,
}

pub(crate) struct LogStore {
    hub: Arc<EventHub>,
    allowed: bool,
    recording: AtomicBool,
    stopped: AtomicBool,
    level: AtomicU8,
}

impl LogStore {
    pub(crate) fn new(instance_id: String, recording: bool, level: &str) -> Self {
        let hub = Arc::new(EventHub::logs(instance_id));
        hub.set_recording(recording);
        Self {
            hub,
            allowed: recording,
            recording: AtomicBool::new(recording),
            stopped: AtomicBool::new(false),
            level: AtomicU8::new(level_number(level).expect("validated native log level")),
        }
    }

    pub(crate) fn set_limit(&self, limit: usize) {
        self.hub.set_limit(limit);
    }

    pub(crate) fn set_level(&self, level: &str) {
        let level = level_number(level).expect("validated native log level");
        if self.level.swap(level, Ordering::AcqRel) != level {
            tracing::callsite::rebuild_interest_cache();
        }
    }

    pub(crate) fn set_recording(&self, recording: bool) {
        let recording = recording && !self.stopped.load(Ordering::Acquire);
        if self.recording.load(Ordering::Acquire) == recording {
            return;
        }
        if recording && !self.stopped.load(Ordering::Acquire) {
            self.hub.set_recording(true);
            self.recording.store(true, Ordering::Release);
        } else {
            self.recording.store(false, Ordering::Release);
            self.hub.set_recording(false);
        }
        tracing::callsite::rebuild_interest_cache();
    }

    pub(crate) fn shutdown(&self) {
        self.stopped.store(true, Ordering::Release);
        self.recording.store(false, Ordering::Release);
        self.hub.shutdown();
        tracing::callsite::rebuild_interest_cache();
    }

    pub(crate) fn capability(&self) -> Value {
        json!({
            "available": self.allowed && !self.stopped.load(Ordering::Acquire),
            "levels": ["trace", "debug", "info", "warn", "error"],
            "max_buffered_records": MAX_RECORDS,
        })
    }

    fn accepts(&self, metadata: &Metadata<'_>) -> bool {
        self.recording.load(Ordering::Acquire)
            && !self.stopped.load(Ordering::Acquire)
            && metadata.is_event()
            && severity(metadata.level()) <= self.level.load(Ordering::Acquire)
    }

    fn capture(&self, event: &Event<'_>) {
        let epoch = self.hub.capture_epoch();
        let metadata = event.metadata();
        if epoch.is_multiple_of(2) || !self.accepts(metadata) {
            return;
        }
        if metadata.target().is_empty()
            || metadata.target().len() > 256
            || !metadata
                .target()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_:-.".contains(&byte))
        {
            self.hub.reject_log(epoch);
            return;
        }
        let ts = timestamp(SystemTime::now());
        let mut projection = Projection::default();
        event.record(&mut projection);
        let (message, fields) = projection.finish(metadata.target());
        let level = severity(metadata.level());
        let payload = LogRecord {
            ts,
            level: LEVELS[usize::from(level - 1)],
            target: metadata.target(),
            message,
            fields,
        };
        self.hub.publish_log(
            level,
            metadata.target(),
            Bytes::from(
                serde_json::to_vec(&payload).expect("bounded log projection is serializable"),
            ),
            epoch,
        );
    }

    fn response(self: &Arc<Self>, request: &Request, id: &RequestId) -> Result<Response, ApiError> {
        Ok(events::stream_response(self.subscribe(request, id)?))
    }

    fn subscribe(
        self: &Arc<Self>,
        request: &Request,
        id: &RequestId,
    ) -> Result<events::Subscription, ApiError> {
        let values = parse_query(request.uri(), &["level", "target"], id)?;
        let level = values.get("level").map_or(Ok(5), |value| {
            level_number(value).ok_or_else(|| invalid(id))
        })?;
        let target = values.get("target").cloned();
        if target.as_ref().is_some_and(|target| {
            target.is_empty() || target.len() > 256 || target.chars().any(char::is_control)
        }) {
            return Err(invalid(id));
        }
        let cursor = events::request_cursor(request, id)?;
        let filter = events::Filter::logs(level, target);
        if !self.allowed {
            return Err(error(
                StatusCode::NOT_FOUND,
                ErrorCode::CapabilityNotSupported,
                "Log recording is disabled",
                id,
            ));
        }
        self.hub.subscribe(filter, cursor.as_deref(), id)
    }
}

fn severity(level: &tracing::Level) -> u8 {
    match *level {
        tracing::Level::ERROR => 1,
        tracing::Level::WARN => 2,
        tracing::Level::INFO => 3,
        tracing::Level::DEBUG => 4,
        tracing::Level::TRACE => 5,
    }
}

fn level_number(level: &str) -> Option<u8> {
    match level {
        "error" => Some(1),
        "warn" => Some(2),
        "info" => Some(3),
        "debug" => Some(4),
        "trace" => Some(5),
        _ => None,
    }
}

#[derive(Clone)]
pub(crate) struct LogBinding(Arc<RwLock<Weak<LogStore>>>);

impl LogBinding {
    pub(crate) fn bind(&self, store: Weak<LogStore>) {
        *self.0.write() = store;
        tracing::callsite::rebuild_interest_cache();
    }

    fn accepts(&self, metadata: &Metadata<'_>) -> bool {
        self.0
            .read()
            .upgrade()
            .is_some_and(|store| store.accepts(metadata))
    }
}

struct CaptureLayer(LogBinding);
struct CaptureFilter(LogBinding);

impl<S: Subscriber> Filter<S> for CaptureFilter {
    fn enabled(&self, metadata: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        self.0.accepts(metadata)
    }

    fn callsite_enabled(
        &self,
        metadata: &'static Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        // Per-layer `enabled` suppresses delivery, not necessarily field evaluation.
        // Binding and settings changes rebuild this cache outside their locks.
        if self.0.accepts(metadata) {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }
}

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if let Some(store) = self.0.0.read().upgrade() {
            store.capture(event);
        }
    }
}

/// Attach independently of console/Clash filters; bind only after listener initialization.
pub(crate) fn tracing_layer<S>() -> (impl Layer<S>, LogBinding)
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let binding = LogBinding(Arc::new(RwLock::new(Weak::new())));
    let layer = CaptureLayer(binding.clone()).with_filter(CaptureFilter(binding.clone()));
    (layer, binding)
}

#[derive(Default)]
struct Projection {
    message: Option<&'static str>,
    nodes: Option<u64>,
    tcp: Option<bool>,
    udp: Option<bool>,
    withheld: bool,
}

impl Visit for Projection {
    fn record_debug(&mut self, field: &Field, _: &dyn fmt::Debug) {
        if field.name() != "message" {
            self.withheld = true;
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = audited_message(value);
        } else {
            self.withheld = true;
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "nodes" => self.nodes = Some(value),
            _ => self.withheld = true,
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        match field.name() {
            "tcp" => self.tcp = Some(value),
            "udp" => self.udp = Some(value),
            _ => self.withheld = true,
        }
    }
}

// Literal messages are safe only at their audited target, with these typed fields.
fn audited_message(message: &str) -> Option<&'static str> {
    match message {
        "native HTTP supervisor failed" => Some("native HTTP supervisor failed"),
        "native HTTP sampler stopped unexpectedly" => {
            Some("native HTTP sampler stopped unexpectedly")
        }
        "native HTTP connection task failed" => Some("native HTTP connection task failed"),
        "native HTTP listener failed" => Some("native HTTP listener failed"),
        "Publishing accepted subscription body" => Some("Publishing accepted subscription body"),
        "Subscription runtime publication applied" => {
            Some("Subscription runtime publication applied")
        }
        "Subscription runtime publication rejected" => {
            Some("Subscription runtime publication rejected")
        }
        "Standalone DNS listener started" => Some("Standalone DNS listener started"),
        "native API listener ready" => Some("native API listener ready"),
        _ => None,
    }
}

impl Projection {
    fn finish(self, target: &str) -> (&'static str, Option<Map<String, Value>>) {
        let Some(message) = self.message else {
            return (WITHHELD, None);
        };
        let allowed = match target {
            "honk_core::native_api" => message.starts_with("native HTTP "),
            "honk_core::control::runtime" => matches!(
                message,
                "Publishing accepted subscription body"
                    | "Subscription runtime publication applied"
                    | "Subscription runtime publication rejected"
                    | "Standalone DNS listener started"
            ),
            "honk_core" => message == "native API listener ready",
            _ => false,
        };
        if !allowed {
            return (WITHHELD, None);
        }
        let mut fields = Map::new();
        if message == "Publishing accepted subscription body"
            && let Some(nodes) = self.nodes
        {
            fields.insert("nodes".into(), json!(nodes));
        }
        if message == "Standalone DNS listener started" {
            if let Some(tcp) = self.tcp {
                fields.insert("tcp".into(), json!(tcp));
            }
            if let Some(udp) = self.udp {
                fields.insert("udp".into(), json!(udp));
            }
        }
        if self.withheld
            || (self.nodes.is_some() && message != "Publishing accepted subscription body")
            || ((self.tcp.is_some() || self.udp.is_some())
                && message != "Standalone DNS listener started")
        {
            fields.insert("native_withheld_fields".into(), json!(true));
        }
        (message, Some(fields))
    }
}

fn invalid(id: &RequestId) -> ApiError {
    error(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid log stream request",
        id,
    )
}

pub(super) async fn serve(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    if request.method() == axum::http::Method::GET {
        let subscription =
            state
                .observation
                .settings
                .subscribe(&state.observation, false, || {
                    state.observation.logs.subscribe(&request, id)
                })?;
        Ok(events::stream_response(subscription))
    } else {
        state.observation.logs.response(&request, id)
    }
}

#[cfg(test)]
mod tests;
