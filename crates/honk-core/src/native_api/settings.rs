//! One transition owner for runtime-only native recorder settings.

use std::sync::Arc;
use tokio::time::{Duration, Instant};

use axum::{
    Json,
    extract::Request,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use honk_config::Config;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    ApiError, ErrorCode, NativeState, observation::NativeObservation, parse_query, types::RequestId,
};

/// The smallest log, DNS log or flow ring a PATCH may set.
pub(super) const MIN_RECORDS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}
impl Level {
    pub(crate) fn configured(value: &str) -> Self {
        if value.eq_ignore_ascii_case("trace") {
            Self::Trace
        } else if value.eq_ignore_ascii_case("debug") {
            Self::Debug
        } else if value.eq_ignore_ascii_case("warn") || value.eq_ignore_ascii_case("warning") {
            Self::Warn
        } else if value.eq_ignore_ascii_case("error") {
            Self::Error
        } else {
            Self::Info
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum RecorderMode {
    #[default]
    Auto,
    On,
    Off,
}

impl<'de> Deserialize<'de> for RecorderMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)?.as_str() {
            Some("on") => Ok(Self::On),
            Some("off") => Ok(Self::Off),
            Some("auto") => Ok(Self::Auto),
            _ => Err(serde::de::Error::custom("expected on, off, or auto")),
        }
    }
}

/// Diagnostics requested by one admitted stream or successful observation read.
/// Ordinary event attachment is separate from these three recorder demands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Demand {
    pub(crate) flows: bool,
    pub(crate) logs: bool,
    pub(crate) dns_log: bool,
}
impl Demand {
    pub(crate) const NONE: Self = Self {
        flows: false,
        logs: false,
        dns_log: false,
    };
    pub(crate) const FLOWS: Self = Self {
        flows: true,
        ..Self::NONE
    };
    pub(crate) const LOGS: Self = Self {
        logs: true,
        ..Self::NONE
    };
    pub(crate) const DNS_LOG: Self = Self {
        dns_log: true,
        ..Self::NONE
    };

    fn recorders(self) -> [bool; 3] {
        [self.flows, self.logs, self.dns_log]
    }
    fn attachments(self) -> impl Iterator<Item = usize> {
        std::iter::once(0).chain(
            self.recorders()
                .into_iter()
                .enumerate()
                .filter_map(|(index, requested)| requested.then_some(index + 1)),
        )
    }
}

#[derive(Clone, Copy)]
struct Values {
    level: Level,
    /// A PATCH chose `level`, which then also applies to console and file.
    level_overridden: bool,
    logs: usize,
    dns: usize,
    flows: usize,
    retention: u64,
    overridden: bool,
    allowed: [bool; 3],
    modes: [RecorderMode; 3],
    attached: bool,
    demand: Demand,
}
impl Values {
    fn configured(config: &Config) -> Self {
        Self {
            level: Level::configured(&config.global.log_level),
            level_overridden: false,
            logs: super::logs::MAX_RECORDS,
            dns: super::dns::log::MAX_RECORDS,
            flows: crate::observe::flows::MAX_RECORDS,
            retention: crate::observe::flows::TERMINAL_TTL.as_secs(),
            overridden: false,
            allowed: [
                config.experimental.native_api.record_flows,
                config.experimental.native_api.record_logs,
                config.experimental.native_api.record_dns_log,
            ],
            modes: [RecorderMode::Auto; 3],
            attached: false,
            demand: Demand::NONE,
        }
    }
    fn active(self) -> [bool; 3] {
        std::array::from_fn(|index| {
            self.allowed[index]
                && match self.modes[index] {
                    RecorderMode::Auto => self.demand.recorders()[index],
                    RecorderMode::On => true,
                    RecorderMode::Off => false,
                }
        })
    }
    fn events_active(self) -> bool {
        self.attached
            || self
                .allowed
                .iter()
                .zip(self.modes)
                .any(|(allowed, mode)| *allowed && mode == RecorderMode::On)
    }
    fn json(self) -> Value {
        let active = self.active();
        let recorder = |index: usize| json!({"allowed": self.allowed[index], "mode": self.modes[index], "active": active[index]});
        json!({"observed_at":super::timestamp(std::time::SystemTime::now()),"source":if self.overridden {"runtime"} else {"config"},
            "log":{"level":self.level,"buffered_records":self.logs},"dns_log":{"max_records":self.dns},
            "flows":{"max_flows":self.flows,"retention_seconds":self.retention},
            "recording":{"flows":recorder(0),"logs":recorder(1),"dns_log":recorder(2),"events":{"active":self.events_active()},"grace_remaining_seconds":0}})
    }
    fn apply(self, owner: &NativeObservation) {
        owner.logs.set_level(self.level.as_str());
        owner
            .logs
            .set_engine_level(self.level_overridden.then(|| self.level.as_str()));
        owner.logs.set_limit(self.logs);
        owner.dns.set_log_limit(self.dns);
        owner.core.flows.set_limits(self.flows, self.retention);
        self.apply_recording(owner);
    }
    fn apply_recording(self, owner: &NativeObservation) {
        let active = self.active();
        if self.events_active() {
            owner.events.set_recording(true);
        }
        owner.core.flows.set_recording(active[0]);
        owner.logs.set_recording(active[1]);
        owner.dns.set_recording(active[2]);
        if !self.events_active() {
            owner.events.set_recording(false);
        }
    }
}

#[derive(Default)]
struct Attachment {
    streams: usize,
    deadline: Option<Instant>,
}

impl Attachment {
    fn active(&self, now: Instant) -> bool {
        self.streams != 0 || self.deadline.is_some_and(|deadline| now < deadline)
    }
    fn remaining(&self) -> u64 {
        if self.streams != 0 {
            return 0;
        }
        self.deadline.map_or(0, |deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .as_secs_f64()
                .ceil() as u64
        })
    }
}

pub(super) struct StreamLease {
    attachment: Arc<Mutex<[Attachment; 4]>>,
    demand: Demand,
}
impl Drop for StreamLease {
    fn drop(&mut self) {
        let mut attachments = self.attachment.lock();
        for index in self.demand.attachments() {
            let attachment = &mut attachments[index];
            attachment.streams -= 1;
            if attachment.streams == 0 {
                attachment.deadline = Some(Instant::now() + Duration::from_secs(60));
            }
        }
    }
}

pub(crate) struct Settings {
    values: Mutex<Values>,
    // General attachment and each diagnostic demand expire independently.
    attachment: Arc<Mutex<[Attachment; 4]>>,
    stopped: std::sync::atomic::AtomicBool,
}
impl Settings {
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            values: Mutex::new(Values::configured(config)),
            attachment: Arc::new(Mutex::new(std::array::from_fn(|_| Attachment::default()))),
            stopped: std::sync::atomic::AtomicBool::new(false),
        }
    }
    pub(crate) fn activate(&self, owner: &NativeObservation, config: &Config) {
        let mut current = self.values.lock();
        let mut next = Values::configured(config);
        next.allowed = current.allowed;
        next.attached =
            current.attached && !self.stopped.load(std::sync::atomic::Ordering::Acquire);
        next.demand = if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            Demand::NONE
        } else {
            current.demand
        };
        next.apply(owner);
        *current = next;
    }
    pub(crate) fn flow_recording(&self) -> bool {
        self.values.lock().active()[0]
    }
    /// The flow recorder's policy for `resources.flows.recording`, not
    /// whether it captures now.
    pub(crate) fn flow_recording_policy(&self) -> &'static str {
        let values = self.values.lock();
        match values.modes[0] {
            _ if !values.allowed[0] => "off",
            RecorderMode::Auto => "auto",
            RecorderMode::On => "on",
            RecorderMode::Off => "off",
        }
    }
    fn snapshot(&self) -> Value {
        let current = self.values.lock();
        self.json(*current)
    }
    fn json(&self, values: Values) -> Value {
        let mut value = values.json();
        value["recording"]["grace_remaining_seconds"] =
            json!(self.attachment.lock()[0].remaining());
        value
    }
    pub(crate) fn renew(&self, owner: &NativeObservation, demand: Demand) {
        let mut current = self.values.lock();
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let mut attachments = self.attachment.lock();
        for index in demand.attachments() {
            attachments[index].deadline = Some(Instant::now() + Duration::from_secs(60));
        }
        drop(attachments);
        self.refresh(&mut current, owner);
    }
    pub(crate) fn maintain(&self, owner: &NativeObservation) {
        self.refresh(&mut self.values.lock(), owner);
    }

    fn refresh(&self, current: &mut Values, owner: &NativeObservation) {
        let [attached, flows, logs, dns_log] = {
            let attachment = self.attachment.lock();
            let running = !self.stopped.load(std::sync::atomic::Ordering::Acquire);
            let now = Instant::now();
            std::array::from_fn(|index| running && attachment[index].active(now))
        };
        let demand = Demand {
            flows,
            logs,
            dns_log,
        };
        if current.attached != attached || current.demand != demand {
            current.attached = attached;
            current.demand = demand;
            current.apply_recording(owner);
        }
    }
    /// Fixtures that drive flows directly and advance virtual time past the
    /// attachment grace keep every permitted recorder pinned on.
    #[cfg(test)]
    pub(crate) fn pin_for_test(&self, owner: &NativeObservation) {
        let mut current = self.values.lock();
        current.modes = [RecorderMode::On; 3];
        current.apply_recording(owner);
    }

    pub(crate) fn shutdown(&self, owner: &NativeObservation) {
        let mut current = self.values.lock();
        self.stopped
            .store(true, std::sync::atomic::Ordering::Release);
        current.attached = false;
        current.demand = Demand::NONE;
        current.modes = [RecorderMode::Off; 3];
        current.apply_recording(owner);
    }
    pub(super) fn subscribe(
        &self,
        owner: &NativeObservation,
        demand: Demand,
        admit: impl FnOnce() -> Result<super::events::Subscription, ApiError>,
    ) -> Result<super::events::Subscription, ApiError> {
        let mut current = self.values.lock();
        let mut stream = admit()?;
        if !self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            let mut attachments = self.attachment.lock();
            for index in demand.attachments() {
                attachments[index].streams += 1;
            }
            drop(attachments);
            stream.attach(StreamLease {
                attachment: Arc::clone(&self.attachment),
                demand,
            });
            self.refresh(&mut current, owner);
        }
        Ok(stream)
    }
    #[cfg(test)]
    fn patch(
        &self,
        owner: &NativeObservation,
        settings: &honk_config::experimental::NativeApiConfig,
        patch: Patch,
        id: &RequestId,
    ) -> Result<Value, ApiError> {
        self.patch_with(owner, settings, patch, id, || Ok(()))
    }

    /// Applies `patch` once it is valid and `commit` succeeded, so a stored
    /// change made by `commit` and this one land together or not at all.
    fn patch_with(
        &self,
        owner: &NativeObservation,
        settings: &honk_config::experimental::NativeApiConfig,
        patch: Patch,
        id: &RequestId,
        commit: impl FnOnce() -> Result<(), ApiError>,
    ) -> Result<Value, ApiError> {
        let mut current = self.values.lock();
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return Err(invalid(id));
        }
        let mut next = *current;
        // A bound or schema error is 400 even when the same patch also names
        // an unadvertised field, so 422 waits until every value is checked.
        let mut unadvertised = false;
        if patch.log.is_none()
            && patch.dns_log.is_none()
            && patch.flows.is_none()
            && patch.record_flows.is_none()
            && patch.record_logs.is_none()
            && patch.record_dns_log.is_none()
        {
            return Err(invalid(id));
        }
        if let Some(log) = patch.log {
            if log.level.is_none() && log.buffered_records.is_none() {
                return Err(invalid(id));
            }
            unadvertised |= !settings.record_logs;
            if let Some(level) = log.level {
                next.level = level;
                next.level_overridden = true;
            }
            if let Some(count) = log.buffered_records {
                if !(MIN_RECORDS..=super::logs::MAX_RECORDS).contains(&count) {
                    return Err(invalid(id));
                }
                next.logs = count;
            }
        }
        if let Some(dns) = patch.dns_log {
            let Some(count) = dns.max_records else {
                return Err(invalid(id));
            };
            if !(MIN_RECORDS..=super::dns::log::MAX_RECORDS).contains(&count) {
                return Err(invalid(id));
            }
            unadvertised |= !settings.record_dns_log;
            next.dns = count;
        }
        if let Some(flows) = patch.flows {
            if flows.max_flows.is_none() && flows.retention_seconds.is_none() {
                return Err(invalid(id));
            }
            unadvertised |= !settings.record_flows;
            if let Some(count) = flows.max_flows {
                if !(MIN_RECORDS..=crate::observe::flows::MAX_RECORDS).contains(&count) {
                    return Err(invalid(id));
                }
                next.flows = count;
            }
            if let Some(seconds) = flows.retention_seconds {
                if !(1..=crate::observe::flows::TERMINAL_TTL.as_secs()).contains(&seconds) {
                    return Err(invalid(id));
                }
                next.retention = seconds;
            }
        }
        for (index, mode) in [patch.record_flows, patch.record_logs, patch.record_dns_log]
            .into_iter()
            .enumerate()
        {
            if let Some(mode) = mode {
                unadvertised |= mode == RecorderMode::On && !next.allowed[index];
                next.modes[index] = mode;
            }
        }
        if unadvertised {
            return Err(unsupported(id));
        }
        commit()?;
        next.overridden = true;
        next.apply(owner);
        *current = next;
        Ok(self.json(next))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Patch {
    record_flows: Option<RecorderMode>,
    record_logs: Option<RecorderMode>,
    record_dns_log: Option<RecorderMode>,
    log: Option<LogPatch>,
    dns_log: Option<DnsPatch>,
    flows: Option<FlowPatch>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogPatch {
    level: Option<Level>,
    buffered_records: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsPatch {
    max_records: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowPatch {
    max_flows: Option<usize>,
    retention_seconds: Option<u64>,
}

pub(super) fn capability(
    settings: &honk_config::experimental::NativeApiConfig,
    geodata: bool,
) -> Value {
    let mut fields = vec!["record_flows", "record_logs", "record_dns_log"];
    if settings.record_logs {
        fields.extend(["log.level", "log.buffered_records"]);
    }
    if settings.record_dns_log {
        fields.push("dns_log.max_records");
    }
    if settings.record_flows {
        fields.extend(["flows.max_flows", "flows.retention_seconds"]);
    }
    if geodata {
        fields.push("geodata");
    }
    json!({"available":true,"fields":fields})
}

pub(super) async fn get(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let active = state.config.read().await;
    Ok(Json(with_geodata(
        state,
        state.observation.settings.snapshot(),
        &active,
    ))
    .into_response())
}

/// Adds the geodata sources, URLs as written apart from listener secrets.
fn with_geodata(state: &NativeState, mut value: Value, active: &Config) -> Value {
    if let Some(sources) = state.geodata.as_ref() {
        let secrets = state.observation.configuration.secrets_with(active);
        value["geodata"] = sources.effective().json(
            |url| secrets.mask(url).0,
            |name| super::geodata::group_id(&state.observation.core.catalog, name),
        );
    }
    value
}

pub(super) async fn patch(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    super::config::json_type(&request)?;
    let bytes = super::body::buffered(request.into_body()).await;
    let mut value = super::body::value(&bytes, || invalid(id))?;
    let geodata = value
        .as_object_mut()
        .and_then(|object| object.remove("geodata"))
        .map(|patch| {
            if !state.settings.credentialed() {
                return Err(super::error(
                    StatusCode::FORBIDDEN,
                    ErrorCode::PermissionDenied,
                    "Geodata sources need an authenticated caller",
                    id,
                ));
            }
            let mut patch = super::geodata::SourcesPatch::parse(patch, || invalid(id))?;
            let groups = state.observation.core.catalog.snapshot();
            let current = patch.as_mut().is_none_or(|patch| {
                patch.resolve_group(|id| {
                    groups
                        .groups
                        .iter()
                        .find(|(_, group_id)| group_id.as_str() == id)
                        .map(|(name, _)| name.clone())
                })
            });
            Ok((patch, current))
        })
        .transpose()?;
    let others = value.as_object().is_some_and(|object| !object.is_empty());
    if value
        .as_object()
        .is_none_or(|object| object.values().any(Value::is_null))
        || value.as_object().is_some_and(|object| {
            object
                .values()
                .filter_map(Value::as_object)
                .any(|object| object.values().any(Value::is_null))
        })
        || (!others && geodata.is_none())
    {
        return Err(invalid(id));
    }
    let active = state.config.read().await;
    let commit = || match (geodata, state.geodata.as_ref()) {
        (Some(_), None) => Err(unsupported(id)),
        (Some((_, false)), Some(_)) => Err(super::error(
            StatusCode::CONFLICT,
            ErrorCode::StateConflict,
            "geodata.download.group_id is not a current group",
            id,
        )),
        (Some((patch, true)), Some(sources)) => sources.apply(patch).map(drop).map_err(|_| {
            super::error(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::TemporarilyUnavailable,
                "Geodata settings could not be stored",
                id,
            )
        }),
        _ => Ok(()),
    };
    let settings = if others {
        let patch: Patch = super::body::decode_value(value, "", || invalid(id))?;
        state.observation.settings.patch_with(
            &state.observation,
            &state.settings,
            patch,
            id,
            commit,
        )?
    } else {
        commit()?;
        state.observation.settings.snapshot()
    };
    Ok(Json(with_geodata(state, settings, &active)).into_response())
}

fn invalid(id: &RequestId) -> ApiError {
    super::error(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Unsupported or invalid runtime setting",
        id,
    )
}

fn unsupported(id: &RequestId) -> ApiError {
    super::error(
        StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::UnsupportedValue,
        "Runtime setting is not advertised",
        id,
    )
}

#[cfg(test)]
mod tests;
