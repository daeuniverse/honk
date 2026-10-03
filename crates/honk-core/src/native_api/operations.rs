//! Bounded daemon operations. Reservation admission precedes coordinator side effects.

use std::{
    collections::VecDeque,
    io::{self, Write},
    sync::{Arc, Weak},
    time::{Duration, SystemTime},
};

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{sync::watch, time::Instant};
use uuid::Uuid;

use super::{ApiError, ErrorCode, events::EventHub, timestamp};

const MAX_OPERATIONS: usize = 32;
pub(super) const RETENTION: Duration = Duration::from_secs(300);
pub(super) const MAX_TOMBSTONES: usize = 1024;
const MAX_ERROR_DETAILS: usize = 4096;
const MAX_RESULT_BYTES: usize = 262144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationKind {
    Reload,
    Probe,
    ProviderRefresh,
    GroupUpdate,
    GeodataUpdate,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum OperationResult {
    Reload {
        active_generation_id: Option<String>,
        datapath_generation_id: Option<String>,
    },
    Probe(super::probes::ProbeResult),
    ProviderRefresh(super::providers::Provider),
    Geodata(super::geodata::GeoData),
    GroupUpdate {
        group_id: String,
        config_revision: String,
    },
}

impl OperationResult {
    fn kind(&self) -> OperationKind {
        match self {
            Self::Reload { .. } => OperationKind::Reload,
            Self::Probe(_) => OperationKind::Probe,
            Self::ProviderRefresh(_) => OperationKind::ProviderRefresh,
            Self::Geodata(_) => OperationKind::GeodataUpdate,
            Self::GroupUpdate { .. } => OperationKind::GroupUpdate,
        }
    }
}

type Admission = Option<Result<OperationAcceptedResponse, ApiError>>;

pub(crate) struct OperationStore {
    instance_id: String,
    events: Arc<EventHub>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    // ponytail: linear scans over at most 32 records and 1024 tombstones; index by
    // scope only if these ceilings grow.
    records: Vec<Record>,
    /// Evicted keyed operations, kept only to answer replays for their retention window.
    tombstones: VecDeque<Tombstone>,
}

struct Record {
    id: String,
    kind: OperationKind,
    replay: Option<Replay>,
    admission: watch::Sender<Admission>,
    operation: Option<Operation>,
    terminal_at: Option<Instant>,
}

struct Tombstone {
    id: String,
    kind: OperationKind,
    replay: Replay,
    terminal_at: Instant,
}

struct Replay {
    scope: [u8; 32],
    body: [u8; 32],
}

impl Replay {
    fn new(
        instance: &str,
        principal: &str,
        method: &str,
        path: &str,
        key: &str,
        body: &[u8],
    ) -> Self {
        let principal = digest(&[instance.as_bytes(), principal.as_bytes()]);
        let scope = digest(&[
            instance.as_bytes(),
            &principal,
            method.as_bytes(),
            path.as_bytes(),
            key.as_bytes(),
        ]);
        Self {
            body: digest(&[&scope, body]),
            scope,
        }
    }
}

struct Operation {
    status: Status,
    created_at: SystemTime,
    started_at: Option<SystemTime>,
    finished_at: Option<SystemTime>,
    result: Option<OperationResult>,
    error: Option<SafeError>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Serialize)]
struct SafeError {
    code: &'static str,
    message: &'static str,
    details: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct OperationAcceptedResponse {
    pub(crate) operation_id: String,
    pub(crate) kind: OperationKind,
    pub(crate) status: &'static str,
    pub(crate) href: String,
}

impl IntoResponse for OperationAcceptedResponse {
    fn into_response(self) -> Response {
        let location =
            HeaderValue::from_str(&self.href).expect("generated operation href is valid");
        let mut response = (
            StatusCode::ACCEPTED,
            [
                ("retry-after", "1"),
                ("cache-control", "no-store"),
                ("x-content-type-options", "nosniff"),
            ],
            Json(self),
        )
            .into_response();
        response.headers_mut().insert(header::LOCATION, location);
        response
    }
}

/// Move the fresh reservation into the daemon queue, not a request-owned task.
/// Dropping its preparation owner wakes all waiters without publishing an operation.
pub(crate) struct Reservation {
    pub(crate) id: String,
    pub(crate) fresh: bool,
    /// Who asked, as recorded in configuration revisions.
    pub(crate) principal: String,
    admission: watch::Receiver<Admission>,
    owner: Option<Weak<OperationStore>>,
}

impl Reservation {
    /// The returned future owns its receiver, so the reservation can move to the coordinator.
    pub(crate) fn admission(
        &self,
    ) -> impl Future<Output = Result<OperationAcceptedResponse, ApiError>> + Send + 'static + use<>
    {
        let mut receiver = self.admission.clone();
        async move {
            loop {
                if let Some(result) = receiver.borrow_and_update().clone() {
                    return result;
                }
                if receiver.changed().await.is_err() {
                    return Err(unavailable());
                }
            }
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.as_ref().and_then(Weak::upgrade) {
            owner.reject(&self.id, unavailable());
        }
    }
}

impl OperationStore {
    pub(crate) fn new(instance_id: String, events: Arc<EventHub>) -> Self {
        Self {
            instance_id,
            events,
            state: Mutex::default(),
        }
    }

    /// Finds a retained admission without allocating or evicting an operation slot.
    pub(crate) fn replay(
        &self,
        principal: &str,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: &[u8],
    ) -> Result<Option<Reservation>, ApiError> {
        let Some(key) = key else {
            return Ok(None);
        };
        let replay = Replay::new(&self.instance_id, principal, method, path, key, body);
        let mut state = self.state.lock();
        state.prune();
        state.reservation(principal, &replay)
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        principal: &str,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: &[u8],
        kind: OperationKind,
    ) -> Result<Reservation, ApiError> {
        if key == Some("") {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidRequest,
                "Idempotency-Key must not be empty.",
                None,
            ));
        }
        let replay =
            key.map(|key| Replay::new(&self.instance_id, principal, method, path, key, body));
        let mut state = self.state.lock();
        state.prune();
        if let Some(replay) = &replay
            && let Some(reservation) = state.reservation(principal, replay)?
        {
            return Ok(reservation);
        }
        if kind == OperationKind::GeodataUpdate
            && state
                .records
                .iter()
                .any(|record| record.kind == kind && record.terminal_at.is_none())
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::StateConflict,
                "A geodata update is already queued or running.",
                None,
            ));
        }
        if state.records.len() == MAX_OPERATIONS {
            state.evict_oldest_terminal()?;
        }
        let id = Uuid::new_v4().to_string();
        let (sender, receiver) = watch::channel(None);
        state.records.push(Record {
            id: id.clone(),
            kind,
            replay,
            admission: sender,
            operation: None,
            terminal_at: None,
        });
        Ok(Reservation {
            id,
            fresh: true,
            principal: principal.to_owned(),
            admission: receiver,
            owner: Some(Arc::downgrade(self)),
        })
    }

    /// Call only after durable source replacement (when needed) and real reload queue admission.
    pub(crate) fn accept(&self, id: &str) -> bool {
        let mut state = self.state.lock();
        let Some(record) = state.records.iter_mut().find(|record| record.id == id) else {
            return false;
        };
        if record.operation.is_some() {
            return false;
        }
        record.operation = Some(Operation {
            status: Status::Queued,
            created_at: SystemTime::now(),
            started_at: None,
            finished_at: None,
            result: None,
            error: None,
        });
        self.publish(id, Status::Queued);
        record
            .admission
            .send_replace(Some(Ok(accepted(id, record.kind))));
        true
    }

    pub(crate) fn reject(&self, id: &str, error: ApiError) -> bool {
        let mut state = self.state.lock();
        let Some(index) = state
            .records
            .iter()
            .position(|record| record.id == id && record.operation.is_none())
        else {
            return false;
        };
        let record = state.records.swap_remove(index);
        record.admission.send_replace(Some(Err(error)));
        true
    }

    pub(crate) fn running(&self, id: &str) -> bool {
        let mut state = self.state.lock();
        let Some(operation) = state
            .records
            .iter_mut()
            .find(|record| record.id == id)
            .and_then(|record| record.operation.as_mut())
        else {
            return false;
        };
        if operation.status != Status::Queued {
            return false;
        }
        operation.status = Status::Running;
        operation.started_at = Some(SystemTime::now());
        self.publish(id, Status::Running);
        true
    }

    pub(crate) fn succeed(&self, id: &str, result: OperationResult) -> bool {
        if serde_json::to_writer(DetailsBudget(MAX_RESULT_BYTES), &result).is_err() {
            return self.fail(
                id,
                "result_too_large",
                "Operation result exceeds its memory limit",
                None,
            );
        }
        self.finish(id, Ok(result))
    }

    /// Details must already be safe structured fields, not engine error strings or source text.
    pub(crate) fn fail(
        &self,
        id: &str,
        code: &'static str,
        message: &'static str,
        details: Option<Value>,
    ) -> bool {
        let details = details.filter(error_details_fit);
        self.finish(
            id,
            Err(SafeError {
                code,
                message,
                details,
            }),
        )
    }

    /// Preserve completed measurement facts in `error.details` when lifecycle cleanup
    /// fails; a failed operation's `result` stays null.
    pub(crate) fn fail_with_result(
        &self,
        id: &str,
        code: &'static str,
        message: &'static str,
        result: OperationResult,
    ) -> bool {
        let details = serde_json::to_value(result)
            .ok()
            .filter(|value| serde_json::to_writer(DetailsBudget(MAX_RESULT_BYTES), value).is_ok());
        self.finish(
            id,
            Err(SafeError {
                code,
                message,
                details,
            }),
        )
    }

    fn finish(&self, id: &str, result: Result<OperationResult, SafeError>) -> bool {
        let mut state = self.state.lock();
        let Some(record) = state.records.iter_mut().find(|record| record.id == id) else {
            return false;
        };
        let Some(operation) = record.operation.as_mut() else {
            return false;
        };
        if record.terminal_at.is_some() || (result.is_ok() && operation.status != Status::Running) {
            return false;
        }
        let result = result.and_then(|result| {
            if result.kind() == record.kind {
                Ok(result)
            } else {
                Err(SafeError {
                    code: "invalid_operation_result",
                    message: "Operation result has an incompatible kind",
                    details: None,
                })
            }
        });
        match result {
            Ok(result) => {
                operation.status = Status::Succeeded;
                operation.result = Some(result);
            }
            Err(error) => {
                operation.status = Status::Failed;
                operation.error = Some(error);
            }
        }
        operation.finished_at = Some(SystemTime::now());
        record.terminal_at = Some(Instant::now());
        self.publish(id, operation.status);
        true
    }

    pub(crate) fn get(&self, id: &str) -> Result<Response, ApiError> {
        let mut state = self.state.lock();
        state.prune();
        let record = state.records.iter().find(|record| record.id == id);
        let (record, operation) = record
            .and_then(|record| {
                record
                    .operation
                    .as_ref()
                    .map(|operation| (record, operation))
            })
            .ok_or_else(not_found)?;
        let body = json!({
            "operation_id": record.id,
            "kind": record.kind,
            "status": operation.status,
            "created_at": timestamp(operation.created_at),
            "started_at": operation.started_at.map(timestamp),
            "finished_at": operation.finished_at.map(timestamp),
            "result": operation.result,
            "error": operation.error,
        });
        let mut response = (
            [
                ("cache-control", "no-store"),
                ("x-content-type-options", "nosniff"),
            ],
            Json(body),
        )
            .into_response();
        if record.terminal_at.is_none() {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        Ok(response)
    }

    fn publish(&self, id: &str, status: Status) {
        // Keep publication inside the state lock: concurrent transitions must not reorder events.
        self.events.publish(
            "operation.updated",
            json!({"resource_id": id, "status": status}),
            None,
        );
    }
}

impl State {
    fn reservation(
        &self,
        principal: &str,
        replay: &Replay,
    ) -> Result<Option<Reservation>, ApiError> {
        let Some((id, body, admission)) = self.replay(&replay.scope) else {
            return Ok(None);
        };
        if body != replay.body {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::IdempotencyConflict,
                "Idempotency-Key was already used with a different request body.",
                None,
            ));
        }
        Ok(Some(Reservation {
            id: id.to_owned(),
            fresh: false,
            principal: principal.to_owned(),
            admission,
            owner: None,
        }))
    }

    fn prune(&mut self) {
        let now = Instant::now();
        let retained = |terminal: Instant| now.duration_since(terminal) < RETENTION;
        self.records
            .retain(|record| record.terminal_at.is_none_or(retained));
        self.tombstones
            .retain(|tombstone| retained(tombstone.terminal_at));
    }

    /// The earlier admission under `scope`, live or evicted: its id, body digest and result.
    fn replay(&self, scope: &[u8; 32]) -> Option<(&str, [u8; 32], watch::Receiver<Admission>)> {
        self.records
            .iter()
            .find_map(|record| {
                let old = record.replay.as_ref().filter(|old| &old.scope == scope)?;
                Some((record.id.as_str(), old.body, record.admission.subscribe()))
            })
            .or_else(|| {
                let old = self
                    .tombstones
                    .iter()
                    .find(|old| &old.replay.scope == scope)?;
                let accepted = accepted(&old.id, old.kind);
                Some((
                    old.id.as_str(),
                    old.replay.body,
                    watch::channel(Some(Ok(accepted))).1,
                ))
            })
    }

    /// Frees the slot of the earliest-finished operation; a keyed one leaves a tombstone.
    fn evict_oldest_terminal(&mut self) -> Result<(), ApiError> {
        let oldest = self
            .records
            .iter()
            .enumerate()
            .filter_map(|(index, record)| record.terminal_at.map(|at| (at, index)))
            .min()
            .map(|(_, index)| index)
            .ok_or_else(unavailable)?;
        let evicted = self.records.remove(oldest);
        if let (Some(replay), Some(terminal_at)) = (evicted.replay, evicted.terminal_at) {
            if self.tombstones.len() == MAX_TOMBSTONES {
                self.tombstones.pop_front();
            }
            self.tombstones.push_back(Tombstone {
                id: evicted.id,
                kind: evicted.kind,
                replay,
                terminal_at,
            });
        }
        Ok(())
    }
}

fn accepted(id: &str, kind: OperationKind) -> OperationAcceptedResponse {
    OperationAcceptedResponse {
        operation_id: id.into(),
        kind,
        status: "queued",
        href: format!("/api/v1/operations/{id}"),
    }
}

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Operation admission is temporarily unavailable.",
        None,
    )
}

fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "The requested operation was not found.",
        None,
    )
}

/// Whether `details` is an object that fits an operation error.
pub(crate) fn error_details_fit(details: &Value) -> bool {
    details.is_object() && serde_json::to_writer(DetailsBudget(MAX_ERROR_DETAILS), details).is_ok()
}

struct DetailsBudget(usize);

impl Write for DetailsBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
