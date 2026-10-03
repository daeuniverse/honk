//! Daemon-owned, bounded typed probes over captured configuration and runtime owners.

use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use honk_config::{Config, node::Node};
use honk_outbound::{
    alive::{
        GroupProbeContext, HealthMeasurement, HealthObservation, HealthPurpose, HealthState,
        HealthTransport, HealthWarmth, IpVersion, ProbeDomain, ProbeMeasurement, ProbeTicket,
    },
    group::{GroupManager, GroupMember, SelectionNetwork},
    runtime::OutboundRuntimeRegistry,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    sync::{Notify, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use uuid::Uuid;

use super::{
    ApiError, ErrorCode, NativeState, config,
    operations::{OperationKind, OperationResult, OperationStore, Reservation},
    parse_query,
    security::{REQUESTS_PER_MINUTE, RequestRate},
    timestamp,
    types::RequestId,
};
use crate::observe::catalog::CatalogIdentity;

mod planning;
#[cfg(test)]
mod tests;
mod wire;

use planning::{Attempt, Context, Plan, PreparedPlan, capture, prepare};
use wire::execute;

const MAX_MEMBERS: usize = 64;
const MAX_RESULTS: usize = 256;
const MAX_ACTIVE: usize = 4;
const MAX_QUEUED: usize = 16;
const DEADLINE: Duration = Duration::from_secs(30);

/// Operation error for an admitted job that ended before measurement.
type Unmeasured = (&'static str, &'static str);
const CANCELLED: Unmeasured = ("probe_cancelled", "Probe was cancelled before measurement.");
const EXPIRED: Unmeasured = (
    "probe_deadline",
    "Probe deadline expired before measurement.",
);
const ENGINE_UNAVAILABLE: Unmeasured = (
    "engine_unavailable",
    "Engine is not ready for this operation",
);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    TcpConnect,
    Http,
    Dns,
}
impl Kind {
    /// The health purpose the kind measures; a request cannot choose it.
    fn purpose(self) -> Purpose {
        match self {
            Self::TcpConnect | Self::Http => Purpose::Data,
            Self::Dns => Purpose::Dns,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
enum Transport {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
enum Family {
    Ipv4,
    Ipv6,
}
impl Family {
    fn ip(self) -> IpVersion {
        match self {
            Self::Ipv4 => IpVersion::V4,
            Self::Ipv6 => IpVersion::V6,
        }
    }
    fn matches(self, ip: IpAddr) -> bool {
        ip.is_ipv4() == (self == Self::Ipv4)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum RequestedFamily {
    Ipv4,
    Ipv6,
    Any,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Warmth {
    Cold,
    Warm,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum Target {
    Node { node_id: String },
    Group { group_id: String },
}
impl Target {
    fn key(&self) -> String {
        match self {
            Self::Node { node_id } => format!("node:{node_id}"),
            Self::Group { group_id } => format!("group:{group_id}"),
        }
    }
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Members {
    Scope(MemberScope),
    Ids(Vec<String>),
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum MemberScope {
    Direct,
    Leaves,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeRequest {
    target: Target,
    kind: Kind,
    transport: Vec<Transport>,
    ip_version: RequestedFamily,
    warmth: Warmth,
    #[serde(default, deserialize_with = "present_members")]
    members: Option<Members>,
}
fn present_members<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Members>, D::Error> {
    Members::deserialize(deserializer).map(Some)
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Purpose {
    Data,
    Dns,
}
#[derive(Debug, Serialize)]
pub(crate) struct ProbeResult {
    target: Target,
    selection_changed: TransportMap<bool>,
    selection_before: TransportMap<Option<String>>,
    selection_after: TransportMap<Option<String>>,
    results: Vec<ResultRow>,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct TransportMap<T> {
    tcp: T,
    udp: T,
}
#[derive(Debug, Serialize)]
struct ResultRow {
    member_id: String,
    resolved_leaf_node_id: Option<String>,
    kind: Kind,
    purpose: Purpose,
    transport: Transport,
    ip_version: Family,
    warmth: &'static str,
    state: &'static str,
    latency_ms: Option<f64>,
    health_updated: bool,
    error: Option<&'static str>,
    observed_at: String,
}
struct Job {
    reservation: Reservation,
    plan: Plan,
    deadline: Instant,
}
struct RunningJob<'a> {
    service: &'a ProbeService,
    target: String,
    id: String,
}
impl Drop for RunningJob<'_> {
    fn drop(&mut self) {
        self.service.targets.lock().remove(&self.target);
        self.service.operations.fail(
            &self.id,
            "probe_interrupted",
            "Probe worker did not complete.",
            None,
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProbeLifecycleError {
    #[error("Probe worker is unavailable")]
    Unavailable,
    #[error("Probe worker transition conflicts with its current state")]
    Conflict,
    #[error("Probe worker cleanup failed")]
    CleanupFailed,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkerState {
    NotStarted,
    Running,
    Transitioning,
    Faulted,
    Stopped,
}
enum Command {
    Pause(oneshot::Sender<Result<(), ProbeLifecycleError>>),
}
struct Gate {
    state: WorkerState,
    requests: usize,
    cancel: watch::Sender<bool>,
    engine: Option<std::sync::Weak<NativeState>>,
}
struct RequestGuard<'a> {
    service: &'a ProbeService,
    cancel: Option<watch::Receiver<bool>>,
}
impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        if self.cancel.is_some() {
            let mut gate = self.service.gate.lock();
            gate.requests -= 1;
            if gate.requests == 0 {
                self.service.requests_drained.notify_one();
            }
        }
    }
}

pub(crate) struct ProbeService {
    operations: Arc<OperationStore>,
    rate: RequestRate,
    sender: mpsc::Sender<Job>,
    receiver: Mutex<Option<(mpsc::Receiver<Job>, mpsc::Receiver<Command>)>>,
    commands: mpsc::Sender<Command>,
    targets: Mutex<HashSet<String>>,
    gate: Mutex<Gate>,
    requests_drained: Notify,
}

impl ProbeService {
    pub(crate) fn new(operations: Arc<OperationStore>) -> Self {
        let (sender, receiver) = mpsc::channel(MAX_QUEUED);
        let (commands, command_receiver) = mpsc::channel(1);
        let (cancel, _) = watch::channel(false);
        Self {
            operations,
            rate: RequestRate::new(),
            sender,
            receiver: Mutex::new(Some((receiver, command_receiver))),
            commands,
            targets: Mutex::new(HashSet::new()),
            gate: Mutex::new(Gate {
                state: WorkerState::NotStarted,
                requests: 0,
                cancel,
                engine: None,
            }),
            requests_drained: Notify::new(),
        }
    }
    pub(crate) fn running(&self) -> bool {
        let gate = self.gate.lock();
        gate.state == WorkerState::Running
            && gate
                .engine
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .is_some_and(|state| state.require_running().is_ok())
    }
    pub(crate) async fn pause(&self) -> Result<(), ProbeLifecycleError> {
        let (reply, result) = oneshot::channel();
        {
            let mut gate = self.gate.lock();
            match gate.state {
                WorkerState::Running => {}
                WorkerState::NotStarted | WorkerState::Stopped => {
                    return Err(ProbeLifecycleError::Unavailable);
                }
                WorkerState::Faulted => return Err(ProbeLifecycleError::CleanupFailed),
                _ => return Err(ProbeLifecycleError::Conflict),
            }
            let permit = self
                .commands
                .try_reserve()
                .map_err(|_| ProbeLifecycleError::Unavailable)?;
            gate.state = WorkerState::Transitioning;
            gate.cancel.send_replace(true);
            permit.send(Command::Pause(reply));
        }
        result
            .await
            .unwrap_or(Err(ProbeLifecycleError::Unavailable))
    }
    fn request(&self) -> RequestGuard<'_> {
        let mut gate = self.gate.lock();
        let cancel = if gate.state == WorkerState::Running {
            gate.requests += 1;
            Some(gate.cancel.subscribe())
        } else {
            None
        };
        RequestGuard {
            service: self,
            cancel,
        }
    }
    async fn drain_requests(&self) {
        while self.gate.lock().requests != 0 {
            self.requests_drained.notified().await;
        }
    }
    pub(crate) fn capability(&self) -> Value {
        json!({"available": self.running(), "targets":["node","group"], "kinds":["tcp_connect","http","dns"], "transports":["tcp","udp"], "ip_versions":["ipv4","ipv6"], "limits":{"max_members_per_job":MAX_MEMBERS,"max_results_per_job":MAX_RESULTS,"max_active_jobs":MAX_ACTIVE,"max_queued_jobs":MAX_QUEUED,"max_concurrent_per_target":1,"job_timeout_ms":DEADLINE.as_millis(),"per_principal_requests_per_minute":REQUESTS_PER_MINUTE,"global_requests_per_minute":REQUESTS_PER_MINUTE}})
    }
    pub(crate) fn start(
        self: &Arc<Self>,
        state: Arc<NativeState>,
        mut stop: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        let (mut receiver, mut commands) = self
            .receiver
            .lock()
            .take()
            .expect("probe service starts once");
        {
            let mut gate = self.gate.lock();
            gate.state = WorkerState::Running;
            gate.engine = Some(Arc::downgrade(&state));
        }
        let owner = Arc::clone(self);
        tokio::spawn(async move {
            let mut jobs = JoinSet::new();
            let mut clean = true;
            loop {
                if *stop.borrow() {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = stop.changed() => break,
                    command = commands.recv() => match command {
                        Some(Command::Pause(reply)) => {
                            while let Ok(job) = receiver.try_recv() {
                                owner.cancel_queued(&job);
                            }
                            owner.drain_requests().await;
                            while let Some(result) = jobs.join_next().await { clean &= matches!(result, Ok(Ok(()))); }
                            owner.gate.lock().state = if clean { WorkerState::Stopped } else { WorkerState::Faulted };
                            let _ = reply.send(if clean { Ok(()) } else { Err(ProbeLifecycleError::CleanupFailed) });
                        }
                        None => break,
                    },
                    completed = jobs.join_next(), if !jobs.is_empty() => {
                        clean &= matches!(completed, Some(Ok(Ok(()))));
                        if !clean {
                            let mut gate = owner.gate.lock();
                            gate.state = WorkerState::Faulted;
                            gate.cancel.send_replace(true);
                        }
                    },
                    job = receiver.recv(), if jobs.len() < MAX_ACTIVE => {
                        let Some(job) = job else { break; };
                        let gate = owner.gate.lock();
                        if gate.state != WorkerState::Running {
                            owner.cancel_queued(&job);
                            continue;
                        }
                        let cancel = gate.cancel.subscribe();
                        let owner = Arc::clone(&owner);
                        let state = Arc::clone(&state);
                        jobs.spawn(async move { owner.run_job(&state, job, cancel).await });
                    }
                }
            }
            {
                let mut gate = owner.gate.lock();
                gate.state = WorkerState::Stopped;
                gate.cancel.send_replace(true);
            }
            commands.close();
            receiver.close();
            while let Some(job) = receiver.recv().await {
                owner.cancel_queued(&job);
            }
            owner.drain_requests().await;
            while jobs.join_next().await.is_some() {}
        })
    }
    fn enqueue(&self, job: Job) -> Result<(), ApiError> {
        let gate = self.gate.lock();
        let mut targets = self.targets.lock();
        let reject = |error: ApiError| {
            self.operations.reject(&job.reservation.id, error.clone());
            error
        };
        if gate.state != WorkerState::Running {
            return Err(reject(unavailable()));
        }
        let key = job.plan.context.spec.target.key();
        if targets.contains(&key) {
            return Err(reject(
                ApiError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    ErrorCode::RateLimited,
                    "A probe for this target is already admitted.",
                    None,
                )
                .with_retry_after(1),
            ));
        }
        let permit = self
            .sender
            .try_reserve()
            .map_err(|_| reject(unavailable()))?;
        targets.insert(key);
        self.operations.accept(&job.reservation.id);
        permit.send(job);
        Ok(())
    }
    fn cancel_queued(&self, job: &Job) {
        let (code, message) = CANCELLED;
        self.operations
            .fail(&job.reservation.id, code, message, None);
        self.targets
            .lock()
            .remove(&job.plan.context.spec.target.key());
    }
    async fn run_job(
        &self,
        state: &NativeState,
        job: Job,
        stop: watch::Receiver<bool>,
    ) -> Result<(), ProbeLifecycleError> {
        let _running = RunningJob {
            service: self,
            target: job.plan.context.spec.target.key(),
            id: job.reservation.id.clone(),
        };
        let id = &job.reservation.id;
        self.operations.running(id);
        let preparation = wire::bounded(job.deadline, stop.clone(), async {
            state
                .require_running()
                .map_err(|_| (ENGINE_UNAVAILABLE, None))?;
            // Preparation refuses only with unsupported_value; keep its safe message and details.
            prepare(job.plan)
                .await
                .map_err(|error| (("unsupported_value", error.message()), error.into_details()))
        })
        .await;
        let ((code, message), details) = match preparation {
            Ok(Ok(mut plan)) => {
                let start = {
                    let gate = self.gate.lock();
                    if gate.state != WorkerState::Running || *stop.borrow() {
                        Err(CANCELLED)
                    } else {
                        state.require_running().map_err(|_| ENGINE_UNAVAILABLE)
                    }
                };
                match start {
                    Ok(()) => {
                        if execute(state, &mut plan, job.deadline, stop).await.is_err() {
                            self.operations.fail_with_result(
                                id,
                                "probe_cleanup_failed",
                                "Probe runtime cleanup failed.",
                                OperationResult::Probe(plan.result),
                            );
                            return Err(ProbeLifecycleError::CleanupFailed);
                        }
                        self.operations
                            .succeed(id, OperationResult::Probe(plan.result));
                        return Ok(());
                    }
                    Err(unmeasured) => (unmeasured, None),
                }
            }
            Ok(Err(refusal)) => refusal,
            Err(_) if *stop.borrow() => (CANCELLED, None),
            Err(_) => (EXPIRED, None),
        };
        self.operations.fail(id, code, message, details);
        Ok(())
    }
}

pub(super) async fn create(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let deadline = Instant::now() + DEADLINE;
    parse_query(request.uri(), &[], id)?;
    let key = config::request_header(&request, "idempotency-key")?.map(str::to_owned);
    config::json_type(&request)?;
    let service = &state.observation.probes;
    let guard = service.request();
    let bytes = super::body::buffered(request.into_body()).await;
    let request: ProbeRequest = super::body::decode(&bytes, invalid)?;
    planning::validate(&request)?;
    let reservation = service.operations.reserve(
        state.principal(),
        "POST",
        "/api/v1/probes",
        key.as_deref(),
        &bytes,
        OperationKind::Probe,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        let operation_id = reservation.id.clone();
        let preparation = async {
            state.require_running()?;
            if guard.cancel.as_ref().is_none_or(|cancel| *cancel.borrow()) {
                return Err(unavailable());
            }
            let plan = capture(state, request).await?;
            state.require_running()?;
            service.rate.admit(id)?;
            Ok(plan)
        };
        let result = if let Some(cancel) = &guard.cancel {
            wire::bounded(deadline, cancel.clone(), preparation)
                .await
                .unwrap_or_else(|_| Err(unavailable()))
        } else {
            preparation.await
        };
        match result {
            Ok(plan) => service.enqueue(Job {
                reservation,
                plan,
                deadline,
            })?,
            Err(error) => {
                service.operations.reject(&operation_id, error.clone());
                return Err(error);
            }
        }
    }
    drop(guard);
    Ok(admission.await?.into_response())
}
fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid probe request.",
        None,
    )
}
/// Details name the request field with its allowed values, or the governing
/// setting; configured targets, ports and addresses are never echoed.
fn unsupported(message: &'static str, details: Value) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::UnsupportedValue,
        message,
        None,
    )
    .with_details(details)
}
fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "Probe target or member was not found.",
        None,
    )
}
fn too_large() -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::RequestTooLarge,
        "Probe fan-out exceeds its bounded limits.",
        None,
    )
}
fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Probe admission is temporarily unavailable.",
        None,
    )
    .with_retry_after(1)
}
