use super::*;
use crate::configuration::{ActivationCompletion, ActivationFailure, ActivationRequest};
use crate::native_api::operations::OperationResult;
use crate::native_api::store::Committed;

impl ActivationFailure {
    fn reason(self) -> (&'static str, &'static str) {
        match self {
            Self::EngineUnavailable => ("engine_unavailable", "Reload engine is unavailable"),
            Self::Unconfirmed => (
                "activation_unconfirmed",
                "Reload engine stopped before completion",
            ),
            Self::Rejected => ("reload_rejected", "Configuration reload was rejected"),
            Self::Degraded(_) => (
                "reload_degraded",
                "Configuration committed with degraded datapath",
            ),
            Self::Reconciliation(_) => (
                "supervisor_reconciliation_failed",
                "Configuration committed but worker reconciliation failed",
            ),
        }
    }

    /// Whether the new generation is active; `None` when the server cannot tell.
    fn committed(self) -> Option<bool> {
        match self {
            Self::Unconfirmed => None,
            Self::Degraded(_) | Self::Reconciliation(_) => Some(true),
            _ => Some(false),
        }
    }

    fn active_generation_id(self, instance: &str) -> Option<String> {
        match self {
            Self::Degraded(generation) => Some(format!("{instance}:{generation}")),
            Self::Reconciliation(generation) => {
                generation.map(|generation| format!("{instance}:{generation}"))
            }
            _ => None,
        }
    }

    pub(super) fn management_error(self, written: bool, instance: &str) -> ApiError {
        management::activation_error(
            self.reason().0,
            Some(written),
            written.then_some(true),
            self.committed(),
            self.active_generation_id(instance),
        )
    }

    /// The activation outcome of a failed operation; `written` is `None` for a plain reload.
    fn details(self, written: Option<bool>, instance: &str) -> Value {
        let mut details = json!({"committed": self.committed()});
        if let Some(written) = written {
            details["written"] = json!(written);
        }
        if self.committed() == Some(true) {
            details["active_generation_id"] = json!(self.active_generation_id(instance));
        }
        details
    }
}

/// The outcome code and message of a failure `Worker::record` reports.
pub(super) fn record_failure(completion: &ActivationCompletion) -> (&'static str, &'static str) {
    match completion {
        Err(ActivationFailure::Unconfirmed) => ActivationFailure::Unconfirmed.reason(),
        _ => (
            "store_unavailable",
            "Configuration is active but was not recorded",
        ),
    }
}

pub(super) fn log_sighup(completion: ActivationCompletion) {
    match completion {
        Ok(outcome) => tracing::info!(generation = outcome.generation(), "SIGHUP reload applied"),
        Err(ActivationFailure::Degraded(generation)) => {
            tracing::warn!(generation, "SIGHUP reload committed with degraded datapath")
        }
        Err(failure) => tracing::warn!(stage = failure.reason().0, "SIGHUP reload rejected"),
    }
}

impl Worker {
    pub(super) async fn replace_operation(
        &mut self,
        id: &str,
        request: ActivationRequest,
        group: Option<&str>,
        committed: Committed,
    ) {
        self.begin_record(&committed);
        let pending = match self.activation.dispatch(request).await {
            Ok(pending) => pending,
            Err(failure) => {
                let written = committed.written();
                let mut details = failure.details(Some(written), &self.service.instance_id);
                details["stage"] = json!(failure.reason().0);
                let error = unavailable().with_details(details);
                let error = if written {
                    error.without_retry_after()
                } else {
                    error
                };
                self.service.operations.reject(id, error);
                *self.service.recording.write() = RecordState::Idle;
                return;
            }
        };
        self.service.operations.accept(id);
        self.service.operations.running(id);
        let completion = self.activation.complete(pending).await;
        let stored = match self.record(committed, &completion).await {
            Ok(stored) => stored,
            Err(details) => {
                let (code, message) = record_failure(&completion);
                self.failed(id, code, message, Some(details));
                return;
            }
        };
        self.publish_operation(id, completion, group, Some(stored));
    }

    pub(super) fn begin_record(&self, committed: &Committed) {
        if !committed.written() {
            let revision = self.service.sources.revision();
            *self.service.recording.write() = RecordState::Pending(revision);
        }
    }

    /// Records an activated candidate in the store. `Ok` says whether the store
    /// now holds the candidate; `Err` carries the failure details.
    pub(super) async fn record(
        &self,
        committed: Committed,
        completion: &ActivationCompletion,
    ) -> Result<bool, Value> {
        if committed.written() {
            return Ok(true);
        }
        let instance = &self.service.instance_id;
        let result = match completion {
            Ok(_) | Err(ActivationFailure::Degraded(_) | ActivationFailure::Reconciliation(_)) => {
                let writer = self.store.clone();
                match tokio::task::spawn_blocking(move || writer.promote(committed)).await {
                    Ok(Ok(())) => Ok(true),
                    _ => {
                        self.store.block();
                        let active = match completion {
                            Ok(outcome) => outcome
                                .generation()
                                .map(|generation| format!("{instance}:{generation}")),
                            Err(failure) => failure.active_generation_id(instance),
                        };
                        Err(json!({"committed":true,"written":false,"active_generation_id":active}))
                    }
                }
            }
            Err(ActivationFailure::Unconfirmed) => {
                self.store.block();
                Err(json!({"committed":null,"written":false}))
            }
            Err(_) => Ok(false),
        };
        *self.service.recording.write() = RecordState::Idle;
        result
    }

    pub(super) async fn reload_operation(&mut self, id: &str, request: ActivationRequest) {
        let completion = self.activation.activate(request).await;
        self.publish_operation(id, completion, None, None);
    }

    fn publish_operation(
        &self,
        id: &str,
        completion: ActivationCompletion,
        group: Option<&str>,
        // Whether the store holds the change; `None` for a plain reload.
        written: Option<bool>,
    ) {
        match completion {
            Err(failure) => {
                let details = failure.details(written, &self.service.instance_id);
                let (code, message) = failure.reason();
                self.failed(id, code, message, Some(details));
            }
            Ok(outcome) => {
                let result = if let Some(group_id) = group {
                    let Some(config_revision) = self.service.sources.revision() else {
                        self.failed(
                            id,
                            "source_authority_lost",
                            "Group committed without retained source authority",
                            None,
                        );
                        return;
                    };
                    OperationResult::GroupUpdate {
                        group_id: group_id.to_owned(),
                        config_revision,
                    }
                } else {
                    OperationResult::Reload {
                        active_generation_id: outcome
                            .generation()
                            .map(|generation| format!("{}:{generation}", self.service.instance_id)),
                        datapath_generation_id: None,
                    }
                };
                self.service.operations.succeed(id, result);
                self.reloaded(id);
            }
        }
    }

    pub(super) fn reloaded(&self, id: &str) {
        *self.service.last_reload.write() = Some(
            json!({"operation_id":id,"status":"succeeded","finished_at":timestamp(SystemTime::now()),"error":null}),
        );
    }

    pub(super) fn failed(
        &self,
        id: &str,
        code: &'static str,
        message: &'static str,
        details: Option<Value>,
    ) {
        // `last_reload` reports only what the operation keeps.
        let details = details.filter(crate::native_api::operations::error_details_fit);
        self.service
            .operations
            .fail(id, code, message, details.clone());
        *self.service.last_reload.write() = Some(
            json!({"operation_id":id,"status":"failed","finished_at":timestamp(SystemTime::now()),"error":{"code":code,"message":message,"details":details}}),
        );
    }
}
