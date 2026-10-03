//! Shared configuration activation; native HTTP only projects its typed completion.

#[cfg(feature = "native-api")]
mod accepted;
#[cfg(feature = "native-api")]
pub(crate) use accepted::*;

use honk_config::{Config, diagnostic::DetailedDiagnostic};
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, oneshot};

use crate::control::{ControlCommand, ReloadOutcome, ReloadReply};
use crate::subscription::SubscriptionSupervisorHandle;

pub(crate) struct ActivationRequest {
    pub(crate) candidate: Config,
    pub(crate) diagnostics: Vec<DetailedDiagnostic>,
    #[cfg(feature = "native-api")]
    pub(crate) sources: Option<SourceUpdate>,
    #[cfg(feature = "native-api")]
    pub(crate) expected_group_revision: Option<String>,
    #[cfg(feature = "native-api")]
    pub(crate) deferred_provider: Option<uuid::Uuid>,
}

pub(crate) struct PendingActivation {
    reply: oneshot::Receiver<ReloadReply>,
    #[cfg(feature = "native-api")]
    deferred_provider: Option<uuid::Uuid>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ActivationFailure {
    EngineUnavailable,
    Unconfirmed,
    Rejected,
    Degraded(u64),
    Reconciliation(Option<u64>),
}

pub(crate) type ActivationCompletion = Result<ReloadOutcome, ActivationFailure>;

pub(crate) struct Activation {
    commands: mpsc::Sender<ControlCommand>,
    subscriptions: SubscriptionSupervisorHandle,
    request_id: u64,
}

impl Activation {
    pub(crate) fn new(
        commands: mpsc::Sender<ControlCommand>,
        subscriptions: SubscriptionSupervisorHandle,
    ) -> Self {
        Self {
            commands,
            subscriptions,
            request_id: 0,
        }
    }

    pub(crate) async fn dispatch(
        &mut self,
        request: ActivationRequest,
    ) -> Result<PendingActivation, ActivationFailure> {
        self.request_id += 1;
        let (result, reply) = oneshot::channel();
        self.commands
            .send(ControlCommand::ReloadConfig {
                request_id: self.request_id,
                config: Box::new(request.candidate),
                diagnostics: request.diagnostics,
                result,
                #[cfg(feature = "native-api")]
                sources: request.sources.map(std::sync::Arc::new),
                #[cfg(feature = "native-api")]
                expected_group_revision: request.expected_group_revision,
            })
            .await
            .map_err(|_| ActivationFailure::EngineUnavailable)?;
        Ok(PendingActivation {
            reply,
            #[cfg(feature = "native-api")]
            deferred_provider: request.deferred_provider,
        })
    }

    pub(crate) async fn complete(&self, pending: PendingActivation) -> ActivationCompletion {
        let reply = pending
            .reply
            .await
            .map_err(|_| ActivationFailure::Unconfirmed)?;
        if reply.outcome.accepted() {
            #[cfg(feature = "native-api")]
            let reconciliation = match pending.deferred_provider {
                Some(provider) => {
                    self.subscriptions
                        .reconcile_managed(reply.authorized, provider)
                        .await
                }
                None => self.subscriptions.reconcile(reply.authorized).await,
            };
            #[cfg(not(feature = "native-api"))]
            let reconciliation = self.subscriptions.reconcile(reply.authorized).await;
            if reconciliation.is_err() {
                let _ = self.commands.send(ControlCommand::Shutdown).await;
                return Err(ActivationFailure::Reconciliation(
                    reply.outcome.generation(),
                ));
            }
        }
        match reply.outcome {
            ReloadOutcome::Rejected => Err(ActivationFailure::Rejected),
            ReloadOutcome::CommittedDegraded { generation } => {
                Err(ActivationFailure::Degraded(generation))
            }
            outcome => Ok(outcome),
        }
    }

    pub(crate) async fn activate(&mut self, request: ActivationRequest) -> ActivationCompletion {
        let pending = self.dispatch(request).await?;
        self.complete(pending).await
    }
}

/// Lowercase hex SHA-256 of `bytes`.
pub(crate) fn digest(bytes: &[u8]) -> String {
    encode_digest(&Sha256::digest(bytes))
}

pub(crate) fn encode_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a String is infallible");
    }
    output
}
