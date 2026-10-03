use crate::control::{ControlCommand, ControlPlane, EnginePhase, ReloadOutcome, ReloadReply};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// How the test engine answers `ReloadConfig`; fixtures share it as an `AtomicU8`.
#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum ReloadBehavior {
    Apply,
    /// Answer `Rejected` without applying.
    Reject,
    /// Drop the reply unanswered.
    Drop,
    /// Apply, but report a commit as degraded.
    Degraded,
}

impl ReloadBehavior {
    fn load(cell: &AtomicU8) -> Self {
        let value = cell.load(Ordering::SeqCst);
        [Self::Apply, Self::Reject, Self::Drop, Self::Degraded]
            .into_iter()
            .find(|behavior| *behavior as u8 == value)
            .expect("unknown reload behavior")
    }
}

impl ControlPlane {
    /// Serve commands without binding a datapath, rewriting reload replies on the
    /// way in, then tear down like a startup that failed before binding.
    pub(crate) async fn run_native_config_test_commands(
        &mut self,
        reloads: Arc<AtomicUsize>,
        gate: Option<mpsc::UnboundedSender<oneshot::Sender<()>>>,
        behavior: Arc<AtomicU8>,
    ) -> anyhow::Result<()> {
        let mut inbound = self
            .command_rx
            .take()
            .expect("command receiver already taken");
        let (sender, commands) = mpsc::channel(1);
        self.command_rx = Some(commands);
        let intercept = tokio::spawn(async move {
            while let Some(command) = inbound.recv().await {
                let command = match command {
                    command @ ControlCommand::ReloadConfig { .. } => {
                        reloads.fetch_add(1, Ordering::SeqCst);
                        if let Some(gate) = &gate {
                            let (release, wait) = oneshot::channel();
                            if gate.send(release).is_ok() {
                                let _ = tokio::time::timeout(Duration::from_secs(5), wait).await?;
                            }
                        }
                        match ReloadBehavior::load(&behavior) {
                            ReloadBehavior::Apply => command,
                            ReloadBehavior::Reject => {
                                if let ControlCommand::ReloadConfig { result, .. } = command {
                                    let _ = result.send(ReloadReply {
                                        outcome: ReloadOutcome::Rejected,
                                        authorized: Vec::new(),
                                    });
                                }
                                continue;
                            }
                            ReloadBehavior::Drop => continue,
                            ReloadBehavior::Degraded => degrade(command),
                        }
                    }
                    command => command,
                };
                if sender.send(command).await.is_err() {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        });
        let served = async {
            self.initialize_datapath_flags(false, false).await?;
            self.publish_phase(EnginePhase::Running);
            self.serve_control_commands().await
        }
        .await;
        intercept.abort();
        let intercepted = match intercept.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        };
        self.shutdown_runtime(None, served.and(intercepted).err())
            .await
    }
}

fn degrade(mut command: ControlCommand) -> ControlCommand {
    if let ControlCommand::ReloadConfig { result, .. } = &mut command {
        let (inner, reply) = oneshot::channel::<ReloadReply>();
        let outer = std::mem::replace(result, inner);
        tokio::spawn(async move {
            if let Ok(mut reply) = reply.await {
                if let ReloadOutcome::Committed { generation } = reply.outcome {
                    reply.outcome = ReloadOutcome::CommittedDegraded { generation };
                }
                let _ = outer.send(reply);
            }
        });
    }
    command
}
