use super::*;
use crate::ebpf::{RETIRE_BATCH_CAPACITY, UdpDecisionCommit};
use futures::FutureExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::oneshot;

pub(super) struct CommitPump {
    tx: mpsc::Sender<CommitRequest>,
    task: tokio::sync::Mutex<CommitTask>,
    stop: watch::Sender<bool>,
    work: AtomicUsize,
    #[cfg(test)]
    pub(super) after_lock_delay: Mutex<Option<Duration>>,
}

struct CommitTask {
    receiver: Option<mpsc::Receiver<CommitRequest>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl CommitPump {
    pub(super) fn new() -> Self {
        let (tx, rx) = mpsc::channel(MAX_CORRELATOR_FLOWS);
        let (stop, _) = watch::channel(false);
        Self {
            tx,
            task: tokio::sync::Mutex::new(CommitTask {
                receiver: Some(rx),
                handle: None,
            }),
            stop,
            work: AtomicUsize::new(0),
            #[cfg(test)]
            after_lock_delay: Mutex::new(None),
        }
    }

    pub(super) fn is_idle(&self) -> bool {
        self.work.load(Ordering::Acquire) == 0
    }
}

struct CommitRequest {
    owner: Arc<PendingUdpVerdicts>,
    cell: Arc<FlowCell>,
    transition: UdpDecisionTransition,
    deadline: Instant,
    lease: Option<UdpInitLease>,
    reply: Option<oneshot::Sender<Result<(), PendingUdpDecisionError>>>,
}

impl CommitRequest {
    fn respond(&mut self, result: Result<(), PendingUdpDecisionError>) {
        drop(self.lease.take());
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(result);
        }
    }
}

impl Drop for CommitRequest {
    fn drop(&mut self) {
        drop(self.lease.take());
        self.owner.commits.work.fetch_sub(1, Ordering::Release);
        self.owner.empty.notify_waiters();
    }
}

enum Completion {
    NotRun,
    Expired,
    Refused(PendingUdpDecisionError),
    Armed,
    Terminal(VecDeque<HeldVerdict>, DropOutcome),
}

impl PendingUdpVerdicts {
    pub(super) async fn commit_pending(
        self: &Arc<Self>,
        cell: Arc<FlowCell>,
        transition: UdpDecisionTransition,
        lease: Option<UdpInitLease>,
    ) -> Result<(), PendingUdpDecisionError> {
        let deadline = {
            let state = cell.state.lock();
            let CellState::Pending { started_at, .. } = &*state else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            *started_at + HARD_HOLD_TIMEOUT
        };
        {
            let mut task = self.commits.task.lock().await;
            if *self.commits.stop.borrow() {
                return Err(PendingUdpDecisionError::StaleIdentity);
            }
            if task.handle.is_none() {
                let rx = task.receiver.take().expect("one commit pump receiver");
                let pending = Arc::clone(self);
                let stop = self.commits.stop.subscribe();
                task.handle = Some(tokio::spawn(async move {
                    if std::panic::AssertUnwindSafe(Arc::clone(&pending).run_commits(rx, stop))
                        .catch_unwind()
                        .await
                        .is_err()
                    {
                        pending.signal_fatal(PendingUdpFatal::new("commit pump", "task panicked"));
                    }
                }));
            }
        }
        let slot = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.commits.tx.reserve(),
        )
        .await
        {
            Ok(Ok(slot)) => slot,
            Ok(Err(_)) if *self.commits.stop.borrow() => {
                return Err(PendingUdpDecisionError::StaleIdentity);
            }
            Ok(Err(_)) => return Err(self.fatal_error("commit pump", "queue closed".into())),
            Err(_) => return Err(self.expire_commit(&cell)),
        };
        let (reply, result) = oneshot::channel();
        self.commits.work.fetch_add(1, Ordering::Relaxed);
        slot.send(CommitRequest {
            owner: Arc::clone(self),
            cell,
            transition,
            deadline,
            lease,
            reply: Some(reply),
        });
        result
            .await
            .unwrap_or_else(|_| Err(self.fatal_error("commit pump", "request lost".into())))
    }

    async fn run_commits(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<CommitRequest>,
        mut stop: watch::Receiver<bool>,
    ) {
        let mut closing = false;
        let mut batch = Vec::with_capacity(RETIRE_BATCH_CAPACITY);
        let mut requests = Vec::with_capacity(RETIRE_BATCH_CAPACITY);
        let mut completed = Vec::with_capacity(RETIRE_BATCH_CAPACITY);
        loop {
            let first = tokio::select! {
                biased;
                changed = stop.changed(), if !closing => {
                    let _ = changed;
                    closing = true;
                    rx.close();
                    continue;
                }
                request = rx.recv() => request,
            };
            let Some(first) = first else { break };
            batch.push(first);
            // One scheduler turn coalesces ready callers without adding a timer
            // or extending the first packet's absolute hold deadline.
            tokio::task::yield_now().await;
            while batch.len() < RETIRE_BATCH_CAPACITY {
                let Ok(request) = rx.try_recv() else { break };
                batch.push(request);
            }
            self.process_commits(&mut batch, &mut requests, &mut completed)
                .await;
            batch.clear();
        }
    }

    pub(super) fn expire_commit(&self, cell: &Arc<FlowCell>) -> PendingUdpDecisionError {
        let armed = matches!(&*cell.state.lock(), CellState::Pending { armed: true, .. });
        if armed {
            self.fail_armed(cell, cell.identity);
            PendingUdpDecisionError::ArmedInProgress
        } else {
            self.expire_unarmed_pending(cell, cell.identity)
        }
    }

    fn discard_expired_commits(&self, batch: &mut Vec<CommitRequest>) {
        self.reject_expired_commits(take_expired_commits(batch));
    }

    fn reject_expired_commits(&self, expired: Vec<CommitRequest>) {
        for mut request in expired {
            request.respond(Err(self.expire_commit(&request.cell)));
        }
    }

    async fn process_commits(
        &self,
        batch: &mut Vec<CommitRequest>,
        requests: &mut Vec<UdpDecisionCommit>,
        completed: &mut Vec<Completion>,
    ) {
        requests.clear();
        completed.clear();
        self.discard_expired_commits(batch);
        let mut backend = loop {
            let Some(deadline) = batch.iter().map(|request| request.deadline).min() else {
                return;
            };
            match tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.ebpf.write(),
            )
            .await
            {
                Ok(backend) => break backend,
                Err(_) => self.discard_expired_commits(batch),
            }
        };
        #[cfg(test)]
        if let Some(delay) = self.commits.after_lock_delay.lock().take() {
            std::thread::sleep(delay);
        }
        // Expiry drops held verdicts and retires endpoints; keep that I/O off backend W.
        let expired = take_expired_commits(batch);
        if batch.is_empty() {
            drop(backend);
            self.reject_expired_commits(expired);
            return;
        }
        requests.extend(batch.iter().map(|request| UdpDecisionCommit {
            key: request.cell.identity.tuples(),
            token: request.cell.identity.owner.token,
            transition: request.transition,
        }));
        completed.resize_with(batch.len(), || Completion::NotRun);
        let result = blocking_section(|| {
            backend.commit_udp_batch(requests, &mut |index, apply| {
                completed[index] = self.apply_pending_commit(&batch[index], apply)?;
                Ok(())
            })
        });
        drop(backend);
        self.reject_expired_commits(expired);
        if let Err(error) = result {
            let fatal = PendingUdpFatal::new("commit batch", format!("{error:#}"));
            self.signal_fatal(fatal.clone());
            for (request, completion) in batch.iter_mut().zip(completed.drain(..)) {
                match completion {
                    Completion::Armed => self.fail_armed(&request.cell, request.cell.identity),
                    Completion::Terminal(verdicts, _) => {
                        self.drop_many(verdicts, DropOutcome::Cancel)
                    }
                    _ => {}
                }
                request.respond(Err(fatal.clone().into()));
            }
            return;
        }
        // Terminal verdicts must not wait behind another flow's second backend
        // acquisition. Each direct flow still completes Arm -> FIFO -> Activate.
        for (request, completion) in batch.iter_mut().zip(completed.iter_mut()) {
            if !matches!(completion, Completion::Armed) {
                let completion = std::mem::replace(completion, Completion::NotRun);
                self.complete_request(request, completion).await;
            }
        }
        for (request, completion) in batch.iter_mut().zip(completed.drain(..)) {
            if matches!(completion, Completion::Armed) {
                self.complete_request(request, completion).await;
            }
        }
    }

    async fn complete_request(&self, request: &mut CommitRequest, completion: Completion) {
        let result = match completion {
            Completion::Expired => Err(self.expire_commit(&request.cell)),
            Completion::Refused(error) => Err(error),
            Completion::Armed => {
                let UdpDecisionTransition::ArmDirect(mark) = request.transition else {
                    unreachable!()
                };
                self.finish_armed_direct(&request.cell, request.cell.identity, mark)
                    .await
            }
            Completion::Terminal(verdicts, outcome) => {
                let mut result = Ok(());
                for verdict in verdicts {
                    if let Err(error) = self.drop_one_fatal(verdict, outcome) {
                        result = Err(error);
                        break;
                    }
                }
                result
            }
            Completion::NotRun => {
                Err(self.fatal_error("commit batch", "backend omitted item".into()))
            }
        };
        let result = result.and_then(|()| {
            if let Some(lease) = request.lease.as_mut()
                && !lease.commit_kernel_handoff()
            {
                return Err(if lease.initialization_cancelled() {
                    PendingUdpDecisionError::StaleIdentity
                } else {
                    self.fatal_error(
                        "terminal endpoint handoff",
                        "backend committed after endpoint identity was retired".into(),
                    )
                });
            }
            Ok(())
        });
        request.respond(result);
    }

    fn apply_pending_commit(
        &self,
        request: &CommitRequest,
        apply: &mut dyn FnMut() -> anyhow::Result<UdpDecisionCommitResult>,
    ) -> anyhow::Result<Completion> {
        let mut state = request.cell.state.lock();
        if Instant::now() >= request.deadline {
            return Ok(Completion::Expired);
        }
        let CellState::Pending {
            armed,
            cancelling,
            verdicts,
            ..
        } = &mut *state
        else {
            return Ok(Completion::Refused(PendingUdpDecisionError::StaleIdentity));
        };
        if *armed {
            return Ok(Completion::Refused(
                PendingUdpDecisionError::ArmedInProgress,
            ));
        }
        if *cancelling {
            return Ok(Completion::Refused(PendingUdpDecisionError::StaleIdentity));
        }
        let result = apply()?;
        if result != UdpDecisionCommitResult::Applied {
            self.record_commit_mismatch(result);
            return Ok(Completion::Refused(PendingUdpDecisionError::StaleIdentity));
        }
        let completion = match request.transition {
            UdpDecisionTransition::ArmDirect(_) => {
                *armed = true;
                Completion::Armed
            }
            UdpDecisionTransition::ActivateProxy(_, _) | UdpDecisionTransition::Block => {
                let verdicts = std::mem::take(verdicts);
                let expires_at = Instant::now() + TERMINAL_GRACE;
                let outcome = if matches!(request.transition, UdpDecisionTransition::Block) {
                    *state = CellState::Block { expires_at };
                    DropOutcome::Block
                } else {
                    *state = CellState::Proxy { expires_at };
                    DropOutcome::Proxy
                };
                Completion::Terminal(verdicts, outcome)
            }
            UdpDecisionTransition::ActivateDirect(_) => {
                unreachable!("activation is never batched behind a grace period")
            }
        };
        drop(state);
        request.cell.changed.notify_waiters();
        Ok(completion)
    }

    pub(in crate::control) async fn shutdown_commit_pump(&self) -> anyhow::Result<()> {
        // Under the task lock a pump spawn either sees stop or subscribes before it.
        let mut task = self.commits.task.lock().await;
        self.commits.stop.send_replace(true);
        if let Some(handle) = task.handle.as_mut() {
            let result = handle.await;
            task.handle = None;
            result.map_err(|error| anyhow::anyhow!("join NFQUEUE commit pump: {error}"))?;
        } else if let Some(mut rx) = task.receiver.take() {
            rx.close();
        }
        Ok(())
    }
}

fn take_expired_commits(batch: &mut Vec<CommitRequest>) -> Vec<CommitRequest> {
    let now = Instant::now();
    batch
        .extract_if(.., |request| now >= request.deadline)
        .collect()
}

#[cfg(test)]
#[test]
fn commit_queue_rejects_work_beyond_its_hard_bound() {
    let (pending, _) = PendingUdpVerdicts::new(
        Arc::new(RwLock::new(Box::new(
            crate::ebpf::mock::MockEbpfBackend::new(),
        ))),
        Arc::new(UdpEndpointPool::new()),
        Arc::new(StatsManager::new()),
    );
    let pending = Arc::new(pending);
    let rx = pending
        .commits
        .task
        .try_lock()
        .unwrap()
        .receiver
        .take()
        .unwrap();
    let identity = PendingUdpIdentity::new(
        honk_datapath::ScopeId::HOST,
        FlowKey::new(
            "192.0.2.1:40000".parse().unwrap(),
            "198.51.100.1:443".parse().unwrap(),
        ),
        crate::ebpf::UdpFlowOwner::new(1, None).unwrap(),
        1,
    );
    let cell = Arc::new(FlowCell::terminal(
        identity,
        CellState::Dead {
            expires_at: Instant::now(),
        },
        Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
    ));
    for _ in 0..MAX_CORRELATOR_FLOWS {
        let (reply, _) = oneshot::channel();
        pending.commits.work.fetch_add(1, Ordering::Relaxed);
        pending
            .commits
            .tx
            .try_send(CommitRequest {
                owner: Arc::clone(&pending),
                cell: Arc::clone(&cell),
                transition: UdpDecisionTransition::Block,
                deadline: Instant::now() + HARD_HOLD_TIMEOUT,
                lease: None,
                reply: Some(reply),
            })
            .unwrap_or_else(|_| panic!("queue filled before its bound"));
    }
    assert!(matches!(
        pending.commits.tx.try_reserve(),
        Err(mpsc::error::TrySendError::Full(()))
    ));
    drop(rx);
    assert!(pending.commits.is_idle());
}
