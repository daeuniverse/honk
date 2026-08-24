use super::*;

#[cfg(feature = "ebpf")]
const NFQUEUE_STATS_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(feature = "ebpf")]
pub(super) const NFQUEUE_INGEST_QUEUE_LEN: usize = 256;
#[cfg(feature = "ebpf")]
pub(super) const NFQUEUE_INGEST_BYTE_BUDGET: usize = 8 * 1024 * 1024;
#[cfg(feature = "ebpf")]
const NFQUEUE_TOKEN_RETRY_DELAYS: [Duration; 4] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(30),
];

#[cfg(feature = "ebpf")]
#[derive(Debug, Default)]
pub(super) struct NfqueueTokenRetryBackoff {
    failures: usize,
}

#[cfg(feature = "ebpf")]
impl NfqueueTokenRetryBackoff {
    pub(super) fn failed(&mut self) -> Duration {
        let delay =
            NFQUEUE_TOKEN_RETRY_DELAYS[self.failures.min(NFQUEUE_TOKEN_RETRY_DELAYS.len() - 1)];
        self.failures = self.failures.saturating_add(1);
        delay
    }

    pub(super) fn reset(&mut self) {
        self.failures = 0;
    }
}

#[cfg(feature = "ebpf")]
#[derive(Debug)]
struct NfqueueActorQueueEntry {
    received_at: Instant,
    payload_bytes: usize,
}

#[cfg(feature = "ebpf")]
#[derive(Debug, Default)]
struct NfqueueActorQueueState {
    entries: std::collections::VecDeque<NfqueueActorQueueEntry>,
    payload_bytes: usize,
}

#[cfg(feature = "ebpf")]
#[derive(Debug)]
pub(super) struct NfqueueActorQueue {
    state: parking_lot::Mutex<NfqueueActorQueueState>,
    stats: Arc<StatsManager>,
    slow_limit: Arc<tokio::sync::Semaphore>,
}

#[cfg(feature = "ebpf")]
impl NfqueueActorQueue {
    pub(super) fn new(stats: Arc<StatsManager>, slow_limit: Arc<tokio::sync::Semaphore>) -> Self {
        Self {
            state: parking_lot::Mutex::new(NfqueueActorQueueState::default()),
            stats,
            slow_limit,
        }
    }

    pub(super) fn try_enqueue(&self, received_at: Instant, payload_bytes: usize) -> bool {
        let mut state = self.state.lock();
        if state.entries.len() >= NFQUEUE_INGEST_QUEUE_LEN
            || state.payload_bytes.saturating_add(payload_bytes) > NFQUEUE_INGEST_BYTE_BUDGET
        {
            return false;
        }
        state.entries.push_back(NfqueueActorQueueEntry {
            received_at,
            payload_bytes,
        });
        state.payload_bytes += payload_bytes;
        self.publish(&state);
        true
    }

    pub(super) fn dequeue(
        &self,
        payload_bytes: usize,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let mut state = self.state.lock();
        let entry = state
            .entries
            .pop_front()
            .expect("NFQUEUE actor queue accounting underflow");
        debug_assert_eq!(entry.payload_bytes, payload_bytes);
        state.payload_bytes = state.payload_bytes.saturating_sub(entry.payload_bytes);
        self.publish(&state);
        drop(state);
        Arc::clone(&self.slow_limit).try_acquire_owned().ok()
    }

    fn sample(&self) {
        self.publish(&self.state.lock());
    }

    fn publish(&self, state: &NfqueueActorQueueState) {
        self.stats.update_udp_nfqueue_actor_queue(
            state.entries.len(),
            state.payload_bytes,
            state
                .entries
                .front()
                .map_or(Duration::ZERO, |entry| entry.received_at.elapsed()),
        );
    }
}

#[cfg(feature = "ebpf")]
#[derive(Debug, thiserror::Error)]
pub(super) enum NfqueueRuntimeFatal {
    #[error("NFQUEUE listener failed: {0}")]
    Listener(#[source] honk_nfqueue::FatalError),
    #[error("NFQUEUE listener fatal channel closed")]
    ListenerChannelClosed,
    #[error("{0}")]
    Pending(#[source] nfqueue::PendingUdpFatal),
    #[error("NFQUEUE pending fatal channel closed")]
    PendingChannelClosed,
    #[error("UDP decision token backstop failed: {0}")]
    TokenBackstop(String),
    #[error("NFQUEUE watchdog exited unexpectedly: {0}")]
    Watchdog(String),
    #[error("NFQUEUE ingest actor exited unexpectedly: {0}")]
    IngestActor(String),
    #[error("NFQUEUE stats sampler exited unexpectedly: {0}")]
    StatsSampler(String),
}

#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
pub(super) enum NfqueueRuntimeEvent {
    Fatal(anyhow::Error),
    TokenExhausted,
}

#[cfg(feature = "ebpf")]
pub(super) struct NfqueueRuntime {
    pub(super) service: Option<honk_nfqueue::NfqueueService>,
    pub(super) listener_fatal: honk_nfqueue::FatalReceiver,
    pub(super) pending_fatal: mpsc::Receiver<nfqueue::PendingUdpFatal>,
    pub(super) stats: Arc<StatsManager>,
    pub(super) pending: Arc<nfqueue::PendingUdpVerdicts>,
    pub(super) stop: tokio::sync::watch::Sender<bool>,
    pub(super) watchdog: Option<tokio::task::JoinHandle<()>>,
    pub(super) ingest_worker: Option<tokio::task::JoinHandle<()>>,
    pub(super) stats_sampler: Option<tokio::task::JoinHandle<()>>,
    pub(super) token_backstop: tokio::time::Interval,
    pub(super) token_retry: NfqueueTokenRetryBackoff,
    pub(super) sequence_ready: bool,
}

#[cfg(feature = "ebpf")]
impl NfqueueRuntime {
    pub(super) async fn next_event(
        &mut self,
        ebpf: &Arc<RwLock<Box<dyn EbpfBackend>>>,
    ) -> NfqueueRuntimeEvent {
        enum ExitedTask {
            Watchdog(Result<(), tokio::task::JoinError>),
            IngestActor(Result<(), tokio::task::JoinError>),
            StatsSampler(Result<(), tokio::task::JoinError>),
        }
        loop {
            let listener_fatal = &mut self.listener_fatal;
            let pending_fatal = &mut self.pending_fatal;
            let token_backstop = &mut self.token_backstop;
            let watchdog = self
                .watchdog
                .as_mut()
                .expect("NFQUEUE watchdog is retained until shutdown");
            let stats_sampler = self
                .stats_sampler
                .as_mut()
                .expect("NFQUEUE stats sampler is retained until shutdown");
            let ingest_worker = self
                .ingest_worker
                .as_mut()
                .expect("NFQUEUE ingest actor is retained until shutdown");
            let exited = tokio::select! {
                result = listener_fatal => {
                    return NfqueueRuntimeEvent::Fatal(anyhow::Error::new(match result {
                        Ok(error) => NfqueueRuntimeFatal::Listener(error),
                        Err(_) => NfqueueRuntimeFatal::ListenerChannelClosed,
                    }));
                }
                fatal = pending_fatal.recv() => {
                    return NfqueueRuntimeEvent::Fatal(anyhow::Error::new(
                        fatal
                            .map(NfqueueRuntimeFatal::Pending)
                            .unwrap_or(NfqueueRuntimeFatal::PendingChannelClosed),
                    ));
                }
                result = watchdog => Some(ExitedTask::Watchdog(result)),
                result = ingest_worker => Some(ExitedTask::IngestActor(result)),
                result = stats_sampler => Some(ExitedTask::StatsSampler(result)),
                _ = token_backstop.tick() => None,
            };
            // A resolved JoinHandle panics if awaited again; drop it so the
            // shutdown path skips the already-consumed task.
            if let Some(exited) = exited {
                let fatal = match exited {
                    ExitedTask::Watchdog(result) => {
                        self.watchdog.take();
                        NfqueueRuntimeFatal::Watchdog(match result {
                            Ok(()) => "completed".to_string(),
                            Err(error) => error.to_string(),
                        })
                    }
                    ExitedTask::IngestActor(result) => {
                        self.ingest_worker.take();
                        NfqueueRuntimeFatal::IngestActor(match result {
                            Ok(()) => "completed".to_string(),
                            Err(error) => error.to_string(),
                        })
                    }
                    ExitedTask::StatsSampler(result) => {
                        self.stats_sampler.take();
                        NfqueueRuntimeFatal::StatsSampler(match result {
                            Ok(()) => "completed".to_string(),
                            Err(error) => error.to_string(),
                        })
                    }
                };
                return NfqueueRuntimeEvent::Fatal(anyhow::Error::new(fatal));
            }
            match ebpf.read().await.udp_decision_sequence_status() {
                Ok(status) if status.exhausted() => {
                    self.stats.record_udp_nfqueue_token_exhaustion();
                    return NfqueueRuntimeEvent::TokenExhausted;
                }
                Ok(_) => {}
                Err(error) => {
                    return NfqueueRuntimeEvent::Fatal(anyhow::Error::new(
                        NfqueueRuntimeFatal::TokenBackstop(error.to_string()),
                    ));
                }
            }
        }
    }
    pub(super) async fn check_startup_health(&mut self) -> Result<(), NfqueueRuntimeFatal> {
        match self.listener_fatal.try_recv() {
            Ok(error) => return Err(NfqueueRuntimeFatal::Listener(error)),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                return Err(NfqueueRuntimeFatal::ListenerChannelClosed);
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
        }
        match self.pending_fatal.try_recv() {
            Ok(error) => return Err(NfqueueRuntimeFatal::Pending(error)),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return Err(NfqueueRuntimeFatal::PendingChannelClosed);
            }
            Err(mpsc::error::TryRecvError::Empty) => {}
        }
        if self
            .watchdog
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            return Err(NfqueueRuntimeFatal::Watchdog("completed".to_string()));
        }
        if self
            .stats_sampler
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            return Err(NfqueueRuntimeFatal::StatsSampler("completed".to_string()));
        }
        if self
            .ingest_worker
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            return Err(NfqueueRuntimeFatal::IngestActor("completed".to_string()));
        }
        Ok(())
    }
    pub(super) async fn begin_pending_drain(&self) {
        self.pending.cancel_all().await;
        self.pending.wait_empty().await;
    }

    async fn stop_observers(&mut self) -> anyhow::Result<()> {
        let _ = self.stop.send(true);
        if let Some(stats_sampler) = self.stats_sampler.take() {
            stats_sampler
                .await
                .map_err(|error| anyhow::anyhow!("join NFQUEUE stats sampler: {error}"))?;
        }
        if let Some(watchdog) = self.watchdog.take() {
            watchdog
                .await
                .map_err(|error| anyhow::anyhow!("join NFQUEUE watchdog: {error}"))?;
        }
        Ok(())
    }

    pub(super) async fn finish_pending_drain(&mut self) -> anyhow::Result<()> {
        let observer_result = self.stop_observers().await;
        if let Some(worker) = self.ingest_worker.take() {
            worker
                .await
                .map_err(|error| anyhow::anyhow!("join NFQUEUE ingest actor: {error}"))?;
        }
        self.pending.cancel_all().await;
        self.pending.wait_empty().await;
        observer_result
    }

    pub(super) async fn shutdown_service(&mut self) -> anyhow::Result<()> {
        let observer_result = self.stop_observers().await;
        let service_result = async {
            let service = self
                .service
                .take()
                .ok_or_else(|| anyhow::anyhow!("NFQUEUE service already stopped"))?;
            tokio::task::spawn_blocking(move || service.shutdown())
                .await
                .map_err(|error| anyhow::anyhow!("join NFQUEUE shutdown: {error}"))?
                .map_err(|error| anyhow::anyhow!("shutdown NFQUEUE: {error}"))
        }
        .await;
        observer_result?;
        service_result
    }
    async fn hard_rebind_service(&mut self) -> anyhow::Result<()> {
        self.check_startup_health()
            .await
            .map_err(anyhow::Error::new)?;
        let service = self
            .service
            .take()
            .ok_or_else(|| anyhow::anyhow!("NFQUEUE service already stopped"))?;
        let (service, listener_fatal) = tokio::task::spawn_blocking(move || service.rebind())
            .await
            .map_err(|error| anyhow::anyhow!("join NFQUEUE hard rebind: {error}"))?
            .map_err(|error| anyhow::anyhow!("hard rebind NFQUEUE: {error}"))?;
        let old_fatal = self.listener_fatal.try_recv().ok();
        self.service = Some(service);
        self.listener_fatal = listener_fatal;
        if let Some(error) = old_fatal {
            return Err(anyhow::Error::new(NfqueueRuntimeFatal::Listener(error)));
        }
        self.check_startup_health()
            .await
            .map_err(anyhow::Error::new)
    }

    pub(super) fn take_shutdown_fatal(&mut self) -> Option<NfqueueRuntimeFatal> {
        if let Ok(error) = self.listener_fatal.try_recv() {
            return Some(NfqueueRuntimeFatal::Listener(error));
        }
        if let Ok(error) = self.pending_fatal.try_recv() {
            return Some(NfqueueRuntimeFatal::Pending(error));
        }
        None
    }

    fn defer_token_retry(&mut self) {
        self.token_backstop.reset_after(self.token_retry.failed());
    }

    fn reset_token_retry(&mut self) {
        self.token_retry.reset();
        self.token_backstop.reset_after(nfqueue::WATCHDOG_INTERVAL);
    }
}
#[cfg(feature = "ebpf")]
pub(super) async fn wait_nfqueue_event(
    runtime: &mut Option<NfqueueRuntime>,
    ebpf: &Arc<RwLock<Box<dyn EbpfBackend>>>,
) -> NfqueueRuntimeEvent {
    let Some(runtime) = runtime.as_mut() else {
        return std::future::pending::<NfqueueRuntimeEvent>().await;
    };
    runtime.next_event(ebpf).await
}

impl ControlPlane {
    #[cfg(feature = "ebpf")]
    pub(super) async fn rotate_udp_decision_generation(&self) -> anyhow::Result<bool> {
        let mut backend = self.ebpf.write().await;
        backend
            .verify_udp_decision_sequence()
            .map_err(|error| anyhow::anyhow!("verify UDP decision sequence: {error}"))?;
        let status = backend.udp_decision_sequence_status()?;
        if !status.exhausted() {
            return Ok(true);
        }
        backend.quiesce_udp_staging()?;
        for offset in 1..=UDP_DECISION_GENERATION_MASK + 1 {
            let generation = (status.generation + offset) & UDP_DECISION_GENERATION_MASK;
            if backend.reset_udp_decision_sequence(generation)? {
                self.stats.record_udp_nfqueue_token_rollover();
                info!(
                    generation,
                    "rotated exhausted UDP decision token generation"
                );
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(feature = "ebpf")]
    pub(super) async fn recover_nfqueue_token_exhaustion(
        &self,
        runtime: &mut NfqueueRuntime,
    ) -> anyhow::Result<()> {
        if runtime.sequence_ready {
            let flags = self
                .datapath_flags
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("datapath flags writer is not initialized"))?;
            flags.fence_nfqueue().await?;
            runtime.sequence_ready = false;
            runtime.pending.cancel_all().await;
            runtime.pending.wait_empty().await;
            runtime.hard_rebind_service().await?;
            runtime.pending.cancel_all().await;
            runtime.pending.wait_empty().await;
        }
        if !self.rotate_udp_decision_generation().await? {
            runtime.defer_token_retry();
            warn!("all UDP decision token generations remain live; NFQUEUE staging stays fenced");
            return Ok(());
        }
        runtime
            .check_startup_health()
            .await
            .map_err(anyhow::Error::new)?;
        runtime.pending.open_admission();
        self.datapath_flags
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("datapath flags writer is not initialized"))?
            .reopen_nfqueue()
            .await?;
        runtime.sequence_ready = true;
        runtime.reset_token_retry();
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    pub(super) async fn start_nfqueue_runtime(
        &mut self,
        enabled: bool,
        sequence_ready: bool,
    ) -> anyhow::Result<Option<NfqueueRuntime>> {
        if !enabled {
            return Ok(None);
        }

        if !sequence_ready {
            self.stats.record_udp_nfqueue_token_exhaustion();
            warn!("all UDP decision token generations are live; starting with NFQUEUE fenced");
        }

        let (pending, pending_fatal) = nfqueue::PendingUdpVerdicts::new(
            Arc::clone(&self.ebpf),
            Arc::clone(&self.udp_pool),
            Arc::clone(&self.stats),
        );
        let pending = Arc::new(pending);
        self.pending_udp_verdicts = Some(Arc::clone(&pending));

        type IngestRequest = (honk_nfqueue::QueuedPacket, honk_nfqueue::VerdictGuard);
        let (ingest_tx, mut ingest_rx) = mpsc::channel::<IngestRequest>(NFQUEUE_INGEST_QUEUE_LEN);
        let slow_limit = Arc::clone(&self.udp_concurrency_limit);
        let actor_queue = Arc::new(NfqueueActorQueue::new(Arc::clone(&self.stats), slow_limit));
        let callback_pending = Arc::clone(&pending);
        let callback_queue = Arc::clone(&actor_queue);
        let callback: honk_nfqueue::PacketCallback = Arc::new(move |packet, guard| {
            let Ok(slot) = ingest_tx.try_reserve() else {
                callback_pending.reject_actor_queue(packet, guard);
                return;
            };
            if !callback_queue.try_enqueue(packet.received_at, packet.payload.len()) {
                callback_pending.reject_actor_queue(packet, guard);
                return;
            }
            slot.send((packet, guard));
        });
        let (service, listener_fatal) = match honk_nfqueue::NfqueueService::start(callback) {
            Ok(runtime) => runtime,
            Err(error) => {
                self.pending_udp_verdicts = None;
                return Err(anyhow::anyhow!("start UDP NFQUEUE service: {error}"));
            }
        };
        let actor_pending = Arc::clone(&pending);
        let initializer = self.spawn_handle();
        let drain = Arc::clone(&self.drain_tracker);
        let ingest_queue = Arc::clone(&actor_queue);
        let ingest_worker = tokio::spawn(async move {
            while let Some((packet, guard)) = ingest_rx.recv().await {
                let permit = ingest_queue.dequeue(packet.payload.len());
                let nfqueue::NfqueueIngest::Initialize { lease, identity } =
                    actor_pending.ingest_wait(packet, guard, permit).await
                else {
                    continue;
                };
                let initializer = initializer.clone();
                let pending = Arc::clone(&actor_pending);
                let drain = Arc::clone(&drain);
                tokio::spawn(async move {
                    let _guard = ConnectionGuard::new(drain);
                    match std::panic::AssertUnwindSafe(initializer.serve_udp_connection(lease))
                        .catch_unwind()
                        .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            warn!(%error, "NFQUEUE UDP initializer failed");
                            let _ = pending.cancel(identity).await;
                        }
                        Err(_) => {
                            error!("NFQUEUE UDP initializer panicked");
                            let _ = pending.cancel(identity).await;
                        }
                    }
                });
            }
        });
        let (stop, stop_receiver) = tokio::sync::watch::channel(false);
        let watchdog = tokio::spawn(Arc::clone(&pending).run_watchdog(stop_receiver));
        let stats_reader = service.stats_reader();
        let sampler_stats = Arc::clone(&self.stats);
        let sampler_queue = Arc::clone(&actor_queue);
        let mut sampler_stop = stop.subscribe();
        let stats_sampler = tokio::spawn(async move {
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now() + NFQUEUE_STATS_INTERVAL,
                NFQUEUE_STATS_INTERVAL,
            );
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut unavailable = false;
            loop {
                tokio::select! {
                    changed = sampler_stop.changed() => {
                        if changed.is_err() || *sampler_stop.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        sampler_queue.sample();
                        sampler_stats.update_udp_nfqueue_local_stats(stats_reader.local_stats());
                        match stats_reader.stats().await {
                            Ok(sample) => {
                                if unavailable {
                                    info!("NFQUEUE kernel statistics are available again");
                                }
                                unavailable = false;
                                sampler_stats.update_udp_nfqueue_service_stats(sample);
                            }
                            Err(error) => {
                                sampler_stats.record_udp_nfqueue_service_stats_error();
                                if !unavailable {
                                    warn!(%error, "NFQUEUE kernel statistics are unavailable");
                                }
                                unavailable = true;
                            }
                        }
                    }
                }
            }
        });
        let mut token_retry = NfqueueTokenRetryBackoff::default();
        let first_token_check = if sequence_ready {
            nfqueue::WATCHDOG_INTERVAL
        } else {
            token_retry.failed()
        };
        let mut token_backstop = tokio::time::interval_at(
            tokio::time::Instant::now() + first_token_check,
            nfqueue::WATCHDOG_INTERVAL,
        );
        token_backstop.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Ok(Some(NfqueueRuntime {
            service: Some(service),
            listener_fatal,
            pending_fatal,
            stats: Arc::clone(&self.stats),
            pending,
            stop,
            watchdog: Some(watchdog),
            ingest_worker: Some(ingest_worker),
            stats_sampler: Some(stats_sampler),
            token_backstop,
            token_retry,
            sequence_ready,
        }))
    }
}
