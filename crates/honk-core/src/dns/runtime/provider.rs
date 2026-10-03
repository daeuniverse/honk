use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::{Mutex, MutexGuard, RwLock, RwLockWriteGuard};
use tokio::task::JoinSet;

use super::{
    DnsPauseError, DnsRuntime, DnsUnavailable, MAX_RETIRED_RUNTIMES, RETIREMENT_DEADLINE,
    RuntimeGeneration, RuntimeLease, RuntimeState,
};

struct ProviderState {
    current: Arc<DnsRuntime>,
    retired: VecDeque<Arc<RetiredRuntime>>,
    paused: bool,
    pausing: bool,
    stopped: bool,
    failure: Option<DnsPauseError>,
}

/// Owns a retired generation's outbound shutdown after its supervisor has
/// released the runtime, so reloads do not pin old forwarders and routers.
struct RetiredRuntime {
    generation: RuntimeGeneration,
    outbound: Option<Arc<honk_outbound::runtime::OutboundRuntimeRegistry>>,
    cleanup_failed: AtomicBool,
    runtime: Mutex<Option<Arc<DnsRuntime>>>,
}

impl RetiredRuntime {
    fn new(runtime: Arc<DnsRuntime>) -> Arc<Self> {
        Arc::new(Self {
            generation: runtime.generation(),
            outbound: runtime.parts.outbound_runtime.clone(),
            cleanup_failed: AtomicBool::new(false),
            runtime: Mutex::new(Some(runtime)),
        })
    }

    fn runtime(&self) -> Option<Arc<DnsRuntime>> {
        self.runtime.lock().clone()
    }

    fn release(&self, cleanup: Result<(), DnsPauseError>) {
        self.cleanup_failed
            .store(cleanup.is_err(), Ordering::Release);
        // Run the runtime destructors outside the entry lock.
        let released = self.runtime.lock().take();
        drop(released);
    }

    async fn force_shutdown_outbound(&self) -> Result<(), DnsPauseError> {
        if let Some(outbound) = &self.outbound {
            outbound.shutdown().await;
        }
        match self.runtime() {
            Some(runtime) => runtime.cleanup_result(),
            None if self.cleanup_failed.load(Ordering::Acquire)
                || self
                    .outbound
                    .as_ref()
                    .is_some_and(|outbound| outbound.tasks_failed()) =>
            {
                Err(DnsPauseError::TaskFailed)
            }
            None => Ok(()),
        }
    }
}

pub(crate) struct DnsServiceProvider {
    state: RwLock<ProviderState>,
    supervisors: Mutex<JoinSet<Result<(), DnsPauseError>>>,
    pauses: Mutex<JoinSet<Result<(), DnsPauseError>>>,
    pause_waiter: tokio::sync::Mutex<()>,
    deadline: Duration,
}

pub(crate) struct PreparedPublication<'a> {
    state: RwLockWriteGuard<'a, ProviderState>,
    supervisors: MutexGuard<'a, JoinSet<Result<(), DnsPauseError>>>,
    replacement: Arc<DnsRuntime>,
    deadline: Duration,
}

impl PreparedPublication<'_> {
    pub(crate) fn commit(mut self) {
        #[cfg(feature = "native-api")]
        self.replacement.lifecycle_enabled.store(
            self.state
                .current
                .lifecycle_enabled
                .load(std::sync::atomic::Ordering::Acquire),
            std::sync::atomic::Ordering::Release,
        );
        while let Some(result) = self.supervisors.try_join_next() {
            if !matches!(result, Ok(Ok(()))) {
                self.state.failure = Some(DnsPauseError::TaskFailed);
            }
        }
        let retired = std::mem::replace(&mut self.state.current, self.replacement);
        let needs_retirement =
            retired.state() != RuntimeState::Closed || retired.lease_count() != 0;
        retired.start_draining();
        if self.state.paused {
            retired.request_cancellation();
        }
        let entry = RetiredRuntime::new(Arc::clone(&retired));
        self.state.retired.push_back(Arc::clone(&entry));
        if self.state.retired.len() > MAX_RETIRED_RUNTIMES
            && let Some(oldest) = self.state.retired.pop_front()
        {
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::RuntimeForcedClose);
            tracing::warn!(
                generation = oldest.generation.get(),
                reason = "retired_runtime_limit",
                "DNS runtime forced close"
            );
            let runtime = oldest.runtime();
            if let Some(runtime) = &runtime {
                runtime.request_cancellation();
            }
            if !self.state.paused
                || runtime.is_some_and(|runtime| {
                    runtime.state() != RuntimeState::Closed || runtime.lease_count() != 0
                })
            {
                self.supervisors
                    .spawn(async move { oldest.force_shutdown_outbound().await });
            }
        }
        if needs_retirement {
            let deadline = self.deadline;
            self.supervisors.spawn(async move {
                Arc::clone(&retired).retire(deadline).await;
                // Keep even cap-evicted generations owned until their last caller exits.
                retired.wait_for_zero_leases().await;
                let cleanup = retired.cleanup_result();
                entry.release(cleanup);
                cleanup
            });
        } else {
            entry.release(retired.cleanup_result());
        }
    }
}

impl DnsServiceProvider {
    pub(crate) fn new(current: Arc<DnsRuntime>) -> Self {
        Self::with_deadline(current, RETIREMENT_DEADLINE)
    }

    pub(crate) fn with_deadline(current: Arc<DnsRuntime>, deadline: Duration) -> Self {
        Self {
            state: RwLock::new(ProviderState {
                current,
                retired: VecDeque::new(),
                paused: false,
                pausing: false,
                stopped: false,
                failure: None,
            }),
            supervisors: Mutex::new(JoinSet::new()),
            pauses: Mutex::new(JoinSet::new()),
            pause_waiter: tokio::sync::Mutex::new(()),
            deadline,
        }
    }

    pub(crate) fn try_acquire(&self) -> Result<RuntimeLease, DnsUnavailable> {
        let state = self.state.read();
        if state.paused || state.stopped || state.current.state() != RuntimeState::Active {
            return Err(DnsUnavailable {
                reason: honk_outbound::proxy::PacketRejection::Cancelled,
            });
        }
        Ok(DnsRuntime::acquire(&state.current))
    }

    pub(crate) fn current(&self) -> Arc<DnsRuntime> {
        Arc::clone(&self.state.read().current)
    }

    #[cfg(test)]
    pub(crate) fn publish(&self, replacement: Arc<DnsRuntime>) {
        self.prepare_publication(replacement).commit();
    }

    pub(crate) fn prepare_publication(
        &self,
        replacement: Arc<DnsRuntime>,
    ) -> PreparedPublication<'_> {
        PreparedPublication {
            state: self.state.write(),
            supervisors: self.supervisors.lock(),
            replacement,
            deadline: self.deadline,
        }
    }

    pub(crate) fn current_generation(&self) -> RuntimeGeneration {
        self.state.read().current.generation()
    }

    #[cfg(test)]
    pub(crate) fn retired_count(&self) -> usize {
        self.state.read().retired.len()
    }

    #[cfg(test)]
    pub(crate) fn supervisor_count(&self) -> usize {
        self.supervisors.lock().len()
    }
    #[cfg(feature = "native-api")]
    pub(crate) fn enable_lifecycle(&self) {
        self.state
            .write()
            .current
            .lifecycle_enabled
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn begin_pause(&self) {
        let mut state = self.state.write();
        state.paused = true;
        if state.pausing {
            return;
        }
        state.pausing = true;
        let current = Arc::clone(&state.current);
        let retired = state.retired.iter().cloned().collect::<Vec<_>>();
        current.request_cancellation();
        for runtime in retired.iter().filter_map(|entry| entry.runtime()) {
            runtime.request_cancellation();
        }
        let mut supervisors = std::mem::take(&mut *self.supervisors.lock());
        if state.current.state() == RuntimeState::Active {
            state.current.start_draining();
            let current = Arc::clone(&state.current);
            supervisors.spawn(async move {
                Arc::clone(&current).retire(Duration::ZERO).await;
                current.wait_for_zero_leases().await;
                current.cleanup_result()
            });
        }
        let deadline = tokio::time::Instant::now() + self.deadline;
        // This task, not the caller's wait future, owns every asynchronous close.
        self.pauses.lock().spawn(async move {
            let mut failed = false;
            while let Some(result) = supervisors.join_next().await {
                failed |= !matches!(result, Ok(Ok(())));
            }
            current.wait_for_zero_leases().await;
            failed |= current.force_shutdown_outbound().await.is_err();
            for entry in retired {
                if let Some(runtime) = entry.runtime() {
                    runtime.wait_for_zero_leases().await;
                }
                failed |= entry.force_shutdown_outbound().await.is_err();
            }
            if failed {
                Err(DnsPauseError::TaskFailed)
            } else if tokio::time::Instant::now() >= deadline {
                Err(DnsPauseError::Deadline)
            } else {
                Ok(())
            }
        });
    }

    pub(crate) async fn finish_pause(&self) -> Result<(), DnsPauseError> {
        let _waiter = self.pause_waiter.lock().await;
        if !self.state.read().paused {
            return Err(DnsPauseError::NotReady);
        }
        while let Some(result) =
            std::future::poll_fn(|cx| self.pauses.lock().poll_join_next(cx)).await
        {
            let failure = match result {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error),
                Err(_) => Some(DnsPauseError::TaskFailed),
            };
            if let Some(error) = failure {
                self.state.write().failure = Some(error);
            }
        }
        let mut state = self.state.write();
        state.pausing = false;
        state.failure.map_or(Ok(()), Err)
    }

    pub(crate) async fn shutdown(&self) {
        self.state.write().stopped = true;
        self.begin_pause();
        if let Err(error) = self.finish_pause().await {
            tracing::error!(%error, "DNS runtime provider cleanup failed");
        }
    }
}
