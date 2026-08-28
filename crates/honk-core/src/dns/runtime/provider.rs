use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, MutexGuard, RwLock, RwLockWriteGuard};
use tokio::task::JoinSet;

use super::{
    DnsRuntime, MAX_RETIRED_RUNTIMES, RETIREMENT_DEADLINE, RuntimeGeneration, RuntimeLease,
    RuntimeState,
};

struct ProviderState {
    current: Arc<DnsRuntime>,
    retired: VecDeque<Arc<DnsRuntime>>,
}

pub(crate) struct DnsServiceProvider {
    state: RwLock<ProviderState>,
    supervisors: Mutex<JoinSet<()>>,
    deadline: Duration,
}

pub(crate) struct PreparedPublication<'a> {
    state: RwLockWriteGuard<'a, ProviderState>,
    supervisors: MutexGuard<'a, JoinSet<()>>,
    replacement: Arc<DnsRuntime>,
    deadline: Duration,
}

impl PreparedPublication<'_> {
    pub(crate) fn commit(mut self) {
        while self.supervisors.try_join_next().is_some() {}
        let retired = std::mem::replace(&mut self.state.current, self.replacement);
        retired.start_draining();
        self.state.retired.push_back(Arc::clone(&retired));
        if self.state.retired.len() > MAX_RETIRED_RUNTIMES
            && let Some(oldest) = self.state.retired.pop_front()
        {
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::RuntimeForcedClose);
            tracing::warn!(
                generation = oldest.generation().get(),
                reason = "retired_runtime_limit",
                "DNS runtime forced close"
            );
            oldest.request_cancellation();
            // The evicted runtime is no longer reachable from `state.retired`.
            // Publication is synchronous under the provider guards, so its
            // asynchronous outbound shutdown remains owned by the same supervisor
            // set as runtime retirement and is joined during provider shutdown.
            self.supervisors
                .spawn(async move { oldest.force_shutdown_outbound().await });
        }
        let deadline = self.deadline;
        self.supervisors
            .spawn(async move { retired.retire(deadline).await });
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
            }),
            supervisors: Mutex::new(JoinSet::new()),
            deadline,
        }
    }

    pub(crate) fn acquire(&self) -> RuntimeLease {
        let state = self.state.read();
        DnsRuntime::acquire(&state.current)
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

    pub(crate) async fn shutdown(&self) {
        let runtimes = {
            let state = self.state.read();
            std::iter::once(Arc::clone(&state.current))
                .chain(state.retired.iter().cloned())
                .collect::<Vec<_>>()
        };
        for runtime in &runtimes {
            runtime.request_cancellation();
            runtime.start_draining();
            if runtime.state() != RuntimeState::Closed {
                let runtime_for_close = Arc::clone(runtime);
                self.supervisors
                    .lock()
                    .spawn(async move { runtime_for_close.retire(Duration::ZERO).await });
            }
        }
        let mut supervisors = {
            let mut guard = self.supervisors.lock();
            std::mem::take(&mut *guard)
        };
        while supervisors.join_next().await.is_some() {}
        for runtime in runtimes {
            runtime.force_shutdown_outbound().await;
        }
    }
}
