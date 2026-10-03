use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError};

use super::forwarder::DnsForwarder;

pub(crate) const RETIREMENT_DEADLINE: Duration = Duration::from_secs(30);
pub(crate) const MAX_RETIRED_RUNTIMES: usize = 4;
const MAX_CONCURRENT_QUERIES: usize = 2048;

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("DNS network admission is unavailable")]
pub(crate) struct DnsUnavailable {
    #[source]
    reason: honk_outbound::proxy::PacketRejection,
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub(crate) enum DnsPauseError {
    #[error("DNS cleanup exceeded its deadline")]
    Deadline,
    #[error("DNS runtime cleanup task failed")]
    TaskFailed,
    #[error("DNS runtime is not paused")]
    NotReady,
}
mod provider;
pub(crate) use provider::DnsServiceProvider;
mod resources {
    use async_trait::async_trait;

    use crate::dns::upstream_pool::UpstreamPool;

    #[async_trait]
    pub(crate) trait RuntimeTransport: Send + Sync {
        async fn close(&self);
        fn tasks_failed(&self) -> bool {
            false
        }
        fn reap_idle_resources(&self) -> usize {
            0
        }
    }

    #[async_trait]
    impl RuntimeTransport for UpstreamPool {
        async fn close(&self) {
            UpstreamPool::close(self).await;
        }

        fn tasks_failed(&self) -> bool {
            UpstreamPool::tasks_failed(self)
        }

        fn reap_idle_resources(&self) -> usize {
            UpstreamPool::reap_idle_resources(self)
        }
    }
}
pub(crate) use resources::RuntimeTransport;
mod state {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub(crate) struct RuntimeGeneration(u64);

    impl RuntimeGeneration {
        pub(crate) const fn new(value: u64) -> Self {
            Self(value)
        }

        pub(crate) const fn get(self) -> u64 {
            self.0
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub(crate) enum RuntimeState {
        Active,
        Draining,
        Closing,
        Closed,
    }

    impl RuntimeState {
        pub(super) const fn from_raw(value: u8) -> Self {
            match value {
                0 => Self::Active,
                1 => Self::Draining,
                2 => Self::Closing,
                _ => Self::Closed,
            }
        }
    }
}
pub(crate) use state::{RuntimeGeneration, RuntimeState};
#[cfg(test)]
mod tests;

pub(crate) use super::projection::RoutingProjectionSnapshot;

pub(crate) struct DnsRuntimeParts {
    pub(crate) generation: RuntimeGeneration,
    pub(crate) udp_query_limit: usize,
    pub(crate) forwarder: Arc<DnsForwarder>,
    pub(crate) routing_projection: Arc<RoutingProjectionSnapshot>,
    /// Defers reusable-state retirement of the traffic registry until this
    /// generation drains. DNS transports own a separate registry so admitted
    /// DNS dials can outlive traffic admission.
    pub(crate) outbound_runtime: Option<Arc<honk_outbound::runtime::OutboundRuntimeRegistry>>,
    pub(crate) transport: Arc<dyn RuntimeTransport>,
}

pub(crate) struct DnsRuntime {
    parts: DnsRuntimeParts,
    query_limit: Arc<Semaphore>,
    udp_query_limit: Arc<Semaphore>,
    state: AtomicU8,
    leases: AtomicUsize,
    lease_released: Notify,
    cancellation_requested: AtomicBool,
    cancellation: Notify,
    closed: Notify,
    cleanup_failed: AtomicBool,
    #[cfg(feature = "native-api")]
    lifecycle_enabled: AtomicBool,
    #[cfg(feature = "native-api")]
    network_tasks: std::sync::LazyLock<Arc<honk_outbound::runtime::TaskOwner>>,
    #[cfg(feature = "native-api")]
    flow_catalog: std::sync::OnceLock<Arc<crate::observe::catalog::CatalogIdentity>>,
}

impl DnsRuntime {
    pub(crate) fn new(parts: DnsRuntimeParts) -> Arc<Self> {
        Arc::new(Self {
            query_limit: Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES)),
            udp_query_limit: Arc::new(Semaphore::new(parts.udp_query_limit)),
            parts,
            state: AtomicU8::new(RuntimeState::Active as u8),
            leases: AtomicUsize::new(0),
            lease_released: Notify::new(),
            cancellation_requested: AtomicBool::new(false),
            cancellation: Notify::new(),
            closed: Notify::new(),
            cleanup_failed: AtomicBool::new(false),
            #[cfg(feature = "native-api")]
            lifecycle_enabled: AtomicBool::new(false),
            #[cfg(feature = "native-api")]
            network_tasks: std::sync::LazyLock::new(|| {
                Arc::new(honk_outbound::runtime::TaskOwner::production())
            }),
            #[cfg(feature = "native-api")]
            flow_catalog: std::sync::OnceLock::new(),
        })
    }

    pub(crate) const fn generation(&self) -> RuntimeGeneration {
        self.parts.generation
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn bind_flow_catalog(
        &self,
        identity: Arc<crate::observe::catalog::CatalogIdentity>,
    ) {
        assert!(
            self.flow_catalog.set(identity).is_ok(),
            "DNS catalog must be bound before publication exactly once"
        );
    }

    pub(crate) fn state(&self) -> RuntimeState {
        RuntimeState::from_raw(self.state.load(Ordering::Acquire))
    }

    pub(crate) fn lease_count(&self) -> usize {
        self.leases.load(Ordering::Acquire)
    }

    pub(crate) fn try_acquire_query(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        Arc::clone(&self.query_limit).try_acquire_owned()
    }

    pub(crate) fn try_acquire_udp_query(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        Arc::clone(&self.udp_query_limit).try_acquire_owned()
    }

    pub(crate) fn forwarder(&self) -> &Arc<DnsForwarder> {
        &self.parts.forwarder
    }

    pub(crate) fn routing_projection(&self) -> &Arc<RoutingProjectionSnapshot> {
        &self.parts.routing_projection
    }

    pub(crate) fn reap_idle_resources(&self) -> usize {
        self.parts.transport.reap_idle_resources()
    }

    pub(crate) fn cache(&self) -> Arc<tokio::sync::Mutex<super::cache::DnsCache>> {
        self.parts.forwarder.cache()
    }

    fn acquire(runtime: &Arc<Self>) -> RuntimeLease {
        runtime.leases.fetch_add(1, Ordering::AcqRel);
        RuntimeLease {
            runtime: Arc::clone(runtime),
        }
    }

    fn start_draining(&self) {
        let _ = self.state.compare_exchange(
            RuntimeState::Active as u8,
            RuntimeState::Draining as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn request_cancellation(&self) {
        self.cancellation_requested.store(true, Ordering::Release);
        self.parts.forwarder.request_background_shutdown();
        #[cfg(feature = "native-api")]
        if let Some(owner) = std::sync::LazyLock::get(&self.network_tasks) {
            owner.abort();
        }
        self.cancellation.notify_waiters();
    }

    async fn cancelled(&self) {
        let cancelled = self.cancellation.notified();
        if !self.cancellation_requested.load(Ordering::Acquire) {
            cancelled.await;
        }
    }

    #[cfg(feature = "native-api")]
    fn network_tasks(&self) -> &Arc<honk_outbound::runtime::TaskOwner> {
        let owner = std::sync::LazyLock::force(&self.network_tasks);
        // Cancellation can race the first lookup scope's lazy initialization.
        if self.cancellation_requested.load(Ordering::Acquire) {
            owner.abort();
        }
        owner
    }

    pub(crate) async fn retire(self: Arc<Self>, deadline: Duration) {
        self.start_draining();
        if self.lease_count() != 0 && !self.cancellation_requested.load(Ordering::Acquire) {
            let timed_out = tokio::select! {
                () = Self::wait_for_zero_leases(&self) => false,
                () = tokio::time::sleep(deadline) => true,
                () = self.cancelled() => false,
            };
            if timed_out {
                crate::stats::record_dns_event(
                    crate::stats::DnsStatEvent::RuntimeRetirementTimeout,
                );
                tracing::warn!(
                    generation = self.generation().get(),
                    active_leases = self.lease_count(),
                    "DNS runtime retirement timed out"
                );
            }
        }
        if self
            .state
            .compare_exchange(
                RuntimeState::Draining as u8,
                RuntimeState::Closing as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.wait_closed().await;
            return;
        }
        self.request_cancellation();
        if !self.parts.forwarder.shutdown_background_tasks().await {
            self.cleanup_failed.store(true, Ordering::Release);
        }
        self.parts.transport.close().await;
        #[cfg(feature = "native-api")]
        if let Some(owner) = std::sync::LazyLock::get(&self.network_tasks) {
            owner.close().await;
        }
        if let Some(runtime) = &self.parts.outbound_runtime {
            runtime.retire_reusable_state().await;
        }
        self.state
            .store(RuntimeState::Closed as u8, Ordering::Release);
        self.closed.notify_waiters();
    }

    async fn wait_for_zero_leases(&self) {
        loop {
            let released = self.lease_released.notified();
            if self.lease_count() == 0 {
                return;
            }
            released.await;
        }
    }

    pub(crate) async fn wait_closed(&self) {
        loop {
            let closed = self.closed.notified();
            if self.state() == RuntimeState::Closed {
                return;
            }
            closed.await;
        }
    }

    fn cleanup_result(&self) -> Result<(), DnsPauseError> {
        #[cfg(feature = "native-api")]
        if std::sync::LazyLock::get(&self.network_tasks).is_some_and(|owner| owner.has_failed()) {
            return Err(DnsPauseError::TaskFailed);
        }
        if self.cleanup_failed.load(Ordering::Acquire)
            || self.parts.transport.tasks_failed()
            || self
                .parts
                .outbound_runtime
                .as_ref()
                .is_some_and(|runtime| runtime.tasks_failed())
        {
            Err(DnsPauseError::TaskFailed)
        } else {
            Ok(())
        }
    }

    async fn force_shutdown_outbound(&self) -> Result<(), DnsPauseError> {
        if let Some(runtime) = &self.parts.outbound_runtime {
            runtime.shutdown().await;
        }
        self.cleanup_result()
    }
}

pub(crate) struct RuntimeLease {
    runtime: Arc<DnsRuntime>,
}

#[derive(Debug, thiserror::Error)]
#[error("DNS runtime generation {generation} retired")]
pub(crate) struct RuntimeCancelled {
    generation: u64,
    #[source]
    reason: honk_outbound::proxy::PacketRejection,
}

impl RuntimeLease {
    pub(crate) fn runtime(&self) -> &DnsRuntime {
        &self.runtime
    }

    pub(crate) async fn cancelled(&self) -> RuntimeCancelled {
        self.runtime.cancelled().await;
        RuntimeCancelled {
            generation: self.runtime.generation().get(),
            reason: honk_outbound::proxy::PacketRejection::Cancelled,
        }
    }

    pub(crate) async fn run<T>(
        &self,
        operation: std::pin::Pin<&mut impl Future<Output = T>>,
    ) -> Result<T, RuntimeCancelled> {
        #[cfg(feature = "native-api")]
        let observer = honk_outbound::runtime::flow_observation::current().map(|observer| {
            let mut context = observer.context();
            context.generation = self.runtime.generation().get();
            observer.with_context(context)
        });
        #[cfg(feature = "native-api")]
        let operation = async {
            match observer {
                Some(observer) => {
                    crate::observe::flows::dns::scope_catalog(
                        self.runtime.flow_catalog.get().cloned(),
                        observer.scope(operation),
                    )
                    .await
                }
                None => operation.await,
            }
        };
        #[cfg(feature = "native-api")]
        let operation = std::pin::pin!(operation);
        #[cfg(feature = "native-api")]
        let operation = async {
            if self.runtime.lifecycle_enabled.load(Ordering::Acquire) {
                self.runtime
                    .network_tasks()
                    .task_scope()
                    .scope_owned(operation)
                    .await
            } else {
                operation.await
            }
        };
        tokio::select! {
            biased;
            error = self.cancelled() => Err(error),
            result = operation => Ok(result),
        }
    }

    pub(crate) async fn run_reply<T>(
        &self,
        operation: impl Future<Output = T>,
    ) -> Result<T, RuntimeCancelled> {
        tokio::select! {
            biased;
            result = operation => Ok(result),
            error = self.cancelled() => Err(error),
        }
    }
}

impl Drop for RuntimeLease {
    fn drop(&mut self) {
        if self.runtime.leases.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.runtime.lease_released.notify_waiters();
        }
    }
}
