use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError};

use super::forwarder::DnsForwarder;

pub(crate) const RETIREMENT_DEADLINE: Duration = Duration::from_secs(30);
pub(crate) const MAX_RETIRED_RUNTIMES: usize = 4;
const MAX_CONCURRENT_QUERIES: usize = 2048;

mod provider;
pub(crate) use provider::DnsServiceProvider;
mod resources {
    use async_trait::async_trait;

    use crate::dns::upstream_pool::UpstreamPool;

    #[async_trait]
    pub(crate) trait RuntimeTransport: Send + Sync {
        async fn close(&self);
        fn reap_tls_connectors(&self, _now: std::time::Instant) -> usize {
            0
        }
    }

    #[async_trait]
    impl RuntimeTransport for UpstreamPool {
        async fn close(&self) {
            UpstreamPool::close(self).await;
        }

        fn reap_tls_connectors(&self, now: std::time::Instant) -> usize {
            UpstreamPool::reap_tls_connectors(self, now)
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
mod prefetch_tests;
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
        })
    }

    pub(crate) const fn generation(&self) -> RuntimeGeneration {
        self.parts.generation
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

    pub(crate) fn reap_tls_connectors(&self, now: std::time::Instant) -> usize {
        self.parts.transport.reap_tls_connectors(now)
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
        self.cancellation.notify_waiters();
    }

    async fn cancelled(&self) {
        let cancelled = self.cancellation.notified();
        if !self.cancellation_requested.load(Ordering::Acquire) {
            cancelled.await;
        }
    }

    async fn retire(self: Arc<Self>, deadline: Duration) {
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
        self.parts.forwarder.shutdown_background_tasks().await;
        self.parts.transport.close().await;
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

    async fn force_shutdown_outbound(&self) {
        if let Some(runtime) = &self.parts.outbound_runtime {
            runtime.shutdown().await;
        }
    }
}

pub(crate) struct RuntimeLease {
    runtime: Arc<DnsRuntime>,
}

#[derive(Debug, thiserror::Error)]
#[error("DNS runtime generation {generation} retired")]
pub(crate) struct RuntimeCancelled {
    generation: u64,
}

impl RuntimeLease {
    pub(crate) fn runtime(&self) -> &DnsRuntime {
        &self.runtime
    }

    pub(crate) async fn cancelled(&self) -> RuntimeCancelled {
        self.runtime.cancelled().await;
        RuntimeCancelled {
            generation: self.runtime.generation().get(),
        }
    }

    pub(crate) async fn run<T>(
        &self,
        operation: impl Future<Output = T>,
    ) -> Result<T, RuntimeCancelled> {
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
