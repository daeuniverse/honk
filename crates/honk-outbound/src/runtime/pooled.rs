use std::sync::Arc;

use super::{AnyTlsRuntime, CapturedDialAdmission, NodeRuntime, ProtocolRuntime, WarmRetention};
use crate::proxy::transport::xhttp::XhttpRuntime;

trait PooledLifecycle {
    fn sync_warm_retention(&self, retention: u8, was_unretained: bool);
    fn retire(&self);
    fn shutdown(&self);
    fn reap_unretained_idle(&self) -> usize;
    fn live_session_count(&self) -> usize;
    fn is_warm_or_stateless_for(&self, requirement: crate::proxy::WarmRequirement) -> bool;
    fn bind_dial_admission(&self, admission: &CapturedDialAdmission);
}

impl PooledLifecycle for AnyTlsRuntime {
    fn sync_warm_retention(&self, retention: u8, was_unretained: bool) {
        if retention == 0 || was_unretained {
            self.pool.set_warm_retained(retention != 0);
        }
        if retention == 0 {
            self.tls.evict();
        }
    }
    fn retire(&self) {
        self.pool.retire();
        self.tls.close();
    }
    fn shutdown(&self) {
        self.pool.shutdown();
    }
    fn bind_dial_admission(&self, admission: &CapturedDialAdmission) {
        self.pool.set_dial_admission(admission.clone());
    }
    fn reap_unretained_idle(&self) -> usize {
        0
    }
    fn live_session_count(&self) -> usize {
        self.pool.live_session_count()
    }
    fn is_warm_or_stateless_for(&self, _: crate::proxy::WarmRequirement) -> bool {
        self.pool.has_usable_session()
    }
}

#[cfg(any(feature = "rprx", test))]
impl PooledLifecycle for super::VlessRuntime {
    fn sync_warm_retention(&self, retention: u8, _: bool) {
        self.sync_warm_retention(retention);
    }
    fn retire(&self) {
        self.retire();
    }
    fn shutdown(&self) {
        self.shutdown();
    }
    fn reap_unretained_idle(&self) -> usize {
        self.reap_unretained_idle()
    }
    fn live_session_count(&self) -> usize {
        self.live_session_count()
    }
    fn is_warm_or_stateless_for(&self, requirement: crate::proxy::WarmRequirement) -> bool {
        self.is_warm_or_stateless_for(requirement)
    }
    fn bind_dial_admission(&self, _: &CapturedDialAdmission) {}
}

impl PooledLifecycle for XhttpRuntime {
    fn sync_warm_retention(&self, retention: u8, _: bool) {
        self.set_warm_retained(retention != 0);
    }
    fn retire(&self) {
        self.retire();
    }
    fn shutdown(&self) {
        self.shutdown();
    }
    fn reap_unretained_idle(&self) -> usize {
        self.pools().map(|pool| pool.reap_unretained_idle()).sum()
    }
    fn live_session_count(&self) -> usize {
        self.pools().map(|pool| pool.live_session_count()).sum()
    }
    fn is_warm_or_stateless_for(&self, _: crate::proxy::WarmRequirement) -> bool {
        self.pools().all(|pool| pool.has_usable_session())
    }
    fn bind_dial_admission(&self, admission: &CapturedDialAdmission) {
        self.set_dial_admission(admission.clone());
    }
}

impl NodeRuntime {
    fn protocol_pool(&self) -> Option<&dyn PooledLifecycle> {
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => Some(runtime),
            #[cfg(any(feature = "rprx", test))]
            ProtocolRuntime::Vless(runtime) => Some(runtime),
            ProtocolRuntime::None | ProtocolRuntime::Quic(_) => None,
        }
    }

    fn transport_pool(&self) -> Option<&dyn PooledLifecycle> {
        self.xhttp
            .as_deref()
            .map(|runtime| runtime as &dyn PooledLifecycle)
    }

    fn pooled_lifecycles(&self) -> impl DoubleEndedIterator<Item = &dyn PooledLifecycle> {
        self.transport_pool()
            .into_iter()
            .chain(self.protocol_pool())
    }

    fn sync_pooled_retention(&self, retention: u8, was_unretained: bool) {
        for pool in self.pooled_lifecycles() {
            pool.sync_warm_retention(retention, was_unretained);
        }
    }

    pub(super) fn bind_dial_admission(&self, admission: &CapturedDialAdmission) {
        for pool in self.pooled_lifecycles() {
            pool.bind_dial_admission(admission);
        }
    }

    pub(super) fn shutdown_pools(&self) {
        for pool in self.pooled_lifecycles() {
            pool.shutdown();
        }
    }

    pub(super) fn retire_pools(&self) {
        for pool in self.pooled_lifecycles() {
            pool.retire();
        }
    }

    pub(super) fn pooled_session_count(&self) -> usize {
        self.pooled_lifecycles()
            .rev()
            .map(PooledLifecycle::live_session_count)
            .sum()
    }
    pub(super) fn pools_are_warm_for(&self, requirement: crate::proxy::WarmRequirement) -> bool {
        self.pooled_lifecycles()
            .all(|pool| pool.is_warm_or_stateless_for(requirement))
    }
    pub(crate) async fn retain_warm(self: &Arc<Self>, reason: WarmRetention) -> WarmAttempt {
        let mut retention = Arc::clone(&self.warm_retention).lock_owned().await;
        let bit = reason.bit();
        let inserted = *retention & bit == 0;
        let was_unretained = *retention == 0;
        *retention |= bit;
        if inserted {
            self.sync_pooled_retention(*retention, was_unretained);
        }
        WarmAttempt {
            runtime: Arc::clone(self),
            retention: Some(retention),
            reason,
            inserted,
        }
    }

    async fn release_warm_state(&self) {
        self.sync_pooled_retention(0, false);
        if let ProtocolRuntime::Quic(runtime) = &self.runtime {
            runtime.release_warm().await;
        }
    }

    async fn release_warm_locked(
        self: &Arc<Self>,
        mut retention: tokio::sync::OwnedMutexGuard<u8>,
        reason: WarmRetention,
    ) {
        let bit = reason.bit();
        if *retention & bit == 0 {
            return;
        }
        *retention &= !bit;
        self.sync_pooled_retention(*retention, false);
        if *retention != 0 {
            return;
        }
        if matches!(&self.runtime, ProtocolRuntime::Quic(_)) {
            drop(retention);
            let runtime = Arc::clone(self);
            // Spawn before awaiting so cancellation of the releasing caller
            // cannot strand a client after the ownership bit reached zero.
            let cleanup = tokio::spawn(async move { runtime.release_if_unretained().await });
            let _ = cleanup.await;
        }
    }

    /// Finish cancellation-driven QUIC cleanup after the owned guard drops.
    /// A successor may have retained the runtime meanwhile, so zero is
    /// revalidated under the same lock before releasing the client slot.
    async fn release_if_unretained(self: Arc<Self>) {
        let retention = Arc::clone(&self.warm_retention).lock_owned().await;
        if *retention == 0 {
            self.release_warm_state().await;
        }
    }

    /// Release one policy's warm ownership. A later selection may warm this
    /// runtime again; active logical flows are never cut.
    pub async fn release_warm(self: &Arc<Self>, reason: WarmRetention) {
        let retention = Arc::clone(&self.warm_retention).lock_owned().await;
        self.release_warm_locked(retention, reason).await;
    }

    /// Close every session-layer resource this runtime owns: AnyTLS or VLESS
    /// mux pool sessions (connections + drivers), or one cached QUIC client
    /// (connection + endpoint driver). Terminal for the runtime; idempotent.
    pub async fn close(&self) {
        self.shutdown_pools();
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => runtime.tls.close(),
            ProtocolRuntime::Quic(runtime) => runtime.force_close().await,
            _ => {}
        }
    }
}
/// Warm establishment transaction. Cancellation rolls back only a bit this
/// attempt inserted; QUIC cleanup rechecks the bitmap after reacquiring the
/// lock so it cannot dismantle a successor attempt's client.
pub(crate) struct WarmAttempt {
    runtime: Arc<NodeRuntime>,
    retention: Option<tokio::sync::OwnedMutexGuard<u8>>,
    reason: WarmRetention,
    inserted: bool,
}

impl WarmAttempt {
    pub(crate) fn commit(mut self) {
        self.retention.take();
    }

    pub(crate) async fn rollback(mut self) {
        let retention = self
            .retention
            .take()
            .expect("live warm attempt owns the retention lock");
        if self.inserted {
            self.runtime
                .release_warm_locked(retention, self.reason)
                .await;
        }
    }
}

impl Drop for WarmAttempt {
    fn drop(&mut self) {
        if !self.inserted {
            return;
        }
        let Some(mut retention) = self.retention.take() else {
            return;
        };
        *retention &= !self.reason.bit();
        self.runtime.sync_pooled_retention(*retention, false);
        if *retention == 0 && matches!(&self.runtime.runtime, ProtocolRuntime::Quic(_)) {
            drop(retention);
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let runtime = Arc::clone(&self.runtime);
                handle.spawn(async move { runtime.release_if_unretained().await });
            }
        }
    }
}

impl super::OutboundRuntimeRegistry {
    pub(super) fn reap_session_pools(&self) -> usize {
        self.nodes
            .values()
            .filter_map(|runtime| runtime.protocol_pool())
            .chain(
                self.nodes
                    .values()
                    .filter_map(|runtime| runtime.transport_pool()),
            )
            .map(PooledLifecycle::reap_unretained_idle)
            .sum()
    }
}
