//! Per-node runtime ownership: the ControlPlane owns every outbound's
//! session-layer resources through immutable runtime generations.
//!
//! `OutboundRuntimeRegistry` maps `Node.id` (UUID) to a `NodeRuntime` —
//! immutable node config, its UDP capability, and generation-owned protocol
//! state.
//! The registry lives on the ControlPlane (never on the GroupManager — a leaf
//! node may belong to many groups, and group rebuilds must not destroy
//! live sessions). ProxyRegistry stays stateless handlers.
//!
//! AnyTLS, VLESS H2MUX, and VLESS Mux.Cool own node-local session pools here;
//! QUIC protocols own their per-node client (and shared connection) here.

mod admission;
pub mod flow_observation;
mod tasks;
pub use tasks::TaskOwner;
pub use tasks::TaskScope;
pub(crate) use tasks::{
    RuntimeEndpoint, SharedTask, new_owned_quic_endpoint, spawn_joinable, spawn_owned,
};
#[cfg(any(feature = "rprx", test))]
mod vless;

pub(crate) use admission::pinned_server_address;
pub(crate) use admission::{
    CapturedDialAdmission, admit_physical_dial, admit_replacement_dial, capture_dial_admission,
    capture_dial_scope, start_scoped_dial, try_capture_dial_admission,
};
pub use admission::{DialPermit, DialScope};
#[cfg(any(feature = "rprx", test))]
pub use vless::VlessRuntime;

use honk_config::node::Node;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
#[cfg(any(feature = "rprx", test))]
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
pub const REAP_INTERVAL: Duration = Duration::from_secs(60);

static NEXT_RUNTIME_GENERATION: AtomicU64 = AtomicU64::new(1);
#[cfg(any(feature = "rprx", test))]
static STANDALONE_VLESS_CARRIERS: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(128)));

/// The generation-scoped session runtime a protocol owns, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationRuntime {
    None,
    AnyTls,
    Vless,
    Quic,
}

impl GenerationRuntime {
    pub(crate) fn build(
        self,
        node: &Node,
        metrics_enabled: bool,
        quality: Arc<crate::transport_quality::TransportQuality>,
    ) -> ProtocolRuntime {
        match self {
            Self::None => ProtocolRuntime::None,
            Self::AnyTls => ProtocolRuntime::AnyTls(AnyTlsRuntime::new()),
            #[cfg(any(feature = "rprx", test))]
            Self::Vless => ProtocolRuntime::Vless(VlessRuntime::new(
                node.vless().expect("VLESS runtime requires VLESS config"),
            )),
            #[cfg(not(any(feature = "rprx", test)))]
            Self::Vless => {
                let _ = node;
                ProtocolRuntime::None
            }
            Self::Quic => ProtocolRuntime::Quic(QuicRuntime::new(metrics_enabled, quality)),
        }
    }
}

/// The session-layer runtime for one node. Multiplexed protocols own
/// `SessionPool`s; QUIC protocols own connection/auth state here instead of
/// in handlers so a reload cannot send an old flow to a replacement generation.
#[derive(Debug)]
pub enum ProtocolRuntime {
    None,
    /// One node-local AnyTLS session pool.
    AnyTls(AnyTlsRuntime),
    /// Node-local VLESS path pools and source-association key.
    #[cfg(any(feature = "rprx", test))]
    Vless(VlessRuntime),
    /// Type-erased TUIC, Juicity, or Hysteria2 client slot. Policy warm
    /// ownership may release the cached client before generation retirement.
    Quic(QuicRuntime),
}

/// A protocol client stored in [`QuicRuntime`]. Implemented by the
/// TUIC/Juicity/Hysteria2 per-server clients so a terminating generation
/// can force-close the shared connection without knowing the concrete type.
#[async_trait::async_trait]
pub trait QuicRuntimeClient: Send + Sync + 'static {
    fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync>;
    /// Activate persistent-carrier telemetry without reporting business outcomes.
    async fn enable_metrics(&self, _quality: Arc<crate::transport_quality::TransportQuality>) {}
    /// Close the cached connection and endpoint, awaiting any in-flight
    /// dial so its late-arriving connection is closed too.
    async fn force_close(&self);
    /// Drop only reusable warm ownership. Existing flows keep their own
    /// connection/state clones and future dials may rebuild the client.
    async fn release_warm(&self);
}

/// Generation-owned storage for one protocol-specific QUIC client.
///
/// Each node has one immutable protocol, so a runtime needs one type-erased
/// slot rather than a type-indexed map. The mutex deliberately covers
/// construction and promotion: first traffic, warm-up, and a finalized
/// speculative transport must converge on one reusable client.
pub struct QuicRuntime {
    state: tokio::sync::Mutex<QuicRuntimeState>,
    flow_control_profiles: Arc<crate::quic::AdaptiveFlowProfiles>,
    transport_quality: Arc<crate::transport_quality::TransportQuality>,
}

#[derive(Default)]
struct QuicRuntimeState {
    client: Option<Arc<dyn QuicRuntimeClient>>,
    closed: bool,
    metrics_enabled: bool,
}

impl std::fmt::Debug for QuicRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicRuntime").finish_non_exhaustive()
    }
}
impl QuicRuntime {
    pub(crate) fn new(
        metrics_enabled: bool,
        transport_quality: Arc<crate::transport_quality::TransportQuality>,
    ) -> Self {
        Self {
            flow_control_profiles: Arc::new(crate::quic::AdaptiveFlowProfiles::default()),
            state: tokio::sync::Mutex::new(QuicRuntimeState {
                metrics_enabled,
                ..Default::default()
            }),
            transport_quality,
        }
    }

    pub(crate) fn flow_control_profiles(&self) -> Arc<crate::quic::AdaptiveFlowProfiles> {
        Arc::clone(&self.flow_control_profiles)
    }

    pub async fn client<T, F, Fut>(&self, build: F) -> anyhow::Result<Arc<T>>
    where
        T: QuicRuntimeClient,
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<Arc<T>>>,
    {
        let mut state = self.state.lock().await;
        if state.closed {
            anyhow::bail!("QUIC runtime is closed");
        }
        if let Some(client) = state.client.as_ref() {
            return Arc::clone(client)
                .into_erased()
                .downcast::<T>()
                .map_err(|_| anyhow::anyhow!("QUIC client slot type mismatch"));
        }
        let client = build().await?;
        if state.metrics_enabled {
            client
                .enable_metrics(Arc::clone(&self.transport_quality))
                .await;
        }
        state.client = Some(Arc::clone(&client) as Arc<dyn QuicRuntimeClient>);
        Ok(client)
    }

    /// Publish a detached speculative client after its transport wins. If
    /// ordinary traffic filled the slot meanwhile, retain that incumbent:
    /// the winning transport already owns its connection/state clones. There
    /// is no await after slot mutation, so cancellation cannot publish a
    /// client without completing the commit.
    pub(crate) async fn publish_client<T>(&self, client: Arc<T>) -> anyhow::Result<()>
    where
        T: QuicRuntimeClient,
    {
        let mut state = self.state.lock().await;
        if state.closed {
            anyhow::bail!("QUIC runtime is closed");
        }
        if let Some(incumbent) = state.client.as_ref() {
            Arc::clone(incumbent)
                .into_erased()
                .downcast::<T>()
                .map_err(|_| anyhow::anyhow!("QUIC client slot type mismatch"))?;
            if state.metrics_enabled {
                client
                    .enable_metrics(Arc::clone(&self.transport_quality))
                    .await;
            }
            return Ok(());
        }
        if state.metrics_enabled {
            client
                .enable_metrics(Arc::clone(&self.transport_quality))
                .await;
        }
        state.client = Some(client as Arc<dyn QuicRuntimeClient>);
        Ok(())
    }

    /// Force-close the cached client and reject future client builds.
    /// Awaits the construction/promotion critical section, so a client
    /// completed just before close cannot leak into a terminal generation.
    pub(crate) async fn force_close(&self) {
        let client = {
            let mut state = self.state.lock().await;
            state.closed = true;
            state.client.take()
        };
        if let Some(client) = client {
            client.force_close().await;
        }
    }

    /// Drop reusable ownership without making this runtime terminal.
    /// Established flows retain their own connection clones.
    async fn release_warm(&self) {
        let client = self.state.lock().await.client.take();
        if let Some(client) = client {
            client.release_warm().await;
        }
    }

    /// Occupancy (zero or one), or `None` while the slot lock is held.
    /// Gauges treat contention as unknown rather than pruning attribution.
    pub(crate) fn client_count(&self) -> Option<usize> {
        self.state
            .try_lock()
            .map(|state| usize::from(state.client.is_some()))
            .ok()
    }
}

/// Lazily built, generation-local TLS state. Contexts are shared per shape in
/// `tls`, so holding the connector costs a few KiB and needs no idle reaping.
#[derive(Debug, Default)]
struct TlsConnectorSlot {
    state: parking_lot::Mutex<TlsConnectorSlotState>,
}

#[derive(Debug, Default)]
struct TlsConnectorSlotState {
    cached: Option<Arc<crate::tls::TlsConnector>>,
    closed: bool,
}

impl TlsConnectorSlot {
    fn get_or_build(&self, node: &Node) -> anyhow::Result<Arc<crate::tls::TlsConnector>> {
        let mut state = self.state.lock();
        anyhow::ensure!(!state.closed, "TLS runtime is closed");
        if let Some(connector) = &state.cached {
            return Ok(Arc::clone(connector));
        }
        let connector = Arc::new(crate::tls::build_connector(node)?);
        state.cached = Some(Arc::clone(&connector));
        Ok(connector)
    }

    // Pool shutdown signals detached factories; it does not join them.
    fn close(&self) {
        let mut state = self.state.lock();
        state.closed = true;
        state.cached = None;
    }

    #[cfg(test)]
    fn is_loaded(&self) -> bool {
        self.state.lock().cached.is_some()
    }
}

/// AnyTLS session runtime: the pool stays generation-owned, while the TLS
/// connector is materialized on the first dial.
#[derive(Debug)]
pub struct AnyTlsRuntime {
    pub(crate) pool: Arc<crate::proxy::anytls::AnyTlsPool>,
    tls: TlsConnectorSlot,
}

impl AnyTlsRuntime {
    fn new() -> Self {
        Self {
            pool: Arc::new(crate::proxy::anytls::AnyTlsPool::new()),
            tls: TlsConnectorSlot::default(),
        }
    }
}

/// Live warm-state gauge of one runtime: retained AnyTLS/VLESS mux sessions
/// and one occupied QUIC client slot (`None` = count unknown under lock
/// contention, to be treated as warm rather than cold).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarmCounts {
    pub sessions: usize,
    pub clients: Option<usize>,
}

impl Default for WarmCounts {
    fn default() -> Self {
        Self {
            sessions: 0,
            clients: Some(0),
        }
    }
}

/// Independent policy-warm owners of reusable node state. The final policy
/// release drops future reuse without cutting active flow-owned clones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmRetention {
    Selector,
    Udp,
}

impl WarmRetention {
    fn bit(self) -> u8 {
        match self {
            Self::Selector => 1,
            Self::Udp => 1 << 1,
        }
    }
}

/// Immutable configuration and reusable protocol state for one node.
#[derive(Debug)]
pub struct NodeRuntime {
    /// Immutable node config for this generation.
    pub node: Arc<Node>,
    pub udp_capable: bool,
    pub runtime: ProtocolRuntime,
    transport_quality: Arc<crate::transport_quality::TransportQuality>,
    /// One-shot runtime outside any generation (see [`Self::ephemeral`]).
    /// Session protocols skip their standby janitor for these: there is no
    /// long-lived owner to keep warm state for, only [`Self::close`] to
    /// release it deterministically.
    ephemeral: bool,
    #[cfg(feature = "owned-tasks")]
    task_owner: Option<Arc<tasks::TaskOwner>>,
    /// Serializes warm establishment and release while tracking independent
    /// selector/UDP owners across runtime reuse on reload.
    warm_retention: Arc<tokio::sync::Mutex<u8>>,
    #[cfg(any(feature = "rprx", test))]
    vless_carriers: Arc<tokio::sync::Semaphore>,
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
        #[cfg(any(feature = "rprx", test))]
        if let ProtocolRuntime::Vless(runtime) = &self.runtime.runtime {
            runtime.sync_warm_retention(*retention);
            return;
        }
        if *retention != 0 {
            return;
        }
        match &self.runtime.runtime {
            ProtocolRuntime::AnyTls(runtime) => {
                runtime.pool.set_warm_retained(false);
            }
            ProtocolRuntime::Quic(_) => {
                drop(retention);
                if tokio::runtime::Handle::try_current().is_ok() {
                    let runtime = Arc::clone(&self.runtime);
                    let _ = self
                        .runtime
                        .task_scope()
                        .spawn(async move { runtime.release_if_unretained().await });
                }
            }
            ProtocolRuntime::None => {}
            #[cfg(any(feature = "rprx", test))]
            ProtocolRuntime::Vless(_) => {}
        }
    }
}

impl NodeRuntime {
    fn build(
        node: &Node,
        ephemeral: bool,
        #[cfg(feature = "owned-tasks")] task_owner: Option<Arc<tasks::TaskOwner>>,
        #[cfg(any(feature = "rprx", test))] vless_carriers: Arc<tokio::sync::Semaphore>,
    ) -> Arc<Self> {
        let transport_quality = Arc::new(crate::transport_quality::TransportQuality::default());
        let build = || {
            Arc::new(Self {
                node: Arc::new(node.clone()),
                udp_capable: (crate::descriptor::descriptor(node.protocol()).supports_udp)(node),
                runtime: crate::descriptor::descriptor(node.protocol())
                    .generation_runtime
                    .build(node, !ephemeral, Arc::clone(&transport_quality)),
                ephemeral,
                transport_quality,
                #[cfg(feature = "owned-tasks")]
                task_owner: task_owner.clone(),
                warm_retention: Arc::new(tokio::sync::Mutex::new(0)),
                #[cfg(any(feature = "rprx", test))]
                vless_carriers,
            })
        };
        #[cfg(feature = "owned-tasks")]
        return tasks::sync_scope_owner(task_owner.as_ref().map(Arc::downgrade), build);
        #[cfg(not(feature = "owned-tasks"))]
        build()
    }

    fn build_ephemeral_with_vless_carriers(
        node: &Node,
        #[cfg(any(feature = "rprx", test))] vless_carriers: Arc<tokio::sync::Semaphore>,
    ) -> Arc<Self> {
        Self::build(
            node,
            true,
            #[cfg(feature = "owned-tasks")]
            Some(Arc::new(tasks::TaskOwner::default())),
            #[cfg(any(feature = "rprx", test))]
            vless_carriers,
        )
    }

    fn build_ephemeral(node: &Node) -> Arc<Self> {
        Self::build_ephemeral_with_vless_carriers(
            node,
            #[cfg(any(feature = "rprx", test))]
            Arc::clone(&STANDALONE_VLESS_CARRIERS),
        )
    }

    /// Validate a node before any one-shot runtime state is cloned or built.
    pub(crate) fn validate_for_ephemeral(node: &Node) -> Result<(), RuntimeRegistryError> {
        honk_config::node::validate_node_collection(std::slice::from_ref(node))
            .map_err(RuntimeRegistryError::Admission)
    }

    /// Admit a canonical node and build a generation-free one-shot runtime.
    ///
    /// Rejects nil IDs, intrinsic errors and stale IDs before allocating sessions.
    /// The caller must [`Self::close`] session-owning runtimes when done; prefer
    /// [`Self::try_ephemeral_guarded`] for cleanup on cancellation or drop.
    pub fn try_ephemeral(node: &Node) -> Result<Arc<Self>, RuntimeRegistryError> {
        Self::validate_for_ephemeral(node)?;
        Ok(Self::build_ephemeral(node))
    }

    /// [`Self::try_ephemeral`] with an ownership guard that closes on drop.
    pub fn try_ephemeral_guarded(
        node: &Node,
    ) -> Result<EphemeralRuntimeGuard, RuntimeRegistryError> {
        Self::validate_for_ephemeral(node)?;
        Ok(Self::ephemeral_guarded_after_admission(node))
    }

    pub(crate) fn ephemeral_guarded_after_admission(node: &Node) -> EphemeralRuntimeGuard {
        EphemeralRuntimeGuard {
            runtime: Some(Self::build_ephemeral(node)),
        }
    }

    pub(crate) fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    /// Scope protocol jobs to this runtime, never to a caller's probe owner.
    /// Callers retain and drain their own dialing future before final shutdown.
    pub fn scope_tasks<T, F>(&self, future: F) -> impl Future<Output = anyhow::Result<T>>
    where
        F: Future<Output = anyhow::Result<T>>,
    {
        #[cfg(feature = "owned-tasks")]
        match &self.task_owner {
            Some(owner) => futures_util::future::Either::Left(owner.scope(future)),
            None => futures_util::future::Either::Right(tasks::scope_owner(None, future)),
        }
        #[cfg(not(feature = "owned-tasks"))]
        future
    }

    pub(crate) fn task_scope(&self) -> TaskScope {
        #[cfg(feature = "owned-tasks")]
        if let Some(owner) = &self.task_owner {
            return owner.task_scope();
        }
        TaskScope::default()
    }

    /// Advisory evidence belongs to this runtime, not merely its reusable node ID.
    pub fn transport_quality(&self) -> Arc<crate::transport_quality::TransportQuality> {
        Arc::clone(&self.transport_quality)
    }

    pub(crate) async fn retain_warm(self: &Arc<Self>, reason: WarmRetention) -> WarmAttempt {
        let mut retention = Arc::clone(&self.warm_retention).lock_owned().await;
        let bit = reason.bit();
        let inserted = *retention & bit == 0;
        let was_unretained = *retention == 0;
        *retention |= bit;
        if inserted {
            match &self.runtime {
                #[cfg(any(feature = "rprx", test))]
                ProtocolRuntime::Vless(runtime) => runtime.sync_warm_retention(*retention),
                ProtocolRuntime::AnyTls(runtime) if was_unretained => {
                    runtime.pool.set_warm_retained(true)
                }
                ProtocolRuntime::None | ProtocolRuntime::AnyTls(_) | ProtocolRuntime::Quic(_) => {}
            }
        }
        WarmAttempt {
            runtime: Arc::clone(self),
            retention: Some(retention),
            reason,
            inserted,
        }
    }

    async fn release_warm_state(&self) {
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => {
                runtime.pool.set_warm_retained(false);
            }
            #[cfg(any(feature = "rprx", test))]
            ProtocolRuntime::Vless(runtime) => runtime.sync_warm_retention(0),
            ProtocolRuntime::Quic(runtime) => runtime.release_warm().await,
            ProtocolRuntime::None => {}
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
        #[cfg(any(feature = "rprx", test))]
        if let ProtocolRuntime::Vless(runtime) = &self.runtime {
            runtime.sync_warm_retention(*retention);
            return;
        }
        if *retention != 0 {
            return;
        }
        if matches!(&self.runtime, ProtocolRuntime::Quic(_)) {
            drop(retention);
            let runtime = Arc::clone(self);
            // Spawn before awaiting so cancellation of the releasing caller
            // cannot strand a client after the ownership bit reached zero.
            let (finished, done) = tokio::sync::oneshot::channel();
            let _ = self.task_scope().spawn(async move {
                runtime.release_if_unretained().await;
                let _ = finished.send(());
            });
            let _ = done.await;
        } else {
            self.release_warm_state().await;
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
        #[cfg(feature = "owned-tasks")]
        if let Some(owner) = &self.task_owner {
            owner.abort();
        }
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => {
                runtime.pool.shutdown();
                runtime.tls.close();
            }
            #[cfg(any(feature = "rprx", test))]
            ProtocolRuntime::Vless(runtime) => runtime.shutdown(),
            ProtocolRuntime::Quic(runtime) => runtime.force_close().await,
            ProtocolRuntime::None => {}
        }
        #[cfg(feature = "owned-tasks")]
        if let Some(owner) = &self.task_owner {
            owner.close().await;
        }
    }

    /// Whether an owned protocol task panicked, including already reaped tasks.
    pub fn tasks_failed(&self) -> bool {
        #[cfg(feature = "owned-tasks")]
        return self
            .task_owner
            .as_ref()
            .is_some_and(|owner| owner.has_failed());
        #[cfg(not(feature = "owned-tasks"))]
        false
    }

    pub(crate) fn anytls_pool(&self) -> anyhow::Result<Arc<crate::proxy::anytls::AnyTlsPool>> {
        let ProtocolRuntime::AnyTls(runtime) = &self.runtime else {
            anyhow::bail!("node '{}' has no AnyTLS runtime", self.node.name);
        };
        Ok(Arc::clone(&runtime.pool))
    }

    #[cfg(feature = "rprx")]
    pub(crate) fn vless_h2_pool(
        &self,
    ) -> anyhow::Result<Arc<crate::proxy::vless::mux::VlessMuxPool>> {
        let ProtocolRuntime::Vless(runtime) = &self.runtime else {
            anyhow::bail!("node '{}' has no VLESS runtime", self.node.name);
        };
        runtime.h2_pool()
    }

    #[cfg(feature = "rprx")]
    pub(crate) fn vless_shared_cool_pool(
        &self,
    ) -> anyhow::Result<Arc<crate::proxy::vless::cool::VlessCoolPool>> {
        let ProtocolRuntime::Vless(runtime) = &self.runtime else {
            anyhow::bail!("node '{}' has no VLESS runtime", self.node.name);
        };
        runtime.shared_cool_pool()
    }

    #[cfg(feature = "rprx")]
    pub(crate) fn vless_separate_cool_pool(
        &self,
    ) -> anyhow::Result<Arc<crate::proxy::vless::cool::VlessCoolPool>> {
        let ProtocolRuntime::Vless(runtime) = &self.runtime else {
            anyhow::bail!("node '{}' has no VLESS runtime", self.node.name);
        };
        runtime.separate_cool_pool()
    }

    #[cfg(any(feature = "rprx", test))]
    pub fn vless_source_id(
        &self,
        client: std::net::SocketAddr,
        path: honk_config::node::VlessUdpPath,
        reply_destination: Option<std::net::SocketAddr>,
    ) -> anyhow::Result<[u8; 8]> {
        let ProtocolRuntime::Vless(runtime) = &self.runtime else {
            anyhow::bail!("node '{}' has no VLESS runtime", self.node.name);
        };
        Ok(runtime.source_id(client, path, reply_destination))
    }

    #[cfg(any(feature = "rprx", test))]
    pub(crate) fn acquire_vless_carrier(
        &self,
    ) -> anyhow::Result<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.vless_carriers)
            .try_acquire_owned()
            .map_err(|_| anyhow::Error::new(crate::proxy::PacketRejection::Capacity))
    }

    pub(crate) async fn quic_client<T, F, Fut>(&self, build: F) -> anyhow::Result<Arc<T>>
    where
        T: QuicRuntimeClient,
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<Arc<T>>>,
    {
        let ProtocolRuntime::Quic(runtime) = &self.runtime else {
            anyhow::bail!("node '{}' has no QUIC runtime", self.node.name);
        };
        self.scope_tasks(runtime.client(build)).await
    }

    pub(crate) fn quic_flow_control_profiles(
        &self,
    ) -> anyhow::Result<Arc<crate::quic::AdaptiveFlowProfiles>> {
        let ProtocolRuntime::Quic(runtime) = &self.runtime else {
            anyhow::bail!("node '{}' has no QUIC runtime", self.node.name);
        };
        Ok(runtime.flow_control_profiles())
    }

    pub(crate) fn anytls_tls_connector(&self) -> anyhow::Result<Arc<crate::tls::TlsConnector>> {
        let ProtocolRuntime::AnyTls(runtime) = &self.runtime else {
            anyhow::bail!("node '{}' has no AnyTLS runtime", self.node.name);
        };
        runtime.tls.get_or_build(&self.node)
    }

    /// Whether one-shot work for `requirement` should reuse this generation.
    /// Stateless paths are always safe; pooled paths qualify only when their
    /// selected pool already has a reusable session/client.
    pub fn is_warm_or_stateless_for(&self, requirement: crate::proxy::WarmRequirement) -> bool {
        #[cfg(not(any(feature = "rprx", test)))]
        let _ = requirement;
        match &self.runtime {
            ProtocolRuntime::None => true,
            ProtocolRuntime::AnyTls(runtime) => runtime.pool.has_usable_session(),
            #[cfg(any(feature = "rprx", test))]
            ProtocolRuntime::Vless(runtime) => runtime.is_warm_or_stateless_for(requirement),
            ProtocolRuntime::Quic(runtime) => runtime.client_count().is_none_or(|count| count != 0),
        }
    }

    /// Live reusable state: AnyTLS/VLESS sessions or one occupied QUIC client slot.
    /// `clients` is `None` while the slot lock is held; callers treat that
    /// in-flight state as warm rather than pruning its attribution.
    pub fn warm_counts(&self) -> WarmCounts {
        match &self.runtime {
            ProtocolRuntime::None => WarmCounts::default(),
            ProtocolRuntime::AnyTls(runtime) => WarmCounts {
                sessions: runtime.pool.live_session_count(),
                clients: Some(0),
            },
            #[cfg(any(feature = "rprx", test))]
            ProtocolRuntime::Vless(runtime) => WarmCounts {
                sessions: runtime.live_session_count(),
                clients: Some(0),
            },
            ProtocolRuntime::Quic(runtime) => WarmCounts {
                sessions: 0,
                clients: runtime.client_count(),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn tls_connector_loaded(&self) -> bool {
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => runtime.tls.is_loaded(),
            ProtocolRuntime::None | ProtocolRuntime::Vless(_) | ProtocolRuntime::Quic(_) => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("outbound runtime cleanup failed")]
pub struct RuntimeCleanupError;

/// Ownership guard for an ephemeral [`NodeRuntime`]: Drop initiates the
/// close, so a probe future dropped mid-flight (timeout, task abort) still
/// releases the session-layer resources. Use [`Self::close`] on the normal
/// path to also await the teardown.
#[derive(Debug)]
pub struct EphemeralRuntimeGuard {
    runtime: Option<Arc<NodeRuntime>>,
}

impl EphemeralRuntimeGuard {
    /// The guarded runtime for dialing. Valid until [`Self::close`].
    pub fn runtime(&self) -> Arc<NodeRuntime> {
        Arc::clone(
            self.runtime
                .as_ref()
                .expect("EphemeralRuntimeGuard outlives its uses"),
        )
    }

    /// Initiate the close without awaiting it: idempotent and Drop-safe.
    /// This signals background work but does not join it; native supervisors
    /// retain the runtime and await [`NodeRuntime::close`] before releasing work.
    pub fn request_close(&mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        #[cfg(feature = "owned-tasks")]
        if let Some(owner) = &runtime.task_owner {
            owner.abort();
        }
        match &runtime.runtime {
            ProtocolRuntime::AnyTls(anytls) => anytls.pool.shutdown(),
            #[cfg(any(feature = "rprx", test))]
            ProtocolRuntime::Vless(vless) => vless.shutdown(),
            ProtocolRuntime::Quic(_) => {
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(async move { runtime.close().await });
                }
            }
            ProtocolRuntime::None => {}
        }
    }

    /// Close and join all owned work. Cancelling this waiter retains ownership
    /// in the guard so another waiter can finish the same teardown. Once a call
    /// completes, later calls return `Ok(())`; an error only reports that an
    /// owned task failed, after teardown has finished.
    pub async fn close(&mut self) -> Result<(), RuntimeCleanupError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(());
        };
        runtime.close().await;
        let result = if runtime.tasks_failed() {
            Err(RuntimeCleanupError)
        } else {
            Ok(())
        };
        self.runtime.take();
        result
    }
}

impl Drop for EphemeralRuntimeGuard {
    fn drop(&mut self) {
        self.request_close();
    }
}

/// Full node-config equality for runtime reuse across generations, ignoring
/// the parse-time `created_at`/`updated_at` stamps (metadata, not dial
/// configuration).
fn same_node_config(a: &Node, b: &Node) -> bool {
    let mut a = a.clone();
    a.created_at = b.created_at;
    a.updated_at = b.updated_at;
    &a == b
}

/// Registry build/validation errors. A failure here aborts the reload
/// (the current generation stays live).
#[derive(Debug, thiserror::Error)]
pub enum RuntimeRegistryError {
    #[error("registry node admission failed")]
    Admission(#[source] honk_config::error::DetailedConfigError),
    #[error("node TLS configuration rejected")]
    Tls(#[source] Option<std::io::Error>),
}

/// The single owner of per-node session runtimes for one config
/// generation. Rebuilt with the config; shutdown makes a generation
/// terminal before closing its owned pools so late work can never fall
/// through to a newer generation.
#[derive(Debug)]
pub struct OutboundRuntimeRegistry {
    generation: u64,
    nodes: HashMap<uuid::Uuid, Arc<NodeRuntime>>,
    terminal: AtomicBool,
    /// Runtimes a successor generation took over at the reload commit point.
    /// Recorded only after the successor is published, so an aborted reload
    /// leaves this generation's ownership untouched; drain/shutdown skip
    /// exactly these entries (the successor closes them as their full owner).
    moved_out: parking_lot::Mutex<HashSet<uuid::Uuid>>,
    /// Generation-local configured admission budget. DNS forks share the
    /// source generation's semaphore so one config generation cannot exceed
    /// its configured aggregate dial limit.
    dial_semaphore: Arc<tokio::sync::Semaphore>,
    dial_limit: usize,
    /// Process-wide descriptor gate shared by every overlapping generation.
    dial_ceiling_semaphore: Arc<tokio::sync::Semaphore>,
    dial_ceiling_limit: usize,
    #[cfg(feature = "owned-tasks")]
    own_node_tasks: bool,
    background_tasks: std::sync::LazyLock<Arc<tasks::TaskOwner>>,
    #[cfg(any(feature = "rprx", test))]
    vless_carrier_semaphore: Arc<tokio::sync::Semaphore>,
}

/// Shared cell swapped atomically on reload (same pattern as
/// `SharedGroupManager`).
pub type SharedRuntimeRegistry = Arc<parking_lot::RwLock<Arc<OutboundRuntimeRegistry>>>;

impl OutboundRuntimeRegistry {
    /// Build and validate a registry from the generation's node set.
    pub fn build(nodes: &[Node]) -> Result<Self, RuntimeRegistryError> {
        Self::build_reusing(
            nodes,
            honk_config::config::GlobalConfig::default().max_concurrent_dials,
            None,
        )
        .map(|(registry, _)| registry)
    }

    /// Admit a cold one-shot runtime using this generation's shared carrier budget.
    /// The caller must scope dials to this registry and close the returned guard.
    #[cfg(feature = "owned-tasks")]
    pub fn try_ephemeral_guarded(
        &self,
        node: &Node,
    ) -> Result<EphemeralRuntimeGuard, RuntimeRegistryError> {
        NodeRuntime::validate_for_ephemeral(node)?;
        Ok(self.ephemeral_guarded_after_admission(node))
    }

    pub(crate) fn ephemeral_guarded_after_admission(&self, node: &Node) -> EphemeralRuntimeGuard {
        EphemeralRuntimeGuard {
            runtime: Some(NodeRuntime::build_ephemeral_with_vless_carriers(
                node,
                #[cfg(any(feature = "rprx", test))]
                Arc::clone(&self.vless_carrier_semaphore),
            )),
        }
    }

    /// Build with a generation-local dial limit. Descriptor-aware owners that
    /// overlap generations should use [`Self::build_reusing_with_dial_ceiling`].
    pub fn build_reusing(
        nodes: &[Node],
        max_concurrent_dials: usize,
        previous: Option<&Self>,
    ) -> Result<(Self, HashSet<uuid::Uuid>), RuntimeRegistryError> {
        let dial_ceiling_limit = previous.map_or(max_concurrent_dials.max(1), |previous| {
            previous.dial_ceiling_limit
        });
        #[cfg(any(feature = "rprx", test))]
        let vless_carriers = previous.map_or_else(
            || Arc::clone(&STANDALONE_VLESS_CARRIERS),
            |previous| Arc::clone(&previous.vless_carrier_semaphore),
        );
        Self::build_reusing_with_admission(
            nodes,
            max_concurrent_dials,
            previous.map_or_else(
                || Arc::new(tokio::sync::Semaphore::new(dial_ceiling_limit)),
                |previous| Arc::clone(&previous.dial_ceiling_semaphore),
            ),
            dial_ceiling_limit,
            #[cfg(any(feature = "rprx", test))]
            vless_carriers,
            previous.is_some_and(Self::owns_tasks),
            previous,
        )
    }

    /// Build a DNS-owned runtime fork from this generation's immutable node
    /// configuration. The fork owns fresh protocol sessions and terminal
    /// lifecycle state, while sharing this generation's dial admission and
    /// startup dial/VLESS-carrier ceilings.
    pub fn fork_for_dns(&self) -> Result<Self, RuntimeRegistryError> {
        let nodes: Vec<Node> = self
            .nodes
            .values()
            .map(|runtime| runtime.node.as_ref().clone())
            .collect();
        let (mut fork, _) = Self::build_reusing_with_admission(
            &nodes,
            self.dial_limit,
            Arc::clone(&self.dial_ceiling_semaphore),
            self.dial_ceiling_limit,
            #[cfg(any(feature = "rprx", test))]
            Arc::clone(&self.vless_carrier_semaphore),
            self.owns_tasks(),
            None,
        )?;
        fork.dial_semaphore = Arc::clone(&self.dial_semaphore);
        Ok(fork)
    }

    /// Build while sharing immutable process-wide dial and VLESS carrier ceilings
    /// with `previous`. A successor may change its generation-local configured
    /// dial limit, but old and new lifetime permits never exceed the startup gates.
    pub fn build_reusing_with_dial_ceiling(
        nodes: &[Node],
        max_concurrent_dials: usize,
        startup_dial_ceiling: usize,
        startup_vless_carrier_ceiling: usize,
        own_tasks: bool,
        previous: Option<&Self>,
    ) -> Result<(Self, HashSet<uuid::Uuid>), RuntimeRegistryError> {
        let (dial_ceiling_semaphore, dial_ceiling_limit) = match previous {
            Some(previous) => (
                Arc::clone(&previous.dial_ceiling_semaphore),
                previous.dial_ceiling_limit,
            ),
            None => {
                let limit = startup_dial_ceiling.max(1);
                (Arc::new(tokio::sync::Semaphore::new(limit)), limit)
            }
        };
        #[cfg(any(feature = "rprx", test))]
        let vless_carrier_semaphore = previous.map_or_else(
            || Arc::new(tokio::sync::Semaphore::new(startup_vless_carrier_ceiling)),
            |previous| Arc::clone(&previous.vless_carrier_semaphore),
        );
        #[cfg(not(any(feature = "rprx", test)))]
        let _ = startup_vless_carrier_ceiling;
        Self::build_reusing_with_admission(
            nodes,
            max_concurrent_dials,
            dial_ceiling_semaphore,
            dial_ceiling_limit,
            #[cfg(any(feature = "rprx", test))]
            vless_carrier_semaphore,
            own_tasks,
            previous,
        )
    }

    fn build_reusing_with_admission(
        nodes: &[Node],
        max_concurrent_dials: usize,
        dial_ceiling_semaphore: Arc<tokio::sync::Semaphore>,
        dial_ceiling_limit: usize,
        #[cfg(any(feature = "rprx", test))] vless_carrier_semaphore: Arc<tokio::sync::Semaphore>,
        own_tasks: bool,
        previous: Option<&Self>,
    ) -> Result<(Self, HashSet<uuid::Uuid>), RuntimeRegistryError> {
        honk_config::node::validate_node_collection(nodes)
            .map_err(RuntimeRegistryError::Admission)?;
        let own_tasks = cfg!(feature = "owned-tasks") && own_tasks;
        let mut map = HashMap::with_capacity(nodes.len());
        let mut reused = HashSet::new();
        for node in nodes {
            // Validate cheap, fail-closed TLS inputs before publishing the
            // generation. The heavyweight SSL_CTX/root store stays lazy.
            if node
                .tls()
                .is_some_and(|tls| tls.enabled || !tls.alpn.is_empty())
            {
                crate::tls::validate_connector_config(node).map_err(|error| {
                    // Preserve typed I/O failures without retaining paths or raw TLS values.
                    RuntimeRegistryError::Tls(error.chain().find_map(|cause| {
                        cause
                            .downcast_ref::<std::io::Error>()
                            .map(|error| std::io::Error::from(error.kind()))
                    }))
                })?;
            }
            let reused_runtime = previous.and_then(|previous| {
                if previous.is_shutdown() || previous.owns_tasks() != own_tasks {
                    return None;
                }
                let runtime = previous.get(&node.id)?;
                #[cfg(feature = "owned-tasks")]
                if runtime
                    .task_owner
                    .as_ref()
                    .is_some_and(|owner| owner.is_closed())
                {
                    return None;
                }
                same_node_config(&runtime.node, node).then_some(runtime)
            });
            let runtime = match reused_runtime {
                Some(runtime) => {
                    reused.insert(node.id);
                    runtime
                }
                None => NodeRuntime::build(
                    node,
                    false,
                    #[cfg(feature = "owned-tasks")]
                    own_tasks.then(|| Arc::new(tasks::TaskOwner::production())),
                    #[cfg(any(feature = "rprx", test))]
                    Arc::clone(&vless_carrier_semaphore),
                ),
            };
            map.insert(node.id, runtime);
        }
        Ok((
            Self {
                generation: NEXT_RUNTIME_GENERATION.fetch_add(1, Ordering::Relaxed),
                nodes: map,
                terminal: AtomicBool::new(false),
                moved_out: parking_lot::Mutex::new(HashSet::new()),
                dial_semaphore: Arc::new(tokio::sync::Semaphore::new(
                    max_concurrent_dials.max(1).min(dial_ceiling_limit),
                )),
                dial_limit: max_concurrent_dials.max(1).min(dial_ceiling_limit),
                dial_ceiling_semaphore,
                dial_ceiling_limit,
                #[cfg(feature = "owned-tasks")]
                own_node_tasks: own_tasks,
                background_tasks: std::sync::LazyLock::new(|| {
                    Arc::new(tasks::TaskOwner::production())
                }),
                #[cfg(any(feature = "rprx", test))]
                vless_carrier_semaphore,
            },
            reused,
        ))
    }

    fn owns_tasks(&self) -> bool {
        #[cfg(feature = "owned-tasks")]
        return self.own_node_tasks;
        #[cfg(not(feature = "owned-tasks"))]
        false
    }

    /// Spawn generation-local deposits, never accepted flows or reused-node drivers.
    pub fn spawn_background<F>(&self, future: F) -> Option<tokio::task::AbortHandle>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.is_shutdown() {
            if let Some(owner) = std::sync::LazyLock::get(&self.background_tasks) {
                owner.sync_scope(|| drop(future));
            }
            return None;
        }
        let owner = std::sync::LazyLock::force(&self.background_tasks);
        if self.is_shutdown() {
            owner.abort();
        }
        owner.spawn(future)
    }

    /// Wrap into the shared cell used by the control plane.
    pub fn into_shared(self) -> SharedRuntimeRegistry {
        Arc::new(parking_lot::RwLock::new(Arc::new(self)))
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn get(&self, id: &uuid::Uuid) -> Option<Arc<NodeRuntime>> {
        self.nodes.get(id).map(Arc::clone)
    }

    /// Iterate every runtime of this generation (observability/gauges).
    pub fn values(&self) -> impl Iterator<Item = &Arc<NodeRuntime>> {
        self.nodes.values()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Reap finished tasks and idle VLESS carriers above explicit or runtime
    /// warm retention.
    pub fn reap_idle_resources(&self) -> usize {
        if let Some(owner) = std::sync::LazyLock::get(&self.background_tasks) {
            owner.reap();
        }
        #[cfg(feature = "owned-tasks")]
        {
            for runtime in self.nodes.values() {
                if let Some(owner) = &runtime.task_owner {
                    owner.reap();
                }
            }
        }
        #[cfg(any(feature = "rprx", test))]
        let reaped: usize = self
            .nodes
            .values()
            .filter_map(|runtime| match &runtime.runtime {
                ProtocolRuntime::Vless(vless) => Some(vless.reap_unretained_idle()),
                _ => None,
            })
            .sum();
        #[cfg(not(any(feature = "rprx", test)))]
        let reaped = 0;
        reaped
    }

    /// Whether this generation has become terminal. Warm-up work must reject
    /// rather than consulting a replacement generation once this is true.
    pub fn is_shutdown(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }

    /// Sticky task failure status for this generation's retained ownership.
    pub fn tasks_failed(&self) -> bool {
        if std::sync::LazyLock::get(&self.background_tasks).is_some_and(|owner| owner.has_failed())
        {
            return true;
        }
        #[cfg(feature = "owned-tasks")]
        {
            let moved_out = self.moved_out.lock();
            self.nodes
                .iter()
                .any(|(id, runtime)| !moved_out.contains(id) && runtime.tasks_failed())
        }
        #[cfg(not(feature = "owned-tasks"))]
        false
    }

    /// Make the generation unavailable to new generation-owned work without
    /// cutting streams that already own its sessions. The DNS runtime that
    /// captured this generation starts pool draining after its leases retire.
    pub fn begin_retirement(&self) {
        self.terminal.store(true, Ordering::Release);
        if let Some(owner) = std::sync::LazyLock::get(&self.background_tasks) {
            owner.abort();
        }
    }

    /// Record runtimes a published successor generation has taken over.
    /// Called only at the reload commit point (after the successor registry
    /// replaces this one); this generation then leaves those runtimes alone
    /// at drain/shutdown — the successor owns and closes them.
    pub fn mark_moved_out(&self, ids: impl IntoIterator<Item = uuid::Uuid>) {
        self.moved_out.lock().extend(ids);
    }

    /// Reject new reusable work and release every non-flow resource after the
    /// generation's leases drain. Active streams and QUIC flows keep their
    /// own handles. Runtimes transferred to a successor are left untouched.
    pub async fn retire_reusable_state(&self) {
        self.begin_retirement();
        let moved_out: HashSet<uuid::Uuid> = self.moved_out.lock().clone();
        for (id, runtime) in &self.nodes {
            if moved_out.contains(id) {
                continue;
            }
            match &runtime.runtime {
                ProtocolRuntime::AnyTls(anytls) => {
                    anytls.pool.retire();
                    anytls.tls.close();
                }
                #[cfg(any(feature = "rprx", test))]
                ProtocolRuntime::Vless(vless) => vless.retire(),
                ProtocolRuntime::Quic(quic) => quic.release_warm().await,
                ProtocolRuntime::None => {}
            }
        }
    }

    /// Force-close every owned runtime. Used only after process-level flow
    /// drain; unlike retirement this deliberately terminates all sessions.
    /// Idempotent, including after [`Self::begin_retirement`].
    pub async fn shutdown(&self) {
        self.begin_retirement();
        let moved_out: HashSet<uuid::Uuid> = self.moved_out.lock().clone();
        #[cfg(feature = "owned-tasks")]
        {
            for (id, runtime) in &self.nodes {
                if !moved_out.contains(id)
                    && let Some(owner) = &runtime.task_owner
                {
                    owner.abort();
                }
            }
        }
        if let Some(owner) = std::sync::LazyLock::get(&self.background_tasks) {
            owner.close().await;
        }
        for (id, runtime) in &self.nodes {
            if moved_out.contains(id) {
                continue;
            }
            runtime.close().await;
        }
    }
}

#[cfg(test)]
mod tests;
