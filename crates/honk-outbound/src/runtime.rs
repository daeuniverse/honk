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
#[cfg(any(feature = "rprx", test))]
mod vless;

pub use admission::DialPermit;
pub(crate) use admission::{
    CapturedDialAdmission, admit_physical_dial, admit_replacement_dial, capture_dial_admission,
    capture_dial_scope, start_scoped_dial, try_capture_dial_admission,
};
#[cfg(any(feature = "rprx", test))]
pub use vless::VlessRuntime;

use honk_config::node::Node;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
#[cfg(any(feature = "rprx", test))]
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
const TLS_ACTIVE_RATIO_NUMERATOR: usize = 1;
const TLS_ACTIVE_RATIO_DENOMINATOR: usize = 10;
const TLS_ACTIVE_MIN: usize = 8;
pub const TLS_IDLE_RETENTION: Duration = Duration::from_secs(10 * 60);
pub const TLS_REAP_INTERVAL: Duration = Duration::from_secs(60);

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
    pub(crate) fn build(self, node: &Node, metrics_enabled: bool) -> ProtocolRuntime {
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
            Self::Quic => ProtocolRuntime::Quic(QuicRuntime::new(metrics_enabled)),
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
    /// Start aggregate telemetry for a persistent QUIC client.
    async fn enable_metrics(&self) {}
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
    pub(crate) fn new(metrics_enabled: bool) -> Self {
        Self {
            flow_control_profiles: Arc::new(crate::quic::AdaptiveFlowProfiles::default()),
            state: tokio::sync::Mutex::new(QuicRuntimeState {
                metrics_enabled,
                ..Default::default()
            }),
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
            client.enable_metrics().await;
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
                client.enable_metrics().await;
            }
            return Ok(());
        }
        if state.metrics_enabled {
            client.enable_metrics().await;
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

/// Lazily built TLS state. An in-flight handshake owns an `Arc`, so evicting
/// the cached reference never invalidates active work.
#[derive(Debug, Default)]
struct TlsConnectorSlot {
    state: parking_lot::Mutex<TlsConnectorSlotState>,
}

#[derive(Debug, Default)]
struct TlsConnectorSlotState {
    cached: Option<(Arc<crate::tls::TlsConnector>, Instant)>,
    revision: u64,
    closed: bool,
}

impl TlsConnectorSlot {
    fn get_or_build(&self, node: &Node) -> anyhow::Result<Arc<crate::tls::TlsConnector>> {
        let mut state = self.state.lock();
        anyhow::ensure!(!state.closed, "TLS runtime is closed");
        state.revision = state.revision.wrapping_add(1);
        if let Some((connector, used_at)) = state.cached.as_mut() {
            *used_at = Instant::now();
            return Ok(Arc::clone(connector));
        }
        let connector = Arc::new(crate::tls::build_connector(node)?);
        state.cached = Some((Arc::clone(&connector), Instant::now()));
        Ok(connector)
    }

    fn sample(&self) -> Option<(Instant, u64)> {
        let state = self.state.lock();
        state
            .cached
            .as_ref()
            .map(|(_, used_at)| (*used_at, state.revision))
    }

    fn evict_if_sample(&self, sample: (Instant, u64)) -> bool {
        let mut state = self.state.lock();
        let unchanged = state.revision == sample.1
            && state
                .cached
                .as_ref()
                .is_some_and(|(_, used_at)| *used_at == sample.0);
        if !unchanged {
            return false;
        }
        state.cached.take();
        state.revision = state.revision.wrapping_add(1);
        true
    }

    fn evict(&self) {
        let mut state = self.state.lock();
        if state.cached.take().is_some() {
            state.revision = state.revision.wrapping_add(1);
        }
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

/// AnyTLS session runtime: the pool stays generation-owned, while expensive
/// BoringSSL state is materialized only for nodes entering the active set.
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
    /// One-shot runtime outside any generation (see [`Self::ephemeral`]).
    /// Session protocols skip their standby janitor for these: there is no
    /// long-lived owner to keep warm state for, only [`Self::close`] to
    /// release it deterministically.
    ephemeral: bool,
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
                runtime.tls.evict();
            }
            ProtocolRuntime::Quic(_) => {
                drop(retention);
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    let runtime = Arc::clone(&self.runtime);
                    handle.spawn(async move { runtime.release_if_unretained().await });
                }
            }
            ProtocolRuntime::None => {}
            #[cfg(any(feature = "rprx", test))]
            ProtocolRuntime::Vless(_) => {}
        }
    }
}

impl NodeRuntime {
    fn build_ephemeral_with_vless_carriers(
        node: &Node,
        #[cfg(any(feature = "rprx", test))] vless_carriers: Arc<tokio::sync::Semaphore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            node: Arc::new(node.clone()),
            udp_capable: (crate::descriptor::descriptor(node.protocol()).supports_udp)(node),
            runtime: crate::descriptor::descriptor(node.protocol())
                .generation_runtime
                .build(node, false),
            ephemeral: true,
            warm_retention: Arc::new(tokio::sync::Mutex::new(0)),
            #[cfg(any(feature = "rprx", test))]
            vless_carriers,
        })
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
                runtime.tls.evict();
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
            let cleanup = tokio::spawn(async move { runtime.release_if_unretained().await });
            let _ = cleanup.await;
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
        runtime.client(build).await
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

    fn tls_connector_sample(&self) -> Option<(Instant, u64)> {
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => runtime.tls.sample(),
            ProtocolRuntime::None | ProtocolRuntime::Quic(_) => None,
            #[cfg(any(feature = "rprx", test))]
            ProtocolRuntime::Vless(_) => None,
        }
    }

    fn evict_tls_connector_if_sample(&self, sample: (Instant, u64)) -> bool {
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => runtime.tls.evict_if_sample(sample),
            ProtocolRuntime::None | ProtocolRuntime::Quic(_) => false,
            #[cfg(any(feature = "rprx", test))]
            ProtocolRuntime::Vless(_) => false,
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
    /// AnyTLS/VLESS mux pool teardown is synchronous and completes here;
    /// QUIC client teardown awaits locks, so it is handed to a runtime-driven
    /// task when one is available.
    pub fn request_close(&mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
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

    /// Close the runtime and await full teardown.
    pub async fn close(mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.close().await;
        }
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
        let dial_ceiling_limit = max_concurrent_dials.max(1);
        #[cfg(any(feature = "rprx", test))]
        let vless_carriers = previous.map_or_else(
            || Arc::clone(&STANDALONE_VLESS_CARRIERS),
            |previous| Arc::clone(&previous.vless_carrier_semaphore),
        );
        Self::build_reusing_with_admission(
            nodes,
            max_concurrent_dials,
            Arc::new(tokio::sync::Semaphore::new(dial_ceiling_limit)),
            dial_ceiling_limit,
            #[cfg(any(feature = "rprx", test))]
            vless_carriers,
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
            previous,
        )
    }

    fn build_reusing_with_admission(
        nodes: &[Node],
        max_concurrent_dials: usize,
        dial_ceiling_semaphore: Arc<tokio::sync::Semaphore>,
        dial_ceiling_limit: usize,
        #[cfg(any(feature = "rprx", test))] vless_carrier_semaphore: Arc<tokio::sync::Semaphore>,
        previous: Option<&Self>,
    ) -> Result<(Self, HashSet<uuid::Uuid>), RuntimeRegistryError> {
        honk_config::node::validate_node_collection(nodes)
            .map_err(RuntimeRegistryError::Admission)?;
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
                let runtime = previous.get(&node.id)?;
                same_node_config(&runtime.node, node).then_some(runtime)
            });
            let runtime = match reused_runtime {
                Some(runtime) => {
                    reused.insert(node.id);
                    runtime
                }
                None => Arc::new(NodeRuntime {
                    node: Arc::new(node.clone()),
                    udp_capable: (crate::descriptor::descriptor(node.protocol()).supports_udp)(
                        node,
                    ),
                    runtime: crate::descriptor::descriptor(node.protocol())
                        .generation_runtime
                        .build(node, true),
                    ephemeral: false,
                    warm_retention: Arc::new(tokio::sync::Mutex::new(0)),
                    #[cfg(any(feature = "rprx", test))]
                    vless_carriers: Arc::clone(&vless_carrier_semaphore),
                }),
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
                #[cfg(any(feature = "rprx", test))]
                vless_carrier_semaphore,
            },
            reused,
        ))
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

    /// Reap idle runtime resources while retaining each protocol's hot floor.
    /// AnyTLS keeps its recent connector working set; VLESS closes only idle
    /// carriers above explicit or runtime warm retention.
    pub fn reap_idle_resources(&self, now: Instant) -> usize {
        #[cfg(any(feature = "rprx", test))]
        let mut reaped = self
            .nodes
            .values()
            .filter_map(|runtime| match &runtime.runtime {
                ProtocolRuntime::Vless(vless) => Some(vless.reap_unretained_idle()),
                _ => None,
            })
            .sum();
        #[cfg(not(any(feature = "rprx", test)))]
        let mut reaped = 0;
        let anytls_count = self
            .nodes
            .values()
            .filter(|runtime| matches!(runtime.runtime, ProtocolRuntime::AnyTls(_)))
            .count();
        let target = anytls_count
            .saturating_mul(TLS_ACTIVE_RATIO_NUMERATOR)
            .div_ceil(TLS_ACTIVE_RATIO_DENOMINATOR)
            .max(TLS_ACTIVE_MIN)
            .min(anytls_count);
        let mut loaded: Vec<_> = self
            .nodes
            .values()
            .filter_map(|runtime| {
                runtime
                    .tls_connector_sample()
                    .map(|sample| (sample, runtime))
            })
            .collect();
        loaded.sort_unstable_by_key(|((used_at, _), _)| std::cmp::Reverse(*used_at));

        for (index, (sample, runtime)) in loaded.into_iter().enumerate() {
            if (index >= target || now.saturating_duration_since(sample.0) >= TLS_IDLE_RETENTION)
                && runtime.evict_tls_connector_if_sample(sample)
            {
                reaped += 1;
            }
        }
        reaped
    }

    /// Whether this generation has become terminal. Warm-up work must reject
    /// rather than consulting a replacement generation once this is true.
    pub fn is_shutdown(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }

    /// Make the generation unavailable to new generation-owned work without
    /// cutting streams that already own its sessions. The DNS runtime that
    /// captured this generation starts pool draining after its leases retire.
    pub fn begin_retirement(&self) {
        self.terminal.store(true, Ordering::Release);
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
        self.terminal.store(true, Ordering::Release);
        let moved_out: HashSet<uuid::Uuid> = self.moved_out.lock().clone();
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
