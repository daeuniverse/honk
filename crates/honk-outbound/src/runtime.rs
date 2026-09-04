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

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
const TLS_ACTIVE_RATIO_NUMERATOR: usize = 1;
const TLS_ACTIVE_RATIO_DENOMINATOR: usize = 10;
const TLS_ACTIVE_MIN: usize = 8;
pub const TLS_IDLE_RETENTION: Duration = Duration::from_secs(10 * 60);
pub const TLS_REAP_INTERVAL: Duration = Duration::from_secs(60);

use honk_config::node::Node;

/// The generation-scoped session runtime a protocol owns, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationRuntime {
    None,
    AnyTls,
    VlessH2Mux,
    VlessCoolMux,
    Quic,
}

impl GenerationRuntime {
    pub(crate) fn build(self, metrics_enabled: bool) -> ProtocolRuntime {
        match self {
            Self::None => ProtocolRuntime::None,
            Self::AnyTls => ProtocolRuntime::AnyTls(AnyTlsRuntime::new()),
            Self::VlessH2Mux => ProtocolRuntime::VlessMux(VlessMuxRuntime::h2()),
            Self::VlessCoolMux => ProtocolRuntime::VlessMux(VlessMuxRuntime::cool()),
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
    /// One concrete node-local H2MUX or Mux.Cool session pool.
    VlessMux(VlessMuxRuntime),
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
}

impl TlsConnectorSlot {
    fn get_or_build(&self, node: &Node) -> anyhow::Result<Arc<crate::tls::TlsConnector>> {
        let mut state = self.state.lock();
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

#[derive(Debug)]
pub enum VlessMuxRuntime {
    H2(Arc<crate::proxy::vless_mux::VlessMuxPool>),
    Cool(Arc<crate::proxy::vless_cool::VlessCoolPool>),
}

impl VlessMuxRuntime {
    fn h2() -> Self {
        Self::H2(Arc::new(crate::session::SessionPool::new(
            crate::proxy::vless_mux::session_pool_config(),
        )))
    }

    fn cool() -> Self {
        Self::Cool(Arc::new(crate::session::SessionPool::new(
            crate::proxy::vless_cool::session_pool_config(),
        )))
    }

    fn set_warm_retained(&self, retained: bool) {
        match self {
            Self::H2(pool) => pool.set_warm_retained(retained),
            Self::Cool(pool) => pool.set_warm_retained(retained),
        }
    }

    fn shutdown(&self) {
        match self {
            Self::H2(pool) => pool.shutdown(),
            Self::Cool(pool) => pool.shutdown(),
        }
    }

    fn retire(&self) {
        match self {
            Self::H2(pool) => pool.retire(),
            Self::Cool(pool) => pool.retire(),
        }
    }

    fn has_usable_session(&self) -> bool {
        match self {
            Self::H2(pool) => pool.has_usable_session(),
            Self::Cool(pool) => pool.has_usable_session(),
        }
    }

    fn live_session_count(&self) -> usize {
        match self {
            Self::H2(pool) => pool.live_session_count(),
            Self::Cool(pool) => pool.live_session_count(),
        }
    }

    #[cfg(test)]
    fn is_warm_retained(&self) -> bool {
        match self {
            Self::H2(pool) => pool.is_warm_retained(),
            Self::Cool(pool) => pool.is_warm_retained(),
        }
    }

    #[cfg(test)]
    fn is_retired(&self) -> bool {
        match self {
            Self::H2(pool) => pool.is_retired(),
            Self::Cool(pool) => pool.is_retired(),
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
        if *retention != 0 {
            return;
        }
        match &self.runtime.runtime {
            ProtocolRuntime::AnyTls(runtime) => {
                runtime.pool.set_warm_retained(false);
                runtime.tls.evict();
            }
            ProtocolRuntime::VlessMux(runtime) => runtime.set_warm_retained(false),
            ProtocolRuntime::Quic(_) => {
                drop(retention);
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    let runtime = Arc::clone(&self.runtime);
                    handle.spawn(async move { runtime.release_if_unretained().await });
                }
            }
            ProtocolRuntime::None => {}
        }
    }
}

impl NodeRuntime {
    /// A generation-free runtime for one-shot callers (standalone probing,
    /// tests): session protocols get a throwaway pool per runtime. The
    /// caller MUST [`Self::close`] it when done — an unclosed ephemeral
    /// pool keeps its demux-held sessions (and their connections) open
    /// forever. Prefer [`Self::ephemeral_guarded`], which closes on drop.
    pub fn ephemeral(node: &Node) -> Arc<Self> {
        Arc::new(Self {
            node: Arc::new(node.clone()),
            udp_capable: (crate::descriptor::descriptor(node.protocol()).supports_udp)(node),
            runtime: crate::descriptor::descriptor(node.protocol())
                .generation_runtime(node)
                .build(false),
            ephemeral: true,
            warm_retention: Arc::new(tokio::sync::Mutex::new(0)),
        })
    }

    /// [`Self::ephemeral`] wrapped in an ownership guard whose Drop starts
    /// the close, so timeout/abort paths that simply drop the probe future
    /// cannot leak the session-layer resources.
    pub fn ephemeral_guarded(node: &Node) -> EphemeralRuntimeGuard {
        EphemeralRuntimeGuard {
            runtime: Some(Self::ephemeral(node)),
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
        if was_unretained {
            match &self.runtime {
                ProtocolRuntime::AnyTls(runtime) => runtime.pool.set_warm_retained(true),
                ProtocolRuntime::VlessMux(runtime) => runtime.set_warm_retained(true),
                ProtocolRuntime::None | ProtocolRuntime::Quic(_) => {}
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
            ProtocolRuntime::VlessMux(runtime) => runtime.set_warm_retained(false),
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
            ProtocolRuntime::AnyTls(runtime) => runtime.pool.shutdown(),
            ProtocolRuntime::VlessMux(runtime) => runtime.shutdown(),
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

    #[cfg_attr(not(feature = "rprx"), allow(dead_code))]
    pub(crate) fn vless_h2_pool(
        &self,
    ) -> anyhow::Result<Arc<crate::proxy::vless_mux::VlessMuxPool>> {
        let ProtocolRuntime::VlessMux(VlessMuxRuntime::H2(pool)) = &self.runtime else {
            anyhow::bail!("node '{}' has no VLESS H2MUX runtime", self.node.name);
        };
        Ok(Arc::clone(pool))
    }

    #[cfg_attr(not(feature = "rprx"), allow(dead_code))]
    pub(crate) fn vless_cool_pool(
        &self,
    ) -> anyhow::Result<Arc<crate::proxy::vless_cool::VlessCoolPool>> {
        let ProtocolRuntime::VlessMux(VlessMuxRuntime::Cool(pool)) = &self.runtime else {
            anyhow::bail!("node '{}' has no VLESS Mux.Cool runtime", self.node.name);
        };
        Ok(Arc::clone(pool))
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

    /// Whether one-shot work should use this generation instead of an
    /// ephemeral runtime. Stateless protocols are always safe; session
    /// protocols qualify only when a reusable session/client exists or a
    /// QUIC client build already holds the slot lock.
    pub fn is_warm_or_stateless(&self) -> bool {
        match &self.runtime {
            ProtocolRuntime::None => true,
            ProtocolRuntime::AnyTls(runtime) => runtime.pool.has_usable_session(),
            ProtocolRuntime::VlessMux(runtime) => runtime.has_usable_session(),
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
            ProtocolRuntime::VlessMux(runtime) => WarmCounts {
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
            ProtocolRuntime::None | ProtocolRuntime::VlessMux(_) | ProtocolRuntime::Quic(_) => None,
        }
    }

    fn evict_tls_connector_if_sample(&self, sample: (Instant, u64)) -> bool {
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => runtime.tls.evict_if_sample(sample),
            ProtocolRuntime::None | ProtocolRuntime::VlessMux(_) | ProtocolRuntime::Quic(_) => {
                false
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn tls_connector_loaded(&self) -> bool {
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => runtime.tls.is_loaded(),
            ProtocolRuntime::None | ProtocolRuntime::VlessMux(_) | ProtocolRuntime::Quic(_) => {
                false
            }
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
            ProtocolRuntime::VlessMux(vless) => vless.shutdown(),
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
    let (mut a, b) = (a.clone(), b.clone());
    a.created_at = b.created_at;
    a.updated_at = b.updated_at;
    a == b
}

/// Registry build/validation errors. A failure here aborts the reload
/// (the current generation stays live).
#[derive(Debug, thiserror::Error)]
pub enum RuntimeRegistryError {
    #[error("node '{0}' has a nil UUID")]
    NilId(String),
    #[error("duplicate node UUID {0} (nodes '{1}' and '{2}')")]
    DuplicateId(uuid::Uuid, String, String),
    #[error("node '{node}' has invalid TLS configuration: {source}")]
    Tls {
        node: String,
        #[source]
        source: anyhow::Error,
    },
}

/// The single owner of per-node session runtimes for one config
/// generation. Rebuilt with the config; shutdown makes a generation
/// terminal before closing its owned pools so late work can never fall
/// through to a newer generation.
#[derive(Debug)]
pub struct OutboundRuntimeRegistry {
    nodes: HashMap<uuid::Uuid, Arc<NodeRuntime>>,
    terminal: AtomicBool,
    /// Runtimes a successor generation took over at the reload commit point.
    /// Recorded only after the successor is published, so an aborted reload
    /// leaves this generation's ownership untouched; drain/shutdown skip
    /// exactly these entries (the successor closes them as their full owner).
    moved_out: parking_lot::Mutex<HashSet<uuid::Uuid>>,
    /// Generation-local configured admission budget. The process-wide
    /// descriptor gate below is shared by every overlapping generation.
    dial_semaphore: Arc<tokio::sync::Semaphore>,
    dial_limit: usize,
    dial_ceiling_semaphore: Arc<tokio::sync::Semaphore>,
    dial_ceiling_limit: usize,
}
#[derive(Clone)]
struct DialAdmission {
    generation: Arc<tokio::sync::Semaphore>,
    process: Arc<tokio::sync::Semaphore>,
}

impl DialAdmission {
    fn for_registry(registry: &OutboundRuntimeRegistry) -> Self {
        Self {
            generation: Arc::clone(&registry.dial_semaphore),
            process: Arc::clone(&registry.dial_ceiling_semaphore),
        }
    }

    fn standalone() -> Self {
        STANDALONE_DIAL_ADMISSION.clone()
    }

    fn matches_registry(&self, registry: &OutboundRuntimeRegistry) -> bool {
        Arc::ptr_eq(&self.generation, &registry.dial_semaphore)
            && Arc::ptr_eq(&self.process, &registry.dial_ceiling_semaphore)
    }

    async fn acquire(self) -> DialPermit {
        let generation = Arc::clone(&self.generation)
            .acquire_owned()
            .await
            .expect("dial semaphore is never closed");
        let process = Arc::clone(&self.process)
            .acquire_owned()
            .await
            .expect("dial ceiling semaphore is never closed");
        DialPermit {
            _generation: generation,
            _process: process,
        }
    }
}

static STANDALONE_DIAL_ADMISSION: LazyLock<DialAdmission> = LazyLock::new(|| DialAdmission {
    generation: Arc::new(tokio::sync::Semaphore::new(
        tokio::sync::Semaphore::MAX_PERMITS,
    )),
    process: Arc::new(tokio::sync::Semaphore::new(
        tokio::sync::Semaphore::MAX_PERMITS,
    )),
});

type DialStart = Arc<parking_lot::Mutex<Option<Box<dyn FnOnce() + Send>>>>;

#[derive(Default)]
struct HeldDialPermits {
    first: Option<DialPermit>,
    extra: Vec<DialPermit>,
}

struct DialScope {
    admission: DialAdmission,
    held: parking_lot::Mutex<HeldDialPermits>,
    on_start: Option<DialStart>,
}

impl DialScope {
    fn new(admission: DialAdmission, on_start: Option<DialStart>) -> Arc<Self> {
        Arc::new(Self {
            admission,
            held: parking_lot::Mutex::new(HeldDialPermits::default()),
            on_start,
        })
    }

    fn start(&self) {
        let callback = self
            .on_start
            .as_ref()
            .and_then(|callback| callback.lock().take());
        if let Some(callback) = callback {
            callback();
        }
    }
}

tokio::task_local! {
    static DIAL_SCOPE: Arc<DialScope>;
}

/// One physical proxy dial admitted by both its generation and the shared
/// process descriptor partition.
pub struct DialPermit {
    _generation: tokio::sync::OwnedSemaphorePermit,
    _process: tokio::sync::OwnedSemaphorePermit,
}

/// Captured logical operation state for spawned child work. Clones share
/// successful permits and the first-dial callback with their parent.
#[derive(Clone)]
pub(crate) struct CapturedDialScope(Arc<DialScope>);

impl CapturedDialScope {
    fn standalone() -> Self {
        Self(DialScope::new(DialAdmission::standalone(), None))
    }

    pub(crate) async fn scope<F>(self, future: F) -> F::Output
    where
        F: Future,
    {
        DIAL_SCOPE.scope(self.0, future).await
    }
}

/// Reusable admission identity for autonomous dial operations. Each scoped
/// future receives its own permit-holding operation scope.
#[derive(Clone)]
pub(crate) struct CapturedDialAdmission(DialAdmission);

impl CapturedDialAdmission {
    fn standalone() -> Self {
        Self(DialAdmission::standalone())
    }

    pub(crate) async fn scope<F>(self, future: F) -> F::Output
    where
        F: Future,
    {
        DIAL_SCOPE
            .scope(DialScope::new(self.0, None), future)
            .await
    }

    #[cfg(test)]
    pub(crate) fn matches_registry(&self, registry: &OutboundRuntimeRegistry) -> bool {
        self.0.matches_registry(registry)
    }
}

pub(crate) fn capture_dial_scope() -> CapturedDialScope {
    DIAL_SCOPE
        .try_with(|scope| CapturedDialScope(Arc::clone(scope)))
        .unwrap_or_else(|_| CapturedDialScope::standalone())
}

pub(crate) fn try_capture_dial_admission() -> Option<CapturedDialAdmission> {
    DIAL_SCOPE
        .try_with(|scope| CapturedDialAdmission(scope.admission.clone()))
        .ok()
}

pub(crate) fn capture_dial_admission() -> CapturedDialAdmission {
    try_capture_dial_admission().unwrap_or_else(CapturedDialAdmission::standalone)
}

pub(crate) async fn admit_physical_dial<T, E, F>(future: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let scope = DIAL_SCOPE.try_with(Arc::clone).ok();
    let permit = match &scope {
        Some(scope) => scope.admission.clone().acquire().await,
        None => DialAdmission::standalone().acquire().await,
    };
    if let Some(scope) = &scope {
        scope.start();
    }
    let result = future.await;
    if result.is_ok()
        && let Some(scope) = scope
    {
        let mut held = scope.held.lock();
        if held.first.is_none() {
            held.first = Some(permit);
        } else {
            held.extra.push(permit);
        }
    }
    result
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

    /// Build with a generation-local dial limit. Descriptor-aware owners that
    /// overlap generations should use [`Self::build_reusing_with_dial_ceiling`].
    pub fn build_reusing(
        nodes: &[Node],
        max_concurrent_dials: usize,
        previous: Option<&Self>,
    ) -> Result<(Self, HashSet<uuid::Uuid>), RuntimeRegistryError> {
        let dial_ceiling_limit = max_concurrent_dials.max(1);
        Self::build_reusing_with_admission(
            nodes,
            max_concurrent_dials,
            Arc::new(tokio::sync::Semaphore::new(dial_ceiling_limit)),
            dial_ceiling_limit,
            previous,
        )
    }

    /// Build while sharing one immutable process-wide dial descriptor ceiling
    /// with `previous`. A successor may change its generation-local configured
    /// limit, but old and new permits together never exceed the startup gate.
    pub fn build_reusing_with_dial_ceiling(
        nodes: &[Node],
        max_concurrent_dials: usize,
        startup_dial_ceiling: usize,
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
        Self::build_reusing_with_admission(
            nodes,
            max_concurrent_dials,
            dial_ceiling_semaphore,
            dial_ceiling_limit,
            previous,
        )
    }

    fn build_reusing_with_admission(
        nodes: &[Node],
        max_concurrent_dials: usize,
        dial_ceiling_semaphore: Arc<tokio::sync::Semaphore>,
        dial_ceiling_limit: usize,
        previous: Option<&Self>,
    ) -> Result<(Self, HashSet<uuid::Uuid>), RuntimeRegistryError> {
        let mut map = HashMap::with_capacity(nodes.len());
        let mut reused = HashSet::new();
        for node in nodes {
            if node.id.is_nil() {
                return Err(RuntimeRegistryError::NilId(node.name.clone()));
            }
            // Validate cheap, fail-closed TLS inputs before publishing the
            // generation. The heavyweight SSL_CTX/root store stays lazy.
            if node.tls().is_some_and(|tls| tls.enabled) {
                crate::tls::validate_connector_config(node).map_err(|source| {
                    RuntimeRegistryError::Tls {
                        node: node.name.clone(),
                        source,
                    }
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
                        .generation_runtime(node)
                        .build(true),
                    ephemeral: false,
                    warm_retention: Arc::new(tokio::sync::Mutex::new(0)),
                }),
            };
            if let Some(prev) = map.insert(node.id, runtime) {
                return Err(RuntimeRegistryError::DuplicateId(
                    node.id,
                    prev.node.name.clone(),
                    node.name.clone(),
                ));
            }
        }
        Ok((
            Self {
                nodes: map,
                terminal: AtomicBool::new(false),
                moved_out: parking_lot::Mutex::new(HashSet::new()),
                dial_semaphore: Arc::new(tokio::sync::Semaphore::new(
                    max_concurrent_dials.max(1).min(dial_ceiling_limit),
                )),
                dial_limit: max_concurrent_dials.max(1).min(dial_ceiling_limit),
                dial_ceiling_semaphore,
                dial_ceiling_limit,
            },
            reused,
        ))
    }

    /// Wrap into the shared cell used by the control plane.
    pub fn into_shared(self) -> SharedRuntimeRegistry {
        Arc::new(parking_lot::RwLock::new(Arc::new(self)))
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

    /// Retain the most recently used AnyTLS connectors as the hot working set.
    /// Idle entries are always released; under a broad burst, the newest 10%
    /// (at least eight) remain ready so common nodes avoid connector rebuilds.
    pub fn reap_tls_connectors(&self, now: Instant) -> usize {
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

        let mut evicted = 0;
        for (index, (sample, runtime)) in loaded.into_iter().enumerate() {
            if (index >= target || now.saturating_duration_since(sample.0) >= TLS_IDLE_RETENTION)
                && runtime.evict_tls_connector_if_sample(sample)
            {
                evicted += 1;
            }
        }
        evicted
    }

    /// Whether this generation has become terminal. Warm-up work must reject
    /// rather than consulting a replacement generation once this is true.
    pub fn is_shutdown(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }

    /// Configured admission ceiling for this immutable generation.
    pub fn dial_limit(&self) -> usize {
        self.dial_limit
    }

    /// Acquire generation-local admission before the shared process gate so
    /// low configured limits cannot hoard process capacity while waiting.
    pub async fn acquire_dial_permit(&self) -> DialPermit {
        DialAdmission::for_registry(self).acquire().await
    }

    /// Bind physical attempts made by `future` to this generation's gates.
    /// Nested dispatch through the same registry keeps the existing scope.
    pub async fn scope_dials<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        if DIAL_SCOPE
            .try_with(|scope| scope.admission.matches_registry(self))
            .unwrap_or(false)
        {
            return future.await;
        }
        DIAL_SCOPE
            .scope(
                DialScope::new(DialAdmission::for_registry(self), None),
                future,
            )
            .await
    }

    /// As [`Self::scope_dials`], starting feedback at the first admitted
    /// physical attempt. A warm logical dial starts feedback on completion.
    pub async fn scope_dials_with_start<F, C>(&self, future: F, on_start: C) -> F::Output
    where
        F: Future,
        C: FnOnce() + Send + 'static,
    {
        let callback: DialStart = Arc::new(parking_lot::Mutex::new(Some(Box::new(on_start))));
        let scope = DialScope::new(DialAdmission::for_registry(self), Some(callback));
        let output = DIAL_SCOPE.scope(Arc::clone(&scope), future).await;
        scope.start();
        output
    }

    /// Make the generation unavailable to new generation-owned work without
    /// cutting streams that already own its sessions. The DNS runtime that
    /// captured this generation starts pool draining after its leases retire.
    pub fn begin_retirement(&self) {
        self.terminal.store(true, Ordering::Release);
    }

    /// Rebind autonomous AnyTLS replacement dials after this generation is
    /// published. Reused pools must stop consulting the predecessor's gate.
    pub fn activate_background_dial_admission(&self) {
        let admission = CapturedDialAdmission(DialAdmission::for_registry(self));
        for runtime in self.nodes.values() {
            if let ProtocolRuntime::AnyTls(anytls) = &runtime.runtime {
                anytls.pool.set_dial_admission(admission.clone());
            }
        }
    }

    /// Record runtimes a published successor generation has taken over.
    /// Called only at the reload commit point (after the successor registry
    /// replaces this one); this generation then leaves those runtimes alone
    /// at drain/shutdown — the successor owns and closes them.
    pub fn mark_moved_out(&self, ids: impl IntoIterator<Item = uuid::Uuid>) {
        self.moved_out.lock().extend(ids);
    }

    /// Reject new pool work and let published sessions close after their last
    /// stream releases. Existing streams remain usable while draining.
    /// Runtimes transferred to a successor generation are left alone. QUIC
    /// connections need no drain step: new work is rejected by the terminal
    /// flag at the registry checks, and in-flight flows keep their
    /// connections until they finish.
    pub fn drain_session_pools(&self) {
        self.begin_retirement();
        let moved_out = self.moved_out.lock();
        for (id, runtime) in &self.nodes {
            if moved_out.contains(id) {
                continue;
            }
            match &runtime.runtime {
                ProtocolRuntime::AnyTls(anytls) => anytls.pool.retire(),
                ProtocolRuntime::VlessMux(vless) => vless.retire(),
                ProtocolRuntime::None | ProtocolRuntime::Quic(_) => {}
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
