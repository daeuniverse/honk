//! One mode/target owner for routing and composed datapath flags.
//! Native-enabled processes use transient identities; legacy Clash-only
//! processes continue restoring and persisting their name-based selection.

use std::sync::Arc;

use anyhow::Context;
type SharedEbpfBackend = Arc<tokio::sync::RwLock<Box<dyn crate::ebpf::EbpfBackend>>>;

/// Shared outbound mode; native targets retain identity rather than display names.
#[derive(Debug, Clone)]
pub struct ModeState {
    /// Canonical clash mode: `"Rule"` | `"Global"` | `"Direct"`.
    pub mode: String,
    pub(crate) selection: Selection,
    #[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
    pub(crate) source: ModeSource,
}

/// The GLOBAL selection: a persisted name for legacy Clash-only processes, a
/// transient identity when native is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Selection {
    Name(String),
    #[cfg(feature = "native-api")]
    Target(Option<ModeTarget>),
}

/// Shared routing snapshot, published only through [`DatapathFlagsHandle`].
pub type SharedModeState = Arc<parking_lot::RwLock<ModeState>>;

#[cfg(feature = "native-api")]
#[cfg_attr(not(any(feature = "clash-api", test)), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ModeTarget {
    Node { id: uuid::Uuid, name: String },
    Group { id: String, name: String },
}

#[cfg(feature = "native-api")]
impl ModeTarget {
    #[cfg(any(feature = "clash-api", test))]
    pub(crate) fn from_name(
        name: &str,
        config: &honk_config::Config,
        groups: &std::collections::HashMap<String, String>,
    ) -> Option<Self> {
        let mut nodes = config.nodes.iter().filter(|node| node.name == name);
        let node = nodes.next();
        let group = groups.get(name);
        if nodes.next().is_some() || (node.is_some() && group.is_some()) {
            return None;
        }
        match (node, group) {
            (Some(node), None) => Some(Self::Node {
                id: node.id,
                name: node.name.clone(),
            }),
            (None, Some(id)) => Some(Self::Group {
                id: id.clone(),
                name: name.to_owned(),
            }),
            _ => None,
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Node { name, .. } | Self::Group { name, .. } => name,
        }
    }

    #[cfg(any(feature = "clash-api", test))]
    fn present(
        &self,
        config: &honk_config::Config,
        groups: &std::collections::HashMap<String, String>,
    ) -> bool {
        match self {
            Self::Node { id, .. } => config.nodes.iter().any(|node| node.id == *id),
            Self::Group { id, name } => groups.get(name) == Some(id),
        }
    }
}

#[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModeSource {
    Config,
    Runtime,
}

#[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ModeOverride {
    Unchanged,
    Direct,
    Block,
    Node(uuid::Uuid),
    Group(String),
}

impl ModeState {
    /// Create a new state; an unrecognized `mode` falls back to `Rule`.
    pub fn new(mode: &str, global_selection: impl Into<String>) -> Self {
        Self {
            mode: Self::normalize(mode).unwrap_or_else(|| "Rule".to_string()),
            selection: Selection::Name(global_selection.into()),
            #[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
            source: ModeSource::Config,
        }
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn native() -> Self {
        Self {
            selection: Selection::Target(None),
            ..Self::new("Rule", "")
        }
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn is_native(&self) -> bool {
        matches!(self.selection, Selection::Target(_))
    }

    /// Clash GLOBAL display name; native routing uses the target, never this name.
    pub fn global_selection(&self) -> &str {
        match &self.selection {
            Selection::Name(name) => name,
            #[cfg(feature = "native-api")]
            Selection::Target(target) => target.as_ref().map_or("", ModeTarget::name),
        }
    }

    /// Call with the accepted config and catalog under the config read barrier.
    /// The returned node identity must remain typed through candidate selection.
    #[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
    pub(crate) fn native_override(
        &self,
        outbound: &str,
        must: bool,
        config: &honk_config::Config,
        groups: &std::collections::HashMap<String, String>,
    ) -> ModeOverride {
        let Selection::Target(target) = &self.selection else {
            return ModeOverride::Unchanged;
        };
        if must || outbound == "block" || self.is_rule() {
            return ModeOverride::Unchanged;
        }
        if self.is_direct() {
            return ModeOverride::Direct;
        }
        match target
            .as_ref()
            .filter(|target| target.present(config, groups))
        {
            Some(ModeTarget::Node { id, .. }) => ModeOverride::Node(*id),
            Some(ModeTarget::Group { name, .. }) => ModeOverride::Group(name.clone()),
            None => ModeOverride::Block,
        }
    }

    /// Normalize a mode string to canonical case (`"global"` → `"Global"`).
    /// Returns `None` for values outside Rule/Global/Direct.
    pub fn normalize(mode: &str) -> Option<String> {
        if mode.eq_ignore_ascii_case("rule") {
            Some("Rule".to_string())
        } else if mode.eq_ignore_ascii_case("global") {
            Some("Global".to_string())
        } else if mode.eq_ignore_ascii_case("direct") {
            Some("Direct".to_string())
        } else {
            None
        }
    }

    /// Whether the current mode is `Direct`.
    pub fn is_direct(&self) -> bool {
        self.mode.eq_ignore_ascii_case("direct")
    }

    /// Whether the current mode is `Rule` — in `Rule` the mode override is
    /// the identity, so the eBPF datapath may offload non-`must` `direct`
    /// flows (subject to the domain-rule constraint).
    pub fn is_rule(&self) -> bool {
        self.mode.eq_ignore_ascii_case("rule")
    }

    /// Whether the current mode is `Global`.
    pub fn is_global(&self) -> bool {
        self.mode.eq_ignore_ascii_case("global")
    }

    /// The mode-dependent part of the eBPF datapath policy.
    pub fn direct_offload_mode_bits(&self) -> u32 {
        if self.is_global() {
            let direct = match &self.selection {
                Selection::Name(name) => name == "direct",
                #[cfg(feature = "native-api")]
                Selection::Target(target) => {
                    matches!(target, Some(ModeTarget::Node { id, .. }) if *id == honk_config::config::DIRECT_NODE_ID)
                }
            };
            return if direct {
                honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_ALL
            } else {
                0
            };
        }
        if self.is_direct() {
            honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_ALL
        } else if self.is_rule() {
            honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_RULE_DIRECT
        } else {
            0
        }
    }

    /// Legacy name-based override, preserving final `must` and `block` decisions.
    /// An unresolved legacy Global selection retains the ordinary route.
    /// Native Global is deliberately blocked here: its caller must use the typed
    /// identity returned by `native_override`, not collapse it into a display name.
    pub fn override_outbound(
        &self,
        outbound_name: &str,
        must: bool,
        selection_resolvable: bool,
    ) -> String {
        if must || outbound_name == "block" {
            return outbound_name.to_string();
        }
        if self.is_direct() {
            return "direct".to_string();
        }
        if self.is_global() {
            match &self.selection {
                Selection::Name(name) if !name.is_empty() && selection_resolvable => {
                    return name.clone();
                }
                Selection::Name(_) => {}
                // Native callers must carry the identity, not downgrade to a display name.
                #[cfg(feature = "native-api")]
                Selection::Target(_) => return "block".to_owned(),
            }
        }
        outbound_name.to_string()
    }
}

/// Apply a request under the command owner's reload lock and config read barrier.
#[cfg(all(feature = "native-api", feature = "clash-api"))]
pub(crate) async fn apply_mode_request(
    config: &honk_config::Config,
    groups: &std::collections::HashMap<String, String>,
    flags: &DatapathFlagsHandle,
    request: crate::control::client::ModeRequest,
) -> Result<ModeState, crate::control::client::ControlError> {
    use crate::control::client::{ControlError, ModeRequest};

    match request {
        ModeRequest::ClashMode(mode) => {
            if ModeState::normalize(&mode).is_none() {
                return Err(ControlError::Unsupported);
            }
            flags.set_clash_mode(&mode, config, groups).await
        }
        ModeRequest::ClashSelection(selection) => {
            if flags.snapshot().is_native()
                && ModeTarget::from_name(&selection, config, groups).is_none()
            {
                return Err(ControlError::Unsupported);
            }
            flags
                .set_clash_global_selection(selection, config, groups)
                .await
        }
    }
    .map_err(|error| {
        tracing::warn!(%error, "mode publication failed");
        ControlError::Unavailable
    })
}

#[cfg(all(test, feature = "native-api"))]
mod request_tests;

#[derive(Clone)]
pub struct DatapathFlagsHandle {
    inner: Arc<tokio::sync::Mutex<DatapathFlagsInner>>,
    mode_state: SharedModeState,
}

#[derive(Clone)]
struct DatapathFlagsState {
    nfqueue_enabled: bool,
    nfqueue_ready: bool,
    trace_enabled: bool,
    initialized: bool,
    quiescence_failed: bool,
}

impl DatapathFlagsState {
    fn compose(&self, mode: &ModeState) -> u32 {
        let mut flags = mode.direct_offload_mode_bits();
        if self.nfqueue_enabled {
            flags |= honk_ebpf_common::DATAPATH_FLAG_NFQ_ENABLED;
            if self.nfqueue_ready {
                flags |= honk_ebpf_common::DATAPATH_FLAG_NFQ_READY;
            }
        }
        if self.trace_enabled {
            flags |= honk_ebpf_common::DATAPATH_FLAG_TRACE_ENABLED;
        }
        flags
    }
}

enum Persistence {
    None,
    Mode,
    Global,
}

struct DatapathFlagsInner {
    backend: SharedEbpfBackend,
    mode_state: SharedModeState,
    cache_db: Option<Arc<crate::state::cache::CacheDb>>,
    state: DatapathFlagsState,
}

impl DatapathFlagsHandle {
    pub fn new(
        backend: SharedEbpfBackend,
        mode_state: SharedModeState,
        cache_db: Option<Arc<crate::state::cache::CacheDb>>,
    ) -> Self {
        Self {
            mode_state: Arc::clone(&mode_state),
            inner: Arc::new(tokio::sync::Mutex::new(DatapathFlagsInner {
                backend,
                mode_state,
                cache_db,
                state: DatapathFlagsState {
                    nfqueue_enabled: false,
                    nfqueue_ready: false,
                    trace_enabled: false,
                    initialized: false,
                    quiescence_failed: false,
                },
            })),
        }
    }

    pub fn snapshot(&self) -> ModeState {
        self.mode_state.read().clone()
    }

    /// Clash participates in the same transient identity owner when native is enabled.
    #[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
    pub(crate) async fn set_clash_mode(
        &self,
        mode: &str,
        config: &honk_config::Config,
        groups: &std::collections::HashMap<String, String>,
    ) -> anyhow::Result<ModeState> {
        let mode = ModeState::normalize(mode).context("invalid clash mode")?;
        self.update(false, move |state, current| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            if let Selection::Target(target) = &mut current.selection {
                if mode == "Global" {
                    // Never replace a stale pinned identity by today's same-name object.
                    if target.is_none() {
                        *target = config
                            .groups
                            .iter()
                            .find_map(|group| {
                                groups.get(&group.name).map(|id| ModeTarget::Group {
                                    id: id.clone(),
                                    name: group.name.clone(),
                                })
                            })
                            .or_else(|| {
                                config.nodes.first().map(|node| ModeTarget::Node {
                                    id: node.id,
                                    name: node.name.clone(),
                                })
                            });
                    }
                    anyhow::ensure!(
                        target
                            .as_ref()
                            .is_some_and(|target| target.present(config, groups)),
                        "mode target is unavailable"
                    );
                }
                current.source = ModeSource::Runtime;
            }
            current.mode = mode;
            Ok(Persistence::Mode)
        })
        .await
    }

    #[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
    pub(crate) async fn set_clash_global_selection(
        &self,
        selection: String,
        config: &honk_config::Config,
        groups: &std::collections::HashMap<String, String>,
    ) -> anyhow::Result<ModeState> {
        self.update(false, move |state, current| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            current.selection = if current.is_native() {
                current.source = ModeSource::Runtime;
                Selection::Target(Some(
                    ModeTarget::from_name(&selection, config, groups)
                        .context("unknown or ambiguous GLOBAL selection")?,
                ))
            } else {
                Selection::Name(selection)
            };
            Ok(Persistence::Global)
        })
        .await
    }

    /// Lock after config, before backend. Drop before calling any other flags method.
    #[cfg(feature = "native-api")]
    pub(crate) async fn publication(&self) -> DatapathFlagsPublication<'_> {
        DatapathFlagsPublication {
            inner: self.inner.lock().await,
        }
    }

    async fn update(
        &self,
        quiesce: bool,
        change: impl FnOnce(&mut DatapathFlagsState, &mut ModeState) -> anyhow::Result<Persistence>,
    ) -> anyhow::Result<ModeState> {
        let mut inner = self.inner.lock().await;
        let mut state = inner.state.clone();
        let mut mode = inner.mode_state.read().clone();
        let persistence = change(&mut state, &mut mode)?;
        let flags = state.compose(&mode);
        let quiescence = {
            let mut backend = inner.backend.write().await;
            backend
                .set_datapath_flags(flags)
                .with_context(|| format!("failed to publish datapath flags {flags:#010x}"))?;
            if quiesce {
                backend
                    .quiesce_udp_staging()
                    .context("failed to quiesce staged UDP decisions")
            } else {
                Ok(())
            }
        };
        if quiesce {
            state.quiescence_failed = quiescence.is_err();
        }
        inner.state = state;
        *inner.mode_state.write() = mode.clone();
        // The flags write already fenced READY even if staged-state cleanup failed.
        quiescence?;
        #[cfg(feature = "native-api")]
        let persist = !mode.is_native();
        #[cfg(not(feature = "native-api"))]
        let persist = true;
        if let Some(db) = &inner.cache_db
            && persist
        {
            match persistence {
                Persistence::None => {}
                Persistence::Mode => db.save_clash_mode(&mode.mode),
                Persistence::Global => db.save_clash_global(mode.global_selection()),
            }
        }
        Ok(mode)
    }

    pub async fn initialize(
        &self,
        nfqueue_enabled: bool,
        nfqueue_ready: bool,
    ) -> anyhow::Result<()> {
        self.update(false, |state, _| {
            anyhow::ensure!(!state.initialized, "datapath flags are already initialized");
            state.nfqueue_enabled = nfqueue_enabled;
            state.nfqueue_ready = nfqueue_enabled && nfqueue_ready;
            state.initialized = true;
            state.quiescence_failed = false;
            Ok(Persistence::None)
        })
        .await
        .map(|_| ())
    }

    /// Optional observation only: retain the applied state on write failure and
    /// retry on the next maintenance pass without fencing business traffic.
    /// `recording` must be a side-effect-free effective Settings snapshot.
    #[cfg(feature = "native-api")]
    pub(crate) async fn reconcile_kernel_trace(
        &self,
        recording: impl Fn() -> bool,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().await;
        if !inner.state.initialized || inner.state.trace_enabled == recording() {
            return Ok(());
        }
        let backend = Arc::clone(&inner.backend);
        let mut backend = backend.write().await;
        // Demand may have changed while waiting for either publication lock.
        // The callback takes only a synchronous Settings snapshot, never a guard
        // across await; terminal disable cannot be undone by this publisher.
        let enabled = recording();
        if inner.state.trace_enabled == enabled {
            return Ok(());
        }
        let mut next = inner.state.clone();
        next.trace_enabled = enabled;
        let flags = next.compose(&inner.mode_state.read());
        backend
            .set_datapath_flags(flags)
            .context("failed to publish kernel trace admission")?;
        inner.state = next;
        Ok(())
    }

    pub async fn set_mode(&self, mode: &str) -> anyhow::Result<()> {
        let mode = ModeState::normalize(mode).context("invalid clash mode")?;
        self.update(false, move |state, current| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            #[cfg(feature = "native-api")]
            anyhow::ensure!(
                !current.is_native(),
                "native mode requires identity-aware control"
            );
            current.mode = mode;
            Ok(Persistence::Mode)
        })
        .await
        .map(|_| ())
    }

    pub async fn set_global_selection(&self, selection: String) -> anyhow::Result<()> {
        self.update(false, move |state, mode| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            #[cfg(feature = "native-api")]
            anyhow::ensure!(
                !mode.is_native(),
                "native selection requires identity-aware control"
            );
            mode.selection = Selection::Name(selection);
            Ok(Persistence::Global)
        })
        .await
        .map(|_| ())
    }

    pub async fn fence_nfqueue(&self) -> anyhow::Result<()> {
        self.update(true, |state, _| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            state.nfqueue_ready = false;
            Ok(Persistence::None)
        })
        .await
        .map(|_| ())
    }

    pub async fn reopen_nfqueue(&self) -> anyhow::Result<()> {
        self.update(false, |state, _| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            anyhow::ensure!(
                !state.quiescence_failed,
                "NFQUEUE requires a complete fence before reopening"
            );
            state.nfqueue_ready = state.nfqueue_enabled;
            Ok(Persistence::None)
        })
        .await
        .map(|_| ())
    }

    pub async fn disable(&self) -> anyhow::Result<()> {
        self.update(false, |state, _| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            state.nfqueue_enabled = false;
            state.nfqueue_ready = false;
            state.trace_enabled = false;
            state.initialized = false;
            Ok(Persistence::None)
        })
        .await
        .map(|_| ())
    }
}

#[cfg(feature = "native-api")]
pub(crate) struct DatapathFlagsPublication<'a> {
    inner: tokio::sync::MutexGuard<'a, DatapathFlagsInner>,
}

#[cfg(feature = "native-api")]
impl DatapathFlagsPublication<'_> {
    /// No await or flags/backend acquisition; uses the already-owned publication backend.
    /// Failure leaves the previous mode/source intact. After routing-root commit the
    /// caller must commit degraded and keep admission closed, not report rejection.
    pub(crate) fn reset_for_activation(
        &mut self,
        backend: &mut dyn crate::ebpf::EbpfBackend,
    ) -> anyhow::Result<()> {
        if !self.inner.mode_state.read().is_native() {
            return Ok(());
        }
        anyhow::ensure!(
            self.inner.state.initialized,
            "datapath flags are not initialized"
        );
        let mode = ModeState::native();
        backend
            .set_datapath_flags(self.inner.state.compose(&mode))
            .context("failed to reset runtime mode")?;
        *self.inner.mode_state.write() = mode;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_offload_mode_bits() {
        use honk_ebpf_common::{
            DATAPATH_FLAG_OFFLOAD_ALL as ALL, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as RULE,
        };
        assert_eq!(
            ModeState::new("rule", "proxy").direct_offload_mode_bits(),
            RULE
        );
        assert_eq!(
            ModeState::new("direct", "proxy").direct_offload_mode_bits(),
            ALL
        );
        assert_eq!(
            ModeState::new("global", "direct").direct_offload_mode_bits(),
            ALL
        );
        assert_eq!(
            ModeState::new("global", "Direct").direct_offload_mode_bits(),
            0
        );
        assert_eq!(
            ModeState::new("global", "proxy").direct_offload_mode_bits(),
            0
        );
    }

    #[test]
    fn test_normalize() {
        assert_eq!(ModeState::normalize("rule").as_deref(), Some("Rule"));
        assert_eq!(ModeState::normalize("GLOBAL").as_deref(), Some("Global"));
        assert_eq!(ModeState::normalize("Direct").as_deref(), Some("Direct"));
        assert_eq!(ModeState::normalize("bogus"), None);
    }

    #[test]
    fn test_new_fallback() {
        let s = ModeState::new("bogus", "proxy");
        assert_eq!(s.mode, "Rule");
        assert_eq!(s.global_selection(), "proxy");
        assert!(!s.is_direct());
        assert!(!s.is_global());
    }

    #[test]
    fn test_override_outbound_rule_mode_keeps_routing() {
        let s = ModeState::new("rule", "proxy");
        assert_eq!(s.override_outbound("proxy", false, true), "proxy");
        assert_eq!(s.override_outbound("direct", false, true), "direct");
    }

    #[test]
    fn test_override_outbound_direct_and_global() {
        let direct = ModeState::new("direct", "proxy");
        assert_eq!(direct.override_outbound("proxy", false, true), "direct");

        let global = ModeState::new("global", "proxy");
        assert_eq!(global.override_outbound("other", false, true), "proxy");
        // Unresolvable GLOBAL selection keeps the routed outbound.
        assert_eq!(global.override_outbound("other", false, false), "other");
        // Empty selection behaves the same way.
        let empty = ModeState::new("global", "");
        assert_eq!(empty.override_outbound("other", false, true), "other");
    }

    #[test]
    fn test_override_outbound_block_never_overridden() {
        let direct = ModeState::new("direct", "proxy");
        let global = ModeState::new("global", "proxy");
        assert_eq!(direct.override_outbound("block", false, true), "block");
        assert_eq!(global.override_outbound("block", false, true), "block");
    }

    /// dae must-rule semantics: a `(must)` routing result is final and
    /// must survive Direct/Global mode switches, exactly like `block`.
    #[test]
    fn test_override_outbound_must_never_overridden() {
        let rule = ModeState::new("rule", "proxy");
        let direct = ModeState::new("direct", "proxy");
        let global = ModeState::new("global", "proxy");
        for state in [&rule, &direct, &global] {
            assert_eq!(state.override_outbound("proxy", true, true), "proxy");
            assert_eq!(state.override_outbound("direct", true, true), "direct");
            assert_eq!(state.override_outbound("block", true, true), "block");
        }
    }

    type FlagsFixture = (
        DatapathFlagsHandle,
        SharedModeState,
        Arc<parking_lot::Mutex<Vec<u32>>>,
        SharedEbpfBackend,
    );

    fn flags_fixture() -> FlagsFixture {
        let backend = crate::ebpf::mock::MockEbpfBackend::new();
        let writes = backend.datapath_flags_writes.clone();
        let backend: SharedEbpfBackend = Arc::new(tokio::sync::RwLock::new(Box::new(backend)));
        let state = Arc::new(parking_lot::RwLock::new(ModeState::new("Rule", "Proxy")));
        let handle = DatapathFlagsHandle::new(Arc::clone(&backend), Arc::clone(&state), None);
        (handle, state, writes, backend)
    }

    #[tokio::test]
    async fn flags_fence_wins_racing_mode_and_global_updates() {
        use honk_ebpf_common::{
            DATAPATH_FLAG_NFQ_ENABLED as ENABLED, DATAPATH_FLAG_NFQ_READY as READY,
            DATAPATH_FLAG_OFFLOAD_ALL as ALL,
        };

        let (handle, state, writes, _) = flags_fixture();
        handle.initialize(true, true).await.unwrap();
        handle.fence_nfqueue().await.unwrap();
        let fenced_at = writes.lock().len();
        let (mode_result, selection_result) = tokio::join!(
            handle.set_mode("Global"),
            handle.set_global_selection("direct".to_string()),
        );
        mode_result.unwrap();
        selection_result.unwrap();
        assert_eq!(state.read().mode, "Global");
        assert_eq!(state.read().global_selection(), "direct");
        assert!(
            writes.lock()[fenced_at..]
                .iter()
                .all(|flags| flags & READY == 0)
        );
        handle.reopen_nfqueue().await.unwrap();
        assert_eq!(writes.lock().last().copied(), Some(ALL | ENABLED | READY));
    }

    #[tokio::test]
    async fn flags_fence_quiesces_undelivered_staged_state() {
        use honk_ebpf_common::conn::{ConnState, UdpDecisionState};

        let key = honk_ebpf_common::redirect_need::TuplesKey::default();
        let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
        mock.seed_staged_udp_flow(
            &key,
            ConnState {
                state: UdpDecisionState::Pending as u8,
                decision_token: 41,
                ..ConnState::default()
            },
        );
        let backend: SharedEbpfBackend = Arc::new(tokio::sync::RwLock::new(Box::new(mock)));
        let state = Arc::new(parking_lot::RwLock::new(ModeState::new("Rule", "Proxy")));
        let handle = DatapathFlagsHandle::new(Arc::clone(&backend), state, None);

        handle.initialize(true, true).await.unwrap();
        handle.fence_nfqueue().await.unwrap();
        assert!(
            backend
                .read()
                .await
                .udp_conn_state_lookup(&key)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn cancelled_update_leaves_public_and_kernel_state_unchanged() {
        use honk_ebpf_common::{
            DATAPATH_FLAG_NFQ_ENABLED as ENABLED, DATAPATH_FLAG_NFQ_READY as READY,
            DATAPATH_FLAG_OFFLOAD_ALL as ALL, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as RULE,
        };

        let (handle, state, writes, backend) = flags_fixture();
        handle.initialize(true, true).await.unwrap();
        let backend_guard = backend.write().await;
        let pending = {
            let handle = handle.clone();
            tokio::spawn(async move { handle.set_mode("Direct").await })
        };
        tokio::task::yield_now().await;
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        drop(backend_guard);

        assert_eq!(state.read().mode, "Rule");
        assert_eq!(writes.lock().as_slice(), [RULE | ENABLED | READY]);
        handle.set_mode("Direct").await.unwrap();
        assert_eq!(state.read().mode, "Direct");
        assert_eq!(
            writes.lock().as_slice(),
            [RULE | ENABLED | READY, ALL | ENABLED | READY]
        );
    }

    #[cfg(feature = "native-api")]
    #[tokio::test]
    async fn trace_publication_retries_failure_without_changing_mode_or_nfqueue() {
        use honk_ebpf_common::{
            DATAPATH_FLAG_NFQ_ENABLED as ENABLED, DATAPATH_FLAG_NFQ_READY as READY,
            DATAPATH_FLAG_OFFLOAD_ALL as ALL, DATAPATH_FLAG_TRACE_ENABLED as TRACE,
        };
        let (handle, _, writes, backend) = flags_fixture();
        handle.initialize(true, true).await.unwrap();
        for (previous, desired) in [(false, true), (true, false)] {
            backend
                .write()
                .await
                .arm_datapath_flags_write_fault(1)
                .unwrap();
            assert!(handle.reconcile_kernel_trace(|| desired).await.is_err());
            assert_eq!(handle.inner.lock().await.state.trace_enabled, previous);
            handle.set_mode("Direct").await.unwrap();
            assert_eq!(
                writes.lock().last().copied(),
                Some(ALL | ENABLED | READY | if previous { TRACE } else { 0 })
            );
            handle.reconcile_kernel_trace(|| desired).await.unwrap();
            assert_eq!(
                writes.lock().last().copied(),
                Some(ALL | ENABLED | READY | if desired { TRACE } else { 0 })
            );
            let count = writes.lock().len();
            handle.reconcile_kernel_trace(|| desired).await.unwrap();
            assert_eq!(
                writes.lock().len(),
                count,
                "unchanged demand must not write"
            );
        }
        handle.reconcile_kernel_trace(|| true).await.unwrap();
        let (fenced, mode) = tokio::join!(handle.fence_nfqueue(), handle.set_mode("Global"));
        fenced.unwrap();
        mode.unwrap();
        handle.set_global_selection("direct".into()).await.unwrap();
        assert_eq!(writes.lock().last().copied(), Some(ALL | ENABLED | TRACE));
        handle.reopen_nfqueue().await.unwrap();
        assert_eq!(
            writes.lock().last().copied(),
            Some(ALL | ENABLED | READY | TRACE)
        );
        handle.disable().await.unwrap();
        assert_eq!(writes.lock().last().copied(), Some(ALL));
        let count = writes.lock().len();
        handle.reconcile_kernel_trace(|| true).await.unwrap();
        assert_eq!(
            writes.lock().len(),
            count,
            "terminal disable cannot be reopened"
        );
    }

    #[cfg(feature = "native-api")]
    #[tokio::test]
    async fn trace_publication_rechecks_demand_after_backend_wait() {
        use honk_ebpf_common::DATAPATH_FLAG_TRACE_ENABLED as TRACE;
        use std::sync::atomic::{AtomicBool, Ordering};
        let (handle, _, writes, backend) = flags_fixture();
        handle.initialize(true, true).await.unwrap();
        let recording = AtomicBool::new(true);
        let held = backend.write().await;
        let pending = handle.reconcile_kernel_trace(|| recording.load(Ordering::Acquire));
        tokio::pin!(pending);
        assert!(futures::poll!(pending.as_mut()).is_pending());
        recording.store(false, Ordering::Release);
        drop(held);
        pending.await.unwrap();
        assert_eq!(
            writes.lock().len(),
            1,
            "a withdrawn enable must not publish"
        );
        handle.reconcile_kernel_trace(|| true).await.unwrap();
        assert_ne!(writes.lock().last().unwrap() & TRACE, 0);
        let held = backend.write().await;
        let pending = handle.reconcile_kernel_trace(|| recording.load(Ordering::Acquire));
        tokio::pin!(pending);
        assert!(futures::poll!(pending.as_mut()).is_pending());
        recording.store(true, Ordering::Release);
        drop(held);
        pending.await.unwrap();
        assert_eq!(
            writes.lock().len(),
            2,
            "a withdrawn disable must not publish"
        );
        recording.store(false, Ordering::Release);
        let held = backend.write().await;
        let pending = handle.reconcile_kernel_trace(|| recording.load(Ordering::Acquire));
        tokio::pin!(pending);
        assert!(futures::poll!(pending.as_mut()).is_pending());
        let disabled = handle.disable();
        tokio::pin!(disabled);
        assert!(futures::poll!(disabled.as_mut()).is_pending());
        drop(held);
        pending.await.unwrap();
        disabled.await.unwrap();
        assert_eq!(writes.lock().last().unwrap() & TRACE, 0);
        let count = writes.lock().len();
        handle.reconcile_kernel_trace(|| true).await.unwrap();
        assert_eq!(writes.lock().len(), count);
    }
}
