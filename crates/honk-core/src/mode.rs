//! Shared clash mode state (sing-box `mode` / `StoreMode` equivalent).
//!
//! Holds the current clash mode (`Rule` / `Global` / `Direct`) and the
//! GLOBAL group's current selection. One instance is shared between the
//! control plane (which applies the mode override on the outbound decision
//! path) and the clash API (which reads/writes it via `/configs` and
//! `/proxies/GLOBAL`). Values are restored from and persisted to cache.db.

use std::sync::Arc;

use anyhow::Context;
type SharedEbpfBackend = Arc<tokio::sync::RwLock<Box<dyn crate::ebpf::EbpfBackend>>>;

/// Clash mode + GLOBAL selection, shared via [`SharedModeState`].
#[derive(Debug, Clone)]
pub struct ModeState {
    /// Canonical clash mode: `"Rule"` | `"Global"` | `"Direct"`.
    pub mode: String,
    /// Current GLOBAL selection: a configured group or node name.
    pub global_selection: String,
}

/// Shared handle to the clash mode state.
pub type SharedModeState = Arc<parking_lot::RwLock<ModeState>>;

impl ModeState {
    /// Create a new state; an unrecognized `mode` falls back to `Rule`.
    pub fn new(mode: &str, global_selection: impl Into<String>) -> Self {
        Self {
            mode: Self::normalize(mode).unwrap_or_else(|| "Rule".to_string()),
            global_selection: global_selection.into(),
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
        if self.is_direct() || (self.is_global() && self.global_selection == "direct") {
            honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_ALL
        } else if self.is_rule() {
            honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_RULE_DIRECT
        } else {
            0
        }
    }

    /// Decide the effective outbound after clash-mode override.
    ///
    /// - `block` results and `must` results (dae `(must)` rules / eBPF
    ///   handoff must flag) are final routing decisions and are never
    ///   overridden — a block rule is an explicit safety decision and a
    ///   must rule is an explicit force, neither of which a mode switch
    ///   may bypass;
    /// - mode `Direct` forces `direct`;
    /// - mode `Global` forces the current GLOBAL selection when it
    ///   resolves (`selection_resolvable` — the caller owns the config);
    ///   an unresolvable selection keeps the routed outbound;
    /// - mode `Rule` (or anything else) keeps the routed outbound.
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
        if self.is_global() && !self.global_selection.is_empty() && selection_resolvable {
            return self.global_selection.clone();
        }
        outbound_name.to_string()
    }
}

#[derive(Clone)]
pub struct DatapathFlagsHandle {
    inner: Arc<tokio::sync::Mutex<DatapathFlagsInner>>,
}

#[derive(Clone)]
struct DatapathFlagsState {
    static_flags: u32,
    nfqueue_enabled: bool,
    nfqueue_ready: bool,
    initialized: bool,
}

impl DatapathFlagsState {
    fn managed_mask() -> u32 {
        honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_RULE_DIRECT
            | honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_ALL
            | honk_ebpf_common::DATAPATH_FLAG_NFQ_ENABLED
            | honk_ebpf_common::DATAPATH_FLAG_NFQ_READY
    }

    fn sanitize_static(flags: u32) -> u32 {
        flags & !Self::managed_mask()
    }

    fn compose(&self, mode: &ModeState) -> u32 {
        let mut flags = self.static_flags | mode.direct_offload_mode_bits();
        if self.nfqueue_enabled {
            flags |= honk_ebpf_common::DATAPATH_FLAG_NFQ_ENABLED;
            if self.nfqueue_ready {
                flags |= honk_ebpf_common::DATAPATH_FLAG_NFQ_READY;
            }
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
    cache_db: Option<Arc<crate::cachedb::CacheDb>>,
    state: DatapathFlagsState,
}

impl DatapathFlagsHandle {
    pub fn new(
        backend: SharedEbpfBackend,
        mode_state: SharedModeState,
        cache_db: Option<Arc<crate::cachedb::CacheDb>>,
    ) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(DatapathFlagsInner {
                backend,
                mode_state,
                cache_db,
                state: DatapathFlagsState {
                    static_flags: 0,
                    nfqueue_enabled: false,
                    nfqueue_ready: false,
                    initialized: false,
                },
            })),
        }
    }

    async fn update(
        &self,
        quiesce: bool,
        change: impl FnOnce(&mut DatapathFlagsState, &mut ModeState) -> anyhow::Result<Persistence>,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().await;
        let mut state = inner.state.clone();
        let mut mode = inner.mode_state.read().clone();
        let persistence = change(&mut state, &mut mode)?;
        let flags = state.compose(&mode);
        {
            let mut backend = inner.backend.write().await;
            backend
                .set_datapath_flags(flags)
                .with_context(|| format!("failed to publish datapath flags {flags:#010x}"))?;
            if quiesce {
                backend
                    .quiesce_udp_staging()
                    .context("failed to quiesce staged UDP decisions")?;
            }
        }
        inner.state = state;
        *inner.mode_state.write() = mode.clone();
        if let Some(db) = &inner.cache_db {
            match persistence {
                Persistence::None => {}
                Persistence::Mode => db.save_clash_mode(&mode.mode),
                Persistence::Global => db.save_selector_choice("GLOBAL", &mode.global_selection),
            }
        }
        Ok(())
    }

    pub async fn initialize(
        &self,
        static_flags: u32,
        nfqueue_enabled: bool,
        nfqueue_ready: bool,
    ) -> anyhow::Result<()> {
        self.update(false, |state, _| {
            anyhow::ensure!(!state.initialized, "datapath flags are already initialized");
            state.static_flags = DatapathFlagsState::sanitize_static(static_flags);
            state.nfqueue_enabled = nfqueue_enabled;
            state.nfqueue_ready = nfqueue_enabled && nfqueue_ready;
            state.initialized = true;
            Ok(Persistence::None)
        })
        .await
    }

    pub async fn set_mode(&self, mode: &str) -> anyhow::Result<()> {
        let mode = ModeState::normalize(mode).context("invalid clash mode")?;
        self.update(false, move |state, current| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            current.mode = mode;
            Ok(Persistence::Mode)
        })
        .await
    }

    pub async fn set_global_selection(&self, selection: String) -> anyhow::Result<()> {
        self.update(false, move |state, mode| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            mode.global_selection = selection;
            Ok(Persistence::Global)
        })
        .await
    }

    pub async fn set_static(&self, flags: u32) -> anyhow::Result<()> {
        self.update(false, move |state, _| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            state.static_flags = DatapathFlagsState::sanitize_static(flags);
            Ok(Persistence::None)
        })
        .await
    }

    pub async fn fence_nfqueue(&self) -> anyhow::Result<()> {
        self.update(true, |state, _| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            state.nfqueue_ready = false;
            Ok(Persistence::None)
        })
        .await
    }

    pub async fn reopen_nfqueue(&self) -> anyhow::Result<()> {
        self.update(false, |state, _| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            state.nfqueue_ready = state.nfqueue_enabled;
            Ok(Persistence::None)
        })
        .await
    }

    pub async fn disable(&self) -> anyhow::Result<()> {
        self.update(false, |state, _| {
            anyhow::ensure!(state.initialized, "datapath flags are not initialized");
            state.nfqueue_enabled = false;
            state.nfqueue_ready = false;
            state.initialized = false;
            Ok(Persistence::None)
        })
        .await
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
        assert_eq!(s.global_selection, "proxy");
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
        Arc<std::sync::Mutex<Vec<u32>>>,
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
    async fn flags_fence_wins_racing_mode_global_and_static_updates() {
        use honk_ebpf_common::{
            DATAPATH_FLAG_NFQ_ENABLED as ENABLED, DATAPATH_FLAG_NFQ_READY as READY,
            DATAPATH_FLAG_OFFLOAD_ALL as ALL, DATAPATH_FLAG_OFFLOAD_NO_DOMAIN_RULES as STATIC,
            DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as RULE,
        };

        let (handle, state, writes, _) = flags_fixture();
        handle.initialize(STATIC, true, true).await.unwrap();
        handle.fence_nfqueue().await.unwrap();
        let (mode_result, selection_result) = tokio::join!(
            handle.set_mode("Global"),
            handle.set_global_selection("direct".to_string()),
        );
        mode_result.unwrap();
        selection_result.unwrap();
        handle.set_static(STATIC | RULE | READY).await.unwrap();
        handle.reopen_nfqueue().await.unwrap();

        assert_eq!(state.read().mode, "Global");
        assert_eq!(state.read().global_selection, "direct");
        let writes = writes.lock().unwrap().clone();
        assert_eq!(writes.len(), 6);
        assert_eq!(writes[0], STATIC | RULE | ENABLED | READY);
        assert_eq!(writes[1], STATIC | RULE | ENABLED);
        assert!(writes[2..5].iter().all(|flags| flags & READY == 0));
        assert_eq!(writes[4], STATIC | ALL | ENABLED);
        assert_eq!(writes[5], STATIC | ALL | ENABLED | READY);
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

        handle.initialize(0, true, true).await.unwrap();
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
        handle.initialize(0, true, true).await.unwrap();
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
        assert_eq!(writes.lock().unwrap().as_slice(), [RULE | ENABLED | READY]);
        handle.set_mode("Direct").await.unwrap();
        assert_eq!(state.read().mode, "Direct");
        assert_eq!(
            writes.lock().unwrap().as_slice(),
            [RULE | ENABLED | READY, ALL | ENABLED | READY]
        );
    }
}
