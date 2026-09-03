//! eBPF backend abstraction.

pub mod maps;
pub mod mock;
pub mod probe;
#[cfg(feature = "ebpf")]
pub mod real;

use async_trait::async_trait;
use honk_ebpf_common::*;
use std::sync::atomic::AtomicU64;

pub const UDP_DECISION_SEQUENCE_MAP: &str = "UDP_DECISION_SEQUENCE";
pub const UDP_DECISION_EPOCH_MAP: &str = "UDP_DECISION_EPOCH";
pub const UDP_DECISION_INFLIGHT_MAP: &str = "UDP_DECISION_INFLIGHT";
pub const UDP_DECISION_RETIRE_FENCE_MAP: &str = "UDP_DECISION_RETIRE_FENCE";

/// Cumulative conn-state entries deleted by userspace (TCP relay teardown,
/// UDP endpoint reaper), for the janitor's occupancy gauge.  eBPF-side
/// inserts/deletes are counted by the `CONN_STATE_OCCUPANCY` map; deletions
/// initiated from userspace must be accounted separately or the gauge
/// overestimates live occupancy between sweep calibrations.
pub static USERSPACE_CONN_STATE_DELETES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct BpfLoadParams {
    pub tproxy_port: u16,
    pub tproxy_mark: u32,
    pub so_mark: u32,
    pub control_plane_pid: u32,
    pub dae0_ifindex: u32,
    pub lo_ifindex: u32,
    pub dae_netns_id: u32,
    pub dae0peer_mac: [u8; 6],
    pub local_ip: u32,
}

impl Default for BpfLoadParams {
    fn default() -> Self {
        Self {
            tproxy_port: 12345,
            tproxy_mark: 0x0800_0000,
            so_mark: 0,
            control_plane_pid: 0,
            dae0_ifindex: 0,
            lo_ifindex: 0,
            dae_netns_id: 0,
            dae0peer_mac: [0u8; 6],
            local_ip: 0,
        }
    }
}

/// Raw key sets identifying the LPM entries that belong to the current
/// ruleset generation, consumed by [`EbpfBackend::prune_lpm_entries`].
/// Keys are the 20-byte raw `LpmKey` encoding produced by
/// [`maps::lpm_key_bytes`].
#[derive(Debug, Default, Clone)]
pub struct LpmKeepSet {
    /// Keys present in DEST_LPM_ROUTING_MAP for the current generation.
    pub dest: std::collections::HashSet<[u8; 20]>,
    /// Keys present in SOURCE_LPM_ROUTING_MAP for the current generation.
    pub source: std::collections::HashSet<[u8; 20]>,
    /// Keys present in MAC_LPM_ROUTING_MAP for the current generation.
    pub mac: std::collections::HashSet<[u8; 20]>,
}

/// Callback for a bounded janitor scan. Return `false` to stop the scan at a
/// chunk boundary (used to enforce the janitor time budget).
pub type ConnStateChunkVisitor<'a> = dyn FnMut(&[(TuplesKey, ConnState)]) -> bool + 'a;
pub type RedirectTrackChunkVisitor<'a> = dyn FnMut(&[(RedirectTuple, RedirectEntry)]) -> bool + 'a;
pub type CookiePidChunkVisitor<'a> = dyn FnMut(&[(u64, PIDName)]) -> bool + 'a;
pub type RoutingHandoffChunkVisitor<'a> =
    dyn FnMut(&[(TuplesKey, RoutingHandoffEntry)]) -> bool + 'a;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPushPhase {
    DomainRouting,
    Rules,
    DestinationLpm,
    SourceLpm,
    MacLpm,
    Meta,
    PruneLpm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDecisionTransition {
    ArmDirect(u32),
    ActivateDirect(u32),
    ActivateProxy(u8, u32),
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDecisionCommitResult {
    Applied,
    Missing,
    /// A newer kernel incarnation owns the tuple; nothing was removed.
    Superseded,
    TokenMismatch,
    StateMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDecisionSequenceStatus {
    pub next: u32,
    pub generation: u32,
}

impl UdpDecisionSequenceStatus {
    pub fn exhausted(self) -> bool {
        self.next >= honk_ebpf_common::UDP_DECISION_SEQUENCE_MASK
    }
}

pub(crate) fn validate_udp_decision_transition(
    transition: UdpDecisionTransition,
) -> anyhow::Result<()> {
    let mark = match transition {
        UdpDecisionTransition::ArmDirect(mark)
        | UdpDecisionTransition::ActivateDirect(mark)
        | UdpDecisionTransition::ActivateProxy(_, mark) => mark,
        UdpDecisionTransition::Block => return Ok(()),
    };
    anyhow::ensure!(
        !skb_mark_has_reserved_bits(mark),
        "UDP decision rule mark contains reserved skb bits: 0x{mark:08x}"
    );
    Ok(())
}

fn final_udp_meta(previous: RoutingMeta, outbound: u8, mark: u32, offload: bool) -> RoutingMeta {
    const DSCP_MASK: u64 = 0xff << 48;
    let preserved = unsafe { previous.raw } & (DSCP_MASK | ROUTING_META_FLAG_PUBLISHED);
    let flags = if offload {
        ROUTING_META_FLAG_OFFLOAD
    } else {
        0
    };
    RoutingMeta {
        raw: preserved | outbound as u64 | ((mark as u64) << 8) | flags,
    }
}

pub(crate) fn apply_udp_decision_transition(
    state: &mut ConnState,
    transition: UdpDecisionTransition,
) -> Result<(), UdpDecisionCommitResult> {
    let expected = match transition {
        UdpDecisionTransition::ActivateDirect(_) => UdpDecisionState::DirectArmed,
        UdpDecisionTransition::ArmDirect(_)
        | UdpDecisionTransition::ActivateProxy(_, _)
        | UdpDecisionTransition::Block => UdpDecisionState::Pending,
    };
    if state.state != expected as u8 {
        return Err(UdpDecisionCommitResult::StateMismatch);
    }
    if let UdpDecisionTransition::ActivateDirect(mark) = transition {
        let raw = unsafe { state.meta.raw };
        let armed_mark = ((raw >> 8) & 0xffff_ffff) as u32;
        if raw & 0xff != OutboundIndex::Direct as u64
            || armed_mark != mark
            || raw & ROUTING_META_FLAG_OFFLOAD != 0
        {
            return Err(UdpDecisionCommitResult::StateMismatch);
        }
    }
    match transition {
        UdpDecisionTransition::ArmDirect(mark) => {
            state.state = UdpDecisionState::DirectArmed as u8;
            state.meta = final_udp_meta(state.meta, OutboundIndex::Direct as u8, mark, false);
        }
        UdpDecisionTransition::ActivateDirect(mark) => {
            state.state = UdpDecisionState::None as u8;
            state.meta = final_udp_meta(state.meta, OutboundIndex::Direct as u8, mark, true);
        }
        UdpDecisionTransition::ActivateProxy(outbound, mark) => {
            state.state = UdpDecisionState::Proxy as u8;
            state.meta = final_udp_meta(state.meta, outbound, mark, false);
        }
        UdpDecisionTransition::Block => {
            state.state = UdpDecisionState::Block as u8;
            state.meta = final_udp_meta(state.meta, OutboundIndex::Block as u8, 0, false);
        }
    }
    Ok(())
}

pub(crate) fn udp_state_is_userspace_owned(state: u8) -> bool {
    state == UdpDecisionState::Preparing as u8
        || state == UdpDecisionState::Pending as u8
        || state == UdpDecisionState::Proxy as u8
}

pub(crate) fn udp_state_is_legacy_userspace_owned(state: &ConnState) -> bool {
    if state.decision_token != 0 || state.state != UdpDecisionState::None as u8 {
        return false;
    }
    let raw = unsafe { state.meta.raw };
    if raw & ROUTING_META_FLAG_PUBLISHED == 0 || raw & ROUTING_META_FLAG_OFFLOAD != 0 {
        return false;
    }
    let outbound = (raw & 0xff) as u8;
    let must = ((raw >> 40) & 1) != 0;
    outbound != OutboundIndex::Block as u8 && !(outbound == OutboundIndex::Direct as u8 && must)
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionMapOperation {
    Set,
    Remove,
}

#[derive(Debug, thiserror::Error)]
pub enum DomainRouteWriteError {
    #[error("domain routing map capacity exhausted")]
    MapFull,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl DomainRouteWriteError {
    pub const fn is_map_full(&self) -> bool {
        matches!(self, Self::MapFull)
    }
}

/// Which config list an interface came from; selects the TC programs a
/// dynamic attach installs on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfaceRole {
    Lan,
    Wan,
    /// LAN and WAN resolve to the same interface. The startup datapath uses
    /// LAN ingress plus WAN egress, not the LAN egress/WAN ingress pair.
    LanWan,
    /// Slave port of a configured LAN bridge master: forwarded L2 traffic
    /// never crosses the master's TC hooks, so the LAN programs go on each
    /// slave (mirrors the startup expansion).
    LanBridgeSlave,
    /// Slave of a configured LAN bond master: packets may arrive/leave on the
    /// slave without touching the master's qdiscs, so it gets
    /// lan_ingress + wan_egress (mirrors the startup expansion).
    LanBondSlave,
    /// Slave of a WAN bond master: locally-originated traffic can bypass the
    /// master's egress qdisc, so only wan_egress belongs on this interface.
    WanBondSlave,
}

/// Per-direction outcome of a dynamic attach: which hooks are live on the
/// interface after the call (including ones attached earlier).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DynamicHooks {
    pub ingress: bool,
    pub egress: bool,
}

#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DatapathFlagsWriteOrigin {
    #[default]
    Other,
    FenceNfqueue,
    SetStatic,
    ReopenNfqueue,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatapathFlagsWriteTrace {
    pub ordinal: usize,
    pub origin: DatapathFlagsWriteOrigin,
    pub flags: u32,
    pub failed: bool,
}

#[async_trait]
pub trait EbpfBackend: Send + Sync {
    fn inject_routing_fault(
        &mut self,
        _phase: RoutingPushPhase,
        _times: usize,
    ) -> anyhow::Result<()> {
        anyhow::bail!("routing fault injection is unsupported")
    }
    #[cfg(test)]
    fn inject_projection_fault(
        &mut self,
        _operation: ProjectionMapOperation,
        _times: usize,
        _map_full: bool,
    ) -> anyhow::Result<()> {
        anyhow::bail!("projection fault injection is unsupported")
    }
    /// Fail the next `times` `add_domain_ip_bitmap` writes (the sniffed-
    /// domain writeback path).  Test-only, mirroring
    /// `inject_projection_fault`.
    #[cfg(test)]
    fn inject_domain_bitmap_add_fault(&mut self, _times: usize) -> anyhow::Result<()> {
        anyhow::bail!("domain bitmap add fault injection is unsupported")
    }
    #[cfg(test)]
    fn projection_map_snapshot(&self) -> Vec<([u8; 20], DomainRouting)> {
        Vec::new()
    }
    #[cfg(test)]
    fn projection_write_log(&self) -> Vec<ProjectionMapOperation> {
        Vec::new()
    }
    #[cfg(test)]
    fn clear_projection_write_log(&mut self) {}
    fn detach_hooks(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    fn eject(&mut self) {}
    fn inject(&mut self, _params: &BpfLoadParams) -> anyhow::Result<()> {
        Ok(())
    }
    fn attach_dae0_programs(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    /// Open or close admission at the TC entry points. Implementations must
    /// publish listener sockets before setting this to `true`.
    fn set_datapath_ready(&mut self, _ready: bool) -> anyhow::Result<()> {
        Ok(())
    }

    /// Write the mode-based direct-offload policy (the
    /// `DATAPATH_FLAG_OFFLOAD_*` bits) into `DATAPATH_FLAGS_MAP`.  The
    /// control plane recomputes and pushes the full word on startup, at the
    /// reload commit point, and on every clash mode switch; `lan_ingress`
    /// reads it once per new flow and caches the decision per flow, so the
    /// write takes effect for new flows only — established flows keep the
    /// decision they were created with.
    fn set_datapath_flags(&mut self, _flags: u32) -> anyhow::Result<()> {
        Ok(())
    }
    #[cfg(test)]
    fn arm_datapath_flags_write_fault(&mut self, _nth: usize) -> anyhow::Result<()> {
        anyhow::bail!("datapath flag fault injection is unsupported")
    }
    #[cfg(test)]
    fn mark_datapath_flags_write_origin(&mut self, _origin: DatapathFlagsWriteOrigin) {}
    #[cfg(test)]
    fn arm_quiesce_fault(&mut self) {}
    #[cfg(test)]
    fn datapath_flags_write_log(&self) -> Vec<u32> {
        Vec::new()
    }
    #[cfg(test)]
    fn datapath_flags_write_trace(&self) -> Vec<DatapathFlagsWriteTrace> {
        Vec::new()
    }
    #[cfg(test)]
    fn clear_datapath_flags_write_log(&mut self) {}

    /// After READY has been cleared, wait for every kernel invocation that
    /// observed the prior fence to finish, then remove all unpublished or
    /// pending staged states. Delayed NFQUEUE deliveries therefore fail
    /// token lookup instead of crossing a runtime-generation boundary.
    fn quiesce_udp_staging(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Attach the dae0peer_ingress TC program after dae0peer has been moved
    /// into the isolated daens namespace.  The attach runs inside a scoped
    /// `with_daens_netns` switch — the process threads always stay in the
    /// host netns — while the dae0peer interface and the TPROXY listener
    /// sockets both live in daens.
    fn attach_dae0peer_ingress(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Attach the sk_lookup program to the isolated daens namespace (also a
    /// scoped switch).  The program overrides socket selection for
    /// proxy-bound packets arriving on dae0peer and delivers them to the
    /// daens-resident TPROXY listener while keeping the original destination
    /// intact.
    fn attach_sk_lookup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Publish the raw file descriptors of the tproxy listener sockets into the
    /// eBPF listen_socket_map so TC programs can bpf_sk_assign() inbound proxy
    /// traffic directly to the userspace listeners.
    ///
    /// Key mapping: 0 = IPv4 TCP, 1 = IPv6 TCP, 2.. = IPv4 UDP group,
    /// 2 + UDP_LISTENER_COUNT.. = IPv6 UDP group. The eBPF programs hash the
    /// flow tuple into the UDP group, so `udp4_fds`/`udp6_fds` must be in
    /// hash-slot order.
    fn publish_listener_sockets(
        &mut self,
        _tcp4_fd: std::os::unix::io::RawFd,
        _tcp6_fd: std::os::unix::io::RawFd,
        _udp4_fds: &[std::os::unix::io::RawFd],
        _udp6_fds: &[std::os::unix::io::RawFd],
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn cleanup(&mut self) -> anyhow::Result<()>;

    /// Attach TC programs to a configured interface that appeared after
    /// startup.  Backends dedupe per (ifindex, direction): a direction that
    /// is already hooked is reported, never re-attached, so retrying after
    /// a partial failure cannot stack duplicate hooks.
    fn attach_dynamic_interface(
        &mut self,
        _ifname: &str,
        _role: IfaceRole,
        _single_homed: bool,
    ) -> anyhow::Result<DynamicHooks> {
        Ok(DynamicHooks::default())
    }

    /// Drop any dynamic-attach state for `ifindex` (the device is gone or
    /// was recreated, so its hooks died with it).
    fn forget_dynamic_interface(&mut self, _ifindex: u32) {}

    fn set_param(&mut self, key: ParamKey, value: u32) -> anyhow::Result<()>;
    fn get_param(&self, key: ParamKey) -> anyhow::Result<Option<u32>>;

    /// Fill the inactive physical routing-rule bank. The bank is not visible
    /// to the datapath until `publish_routing_generation` flips its selector.
    fn set_routing_rules(&mut self, generation: u32, rules: &[MatchSet]) -> anyhow::Result<()>;
    /// Return the bank currently selected by the datapath.
    fn active_routing_generation(&self) -> anyhow::Result<u32> {
        Ok(0)
    }
    /// Fill the inactive generation's exploded introspection metadata and all
    /// four packed `RoutingGroupMeta` entries, then atomically activate it by
    /// writing only the selector slot. Implementations MUST leave the prior
    /// generation selected until every packed entry is complete.
    fn publish_routing_generation(
        &mut self,
        generation: u32,
        count: u32,
        group_bitmaps: &RoutingGroupBitmaps,
    ) -> anyhow::Result<()>;
    fn add_domain_route(&mut self, domain: &str, outbound: OutboundIndex) -> anyhow::Result<()>;
    fn add_domain_routing_bitmap(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()>;
    fn add_source_routing_bitmap(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let _ = key;
        let _ = bitmap;
        Ok(())
    }
    fn add_dest_lpm_bitmap(&mut self, key: &LpmKey, bitmap: &DomainRouting) -> anyhow::Result<()> {
        let _ = key;
        let _ = bitmap;
        Ok(())
    }
    fn add_source_lpm_bitmap(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let _ = key;
        let _ = bitmap;
        Ok(())
    }
    fn add_mac_lpm_bitmap(&mut self, key: &LpmKey, bitmap: &DomainRouting) -> anyhow::Result<()> {
        let _ = key;
        let _ = bitmap;
        Ok(())
    }
    /// Merge a resolved-IP bitmap into the active routing generation.
    fn add_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let _ = ip_key;
        let _ = bitmap;
        Ok(())
    }
    /// Replace the active generation's bitmap while retaining the inactive
    /// half for packets that entered before a routing publication.
    fn set_domain_ip_bitmap(
        &mut self,
        _ip_key: &LpmKey,
        _bitmap: &DomainRouting,
    ) -> Result<(), DomainRouteWriteError> {
        Ok(())
    }

    /// Overwrite a bounded batch of DOMAIN_ROUTING_MAP entries. The default
    /// keeps every backend correct; native backends may replace it with one
    /// batch syscall without changing projection reconciliation semantics.
    fn set_domain_ip_bitmap_batch(
        &mut self,
        entries: &[(LpmKey, DomainRouting)],
    ) -> Result<(), (usize, DomainRouteWriteError)> {
        for (index, (key, bitmap)) in entries.iter().enumerate() {
            self.set_domain_ip_bitmap(key, bitmap)
                .map_err(|error| (index, error))?;
        }
        Ok(())
    }
    /// Remove the DOMAIN_ROUTING_MAP entry for `ip_key` (16-byte IP key).
    /// Used by the domain-route rebuild for learned IPs whose domain no
    /// longer matches any domain rule under the current ruleset.
    fn remove_domain_ip_bitmap(&mut self, _ip_key: &LpmKey) -> Result<(), DomainRouteWriteError> {
        Ok(())
    }

    /// Remove a bounded batch of DOMAIN_ROUTING_MAP entries. The returned
    /// index identifies the first entry not known to have been applied.
    fn remove_domain_ip_bitmap_batch(
        &mut self,
        keys: &[LpmKey],
    ) -> Result<(), (usize, DomainRouteWriteError)> {
        for (index, key) in keys.iter().enumerate() {
            self.remove_domain_ip_bitmap(key)
                .map_err(|error| (index, error))?;
        }
        Ok(())
    }

    /// Populate the inactive generation for every learned domain route before
    /// publishing its matching rule bank.
    fn stage_domain_routing_generation(
        &mut self,
        generation: u32,
        entries: &[(LpmKey, DomainRouting)],
    ) -> anyhow::Result<()>;
    fn add_ip_route(&mut self, prefix: &str, outbound: OutboundIndex) -> anyhow::Result<()>;
    /// Fully reset all routing-related maps (MatchSets, routing metadata,
    /// domain routing, and LPM tries). NOT used by the routing push path:
    /// clearing the active bank and metadata makes the eBPF datapath fail
    /// closed until a complete generation is published. Kept for tests and
    /// full-reset scenarios only.
    fn clear_routes(&mut self) -> anyhow::Result<()>;
    /// Delete dest/source/MAC LPM entries whose raw key is not in `keep`.
    ///
    /// Post-commit cleanup for the two-phase routing push.  This replaces
    /// the former `clear_stale_lpm_entries` (zero-bitmap deletion): LPM
    /// values are now overwritten per key during the push, so stale state
    /// is exactly the set of keys the new ruleset no longer references.
    fn prune_lpm_entries(&mut self, _keep: &LpmKeepSet) -> anyhow::Result<()> {
        Ok(())
    }

    fn tcp_conn_state_lookup(&self, key: &TuplesKey) -> anyhow::Result<Option<ConnState>>;
    fn tcp_conn_state_store(&mut self, key: &TuplesKey, state: &ConnState) -> anyhow::Result<()>;
    fn tcp_conn_state_remove(&mut self, key: &TuplesKey) -> anyhow::Result<()>;
    fn udp_conn_state_lookup(&self, key: &TuplesKey) -> anyhow::Result<Option<ConnState>>;
    fn udp_conn_state_store(&mut self, key: &TuplesKey, state: &ConnState) -> anyhow::Result<()>;
    fn udp_conn_state_remove(&mut self, key: &TuplesKey) -> anyhow::Result<()>;
    /// Remove a bounded batch of UDP conntrack entries. Backends may override
    /// this to amortize map access; the default preserves single-delete errors.
    fn udp_conn_state_remove_batch(&mut self, keys: &[TuplesKey]) -> anyhow::Result<usize> {
        for key in keys {
            self.udp_conn_state_remove(key)?;
        }
        Ok(keys.len())
    }

    /// Publish one token-bound UDP decision transition. The caller holds the
    /// backend write lock; implementations validate the state incarnation and
    /// every auxiliary entry before changing any map.
    fn commit_udp_decision(
        &mut self,
        key: &TuplesKey,
        token: u32,
        transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult>;

    /// Fail a staged flow closed without touching a later tuple incarnation.
    fn abort_pending_udp_flow(
        &mut self,
        key: &TuplesKey,
        token: u32,
    ) -> anyhow::Result<UdpDecisionCommitResult>;

    /// Retire a userspace-owned flow. Nonzero tokens remove only the matching
    /// staged/proxy incarnation and auxiliaries; zero removes only a legacy
    /// published, non-offloaded forward state. Kernel handoffs and superseding
    /// tuple incarnations are retained.
    fn remove_udp_flow(
        &mut self,
        key: &TuplesKey,
        token: u32,
    ) -> anyhow::Result<UdpDecisionCommitResult>;

    /// Validate the pinned allocator map and its locked value before admission.
    fn verify_udp_decision_sequence(&self) -> anyhow::Result<()>;

    /// Read the persistent allocator under its embedded BPF spin lock.
    fn udp_decision_sequence_status(&self) -> anyhow::Result<UdpDecisionSequenceStatus>;

    /// Reset an exhausted allocator only when no live token is reachable by a
    /// rolled-back legacy monotonic allocator starting at `generation`.
    fn reset_udp_decision_sequence(&mut self, generation: u32) -> anyhow::Result<bool>;

    /// Inspect a staged handoff without consuming it. UDP decision commit owns
    /// the token-checked removal; legacy consumers may still use `take`.
    fn routing_handoff_lookup(
        &self,
        key: &TuplesKey,
    ) -> anyhow::Result<Option<RoutingHandoffEntry>>;

    fn redirect_track_lookup(&self, key: &RedirectTuple) -> anyhow::Result<Option<RedirectEntry>>;
    fn redirect_track_store(
        &mut self,
        key: &RedirectTuple,
        entry: &RedirectEntry,
    ) -> anyhow::Result<()>;
    fn redirect_track_remove(&mut self, key: &RedirectTuple) -> anyhow::Result<()>;

    /// Atomically look up and remove the handoff entry for `key`.
    ///
    /// The real backend prefers a single `BPF_MAP_LOOKUP_AND_DELETE_ELEM`
    /// syscall (kernel 4.20+) and falls back to lookup+delete on kernels
    /// without it.  The fallback is not atomic: the eBPF datapath may
    /// re-insert the key between the two syscalls, in which case the fresh
    /// entry is dropped and the flow is re-routed in userspace — harmless
    /// for a best-effort handoff hint.
    ///
    /// Takes `&self` so the per-connection hot path only needs a read lock
    /// on the backend: individual bpf() map operations are serialized by
    /// the kernel and no userspace backend state is touched.  The lock's
    /// only job is to keep the backend (and its map fds) alive against
    /// `cleanup()`, which takes the write lock.
    fn routing_handoff_take(&self, key: &TuplesKey) -> anyhow::Result<Option<RoutingHandoffEntry>>;

    fn cookie_pid_lookup(&self, cookie: u64) -> anyhow::Result<Option<PIDName>>;
    fn cookie_pid_store(&mut self, cookie: u64, entry: &PIDName) -> anyhow::Result<()>;
    fn cookie_pid_remove(&mut self, cookie: &u64) -> anyhow::Result<()>;

    fn set_outbound_alive(
        &mut self,
        outbound: u8,
        domain: u32,
        ipver: u32,
        alive: bool,
    ) -> anyhow::Result<()>;
    fn get_outbound_alive(&self, outbound: u8, domain: u32, ipver: u32) -> anyhow::Result<bool>;

    fn get_outbound_stats(&self, outbound: OutboundIndex) -> anyhow::Result<OutboundStats>;
    fn clear_outbound_stats(&mut self, outbound: OutboundIndex) -> anyhow::Result<()>;
    fn get_bpf_stats(&self, key: u32) -> anyhow::Result<Option<u64>>;

    // CONN_STATE_MAP is a plain hash: the datapath expires entries lazily on
    // hit, and the janitor sweeps it proactively with state-based timeouts
    // (mirroring the datapath's own expiry rules).  The kernel never evicts
    // on its own — silent LRU eviction could re-route or break live flows.

    /// Snapshot all (key, entry) pairs from CONN_STATE_MAP.
    /// Same consistency notes as [`Self::redirect_track_snapshot`].
    fn conn_state_snapshot(&self, out: &mut Vec<(TuplesKey, ConnState)>) -> anyhow::Result<()>;

    /// Remove multiple CONN_STATE_MAP entries (batched when supported).
    fn conn_state_remove_batch(&mut self, keys: &[TuplesKey]) -> anyhow::Result<()>;

    /// Visit CONN_STATE_MAP entries in bounded chunks without accumulating
    /// the whole map (524K entries would otherwise spike memory on every
    /// sweep). Backends with `BPF_MAP_LOOKUP_BATCH` stream chunks straight
    /// from the kernel; others fall back to a snapshot chunked into visits
    /// (fine for small/mock maps).
    fn conn_state_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut ConnStateChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut entries = Vec::new();
        self.conn_state_snapshot(&mut entries)?;
        for chunk in entries.chunks(chunk_size.max(1)) {
            if !visit(chunk) {
                break;
            }
        }
        Ok(())
    }

    /// Read the datapath's CONN_STATE_MAP occupancy counters:
    /// `(cumulative_inserts, cumulative_ebpf_deletes)`.  Userspace combines
    /// these with its own janitor-delete accounting to estimate live
    /// occupancy between sweeps (see `CONN_STATE_OCCUPANCY` in the eBPF
    /// maps).  Backends without the gauge return `(0, 0)`.
    fn conn_state_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        Ok((0, 0))
    }

    fn redirect_track_snapshot(
        &self,
        out: &mut Vec<(RedirectTuple, RedirectEntry)>,
    ) -> anyhow::Result<()>;
    fn cookie_pid_snapshot(&self, out: &mut Vec<(u64, PIDName)>) -> anyhow::Result<()>;
    fn routing_handoff_snapshot(
        &self,
        out: &mut Vec<(TuplesKey, RoutingHandoffEntry)>,
    ) -> anyhow::Result<()>;
    fn redirect_track_remove_batch(&mut self, keys: &[RedirectTuple]) -> anyhow::Result<()>;
    fn cookie_pid_remove_batch(&mut self, cookies: &[u64]) -> anyhow::Result<()>;
    fn routing_handoff_remove_batch(&mut self, keys: &[TuplesKey]) -> anyhow::Result<()>;

    /// Stream REDIRECT_TRACK in bounded chunks. The callback can stop at a
    /// chunk boundary so callers can retain a wall-clock budget.
    fn redirect_track_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut RedirectTrackChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut entries = Vec::new();
        self.redirect_track_snapshot(&mut entries)?;
        for chunk in entries.chunks(chunk_size.max(1)) {
            if !visit(chunk) {
                break;
            }
        }
        Ok(())
    }

    fn cookie_pid_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut CookiePidChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut entries = Vec::new();
        self.cookie_pid_snapshot(&mut entries)?;
        for chunk in entries.chunks(chunk_size.max(1)) {
            if !visit(chunk) {
                break;
            }
        }
        Ok(())
    }

    fn routing_handoff_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut RoutingHandoffChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut entries = Vec::new();
        self.routing_handoff_snapshot(&mut entries)?;
        for chunk in entries.chunks(chunk_size.max(1)) {
            if !visit(chunk) {
                break;
            }
        }
        Ok(())
    }

    /// Re-check candidates before deleting them. A key reused or transitioned
    /// after the scan is retained unless its current timestamp and TCP state
    /// match the scanned incarnation and it is no newer than
    /// `expired_before_ns`.
    fn conn_state_remove_if_unchanged(
        &mut self,
        entries: &[(TuplesKey, ConnState)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64>;
    fn redirect_track_remove_if_unchanged(
        &mut self,
        entries: &[(RedirectTuple, RedirectEntry)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64>;
    fn cookie_pid_remove_if_unchanged(
        &mut self,
        entries: &[(u64, PIDName)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64>;
    fn routing_handoff_remove_if_unchanged(
        &mut self,
        entries: &[(TuplesKey, RoutingHandoffEntry)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64>;

    fn conn_track_lookup(&self, tuple: &ConnTuple) -> anyhow::Result<Option<u32>>;
    fn conn_track_store(&mut self, tuple: &ConnTuple, outbound_idx: u32) -> anyhow::Result<()>;
    fn conn_track_remove(&mut self, tuple: &ConnTuple) -> anyhow::Result<()>;
}
