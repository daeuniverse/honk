//! Mock eBPF backend for testing.
//!
//! This backend implements the `EbpfBackend` trait using in-memory
//! data structures instead of real kernel eBPF. All operations use
//! HashMap storage.

#[cfg(test)]
use super::{DatapathFlagsWriteOrigin, DatapathFlagsWriteTrace, ProjectionMapOperation};
use super::{
    EbpfBackend, LpmKeepSet, RoutingPushPhase, UdpDecisionCommitResult, UdpDecisionSequenceStatus,
    UdpDecisionTransition, apply_udp_decision_transition, udp_state_is_legacy_userspace_owned,
    udp_state_is_userspace_owned, validate_udp_decision_transition,
};
use async_trait::async_trait;
use honk_ebpf_common::*;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockRoutingSnapshot {
    pub routing_map: Vec<(u32, MockMatchSetSnapshot)>,
    pub routing_meta: Vec<(u32, u32)>,
    pub dest_lpm: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub source_lpm: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub mac_lpm: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub domain: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockRoutingPublicationWrite {
    Exploded(u32),
    Packed(u32),
    Selector(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockMatchSetSnapshot {
    pub value: MockMatchValue,
    pub not: u8,
    pub match_type: u8,
    pub outbound: u8,
    pub must: u8,
    pub mark: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockMatchValue {
    Zero([u8; 16]),
    PortRange { start: u16, end: u16 },
    L4Protocol(u8),
    IpVersion(u8),
    ProcessName([u32; TASK_COMM_LEN / 4]),
    Dscp(u8),
    Index(u32),
    Unknown,
}

impl MockMatchSetSnapshot {
    fn from_match_set(value: &MatchSet) -> Self {
        let normalized = match MatchType::from_u8(value.match_type) {
            Some(
                MatchType::DomainSet
                | MatchType::IpSet
                | MatchType::SourceIpSet
                | MatchType::Mac
                | MatchType::Fallback
                | MatchType::MustRules,
            ) => {
                // SAFETY: [Category 4 — Uninitialized Memory] the routing compiler
                // initializes `MatchSetValue::raw` for these tags. `MatchSetValue`
                // is `repr(C)`, so the active field starts at the union's address,
                // and `[u8; 16]` accepts every initialized bit pattern.
                MockMatchValue::Zero(unsafe { value.value.raw })
            }
            Some(MatchType::Port | MatchType::SourcePort) => {
                // SAFETY: [Category 4 — Uninitialized Memory] the routing compiler
                // initializes `MatchSetValue::port_range` before assigning either
                // port tag. `repr(C)` places that active field at the union's
                // address, and both `u16` members accept every bit pattern.
                let range = unsafe { value.value.port_range };
                MockMatchValue::PortRange {
                    start: range.port_start,
                    end: range.port_end,
                }
            }
            Some(MatchType::L4Proto) => {
                // SAFETY: [Category 5 — Invalid Values] the routing compiler writes
                // a validated `L4ProtoType` to the active `l4proto_type` field
                // before assigning this tag. `repr(C)` places the active field at
                // the union's address, preserving the enum discriminant.
                MockMatchValue::L4Protocol(unsafe { value.value.l4proto_type } as u8)
            }
            Some(MatchType::IpVersion) => {
                // SAFETY: [Category 5 — Invalid Values] the routing compiler writes
                // a validated `IpVersionType` to the active `ip_version` field
                // before assigning this tag. `repr(C)` places the active field at
                // the union's address, preserving the enum discriminant.
                MockMatchValue::IpVersion(unsafe { value.value.ip_version } as u8)
            }
            Some(MatchType::ProcessName) => {
                // SAFETY: [Category 4 — Uninitialized Memory] the routing compiler
                // initializes the complete `pname` array before assigning this tag.
                // `repr(C)` places the active array at the union's address, and
                // every `u32` element accepts every bit pattern.
                MockMatchValue::ProcessName(unsafe { value.value.pname })
            }
            Some(MatchType::Dscp) => {
                // SAFETY: [Category 4 — Uninitialized Memory] the routing compiler
                // initializes `dscp` before assigning this tag. `repr(C)` places
                // the active `u8` at the union's address, and every byte is valid.
                MockMatchValue::Dscp(unsafe { value.value.dscp })
            }
            Some(MatchType::Upstream | MatchType::QType) => {
                // SAFETY: [Category 4 — Uninitialized Memory] producers initialize
                // `index` before assigning either index-bearing tag. `repr(C)`
                // places the active `u32` at the union's address, and every `u32`
                // bit pattern is valid.
                MockMatchValue::Index(unsafe { value.value.index })
            }
            None => MockMatchValue::Unknown,
        };
        Self {
            value: normalized,
            not: value.not,
            match_type: value.match_type,
            outbound: value.outbound,
            must: value.must,
            mark: value.mark,
        }
    }
}

/// Mock eBPF backend using in-memory maps.
#[derive(Debug, Default)]
pub struct MockEbpfBackend {
    /// Parameter map (key → value)
    pub params: HashMap<u32, u32>,
    /// Domain routing map (hash → outbound index)
    pub domain_routes: HashMap<u64, u32>,
    /// IP routing map (prefix → outbound index, stored as (ip, prefix_len) → index)
    pub ip_routes: HashMap<(u32, u8), u32>,
    /// Outbound statistics
    pub stats: HashMap<u32, OutboundStats>,
    /// Connection tracking (legacy)
    pub conn_track: HashMap<[u8; 37], u32>,

    /// Routing rules: index → MatchSet (array-style BPF map)
    pub routing_map: HashMap<u32, MatchSet>,
    /// Exploded routing metadata: key 0 selects the active generation; each
    /// following generation block holds its rule count and group bitmaps.
    pub routing_meta: HashMap<u32, u32>,
    /// Packed count/bitmap entries consumed by the datapath.
    pub routing_group_meta: HashMap<u32, RoutingGroupMeta>,
    /// Domain routing bitmap: LpmKey → DomainRouting
    pub domain_routing_bitmap: HashMap<[u8; 20], DomainRouting>,
    /// Destination IP LPM routing bitmap: LpmKey → DomainRouting
    pub dest_lpm_bitmap: HashMap<[u8; 20], DomainRouting>,
    /// Source IP LPM routing bitmap: LpmKey → DomainRouting
    pub source_lpm_bitmap: HashMap<[u8; 20], DomainRouting>,
    /// MAC LPM routing bitmap: LpmKey → DomainRouting
    pub mac_lpm_bitmap: HashMap<[u8; 20], DomainRouting>,
    /// TCP connection states (TuplesKey → ConnState)
    pub tcp_conn_states: HashMap<[u8; 40], ConnState>,
    /// UDP connection states (TuplesKey → ConnState)
    pub udp_conn_states: HashMap<[u8; 40], ConnState>,
    /// Redirect tracking (full directional `RedirectTuple` → `RedirectEntry`).
    pub redirect_tracks: HashMap<[u8; 40], RedirectEntry>,
    /// Routing handoff table (TuplesKey → RoutingHandoffEntry).
    ///
    /// Behind a Mutex because `routing_handoff_take` takes `&self` (the
    /// per-connection hot path holds only a read lock on the backend).
    pub routing_handoffs: parking_lot::Mutex<HashMap<[u8; 40], RoutingHandoffEntry>>,
    /// Exact tuple retirement fences (TuplesKey → decision token).
    udp_retire_fences: HashMap<[u8; 40], u32>,
    /// Cookie PID map (cookie → PIDName)
    pub cookie_pids: HashMap<u64, PIDName>,
    /// Outbound alive bitmap: (outbound*6 + domain*2 + ipver) → 0|1
    pub outbound_alive: HashMap<u32, u32>,
    /// BPF statistics overflow counters
    pub bpf_stats: HashMap<u32, u64>,
    /// Whether TC entry points may redirect traffic into the control plane.
    pub datapath_ready: bool,
    pub listener_sockets_published: bool,
    /// Every `set_datapath_flags` value written (shared so tests can read it
    /// after the backend is boxed).
    pub datapath_flags_writes: std::sync::Arc<std::sync::Mutex<Vec<u32>>>,
    /// Lifecycle counters (shared so tests can read them after the backend is
    /// boxed): detach_hooks must only ever run during shutdown.
    pub detach_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub dynamic_attach_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub dynamic_forget_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub routing_meta_write_order: Vec<u32>,
    pub routing_publication_order: Vec<MockRoutingPublicationWrite>,
    #[cfg(feature = "reload-bench-counters")]
    routing_map_writes: std::sync::Arc<std::sync::atomic::AtomicU64>,
    #[cfg(feature = "reload-bench-counters")]
    outbound_alive_writes: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Persistent allocator state; cleanup intentionally leaves this intact.
    pub udp_decision_sequence_next: u32,
    pub udp_decision_sequence_generation: u32,
    routing_fault: Option<(RoutingPushPhase, usize)>,
    #[cfg(test)]
    projection_fault: Option<(ProjectionMapOperation, usize, bool)>,
    #[cfg(test)]
    projection_writes: Vec<ProjectionMapOperation>,
    #[cfg(test)]
    domain_bitmap_add_faults: usize,
    #[cfg(test)]
    datapath_flags_fault_nth: Option<usize>,
    #[cfg(test)]
    datapath_flags_writes_after_arm: usize,
    #[cfg(test)]
    datapath_flags_write_origin: DatapathFlagsWriteOrigin,
    #[cfg(test)]
    datapath_flags_write_trace: Vec<DatapathFlagsWriteTrace>,
}

impl MockEbpfBackend {
    /// Create a new mock backend.
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "reload-bench-counters")]
    pub fn routing_map_write_counter(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        std::sync::Arc::clone(&self.routing_map_writes)
    }

    #[cfg(feature = "reload-bench-counters")]
    pub fn outbound_alive_write_counter(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        std::sync::Arc::clone(&self.outbound_alive_writes)
    }

    #[inline]
    fn count_routing_writes(&self, count: u64) {
        #[cfg(feature = "reload-bench-counters")]
        self.routing_map_writes
            .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(feature = "reload-bench-counters"))]
        let _ = count;
    }

    #[inline]
    fn count_outbound_alive_write(&self) {
        #[cfg(feature = "reload-bench-counters")]
        self.outbound_alive_writes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn seed_staged_udp_flow(&mut self, key: &TuplesKey, state: ConnState) {
        let token = state.decision_token;
        assert_ne!(token, 0);
        assert_eq!(state.state, UdpDecisionState::Pending as u8);
        self.udp_conn_state_store(key, &state).unwrap();
        self.routing_handoffs.lock().insert(
            Self::tuples_key_bytes(key),
            RoutingHandoffEntry {
                result: RoutingResult {
                    decision_token: token,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        self.redirect_track_store(
            &RedirectTuple::from_tuples(key),
            &RedirectEntry {
                decision_token: token,
                outbound: OutboundIndex::UserBase as u8,
                ..Default::default()
            },
        )
        .unwrap();
    }

    fn remove_token_bound_udp_flow(
        &mut self,
        key: &TuplesKey,
        token: u32,
        pending_only: bool,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        if token == 0 && !pending_only {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let key_bytes = Self::tuples_key_bytes(key);
        let Some(state) = self.udp_conn_states.get(&key_bytes).copied() else {
            return Ok(UdpDecisionCommitResult::Missing);
        };
        if state.decision_token != token {
            return Ok(if pending_only {
                UdpDecisionCommitResult::TokenMismatch
            } else {
                UdpDecisionCommitResult::Superseded
            });
        }
        let state_allowed = if pending_only {
            state.state == UdpDecisionState::Preparing as u8
                || state.state == UdpDecisionState::Pending as u8
        } else {
            udp_state_is_userspace_owned(state.state)
        };
        if !state_allowed {
            return Ok(UdpDecisionCommitResult::StateMismatch);
        }
        let handoff = self.routing_handoffs.lock().get(&key_bytes).copied();
        if handoff.is_some_and(|entry| entry.result.decision_token != token) {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let track_key = Self::redirect_tuple_bytes(&RedirectTuple::from_tuples(key));
        if self
            .redirect_tracks
            .get(&track_key)
            .is_some_and(|entry| entry.decision_token != token)
        {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        if handoff.is_some() {
            self.routing_handoffs.lock().remove(&key_bytes);
        }
        self.redirect_tracks.remove(&track_key);
        if self.udp_conn_states.remove(&key_bytes).is_some() {
            super::USERSPACE_CONN_STATE_DELETES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(UdpDecisionCommitResult::Applied)
    }

    pub fn fail_next_routing_phase(&mut self, phase: RoutingPushPhase) {
        self.routing_fault = Some((phase, 1));
    }

    pub fn routing_snapshot(&self) -> MockRoutingSnapshot {
        fn sorted_bitmap_map(
            map: &HashMap<[u8; 20], DomainRouting>,
            generation: u32,
        ) -> Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])> {
            let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
            let mut entries = map
                .iter()
                .filter_map(|(key, value)| {
                    let mut logical = [0; ROUTING_BITMAP_WORDS];
                    logical[..ROUTING_BITMAP_WORDS_PER_GENERATION].copy_from_slice(
                        &value.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION],
                    );
                    logical
                        .iter()
                        .any(|word| *word != 0)
                        .then_some((*key, logical))
                })
                .collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            entries
        }
        let generation = self
            .routing_meta
            .get(&ROUTING_META_ACTIVE_GENERATION_SLOT)
            .copied()
            .unwrap_or(0);
        let count = self
            .routing_meta
            .get(&routing_meta_count_slot(generation))
            .copied()
            .unwrap_or(0);
        let base = generation * MAX_MATCH_SET_LEN;
        let routing_map = (0..count)
            .filter_map(|index| {
                self.routing_map
                    .get(&(base + index))
                    .map(|value| (index, MockMatchSetSnapshot::from_match_set(value)))
            })
            .collect();
        let meta_base = routing_meta_generation_base(generation);
        let routing_meta = (0..ROUTING_META_GENERATION_STRIDE as u32)
            .map(|offset| {
                (
                    offset,
                    self.routing_meta
                        .get(&(meta_base + offset))
                        .copied()
                        .unwrap_or(0),
                )
            })
            .collect();
        MockRoutingSnapshot {
            routing_map,
            routing_meta,
            dest_lpm: sorted_bitmap_map(&self.dest_lpm_bitmap, generation),
            source_lpm: sorted_bitmap_map(&self.source_lpm_bitmap, generation),
            mac_lpm: sorted_bitmap_map(&self.mac_lpm_bitmap, generation),
            domain: sorted_bitmap_map(&self.domain_routing_bitmap, generation),
        }
    }

    pub fn active_routing_rule(&self, index: u32) -> Option<&MatchSet> {
        let generation = self
            .routing_meta
            .get(&ROUTING_META_ACTIVE_GENERATION_SLOT)
            .copied()
            .unwrap_or(0);
        self.routing_map
            .get(&(generation * MAX_MATCH_SET_LEN + index))
    }

    pub fn active_routing_rule_count(&self) -> u32 {
        let generation = self
            .routing_meta
            .get(&ROUTING_META_ACTIVE_GENERATION_SLOT)
            .copied()
            .unwrap_or(0);
        self.routing_meta
            .get(&routing_meta_count_slot(generation))
            .copied()
            .unwrap_or(0)
    }

    pub fn active_routing_group_word(&self, group: usize, word: usize) -> u32 {
        let generation = self
            .routing_meta
            .get(&ROUTING_META_ACTIVE_GENERATION_SLOT)
            .copied()
            .unwrap_or(0);
        let slot = routing_meta_bitmap_base(generation)
            + (group * ROUTING_GROUP_BITMAP_WORDS + word) as u32;
        self.routing_meta.get(&slot).copied().unwrap_or(0)
    }

    pub fn active_routing_group_meta(&self, group: u32) -> Option<RoutingGroupMeta> {
        let generation = self
            .routing_meta
            .get(&ROUTING_META_ACTIVE_GENERATION_SLOT)
            .copied()
            .unwrap_or(0);
        self.routing_group_meta
            .get(&routing_group_meta_index(generation, group))
            .copied()
    }

    fn take_routing_fault(&mut self, phase: RoutingPushPhase) -> anyhow::Result<()> {
        if let Some((configured, remaining)) = self.routing_fault
            && configured == phase
        {
            self.routing_fault = if remaining > 1 {
                Some((configured, remaining - 1))
            } else {
                None
            };
            anyhow::bail!("injected routing push failure at {phase:?}");
        }
        Ok(())
    }

    #[cfg(test)]
    fn take_projection_fault(
        &mut self,
        operation: ProjectionMapOperation,
    ) -> Result<(), super::DomainRouteWriteError> {
        self.projection_writes.push(operation);
        if let Some((configured, remaining, map_full)) = self.projection_fault
            && configured == operation
        {
            self.projection_fault = if remaining > 1 {
                Some((configured, remaining - 1, map_full))
            } else {
                None
            };
            if map_full {
                return Err(super::DomainRouteWriteError::MapFull);
            }
            return Err(super::DomainRouteWriteError::Other(anyhow::anyhow!(
                "injected projection {operation:?} failure"
            )));
        }
        Ok(())
    }

    // These convert repr(C) types to fixed-size byte arrays so they
    // can be used as HashMap keys (which require Hash + Eq).

    /// Hash a ConnTuple into a fixed-size key for HashMap storage.
    fn tuple_key(tuple: &ConnTuple) -> [u8; 37] {
        let mut key = [0u8; 37];
        key[0..16].copy_from_slice(&tuple.src_ip);
        key[16..32].copy_from_slice(&tuple.dst_ip);
        key[32..34].copy_from_slice(&tuple.src_port.to_be_bytes());
        key[34..36].copy_from_slice(&tuple.dst_port.to_be_bytes());
        key[36] = tuple.protocol;
        key
    }

    /// Convert a TuplesKey into a 40-byte array (includes repr(C) padding).
    fn tuples_key_bytes(key: &TuplesKey) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..16].copy_from_slice(unsafe { &key.src_ip.u6_addr8 });
        buf[16..32].copy_from_slice(unsafe { &key.dst_ip.u6_addr8 });
        buf[32..34].copy_from_slice(&key.src_port.to_ne_bytes());
        buf[34..36].copy_from_slice(&key.dst_port.to_ne_bytes());
        buf[36] = key.l4proto;
        // bytes 37..40 are padding (already zero)
        buf
    }

    /// Convert a RedirectTuple into its exact 40-byte `repr(C)` map key.
    fn redirect_tuple_bytes(key: &RedirectTuple) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..16].copy_from_slice(unsafe { &key.src_ip.u6_addr8 });
        buf[16..32].copy_from_slice(unsafe { &key.dst_ip.u6_addr8 });
        buf[32..34].copy_from_slice(&key.src_port.to_ne_bytes());
        buf[34..36].copy_from_slice(&key.dst_port.to_ne_bytes());
        buf[36] = key.l4proto;
        buf
    }

    /// Convert an LpmKey into a 20-byte array.
    fn lpm_key_bytes(key: &LpmKey) -> [u8; 20] {
        super::maps::lpm_key_bytes(key)
    }

    fn bitmap_for_active_generation(&self, bitmap: &DomainRouting) -> DomainRouting {
        let generation = self
            .routing_meta
            .get(&ROUTING_META_ACTIVE_GENERATION_SLOT)
            .copied()
            .unwrap_or(0);
        bitmap.for_generation(generation)
    }

    fn replace_active_bitmap(
        &self,
        current: Option<DomainRouting>,
        bitmap: &DomainRouting,
    ) -> DomainRouting {
        let generation = self
            .routing_meta
            .get(&ROUTING_META_ACTIVE_GENERATION_SLOT)
            .copied()
            .unwrap_or(0);
        let mut value = current.unwrap_or_default();
        let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
        value.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION]
            .copy_from_slice(&bitmap.bitmap[..ROUTING_BITMAP_WORDS_PER_GENERATION]);
        value
    }

    /// OR a DomainRouting bitmap into the given in-memory map keyed by LpmKey.
    fn or_bitmap(map: &mut HashMap<[u8; 20], DomainRouting>, key: &LpmKey, bm: &DomainRouting) {
        let k = Self::lpm_key_bytes(key);
        let mut cur = map.get(&k).copied().unwrap_or_default();
        for i in 0..cur.bitmap.len() {
            cur.bitmap[i] |= bm.bitmap[i];
        }
        map.insert(k, cur);
    }

    /// Reverse of tuples_key_bytes.
    fn bytes_to_tuples_key(buf: &[u8; 40]) -> TuplesKey {
        TuplesKey {
            src_ip: honk_ebpf_common::dae_ip::In6Addr {
                u6_addr8: buf[0..16].try_into().unwrap(),
            },
            dst_ip: honk_ebpf_common::dae_ip::In6Addr {
                u6_addr8: buf[16..32].try_into().unwrap(),
            },
            src_port: u16::from_ne_bytes([buf[32], buf[33]]),
            dst_port: u16::from_ne_bytes([buf[34], buf[35]]),
            l4proto: buf[36],
        }
    }

    /// Reverse of redirect_tuple_bytes.
    fn bytes_to_redirect_tuple(buf: &[u8; 40]) -> RedirectTuple {
        RedirectTuple {
            src_ip: honk_ebpf_common::dae_ip::In6Addr {
                u6_addr8: buf[0..16].try_into().unwrap(),
            },
            dst_ip: honk_ebpf_common::dae_ip::In6Addr {
                u6_addr8: buf[16..32].try_into().unwrap(),
            },
            src_port: u16::from_ne_bytes([buf[32], buf[33]]),
            dst_port: u16::from_ne_bytes([buf[34], buf[35]]),
            l4proto: buf[36],
            padding: [0; 3],
        }
    }
}

#[async_trait]
impl EbpfBackend for MockEbpfBackend {
    fn inject_routing_fault(
        &mut self,
        phase: RoutingPushPhase,
        times: usize,
    ) -> anyhow::Result<()> {
        self.routing_fault = (times != 0).then_some((phase, times));
        Ok(())
    }

    #[cfg(test)]
    fn inject_projection_fault(
        &mut self,
        operation: ProjectionMapOperation,
        times: usize,
        map_full: bool,
    ) -> anyhow::Result<()> {
        self.projection_fault = (times != 0).then_some((operation, times, map_full));
        Ok(())
    }

    #[cfg(test)]
    fn inject_domain_bitmap_add_fault(&mut self, times: usize) -> anyhow::Result<()> {
        self.domain_bitmap_add_faults = times;
        Ok(())
    }

    #[cfg(test)]
    fn projection_map_snapshot(&self) -> Vec<([u8; 20], DomainRouting)> {
        let mut snapshot = self
            .domain_routing_bitmap
            .iter()
            .map(|(key, bitmap)| (*key, *bitmap))
            .collect::<Vec<_>>();
        snapshot.sort_by_key(|(key, _)| *key);
        snapshot
    }

    #[cfg(test)]
    fn projection_write_log(&self) -> Vec<ProjectionMapOperation> {
        self.projection_writes.clone()
    }

    #[cfg(test)]
    fn clear_projection_write_log(&mut self) {
        self.projection_writes.clear();
    }
    fn publish_listener_sockets(
        &mut self,
        _tcp4_fd: std::os::fd::RawFd,
        _tcp6_fd: std::os::fd::RawFd,
        _udp4_fds: &[std::os::fd::RawFd],
        _udp6_fds: &[std::os::fd::RawFd],
    ) -> anyhow::Result<()> {
        self.listener_sockets_published = true;
        Ok(())
    }

    fn set_datapath_ready(&mut self, ready: bool) -> anyhow::Result<()> {
        if ready && !self.listener_sockets_published {
            anyhow::bail!("listener socket generation is not fully published");
        }
        self.datapath_ready = ready;
        Ok(())
    }

    fn set_datapath_flags(&mut self, flags: u32) -> anyhow::Result<()> {
        self.datapath_flags_writes.lock().unwrap().push(flags);
        #[cfg(test)]
        {
            self.datapath_flags_writes_after_arm =
                self.datapath_flags_writes_after_arm.saturating_add(1);
            let ordinal = self.datapath_flags_writes_after_arm;
            let failed = self.datapath_flags_fault_nth == Some(ordinal);
            self.datapath_flags_write_trace
                .push(DatapathFlagsWriteTrace {
                    ordinal,
                    origin: std::mem::take(&mut self.datapath_flags_write_origin),
                    flags,
                    failed,
                });
            if failed {
                self.datapath_flags_fault_nth = None;
                anyhow::bail!("injected datapath flags write failure at ordinal {ordinal}");
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn arm_datapath_flags_write_fault(&mut self, nth: usize) -> anyhow::Result<()> {
        anyhow::ensure!(nth != 0, "datapath flags write ordinal must be non-zero");
        self.datapath_flags_fault_nth = Some(nth);
        self.datapath_flags_writes_after_arm = 0;
        Ok(())
    }

    #[cfg(test)]
    fn mark_datapath_flags_write_origin(&mut self, origin: DatapathFlagsWriteOrigin) {
        self.datapath_flags_write_origin = origin;
    }

    #[cfg(test)]
    fn datapath_flags_write_log(&self) -> Vec<u32> {
        self.datapath_flags_writes.lock().unwrap().clone()
    }

    #[cfg(test)]
    fn datapath_flags_write_trace(&self) -> Vec<DatapathFlagsWriteTrace> {
        self.datapath_flags_write_trace.clone()
    }

    #[cfg(test)]
    fn clear_datapath_flags_write_log(&mut self) {
        self.datapath_flags_writes.lock().unwrap().clear();
        self.datapath_flags_write_trace.clear();
        self.datapath_flags_writes_after_arm = 0;
    }

    fn quiesce_udp_staging(&mut self) -> anyhow::Result<()> {
        let staged = self
            .udp_conn_states
            .iter()
            .filter_map(|(key, state)| {
                (state.state == UdpDecisionState::Preparing as u8
                    || state.state == UdpDecisionState::Pending as u8)
                    .then_some((Self::bytes_to_tuples_key(key), state.decision_token))
            })
            .collect::<Vec<_>>();
        for (key, token) in staged {
            let result = self.remove_token_bound_udp_flow(&key, token, true)?;
            anyhow::ensure!(
                matches!(
                    result,
                    UdpDecisionCommitResult::Applied | UdpDecisionCommitResult::Missing
                ),
                "mock UDP staging quiescence rejected {token}: {result:?}"
            );
        }
        Ok(())
    }

    fn set_param(&mut self, key: ParamKey, value: u32) -> anyhow::Result<()> {
        self.params.insert(key as u32, value);
        Ok(())
    }

    fn get_param(&self, key: ParamKey) -> anyhow::Result<Option<u32>> {
        Ok(self.params.get(&(key as u32)).copied())
    }

    fn set_routing_rules(&mut self, generation: u32, rules: &[MatchSet]) -> anyhow::Result<()> {
        self.take_routing_fault(RoutingPushPhase::Rules)?;
        let base = generation * MAX_MATCH_SET_LEN;
        for (i, rule) in rules.iter().enumerate() {
            self.routing_map.insert(base + i as u32, *rule);
        }
        self.count_routing_writes(rules.len() as u64);
        Ok(())
    }

    fn active_routing_generation(&self) -> anyhow::Result<u32> {
        Ok(self
            .routing_meta
            .get(&ROUTING_META_ACTIVE_GENERATION_SLOT)
            .copied()
            .unwrap_or(0))
    }

    fn publish_routing_generation(
        &mut self,
        generation: u32,
        count: u32,
        group_bitmaps: &RoutingGroupBitmaps,
    ) -> anyhow::Result<()> {
        self.take_routing_fault(RoutingPushPhase::Meta)?;
        for (g, words) in group_bitmaps.iter().enumerate() {
            for (w, word) in words.iter().enumerate() {
                let slot = routing_meta_bitmap_base(generation)
                    + (g * ROUTING_GROUP_BITMAP_WORDS + w) as u32;
                self.routing_meta.insert(slot, *word);
                self.routing_meta_write_order.push(slot);
                self.routing_publication_order
                    .push(MockRoutingPublicationWrite::Exploded(slot));
            }
        }
        self.routing_meta
            .insert(routing_meta_count_slot(generation), count);
        self.routing_meta_write_order
            .push(routing_meta_count_slot(generation));
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::Exploded(
                routing_meta_count_slot(generation),
            ));
        for (group, bitmap) in group_bitmaps.iter().enumerate() {
            let index = routing_group_meta_index(generation, group as u32);
            self.routing_group_meta.insert(
                index,
                RoutingGroupMeta {
                    rule_count: count,
                    bitmap: *bitmap,
                },
            );
            self.routing_publication_order
                .push(MockRoutingPublicationWrite::Packed(index));
        }
        self.routing_meta
            .insert(ROUTING_META_ACTIVE_GENERATION_SLOT, generation);
        self.routing_meta_write_order
            .push(ROUTING_META_ACTIVE_GENERATION_SLOT);
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::Selector(generation));
        self.count_routing_writes(
            (ROUTING_GROUP_COUNT * ROUTING_GROUP_BITMAP_WORDS + ROUTING_GROUP_COUNT + 2) as u64,
        );
        Ok(())
    }

    fn add_domain_route(&mut self, domain: &str, outbound: OutboundIndex) -> anyhow::Result<()> {
        let hash = fnv1a_hash(domain.as_bytes());
        self.domain_routes.insert(hash, outbound as u32);
        Ok(())
    }

    fn add_domain_routing_bitmap(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let bitmap = self.bitmap_for_active_generation(bitmap);
        Self::or_bitmap(&mut self.domain_routing_bitmap, key, &bitmap);
        self.count_routing_writes(1);
        Ok(())
    }

    fn add_dest_lpm_bitmap(&mut self, key: &LpmKey, bitmap: &DomainRouting) -> anyhow::Result<()> {
        self.take_routing_fault(RoutingPushPhase::DestinationLpm)?;
        // Overwrite semantics, matching the real backend: an LPM trie lookup
        // returns the longest-prefix *match*, not the exact entry, so the
        // real backend cannot read-modify-write and overwrites instead.
        // Cross-rule bitmap merging happens in the push plan before entries
        // reach the backend.
        self.dest_lpm_bitmap
            .insert(Self::lpm_key_bytes(key), *bitmap);
        self.count_routing_writes(1);
        Ok(())
    }

    fn add_source_lpm_bitmap(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        self.take_routing_fault(RoutingPushPhase::SourceLpm)?;
        self.source_lpm_bitmap
            .insert(Self::lpm_key_bytes(key), *bitmap);
        self.count_routing_writes(1);
        Ok(())
    }

    fn add_mac_lpm_bitmap(&mut self, key: &LpmKey, bitmap: &DomainRouting) -> anyhow::Result<()> {
        self.take_routing_fault(RoutingPushPhase::MacLpm)?;
        self.mac_lpm_bitmap
            .insert(Self::lpm_key_bytes(key), *bitmap);
        self.count_routing_writes(1);
        Ok(())
    }

    fn add_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        #[cfg(test)]
        if self.domain_bitmap_add_faults > 0 {
            self.domain_bitmap_add_faults -= 1;
            anyhow::bail!("injected domain bitmap write failure");
        }
        let bitmap = self.bitmap_for_active_generation(bitmap);
        Self::or_bitmap(&mut self.domain_routing_bitmap, ip_key, &bitmap);
        self.count_routing_writes(1);
        Ok(())
    }

    fn set_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> Result<(), super::DomainRouteWriteError> {
        #[cfg(test)]
        self.take_projection_fault(ProjectionMapOperation::Set)?;
        let key = Self::lpm_key_bytes(ip_key);
        let bitmap =
            self.replace_active_bitmap(self.domain_routing_bitmap.get(&key).copied(), bitmap);
        self.domain_routing_bitmap.insert(key, bitmap);
        self.count_routing_writes(1);
        Ok(())
    }
    fn remove_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
    ) -> Result<(), super::DomainRouteWriteError> {
        #[cfg(test)]
        self.take_projection_fault(ProjectionMapOperation::Remove)?;
        let key = Self::lpm_key_bytes(ip_key);
        let Some(mut bitmap) = self.domain_routing_bitmap.get(&key).copied() else {
            return Ok(());
        };
        let generation = self.active_routing_generation()?;
        let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
        bitmap.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION].fill(0);
        if bitmap.bitmap.iter().all(|word| *word == 0) {
            self.domain_routing_bitmap.remove(&key);
        } else {
            self.domain_routing_bitmap.insert(key, bitmap);
        }
        self.count_routing_writes(1);
        Ok(())
    }

    fn stage_domain_routing_generation(
        &mut self,
        generation: u32,
        entries: &[(LpmKey, DomainRouting)],
    ) -> anyhow::Result<()> {
        self.take_routing_fault(RoutingPushPhase::DomainRouting)?;
        anyhow::ensure!(
            generation < ROUTING_BITMAP_GENERATIONS as u32,
            "invalid routing generation {generation}"
        );
        let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
        let entries_before = self.domain_routing_bitmap.len();
        for bitmap in self.domain_routing_bitmap.values_mut() {
            bitmap.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION].fill(0);
        }
        for (key, logical) in entries {
            let bitmap = self
                .domain_routing_bitmap
                .entry(Self::lpm_key_bytes(key))
                .or_default();
            bitmap.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION]
                .copy_from_slice(&logical.bitmap[..ROUTING_BITMAP_WORDS_PER_GENERATION]);
        }
        self.count_routing_writes((entries_before + entries.len()) as u64);
        Ok(())
    }

    fn add_ip_route(&mut self, prefix: &str, outbound: OutboundIndex) -> anyhow::Result<()> {
        let (ip_str, len_str) = prefix.split_once('/').unwrap_or((prefix, "32"));
        let ip: u32 = parse_ipv4(ip_str)?;
        let prefix_len: u8 = len_str.parse().unwrap_or(32);
        self.ip_routes.insert((ip, prefix_len), outbound as u32);
        Ok(())
    }

    fn clear_routes(&mut self) -> anyhow::Result<()> {
        self.domain_routes.clear();
        self.ip_routes.clear();
        self.routing_map.clear();
        self.routing_meta.clear();
        self.routing_group_meta.clear();
        self.routing_meta_write_order.clear();
        self.routing_publication_order.clear();
        self.domain_routing_bitmap.clear();
        self.dest_lpm_bitmap.clear();
        self.source_lpm_bitmap.clear();
        self.mac_lpm_bitmap.clear();
        Ok(())
    }

    fn prune_lpm_entries(&mut self, keep: &LpmKeepSet) -> anyhow::Result<()> {
        self.take_routing_fault(RoutingPushPhase::PruneLpm)?;
        let entries_before =
            self.dest_lpm_bitmap.len() + self.source_lpm_bitmap.len() + self.mac_lpm_bitmap.len();
        self.dest_lpm_bitmap.retain(|k, _| keep.dest.contains(k));
        self.source_lpm_bitmap
            .retain(|k, _| keep.source.contains(k));
        self.mac_lpm_bitmap.retain(|k, _| keep.mac.contains(k));
        let entries_after =
            self.dest_lpm_bitmap.len() + self.source_lpm_bitmap.len() + self.mac_lpm_bitmap.len();
        self.count_routing_writes((entries_before - entries_after) as u64);
        Ok(())
    }

    fn tcp_conn_state_lookup(&self, key: &TuplesKey) -> anyhow::Result<Option<ConnState>> {
        Ok(self
            .tcp_conn_states
            .get(&Self::tuples_key_bytes(key))
            .copied())
    }

    fn tcp_conn_state_store(&mut self, key: &TuplesKey, state: &ConnState) -> anyhow::Result<()> {
        self.tcp_conn_states
            .insert(Self::tuples_key_bytes(key), *state);
        Ok(())
    }

    fn tcp_conn_state_remove(&mut self, key: &TuplesKey) -> anyhow::Result<()> {
        self.tcp_conn_states.remove(&Self::tuples_key_bytes(key));
        Ok(())
    }

    fn udp_conn_state_lookup(&self, key: &TuplesKey) -> anyhow::Result<Option<ConnState>> {
        Ok(self
            .udp_conn_states
            .get(&Self::tuples_key_bytes(key))
            .copied())
    }

    fn udp_conn_state_store(&mut self, key: &TuplesKey, state: &ConnState) -> anyhow::Result<()> {
        self.udp_conn_states
            .insert(Self::tuples_key_bytes(key), *state);
        Ok(())
    }

    fn udp_conn_state_remove(&mut self, key: &TuplesKey) -> anyhow::Result<()> {
        self.udp_conn_states.remove(&Self::tuples_key_bytes(key));
        Ok(())
    }

    fn commit_udp_decision(
        &mut self,
        key: &TuplesKey,
        token: u32,
        transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        validate_udp_decision_transition(transition)?;
        if token == 0 {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let key_bytes = Self::tuples_key_bytes(key);
        let Some(mut state) = self.udp_conn_states.get(&key_bytes).copied() else {
            return Ok(UdpDecisionCommitResult::Missing);
        };
        if state.decision_token != token {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        if let Err(result) = apply_udp_decision_transition(&mut state, transition) {
            return Ok(result);
        }
        let handoff = self.routing_handoffs.lock().get(&key_bytes).copied();
        if handoff.is_some_and(|entry| entry.result.decision_token != token) {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let track_key = Self::redirect_tuple_bytes(&RedirectTuple::from_tuples(key));
        let track = self.redirect_tracks.get(&track_key).copied();
        if track.is_some_and(|entry| entry.decision_token != token) {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let initial_transition = !matches!(transition, UdpDecisionTransition::ActivateDirect(_));
        if initial_transition && (handoff.is_none() || track.is_none()) {
            return Ok(UdpDecisionCommitResult::Missing);
        }

        if handoff.is_some() {
            self.routing_handoffs.lock().remove(&key_bytes);
        }
        match transition {
            UdpDecisionTransition::ActivateProxy(outbound, _) => {
                let mut track = track.expect("proxy track checked above");
                track.outbound = outbound;
                self.redirect_tracks.insert(track_key, track);
            }
            UdpDecisionTransition::ArmDirect(_)
            | UdpDecisionTransition::ActivateDirect(_)
            | UdpDecisionTransition::Block => {
                self.redirect_tracks.remove(&track_key);
            }
        }
        self.udp_conn_states.insert(key_bytes, state);
        Ok(UdpDecisionCommitResult::Applied)
    }

    fn abort_pending_udp_flow(
        &mut self,
        key: &TuplesKey,
        token: u32,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        self.remove_token_bound_udp_flow(key, token, true)
    }

    fn remove_udp_flow(
        &mut self,
        key: &TuplesKey,
        token: u32,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        if token != 0 {
            return self.remove_token_bound_udp_flow(key, token, false);
        }
        let key_bytes = Self::tuples_key_bytes(key);
        let Some(state) = self.udp_conn_states.get(&key_bytes).copied() else {
            return Ok(UdpDecisionCommitResult::Missing);
        };
        if !udp_state_is_legacy_userspace_owned(&state) {
            return Ok(UdpDecisionCommitResult::Superseded);
        }
        if self.udp_conn_states.remove(&key_bytes).is_some() {
            super::USERSPACE_CONN_STATE_DELETES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(UdpDecisionCommitResult::Applied)
        } else {
            Ok(UdpDecisionCommitResult::Missing)
        }
    }

    fn verify_udp_decision_sequence(&self) -> anyhow::Result<()> {
        self.udp_decision_sequence_status().map(|_| ())
    }
    fn udp_decision_sequence_status(&self) -> anyhow::Result<UdpDecisionSequenceStatus> {
        anyhow::ensure!(
            self.udp_decision_sequence_next <= honk_ebpf_common::UDP_DECISION_SEQUENCE_MASK,
            "invalid mock UDP decision sequence"
        );
        anyhow::ensure!(
            self.udp_decision_sequence_generation <= honk_ebpf_common::UDP_DECISION_GENERATION_MASK,
            "invalid mock UDP decision generation"
        );
        Ok(UdpDecisionSequenceStatus {
            next: self.udp_decision_sequence_next,
            generation: self.udp_decision_sequence_generation,
        })
    }

    fn reset_udp_decision_sequence(&mut self, generation: u32) -> anyhow::Result<bool> {
        anyhow::ensure!(
            generation <= honk_ebpf_common::UDP_DECISION_GENERATION_MASK,
            "invalid UDP decision generation {generation}"
        );
        anyhow::ensure!(
            self.udp_decision_sequence_status()?.exhausted(),
            "UDP decision sequence is not exhausted"
        );
        let conflicts_with_rollback = |token| {
            token != 0 && honk_ebpf_common::udp_decision_token_generation(token) >= generation
        };
        let generation_is_live = self
            .udp_conn_states
            .values()
            .any(|state| conflicts_with_rollback(state.decision_token))
            || self
                .udp_retire_fences
                .values()
                .any(|token| conflicts_with_rollback(*token))
            || self
                .routing_handoffs
                .lock()
                .values()
                .any(|entry| conflicts_with_rollback(entry.result.decision_token))
            || self
                .redirect_tracks
                .values()
                .any(|entry| conflicts_with_rollback(entry.decision_token));
        if generation_is_live {
            return Ok(false);
        }
        self.udp_decision_sequence_next = 0;
        self.udp_decision_sequence_generation = generation;
        Ok(true)
    }

    fn routing_handoff_lookup(
        &self,
        key: &TuplesKey,
    ) -> anyhow::Result<Option<RoutingHandoffEntry>> {
        Ok(self
            .routing_handoffs
            .lock()
            .get(&Self::tuples_key_bytes(key))
            .copied())
    }

    fn redirect_track_lookup(&self, key: &RedirectTuple) -> anyhow::Result<Option<RedirectEntry>> {
        Ok(self
            .redirect_tracks
            .get(&Self::redirect_tuple_bytes(key))
            .copied())
    }

    fn redirect_track_store(
        &mut self,
        key: &RedirectTuple,
        entry: &RedirectEntry,
    ) -> anyhow::Result<()> {
        self.redirect_tracks
            .insert(Self::redirect_tuple_bytes(key), *entry);
        Ok(())
    }

    fn redirect_track_remove(&mut self, key: &RedirectTuple) -> anyhow::Result<()> {
        self.redirect_tracks
            .remove(&Self::redirect_tuple_bytes(key));
        Ok(())
    }

    fn routing_handoff_take(&self, key: &TuplesKey) -> anyhow::Result<Option<RoutingHandoffEntry>> {
        Ok(self
            .routing_handoffs
            .lock()
            .remove(&Self::tuples_key_bytes(key)))
    }

    fn cookie_pid_lookup(&self, cookie: u64) -> anyhow::Result<Option<PIDName>> {
        Ok(self.cookie_pids.get(&cookie).copied())
    }

    fn cookie_pid_store(&mut self, cookie: u64, entry: &PIDName) -> anyhow::Result<()> {
        self.cookie_pids.insert(cookie, *entry);
        Ok(())
    }

    fn cookie_pid_remove(&mut self, cookie: &u64) -> anyhow::Result<()> {
        self.cookie_pids.remove(cookie);
        Ok(())
    }

    fn set_outbound_alive(
        &mut self,
        outbound: u8,
        domain: u32,
        ipver: u32,
        alive: bool,
    ) -> anyhow::Result<()> {
        let key = (outbound as u32)
            .wrapping_mul(6)
            .wrapping_add(domain.wrapping_mul(2))
            .wrapping_add(ipver);
        self.count_outbound_alive_write();
        self.outbound_alive.insert(key, if alive { 1 } else { 0 });
        Ok(())
    }

    fn get_outbound_alive(&self, outbound: u8, domain: u32, ipver: u32) -> anyhow::Result<bool> {
        let key = (outbound as u32)
            .wrapping_mul(6)
            .wrapping_add(domain.wrapping_mul(2))
            .wrapping_add(ipver);
        Ok(self.outbound_alive.get(&key).copied().unwrap_or(0) != 0)
    }

    fn get_outbound_stats(&self, outbound: OutboundIndex) -> anyhow::Result<OutboundStats> {
        Ok(self
            .stats
            .get(&(outbound as u32))
            .copied()
            .unwrap_or_default())
    }

    fn clear_outbound_stats(&mut self, outbound: OutboundIndex) -> anyhow::Result<()> {
        self.stats.insert(outbound as u32, OutboundStats::default());
        Ok(())
    }

    fn get_bpf_stats(&self, key: u32) -> anyhow::Result<Option<u64>> {
        Ok(self.bpf_stats.get(&key).copied())
    }

    fn conn_track_lookup(&self, tuple: &ConnTuple) -> anyhow::Result<Option<u32>> {
        Ok(self.conn_track.get(&Self::tuple_key(tuple)).copied())
    }

    fn conn_track_store(&mut self, tuple: &ConnTuple, outbound_idx: u32) -> anyhow::Result<()> {
        self.conn_track.insert(Self::tuple_key(tuple), outbound_idx);
        Ok(())
    }

    fn conn_track_remove(&mut self, tuple: &ConnTuple) -> anyhow::Result<()> {
        self.conn_track.remove(&Self::tuple_key(tuple));
        Ok(())
    }

    fn redirect_track_snapshot(
        &self,
        out: &mut Vec<(RedirectTuple, RedirectEntry)>,
    ) -> anyhow::Result<()> {
        for (kb, entry) in &self.redirect_tracks {
            out.push((Self::bytes_to_redirect_tuple(kb), *entry));
        }
        Ok(())
    }

    fn redirect_track_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut super::RedirectTrackChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut chunk = Vec::with_capacity(chunk_size.max(1));
        for (key, entry) in &self.redirect_tracks {
            chunk.push((Self::bytes_to_redirect_tuple(key), *entry));
            if chunk.len() == chunk_size.max(1) {
                if !visit(&chunk) {
                    return Ok(());
                }
                chunk.clear();
            }
        }
        if !chunk.is_empty() {
            visit(&chunk);
        }
        Ok(())
    }

    fn cookie_pid_snapshot(&self, out: &mut Vec<(u64, PIDName)>) -> anyhow::Result<()> {
        out.extend(self.cookie_pids.iter().map(|(&c, &e)| (c, e)));
        Ok(())
    }

    fn cookie_pid_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut super::CookiePidChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut chunk = Vec::with_capacity(chunk_size.max(1));
        for (&cookie, &entry) in &self.cookie_pids {
            chunk.push((cookie, entry));
            if chunk.len() == chunk_size.max(1) {
                if !visit(&chunk) {
                    return Ok(());
                }
                chunk.clear();
            }
        }
        if !chunk.is_empty() {
            visit(&chunk);
        }
        Ok(())
    }

    fn routing_handoff_snapshot(
        &self,
        out: &mut Vec<(TuplesKey, RoutingHandoffEntry)>,
    ) -> anyhow::Result<()> {
        for (kb, entry) in self.routing_handoffs.lock().iter() {
            out.push((Self::bytes_to_tuples_key(kb), *entry));
        }
        Ok(())
    }

    fn routing_handoff_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut super::RoutingHandoffChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut chunk = Vec::with_capacity(chunk_size.max(1));
        for (key, entry) in self.routing_handoffs.lock().iter() {
            chunk.push((Self::bytes_to_tuples_key(key), *entry));
            if chunk.len() == chunk_size.max(1) {
                if !visit(&chunk) {
                    return Ok(());
                }
                chunk.clear();
            }
        }
        if !chunk.is_empty() {
            visit(&chunk);
        }
        Ok(())
    }

    fn redirect_track_remove_batch(&mut self, keys: &[RedirectTuple]) -> anyhow::Result<()> {
        for key in keys {
            self.redirect_tracks
                .remove(&Self::redirect_tuple_bytes(key));
        }
        Ok(())
    }

    fn conn_state_snapshot(&self, out: &mut Vec<(TuplesKey, ConnState)>) -> anyhow::Result<()> {
        for (kb, entry) in self
            .tcp_conn_states
            .iter()
            .chain(self.udp_conn_states.iter())
        {
            out.push((Self::bytes_to_tuples_key(kb), *entry));
        }
        Ok(())
    }

    fn conn_state_remove_batch(&mut self, keys: &[TuplesKey]) -> anyhow::Result<()> {
        for key in keys {
            let kb = Self::tuples_key_bytes(key);
            self.tcp_conn_states.remove(&kb);
            self.udp_conn_states.remove(&kb);
        }
        Ok(())
    }

    fn cookie_pid_remove_batch(&mut self, cookies: &[u64]) -> anyhow::Result<()> {
        for cookie in cookies {
            self.cookie_pids.remove(cookie);
        }
        Ok(())
    }

    fn routing_handoff_remove_batch(&mut self, keys: &[TuplesKey]) -> anyhow::Result<()> {
        let handoffs = self.routing_handoffs.get_mut();
        for key in keys {
            handoffs.remove(&Self::tuples_key_bytes(key));
        }
        Ok(())
    }

    fn conn_state_remove_if_unchanged(
        &mut self,
        entries: &[(TuplesKey, ConnState)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        for (key, scanned) in entries {
            let map = if key.l4proto == 6 {
                &mut self.tcp_conn_states
            } else {
                &mut self.udp_conn_states
            };
            let raw = Self::tuples_key_bytes(key);
            if map.get(&raw).is_some_and(|current| {
                current.last_seen_ns == scanned.last_seen_ns
                    && current.state == scanned.state
                    && current.last_seen_ns <= expired_before_ns
            }) {
                map.remove(&raw);
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn redirect_track_remove_if_unchanged(
        &mut self,
        entries: &[(RedirectTuple, RedirectEntry)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        for (key, scanned) in entries {
            let raw = Self::redirect_tuple_bytes(key);
            if self.redirect_tracks.get(&raw).is_some_and(|current| {
                current.last_seen_ns == scanned.last_seen_ns
                    && current.last_seen_ns <= expired_before_ns
            }) {
                self.redirect_tracks.remove(&raw);
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn cookie_pid_remove_if_unchanged(
        &mut self,
        entries: &[(u64, PIDName)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        for (cookie, scanned) in entries {
            if self.cookie_pids.get(cookie).is_some_and(|current| {
                current.last_seen_ns == scanned.last_seen_ns
                    && current.last_seen_ns <= expired_before_ns
            }) {
                self.cookie_pids.remove(cookie);
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn routing_handoff_remove_if_unchanged(
        &mut self,
        entries: &[(TuplesKey, RoutingHandoffEntry)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        let handoffs = self.routing_handoffs.get_mut();
        for (key, scanned) in entries {
            let raw = Self::tuples_key_bytes(key);
            if handoffs.get(&raw).is_some_and(|current| {
                current.last_seen_ns == scanned.last_seen_ns
                    && current.last_seen_ns <= expired_before_ns
            }) {
                handoffs.remove(&raw);
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn detach_hooks(&mut self) -> anyhow::Result<()> {
        self.detach_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn attach_dynamic_interface(
        &mut self,
        _ifname: &str,
        _role: super::IfaceRole,
        _single_homed: bool,
    ) -> anyhow::Result<super::DynamicHooks> {
        self.dynamic_attach_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(super::DynamicHooks {
            ingress: true,
            egress: true,
        })
    }

    fn forget_dynamic_interface(&mut self, _ifindex: u32) {
        self.dynamic_forget_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    async fn cleanup(&mut self) -> anyhow::Result<()> {
        self.params.clear();
        self.datapath_ready = false;
        self.listener_sockets_published = false;
        self.domain_routes.clear();
        self.ip_routes.clear();
        self.stats.clear();
        self.conn_track.clear();
        self.routing_map.clear();
        self.routing_meta.clear();
        self.domain_routing_bitmap.clear();
        self.tcp_conn_states.clear();
        self.udp_conn_states.clear();
        self.redirect_tracks.clear();
        self.routing_handoffs.get_mut().clear();
        self.cookie_pids.clear();
        self.outbound_alive.clear();
        self.bpf_stats.clear();
        Ok(())
    }
}

#[cfg(test)]
mod janitor_conditional_delete_tests {
    use super::*;

    #[test]
    fn reused_tuple_survives_stale_conditional_delete() {
        let mut backend = MockEbpfBackend::default();
        let key = TuplesKey {
            l4proto: 6,
            ..Default::default()
        };
        let old = ConnState {
            last_seen_ns: 1,
            ..Default::default()
        };
        let fresh = ConnState {
            last_seen_ns: 2,
            ..Default::default()
        };
        backend.tcp_conn_state_store(&key, &old).unwrap();
        backend.tcp_conn_state_store(&key, &fresh).unwrap();

        assert_eq!(
            backend
                .conn_state_remove_if_unchanged(&[(key, old)], 10)
                .unwrap(),
            0
        );
        assert_eq!(
            backend
                .tcp_conn_state_lookup(&key)
                .unwrap()
                .unwrap()
                .last_seen_ns,
            fresh.last_seen_ns
        );
    }

    #[test]
    fn unchanged_expired_entry_is_removed() {
        let mut backend = MockEbpfBackend::default();
        let key = TuplesKey {
            l4proto: 6,
            ..Default::default()
        };
        let stale = ConnState {
            last_seen_ns: 1,
            ..Default::default()
        };
        backend.tcp_conn_state_store(&key, &stale).unwrap();

        assert_eq!(
            backend
                .conn_state_remove_if_unchanged(&[(key, stale)], 10)
                .unwrap(),
            1
        );
        assert!(backend.tcp_conn_state_lookup(&key).unwrap().is_none());
    }
}

/// FNV-1a hash function (same as eBPF side).
fn fnv1a_hash(data: &[u8]) -> u64 {
    super::maps::fnv1a_hash(data)
}

/// Parse an IPv4 string to u32.
fn parse_ipv4(s: &str) -> anyhow::Result<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        anyhow::bail!("Invalid IPv4: {}", s);
    }
    let mut ip: u32 = 0;
    for (i, part) in parts.iter().enumerate() {
        let byte: u8 = part.parse()?;
        ip |= (byte as u32) << (24 - i * 8);
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_ebpf_common::conn::TcpState;
    use honk_ebpf_common::dae_ip::In6Addr;

    #[test]
    fn conn_state_conditional_delete_rejects_state_change() {
        let mut backend = MockEbpfBackend::new();
        let mut key: TuplesKey = unsafe { std::mem::zeroed() };
        key.l4proto = 6;
        let scanned = ConnState {
            state: TcpState::TcpStateActive as u8,
            last_seen_ns: 1,
            ..Default::default()
        };
        let current = ConnState {
            state: TcpState::TcpStateClosing as u8,
            ..scanned
        };
        backend.tcp_conn_state_store(&key, &current).unwrap();

        assert_eq!(
            backend
                .conn_state_remove_if_unchanged(&[(key, scanned)], 10)
                .unwrap(),
            0
        );
        assert_eq!(
            backend.tcp_conn_state_lookup(&key).unwrap().unwrap().state,
            current.state
        );
    }

    #[test]
    fn test_mock_params() {
        let mut backend = MockEbpfBackend::new();
        backend
            .set_param(ParamKey::BigEndianTproxyPort, 12345)
            .unwrap();
        assert_eq!(
            backend.get_param(ParamKey::BigEndianTproxyPort).unwrap(),
            Some(12345)
        );
        assert_eq!(backend.get_param(ParamKey::ControlPlanePid).unwrap(), None);
    }

    #[test]
    fn test_mock_datapath_readiness() {
        let mut backend = MockEbpfBackend::new();
        assert!(!backend.datapath_ready);
        assert!(backend.set_datapath_ready(true).is_err());
        backend
            .publish_listener_sockets(10, 11, &[12, 13, 14, 15], &[16, 17, 18, 19])
            .unwrap();
        backend.set_datapath_ready(true).unwrap();
        assert!(backend.datapath_ready);
        backend.set_datapath_ready(false).unwrap();
        assert!(!backend.datapath_ready);
    }

    #[test]
    fn test_mock_domain_route() {
        let mut backend = MockEbpfBackend::new();
        backend
            .add_domain_route("google.com", OutboundIndex::UserBase)
            .unwrap();
        let hash = fnv1a_hash(b"google.com");
        assert!(backend.domain_routes.contains_key(&hash));
    }

    #[test]
    fn test_mock_ip_route() {
        let mut backend = MockEbpfBackend::new();
        backend
            .add_ip_route("10.0.0.0/8", OutboundIndex::Direct)
            .unwrap();
        assert_eq!(backend.ip_routes.len(), 1);
    }

    #[test]
    fn test_mock_conn_track() {
        let mut backend = MockEbpfBackend::new();
        let tuple = ConnTuple::default();
        backend
            .conn_track_store(&tuple, OutboundIndex::Direct as u32)
            .unwrap();
        assert_eq!(
            backend.conn_track_lookup(&tuple).unwrap(),
            Some(OutboundIndex::Direct as u32)
        );
        backend.conn_track_remove(&tuple).unwrap();
        assert_eq!(backend.conn_track_lookup(&tuple).unwrap(), None);
    }

    fn decision_test_key() -> TuplesKey {
        let mut key: TuplesKey = unsafe { std::mem::zeroed() };
        key.dst_ip[15] = 1;
        key.src_ip[15] = 2;
        key.dst_port = 443;
        key.src_port = 53000;
        key.l4proto = 17;
        key
    }

    fn decision_test_meta(outbound: u8, mark: u32, dscp: u8) -> RoutingMeta {
        RoutingMeta {
            raw: outbound as u64
                | ((mark as u64) << 8)
                | (1 << 40)
                | ((dscp as u64) << 48)
                | ROUTING_META_FLAG_PUBLISHED,
        }
    }

    fn seed_staged_flow(backend: &mut MockEbpfBackend, key: &TuplesKey, token: u32) {
        backend.seed_staged_udp_flow(
            key,
            ConnState {
                state: UdpDecisionState::Pending as u8,
                decision_token: token,
                last_seen_ns: 1,
                meta: decision_test_meta(OutboundIndex::UserBase as u8, TPROXY_MARK, 5),
                pid: 99,
                ..Default::default()
            },
        );
    }

    #[test]
    fn udp_direct_transition_is_two_phase_and_preserves_metadata() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        seed_staged_flow(&mut backend, &key, 7);

        assert_eq!(
            backend
                .commit_udp_decision(&key, 7, UdpDecisionTransition::ArmDirect(0x1234))
                .unwrap(),
            UdpDecisionCommitResult::Applied
        );
        let armed = backend.udp_conn_state_lookup(&key).unwrap().unwrap();
        let armed_raw = unsafe { armed.meta.raw };
        assert_eq!(armed.state, UdpDecisionState::DirectArmed as u8);
        assert_eq!(armed.decision_token, 7);
        assert_eq!(armed.pid, 99);
        assert_eq!(armed_raw & 0xff, OutboundIndex::Direct as u64);
        assert_eq!((armed_raw >> 8) & 0xffff_ffff, 0x1234);
        assert_eq!((armed_raw >> 48) & 0xff, 5);
        assert_eq!(armed_raw & ROUTING_META_FLAG_OFFLOAD, 0);
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .is_none()
        );

        assert_eq!(
            backend
                .commit_udp_decision(&key, 7, UdpDecisionTransition::ActivateDirect(0x5678))
                .unwrap(),
            UdpDecisionCommitResult::StateMismatch
        );
        assert_eq!(
            backend
                .commit_udp_decision(&key, 7, UdpDecisionTransition::ActivateDirect(0x1234))
                .unwrap(),
            UdpDecisionCommitResult::Applied
        );
        let active = backend.udp_conn_state_lookup(&key).unwrap().unwrap();
        let active_raw = unsafe { active.meta.raw };
        assert_eq!(active.state, UdpDecisionState::None as u8);
        assert_eq!((active_raw >> 8) & 0xffff_ffff, 0x1234);
        assert_ne!(active_raw & ROUTING_META_FLAG_OFFLOAD, 0);
        assert_eq!(
            backend
                .commit_udp_decision(&key, 7, UdpDecisionTransition::ActivateDirect(0x1234))
                .unwrap(),
            UdpDecisionCommitResult::StateMismatch
        );
    }

    #[test]
    fn udp_proxy_transition_rewrites_exact_track() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        seed_staged_flow(&mut backend, &key, 11);
        assert_eq!(
            backend
                .commit_udp_decision(
                    &key,
                    11,
                    UdpDecisionTransition::ActivateProxy(OutboundIndex::UserBase as u8 + 2, 42),
                )
                .unwrap(),
            UdpDecisionCommitResult::Applied
        );
        let state = backend.udp_conn_state_lookup(&key).unwrap().unwrap();
        let raw = unsafe { state.meta.raw };
        assert_eq!(state.state, UdpDecisionState::Proxy as u8);
        assert_eq!(raw & 0xff, (OutboundIndex::UserBase as u8 + 2) as u64);
        assert_eq!((raw >> 8) & 0xffff_ffff, 42);
        assert_eq!((raw >> 48) & 0xff, 5);
        let track = backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .unwrap();
        assert_eq!(track.decision_token, 11);
        assert_eq!(track.outbound, OutboundIndex::UserBase as u8 + 2);
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
        assert_eq!(
            backend.remove_udp_flow(&key, 11).unwrap(),
            UdpDecisionCommitResult::Applied
        );
        assert!(backend.udp_conn_state_lookup(&key).unwrap().is_none());
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn udp_transition_distinguishes_missing_token_and_state_mismatches() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        assert_eq!(
            backend
                .commit_udp_decision(&key, 1, UdpDecisionTransition::Block)
                .unwrap(),
            UdpDecisionCommitResult::Missing
        );
        seed_staged_flow(&mut backend, &key, 17);
        assert_eq!(
            backend
                .commit_udp_decision(&key, 18, UdpDecisionTransition::Block)
                .unwrap(),
            UdpDecisionCommitResult::TokenMismatch
        );
        let mut newer = backend.udp_conn_state_lookup(&key).unwrap().unwrap();
        newer.state = UdpDecisionState::Proxy as u8;
        backend.udp_conn_state_store(&key, &newer).unwrap();
        assert_eq!(
            backend
                .commit_udp_decision(&key, 17, UdpDecisionTransition::Block)
                .unwrap(),
            UdpDecisionCommitResult::StateMismatch
        );
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_some());
    }

    #[test]
    fn stale_auxiliary_token_never_mutates_newer_incarnation() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        seed_staged_flow(&mut backend, &key, 21);
        backend
            .routing_handoffs
            .lock()
            .get_mut(&MockEbpfBackend::tuples_key_bytes(&key))
            .unwrap()
            .result
            .decision_token = 22;
        assert_eq!(
            backend.abort_pending_udp_flow(&key, 21).unwrap(),
            UdpDecisionCommitResult::TokenMismatch
        );
        assert_eq!(
            backend
                .udp_conn_state_lookup(&key)
                .unwrap()
                .unwrap()
                .decision_token,
            21
        );
        assert_eq!(
            backend
                .routing_handoff_lookup(&key)
                .unwrap()
                .unwrap()
                .result
                .decision_token,
            22
        );
    }

    #[test]
    fn legacy_removal_deletes_only_non_offloaded_forward_state() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        backend
            .udp_conn_state_store(
                &key,
                &ConnState {
                    state: UdpDecisionState::None as u8,
                    meta: RoutingMeta {
                        raw: OutboundIndex::UserBase as u64 | ROUTING_META_FLAG_PUBLISHED,
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        backend.routing_handoffs.lock().insert(
            MockEbpfBackend::tuples_key_bytes(&key),
            RoutingHandoffEntry::default(),
        );
        backend
            .redirect_track_store(&RedirectTuple::from_tuples(&key), &RedirectEntry::default())
            .unwrap();

        assert_eq!(
            backend.remove_udp_flow(&key, 0).unwrap(),
            UdpDecisionCommitResult::Applied
        );
        assert!(backend.udp_conn_state_lookup(&key).unwrap().is_none());
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_some());
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .is_some()
        );

        for terminal_raw in [
            OutboundIndex::Direct as u64 | ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD,
            OutboundIndex::Direct as u64 | ROUTING_META_FLAG_PUBLISHED | (1 << 40),
            OutboundIndex::Block as u64 | ROUTING_META_FLAG_PUBLISHED,
        ] {
            backend
                .udp_conn_state_store(
                    &key,
                    &ConnState {
                        state: UdpDecisionState::None as u8,
                        meta: RoutingMeta { raw: terminal_raw },
                        ..Default::default()
                    },
                )
                .unwrap();
            assert_eq!(
                backend.remove_udp_flow(&key, 0).unwrap(),
                UdpDecisionCommitResult::Superseded
            );
            assert!(backend.udp_conn_state_lookup(&key).unwrap().is_some());
        }
    }

    #[test]
    fn abort_accounts_state_delete_and_sequence_survives_cleanup() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        seed_staged_flow(&mut backend, &key, 31);
        let before =
            crate::ebpf::USERSPACE_CONN_STATE_DELETES.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            backend.abort_pending_udp_flow(&key, 31).unwrap(),
            UdpDecisionCommitResult::Applied
        );
        assert!(
            crate::ebpf::USERSPACE_CONN_STATE_DELETES.load(std::sync::atomic::Ordering::Relaxed)
                > before
        );
        backend.udp_decision_sequence_next = 123;
        futures::executor::block_on(backend.cleanup()).unwrap();
        assert_eq!(backend.udp_decision_sequence_next, 123);
    }

    #[test]
    fn exhausted_sequence_skips_rollback_reachable_generations() {
        let mut backend = MockEbpfBackend::new();
        backend.udp_decision_sequence_next = UDP_DECISION_SEQUENCE_MASK;
        let key = decision_test_key();
        let live_token = udp_decision_token(1, 7).unwrap();
        backend
            .udp_conn_state_store(
                &key,
                &ConnState {
                    state: UdpDecisionState::Proxy as u8,
                    decision_token: live_token,
                    ..Default::default()
                },
            )
            .unwrap();

        assert!(!backend.reset_udp_decision_sequence(0).unwrap());
        assert!(!backend.reset_udp_decision_sequence(1).unwrap());

        assert!(backend.reset_udp_decision_sequence(2).unwrap());
        assert_eq!(
            backend.udp_decision_sequence_status().unwrap(),
            UdpDecisionSequenceStatus {
                next: 0,
                generation: 2,
            }
        );
    }

    #[test]
    fn exhausted_sequence_skips_live_retirement_fence() {
        let mut backend = MockEbpfBackend::new();
        backend.udp_decision_sequence_next = UDP_DECISION_SEQUENCE_MASK;
        let key = decision_test_key();
        backend.udp_retire_fences.insert(
            MockEbpfBackend::tuples_key_bytes(&key),
            udp_decision_token(1, 7).unwrap(),
        );

        assert!(!backend.reset_udp_decision_sequence(1).unwrap());
        backend.udp_retire_fences.clear();
        assert!(backend.reset_udp_decision_sequence(1).unwrap());
    }

    #[test]
    fn test_parse_ipv4() {
        assert_eq!(parse_ipv4("192.168.1.1").unwrap(), 0xc0a80101);
        assert_eq!(parse_ipv4("10.0.0.0").unwrap(), 0x0a000000);
        assert!(parse_ipv4("invalid").is_err());
    }

    #[test]
    fn test_set_routing_rules_and_count() {
        let mut backend = MockEbpfBackend::new();

        let rules = vec![
            MatchSet {
                outbound: 10,
                ..Default::default()
            },
            MatchSet {
                outbound: 20,
                ..Default::default()
            },
            MatchSet {
                outbound: 30,
                ..Default::default()
            },
        ];

        backend.set_routing_rules(0, &rules).unwrap();
        let all_groups: RoutingGroupBitmaps =
            [[u32::MAX; ROUTING_GROUP_BITMAP_WORDS]; ROUTING_GROUP_COUNT];
        backend
            .publish_routing_generation(0, 3, &all_groups)
            .unwrap();

        assert_eq!(backend.routing_map.len(), 3);
        assert_eq!(backend.routing_map.get(&0).unwrap().outbound, 10);
        assert_eq!(backend.routing_map.get(&1).unwrap().outbound, 20);
        assert_eq!(backend.routing_map.get(&2).unwrap().outbound, 30);
        assert_eq!(
            backend
                .routing_meta
                .get(&ROUTING_META_ACTIVE_GENERATION_SLOT)
                .copied(),
            Some(0)
        );
        assert_eq!(
            backend
                .routing_meta
                .get(&routing_meta_count_slot(0))
                .copied(),
            Some(3)
        );
        for g in 0..ROUTING_GROUP_COUNT {
            for w in 0..ROUTING_GROUP_BITMAP_WORDS {
                let slot =
                    routing_meta_bitmap_base(0) + (g * ROUTING_GROUP_BITMAP_WORDS + w) as u32;
                assert_eq!(backend.routing_meta.get(&slot).copied(), Some(u32::MAX));
            }
        }

        let fewer = vec![MatchSet {
            outbound: 99,
            ..Default::default()
        }];
        backend.set_routing_rules(0, &fewer).unwrap();
        backend
            .publish_routing_generation(0, 1, &all_groups)
            .unwrap();
        assert_eq!(backend.routing_map.len(), 3);
        assert_eq!(backend.routing_map.get(&0).unwrap().outbound, 99);
        assert!(backend.routing_map.contains_key(&1));
        assert_eq!(
            backend
                .routing_meta
                .get(&routing_meta_count_slot(0))
                .copied(),
            Some(1)
        );
    }

    #[test]
    fn test_add_domain_routing_bitmap() {
        let mut backend = MockEbpfBackend::new();

        let key = LpmKey {
            prefix_len: 24,
            data: [0x0a000001, 0, 0, 0],
        };
        let mut bitmap = DomainRouting::default();
        bitmap.bitmap[0] = 0xDEADBEEF;
        bitmap.bitmap[1] = 0xCAFEBABE;

        backend.add_domain_routing_bitmap(&key, &bitmap).unwrap();

        let stored = backend
            .domain_routing_bitmap
            .get(&MockEbpfBackend::lpm_key_bytes(&key));
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().bitmap[0], 0xDEADBEEF);
        assert_eq!(stored.unwrap().bitmap[1], 0xCAFEBABE);

        let key2 = LpmKey {
            prefix_len: 16,
            data: [0x0a000001, 0, 0, 0],
        };
        assert!(
            !backend
                .domain_routing_bitmap
                .contains_key(&MockEbpfBackend::lpm_key_bytes(&key2))
        );
    }

    #[test]
    fn test_domain_ip_bitmap_set_overwrites_and_remove() {
        let mut backend = MockEbpfBackend::new();
        let key = LpmKey {
            prefix_len: 128,
            data: [0, 0, 0xffff0000, 0x0a000001],
        };
        let mut bm1 = DomainRouting::default();
        bm1.bitmap[0] = 0b001;
        let mut bm2 = DomainRouting::default();
        bm2.bitmap[0] = 0b100;

        // add_domain_ip_bitmap has OR semantics; set_domain_ip_bitmap must
        // replace the entry wholesale (used by the post-push rebuild so
        // bitmaps from a previous rule generation do not accumulate).
        backend.add_domain_ip_bitmap(&key, &bm1).unwrap();
        backend.set_domain_ip_bitmap(&key, &bm2).unwrap();
        let stored = backend
            .domain_routing_bitmap
            .get(&MockEbpfBackend::lpm_key_bytes(&key))
            .unwrap();
        assert_eq!(stored.bitmap[0], 0b100, "set must replace, not OR");

        backend.remove_domain_ip_bitmap(&key).unwrap();
        assert!(backend.domain_routing_bitmap.is_empty());
    }

    #[test]
    fn test_prune_lpm_entries() {
        let mut backend = MockEbpfBackend::new();
        let k1 = LpmKey {
            prefix_len: 104,
            data: [0, 0, 0xffff0000, 0x0a000000],
        };
        let k2 = LpmKey {
            prefix_len: 120,
            data: [0, 0, 0xffff0000, 0x01a8c0],
        };
        let mut bm = DomainRouting::default();
        bm.bitmap[0] = 1;
        backend.add_dest_lpm_bitmap(&k1, &bm).unwrap();
        backend.add_dest_lpm_bitmap(&k2, &bm).unwrap();

        let mut keep = LpmKeepSet::default();
        keep.dest.insert(MockEbpfBackend::lpm_key_bytes(&k2));
        backend.prune_lpm_entries(&keep).unwrap();
        assert_eq!(backend.dest_lpm_bitmap.len(), 1);
        assert!(
            backend
                .dest_lpm_bitmap
                .contains_key(&MockEbpfBackend::lpm_key_bytes(&k2))
        );
    }

    #[test]
    fn routing_snapshot_detects_union_payload_changes() {
        let mut backend = MockEbpfBackend::new();
        let rule = |port| MatchSet {
            value: MatchSetValue {
                port_range: PortRange {
                    port_start: port,
                    port_end: port,
                },
            },
            match_type: MatchType::Port as u8,
            ..MatchSet::default()
        };
        backend.routing_map.insert(0, rule(80));
        backend.routing_meta.insert(routing_meta_count_slot(0), 1);
        let before = backend.routing_snapshot();

        backend.routing_map.insert(0, rule(81));

        assert_ne!(backend.routing_snapshot(), before);
    }

    #[test]
    fn test_snapshots_and_remove_batch() {
        let mut backend = MockEbpfBackend::new();

        let rt_key = RedirectTuple {
            src_ip: In6Addr::default(),
            dst_ip: In6Addr::default(),
            ..Default::default()
        };
        let rt_entry = RedirectEntry {
            last_seen_ns: 111,
            ..Default::default()
        };
        backend.redirect_track_store(&rt_key, &rt_entry).unwrap();
        backend.cookie_pid_store(42, &PIDName::default()).unwrap();

        let handoff_key = TuplesKey {
            src_ip: In6Addr::default(),
            dst_ip: In6Addr::default(),
            src_port: 3000,
            dst_port: 80,
            l4proto: 6,
        };
        let handoff_entry = RoutingHandoffEntry {
            last_seen_ns: 222,
            result: RoutingResult {
                mark: 7,
                outbound: 3,
                ..Default::default()
            },
        };
        backend.routing_handoffs.lock().insert(
            MockEbpfBackend::tuples_key_bytes(&handoff_key),
            handoff_entry,
        );

        let mut rt_out = Vec::new();
        backend.redirect_track_snapshot(&mut rt_out).unwrap();
        assert_eq!(rt_out.len(), 1);
        assert_eq!(rt_out[0].1.last_seen_ns, 111);

        let mut cp_out = Vec::new();
        backend.cookie_pid_snapshot(&mut cp_out).unwrap();
        assert_eq!(cp_out.len(), 1);
        assert_eq!(cp_out[0].0, 42);

        let mut ho_out = Vec::new();
        backend.routing_handoff_snapshot(&mut ho_out).unwrap();
        assert_eq!(ho_out.len(), 1);
        assert_eq!(ho_out[0].1.result.mark, 7);

        backend.redirect_track_remove_batch(&[rt_key]).unwrap();
        backend.cookie_pid_remove_batch(&[42]).unwrap();
        backend
            .routing_handoff_remove_batch(&[handoff_key])
            .unwrap();

        assert!(backend.redirect_tracks.is_empty());
        assert!(backend.cookie_pids.is_empty());
        assert!(backend.routing_handoffs.lock().is_empty());
    }

    #[test]
    fn test_conn_state_snapshot_and_remove_batch() {
        let mut backend = MockEbpfBackend::new();

        let tcp_key = TuplesKey {
            src_ip: In6Addr::default(),
            dst_ip: In6Addr::default(),
            src_port: 4000,
            dst_port: 443,
            l4proto: 6,
        };
        let udp_key = TuplesKey {
            l4proto: 17,
            ..tcp_key
        };
        let state = ConnState {
            last_seen_ns: 999,
            ..Default::default()
        };
        backend.tcp_conn_state_store(&tcp_key, &state).unwrap();
        backend.udp_conn_state_store(&udp_key, &state).unwrap();

        let mut out = Vec::new();
        backend.conn_state_snapshot(&mut out).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|(_, s)| s.last_seen_ns == 999));

        backend
            .conn_state_remove_batch(&[tcp_key, udp_key])
            .unwrap();
        assert!(backend.tcp_conn_states.is_empty());
        assert!(backend.udp_conn_states.is_empty());

        let mut out = Vec::new();
        backend.conn_state_snapshot(&mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn test_tcp_conn_state_crud() {
        let mut backend = MockEbpfBackend::new();

        let key = TuplesKey {
            src_ip: In6Addr::default(),
            dst_ip: In6Addr::default(),
            src_port: 8080,
            dst_port: 443,
            l4proto: 6,
        };
        let state = ConnState {
            last_seen_ns: 1234567890,
            is_wan_ingress_direction: 1,
            state: 2,
            mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ..Default::default()
        };

        assert!(backend.tcp_conn_state_lookup(&key).unwrap().is_none());

        backend.tcp_conn_state_store(&key, &state).unwrap();
        let found = backend.tcp_conn_state_lookup(&key).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().last_seen_ns, 1234567890);
        assert_eq!(found.unwrap().state, 2);

        backend.tcp_conn_state_remove(&key).unwrap();
        assert!(backend.tcp_conn_state_lookup(&key).unwrap().is_none());
    }

    #[test]
    fn test_udp_conn_state_crud() {
        let mut backend = MockEbpfBackend::new();

        let key = TuplesKey {
            src_ip: In6Addr::default(),
            dst_ip: In6Addr::default(),
            src_port: 53,
            dst_port: 12345,
            l4proto: 17,
        };
        let state = ConnState {
            last_seen_ns: 987654321,
            is_wan_ingress_direction: 0,
            mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ..Default::default()
        };

        assert!(backend.udp_conn_state_lookup(&key).unwrap().is_none());

        backend.udp_conn_state_store(&key, &state).unwrap();
        let found = backend.udp_conn_state_lookup(&key).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().last_seen_ns, 987654321);

        backend.udp_conn_state_remove(&key).unwrap();
        assert!(backend.udp_conn_state_lookup(&key).unwrap().is_none());
    }

    #[test]
    fn test_redirect_track_crud() {
        let mut backend = MockEbpfBackend::new();

        let key = RedirectTuple {
            src_ip: In6Addr::default(),
            dst_ip: In6Addr::default(),
            ..Default::default()
        };
        let entry = RedirectEntry {
            last_seen_ns: 1111111111,
            dmac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            smac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            from_wan: 0,
            ifindex: 2,
            ..Default::default()
        };

        assert!(backend.redirect_track_lookup(&key).unwrap().is_none());

        backend.redirect_track_store(&key, &entry).unwrap();
        let found = backend.redirect_track_lookup(&key).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().last_seen_ns, 1111111111);

        backend.redirect_track_remove(&key).unwrap();
        assert!(backend.redirect_track_lookup(&key).unwrap().is_none());
    }

    #[test]
    fn test_routing_handoff_take() {
        let backend = MockEbpfBackend::new();

        let key = TuplesKey {
            src_ip: In6Addr::default(),
            dst_ip: In6Addr::default(),
            src_port: 3000,
            dst_port: 80,
            l4proto: 6,
        };

        let entry = RoutingHandoffEntry {
            last_seen_ns: 0,
            result: RoutingResult {
                mark: 1234,
                outbound: 5,
                ..Default::default()
            },
        };
        backend
            .routing_handoffs
            .lock()
            .insert(MockEbpfBackend::tuples_key_bytes(&key), entry);

        // take() returns the entry and removes it in one step.
        let found = backend.routing_handoff_take(&key).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().result.mark, 1234);

        assert!(backend.routing_handoff_take(&key).unwrap().is_none());
    }

    #[test]
    fn test_cookie_pid_store_lookup() {
        let mut backend = MockEbpfBackend::new();

        let cookie: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let entry = PIDName {
            pid: 12345,
            pname: {
                let mut buf = [0u8; 16];
                buf[0..4].copy_from_slice(b"curl");
                buf
            },
            ..Default::default()
        };

        assert!(backend.cookie_pid_lookup(cookie).unwrap().is_none());

        backend.cookie_pid_store(cookie, &entry).unwrap();
        let found = backend.cookie_pid_lookup(cookie).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().pid, 12345);

        assert!(backend.cookie_pid_lookup(cookie + 1).unwrap().is_none());
    }

    #[test]
    fn test_outbound_alive_set_get() {
        let mut backend = MockEbpfBackend::new();

        let outbound: u8 = 2;
        let domain: u32 = 5;
        let ipver: u32 = 4;

        assert!(!backend.get_outbound_alive(outbound, domain, ipver).unwrap());

        backend
            .set_outbound_alive(outbound, domain, ipver, true)
            .unwrap();
        assert!(backend.get_outbound_alive(outbound, domain, ipver).unwrap());

        backend
            .set_outbound_alive(outbound, domain, ipver, false)
            .unwrap();
        assert!(!backend.get_outbound_alive(outbound, domain, ipver).unwrap());

        backend.set_outbound_alive(3, domain, ipver, true).unwrap();
        assert!(!backend.get_outbound_alive(outbound, domain, ipver).unwrap());
        assert!(backend.get_outbound_alive(3, domain, ipver).unwrap());
    }

    #[test]
    fn test_get_bpf_stats() {
        let mut backend = MockEbpfBackend::new();

        assert!(backend.get_bpf_stats(0).unwrap().is_none());
        assert!(backend.get_bpf_stats(42).unwrap().is_none());

        backend.bpf_stats.insert(0, 100);
        backend.bpf_stats.insert(1, 250);
        backend.bpf_stats.insert(99, 999);

        assert_eq!(backend.get_bpf_stats(0).unwrap(), Some(100));
        assert_eq!(backend.get_bpf_stats(1).unwrap(), Some(250));
        assert_eq!(backend.get_bpf_stats(99).unwrap(), Some(999));
        assert!(backend.get_bpf_stats(50).unwrap().is_none());
    }

    #[test]
    fn test_outbound_stats_get_and_clear() {
        // The mock mirrors the real backend's read semantics: a missing
        // entry reads as all-zero (the per-CPU array in the kernel also
        // starts zeroed), and clear() resets the counters without
        // disturbing other outbounds.
        let mut backend = MockEbpfBackend::new();

        let empty = backend.get_outbound_stats(OutboundIndex::UserBase).unwrap();
        assert_eq!(empty.tx_bytes, 0);
        assert_eq!(empty.rx_bytes, 0);
        assert_eq!(empty.tx_packets, 0);
        assert_eq!(empty.rx_packets, 0);

        let stored = OutboundStats {
            tx_bytes: 1000,
            rx_bytes: 2000,
            tx_packets: 10,
            rx_packets: 20,
            ..Default::default()
        };
        backend.stats.insert(OutboundIndex::UserBase as u32, stored);
        backend.stats.insert(
            OutboundIndex::Direct as u32,
            OutboundStats {
                tx_bytes: 5,
                ..Default::default()
            },
        );

        let got = backend.get_outbound_stats(OutboundIndex::UserBase).unwrap();
        assert_eq!(got.tx_bytes, 1000);
        assert_eq!(got.rx_bytes, 2000);
        assert_eq!(got.tx_packets, 10);
        assert_eq!(got.rx_packets, 20);

        // Clearing one outbound leaves the others untouched.
        backend
            .clear_outbound_stats(OutboundIndex::UserBase)
            .unwrap();
        let cleared = backend.get_outbound_stats(OutboundIndex::UserBase).unwrap();
        assert_eq!(cleared.tx_bytes, 0);
        assert_eq!(cleared.rx_packets, 0);
        assert_eq!(
            backend
                .get_outbound_stats(OutboundIndex::Direct)
                .unwrap()
                .tx_bytes,
            5
        );
    }

    #[test]
    fn test_cleanup_clears_all_maps() {
        let mut backend = MockEbpfBackend::new();

        backend
            .set_param(ParamKey::BigEndianTproxyPort, 12345)
            .unwrap();
        backend
            .add_domain_route("example.com", OutboundIndex::Direct)
            .unwrap();
        backend
            .set_routing_rules(0, &[MatchSet::default()])
            .unwrap();
        backend
            .publish_routing_generation(
                0,
                1,
                &[[u32::MAX; ROUTING_GROUP_BITMAP_WORDS]; ROUTING_GROUP_COUNT],
            )
            .unwrap();

        let tcp_key = TuplesKey::default();
        backend
            .tcp_conn_state_store(&tcp_key, &ConnState::default())
            .unwrap();

        let udp_key = TuplesKey::default();
        backend
            .udp_conn_state_store(&udp_key, &ConnState::default())
            .unwrap();

        let rt_key = RedirectTuple::default();
        backend
            .redirect_track_store(&rt_key, &RedirectEntry::default())
            .unwrap();

        backend.cookie_pid_store(42, &PIDName::default()).unwrap();
        backend.set_outbound_alive(1, 0, 4, true).unwrap();
        backend.bpf_stats.insert(0, 999);

        let ct = ConnTuple::default();
        backend.conn_track_store(&ct, 7).unwrap();

        futures::executor::block_on(backend.cleanup()).unwrap();

        assert!(backend.params.is_empty());
        assert!(backend.domain_routes.is_empty());
        assert!(backend.routing_map.is_empty());
        assert!(backend.routing_meta.is_empty());
        assert!(backend.domain_routing_bitmap.is_empty());
        assert!(backend.tcp_conn_states.is_empty());
        assert!(backend.udp_conn_states.is_empty());
        assert!(backend.redirect_tracks.is_empty());
        assert!(backend.routing_handoffs.lock().is_empty());
        assert!(backend.cookie_pids.is_empty());
        assert!(backend.outbound_alive.is_empty());
        assert!(backend.bpf_stats.is_empty());
        assert!(backend.conn_track.is_empty());
        assert!(backend.stats.is_empty());
        assert!(backend.ip_routes.is_empty());
    }
}
