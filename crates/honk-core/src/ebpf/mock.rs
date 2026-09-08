//! Mock eBPF backend for testing.
//!
//! This backend implements the `EbpfBackend` trait using in-memory
//! data structures instead of real kernel eBPF. All operations use
//! HashMap storage.

#[cfg(test)]
use super::{DatapathFlagsWriteOrigin, DatapathFlagsWriteTrace, ProjectionMapOperation};
use super::{
    EbpfBackend, RoutingPushPhase, UdpDecisionCommitResult, UdpDecisionSequenceStatus,
    UdpDecisionTransition, apply_udp_decision_transition, udp_state_is_legacy_userspace_owned,
    udp_state_is_userspace_owned, validate_udp_decision_transition,
};
use async_trait::async_trait;
use honk_ebpf_common::*;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockRoutingSnapshot {
    pub active_slot: u32,
    pub descriptor: RoutingPolicyDescriptor,
    pub plan_fingerprint: [u8; 32],
    pub rule_count: usize,
    pub destination_v4: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub destination_v6: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub source_v4: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub source_v6: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub mac: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub domain: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockRoutingPublicationWrite {
    FactMaps(u32),
    Program(u32),
    Attach(u32),
    Root(u32),
}

#[derive(Debug, Clone)]
struct MockRoutingGeneration {
    fingerprint: [u8; 32],
    rule_count: usize,
    facts: crate::control::routing_matcher::RoutingFactMaps,
    domain: HashMap<[u32; 4], DomainRouting>,
}

/// In-memory transactional routing backend used by control-plane tests.
#[derive(Debug, Default)]
pub struct MockEbpfBackend {
    /// Only the generation selected by the stable root remains resident.
    routing_generation: Option<MockRoutingGeneration>,
    active_slot: u32,
    descriptor: RoutingPolicyDescriptor,
    next_generation: u64,
    next_domain_map_id: u32,
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
    /// Every mode-policy write, shared so tests can inspect boxed backends.
    pub datapath_flags_writes: std::sync::Arc<parking_lot::Mutex<Vec<u32>>>,
    pub detach_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub dynamic_attach_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub dynamic_forget_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
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
    fail_next_quiesce: bool,
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

    fn fact_snapshot(
        entries: &[(LpmKey, DomainRouting)],
    ) -> Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])> {
        let mut result = entries
            .iter()
            .map(|(key, value)| (Self::lpm_key_bytes(key), value.bitmap))
            .collect::<Vec<_>>();
        result.sort_by_key(|(key, _)| *key);
        result
    }

    pub fn routing_snapshot(&self) -> MockRoutingSnapshot {
        let generation = self.routing_generation.as_ref();
        let (fingerprint, rule_count, facts, mut domain) =
            generation.map_or(([0; 32], 0, None, Vec::new()), |generation| {
                let domain = generation
                    .domain
                    .iter()
                    .map(|(key, value)| {
                        let key = LpmKey {
                            prefix_len: 128,
                            data: *key,
                        };
                        (Self::lpm_key_bytes(&key), value.bitmap)
                    })
                    .collect::<Vec<_>>();
                (
                    generation.fingerprint,
                    generation.rule_count,
                    Some(&generation.facts),
                    domain,
                )
            });
        domain.sort_by_key(|(key, _)| *key);
        let (destination_v4, destination_v6, source_v4, source_v6, mac) = facts.map_or(
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()),
            |facts| {
                (
                    Self::fact_snapshot(&facts.destination_v4),
                    Self::fact_snapshot(&facts.destination_v6),
                    Self::fact_snapshot(&facts.source_v4),
                    Self::fact_snapshot(&facts.source_v6),
                    Self::fact_snapshot(&facts.mac),
                )
            },
        );
        MockRoutingSnapshot {
            active_slot: self.active_slot,
            descriptor: self.descriptor,
            plan_fingerprint: fingerprint,
            rule_count,
            destination_v4,
            destination_v6,
            source_v4,
            source_v6,
            mac,
            domain,
        }
    }

    fn take_routing_fault(&mut self, phase: RoutingPushPhase) -> anyhow::Result<()> {
        if let Some((configured, remaining)) = self.routing_fault
            && configured == phase
        {
            self.routing_fault = (remaining > 1).then_some((configured, remaining - 1));
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
            self.projection_fault =
                (remaining > 1).then_some((configured, remaining - 1, map_full));
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
            .routing_generation
            .as_ref()
            .map(|generation| {
                generation
                    .domain
                    .iter()
                    .map(|(key, bitmap)| {
                        (
                            Self::lpm_key_bytes(&LpmKey {
                                prefix_len: 128,
                                data: *key,
                            }),
                            *bitmap,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
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
        self.datapath_flags_writes.lock().push(flags);
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
    fn arm_quiesce_fault(&mut self) {
        self.fail_next_quiesce = true;
    }

    #[cfg(test)]
    fn mark_datapath_flags_write_origin(&mut self, origin: DatapathFlagsWriteOrigin) {
        self.datapath_flags_write_origin = origin;
    }

    #[cfg(test)]
    fn datapath_flags_write_log(&self) -> Vec<u32> {
        self.datapath_flags_writes.lock().clone()
    }

    #[cfg(test)]
    fn datapath_flags_write_trace(&self) -> Vec<DatapathFlagsWriteTrace> {
        self.datapath_flags_write_trace.clone()
    }

    #[cfg(test)]
    fn clear_datapath_flags_write_log(&mut self) {
        self.datapath_flags_writes.lock().clear();
        self.datapath_flags_write_trace.clear();
        self.datapath_flags_writes_after_arm = 0;
    }

    fn quiesce_udp_staging(&mut self) -> anyhow::Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_quiesce) {
            anyhow::bail!("injected quiesce failure");
        }
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

    fn publish_routing_plan(
        &mut self,
        plan: &crate::control::routing_matcher::RoutingPushPlan,
        learned_domains: &[(LpmKey, DomainRouting)],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.active_slot < 2,
            "invalid active routing slot {}",
            self.active_slot
        );
        let slot = self.active_slot ^ 1;
        self.take_routing_fault(RoutingPushPhase::DomainRouting)?;
        let domain: HashMap<_, _> = learned_domains
            .iter()
            .map(|(key, bitmap)| (key.data, *bitmap))
            .collect();
        self.take_routing_fault(RoutingPushPhase::DestinationLpm)?;
        self.take_routing_fault(RoutingPushPhase::SourceLpm)?;
        self.take_routing_fault(RoutingPushPhase::MacLpm)?;
        let domain_write_count = domain.len();
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::FactMaps(slot));
        self.take_routing_fault(RoutingPushPhase::Program)?;
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::Program(slot));
        self.take_routing_fault(RoutingPushPhase::Attach)?;
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::Attach(slot));

        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("routing generation counter exhausted"))?;
        let domain_map_id = self
            .next_domain_map_id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("domain map id counter exhausted"))?;
        let candidate = MockRoutingGeneration {
            fingerprint: plan.fingerprint,
            rule_count: plan.rules.len(),
            facts: plan.facts.clone(),
            domain,
        };
        self.take_routing_fault(RoutingPushPhase::Root)?;
        self.routing_generation = Some(candidate);
        self.active_slot = slot;
        self.descriptor = RoutingPolicyDescriptor {
            slot,
            features: plan.features,
            generation,
            domain_map_id,
            reserved: 0,
        };
        self.next_generation = generation;
        self.next_domain_map_id = domain_map_id;
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::Root(slot));
        self.count_routing_writes(
            (plan.facts.destination_v4.len()
                + plan.facts.destination_v6.len()
                + plan.facts.source_v4.len()
                + plan.facts.source_v6.len()
                + plan.facts.mac.len()
                + plan.rules.len()
                + domain_write_count
                + 1) as u64,
        );
        Ok(())
    }

    fn active_routing_generation(&self) -> anyhow::Result<u32> {
        Ok(self.active_slot)
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
        let generation = self
            .routing_generation
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no active routing generation"))?;
        let current = generation.domain.entry(ip_key.data).or_default();
        for (current, update) in current.bitmap.iter_mut().zip(bitmap.bitmap) {
            *current |= update;
        }
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
        let generation = self.routing_generation.as_mut().ok_or_else(|| {
            super::DomainRouteWriteError::Other(anyhow::anyhow!("no active routing generation"))
        })?;
        generation.domain.insert(ip_key.data, *bitmap);
        self.count_routing_writes(1);
        Ok(())
    }

    fn remove_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
    ) -> Result<(), super::DomainRouteWriteError> {
        #[cfg(test)]
        self.take_projection_fault(ProjectionMapOperation::Remove)?;
        let generation = self.routing_generation.as_mut().ok_or_else(|| {
            super::DomainRouteWriteError::Other(anyhow::anyhow!("no active routing generation"))
        })?;
        generation.domain.remove(&ip_key.data);
        self.count_routing_writes(1);
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

    fn get_bpf_stats(&self, key: u32) -> anyhow::Result<Option<u64>> {
        Ok(self.bpf_stats.get(&key).copied())
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
        self.datapath_ready = false;
        self.listener_sockets_published = false;
        self.routing_generation = None;
        self.descriptor = RoutingPolicyDescriptor::default();
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

    fn routing_plan(tag: u8) -> crate::control::routing_matcher::RoutingPushPlan {
        let rule = honk_config::routing::RoutingRule {
            name: format!("policy-{tag}"),
            condition: honk_config::routing::RoutingCondition {
                domain: vec![format!("policy-{tag}.test")],
                ip: vec![format!("192.0.2.{tag}/32")],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: u32::from(tag),
        };
        let router = crate::routing::Router::new(&[rule], "direct").unwrap();
        crate::control::routing_matcher::RoutingPushPlan::compile(
            &router,
            &HashMap::from([("direct".into(), 0)]),
            "direct",
            honk_config::types::DialMode::Domain,
        )
        .unwrap()
    }

    #[test]
    fn routing_publish_is_atomic_and_root_is_last() {
        let mut backend = MockEbpfBackend::new();
        backend.publish_routing_plan(&routing_plan(1), &[]).unwrap();
        let accepted = backend.routing_snapshot();

        let domain_key = LpmKey {
            prefix_len: 128,
            data: [0, 0, 0xffff0000, 2],
        };
        backend.fail_next_routing_phase(RoutingPushPhase::Root);
        assert!(
            backend
                .publish_routing_plan(&routing_plan(2), &[(domain_key, DomainRouting::default())],)
                .is_err()
        );
        assert_eq!(backend.routing_snapshot(), accepted);

        backend.publish_routing_plan(&routing_plan(3), &[]).unwrap();
        assert!(backend.routing_snapshot().domain.is_empty());
        let replacement = routing_plan(2);
        backend
            .publish_routing_plan(&replacement, &[(domain_key, DomainRouting::default())])
            .unwrap();
        let current = backend.routing_snapshot();
        assert_eq!(current.active_slot, 1);
        assert_eq!(current.plan_fingerprint, replacement.fingerprint);
        assert_eq!(current.domain.len(), 1);
        assert_eq!(current.domain[0].1, [0; ROUTING_BITMAP_WORDS]);
        assert!(matches!(
            backend.routing_publication_order.last(),
            Some(MockRoutingPublicationWrite::Root(1))
        ));
    }

    #[test]
    fn active_domain_zero_is_present_until_removed() {
        let mut backend = MockEbpfBackend::new();
        backend.publish_routing_plan(&routing_plan(1), &[]).unwrap();
        let key = LpmKey {
            prefix_len: 128,
            data: [0, 0, 0xffff0000, 3],
        };
        backend
            .set_domain_ip_bitmap(&key, &DomainRouting::default())
            .unwrap();
        assert_eq!(backend.routing_snapshot().domain.len(), 1);
        backend.remove_domain_ip_bitmap(&key).unwrap();
        assert!(backend.routing_snapshot().domain.is_empty());
    }

    #[test]
    fn test_conn_state_snapshot() {
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
    fn test_cleanup_clears_all_maps() {
        let mut backend = MockEbpfBackend::new();
        backend
            .tcp_conn_state_store(&TuplesKey::default(), &ConnState::default())
            .unwrap();
        backend
            .udp_conn_state_store(&TuplesKey::default(), &ConnState::default())
            .unwrap();
        backend
            .redirect_track_store(&RedirectTuple::default(), &RedirectEntry::default())
            .unwrap();
        backend.cookie_pid_store(42, &PIDName::default()).unwrap();
        backend.set_outbound_alive(1, 0, 4, true).unwrap();
        backend.bpf_stats.insert(0, 999);

        futures::executor::block_on(backend.cleanup()).unwrap();

        assert!(backend.tcp_conn_states.is_empty());
        assert!(backend.udp_conn_states.is_empty());
        assert!(backend.redirect_tracks.is_empty());
        assert!(backend.routing_handoffs.lock().is_empty());
        assert!(backend.cookie_pids.is_empty());
        assert!(backend.outbound_alive.is_empty());
        assert!(backend.bpf_stats.is_empty());
    }
}
