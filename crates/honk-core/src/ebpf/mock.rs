//! Mock eBPF backend for testing.
//!
//! This backend implements the `EbpfBackend` trait using in-memory
//! data structures instead of real kernel eBPF. All operations use
//! HashMap storage.

#[cfg(test)]
use super::RetireKind;
#[cfg(test)]
use super::TcpSocketOwnership;
#[cfg(test)]
use super::retirement::retire_fixture;
use super::retirement::{
    Owners, RedirectEffect, account_retirement, plan_retirement, plan_udp_commit, retire_staged_udp,
};
#[cfg(test)]
use super::{DatapathFlagsWriteOrigin, DatapathFlagsWriteTrace, ProjectionMapOperation};
use super::{
    EbpfBackend, RoutingPushPhase, UdpDecisionCommitResult, UdpDecisionSequenceStatus,
    UdpDecisionTransition, validate_udp_decision_transition,
};
use super::{
    FlowExpiryHint, RETIRE_BATCH_CAPACITY, RetireCounts, RetireError, RetireOutcome, RetireRequest,
    udp_state_is_staged,
};
use async_trait::async_trait;
use honk_ebpf_common::*;
use std::collections::HashMap;

// Stable ordering models a kernel bucket cursor without relying on HashMap's
// randomized order, which can change when a previous scan retires elements.
fn scan_model<K, V: Copy>(
    entries: impl Iterator<Item = ([u8; 40], V)>,
    chunk_size: usize,
    cursor: &mut super::FlowScanCursor,
    decode: impl Fn(&[u8; 40]) -> K,
    mut visit: impl FnMut(&[(K, V)]) -> bool,
) {
    let mut entries: Vec<_> = entries
        .filter(|(key, _)| cursor.next_key.is_none_or(|next| *key >= next))
        .collect();
    entries.sort_unstable_by_key(|(key, _)| *key);
    let size = chunk_size.max(1);
    let mut chunk = Vec::with_capacity(size);
    for (index, entries_chunk) in entries.chunks(size).enumerate() {
        chunk.clear();
        chunk.extend(
            entries_chunk
                .iter()
                .map(|(key, value)| (decode(key), *value)),
        );
        cursor.next_key = entries.get((index + 1) * size).map(|(key, _)| *key);
        if !visit(&chunk) {
            return;
        }
    }
    cursor.next_key = None;
}

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

#[cfg(test)]
#[derive(Debug, Default)]
pub struct MockTelemetryFaults {
    pub stats: bool,
    pub conn_occupancy: bool,
    pub aux_occupancy: bool,
}

/// In-memory transactional routing backend used by control-plane tests.
#[derive(Debug, Default)]
pub struct MockEbpfBackend {
    policy: super::policy_state::PolicyState,
    #[cfg(feature = "native-api")]
    trace_dictionaries: crate::observe::flows::kernel::KernelTraceDictionaries,
    pub route_witnesses: HashMap<u32, KernelRouteWitness>,
    next_trace_id: u32,
    /// Remaining `adopt_tcp` calls that report the child proof as not published yet.
    #[cfg(test)]
    pub adopt_proof_pending: std::sync::atomic::AtomicU32,
    /// TCP connection states (TuplesKey → ConnState)
    pub tcp_conn_states: HashMap<[u8; 40], ConnState>,
    /// UDP connection states (TuplesKey → ConnState)
    pub udp_conn_states: HashMap<[u8; 40], ConnState>,
    /// Redirect tracking (full directional `RedirectTuple` → `RedirectEntry`).
    pub redirect_tracks: HashMap<[u8; 40], RedirectEntry>,
    /// Routing handoff table (TuplesKey → RoutingHandoffEntry).
    pub routing_handoffs: parking_lot::Mutex<HashMap<[u8; 40], RoutingHandoffEntry>>,
    /// Tuple fences retained by model fixtures for allocator conflict checks.
    retire_fences: HashMap<[u8; 40], RetirementFence>,
    /// Model grace latency; a batch waits once rather than once per item.
    #[cfg(test)]
    pub commit_delay: Option<std::time::Duration>,
    #[cfg(test)]
    pub commit_barrier_fault: bool,
    #[cfg(test)]
    pub commit_release_fault: bool,
    #[cfg(test)]
    pub commit_release_delay: Option<std::time::Duration>,
    #[cfg(test)]
    pub commit_fence_unresolved: bool,
    #[cfg(test)]
    pub commit_item_delay: Option<(usize, std::time::Duration)>,
    #[cfg(test)]
    pub commit_batch_sizes: std::sync::Arc<parking_lot::Mutex<Vec<usize>>>,
    #[cfg(test)]
    pub commit_trace: std::sync::Arc<parking_lot::Mutex<Vec<(u32, UdpDecisionTransition)>>>,
    #[cfg(test)]
    pub retire_fault_after: Option<usize>,
    /// BPF statistics overflow counters
    pub bpf_stats: HashMap<u32, u64>,
    #[cfg(test)]
    pub telemetry_faults: std::sync::Arc<parking_lot::Mutex<MockTelemetryFaults>>,
    /// Whether TC entry points may redirect traffic into the control plane.
    pub datapath_ready: bool,
    pub admission_pressure: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub listener_sockets_published: bool,
    listener_socket_slots: HashMap<u32, std::os::fd::RawFd>,
    #[cfg(test)]
    pub listener_clear_fault_at: Option<u32>,
    /// Every mode-policy write, shared so tests can inspect boxed backends.
    pub datapath_flags_writes: std::sync::Arc<parking_lot::Mutex<Vec<u32>>>,
    pub detach_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub dynamic_attach_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    #[cfg(test)]
    pub dynamic_attach_fault: bool,
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
    pub quiesce_datapath_ready: std::sync::Arc<parking_lot::Mutex<Vec<bool>>>,
    #[cfg(test)]
    datapath_flags_fault_nth: Option<usize>,
    #[cfg(test)]
    datapath_flags_writes_after_arm: usize,
    #[cfg(test)]
    datapath_flags_write_origin: DatapathFlagsWriteOrigin,
    #[cfg(test)]
    datapath_flags_write_trace: Vec<DatapathFlagsWriteTrace>,
    #[cfg(test)]
    pub datapath_observation_fixture: Option<super::DatapathObservation>,
    #[cfg(test)]
    pub pname_support: super::PnameSupport,
}

impl MockEbpfBackend {
    /// Create a new mock backend.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn capture_route_witness(&mut self, mut witness: KernelRouteWitness) -> u32 {
        if witness.output.flags & ROUTE_TRACE_ENABLED == 0 {
            return 0;
        }
        if self.next_trace_id >= ROUTE_TRACE_LOST - 1 {
            return ROUTE_TRACE_LOST;
        }
        self.next_trace_id += 1;
        let id = self.next_trace_id;
        witness.capture_id = id;
        if self.route_witnesses.len() >= ROUTE_TRACE_CAPACITY as usize
            && let Some(oldest) = self.route_witnesses.keys().min().copied()
        {
            self.route_witnesses.remove(&oldest);
        }
        self.route_witnesses.insert(id, witness);
        id
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
                routing_generation: 0,
                incarnation: state.incarnation,
                ..Default::default()
            },
        );
        self.redirect_track_store(
            &RedirectTuple::from_tuples(key),
            &RedirectEntry {
                decision_token: token,
                outbound: OutboundIndex::UserBase as u8,
                incarnation: state.incarnation,
                ..Default::default()
            },
        )
        .unwrap();
    }

    fn conn_states(&self, proto: u8) -> &HashMap<[u8; 40], ConnState> {
        if proto == libc::IPPROTO_TCP as u8 {
            &self.tcp_conn_states
        } else {
            &self.udp_conn_states
        }
    }

    fn conn_states_mut(&mut self, proto: u8) -> &mut HashMap<[u8; 40], ConnState> {
        if proto == libc::IPPROTO_TCP as u8 {
            &mut self.tcp_conn_states
        } else {
            &mut self.udp_conn_states
        }
    }

    // Explicit model fixtures may use zero identities that native backends reject, and
    // exclusive access stands in for the kernel fence and grace barrier.
    fn retire_model_request(
        &mut self,
        request: &RetireRequest<'_>,
        counts: &mut RetireCounts,
    ) -> RetireOutcome {
        let raw = Self::tuples_key_bytes(&request.key);
        let track_raw = Self::redirect_tuple_bytes(&RedirectTuple::from_tuples(&request.key));
        let reads = request.kind.owner_reads();
        let conn = reads
            .conn
            .then(|| self.conn_states(request.key.l4proto).get(&raw).copied())
            .flatten();
        let handoff = reads
            .handoff
            .then(|| self.routing_handoffs.lock().get(&raw).copied())
            .flatten();
        let redirect = reads
            .redirect
            .then(|| self.redirect_tracks.get(&track_raw).copied())
            .flatten();
        let owners = Owners {
            conn: conn.as_ref(),
            handoff: handoff.as_ref(),
            redirect: redirect.as_ref(),
        };
        let plan = match plan_retirement(request, &owners) {
            Ok(plan) => plan,
            Err(result) => return result.into(),
        };
        let before = *counts;
        if plan.handoff {
            counts.handoff += u64::from(self.routing_handoffs.get_mut().remove(&raw).is_some());
        }
        if plan.redirect {
            counts.redirect += u64::from(self.redirect_tracks.remove(&track_raw).is_some());
        }
        if plan.conn {
            counts.conn += u64::from(
                self.conn_states_mut(request.key.l4proto)
                    .remove(&raw)
                    .is_some(),
            );
        }
        plan.outcome((*counts).since(before))
    }

    fn retire_model_batch(
        &mut self,
        requests: &[RetireRequest<'_>],
        outcomes: &mut [RetireOutcome],
        counts: &mut RetireCounts,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            requests.len() == outcomes.len() && requests.len() <= RETIRE_BATCH_CAPACITY,
            "invalid retirement batch length"
        );
        anyhow::ensure!(
            self.retire_fences.is_empty(),
            "unresolved model retirement fences"
        );
        for (index, (request, outcome)) in requests.iter().zip(outcomes).enumerate() {
            #[cfg(test)]
            if self.retire_fault_after == Some(index) {
                self.retire_fault_after = None;
                anyhow::bail!("injected retirement failure");
            }
            #[cfg(not(test))]
            let _ = index;
            *outcome = self.retire_model_request(request, counts);
        }
        Ok(())
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
        let generation = self.policy.routing_generation.as_ref();
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
            active_slot: self.policy.active_slot,
            descriptor: self.policy.descriptor,
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
            padding: [0; 3],
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

mod backend;

#[cfg(test)]
mod batch_retirement_tests;

#[cfg(test)]
mod tests;
