//! Connection tracking for honk-ebpf.
//!
//! Ported from daed/wing/dae-core/control/kern/tproxy.c

#![allow(clippy::too_many_arguments)]

use crate::log_shim::*;
use crate::{
    event::send_dae_event,
    maps::{
        BPF_STATS_MAP, CONN_STATE_MAP, CONN_STATE_OCCUPANCY, CONNTRACK_ARGS_MAP,
        UDP_DECISION_SEQUENCE, udp_decision_retiring,
    },
};
use aya_ebpf_bindings::{
    bindings::{BPF_EXIST, BPF_NOEXIST},
    helpers::{bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock},
};
use honk_ebpf_common::{
    NFQUEUE_TOKEN_MASK, RoutingMeta, UDP_DECISION_SEQUENCE_MASK,
    conn::{
        BpfStatsKey, ConnState, ConntrackArgs, OCCUPANCY_EBPF_DELETES, OCCUPANCY_INSERTS, TcpState,
        UDP_CONN_STATE_TIMEOUT_NS, UdpDecisionState, tcp_conn_state_expired,
    },
    redirect_need::TuplesKey,
};
use network_types::tcp::TcpHdr;

/// Lazy-timestamp update interval: only bump `last_seen_ns` when > 1 s elapsed.
pub const UDP_CONN_STATE_UPDATE_INTERVAL_NS: u64 = 1_000_000_000;

/// Refresh interval for `COOKIE_PID_MAP`, `REDIRECT_TRACK`, and
/// `ROUTING_HANDOFF_MAP`: cached packets skip timestamp writes while an entry
/// is fresher than one second. Time comparisons use `wrapping_sub` for
/// verifier-friendly monotonic arithmetic.
pub const AUXILIARY_MAP_REFRESH_INTERVAL_NS: u64 = 1_000_000_000;

pub const TCP_CONN_STATE_UPDATE_INTERVAL_NS: u64 = 1_000_000_000; // 1 second

/// Bump a slot of the CONN_STATE_OCCUPANCY gauge (per-CPU, contention-free).
#[inline(always)]
fn occupancy_add(slot: u32) {
    if let Some(counter) = CONN_STATE_OCCUPANCY.get_ptr_mut(slot) {
        unsafe {
            *counter += 1;
        }
    }
}

/// Atomically reserve a new UDP tuple for the current CPU's route decision.
#[inline(always)]
pub fn claim_udp_preparing(key: &TuplesKey, mac: &[u8; 6]) -> bool {
    if udp_decision_retiring(key) {
        return false;
    }
    let mut state: ConnState = unsafe { core::mem::zeroed() };
    state.state = UdpDecisionState::Preparing as u8;
    state.last_seen_ns = unsafe { bpf_ktime_get_ns() };
    state.mac.copy_from_slice(mac);

    if CONN_STATE_MAP
        .insert(key, state, BPF_NOEXIST as u64)
        .is_ok()
    {
        occupancy_add(OCCUPANCY_INSERTS);
        return true;
    }

    if CONN_STATE_MAP.get_ptr(key).is_none() {
        let stats_key = BpfStatsKey::UdpConnOverflow as u32;
        if let Some(counter) = BPF_STATS_MAP.get_ptr_mut(stats_key) {
            unsafe {
                *counter += 1;
            }
        }
        send_dae_event(
            honk_ebpf_common::event::DaeEventType::UdpConnOverflow as u32,
            0,
            None,
            0,
            key.l4proto,
            Some(unsafe { &key.src_ip.u6_addr32 }),
            Some(unsafe { &key.dst_ip.u6_addr32 }),
            key.src_port,
            key.dst_port,
        );
    }
    false
}

/// Replace only the Preparing claim; followers can never publish a decision.
#[inline(always)]
pub fn publish_claimed_udp_state(key: &TuplesKey, state: &ConnState) -> bool {
    let Some(current) = CONN_STATE_MAP.get_ptr(key) else {
        return false;
    };
    if unsafe {
        (*current).state != UdpDecisionState::Preparing as u8 || (*current).decision_token != 0
    } {
        return false;
    }
    CONN_STATE_MAP.insert(key, state, BPF_EXIST as u64).is_ok()
}

/// Remove only this unpublished claim and account for its successful insertion.
#[inline(always)]
pub fn remove_udp_preparing(key: &TuplesKey) {
    let Some(current) = CONN_STATE_MAP.get_ptr(key) else {
        return;
    };
    if unsafe {
        (*current).state != UdpDecisionState::Preparing as u8 || (*current).decision_token != 0
    } {
        return;
    }
    if CONN_STATE_MAP.remove(key).is_ok() {
        occupancy_add(OCCUPANCY_EBPF_DELETES);
    }
}

#[inline(always)]
pub fn populate_udp_conn_state(
    conn: &mut ConnState,
    meta: RoutingMeta,
    mac: &[u8; 6],
    state: UdpDecisionState,
    decision_token: u32,
) {
    *conn = unsafe { core::mem::zeroed() };
    conn.state = state as u8;
    conn.decision_token = decision_token;
    conn.last_seen_ns = unsafe { bpf_ktime_get_ns() };
    conn.meta = meta;
    conn.mac.copy_from_slice(mac);
}

/// Allocate each generation-tagged mark token once until userspace rotates it.
#[inline(always)]
pub fn allocate_udp_decision_token(key: &TuplesKey) -> Option<u32> {
    let sequence_ptr = UDP_DECISION_SEQUENCE.get_ptr_mut(0)?;
    let sequence = unsafe { &mut *sequence_ptr };
    unsafe {
        bpf_spin_lock(&mut sequence.lock);
    }

    let mut became_exhausted = false;
    let token = if sequence.exhausted != 0
        || sequence.next & UDP_DECISION_SEQUENCE_MASK >= UDP_DECISION_SEQUENCE_MASK
    {
        0
    } else {
        sequence.next += 1;
        became_exhausted = sequence.next & UDP_DECISION_SEQUENCE_MASK == UDP_DECISION_SEQUENCE_MASK;
        if sequence.next == NFQUEUE_TOKEN_MASK {
            sequence.exhausted = 1;
        }
        sequence.next
    };

    unsafe {
        bpf_spin_unlock(&mut sequence.lock);
    }

    if became_exhausted {
        send_dae_event(
            honk_ebpf_common::event::DaeEventType::UdpDecisionTokenExhausted as u32,
            0,
            None,
            0,
            key.l4proto,
            Some(unsafe { &key.src_ip.u6_addr32 }),
            Some(unsafe { &key.dst_ip.u6_addr32 }),
            key.src_port,
            key.dst_port,
        );
    }

    if token == 0 { None } else { Some(token) }
}

/// Build a [`RoutingMeta`] from routing parameters.
///
/// Encodes the routing decision into a `u64` for storage in [`ConnState::meta`].
/// The bit layout must match [`RoutingMetaData`] for struct-field access to work:
///
/// | bits    | field       |
/// |---------|-------------|
/// |  0–7    | `outbound`  |
/// |  8–39   | `mark`      |
/// |  40–47  | `must`      |
/// |  48–55  | `dscp`      |
/// |  56     | `has_routing` |
/// |  57     | `offload` (mode-based direct offload; see
///           [`honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD`]) |
///
/// **Note**: this differs from the C dae layout (where mark occupies bits 0–31
/// and outbound bits 32–39). Do **not** copy bit offsets from C code.
#[inline(always)]
pub fn build_routing_meta(outbound: u8, mark: u32, must: u8, dscp: u8) -> RoutingMeta {
    build_routing_meta_with_offload(outbound, mark, must, dscp, false)
}

/// [`build_routing_meta`] plus the per-flow offload bit, set only by
/// `lan_ingress` when the mode-based policy selected this flow for kernel
/// direct offload at route-decision time.
#[inline(always)]
pub fn build_routing_meta_with_offload(
    outbound: u8,
    mark: u32,
    must: u8,
    dscp: u8,
    offload: bool,
) -> RoutingMeta {
    let raw: u64 = (outbound as u64)
        | ((mark as u64) << 8)
        | ((must as u64) << 40)
        | ((dscp as u64) << 48)
        | (1u64 << 56)
        | if offload {
            honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD
        } else {
            0
        };
    RoutingMeta { raw }
}

/// BPF-compatible compiler barrier.
/// Equivalent to C's `barrier()`.
/// Uses volatile pointer read to avoid LLVM AtomicFence instructions
/// which crash the BPF backend.
#[inline(always)]
fn bpf_barrier() {
    let dummy: u8 = 0;
    unsafe {
        core::ptr::read_volatile(&dummy);
    }
}

/// Publish a [`RoutingMeta`] with a compiler fence, mimicking C's
/// `barrier() + volatile` write so side fields (mac/pname/pid) are
/// visible before routing.
#[inline(always)]
pub fn publish_routing_meta(dst: &mut RoutingMeta, meta: RoutingMeta) {
    bpf_barrier();
    unsafe {
        dst.raw = meta.raw;
    }
    bpf_barrier();
}

/// Copy a [`TuplesKey`] with src↔dst and sport↔dport swapped,
/// preserving `l4proto`.  Zero-initialises `dst` first.
#[inline(always)]
pub fn copy_reversed_tuples(key: &TuplesKey, dst: &mut TuplesKey) {
    *dst = unsafe { core::mem::zeroed() };
    dst.dst_ip = key.src_ip;
    dst.src_ip = key.dst_ip;
    dst.dst_port = key.src_port;
    dst.src_port = key.dst_port;
    dst.l4proto = key.l4proto;
}

/// DNS queries/replies are short-lived; skipping conntrack for them
/// reduces unnecessary UDP state churn.
#[inline(always)]
pub fn is_short_lived_udp_traffic(key: &TuplesKey) -> bool {
    // Ports are stored in host byte order (see transport::get_tuples).
    key.l4proto == crate::transport::IPPROTO_UDP && (key.dst_port == 53 || key.src_port == 53)
}

/// Returns `true` when the TCP header carries a pure SYN (SYN set, ACK clear).
#[inline(always)]
pub fn is_new_tcp_connection(tcph: &TcpHdr) -> bool {
    tcph.syn() != 0 && tcph.ack() == 0
}

/// UDP connection state expiry: 120 s backstop.
#[inline(always)]
fn udp_conn_state_expired(state: &ConnState, now: u64) -> bool {
    now.wrapping_sub(state.last_seen_ns) > UDP_CONN_STATE_TIMEOUT_NS
}

/// Noinline core for TCP connection tracking.
///
/// `tcp_flags` encoding (same as C):
///   - bit 0: SYN && !ACK (new connection)
///   - bit 1: FIN || RST   (connection closing)
///
/// Returns a mutable reference to the [`ConnState`] entry on success,
/// or `None` when allocation fails or a non-SYN packet has no cached state.
///
/// # Safety
///
/// The returned `'static` reference aliases the map entry living in the
/// static `CONN_STATE_MAP`.  Callers must use the reference within the
/// current BPF program invocation — the map may be mutated by concurrent
/// per-CPU access or a later lookup on the same key.
fn __mark_tcp_seen(
    key: *const TuplesKey,
    is_wan_ingress_direction: u8,
    tcp_flags: u8,
    args: *const ConntrackArgs,
) -> *mut ConnState {
    let key = unsafe { &*key };
    let args = unsafe { &*args };
    let now = unsafe { bpf_ktime_get_ns() };

    let new_conn_syn = (tcp_flags & 1) != 0;
    let is_fin_rst = (tcp_flags & 2) != 0;

    let ptr_opt = CONN_STATE_MAP.get_ptr_mut(key);

    if new_conn_syn {
        // A pure SYN always starts a fresh TCP lifecycle.  If an older entry still
        // exists under the same 4-tuple (for example because only the reverse-side
        // FIN/RST was observed previously), drop it now so the new connection does
        // not inherit stale routing metadata.  Fall through to the slow path.
        if ptr_opt.is_some() {
            let _ = CONN_STATE_MAP.remove(key);
            occupancy_add(OCCUPANCY_EBPF_DELETES);
        }
    } else if let Some(ptr) = ptr_opt {
        // Non-SYN fast path: hold the pointer from a single lookup, check
        // expiry, and mutate in place.  Only re-look up after a remove.
        let state = unsafe { &mut *ptr };
        if tcp_conn_state_expired(state, now.wrapping_sub(state.last_seen_ns)) {
            let _ = CONN_STATE_MAP.remove(key);
            occupancy_add(OCCUPANCY_EBPF_DELETES);
            // Non-SYN packets without valid state must never allocate.
            return core::ptr::null_mut();
        }

        if now.wrapping_sub(state.last_seen_ns) > TCP_CONN_STATE_UPDATE_INTERVAL_NS {
            state.last_seen_ns = now;
        }

        if is_fin_rst {
            state.state = TcpState::TcpStateClosing as u8;
        }

        // Update routing if provided (rare: routing decision changed)
        if args.has_routing() {
            let meta = build_routing_meta(args.outbound, args.mark, args.must, args.dscp);

            if args.has_mac() {
                state.mac.copy_from_slice(&args.mac);
            }
            if args.has_pname() {
                state.pname.copy_from_slice(&args.pname);
            }
            state.pid = args.pid;
            publish_routing_meta(&mut state.meta, meta);
        }

        return state as *mut ConnState;
    } else {
        // Non-SYN packets without existing state must never allocate new state.
        return core::ptr::null_mut();
    }

    // Only SYN reaches this point (the non-SYN paths all return early above).
    if new_conn_syn {
        let has_rt = args.has_routing();

        let mut new_state: ConnState = unsafe { core::mem::zeroed() };
        new_state.is_wan_ingress_direction = (is_wan_ingress_direction != 0) as u8;
        new_state.state = TcpState::TcpStateActive as u8;
        new_state.last_seen_ns = now;
        new_state.pid = args.pid;

        if has_rt {
            new_state.meta = build_routing_meta(args.outbound, args.mark, args.must, args.dscp);
            if args.has_mac() {
                new_state.mac.copy_from_slice(&args.mac);
            }
            if args.has_pname() {
                new_state.pname.copy_from_slice(&args.pname);
            }
        }

        let ret = CONN_STATE_MAP.insert(key, new_state, 0u64);
        if ret.is_err() {
            let stats_key: u32 = BpfStatsKey::TcpConnOverflow as u32;
            if let Some(overflow_count) = BPF_STATS_MAP.get_ptr_mut(stats_key) {
                unsafe {
                    *overflow_count += 1;
                }
            }
            send_dae_event(
                honk_ebpf_common::event::DaeEventType::TcpConnOverflow as u32,
                args.pid,
                args.pname_or_null(),
                0,
                key.l4proto,
                Some(unsafe { &key.src_ip.u6_addr32 }),
                Some(unsafe { &key.dst_ip.u6_addr32 }),
                key.src_port,
                key.dst_port,
            );
            warn!((), target: "honk", "tcp conn state map overflow, key: {:i}:{} -> {:i}:{}", unsafe { key.src_ip.u6_addr8 }, key.src_port, unsafe { key.dst_ip.u6_addr8 }, key.dst_port);
            return core::ptr::null_mut();
        }
        occupancy_add(OCCUPANCY_INSERTS);

        CONN_STATE_MAP
            .get_ptr_mut(key)
            .unwrap_or(core::ptr::null_mut())
    } else {
        // Non-SYN packets without existing state must never allocate new state.
        core::ptr::null_mut()
    }
}

/// Thin inline wrapper: populates the per-CPU `CONNTRACK_ARGS_MAP` scratch
/// and delegates to [`__mark_tcp_seen`].
#[inline(always)]
pub fn mark_tcp_seen(
    key: &TuplesKey,
    tcph: &TcpHdr,
    is_wan_ingress_direction: u8,
    outbound: Option<&u8>,
    mark: Option<&u32>,
    must: Option<&u8>,
    mac: Option<&[u8; 6]>,
    dscp: u8,
    pname: Option<&[u8; 16]>,
    pid: u32,
) -> Option<&'static mut ConnState> {
    let zero: u32 = 0;
    let args = unsafe { CONNTRACK_ARGS_MAP.get_ptr_mut(zero).map(|ptr| &mut *ptr)? };

    // Build routing tuple (all three must be present for routing to be set).
    let routing = match (outbound, mark, must) {
        (Some(o), Some(mk), Some(ms)) => Some((o, mk, ms)),
        _ => None,
    };

    args.set(dscp, pid, routing, mac, pname);

    // Encode tcp_flags: bit 0 = pure SYN, bit 1 = FIN || RST
    let mut tcp_flags: u8 = 0;
    if tcph.syn() != 0 && tcph.ack() == 0 {
        tcp_flags |= 1;
    }
    if tcph.fin() != 0 || tcph.rst() != 0 {
        tcp_flags |= 2;
    }

    let key_ptr: *const TuplesKey = key;
    let args_ptr: *const ConntrackArgs = args;
    let result = __mark_tcp_seen(key_ptr, is_wan_ingress_direction, tcp_flags, args_ptr);
    if result.is_null() {
        None
    } else {
        Some(unsafe { &mut *result })
    }
}

#[inline(always)]
fn lookup_udp_seen_at(key: &TuplesKey, now: u64) -> Option<&'static mut ConnState> {
    let ptr = CONN_STATE_MAP.get_ptr_mut(key)?;
    if udp_conn_state_expired(unsafe { &*ptr }, now) {
        let _ = CONN_STATE_MAP.remove(key);
        occupancy_add(OCCUPANCY_EBPF_DELETES);
        return None;
    }
    let state = unsafe { &mut *ptr };
    if now.wrapping_sub(state.last_seen_ns) > UDP_CONN_STATE_UPDATE_INTERVAL_NS {
        state.last_seen_ns = now;
    }
    Some(state)
}

/// Look up an existing live UDP entry and lazily refresh its timestamp.
/// Missing or expired entries are never allocated on this path.
#[inline(always)]
pub fn lookup_udp_seen(key: &TuplesKey) -> Option<&'static mut ConnState> {
    lookup_udp_seen_at(key, unsafe { bpf_ktime_get_ns() })
}

/// Noinline core for UDP connection tracking.
///
/// Returns a mutable reference to the [`ConnState`] entry on success,
/// or `None` when the map is full.
fn __mark_udp_seen(
    key: *const TuplesKey,
    is_wan_ingress_direction: u8,
    args: *const ConntrackArgs,
    routing_meta_flags: u64,
) -> *mut ConnState {
    let key = unsafe { &*key };
    let args = unsafe { &*args };
    let now = unsafe { bpf_ktime_get_ns() };

    if let Some(state) = lookup_udp_seen_at(key, now) {
        // Update routing only when the caller publishes a complete decision.
        if args.has_routing() {
            let mut meta = build_routing_meta(args.outbound, args.mark, args.must, args.dscp);
            unsafe { meta.raw |= routing_meta_flags };
            if args.has_mac() {
                state.mac.copy_from_slice(&args.mac);
            }
            if args.has_pname() {
                state.pname.copy_from_slice(&args.pname);
            }
            state.pid = args.pid;
            publish_routing_meta(&mut state.meta, meta);
        }
        return state as *mut ConnState;
    }

    let has_rt = args.has_routing();

    let mut new_state: ConnState = unsafe { core::mem::zeroed() };
    new_state.is_wan_ingress_direction = (is_wan_ingress_direction != 0) as u8;
    new_state.state = UdpDecisionState::None as u8;
    new_state.last_seen_ns = now;
    new_state.pid = args.pid;

    if has_rt {
        new_state.meta = build_routing_meta(args.outbound, args.mark, args.must, args.dscp);
        unsafe { new_state.meta.raw |= routing_meta_flags };
        if args.has_mac() {
            new_state.mac.copy_from_slice(&args.mac);
        }
        if args.has_pname() {
            new_state.pname.copy_from_slice(&args.pname);
        }
    }

    let ret = CONN_STATE_MAP.insert(key, new_state, 0u64);
    if ret.is_err() {
        let stats_key: u32 = BpfStatsKey::UdpConnOverflow as u32;
        if let Some(overflow_count) = BPF_STATS_MAP.get_ptr_mut(stats_key) {
            unsafe {
                *overflow_count += 1;
            }
        }
        send_dae_event(
            honk_ebpf_common::event::DaeEventType::UdpConnOverflow as u32,
            args.pid,
            args.pname_or_null(),
            0,
            key.l4proto,
            Some(unsafe { &key.src_ip.u6_addr32 }),
            Some(unsafe { &key.dst_ip.u6_addr32 }),
            key.src_port,
            key.dst_port,
        );
        warn!((), target: "honk", "udp conn state map overflow, key: {:i}:{} -> {:i}:{}", unsafe { key.src_ip.u6_addr8 }, key.src_port, unsafe { key.dst_ip.u6_addr8 }, key.dst_port);
        return core::ptr::null_mut();
    }
    occupancy_add(OCCUPANCY_INSERTS);

    CONN_STATE_MAP
        .get_ptr_mut(key)
        .unwrap_or(core::ptr::null_mut())
}

/// Thin inline wrapper: populates the per-CPU `CONNTRACK_ARGS_MAP` scratch
/// and delegates to [`__mark_udp_seen`].
#[inline(always)]
pub fn mark_udp_seen(
    key: &TuplesKey,
    is_wan_ingress_direction: u8,
    outbound: Option<&u8>,
    mark: Option<&u32>,
    must: Option<&u8>,
    mac: Option<&[u8; 6]>,
    dscp: u8,
    pname: Option<&[u8; 16]>,
    pid: u32,
    routing_meta_flags: u64,
) -> Option<&'static mut ConnState> {
    let zero: u32 = 0;
    let args = unsafe { CONNTRACK_ARGS_MAP.get_ptr_mut(zero).map(|ptr| &mut *ptr)? };

    // Build routing tuple (all three must be present for routing to be set).
    let routing = match (outbound, mark, must) {
        (Some(o), Some(mk), Some(ms)) => Some((o, mk, ms)),
        _ => None,
    };

    args.set(dscp, pid, routing, mac, pname);
    let key_ptr: *const TuplesKey = key;
    let args_ptr: *const ConntrackArgs = args;
    let result = __mark_udp_seen(
        key_ptr,
        is_wan_ingress_direction,
        args_ptr,
        routing_meta_flags,
    );
    if result.is_null() {
        None
    } else {
        Some(unsafe { &mut *result })
    }
}
