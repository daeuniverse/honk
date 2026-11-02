//! Connection tracking for honk-ebpf.
//!
//! Ported from daed/wing/dae-core/control/kern/tproxy.c

#![allow(clippy::too_many_arguments)]

pub mod tcp;
pub mod udp;

use crate::{
    event::send_flow_expired,
    maps::{
        CONN_STATE_OCCUPANCY, CONNTRACK_SNAPSHOT_MAP, FLOW_INCARNATION_SEQUENCE, TCP_LIVE_PINS,
        tuple_retiring,
    },
};
use aya_ebpf_bindings::helpers::{bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock};
use core::mem;
use honk_ebpf_common::{
    RoutingMeta, TASK_COMM_LEN,
    conn::{
        ConnState, FLOW_INCARNATION_MAX, TCP_CONN_STATE_CLOSING_TIMEOUT_NS, TcpState,
        UDP_CONN_STATE_TIMEOUT_NS, UdpDecisionState,
    },
    redirect_need::TuplesKey,
};
use network_types::tcp::TcpHdr;

const CT_ARGS_HAS_ROUTING: u8 = 1 << 0;
const CT_ARGS_HAS_MAC: u8 = 1 << 1;
const CT_ARGS_HAS_PNAME: u8 = 1 << 2;

/// Per-CPU scratch for one packet's routing facts. `tcp_binding` also reuses it as the
/// `bpf_sock_tuple` lookup buffer, hence the size/alignment asserts there.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConntrackArgs {
    flags: u8,
    outbound: u8,
    must: u8,
    dscp: u8,
    mark: u32,
    pid: u32,
    mac: [u8; 6],
    padding: [u8; 2],
    pname: [u8; TASK_COMM_LEN],
    trace_id: u32,
    incarnation: u64,
    tcp_syn_isn: u32,
    tcp_padding: [u8; 4],
}

impl ConntrackArgs {
    #[inline(always)]
    fn has_routing(&self) -> bool {
        (self.flags & CT_ARGS_HAS_ROUTING) != 0
    }

    #[inline(always)]
    fn has_mac(&self) -> bool {
        (self.flags & CT_ARGS_HAS_MAC) != 0
    }

    #[inline(always)]
    fn has_pname(&self) -> bool {
        (self.flags & CT_ARGS_HAS_PNAME) != 0
    }

    #[inline(always)]
    fn set(
        &mut self,
        dscp: u8,
        pid: u32,
        routing: Option<(&u8, &u32, &u8)>,
        mac: Option<&[u8; 6]>,
        pname: Option<&[u8; TASK_COMM_LEN]>,
    ) {
        *self = unsafe { mem::zeroed() };
        self.dscp = dscp;
        self.pid = pid;

        if let Some((outbound, mark, must)) = routing {
            self.flags |= CT_ARGS_HAS_ROUTING;
            self.outbound = *outbound;
            self.mark = *mark;
            self.must = *must;
        }

        if let Some(mac_addr) = mac {
            self.flags |= CT_ARGS_HAS_MAC;
            self.mac.copy_from_slice(mac_addr);
        }

        if let Some(pname_bytes) = pname {
            self.flags |= CT_ARGS_HAS_PNAME;
            self.pname.copy_from_slice(pname_bytes);
        }
    }

    #[inline(always)]
    fn pname_or_null(&self) -> Option<&[u8; TASK_COMM_LEN]> {
        if self.has_pname() {
            Some(&self.pname)
        } else {
            None
        }
    }
}

/// Bump a slot of the CONN_STATE_OCCUPANCY gauge (per-CPU, contention-free).
#[inline(always)]
fn occupancy_add(slot: u32) {
    if let Some(counter) = CONN_STATE_OCCUPANCY.get_ptr_mut(slot) {
        unsafe {
            *counter += 1;
        }
    }
}

/// Allocate a nonzero ID once per generation. Exhaustion never wraps or resets.
#[inline(always)]
pub fn allocate_flow_incarnation() -> Option<u64> {
    let sequence = unsafe { &mut *FLOW_INCARNATION_SEQUENCE.get_ptr_mut(0)? };
    unsafe { bpf_spin_lock(&mut sequence.lock) };
    let incarnation = if sequence.next < FLOW_INCARNATION_MAX {
        sequence.next += 1;
        sequence.next
    } else {
        0
    };
    unsafe { bpf_spin_unlock(&mut sequence.lock) };
    if incarnation == 0 {
        None
    } else {
        Some(incarnation)
    }
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

/// Expiry refuses this invocation rather than masquerading as a lookup miss.
#[inline(always)]
pub fn tuple_unavailable(key: &TuplesKey) -> bool {
    available_tuple_lifecycle(key, None).is_err()
}

#[inline(always)]
pub(crate) fn available_tuple_lifecycle(
    key: &TuplesKey,
    now: Option<u64>,
) -> Result<Option<crate::flow::ConnLifecycle>, ()> {
    if tuple_retiring(key) {
        return Err(());
    }
    let Some(state) = crate::flow::conn_lifecycle(key) else {
        return Ok(None);
    };
    let now = now.unwrap_or_else(|| unsafe { bpf_ktime_get_ns() });
    let expired = if key.l4proto == crate::transport::IPPROTO_TCP {
        state.state == TcpState::TcpStateClosing as u8
            && now.saturating_sub(state.last_seen_ns) > TCP_CONN_STATE_CLOSING_TIMEOUT_NS
            && !tcp_live_pinned(state.incarnation)
    } else {
        state.state == UdpDecisionState::Aborted as u8
            || now.saturating_sub(state.last_seen_ns) > UDP_CONN_STATE_TIMEOUT_NS
    };
    if expired {
        send_flow_expired(key, state.incarnation);
    }
    if expired
        || (key.l4proto == crate::transport::IPPROTO_UDP
            && state.state == UdpDecisionState::Preparing as u8)
    {
        Err(())
    } else {
        Ok(Some(state))
    }
}

#[inline(always)]
fn conntrack_output() -> Option<*mut ConnState> {
    // Keep array keys on stack, away from overridable zero-valued globals.
    let mut zero = 0u32;
    unsafe { core::ptr::write_volatile(&mut zero, 0) };
    CONNTRACK_SNAPSHOT_MAP.get_ptr_mut(unsafe { core::ptr::read_volatile(&zero) })
}

#[inline(always)]
pub fn tcp_live_pinned(incarnation: u64) -> bool {
    incarnation != 0 && TCP_LIVE_PINS.get_ptr(&incarnation).is_some()
}
