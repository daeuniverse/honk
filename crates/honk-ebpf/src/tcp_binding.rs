//! Accepted-child ownership proof and the native SYN-owner lookup.
//!
//! `honk_tcp_passive` binds an accepted child to the SYN published for its tuple once the
//! handshake completes; `native_syn_owner` lets TC decide whether a retransmitted SYN belongs
//! to that publication. Neither reads kernel memory, so both load on kernels that lack
//! CONFIG_BPF_EVENTS and in-kernel BTF.

use crate::ctx::raw_skb;
use crate::flow::{handoff_incarnation, handoff_snapshot, redirect_incarnation};
use crate::maps::{
    CONN_STATE_MAP, CONNTRACK_ARGS_MAP, PARAM, TCP_SOCKET_BINDING, increment_bpf_stat,
    tuple_retiring,
};
use crate::transport::IPPROTO_TCP;
use aya_ebpf::{
    Global,
    bindings::BPF_SK_STORAGE_GET_F_CREATE,
    helpers::{bpf_ktime_get_ns, bpf_sk_storage_get},
    macros::sock_ops,
    programs::{SockOpsContext, TcContext},
};
use aya_ebpf_bindings::{
    bindings::{
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, bpf_sock, bpf_sock_ops, bpf_sock_tuple,
        bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1, bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2,
    },
    helpers::{
        bpf_get_netns_cookie, bpf_sk_fullsock, bpf_sk_release, bpf_skc_lookup_tcp, bpf_spin_lock,
        bpf_spin_unlock,
    },
};
use core::{mem, ptr};
use honk_ebpf_common::{
    RedirectTuple,
    conn::{BpfStatsKey, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TCP_SYN_ORIGINAL_INTERCEPT},
    dae_ip::In6Addr,
    redirect_need::{TCP_BINDING_CHILD, TcpSocketBinding, TuplesKey},
};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;

/// `SO_NETNS_COOKIE` of the owned daens, set at load. Zero matches no namespace: without a
/// daens there is no interception to prove (`TcpPublisher::acquire` refuses such SYNs).
#[unsafe(no_mangle)]
pub static TCP_DAENS_NETNS_COOKIE: Global<u64> = Global::new(0);

#[inline(always)]
fn same_tuple(left: &TuplesKey, right: &TuplesKey) -> bool {
    (unsafe {
        left.src_ip.u6_addr64 == right.src_ip.u6_addr64
            && left.dst_ip.u6_addr64 == right.dst_ip.u6_addr64
    }) && left.src_port == right.src_port
        && left.dst_port == right.dst_port
        && left.l4proto == right.l4proto
}

/// Shared by the producer (`honk_tcp_passive`) and the TC consumer: the binding is acceptable
/// when tuple, ISN and incarnation agree with the live conn/handoff/redirect publication. The
/// conn need not be Active: TC marks Closing on any FIN/RST, including one it sees before the
/// stack processes the handshake-completing segment (or carried by that segment itself).
#[inline(always)]
fn valid_proof(binding: &TcpSocketBinding, tuples: &TuplesKey, isn: u32) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    let incarnation = binding.handoff.incarnation;
    if binding.kind != TCP_BINDING_CHILD
        || !same_tuple(&binding.tuples, tuples)
        || binding.syn_isn != isn
        || now < binding.handoff.last_seen_ns
        || now - binding.handoff.last_seen_ns > TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS
        || incarnation == 0
        || tuple_retiring(tuples)
    {
        return false;
    }
    let Some(conn) = CONN_STATE_MAP.get_ptr_mut(tuples) else {
        return false;
    };
    unsafe { bpf_spin_lock(&mut (*conn).lock) };
    let state = unsafe { &raw const (*conn).value };
    let owned = unsafe {
        (&raw const (*state).incarnation).read_volatile() == incarnation
            && (&raw const (*state).tcp_syn_isn).read_volatile() == isn
            && (&raw const (*state).tcp_syn_flags).read_volatile() & TCP_SYN_ORIGINAL_INTERCEPT != 0
    };
    unsafe { bpf_spin_unlock(&mut (*conn).lock) };
    owned
        && !tuple_retiring(tuples)
        && handoff_incarnation(tuples) == Some(incarnation)
        && redirect_incarnation(&RedirectTuple::from_tuples(tuples)) == Some(incarnation)
}

/// Scalar decision: 0 absent, reserved top values for fresh/refuse, otherwise
/// the cached incarnation (always within the nonzero 56-bit domain). Scalars
/// stay fully initialized across lookup/release helper calls.
pub const SYN_OWNER_ABSENT: u64 = 0;
pub const SYN_OWNER_FRESH: u64 = u64::MAX - 1;
pub const SYN_OWNER_REFUSE: u64 = u64::MAX;

// Keep common-socket field access in its own subprogram.
#[inline(never)]
fn socket_state(sk: *const bpf_sock) -> u32 {
    unsafe { (*sk).state }
}

/// A listener or a pending request owns nothing: the SYN is judged from the tuple's own
/// publication. Only an established child carries a binding to check.
#[inline(always)]
fn inspect_syn_owner(sk: *mut bpf_sock, tuples: &TuplesKey, isn: u32) -> u64 {
    match socket_state(sk) {
        6 => SYN_OWNER_FRESH, // TIME_WAIT is never child storage authority.
        10 | 12 => SYN_OWNER_ABSENT,
        _ => {
            let full = unsafe { bpf_sk_fullsock(sk) };
            if full.is_null() {
                return SYN_OWNER_REFUSE;
            }
            let binding = unsafe {
                bpf_sk_storage_get(
                    (&raw const TCP_SOCKET_BINDING).cast_mut().cast(),
                    full.cast(),
                    ptr::null_mut(),
                    0,
                )
            }
            .cast::<TcpSocketBinding>();
            if binding.is_null() || unsafe { (*binding).kind != TCP_BINDING_CHILD } {
                return SYN_OWNER_REFUSE;
            }
            let binding = unsafe { &*binding };
            if binding.syn_isn != isn {
                return SYN_OWNER_FRESH;
            }
            if !valid_proof(binding, tuples, isn) {
                return SYN_OWNER_REFUSE;
            }
            binding.handoff.incarnation
        }
    }
}

/// Only an established child can authorize native cached-SYN reuse.
#[inline(always)]
pub fn native_syn_owner(ctx: &TcContext, tuples: &TuplesKey, isn: u32) -> u64 {
    let nsid = PARAM.load().tcp_daens_netns_id;
    if nsid < 0 || tuple_retiring(tuples) {
        return SYN_OWNER_REFUSE;
    }
    // The conntrack argument scratch is dead until mark_tcp_seen rezeroes it;
    // using it keeps the 36-byte lookup tuple out of this 3-call stack chain.
    let mut zero = 0u32;
    unsafe { ptr::write_volatile(&mut zero, 0) };
    let Some(scratch) = CONNTRACK_ARGS_MAP.get_ptr_mut(unsafe { ptr::read_volatile(&zero) }) else {
        return SYN_OWNER_REFUSE;
    };
    const _: () = assert!(
        mem::size_of::<bpf_sock_tuple>() <= mem::size_of::<crate::contrack::ConntrackArgs>()
    );
    const _: () = assert!(
        mem::align_of::<bpf_sock_tuple>() <= mem::align_of::<crate::contrack::ConntrackArgs>()
    );
    let tuple = scratch.cast::<bpf_sock_tuple>();
    unsafe { ptr::write_bytes(tuple, 0, 1) };
    let size = if tuples.src_ip.is_v4_mapped() {
        unsafe {
            (*tuple).__bindgen_anon_1.ipv4.saddr = tuples.src_ip.u6_addr32[3];
            (*tuple).__bindgen_anon_1.ipv4.daddr = tuples.dst_ip.u6_addr32[3];
            (*tuple).__bindgen_anon_1.ipv4.sport = tuples.src_port.to_be();
            (*tuple).__bindgen_anon_1.ipv4.dport = tuples.dst_port.to_be();
        }
        mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1>() as u32
    } else {
        unsafe {
            (*tuple).__bindgen_anon_1.ipv6.saddr = tuples.src_ip.u6_addr32;
            (*tuple).__bindgen_anon_1.ipv6.daddr = tuples.dst_ip.u6_addr32;
            (*tuple).__bindgen_anon_1.ipv6.sport = tuples.src_port.to_be();
            (*tuple).__bindgen_anon_1.ipv6.dport = tuples.dst_port.to_be();
        }
        mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2>() as u32
    };
    let sk = unsafe { bpf_skc_lookup_tcp(raw_skb(ctx).cast(), tuple, size, nsid as u64, 0) };
    if sk.is_null() {
        return SYN_OWNER_ABSENT;
    }
    let result = inspect_syn_owner(sk, tuples, isn);
    unsafe { bpf_sk_release(sk.cast()) };
    result
}

// `#[inline(never)]` keeps each family in its own subprogram, and the volatile word loads keep
// every ctx read a constant-offset access: a merged 64-bit copy of `remote_ip6` is rewritten
// through a modified ctx pointer, which the verifier rejects ("dereference of modified ctx ptr").
#[inline(never)]
fn fill_addresses_v4(ops: *const bpf_sock_ops, key: &mut TuplesKey) {
    let (remote, local) = unsafe {
        (
            (&raw const (*ops).remote_ip4).read_volatile(),
            (&raw const (*ops).local_ip4).read_volatile(),
        )
    };
    key.src_ip = In6Addr::from_ipv4_bytes(remote.to_ne_bytes());
    key.dst_ip = In6Addr::from_ipv4_bytes(local.to_ne_bytes());
}

#[inline(never)]
fn fill_addresses_v6(ops: *const bpf_sock_ops, key: &mut TuplesKey) {
    unsafe {
        key.src_ip = In6Addr {
            u6_addr32: [
                (&raw const (*ops).remote_ip6[0]).read_volatile(),
                (&raw const (*ops).remote_ip6[1]).read_volatile(),
                (&raw const (*ops).remote_ip6[2]).read_volatile(),
                (&raw const (*ops).remote_ip6[3]).read_volatile(),
            ],
        };
        key.dst_ip = In6Addr {
            u6_addr32: [
                (&raw const (*ops).local_ip6[0]).read_volatile(),
                (&raw const (*ops).local_ip6[1]).read_volatile(),
                (&raw const (*ops).local_ip6[2]).read_volatile(),
                (&raw const (*ops).local_ip6[3]).read_volatile(),
            ],
        };
    }
}

/// Publish the accepted child's binding. The child's local address is the SYN's destination,
/// so the key matches the one TC published, with the client as source.
#[inline(always)]
fn bind_child(ctx: &SockOpsContext) {
    let ops = ctx.ops;
    let owned = TCP_DAENS_NETNS_COOKIE.load();
    if owned == 0 || unsafe { bpf_get_netns_cookie(ops.cast()) } != owned {
        return;
    }
    let sk = unsafe { (*ops).__bindgen_anon_2.sk };
    if sk.is_null() {
        return;
    }
    let mut key = TuplesKey {
        src_ip: In6Addr::zero(),
        dst_ip: In6Addr::zero(),
        // remote_port is network order in the high half; local_port is host order.
        src_port: u16::from_be((unsafe { (*ops).remote_port } >> 16) as u16),
        dst_port: unsafe { (*ops).local_port } as u16,
        l4proto: IPPROTO_TCP,
        padding: [0; 3],
    };
    match unsafe { (*ops).family } {
        AF_INET => fill_addresses_v4(ops, &mut key),
        AF_INET6 => fill_addresses_v6(ops, &mut key),
        _ => return,
    }
    let Some(handoff) = handoff_snapshot(&key) else {
        return;
    };
    // The callback runs when the handshake completes: rcv_nxt is the client ISN + 1.
    let isn = unsafe { (*ops).rcv_nxt }.wrapping_sub(1);
    let mut binding = TcpSocketBinding {
        tuples: key,
        handoff,
        kind: TCP_BINDING_CHILD,
        syn_isn: isn,
    };
    if !valid_proof(&binding, &key, isn) {
        return;
    }
    // One call links a fully copied element: TC readers never observe a partial binding.
    let stored = unsafe {
        bpf_sk_storage_get(
            (&raw const TCP_SOCKET_BINDING).cast_mut().cast(),
            sk.cast(),
            (&raw mut binding).cast(),
            BPF_SK_STORAGE_GET_F_CREATE as u64,
        )
    };
    if stored.is_null() {
        increment_bpf_stat(BpfStatsKey::TcpChildProofStorageFailure);
    }
}

/// Every other op fires for each host TCP socket and must stay inert; an unproven child is
/// refused by userspace adoption, so the verdict is always "continue".
#[sock_ops]
pub fn honk_tcp_passive(ctx: SockOpsContext) -> u32 {
    if ctx.op() == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB {
        bind_child(&ctx);
    }
    1
}
