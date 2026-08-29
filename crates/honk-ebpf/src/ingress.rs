//! TC ingress program entry points and helpers.
//!
//! `lan_ingress` intercepts LAN traffic, makes a routing decision, and
//! redirects proxy-bound flows into the isolated `daens` namespace via the
//! `dae0` link. The `sk_lookup` BPF program in `daens` then assigns the
//! packet to the local transparent listener socket.  `dae0_ingress` rewrites
//! replies from that listener back onto the original LAN interface so the
//! three-way handshake can complete without involving host IP forwarding.

use core::{
    ffi::{c_long, c_void},
    mem, ptr,
};

use crate::{
    action::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT, Verdict, flatten},
    log_shim::*,
    maps::LISTEN_SOCKET_MAP,
    transport::ParsedPacket,
};
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::{
    bindings::{
        __sk_buff, BPF_FIB_LKUP_RET_NOT_FWDED, bpf_fib_lookup as BpfFibLookup, bpf_sock_tuple,
        bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1, bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2,
    },
    helpers::{
        bpf_fib_lookup, bpf_ktime_get_ns, bpf_redirect, bpf_redirect_peer, bpf_skb_store_bytes,
    },
};
use honk_ebpf_common::{
    CLASSIFIED_MARK, DATAPATH_FLAG_NFQ_ENABLED, DATAPATH_FLAG_NFQ_READY, IpVersionType,
    NFQUEUE_PENDING_MARK, NFQUEUE_SIGNATURE_MARK, RedirectEntry, RedirectTuple, RoutingMeta,
    TPROXY_MARK,
    conn::{BpfStatsKey, ConnState, UdpDecisionState},
    pack_nfqueue_mark,
    redirect_need::{RoutingHandoffEntry, TuplesKey},
};
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};

use crate::{
    maps::{
        OUTBOUND_CONNECTIVITY_MAP, PARAM, PKT_SCRATCH_KEY, REDIRECT_TRACK, ROUTE_CTX_SCRATCH_MAP,
        ROUTING_HANDOFF_MAP, UDP_DECISION_SCRATCH_MAP, increment_bpf_stat,
    },
    route::{
        OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT, RouteCtx, RouteStateFlags,
    },
    sk,
    transport::{
        ETH_HLEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_TCP, IPPROTO_UDP, parse_packet,
        udp_has_quic_long_header,
    },
};
const IPV6_BYTE_LENGTH: usize = 16;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// Handoff write modes for [`redirect_lan_packet_to_control_plane`].
///
/// `HANDOFF_WRITE_ALWAYS`: new TCP flow (pure-SYN path).  Userspace
///   consumes the entry once when the connection is accepted, so every new
///   flow must leave one behind.  `REDIRECT_TRACK` is written
///   unconditionally as well.
/// `HANDOFF_WRITE_SKIP`: established TCP on the cached-routing path.
///   Userspace never looks up handoffs for these packets, so writing one
///   would just sit in the map until the janitor sweeps it.
///   `REDIRECT_TRACK` is refreshed only when stale.
/// `HANDOFF_WRITE_REFRESH`: UDP, first packet and cached path alike.
///   Write when no entry exists or the existing one is older than
///   [`crate::contrack::AUXILIARY_MAP_REFRESH_INTERVAL_NS`]. A new flow's first
///   packet always finds the entry absent (or long consumed) and therefore
///   rewrites it, so userspace still sees a handoff on endpoint-pool miss.
const HANDOFF_WRITE_ALWAYS: u8 = 0;
const HANDOFF_WRITE_SKIP: u8 = 1;
const HANDOFF_WRITE_REFRESH: u8 = 2;

#[inline(always)]
fn redirect_lan_packet_to_control_plane(
    ctx: &TcContext,
    _link_h_len: u32,
    pkt: &ParsedPacket,
    routing_meta_raw: u64,
    handoff_mode: u8,
    decision_token: u32,
) -> Verdict {
    let routing_meta = RoutingMeta {
        raw: routing_meta_raw,
    };
    let now = unsafe { bpf_ktime_get_ns() };

    // Account this LAN → outbound packet against the final outbound
    // (redirect path; the direct+must pass-through exits count separately).
    crate::stats::count_tx(ctx, unsafe { routing_meta.data.outbound });

    // Set mark and cb for later processing.  The cross-namespace redirect
    // path preserves skb->mark but not cb[], so encode the listener l4proto
    // in the low byte of the mark (TPROXY_MARK only uses bit 27).
    ctx.skb
        .set_mark(TPROXY_MARK | (pkt.listener_l4proto as u32));
    unsafe {
        (*ctx.skb.skb).cb[0] = TPROXY_MARK;
        (*ctx.skb.skb).cb[1] = pkt.listener_l4proto as u32;
    }

    // Handoff entry for userspace lookup, throttled by mode (see the
    // HANDOFF_WRITE_* constants): established TCP flows never write, UDP
    // flows write at most once per AUXILIARY_MAP_REFRESH_INTERVAL_NS.
    let write_handoff = match handoff_mode {
        HANDOFF_WRITE_ALWAYS => true,
        HANDOFF_WRITE_REFRESH => match ROUTING_HANDOFF_MAP.get_ptr_mut(pkt.tuples.five) {
            Some(old) => unsafe {
                if (*old).result.decision_token != decision_token {
                    return Err(TC_ACT_SHOT);
                }
                now.wrapping_sub((*old).last_seen_ns)
                    >= crate::contrack::AUXILIARY_MAP_REFRESH_INTERVAL_NS
            },
            None => true,
        },
        _ => false,
    };
    if write_handoff {
        let mut handoff: RoutingHandoffEntry = unsafe { mem::zeroed() };
        handoff.last_seen_ns = now;
        unsafe {
            handoff.result.mark = routing_meta.data.mark;
            handoff.result.must = routing_meta.data.must;
            handoff.result.outbound = routing_meta.data.outbound;
            handoff.result.dscp = routing_meta.data.dscp;
        }
        handoff.result.decision_token = decision_token;
        handoff.result.mac.copy_from_slice(&pkt.ethh.src_addr);
        if ROUTING_HANDOFF_MAP
            .insert(pkt.tuples.five, handoff, 0)
            .is_err()
        {
            increment_bpf_stat(BpfStatsKey::RoutingHandoffInsertFailure);
            // The control plane would otherwise receive an unrouteable flow;
            // do not redirect it without the required handoff.
            return Err(TC_ACT_SHOT);
        }
    }

    // Store the original LAN framing so dae0_ingress can rewrite replies
    // back to the original client without involving host IP forwarding.
    // New flows write unconditionally; cached-flow packets only refresh the
    // entry once it is older than AUXILIARY_MAP_REFRESH_INTERVAL_NS.
    let redirect_tuple = RedirectTuple::from_tuples(&pkt.tuples.five);
    let write_track = if handoff_mode == HANDOFF_WRITE_ALWAYS {
        true
    } else {
        match REDIRECT_TRACK.get_ptr_mut(redirect_tuple) {
            Some(old) => unsafe {
                if (*old).decision_token != decision_token {
                    return Err(TC_ACT_SHOT);
                }
                now.wrapping_sub((*old).last_seen_ns)
                    >= crate::contrack::AUXILIARY_MAP_REFRESH_INTERVAL_NS
            },
            None => true,
        }
    };
    if write_track {
        let mut redirect_entry: RedirectEntry = unsafe { mem::zeroed() };
        redirect_entry.ifindex = unsafe { (*ctx.skb.skb).ifindex };
        redirect_entry.smac.copy_from_slice(&pkt.ethh.src_addr);
        redirect_entry.dmac.copy_from_slice(&pkt.ethh.dst_addr);
        redirect_entry.last_seen_ns = now;
        // Record the final outbound so dae0_ingress can attribute replies.
        redirect_entry.outbound = unsafe { routing_meta.data.outbound };
        redirect_entry.decision_token = decision_token;
        if REDIRECT_TRACK
            .insert(redirect_tuple, redirect_entry, 0)
            .is_err()
        {
            increment_bpf_stat(BpfStatsKey::RedirectTrackInsertFailure);
            // Do not redirect when reply restoration cannot be guaranteed.
            return Err(TC_ACT_SHOT);
        }
    }

    // Redirect to host-side dae0. The netkit or veth peer delivers it inside
    // daens as dae0peer, where sk_lookup selects the local TPROXY listener.
    let param = PARAM.load();
    // bpf_redirect_peer() bypasses the CPU backlog for paired links.
    // Requires kernel >= 6.8 (CVE-2025-37959 fix). Userspace verifies the
    // kernel version before enabling this flag.
    if param.use_redirect_peer != 0 {
        Ok(unsafe { bpf_redirect_peer(param.dae0_ifindex, 0) } as c_long)
    } else {
        Ok(unsafe { bpf_redirect(param.dae0_ifindex, 0) } as c_long)
    }
}

#[inline(always)]
fn remove_udp_stage_aux(key: &TuplesKey, decision_token: u32) {
    if let Some(handoff) = ROUTING_HANDOFF_MAP.get_ptr(key)
        && unsafe { (*handoff).result.decision_token } == decision_token
    {
        let _ = ROUTING_HANDOFF_MAP.remove(key);
    }
    let redirect_tuple = RedirectTuple::from_tuples(key);
    if let Some(track) = REDIRECT_TRACK.get_ptr(redirect_tuple)
        && unsafe { (*track).decision_token } == decision_token
    {
        let _ = REDIRECT_TRACK.remove(redirect_tuple);
    }
}

/// Publish all token-bound auxiliary state before exposing Pending to followers.
#[inline(never)]
fn stage_udp_decision(ctx: &TcContext, pkt: &ParsedPacket, routing_meta_raw: u64) -> Verdict {
    let routing_meta = RoutingMeta {
        raw: routing_meta_raw,
    };
    let outbound = unsafe { routing_meta.data.outbound };
    let mark = unsafe { routing_meta.data.mark };
    let must = unsafe { routing_meta.data.must };
    let Some(scratch_ptr) = UDP_DECISION_SCRATCH_MAP.get_ptr_mut(0) else {
        crate::contrack::remove_udp_preparing(&pkt.tuples.five);
        return Err(TC_ACT_SHOT);
    };
    unsafe {
        ptr::write_bytes(scratch_ptr, 0, 1);
    }
    let scratch = unsafe { &mut *scratch_ptr };
    let Some(decision_token) = crate::contrack::allocate_udp_decision_token(&pkt.tuples.five)
    else {
        crate::contrack::remove_udp_preparing(&pkt.tuples.five);
        return Err(TC_ACT_SHOT);
    };
    let now = unsafe { bpf_ktime_get_ns() };
    scratch.redirect_key = RedirectTuple::from_tuples(&pkt.tuples.five);

    scratch.redirect.ifindex = unsafe { (*ctx.skb.skb).ifindex };
    scratch.redirect.smac.copy_from_slice(&pkt.ethh.src_addr);
    scratch.redirect.dmac.copy_from_slice(&pkt.ethh.dst_addr);
    scratch.redirect.last_seen_ns = now;
    scratch.redirect.outbound = OUTBOUND_CONTROL_PLANE_ROUTING;
    scratch.redirect.decision_token = decision_token;
    if REDIRECT_TRACK
        .insert(scratch.redirect_key, scratch.redirect, 0)
        .is_err()
    {
        increment_bpf_stat(BpfStatsKey::RedirectTrackInsertFailure);
        crate::contrack::remove_udp_preparing(&pkt.tuples.five);
        return Err(TC_ACT_SHOT);
    }

    scratch.handoff.last_seen_ns = now;
    scratch.handoff.result.mark = mark;
    scratch.handoff.result.must = must;
    scratch.handoff.result.outbound = outbound;
    scratch.handoff.result.dscp = pkt.tuples.dscp;
    scratch.handoff.result.decision_token = decision_token;
    scratch
        .handoff
        .result
        .mac
        .copy_from_slice(&pkt.ethh.src_addr);
    if ROUTING_HANDOFF_MAP
        .insert(pkt.tuples.five, scratch.handoff, 0)
        .is_err()
    {
        increment_bpf_stat(BpfStatsKey::RoutingHandoffInsertFailure);
        remove_udp_stage_aux(&pkt.tuples.five, decision_token);
        crate::contrack::remove_udp_preparing(&pkt.tuples.five);
        return Err(TC_ACT_SHOT);
    }

    crate::contrack::populate_udp_conn_state(
        &mut scratch.state,
        routing_meta,
        &pkt.ethh.src_addr,
        UdpDecisionState::Pending,
        decision_token,
    );
    if !crate::contrack::publish_claimed_udp_state(&pkt.tuples.five, &scratch.state) {
        remove_udp_stage_aux(&pkt.tuples.five, decision_token);
        crate::contrack::remove_udp_preparing(&pkt.tuples.five);
        return Err(TC_ACT_SHOT);
    }

    ctx.skb.set_mark(NFQUEUE_SIGNATURE_MARK | decision_token);
    Err(TC_ACT_OK)
}

#[inline(always)]
fn cached_udp_decision(
    ctx: &TcContext,
    link_h_len: u32,
    pkt: &ParsedPacket,
    state: &mut ConnState,
) -> Verdict {
    let decision_token = state.decision_token;
    if decision_token == 0 {
        return cached_udp_decision_inner(ctx, link_h_len, pkt, state);
    }
    let Some(epoch) = crate::maps::begin_udp_decision() else {
        return Err(TC_ACT_SHOT);
    };
    let verdict = if crate::maps::udp_decision_retiring(&pkt.tuples.five) {
        Err(TC_ACT_SHOT)
    } else if let Some(current) = crate::contrack::lookup_udp_seen(&pkt.tuples.five) {
        if current.decision_token == decision_token {
            cached_udp_decision_inner(ctx, link_h_len, pkt, current)
        } else {
            Err(TC_ACT_SHOT)
        }
    } else {
        Err(TC_ACT_SHOT)
    };
    crate::maps::end_udp_decision(epoch);
    verdict
}

#[inline(always)]
fn cached_udp_decision_inner(
    ctx: &TcContext,
    link_h_len: u32,
    pkt: &ParsedPacket,
    state: &mut ConnState,
) -> Verdict {
    if state.is_wan_ingress_direction != 0 {
        return pass_through_classified(ctx);
    }

    if state.state == UdpDecisionState::Preparing as u8 {
        return Err(TC_ACT_SHOT);
    }
    if state.state == UdpDecisionState::Pending as u8
        || state.state == UdpDecisionState::DirectArmed as u8
    {
        let flags = crate::maps::datapath_flags();
        if flags & DATAPATH_FLAG_NFQ_ENABLED != 0
            && flags & DATAPATH_FLAG_NFQ_READY != 0
            && let Some(mark) = pack_nfqueue_mark(state.decision_token)
        {
            ctx.skb.set_mark(mark);
            return Err(TC_ACT_OK);
        }
        return Err(TC_ACT_SHOT);
    }
    if state.state == UdpDecisionState::Block as u8 {
        return Err(TC_ACT_SHOT);
    }
    if state.state != UdpDecisionState::None as u8 && state.state != UdpDecisionState::Proxy as u8 {
        return Err(TC_ACT_SHOT);
    }

    let meta_raw = unsafe { state.meta.raw };
    if (meta_raw >> 56) & 1 == 0 {
        return pass_through_classified(ctx);
    }
    let outbound = unsafe { state.meta.data.outbound };
    let mark = unsafe { state.meta.data.mark };
    let must = unsafe { state.meta.data.must };
    let offload = meta_raw & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD != 0;

    if state.state == UdpDecisionState::Proxy as u8 {
        if state.decision_token == 0 {
            return Err(TC_ACT_SHOT);
        }
        return redirect_lan_packet_to_control_plane(
            ctx,
            link_h_len,
            pkt,
            meta_raw,
            HANDOFF_WRITE_SKIP,
            state.decision_token,
        );
    }
    if state.decision_token != 0 && (outbound != OUTBOUND_DIRECT || !offload || must != 0) {
        return Err(TC_ACT_SHOT);
    }
    if outbound == OUTBOUND_DIRECT && (must != 0 || offload) {
        crate::stats::count_tx(ctx, outbound);
        ctx.skb.set_mark(mark | CLASSIFIED_MARK);
        return Err(TC_ACT_OK);
    }
    if outbound == OUTBOUND_DIRECT || outbound == OUTBOUND_BLOCK {
        if !wan_outbound_is_alive(ctx, outbound, pkt.l4proto, pkt.tuples.five.dst_port) {
            return Err(TC_ACT_SHOT);
        }
        return redirect_lan_packet_to_control_plane(
            ctx,
            link_h_len,
            pkt,
            meta_raw,
            HANDOFF_WRITE_REFRESH,
            state.decision_token,
        );
    }
    if !wan_outbound_is_alive(ctx, outbound, pkt.l4proto, pkt.tuples.five.dst_port) {
        return Err(TC_ACT_SHOT);
    }
    redirect_lan_packet_to_control_plane(
        ctx,
        link_h_len,
        pkt,
        meta_raw,
        HANDOFF_WRITE_REFRESH,
        state.decision_token,
    )
}

/// Early-exit `TC_ACT_OK` after tagging the skb with `CLASSIFIED_MARK`, so the
/// second TC pass (bridge master + slave double-attach) short-circuits at
/// the `do_tproxy_lan_ingress` entry check instead of redoing the full
/// classification.
#[inline(always)]
fn pass_through_classified(ctx: &TcContext) -> Verdict {
    ctx.skb
        .set_mark(unsafe { (*ctx.skb.skb).mark } | CLASSIFIED_MARK);
    Err(TC_ACT_OK)
}

#[inline(always)]
fn wan_outbound_is_alive(ctx: &TcContext, outbound: u8, l4proto: u8, dport: u16) -> bool {
    // DNS must always reach the control plane regardless of outbound health
    // (Go dae tproxy.c:2606 — userspace DNS handles its own fallback);
    // applies to both TCP and UDP port 53.
    if dport == 53 {
        return true;
    }

    let protocol = ctx.skb.protocol() as u16;
    let domain_idx = match (l4proto, dport) {
        (IPPROTO_UDP, 53) => 1,
        (IPPROTO_UDP, _) => 2,
        _ => 0,
    };

    let ip_idx: u64 = if protocol == ETH_P_IP.to_be() { 0 } else { 1 };
    let key: u32 = (outbound as u32) * 6 + (domain_idx as u32) * 2 + (ip_idx as u32);

    match OUTBOUND_CONNECTIVITY_MAP.get(key) {
        Some(alive_val) => *alive_val != 0,
        None => true,
    }
}

/// Confirm that a wildcard socket match names a host-local route. Socket
/// lookup also matches forwarded destinations; only `NOT_FWDED` is eligible
/// after the earlier broadcast/multicast rejection. Every forwarded or
/// ambiguous FIB result stays on the transparent routing path.
#[inline(always)]
fn wildcard_socket_destination_is_local(ctx: &TcContext, pkt: &ParsedPacket) -> bool {
    let mut fib: BpfFibLookup = unsafe { mem::zeroed() };
    fib.family = if pkt.ethh.ether_type == ETH_P_IP.to_be() {
        AF_INET
    } else {
        AF_INET6
    };
    fib.l4_protocol = pkt.l4proto;
    fib.sport = pkt.tuples.five.src_port.to_be();
    fib.dport = pkt.tuples.five.dst_port.to_be();
    fib.ifindex = unsafe { (*ctx.skb.skb).ifindex };
    unsafe {
        fib.__bindgen_anon_1.tot_len = (*ctx.skb.skb).len as u16;
        if fib.family == AF_INET {
            fib.__bindgen_anon_2.tos = pkt.tuples.dscp << 2;
        }
        if fib.family == AF_INET {
            fib.__bindgen_anon_3.ipv4_src = pkt.tuples.five.src_ip.u6_addr32[3];
            fib.__bindgen_anon_4.ipv4_dst = pkt.tuples.five.dst_ip.u6_addr32[3];
        } else {
            fib.__bindgen_anon_3.ipv6_src = pkt.tuples.five.src_ip.u6_addr32;
            fib.__bindgen_anon_4.ipv6_dst = pkt.tuples.five.dst_ip.u6_addr32;
        }
    }
    let result = unsafe {
        bpf_fib_lookup(
            ctx.skb.skb as *mut c_void,
            &mut fib,
            mem::size_of::<BpfFibLookup>() as i32,
            0,
        )
    };
    result == BPF_FIB_LKUP_RET_NOT_FWDED as c_long
}

/// Existing flows probe for a local owner as before. Pure SYNs normally skip
/// this lookup, except TCP DNS: a real host-netns port-53 LISTEN socket must
/// get first refusal before the unconditional DNS redirect.
#[inline(always)]
const fn tcp_socket_probe_required(pure_syn: bool, destination_port: u16) -> bool {
    !pure_syn || destination_port == 53
}

// Host-build-free structural coverage for the no_std eBPF crate.
const _: [(); 1] = [(); tcp_socket_probe_required(true, 53) as usize];
const _: [(); 0] = [(); tcp_socket_probe_required(true, 443) as usize];
const _: [(); 1] = [(); tcp_socket_probe_required(false, 443) as usize];

/// Check if a destination IP is likely a local address where a socket lookup
/// could find a matching listening socket (RFC 1918, loopback, ULA, link-local).
// #[inline(never)]: shared by lan_ingress_l2/l3. 5-level call chain
// with 256B baseline stays under the 512B BPF stack limit.
#[inline(never)]
fn do_tproxy_lan_ingress(ctx: &TcContext, link_h_len: u32) -> Verdict {
    if !crate::maps::datapath_ready() {
        return Err(TC_ACT_OK);
    }
    // Bridge master/slave double attachment must not reclassify either an
    // already-final packet or a held packet carrying its unique queue token.
    if unsafe { (*ctx.skb.skb).mark } & (CLASSIFIED_MARK | NFQUEUE_PENDING_MARK) != 0 {
        return Err(TC_ACT_OK);
    }

    let scratch_key: u32 = 0;
    let pkt = match PKT_SCRATCH_KEY.get_ptr_mut(scratch_key) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };

    let ret = parse_packet(ctx, link_h_len, pkt);
    if ret != 0 {
        return pass_through_classified(ctx);
    }

    // Broadcast/multicast destinations (DHCP, mDNS, SSDP, LLMNR) must never
    // be routed, marked, or conntracked — pass through immediately.
    if crate::transport::dst_is_special(pkt, link_h_len) {
        return pass_through_classified(ctx);
    }

    if pkt.l4proto == IPPROTO_TCP && !crate::contrack::is_new_tcp_connection(&pkt.tcph) {
        let tcp_state = crate::contrack::mark_tcp_seen(
            &pkt.tuples.five,
            &pkt.tcph,
            0u8,
            None,
            None,
            None,
            None,
            0,
            None,
            0,
        );
        let tcp_state = match tcp_state {
            Some(state) => state,
            None => return pass_through_classified(ctx),
        };
        if (unsafe { tcp_state.meta.raw } >> 56) & 1 == 0 {
            return pass_through_classified(ctx);
        }

        let outbound = unsafe { tcp_state.meta.data.outbound };
        let mark = unsafe { tcp_state.meta.data.mark };

        let must = unsafe { tcp_state.meta.data.must };
        let offload =
            unsafe { tcp_state.meta.raw } & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD != 0;

        // The offload decision was cached per flow at route-decision time
        // (must-direct, or the mode-based policy).  Flows the DNS fast path
        // publishes carry neither bit and keep redirecting to the control
        // plane, so TCP DNS is never split by this pass-through.
        if outbound == OUTBOUND_DIRECT && (must != 0 || offload) {
            crate::stats::count_tx(ctx, outbound);
            ctx.skb.set_mark(mark | CLASSIFIED_MARK);
            return Err(TC_ACT_OK);
        }
        if outbound == OUTBOUND_DIRECT {
            return redirect_lan_packet_to_control_plane(
                ctx,
                link_h_len,
                pkt,
                unsafe { tcp_state.meta.raw },
                HANDOFF_WRITE_SKIP,
                0,
            );
        }
        if outbound == OUTBOUND_BLOCK {
            // Redirect BLOCK to control plane so userspace can drop/log it.
            return redirect_lan_packet_to_control_plane(
                ctx,
                link_h_len,
                pkt,
                unsafe { tcp_state.meta.raw },
                HANDOFF_WRITE_SKIP,
                0,
            );
        }
        if !wan_outbound_is_alive(ctx, outbound, pkt.l4proto, pkt.tuples.five.dst_port) {
            return Err(TC_ACT_SHOT);
        }
        return redirect_lan_packet_to_control_plane(
            ctx,
            link_h_len,
            pkt,
            unsafe { tcp_state.meta.raw },
            HANDOFF_WRITE_SKIP,
            0,
        );
    }

    // Per-flow log, gated by PARAM.padding2 bit 0 (userspace writes 0 → off).
    if PARAM.load().padding2 & 1 != 0 {
        info!(ctx, target: "honk", "lan new flow: l4proto={} sport={} dport={}", pkt.l4proto, pkt.tuples.five.src_port, pkt.tuples.five.dst_port);
    }
    let mut route_flag: [u32; 8] = [0; 8];
    let mut tcp_state: Option<&mut ConnState> = None;

    if pkt.l4proto == IPPROTO_TCP {
        tcp_state = crate::contrack::mark_tcp_seen(
            &pkt.tuples.five,
            &pkt.tcph,
            0u8,
            None,
            None,
            None,
            None,
            pkt.tuples.dscp,
            None,
            0,
        );
        route_flag[0] = 1; // L4ProtoType_TCP
    } else {
        if !crate::contrack::is_short_lived_udp_traffic(&pkt.tuples.five)
            && let Some(state) = crate::contrack::lookup_udp_seen(&pkt.tuples.five)
        {
            return cached_udp_decision(ctx, link_h_len, pkt, state);
        }
        route_flag[0] = 2; // L4ProtoType_UDP
    }

    // New-flow handoff policy from here on: a pure TCP SYN must always leave
    // a handoff for userspace to consume at accept time; UDP writes are
    // throttled to absent-or-stale (userspace only reads them on endpoint
    // pool miss, and the first packet always finds the entry absent).
    let handoff_mode = if pkt.l4proto == IPPROTO_TCP {
        HANDOFF_WRITE_ALWAYS
    } else {
        HANDOFF_WRITE_REFRESH
    };

    let protocol = unsafe { (*ctx.skb.skb).protocol as u16 };
    route_flag[1] = if protocol == ETH_P_IP.to_be() {
        IpVersionType::V4 as u32
    } else {
        IpVersionType::V6 as u32
    };
    route_flag[6] = pkt.tuples.dscp as u32;

    let mac_be: [u32; 4] = [
        0,
        0,
        (((pkt.ethh.src_addr[0] as u32) << 8) | (pkt.ethh.src_addr[1] as u32)).to_be(),
        (((pkt.ethh.src_addr[2] as u32) << 24)
            | ((pkt.ethh.src_addr[3] as u32) << 16)
            | ((pkt.ethh.src_addr[4] as u32) << 8)
            | (pkt.ethh.src_addr[5] as u32))
            .to_be(),
    ];

    if pkt.l4proto == IPPROTO_TCP || pkt.l4proto == IPPROTO_UDP {
        let mut tuple: bpf_sock_tuple = unsafe { mem::zeroed() };
        let tuple_size = if pkt.ethh.ether_type == ETH_P_IP.to_be() {
            unsafe {
                tuple.__bindgen_anon_1.ipv4.daddr = pkt.tuples.five.dst_ip.u6_addr32[3];
                tuple.__bindgen_anon_1.ipv4.saddr = pkt.tuples.five.src_ip.u6_addr32[3];
                tuple.__bindgen_anon_1.ipv4.dport = pkt.tuples.five.dst_port.to_be();
                tuple.__bindgen_anon_1.ipv4.sport = pkt.tuples.five.src_port.to_be();
            }
            mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1>() as u32
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    pkt.tuples.five.dst_ip.u6_addr32.as_ptr(),
                    tuple.__bindgen_anon_1.ipv6.daddr.as_mut_ptr(),
                    4,
                );
                core::ptr::copy_nonoverlapping(
                    pkt.tuples.five.src_ip.u6_addr32.as_ptr(),
                    tuple.__bindgen_anon_1.ipv6.saddr.as_mut_ptr(),
                    4,
                );
                tuple.__bindgen_anon_1.ipv6.dport = pkt.tuples.five.dst_port.to_be();
                tuple.__bindgen_anon_1.ipv6.sport = pkt.tuples.five.src_port.to_be();
            }
            mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2>() as u32
        };

        if pkt.l4proto == IPPROTO_TCP {
            // Preserve the general pure-SYN lookup skip. TCP DNS is the sole
            // exception so LAN clients can reach an ordinary host listener
            // before the unconditional port-53 fast path below.
            let pure_syn = pkt.tcph.syn() != 0 && pkt.tcph.ack() == 0;
            if tcp_socket_probe_required(pure_syn, pkt.tuples.five.dst_port) {
                let param = PARAM.load();
                if let Some(probe) =
                    sk::probe_tcp_socket(ctx, &mut tuple, tuple_size, param.dae_netns_id as u64)
                {
                    // A local (non-dae) LISTEN socket owns this destination:
                    // NAT loopback — leave it to the kernel.
                    // BPF_TCP_LISTEN = 10
                    if !probe.is_dae_socket
                        && probe.state == 10
                        && (!probe.is_wildcard || wildcard_socket_destination_is_local(ctx, pkt))
                    {
                        return pass_through_classified(ctx);
                    }
                }
            }
        } else {
            let param = PARAM.load();
            if let Some(probe) =
                sk::probe_udp_socket(ctx, &mut tuple, tuple_size, param.dae_netns_id as u64)
                && !probe.is_dae_socket
                && (!probe.is_wildcard || wildcard_socket_destination_is_local(ctx, pkt))
            {
                return pass_through_classified(ctx);
            }
        }
    }

    // DNS fast path: skip the expensive route_loop + LPM/domain lookups.
    if pkt.tuples.five.dst_port == 53 {
        // Update conn state for TCP DNS (UDP DNS is short-lived, skipped anyway)
        if pkt.l4proto == IPPROTO_TCP
            && let Some(state) = &mut tcp_state
        {
            state.mac.copy_from_slice(&pkt.ethh.src_addr);
            let meta = crate::contrack::build_routing_meta(OUTBOUND_DIRECT, 0, 0, pkt.tuples.dscp);
            crate::contrack::publish_routing_meta(&mut state.meta, meta);
        }
        return redirect_lan_packet_to_control_plane(
            ctx,
            link_h_len,
            pkt,
            unsafe {
                crate::contrack::build_routing_meta(OUTBOUND_DIRECT, 0, 0, pkt.tuples.dscp).raw
            },
            handoff_mode,
            0,
        );
    }

    let flags = crate::maps::datapath_flags();
    let short_lived_udp =
        pkt.l4proto == IPPROTO_UDP && crate::contrack::is_short_lived_udp_traffic(&pkt.tuples.five);
    let udp_claimed =
        if pkt.l4proto == IPPROTO_UDP && !short_lived_udp && flags & DATAPATH_FLAG_NFQ_ENABLED != 0
        {
            if crate::contrack::claim_udp_preparing(&pkt.tuples.five, &pkt.ethh.src_addr) {
                true
            } else if let Some(state) = crate::contrack::lookup_udp_seen(&pkt.tuples.five) {
                return cached_udp_decision(ctx, link_h_len, pkt, state);
            } else {
                return Err(TC_ACT_SHOT);
            }
        } else {
            false
        };

    let route_ctx_ptr = ROUTE_CTX_SCRATCH_MAP.get_ptr_mut(0);
    if route_ctx_ptr.is_none() {
        if udp_claimed {
            crate::contrack::remove_udp_preparing(&pkt.tuples.five);
        }
        return Err(TC_ACT_SHOT);
    }
    let route_ctx = unsafe { &mut *route_ctx_ptr.unwrap() };

    unsafe {
        core::ptr::write_bytes(
            route_ctx as *mut RouteCtx as *mut u8,
            0,
            mem::size_of::<RouteCtx>(),
        );
    }
    route_ctx.is_wan = 0;
    route_ctx.l4proto_type = route_flag[0] as u8;
    route_ctx.ipversion_type = route_flag[1] as u8;
    route_ctx.dscp_cache = route_flag[6] as u8;
    route_ctx.pname_cache = [route_flag[2], route_flag[3], route_flag[4], route_flag[5]];
    route_ctx.mac.copy_from_slice(&mac_be);

    if pkt.l4proto == IPPROTO_TCP {
        route_ctx.h_dport = u16::from_be_bytes(pkt.tcph.dest);
        route_ctx.h_sport = u16::from_be_bytes(pkt.tcph.source);
    } else {
        route_ctx.h_dport = u16::from_be_bytes(pkt.udph.dst);
        route_ctx.h_sport = u16::from_be_bytes(pkt.udph.src);
    }

    if route_ctx.h_dport == 53 && (route_flag[0] == 2 || route_flag[0] == 1) {
        route_ctx.route_state |= 1 << 3; // ROUTE_STATE_DNS_QUERY
    }

    // Copy the raw network-order bytes into the LPM key data. Using u6_addr32
    // chunks would swap bytes on little-endian BPF hosts, breaking lookups
    // against the network-order keys pushed by userspace.
    route_ctx.lpm_key_saddr.prefix_len = (IPV6_BYTE_LENGTH * 8) as u32;
    route_ctx.lpm_key_daddr.prefix_len = (IPV6_BYTE_LENGTH * 8) as u32;
    route_ctx.lpm_key_mac.prefix_len = (IPV6_BYTE_LENGTH * 8) as u32;
    unsafe {
        core::ptr::copy_nonoverlapping(
            pkt.tuples.five.src_ip.as_bytes().as_ptr(),
            core::ptr::addr_of_mut!(route_ctx.lpm_key_saddr.data).cast::<u8>(),
            IPV6_BYTE_LENGTH,
        );
        core::ptr::copy_nonoverlapping(
            pkt.tuples.five.dst_ip.as_bytes().as_ptr(),
            core::ptr::addr_of_mut!(route_ctx.lpm_key_daddr.data).cast::<u8>(),
            IPV6_BYTE_LENGTH,
        );
        core::ptr::copy_nonoverlapping(
            mac_be.as_ptr(),
            core::ptr::addr_of_mut!(route_ctx.lpm_key_mac.data).cast(),
            4,
        );
    }

    let active_rules_len = route_ctx.prepare_generation();

    let loop_ret = route_ctx.route_loop(active_rules_len);
    if loop_ret < 0 {
        error!(ctx, target: "honk", "shot routing: {}", loop_ret);
        if udp_claimed {
            crate::contrack::remove_udp_preparing(&pkt.tuples.five);
        }
        return Err(TC_ACT_SHOT);
    }

    let s64_ret = route_ctx.result;
    if s64_ret < 0 {
        error!(ctx, target: "honk", "lan_ingress route fail: {}", s64_ret);
        if udp_claimed {
            crate::contrack::remove_udp_preparing(&pkt.tuples.five);
        }
        return Err(TC_ACT_SHOT);
    }

    let outbound = s64_ret as u8;
    let mark = (s64_ret >> 8) as u32;
    let must = ((s64_ret >> 40) & 1) as u8;

    // Mode-based direct offload, decided once per new flow and cached in the
    // flow's routing meta (ROUTING_META_FLAG_OFFLOAD) — the only read of
    // DATAPATH_FLAGS_MAP on this path.  must/block finals are never
    // offloaded beyond the must-direct case, in any mode.  In Rule mode a
    // non-must direct decision is offloaded only when no SNI re-evaluation
    // can change it: the config provably has no domain-class rules (static
    // flag), or this flow's domain was DNS-learned and the route loop just
    // evaluated the complete bitmap.  In Direct mode every non-final flow
    // is offloaded regardless — the userspace override would force direct
    // anyway — and its cached outbound is normalized to direct so the
    // established fast path and tx stats treat it as what it physically is.
    let offload_direct = must == 0
        && outbound != OUTBOUND_BLOCK
        && ((flags & honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_ALL != 0)
            || (flags & honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_RULE_DIRECT != 0
                && outbound == OUTBOUND_DIRECT
                && (flags & honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_NO_DOMAIN_RULES != 0
                    || route_ctx.route_state & (RouteStateFlags::DomainKnown as u8) != 0)));
    let meta_outbound = if offload_direct {
        OUTBOUND_DIRECT
    } else {
        outbound
    };

    let mut udp_published = true;
    if short_lived_udp {
        // DNS deliberately has no UDP conn-state entry.
    } else if pkt.l4proto == IPPROTO_TCP {
        if let Some(state) = &mut tcp_state {
            state.mac.copy_from_slice(&pkt.ethh.src_addr);
            let meta = crate::contrack::build_routing_meta_with_offload(
                meta_outbound,
                mark,
                must,
                pkt.tuples.dscp,
                offload_direct,
            );
            crate::contrack::publish_routing_meta(&mut state.meta, meta);
        }
    } else if pkt.l4proto == IPPROTO_UDP {
        let unresolved_direct = outbound == OUTBOUND_DIRECT && !offload_direct;
        let control_plane_routing = outbound == OUTBOUND_CONTROL_PLANE_ROUTING;
        let preliminary_proxy = outbound != OUTBOUND_DIRECT
            && outbound != OUTBOUND_BLOCK
            && outbound != OUTBOUND_CONTROL_PLANE_ROUTING;
        let domain_can_change = flags & honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_NO_DOMAIN_RULES
            == 0
            && route_ctx.route_state & (RouteStateFlags::DomainKnown as u8) == 0;
        let stage_required = must == 0
            && !offload_direct
            && outbound != OUTBOUND_BLOCK
            && (unresolved_direct
                || control_plane_routing
                || (preliminary_proxy
                    && domain_can_change
                    && udp_has_quic_long_header(ctx, link_h_len, pkt)));

        if stage_required && flags & DATAPATH_FLAG_NFQ_ENABLED != 0 {
            let Some(epoch) = crate::maps::begin_udp_decision() else {
                if udp_claimed {
                    crate::contrack::remove_udp_preparing(&pkt.tuples.five);
                }
                return Err(TC_ACT_SHOT);
            };
            let current_nfq_flags = crate::maps::datapath_flags();
            let verdict = if flags & DATAPATH_FLAG_NFQ_READY == 0
                || current_nfq_flags & (DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
                    != (DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
                || !udp_claimed
            {
                if udp_claimed {
                    crate::contrack::remove_udp_preparing(&pkt.tuples.five);
                }
                Err(TC_ACT_SHOT)
            } else {
                let pending_meta =
                    crate::contrack::build_routing_meta(outbound, mark, must, pkt.tuples.dscp);
                stage_udp_decision(ctx, pkt, unsafe { pending_meta.raw })
            };
            crate::maps::end_udp_decision(epoch);
            return verdict;
        }

        let meta = crate::contrack::build_routing_meta_with_offload(
            meta_outbound,
            mark,
            must,
            pkt.tuples.dscp,
            offload_direct,
        );
        if udp_claimed {
            let Some(scratch_ptr) = UDP_DECISION_SCRATCH_MAP.get_ptr_mut(0) else {
                crate::contrack::remove_udp_preparing(&pkt.tuples.five);
                return Err(TC_ACT_SHOT);
            };
            let state = unsafe { &mut (*scratch_ptr).state };
            crate::contrack::populate_udp_conn_state(
                state,
                meta,
                &pkt.ethh.src_addr,
                UdpDecisionState::None,
                0,
            );
            udp_published = crate::contrack::publish_claimed_udp_state(&pkt.tuples.five, state);
            if !udp_published {
                crate::contrack::remove_udp_preparing(&pkt.tuples.five);
            }
        } else {
            let state = crate::contrack::mark_udp_seen(
                &pkt.tuples.five,
                0u8,
                Some(&meta_outbound),
                Some(&mark),
                Some(&must),
                Some(&pkt.ethh.src_addr),
                pkt.tuples.dscp,
                None,
                0,
            );
            if let Some(state) = state {
                state.state = UdpDecisionState::None as u8;
                state.decision_token = 0;
                crate::contrack::publish_routing_meta(&mut state.meta, meta);
            } else {
                udp_published = false;
            }
        }
    }

    // Fail-closed for TCP when the conn state map is full.  Reuses the
    // offload decision computed above — no second flags read.
    if pkt.l4proto == IPPROTO_TCP && tcp_state.is_none() {
        if (outbound == OUTBOUND_DIRECT && must != 0 || offload_direct) && mark == 0 {
            ctx.skb.set_mark(mark | CLASSIFIED_MARK);
            return Err(TC_ACT_OK);
        }
        return Err(TC_ACT_SHOT);
    }

    if pkt.l4proto == IPPROTO_UDP && !short_lived_udp && !udp_published {
        return Err(TC_ACT_SHOT);
    }

    if (outbound == OUTBOUND_DIRECT && must != 0) || offload_direct {
        if PARAM.load().padding2 & 1 != 0 {
            info!(ctx, target: "honk", "direct offload path");
        }
        crate::stats::count_tx(ctx, meta_outbound);
        ctx.skb.set_mark(mark | CLASSIFIED_MARK);
        return Err(TC_ACT_OK);
    }
    if outbound == OUTBOUND_DIRECT {
        // Non-must direct the mode policy may not offload (Global mode, or
        // Rule mode with a possible SNI re-route pending): redirect to the
        // control plane so the mode override — and the SNI-sniffed
        // re-route — can re-decide the flow in userspace.
        if PARAM.load().padding2 & 1 != 0 {
            info!(ctx, target: "honk", "direct(no must, no offload) → control plane");
        }
        return redirect_lan_packet_to_control_plane(
            ctx,
            link_h_len,
            pkt,
            unsafe {
                crate::contrack::build_routing_meta(outbound, mark, must, pkt.tuples.dscp).raw
            },
            handoff_mode,
            0,
        );
    }
    if outbound == OUTBOUND_BLOCK {
        // Redirect BLOCK to control plane.
        if !wan_outbound_is_alive(ctx, outbound, pkt.l4proto, pkt.tuples.five.dst_port) {
            return Err(TC_ACT_SHOT);
        }
        return redirect_lan_packet_to_control_plane(
            ctx,
            link_h_len,
            pkt,
            unsafe { crate::contrack::build_routing_meta(outbound, mark, 0, pkt.tuples.dscp).raw },
            handoff_mode,
            0,
        );
    }

    if !wan_outbound_is_alive(ctx, outbound, pkt.l4proto, pkt.tuples.five.dst_port) {
        return Err(TC_ACT_SHOT);
    }

    redirect_lan_packet_to_control_plane(
        ctx,
        link_h_len,
        pkt,
        unsafe { crate::contrack::build_routing_meta(outbound, mark, must, pkt.tuples.dscp).raw },
        handoff_mode,
        0,
    )
}

// #[inline(never)]: shared by wan_ingress_l2/l3. Shallow call chain
// (only parse_packet + conn state update).
#[inline(never)]
fn do_tproxy_wan_ingress(ctx: &TcContext, link_h_len: u32) -> Verdict {
    let scratch_key: u32 = 0;
    let pkt = match PKT_SCRATCH_KEY.get_ptr_mut(scratch_key) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };

    let ret = parse_packet(ctx, link_h_len, pkt);
    if ret != 0 {
        if ret < 0 {
            error!(ctx, target: "honk", "parse_transport error: {}, dropping", ret);
            return Err(TC_ACT_SHOT);
        }
        return Err(TC_ACT_OK);
    }

    if pkt.l4proto == IPPROTO_TCP {
        let mut reversed_key: TuplesKey = unsafe { mem::zeroed() };
        crate::contrack::copy_reversed_tuples(&pkt.tuples.five, &mut reversed_key);
        let _ = crate::contrack::mark_tcp_seen(
            &reversed_key,
            &pkt.tcph,
            1u8,
            None,
            None,
            None,
            None,
            0,
            None,
            0,
        );
    } else if pkt.l4proto == IPPROTO_UDP {
        let src_port = u16::from_be_bytes(pkt.udph.src);
        let dst_port = u16::from_be_bytes(pkt.udph.dst);
        if src_port == 53 || dst_port == 53 {
            return Err(TC_ACT_PIPE);
        }

        let mut reversed_key: TuplesKey = unsafe { mem::zeroed() };
        crate::contrack::copy_reversed_tuples(&pkt.tuples.five, &mut reversed_key);
        let _ =
            crate::contrack::mark_udp_seen(&reversed_key, 1u8, None, None, None, None, 0, None, 0);
    }

    Ok(TC_ACT_PIPE)
}

// #[inline(never)]: standalone program, no deep call chain.
#[inline(never)]
fn do_tproxy_dae0peer_ingress(ctx: &TcContext) -> Verdict {
    // Only packets redirected from wan_egress or lan_ingress carry this cb
    // mark.  Other traffic (e.g. replies to locally-generated proxy outbound
    // connections) must be passed through so the daens IP stack can deliver it
    // to the correct local socket.
    let cb0 = unsafe { (*ctx.skb.skb).cb[0] };
    if cb0 != TPROXY_MARK {
        return Err(TC_ACT_SHOT);
    }

    // listener_l4proto is stored in cb[1] only when the control-plane handoff
    // needs an explicit listener assignment (UDP or TCP SYN, including first
    // fragments that still expose those headers).  Established TCP can return
    // to the stack without bpf_sk_assign; the kernel will find the child
    // socket via normal socket lookup.
    let listener_l4proto = (unsafe { (*ctx.skb.skb).cb[1] }) as u8;
    ctx.set_mark(TPROXY_MARK);
    // Force the packet type to HOST so the IP stack accepts it and returns
    // it to the stack, letting the netfilter PREROUTING TPROXY rule (or the
    // attached sk_lookup BPF program) deliver it to the transparent listener
    // socket.  Established TCP (cb[1] == 0) intentionally skips bpf_sk_assign:
    // assigning here would bypass PREROUTING and prevent the kernel from
    // creating proper child sockets for intercepted TCP flows.
    let _ = ctx.change_type(0);
    if listener_l4proto != 0 {
        let _ = assign_listener(ctx, listener_l4proto);
    }

    Ok(TC_ACT_OK)
}

/// SockMap keys for `LISTEN_SOCKET_MAP`, shared with `sk_lookup.rs` and the
/// userspace publish path: 0 = TCP4, 1 = TCP6, 2.. = UDP4 group,
/// 2 + UDP_LISTENER_COUNT.. = UDP6 group.
use crate::sk_lookup::{KEY_TCP4, KEY_TCP6, KEY_UDP4_BASE, KEY_UDP6_BASE, listener_hash};

/// Assign the TPROXY listener socket to the current skb so the kernel delivers
/// the packet to the transparent proxy listener instead of performing a normal
/// route lookup.
///
/// Ported from Go dae's `assign_listener` in `control/kern/tproxy.c`.  Uses
/// `bpf_sk_assign` via a SOCKMAP lookup — the same proven pattern employed by
/// the `tproxy_sk_lookup` program in `sk_lookup.rs`, shared via
/// [`sk::sk_assign_by_index`].  UDP flows are hashed across the parallel
/// listener group so each userspace receive loop drains a subset of flows.
#[inline(always)]
fn assign_listener(ctx: &TcContext, listener_l4proto: u8) -> Result<(), c_long> {
    // SockMap keys differentiate IPv4 vs IPv6 to match the per-family
    // listeners published by userspace.
    let is_v6 = unsafe { (*ctx.skb.skb).protocol as u16 } == ETH_P_IPV6.to_be();
    let key = if listener_l4proto == IPPROTO_TCP {
        if is_v6 { KEY_TCP6 } else { KEY_TCP4 }
    } else {
        let h = udp_listener_hash(ctx, is_v6);
        if is_v6 {
            KEY_UDP6_BASE + h
        } else {
            KEY_UDP4_BASE + h
        }
    };

    let map_ptr = ptr::from_ref(&LISTEN_SOCKET_MAP).cast::<c_void>();
    sk::sk_assign_by_index(ctx, map_ptr, &key, 0)
}

/// Flow-consistent listener index for a UDP packet: the same 4-tuple always
/// lands on the same socket while different flows spread over the group.
/// Header-missing packets (short reads) hash with zeroed ports, which is
/// still deterministic per flow.
#[inline(always)]
fn udp_listener_hash(ctx: &TcContext, is_v6: bool) -> u32 {
    // Guarantee the headers are in the linear data area; bounds checks
    // below still guard the actual reads.
    let _ = ctx.pull_data(ETH_HLEN + 40 + 8);
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    if unsafe { data.add(mem::size_of::<EthHdr>()) } > data_end {
        return 0;
    }
    let (src, dst, l4off) = if is_v6 {
        if unsafe { data.add(ETH_HLEN as usize + mem::size_of::<Ipv6Hdr>()) } > data_end {
            return 0;
        }
        let v6h = unsafe { &*(data.add(ETH_HLEN as usize) as *const Ipv6Hdr) };
        let src = u32::from_be_bytes(v6h.src_addr[12..16].try_into().unwrap_or([0; 4]));
        let dst = u32::from_be_bytes(v6h.dst_addr[12..16].try_into().unwrap_or([0; 4]));
        (src, dst, ETH_HLEN as usize + mem::size_of::<Ipv6Hdr>())
    } else {
        if unsafe { data.add(ETH_HLEN as usize + mem::size_of::<Ipv4Hdr>()) } > data_end {
            return 0;
        }
        let v4h = unsafe { &*(data.add(ETH_HLEN as usize) as *const Ipv4Hdr) };
        let ihl = (v4h.vihl & 0x0f) as usize * 4;
        if ihl < 20 {
            return 0;
        }
        (
            u32::from_be_bytes(v4h.src_addr),
            u32::from_be_bytes(v4h.dst_addr),
            ETH_HLEN as usize + ihl,
        )
    };
    let (sport, dport) = if unsafe { data.add(l4off + 4) } > data_end {
        (0u16, 0u16)
    } else {
        let udph = unsafe { &*(data.add(l4off) as *const UdpHdr) };
        (u16::from_be_bytes(udph.src), u16::from_be_bytes(udph.dst))
    };
    listener_hash(src, dst, ((sport as u32) << 16) | dport as u32, 0)
}

// #[inline(never)]: standalone program, no deep call chain.
#[inline(never)]
fn do_tproxy_dae0_ingress(ctx: &TcContext) -> Verdict {
    // Parse the complete reply tuple, then reverse it into the original
    // redirect direction.  Address-only keys alias concurrent TCP/UDP flows
    // sharing an IP pair; the map key must retain ports and protocol.
    let pkt = match PKT_SCRATCH_KEY.get_ptr_mut(0) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };
    if parse_packet(ctx, ETH_HLEN, pkt) != 0 {
        return Err(TC_ACT_OK);
    }
    let redirect_tuple = RedirectTuple::from_tuples(&pkt.tuples.five).reverse();

    let entry_ptr = REDIRECT_TRACK.get_ptr_mut(redirect_tuple);
    if entry_ptr.is_none() {
        return Err(TC_ACT_OK);
    }
    let entry = unsafe { &mut *entry_ptr.unwrap() };

    let now = unsafe { bpf_ktime_get_ns() };
    if now.wrapping_sub(entry.last_seen_ns) >= crate::contrack::AUXILIARY_MAP_REFRESH_INTERVAL_NS {
        entry.last_seen_ns = now;
    }

    // Account this reply (outbound → LAN) against the outbound recorded
    // when the flow was redirected to the control plane.  The full packet
    // tuple was reversed above, so a successful lookup is a proxy reply.
    // Restore the original LAN framing and redirect to its interface.
    //
    // Host-originated flows (from_wan != 0, e.g. gateway's own traffic out a
    // PPPoE WAN) have no LAN framing to restore: inject the reply into the
    // WAN interface's RX path (BPF_F_INGRESS) as PACKET_HOST so the local
    // stack accepts it, mirroring Go dae's tproxy_dae0_ingress.
    let dmac = entry.smac;
    let smac = entry.dmac;
    let from_wan = entry.from_wan;
    unsafe {
        bpf_skb_store_bytes(
            ctx.skb.skb,
            mem::offset_of!(EthHdr, src_addr) as u32,
            smac.as_ptr() as *const _,
            6,
            0,
        );
        bpf_skb_store_bytes(
            ctx.skb.skb,
            mem::offset_of!(EthHdr, dst_addr) as u32,
            dmac.as_ptr() as *const _,
            6,
            0,
        );
    }

    let pkt_type: u32 = if from_wan != 0 { 0 } else { 1 }; // PACKET_HOST : PACKET_OTHERHOST
    let flags: u64 = if from_wan != 0 { 1 } else { 0 }; // BPF_F_INGRESS
    let _ = ctx.skb.change_type(pkt_type);
    Ok(unsafe { bpf_redirect(entry.ifindex, flags) } as c_long)
}

// TC entry points use raw __sk_buff pointer to avoid verifier
// "Arg#0 type STRUCT not supported" error on kernel >= 7.0.

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_lan_ingress(&TcContext::new(ctx), 14))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_lan_ingress(&TcContext::new(ctx), 0))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_wan_ingress(&TcContext::new(ctx), 14))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_wan_ingress(&TcContext::new(ctx), 0))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn dae0peer_ingress(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_dae0peer_ingress(&TcContext::new(ctx)))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn dae0_ingress(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_dae0_ingress(&TcContext::new(ctx)))
}
