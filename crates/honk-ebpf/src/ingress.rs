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
    action::{TC_ACT_OK, TC_ACT_SHOT, TC_ACT_UNSPEC, Verdict, flatten},
    egress::wan_outbound_is_alive,
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
    L4ProtoType, NFQUEUE_PENDING_MARK, NFQUEUE_SIGNATURE_MARK, RedirectEntry, RedirectTuple,
    RoutingMeta, TPROXY_MARK, UdpDnsRoute,
    conn::{BpfStatsKey, ConnState, UdpDecisionState},
    dae_ip::In6Addr,
    pack_nfqueue_mark,
    redirect_need::TuplesKey,
};
use network_types::eth::EthHdr;

use crate::{
    auxiliary::{AuxPrep, redirect_needs_publish},
    maps::{
        CLIENT_REPLY_TRACK, PARAM, PKT_SCRATCH_KEY, ROUTING_HANDOFF_MAP, UDP_DECISION_SCRATCH_MAP,
        increment_bpf_stat,
    },
    route::{OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT},
    sk,
    transport::{
        ETH_HLEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_TCP, IPPROTO_UDP, PARSE_FRAGMENT, PASS_UNSUPPORTED,
        is_vlan_tagged, parse_packet, udp_has_quic_long_header,
    },
};
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

#[inline(always)]
fn redirect_lan_packet_to_control_plane(
    ctx: &TcContext,
    _link_h_len: u32,
    pkt: &ParsedPacket,
    routing_meta_raw: u64,
    policy: AuxPrep,
    decision_token: u32,
    routing_generation: u64,
    trace_id: u32,
    incarnation: u64,
) -> Verdict {
    if pkt.l4proto == IPPROTO_TCP && PARAM.load().tcp_daens_netns_id < 0 {
        return Err(TC_ACT_SHOT);
    }
    let routing_meta = RoutingMeta {
        raw: routing_meta_raw,
    };
    let dns_route_mark = if pkt.l4proto == IPPROTO_UDP && pkt.tuples.five.dst_port == 53 {
        let Some(route) =
            UdpDnsRoute::new(unsafe { routing_meta.data.outbound }, routing_generation)
        else {
            return Err(TC_ACT_SHOT);
        };
        if pkt.is_fragmented != 0 {
            route.to_nfqueue_mark()
        } else {
            route.to_mark()
        }
    } else {
        0
    };
    let dns_fragment = dns_route_mark & NFQUEUE_SIGNATURE_MARK != 0;
    let now = unsafe { bpf_ktime_get_ns() };

    // Account this LAN → outbound packet against the final outbound
    // (redirect path; the direct+must pass-through exits count separately).
    crate::stats::count_tx(ctx, unsafe { routing_meta.data.outbound });

    if !dns_fragment {
        // The link crossing may scrub skb->mark; dae0peer restores routing
        // authority from cb[2] after validating the carrier.
        ctx.skb
            .set_mark(TPROXY_MARK | (pkt.listener_l4proto as u32));
        unsafe {
            (*ctx.skb.skb).cb[0] = TPROXY_MARK;
            (*ctx.skb.skb).cb[1] = pkt.listener_l4proto as u32;
            (*ctx.skb.skb).cb[2] = dns_route_mark;
            let syn =
                pkt.l4proto == IPPROTO_TCP && crate::contrack::is_new_tcp_connection(&pkt.tcph);
            // Values first, then stores at fixed offsets: branch-local stores
            // get merged into one store through a modified ctx pointer.
            let (cb3, cb4) = if syn {
                (incarnation as u32, (incarnation >> 32) as u32)
            } else if pkt.l4proto == IPPROTO_UDP {
                (trace_id, udp_listener_marker(&pkt.tuples.five))
            } else {
                (0, 0)
            };
            (*ctx.skb.skb).cb[3] = cb3;
            (*ctx.skb.skb).cb[4] = cb4;
        }
    }

    // Raw must UDP53 is admitted from the per-packet carrier, so only flows
    // that userspace may look up publish a tuple handoff.
    let raw_must_dns = dns_route_mark != 0 && unsafe { routing_meta.data.must != 0 };
    let write_handoff = !raw_must_dns
        && policy
            .handoff_needs_publish(&pkt.tuples.five, decision_token, incarnation, now)
            .map_err(|_| TC_ACT_SHOT)?;
    if write_handoff {
        let scratch = UDP_DECISION_SCRATCH_MAP.get_ptr_mut(0).ok_or(TC_ACT_SHOT)?;
        let scratch = unsafe { &mut *scratch };
        let handoff = &mut scratch.handoff;
        unsafe { ptr::write_bytes(handoff, 0, 1) };
        handoff.last_seen_ns = now;
        handoff.routing_generation = if routing_generation != 0 {
            routing_generation
        } else {
            crate::route::captured_generation(trace_id)
        };
        handoff.trace_id = trace_id;
        handoff.incarnation = incarnation;
        unsafe {
            handoff.result.mark = routing_meta.data.mark;
            handoff.result.must = routing_meta.data.must;
            handoff.result.outbound = routing_meta.data.outbound;
            handoff.result.dscp = routing_meta.data.dscp;
        }
        handoff.result.decision_token = decision_token;
        handoff.result.mac.copy_from_slice(&pkt.ethh.src_addr);
        crate::auxiliary::publish_handoff(&pkt.tuples.five, scratch, policy == AuxPrep::Publish)
            .map_err(|_| TC_ACT_SHOT)?;
    }

    // Keep reverse-path framing stable and refresh cached ownership lazily.
    let redirect_tuple = RedirectTuple::from_tuples(&pkt.tuples.five);
    let write_track = redirect_needs_publish(
        &pkt.tuples.five,
        &redirect_tuple,
        policy,
        decision_token,
        incarnation,
        now,
    )
    .map_err(|_| TC_ACT_SHOT)?;
    if write_track {
        // Built in per-CPU scratch, not on the stack: the LAN classifier is at
        // the verifier's combined stack limit.
        let Some(scratch) = UDP_DECISION_SCRATCH_MAP.get_ptr_mut(0) else {
            increment_bpf_stat(BpfStatsKey::RedirectTrackInsertFailure);
            return Err(TC_ACT_SHOT);
        };
        let scratch = unsafe { &mut *scratch };
        scratch.redirect_key = redirect_tuple;
        unsafe { ptr::write_bytes(&mut scratch.redirect, 0, 1) };
        scratch.redirect.ifindex = unsafe { (*ctx.skb.skb).ifindex };
        scratch.redirect.smac.copy_from_slice(&pkt.ethh.src_addr);
        scratch.redirect.dmac.copy_from_slice(&pkt.ethh.dst_addr);
        scratch.redirect.last_seen_ns = now;
        // Record the final outbound so dae0_ingress can attribute replies.
        scratch.redirect.outbound = unsafe { routing_meta.data.outbound };
        scratch.redirect.decision_token = decision_token;
        scratch.redirect.incarnation = incarnation;
        crate::auxiliary::publish_redirect(&pkt.tuples.five, scratch, policy == AuxPrep::Publish)
            .map_err(|_| TC_ACT_SHOT)?;
    }
    if policy == AuxPrep::Publish
        && !crate::contrack::tcp::commit_tcp_intercept(
            &pkt.tuples.five,
            u32::from_be_bytes(pkt.tcph.seq),
            incarnation,
        )
    {
        return Err(TC_ACT_SHOT);
    }

    if dns_fragment {
        // Keep all pieces in the host for native reassembly. TC cb is not
        // netfilter metadata; the offset-zero skb mark carries DNS authority.
        ctx.skb.set_mark(dns_route_mark);
        unsafe { (*ctx.skb.skb).priority = trace_id };
        return Err(TC_ACT_OK);
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

/// The client record for a UDP reply with no exact flow record. Replies from
/// honk's own link addresses come from the TPROXY listener and are never
/// forwarded to a client.
#[inline(always)]
fn client_reply_entry(pkt: &ParsedPacket, mut key: RedirectTuple) -> Option<RedirectEntry> {
    if pkt.l4proto != IPPROTO_UDP || pkt.tuples.five.src_ip.is_dae0_link() {
        return None;
    }
    key.dst_ip = In6Addr::zero();
    key.dst_port = 0;
    CLIENT_REPLY_TRACK
        .get_ptr(key)
        .map(|entry| unsafe { *entry })
}

/// Publish all token-bound auxiliary state before exposing Pending to followers.
#[inline(never)]
fn stage_udp_decision(
    ctx: &TcContext,
    pkt: &mut ParsedPacket,
    routing_meta_raw: u64,
    routing_generation: u64,
) -> Verdict {
    let routing_meta = RoutingMeta {
        raw: routing_meta_raw,
    };
    let outbound = unsafe { routing_meta.data.outbound };
    let mark = unsafe { routing_meta.data.mark };
    let must = unsafe { routing_meta.data.must };
    let Some(scratch_ptr) = UDP_DECISION_SCRATCH_MAP.get_ptr_mut(0) else {
        crate::contrack::udp::abort_udp_preparing(&pkt.tuples.five, pkt.incarnation, 0);
        return Err(TC_ACT_SHOT);
    };
    unsafe {
        ptr::write_bytes(scratch_ptr, 0, 1);
    }
    let scratch = unsafe { &mut *scratch_ptr };
    let Some(decision_token) = crate::contrack::udp::allocate_udp_decision_token(&pkt.tuples.five)
    else {
        crate::contrack::udp::abort_udp_preparing(&pkt.tuples.five, pkt.incarnation, 0);
        return Err(TC_ACT_SHOT);
    };
    pkt.trace_id = crate::route::capture(
        &mut pkt.route_witness,
        &pkt.tuples.five,
        decision_token,
        false,
    );
    let now = unsafe { bpf_ktime_get_ns() };
    scratch.redirect_key = RedirectTuple::from_tuples(&pkt.tuples.five);

    scratch.redirect.ifindex = unsafe { (*ctx.skb.skb).ifindex };
    scratch.redirect.smac.copy_from_slice(&pkt.ethh.src_addr);
    scratch.redirect.dmac.copy_from_slice(&pkt.ethh.dst_addr);
    scratch.redirect.last_seen_ns = now;
    scratch.redirect.outbound = OUTBOUND_CONTROL_PLANE_ROUTING;
    scratch.redirect.decision_token = decision_token;
    scratch.redirect.incarnation = pkt.incarnation;
    if crate::auxiliary::publish_redirect(&pkt.tuples.five, scratch, false).is_err() {
        crate::contrack::udp::abort_udp_preparing(
            &pkt.tuples.five,
            pkt.incarnation,
            decision_token,
        );
        return Err(TC_ACT_SHOT);
    }

    scratch.handoff.last_seen_ns = now;
    scratch.handoff.routing_generation = routing_generation;
    scratch.handoff.trace_id = pkt.trace_id;
    scratch.handoff.incarnation = pkt.incarnation;
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
    if crate::auxiliary::publish_handoff(&pkt.tuples.five, scratch, false).is_err() {
        crate::contrack::udp::abort_udp_preparing(
            &pkt.tuples.five,
            pkt.incarnation,
            decision_token,
        );
        return Err(TC_ACT_SHOT);
    }

    crate::contrack::udp::populate_udp_conn_state(
        &mut scratch.state,
        routing_meta,
        &pkt.ethh.src_addr,
        UdpDecisionState::Pending,
        decision_token,
        pkt.incarnation,
    );
    scratch.state.trace_id = pkt.trace_id;
    if !crate::contrack::udp::publish_claimed_udp_state(&pkt.tuples.five, &scratch.state) {
        crate::contrack::udp::abort_udp_preparing(
            &pkt.tuples.five,
            pkt.incarnation,
            decision_token,
        );
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
    state: &ConnState,
) -> Verdict {
    if state.is_wan_ingress_direction != 0 {
        return pass_through_classified(ctx);
    }

    if state.state == UdpDecisionState::Preparing as u8
        || state.state == UdpDecisionState::Aborted as u8
    {
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
            AuxPrep::RedirectOnly,
            state.decision_token,
            0,
            state.trace_id,
            state.incarnation,
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

    // Direct/block cached UDP flows still require the outbound health gate;
    // unlike cached TCP, neither has a control-plane exemption here.
    if !wan_outbound_is_alive(ctx, outbound, pkt.l4proto, pkt.tuples.five.dst_port) {
        return Err(TC_ACT_SHOT);
    }
    redirect_lan_packet_to_control_plane(
        ctx,
        link_h_len,
        pkt,
        meta_raw,
        AuxPrep::Refresh,
        state.decision_token,
        0,
        state.trace_id,
        state.incarnation,
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

// #[inline(never)]: shared by lan_ingress_l2/l3. 5-level call chain
// with 256B baseline stays under the 512B BPF stack limit.
#[inline(never)]
fn do_tproxy_lan_ingress(ctx: &TcContext, link_h_len: u32) -> Verdict {
    let scratch_key: u32 = 0;
    let pkt = match PKT_SCRATCH_KEY.get_ptr_mut(scratch_key) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };
    // Fragment verdict retirement must not observe a previous packet on early exits.
    pkt.is_fragmented = 0;

    if !crate::maps::datapath_ready() {
        return Err(TC_ACT_UNSPEC);
    }
    if is_vlan_tagged(ctx, link_h_len) {
        return Err(TC_ACT_UNSPEC);
    }
    // Bridge master/slave double attachment must not reclassify either an
    // already-final packet or a held packet carrying its unique queue token.
    if unsafe { (*ctx.skb.skb).mark } & (CLASSIFIED_MARK | NFQUEUE_PENDING_MARK) != 0 {
        return Err(TC_ACT_OK);
    }

    let ret = parse_packet(ctx, link_h_len, pkt);
    if ret != 0 {
        if ret == PARSE_FRAGMENT as c_long && crate::fragment::condemned(pkt) {
            return Err(TC_ACT_SHOT);
        }
        // Non-IP and unsupported-L4 frames carry no classification: leave them
        // unmarked so an upper device (macsec, vlan) still classifies its own
        // frame. `pkt.ethh` is not written on failure; do not read it here.
        if ret == PASS_UNSUPPORTED {
            return Err(TC_ACT_UNSPEC);
        }
        return pass_through_classified(ctx);
    }

    // Broadcast/multicast destinations (DHCP, mDNS, SSDP, LLMNR) must never
    // be routed, marked, or conntracked — pass through immediately.
    if crate::transport::dst_is_special(pkt, link_h_len) {
        return pass_through_classified(ctx);
    }

    if pkt.l4proto == IPPROTO_TCP || pkt.l4proto == IPPROTO_UDP {
        // An originated socket must also survive an explicitly LAN-bound lo.
        let bypass_mark = PARAM.load().dae_socket_mark;
        if bypass_mark != 0 && unsafe { (*ctx.skb.skb).mark } == bypass_mark {
            return pass_through_classified(ctx);
        }
    }
    // Ordinary UDP combines availability with its cached lookup below.
    if pkt.l4proto != IPPROTO_TCP
        && (pkt.l4proto != IPPROTO_UDP
            || crate::contrack::is_short_lived_udp_traffic(&pkt.tuples.five))
        && crate::contrack::tuple_unavailable(&pkt.tuples.five)
    {
        return Err(TC_ACT_SHOT);
    }
    let mut tcp_publisher = crate::contrack::tcp::TcpPublisher::new(&pkt.tuples.five);
    if pkt.l4proto == IPPROTO_TCP && crate::contrack::is_new_tcp_connection(&pkt.tcph) {
        // Before any conn/aux element exists, so a rejected flood leaves no state behind.
        if crate::new_flow_limit::exceeded(&pkt.tuples.five.src_ip) {
            return Err(TC_ACT_SHOT);
        }
        if !tcp_publisher.acquire(ctx, &pkt.tcph) {
            return Err(TC_ACT_SHOT);
        }
        pkt.incarnation = tcp_publisher.incarnation;
    }

    if pkt.l4proto == IPPROTO_TCP && !tcp_publisher.is_fresh() {
        let tcp_state = crate::contrack::tcp::mark_tcp_seen(
            &pkt.tuples.five,
            &pkt.tcph,
            None,
            None,
            None,
            None,
            0,
            None,
            0,
            0,
            &tcp_publisher,
        );
        let tcp_state = match tcp_state {
            Some(state) => state,
            None => {
                if crate::contrack::is_new_tcp_connection(&pkt.tcph)
                    || crate::contrack::tuple_unavailable(&pkt.tuples.five)
                {
                    return Err(TC_ACT_SHOT);
                }
                return pass_through_classified(ctx);
            }
        };
        if (unsafe { tcp_state.meta.raw } >> 56) & 1 == 0 {
            return pass_through_classified(ctx);
        }

        let outbound = unsafe { tcp_state.meta.data.outbound };
        let mark = unsafe { tcp_state.meta.data.mark };

        let must = unsafe { tcp_state.meta.data.must };
        if pkt.tuples.five.dst_port == 53 && outbound == OUTBOUND_BLOCK {
            return Err(TC_ACT_SHOT);
        }
        let offload =
            unsafe { tcp_state.meta.raw } & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD != 0;

        // DNS never carries the mode-offload bit; only a terminal must-direct
        // result can pass natively on this path.
        if outbound == OUTBOUND_DIRECT && (must != 0 || offload) {
            crate::stats::count_tx(ctx, outbound);
            ctx.skb.set_mark(mark | CLASSIFIED_MARK);
            return Err(TC_ACT_OK);
        }
        return redirect_lan_packet_to_control_plane(
            ctx,
            link_h_len,
            pkt,
            unsafe { tcp_state.meta.raw },
            AuxPrep::tcp(&tcp_publisher),
            0,
            0,
            tcp_state.trace_id,
            tcp_state.incarnation,
        );
    }

    // Per-flow log, gated by PARAM.padding2 bit 0 (userspace writes 0 → off).
    if PARAM.load().padding2 & 1 != 0 {
        info!(ctx, target: "honk", "lan new flow: l4proto={} sport={} dport={}", pkt.l4proto, pkt.tuples.five.src_port, pkt.tuples.five.dst_port);
    }
    let mut tcp_state: Option<&mut ConnState> = None;

    if pkt.l4proto == IPPROTO_TCP {
        tcp_state = crate::contrack::tcp::mark_tcp_seen(
            &pkt.tuples.five,
            &pkt.tcph,
            None,
            None,
            None,
            None,
            pkt.tuples.dscp,
            None,
            0,
            0,
            &tcp_publisher,
        );
        if tcp_state.is_none() && crate::maps::tuple_retiring(&pkt.tuples.five) {
            return Err(TC_ACT_SHOT);
        }
    } else if !crate::contrack::is_short_lived_udp_traffic(&pkt.tuples.five) {
        // Refusal is not a miss: expired/Preparing tuples never reach probing
        // or new-flow publication.
        if let Some(state) =
            crate::contrack::udp::lookup_udp_available(&pkt.tuples.five).map_err(|_| TC_ACT_SHOT)?
        {
            return cached_udp_decision(ctx, link_h_len, pkt, state);
        }
    }

    // Only a fresh TCP publication captures the immutable accept-time handoff.
    // UDP tuple handoffs are refreshed only when userspace may need them;
    // raw must UDP53 is authoritative from its per-packet carrier.
    let aux_policy = if pkt.l4proto == IPPROTO_TCP {
        AuxPrep::Publish
    } else {
        AuxPrep::Refresh
    };

    let protocol = unsafe { (*ctx.skb.skb).protocol as u16 };
    let ip_version = if protocol == ETH_P_IP.to_be() {
        IpVersionType::V4 as u8
    } else {
        IpVersionType::V6 as u8
    };

    // A local DNS listener must not short-circuit the configured traffic policy.
    if pkt.l4proto == IPPROTO_UDP && pkt.tuples.five.dst_port != 53 {
        if crate::contrack::udp::local_udp_reply_seen(&pkt.tuples.five) {
            return pass_through_classified(ctx);
        }
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

        let param = PARAM.load();
        if let Some(probe) =
            sk::probe_udp_socket(ctx, &mut tuple, tuple_size, param.dae_netns_id as u64)
            && !probe.is_dae_socket
            && (!probe.is_wildcard || wildcard_socket_destination_is_local(ctx, pkt))
        {
            // No routing witness is consumed after this local-service exit.
            // Its tuple keeps nested expiry hints off the bounded TC stack.
            crate::contrack::udp::observe_local_udp_reply(
                &pkt.tuples.five,
                &mut pkt.route_witness.tuple,
            );
            return pass_through_classified(ctx);
        }
    }

    // Counts the first packet of every UDP flow and each stateless UDP/53 packet.
    if pkt.l4proto == IPPROTO_UDP && crate::new_flow_limit::exceeded(&pkt.tuples.five.src_ip) {
        return Err(TC_ACT_SHOT);
    }

    let flags = crate::maps::datapath_flags();
    let short_lived_udp =
        pkt.l4proto == IPPROTO_UDP && crate::contrack::is_short_lived_udp_traffic(&pkt.tuples.five);
    if pkt.l4proto == IPPROTO_UDP && !short_lived_udp {
        if let Some(incarnation) =
            crate::contrack::udp::claim_udp_preparing(&pkt.tuples.five, &pkt.ethh.src_addr)
        {
            pkt.incarnation = incarnation;
        } else if let Some(state) = crate::contrack::udp::lookup_udp_seen(&pkt.tuples.five) {
            return cached_udp_decision(ctx, link_h_len, pkt, state);
        } else {
            return Err(TC_ACT_SHOT);
        }
    }

    let route_l4proto = if pkt.l4proto == IPPROTO_TCP {
        L4ProtoType::Tcp as u8
    } else {
        L4ProtoType::Udp as u8
    };
    let route_mac = if link_h_len == ETH_HLEN {
        Some(&pkt.ethh.src_addr)
    } else {
        None
    };
    crate::route::build_input(
        &mut pkt.routing_input,
        &pkt.tuples,
        route_mac,
        route_l4proto,
        ip_version,
        false,
    );
    let (mut decision, routing_generation) = match crate::route::route(
        &mut pkt.routing_input,
        None,
        flags,
        &mut pkt.route_witness.output,
    ) {
        Ok(result) => result,
        Err(_error) => {
            error!(ctx, target: "honk", "lan_ingress route fail: {}", _error);
            if pkt.l4proto == IPPROTO_UDP && !short_lived_udp {
                crate::contrack::udp::abort_udp_preparing(&pkt.tuples.five, pkt.incarnation, 0);
            }
            return Err(TC_ACT_SHOT);
        }
    };
    decision.apply_mode_flags(flags, pkt.tuples.five.dst_port);

    let outbound = decision.outbound as u8;
    let mark = decision.mark;
    let must = decision.must as u8;
    let domain_final = decision.domain_final != 0;

    // Cache mode-owned offload once per new flow. The generated decision's
    // finality is from the same policy generation as its outbound, so direct
    // safety no longer depends on a separately published global flag.
    let offload_direct = pkt.tuples.five.dst_port != 53
        && must == 0
        && outbound != OUTBOUND_BLOCK
        && ((flags & honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_ALL != 0)
            || (flags & honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_RULE_DIRECT != 0
                && outbound == OUTBOUND_DIRECT
                && domain_final));
    let meta_outbound = if offload_direct {
        OUTBOUND_DIRECT
    } else {
        decision.handoff_outbound()
    };

    pkt.trace_id = 0;
    if (short_lived_udp || pkt.l4proto == IPPROTO_TCP)
        && !offload_direct
        && !(outbound == OUTBOUND_DIRECT && must != 0)
    {
        let ambiguous = pkt.route_witness.output.flags & honk_ebpf_common::ROUTE_TRACE_ENABLED != 0
            && pkt.l4proto == IPPROTO_TCP
            && (tcp_state
                .as_ref()
                .is_some_and(|state| state.trace_id == honk_ebpf_common::ROUTE_TRACE_LOST)
                || ROUTING_HANDOFF_MAP.get_ptr(&pkt.tuples.five).is_some());
        pkt.trace_id =
            crate::route::capture(&mut pkt.route_witness, &pkt.tuples.five, 0, ambiguous);
    }
    if short_lived_udp {
        // DNS deliberately has no UDP conn-state entry.
    } else if pkt.l4proto == IPPROTO_TCP {
        if let Some(state) = &mut tcp_state {
            state.mac.copy_from_slice(&pkt.ethh.src_addr);
            state.trace_id = pkt.trace_id;
            let meta = crate::contrack::build_routing_meta_with_offload(
                meta_outbound,
                mark,
                must,
                pkt.tuples.dscp,
                offload_direct,
            );
            state.meta = meta;
            if !crate::contrack::tcp::publish_tcp_routing(&pkt.tuples.five, state) {
                return Err(TC_ACT_SHOT);
            }
        }
    } else if pkt.l4proto == IPPROTO_UDP {
        let unresolved_direct = outbound == OUTBOUND_DIRECT && !offload_direct;
        let control_plane_routing = outbound == OUTBOUND_CONTROL_PLANE_ROUTING;
        let preliminary_proxy = outbound != OUTBOUND_DIRECT
            && outbound != OUTBOUND_BLOCK
            && outbound != OUTBOUND_CONTROL_PLANE_ROUTING;
        let domain_can_change = !domain_final;
        let stage_required = must == 0
            && !offload_direct
            && outbound != OUTBOUND_BLOCK
            && (unresolved_direct
                || control_plane_routing
                || (preliminary_proxy
                    && domain_can_change
                    && udp_has_quic_long_header(ctx, link_h_len, pkt)));

        if stage_required && flags & DATAPATH_FLAG_NFQ_ENABLED != 0 {
            let current_nfq_flags = crate::maps::datapath_flags();
            let verdict = if flags & DATAPATH_FLAG_NFQ_READY == 0
                || current_nfq_flags & (DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
                    != (DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
            {
                crate::contrack::udp::abort_udp_preparing(&pkt.tuples.five, pkt.incarnation, 0);
                Err(TC_ACT_SHOT)
            } else {
                let pending_meta =
                    crate::contrack::build_routing_meta(meta_outbound, mark, must, pkt.tuples.dscp);
                stage_udp_decision(ctx, pkt, unsafe { pending_meta.raw }, routing_generation)
            };
            return verdict;
        }

        if !offload_direct && !(outbound == OUTBOUND_DIRECT && must != 0) {
            pkt.trace_id =
                crate::route::capture(&mut pkt.route_witness, &pkt.tuples.five, 0, false);
        }
        let meta = crate::contrack::build_routing_meta_with_offload(
            meta_outbound,
            mark,
            must,
            pkt.tuples.dscp,
            offload_direct,
        );
        let Some(scratch_ptr) = UDP_DECISION_SCRATCH_MAP.get_ptr_mut(0) else {
            crate::contrack::udp::abort_udp_preparing(&pkt.tuples.five, pkt.incarnation, 0);
            return Err(TC_ACT_SHOT);
        };
        let state = unsafe { &mut (*scratch_ptr).state };
        crate::contrack::udp::populate_udp_conn_state(
            state,
            meta,
            &pkt.ethh.src_addr,
            UdpDecisionState::None,
            0,
            pkt.incarnation,
        );
        state.trace_id = pkt.trace_id;
        if !crate::contrack::udp::publish_claimed_udp_state(&pkt.tuples.five, state) {
            crate::contrack::udp::abort_udp_preparing(&pkt.tuples.five, pkt.incarnation, 0);
            return Err(TC_ACT_SHOT);
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

    if pkt.tuples.five.dst_port == 53 && outbound == OUTBOUND_BLOCK {
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
    }
    // Direct bypasses the health gate; block and proxy outbounds do not.
    if outbound != OUTBOUND_DIRECT
        && !wan_outbound_is_alive(ctx, outbound, pkt.l4proto, pkt.tuples.five.dst_port)
    {
        return Err(TC_ACT_SHOT);
    }
    let redirect_must = if outbound == OUTBOUND_BLOCK { 0 } else { must };
    if pkt.l4proto == IPPROTO_UDP && pkt.tuples.five.dst_port == 53 && pkt.is_fragmented != 0 {
        // Non-host Ethernet traffic may be bridged without inet prerouting, even before
        // an interface watcher has installed the destination port's egress fence.
        if link_h_len != 0 && unsafe { (*ctx.skb.skb).pkt_type } != 0 {
            return Err(TC_ACT_SHOT);
        }
        // Re-read readiness before publication; the kernel grace barrier drains this invocation.
        let current_nfq_flags = crate::maps::datapath_flags();
        if current_nfq_flags & (DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
            != (DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
        {
            return Err(TC_ACT_SHOT);
        }
    }
    let verdict = redirect_lan_packet_to_control_plane(
        ctx,
        link_h_len,
        pkt,
        unsafe {
            crate::contrack::build_routing_meta(meta_outbound, mark, redirect_must, pkt.tuples.dscp)
                .raw
        },
        aux_policy,
        0,
        routing_generation,
        pkt.trace_id,
        pkt.incarnation,
    );
    verdict
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
        return Err(TC_ACT_UNSPEC);
    }

    if pkt.l4proto == IPPROTO_TCP {
        let mut reversed_key: TuplesKey = unsafe { mem::zeroed() };
        crate::contrack::copy_reversed_tuples(&pkt.tuples.five, &mut reversed_key);
        let tcp_publisher = crate::contrack::tcp::TcpPublisher::new(&reversed_key);
        let seen = crate::contrack::tcp::mark_tcp_seen(
            &reversed_key,
            &pkt.tcph,
            None,
            None,
            None,
            None,
            0,
            None,
            0,
            0,
            &tcp_publisher,
        );
        if seen.is_none() && crate::contrack::tuple_unavailable(&reversed_key) {
            return Err(TC_ACT_SHOT);
        }
    } else if pkt.l4proto == IPPROTO_UDP {
        let src_port = u16::from_be_bytes(pkt.udph.src);
        let dst_port = u16::from_be_bytes(pkt.udph.dst);
        if src_port == 53 || dst_port == 53 {
            return Err(TC_ACT_UNSPEC);
        }

        let mut reversed_key: TuplesKey = unsafe { mem::zeroed() };
        crate::contrack::copy_reversed_tuples(&pkt.tuples.five, &mut reversed_key);
        if !crate::contrack::udp::reverse_udp_available(&reversed_key, true) {
            return Err(TC_ACT_SHOT);
        }
    }

    Ok(TC_ACT_UNSPEC)
}

// #[inline(never)]: standalone program, no deep call chain.
#[inline(never)]
fn do_tproxy_dae0peer_ingress(ctx: &TcContext) -> Verdict {
    // This private link accepts only same-skb handoffs from the LAN/WAN classifiers.
    let cb0 = unsafe { (*ctx.skb.skb).cb[0] };
    if cb0 != TPROXY_MARK {
        return Err(TC_ACT_SHOT);
    }

    // TCP must resolve established/TIME_WAIT owners before sk_lookup selects a listener.
    let listener_l4proto = (unsafe { (*ctx.skb.skb).cb[1] }) as u8;
    if listener_l4proto != 0 && listener_l4proto != IPPROTO_UDP {
        return Err(TC_ACT_SHOT);
    }
    let route_mark = unsafe { (*ctx.skb.skb).cb[2] };
    let mark = if route_mark == 0 {
        TPROXY_MARK
    } else {
        // Ingress already parsed the packet; peer redirects may retain L3-only framing.
        if listener_l4proto != IPPROTO_UDP || UdpDnsRoute::from_mark(route_mark).is_none() {
            return Err(TC_ACT_SHOT);
        }
        route_mark
    };
    if listener_l4proto == IPPROTO_UDP {
        ctx.set_mark(mark);
        unsafe { (*ctx.skb.skb).priority = (*ctx.skb.skb).cb[3] };
    } else {
        // Restore only after the namespace crossing has scrubbed link metadata.
        let low = unsafe { (*ctx.skb.skb).cb[3] };
        let high = unsafe { (*ctx.skb.skb).cb[4] };
        if high & 0xff000000 != 0 {
            return Err(TC_ACT_SHOT);
        }
        ctx.set_mark(TPROXY_MARK | (low & 0x00ffffff));
        unsafe { (*ctx.skb.skb).priority = (low >> 24) | (high << 8) };
    }
    // Redirected frames may still carry the original destination MAC.
    let _ = ctx.change_type(0);
    if listener_l4proto == IPPROTO_UDP {
        // Without the redirect site's marker the packet reaches sk_lookup unassigned.
        let marker = unsafe { (*ctx.skb.skb).cb[4] };
        let key = udp_assign_key(ctx, marker);
        // BPF_PROG_TEST_RUN never runs at TC ingress, so assignment cannot take
        // effect there; fixtures read the chosen map key back from cb[4].
        #[cfg(feature = "routing-test")]
        unsafe {
            (*ctx.skb.skb).cb[4] = key.unwrap_or(0)
        };
        if let Some(key) = key {
            let map_ptr = ptr::from_ref(&LISTEN_SOCKET_MAP).cast::<c_void>();
            let _ = sk::sk_assign_by_index(ctx, map_ptr, &key, 0);
        }
    }

    Ok(TC_ACT_OK)
}

use crate::sk_lookup::{
    KEY_UDP4_BASE, KEY_UDP6_BASE, UDP_LISTENER_COUNT, UDP_LISTENER_MARKER, udp_listener_marker,
};

/// Listener map key named by a redirect site's `cb[4]` marker.
#[inline(always)]
fn udp_assign_key(ctx: &TcContext, marker: u32) -> Option<u32> {
    let index = marker.wrapping_sub(UDP_LISTENER_MARKER);
    if index >= UDP_LISTENER_COUNT {
        return None;
    }
    let is_v6 = unsafe { (*ctx.skb.skb).protocol as u16 } == ETH_P_IPV6.to_be();
    Some(if is_v6 {
        KEY_UDP6_BASE + index
    } else {
        KEY_UDP4_BASE + index
    })
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
        return Err(TC_ACT_UNSPEC);
    }
    let mut canonical: TuplesKey = unsafe { mem::zeroed() };
    crate::contrack::copy_reversed_tuples(&pkt.tuples.five, &mut canonical);
    let now = unsafe { bpf_ktime_get_ns() };
    let lifecycle = crate::contrack::available_tuple_lifecycle(&canonical, Some(now))
        .map_err(|_| TC_ACT_SHOT)?;
    let redirect_tuple = RedirectTuple::from_tuples(&pkt.tuples.five).reverse();

    let entry = match crate::auxiliary::reverse_redirect(&canonical, &redirect_tuple, now)
        .map_err(|_| TC_ACT_SHOT)?
    {
        Some(entry) => {
            crate::stats::count_rx(ctx, entry.outbound);
            if pkt.l4proto == IPPROTO_UDP
                && !crate::contrack::is_short_lived_udp_traffic(&canonical)
                && let Some(snapshot) = lifecycle.as_ref()
            {
                crate::contrack::udp::renew_udp_reply(&canonical, snapshot, &entry, now);
            }
            entry
        }
        // No outbound owns this reply, so it is not counted against one.
        None => match client_reply_entry(pkt, redirect_tuple) {
            Some(entry) => entry,
            None => return Err(TC_ACT_UNSPEC),
        },
    };

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
    crate::fragment::record(flatten(do_tproxy_lan_ingress(&TcContext::new(ctx), 14)))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    let ctx = TcContext::new(ctx);
    let link_h_len = crate::transport::l3_link_h_len(&ctx);
    crate::fragment::record(flatten(do_tproxy_lan_ingress(&ctx, link_h_len)))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_ingress_l2(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_wan_ingress(&TcContext::new(ctx), 14))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_ingress_l3(ctx: *mut __sk_buff) -> i32 {
    let ctx = TcContext::new(ctx);
    flatten(do_tproxy_wan_ingress(
        &ctx,
        crate::transport::l3_link_h_len(&ctx),
    ))
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
