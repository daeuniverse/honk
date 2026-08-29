//! TC egress programs ported from daed/wing/dae-core/control/kern/tproxy.c
//!
//! Contains:
//! - `tproxy_lan_egress_l2` / `tproxy_lan_egress_l3` — update reverse conn state
//! - `tproxy_wan_egress_l2` / `tproxy_wan_egress_l3` — routing + redirect to control plane

#![allow(clippy::too_many_arguments)]
#![allow(unused_unsafe)]

use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::{
    bindings::__sk_buff,
    helpers::{
        bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_redirect, bpf_skb_change_head,
        bpf_skb_load_bytes, bpf_skb_store_bytes,
    },
};
use aya_ebpf_cty::c_void;
use core::ffi::c_long;
use core::mem;
use honk_ebpf_common::{
    IpVersionType, RedirectEntry, RedirectTuple, TASK_COMM_LEN, TPROXY_MARK,
    conn::BpfStatsKey,
    redirect_need::{PIDName, RoutingHandoffEntry, Tuples, TuplesKey},
};
use network_types::eth::EthHdr;
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use crate::{
    contrack::{
        AUXILIARY_MAP_REFRESH_INTERVAL_NS, copy_reversed_tuples, is_new_tcp_connection,
        is_short_lived_udp_traffic, lookup_udp_seen, mark_tcp_seen, mark_udp_seen,
    },
    maps::{
        COOKIE_PID_MAP, OUTBOUND_CONNECTIVITY_MAP, PARAM, PKT_SCRATCH_KEY, REDIRECT_TRACK,
        ROUTING_HANDOFF_MAP, WAN_EGRESS_ROUTE_SCRATCH_MAP, increment_bpf_stat,
    },
    route::{OUTBOUND_BLOCK, OUTBOUND_DIRECT},
    transport::{
        ETH_HLEN, ETH_P_IP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, parse_packet,
        tcp_listener_l4proto,
    },
};

use crate::action::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT, TC_ACT_UNSPEC, Verdict, flatten};

/// Ingress ifindex for locally-generated packets (not from any interface).
const NOWHERE_IFINDEX: u32 = 0;
/// ICMPv6 Neighbor Discovery Redirect type.
const NDP_REDIRECT: u8 = 137;
const TOKEN_IDENTITY_MISMATCH: i32 = -2;

#[inline(always)]
fn skb_ingress_ifindex(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).ingress_ifindex }
}

#[inline(always)]
fn skb_ifindex(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).ifindex }
}

#[inline(always)]
fn skb_mark(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).mark }
}

const DOMAIN_DNS: u32 = 1;
const DOMAIN_UDP_OTHER: u32 = 2;
const DOMAIN_DEFAULT: u32 = 0;

/// Check whether the selected outbound is currently alive.
///
/// DNS UDP (dport == 53) is always considered alive because user-space DNS
/// routing is responsible for fallback/rejection.  For all other traffic the
/// function consults `OUTBOUND_CONNECTIVITY_MAP`.
///
/// Map key layout (mirrors C):
///   key = outbound * 6 + domain_idx * 2 + ip_idx
///   - domain_idx: 0 = TCP, 1 = DNS UDP, 2 = data UDP
///   - ip_idx: 0 = IPv4, 1 = IPv6
#[inline(always)]
pub fn wan_outbound_is_alive(ctx: &TcContext, outbound: u8, l4proto: u8, dport: u16) -> bool {
    if l4proto == IPPROTO_UDP && dport == 53u16 {
        return true;
    }

    let domain_idx: u32 = match (l4proto, dport) {
        (IPPROTO_UDP, 53) => DOMAIN_DNS,
        (IPPROTO_UDP, _) => DOMAIN_UDP_OTHER,
        _ => DOMAIN_DEFAULT,
    };

    let proto = ctx.skb.protocol() as u16;
    let ip_idx: u32 = if proto == ETH_P_IP.to_be() { 0 } else { 1 };

    let key: u32 = (outbound as u32)
        .wrapping_mul(6)
        .wrapping_add(domain_idx.wrapping_mul(2))
        .wrapping_add(ip_idx);

    // OUTBOUND_CONNECTIVITY_MAP is `Array<u64, 1536>` — key is u32 index.
    match OUTBOUND_CONNECTIVITY_MAP.get(key) {
        Some(val) => *val != 0,
        None => true, // absent entry → assume alive
    }
}

/// Look up the socket cookie in `COOKIE_PID_MAP` to determine whether this
/// packet originated from the control-plane daemon process. A hit refreshes
/// `last_seen_ns` only after the shared one-second auxiliary-map interval.
/// Returns `None` when no PID mapping exists.
///
/// The caller must additionally check:
/// - `pid_name.pid == PARAM.control_plane_pid` to detect the control plane
/// - `PARAM.dae_socket_mark && skb_mark == PARAM.dae_socket_mark`
/// - `skb_mark & 0x100 == 0x100`
///   to determine whether the packet should be allowed to pass.
#[inline(always)]
pub fn pid_is_control_plane(ctx: &TcContext) -> Option<&PIDName> {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut c_void) };
    let ptr = COOKIE_PID_MAP.get_ptr_mut(cookie)?;
    let now = unsafe { bpf_ktime_get_ns() };
    let entry = unsafe { &mut *ptr };
    if now.wrapping_sub(entry.last_seen_ns) >= AUXILIARY_MAP_REFRESH_INTERVAL_NS {
        entry.last_seen_ns = now;
    }
    Some(entry)
}

/// Convenience: true when the packet is from the control plane (any detection
/// method).
#[inline(always)]
pub fn is_control_plane(ctx: &TcContext) -> bool {
    if let Some(pid_pname) = pid_is_control_plane(ctx) {
        let param = PARAM.load();
        if param.control_plane_pid != 0 && pid_pname.pid == param.control_plane_pid {
            return true;
        }
    }

    let param = PARAM.load();
    let mark = skb_mark(ctx);

    if param.dae_socket_mark != 0 && mark == param.dae_socket_mark {
        return true;
    }
    if (mark & 0x100) == 0x100 {
        return true;
    }

    false
}

/// Prepare a packet for redirection to the control plane.
///
/// Stores the original source/dest MAC in `REDIRECT_TRACK` so the dae0 ingress
/// handler can reverse the tuple later.  For L3-only packets (no Ethernet header)
/// a new Ethernet header is prepended.  `outbound` is recorded in the entry so
/// `dae0_ingress` can attribute reply traffic in `OUTBOUND_STATS`.
///
/// When `refresh_if_stale` is true (cached-flow packets, where every packet
/// would otherwise rewrite the same entry) the `REDIRECT_TRACK` update is
/// skipped while the existing entry is fresher than
/// [`crate::contrack::AUXILIARY_MAP_REFRESH_INTERVAL_NS`]. New flows pass false
/// and always write.
///
/// Returns 0 on success, non-zero on failure.
#[inline(always)]
pub fn prep_redirect_to_control_plane(
    ctx: &TcContext,
    link_h_len: u32,
    tuples: &Tuples,
    ethh: &EthHdr,
    from_wan: u8,
    refresh_if_stale: bool,
    outbound: u8,
    decision_token: u32,
) -> i32 {
    let param = PARAM.load();

    // bpf_redirect_peer is NOT supported in egress direction;
    // only use for ingress (from_wan == 0).
    let use_redirect_peer = param.use_redirect_peer != 0 && from_wan == 0;

    if !use_redirect_peer {
        if link_h_len == 0 {
            let l3proto = ctx.skb.protocol() as u16;
            let zero_mac: [u8; 6] = [0; 6];
            let ret =
                unsafe { bpf_skb_change_head(ctx.skb.skb, mem::size_of::<EthHdr>() as u32, 0) };
            if ret != 0 {
                return ret as i32;
            }
            unsafe {
                bpf_skb_store_bytes(
                    ctx.skb.skb,
                    12, // offsetof(struct ethhdr, h_proto)
                    &l3proto as *const u16 as *const _,
                    mem::size_of::<u16>() as u32,
                    0,
                );
                bpf_skb_store_bytes(
                    ctx.skb.skb,
                    6, // offsetof(struct ethhdr, h_source)
                    zero_mac.as_ptr() as *const _,
                    6,
                    0,
                );
            }
        }

        unsafe {
            bpf_skb_store_bytes(
                ctx.skb.skb,
                0, // offsetof(struct ethhdr, h_dest)
                param.dae0peer_mac.as_ptr() as *const _,
                6,
                0,
            );
        }
    }

    let redirect_tuple = RedirectTuple::from_tuples(&tuples.five);

    // Cached-flow throttle: skip the update while the existing entry is
    // fresh.  The header rewrite above is per-packet and must stay
    // unconditional; only the map write is throttled.
    if refresh_if_stale {
        let now = unsafe { bpf_ktime_get_ns() };
        let stale = match REDIRECT_TRACK.get_ptr_mut(redirect_tuple) {
            Some(old) => unsafe {
                if (*old).decision_token != decision_token {
                    return TOKEN_IDENTITY_MISMATCH;
                }
                now.wrapping_sub((*old).last_seen_ns)
                    >= crate::contrack::AUXILIARY_MAP_REFRESH_INTERVAL_NS
            },
            None => true,
        };
        if !stale {
            return 0;
        }
    }

    let mut redirect_entry: RedirectEntry = unsafe { mem::zeroed() };

    redirect_entry.ifindex = skb_ifindex(ctx);
    redirect_entry.from_wan = from_wan;
    redirect_entry.last_seen_ns = unsafe { bpf_ktime_get_ns() };
    // Record the final outbound so dae0_ingress can attribute replies.
    redirect_entry.outbound = outbound;
    redirect_entry.decision_token = decision_token;

    if link_h_len == ETH_HLEN {
        redirect_entry.smac.copy_from_slice(&ethh.src_addr);
        redirect_entry.dmac.copy_from_slice(&ethh.dst_addr);
    }
    // else: L3-only — MACs stay zero.

    if REDIRECT_TRACK
        .insert(redirect_tuple, redirect_entry, 0u64)
        .is_err()
    {
        increment_bpf_stat(BpfStatsKey::RedirectTrackInsertFailure);
        // A redirect without its reverse-path state blackholes replies.
        // Preserve the caller's documented direct-pass safety path instead.
        return -1;
    }

    0
}

/// Egress redirect to the control plane (dae0 interface).
///
/// bpf_redirect_peer is NOT supported in the egress direction.
#[inline(always)]
pub fn redirect_to_control_plane_egress() -> Verdict {
    let param = PARAM.load();
    Ok(unsafe { bpf_redirect(param.dae0_ifindex, 0) } as c_long)
}

/// LAN egress: update reverse-direction connection tracking state so the
/// server/local FIN/RST keeps the client-side lifecycle in sync.
///
/// Also drops NDP REDIRECT packets originated from localhost to prevent
/// kernel ND proxy from interfering with dae's routing.
///
/// #[inline(never)]: shared by lan_egress_l2/l3. Shallow call chain.
#[inline(never)]
pub fn do_tproxy_lan_egress(ctx: &TcContext, link_h_len: u32) -> Verdict {
    let scratch_key: u32 = 0;
    let pkt = match unsafe { PKT_SCRATCH_KEY.get_ptr_mut(scratch_key) } {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };

    let ret = parse_packet(ctx, link_h_len, pkt);
    if ret != 0 {
        // Negative: error → drop; Positive: unsupported protocol → pass through.
        if ret < 0 {
            return Err(TC_ACT_SHOT);
        }
        return Err(TC_ACT_OK);
    }

    // Broadcast/multicast (DHCPOFFER, mDNS, NetBIOS) is never conn-tracked.
    if crate::transport::dst_is_special(pkt, link_h_len) {
        return Err(TC_ACT_OK);
    }

    // Drop NDP REDIRECT packets from localhost to prevent ND proxy interference.
    if skb_ingress_ifindex(ctx) == NOWHERE_IFINDEX && pkt.l4proto == IPPROTO_ICMPV6 {
        // ICMPv6 type is at offset: link_h_len + ipv6hdr(40) + 0(icmp6_type).
        let icmp6_offset = if link_h_len == ETH_HLEN {
            (link_h_len + 40) as usize
        } else {
            40usize
        };
        let mut icmp6_type: u8 = 0;
        unsafe {
            let _ = bpf_skb_load_bytes(
                ctx.skb.skb as *mut _,
                icmp6_offset as u32,
                &mut icmp6_type as *mut u8 as *mut _,
                1,
            );
        }
        if icmp6_type == NDP_REDIRECT {
            return Err(TC_ACT_SHOT);
        }
    }

    match pkt.l4proto {
        IPPROTO_TCP => {
            let mut reversed_key: TuplesKey = unsafe { mem::zeroed() };
            copy_reversed_tuples(&pkt.tuples.five, &mut reversed_key);
            mark_tcp_seen(
                &reversed_key,
                &pkt.tcph,
                1u8,  // is_wan_ingress_direction
                None, // outbound
                None, // mark
                None, // must
                None, // mac
                0,    // dscp
                None, // pname
                0,    // pid
            );
        }
        IPPROTO_UDP => {
            // Skip DNS traffic to reduce state churn.
            if u16::from_be_bytes(pkt.udph.src) == 53 || u16::from_be_bytes(pkt.udph.dst) == 53 {
                return Err(TC_ACT_PIPE);
            }
            let mut reversed_key: TuplesKey = unsafe { mem::zeroed() };
            copy_reversed_tuples(&pkt.tuples.five, &mut reversed_key);
            mark_udp_seen(
                &reversed_key,
                1u8,  // is_wan_ingress_direction
                None, // outbound
                None, // mark
                None, // must
                None, // mac
                0,    // dscp
                None, // pname
                0,    // pid
            );
        }
        _ => {}
    }

    Ok(TC_ACT_PIPE)
}

/// WAN egress TCP handler: route new connections and cache the decision;
/// for established flows, reuse the cached routing.
#[inline(always)]
fn do_tproxy_wan_egress_tcp(
    ctx: &TcContext,
    link_h_len: u32,
    tuples: &Tuples,
    ethh: &EthHdr,
    tcph: &TcpHdr,
) -> Verdict {
    let tcp_state_syn = is_new_tcp_connection(tcph);
    let outbound: u8;
    let must: bool;
    let mark: u32;

    let mut handoff_pname: Option<&[u8; TASK_COMM_LEN]> = None;
    let mut handoff_pid: u32 = 0;

    let scratch_key: u32 = 0;
    let scratch = match unsafe { WAN_EGRESS_ROUTE_SCRATCH_MAP.get_ptr_mut(scratch_key) } {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };

    if tcp_state_syn {
        *scratch = unsafe { mem::zeroed() };
        scratch.flag[0] = 1u32; // L4ProtoType_TCP = 1

        let proto = ctx.skb.protocol() as u16;
        scratch.flag[1] = if proto == ETH_P_IP.to_be() {
            IpVersionType::V4 as u32
        } else {
            IpVersionType::V6 as u32
        };
        scratch.flag[6] = tuples.dscp as u32;

        // Look up PID info for process-name routing; also check
        // control-plane traffic (single cookie lookup).
        let pid_pname_opt = pid_is_control_plane(ctx);
        if let Some(pid_pname) = pid_pname_opt {
            let param = PARAM.load();
            if pid_pname.pid == param.control_plane_pid {
                return Err(TC_ACT_OK);
            }

            // Copy pname into flag[2..6] (4 × u32 = 16 bytes = TASK_COMM_LEN).
            let pname_ptr = pid_pname.pname.as_ptr() as *const u32;
            unsafe {
                scratch.flag[2] = *pname_ptr;
                scratch.flag[3] = *pname_ptr.add(1);
                scratch.flag[4] = *pname_ptr.add(2);
                scratch.flag[5] = *pname_ptr.add(3);
            }
            handoff_pname = Some(&pid_pname.pname);
            handoff_pid = pid_pname.pid;
        }

        scratch.flag[7] = 1; // is_wan = 1

        if link_h_len == ETH_HLEN {
            let h_src = &ethh.src_addr;
            scratch.mac_be[2] = u32::from_be_bytes([0, 0, h_src[0], h_src[1]]);
            scratch.mac_be[3] = u32::from_be_bytes([h_src[2], h_src[3], h_src[4], h_src[5]]);
            scratch.mac.copy_from_slice(h_src);
        }

        let h_dport = u16::from_be_bytes(tcph.dest);
        let h_sport = u16::from_be_bytes(tcph.source);

        let saddr = unsafe { &tuples.five.src_ip.u6_addr32 };
        let daddr = unsafe { &tuples.five.dst_ip.u6_addr32 };
        let s64_ret = crate::route::route(
            &scratch.flag,
            h_dport,
            h_sport,
            saddr,
            daddr,
            &scratch.mac_be,
        );

        if s64_ret < 0 {
            return Err(TC_ACT_SHOT);
        }

        outbound = (s64_ret & 0xFF) as u8;
        mark = (s64_ret >> 8) as u32;
        must = ((s64_ret >> 40) & 1) != 0;
        scratch.must_val = must as u8;

        let dscp = tuples.dscp;
        let (outbound_ptr, mark_ptr, must_ptr): (Option<&u8>, Option<&u32>, Option<&u8>) =
            if outbound == OUTBOUND_DIRECT && mark == 0 && !must {
                (None, None, None)
            } else {
                (Some(&outbound), Some(&mark), Some(&scratch.must_val))
            };

        let pname_bytes: Option<&[u8; TASK_COMM_LEN]> = handoff_pname;

        let tcp_conn = mark_tcp_seen(
            &tuples.five,
            tcph,
            0u8, // is_wan_ingress_direction
            outbound_ptr,
            mark_ptr,
            must_ptr,
            Some(&scratch.mac),
            dscp,
            pname_bytes,
            handoff_pid,
        );

        if tcp_conn.is_none() {
            if outbound == OUTBOUND_DIRECT && mark == 0 {
                return Err(TC_ACT_OK);
            }
            return Err(TC_ACT_SHOT);
        }
    } else {
        let tcp_conn = mark_tcp_seen(
            &tuples.five,
            tcph,
            0u8,  // is_wan_ingress_direction
            None, // outbound
            None, // mark
            None, // must
            None, // mac
            0,    // dscp
            None, // pname
            0,    // pid
        );

        if let Some(conn) = tcp_conn {
            // Check has_routing from raw u64: bit 56.
            let meta_raw = unsafe { conn.meta.raw };
            if ((meta_raw >> 56) & 1) != 0 {
                outbound = (meta_raw & 0xFF) as u8;
                mark = ((meta_raw >> 8) & 0xFFFFFFFF) as u32;
                must = ((meta_raw >> 40) & 1) != 0;
                handoff_pname = Some(&conn.pname);
                handoff_pid = conn.pid;
                scratch.mac.copy_from_slice(&conn.mac);
            } else {
                // No cached routing — direct connection, pass through.
                return Err(TC_ACT_OK);
            }
        } else {
            // No state at all — pass through.
            return Err(TC_ACT_OK);
        }
    }

    if outbound == OUTBOUND_DIRECT && mark == 0 {
        ctx.set_mark(mark);
        return Err(TC_ACT_OK);
    } else if outbound == OUTBOUND_BLOCK {
        return Err(TC_ACT_SHOT);
    }

    if !wan_outbound_is_alive(ctx, outbound, IPPROTO_TCP, tuples.five.dst_port) {
        return Err(TC_ACT_SHOT);
    }

    let prepare_result = prep_redirect_to_control_plane(
        ctx,
        link_h_len,
        tuples,
        ethh,
        1,
        !tcp_state_syn,
        outbound,
        0,
    );
    if prepare_result != 0 {
        if prepare_result == TOKEN_IDENTITY_MISMATCH {
            return Err(TC_ACT_SHOT);
        }
        // Preserve the existing direct-pass fallback for map write failures.
        return Err(TC_ACT_OK);
    }

    // Set cb marks for dae0peer_ingress.
    unsafe {
        (*ctx.skb.skb).cb[0] = TPROXY_MARK;
        (*ctx.skb.skb).cb[1] = tcp_listener_l4proto(tcph) as u32;
    }

    // Write routing handoff entry for the control plane.  Only the SYN that
    // starts the connection needs one: userspace consumes handoffs once per
    // accepted connection, so per-packet writes on established flows would
    // just churn the map until the janitor sweeps them.
    if tcp_state_syn {
        let mut handoff: RoutingHandoffEntry = unsafe { mem::zeroed() };
        handoff.last_seen_ns = unsafe { bpf_ktime_get_ns() };
        handoff.result.mark = mark;
        handoff.result.must = must as u8;
        handoff.result.outbound = outbound;
        handoff.result.pid = handoff_pid;
        handoff.result.dscp = tuples.dscp;
        handoff.result.decision_token = 0;
        handoff.result.mac.copy_from_slice(&scratch.mac);
        if let Some(pname) = handoff_pname {
            handoff.result.pname.copy_from_slice(pname);
        }
        if ROUTING_HANDOFF_MAP
            .insert(tuples.five, handoff, 0u64)
            .is_err()
        {
            increment_bpf_stat(BpfStatsKey::RoutingHandoffInsertFailure);
        }
    }

    redirect_to_control_plane_egress()
}

/// Fast-path decision after routing (shared by the cached and full-routing
/// UDP paths).
#[inline(always)]
fn fast_path_decision(
    ctx: &TcContext,
    link_h_len: u32,
    tuples: &Tuples,
    ethh: &EthHdr,
    outbound: u8,
    mark: u32,
    must: bool,
    mac: [u8; 6],
    handoff_pname: Option<&[u8; TASK_COMM_LEN]>,
    handoff_pid: u32,
    decision_token: u32,
) -> Verdict {
    if outbound == OUTBOUND_DIRECT && mark == 0 {
        return Err(TC_ACT_OK);
    } else if outbound == OUTBOUND_BLOCK {
        return Err(TC_ACT_SHOT);
    }

    if !wan_outbound_is_alive(ctx, outbound, IPPROTO_UDP, tuples.five.dst_port) {
        return Err(TC_ACT_SHOT);
    }

    let prepare_result = prep_redirect_to_control_plane(
        ctx,
        link_h_len,
        tuples,
        ethh,
        1,
        true,
        outbound,
        decision_token,
    );
    if prepare_result != 0 {
        if prepare_result == TOKEN_IDENTITY_MISMATCH || decision_token != 0 {
            return Err(TC_ACT_SHOT);
        }
        return Err(TC_ACT_OK);
    }

    unsafe {
        (*ctx.skb.skb).cb[0] = TPROXY_MARK;
        (*ctx.skb.skb).cb[1] = IPPROTO_UDP as u32;
    }

    // Write routing handoff entry, throttled to absent-or-stale.  The first
    // packet of a flow always finds the entry absent (new map entry, or
    // already consumed by userspace) and rewrites it, so userspace still
    // sees a handoff on endpoint-pool miss; later packets of the same flow
    // refresh it at most once per AUXILIARY_MAP_REFRESH_INTERVAL_NS.
    let now = unsafe { bpf_ktime_get_ns() };
    let write_handoff = match ROUTING_HANDOFF_MAP.get_ptr_mut(tuples.five) {
        Some(old) => unsafe {
            if (*old).result.decision_token != decision_token {
                return Err(TC_ACT_SHOT);
            }
            now.wrapping_sub((*old).last_seen_ns)
                >= crate::contrack::AUXILIARY_MAP_REFRESH_INTERVAL_NS
        },
        None => true,
    };
    if write_handoff {
        let mut handoff: RoutingHandoffEntry = unsafe { mem::zeroed() };
        handoff.last_seen_ns = now;
        handoff.result.mark = mark;
        handoff.result.must = must as u8;
        handoff.result.outbound = outbound;
        handoff.result.pid = handoff_pid;
        handoff.result.dscp = tuples.dscp;
        handoff.result.decision_token = decision_token;
        handoff.result.mac.copy_from_slice(&mac);
        if let Some(pname) = handoff_pname {
            handoff.result.pname.copy_from_slice(pname);
        }
        if ROUTING_HANDOFF_MAP
            .insert(tuples.five, handoff, 0u64)
            .is_err()
        {
            increment_bpf_stat(BpfStatsKey::RoutingHandoffInsertFailure);
        }
    }

    redirect_to_control_plane_egress()
}

/// WAN egress UDP handler.
#[inline(always)]
fn do_tproxy_wan_egress_udp(
    ctx: &TcContext,
    link_h_len: u32,
    tuples: &Tuples,
    ethh: &EthHdr,
    udph: &UdpHdr,
) -> Verdict {
    let mut outbound: u8;
    let mut mark: u32;
    let must: bool;
    let mut mac: [u8; 6] = [0; 6];
    let mut handoff_pname: Option<&[u8; TASK_COMM_LEN]> = None;
    let mut handoff_pid: u32 = 0;
    let mut decision_token: u32 = 0;

    let scratch_key: u32 = 0;
    let scratch = match unsafe { WAN_EGRESS_ROUTE_SCRATCH_MAP.get_ptr_mut(scratch_key) } {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };

    *scratch = unsafe { mem::zeroed() };
    scratch.flag[0] = 2u32; // L4ProtoType_UDP = 2

    let proto = ctx.skb.protocol() as u16;
    scratch.flag[1] = if proto == ETH_P_IP.to_be() {
        IpVersionType::V4 as u32
    } else {
        IpVersionType::V6 as u32
    };
    scratch.flag[6] = tuples.dscp as u32;

    // Check control plane (single cookie lookup).
    let pid_pname_opt = pid_is_control_plane(ctx);
    if let Some(pid_pname) = pid_pname_opt {
        let param = PARAM.load();
        if pid_pname.pid == param.control_plane_pid {
            return Err(TC_ACT_OK);
        }
    }

    // A live non-DNS entry already carries a complete routing decision.
    // Lookup-only admission avoids allocating an empty entry before a miss is
    // routed and refreshes the cached entry's timestamp at most once per second.
    if !is_short_lived_udp_traffic(&tuples.five)
        && let Some(conn_state) = lookup_udp_seen(&tuples.five)
    {
        if conn_state.is_wan_ingress_direction != 0 {
            return Err(TC_ACT_OK);
        }

        let meta_raw = unsafe { conn_state.meta.raw };
        if (meta_raw >> 56) & 1 != 0 {
            outbound = (meta_raw & 0xFF) as u8;
            mark = ((meta_raw >> 8) & 0xFFFFFFFF) as u32;
            must = ((meta_raw >> 40) & 1) != 0;
            mac.copy_from_slice(&conn_state.mac);
            handoff_pname = Some(&conn_state.pname);
            handoff_pid = conn_state.pid;
            decision_token = conn_state.decision_token;

            return fast_path_decision(
                ctx,
                link_h_len,
                tuples,
                ethh,
                outbound,
                mark,
                must,
                mac,
                handoff_pname,
                handoff_pid,
                decision_token,
            );
        }
    }

    if let Some(pid_pname) = pid_pname_opt {
        let pname_ptr = pid_pname.pname.as_ptr() as *const u32;
        unsafe {
            scratch.flag[2] = *pname_ptr;
            scratch.flag[3] = *pname_ptr.add(1);
            scratch.flag[4] = *pname_ptr.add(2);
            scratch.flag[5] = *pname_ptr.add(3);
        }
        handoff_pname = Some(&pid_pname.pname);
        handoff_pid = pid_pname.pid;
    }

    scratch.flag[7] = 1; // is_wan = 1

    if link_h_len == ETH_HLEN {
        let h_src = &ethh.src_addr;
        scratch.mac_be[2] = u32::from_be_bytes([0, 0, h_src[0], h_src[1]]);
        scratch.mac_be[3] = u32::from_be_bytes([h_src[2], h_src[3], h_src[4], h_src[5]]);
        mac.copy_from_slice(h_src);
        scratch.mac.copy_from_slice(h_src);
    }

    let h_dport = u16::from_be_bytes(udph.dst);
    let h_sport = u16::from_be_bytes(udph.src);

    let saddr = unsafe { &tuples.five.src_ip.u6_addr32 };
    let daddr = unsafe { &tuples.five.dst_ip.u6_addr32 };
    let s64_ret = crate::route::route(
        &scratch.flag,
        h_dport,
        h_sport,
        saddr,
        daddr,
        &scratch.mac_be,
    );

    if s64_ret < 0 {
        return Err(TC_ACT_SHOT);
    }

    outbound = (s64_ret & 0xFF) as u8;
    mark = (s64_ret >> 8) as u32;
    must = ((s64_ret >> 40) & 1) != 0;
    if !must
        && outbound != OUTBOUND_BLOCK
        && crate::maps::datapath_flags() & honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_ALL != 0
    {
        if outbound != OUTBOUND_DIRECT {
            mark = 0;
        }
        outbound = OUTBOUND_DIRECT;
    }

    if !is_short_lived_udp_traffic(&tuples.five) {
        let must_u8 = must as u8;
        let pname = pid_pname_opt.map(|pid_pname| &pid_pname.pname);
        let pid = pid_pname_opt.map_or(0, |pid_pname| pid_pname.pid);
        if mark_udp_seen(
            &tuples.five,
            0u8,
            Some(&outbound),
            Some(&mark),
            Some(&must_u8),
            Some(&mac),
            tuples.dscp,
            pname,
            pid,
        )
        .is_none()
        {
            if outbound == OUTBOUND_DIRECT && mark == 0 {
                return Err(TC_ACT_OK);
            }
            return Err(TC_ACT_SHOT);
        }
    }

    fast_path_decision(
        ctx,
        link_h_len,
        tuples,
        ethh,
        outbound,
        mark,
        must,
        mac,
        handoff_pname,
        handoff_pid,
        decision_token,
    )
}

/// WAN egress entry point: parse the packet first so the verifier accepts
/// direct `__sk_buff` field access, skip non-localhost traffic, then dispatch
/// to the TCP or UDP handler.
#[inline(always)]
fn do_tproxy_wan_egress(ctx: &TcContext, link_h_len: u32) -> Verdict {
    if !crate::maps::datapath_ready() {
        return Err(TC_ACT_OK);
    }
    let scratch_key: u32 = 0;
    let pkt = match unsafe { PKT_SCRATCH_KEY.get_ptr_mut(scratch_key) } {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Err(TC_ACT_SHOT),
    };

    // Parse before reading __sk_buff fields: ctx.load() proves to the verifier
    // that ctx.skb.skb is a valid non-null pointer.
    let ret = parse_packet(ctx, link_h_len, pkt);
    if ret != 0 {
        // Unsupported or malformed traffic is left untouched.
        return Err(TC_ACT_OK);
    }

    // Broadcast/multicast is never re-routed into daens.
    if crate::transport::dst_is_special(pkt, link_h_len) {
        return Err(TC_ACT_OK);
    }

    // Bypass locally-generated traffic destined for the honk host itself.
    // Without this, connections to the honk management port (e.g. 10.10.10.1:9999)
    // are intercepted and routed through the proxy, creating a loop.
    let param = PARAM.load();
    if param.local_ip != 0 {
        let dst_ip = pkt.tuples.five.dst_ip;
        let dst_ipv4 = unsafe { dst_ip.u6_addr32[3] };
        if dst_ip.is_v4_mapped() && dst_ipv4 == param.local_ip {
            return Err(TC_ACT_OK);
        }
    }

    // Pure forwarded traffic stays on the native path here; continue so a
    // downstream external-interface NAT classifier can still translate it.
    if skb_ingress_ifindex(ctx) != NOWHERE_IFINDEX {
        return Err(TC_ACT_UNSPEC);
    }

    // Control-plane bypass (Go dae `pid_is_control_plane` mark fallback,
    // tproxy.c:2613-2616): packets from dae's own marked sockets are never
    // re-routed.  The cookie/PID check inside the per-protocol handlers only
    // covers sockets the cgroup hooks recorded; when that mapping is missing
    // (hook not attached, cookie lookup miss) the mark check here is the
    // reliable fallback that prevents dae's own dials from being redirected
    // back into daens and looping.
    let mark = skb_mark(ctx);
    if (param.dae_socket_mark != 0 && mark == param.dae_socket_mark) || (mark & 0x100) == 0x100 {
        return Err(TC_ACT_OK);
    }

    match pkt.l4proto {
        IPPROTO_TCP => do_tproxy_wan_egress_tcp(ctx, link_h_len, &pkt.tuples, &pkt.ethh, &pkt.tcph),
        IPPROTO_UDP => do_tproxy_wan_egress_udp(ctx, link_h_len, &pkt.tuples, &pkt.ethh, &pkt.udph),
        _ => Ok(TC_ACT_OK),
    }
}

// TC entry points use raw __sk_buff pointer for verifier compatibility.

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_egress_l2(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_lan_egress(&TcContext::new(ctx), 14))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn lan_egress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_lan_egress(&TcContext::new(ctx), 0))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress_l2(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_wan_egress(&TcContext::new(ctx), 14))
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn wan_egress_l3(ctx: *mut __sk_buff) -> i32 {
    flatten(do_tproxy_wan_egress(&TcContext::new(ctx), 0))
}
