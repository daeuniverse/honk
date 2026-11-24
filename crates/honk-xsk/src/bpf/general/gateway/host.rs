use super::*;
use aya_obj::generated::bpf_func_id;
use honk_ebpf_common::host::{HOST_SK_DIRECT, HOST_SK_ENDPOINT, HostSkDecision, HostSkIdentity};
use honk_ebpf_common::xdp_gateway::{HOLD_MANAGED, HOLD_NATIVE, HostFlowMeta, HostFlowOwner};
use std::mem::offset_of;

mod flow;

const HOST_META: i16 = QUOTE_AVAILABLE - size_of::<HostFlowMeta>() as i16;
const IDENTITY: i16 = HOST_META + offset_of!(HostFlowMeta, pid) as i16;
const DECISION: i16 = HOST_META - 8;
const OLD_STATE: i16 = DECISION - 4;
const DISCONNECTS: i16 = OLD_STATE - 4;
const ISN: i16 = DISCONNECTS - 4;
const PURE_SYN: i16 = ISN - 4;
const MATCHED: i16 = PURE_SYN - 4;
const STAMP: i16 = MATCHED - 12;
const FULL_SOCKET: i16 = STAMP - 8;
const CLASSIFIED_NS: i16 = FULL_SOCKET - 8;
const IDENTITY_PTR: i16 = CLASSIFIED_NS - 8;
const GUARDED: i16 = IDENTITY_PTR - 4;
// Host does not use the physical XDP metadata staging area.
const TCP_SLOT: i16 = META;
const TCP_SLOT_REALM: i16 = META + 8;
const SKB_MARK: i16 = 8;
const SKB_PRIORITY: i16 = 32;
const TC_ACT_REDIRECT: i32 = 7;
const STATE: i16 = offset_of!(HostSkDecision, state) as i16;
const JEQ_X: u8 = 0x1d;
const ATOMIC_W: u8 = 0xc3;
const OR_X: u8 = 0x4f;

const _: () = assert!(size_of::<HostFlowMeta>() == 88 && size_of::<HostSkIdentity>() == 56);
const _: () = assert!(GUARDED >= -480);
const _: () = assert!(HOST_META + size_of::<HostFlowMeta>() as i16 <= QUOTE_AVAILABLE);

fn attached_reply(b: &mut GatewayBuilder, ct: &crate::HostConntrack, reply: Target, bad: Target) {
    let done = b.target();
    let tracked_reply = b.target();
    b.mov(1, 9);
    b.emit(CALL, 0, 2, 0, ct.cast);
    b.load(LDX_DW, 3, 0, ct.nfct);
    b.mov(1, 3);
    b.emit(AND_K, 1, 0, 0, 7);
    b.jump(JEQ_K, 1, 0, 3, tracked_reply); // IP_CT_ESTABLISHED_REPLY
    b.jump(JNE_K, 1, 0, 4, done); // IP_CT_RELATED_REPLY
    b.bind(tracked_reply);
    b.emit(AND_K, 3, 0, 0, -8);
    b.jump(JEQ_K, 3, 0, 0, done);
    // The tagged association is only compared. All object reads use a kfunc-acquired
    // reference, including zone.id (directional zones can also match a zone-zero lookup).
    b.mov(6, 3);
    for reverse in [false, true] {
        let missing = b.target();
        let release = b.target();
        let retry = b.target();
        lookup_conntrack(b, &ct.lookup.0, reverse);
        b.jump(JEQ_K, 0, 0, 0, missing);
        b.mov(1, 0);
        b.imm(7, 1);
        b.jump(JNE_X, 1, 6, 0, release);
        if let Some(zone) = ct.zone {
            b.load(LDX_H, 7, 1, zone);
        } else {
            b.imm(7, 0);
        }
        b.bind(release);
        b.emit(
            CALL,
            0,
            2,
            ct.lookup.0.release_offset,
            ct.lookup.0.release as i32,
        );
        b.jump(JEQ_K, 7, 0, 0, reply);
        b.goto(retry);
        b.bind(missing);
        b.load(LDX_W, 0, 10, OPTS + 4);
        b.jump(JNE32_K, 0, 0, -libc::ENOENT, bad);
        b.bind(retry);
    }
    b.bind(done);
}

fn storage(b: &mut GatewayBuilder, fd: BorrowedFd<'_>, socket: u8, create: bool) {
    b.mov(2, socket);
    b.map(1, fd.as_raw_fd());
    b.imm(3, 0);
    b.imm(4, i32::from(create));
    b.helper(bpf_func_id::BPF_FUNC_sk_storage_get as i32);
}

fn identify_socket(b: &mut GatewayBuilder, host: &HostGatewayLoad<'_>, own: Target) {
    let done = b.target();
    b.emit(ST_DW, 10, 0, IDENTITY_PTR, 0);
    b.emit(ST_DW, 10, 0, FULL_SOCKET, 0);
    b.load(LDX_DW, 1, 9, 168); // __sk_buff.sk
    b.jump(JEQ_K, 1, 0, 0, done);
    b.helper(bpf_func_id::BPF_FUNC_sk_fullsock as i32);
    b.jump(JEQ_K, 0, 0, 0, done);
    b.store(STX_DW, 10, FULL_SOCKET, 0);
    storage(b, host.identity, 0, false);
    b.jump(JEQ_K, 0, 0, 0, done);
    b.store(STX_DW, 10, IDENTITY_PTR, 0);
    if let Some(pid) = host.honk_pid {
        b.load(LDX_W, 0, 0, 0);
        b.jump(JEQ32_K, 0, 0, pid as i32, own);
    }
    b.bind(done);
}

fn snapshot_identity(b: &mut GatewayBuilder, bad: Target) {
    let done = b.target();
    b.zero(IDENTITY, size_of::<HostSkIdentity>() as i16);
    b.load(LDX_DW, 8, 10, IDENTITY_PTR);
    b.jump(JEQ_K, 8, 0, 0, done);
    b.load(LDX_W, 0, 8, 0);
    b.jump(JEQ_K, 0, 0, 0, bad);
    b.load(LDX_B, 0, 8, 4);
    b.jump(JEQ_K, 0, 0, 0, bad);
    b.jump(
        JGT_K,
        0,
        0,
        honk_ebpf_common::ROUTING_PROCESS_MAX_LEN as i32,
        bad,
    );
    b.copy(10, IDENTITY, 8, 0, size_of::<HostSkIdentity>() as i16);
    b.bind(done);
}

fn transport(b: &mut GatewayBuilder, maps: &GatewayMaps, pass: Target, local: Target, bad: Target) {
    let udp = b.target();
    let ports = b.target();
    b.store(STX_W, 10, KEY + 44, 5);
    b.word(PURE_SYN, 0);
    b.word(ISN, 0);
    b.jump(JEQ_K, 5, 0, 17, udp);
    b.jump(JNE_K, 5, 0, 6, pass);
    b.prefix(20, REMAIN, bad);
    b.load(LDX_B, 1, 6, 12);
    b.emit(RSH_K, 1, 0, 0, 4);
    b.jump(JLT_K, 1, 0, 5, bad);
    b.emit(LSH_K, 1, 0, 0, 2);
    b.load_remaining(2, REMAIN, bad);
    b.jump(JGT_X, 1, 2, 0, bad);
    b.load(LDX_W, 1, 6, 4);
    b.store(STX_W, 10, ISN, 1);
    b.load(LDX_B, 1, 6, 13);
    b.store(STX_W, 10, TCP_FLAGS, 1);
    b.emit(AND_K, 1, 0, 0, 0x17);
    b.jump(JNE_K, 1, 0, 2, ports);
    b.word(PURE_SYN, 1);
    b.goto(ports);
    b.bind(udp);
    b.prefix(8, REMAIN, bad);
    b.load(LDX_H, 1, 6, 4);
    b.emit(BE16, 1, 0, 0, 16);
    b.jump(JLT_K, 1, 0, 8, bad);
    b.load(LDX_W, 0, 10, FRAG_STATE);
    let dhcp = b.target();
    b.jump(JSET_K, 0, 0, 1, dhcp);
    b.load_remaining(2, REMAIN, bad);
    b.jump(JGT_X, 1, 2, 0, bad);
    b.bind(dhcp);
    for field in [0, 2] {
        b.load(LDX_H, 0, 6, field);
        for port in [67, 68, 546, 547] {
            b.jump(JEQ_K, 0, 0, i32::from(u16::from_be(port)), pass);
        }
    }
    b.bind(ports);
    b.copy(10, KEY + 40, 6, 0, 4);
    let remote = b.target();
    b.load(LDX_H, 0, 10, KEY + 42);
    b.jump(JEQ_K, 0, 0, i32::from(u16::from_be(53)), remote);
    b.copy(10, LOCAL, 10, KEY + 4, 4);
    b.copy(10, LOCAL + 4, 10, KEY + 24, 16);
    b.word(INDEX, 0);
    b.lookup(maps.local_root.as_raw_fd(), INDEX);
    b.jump(JEQ_K, 0, 0, 0, bad);
    b.mov(1, 0);
    b.address(2, LOCAL);
    b.helper(1);
    b.jump(JNE_K, 0, 0, 0, local);
    b.bind(remote);
}

pub(in crate::bpf::general) fn build(
    pair: &crate::AuxDevicePair,
    realm: u32,
    gateway: &GatewayLoad<'_>,
    host: &HostGatewayLoad<'_>,
) -> io::Result<Program> {
    let guards = gateway
        .arbitration
        .ok_or_else(|| invalid_data("Host gateway requires tuple arbitration"))?
        .guards
        .as_raw_fd();
    let maps = gateway.maps;
    let hook = auxiliary::Ingress::new(pair, maps, realm);
    let mut b = GatewayBuilder::new();
    b.host_broadcasts = Some(pair.host_broadcasts_fd()?.as_raw_fd());
    b.auxiliary = Some(hook);
    let next = b.target();
    let bad = b.target();
    let drop = b.target();
    let queue_capacity = b.target();
    let stale = b.target();
    let ipv4 = b.target();
    let ipv6 = b.target();
    let parsed = b.target();
    let later = b.target();
    let pass = b.target();
    let local = b.target();
    let reply = b.target();
    let finish = b.target();
    let forward = b.target();
    let release = b.target();
    let exit = b.target();
    b.mov(9, 1);
    b.word(GUARDED, 0);
    b.load(LDX_W, 0, 9, 36);
    b.jump(JNE_K, 0, 0, 0, next);
    b.load(LDX_W, 0, 9, SKB_MARK);
    b.jump(JEQ32_K, 0, 0, host.bypass_mark as i32, next);
    b.helper(5);
    b.store(STX_DW, 10, CLASSIFIED_NS, 0);
    // __dev_queue_xmit resets the MAC header to data. Redirect to IFF_TUN strips
    // skb_network_offset, which must agree with the frame actually being parsed.
    b.mov(1, 9);
    b.emit(CALL, 0, 2, 0, host.ct.cast);
    b.load(LDX_B, 1, 0, host.ct.encapsulation.0);
    b.jump(JSET_K, 1, 0, host.ct.encapsulation.1, next);
    b.load(LDX_H, 1, 0, host.ct.mac_header);
    if host.is_l2 {
        b.add(1, 14);
    }
    b.load(LDX_H, 2, 0, host.ct.network_header);
    b.jump(JNE_X, 1, 2, 0, next);
    hook.prologue(&mut b, next, stale);
    if host.is_l2 {
        b.load(LDX_W, 0, 9, 20);
        b.jump(JNE_K, 0, 0, 0, next);
        b.imm(0, 0);
        b.rebase_cursor(bad);
        b.bound(14, bad);
        b.load(LDX_H, 5, 6, 12);
        b.emit(BE16, 5, 0, 0, 16);
        b.load(LDX_W, 0, 9, 16);
        b.emit(BE16, 0, 0, 0, 16);
        b.jump(JNE_X, 0, 5, 0, next);
        b.word(L2_LEN, 14);
    }
    b.jump(JEQ_K, 5, 0, 0x0800, ipv4);
    b.jump(JNE_K, 5, 0, 0x86dd, next);
    b.goto(ipv6);
    for (start, v6) in [(ipv4, false), (ipv6, true)] {
        b.bind(start);
        b.load(LDX_W, 0, 10, L2_LEN);
        b.rebase_cursor(bad);
        b.bound(1, bad);
        b.load(LDX_B, 0, 6, 0);
        b.emit(RSH_K, 0, 0, 0, 4);
        b.jump(JNE_K, 0, 0, if v6 { 6 } else { 4 }, next);
        parse_ip(
            &mut b,
            false,
            v6,
            &[],
            &ParseTargets {
                bad,
                later,
                done: parsed,
                pass,
                drop,
            },
        );
    }
    b.bind(parsed);
    transport(&mut b, maps, pass, local, bad);
    identify_socket(&mut b, host, pass);
    attached_reply(&mut b, host.ct, reply, bad);
    let calls = flow::emit(&mut b, realm, hook, gateway, host, finish, drop)?;
    b.bind(later);
    // An IPv6 extension after Fragment may precede the transport header even in a later fragment.
    b.load(LDX_B, 0, 10, FRAGMENT + 44);
    let tracked = b.target();
    for proto in [6, 17, 0, 43, 51, 60] {
        b.jump(JEQ_K, 0, 0, proto, tracked);
    }
    b.goto(pass);
    b.bind(tracked);
    b.lookup(maps.fragments.as_raw_fd(), FRAGMENT);
    let miss = b.target();
    b.jump(JEQ_K, 0, 0, 0, miss);
    b.mov(8, 0);
    b.helper(5);
    b.load(LDX_DW, 1, 8, 8);
    b.jump(JLT_X, 0, 1, 0, miss);
    b.emit(SUB_X, 0, 1, 0, 0);
    b.constant(1, FRAGMENT_TTL_NS);
    b.jump(JGT_X, 0, 1, 0, miss);
    b.load(LDX_W, 0, 8, 0);
    b.store(STX_W, 10, VERDICT, 0);
    let frag_pass = b.target();
    b.jump(JEQ_K, 0, 0, VERDICT_PASS, frag_pass);
    b.jump(JNE_K, 0, 0, VERDICT_ENDPOINT, miss);
    b.reason(GatewayReason::XskFragment, finish);
    b.bind(frag_pass);
    b.reason(GatewayReason::PassFragment, finish);
    b.bind(miss);
    b.stat(maps, GatewayReason::FragmentMiss);
    b.goto(drop);
    for (label, reason) in [
        (pass, GatewayReason::PassNonTransport),
        (local, GatewayReason::PassLocal),
        (reply, GatewayReason::PassCtReply),
    ] {
        b.bind(label);
        b.word(VERDICT, VERDICT_PASS);
        b.reason(reason, finish);
    }
    b.bind(finish);
    hook.authorize(&mut b, stale, stale);
    let within_capacity = b.target();
    b.load(LDX_W, 0, 10, VERDICT);
    b.jump(JNE_K, 0, 0, VERDICT_ENDPOINT, within_capacity);
    b.load(LDX_W, 0, 9, 0); // __sk_buff.len includes the Ethernet header before redirect.
    b.jump(
        JGT_K,
        0,
        0,
        65_536 + if host.is_l2 { 14 } else { 0 },
        queue_capacity,
    );
    b.mov(1, 9);
    b.emit(CALL, 0, 2, 0, host.ct.cast);
    b.load(LDX_W, 1, 0, host.ct.skb_truesize);
    b.jump(
        JGT_K,
        1,
        0,
        honk_ebpf_common::xdp_gateway::HOST_SKB_CHARGE_MAX as i32,
        queue_capacity,
    );
    b.load(LDX_W, 1, 0, host.ct.skb_end);
    b.jump(JGT_K, 1, 0, host.ct.skb_end_limit()?, queue_capacity);
    b.bind(within_capacity);
    auxiliary::check_endpoint_gso(&mut b, bad);
    let completed = b.target();
    b.load(LDX_W, 0, 10, FRAG_STATE);
    b.emit(AND_K, 0, 0, 0, 1);
    b.jump(JEQ_K, 0, 0, 0, completed);
    b.copy(10, VALUE, 10, VERDICT, 4);
    b.word(VALUE + 4, 0);
    b.helper(5);
    b.load(LDX_DW, 1, 10, CLASSIFIED_NS);
    b.store(STX_DW, 10, VALUE + 8, 1);
    b.emit(SUB_X, 0, 1, 0, 0);
    b.constant(1, FRAGMENT_TTL_NS);
    b.jump(JGT_X, 0, 1, 0, drop);
    b.update(maps.fragments.as_raw_fd(), FRAGMENT, VALUE, 0);
    b.jump(JEQ_K, 0, 0, 0, completed);
    b.stat(maps, GatewayReason::FragmentVerdictInsertFailed);
    b.goto(drop);
    b.bind(completed);
    b.copy(10, INDEX, 10, REASON, 4);
    b.stat_index(maps.stats.as_raw_fd());
    b.load(LDX_W, 0, 10, VERDICT);
    b.jump(JEQ_K, 0, 0, VERDICT_ENDPOINT, forward);
    b.bind(next);
    b.imm(6, auxiliary::TCX_NEXT);
    b.goto(release);
    b.bind(forward);
    b.load(LDX_DW, 7, 10, CLASSIFIED_NS);
    b.constant(1, 1 << 63);
    b.jump(JLE_X, 1, 7, 0, bad);
    auxiliary::Ingress::request_redirect(&mut b);
    b.jump(JNE_K, 0, 0, TC_ACT_REDIRECT, bad);
    // These fields survive __bpf_tx_skb and GSO segmentation on this private hop.
    // Keep the operator's values until the exact tuple guard has been released.
    b.load(LDX_W, 8, 9, SKB_PRIORITY);
    b.load(LDX_W, 1, 9, SKB_MARK);
    b.store(STX_W, 9, SKB_MARK, 7);
    b.emit(RSH_K, 7, 0, 0, 32);
    b.emit(OR_K, 7, 0, 0, i32::MIN);
    b.store(STX_W, 9, SKB_PRIORITY, 7);
    b.mov(7, 1);
    b.imm(6, TC_ACT_REDIRECT);
    b.goto(release);
    b.bind(queue_capacity);
    b.stat(maps, GatewayReason::HostQueueCapacity);
    b.goto(drop);
    b.bind(bad);
    b.stat(maps, GatewayReason::UnclassifiableHeader);
    b.goto(drop);
    b.bind(stale);
    b.stat(maps, GatewayReason::UnknownRealm);
    b.bind(drop);
    b.imm(6, auxiliary::TCX_DROP);
    b.bind(release);
    b.load(LDX_W, 0, 10, GUARDED);
    b.jump(JEQ_K, 0, 0, 0, exit);
    b.word(KEY, 0);
    flow::remove(&mut b, guards);
    b.jump(JEQ_K, 0, 0, 0, exit);
    let release_failed = b.target();
    b.jump(JNE_K, 6, 0, TC_ACT_REDIRECT, release_failed);
    b.store(STX_W, 9, SKB_MARK, 7);
    b.store(STX_W, 9, SKB_PRIORITY, 8);
    b.bind(release_failed);
    b.stat(maps, GatewayReason::HoldGuardReleaseFailed);
    b.imm(6, auxiliary::TCX_DROP);
    b.bind(exit);
    b.mov(0, 6);
    b.emit(EXIT, 0, 0, 0, 0);
    b.finish(gateway.routing, calls.into_iter().flatten())
}
