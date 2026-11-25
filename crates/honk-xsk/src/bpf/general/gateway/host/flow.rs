use super::*;

const BUSY: i32 = 3;
const COOKIE: i16 = HOST_META + offset_of!(HostFlowMeta, socket_cookie) as i16;

pub(super) fn remove(b: &mut GatewayBuilder, fd: RawFd) {
    b.map(1, fd);
    b.address(2, KEY);
    b.helper(3);
}

// TUPLE is dead between the connection lookup and DNS classification.
fn require_origin_gate(
    b: &mut GatewayBuilder,
    bindings: RawFd,
    devices: RawFd,
    realm: u32,
    conflict: Target,
) {
    b.word(TUPLE + 4, 0);
    let local = b.target();
    b.load(LDX_W, 0, 10, TUPLE);
    b.jump(JEQ32_K, 0, 0, realm as i32, local);
    b.lookup(devices, TUPLE);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.mov(6, 0);
    for slot in [
        crate::bpf::tcx_aux::OUTER_SLOT,
        crate::bpf::tcx_aux::INNER_SLOT,
    ] {
        b.mov(1, 6);
        b.word(INDEX, slot);
        b.address(2, INDEX);
        b.helper(1);
        b.jump(JEQ_K, 0, 0, 0, conflict);
        b.load(LDX_W, 1, 0, 0);
        b.jump(JEQ_K, 1, 0, 0, conflict);
    }
    b.bind(local);
    b.lookup(bindings, TUPLE);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.mov(1, 0);
    b.word(INDEX, 0);
    b.address(2, INDEX);
    b.helper(1);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.load(LDX_W, 1, 0, 0);
    b.jump(JNE_K, 1, 0, 1, conflict);
}

fn socket_decision(
    b: &mut GatewayBuilder,
    host: &HostGatewayLoad<'_>,
    bindings: RawFd,
    devices: RawFd,
    realm: u32,
    conflict: Target,
) {
    let done = b.target();
    b.emit(ST_DW, 10, 0, DECISION, 0);
    b.emit(ST_DW, 10, 0, COOKIE, 0);
    b.word(MATCHED, 0);
    b.word(OLD_STATE, 0);
    b.load(LDX_DW, 7, 10, FULL_SOCKET);
    b.jump(JEQ_K, 7, 0, 0, done);
    b.mov(1, 9);
    b.helper(bpf_func_id::BPF_FUNC_get_socket_cookie as i32);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.store(STX_DW, 10, COOKIE, 0);
    b.load(LDX_B, 0, 10, KEY + 44);
    b.jump(JNE_K, 0, 0, 6, done);
    // __sk_buff.sk has socket-common type for storage. For a kernel struct member read
    // take the same skb's native sock pointer, while the fullsock proof is still live.
    b.mov(1, 9);
    b.emit(CALL, 0, 2, 0, host.ct.cast);
    b.load(LDX_DW, 3, 0, host.ct.sk);
    b.jump(JEQ_K, 3, 0, 0, conflict);
    // Linux uses a kernel-created SOCK_RAW/IPPROTO_TCP for orphan control replies.
    // A userspace raw socket has no TCP connection incarnation.
    let stream = b.target();
    b.load(LDX_W, 1, 7, 12); // bpf_sock.protocol
    b.jump(JNE_K, 1, 0, libc::IPPROTO_TCP, conflict);
    b.load(LDX_W, 1, 7, 8); // bpf_sock.type
    b.jump(JEQ_K, 1, 0, libc::SOCK_STREAM, stream);
    b.jump(JNE_K, 1, 0, libc::SOCK_RAW, conflict);
    b.add(3, host.ct.kernel_socket.0);
    b.address(1, INDEX);
    b.imm(2, 1);
    b.helper(bpf_func_id::BPF_FUNC_probe_read_kernel as i32);
    b.jump(JNE_K, 0, 0, 0, conflict);
    b.load(LDX_B, 0, 10, INDEX);
    b.emit(AND_K, 0, 0, 0, host.ct.kernel_socket.1);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.emit(ST_DW, 10, 0, COOKIE, 0);
    b.goto(done);
    b.bind(stream);
    b.add(3, host.ct.disconnects);
    b.address(1, DISCONNECTS);
    b.imm(2, 4);
    b.helper(bpf_func_id::BPF_FUNC_probe_read_kernel as i32);
    b.jump(JNE_K, 0, 0, 0, conflict);
    b.load(LDX_W, 0, 10, PURE_SYN);
    let existing = b.target();
    let found = b.target();
    b.jump(JEQ_K, 0, 0, 0, existing);
    storage(b, host.decision, 7, true);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.goto(found);
    b.bind(existing);
    storage(b, host.decision, 7, false);
    b.jump(JEQ_K, 0, 0, 0, done);
    b.bind(found);
    b.mov(7, 0);
    b.load(LDX_W, 0, 7, STATE);
    b.jump(JGT_K, 0, 0, HOST_SK_ENDPOINT as i32, conflict);
    b.store(STX_W, 10, OLD_STATE, 0);
    b.mov(1, 0);
    b.imm(2, BUSY);
    // Different tuple guards can meet on a socket being disconnected/reconnected.
    b.emit(ATOMIC_W, 7, 2, STATE, CMPXCHG);
    b.jump(JNE_X, 0, 1, 0, conflict);
    b.store(STX_DW, 10, DECISION, 7);
    b.jump(JEQ_K, 0, 0, 0, done);
    b.load(LDX_W, 1, 7, offset_of!(HostSkDecision, disconnects) as i16);
    b.load(LDX_W, 0, 10, DISCONNECTS);
    let connection = b.target();
    b.jump(JEQ_X, 0, 1, 0, connection);
    // inet_stream_connect increments sk_disconnects before tcp_disconnect emits
    // its final RST on the old connection in TCP_CLOSE.
    b.add(1, 1);
    b.jump(JNE_X, 0, 1, 0, done);
    b.load(LDX_W, 0, 10, TCP_FLAGS);
    b.emit(AND_K, 0, 0, 0, 0x06);
    b.jump(JNE_K, 0, 0, 0x04, done);
    b.load(LDX_DW, 1, 10, FULL_SOCKET);
    b.jump(JEQ_K, 1, 0, 0, conflict);
    b.load(LDX_W, 0, 1, 72); // bpf_sock.state
    b.jump(JNE_K, 0, 0, 7, done);
    b.bind(connection);
    b.load(LDX_W, 0, 10, KEY + 4);
    b.load(LDX_W, 1, 7, 4);
    b.jump(JNE_X, 0, 1, 0, conflict);
    for off in (8..48).step_by(8) {
        b.load(LDX_DW, 0, 10, KEY + off);
        b.load(LDX_DW, 1, 7, off);
        b.jump(JNE_X, 0, 1, 0, conflict);
    }
    let local = b.target();
    let authorized = b.target();
    b.load(LDX_W, 0, 7, 0);
    b.load(LDX_W, 1, 10, KEY);
    b.jump(JEQ_X, 0, 1, 0, local);
    b.store(STX_W, 10, TUPLE, 0);
    b.load(LDX_W, 0, 10, OLD_STATE);
    b.jump(JNE_K, 0, 0, HOST_SK_DIRECT as i32, conflict);
    b.load(LDX_DW, 0, 7, offset_of!(HostSkDecision, binding) as i16);
    b.store(STX_DW, 10, TUPLE + 8, 0);
    require_origin_gate(b, bindings, devices, realm, conflict);
    b.goto(authorized);
    b.bind(local);
    b.constant(0, host.binding);
    b.load(LDX_DW, 1, 7, offset_of!(HostSkDecision, binding) as i16);
    b.jump(JNE_X, 0, 1, 0, conflict);
    b.bind(authorized);
    let same = b.target();
    b.load(LDX_W, 0, 10, PURE_SYN);
    b.jump(JEQ_K, 0, 0, 0, same);
    b.load(LDX_W, 0, 10, ISN);
    b.load(LDX_W, 1, 7, offset_of!(HostSkDecision, isn) as i16);
    b.jump(JNE_X, 0, 1, 0, conflict);
    b.bind(same);
    b.load(LDX_DW, 0, 7, offset_of!(HostSkDecision, stamp) as i16);
    b.store(STX_DW, 10, STAMP, 0);
    b.mov(1, 0);
    b.emit(LSH_K, 1, 0, 0, 2);
    b.jump(JEQ_K, 1, 0, 0, conflict);
    b.emit(RSH_K, 0, 0, 0, 62);
    b.load(LDX_W, 1, 10, OLD_STATE);
    b.jump(JNE_X, 0, 1, 0, conflict);
    b.word(MATCHED, 1);
    b.bind(done);
}

// Only the previous socket incarnation can release this exact native reservation.
fn retire_reconnected_direct(b: &mut GatewayBuilder, binding: u64, slots: RawFd, conflict: Target) {
    b.load(LDX_W, 1, 10, OLD_STATE);
    b.jump(JNE_K, 1, 0, HOST_SK_DIRECT as i32, conflict);
    b.load(LDX_DW, 1, 10, FULL_SOCKET);
    b.jump(JEQ_K, 1, 0, 0, conflict);
    b.load(LDX_W, 1, 1, 72); // bpf_sock.state
    b.jump(JNE_K, 1, 0, 2, conflict); // TCP_SYN_SENT
    b.load(LDX_DW, 7, 10, DECISION);
    b.jump(JEQ_K, 7, 0, 0, conflict);
    b.load(LDX_W, 1, 7, offset_of!(HostSkDecision, disconnects) as i16);
    b.load(LDX_W, 2, 10, DISCONNECTS);
    b.jump(JLE_X, 2, 1, 0, conflict);
    for off in (0..48).step_by(8) {
        b.load(LDX_DW, 1, 10, KEY + off);
        b.load(LDX_DW, 2, 7, off);
        b.jump(JNE_X, 1, 2, 0, conflict);
    }
    b.constant(8, binding);
    b.load(LDX_DW, 1, 7, offset_of!(HostSkDecision, binding) as i16);
    b.jump(JNE_X, 1, 8, 0, conflict);
    b.load(LDX_DW, 6, 0, 0);
    b.load(LDX_DW, 1, 7, offset_of!(HostSkDecision, stamp) as i16);
    b.jump(JNE_X, 1, 6, 0, conflict);
    b.constant(2, HOLD_NATIVE);
    b.jump(JLE_X, 6, 2, 0, conflict);
    b.constant(2, HOLD_MANAGED);
    b.jump(JLE_X, 2, 6, 0, conflict);
    b.load(LDX_DW, 1, 0, offset_of!(HostFlowOwner, binding) as i16);
    b.jump(JNE_X, 1, 8, 0, conflict);
    b.load(LDX_DW, 1, 10, COOKIE);
    b.jump(JEQ_K, 1, 0, 0, conflict);
    b.load(
        LDX_DW,
        2,
        0,
        offset_of!(HostFlowOwner, socket_cookie) as i16,
    );
    b.jump(JNE_X, 1, 2, 0, conflict);
    remove(b, slots);
    b.jump(JNE_K, 0, 0, 0, conflict);
    b.word(OLD_STATE, 0);
    b.word(TCP_SLOT_REALM, 0);
    b.emit(ST_DW, 10, 0, TCP_SLOT, 0);
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit(
    b: &mut GatewayBuilder,
    realm: u32,
    hook: auxiliary::Ingress,
    gateway: &GatewayLoad<'_>,
    host: &HostGatewayLoad<'_>,
    finish: Target,
    drop: Target,
) -> io::Result<[Option<usize>; 2]> {
    let maps = gateway.maps;
    let arb = gateway
        .arbitration
        .ok_or_else(|| invalid_data("Host gateway requires tuple arbitration"))?;
    let meta = maps
        .host_meta_fd()
        .ok_or_else(|| invalid_data("missing Host flow metadata map"))?
        .as_raw_fd();
    let hold = maps
        .host_hold_fd()
        .ok_or_else(|| invalid_data("missing Host hold table"))?
        .as_raw_fd();
    let slots = maps
        .host_direct_tcp_fd()
        .ok_or_else(|| invalid_data("missing Host Direct TCP slots"))?
        .as_raw_fd();
    let bindings = maps
        .host_bindings_fd()
        .ok_or_else(|| invalid_data("missing Host origin gates"))?
        .as_raw_fd();
    let devices = maps
        .host_devices_fd()
        .ok_or_else(|| invalid_data("missing Host origin devices"))?
        .as_raw_fd();
    let guards = arb.guards.as_raw_fd();
    let conflict = b.target();
    let failure = b.target();
    let unlock = b.target();
    let held = b.target();
    let inserted = b.target();
    let new_flow = b.target();
    let native = b.target();
    let endpoint = b.target();
    let publish = b.target();
    let store_hold = b.target();
    let guard = b.target();
    let cached = b.target();
    let missed = b.target();
    let full = b.target();
    let record = b.target();
    let tcp_owner = b.target();
    let tcp_store = b.target();
    let tcp_failed = b.target();
    b.word(KEY, 0);
    b.word(INDEX, 1);
    for _ in 0..2 {
        b.update(guards, KEY, INDEX, 1);
        b.jump(JEQ_K, 0, 0, 0, guard);
        b.jump(JNE32_K, 0, 0, -libc::EEXIST, missed);
    }
    b.stat(maps, GatewayReason::DropHoldContention);
    b.goto(drop);
    b.bind(missed);
    b.stat(maps, GatewayReason::DropHoldUnavailable);
    b.goto(drop);
    b.bind(guard);
    b.word(GUARDED, 1);
    b.word(KEY, realm as i32);
    socket_decision(b, host, bindings, devices, realm, conflict);
    b.emit(ST_DW, 10, 0, TCP_SLOT, 0);
    b.word(TCP_SLOT_REALM, 0);
    let scan_hold = b.target();
    b.load(LDX_B, 0, 10, KEY + 44);
    b.jump(JNE_K, 0, 0, 6, scan_hold);
    for &candidate in maps.host_realms() {
        let absent = b.target();
        b.word(KEY, candidate as i32);
        b.lookup(slots, KEY);
        b.jump(JEQ_K, 0, 0, 0, absent);
        b.load(LDX_W, 1, 10, TCP_SLOT_REALM);
        b.jump(JNE_K, 1, 0, 0, conflict);
        b.store(STX_DW, 10, TCP_SLOT, 0);
        b.word(TCP_SLOT_REALM, candidate as i32);
        b.bind(absent);
    }
    b.bind(scan_hold);
    for other in maps
        .host_realms()
        .iter()
        .copied()
        .filter(|other| *other != realm)
    {
        b.word(KEY, other as i32);
        b.lookup(hold, KEY);
        b.jump(JNE_K, 0, 0, 0, held);
    }
    b.word(KEY, realm as i32);
    b.lookup(hold, KEY);
    b.jump(JNE_K, 0, 0, 0, held);
    b.load(LDX_W, 0, 10, TCP_SLOT_REALM);
    let vacant = b.target();
    b.jump(JEQ_K, 0, 0, 0, vacant);
    b.jump(JNE32_K, 0, 0, realm as i32, tcp_owner);
    b.load(LDX_W, 1, 10, PURE_SYN);
    b.jump(JEQ_K, 1, 0, 0, tcp_owner);
    b.load(LDX_W, 1, 10, MATCHED);
    b.jump(JNE_K, 1, 0, 0, tcp_owner);
    b.load(LDX_DW, 0, 10, TCP_SLOT);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    retire_reconnected_direct(b, host.binding, slots, conflict);
    b.goto(new_flow);
    b.bind(vacant);
    b.load(LDX_W, 0, 10, MATCHED);
    b.jump(JNE_K, 0, 0, 0, cached);
    b.load(LDX_B, 0, 10, KEY + 44);
    b.jump(JEQ_K, 0, 0, 17, new_flow);
    b.load(LDX_W, 0, 10, PURE_SYN);
    let syn = b.target();
    b.jump(JNE_K, 0, 0, 0, syn);
    b.word(VERDICT, VERDICT_PASS);
    b.reason(GatewayReason::PassTcpNonSynMiss, unlock);
    b.bind(syn);
    b.load(LDX_DW, 0, 10, DECISION);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.bind(new_flow);
    snapshot_identity(b, conflict);
    let call = routing_call(b, maps, hook.scratch, conflict, Some(IDENTITY));
    let stale = b.target();
    hook.after_policy(b, stale);
    let replay = gateway.dns.map(|_| b.target());
    if let Some(replay) = replay {
        b.jump(JEQ_K, 0, 0, GATEWAY_ROUTE_NEED_DNS, replay);
    }
    b.emit(ST_DW, 8, 0, 0, 0);
    b.jump(JEQ_K, 0, 0, 1, native);
    b.jump(JEQ_K, 0, 0, 0, endpoint);
    b.jump(JEQ_K, 0, 0, GATEWAY_ROUTE_NEED_DNS, endpoint);
    b.goto(conflict);
    b.bind(stale);
    b.emit(ST_DW, 8, 0, 0, 0);
    b.goto(conflict);
    let dns_call = gateway.dns.zip(replay).map(|(dns, replay)| {
        let proved = b.target();
        b.bind(replay);
        b.word(KEY, host.dns_realm as i32);
        let call = dns_shadow(b, dns, None, Some(proved), endpoint, conflict, conflict);
        b.bind(proved);
        b.word(VERDICT, VERDICT_PASS);
        b.reason(GatewayReason::PassDnsD1, publish);
        call
    });
    b.bind(native);
    b.word(VERDICT, VERDICT_PASS);
    b.reason(GatewayReason::PassD1, publish);
    b.bind(endpoint);
    b.word(VERDICT, VERDICT_ENDPOINT);
    b.reason(GatewayReason::XskNewFlow, publish);
    b.bind(publish);
    b.word(KEY, realm as i32);
    b.word(INDEX, 0);
    b.lookup(arb.control.as_raw_fd(), INDEX);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.mov(8, 0);
    ownership::issue_sequence(b, conflict);
    b.constant(1, HOLD_NATIVE);
    b.load(LDX_W, 0, 10, VERDICT);
    let tag = b.target();
    b.jump(JEQ_K, 0, 0, VERDICT_PASS, tag);
    b.constant(1, HOLD_MANAGED);
    b.bind(tag);
    b.emit(OR_X, 2, 1, 0, 0);
    b.store(STX_DW, 10, STAMP, 2);
    b.load(LDX_W, 0, 10, VERDICT);
    b.jump(JNE_K, 0, 0, VERDICT_PASS, store_hold);
    b.load(LDX_B, 0, 10, KEY + 44);
    b.jump(JEQ_K, 0, 0, 6, tcp_store);
    b.goto(store_hold);
    b.bind(cached);
    b.load(LDX_W, 0, 10, OLD_STATE);
    let restore = b.target();
    b.jump(JEQ_K, 0, 0, HOST_SK_ENDPOINT as i32, restore);
    b.word(VERDICT, VERDICT_PASS);
    b.word(REASON, GatewayReason::PassD1 as i32);
    b.goto(publish);
    b.bind(restore);
    b.load(LDX_DW, 7, 10, DECISION);
    b.jump(JEQ_K, 7, 0, 0, conflict);
    b.load(
        LDX_W,
        0,
        7,
        offset_of!(HostSkDecision, identity_present) as i16,
    );
    let absent = b.target();
    let ready = b.target();
    b.jump(JEQ_K, 0, 0, 0, absent);
    snapshot_identity(b, conflict);
    b.load(LDX_W, 0, 10, IDENTITY);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.goto(ready);
    b.bind(absent);
    b.zero(IDENTITY, size_of::<HostSkIdentity>() as i16);
    b.bind(ready);
    b.word(VERDICT, VERDICT_ENDPOINT);
    b.word(REASON, GatewayReason::XskEndpointHold as i32);
    b.goto(publish);
    b.bind(tcp_store);
    b.load(LDX_DW, 7, 10, DECISION);
    b.jump(JEQ_K, 7, 0, 0, conflict);
    b.load(LDX_DW, 0, 10, COOKIE);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.store(STX_DW, 10, TUPLE + 16, 0);
    b.constant(1, host.binding);
    let selected = b.target();
    b.load(LDX_W, 0, 10, MATCHED);
    b.jump(JEQ_K, 0, 0, 0, selected);
    b.copy(10, KEY, 7, 0, 4);
    b.load(LDX_DW, 1, 7, offset_of!(HostSkDecision, binding) as i16);
    b.bind(selected);
    b.store(STX_DW, 10, TUPLE + 24, 1);
    b.load(LDX_DW, 1, 10, STAMP);
    b.store(STX_DW, 10, TUPLE, 1);
    b.helper(5);
    b.store(STX_DW, 10, TUPLE + 8, 0);
    b.update(slots, KEY, TUPLE, 1);
    b.jump(JEQ_K, 0, 0, 0, record);
    b.jump(JNE32_K, 0, 0, -libc::EEXIST, tcp_failed);
    b.lookup(slots, KEY);
    b.jump(JEQ_K, 0, 0, 0, tcp_failed);
    b.store(STX_DW, 10, TCP_SLOT, 0);
    b.copy(10, TCP_SLOT_REALM, 10, KEY, 4);
    b.goto(tcp_owner);
    b.bind(store_hold);
    b.load(LDX_DW, 1, 10, STAMP);
    b.store(STX_DW, 10, TUPLE, 1);
    b.helper(5);
    b.store(STX_DW, 10, TUPLE + 8, 0);
    b.load(LDX_DW, 1, 10, COOKIE);
    b.store(STX_DW, 10, TUPLE + 16, 1);
    b.constant(1, host.binding);
    b.store(STX_DW, 10, TUPLE + 24, 1);
    b.update(hold, KEY, TUPLE, 1);
    b.jump(JEQ_K, 0, 0, 0, inserted);
    b.jump(JEQ32_K, 0, 0, -libc::E2BIG, full);
    b.jump(JNE32_K, 0, 0, -libc::EEXIST, failure);
    b.lookup(hold, KEY);
    b.jump(JNE_K, 0, 0, 0, held);
    b.goto(failure);
    b.bind(full);
    b.load(LDX_B, 0, 10, KEY + 44);
    b.jump(JNE_K, 0, 0, 17, failure);
    b.load(LDX_W, 0, 10, VERDICT);
    b.jump(JNE_K, 0, 0, VERDICT_PASS, failure);
    b.reason(GatewayReason::HostDirectUnrecorded, unlock);
    b.bind(inserted);
    b.load(LDX_W, 0, 10, VERDICT);
    b.jump(JEQ_K, 0, 0, VERDICT_PASS, record);
    b.load(LDX_DW, 1, 10, TUPLE + 8);
    b.store(
        STX_DW,
        10,
        HOST_META + offset_of!(HostFlowMeta, born_ns) as i16,
        1,
    );
    b.load(LDX_DW, 1, 10, STAMP);
    b.store(STX_DW, 10, HOST_META, 1);
    b.constant(1, host.binding);
    b.store(STX_DW, 10, HOST_META + 8, 1);
    b.update(meta, KEY, HOST_META, 1);
    b.jump(JEQ_K, 0, 0, 0, record);
    // A stale sidecar must never authorize this new stamp. No reader can enter until unlock.
    remove(b, hold);
    b.word(VERDICT, VERDICT_DROP);
    b.reason(GatewayReason::HostMetaInsertFailed, unlock);
    b.bind(record);
    b.load(LDX_DW, 7, 10, DECISION);
    b.jump(JEQ_K, 7, 0, 0, unlock);
    b.load(LDX_DW, 1, 10, STAMP);
    b.store(STX_DW, 7, offset_of!(HostSkDecision, stamp) as i16, 1);
    b.load(LDX_W, 0, 10, MATCHED);
    b.jump(JNE_K, 0, 0, 0, unlock);
    b.copy(7, 0, 10, KEY, 48);
    b.constant(1, host.binding);
    b.store(STX_DW, 7, offset_of!(HostSkDecision, binding) as i16, 1);
    b.imm(1, 0);
    b.load(LDX_W, 0, 10, IDENTITY);
    let missing_identity = b.target();
    b.jump(JEQ_K, 0, 0, 0, missing_identity);
    b.imm(1, 1);
    b.bind(missing_identity);
    b.store(
        STX_W,
        7,
        offset_of!(HostSkDecision, identity_present) as i16,
        1,
    );
    b.copy(
        7,
        offset_of!(HostSkDecision, disconnects) as i16,
        10,
        DISCONNECTS,
        4,
    );
    b.copy(7, offset_of!(HostSkDecision, isn) as i16, 10, ISN, 4);
    b.word(OLD_STATE, HOST_SK_DIRECT as i32);
    b.load(LDX_W, 0, 10, VERDICT);
    b.jump(JEQ_K, 0, 0, VERDICT_PASS, unlock);
    b.word(OLD_STATE, HOST_SK_ENDPOINT as i32);
    b.goto(unlock);
    b.bind(held);
    b.mov(8, 0);
    b.load(LDX_W, 1, 10, TCP_SLOT_REALM);
    b.jump(JNE_K, 1, 0, 0, conflict);
    b.load(LDX_DW, 6, 8, 0);
    b.mov(1, 6);
    b.emit(LSH_K, 1, 0, 0, 2);
    b.jump(JEQ_K, 1, 0, 0, conflict);
    b.load(LDX_W, 1, 10, MATCHED);
    let verify_hold = b.target();
    let unmatched = b.target();
    b.jump(JEQ_K, 1, 0, 0, unmatched);
    b.load(LDX_DW, 1, 10, STAMP);
    b.jump(JNE_X, 6, 1, 0, conflict);
    b.goto(verify_hold);
    b.bind(unmatched);
    b.load(LDX_B, 0, 10, KEY + 44);
    b.jump(JEQ_K, 0, 0, 17, verify_hold);
    b.load(LDX_W, 0, 10, PURE_SYN);
    b.jump(JNE_K, 0, 0, 0, conflict);
    b.load(LDX_DW, 0, 10, COOKIE);
    b.jump(JNE_K, 0, 0, 0, conflict);
    b.bind(verify_hold);
    b.mov(1, 6);
    b.emit(RSH_K, 1, 0, 0, 62);
    let held_native = b.target();
    b.jump(JEQ_K, 1, 0, 1, held_native);
    b.jump(JNE_K, 1, 0, 2, conflict);
    b.load(LDX_W, 1, 10, KEY);
    b.jump(JNE32_K, 1, 0, realm as i32, conflict);
    b.load(LDX_DW, 1, 8, offset_of!(HostFlowOwner, binding) as i16);
    b.constant(2, host.binding);
    b.jump(JNE_X, 1, 2, 0, conflict);
    b.lookup(meta, KEY);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.load(LDX_DW, 1, 0, 0);
    b.jump(JNE_X, 1, 6, 0, conflict);
    b.load(
        LDX_DW,
        1,
        8,
        offset_of!(HostFlowOwner, socket_cookie) as i16,
    );
    b.load(LDX_DW, 2, 0, offset_of!(HostFlowMeta, socket_cookie) as i16);
    b.jump(JNE_X, 1, 2, 0, conflict);
    b.load(LDX_DW, 1, 0, 8);
    b.constant(2, host.binding);
    b.jump(JNE_X, 1, 2, 0, conflict);
    let verified = b.target();
    b.load(LDX_DW, 2, 10, COOKIE);
    b.load(LDX_B, 1, 10, KEY + 44);
    b.jump(JEQ_K, 1, 0, 17, verified);
    let held_endpoint = b.target();
    b.jump(JEQ_K, 2, 0, 0, held_endpoint);
    b.bind(verified);
    b.load(LDX_DW, 1, 0, offset_of!(HostFlowMeta, socket_cookie) as i16);
    b.jump(JNE_X, 1, 2, 0, conflict);
    b.bind(held_endpoint);
    b.word(VERDICT, VERDICT_ENDPOINT);
    b.word(REASON, GatewayReason::XskEndpointHold as i32);
    let refresh = b.target();
    b.goto(refresh);
    b.bind(held_native);
    b.load(LDX_B, 1, 10, KEY + 44);
    b.jump(JNE_K, 1, 0, 17, conflict);
    b.load(LDX_DW, 7, 8, offset_of!(HostFlowOwner, binding) as i16);
    b.load(
        LDX_DW,
        1,
        8,
        offset_of!(HostFlowOwner, socket_cookie) as i16,
    );
    b.load(LDX_DW, 2, 10, COOKIE);
    b.jump(JNE_X, 1, 2, 0, conflict);
    let foreign = b.target();
    b.load(LDX_W, 3, 10, KEY);
    let local_direct = b.target();
    b.jump(JEQ32_K, 3, 0, realm as i32, local_direct);
    b.jump(JEQ_K, 2, 0, 0, conflict);
    b.goto(foreign);
    b.bind(local_direct);
    b.constant(1, host.binding);
    b.jump(JNE_X, 1, 7, 0, conflict);
    b.bind(foreign);
    b.copy(10, TUPLE, 10, KEY, 4);
    b.store(STX_DW, 10, TUPLE + 8, 7);
    require_origin_gate(b, bindings, devices, realm, conflict);
    b.word(VERDICT, VERDICT_PASS);
    b.word(REASON, GatewayReason::PassD1 as i32);
    b.bind(refresh);
    b.mov(0, 8);
    refresh_hold(b, unlock);
    b.bind(tcp_owner);
    b.copy(10, KEY, 10, TCP_SLOT_REALM, 4);
    b.load(LDX_DW, 8, 10, TCP_SLOT);
    b.jump(JEQ_K, 8, 0, 0, conflict);
    b.load(LDX_DW, 6, 8, offset_of!(HostFlowOwner, stamp) as i16);
    b.constant(2, HOLD_NATIVE);
    b.jump(JLE_X, 6, 2, 0, conflict);
    b.constant(2, HOLD_MANAGED);
    b.jump(JLE_X, 2, 6, 0, conflict);
    b.load(
        LDX_DW,
        2,
        8,
        offset_of!(HostFlowOwner, socket_cookie) as i16,
    );
    b.jump(JEQ_K, 2, 0, 0, conflict);
    b.load(LDX_DW, 7, 8, offset_of!(HostFlowOwner, binding) as i16);
    let original = b.target();
    b.load(LDX_W, 1, 10, TCP_SLOT_REALM);
    b.jump(JNE32_K, 1, 0, realm as i32, original);
    b.constant(1, host.binding);
    b.jump(JNE_X, 1, 7, 0, conflict);
    b.bind(original);
    let orphan = b.target();
    let authorized = b.target();
    b.load(LDX_DW, 1, 10, COOKIE);
    b.jump(JEQ_K, 1, 0, 0, orphan);
    b.jump(JNE_X, 1, 2, 0, conflict);
    b.load(LDX_W, 1, 10, MATCHED);
    b.jump(JEQ_K, 1, 0, 0, conflict);
    b.load(LDX_DW, 0, 10, DECISION);
    b.jump(JEQ_K, 0, 0, 0, conflict);
    b.load(LDX_DW, 1, 0, offset_of!(HostSkDecision, binding) as i16);
    b.jump(JNE_X, 1, 7, 0, conflict);
    b.load(LDX_W, 1, 0, 0);
    b.load(LDX_W, 2, 10, TCP_SLOT_REALM);
    b.jump(JNE_X, 1, 2, 0, conflict);
    b.load(LDX_DW, 1, 10, STAMP);
    b.jump(JNE_X, 1, 6, 0, conflict);
    b.goto(authorized);
    b.bind(orphan);
    b.load(LDX_W, 1, 10, PURE_SYN);
    b.jump(JNE_K, 1, 0, 0, conflict);
    b.load(LDX_W, 1, 10, TCP_SLOT_REALM);
    b.jump(JNE32_K, 1, 0, realm as i32, conflict);
    b.bind(authorized);
    b.copy(10, TUPLE, 10, KEY, 4);
    b.store(STX_DW, 10, TUPLE + 8, 7);
    require_origin_gate(b, bindings, devices, realm, conflict);
    b.word(VERDICT, VERDICT_PASS);
    b.word(REASON, GatewayReason::PassD1 as i32);
    b.mov(0, 8);
    refresh_hold(b, unlock);
    b.bind(tcp_failed);
    b.word(VERDICT, VERDICT_DROP);
    b.reason(GatewayReason::HostDirectTcpInsertFailed, unlock);
    b.bind(failure);
    b.word(VERDICT, VERDICT_DROP);
    b.reason(GatewayReason::HoldInsertFailed, unlock);
    b.bind(conflict);
    b.word(VERDICT, VERDICT_DROP);
    b.word(REASON, GatewayReason::DropHoldUnavailable as i32);
    b.bind(unlock);
    b.load(LDX_DW, 7, 10, DECISION);
    let release_guard = b.target();
    b.jump(JEQ_K, 7, 0, 0, release_guard);
    b.load(LDX_W, 1, 10, OLD_STATE);
    b.emit(ATOMIC_W, 7, 1, STATE, XCHG);
    b.bind(release_guard);
    b.load(LDX_W, 0, 10, VERDICT);
    b.jump(JNE_K, 0, 0, VERDICT_DROP, finish);
    b.copy(10, INDEX, 10, REASON, 4);
    b.stat_index(maps.stats.as_raw_fd());
    b.goto(drop);
    Ok([Some(call), dns_call])
}
