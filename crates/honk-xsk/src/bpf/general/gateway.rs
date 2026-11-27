mod auxiliary;
mod host;
pub(super) use host::build as build_host;
mod ownership;

use super::*;
use honk_ebpf_common::xdp_gateway::{
    FRAGMENT_TTL_NS, GATEWAY_DNS_BITMAP_OFFSET, GATEWAY_DNS_READY, GATEWAY_ROUTE_NEED_DNS,
    GatewayReason, HOLD_REFRESH_NS,
};
use honk_ebpf_common::{
    DATAPATH_FLAG_OFFLOAD_RULE_DIRECT, IpVersionType, L4ProtoType,
    ROUTING_INPUT_ALLOW_DIRECT_FINALITY, ROUTING_INPUT_MAC_PRESENT,
};

const LDX_DW: u8 = 0x79;
const ST_DW: u8 = 0x7a;
const STX_DW: u8 = 0x7b;
const STX_B: u8 = 0x73;
const SUB_X: u8 = 0x1f;
const JLT_X: u8 = 0xad;
const JLE_X: u8 = 0xbd;
const JLE_K: u8 = 0xb5;
const CMPXCHG: i32 = 0xf1;
const XCHG: i32 = 0xe1;
const MAX_INSNS: usize = 1_000_000;
const MAX_EXTENSION_HEADERS: usize = 8;
const MAX_EXTENSION_BYTES: i32 = 256;
const MAX_PACKET_CURSOR: i32 = 22 + 40 + MAX_EXTENSION_BYTES + 8 + 40 + MAX_EXTENSION_BYTES;
const PACKET_CURSOR_MASK: i32 = 1023;

// The fragment map preserves the original XDP verdict values across both hooks.
const VERDICT_DROP: i32 = 1;
const VERDICT_PASS: i32 = 2;
const VERDICT_ENDPOINT: i32 = 4;

const REALM: i16 = -16;
const KEY: i16 = -64;
const FRAGMENT: i16 = -112;
const VALUE: i16 = -128;
const META: i16 = -160;
const INDEX: i16 = -164;
const LOCAL: i16 = -184;
const TUPLE: i16 = -224;
const OPTS: i16 = -240;
const FRAG_STATE: i16 = -244;
const REMAIN: i16 = -248;
const DSCP: i16 = -252;
const TCP_FLAGS: i16 = -256;
const EXT_BYTES: i16 = -260;
const L2_LEN: i16 = -264;
const FULL_LEN: i16 = -268;
const IS_QUOTE: i16 = -272;
const HOP_LIMIT: i16 = -276;
const REASON: i16 = -292;
const VERDICT: i16 = -296;
const MAC: i16 = -304;
const INNER_FRAG: i16 = -308;
const INNER_REMAIN: i16 = -312;
const QUOTE_AVAILABLE: i16 = -320;
const CURSOR: i16 = -316;
const SCRATCH_INPUT: i16 = 8;
const SCRATCH_OUTPUT: i16 = 136;
const _: () = assert!(
    SCRATCH_OUTPUT as usize
        + GATEWAY_DNS_BITMAP_OFFSET
        + size_of::<honk_ebpf_common::DomainRouting>()
        <= size_of::<[u64; 64]>()
);

#[derive(Clone, Copy)]
struct Target(usize);

struct GatewayBuilder {
    program: Program,
    labels: Vec<Option<usize>>,
    jumps: Vec<(usize, Target)>,
    auxiliary: Option<auxiliary::Ingress>,
    host_broadcasts: Option<RawFd>,
}

impl GatewayBuilder {
    fn new() -> Self {
        Self {
            program: Builder::new().program,
            labels: Vec::new(),
            jumps: Vec::new(),
            auxiliary: None,
            host_broadcasts: None,
        }
    }

    fn emit(&mut self, code: u8, dst: u8, src: u8, off: i16, imm: i32) -> usize {
        let at = self.program.insns.len();
        self.program.insns.push(Insn::new(code, dst, src, off, imm));
        at
    }

    fn target(&mut self) -> Target {
        let target = Target(self.labels.len());
        self.labels.push(None);
        target
    }

    fn bind(&mut self, target: Target) {
        self.labels[target.0] = Some(self.program.insns.len());
    }

    fn jump(&mut self, code: u8, dst: u8, src: u8, imm: i32, target: Target) {
        let at = self.emit(code, dst, src, 0, imm);
        self.jumps.push((at, target));
    }

    fn goto(&mut self, target: Target) {
        self.jump(JA, 0, 0, 0, target);
    }
    fn mov(&mut self, dst: u8, src: u8) {
        self.emit(MOV_X, dst, src, 0, 0);
    }
    fn imm(&mut self, dst: u8, value: i32) {
        self.emit(MOV_K, dst, 0, 0, value);
    }
    fn add(&mut self, dst: u8, value: i32) {
        self.emit(ADD_K, dst, 0, 0, value);
    }
    fn load(&mut self, code: u8, dst: u8, base: u8, offset: i16) {
        self.emit(code, dst, base, offset, 0);
    }
    fn store(&mut self, code: u8, base: u8, offset: i16, src: u8) {
        self.emit(code, base, src, offset, 0);
    }
    fn word(&mut self, offset: i16, value: i32) {
        self.emit(ST_W, 10, 0, offset, value);
    }
    fn address(&mut self, dst: u8, offset: i16) {
        self.mov(dst, 10);
        self.add(dst, i32::from(offset));
    }
    fn helper(&mut self, id: i32) {
        self.emit(CALL, 0, 0, 0, id);
    }
    fn map(&mut self, dst: u8, fd: RawFd) {
        self.emit(LD_MAP, dst, 1, 0, fd);
        self.emit(0, 0, 0, 0, 0);
    }
    fn constant(&mut self, dst: u8, value: u64) {
        self.emit(LD_MAP, dst, 0, 0, value as u32 as i32);
        self.emit(0, 0, 0, 0, (value >> 32) as u32 as i32);
    }
    fn lookup(&mut self, fd: RawFd, key: i16) {
        self.map(1, fd);
        self.address(2, key);
        self.helper(1);
    }
    fn update(&mut self, fd: RawFd, key: i16, value: i16, flags: i32) {
        self.map(1, fd);
        self.address(2, key);
        self.address(3, value);
        self.imm(4, flags);
        self.helper(2);
    }
    fn copy(&mut self, dst: u8, dst_offset: i16, src: u8, src_offset: i16, bytes: i16) {
        for word in (0..bytes).step_by(4) {
            self.load(LDX_W, 0, src, src_offset + word);
            self.store(STX_W, dst, dst_offset + word, 0);
        }
    }
    fn zero(&mut self, offset: i16, bytes: i16) {
        for word in (0..bytes).step_by(4) {
            self.word(offset + word, 0);
        }
    }
    fn load_remaining(&mut self, dst: u8, offset: i16, bad: Target) {
        self.load(LDX_W, dst, 10, offset);
        self.jump(JGT_K, dst, 0, 0xffff, bad);
        // IPv4 total_len, IPv6 payload_len and their checked suffixes all fit in 16 bits.
        self.emit(AND_K, dst, 0, 0, 0xffff);
    }

    fn rebase_cursor(&mut self, bad: Target) {
        self.jump(JGT_K, 0, 0, MAX_PACKET_CURSOR, bad);
        self.emit(AND_K, 0, 0, 0, PACKET_CURSOR_MASK);
        self.store(STX_W, 10, CURSOR, 0);
        let data = if self.auxiliary.is_some() {
            auxiliary::SKB_DATA
        } else {
            0
        };
        self.load(LDX_W, 6, 9, data);
        self.emit(ADD_X, 6, 0, 0, 0);
        if self.auxiliary.is_none() {
            self.jump(JGT_X, 6, 7, 0, bad);
        }
        for register in 0..=4 {
            self.imm(register, 0);
        }
    }

    fn load_cursor(&mut self, dst: u8, bad: Target) {
        self.load(LDX_W, dst, 10, CURSOR);
        self.jump(JGT_K, dst, 0, MAX_PACKET_CURSOR, bad);
        self.emit(AND_K, dst, 0, 0, PACKET_CURSOR_MASK);
    }

    fn advance_cursor(&mut self, length: u8, bad: Target) {
        self.load_cursor(0, bad);
        self.emit(ADD_X, 0, length, 0, 0);
        self.rebase_cursor(bad);
    }

    fn bound(&mut self, bytes: i32, bad: Target) {
        self.mov(0, 6);
        self.add(0, bytes);
        if self.auxiliary.is_some() {
            self.pull_prefix(bytes, bad);
        } else {
            self.jump(JGT_X, 0, 7, 0, bad);
        }
    }

    fn pull_prefix(&mut self, bytes: i32, bad: Target) {
        let linear = self.target();
        self.jump(JLE_X, 0, 7, 0, linear);
        // The cursor bound is independent of any IP length declared on the wire.
        self.load_cursor(2, bad);
        self.add(2, bytes);
        self.load(LDX_W, 1, 10, FULL_LEN);
        self.jump(JGT_X, 2, 1, 0, bad);
        self.mov(1, 9);
        self.helper(auxiliary::SKB_PULL_DATA);
        self.jump(JNE_K, 0, 0, 0, bad);
        self.load(LDX_W, 7, 9, auxiliary::SKB_DATA_END);
        self.load(LDX_W, 0, 10, CURSOR);
        self.rebase_cursor(bad);
        self.mov(0, 6);
        self.add(0, bytes);
        self.jump(JGT_X, 0, 7, 0, bad);
        self.bind(linear);
    }

    fn prefix(&mut self, bytes: i32, remaining: i16, bad: Target) {
        self.load_remaining(0, remaining, bad);
        self.jump(JLT_K, 0, 0, bytes, bad);
        self.bound(bytes, bad);
    }
    fn stat(&mut self, maps: &GatewayMaps, reason: GatewayReason) {
        self.word(INDEX, reason as i32);
        self.stat_index(maps.stats.as_raw_fd());
    }
    fn stat_index(&mut self, fd: RawFd) {
        let absent = self.target();
        self.lookup(fd, INDEX);
        self.jump(JEQ_K, 0, 0, 0, absent);
        self.imm(1, 1);
        self.emit(ATOMIC_ADD_DW, 0, 1, 0, 0);
        self.bind(absent);
    }
    fn reason(&mut self, reason: GatewayReason, verdict: Target) {
        self.word(REASON, reason as i32);
        self.goto(verdict);
    }
    fn finish(
        mut self,
        routing: &[aya_obj::generated::bpf_insn],
        calls: impl Iterator<Item = usize>,
    ) -> io::Result<Program> {
        validate_routing(routing)?;
        let start = self.program.insns.len();
        let count = start
            .checked_add(routing.len())
            .filter(|n| *n <= MAX_INSNS)
            .ok_or_else(|| invalid_data("gateway instruction count exceeds limit"))?;
        for call in calls {
            self.program.insns[call].imm = i32::try_from(
                start
                    .checked_sub(call + 1)
                    .ok_or_else(|| invalid_data("invalid gateway routing call"))?,
            )
            .map_err(|_| invalid_data("gateway routing call exceeds i32"))?;
        }
        for instruction in routing {
            self.program.insns.push(Insn::new(
                instruction.code,
                instruction.dst_reg(),
                instruction.src_reg(),
                instruction.off,
                instruction.imm,
            ));
        }
        for (at, target) in self.jumps {
            let target = self
                .labels
                .get(target.0)
                .and_then(|value| *value)
                .ok_or_else(|| invalid_data("unresolved gateway branch"))?;
            let offset = i64::try_from(target)
                .ok()
                .zip(i64::try_from(at).ok())
                .and_then(|(target, at)| i16::try_from(target - at - 1).ok())
                .ok_or_else(|| invalid_data("gateway branch exceeds i16"))?;
            self.program.insns[at].off = offset;
        }
        self.program.len = count;
        Ok(self.program)
    }
}

fn validate_routing(routing: &[aya_obj::generated::bpf_insn]) -> io::Result<()> {
    if routing.is_empty() || routing.len() > MAX_INSNS {
        return Err(invalid_data("empty or oversized gateway routing function"));
    }
    let mut continuation = vec![false; routing.len()];
    let mut at = 0;
    while at < routing.len() {
        let instruction = &routing[at];
        if instruction.code == LD_MAP {
            let next = at + 1;
            if next >= routing.len() || routing[next].code != 0 || instruction.src_reg() > 2 {
                return Err(invalid_data("malformed gateway routing immediate"));
            }
            if instruction.src_reg() != 0 && instruction.imm < 0 {
                return Err(invalid_data("invalid gateway routing map FD"));
            }
            continuation[next] = true;
            at += 2;
        } else {
            at += 1;
        }
    }
    for (at, instruction) in routing.iter().enumerate() {
        if continuation[at] {
            continue;
        }
        if instruction.dst_reg() > 10 || instruction.src_reg() > 10 {
            return Err(invalid_data("invalid gateway routing register"));
        }
        if instruction.code == CALL {
            if instruction.src_reg() != 0 || instruction.off != 0 || instruction.imm != 1 {
                return Err(invalid_data(
                    "gateway routing may only call map lookup helpers",
                ));
            }
        } else if matches!(instruction.code & 7, 5 | 6) && instruction.code != EXIT {
            let target = (at as i64)
                .checked_add(1)
                .and_then(|at| at.checked_add(i64::from(instruction.off)))
                .and_then(|target| usize::try_from(target).ok());
            if target.is_none_or(|target| target >= routing.len() || continuation[target]) {
                return Err(invalid_data("gateway routing branch outside function"));
            }
        }
    }
    Ok(())
}

fn layer2(
    b: &mut GatewayBuilder,
    capture: &GeneralCapture,
    maps: &GatewayMaps,
    vlan_kfunc: Option<u32>,
    bad: Target,
    unknown: Target,
) {
    b.zero(REALM, 16);
    b.zero(META, METADATA_LEN as i16);
    b.word(IS_QUOTE, 0);
    b.word(FRAG_STATE, 0);
    b.word(L2_LEN, 14);
    b.word(REALM, capture.authority.ifindex as i32);
    b.emit(ST_H, 10, 0, META, i32::from(METADATA_VERSION));
    b.emit(ST_H, 10, 0, META + 2, METADATA_LEN as i32);
    b.load(LDX_W, 0, 9, 16);
    b.store(STX_W, 10, META + 8, 0);
    b.word(META + 12, capture.authority.ifindex as i32);
    if let Some(kfunc) = vlan_kfunc {
        b.word(VALUE, 0);
        b.word(META + 4, RX_VLAN_CHECKED as i32);
        b.mov(1, 9);
        b.address(2, VALUE);
        b.address(3, VALUE + 2);
        b.emit(CALL, 0, 2, 0, kfunc as i32);
        let absent = b.target();
        b.jump(JEQ32_K, 0, 0, -libc::ENODATA, absent);
        b.jump(JNE32_K, 0, 0, 0, bad);
        b.load(LDX_H, 0, 10, VALUE);
        b.emit(BE16, 0, 0, 0, 16);
        let valid = b.target();
        b.jump(JEQ_K, 0, 0, 0x8100, valid);
        b.jump(JNE_K, 0, 0, 0x88a8, bad);
        b.bind(valid);
        b.store(STX_H, 10, VALUE, 0);
        b.word(META + 4, (RX_VLAN_CHECKED | HIDDEN_VLAN) as i32);
        b.bind(absent);
    }
    b.load(LDX_W, 6, 9, 0);
    b.load(LDX_W, 7, 9, 4);
    b.bound(14, bad);
    b.load(LDX_W, 0, 6, 6);
    b.store(STX_W, 10, MAC, 0);
    b.load(LDX_H, 0, 6, 10);
    b.store(STX_H, 10, MAC + 4, 0);
    b.load(LDX_B, 0, 6, 0);
    b.emit(AND_K, 0, 0, 0, 1);
    b.store(STX_W, 10, INDEX, 0);
    b.load(LDX_H, 5, 6, 12);
    b.emit(BE16, 5, 0, 0, 16);
    b.add(6, 14);
    for tag in 0..2 {
        let tagged = b.target();
        let next = b.target();
        b.jump(JEQ_K, 5, 0, 0x8100, tagged);
        b.jump(JNE_K, 5, 0, 0x88a8, next);
        b.bind(tagged);
        b.bound(4, bad);
        b.store(STX_H, 10, META + 24 + tag * 2, 5);
        b.load(LDX_H, 0, 6, 0);
        b.emit(BE16, 0, 0, 0, 16);
        b.store(STX_H, 10, META + 20 + tag * 2, 0);
        b.load(LDX_H, 5, 6, 2);
        b.emit(BE16, 5, 0, 0, 16);
        b.add(6, 4);
        b.word(L2_LEN, 18 + i32::from(tag) * 4);
        b.emit(ST_H, 10, 0, META + 28, i32::from(tag) + 1);
        b.emit(ST_H, 10, 0, META + 30, i32::from(tag) + 1);
        b.load(LDX_W, 0, 10, META + 4);
        b.emit(OR_K, 0, 0, 0, INLINE_VLAN as i32);
        b.store(STX_W, 10, META + 4, 0);
        b.bind(next);
    }
    b.jump(JEQ_K, 5, 0, 0x8100, unknown);
    b.jump(JEQ_K, 5, 0, 0x88a8, unknown);
    b.load(LDX_W, 0, 10, L2_LEN);
    b.store(STX_H, 10, META + 16, 0);
    b.store(STX_H, 10, META + 18, 5);
    let no_hidden = b.target();
    b.load(LDX_W, 0, 10, META + 4);
    b.emit(AND_K, 0, 0, 0, HIDDEN_VLAN as i32);
    b.jump(JEQ_K, 0, 0, 0, no_hidden);
    b.load(LDX_H, 0, 10, META + 28);
    b.jump(JGT_K, 0, 0, 1, unknown);
    for offset in [META + 20, META + 24] {
        b.load(LDX_H, 0, 10, offset);
        b.store(STX_H, 10, offset + 2, 0);
    }
    b.load(LDX_H, 0, 10, VALUE);
    b.store(STX_H, 10, META + 24, 0);
    b.load(LDX_H, 0, 10, VALUE + 2);
    b.store(STX_H, 10, META + 20, 0);
    b.load(LDX_H, 0, 10, META + 28);
    b.add(0, 1);
    b.store(STX_H, 10, META + 28, 0);
    b.bind(no_hidden);
    b.load(LDX_H, 0, 10, META + 28);
    b.store(STX_W, 10, REALM + 4, 0);
    for tag in 0..2 {
        b.load(LDX_H, 0, 10, META + 24 + tag * 2);
        b.store(STX_H, 10, REALM + 8 + tag * 2, 0);
        b.load(LDX_H, 0, 10, META + 20 + tag * 2);
        b.emit(AND_K, 0, 0, 0, 4095);
        b.store(STX_H, 10, REALM + 12 + tag * 2, 0);
    }
    // Keep the EtherType and group bit across the realm helper.
    b.store(STX_W, 10, TCP_FLAGS, 5);
    b.load(LDX_W, 0, 10, INDEX);
    b.store(STX_W, 10, DSCP, 0);
    b.lookup(maps.realms.as_raw_fd(), REALM);
    b.jump(JEQ_K, 0, 0, 0, unknown);
    b.load(LDX_W, 0, 0, 0);
    b.store(STX_W, 10, KEY, 0);
    b.store(STX_W, 10, FRAGMENT, 0);
    b.load(LDX_W, 5, 10, TCP_FLAGS);
}

struct ParseTargets {
    bad: Target,
    later: Target,
    done: Target,
    pass: Target,
    drop: Target,
}

fn parse_ip(
    b: &mut GatewayBuilder,
    quote: bool,
    ipv6: bool,
    broadcasts: &[std::net::Ipv4Addr],
    targets: &ParseTargets,
) {
    let bad = targets.bad;
    let state = if quote { INNER_FRAG } else { FRAG_STATE };
    let remaining = if quote { INNER_REMAIN } else { REMAIN };
    // A quoted walk starts only after the outer walk has completed.
    let ext_bytes = EXT_BYTES;
    if !quote {
        b.load(LDX_W, 0, 10, L2_LEN);
        b.rebase_cursor(bad);
    }
    b.word(state, 0);
    if ipv6 {
        b.word(ext_bytes, 0);
        if quote {
            b.load_remaining(0, QUOTE_AVAILABLE, bad);
            b.jump(JLT_K, 0, 0, 40, bad);
        }
        b.bound(40, bad);
        b.load(LDX_B, 0, 6, 0);
        b.emit(AND_K, 0, 0, 0, 0xf0);
        b.jump(JNE_K, 0, 0, 0x60, bad);
        b.word(KEY + 4, 6);
        for (src, dst) in if quote {
            [(24, 8), (8, 24)]
        } else {
            [(8, 8), (24, 24)]
        } {
            b.copy(10, KEY + dst, 6, src, 16);
        }
        b.load(LDX_H, 0, 6, 4);
        b.emit(BE16, 0, 0, 0, 16);
        b.emit(AND_K, 0, 0, 0, 0xffff);
        b.store(STX_W, 10, remaining, 0);
        if quote {
            b.load_remaining(1, QUOTE_AVAILABLE, bad);
            b.jump(JLT_K, 1, 0, 40, bad);
            b.add(1, -40);
            b.jump(JGT_K, 1, 0, 0xffff, bad);
            b.emit(AND_K, 1, 0, 0, 0xffff);
            let declared = b.target();
            b.jump(JLE_X, 0, 1, 0, declared);
            b.store(STX_W, 10, remaining, 1);
            b.bind(declared);
        }
        if !quote {
            b.add(0, 40);
            check_packet_length(b, bad);
            b.load(LDX_H, 0, 6, 0);
            b.emit(BE16, 0, 0, 0, 16);
            b.emit(RSH_K, 0, 0, 0, 6);
            b.emit(AND_K, 0, 0, 0, 63);
            b.store(STX_W, 10, DSCP, 0);
            b.load(LDX_B, 0, 6, 7);
            b.store(STX_W, 10, HOP_LIMIT, 0);
            b.copy(10, FRAGMENT + 4, 10, KEY + 4, 36);
            b.word(FRAGMENT + 44, 0);
            for offset in [8, 24] {
                let other = b.target();
                let prefix = honk_ebpf_common::DAE0_IPV6_PREFIX_HI;
                b.load(LDX_W, 0, 6, offset);
                b.jump(
                    JNE32_K,
                    0,
                    0,
                    u32::from_be((prefix >> 32) as u32) as i32,
                    other,
                );
                b.load(LDX_W, 0, 6, offset + 4);
                b.jump(
                    JEQ32_K,
                    0,
                    0,
                    u32::from_be(prefix as u32) as i32,
                    if b.auxiliary.is_some() {
                        targets.pass
                    } else {
                        targets.drop
                    },
                );
                b.bind(other);
            }
            if b.auxiliary.is_some() {
                auxiliary::special_ipv6(b, targets.pass);
            }
        }
        b.load(LDX_B, 5, 6, 6);
        b.imm(2, 40);
        b.advance_cursor(2, bad);
        for _ in 0..MAX_EXTENSION_HEADERS {
            let options = b.target();
            let auth = b.target();
            let fragment = b.target();
            let advance = b.target();
            let next = b.target();
            for protocol in [0, 43, 60] {
                b.jump(JEQ_K, 5, 0, protocol, options);
            }
            b.jump(JEQ_K, 5, 0, 51, auth);
            b.jump(JEQ_K, 5, 0, 44, fragment);
            b.goto(targets.done);
            b.bind(options);
            b.prefix(2, remaining, bad);
            b.load(LDX_B, 2, 6, 1);
            b.add(2, 1);
            b.emit(LSH_K, 2, 0, 0, 3);
            b.goto(advance);
            b.bind(auth);
            b.prefix(2, remaining, bad);
            b.load(LDX_B, 2, 6, 1);
            b.add(2, 2);
            b.emit(LSH_K, 2, 0, 0, 2);
            b.goto(advance);
            b.bind(fragment);
            b.prefix(8, remaining, bad);
            if b.host_broadcasts.is_some() {
                b.load(LDX_B, 0, 6, 0);
                b.store(STX_W, 10, FRAGMENT + 44, 0);
            }
            b.load(LDX_W, 0, 10, ext_bytes);
            b.emit(AND_K, 0, 0, 0, 511);
            b.jump(JGT_K, 0, 0, MAX_EXTENSION_BYTES - 8, bad);
            b.load(LDX_W, 0, 10, state);
            b.jump(JSET_K, 0, 0, 4, bad);
            b.word(state, 4);
            if !quote {
                b.load(LDX_W, 0, 6, 4);
                b.store(STX_W, 10, FRAGMENT + 40, 0);
            }
            b.load(LDX_H, 0, 6, 2);
            b.emit(BE16, 0, 0, 0, 16);
            b.jump(JSET_K, 0, 0, 6, bad);
            let first = b.target();
            b.mov(1, 0);
            b.emit(AND_K, 1, 0, 0, 0xfff8);
            b.jump(JEQ_K, 1, 0, 0, first);
            b.word(state, 6);
            b.goto(targets.later);
            b.bind(first);
            let atomic = b.target();
            b.jump(JEQ_K, 0, 0, 0, atomic);
            b.emit(AND_K, 0, 0, 0, 1);
            b.jump(JEQ_K, 0, 0, 0, bad);
            b.word(state, 5);
            b.bind(atomic);
            b.imm(2, 8);
            b.bind(advance);
            b.jump(JGT_K, 2, 0, MAX_EXTENSION_BYTES, bad);
            b.load(LDX_W, 0, 10, ext_bytes);
            b.emit(AND_K, 0, 0, 0, 511);
            b.emit(ADD_X, 0, 2, 0, 0);
            b.jump(JGT_K, 0, 0, MAX_EXTENSION_BYTES, bad);
            b.emit(AND_K, 0, 0, 0, 511);
            b.store(STX_W, 10, ext_bytes, 0);
            b.load_remaining(0, remaining, bad);
            b.jump(JLT_X, 0, 2, 0, bad);
            b.emit(SUB_X, 0, 2, 0, 0);
            b.jump(JGT_K, 0, 0, 0xffff, bad);
            b.emit(AND_K, 0, 0, 0, 0xffff);
            b.store(STX_W, 10, remaining, 0);
            b.load(LDX_B, 5, 6, 0);
            b.advance_cursor(2, bad);
            b.goto(next);
            b.bind(next);
        }
        for protocol in [0, 43, 60, 51, 44] {
            b.jump(JEQ_K, 5, 0, protocol, bad);
        }
        b.goto(targets.done);
    } else {
        if quote {
            b.load_remaining(0, QUOTE_AVAILABLE, bad);
            b.jump(JLT_K, 0, 0, 20, bad);
        }
        b.bound(20, bad);
        b.load(LDX_B, 0, 6, 0);
        b.mov(2, 0);
        b.emit(AND_K, 0, 0, 0, 0xf0);
        b.jump(JNE_K, 0, 0, 0x40, bad);
        b.emit(AND_K, 2, 0, 0, 15);
        b.jump(JLT_K, 2, 0, 5, bad);
        b.emit(LSH_K, 2, 0, 0, 2);
        if b.auxiliary.is_none() {
            b.mov(0, 6);
            b.emit(ADD_X, 0, 2, 0, 0);
            b.jump(JGT_X, 0, 7, 0, bad);
        }
        b.load(LDX_H, 0, 6, 2);
        b.emit(BE16, 0, 0, 0, 16);
        b.emit(AND_K, 0, 0, 0, 0xffff);
        b.jump(JLT_X, 0, 2, 0, bad);
        b.mov(3, 0);
        b.emit(SUB_X, 3, 2, 0, 0);
        b.jump(JGT_K, 3, 0, 0xffff, bad);
        b.emit(AND_K, 3, 0, 0, 0xffff);
        b.store(STX_W, 10, remaining, 3);
        if quote {
            b.load_remaining(1, QUOTE_AVAILABLE, bad);
            b.jump(JLT_X, 1, 2, 0, bad);
            b.emit(SUB_X, 1, 2, 0, 0);
            b.jump(JGT_K, 1, 0, 0xffff, bad);
            b.emit(AND_K, 1, 0, 0, 0xffff);
            let declared = b.target();
            b.jump(JLE_X, 3, 1, 0, declared);
            b.store(STX_W, 10, remaining, 1);
            b.bind(declared);
        }
        if !quote {
            check_packet_length(b, bad);
        }
        b.word(KEY + 4, 4);
        for (src, dst) in if quote {
            [(16, 8), (12, 24)]
        } else {
            [(12, 8), (16, 24)]
        } {
            b.emit(ST_DW, 10, 0, KEY + dst, 0);
            b.word(KEY + dst + 8, u32::from_ne_bytes([0, 0, 255, 255]) as i32);
            b.load(LDX_W, 0, 6, src);
            b.store(STX_W, 10, KEY + dst + 12, 0);
        }
        b.load(LDX_B, 5, 6, 9);
        b.store(STX_W, 10, KEY + 44, 5);
        if !quote {
            b.load(LDX_B, 0, 6, 1);
            b.emit(RSH_K, 0, 0, 0, 2);
            b.store(STX_W, 10, DSCP, 0);
            b.copy(10, FRAGMENT + 4, 10, KEY + 4, 36);
            b.store(STX_W, 10, FRAGMENT + 44, 5);
            b.load(LDX_H, 0, 6, 4);
            b.store(STX_W, 10, FRAGMENT + 40, 0);
            for offset in [12, 16] {
                b.load(LDX_H, 0, 6, offset);
                if b.host_broadcasts.is_some() {
                    b.jump(JEQ_K, 0, 0, u16::from_be(0xa9fe) as i32, targets.pass);
                }
                b.jump(
                    JEQ_K,
                    0,
                    0,
                    u16::from_be((honk_ebpf_common::DAE0_IPV4_NET >> 16) as u16) as i32,
                    if b.auxiliary.is_some() {
                        targets.pass
                    } else {
                        targets.drop
                    },
                );
            }
            if b.auxiliary.is_some() {
                special_ipv4(b, broadcasts, targets.pass);
                if let Some(root) = b.host_broadcasts {
                    // Preserve the checked IHL and reload the saved next protocol
                    // after the lookup clobbers argument registers.
                    b.mov(8, 2);
                    b.word(INDEX, 0);
                    b.lookup(root, INDEX);
                    b.jump(JEQ_K, 0, 0, 0, bad);
                    b.mov(1, 0);
                    b.address(2, KEY + 36);
                    b.helper(1);
                    b.jump(JNE_K, 0, 0, 0, targets.pass);
                    b.mov(2, 8);
                    b.load(LDX_W, 5, 10, KEY + 44);
                }
            }
        }
        b.load(LDX_H, 0, 6, 6);
        b.emit(BE16, 0, 0, 0, 16);
        b.jump(JSET_K, 0, 0, 0x8000, bad);
        b.mov(1, 0);
        b.emit(AND_K, 1, 0, 0, 0x1fff);
        let first = b.target();
        b.jump(JEQ_K, 1, 0, 0, first);
        b.word(state, 2);
        b.goto(targets.later);
        b.bind(first);
        let whole = b.target();
        b.jump(JSET_K, 0, 0, 0x2000, whole);
        let unfragmented = b.target();
        b.goto(unfragmented);
        b.bind(whole);
        b.word(state, 1);
        b.bind(unfragmented);
        if !quote && b.auxiliary.is_none() {
            special_ipv4(b, broadcasts, targets.pass);
        }
        b.advance_cursor(2, bad);
        b.goto(targets.done);
    }
}

fn special_ipv4(b: &mut GatewayBuilder, broadcasts: &[Ipv4Addr], pass: Target) {
    b.load(LDX_W, 0, 6, 16);
    b.jump(JEQ_K, 0, 0, 0, pass);
    b.jump(JEQ32_K, 0, 0, -1, pass);
    for address in broadcasts {
        b.jump(
            JEQ32_K,
            0,
            0,
            u32::from_ne_bytes(address.octets()) as i32,
            pass,
        );
    }
    b.load(LDX_B, 0, 6, 16);
    b.emit(AND_K, 0, 0, 0, 0xf0);
    b.jump(JEQ_K, 0, 0, 0xe0, pass);
}

fn check_packet_length(b: &mut GatewayBuilder, bad: Target) {
    b.load(LDX_W, 1, 10, FULL_LEN);
    b.load(LDX_W, 4, 10, L2_LEN);
    b.emit(SUB_X, 1, 4, 0, 0);
    if b.auxiliary.is_some() {
        b.jump(JNE_X, 0, 1, 0, bad);
    } else {
        b.jump(JGT_X, 0, 1, 0, bad);
    }
}

fn refresh_hold(b: &mut GatewayBuilder, done: Target) {
    b.mov(8, 0);
    b.helper(5);
    b.mov(2, 0);
    b.load(LDX_DW, 0, 8, 8);
    b.jump(JLE_X, 2, 0, 0, done);
    b.mov(1, 2);
    b.emit(SUB_X, 1, 0, 0, 0);
    b.jump(JLE_K, 1, 0, HOLD_REFRESH_NS as i32, done);
    b.emit(ATOMIC_ADD_DW, 8, 2, 8, CMPXCHG);
    b.goto(done);
}

fn conntrack(
    b: &mut GatewayBuilder,
    ct: &ConntrackKfuncs,
    miss: Target,
    error: Target,
    original: Target,
    reply: Target,
) {
    lookup_conntrack(b, ct, false);
    let missing = b.target();
    b.jump(JEQ_K, 0, 0, 0, missing);
    b.mov(1, 0);
    b.emit(CALL, 0, 2, ct.release_offset, ct.release as i32);
    b.load(LDX_B, 0, 10, OPTS + 9);
    b.jump(JEQ_K, 0, 0, 0, original);
    b.jump(JEQ_K, 0, 0, 1, reply);
    b.goto(error);
    b.bind(missing);
    b.load(LDX_W, 0, 10, OPTS + 4);
    b.jump(JEQ32_K, 0, 0, -libc::ENOENT, miss);
    b.goto(error);
}

fn lookup_conntrack(b: &mut GatewayBuilder, ct: &ConntrackKfuncs, reverse: bool) {
    b.zero(TUPLE, 36);
    b.zero(OPTS, 16);
    b.word(OPTS, -1);
    b.load(LDX_B, 0, 10, KEY + 44);
    b.store(STX_B, 10, OPTS + 8, 0);
    let ipv6 = b.target();
    let ready = b.target();
    b.load(LDX_W, 0, 10, KEY + 4);
    b.jump(JEQ_K, 0, 0, 6, ipv6);
    let (src, dst) = if reverse { (24, 8) } else { (8, 24) };
    b.copy(10, TUPLE, 10, KEY + src + 12, 4);
    b.copy(10, TUPLE + 4, 10, KEY + dst + 12, 4);
    copy_ct_ports(b, TUPLE + 8, reverse);
    b.imm(3, 12);
    b.goto(ready);
    b.bind(ipv6);
    b.copy(10, TUPLE, 10, KEY + src, 16);
    b.copy(10, TUPLE + 16, 10, KEY + dst, 16);
    copy_ct_ports(b, TUPLE + 32, reverse);
    b.imm(3, 36);
    b.bind(ready);
    b.mov(1, 9);
    b.address(2, TUPLE);
    b.address(4, OPTS);
    b.imm(5, 16);
    b.emit(CALL, 0, 2, ct.lookup_offset, ct.lookup as i32);
}

fn copy_ct_ports(b: &mut GatewayBuilder, output: i16, reverse: bool) {
    if reverse {
        for (from, to) in [(42, 0), (40, 2)] {
            b.load(LDX_H, 0, 10, KEY + from);
            b.store(STX_H, 10, output + to, 0);
        }
    } else {
        b.copy(10, output, 10, KEY + 40, 4);
    }
}

fn release_dns_scratch(b: &mut GatewayBuilder, double_exchange: bool) {
    b.imm(1, 0);
    if double_exchange {
        // Hold busy across both exchanges. XCHG returns the old value in its source register.
        b.imm(2, 1);
        b.emit(ATOMIC_ADD_DW, 8, 2, 0, XCHG);
    }
    b.emit(ATOMIC_ADD_DW, 8, 1, 0, XCHG);
}

fn skip_incomplete_udp(b: &mut GatewayBuilder, miss: Target) {
    let eligible = b.target();
    b.load(LDX_W, 0, 10, FRAG_STATE);
    b.jump(JEQ_K, 0, 0, 0, eligible);
    b.load(LDX_B, 1, 10, KEY + 44);
    b.jump(JNE_K, 1, 0, 17, eligible);
    // Only an IPv6 atomic fragment header describes a complete fragmented-form datagram.
    b.jump(JNE_K, 0, 0, 4, miss);
    b.bind(eligible);
}

fn dns_shadow(
    b: &mut GatewayBuilder,
    dns: &crate::GatewayDnsMaps,
    shadow_stats: Option<&GatewayMaps>,
    qualified: Option<Target>,
    new_flow: Target,
    bad: Target,
    stale: Target,
) -> usize {
    // CT has released its reference; its tuple buffer is now private stack space for the DNS key.
    let miss = b.target();
    if qualified.is_some() {
        skip_incomplete_udp(b, miss);
    }
    b.lookup(dns.epochs.as_raw_fd(), KEY);
    b.jump(JEQ_K, 0, 0, 0, miss);
    b.load(LDX_DW, 1, 0, 0);
    b.jump(JEQ_K, 1, 0, 0, miss);
    b.store(STX_DW, 10, TUPLE, 1);
    b.load(LDX_W, 0, 10, KEY);
    b.store(STX_W, 10, TUPLE + 8, 0);
    b.word(TUPLE + 12, 0);
    b.copy(10, TUPLE + 16, 10, KEY + 24, 16);
    b.lookup(dns.facts.as_raw_fd(), TUPLE);
    b.jump(JEQ_K, 0, 0, 0, miss);
    b.mov(1, 0);
    b.load(LDX_DW, 7, 1, 0);
    b.copy(
        8,
        SCRATCH_OUTPUT + GATEWAY_DNS_BITMAP_OFFSET as i16,
        1,
        8,
        32,
    );
    // R7 is callee-saved and contains the copied deadline. Neither read borrows a hash row again.
    b.mov(1, 8);
    b.add(1, i32::from(SCRATCH_INPUT));
    b.mov(2, 8);
    b.add(2, i32::from(SCRATCH_OUTPUT));
    b.imm(3, GATEWAY_DNS_READY);
    let call = b.emit(CALL, 0, 1, 0, 0);
    release_dns_scratch(b, cfg!(target_arch = "aarch64"));
    if let Some(auxiliary) = b.auxiliary {
        auxiliary.after_policy(b, stale);
    }
    b.jump(JEQ_K, 0, 0, 0, new_flow);
    b.jump(JNE_K, 0, 0, 1, bad);
    // After the barrier only the invocation's stack, copied deadline, and independent epoch are live.
    b.lookup(dns.epochs.as_raw_fd(), KEY);
    b.jump(JEQ_K, 0, 0, 0, new_flow);
    b.load(LDX_DW, 0, 0, 0);
    b.load(LDX_DW, 1, 10, TUPLE);
    b.jump(JNE_X, 0, 1, 0, new_flow);
    b.helper(5);
    b.jump(JLE_X, 7, 0, 0, new_flow);
    if let Some(qualified) = qualified {
        b.goto(qualified);
    } else {
        if let Some(maps) = shadow_stats {
            b.stat(maps, GatewayReason::WouldPassDns);
        }
        b.goto(new_flow);
    }
    b.bind(miss);
    b.emit(ST_DW, 8, 0, 0, 0);
    b.goto(new_flow);
    call
}

fn routing_call(
    b: &mut GatewayBuilder,
    maps: &GatewayMaps,
    scratch: RawFd,
    classify_bad: Target,
    identity: Option<i16>,
) -> usize {
    b.stat(maps, GatewayReason::D1Evaluated);
    b.word(INDEX, 0);
    b.lookup(scratch, INDEX);
    b.jump(JEQ_K, 0, 0, 0, classify_bad);
    b.mov(8, 0);
    b.imm(0, 0);
    b.imm(1, 1);
    b.emit(ATOMIC_ADD_DW, 8, 1, 0, CMPXCHG);
    b.jump(JNE_K, 0, 0, 0, classify_bad);
    // Only cold classification initializes the canonical input. The callee owns output initialization.
    for offset in (0..128).step_by(4) {
        b.emit(ST_W, 8, 0, SCRATCH_INPUT + offset, 0);
    }
    b.copy(8, SCRATCH_INPUT, 10, KEY + 8, 32);
    if b.auxiliary.is_none() {
        for half in 0..3 {
            b.load(LDX_H, 0, 10, MAC + half * 2);
            b.store(STX_H, 8, SCRATCH_INPUT + 42 + half * 2, 0);
        }
    }
    if let Some(identity) = identity {
        b.copy(
            8,
            SCRATCH_INPUT + 48,
            10,
            identity + 8,
            honk_ebpf_common::ROUTING_PROCESS_MAX_LEN as i16,
        );
        b.load(LDX_B, 0, 10, identity + 4);
        b.store(STX_W, 8, SCRATCH_INPUT + 120, 0);
    }
    for (source, destination) in [(KEY + 40, 96), (KEY + 42, 100)] {
        b.load(LDX_H, 0, 10, source);
        b.emit(BE16, 0, 0, 0, 16);
        b.store(STX_W, 8, SCRATCH_INPUT + destination, 0);
    }
    for (source, wire_first, first, other, destination) in [
        (
            KEY + 44,
            6,
            L4ProtoType::Tcp as i32,
            L4ProtoType::Udp as i32,
            104,
        ),
        (
            KEY + 4,
            4,
            IpVersionType::V4 as i32,
            IpVersionType::V6 as i32,
            108,
        ),
    ] {
        b.load(LDX_W, 0, 10, source);
        b.imm(1, other);
        let converted = b.target();
        b.jump(JNE_K, 0, 0, wire_first, converted);
        b.imm(1, first);
        b.bind(converted);
        b.store(STX_W, 8, SCRATCH_INPUT + destination, 1);
    }
    b.load(LDX_W, 0, 10, DSCP);
    b.store(STX_W, 8, SCRATCH_INPUT + 112, 0);
    b.lookup(maps.mode_flags.as_raw_fd(), INDEX);
    let flags_present = b.target();
    b.jump(JNE_K, 0, 0, 0, flags_present);
    b.emit(ST_DW, 8, 0, 0, 0);
    b.goto(classify_bad);
    b.bind(flags_present);
    b.load(LDX_W, 0, 0, 0);
    b.emit(AND_K, 0, 0, 0, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as i32);
    let no_finality = b.target();
    let mac_flag = if b.auxiliary.is_none() {
        ROUTING_INPUT_MAC_PRESENT as i32
    } else {
        0
    };
    b.imm(1, mac_flag);
    b.jump(JEQ_K, 0, 0, 0, no_finality);
    b.emit(OR_K, 1, 0, 0, ROUTING_INPUT_ALLOW_DIRECT_FINALITY as i32);
    b.bind(no_finality);
    b.store(STX_W, 8, SCRATCH_INPUT + 124, 1);
    // Discard parser history before the shared canonical call, including its saved caller frame.
    for slot in [
        REMAIN,
        EXT_BYTES,
        L2_LEN,
        FULL_LEN,
        IS_QUOTE,
        HOP_LIMIT,
        TCP_FLAGS,
        DSCP,
        INNER_FRAG,
        INNER_REMAIN,
        QUOTE_AVAILABLE,
        CURSOR,
    ] {
        b.word(slot, 0);
    }
    for register in 0..=7 {
        b.imm(register, 0);
    }
    b.mov(1, 8);
    b.add(1, i32::from(SCRATCH_INPUT));
    b.mov(2, 8);
    b.add(2, i32::from(SCRATCH_OUTPUT));
    b.emit(CALL, 0, 1, 0, 0)
}

#[allow(clippy::too_many_arguments)]
pub(in crate::bpf) fn build(
    capture: &GeneralCapture,
    ipv4_broadcasts: &[std::net::Ipv4Addr],
    queues: u32,
    counters: RawFd,
    xsks: RawFd,
    data: bool,
    vlan_kfunc: Option<u32>,
    gateway: &GatewayLoad<'_>,
) -> io::Result<Program> {
    validate_queues(queues)?;
    if capture.authority.ifindex == 0
        || ipv4_broadcasts.len() > crate::topology::MAX_BROADCASTS
        || capture.vlan_metadata != vlan_kfunc.is_some()
        || vlan_kfunc == Some(0)
    {
        return Err(invalid_data("invalid gateway capture or kfunc authority"));
    }
    build_ingress(
        Ingress::Xdp {
            capture,
            broadcasts: ipv4_broadcasts,
            queues,
            counters,
            xsks,
            data,
            vlan_kfunc,
        },
        gateway,
        gateway
            .conntrack
            .ok_or_else(|| invalid_data("physical gateway requires XDP conntrack"))?,
    )
}

pub(super) fn build_auxiliary(
    pair: &crate::AuxDevicePair,
    realm: u32,
    ipv4_broadcasts: &[Ipv4Addr],
    gateway: &GatewayLoad<'_>,
    ct: &SkbConntrackKfuncs,
) -> io::Result<Program> {
    if ipv4_broadcasts.len() > crate::topology::MAX_BROADCASTS {
        return Err(invalid_data("auxiliary IPv4 broadcast capacity exceeded"));
    }
    build_ingress(
        Ingress::Auxiliary {
            hook: auxiliary::Ingress::new(pair, gateway.maps, realm),
            broadcasts: ipv4_broadcasts,
        },
        gateway,
        &ct.0,
    )
}

#[derive(Clone, Copy)]
enum Ingress<'a> {
    Xdp {
        capture: &'a GeneralCapture,
        broadcasts: &'a [Ipv4Addr],
        queues: u32,
        counters: RawFd,
        xsks: RawFd,
        data: bool,
        vlan_kfunc: Option<u32>,
    },
    Auxiliary {
        hook: auxiliary::Ingress,
        broadcasts: &'a [Ipv4Addr],
    },
}

fn build_ingress(
    ingress: Ingress<'_>,
    gateway: &GatewayLoad<'_>,
    conntrack_kfuncs: &ConntrackKfuncs,
) -> io::Result<Program> {
    if conntrack_kfuncs.lookup == 0
        || conntrack_kfuncs.release == 0
        || [
            conntrack_kfuncs.lookup_offset,
            conntrack_kfuncs.release_offset,
        ]
        .iter()
        .any(|offset| !matches!(*offset, 0 | 1) || (*offset == 1 && conntrack_kfuncs.btf.is_none()))
    {
        return Err(invalid_data("invalid gateway capture or kfunc authority"));
    }
    let maps = gateway.maps;
    let mut b = GatewayBuilder::new();
    let (data, scratch, ipv4_broadcasts, auxiliary) = match ingress {
        Ingress::Xdp {
            data, broadcasts, ..
        } => (data, maps.scratch.as_raw_fd(), broadcasts, None),
        Ingress::Auxiliary { hook, broadcasts } => (true, hook.scratch, broadcasts, Some(hook)),
    };
    b.auxiliary = auxiliary;
    let drop = b.target();
    let bad = b.target();
    let unknown = b.target();
    let foreign = b.target();
    let pass = b.target();
    let xsk = b.target();
    let final_pass = b.target();
    let final_xsk = b.target();
    let ipv4 = b.target();
    let ipv6 = b.target();
    let parsed4 = b.target();
    let parsed6 = b.target();
    let parsed = b.target();
    let later = b.target();
    let transport = b.target();
    let quote = b.target();
    let quoted = b.target();
    let quote_unresolved = b.target();
    let held = b.target();
    let ct_miss = b.target();
    let ct_error = b.target();
    let ct_original = b.target();
    let ct_reply = b.target();
    let non_transport = b.target();
    let local = b.target();
    let non_syn = b.target();
    let d1 = b.target();
    let d1_pass = b.target();
    let new_flow = b.target();
    let insert_failed = b.target();
    let fragment_miss = b.target();
    let fragment_pass = b.target();
    let fragment_xsk = b.target();
    let nd = b.target();
    let owner = gateway
        .arbitration
        .map(|arb| ownership::Owner::new(&mut b, arb, conntrack_kfuncs));
    b.mov(9, 1);
    match ingress {
        Ingress::Xdp {
            capture,
            vlan_kfunc,
            ..
        } => {
            b.program.flags = 1 << 5;
            if vlan_kfunc.is_some() {
                b.program.flags |= 1 << 6;
                b.program.ifindex = capture.authority.ifindex;
            }
            b.load(LDX_W, 0, 9, 12);
            b.jump(JNE32_K, 0, 0, capture.authority.ifindex as i32, unknown);
            b.mov(1, 9);
            b.helper(188); // Total XDP length includes SG payload; data_end bounds only headers.
            b.store(STX_W, 10, FULL_LEN, 0);
            layer2(&mut b, capture, maps, vlan_kfunc, bad, unknown);
            b.jump(JEQ_K, 5, 0, 0x0806, non_transport);
        }
        Ingress::Auxiliary { hook, .. } => hook.prologue(&mut b, foreign, unknown),
    }
    b.jump(JEQ_K, 5, 0, 0x0800, ipv4);
    b.jump(JEQ_K, 5, 0, 0x86dd, ipv6);
    if auxiliary.is_some() {
        b.goto(non_transport);
    } else {
        b.load(LDX_W, 0, 10, DSCP);
        b.jump(JNE_K, 0, 0, 0, non_transport);
        b.goto(drop);
    }
    b.bind(ipv4);
    parse_ip(
        &mut b,
        false,
        false,
        ipv4_broadcasts,
        &ParseTargets {
            bad,
            later,
            done: parsed4,
            pass: non_transport,
            drop,
        },
    );
    b.bind(parsed4);
    b.goto(parsed);
    b.bind(ipv6);
    parse_ip(
        &mut b,
        false,
        true,
        ipv4_broadcasts,
        &ParseTargets {
            bad,
            later,
            done: parsed6,
            pass: non_transport,
            drop,
        },
    );
    b.bind(parsed6);
    if auxiliary.is_none() {
        b.load(LDX_B, 0, 10, KEY + 24);
        b.jump(JNE_K, 0, 0, 0xff, parsed);
        b.jump(JNE_K, 5, 0, 58, non_transport);
        b.prefix(2, REMAIN, bad);
        b.load(LDX_B, 0, 6, 0);
        b.jump(JLT_K, 0, 0, 133, non_transport);
        b.jump(JGT_K, 0, 0, 137, non_transport);
        b.goto(nd);
    }
    b.bind(parsed);
    b.store(STX_W, 10, KEY + 44, 5);
    b.jump(JEQ_K, 5, 0, 6, transport);
    b.jump(JEQ_K, 5, 0, 17, transport);
    let icmp4 = b.target();
    let icmp6 = b.target();
    b.load(LDX_W, 0, 10, KEY + 4);
    b.jump(JEQ_K, 0, 0, 6, icmp6);
    b.jump(JNE_K, 5, 0, 1, non_transport);
    b.prefix(2, REMAIN, bad);
    b.load(LDX_B, 0, 6, 0);
    for kind in [3, 4, 11, 12] {
        b.jump(JEQ_K, 0, 0, kind, quote);
    }
    b.goto(non_transport);
    b.bind(icmp6);
    b.jump(JNE_K, 5, 0, 58, non_transport);
    b.prefix(2, REMAIN, bad);
    b.load(LDX_B, 0, 6, 0);
    b.jump(JLT_K, 0, 0, 1, non_transport);
    b.jump(JGT_K, 0, 0, 4, icmp4);
    b.goto(quote);
    b.bind(icmp4);
    b.jump(JLT_K, 0, 0, 133, non_transport);
    b.jump(JGT_K, 0, 0, 137, non_transport);
    b.bind(nd);
    b.load(LDX_W, 0, 10, HOP_LIMIT);
    b.jump(JNE_K, 0, 0, 255, bad);
    b.load(LDX_B, 0, 6, 1);
    b.jump(JNE_K, 0, 0, 0, bad);
    b.goto(non_transport);

    b.bind(transport);
    let udp = b.target();
    let ports = b.target();
    b.jump(JEQ_K, 5, 0, 17, udp);
    b.prefix(14, REMAIN, bad);
    b.load(LDX_B, 0, 6, 12);
    b.emit(RSH_K, 0, 0, 0, 4);
    b.jump(JLT_K, 0, 0, 5, bad);
    b.emit(LSH_K, 0, 0, 0, 2);
    b.load_remaining(1, REMAIN, bad);
    b.load(LDX_W, 2, 10, FRAG_STATE);
    let tcp_fragment = b.target();
    b.jump(JSET_K, 2, 0, 1, tcp_fragment);
    b.jump(JGT_X, 0, 1, 0, bad);
    b.bind(tcp_fragment);
    b.load(LDX_B, 0, 6, 13);
    b.store(STX_W, 10, TCP_FLAGS, 0);
    b.goto(ports);
    b.bind(udp);
    b.prefix(8, REMAIN, bad);
    b.load(LDX_H, 0, 6, 4);
    b.emit(BE16, 0, 0, 0, 16);
    b.jump(JLT_K, 0, 0, 8, bad);
    b.load(LDX_W, 1, 10, FRAG_STATE);
    let udp_fragment = b.target();
    b.jump(JSET_K, 1, 0, 1, udp_fragment);
    b.load_remaining(1, REMAIN, bad);
    b.jump(JGT_X, 0, 1, 0, bad);
    b.bind(udp_fragment);
    b.bind(ports);
    b.copy(10, KEY + 40, 6, 0, 4);
    let hold_lookup = b.target();
    b.load(LDX_H, 0, 10, KEY + 42);
    b.jump(JEQ_K, 0, 0, u16::from_be(53) as i32, hold_lookup);
    b.load(LDX_W, 0, 10, KEY + 4);
    b.store(STX_W, 10, LOCAL, 0);
    b.copy(10, LOCAL + 4, 10, KEY + 24, 16);
    b.word(INDEX, 0);
    b.lookup(maps.local_root.as_raw_fd(), INDEX);
    b.jump(JEQ_K, 0, 0, 0, bad);
    b.mov(1, 0);
    b.address(2, LOCAL);
    b.helper(1);
    b.jump(JNE_K, 0, 0, 0, local);
    b.bind(hold_lookup);
    if owner.is_none() {
        b.lookup(maps.hold.as_raw_fd(), KEY);
        b.jump(JNE_K, 0, 0, 0, held);
    }
    let ct = b.target();
    b.goto(ct);

    b.bind(quote);
    b.prefix(8, REMAIN, quote_unresolved);
    b.load_remaining(0, REMAIN, quote_unresolved);
    b.add(0, -8);
    b.jump(JGT_K, 0, 0, 0xffff, quote_unresolved);
    b.emit(AND_K, 0, 0, 0, 0xffff);
    b.store(STX_W, 10, QUOTE_AVAILABLE, 0);
    b.jump(JLT_K, 0, 0, 1, quote_unresolved);
    b.imm(2, 8);
    b.advance_cursor(2, quote_unresolved);
    b.word(IS_QUOTE, 1);
    b.bound(1, quote_unresolved);
    b.load(LDX_B, 0, 6, 0);
    b.emit(AND_K, 0, 0, 0, 0xf0);
    let inner4 = b.target();
    let inner6 = b.target();
    b.jump(JEQ_K, 0, 0, 0x40, inner4);
    b.jump(JEQ_K, 0, 0, 0x60, inner6);
    b.goto(quote_unresolved);
    b.bind(inner4);
    parse_ip(
        &mut b,
        true,
        false,
        &[],
        &ParseTargets {
            bad: quote_unresolved,
            later: quote_unresolved,
            done: quoted,
            pass: non_transport,
            drop: quote_unresolved,
        },
    );
    b.bind(inner6);
    parse_ip(
        &mut b,
        true,
        true,
        &[],
        &ParseTargets {
            bad: quote_unresolved,
            later: quote_unresolved,
            done: quoted,
            pass: non_transport,
            drop: quote_unresolved,
        },
    );
    b.bind(quoted);
    b.store(STX_W, 10, KEY + 44, 5);
    let quoted_transport = b.target();
    b.jump(JEQ_K, 5, 0, 6, quoted_transport);
    b.jump(JNE_K, 5, 0, 17, non_transport);
    b.bind(quoted_transport);
    b.prefix(4, INNER_REMAIN, quote_unresolved);
    b.load(LDX_H, 0, 6, 0);
    b.store(STX_H, 10, KEY + 42, 0);
    b.load(LDX_H, 0, 6, 2);
    b.store(STX_H, 10, KEY + 40, 0);
    if let Some(owner) = &owner {
        b.bind(ct);
        owner.observe(&mut b, gateway, data, d1, pass, drop);
    } else {
        b.lookup(maps.hold.as_raw_fd(), KEY);
        b.jump(JNE_K, 0, 0, 0, held);
        b.goto(ct);
        b.bind(ct);
        conntrack(
            &mut b,
            conntrack_kfuncs,
            ct_miss,
            ct_error,
            ct_original,
            ct_reply,
        );
        b.bind(ct_miss);
        b.load(LDX_W, 0, 10, IS_QUOTE);
        b.jump(JNE_K, 0, 0, 0, quote_unresolved);
        b.load(LDX_B, 0, 10, KEY + 44);
        b.jump(JEQ_K, 0, 0, 17, d1);
        b.load(LDX_W, 0, 10, TCP_FLAGS);
        b.emit(AND_K, 0, 0, 0, 0x17);
        b.jump(JNE_K, 0, 0, 2, non_syn);
        b.goto(d1);
        b.bind(held);
        let refreshed = b.target();
        refresh_hold(&mut b, refreshed);
        b.bind(refreshed);
        b.reason(GatewayReason::XskEndpointHold, xsk);
        b.bind(ct_original);
        b.reason(GatewayReason::PassCtOriginal, pass);
        b.bind(ct_reply);
        b.reason(GatewayReason::PassCtReply, pass);
        b.bind(ct_error);
        b.stat(maps, GatewayReason::CtLookupError);
        b.goto(drop);
        b.bind(non_syn);
        b.reason(GatewayReason::PassTcpNonSynMiss, pass);
    }

    b.bind(d1);
    let classify_bad = owner.as_ref().map_or(bad, |owner| owner.bad);
    let classify_stale = owner
        .as_ref()
        .and_then(|owner| owner.stale)
        .unwrap_or(unknown);
    let routing_call = routing_call(&mut b, maps, scratch, classify_bad, None);
    if let Some(auxiliary) = auxiliary {
        let stale = b.target();
        let active = b.target();
        auxiliary.after_policy(&mut b, stale);
        b.goto(active);
        b.bind(stale);
        b.emit(ST_DW, 8, 0, 0, 0);
        b.goto(classify_stale);
        b.bind(active);
    }
    let dns_path = gateway.dns.map(|dns| {
        let target = b.target();
        b.jump(JEQ_K, 0, 0, GATEWAY_ROUTE_NEED_DNS, target);
        (dns, target)
    });
    b.emit(ST_DW, 8, 0, 0, 0);
    b.jump(JEQ_K, 0, 0, 1, d1_pass);
    b.jump(JNE_K, 0, 0, 0, classify_bad);
    b.goto(new_flow);
    b.bind(d1_pass);
    if let Some(owner) = &owner {
        owner.static_pass(&mut b);
    } else {
        b.reason(GatewayReason::PassD1, pass);
    }
    let dns_call = dns_path.map(|(dns, target)| {
        b.bind(target);
        let qualified = owner.as_ref().filter(|_| data).map(|owner| owner.qualified);
        dns_shadow(
            &mut b,
            dns,
            data.then_some(maps),
            qualified,
            new_flow,
            classify_bad,
            classify_stale,
        )
    });
    b.bind(new_flow);
    if let Some(owner) = &owner {
        owner.finish(&mut b, gateway, data, final_pass, drop);
    } else {
        if data {
            b.helper(5);
            b.store(STX_DW, 10, VALUE, 0);
            b.store(STX_DW, 10, VALUE + 8, 0);
            b.update(maps.hold.as_raw_fd(), KEY, VALUE, 1);
            let inserted = b.target();
            b.jump(JEQ_K, 0, 0, 0, inserted);
            b.jump(JNE32_K, 0, 0, -libc::EEXIST, insert_failed);
            b.lookup(maps.hold.as_raw_fd(), KEY);
            b.jump(JEQ_K, 0, 0, 0, insert_failed);
            let raced = b.target();
            refresh_hold(&mut b, raced);
            b.bind(raced);
            b.bind(inserted);
        }
        b.reason(GatewayReason::XskNewFlow, xsk);
        if data {
            b.bind(insert_failed);
            b.stat(maps, GatewayReason::HoldInsertFailed);
            b.goto(drop);
        }
    }

    b.bind(later);
    b.lookup(maps.fragments.as_raw_fd(), FRAGMENT);
    b.jump(JEQ_K, 0, 0, 0, fragment_miss);
    b.mov(8, 0);
    b.helper(5);
    b.load(LDX_DW, 1, 8, 8);
    b.jump(JLT_X, 0, 1, 0, fragment_miss);
    b.emit(SUB_X, 0, 1, 0, 0);
    b.constant(1, FRAGMENT_TTL_NS);
    b.jump(JGT_X, 0, 1, 0, fragment_miss);
    b.load(LDX_W, 0, 8, 0);
    b.jump(JEQ_K, 0, 0, VERDICT_PASS, fragment_pass);
    b.jump(JEQ_K, 0, 0, VERDICT_ENDPOINT, fragment_xsk);
    b.goto(fragment_miss);
    b.bind(fragment_pass);
    b.reason(GatewayReason::PassFragment, pass);
    b.bind(fragment_xsk);
    b.reason(GatewayReason::XskFragment, xsk);
    b.bind(fragment_miss);
    b.stat(maps, GatewayReason::FragmentMiss);
    b.goto(drop);
    b.bind(non_transport);
    b.reason(GatewayReason::PassNonTransport, pass);
    b.bind(local);
    b.reason(GatewayReason::PassLocal, pass);
    b.bind(quote_unresolved);
    if auxiliary.is_some() {
        b.stat(maps, GatewayReason::IcmpQuoteUnresolved);
        b.goto(drop);
    } else {
        b.reason(GatewayReason::IcmpQuoteUnresolved, xsk);
    }
    b.bind(bad);
    b.stat(maps, GatewayReason::UnclassifiableHeader);
    b.goto(drop);
    b.bind(unknown);
    b.stat(maps, GatewayReason::UnknownRealm);
    b.goto(drop);

    b.bind(pass);
    b.word(VERDICT, VERDICT_PASS);
    b.goto(final_pass);
    b.bind(xsk);
    b.word(VERDICT, VERDICT_ENDPOINT);
    b.goto(final_pass);
    b.bind(final_pass);
    if let Some(auxiliary) = auxiliary {
        auxiliary.authorize(&mut b, unknown, unknown);
        auxiliary::check_endpoint_gso(&mut b, bad);
    }
    b.load(LDX_W, 0, 10, FRAG_STATE);
    let no_fragment = b.target();
    b.emit(AND_K, 0, 0, 0, 1);
    b.jump(JEQ_K, 0, 0, 0, no_fragment);
    b.load(LDX_W, 0, 10, VERDICT);
    b.store(STX_W, 10, VALUE, 0);
    b.word(VALUE + 4, 0);
    b.helper(5);
    b.store(STX_DW, 10, VALUE + 8, 0);
    b.update(maps.fragments.as_raw_fd(), FRAGMENT, VALUE, 0);
    b.jump(JEQ_K, 0, 0, 0, no_fragment);
    b.stat(maps, GatewayReason::FragmentVerdictInsertFailed);
    b.bind(no_fragment);
    b.load(LDX_W, 0, 10, REASON);
    b.store(STX_W, 10, INDEX, 0);
    b.stat_index(maps.stats.as_raw_fd());
    b.load(LDX_W, 0, 10, VERDICT);
    b.jump(JNE_K, 0, 0, VERDICT_PASS, final_xsk);
    let native_action = if auxiliary.is_some() {
        auxiliary::TCX_NEXT
    } else {
        XDP_PASS
    };
    b.bind(foreign);
    b.imm(0, native_action);
    b.emit(EXIT, 0, 0, 0, 0);
    b.bind(final_xsk);
    match ingress {
        Ingress::Xdp {
            capture,
            queues,
            counters,
            xsks,
            ..
        } => {
            b.load(LDX_W, 8, 9, 16);
            b.jump(JGE_K, 8, 0, queues as i32, drop);
            if data && capture.vlan_metadata {
                b.mov(1, 9);
                b.imm(2, -(METADATA_LEN as i32));
                b.helper(54);
                let metadata_failed = b.target();
                let metadata_ready = b.target();
                b.jump(JNE_K, 0, 0, 0, metadata_failed);
                b.load(LDX_W, 6, 9, 8);
                b.load(LDX_W, 7, 9, 0);
                b.bound(METADATA_LEN as i32, metadata_failed);
                b.copy(6, 0, 10, META, METADATA_LEN as i16);
                b.goto(metadata_ready);
                b.bind(metadata_failed);
                b.word(INDEX, (queues + 3) as i32);
                b.stat_index(counters);
                b.goto(drop);
                b.bind(metadata_ready);
            }
            b.store(STX_W, 10, INDEX, 8);
            b.stat_index(counters);
            if data {
                b.map(1, xsks);
                b.mov(2, 8);
                b.imm(3, XDP_DROP);
                b.helper(51);
                b.emit(EXIT, 0, 0, 0, 0);
            }
        }
        Ingress::Auxiliary { .. } => auxiliary::Ingress::redirect(&mut b),
    }
    b.bind(drop);
    let drop_action = if auxiliary.is_some() {
        auxiliary::TCX_DROP
    } else {
        XDP_DROP
    };
    b.imm(0, drop_action);
    b.emit(EXIT, 0, 0, 0, 0);
    b.finish(
        gateway.routing,
        std::iter::once(routing_call).chain(dns_call),
    )
    .map_err(|error| {
        if gateway.dns.is_some() {
            crate::bpf::gateway::dns_load_error("verifier_budget", error)
        } else {
            error
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_endian = "little")]
    fn dns_bytecode_retains_busy_until_the_final_exchange() {
        for (double_exchange, expected) in [(false, &[0][..]), (true, &[1, 0][..])] {
            let mut builder = GatewayBuilder::new();
            release_dns_scratch(&mut builder, double_exchange);
            let mut registers = [None; 11];
            let mut busy = 1;
            let mut writes = Vec::new();
            for insn in builder.program.insns {
                let dst = usize::from(insn.regs & 15);
                let src = usize::from(insn.regs >> 4);
                match insn.code {
                    MOV_K => registers[dst] = Some(insn.imm),
                    ATOMIC_ADD_DW => {
                        assert_eq!((dst, insn.off, insn.imm), (8, 0, XCHG));
                        let register = registers[src]
                            .as_mut()
                            .expect("uninitialized exchange source");
                        std::mem::swap(&mut busy, register);
                        writes.push(busy);
                    }
                    _ => panic!("unexpected DNS release instruction {insn:?}"),
                }
            }
            assert_eq!(writes, expected);
        }
    }

    #[test]
    fn conntrack_calls_keep_independent_module_offsets() {
        for (lookup_offset, release_offset) in [(0, 1), (1, 0)] {
            let ct = ConntrackKfuncs {
                lookup: 713,
                release: 729,
                lookup_offset,
                release_offset,
                btf: Some(std::fs::File::open("/dev/null").unwrap().into()),
            };
            let mut b = GatewayBuilder::new();
            let miss = b.target();
            let error = b.target();
            let original = b.target();
            let reply = b.target();
            conntrack(&mut b, &ct, miss, error, original, reply);
            let calls: Vec<_> = b
                .program
                .insns
                .iter()
                .filter(|instruction| instruction.code == CALL)
                .map(|instruction| (instruction.imm, instruction.off))
                .collect();
            assert_eq!(calls, [(713, lookup_offset), (729, release_offset)]);
        }
    }
}
