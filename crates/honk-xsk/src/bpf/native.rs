use super::*;
use crate::capture::GeneralCapture;
use honk_ebpf_common::xdp::{
    METADATA_LEN, METADATA_VERSION, NATIVE_CLAIM_UPDATE_INTERVAL_NS, NATIVE_CLAIM_VALUE_BYTES,
    NATIVE_COUNTER_ENTRIES, NATIVE_COUNTER_FAULT_INDEX, NATIVE_COUNTER_GENERATIONS,
    NATIVE_EXECUTOR_CAPTURE, NATIVE_EXECUTOR_KERNEL, NATIVE_EXECUTOR_PENDING,
    NATIVE_IMPORT_COUNTED, NATIVE_METADATA_LEN, NATIVE_OUTSTANDING_MAX, NATIVE_PHASE_ACTIVE,
    NATIVE_PHASE_ARMED, NATIVE_PHASE_CAPTURE_COMMITTED, NATIVE_PHASE_DRAINING,
    NATIVE_PHASE_PENDING, NativeClaim, NativeClosedCounterV1, NativeKey, NativeRoot, NativeScratch,
};
use honk_ebpf_common::{
    DATAPATH_FLAG_OFFLOAD_ALL, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT, IpVersionType, KernelRouteOutput,
    L4ProtoType, ROUTING_INPUT_ALLOW_DIRECT_FINALITY, ROUTING_MARK_KEEP, RoutingDecision,
    RoutingInput,
};

pub(super) mod captured;
mod dispatch;
mod layout;
pub(super) use dispatch::build as dispatch;
pub(super) use layout::preparation_memory_bytes;

const LDX_DW: u8 = 0x79;
const STX_DW: u8 = 0x7b;
const ST_H: u8 = 0x6a;
const ST_B: u8 = 0x72;
const STX_H: u8 = 0x6b;
const STX_B: u8 = 0x73;
const JEQ32_K: u8 = 0x16;
const JGE_X: u8 = 0x3d;
const JEQ_X: u8 = 0x1d;
const SUB_X: u8 = 0x1f;
const CMPXCHG_DW: i32 = 0xf1;
const CMPXCHG_W: u8 = 0xc3;
const QUERY_MARK: u32 = 0x484e4b51;
const KEY: i16 = -56;
const ORIGINAL: i16 = -112;
const CLAIM: i16 = -184;
// CT tuple scratch is dead before the complete insertion value is initialized.
const TUPLE: i16 = CLAIM + 32;
const OPTS: i16 = -200;
const ROOT: i16 = -208;
const EPOCH: i16 = -216;
const FLAGS: i16 = -220;
const QUERY: i16 = -224;
const QUEUE: i16 = -228;
const OWNER: i16 = -232;
const LIVE: i16 = -236;
const REPLY: i16 = -240;
const INCARNATION: i16 = -248;
const INDEX: i16 = -252;
const DSCP: i16 = -256;
const ETHER_TYPE: i16 = -260;
const INVALID: i16 = -264;
const FRAME_LEN: i16 = -268;
const CLAIM_PTR: i16 = -280;
const ACTIVITY_NOW: i16 = -288;
const CLAIM_LAST_SEEN: i16 = std::mem::offset_of!(NativeClaim, last_seen_ns) as i16;
const CLOSED_COUNTER_INSNS: usize = 64;
pub(super) const CLOSED_COUNTER_PREPARATION_BYTES: usize = 64 << 10;

pub(super) fn validate_recording_config(config: &NativeProgramConfig<'_>) -> io::Result<()> {
    if config.closed_counters < 0
        || config.hook_ids.contains(&0)
        || config.hook_ids[0] == config.hook_ids[1]
        || config.epoch & 1 != 0
    {
        return Err(invalid_data(
            "Native recording requires distinct nonzero hook IDs and a closed epoch",
        ));
    }
    Ok(())
}

pub(super) fn admit_counter_generation(fd: RawFd, epoch: u64) -> io::Result<()> {
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    for hook in 0..2 {
        let index = honk_ebpf_common::xdp::native_closed_counter_index(epoch, hook)
            .ok_or_else(|| invalid_data("Native counter generation requires a closed epoch"))?;
        let cell: NativeClosedCounterV1 = map_value(fd, &index)?;
        if !cell.is_valid(epoch) || cell.overflow != 0 {
            return Err(invalid_data(
                "Native counter generation was not initialized or has overflowed",
            ));
        }
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CounterMapInfo {
    kind: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    entries: u32,
    flags: u32,
}

fn validate_counter_map(info: &CounterMapInfo) -> io::Result<()> {
    if info.kind != 2
        || info.id == 0
        || info.key_size != 4
        || info.value_size != size_of::<NativeClosedCounterV1>() as u32
        || info.entries != NATIVE_COUNTER_ENTRIES
        || info.flags != 0
    {
        return Err(invalid_data("Native closed counter map ABI mismatch"));
    }
    Ok(())
}

fn validate_claim_map_info(info: &CounterMapInfo) -> io::Result<()> {
    if info.kind != 1
        || info.id == 0
        || info.key_size != size_of::<NativeKey>() as u32
        || info.value_size != NATIVE_CLAIM_VALUE_BYTES as u32
        || info.entries == 0
        || info.flags != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Native claim map ABI mismatch: expected HASH key=56 value={NATIVE_CLAIM_VALUE_BYTES} entries>0 flags=0, observed kind={} key={} value={} entries={} flags={}",
                info.kind, info.key_size, info.value_size, info.entries, info.flags,
            ),
        ));
    }
    Ok(())
}

fn admit_claim_map(fd: RawFd) -> io::Result<()> {
    if fd < 0 {
        return Err(invalid_data("Native claim descriptor missing"));
    }
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut info = CounterMapInfo::default();
    object_info(fd, &mut info)?;
    validate_claim_map_info(&info)
}

pub(super) fn admit_closed_counters(fd: RawFd) -> io::Result<u32> {
    if fd < 0 {
        return Err(invalid_data("Native closed counter descriptor missing"));
    }
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut info = CounterMapInfo::default();
    object_info(fd, &mut info)?;
    validate_counter_map(&info)?;
    let fault: NativeClosedCounterV1 = map_value(fd, &NATIVE_COUNTER_FAULT_INDEX)?;
    if !fault.is_valid(0) || fault.ordinary_drops != 0 || fault.overflow != 0 {
        return Err(invalid_data(
            "Native closed counter fault cell is invalid or faulted",
        ));
    }
    Ok(info.id)
}

#[repr(C)]
#[derive(Default)]
struct CounterProgramInfo {
    kind: u32,
    id: u32,
    tag: [u8; 8],
    jited_len: u32,
    xlated_len: u32,
    jited: u64,
    xlated: u64,
    load_time: u64,
    uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
}

fn validate_counter_reference(ids: &[u32], expected: u32) -> io::Result<()> {
    if expected == 0 || ids.iter().filter(|id| **id == expected).count() != 1 {
        return Err(invalid_data(
            "Native program does not reference its admitted closed counter map",
        ));
    }
    Ok(())
}

pub(super) fn admit_counter_reference(program: BorrowedFd<'_>, expected: u32) -> io::Result<()> {
    let mut info = CounterProgramInfo::default();
    object_info(program, &mut info)?;
    let count = info.nr_map_ids as usize;
    // Both admissions run sequentially inside the charged preparation lifetime.
    if count == 0 || count > CLOSED_COUNTER_PREPARATION_BYTES / size_of::<u32>() / 2 {
        return Err(invalid_data(
            "Native program map identities exceed preparation reservation",
        ));
    }
    let mut ids = Vec::new();
    ids.try_reserve_exact(count).map_err(io::Error::other)?;
    ids.resize(count, 0u32);
    // The first reply filled jited_len/xlated_len; resending them with null instruction pointers makes the kernel copy_to_user into NULL (EFAULT) wherever raw dumps are permitted.
    info = CounterProgramInfo {
        nr_map_ids: count as u32,
        map_ids: ids.as_mut_ptr() as u64,
        ..Default::default()
    };
    object_info(program, &mut info)?;
    if info.nr_map_ids as usize != count {
        return Err(invalid_data(
            "Native program map identities changed during admission",
        ));
    }
    validate_counter_reference(&ids, expected)
}
const SCRATCH_INPUT: i16 = std::mem::offset_of!(NativeScratch, input) as i16;
const SCRATCH_OUTPUT: i16 = std::mem::offset_of!(NativeScratch, output) as i16;
const SCRATCH_BUSY: i16 = std::mem::offset_of!(NativeScratch, busy) as i16;
const OUTBOUND: i16 = SCRATCH_OUTPUT + std::mem::offset_of!(RoutingDecision, outbound) as i16;
const MARK: i16 = SCRATCH_OUTPUT + std::mem::offset_of!(RoutingDecision, mark) as i16;
const MARK_KIND: i16 = SCRATCH_OUTPUT + std::mem::offset_of!(KernelRouteOutput, mark_kind) as i16;
const MUST: i16 = SCRATCH_OUTPUT + std::mem::offset_of!(RoutingDecision, must) as i16;
const FINAL: i16 = SCRATCH_OUTPUT + std::mem::offset_of!(RoutingDecision, domain_final) as i16;

#[derive(Clone, Copy)]
struct Target(usize);

struct Asm {
    b: Builder,
    labels: Vec<Option<usize>>,
    jumps: Vec<(usize, Target)>,
}

impl Asm {
    fn new() -> Self {
        Self {
            b: Builder::new(),
            labels: Vec::new(),
            jumps: Vec::new(),
        }
    }
    fn emit(&mut self, code: u8, dst: u8, src: u8, off: i16, imm: i32) -> usize {
        self.b.emit(Insn::new(code, dst, src, off, imm))
    }
    fn label(&mut self) -> Target {
        let target = Target(self.labels.len());
        self.labels.push(None);
        target
    }
    fn bind(&mut self, target: Target) {
        self.labels[target.0] = Some(self.b.program.len);
    }
    fn jump(&mut self, code: u8, dst: u8, src: u8, imm: i32, target: Target) {
        let at = self.emit(code, dst, src, 0, imm);
        self.jumps.push((at, target));
    }
    fn go(&mut self, target: Target) {
        self.jump(JA, 0, 0, 0, target);
    }
    fn mov(&mut self, dst: u8, src: u8) {
        self.emit(MOV_X, dst, src, 0, 0);
    }
    fn imm(&mut self, dst: u8, value: u64) {
        self.emit(LD_MAP, dst, 0, 0, value as i32);
        self.emit(0, 0, 0, 0, (value >> 32) as i32);
    }
    fn ptr(&mut self, dst: u8, base: u8, offset: i16) {
        self.mov(dst, base);
        self.emit(ADD_K, dst, 0, 0, i32::from(offset));
    }
    fn lookup(&mut self, fd: RawFd, offset: i16) {
        self.b.map_fd(fd);
        self.ptr(2, 10, offset);
        self.emit(CALL, 0, 0, 0, 1);
    }
    fn bound(&mut self, length: i32, failure: Target) {
        self.mov(0, 6);
        self.emit(ADD_K, 0, 0, 0, length);
        self.jump(JGT_X, 0, 7, 0, failure);
    }
    fn zero(&mut self, base: u8, start: i16, length: usize) {
        for off in (0..length as i16).step_by(4) {
            self.emit(ST_W, base, 0, start + off, 0);
        }
    }
    fn copy(&mut self, dst: u8, dest: i16, src: u8, source: i16, bytes: usize) {
        for off in (0..bytes as i16).step_by(4) {
            self.emit(LDX_W, 0, src, source + off, 0);
            self.emit(STX_W, dst, 0, dest + off, 0);
        }
    }
    fn exit(&mut self, value: i32) {
        self.emit(MOV_K, 0, 0, 0, value);
        self.emit(EXIT, 0, 0, 0, 0);
    }
    fn finish(mut self) -> io::Result<Program> {
        for (at, target) in self.jumps {
            let target = self.labels[target.0]
                .ok_or_else(|| invalid_data("unresolved native gate label"))?;
            self.b.program.insns[at].off = i16::try_from(target as isize - at as isize - 1)
                .map_err(|_| invalid_data("native gate branch exceeds i16"))?;
        }
        self.b.finish()
    }
}

fn envelope(a: &mut Asm, tc: bool, failure: Target) {
    if tc {
        a.emit(LDX_W, 0, 9, 0, 0);
    } else {
        a.mov(1, 9);
        a.emit(CALL, 0, 0, 0, 188);
    }
    a.emit(STX_W, 10, 0, FRAME_LEN, 0);
    a.emit(LDX_W, 6, 9, if tc { 76 } else { 0 }, 0);
    a.emit(LDX_W, 7, 9, if tc { 80 } else { 4 }, 0);
    a.bound(14, failure);
    a.emit(LDX_H, 5, 6, 12, 0);
    a.emit(BE16, 5, 0, 0, 16);
    a.emit(STX_W, 10, 5, ETHER_TYPE, 0);
    let v4 = a.label();
    let transport = a.label();
    a.jump(JEQ_K, 5, 0, 0x0800, v4);
    a.jump(JNE_K, 5, 0, 0x86dd, failure);
    a.emit(ADD_K, 6, 0, 0, 14);
    a.bound(40, failure);
    a.emit(LDX_B, 0, 6, 0, 0);
    a.emit(AND_K, 0, 0, 0, 0xf0);
    a.jump(JNE_K, 0, 0, 0x60, failure);
    a.copy(10, KEY, 6, 8, 32);
    a.emit(ST_B, 10, 0, KEY + 37, 6);
    a.emit(LDX_H, 0, 6, 0, 0);
    a.emit(BE16, 0, 0, 0, 16);
    a.emit(RSH_K, 0, 0, 0, 6);
    a.emit(AND_K, 0, 0, 0, 63);
    a.emit(STX_W, 10, 0, DSCP, 0);
    a.emit(LDX_H, 4, 6, 4, 0);
    a.emit(BE16, 4, 0, 0, 16);
    a.jump(JEQ_K, 4, 0, 0, failure);
    a.mov(0, 4);
    a.emit(ADD_K, 0, 0, 0, 54);
    a.emit(LDX_W, 1, 10, FRAME_LEN, 0);
    a.jump(JGT_X, 0, 1, 0, failure);
    a.emit(LDX_B, 5, 6, 6, 0);
    a.emit(ADD_K, 6, 0, 0, 40);
    // Unroll the same eight-header limit as wire::ipv6 without another stack slot.
    for _ in 0..8 {
        let extension = a.label();
        let next = a.label();
        a.jump(JEQ_K, 5, 0, 0, extension);
        a.jump(JEQ_K, 5, 0, 43, extension);
        a.jump(JEQ_K, 5, 0, 60, extension);
        a.go(transport);
        a.bind(extension);
        a.jump(JLT_K, 4, 0, 8, failure);
        a.bound(8, failure);
        a.emit(LDX_B, 0, 6, 1, 0);
        a.emit(ADD_K, 0, 0, 0, 1);
        a.emit(LSH_K, 0, 0, 0, 3);
        a.jump(JGT_X, 0, 4, 0, failure);
        a.mov(1, 6);
        a.emit(ADD_X, 1, 0, 0, 0);
        a.jump(JGT_X, 1, 7, 0, failure);
        a.jump(JNE_K, 5, 0, 43, next);
        a.emit(LDX_B, 2, 6, 3, 0);
        a.jump(JNE_K, 2, 0, 0, failure);
        a.bind(next);
        a.emit(LDX_B, 5, 6, 0, 0);
        a.emit(SUB_X, 4, 0, 0, 0);
        a.mov(6, 1);
    }
    a.jump(JEQ_K, 5, 0, 0, failure);
    a.jump(JEQ_K, 5, 0, 43, failure);
    a.jump(JEQ_K, 5, 0, 60, failure);
    a.go(transport);
    a.bind(v4);
    a.emit(ADD_K, 6, 0, 0, 14);
    a.bound(20, failure);
    a.emit(LDX_B, 0, 6, 0, 0);
    a.jump(JNE_K, 0, 0, 0x45, failure);
    a.emit(LDX_H, 0, 6, 6, 0);
    a.jump(JSET_K, 0, 0, i32::from(0xbfff_u16.to_be()), failure);
    a.zero(10, KEY, size_of::<NativeKey>());
    for (source, dest) in [(12, KEY), (16, KEY + 16)] {
        a.emit(
            ST_W,
            10,
            0,
            dest + 8,
            u32::from_ne_bytes([0, 0, 255, 255]) as i32,
        );
        a.emit(LDX_W, 0, 6, source, 0);
        a.emit(STX_W, 10, 0, dest + 12, 0);
    }
    a.emit(ST_B, 10, 0, KEY + 37, 4);
    a.emit(LDX_B, 0, 6, 1, 0);
    a.emit(RSH_K, 0, 0, 0, 2);
    a.emit(STX_W, 10, 0, DSCP, 0);
    a.emit(LDX_H, 4, 6, 2, 0);
    a.emit(BE16, 4, 0, 0, 16);
    a.jump(JLT_K, 4, 0, 20, failure);
    a.mov(0, 4);
    a.emit(ADD_K, 0, 0, 0, 14);
    a.emit(LDX_W, 1, 10, FRAME_LEN, 0);
    a.jump(JGT_X, 0, 1, 0, failure);
    a.emit(ADD_K, 4, 0, 0, -20);
    a.emit(LDX_B, 5, 6, 9, 0);
    a.emit(ADD_K, 6, 0, 0, 20);
    a.bind(transport);
    a.emit(STX_B, 10, 5, KEY + 36, 0);
    a.emit(ST_H, 10, 0, KEY + 38, 0);
    let udp = a.label();
    let done = a.label();
    a.jump(JEQ_K, 5, 0, 17, udp);
    a.jump(JNE_K, 5, 0, 6, failure);
    a.jump(JLT_K, 4, 0, 20, failure);
    a.bound(20, failure);
    a.emit(LDX_B, 0, 6, 12, 0);
    a.emit(RSH_K, 0, 0, 0, 4);
    a.emit(LSH_K, 0, 0, 0, 2);
    a.jump(JLT_K, 0, 0, 20, failure);
    a.jump(JGT_X, 0, 4, 0, failure);
    a.go(done);
    a.bind(udp);
    a.jump(JLT_K, 4, 0, 8, failure);
    a.bound(8, failure);
    a.emit(LDX_H, 0, 6, 4, 0);
    a.emit(BE16, 0, 0, 0, 16);
    a.jump(JNE_X, 0, 4, 0, failure);
    a.bind(done);
    a.emit(LDX_W, 0, 6, 0, 0);
    a.emit(STX_W, 10, 0, KEY + 32, 0);
    a.copy(10, ORIGINAL, 10, KEY, size_of::<NativeKey>());
}

fn tuple(a: &mut Asm) {
    a.zero(10, TUPLE, 36);
    a.emit(LDX_B, 0, 10, KEY + 37, 0);
    let v6 = a.label();
    let ready = a.label();
    a.jump(JEQ_K, 0, 0, 6, v6);
    a.copy(10, TUPLE, 10, KEY + 12, 4);
    a.copy(10, TUPLE + 4, 10, KEY + 28, 4);
    a.copy(10, TUPLE + 8, 10, KEY + 32, 4);
    a.emit(MOV_K, 3, 0, 0, 12);
    a.go(ready);
    a.bind(v6);
    a.copy(10, TUPLE, 10, KEY, 32);
    a.copy(10, TUPLE + 32, 10, KEY + 32, 4);
    a.emit(MOV_K, 3, 0, 0, 36);
    a.bind(ready);
}

fn input_protocol(a: &mut Asm, base: u8, key: i16) {
    for (source, wire, destination, first, second) in [
        (
            36,
            6,
            std::mem::offset_of!(RoutingInput, l4proto),
            L4ProtoType::Tcp as i32,
            L4ProtoType::Udp as i32,
        ),
        (
            37,
            4,
            std::mem::offset_of!(RoutingInput, ip_version),
            IpVersionType::V4 as i32,
            IpVersionType::V6 as i32,
        ),
    ] {
        let mapped = a.label();
        a.emit(LDX_B, 0, base, key + source, 0);
        a.emit(MOV_K, 1, 0, 0, first);
        a.jump(JEQ_K, 0, 0, wire, mapped);
        a.emit(MOV_K, 1, 0, 0, second);
        a.bind(mapped);
        a.emit(STX_W, 8, 1, SCRATCH_INPUT + destination as i16, 0);
    }
}

fn probe(a: &mut Asm, layout: &layout::Layout, failure: Target) {
    tuple(a);
    a.zero(10, OPTS, size_of::<layout::CtOptions>());
    a.emit(
        ST_W,
        10,
        0,
        OPTS + std::mem::offset_of!(layout::CtOptions, netns_id) as i16,
        -1,
    );
    a.emit(LDX_B, 0, 10, KEY + 36, 0);
    a.emit(
        STX_B,
        10,
        0,
        OPTS + std::mem::offset_of!(layout::CtOptions, l4proto) as i16,
        0,
    );
    a.mov(1, 9);
    a.ptr(2, 10, TUPLE);
    a.ptr(4, 10, OPTS);
    a.emit(MOV_K, 5, 0, 0, size_of::<layout::CtOptions>() as i32);
    a.emit(CALL, 0, 2, layout.lookup_offset, layout.lookup as i32);
    let socket = a.label();
    let done = a.label();
    a.jump(JEQ_K, 0, 0, 0, socket);
    a.mov(6, 0);
    a.emit(ST_W, 10, 0, LIVE, 1);
    a.emit(ST_W, 10, 0, INVALID, 0);
    a.emit(
        LDX_B,
        0,
        10,
        OPTS + std::mem::offset_of!(layout::CtOptions, dir) as i16,
        0,
    );
    a.emit(STX_W, 10, 0, REPLY, 0);
    let invalid = a.label();
    let release = a.label();
    a.jump(JGT_K, 0, 0, 1, invalid);
    a.emit(LDX_H, 0, 6, layout.zone, 0);
    a.jump(JNE_K, 0, 0, 0, invalid);
    a.emit(LDX_B, 0, 6, layout.proto, 0);
    a.emit(LDX_B, 1, 10, KEY + 36, 0);
    a.jump(JNE_X, 0, 1, 0, invalid);
    a.zero(10, ORIGINAL, size_of::<NativeKey>());
    a.emit(STX_B, 10, 0, ORIGINAL + 36, 0);
    a.copy(10, ORIGINAL + 40, 10, KEY + 40, 16);
    a.emit(LDX_H, 0, 6, layout.family, 0);
    let v6 = a.label();
    a.jump(JEQ_K, 0, 0, libc::AF_INET6, v6);
    a.jump(JNE_K, 0, 0, libc::AF_INET, invalid);
    for (source, dest) in [(layout.src, ORIGINAL), (layout.dst, ORIGINAL + 16)] {
        a.emit(
            ST_W,
            10,
            0,
            dest + 8,
            u32::from_ne_bytes([0, 0, 255, 255]) as i32,
        );
        a.copy(10, dest + 12, 6, source, 4);
    }
    a.emit(ST_B, 10, 0, ORIGINAL + 37, 4);
    let ports = a.label();
    a.go(ports);
    a.bind(v6);
    a.copy(10, ORIGINAL, 6, layout.src, 16);
    a.copy(10, ORIGINAL + 16, 6, layout.dst, 16);
    a.emit(ST_B, 10, 0, ORIGINAL + 37, 6);
    a.bind(ports);
    for (source, dest) in [(layout.sport, ORIGINAL + 32), (layout.dport, ORIGINAL + 34)] {
        a.emit(LDX_H, 0, 6, source, 0);
        a.emit(STX_H, 10, 0, dest, 0);
    }
    a.go(release);
    a.bind(invalid);
    a.emit(ST_W, 10, 0, INVALID, 1);
    a.bind(release);
    a.mov(1, 6);
    a.emit(CALL, 0, 2, layout.release_offset, layout.release as i32);
    a.emit(LDX_W, 0, 10, INVALID, 0);
    a.jump(JNE_K, 0, 0, 0, failure);
    a.go(done);
    a.bind(socket);
    a.emit(LDX_W, 0, 10, OPTS + 4, 0);
    a.jump(JNE32_K, 0, 0, -libc::ENOENT, failure);
    tuple(a);
    a.mov(1, 9);
    a.ptr(2, 10, TUPLE);
    a.emit(MOV_K, 4, 0, 0, -1);
    a.emit(MOV_K, 5, 0, 0, 0);
    a.emit(LDX_B, 0, 10, KEY + 36, 0);
    let udp = a.label();
    let checked = a.label();
    a.jump(JEQ_K, 0, 0, 17, udp);
    a.emit(CALL, 0, 0, 0, 84);
    a.go(checked);
    a.bind(udp);
    a.emit(CALL, 0, 0, 0, 85);
    a.bind(checked);
    a.jump(JEQ_K, 0, 0, 0, done);
    a.mov(6, 0);
    let socket_release = a.label();
    let socket_ports = a.label();
    let socket_v6 = a.label();
    a.emit(LDX_B, 0, 10, KEY + 37, 0);
    a.jump(JEQ_K, 0, 0, 6, socket_v6);
    for (source, dest) in [
        (layout.socket_remote4, KEY + 12),
        (layout.socket_local4, KEY + 28),
    ] {
        a.emit(LDX_W, 0, 6, source, 0);
        a.emit(LDX_W, 1, 10, dest, 0);
        a.jump(JNE_X, 0, 1, 0, socket_release);
    }
    a.go(socket_ports);
    a.bind(socket_v6);
    for (source, dest) in [
        (layout.socket_remote6, KEY),
        (layout.socket_local6, KEY + 16),
    ] {
        for word in 0..4 {
            a.emit(LDX_W, 0, 6, source + word * 4, 0);
            a.emit(LDX_W, 1, 10, dest + word * 4, 0);
            a.jump(JNE_X, 0, 1, 0, socket_release);
        }
    }
    a.bind(socket_ports);
    a.emit(LDX_H, 0, 6, layout.socket_remote_port, 0);
    a.jump(JEQ_K, 0, 0, 0, socket_release);
    a.emit(LDX_H, 1, 10, KEY + 32, 0);
    a.jump(JNE_X, 0, 1, 0, socket_release);
    a.emit(LDX_W, 0, 6, layout.socket_local_port, 0);
    a.emit(LDX_H, 1, 10, KEY + 34, 0);
    a.emit(BE16, 1, 0, 0, 16);
    a.jump(JNE_X, 0, 1, 0, socket_release);
    a.emit(ST_W, 10, 0, LIVE, 1);
    a.emit(ST_W, 10, 0, REPLY, 2);
    a.bind(socket_release);
    a.mov(1, 6);
    a.emit(CALL, 0, 0, 0, 86);
    a.bind(done);
}

fn claim(a: &mut Asm, config: &NativeProgramConfig<'_>, key: i16, failure: Target) {
    a.lookup(config.claims, key);
    let absent = a.label();
    a.jump(JEQ_K, 0, 0, 0, absent);
    a.mov(6, 0);
    a.emit(LDX_DW, 0, 6, 0, 0);
    a.jump(JEQ_K, 0, 0, 0, failure);
    a.emit(AND_K, 0, 0, 0, 1);
    a.jump(JEQ_K, 0, 0, 0, failure);
    a.emit(LDX_DW, 0, 6, 16, 0);
    a.jump(JEQ_K, 0, 0, 0, failure);
    a.emit(LDX_W, 1, 6, 24, 0);
    let kernel_scope = a.label();
    let capture_scope = a.label();
    a.jump(JEQ_K, 1, 0, NATIVE_EXECUTOR_KERNEL as i32, kernel_scope);
    a.jump(JEQ_K, 1, 0, NATIVE_EXECUTOR_CAPTURE as i32, capture_scope);
    a.jump(JNE_K, 1, 0, NATIVE_EXECUTOR_PENDING as i32, failure);
    a.bind(capture_scope);
    a.imm(1, config.scope);
    a.jump(JNE_X, 0, 1, 0, failure);
    a.bind(kernel_scope);
    transit_selection(a, 6, failure);
    for offset in [40, 48, 56, 64] {
        a.emit(LDX_DW, 0, 6, offset, 0);
        a.jump(JNE_K, 0, 0, 0, failure);
    }
    a.emit(LDX_W, 0, 10, OWNER, 0);
    let first = a.label();
    a.jump(JEQ_K, 0, 0, 0, first);
    // The count changes independently; owner identity and executor must still agree.
    for offset in [0, 8, 16] {
        a.emit(LDX_DW, 0, 6, offset, 0);
        a.emit(LDX_DW, 1, 10, CLAIM + offset, 0);
        a.jump(JNE_X, 0, 1, 0, failure);
    }
    a.emit(LDX_W, 0, 6, 24, 0);
    a.emit(LDX_W, 1, 10, CLAIM + 24, 0);
    a.jump(JNE_X, 0, 1, 0, failure);
    a.bind(first);
    a.emit(LDX_DW, 0, 6, 8, 0);
    a.jump(JEQ_K, 0, 0, 0, failure);
    a.emit(LDX_DW, 1, 6, 0, 0);
    a.jump(JNE_X, 0, 1, 0, failure);
    a.emit(STX_DW, 10, 0, INCARNATION, 0);
    // TUPLE overlaps only the dead value tail; keep this copy narrowed to identity.
    for offset in (0..32).step_by(8) {
        a.emit(LDX_DW, 0, 6, offset, 0);
        a.emit(STX_DW, 10, 0, CLAIM + offset, 0);
    }
    a.emit(STX_DW, 10, 6, CLAIM_PTR, 0);
    a.emit(LDX_W, 0, 6, 24, 0);
    a.emit(STX_W, 10, 0, OWNER, 0);
    a.bind(absent);
}

fn transit_selection(a: &mut Asm, base: u8, failure: Target) {
    let capture = a.label();
    let kernel = a.label();
    let valid = a.label();
    a.emit(LDX_DW, 2, base, 24, 0);
    a.mov(1, 2);
    a.emit(LSH_K, 1, 0, 0, 32);
    a.emit(RSH_K, 1, 0, 0, 32);
    a.mov(0, 2);
    a.emit(RSH_K, 0, 0, 0, 32);
    a.mov(2, 0);
    a.emit(AND_K, 0, 0, 0, 15);
    a.jump(JEQ_K, 1, 0, NATIVE_EXECUTOR_CAPTURE as i32, capture);
    a.jump(JEQ_K, 1, 0, NATIVE_EXECUTOR_KERNEL as i32, kernel);
    a.jump(JNE_K, 1, 0, NATIVE_EXECUTOR_PENDING as i32, failure);
    a.jump(JNE_K, 0, 0, NATIVE_PHASE_PENDING as i32, failure);
    a.go(valid);
    a.bind(capture);
    a.jump(JNE_K, 0, 0, NATIVE_PHASE_CAPTURE_COMMITTED as i32, failure);
    a.go(valid);
    a.bind(kernel);
    a.jump(JEQ_K, 0, 0, NATIVE_PHASE_ARMED as i32, valid);
    a.jump(JEQ_K, 0, 0, NATIVE_PHASE_DRAINING as i32, valid);
    a.jump(JNE_K, 0, 0, NATIVE_PHASE_ACTIVE as i32, failure);
    a.jump(JNE_K, 2, 0, NATIVE_PHASE_ACTIVE as i32, failure);
    a.bind(valid);
}

fn reserve_redirect(a: &mut Asm, limit: u32, failure: Target) {
    let done = a.label();
    a.emit(ST_W, 10, 0, INVALID, 0);
    a.emit(LDX_DW, 6, 10, CLAIM_PTR, 0);
    a.jump(JEQ_K, 6, 0, 0, failure);
    a.emit(LDX_DW, 0, 6, 24, 0);
    for attempt in 0..4 {
        a.mov(1, 0);
        a.emit(LSH_K, 1, 0, 0, 32);
        a.emit(RSH_K, 1, 0, 0, 32);
        a.mov(2, 0);
        a.emit(RSH_K, 2, 0, 0, 32);
        a.emit(AND_K, 2, 0, 0, 15);
        let captured = a.label();
        let pending = a.label();
        let reservable = a.label();
        a.jump(JEQ_K, 1, 0, NATIVE_EXECUTOR_CAPTURE as i32, captured);
        a.jump(JEQ_K, 1, 0, NATIVE_EXECUTOR_PENDING as i32, pending);
        a.jump(JNE_K, 1, 0, NATIVE_EXECUTOR_KERNEL as i32, failure);
        a.jump(JEQ_K, 2, 0, NATIVE_PHASE_ARMED as i32, reservable);
        a.jump(JNE_K, 2, 0, NATIVE_PHASE_DRAINING as i32, failure);
        a.go(reservable);
        a.bind(pending);
        a.jump(JNE_K, 2, 0, NATIVE_PHASE_PENDING as i32, failure);
        a.go(reservable);
        a.bind(captured);
        a.jump(JNE_K, 2, 0, NATIVE_PHASE_CAPTURE_COMMITTED as i32, failure);
        a.go(done);
        a.bind(reservable);
        a.mov(1, 0);
        a.emit(RSH_K, 1, 0, 0, 36);
        a.jump(JGE_K, 1, 0, limit as i32, failure);
        a.mov(2, 0);
        a.mov(1, 0);
        a.imm(3, 1u64 << 36);
        a.emit(ADD_X, 1, 3, 0, 0);
        a.emit(ATOMIC_ADD_DW, 6, 1, 24, CMPXCHG_DW);
        let retry = a.label();
        a.jump(JNE_X, 0, 2, 0, retry);
        a.emit(ST_W, 10, 0, INVALID, NATIVE_IMPORT_COUNTED as i32);
        a.go(done);
        a.bind(retry);
        if attempt == 3 {
            a.go(failure);
        }
    }
    a.bind(done);
}

fn captured_wire_identity(a: &mut Asm, failure: Target) {
    // Metadata64 authenticates the wire key; a CT-only alias has no import consumer.
    for offset in (0..56).step_by(4) {
        a.emit(LDX_W, 0, 10, KEY + offset, 0);
        a.emit(LDX_W, 1, 10, ORIGINAL + offset, 0);
        a.jump(JNE_X, 0, 1, 0, failure);
    }
}

fn ordinary_kernel_udp(a: &mut Asm, other: Target) {
    a.emit(LDX_W, 0, 10, QUERY, 0);
    a.jump(JNE_K, 0, 0, 0, other);
    a.emit(LDX_W, 0, 10, OWNER, 0);
    a.jump(JNE_K, 0, 0, NATIVE_EXECUTOR_KERNEL as i32, other);
    a.emit(LDX_DW, 1, 10, CLAIM_PTR, 0);
    a.jump(JEQ_K, 1, 0, 0, other);
    a.emit(LDX_DW, 0, 1, 24, 0);
    a.imm(
        2,
        u64::from(NATIVE_EXECUTOR_KERNEL) | (u64::from(NATIVE_PHASE_ACTIVE) << 32),
    );
    a.jump(JNE_X, 0, 2, 0, other);
    for key in [KEY, ORIGINAL] {
        a.emit(LDX_B, 0, 10, key + 36, 0);
        a.jump(JNE_K, 0, 0, 17, other);
        for port in [32, 34] {
            a.emit(LDX_H, 0, 10, key + port, 0);
            a.jump(JEQ_K, 0, 0, i32::from(53_u16.to_be()), other);
        }
    }
}

fn retained_continuation(a: &mut Asm, pass: Target, failure: Target) {
    let other = a.label();
    ordinary_kernel_udp(a, other);
    a.emit(CALL, 0, 0, 0, 5);
    a.mov(2, 0);
    a.emit(LDX_DW, 1, 10, CLAIM_PTR, 0);
    a.jump(JEQ_K, 1, 0, 0, failure);
    a.emit(LDX_DW, 0, 1, CLAIM_LAST_SEEN, 0);
    let valid = a.label();
    a.jump(JGE_X, 0, 2, 0, valid);
    a.emit(SUB_X, 2, 0, 0, 0);
    a.imm(3, honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS);
    a.jump(JGT_X, 2, 3, 0, failure);
    a.bind(valid);
    a.emit(LDX_W, 0, 10, REPLY, 0);
    a.jump(JEQ_K, 0, 0, 0, pass);
    a.bind(other);
}

fn claim_activity(a: &mut Asm, failure: Target) {
    let done = a.label();
    a.emit(CALL, 0, 0, 0, 5);
    a.emit(STX_DW, 10, 0, ACTIVITY_NOW, 0);
    a.emit(LDX_DW, 1, 10, CLAIM_PTR, 0);
    a.jump(JEQ_K, 1, 0, 0, failure);
    a.emit(LDX_DW, 2, 10, ACTIVITY_NOW, 0);
    a.emit(LDX_DW, 0, 1, CLAIM_LAST_SEEN, 0);
    for attempt in 0..=4 {
        a.jump(JGE_X, 0, 2, 0, done);
        a.mov(3, 2);
        a.emit(SUB_X, 3, 0, 0, 0);
        a.imm(4, honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS);
        a.jump(JGT_X, 3, 4, 0, failure);
        a.imm(4, NATIVE_CLAIM_UPDATE_INTERVAL_NS);
        a.jump(JGE_X, 4, 3, 0, done);
        if attempt == 4 {
            a.go(failure);
        } else {
            a.mov(3, 0);
            a.emit(ATOMIC_ADD_DW, 1, 2, CLAIM_LAST_SEEN, CMPXCHG_DW);
            a.jump(JEQ_X, 0, 3, 0, done);
        }
    }
    a.bind(done);
}

fn frontier(a: &mut Asm, config: &NativeProgramConfig<'_>, failure: Target) {
    a.emit(LDX_DW, 1, 10, ROOT, 0);
    a.emit(LDX_DW, 0, 10, EPOCH, 0);
    a.mov(2, 0);
    a.emit(
        ATOMIC_ADD_DW,
        1,
        2,
        std::mem::offset_of!(NativeRoot, epoch) as i16,
        CMPXCHG_DW,
    );
    a.jump(JNE_X, 0, 2, 0, failure);
    a.emit(CALL, 0, 0, 0, 125);
    a.imm(1, config.expires_boottime_ns);
    a.jump(JGE_X, 0, 1, 0, failure);
}

fn route(
    a: &mut Asm,
    reply_block_rules: &[u32],
    direct: Target,
    capture_packet: Target,
    failure: Target,
) {
    let capture = a.label();
    a.emit(LDX_W, 0, 10, REPLY, 0);
    a.jump(JEQ_K, 0, 0, 2, direct);
    a.emit(LDX_W, 0, 8, OUTBOUND, 0);
    let decision = a.label();
    a.jump(JNE_K, 0, 0, 1, decision);
    a.emit(LDX_W, 0, 10, REPLY, 0);
    a.jump(JEQ_K, 0, 0, 0, failure);
    a.emit(
        LDX_W,
        0,
        8,
        SCRATCH_OUTPUT + std::mem::offset_of!(RoutingDecision, rule_id) as i16,
        0,
    );
    for rule in reply_block_rules {
        a.jump(JEQ32_K, 0, 0, *rule as i32, failure);
    }
    a.go(direct);
    a.bind(decision);
    a.emit(LDX_W, 0, 10, REPLY, 0);
    let completion = a.label();
    a.jump(JNE_K, 0, 0, 0, completion);
    a.emit(LDX_W, 0, 8, MARK_KIND, 0);
    a.jump(JNE_K, 0, 0, ROUTING_MARK_KEEP as i32, failure);
    a.emit(LDX_W, 0, 8, MARK, 0);
    a.jump(JNE_K, 0, 0, 0, failure);
    a.bind(completion);
    a.emit(LDX_W, 0, 10, OWNER, 0);
    a.jump(JEQ_K, 0, 0, NATIVE_EXECUTOR_CAPTURE as i32, capture);
    a.jump(JEQ_K, 0, 0, NATIVE_EXECUTOR_PENDING as i32, capture);
    a.emit(LDX_W, 0, 10, REPLY, 0);
    a.jump(JNE_K, 0, 0, 0, direct);
    a.emit(LDX_W, 0, 8, MUST, 0);
    let routed = a.label();
    a.jump(JNE_K, 0, 0, 0, routed);
    a.emit(LDX_H, 0, 10, ORIGINAL + 34, 0);
    a.jump(JEQ_K, 0, 0, i32::from(53_u16.to_be()), capture);
    a.emit(LDX_W, 0, 10, FLAGS, 0);
    a.jump(JSET_K, 0, 0, DATAPATH_FLAG_OFFLOAD_ALL as i32, direct);
    a.bind(routed);
    a.emit(LDX_W, 0, 8, OUTBOUND, 0);
    a.jump(JNE_K, 0, 0, 0, capture);
    a.emit(LDX_W, 0, 8, MUST, 0);
    a.jump(JNE_K, 0, 0, 0, direct);
    a.emit(LDX_W, 0, 10, FLAGS, 0);
    a.jump(JSET_K, 0, 0, DATAPATH_FLAG_OFFLOAD_ALL as i32, direct);
    a.emit(AND_K, 0, 0, 0, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as i32);
    a.jump(JEQ_K, 0, 0, 0, capture);
    a.emit(LDX_W, 0, 8, FINAL, 0);
    a.jump(JNE_K, 0, 0, 0, direct);
    a.bind(capture);
    // Retention fixes the executor; a new capture verdict cannot migrate it.
    a.emit(LDX_W, 0, 10, OWNER, 0);
    a.jump(JEQ_K, 0, 0, NATIVE_EXECUTOR_KERNEL as i32, failure);
    a.emit(LDX_W, 0, 10, LIVE, 0);
    a.jump(JNE_K, 0, 0, 0, failure);
    a.go(capture_packet);
}

fn closed_ordinary(a: &mut Asm, counters: RawFd, tc: bool, drop: Target) {
    let fault = a.label();
    a.emit(LDX_DW, 1, 10, EPOCH, 0);
    a.emit(RSH_K, 1, 0, 0, 1);
    a.emit(AND_K, 1, 0, 0, (NATIVE_COUNTER_GENERATIONS - 1) as i32);
    a.emit(LSH_K, 1, 0, 0, 1);
    a.emit(ADD_K, 1, 0, 0, i32::from(tc));
    a.emit(STX_W, 10, 1, INDEX, 0);
    a.lookup(counters, INDEX);
    a.jump(JEQ_K, 0, 0, 0, fault);
    a.emit(
        LDX_DW,
        1,
        0,
        std::mem::offset_of!(NativeClosedCounterV1, epoch) as i16,
        0,
    );
    a.emit(LDX_DW, 2, 10, EPOCH, 0);
    a.jump(JNE_X, 1, 2, 0, fault);
    a.emit(
        LDX_DW,
        1,
        0,
        std::mem::offset_of!(NativeClosedCounterV1, reserved) as i16,
        0,
    );
    a.jump(JNE_K, 1, 0, 0, fault);
    a.emit(
        LDX_DW,
        1,
        0,
        std::mem::offset_of!(NativeClosedCounterV1, overflow) as i16,
        0,
    );
    a.jump(JGT_K, 1, 0, 1, fault);
    a.emit(MOV_K, 1, 0, 0, 1);
    a.emit(
        ATOMIC_ADD_DW,
        0,
        1,
        std::mem::offset_of!(NativeClosedCounterV1, ordinary_drops) as i16,
        1,
    );
    a.jump(JNE_K, 1, 0, -1, drop);
    a.emit(MOV_K, 1, 0, 0, 1);
    a.emit(
        ATOMIC_ADD_DW,
        0,
        1,
        std::mem::offset_of!(NativeClosedCounterV1, overflow) as i16,
        0x40,
    );
    a.go(drop);
    a.bind(fault);
    a.emit(ST_W, 10, 0, INDEX, NATIVE_COUNTER_FAULT_INDEX as i32);
    a.lookup(counters, INDEX);
    // The admitted ARRAY has an initialized permanent cell at this fixed key.
    a.jump(JEQ_K, 0, 0, 0, drop);
    a.emit(MOV_K, 1, 0, 0, 1);
    a.emit(
        ATOMIC_ADD_DW,
        0,
        1,
        std::mem::offset_of!(NativeClosedCounterV1, overflow) as i16,
        0x40,
    );
    a.go(drop);
}

fn publication_gate(
    a: &mut Asm,
    config: &NativeProgramConfig<'_>,
    tc: bool,
    drop: Target,
    query_error: Target,
    parse: Target,
) {
    let ordinary = a.label();
    let open = a.label();
    a.emit(ST_W, 10, 0, INDEX, 0);
    a.lookup(config.root, INDEX);
    a.jump(JEQ_K, 0, 0, 0, query_error);
    a.emit(STX_DW, 10, 0, ROOT, 0);
    a.emit(
        LDX_DW,
        1,
        0,
        std::mem::offset_of!(NativeRoot, epoch) as i16,
        0,
    );
    a.emit(STX_DW, 10, 1, EPOCH, 0);
    a.emit(LDX_W, 2, 10, QUERY, 0);
    a.jump(JEQ_K, 2, 0, 0, ordinary);
    a.jump(JSET_K, 1, 0, 1, query_error);
    a.go(parse);
    a.bind(ordinary);
    a.jump(JSET_K, 1, 0, 1, open);
    closed_ordinary(a, config.closed_counters, tc, drop);
    a.bind(open);
    a.emit(LDX_DW, 0, 10, ROOT, 0);
    a.emit(
        LDX_W,
        1,
        0,
        std::mem::offset_of!(NativeRoot, flags) as i16,
        0,
    );
    a.emit(STX_W, 10, 1, FLAGS, 0);
}

pub(super) fn build(
    capture: &GeneralCapture,
    config: &NativeProgramConfig<'_>,
    counters: RawFd,
    xsks: RawFd,
    queues: u32,
    tc: bool,
) -> io::Result<Program> {
    validate_recording_config(config)?;
    validate_queues(queues)?;
    admit_claim_map(config.claims)?;
    if !cfg!(target_endian = "little")
        || !capture.authority.is_valid()
        || config.scope == 0
        || config.epoch == 0
        || config.expires_boottime_ns == 0
        || config.redirect_limit == 0
        || config.redirect_limit > NATIVE_OUTSTANDING_MAX
        || config.bytecode.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid native gate authority",
        ));
    }
    let layout = layout::Layout::read(tc, capture.vlan_metadata, config.preparation_memory_bytes)?;
    emit_program(capture, config, (counters, xsks), queues, tc, layout)
}

fn emit_program(
    capture: &GeneralCapture,
    config: &NativeProgramConfig<'_>,
    maps: (RawFd, RawFd),
    queues: u32,
    tc: bool,
    layout: layout::Layout,
) -> io::Result<Program> {
    let (counters, xsks) = maps;
    let vlan = layout.vlan;
    let wrapper_reserve = config
        .reply_block_rules
        .len()
        .checked_add(4096 + CLOSED_COUNTER_INSNS)
        .ok_or_else(|| io::Error::other("native wrapper instruction reservation overflow"))?;
    let initial_reserve = config
        .bytecode
        .len()
        .checked_add(wrapper_reserve)
        .ok_or_else(|| io::Error::other("native instruction reservation overflow"))?;
    let mut a = Asm::new();
    a.b.reserve(initial_reserve)?;
    let drop = a.label();
    let query_error = a.label();
    let query_finish = a.label();
    let locked_drop = a.label();
    let pass = a.label();
    let capture_packet = a.label();
    let direct = a.label();
    let classify = a.label();
    a.mov(9, 1);
    a.zero(10, ACTIVITY_NOW, -ACTIVITY_NOW as usize);
    // A full-width spill preserves a known NULL on paths with no claim.
    a.emit(MOV_K, 0, 0, 0, 0);
    a.emit(STX_DW, 10, 0, CLAIM_PTR, 0);
    if !tc {
        a.b.program.flags |= 1 << 5;
    }
    if vlan.is_some() {
        a.b.program.flags |= 1 << 6;
        a.b.program.ifindex = capture.authority.ifindex;
    }
    if tc {
        a.emit(LDX_W, 0, 9, 8, 0);
        let normal = a.label();
        a.jump(JNE32_K, 0, 0, QUERY_MARK as i32, normal);
        a.emit(ST_W, 10, 0, QUERY, 1);
        a.bind(normal);
    } else {
        a.emit(LDX_W, 0, 9, 16, 0);
        a.emit(STX_W, 10, 0, QUEUE, 0);
        a.jump(JGE_K, 0, 0, queues as i32, drop);
    }
    let parse = a.label();
    publication_gate(&mut a, config, tc, drop, query_error, parse);
    a.emit(LDX_W, 0, 9, if tc { 36 } else { 12 }, 0);
    a.jump(JNE32_K, 0, 0, capture.authority.ifindex as i32, drop);
    if tc {
        a.emit(LDX_W, 0, 9, 20, 0);
        a.jump(JNE_K, 0, 0, 0, drop);
    } else if let Some(vlan) = vlan {
        a.mov(1, 9);
        a.ptr(2, 10, TUPLE);
        a.ptr(3, 10, TUPLE + 2);
        a.emit(CALL, 0, 2, 0, vlan as i32);
        a.jump(JNE32_K, 0, 0, -libc::ENODATA, drop);
    }
    a.bind(parse);
    envelope(&mut a, tc, query_error);
    a.imm(0, capture.authority.namespace_cookie);
    a.emit(STX_DW, 10, 0, KEY + 40, 0);
    a.emit(ST_W, 10, 0, KEY + 48, 2 << 16);
    a.emit(ST_W, 10, 0, KEY + 52, 0);
    a.copy(10, ORIGINAL + 40, 10, KEY + 40, 16);
    a.emit(LDX_W, 0, 10, QUERY, 0);
    let probe_only = a.label();
    a.jump(JNE_K, 0, 0, 0, probe_only);
    claim(&mut a, config, KEY, drop);
    a.bind(probe_only);
    probe(&mut a, &layout, query_error);
    a.emit(LDX_W, 0, 10, QUERY, 0);
    a.jump(JNE_K, 0, 0, 0, query_finish);
    claim(&mut a, config, ORIGINAL, drop);
    a.emit(LDX_W, 0, 10, OWNER, 0);
    let no_capture = a.label();
    a.jump(JNE_K, 0, 0, NATIVE_EXECUTOR_CAPTURE as i32, no_capture);
    a.emit(LDX_W, 0, 10, LIVE, 0);
    a.jump(JNE_K, 0, 0, 0, drop);
    a.bind(no_capture);
    a.emit(CALL, 0, 0, 0, 8);
    a.emit(STX_W, 10, 0, INDEX, 0);
    a.lookup(config.scratch, INDEX);
    a.jump(JEQ_K, 0, 0, 0, drop);
    a.mov(8, 0);
    a.emit(MOV_K, 0, 0, 0, 0);
    a.emit(MOV_K, 1, 0, 0, 1);
    a.emit(CMPXCHG_W, 8, 1, SCRATCH_BUSY, CMPXCHG_DW);
    a.jump(JNE_K, 0, 0, 0, drop);
    if !tc {
        let ordinary = a.label();
        a.emit(LDX_DW, 6, 10, CLAIM_PTR, 0);
        a.jump(JEQ_K, 6, 0, 0, ordinary);
        transit_selection(&mut a, 6, locked_drop);
        a.jump(JNE_K, 1, 0, NATIVE_EXECUTOR_KERNEL as i32, ordinary);
        a.emit(AND_K, 2, 0, 0, 15);
        a.jump(JEQ_K, 2, 0, NATIVE_PHASE_ARMED as i32, capture_packet);
        a.jump(JEQ_K, 2, 0, NATIVE_PHASE_DRAINING as i32, capture_packet);
        a.bind(ordinary);
    }
    retained_continuation(&mut a, pass, locked_drop);
    a.zero(
        8,
        SCRATCH_INPUT,
        size_of::<RoutingInput>() + size_of::<KernelRouteOutput>(),
    );
    a.copy(8, SCRATCH_INPUT, 10, ORIGINAL, 32);
    for (source, dest) in [
        (
            ORIGINAL + 32,
            std::mem::offset_of!(RoutingInput, src_port) as i16,
        ),
        (
            ORIGINAL + 34,
            std::mem::offset_of!(RoutingInput, dst_port) as i16,
        ),
    ] {
        a.emit(LDX_H, 0, 10, source, 0);
        a.emit(BE16, 0, 0, 0, 16);
        a.emit(STX_W, 8, 0, SCRATCH_INPUT + dest, 0);
    }
    input_protocol(&mut a, 10, ORIGINAL);
    a.emit(LDX_W, 0, 10, DSCP, 0);
    a.emit(
        STX_W,
        8,
        0,
        SCRATCH_INPUT + std::mem::offset_of!(RoutingInput, dscp) as i16,
        0,
    );
    a.emit(LDX_W, 0, 10, FLAGS, 0);
    let global = a.label();
    a.jump(
        JSET_K,
        0,
        0,
        DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as i32,
        classify,
    );
    a.go(global);
    a.bind(classify);
    a.emit(
        ST_W,
        8,
        0,
        SCRATCH_INPUT + std::mem::offset_of!(RoutingInput, flags) as i16,
        ROUTING_INPUT_ALLOW_DIRECT_FINALITY as i32,
    );
    a.bind(global);
    a.ptr(1, 8, SCRATCH_INPUT);
    a.ptr(2, 8, SCRATCH_OUTPUT);
    let canonical_call = a.emit(CALL, 0, 1, 0, 0);
    a.jump(JNE_K, 0, 0, 0, locked_drop);
    route(
        &mut a,
        config.reply_block_rules,
        direct,
        capture_packet,
        locked_drop,
    );
    a.bind(direct);
    frontier(&mut a, config, locked_drop);
    a.emit(MOV_K, 6, 0, 0, NATIVE_EXECUTOR_KERNEL as i32);
    let publish = a.label();
    a.go(publish);
    a.bind(capture_packet);
    if tc {
        a.go(locked_drop);
    } else {
        captured_wire_identity(&mut a, locked_drop);
        frontier(&mut a, config, locked_drop);
        a.emit(MOV_K, 6, 0, 0, NATIVE_EXECUTOR_PENDING as i32);
    }
    a.bind(publish);
    a.emit(LDX_W, 0, 10, OWNER, 0);
    let winner = a.label();
    a.jump(JNE_K, 0, 0, 0, winner);
    a.zero(10, CLAIM, size_of::<NativeClaim>());
    a.emit(LDX_DW, 0, 10, EPOCH, 0);
    a.emit(
        STX_DW,
        10,
        0,
        CLAIM + std::mem::offset_of!(NativeClaim, epoch) as i16,
        0,
    );
    a.emit(
        STX_DW,
        10,
        0,
        CLAIM + std::mem::offset_of!(NativeClaim, incarnation) as i16,
        0,
    );
    a.imm(0, config.scope);
    a.emit(
        STX_DW,
        10,
        0,
        CLAIM + std::mem::offset_of!(NativeClaim, scope) as i16,
        0,
    );
    a.emit(
        STX_W,
        10,
        6,
        CLAIM + std::mem::offset_of!(NativeClaim, executor) as i16,
        0,
    );
    let pending_value = a.label();
    a.jump(JNE_K, 6, 0, NATIVE_EXECUTOR_KERNEL as i32, pending_value);
    a.emit(ST_W, 10, 0, CLAIM + 28, NATIVE_PHASE_ACTIVE as i32);
    a.bind(pending_value);
    a.emit(CALL, 0, 0, 0, 5);
    a.emit(STX_DW, 10, 0, CLAIM + CLAIM_LAST_SEEN, 0);
    a.b.map_fd(config.claims);
    a.ptr(2, 10, ORIGINAL);
    a.ptr(3, 10, CLAIM);
    a.emit(MOV_K, 4, 0, 0, 1);
    a.emit(CALL, 0, 0, 0, 2);
    let inserted = a.label();
    a.jump(JEQ_K, 0, 0, 0, inserted);
    a.jump(JNE32_K, 0, 0, -libc::EEXIST, locked_drop);
    a.bind(inserted);
    claim(&mut a, config, ORIGINAL, locked_drop);
    a.bind(winner);
    a.emit(LDX_DW, 6, 10, CLAIM_PTR, 0);
    a.jump(JEQ_K, 6, 0, 0, locked_drop);
    transit_selection(&mut a, 6, locked_drop);
    a.mov(0, 1);
    a.emit(STX_W, 10, 0, OWNER, 0);
    let captured_winner = a.label();
    a.jump(JNE_K, 0, 0, NATIVE_EXECUTOR_KERNEL as i32, captured_winner);
    if tc {
        a.go(pass);
    } else {
        a.emit(LDX_DW, 1, 10, CLAIM_PTR, 0);
        a.jump(JEQ_K, 1, 0, 0, locked_drop);
        a.emit(LDX_DW, 0, 1, 24, 0);
        a.imm(
            2,
            u64::from(NATIVE_EXECUTOR_KERNEL) | (u64::from(NATIVE_PHASE_ACTIVE) << 32),
        );
        a.jump(JEQ_X, 0, 2, 0, pass);
    }
    a.bind(captured_winner);
    a.emit(LDX_W, 0, 10, OWNER, 0);
    let capture_owner = a.label();
    a.jump(JEQ_K, 0, 0, NATIVE_EXECUTOR_KERNEL as i32, capture_owner);
    a.jump(JEQ_K, 0, 0, NATIVE_EXECUTOR_PENDING as i32, capture_owner);
    a.jump(JNE_K, 0, 0, NATIVE_EXECUTOR_CAPTURE as i32, locked_drop);
    a.bind(capture_owner);
    if tc {
        a.go(locked_drop);
    } else {
        let selected_kernel = a.label();
        a.emit(LDX_W, 0, 10, OWNER, 0);
        a.jump(JEQ_K, 0, 0, NATIVE_EXECUTOR_KERNEL as i32, selected_kernel);
        a.emit(LDX_W, 0, 10, LIVE, 0);
        a.jump(JNE_K, 0, 0, 0, locked_drop);
        a.bind(selected_kernel);
        captured_wire_identity(&mut a, locked_drop);
        a.emit(LDX_DW, 1, 10, CLAIM_PTR, 0);
        a.jump(JEQ_K, 1, 0, 0, locked_drop);
        a.emit(LDX_DW, 0, 1, 16, 0);
        a.imm(1, config.scope);
        a.jump(JNE_X, 0, 1, 0, locked_drop);
        frontier(&mut a, config, locked_drop);
        let metadata_failure = a.label();
        a.mov(1, 9);
        a.emit(MOV_K, 2, 0, 0, -(NATIVE_METADATA_LEN as i32));
        a.emit(CALL, 0, 0, 0, 54);
        a.jump(JNE_K, 0, 0, 0, metadata_failure);
        a.emit(LDX_W, 6, 9, 8, 0);
        a.emit(LDX_W, 7, 9, 0, 0);
        a.bound(NATIVE_METADATA_LEN as i32, metadata_failure);
        a.zero(6, 0, NATIVE_METADATA_LEN);
        a.emit(ST_H, 6, 0, 0, i32::from(METADATA_VERSION));
        a.emit(ST_H, 6, 0, 2, METADATA_LEN as i32);
        if capture.vlan_metadata {
            a.emit(ST_W, 6, 0, 4, honk_ebpf_common::xdp::RX_VLAN_CHECKED as i32);
        }
        a.emit(LDX_W, 0, 10, QUEUE, 0);
        a.emit(STX_W, 6, 0, 8, 0);
        a.emit(ST_W, 6, 0, 12, capture.authority.ifindex as i32);
        a.emit(ST_H, 6, 0, 16, 14);
        a.emit(LDX_W, 0, 10, ETHER_TYPE, 0);
        a.emit(STX_H, 6, 0, 18, 0);
        a.emit(LDX_DW, 0, 10, EPOCH, 0);
        a.emit(STX_DW, 6, 0, METADATA_LEN as i16, 0);
        a.emit(LDX_DW, 0, 10, INCARNATION, 0);
        a.emit(STX_DW, 6, 0, METADATA_LEN as i16 + 8, 0);
        a.imm(0, config.expires_boottime_ns);
        a.emit(STX_DW, 6, 0, METADATA_LEN as i16 + 16, 0);
        a.lookup(counters, QUEUE);
        a.jump(JEQ_K, 0, 0, 0, locked_drop);
        a.emit(MOV_K, 1, 0, 0, 1);
        a.emit(ATOMIC_ADD_DW, 0, 1, 0, 0);
        frontier(&mut a, config, locked_drop);
        reserve_redirect(&mut a, config.redirect_limit, locked_drop);
        a.emit(LDX_W, 6, 9, 8, 0);
        a.emit(LDX_W, 7, 9, 0, 0);
        a.bound(NATIVE_METADATA_LEN as i32, locked_drop);
        a.emit(LDX_W, 0, 10, INVALID, 0);
        a.emit(STX_W, 6, 0, METADATA_LEN as i16 + 24, 0);
        a.emit(ST_W, 8, 0, SCRATCH_BUSY, 0);
        a.b.map_fd(xsks);
        a.emit(LDX_W, 2, 10, QUEUE, 0);
        a.emit(MOV_K, 3, 0, 0, XDP_DROP);
        a.emit(CALL, 0, 0, 0, 51);
        a.emit(EXIT, 0, 0, 0, 0);
        a.bind(metadata_failure);
        a.emit(ST_W, 10, 0, INDEX, (queues + 3) as i32);
        a.lookup(counters, INDEX);
        a.jump(JEQ_K, 0, 0, 0, locked_drop);
        a.emit(MOV_K, 1, 0, 0, 1);
        a.emit(ATOMIC_ADD_DW, 0, 1, 0, 0);
        a.go(locked_drop);
    }
    a.bind(pass);
    if tc {
        a.emit(MOV_K, 0, 0, 0, 0);
    } else {
        a.emit(LDX_W, 0, 10, QUEUE, 0);
    }
    a.emit(STX_W, 10, 0, INDEX, 0);
    a.jump(JGE_K, 0, 0, queues as i32, locked_drop);
    a.lookup(xsks, INDEX);
    a.jump(JEQ_K, 0, 0, 0, locked_drop);
    let no_activity = a.label();
    ordinary_kernel_udp(&mut a, no_activity);
    claim_activity(&mut a, locked_drop);
    a.bind(no_activity);
    frontier(&mut a, config, locked_drop);
    a.emit(ST_W, 8, 0, SCRATCH_BUSY, 0);
    a.exit(if tc { 0 } else { XDP_PASS });
    a.bind(locked_drop);
    a.emit(ST_W, 8, 0, SCRATCH_BUSY, 0);
    a.go(drop);
    a.bind(query_finish);
    if tc {
        a.emit(LDX_DW, 1, 10, ROOT, 0);
        a.emit(
            LDX_DW,
            0,
            1,
            std::mem::offset_of!(NativeRoot, epoch) as i16,
            0,
        );
        a.emit(LDX_DW, 2, 10, EPOCH, 0);
        a.jump(JNE_X, 0, 2, 0, query_error);
        a.jump(JSET_K, 0, 0, 1, query_error);
        a.emit(ST_W, 9, 0, 48, QUERY_MARK as i32);
        a.emit(LDX_W, 0, 10, LIVE, 0);
        a.emit(STX_W, 9, 0, 52, 0);
        a.exit(2);
    } else {
        a.go(drop);
    }
    a.bind(query_error);
    if tc {
        a.emit(LDX_W, 0, 10, QUERY, 0);
        a.jump(JEQ_K, 0, 0, 0, drop);
        a.emit(ST_W, 9, 0, 48, QUERY_MARK as i32);
        a.emit(ST_W, 9, 0, 52, 2);
    }
    a.bind(drop);
    a.exit(if tc { 2 } else { XDP_DROP });
    if a.b.program.len > wrapper_reserve {
        return Err(invalid_data(
            "Native wrapper exceeds its charged instruction reservation",
        ));
    }
    a.b.reserve(config.bytecode.len())?;
    let body = a.b.program.len;
    a.b.program.insns[canonical_call].imm =
        i32::try_from(body as isize - canonical_call as isize - 1)
            .map_err(|_| invalid_data("native canonical call offset exceeds i32"))?;
    for instruction in config.bytecode {
        a.emit(
            instruction.code,
            instruction.dst_reg(),
            instruction.src_reg(),
            instruction.off,
            instruction.imm,
        );
    }
    let mut program = a.finish()?;
    program.kfunc_btf = layout.btf;
    Ok(program)
}

pub(super) fn kernel_owned(program: BorrowedFd<'_>, key: &NativeKey) -> io::Result<bool> {
    if !key.is_valid()
        || key.domain != 0
        || key.direction != 0
        || key.zone != 0
        || key.zone_state != 2
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid native gate query key",
        ));
    }
    if key.ip_version == 4
        && [key.src_ip, key.dst_ip]
            .iter()
            .any(|ip| ip[..3] != [0, 0, u32::from_ne_bytes([0, 0, 255, 255])])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native IPv4 query key is not canonical mapped IP",
        ));
    }
    let ip = if key.ip_version == 4 { 20 } else { 40 };
    let l4 = if key.l4proto == 6 { 20 } else { 8 };
    let mut packet = vec![0u8; 14 + ip + l4];
    packet[0] = 2;
    packet[6] = 2;
    packet[12..14].copy_from_slice(
        &(if key.ip_version == 4 {
            0x0800u16
        } else {
            0x86dd
        })
        .to_be_bytes(),
    );
    let octets = |words: &[u32; 4]| {
        let mut bytes = [0u8; 16];
        for (word, chunk) in words.iter().zip(bytes.as_chunks_mut::<4>().0) {
            chunk.copy_from_slice(&word.to_ne_bytes());
        }
        bytes
    };
    if key.ip_version == 4 {
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&((ip + l4) as u16).to_be_bytes());
        packet[22] = 64;
        packet[23] = key.l4proto;
        packet[26..30].copy_from_slice(&octets(&key.src_ip)[12..]);
        packet[30..34].copy_from_slice(&octets(&key.dst_ip)[12..]);
    } else {
        packet[14] = 0x60;
        packet[18..20].copy_from_slice(&(l4 as u16).to_be_bytes());
        packet[20] = key.l4proto;
        packet[21] = 64;
        packet[22..38].copy_from_slice(&octets(&key.src_ip));
        packet[38..54].copy_from_slice(&octets(&key.dst_ip));
    }
    let transport = 14 + ip;
    packet[transport..transport + 2].copy_from_slice(&key.src_port.to_ne_bytes());
    packet[transport + 2..transport + 4].copy_from_slice(&key.dst_port.to_ne_bytes());
    if key.l4proto == 6 {
        packet[transport + 12] = 0x50;
    } else {
        packet[transport + 4..transport + 6].copy_from_slice(&(l4 as u16).to_be_bytes());
    }
    let mut input = [0u32; 48];
    let mut output = [0u32; 48];
    input[2] = QUERY_MARK;
    #[repr(C)]
    struct TestRun {
        fd: u32,
        retval: u32,
        size_in: u32,
        size_out: u32,
        data_in: u64,
        data_out: u64,
        repeat: u32,
        duration: u32,
        ctx_size_in: u32,
        ctx_size_out: u32,
        ctx_in: u64,
        ctx_out: u64,
        flags: u32,
        cpu: u32,
        batch_size: u32,
        reserved: u32,
    }
    let mut attr = TestRun {
        fd: program.as_raw_fd() as u32,
        retval: 0,
        size_in: packet.len() as u32,
        size_out: 0,
        data_in: packet.as_ptr() as u64,
        data_out: 0,
        repeat: 1,
        duration: 0,
        ctx_size_in: size_of::<[u32; 48]>() as u32,
        ctx_size_out: size_of::<[u32; 48]>() as u32,
        ctx_in: input.as_ptr() as u64,
        ctx_out: output.as_mut_ptr() as u64,
        flags: 0,
        cpu: 0,
        batch_size: 0,
        reserved: 0,
    };
    bpf(10, &mut attr)?;
    if attr.retval != 2 || output[12] != QUERY_MARK || attr.ctx_size_out < 56 {
        return Err(invalid_data(
            "native gate query returned no authenticated result",
        ));
    }
    match output[13] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(io::Error::other("native gate CT/socket query refused")),
    }
}

#[cfg(test)]
pub(in crate::bpf) mod tests {
    use super::*;

    fn gate_config() -> NativeProgramConfig<'static> {
        NativeProgramConfig {
            bytecode: &[],
            root: 11,
            claims: 13,
            scratch: 14,
            closed_counters: 12,
            hook_ids: [1, 2],
            epoch: 2,
            scope: 1,
            expires_boottime_ns: 100,
            reply_block_rules: &[],
            preparation_memory_bytes: 0,
            redirect_limit: 16,
            captured: None,
        }
    }

    const STACK_ADDR: usize = 0x1200;
    const ROOT_ADDR: usize = 0x2000;
    const CLAIM_ADDR: usize = 0x2100;
    const ORIGINAL_CLAIM_ADDR: usize = 0x2200;
    const SCRATCH_ADDR: usize = 0x3000;
    const CT_ADDR: usize = 0x4000;
    const CONTEXT_ADDR: usize = 0x5000;
    const PACKET_ADDR: usize = 0x6000;

    fn put(memory: &mut [u8], at: usize, value: u64, size: usize) {
        memory[at..at + size].copy_from_slice(&value.to_ne_bytes()[..size]);
    }

    fn claim_bytes(claim: NativeClaim) -> [u8; NATIVE_CLAIM_VALUE_BYTES] {
        let mut bytes = [0; NATIVE_CLAIM_VALUE_BYTES];
        for (at, value, size) in [
            (0, claim.epoch, 8),
            (8, claim.incarnation, 8),
            (16, claim.scope, 8),
            (24, u64::from(claim.executor), 4),
            (28, u64::from(claim.state), 4),
            (32, claim.last_seen_ns, 8),
            (40, claim.owner_cookie, 8),
            (48, claim.owner_incarnation, 8),
            (56, claim.attachment_generation, 8),
            (64, u64::from(claim.mark_kind), 4),
            (68, u64::from(claim.mark_value), 4),
        ] {
            put(&mut bytes, at, value, size);
        }
        bytes
    }

    fn test_layout() -> layout::Layout {
        layout::Layout {
            lookup: 1000,
            release: 1001,
            lookup_offset: 0,
            release_offset: 0,
            btf: None,
            vlan: None,
            src: 0,
            dst: 16,
            sport: 32,
            dport: 34,
            family: 36,
            proto: 38,
            zone: 40,
            socket_remote4: 0,
            socket_local4: 4,
            socket_remote6: 8,
            socket_local6: 24,
            socket_remote_port: 40,
            socket_local_port: 44,
        }
    }

    fn test_capture() -> GeneralCapture {
        GeneralCapture {
            authority: honk_ebpf_common::xdp::CaptureAuthority {
                namespace_cookie: 1,
                attachment_generation: 2,
                scope: 1,
                config_generation: 4,
                ifindex: 1,
                reserved: 0,
            },
            bypass_mark: 128,
            vlan_metadata: false,
        }
    }

    struct NativeRun {
        key: [u8; 56],
        claim: Option<NativeClaim>,
        original: Option<[u8; 56]>,
        original_claim: Option<NativeClaim>,
        race: Option<NativeClaim>,
        second_activity: Option<u64>,
        miss_second: bool,
        now: u64,
        pass_now: Option<u64>,
        boot: u64,
        epoch: u64,
        final_epoch: Option<u64>,
        xsk: bool,
        busy: u32,
        query: bool,
        socket: bool,
        reply: u8,
        redirect_limit: u32,
        selection_values: Vec<u64>,
        probe_error: bool,
        canonical_result: i32,
        output: KernelRouteOutput,
        flags: u32,
        cas_values: Vec<u64>,
    }

    impl Default for NativeRun {
        fn default() -> Self {
            let mut key = [0; 56];
            key[8..16].copy_from_slice(&[0, 0, 255, 255, 192, 0, 2, 2]);
            key[24..32].copy_from_slice(&[0, 0, 255, 255, 198, 51, 100, 2]);
            key[32..34].copy_from_slice(&45004u16.to_be_bytes());
            key[34..36].copy_from_slice(&18101u16.to_be_bytes());
            key[36] = 17;
            key[37] = 4;
            key[40..48].copy_from_slice(&1u64.to_ne_bytes());
            key[50] = 2;
            Self {
                key,
                claim: Some(NativeClaim {
                    epoch: 3,
                    incarnation: 3,
                    scope: 2,
                    executor: NATIVE_EXECUTOR_KERNEL,
                    state: NATIVE_PHASE_ACTIVE,
                    last_seen_ns: 10_000_000_000,
                    ..NativeClaim::default()
                }),
                original: None,
                original_claim: None,
                race: None,
                second_activity: None,
                miss_second: false,
                now: 12_000_000_000,
                pass_now: None,
                boot: 50,
                epoch: 5,
                final_epoch: None,
                xsk: true,
                busy: 0,
                query: false,
                socket: false,
                reply: 0,
                probe_error: false,
                redirect_limit: 16,
                selection_values: Vec::new(),
                canonical_result: 0,
                output: KernelRouteOutput {
                    decision: RoutingDecision {
                        outbound: 0,
                        domain_final: 1,
                        ..RoutingDecision::default()
                    },
                    ..KernelRouteOutput::default()
                },
                flags: DATAPATH_FLAG_OFFLOAD_RULE_DIRECT,
                cas_values: Vec::new(),
            }
        }
    }

    struct NativeResult {
        action: u64,
        memory: Vec<u8>,
        canonical_calls: usize,
        clock_calls: usize,
        activity_atomics: usize,
        updates: usize,
        redirects: usize,
        events: Vec<&'static str>,
    }

    impl NativeRun {
        fn run(&self, tc: bool) -> NativeResult {
            let config = NativeProgramConfig {
                reply_block_rules: &[7],
                redirect_limit: self.redirect_limit,
                ..gate_config()
            };
            let program =
                emit_program(&test_capture(), &config, (15, 16), 1, tc, test_layout()).unwrap();
            let mut memory = vec![0; 0x7000];
            memory[STACK_ADDR - 512..STACK_ADDR].fill(0xa5);
            put(&mut memory, ROOT_ADDR, self.epoch, 8);
            put(
                &mut memory,
                ROOT_ADDR + std::mem::offset_of!(NativeRoot, flags),
                u64::from(self.flags),
                4,
            );
            put(
                &mut memory,
                SCRATCH_ADDR + SCRATCH_BUSY as usize,
                u64::from(self.busy),
                4,
            );
            let mut claim_present = self.claim.is_some();
            let mut stored_key = self.key;
            if let Some(claim) = self.claim {
                memory[CLAIM_ADDR..CLAIM_ADDR + 72].copy_from_slice(&claim_bytes(claim));
            }
            if let Some(claim) = self.original_claim {
                memory[ORIGINAL_CLAIM_ADDR..ORIGINAL_CLAIM_ADDR + 72]
                    .copy_from_slice(&claim_bytes(claim));
            }
            let transport = if self.key[36] == 6 { 20 } else { 8 };
            let length = 14 + 20 + transport;
            memory[PACKET_ADDR + 12..PACKET_ADDR + 14].copy_from_slice(&0x0800u16.to_be_bytes());
            memory[PACKET_ADDR + 14] = 0x45;
            memory[PACKET_ADDR + 16..PACKET_ADDR + 18]
                .copy_from_slice(&((20 + transport) as u16).to_be_bytes());
            memory[PACKET_ADDR + 23] = self.key[36];
            memory[PACKET_ADDR + 26..PACKET_ADDR + 30].copy_from_slice(&self.key[12..16]);
            memory[PACKET_ADDR + 30..PACKET_ADDR + 34].copy_from_slice(&self.key[28..32]);
            memory[PACKET_ADDR + 34..PACKET_ADDR + 38].copy_from_slice(&self.key[32..36]);
            if transport == 8 {
                memory[PACKET_ADDR + 38..PACKET_ADDR + 40].copy_from_slice(&8u16.to_be_bytes());
            } else {
                memory[PACKET_ADDR + 46] = 0x50;
            }
            if tc {
                put(&mut memory, CONTEXT_ADDR, length as u64, 4);
                put(
                    &mut memory,
                    CONTEXT_ADDR + 8,
                    if self.query { u64::from(QUERY_MARK) } else { 0 },
                    4,
                );
                put(&mut memory, CONTEXT_ADDR + 36, 1, 4);
                put(&mut memory, CONTEXT_ADDR + 76, PACKET_ADDR as u64, 4);
                put(
                    &mut memory,
                    CONTEXT_ADDR + 80,
                    (PACKET_ADDR + length) as u64,
                    4,
                );
            } else {
                put(&mut memory, CONTEXT_ADDR, PACKET_ADDR as u64, 4);
                put(
                    &mut memory,
                    CONTEXT_ADDR + 4,
                    (PACKET_ADDR + length) as u64,
                    4,
                );
                put(&mut memory, CONTEXT_ADDR + 12, 1, 4);
            }
            let mut regs = [0; 11];
            let mut selection_atomics = 0;
            regs[1] = CONTEXT_ADDR as u64;
            regs[10] = STACK_ADDR as u64;
            let mut canonical_calls = 0;
            let mut clock_calls = 0;
            let mut activity_atomics = 0;
            let mut updates = 0;
            let mut redirects = 0;
            let mut claim_lookups = 0;
            let mut events = Vec::new();
            let action = execute(&program, &mut memory, &mut regs, |insn, regs, memory| {
                if insn.code == ATOMIC_ADD_DW && insn.imm == CMPXCHG_DW {
                    let dst = (insn.regs & 15) as usize;
                    if regs[dst] == ROOT_ADDR as u64 {
                        events.push("frontier");
                        if let Some(epoch) = self.final_epoch {
                            put(memory, ROOT_ADDR, epoch, 8);
                        }
                    } else if insn.off == CLAIM_LAST_SEEN {
                        events.push("activity");
                        if let Some(value) = self.cas_values.get(activity_atomics) {
                            put(
                                memory,
                                regs[dst] as usize + CLAIM_LAST_SEEN as usize,
                                *value,
                                8,
                            );
                        }
                        activity_atomics += 1;
                    } else {
                        events.push("selection");
                        if let Some(value) = self.selection_values.get(selection_atomics) {
                            put(memory, regs[dst] as usize + 24, *value, 8);
                        }
                        selection_atomics += 1;
                    }
                }
                if insn.code == ST_W && insn.off == SCRATCH_BUSY && insn.regs & 15 == 8 {
                    events.push("release");
                }
                if insn.code == EXIT {
                    events.push("exit");
                }
                if insn.code != CALL {
                    return false;
                }
                let source = insn.regs >> 4;
                regs[0] = match (source, insn.imm) {
                    (1, _) => {
                        canonical_calls += 1;
                        events.push("canonical");
                        for (offset, value) in [
                            (OUTBOUND, self.output.decision.outbound),
                            (MARK, self.output.decision.mark),
                            (MARK_KIND, self.output.mark_kind),
                            (MUST, self.output.decision.must),
                            (FINAL, self.output.decision.domain_final),
                            (
                                SCRATCH_OUTPUT
                                    + std::mem::offset_of!(RoutingDecision, rule_id) as i16,
                                self.output.decision.rule_id,
                            ),
                        ] {
                            put(memory, SCRATCH_ADDR + offset as usize, u64::from(value), 4);
                        }
                        self.canonical_result as i64 as u64
                    }
                    (2, 1000) => {
                        let opts = regs[4] as usize;
                        if let (false, Some(original)) = (self.probe_error, self.original) {
                            memory[CT_ADDR..CT_ADDR + 4].copy_from_slice(&original[12..16]);
                            memory[CT_ADDR + 16..CT_ADDR + 20].copy_from_slice(&original[28..32]);
                            memory[CT_ADDR + 32..CT_ADDR + 36].copy_from_slice(&original[32..36]);
                            put(memory, CT_ADDR + 36, libc::AF_INET as u64, 2);
                            memory[CT_ADDR + 38] = original[36];
                            memory[opts + std::mem::offset_of!(layout::CtOptions, dir)] =
                                self.reply;
                            CT_ADDR as u64
                        } else {
                            put(
                                memory,
                                opts + 4,
                                if self.probe_error {
                                    -libc::EPERM
                                } else {
                                    -libc::ENOENT
                                } as i64 as u64,
                                4,
                            );
                            0
                        }
                    }
                    (2, 1001) | (0, 86) => {
                        events.push("probe-release");
                        0
                    }
                    (0, 84 | 85) => {
                        if self.socket {
                            memory[CT_ADDR..CT_ADDR + 4].copy_from_slice(&self.key[12..16]);
                            memory[CT_ADDR + 4..CT_ADDR + 8].copy_from_slice(&self.key[28..32]);
                            memory[CT_ADDR + 40..CT_ADDR + 42].copy_from_slice(&self.key[32..34]);
                            put(
                                memory,
                                CT_ADDR + 44,
                                u64::from(u16::from_be_bytes(self.key[34..36].try_into().unwrap())),
                                4,
                            );
                            CT_ADDR as u64
                        } else {
                            0
                        }
                    }
                    (0, 188) => length as u64,
                    (0, 8) => 0,
                    (0, 5) => {
                        clock_calls += 1;
                        events.push("monotonic");
                        if clock_calls > 1 {
                            self.pass_now.unwrap_or(self.now)
                        } else {
                            self.now
                        }
                    }
                    (0, 125) => {
                        events.push("boot");
                        self.boot
                    }
                    (0, 1) => match regs[1] as i32 {
                        11 => {
                            let start = (STACK_ADDR as isize + isize::from(ACTIVITY_NOW)) as usize;
                            let end = (STACK_ADDR as isize + isize::from(FRAME_LEN)) as usize;
                            assert!(memory[start..end].iter().all(|byte| *byte == 0));
                            ROOT_ADDR as u64
                        }
                        12 | 15 => 0x2300,
                        14 => SCRATCH_ADDR as u64,
                        16 => {
                            if self.xsk {
                                0x2400
                            } else {
                                0
                            }
                        }
                        13 => {
                            claim_lookups += 1;
                            if claim_lookups == 2 {
                                if let Some(now) = self.second_activity {
                                    put(memory, CLAIM_ADDR + CLAIM_LAST_SEEN as usize, now, 8);
                                }
                                if self.miss_second {
                                    regs[0] = 0;
                                    regs[1..6].fill(0xdead);
                                    return true;
                                }
                            }
                            let key = regs[2] as usize;
                            if memory[key..key + 56] == stored_key {
                                if claim_present { CLAIM_ADDR as u64 } else { 0 }
                            } else if self
                                .original
                                .is_some_and(|original| memory[key..key + 56] == original)
                                && self.original_claim.is_some()
                            {
                                ORIGINAL_CLAIM_ADDR as u64
                            } else {
                                0
                            }
                        }
                        other => panic!("unexpected native map {other}"),
                    },
                    (0, 2) => {
                        updates += 1;
                        assert_eq!(regs[4], 1);
                        let key = regs[2] as usize;
                        assert_eq!(&memory[key..key + 56], &self.original.unwrap_or(self.key));
                        stored_key.copy_from_slice(&memory[key..key + 56]);
                        let at = regs[3] as usize;
                        let bytes: [u8; 72] = memory[at..at + 72].try_into().unwrap();
                        let raced = self.race.map(claim_bytes);
                        memory[CLAIM_ADDR..CLAIM_ADDR + 72]
                            .copy_from_slice(raced.as_ref().unwrap_or(&bytes));
                        claim_present = true;
                        if raced.is_some() {
                            -libc::EEXIST as i64 as u64
                        } else {
                            0
                        }
                    }
                    (0, 54) => {
                        put(
                            memory,
                            CONTEXT_ADDR + 8,
                            (PACKET_ADDR - NATIVE_METADATA_LEN) as u64,
                            4,
                        );
                        0
                    }
                    (0, 51) => {
                        redirects += 1;
                        4
                    }
                    other => panic!("unexpected native helper {other:?}"),
                };
                // Kernel calls destroy caller-saved registers; typed pointers must survive in spills.
                regs[1..6].fill(0xdead);
                true
            });
            NativeResult {
                action,
                memory,
                canonical_calls,
                clock_calls,
                activity_atomics,
                updates,
                redirects,
                events,
            }
        }
    }

    fn load(memory: &[u8], at: usize, size: usize) -> u64 {
        let mut bytes = [0u8; 8];
        bytes[..size].copy_from_slice(&memory[at..at + size]);
        u64::from_ne_bytes(bytes)
    }

    pub(in crate::bpf) fn execute(
        program: &Program,
        memory: &mut [u8],
        regs: &mut [u64; 11],
        mut external: impl FnMut(&Insn, &mut [u64; 11], &mut [u8]) -> bool,
    ) -> u64 {
        let mut pc = 0usize;
        for _ in 0..program.len {
            let insn = program.insns[pc];
            if external(&insn, regs, memory) {
                pc += 1;
                continue;
            }
            let dst = (insn.regs & 15) as usize;
            let src = (insn.regs >> 4) as usize;
            let imm = insn.imm as i64 as u64;
            let address = |base: u64| base.wrapping_add_signed(i64::from(insn.off)) as usize;
            let mut jump = false;
            match insn.code {
                LD_MAP => {
                    regs[dst] = u64::from(insn.imm as u32)
                        | (u64::from(program.insns[pc + 1].imm as u32) << 32);
                    pc += 2;
                    continue;
                }
                MOV_K => regs[dst] = imm,
                MOV_X => regs[dst] = regs[src],
                0xbc => regs[dst] = u64::from(regs[src] as u32),
                ADD_K => regs[dst] = regs[dst].wrapping_add(imm),
                ADD_X => regs[dst] = regs[dst].wrapping_add(regs[src]),
                SUB_X => regs[dst] = regs[dst].wrapping_sub(regs[src]),
                AND_K => regs[dst] &= imm,
                LSH_K => regs[dst] <<= insn.imm,
                RSH_K => regs[dst] >>= insn.imm,
                BE16 => regs[dst] = u64::from((regs[dst] as u16).to_be()),
                LDX_DW | LDX_W | LDX_H | LDX_B => {
                    let size = match insn.code {
                        LDX_DW => 8,
                        LDX_W => 4,
                        LDX_H => 2,
                        _ => 1,
                    };
                    regs[dst] = load(memory, address(regs[src]), size);
                }
                0x7a | ST_W | ST_H | ST_B | STX_DW | STX_W | STX_H | STX_B => {
                    let (size, value) = match insn.code {
                        0x7a => (8, imm),
                        ST_W => (4, imm),
                        ST_H => (2, imm),
                        ST_B => (1, imm),
                        STX_DW => (8, regs[src]),
                        STX_W => (4, regs[src]),
                        STX_H => (2, regs[src]),
                        _ => (1, regs[src]),
                    };
                    let at = address(regs[dst]);
                    memory[at..at + size].copy_from_slice(&value.to_ne_bytes()[..size]);
                }
                ATOMIC_ADD_DW | CMPXCHG_W => {
                    let at = address(regs[dst]);
                    let size = if insn.code == CMPXCHG_W { 4 } else { 8 };
                    let old = load(memory, at, size);
                    let value = match insn.imm {
                        0 => old.wrapping_add(regs[src]),
                        1 => {
                            let value = old.wrapping_add(regs[src]);
                            regs[src] = old;
                            value
                        }
                        0x40 => old | regs[src],
                        CMPXCHG_DW => {
                            let value = if old == regs[0] { regs[src] } else { old };
                            regs[0] = old;
                            value
                        }
                        other => panic!("unexpected native atomic {other}"),
                    };
                    memory[at..at + size].copy_from_slice(&value.to_ne_bytes()[..size]);
                }
                JA => jump = true,
                JEQ_K => jump = regs[dst] == imm,
                JEQ32_K => jump = regs[dst] as u32 == insn.imm as u32,
                JEQ_X => jump = regs[dst] == regs[src],
                JNE_K => jump = regs[dst] != imm,
                JNE32_K => jump = regs[dst] as u32 != insn.imm as u32,
                JNE_X => jump = regs[dst] != regs[src],
                JGT_K => jump = regs[dst] > imm,
                JGT_X => jump = regs[dst] > regs[src],
                JGE_K => jump = regs[dst] >= imm,
                JGE_X => jump = regs[dst] >= regs[src],
                JLT_K => jump = regs[dst] < imm,
                0xad => jump = regs[dst] < regs[src],
                JSET_K => jump = regs[dst] & imm != 0,
                EXIT => return regs[0],
                other => panic!("unexpected native opcode {other:#x}"),
            }
            pc = pc
                .checked_add_signed(1 + if jump { isize::from(insn.off) } else { 0 })
                .unwrap();
        }
        panic!("native instructions did not terminate");
    }

    fn ipv6_frame(
        extensions: &[(u8, usize, u8)],
        proto: u8,
        declared_payload: Option<u16>,
        upper_length: Option<u16>,
    ) -> Vec<u8> {
        let mut upper = vec![0; if proto == 6 { 20 } else { 8 }];
        upper[..2].copy_from_slice(&12345u16.to_be_bytes());
        upper[2..4].copy_from_slice(&443u16.to_be_bytes());
        if proto == 6 {
            upper[12] = 0x50;
        } else if proto == 17 {
            upper[4..6].copy_from_slice(&upper_length.unwrap_or(8).to_be_bytes());
        }
        let extension_bytes: usize = extensions.iter().map(|(_, length, _)| *length).sum();
        let mut payload = Vec::with_capacity(extension_bytes + upper.len());
        for (index, &(kind, length, segments_left)) in extensions.iter().enumerate() {
            let mut header = vec![0; length];
            header[0] = extensions
                .get(index + 1)
                .map_or(proto, |&(next, _, _)| next);
            header[1] = (length / 8 - 1) as u8;
            if kind == 43 {
                header[3] = segments_left;
            }
            payload.extend_from_slice(&header);
        }
        payload.extend_from_slice(&upper);
        let mut frame = vec![0; 14 + 40 + payload.len()];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let ip = 14;
        frame[ip] = 0x6a;
        frame[ip + 1] = 0x90;
        frame[ip + 4..ip + 6].copy_from_slice(
            &declared_payload
                .unwrap_or(payload.len() as u16)
                .to_be_bytes(),
        );
        frame[ip + 6] = extensions.first().map_or(proto, |&(kind, _, _)| kind);
        frame[ip + 7] = 64;
        frame[ip + 8..ip + 24]
            .copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        frame[ip + 24..ip + 40]
            .copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        frame[ip + 40..].copy_from_slice(&payload);
        frame
    }

    fn run_envelope(frame: &[u8], accessible: usize, tc: bool) -> (u64, [u8; 56], Vec<u8>) {
        let mut a = Asm::new();
        let failure = a.label();
        envelope(&mut a, tc, failure);
        a.exit(1);
        a.bind(failure);
        a.exit(0);
        let program = a.finish().unwrap();
        let mut memory = vec![0; 0x7000];
        memory[PACKET_ADDR..PACKET_ADDR + frame.len()].copy_from_slice(frame);
        put(
            &mut memory,
            CONTEXT_ADDR,
            if tc {
                frame.len() as u64
            } else {
                PACKET_ADDR as u64
            },
            4,
        );
        put(
            &mut memory,
            CONTEXT_ADDR + 4,
            (PACKET_ADDR + accessible) as u64,
            4,
        );
        put(&mut memory, CONTEXT_ADDR + 76, PACKET_ADDR as u64, 4);
        put(
            &mut memory,
            CONTEXT_ADDR + 80,
            (PACKET_ADDR + accessible) as u64,
            4,
        );
        let mut regs = [0; 11];
        regs[1] = CONTEXT_ADDR as u64;
        regs[9] = CONTEXT_ADDR as u64;
        regs[10] = STACK_ADDR as u64;
        let action = execute(&program, &mut memory, &mut regs, |insn, regs, _| {
            if insn.code == CALL {
                assert_eq!(insn.imm, 188);
                regs[0] = frame.len() as u64;
                true
            } else {
                false
            }
        });
        let key_at = (STACK_ADDR as isize + isize::from(KEY)) as usize;
        (
            action,
            memory[key_at..key_at + 56].try_into().unwrap(),
            memory,
        )
    }

    #[test]
    fn ipv6_envelope_walks_bounded_extensions_and_rejects_malformed() {
        // Same shape as the daemon fixture: Hop-by-Hop first, then Destination Options.
        let chain = |count: usize| {
            let mut chain = vec![(0, 8, 0)];
            chain.resize(count, (60, 8, 0));
            chain
        };
        let eight = chain(8);
        let mut truncated = ipv6_frame(&[(0, 16, 0)], 17, None, Some(8));
        truncated.truncate(14 + 40 + 8);
        let mut extent_past_accessible = truncated.clone();
        extent_past_accessible[18..20].copy_from_slice(&8u16.to_be_bytes());
        let mut udp_payload = ipv6_frame(&[(0, 16, 0)], 17, None, Some(12));
        udp_payload.extend_from_slice(b"data");
        udp_payload[18..20].copy_from_slice(&28u16.to_be_bytes());
        let mut short_tcp = ipv6_frame(&[(0, 8, 0)], 6, Some(24), None);
        short_tcp.truncate(14 + 40 + 24);
        let mut long_tcp_header = ipv6_frame(&[(0, 8, 0)], 6, None, None);
        long_tcp_header[14 + 40 + 8 + 12] = 0x60;
        // The expected upper protocol is independent of the emitted parser; zero means refusal.
        let cases = vec![
            (ipv6_frame(&[], 17, None, Some(8)), 17),
            (ipv6_frame(&[], 6, None, None), 6),
            (ipv6_frame(&[(0, 8, 0)], 17, None, Some(8)), 17),
            (udp_payload, 17),
            (ipv6_frame(&[(0, 8, 0)], 6, None, None), 6),
            (
                ipv6_frame(&[(60, 16, 0), (43, 24, 0)], 17, None, Some(8)),
                17,
            ),
            (ipv6_frame(&eight, 17, None, Some(8)), 17),
            (ipv6_frame(&eight, 6, None, None), 6),
            (ipv6_frame(&chain(9), 17, None, Some(8)), 0),
            (ipv6_frame(&[(0, 16, 0)], 17, Some(8), Some(8)), 0),
            // Extension ends exactly at the declared payload end, and one byte beyond it.
            (ipv6_frame(&[(0, 8, 0)], 17, Some(8), Some(8)), 0),
            (ipv6_frame(&[(0, 16, 0)], 17, Some(15), Some(8)), 0),
            (truncated, 0),
            (extent_past_accessible, 0),
            (short_tcp, 0),
            (long_tcp_header, 0),
            (ipv6_frame(&[], 17, None, Some(16)), 0),
            (ipv6_frame(&[(0, 8, 0)], 17, None, Some(16)), 0),
            (ipv6_frame(&[(0, 8, 0)], 17, None, Some(0)), 0),
            (ipv6_frame(&[(0, 8, 0)], 17, Some(0), Some(8)), 0),
            (ipv6_frame(&[(43, 8, 1)], 17, None, Some(8)), 0),
            (ipv6_frame(&[(44, 8, 0)], 17, None, Some(8)), 0),
            (ipv6_frame(&[(51, 8, 0)], 17, None, Some(8)), 0),
            (ipv6_frame(&[(50, 8, 0)], 17, None, Some(8)), 0),
            (ipv6_frame(&[(59, 8, 0)], 17, None, Some(8)), 0),
            (ipv6_frame(&[(0, 8, 0)], 253, None, None), 0),
        ];
        for tc in [false, true] {
            for (index, (frame, proto)) in cases.iter().enumerate() {
                let (action, key, memory) = run_envelope(frame, frame.len(), tc);
                assert_eq!(action, u64::from(*proto != 0), "tc={tc} case={index}");
                if *proto != 0 {
                    assert_eq!(key[36], *proto);
                    assert_eq!(key[37], 6);
                    assert_eq!(&key[..32], &frame[22..54]);
                    assert_eq!(&key[32..36], &[0x30, 0x39, 0x01, 0xbb]);
                    assert_eq!(
                        load(&memory, (STACK_ADDR as isize + DSCP as isize) as usize, 4),
                        42
                    );
                    let original = (STACK_ADDR as isize + ORIGINAL as isize) as usize;
                    assert_eq!(&memory[original..original + 56], &key);
                }
                assert_eq!(&memory[PACKET_ADDR..PACKET_ADDR + frame.len()], frame);
            }
            let frame = ipv6_frame(&[(0, 16, 0)], 17, None, Some(8));
            for accessible in 54..frame.len() {
                assert_eq!(
                    run_envelope(&frame, accessible, tc).0,
                    0,
                    "tc={tc} accessible={accessible}"
                );
            }
        }
    }

    fn run_publication_gate(
        tc: bool,
        epoch: Option<u64>,
        query: bool,
        root_after_read: Option<u64>,
        missing_cell: Option<u32>,
        cells: &mut [NativeClosedCounterV1],
    ) -> (u64, usize) {
        const ROOT_ADDR: usize = 0x2000;
        const CELLS_ADDR: usize = 0x3000;
        let config = gate_config();
        let mut a = Asm::new();
        let drop = a.label();
        let query_error = a.label();
        let parse = a.label();
        publication_gate(&mut a, &config, tc, drop, query_error, parse);
        a.bind(parse);
        a.exit(7);
        a.bind(query_error);
        a.exit(8);
        a.bind(drop);
        a.exit(if tc { 2 } else { XDP_DROP });
        let program = a.finish().unwrap();
        let mut memory = vec![0u8; CELLS_ADDR + cells.len() * 32];
        memory[ROOT_ADDR..ROOT_ADDR + 8].copy_from_slice(&epoch.unwrap_or(0).to_ne_bytes());
        for (index, cell) in cells.iter().enumerate() {
            for (field, value) in [
                cell.epoch,
                cell.ordinary_drops,
                cell.overflow,
                cell.reserved,
            ]
            .into_iter()
            .enumerate()
            {
                let at = CELLS_ADDR + index * 32 + field * 8;
                memory[at..at + 8].copy_from_slice(&value.to_ne_bytes());
            }
        }
        let mut regs = [0u64; 11];
        regs[10] = 0x1200;
        let query_at = (regs[10] as i64 + i64::from(QUERY)) as usize;
        memory[query_at..query_at + 4].copy_from_slice(&u32::from(query).to_ne_bytes());
        let mut lookups = 0;
        let result = execute(&program, &mut memory, &mut regs, |insn, regs, memory| {
            if insn.code == STX_DW
                && insn.off == EPOCH
                && let Some(new_epoch) = root_after_read
            {
                memory[ROOT_ADDR..ROOT_ADDR + 8].copy_from_slice(&new_epoch.to_ne_bytes());
            }
            if insn.code != CALL {
                return false;
            }
            assert_eq!(insn.imm, 1);
            let key = load(memory, regs[2] as usize, 4) as u32;
            regs[0] = match regs[1] as i32 {
                11 => {
                    if epoch.is_some() {
                        ROOT_ADDR as u64
                    } else {
                        0
                    }
                }
                12 => {
                    lookups += 1;
                    if missing_cell == Some(key) {
                        0
                    } else {
                        (CELLS_ADDR + key as usize * 32) as u64
                    }
                }
                other => panic!("unexpected gate map {other}"),
            };
            true
        });
        for (index, cell) in cells.iter_mut().enumerate() {
            let at = CELLS_ADDR + index * 32;
            *cell = NativeClosedCounterV1 {
                epoch: load(&memory, at, 8),
                ordinary_drops: load(&memory, at + 8, 8),
                overflow: load(&memory, at + 16, 8),
                reserved: load(&memory, at + 24, 8),
            };
        }
        (result, lookups)
    }

    #[test]
    fn closed_ordinary_gate_counts_exact_hook_and_full_epoch_before_parsing() {
        use honk_ebpf_common::xdp::native_closed_counter_index;
        for tc in [false, true] {
            for epoch in [0, 2, 510, 512, u64::MAX - 1] {
                let mut cells =
                    vec![NativeClosedCounterV1::default(); NATIVE_COUNTER_ENTRIES as usize];
                let index = native_closed_counter_index(epoch, u32::from(tc)).unwrap() as usize;
                cells[index].epoch = epoch;
                assert_eq!(
                    run_publication_gate(tc, Some(epoch), false, None, None, &mut cells),
                    (if tc { 2 } else { XDP_DROP as u64 }, 1)
                );
                assert_eq!(cells[index].ordinary_drops, 1);
                assert_eq!(cells.iter().map(|cell| cell.ordinary_drops).sum::<u64>(), 1);
                assert!(cells.iter().all(|cell| cell.overflow == 0));
            }
        }
    }

    #[test]
    fn query_open_and_missing_root_never_enter_closed_accounting() {
        for tc in [false, true] {
            for (epoch, query, result) in [
                (Some(0), true, 7),
                (Some(3), true, 8),
                (Some(3), false, 7),
                (None, false, 8),
                (None, true, 8),
            ] {
                let mut cells =
                    vec![NativeClosedCounterV1::default(); NATIVE_COUNTER_ENTRIES as usize];
                assert_eq!(
                    run_publication_gate(tc, epoch, query, None, None, &mut cells),
                    (result, 0)
                );
                assert!(
                    cells
                        .iter()
                        .all(|cell| *cell == NativeClosedCounterV1::default())
                );
            }
        }
    }

    #[test]
    fn delayed_closed_invocation_uses_captured_tag_across_reopen_and_close() {
        use honk_ebpf_common::xdp::native_closed_counter_index;
        for tc in [false, true] {
            let mut cells = vec![NativeClosedCounterV1::default(); NATIVE_COUNTER_ENTRIES as usize];
            let old = native_closed_counter_index(510, u32::from(tc)).unwrap() as usize;
            let next = native_closed_counter_index(512, u32::from(tc)).unwrap() as usize;
            cells[old].epoch = 510;
            cells[next].epoch = 512;
            for root_after_read in [511, 512] {
                run_publication_gate(
                    tc,
                    Some(510),
                    false,
                    Some(root_after_read),
                    None,
                    &mut cells,
                );
            }
            assert_eq!(cells[old].ordinary_drops, 2);
            assert_eq!(cells[next].ordinary_drops, 0);
            cells[old].epoch = 1022;
            run_publication_gate(tc, Some(510), false, None, None, &mut cells);
            assert_eq!(cells[old].ordinary_drops, 2);
            assert_eq!(cells[NATIVE_COUNTER_FAULT_INDEX as usize].overflow, 1);
        }
    }

    #[test]
    fn closed_counter_wrap_and_invalid_cells_are_sticky_faults() {
        for tc in [false, true] {
            let index = 2 + usize::from(tc);
            for (cell, missing) in [
                (
                    NativeClosedCounterV1 {
                        epoch: 2,
                        ordinary_drops: u64::MAX,
                        ..NativeClosedCounterV1::default()
                    },
                    false,
                ),
                (
                    NativeClosedCounterV1 {
                        epoch: 514,
                        ..NativeClosedCounterV1::default()
                    },
                    false,
                ),
                (
                    NativeClosedCounterV1 {
                        epoch: 2,
                        reserved: 1,
                        ..NativeClosedCounterV1::default()
                    },
                    false,
                ),
                (
                    NativeClosedCounterV1 {
                        epoch: 2,
                        overflow: 2,
                        ..NativeClosedCounterV1::default()
                    },
                    false,
                ),
                (
                    NativeClosedCounterV1 {
                        epoch: 2,
                        ..NativeClosedCounterV1::default()
                    },
                    true,
                ),
            ] {
                let mut cells =
                    vec![NativeClosedCounterV1::default(); NATIVE_COUNTER_ENTRIES as usize];
                cells[index] = cell;
                let missing_cell = missing.then_some(index as u32);
                for _ in 0..2 {
                    let (result, _) =
                        run_publication_gate(tc, Some(2), false, None, missing_cell, &mut cells);
                    assert_eq!(result, if tc { 2 } else { XDP_DROP as u64 });
                }
                if cell.ordinary_drops == u64::MAX {
                    assert_eq!(cells[index].ordinary_drops, 1);
                    assert_eq!(cells[index].overflow, 1);
                    assert_eq!(cells[NATIVE_COUNTER_FAULT_INDEX as usize].overflow, 0);
                } else {
                    assert_eq!(cells[index], cell);
                    assert_eq!(cells[NATIVE_COUNTER_FAULT_INDEX as usize].overflow, 1);
                }
            }
        }
    }

    #[test]
    fn native_counter_map_abi_and_program_reference_admission_reject_stale_maps() {
        let valid = CounterMapInfo {
            kind: 2,
            id: 7,
            key_size: 4,
            value_size: 32,
            entries: NATIVE_COUNTER_ENTRIES,
            flags: 0,
        };
        validate_counter_map(&valid).unwrap();
        for invalid in [
            CounterMapInfo { kind: 6, ..valid },
            CounterMapInfo { id: 0, ..valid },
            CounterMapInfo {
                key_size: 8,
                ..valid
            },
            CounterMapInfo {
                value_size: 16,
                ..valid
            },
            CounterMapInfo {
                entries: 512,
                ..valid
            },
            CounterMapInfo { flags: 1, ..valid },
        ] {
            assert!(validate_counter_map(&invalid).is_err());
        }
        validate_counter_reference(&[1, 7, 9], 7).unwrap();
        for ids in [&[][..], &[1, 9][..], &[7, 7][..]] {
            assert!(validate_counter_reference(ids, 7).is_err());
        }
        assert!(validate_counter_reference(&[0], 0).is_err());
        assert_eq!(size_of::<CounterProgramInfo>(), 64);
        assert_eq!(std::mem::offset_of!(CounterProgramInfo, nr_map_ids), 52);
        assert_eq!(std::mem::offset_of!(CounterProgramInfo, map_ids), 56);
        let mut a = Asm::new();
        let drop = a.label();
        closed_ordinary(&mut a, 12, false, drop);
        assert!(a.b.program.len <= CLOSED_COUNTER_INSNS);
        a.bind(drop);
        a.exit(XDP_DROP);
        a.finish().unwrap();
    }

    #[test]
    fn recording_configuration_requires_distinct_nonzero_hook_ids_and_closed_epoch() {
        let mut config = gate_config();
        validate_recording_config(&config).unwrap();
        for hooks in [[0, 2], [1, 0], [1, 1]] {
            config.hook_ids = hooks;
            assert!(validate_recording_config(&config).is_err());
        }
        config.hook_ids = [1, 2];
        config.closed_counters = -1;
        assert!(validate_recording_config(&config).is_err());
        config.closed_counters = 12;
        config.epoch = 3;
        assert!(validate_recording_config(&config).is_err());
    }

    #[test]
    fn final_deadline_is_sampled_after_successful_epoch_cas() {
        let mut a = Asm::new();
        let failure = a.label();
        let config = NativeProgramConfig {
            bytecode: &[],
            root: 0,
            claims: 0,
            scratch: 0,
            closed_counters: 0,
            hook_ids: [1, 2],
            epoch: 2,
            scope: 1,
            expires_boottime_ns: 100,
            reply_block_rules: &[],
            preparation_memory_bytes: 0,
            redirect_limit: 16,
            captured: None,
        };
        frontier(&mut a, &config, failure);
        let instructions = &a.b.program.insns[..a.b.program.len];
        let cas = instructions
            .iter()
            .position(|instruction| {
                instruction.code == ATOMIC_ADD_DW && instruction.imm == CMPXCHG_DW
            })
            .unwrap();
        assert_eq!(instructions[cas + 1].code, JNE_X);
        assert_eq!(instructions[cas + 2].code, CALL);
        assert_eq!(instructions[cas + 2].imm, 125);
        assert_eq!(instructions.last().unwrap().code, JGE_X);
        assert!(
            !instructions[..cas]
                .iter()
                .any(|instruction| instruction.code == CALL && instruction.imm == 125)
        );
    }

    fn route_action(
        tc: bool,
        owner: u32,
        live: u32,
        reply: u32,
        output: KernelRouteOutput,
        flags: u32,
        port: u16,
    ) -> i32 {
        let mut a = Asm::new();
        let direct = a.label();
        let capture = a.label();
        let failure = a.label();
        route(&mut a, &[7], direct, capture, failure);
        a.bind(direct);
        a.exit(if tc { 0 } else { XDP_PASS });
        a.bind(capture);
        a.exit(if tc { 2 } else { 4 });
        a.bind(failure);
        a.exit(if tc { 2 } else { XDP_DROP });
        let program = a.finish().unwrap();
        let mut pc = 0usize;
        let mut value = 0u32;
        for _ in 0..program.len {
            let instruction = program.insns[pc];
            let source = if cfg!(target_endian = "little") {
                instruction.regs >> 4
            } else {
                instruction.regs & 15
            };
            let imm = instruction.imm as u32;
            let jump = match instruction.code {
                LDX_W | LDX_H => {
                    value = match (source, instruction.off) {
                        (10, OWNER) => owner,
                        (10, LIVE) => live,
                        (10, REPLY) => reply,
                        (10, FLAGS) => flags,
                        (10, offset) if offset == ORIGINAL + 34 => u32::from(port.to_be()),
                        (8, OUTBOUND) => output.decision.outbound,
                        (8, MARK) => output.decision.mark,
                        (8, MARK_KIND) => output.mark_kind,
                        (8, MUST) => output.decision.must,
                        (8, FINAL) => output.decision.domain_final,
                        (8, offset)
                            if offset
                                == SCRATCH_OUTPUT
                                    + std::mem::offset_of!(RoutingDecision, rule_id) as i16 =>
                        {
                            output.decision.rule_id
                        }
                        _ => panic!("unexpected route load: {instruction:?}"),
                    };
                    false
                }
                AND_K => {
                    value &= imm;
                    false
                }
                MOV_K => {
                    value = imm;
                    false
                }
                JA => true,
                JEQ_K | JEQ32_K => value == imm,
                JNE_K => value != imm,
                JSET_K => value & imm != 0,
                EXIT => return value as i32,
                _ => panic!("unexpected route instruction: {instruction:?}"),
            };
            pc = pc
                .checked_add_signed(
                    1 + if jump {
                        isize::from(instruction.off)
                    } else {
                        0
                    },
                )
                .unwrap();
        }
        panic!("route did not terminate");
    }

    #[test]
    fn noncached_originals_refuse_capture_while_replies_keep_completion_policy() {
        let direct = RoutingDecision {
            outbound: 0,
            domain_final: 1,
            ..RoutingDecision::default()
        };
        let proxy = RoutingDecision {
            outbound: 2,
            ..direct
        };
        let rule = DATAPATH_FLAG_OFFLOAD_RULE_DIRECT;
        let all = DATAPATH_FLAG_OFFLOAD_ALL;
        let cases = [
            (direct, rule, 443, true),
            (proxy, rule, 443, false),
            (proxy, all, 443, true),
            (RoutingDecision { must: 1, ..proxy }, all, 443, false),
            (
                RoutingDecision {
                    domain_final: 0,
                    ..direct
                },
                rule,
                443,
                false,
            ),
            (
                RoutingDecision {
                    domain_final: 0,
                    ..direct
                },
                all,
                443,
                true,
            ),
            (RoutingDecision { must: 1, ..direct }, 0, 53, true),
            (direct, all, 53, false),
            (
                RoutingDecision {
                    outbound: 1,
                    ..direct
                },
                all,
                443,
                false,
            ),
            (RoutingDecision { mark: 8, ..direct }, all, 443, false),
            (direct, 0, 443, false),
        ];
        for tc in [false, true] {
            let pass = if tc { 0 } else { XDP_PASS };
            let drop = if tc { 2 } else { XDP_DROP };
            let capture = if tc { 2 } else { 4 };
            for (owner, live) in [
                (NATIVE_EXECUTOR_KERNEL, 0),
                (0, 1),
                (NATIVE_EXECUTOR_KERNEL, 1),
            ] {
                for (output, flags, port, allowed) in cases {
                    assert_eq!(
                        route_action(
                            tc,
                            owner,
                            live,
                            0,
                            KernelRouteOutput {
                                decision: output,
                                ..Default::default()
                            },
                            flags,
                            port,
                        ),
                        if allowed { pass } else { drop },
                        "tc={tc} owner={owner} live={live} output={output:?} flags={flags} port={port}",
                    );
                }
                for (outbound, rule_id, allowed) in [(2, 7, true), (1, 99, true), (1, 7, false)] {
                    let output = RoutingDecision {
                        outbound,
                        rule_id,
                        mark: 8,
                        must: 1,
                        domain_final: 0,
                        ..direct
                    };
                    assert_eq!(
                        route_action(
                            tc,
                            owner,
                            live,
                            1,
                            KernelRouteOutput {
                                decision: output,
                                mark_kind: honk_ebpf_common::ROUTING_MARK_SET,
                                ..Default::default()
                            },
                            0,
                            53,
                        ),
                        if allowed { pass } else { drop },
                    );
                }
            }
            assert_eq!(
                route_action(
                    tc,
                    0,
                    0,
                    0,
                    KernelRouteOutput {
                        decision: proxy,
                        ..Default::default()
                    },
                    rule,
                    443,
                ),
                capture,
            );
            assert_eq!(
                route_action(
                    tc,
                    NATIVE_EXECUTOR_CAPTURE,
                    0,
                    0,
                    KernelRouteOutput {
                        decision: direct,
                        ..Default::default()
                    },
                    rule,
                    443,
                ),
                capture,
            );
            let block = RoutingDecision {
                outbound: 1,
                rule_id: 7,
                ..direct
            };
            assert_eq!(
                route_action(
                    tc,
                    0,
                    1,
                    2,
                    KernelRouteOutput {
                        decision: block,
                        ..Default::default()
                    },
                    0,
                    53,
                ),
                pass,
            );
        }
    }

    #[test]
    fn native_packet_headers_use_canonical_protocol_masks() {
        for tc in [false, true] {
            for (protocol, expected) in [(6, L4ProtoType::Tcp), (17, L4ProtoType::Udp)] {
                let mut run = NativeRun {
                    claim: None,
                    ..NativeRun::default()
                };
                run.key[36] = protocol;
                let result = run.run(tc);
                assert_eq!(result.action, if tc { 0 } else { XDP_PASS as u64 });
                let input = SCRATCH_ADDR + SCRATCH_INPUT as usize;
                assert_eq!(
                    load(
                        &result.memory,
                        input + std::mem::offset_of!(RoutingInput, l4proto),
                        4
                    ),
                    expected as u64
                );
                assert_eq!(
                    load(
                        &result.memory,
                        input + std::mem::offset_of!(RoutingInput, ip_version),
                        4
                    ),
                    IpVersionType::V4 as u64
                );
            }
        }
    }

    #[test]
    fn native_originals_reject_set_zero_full_width_and_unknown_effects() {
        for tc in [false, true] {
            let drop = if tc { 2 } else { XDP_DROP as u64 };
            for (mark_kind, mark) in [
                (honk_ebpf_common::ROUTING_MARK_SET, 0),
                (honk_ebpf_common::ROUTING_MARK_SET, 9),
                (honk_ebpf_common::ROUTING_MARK_SET, 0x8000_0000),
                (honk_ebpf_common::ROUTING_MARK_SET, u32::MAX),
                (2, 0),
                (ROUTING_MARK_KEEP, 9),
            ] {
                for claim in [
                    None,
                    Some(NativeClaim {
                        scope: 1,
                        ..NativeRun::default().claim.unwrap()
                    }),
                    Some(NativeClaim {
                        scope: 1,
                        executor: NATIVE_EXECUTOR_PENDING,
                        state: NATIVE_PHASE_PENDING,
                        ..NativeRun::default().claim.unwrap()
                    }),
                    Some(NativeClaim {
                        scope: 1,
                        executor: NATIVE_EXECUTOR_CAPTURE,
                        state: NATIVE_PHASE_CAPTURE_COMMITTED,
                        ..NativeRun::default().claim.unwrap()
                    }),
                ] {
                    let mut run = NativeRun {
                        claim,
                        output: KernelRouteOutput {
                            decision: RoutingDecision {
                                outbound: 0,
                                mark,
                                domain_final: 1,
                                ..RoutingDecision::default()
                            },
                            mark_kind,
                            ..KernelRouteOutput::default()
                        },
                        ..NativeRun::default()
                    };
                    run.key[36] = 6;
                    let result = run.run(tc);
                    assert_eq!(result.canonical_calls, 1);
                    assert_eq!(result.action, drop, "tc={tc} kind={mark_kind} mark={mark}");
                    assert_eq!(result.updates, 0);
                    assert_eq!(result.redirects, 0);
                    assert_eq!(
                        load(&result.memory, SCRATCH_ADDR + SCRATCH_BUSY as usize, 4),
                        0,
                    );
                    if let Some(claim) = claim {
                        assert_eq!(
                            &result.memory[CLAIM_ADDR..CLAIM_ADDR + NATIVE_CLAIM_VALUE_BYTES],
                            &claim_bytes(claim),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn native_pending_selection_and_counted_redirect_are_atomic() {
        let run = NativeRun {
            claim: None,
            output: KernelRouteOutput {
                decision: RoutingDecision {
                    outbound: 2,
                    ..RoutingDecision::default()
                },
                ..KernelRouteOutput::default()
            },
            ..NativeRun::default()
        };
        let result = run.run(false);
        assert_eq!(result.action, 4);
        assert_eq!(result.redirects, 1);
        assert_eq!(
            load(&result.memory, CLAIM_ADDR + 24, 8),
            honk_ebpf_common::xdp::native_selection(
                NATIVE_EXECUTOR_PENDING,
                NATIVE_PHASE_PENDING,
                1
            )
            .unwrap()
        );
        assert_eq!(
            load(&result.memory, PACKET_ADDR - NATIVE_METADATA_LEN + 56, 4),
            u64::from(NATIVE_IMPORT_COUNTED)
        );
        assert_eq!(
            load(&result.memory, PACKET_ADDR - NATIVE_METADATA_LEN + 48, 8),
            100
        );
        assert_eq!(
            result
                .events
                .iter()
                .filter(|event| **event == "selection")
                .count(),
            1
        );
        let pending = NativeClaim {
            epoch: 3,
            incarnation: 3,
            scope: 1,
            executor: NATIVE_EXECUTOR_PENDING,
            ..NativeClaim::default()
        };
        let raced = NativeRun {
            claim: Some(pending),
            selection_values: vec![
                honk_ebpf_common::xdp::native_selection(
                    NATIVE_EXECUTOR_PENDING,
                    NATIVE_PHASE_PENDING,
                    1,
                )
                .unwrap(),
            ],
            ..NativeRun::default()
        }
        .run(false);
        assert_eq!(raced.action, 4);
        assert_eq!(load(&raced.memory, CLAIM_ADDR + 28, 4), 2 << 4);
        assert_eq!(
            raced
                .events
                .iter()
                .filter(|event| **event == "selection")
                .count(),
            2
        );
        let full = NativeRun {
            claim: Some(NativeClaim {
                state: 16 << 4,
                ..pending
            }),
            ..NativeRun::default()
        }
        .run(false);
        assert_eq!(full.action, XDP_DROP as u64);
        assert_eq!(full.redirects, 0);
        assert_eq!(load(&full.memory, CLAIM_ADDR + 28, 4), 16 << 4);
        for (executor, phase) in [(2, 0), (1, 0), (3, 2), (4, 0), (1, 5), (2, 7), (3, 6)] {
            let selection = u64::from(executor as u32) | (u64::from(phase as u32) << 32);
            let invalid_race = NativeRun {
                claim: Some(pending),
                selection_values: vec![selection],
                ..NativeRun::default()
            }
            .run(false);
            assert_eq!(invalid_race.action, XDP_DROP as u64, "{executor}/{phase}");
            assert_eq!(invalid_race.redirects, 0);
            assert_eq!(load(&invalid_race.memory, CLAIM_ADDR + 24, 8), selection);
        }
    }

    #[test]
    fn native_capture_transition_preserves_cross_queue_credit() {
        let pending = NativeClaim {
            epoch: 3,
            incarnation: 3,
            scope: 1,
            executor: NATIVE_EXECUTOR_PENDING,
            ..NativeClaim::default()
        };
        let old = NativeRun {
            claim: Some(pending),
            ..NativeRun::default()
        }
        .run(false);
        assert_eq!(old.action, 4);
        assert_eq!(load(&old.memory, CLAIM_ADDR + 28, 4), 1 << 4);
        assert_eq!(
            load(&old.memory, PACKET_ADDR - NATIVE_METADATA_LEN + 56, 4),
            1
        );
        let committed = NativeClaim {
            executor: NATIVE_EXECUTOR_CAPTURE,
            state: (1 << 4) | NATIVE_PHASE_CAPTURE_COMMITTED,
            ..pending
        };
        for _ in 0..3 {
            let new = NativeRun {
                claim: Some(committed),
                ..NativeRun::default()
            }
            .run(false);
            assert_eq!(new.action, 4);
            assert_eq!(
                load(&new.memory, CLAIM_ADDR + 28, 4),
                u64::from(committed.state)
            );
            assert_eq!(
                load(&new.memory, PACKET_ADDR - NATIVE_METADATA_LEN + 56, 4),
                0
            );
            assert_eq!(
                load(&old.memory, PACKET_ADDR - NATIVE_METADATA_LEN + 56, 4),
                1
            );
        }
    }

    #[test]
    fn native_armed_physical_cannot_take_udp_cache() {
        for phase in [NATIVE_PHASE_ARMED, NATIVE_PHASE_DRAINING] {
            let claim = NativeClaim {
                scope: 1,
                state: (1 << 4) | phase,
                ..NativeRun::default().claim.unwrap()
            };
            let run = NativeRun {
                claim: Some(claim),
                ..NativeRun::default()
            };
            let physical = run.run(false);
            assert_eq!(physical.action, 4);
            assert_eq!(physical.redirects, 1);
            assert_eq!(physical.canonical_calls, 0);
            assert_eq!(physical.activity_atomics, 0);
            assert_eq!(
                load(&physical.memory, PACKET_ADDR - NATIVE_METADATA_LEN + 56, 4),
                u64::from(NATIVE_IMPORT_COUNTED)
            );
            assert_eq!(
                load(&physical.memory, CLAIM_ADDR + 28, 4),
                u64::from((2 << 4) | phase)
            );
            let live = NativeRun {
                claim: Some(claim),
                original: Some(NativeRun::default().key),
                ..NativeRun::default()
            }
            .run(false);
            assert_eq!(live.action, 4);
            assert_eq!(live.redirects, 1);
            assert_eq!(
                load(&live.memory, CLAIM_ADDR + 28, 4),
                u64::from((2 << 4) | phase)
            );
            assert_eq!(
                load(&live.memory, PACKET_ADDR - NATIVE_METADATA_LEN + 56, 4),
                u64::from(NATIVE_IMPORT_COUNTED)
            );
            let changed_policy = NativeRun {
                claim: Some(claim),
                output: KernelRouteOutput {
                    decision: RoutingDecision {
                        outbound: 2,
                        ..RoutingDecision::default()
                    },
                    ..KernelRouteOutput::default()
                },
                flags: DATAPATH_FLAG_OFFLOAD_RULE_DIRECT,
                ..NativeRun::default()
            }
            .run(false);
            assert_eq!(changed_policy.action, 4);
            assert_eq!(changed_policy.redirects, 1);
            assert_eq!(changed_policy.canonical_calls, 0);
            assert_eq!(
                load(&changed_policy.memory, CLAIM_ADDR + 28, 4),
                u64::from((2 << 4) | phase)
            );
            assert_eq!(
                load(
                    &changed_policy.memory,
                    PACKET_ADDR - NATIVE_METADATA_LEN + 56,
                    4
                ),
                u64::from(NATIVE_IMPORT_COUNTED)
            );
            let target = run.run(true);
            assert_eq!(target.action, 0);
            assert_eq!(target.redirects, 0);
            assert_eq!(target.canonical_calls, 1);
            assert_eq!(target.activity_atomics, 0);
            let blocked = NativeRun {
                output: KernelRouteOutput {
                    decision: RoutingDecision {
                        outbound: 1,
                        rule_id: 7,
                        ..RoutingDecision::default()
                    },
                    ..KernelRouteOutput::default()
                },
                ..run
            }
            .run(true);
            assert_eq!(blocked.action, 2);
        }
    }

    #[test]
    fn native_armed_ct_aliases_drop_without_reservation_or_redirect() {
        for phase in [
            NATIVE_PHASE_PENDING,
            NATIVE_PHASE_ARMED,
            NATIVE_PHASE_DRAINING,
        ] {
            let claim = NativeClaim {
                epoch: 3,
                incarnation: 3,
                scope: 1,
                executor: if phase == NATIVE_PHASE_PENDING {
                    NATIVE_EXECUTOR_PENDING
                } else {
                    NATIVE_EXECUTOR_KERNEL
                },
                state: (1 << 4) | phase,
                ..NativeClaim::default()
            };
            for reply in [0, 1] {
                let mut original = NativeRun::default().key;
                original[12] ^= 1;
                let result = NativeRun {
                    claim: Some(claim),
                    original: Some(original),
                    original_claim: Some(claim),
                    reply,
                    ..NativeRun::default()
                }
                .run(false);
                assert_eq!(result.action, XDP_DROP as u64, "{phase}/{reply}");
                assert_eq!(result.redirects, 0);
                assert_eq!(result.updates, 0);
                assert_eq!(
                    load(&result.memory, CLAIM_ADDR + 28, 4),
                    u64::from(claim.state)
                );
                assert_eq!(
                    load(&result.memory, ORIGINAL_CLAIM_ADDR + 28, 4),
                    u64::from(claim.state)
                );
                assert!(!result.events.contains(&"selection"));
            }
            let cross_realm = NativeRun {
                claim: Some(NativeClaim { scope: 2, ..claim }),
                ..NativeRun::default()
            }
            .run(false);
            assert_eq!(cross_realm.action, XDP_DROP as u64, "cross realm {phase}");
            assert_eq!(cross_realm.redirects, 0);
            assert_eq!(cross_realm.updates, 0);
            assert_eq!(
                load(&cross_realm.memory, CLAIM_ADDR + 28, 4),
                u64::from(claim.state)
            );
            assert!(!cross_realm.events.contains(&"selection"));
        }
        let mut original = NativeRun::default().key;
        original[12] ^= 1;
        let result = NativeRun {
            claim: None,
            original: Some(original),
            output: KernelRouteOutput {
                decision: RoutingDecision {
                    outbound: 2,
                    ..RoutingDecision::default()
                },
                ..KernelRouteOutput::default()
            },
            ..NativeRun::default()
        }
        .run(false);
        assert_eq!(result.action, XDP_DROP as u64);
        assert_eq!(result.updates, 0);
        assert_eq!(result.redirects, 0);
    }

    #[test]
    fn native_raw_claim_rejects_host_and_invalid_selection() {
        let good = NativeRun::default().claim.unwrap();
        for bad in [
            NativeClaim {
                owner_cookie: 1,
                ..good
            },
            NativeClaim {
                owner_incarnation: 1,
                ..good
            },
            NativeClaim {
                attachment_generation: 1,
                ..good
            },
            NativeClaim {
                mark_kind: 2,
                ..good
            },
            NativeClaim {
                mark_kind: 1,
                ..good
            },
            NativeClaim {
                mark_kind: 1,
                mark_value: 9,
                ..good
            },
            NativeClaim {
                mark_value: 9,
                ..good
            },
            NativeClaim { state: 5, ..good },
            NativeClaim { state: 0, ..good },
            NativeClaim { state: 7, ..good },
            NativeClaim {
                state: NATIVE_PHASE_ACTIVE | (1 << 4),
                ..good
            },
            NativeClaim {
                executor: NATIVE_EXECUTOR_PENDING,
                scope: 1,
                state: 6,
                ..good
            },
            NativeClaim {
                executor: NATIVE_EXECUTOR_CAPTURE,
                scope: 1,
                state: 0,
                ..good
            },
            NativeClaim {
                executor: 4,
                ..good
            },
        ] {
            for tc in [false, true] {
                let result = NativeRun {
                    claim: Some(bad),
                    ..NativeRun::default()
                }
                .run(tc);
                assert_eq!(
                    result.action,
                    if tc { 2 } else { XDP_DROP as u64 },
                    "{bad:?}"
                );
                assert_eq!(result.redirects, 0);
                assert_eq!(result.canonical_calls, 0);
            }
        }
    }

    #[test]
    fn native_claim_stack_slots_are_disjoint_and_fit_canonical_call() {
        let mut reader = Asm::new();
        let failure = reader.label();
        claim(&mut reader, &gate_config(), KEY, failure);
        let copied: Vec<_> = reader.b.program.insns[..reader.b.program.len]
            .iter()
            .filter(|instruction| {
                instruction.code == STX_DW
                    && instruction.regs & 15 == 10
                    && (CLAIM..CLAIM + 72).contains(&instruction.off)
            })
            .map(|instruction| instruction.off)
            .collect();
        assert_eq!(copied, vec![CLAIM, CLAIM + 8, CLAIM + 16, CLAIM + 24]);
        let slots = [
            (KEY, 56, 8),
            (TUPLE, 36, 8),
            (OPTS, 16, 8),
            (ORIGINAL, 56, 8),
            (CLAIM, size_of::<NativeClaim>() as i16, 8),
            (ROOT, 8, 8),
            (EPOCH, 8, 8),
            (FLAGS, 4, 4),
            (QUERY, 4, 4),
            (QUEUE, 4, 4),
            (OWNER, 4, 4),
            (LIVE, 4, 4),
            (REPLY, 4, 4),
            (INCARNATION, 8, 8),
            (INDEX, 4, 4),
            (DSCP, 4, 4),
            (ETHER_TYPE, 4, 4),
            (INVALID, 4, 4),
            (FRAME_LEN, 4, 4),
            (CLAIM_PTR, 8, 8),
            (ACTIVITY_NOW, 8, 8),
        ];
        for (index, &(start, length, alignment)) in slots.iter().enumerate() {
            assert_eq!(start % alignment, 0);
            assert!(start >= ACTIVITY_NOW && start + length <= 0);
            for &(other, other_len, _) in &slots[..index] {
                if (start == TUPLE && other == CLAIM) || (start == CLAIM && other == TUPLE) {
                    const { assert!(TUPLE >= CLAIM + 32 && TUPLE + 36 <= CLAIM + 72) };
                } else {
                    assert!(start + length <= other || other + other_len <= start);
                }
            }
        }
        assert_eq!((-ACTIVITY_NOW as usize).div_ceil(32) * 32 + 192, 480);
        assert!((-ACTIVITY_NOW as usize).div_ceil(32) * 32 + 192 <= 512);
        for tc in [false, true] {
            let mut translated = NativeRun::default().key;
            translated[12] ^= 1;
            for original_key in [None, Some(translated)] {
                let run = NativeRun {
                    claim: None,
                    original: original_key,
                    ..NativeRun::default()
                };
                let result = run.run(tc);
                assert_eq!(result.action, if tc { 0 } else { XDP_PASS as u64 });
                assert_eq!(result.updates, 1);
                let original = (STACK_ADDR as i16 + ORIGINAL) as usize;
                assert_eq!(
                    &result.memory[original..original + 56],
                    &original_key.unwrap_or(run.key)
                );
                assert_eq!(load(&result.memory, CLAIM_ADDR + 32, 8), run.now);
                assert_eq!(
                    load(&result.memory, CLAIM_ADDR + 28, 4),
                    u64::from(NATIVE_PHASE_ACTIVE)
                );
                assert_eq!(load(&result.memory, CLAIM_ADDR, 8), run.epoch);
                let expected = NativeClaim {
                    epoch: run.epoch,
                    incarnation: run.epoch,
                    scope: 1,
                    executor: NATIVE_EXECUTOR_KERNEL,
                    state: NATIVE_PHASE_ACTIVE,
                    last_seen_ns: run.now,
                    ..NativeClaim::default()
                };
                assert_eq!(
                    &result.memory[CLAIM_ADDR..CLAIM_ADDR + 72],
                    &claim_bytes(expected)
                );
            }
        }
        let mut translated = NativeRun::default().key;
        translated[12] ^= 1;
        let existing = NativeRun::default().claim.unwrap();
        for tc in [false, true] {
            let result = NativeRun {
                original: Some(translated),
                original_claim: Some(existing),
                ..NativeRun::default()
            }
            .run(tc);
            assert_eq!(result.action, if tc { 0 } else { XDP_PASS as u64 });
            assert_eq!(result.updates, 0);
            assert_eq!(
                &result.memory[ORIGINAL_CLAIM_ADDR..ORIGINAL_CLAIM_ADDR + 32],
                &claim_bytes(existing)[..32]
            );
        }
        let same_scope = NativeClaim {
            scope: 1,
            ..existing
        };
        for tc in [false, true] {
            let mismatch = NativeRun {
                claim: Some(NativeClaim {
                    executor: NATIVE_EXECUTOR_CAPTURE,
                    state: NATIVE_PHASE_CAPTURE_COMMITTED,
                    ..same_scope
                }),
                original: Some(translated),
                original_claim: Some(same_scope),
                ..NativeRun::default()
            }
            .run(tc);
            assert_eq!(mismatch.action, if tc { 2 } else { XDP_DROP as u64 });
            assert_eq!(mismatch.canonical_calls, 0);
            let mutable_state = NativeRun {
                claim: Some(NativeClaim {
                    state: (1 << 4) | NATIVE_PHASE_DRAINING,
                    ..same_scope
                }),
                original: Some(translated),
                original_claim: Some(same_scope),
                ..NativeRun::default()
            }
            .run(tc);
            assert_eq!(mutable_state.action, if tc { 0 } else { XDP_PASS as u64 });
        }
    }

    #[test]
    fn retained_udp_continuation_skips_current_canonical_in_both_hooks() {
        for tc in [false, true] {
            let pass = if tc { 0 } else { XDP_PASS as u64 };
            let drop = if tc { 2 } else { XDP_DROP as u64 };
            for output in [
                KernelRouteOutput {
                    decision: RoutingDecision {
                        outbound: 1,
                        ..RoutingDecision::default()
                    },
                    ..KernelRouteOutput::default()
                },
                KernelRouteOutput {
                    decision: RoutingDecision {
                        outbound: 2,
                        mark: 9,
                        must: 1,
                        ..RoutingDecision::default()
                    },
                    mark_kind: honk_ebpf_common::ROUTING_MARK_SET,
                    ..KernelRouteOutput::default()
                },
                KernelRouteOutput {
                    mark_kind: honk_ebpf_common::ROUTING_MARK_SET,
                    ..KernelRouteOutput::default()
                },
                KernelRouteOutput::default(),
            ] {
                for (flags, canonical_result) in
                    [(0, 0), (DATAPATH_FLAG_OFFLOAD_ALL, -libc::EFAULT)]
                {
                    let run = NativeRun {
                        output,
                        flags,
                        canonical_result,
                        ..NativeRun::default()
                    };
                    let result = run.run(tc);
                    assert_eq!(result.action, pass);
                    assert_eq!(result.canonical_calls, 0);
                    assert_eq!(result.updates, 0);
                    assert_eq!(result.redirects, 0);
                    assert_eq!(
                        &result.memory[CLAIM_ADDR..CLAIM_ADDR + 32],
                        &claim_bytes(run.claim.unwrap())[..32]
                    );
                    assert_eq!(load(&result.memory, CLAIM_ADDR + 32, 8), run.now);
                }
            }
            for (claim, socket) in [(None, false), (None, true)] {
                let run = NativeRun {
                    claim,
                    socket,
                    output: KernelRouteOutput {
                        decision: RoutingDecision {
                            outbound: 1,
                            rule_id: 7,
                            ..RoutingDecision::default()
                        },
                        ..KernelRouteOutput::default()
                    },
                    ..NativeRun::default()
                };
                let result = run.run(tc);
                assert_eq!(result.canonical_calls, 1);
                assert_eq!(result.action, if socket { pass } else { drop });
            }
            let live_only = NativeRun {
                claim: None,
                original: Some(NativeRun::default().key),
                ..NativeRun::default()
            };
            let result = NativeRun {
                output: KernelRouteOutput {
                    decision: RoutingDecision {
                        outbound: 2,
                        ..RoutingDecision::default()
                    },
                    ..KernelRouteOutput::default()
                },
                ..live_only
            }
            .run(tc);
            assert_eq!(result.canonical_calls, 1);
            assert_eq!(result.action, drop);
            for (protocol, port_offset, port) in [(6, 34, 443), (17, 32, 53), (17, 34, 53)] {
                let mut run = NativeRun {
                    canonical_result: -libc::EFAULT,
                    ..NativeRun::default()
                };
                run.key[36] = protocol;
                run.key[port_offset..port_offset + 2].copy_from_slice(&u16::to_be_bytes(port));
                let result = run.run(tc);
                assert_eq!(result.canonical_calls, 1);
                assert_eq!(result.action, drop);
                assert_eq!(result.clock_calls, 0);
            }
            for port_offset in [32, 34] {
                let mut original = NativeRun::default().key;
                original[port_offset..port_offset + 2].copy_from_slice(&53u16.to_be_bytes());
                let result = NativeRun {
                    original: Some(original),
                    canonical_result: -libc::EFAULT,
                    ..NativeRun::default()
                }
                .run(tc);
                assert_eq!(result.canonical_calls, 1);
                assert_eq!(result.action, drop);
                assert_eq!(result.clock_calls, 0);
            }
            let fresh_proxy = NativeRun {
                claim: None,
                output: KernelRouteOutput {
                    decision: RoutingDecision {
                        outbound: 2,
                        ..RoutingDecision::default()
                    },
                    ..KernelRouteOutput::default()
                },
                ..NativeRun::default()
            }
            .run(tc);
            assert_eq!(fresh_proxy.canonical_calls, 1);
            assert_eq!(fresh_proxy.action, if tc { 2 } else { 4 });
            if !tc {
                assert_eq!(fresh_proxy.redirects, 1);
                assert_eq!(
                    load(&fresh_proxy.memory, CLAIM_ADDR + 24, 4),
                    u64::from(NATIVE_EXECUTOR_PENDING)
                );
                assert_eq!(
                    load(&fresh_proxy.memory, CLAIM_ADDR + 32, 8),
                    NativeRun::default().now
                );
            }
            let mut capture = NativeRun {
                canonical_result: -libc::EFAULT,
                ..NativeRun::default()
            };
            capture.claim.as_mut().unwrap().executor = NATIVE_EXECUTOR_CAPTURE;
            capture.claim.as_mut().unwrap().state = NATIVE_PHASE_CAPTURE_COMMITTED;
            capture.claim.as_mut().unwrap().scope = 1;
            let result = capture.run(tc);
            assert_eq!(result.canonical_calls, 1);
            assert_eq!(result.action, drop);
            assert_eq!(result.clock_calls, 0);
        }
    }

    #[test]
    fn retained_udp_continuation_keeps_frontier_xsk_and_busy_cleanup() {
        for tc in [false, true] {
            let drop = if tc { 2 } else { XDP_DROP as u64 };
            for run in [
                NativeRun {
                    epoch: 4,
                    ..NativeRun::default()
                },
                NativeRun {
                    final_epoch: Some(6),
                    ..NativeRun::default()
                },
                NativeRun {
                    boot: 100,
                    ..NativeRun::default()
                },
                NativeRun {
                    xsk: false,
                    ..NativeRun::default()
                },
                NativeRun {
                    busy: 1,
                    ..NativeRun::default()
                },
                NativeRun {
                    probe_error: true,
                    ..NativeRun::default()
                },
            ] {
                let result = run.run(tc);
                assert_eq!(result.action, drop);
                assert_eq!(result.updates, 0);
                assert_eq!(result.redirects, 0);
                assert_eq!(
                    load(&result.memory, SCRATCH_ADDR + SCRATCH_BUSY as usize, 4),
                    u64::from(run.busy)
                );
                if run.busy != 0 {
                    assert!(!result.events.contains(&"release"));
                }
                if run.final_epoch.is_some() {
                    assert!(!result.events.contains(&"boot"));
                }
                if !run.xsk {
                    assert_eq!(result.activity_atomics, 0);
                }
            }
            let mut original = NativeRun::default().key;
            original[12] ^= 1;
            let first = NativeRun::default().claim.unwrap();
            for conflicting in [
                NativeClaim {
                    executor: NATIVE_EXECUTOR_CAPTURE,
                    state: NATIVE_PHASE_CAPTURE_COMMITTED,
                    scope: 1,
                    ..first
                },
                NativeClaim {
                    epoch: 7,
                    incarnation: 7,
                    ..first
                },
                NativeClaim { scope: 8, ..first },
            ] {
                let result = NativeRun {
                    original: Some(original),
                    original_claim: Some(conflicting),
                    ..NativeRun::default()
                }
                .run(tc);
                assert_eq!(result.action, drop);
                assert_eq!(result.canonical_calls, 0);
                assert!(!result.events.contains(&"release"));
            }
            for run in [
                NativeRun {
                    second_activity: Some(11_000_000_000),
                    ..NativeRun::default()
                },
                NativeRun {
                    miss_second: true,
                    ..NativeRun::default()
                },
                NativeRun {
                    original: Some(original),
                    ..NativeRun::default()
                },
                NativeRun {
                    original: Some(original),
                    original_claim: Some(NativeClaim {
                        last_seen_ns: 11_000_000_000,
                        ..first
                    }),
                    ..NativeRun::default()
                },
            ] {
                let result = run.run(tc);
                assert_eq!(result.action, if tc { 0 } else { XDP_PASS as u64 });
                assert_eq!(result.canonical_calls, 0);
                assert_eq!(
                    &result.events[result.events.len() - 4..],
                    &["frontier", "boot", "release", "exit"]
                );
            }
        }
    }

    #[test]
    fn native_udp_activity_cas_is_monotonic_and_bounded() {
        let second = 1_000_000_000;
        let last = 10 * second;
        let timeout = honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS;
        for tc in [false, true] {
            let pass = if tc { 0 } else { XDP_PASS as u64 };
            let drop = if tc { 2 } else { XDP_DROP as u64 };
            for (now, expected, attempts, action) in [
                (last - 1, last, 0, pass),
                (last + second, last, 0, pass),
                (last + second + 1, last + second + 1, 1, pass),
                (last + timeout, last + timeout, 1, pass),
                (last + timeout + 1, last, 0, drop),
            ] {
                let result = NativeRun {
                    now,
                    ..NativeRun::default()
                }
                .run(tc);
                assert_eq!(result.action, action);
                assert_eq!(load(&result.memory, CLAIM_ADDR + 32, 8), expected);
                assert_eq!(result.activity_atomics, attempts);
                assert_eq!(result.updates, 0);
            }
            for (competitors, expected, attempts, action) in [
                (vec![22 * second], 22 * second, 1, pass),
                (vec![11 * second], 20 * second, 2, pass),
                (
                    vec![11 * second, 12 * second, 13 * second, 14 * second],
                    14 * second,
                    4,
                    drop,
                ),
                (
                    vec![11 * second, 12 * second, 13 * second, 19 * second],
                    19 * second,
                    4,
                    pass,
                ),
            ] {
                let result = NativeRun {
                    now: 20 * second,
                    cas_values: competitors,
                    ..NativeRun::default()
                }
                .run(tc);
                assert_eq!(result.action, action);
                assert_eq!(load(&result.memory, CLAIM_ADDR + 32, 8), expected);
                assert_eq!(result.activity_atomics, attempts);
                assert_eq!(
                    load(&result.memory, SCRATCH_ADDR + SCRATCH_BUSY as usize, 4),
                    0
                );
            }
            for socket in [false, true] {
                let expired = NativeRun {
                    socket,
                    original: (!socket).then_some(NativeRun::default().key),
                    reply: 1,
                    now: last + timeout + 1,
                    ..NativeRun::default()
                }
                .run(tc);
                assert_eq!(expired.action, drop);
                assert_eq!(expired.canonical_calls, 0);
                assert_eq!(expired.activity_atomics, 0);
                assert_eq!(load(&expired.memory, CLAIM_ADDR + 32, 8), last);
            }
            let crossed = NativeRun {
                now: last + timeout,
                pass_now: Some(last + timeout + 1),
                ..NativeRun::default()
            }
            .run(tc);
            assert_eq!(crossed.action, drop);
            assert_eq!(crossed.activity_atomics, 0);
            assert_eq!(load(&crossed.memory, CLAIM_ADDR + 32, 8), last);
            let expired = NativeClaim {
                last_seen_ns: 0,
                ..NativeRun::default().claim.unwrap()
            };
            let raced = NativeRun {
                claim: None,
                race: Some(expired),
                now: timeout + 1,
                ..NativeRun::default()
            }
            .run(tc);
            assert_eq!(raced.action, drop);
            assert_eq!(load(&raced.memory, CLAIM_ADDR + 32, 8), 0);
            let mut active = NativeRun::default();
            let identity = claim_bytes(active.claim.unwrap());
            for tick in [60, 120, 180] {
                active.now = last + tick * second;
                let result = active.run(tc);
                assert_eq!(result.action, pass);
                assert_eq!(&result.memory[CLAIM_ADDR..CLAIM_ADDR + 32], &identity[..32]);
                active.claim.as_mut().unwrap().last_seen_ns =
                    load(&result.memory, CLAIM_ADDR + 32, 8);
            }
        }
    }

    #[test]
    fn native_kernel_query_does_not_touch_activity() {
        for socket in [false, true] {
            let run = NativeRun {
                query: true,
                epoch: 4,
                socket,
                ..NativeRun::default()
            };
            let result = run.run(true);
            assert_eq!(result.action, 2);
            assert_eq!(
                &result.memory[CLAIM_ADDR..CLAIM_ADDR + 72],
                &claim_bytes(run.claim.unwrap())
            );
            assert_eq!(result.clock_calls, 0);
            assert_eq!(result.activity_atomics, 0);
            assert_eq!(result.canonical_calls, 0);
            assert_eq!(result.updates, 0);
            assert_eq!(
                load(&result.memory, CONTEXT_ADDR + 48, 4),
                u64::from(QUERY_MARK)
            );
            assert_eq!(
                load(&result.memory, CONTEXT_ADDR + 52, 4),
                u64::from(socket)
            );
            assert!(!result.events.contains(&"release"));
        }
    }

    #[test]
    fn native_claim_map_admission_rejects_legacy_value_sizes() {
        let valid = CounterMapInfo {
            kind: 1,
            id: 9,
            key_size: 56,
            value_size: 72,
            entries: 1,
            flags: 0,
        };
        validate_claim_map_info(&valid).unwrap();
        for info in [
            CounterMapInfo {
                key_size: 40,
                ..valid
            },
            CounterMapInfo {
                value_size: 40,
                ..valid
            },
            CounterMapInfo {
                value_size: 32,
                ..valid
            },
            CounterMapInfo {
                value_size: 48,
                ..valid
            },
            CounterMapInfo { kind: 2, ..valid },
            CounterMapInfo {
                key_size: 32,
                ..valid
            },
            CounterMapInfo {
                entries: 0,
                ..valid
            },
            CounterMapInfo { flags: 1, ..valid },
            CounterMapInfo { id: 0, ..valid },
        ] {
            assert!(validate_claim_map_info(&info).is_err());
        }
    }
}
