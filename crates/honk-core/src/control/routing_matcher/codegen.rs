//! Native eBPF emitter for the fixed RoutingInput/Decision ABI.
//!
//! The emitter produces only a function body.  The backend supplies the real
//! freplace prototype, BTF and map lifetime; R1 is `*const RoutingInput` and
//! R2 is `*mut RoutingDecision`.

use super::{KernelCondition, KernelPredicate, RoutingPushPlan};
use anyhow::{Context, ensure};
use aya_obj::generated::{
    BPF_ALU64, BPF_AND, BPF_B, BPF_CALL, BPF_DW, BPF_EXIT, BPF_IMM, BPF_JA, BPF_JEQ, BPF_JGE,
    BPF_JGT, BPF_JMP, BPF_JNE, BPF_K, BPF_LD, BPF_LDX, BPF_MEM, BPF_MOV, BPF_ST, BPF_STX, BPF_W,
    BPF_X, bpf_insn,
};
use honk_ebpf_common::{
    ROUTING_FACT_CAPACITY, ROUTING_FEATURE_DOMAIN, ROUTING_FEATURE_DOMAIN_REROUTE,
    ROUTING_FEATURE_PROCESS, ROUTING_PROCESS_MAX_LEN, RoutingDecision, RoutingInput,
};

const R0: u8 = 0;
const R1: u8 = 1;
const R2: u8 = 2;
const R3: u8 = 3;
const R4: u8 = 4;
const R5: u8 = 5;
const R6: u8 = 6;
const R7: u8 = 7;
const R8: u8 = 8;
const R10: u8 = 10;
const STACK_DOMAIN_KEY: i16 = -96;
const MAP_LOOKUP_ELEM: i32 = 1;
const BPF_INSTRUCTION_CAPACITY: usize = 1_000_000;
const PSEUDO_MAP_FD: u8 = 1;
const STACK_KEY: i16 = -64;
const INPUT_SRC_IP: i16 = std::mem::offset_of!(RoutingInput, src_ip) as i16;
const INPUT_DST_IP: i16 = std::mem::offset_of!(RoutingInput, dst_ip) as i16;
const INPUT_MAC: i16 = std::mem::offset_of!(RoutingInput, mac) as i16;
const INPUT_PNAME: i16 = std::mem::offset_of!(RoutingInput, pname) as i16;
const INPUT_SRC_PORT: i16 = std::mem::offset_of!(RoutingInput, src_port) as i16;
const INPUT_DST_PORT: i16 = std::mem::offset_of!(RoutingInput, dst_port) as i16;
const INPUT_PROTO: i16 = std::mem::offset_of!(RoutingInput, l4proto) as i16;
const INPUT_VERSION: i16 = std::mem::offset_of!(RoutingInput, ip_version) as i16;
const INPUT_DSCP: i16 = std::mem::offset_of!(RoutingInput, dscp) as i16;
const INPUT_PNAME_LEN: i16 = std::mem::offset_of!(RoutingInput, pname_len) as i16;
const INPUT_MAC_PRESENT: i16 = std::mem::offset_of!(RoutingInput, mac_present) as i16;
const OUTBOUND: i16 = std::mem::offset_of!(RoutingDecision, outbound) as i16;
const MARK: i16 = std::mem::offset_of!(RoutingDecision, mark) as i16;
const MUST: i16 = std::mem::offset_of!(RoutingDecision, must) as i16;
const DOMAIN_FINAL: i16 = std::mem::offset_of!(RoutingDecision, domain_final) as i16;
const RULE_ID: i16 = std::mem::offset_of!(RoutingDecision, rule_id) as i16;

#[derive(Clone, Copy)]
enum FactKind {
    Destination,
    Source,
    Mac,
}

impl FactKind {
    fn of(predicate: &KernelPredicate) -> Option<Self> {
        match predicate {
            KernelPredicate::DestinationIp(_) => Some(Self::Destination),
            KernelPredicate::SourceIp(_) => Some(Self::Source),
            KernelPredicate::Mac(_) => Some(Self::Mac),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct FactCache {
    pointer: i16,
    ready: i16,
}

struct FactCaches {
    slots: [Option<FactCache>; 3],
    must_ready: u8,
    may_ready: u8,
}

fn fact_caches(plan: &RoutingPushPlan) -> FactCaches {
    let mut uses = [0u8; 3];
    for condition in plan.rules.iter().flat_map(|rule| &rule.conditions) {
        if let Some(kind) = FactKind::of(&condition.predicate) {
            let count = &mut uses[kind as usize];
            *count = (*count + 1).min(2);
        }
    }
    // Separate DW slots preserve ready constants on 6.12; packed W flags
    // lose precision and exhaust the verifier budget on mixed 256-bit policies.
    // Pairs occupy [-32, -1] and [-80, -65], outside both key buffers.
    FactCaches {
        slots: std::array::from_fn(|index| {
            let pointer = [-16, -32, -80][index];
            (uses[index] == 2).then_some(FactCache {
                pointer,
                ready: pointer + 8,
            })
        }),
        must_ready: 0,
        may_ready: 0,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RoutingMapFds {
    pub destination_v4: i32,
    pub destination_v6: i32,
    pub source_v4: i32,
    pub source_v6: i32,
    pub mac: i32,
    pub domain: i32,
}

#[derive(Debug, Clone)]
pub struct RoutingSourceLine {
    pub insn_offset: u32,
    pub line: u32,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct RoutingBytecode {
    pub insns: Vec<bpf_insn>,
    pub lines: Vec<RoutingSourceLine>,
}

#[derive(Debug, Clone, Copy)]
struct Label(usize);

struct Assembler {
    insns: Vec<bpf_insn>,
    lines: Vec<RoutingSourceLine>,
    labels: Vec<Option<usize>>,
    fixups: Vec<(usize, Label)>,
}

impl Assembler {
    fn new() -> Self {
        Self {
            insns: Vec::new(),
            lines: Vec::new(),
            labels: Vec::new(),
            fixups: Vec::new(),
        }
    }

    fn source(&mut self, line: u32, text: impl Into<String>) {
        self.lines.push(RoutingSourceLine {
            insn_offset: self.insns.len() as u32,
            line,
            text: text.into(),
        });
    }

    fn label(&mut self) -> Label {
        let label = Label(self.labels.len());
        self.labels.push(None);
        label
    }

    fn bind(&mut self, label: Label) {
        self.labels[label.0] = Some(self.insns.len());
    }

    fn emit(&mut self, code: u32, dst: u8, src: u8, off: i16, imm: i32) -> anyhow::Result<usize> {
        ensure!(
            self.insns.len() < BPF_INSTRUCTION_CAPACITY,
            "routing program exceeds BPF instruction capacity"
        );
        let insn = bpf_insn {
            code: code as u8,
            _bitfield_align_1: [],
            _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
            off,
            imm,
        };
        let offset = self.insns.len();
        self.insns.push(insn);
        Ok(offset)
    }

    fn jump(&mut self, op: u32, dst: u8, imm: i32, target: Label) -> anyhow::Result<()> {
        let index = self.emit(BPF_JMP | op | BPF_K, dst, 0, 0, imm)?;
        self.fixups.push((index, target));
        Ok(())
    }

    fn ja(&mut self, target: Label) -> anyhow::Result<()> {
        let index = self.emit(BPF_JMP | BPF_JA, 0, 0, 0, 0)?;
        self.fixups.push((index, target));
        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<RoutingBytecode> {
        for (index, label) in self.fixups {
            let target = self
                .labels
                .get(label.0)
                .and_then(|target| *target)
                .with_context(|| format!("unresolved jump label ordinal {}", label.0))?;
            let delta = target as isize - index as isize - 1;
            ensure!(
                i16::try_from(delta).is_ok(),
                "routing jump out of range: {index} -> {target}"
            );
            self.insns[index].off = delta as i16;
        }
        Ok(RoutingBytecode {
            insns: self.insns,
            lines: self.lines,
        })
    }

    fn mov_reg(&mut self, dst: u8, src: u8) -> anyhow::Result<()> {
        self.emit(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)?;
        Ok(())
    }
    fn mov_imm(&mut self, dst: u8, imm: i32) -> anyhow::Result<()> {
        self.emit(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)?;
        Ok(())
    }
    fn add_imm(&mut self, dst: u8, imm: i32) -> anyhow::Result<()> {
        self.emit(BPF_ALU64 | BPF_K, dst, 0, 0, imm)?;
        Ok(())
    }
    fn and_imm(&mut self, dst: u8, imm: i32) -> anyhow::Result<()> {
        self.emit(BPF_ALU64 | BPF_AND | BPF_K, dst, 0, 0, imm)?;
        Ok(())
    }
    fn ldx_w(&mut self, dst: u8, src: u8, off: i16) -> anyhow::Result<()> {
        self.emit(BPF_LDX | BPF_W | BPF_MEM, dst, src, off, 0)?;
        Ok(())
    }
    fn ldx_b(&mut self, dst: u8, src: u8, off: i16) -> anyhow::Result<()> {
        self.emit(BPF_LDX | BPF_B | BPF_MEM, dst, src, off, 0)?;
        Ok(())
    }
    fn ldx_dw(&mut self, dst: u8, src: u8, off: i16) -> anyhow::Result<()> {
        self.emit(BPF_LDX | BPF_DW | BPF_MEM, dst, src, off, 0)?;
        Ok(())
    }
    fn stx_dw(&mut self, dst: u8, src: u8, off: i16) -> anyhow::Result<()> {
        self.emit(BPF_STX | BPF_DW | BPF_MEM, dst, src, off, 0)?;
        Ok(())
    }
    fn stx_w(&mut self, dst: u8, src: u8, off: i16) -> anyhow::Result<()> {
        self.emit(BPF_STX | BPF_W | BPF_MEM, dst, src, off, 0)?;
        Ok(())
    }
    fn st_imm(&mut self, dst: u8, off: i16, imm: i32) -> anyhow::Result<()> {
        self.emit(BPF_ST | BPF_W | BPF_MEM, dst, 0, off, imm)?;
        Ok(())
    }
    fn st_dw_imm(&mut self, dst: u8, off: i16, imm: i32) -> anyhow::Result<()> {
        self.emit(BPF_ST | BPF_DW | BPF_MEM, dst, 0, off, imm)?;
        Ok(())
    }
    fn call(&mut self, helper: i32) -> anyhow::Result<()> {
        self.emit(BPF_JMP | BPF_CALL, 0, 0, 0, helper)?;
        Ok(())
    }
    fn exit(&mut self) -> anyhow::Result<()> {
        self.emit(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)?;
        Ok(())
    }
}

/// Emit a complete RoutingInput -> RoutingDecision function body.
pub fn emit_routing_program(
    plan: &RoutingPushPlan,
    fds: RoutingMapFds,
) -> anyhow::Result<RoutingBytecode> {
    validate_plan(plan)?;
    for (name, fd) in [
        ("destination_v4", fds.destination_v4),
        ("destination_v6", fds.destination_v6),
        ("source_v4", fds.source_v4),
        ("source_v6", fds.source_v6),
        ("mac", fds.mac),
        ("domain", fds.domain),
    ] {
        ensure!(fd >= 0, "invalid {name} routing map fd {fd}");
    }

    let mut asm = Assembler::new();
    asm.source(0, "routing function prologue");
    for register in [R1, R2] {
        let nonnull = asm.label();
        asm.jump(BPF_JNE, register, 0, nonnull)?;
        asm.mov_imm(R0, -libc::EFAULT)?;
        asm.exit()?;
        asm.bind(nonnull);
    }
    asm.mov_reg(R6, R1)?;
    asm.mov_reg(R7, R2)?;
    asm.st_imm(R7, OUTBOUND, plan.fallback as i32)?;
    asm.st_imm(R7, MARK, 0)?;
    asm.st_imm(R7, MUST, 0)?;
    asm.st_imm(
        R7,
        DOMAIN_FINAL,
        (!plan.has_domain_rules || plan.features & ROUTING_FEATURE_DOMAIN_REROUTE == 0) as i32,
    )?;
    asm.st_imm(R7, RULE_ID, u32::MAX as i32)?;

    let mut caches = fact_caches(plan);
    for cache in caches.slots.iter().flatten() {
        asm.st_dw_imm(R10, cache.pointer, 0)?;
        asm.st_dw_imm(R10, cache.ready, 0)?;
    }

    if plan.has_domain_rules {
        write_domain_key_from_input(&mut asm)?;
        load_map_fd(&mut asm, fds.domain)?;
        asm.mov_reg(R2, R10)?;
        asm.add_imm(R2, STACK_DOMAIN_KEY as i32)?;
        asm.call(MAP_LOOKUP_ELEM)?;
        asm.mov_reg(R8, R0)?;
        let domain_absent = asm.label();
        asm.jump(BPF_JEQ, R8, 0, domain_absent)?;
        asm.st_imm(R7, DOMAIN_FINAL, 1)?;
        asm.bind(domain_absent);
    }

    for rule in &plan.rules {
        asm.source(rule.id + 1, rule.source.as_str());
        let fail = asm.label();
        let mut failure_ready: Option<(u8, u8)> = None;
        for condition in &rule.conditions {
            let pass = asm.label();
            emit_condition(&mut asm, condition, pass, fail, &fds, &caches)?;
            if let Some(kind) = FactKind::of(&condition.predicate) {
                let bit = 1u8 << kind as u8;
                caches.must_ready |= bit;
                caches.may_ready |= bit;
            }
            // Every failed condition can enter the next rule, including a
            // short circuit before this rule's first fact lookup.
            failure_ready = Some(match failure_ready {
                None => (caches.must_ready, caches.may_ready),
                Some((must, may)) => (must & caches.must_ready, may | caches.may_ready),
            });
            asm.bind(pass);
        }
        asm.st_imm(R7, OUTBOUND, rule.outbound as i32)?;
        asm.st_imm(R7, MARK, rule.mark as i32)?;
        asm.st_imm(R7, MUST, rule.must as i32)?;
        asm.st_imm(R7, RULE_ID, rule.id as i32)?;
        asm.mov_imm(R0, 0)?;
        asm.exit()?;
        asm.bind(fail);
        (caches.must_ready, caches.may_ready) = failure_ready.unwrap_or_default();
    }

    asm.source(0, "fallback");
    asm.mov_imm(R0, 0)?;
    asm.exit()?;
    asm.finish()
}
fn validate_plan(plan: &RoutingPushPlan) -> anyhow::Result<()> {
    ensure!(
        plan.domain_predicate_count <= ROUTING_FACT_CAPACITY,
        "domain predicate capacity exceeded"
    );
    ensure!(
        plan.has_domain_rules == (plan.domain_predicate_count != 0),
        "inconsistent domain predicate metadata"
    );
    ensure!(
        (plan.features & ROUTING_FEATURE_DOMAIN != 0) == plan.has_domain_rules,
        "inconsistent domain feature metadata"
    );
    ensure!(
        plan.features & ROUTING_FEATURE_DOMAIN_REROUTE == 0 || plan.has_domain_rules,
        "domain reroute feature requires domain predicates"
    );
    let has_process = plan.rules.iter().any(|rule| {
        rule.conditions
            .iter()
            .any(|condition| matches!(&condition.predicate, KernelPredicate::ProcessName(_)))
    });
    ensure!(
        (plan.features & ROUTING_FEATURE_PROCESS != 0) == has_process,
        "inconsistent process feature metadata"
    );
    for rule in &plan.rules {
        ensure!(
            rule.id < (1 << 22) - 1,
            "rule id {} exceeds BPF source-line capacity",
            rule.id
        );
        for condition in &rule.conditions {
            match &condition.predicate {
                KernelPredicate::Domain(id) => ensure!(
                    (*id as usize) < plan.domain_predicate_count,
                    "invalid domain predicate id {id}"
                ),
                KernelPredicate::DestinationIp(id)
                | KernelPredicate::SourceIp(id)
                | KernelPredicate::Mac(id) => ensure!(
                    (*id as usize) < ROUTING_FACT_CAPACITY,
                    "invalid fact predicate id {id}"
                ),
                KernelPredicate::DestinationPort(ranges) | KernelPredicate::SourcePort(ranges) => {
                    ensure!(
                        ranges.iter().all(|range| range.start <= range.end),
                        "invalid emitted port range"
                    )
                }
                KernelPredicate::Protocol(mask) | KernelPredicate::IpVersion(mask) => {
                    ensure!(*mask & !0b11 == 0, "invalid emitted scalar mask {mask:#x}")
                }
                KernelPredicate::ProcessName(names) => ensure!(
                    names
                        .iter()
                        .all(|name| name.len() <= ROUTING_PROCESS_MAX_LEN),
                    "emitted process matcher exceeds {ROUTING_PROCESS_MAX_LEN} bytes"
                ),
                KernelPredicate::Dscp(_) => {}
            }
        }
    }
    ensure!(
        plan.facts
            .destination_v4
            .iter()
            .all(|(key, _)| key.prefix_len <= 32),
        "invalid destination IPv4 prefix"
    );
    ensure!(
        plan.facts
            .source_v4
            .iter()
            .all(|(key, _)| key.prefix_len <= 32),
        "invalid source IPv4 prefix"
    );
    ensure!(
        plan.facts
            .destination_v6
            .iter()
            .all(|(key, _)| key.prefix_len <= 128),
        "invalid destination IPv6 prefix"
    );
    ensure!(
        plan.facts
            .source_v6
            .iter()
            .all(|(key, _)| key.prefix_len <= 128),
        "invalid source IPv6 prefix"
    );
    ensure!(
        plan.facts.mac.iter().all(|(key, _)| key.prefix_len == 128),
        "invalid MAC prefix"
    );
    Ok(())
}

fn emit_condition(
    asm: &mut Assembler,
    condition: &KernelCondition,
    pass: Label,
    fail: Label,
    fds: &RoutingMapFds,
    caches: &FactCaches,
) -> anyhow::Result<()> {
    if condition.not {
        emit_predicate(asm, &condition.predicate, fail, pass, fds, caches)
    } else {
        emit_predicate(asm, &condition.predicate, pass, fail, fds, caches)
    }
}

fn emit_predicate(
    asm: &mut Assembler,
    predicate: &KernelPredicate,
    on_true: Label,
    on_false: Label,
    fds: &RoutingMapFds,
    caches: &FactCaches,
) -> anyhow::Result<()> {
    match predicate {
        KernelPredicate::Domain(id) => {
            emit_bitmap_bit(asm, R8, *id, on_true, on_false)?;
        }
        KernelPredicate::DestinationIp(id) => {
            emit_fact_bit(
                asm,
                FactKind::Destination,
                *id,
                caches,
                on_true,
                on_false,
                fds,
            )?;
        }
        KernelPredicate::SourceIp(id) => {
            emit_fact_bit(asm, FactKind::Source, *id, caches, on_true, on_false, fds)?;
        }
        KernelPredicate::Mac(id) => {
            emit_fact_bit(asm, FactKind::Mac, *id, caches, on_true, on_false, fds)?;
        }
        KernelPredicate::DestinationPort(ranges) => {
            emit_port_ranges(asm, ranges, INPUT_DST_PORT, on_true, on_false)?;
        }
        KernelPredicate::SourcePort(ranges) => {
            emit_port_ranges(asm, ranges, INPUT_SRC_PORT, on_true, on_false)?;
        }
        KernelPredicate::Protocol(mask) => {
            emit_mask_scalar(asm, INPUT_PROTO, *mask as i32, on_true, on_false)?;
        }
        KernelPredicate::IpVersion(mask) => {
            emit_mask_scalar(asm, INPUT_VERSION, *mask as i32, on_true, on_false)?;
        }
        KernelPredicate::Dscp(values) => {
            asm.ldx_w(R0, R6, INPUT_DSCP)?;
            if values.is_empty() {
                asm.ja(on_false)?;
            } else {
                for value in values {
                    asm.jump(BPF_JEQ, R0, *value as i32, on_true)?;
                }
                asm.ja(on_false)?;
            }
        }
        KernelPredicate::ProcessName(names) => {
            emit_process_names(asm, names, on_true, on_false)?;
        }
    }
    Ok(())
}

fn emit_mask_scalar(
    asm: &mut Assembler,
    offset: i16,
    mask: i32,
    on_true: Label,
    on_false: Label,
) -> anyhow::Result<()> {
    asm.ldx_w(R0, R6, offset)?;
    if mask == 0 {
        asm.ja(on_false)?;
    } else {
        asm.and_imm(R0, mask)?;
        asm.jump(BPF_JNE, R0, 0, on_true)?;
        asm.ja(on_false)?;
    }
    Ok(())
}

fn emit_port_ranges(
    asm: &mut Assembler,
    ranges: &[crate::routing::PortRange],
    offset: i16,
    on_true: Label,
    on_false: Label,
) -> anyhow::Result<()> {
    asm.ldx_w(R0, R6, offset)?;
    if ranges.is_empty() {
        asm.ja(on_false)?;
        return Ok(());
    }
    for range in ranges {
        let next = asm.label();
        let inside = asm.label();
        asm.jump(BPF_JGE, R0, range.start as i32, inside)?;
        asm.ja(next)?;
        asm.bind(inside);
        asm.jump(BPF_JGT, R0, range.end as i32, next)?;
        asm.ja(on_true)?;
        asm.bind(next);
    }
    asm.ja(on_false)?;
    Ok(())
}

fn emit_process_names(
    asm: &mut Assembler,
    names: &[Vec<u8>],
    on_true: Label,
    on_false: Label,
) -> anyhow::Result<()> {
    if names.is_empty() {
        asm.ja(on_false)?;
        return Ok(());
    }
    for bytes in names {
        let next_name = asm.label();
        asm.ldx_w(R4, R6, INPUT_PNAME_LEN)?;
        if bytes.is_empty() {
            asm.jump(BPF_JNE, R4, 0, on_true)?;
            continue;
        }
        let long = asm.label();
        asm.jump(BPF_JGE, R4, bytes.len() as i32, long)?;
        asm.ja(next_name)?;
        asm.bind(long);
        // Input pname is bounded to ROUTING_PROCESS_MAX_LEN bytes. Each
        // candidate offset is checked against pname_len before reading, so
        // missing bytes never become ordinary zeroes.
        for offset in 0..=(ROUTING_PROCESS_MAX_LEN.saturating_sub(bytes.len())) {
            let next = asm.label();
            let enough = asm.label();
            asm.jump(BPF_JGE, R4, (offset + bytes.len()) as i32, enough)?;
            asm.ja(next)?;
            asm.bind(enough);
            for (byte_index, byte) in bytes.iter().enumerate() {
                asm.ldx_b(R5, R6, INPUT_PNAME + offset as i16 + byte_index as i16)?;
                asm.jump(BPF_JNE, R5, *byte as i32, next)?;
            }
            asm.ja(on_true)?;
            asm.bind(next);
        }
        asm.bind(next_name);
    }
    asm.ja(on_false)?;
    Ok(())
}

fn emit_bitmap_bit(
    asm: &mut Assembler,
    pointer: u8,
    id: u32,
    on_true: Label,
    on_false: Label,
) -> anyhow::Result<()> {
    asm.jump(BPF_JEQ, pointer, 0, on_false)?;
    asm.ldx_w(R2, pointer, (id / 32 * 4) as i16)?;
    asm.and_imm(R2, (1u32 << (id % 32)) as i32)?;
    asm.jump(BPF_JNE, R2, 0, on_true)?;
    asm.ja(on_false)?;
    Ok(())
}

fn emit_fact_bit(
    asm: &mut Assembler,
    kind: FactKind,
    id: u32,
    caches: &FactCaches,
    on_true: Label,
    on_false: Label,
    fds: &RoutingMapFds,
) -> anyhow::Result<()> {
    if let Some(cache) = caches.slots[kind as usize] {
        let bit = 1u8 << kind as u8;
        if caches.must_ready & bit != 0 {
            asm.ldx_dw(R0, R10, cache.pointer)?;
        } else {
            let branch = (caches.may_ready & bit != 0).then(|| (asm.label(), asm.label()));
            if let Some((reuse, _)) = branch {
                asm.ldx_dw(R0, R10, cache.ready)?;
                asm.jump(BPF_JNE, R0, 0, reuse)?;
            }
            emit_fact_lookup(asm, kind, fds)?;
            asm.stx_dw(R10, R0, cache.pointer)?;
            asm.st_dw_imm(R10, cache.ready, 1)?;
            if let Some((reuse, ready)) = branch {
                asm.ja(ready)?;
                asm.bind(reuse);
                asm.ldx_dw(R0, R10, cache.pointer)?;
                asm.bind(ready);
            }
        }
    } else {
        emit_fact_lookup(asm, kind, fds)?;
    }
    emit_bitmap_bit(asm, R0, id, on_true, on_false)
}

fn emit_fact_lookup(
    asm: &mut Assembler,
    kind: FactKind,
    fds: &RoutingMapFds,
) -> anyhow::Result<()> {
    let absent = asm.label();
    let lookup = asm.label();
    let done = asm.label();
    match kind {
        FactKind::Mac => {
            asm.ldx_w(R0, R6, INPUT_MAC_PRESENT)?;
            asm.jump(BPF_JEQ, R0, 0, absent)?;
            write_key_from_input(asm, INPUT_MAC, 128)?;
            load_map_fd(asm, fds.mac)?;
        }
        FactKind::Destination | FactKind::Source => {
            let (v4_fd, v6_fd, input_offset) = match kind {
                FactKind::Destination => (fds.destination_v4, fds.destination_v6, INPUT_DST_IP),
                _ => (fds.source_v4, fds.source_v6, INPUT_SRC_IP),
            };
            let v4 = asm.label();
            let v6 = asm.label();
            asm.ldx_w(R0, R6, INPUT_VERSION)?;
            asm.jump(BPF_JEQ, R0, 1, v4)?;
            asm.jump(BPF_JEQ, R0, 2, v6)?;
            asm.ja(absent)?;
            asm.bind(v4);
            write_key_from_input(asm, input_offset + 12, 32)?;
            load_map_fd(asm, v4_fd)?;
            asm.ja(lookup)?;
            asm.bind(v6);
            write_key_from_input(asm, input_offset, 128)?;
            load_map_fd(asm, v6_fd)?;
        }
    }
    asm.bind(lookup);
    asm.mov_reg(R2, R10)?;
    asm.add_imm(R2, STACK_KEY as i32)?;
    asm.call(MAP_LOOKUP_ELEM)?;
    asm.ja(done)?;
    asm.bind(absent);
    asm.mov_imm(R0, 0)?;
    asm.bind(done);
    Ok(())
}

fn write_key_from_input(
    asm: &mut Assembler,
    input_offset: i16,
    prefix_len: u32,
) -> anyhow::Result<()> {
    asm.st_imm(R10, STACK_KEY, prefix_len as i32)?;
    let words = if prefix_len == 32 { 1 } else { 4 };
    for index in 0..words {
        let offset = index * 4;
        asm.ldx_w(R3, R6, input_offset + offset)?;
        asm.stx_w(R10, R3, STACK_KEY + 4 + offset)?;
    }
    for index in words..4 {
        asm.st_imm(R10, STACK_KEY + 4 + index * 4, 0)?;
    }
    Ok(())
}

fn write_domain_key_from_input(asm: &mut Assembler) -> anyhow::Result<()> {
    asm.mov_reg(R2, R6)?;
    asm.ldx_dw(R3, R2, INPUT_DST_IP)?;
    asm.stx_dw(R10, R3, STACK_DOMAIN_KEY)?;
    asm.ldx_dw(R3, R2, INPUT_DST_IP + 8)?;
    asm.stx_dw(R10, R3, STACK_DOMAIN_KEY + 8)?;
    Ok(())
}

fn load_map_fd(asm: &mut Assembler, fd: i32) -> anyhow::Result<()> {
    asm.emit(BPF_LD | BPF_DW | BPF_IMM, R1, PSEUDO_MAP_FD, 0, fd)?;
    asm.emit(0, 0, 0, 0, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembler_stops_at_instruction_capacity_without_publishing_fixup() {
        let mut asm = Assembler::new();
        asm.insns
            .resize_with(BPF_INSTRUCTION_CAPACITY - 1, || bpf_insn {
                code: 0,
                _bitfield_align_1: [],
                _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                off: 0,
                imm: 0,
            });

        let last = asm
            .emit(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
            .expect("the last instruction within capacity must be emitted");
        assert_eq!(last, BPF_INSTRUCTION_CAPACITY - 1);
        assert_eq!(asm.insns.len(), BPF_INSTRUCTION_CAPACITY);

        let past_capacity = asm.label();
        assert!(asm.ja(past_capacity).is_err());
        assert_eq!(asm.insns.len(), BPF_INSTRUCTION_CAPACITY);
        assert!(asm.fixups.is_empty());

        let bytecode = asm
            .finish()
            .expect("a boundary-sized program must still finish");
        assert_eq!(bytecode.insns.len(), BPF_INSTRUCTION_CAPACITY);
        assert_eq!(bytecode.insns[last].code, (BPF_JMP | BPF_EXIT) as u8);
    }

    #[test]
    fn assembler_rejects_unresolved_referenced_label() {
        let mut asm = Assembler::new();
        let missing = asm.label();
        asm.ja(missing).expect("jump itself should be emitted");

        assert!(asm.finish().is_err());
    }

    #[test]
    fn assembler_accepts_signed_jump_range_endpoints() {
        let mut forward = Assembler::new();
        let target = forward.label();
        let _unused = forward.label();
        forward.ja(target).unwrap();
        forward
            .insns
            .resize_with(i16::MAX as usize + 1, || bpf_insn {
                code: 0,
                _bitfield_align_1: [],
                _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                off: 0,
                imm: 0,
            });
        forward.bind(target);
        let bytecode = forward.finish().unwrap();
        assert_eq!(bytecode.insns[0].off, i16::MAX);

        let mut backward = Assembler::new();
        let target = backward.label();
        backward.bind(target);
        backward.insns.resize_with(i16::MAX as usize, || bpf_insn {
            code: 0,
            _bitfield_align_1: [],
            _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
            off: 0,
            imm: 0,
        });
        backward.ja(target).unwrap();
        let bytecode = backward.finish().unwrap();
        assert_eq!(bytecode.insns[i16::MAX as usize].off, i16::MIN);

        let mut too_far_forward = Assembler::new();
        let target = too_far_forward.label();
        too_far_forward.ja(target).unwrap();
        too_far_forward
            .insns
            .resize_with(i16::MAX as usize + 2, || bpf_insn {
                code: 0,
                _bitfield_align_1: [],
                _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                off: 0,
                imm: 0,
            });
        too_far_forward.bind(target);
        assert!(too_far_forward.finish().is_err());

        let mut too_far_backward = Assembler::new();
        let target = too_far_backward.label();
        too_far_backward.bind(target);
        too_far_backward
            .insns
            .resize_with(i16::MAX as usize + 1, || bpf_insn {
                code: 0,
                _bitfield_align_1: [],
                _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                off: 0,
                imm: 0,
            });
        too_far_backward.ja(target).unwrap();
        assert!(too_far_backward.finish().is_err());
    }
}
