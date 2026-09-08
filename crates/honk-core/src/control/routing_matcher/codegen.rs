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
    ROUTING_FEATURE_PROCESS, ROUTING_PROCESS_MAX_LEN,
};
use std::collections::HashMap;

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
const PSEUDO_MAP_FD: u8 = 1;
const STACK_KEY: i16 = -64;
const INPUT_SRC_IP: i16 = 0;
const INPUT_DST_IP: i16 = 16;
const INPUT_MAC: i16 = 32;
const INPUT_PNAME: i16 = 48;
const INPUT_SRC_PORT: i16 = 96;
const INPUT_DST_PORT: i16 = 100;
const INPUT_PROTO: i16 = 104;
const INPUT_VERSION: i16 = 108;
const INPUT_DSCP: i16 = 112;
const INPUT_PNAME_LEN: i16 = 120;
const INPUT_MAC_PRESENT: i16 = 124;
const OUTBOUND: i16 = 0;
const MARK: i16 = 4;
const MUST: i16 = 8;
const DOMAIN_FINAL: i16 = 12;
const RULE_ID: i16 = 16;

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

struct Assembler {
    insns: Vec<bpf_insn>,
    lines: Vec<RoutingSourceLine>,
    labels: HashMap<String, usize>,
    fixups: Vec<(usize, String)>,
}

impl Assembler {
    fn new() -> Self {
        Self {
            insns: Vec::new(),
            lines: Vec::new(),
            labels: HashMap::new(),
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

    fn label(&mut self, name: impl AsRef<str>) {
        self.labels
            .insert(name.as_ref().to_owned(), self.insns.len());
    }

    fn emit(&mut self, code: u32, dst: u8, src: u8, off: i16, imm: i32) -> usize {
        let insn = bpf_insn {
            code: code as u8,
            _bitfield_align_1: [],
            _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
            off,
            imm,
        };
        let offset = self.insns.len();
        self.insns.push(insn);
        offset
    }

    fn jump(&mut self, op: u32, dst: u8, imm: i32, target: impl AsRef<str>) {
        let index = self.emit(BPF_JMP | op | BPF_K, dst, 0, 0, imm);
        self.fixups.push((index, target.as_ref().to_owned()));
    }

    fn ja(&mut self, target: impl AsRef<str>) {
        let index = self.emit(BPF_JMP | BPF_JA, 0, 0, 0, 0);
        self.fixups.push((index, target.as_ref().to_owned()));
    }

    fn finish(mut self) -> anyhow::Result<RoutingBytecode> {
        ensure!(
            self.insns.len() <= 1_000_000,
            "routing program exceeds BPF instruction capacity"
        );
        for (index, target) in self.fixups {
            let target = self
                .labels
                .get(&target)
                .copied()
                .with_context(|| format!("unresolved jump label '{target}'"))?;
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

    fn mov_reg(&mut self, dst: u8, src: u8) {
        self.emit(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0);
    }
    fn mov_imm(&mut self, dst: u8, imm: i32) {
        self.emit(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm);
    }
    fn add_imm(&mut self, dst: u8, imm: i32) {
        self.emit(BPF_ALU64 | BPF_K, dst, 0, 0, imm);
    }
    fn and_imm(&mut self, dst: u8, imm: i32) {
        self.emit(BPF_ALU64 | BPF_AND | BPF_K, dst, 0, 0, imm);
    }
    fn ldx_w(&mut self, dst: u8, src: u8, off: i16) {
        self.emit(BPF_LDX | BPF_W | BPF_MEM, dst, src, off, 0);
    }
    fn ldx_b(&mut self, dst: u8, src: u8, off: i16) {
        self.emit(BPF_LDX | BPF_B | BPF_MEM, dst, src, off, 0);
    }
    fn ldx_dw(&mut self, dst: u8, src: u8, off: i16) {
        self.emit(BPF_LDX | BPF_DW | BPF_MEM, dst, src, off, 0);
    }
    fn stx_dw(&mut self, dst: u8, src: u8, off: i16) {
        self.emit(BPF_STX | BPF_DW | BPF_MEM, dst, src, off, 0);
    }
    fn stx_w(&mut self, dst: u8, src: u8, off: i16) {
        self.emit(BPF_STX | BPF_W | BPF_MEM, dst, src, off, 0);
    }
    fn st_imm(&mut self, dst: u8, off: i16, imm: i32) {
        self.emit(BPF_ST | BPF_W | BPF_MEM, dst, 0, off, imm);
    }
    fn call(&mut self, helper: i32) {
        self.emit(BPF_JMP | BPF_CALL, 0, 0, 0, helper);
    }
    fn exit(&mut self) {
        self.emit(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
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
    for (register, label) in [(R1, "input_nonnull"), (R2, "decision_nonnull")] {
        asm.jump(BPF_JNE, register, 0, label);
        asm.mov_imm(R0, -libc::EFAULT);
        asm.exit();
        asm.label(label);
    }
    asm.mov_reg(R6, R1);
    asm.mov_reg(R7, R2);
    asm.st_imm(R7, OUTBOUND, plan.fallback as i32);
    asm.st_imm(R7, MARK, 0);
    asm.st_imm(R7, MUST, 0);
    asm.st_imm(
        R7,
        DOMAIN_FINAL,
        (!plan.has_domain_rules || plan.features & ROUTING_FEATURE_DOMAIN_REROUTE == 0) as i32,
    );
    asm.st_imm(R7, RULE_ID, u32::MAX as i32);

    if plan.has_domain_rules {
        write_domain_key_from_input(&mut asm);
        load_map_fd(&mut asm, fds.domain);
        asm.mov_reg(R2, R10);
        asm.add_imm(R2, STACK_DOMAIN_KEY as i32);
        asm.call(MAP_LOOKUP_ELEM);
        asm.mov_reg(R8, R0);
        asm.jump(BPF_JEQ, R8, 0, "domain_absent");
        asm.st_imm(R7, DOMAIN_FINAL, 1);
        asm.label("domain_absent");
    }

    for (index, rule) in plan.rules.iter().enumerate() {
        asm.source(rule.id + 1, rule.source.clone());
        let fail = format!("rule_{index}_fail");
        for (condition_index, condition) in rule.conditions.iter().enumerate() {
            let pass = format!("rule_{index}_condition_{condition_index}_pass");
            emit_condition(
                &mut asm,
                condition,
                &pass,
                &fail,
                &fds,
                index,
                condition_index,
            )?;
            asm.label(&pass);
        }
        asm.st_imm(R7, OUTBOUND, rule.outbound as i32);
        asm.st_imm(R7, MARK, rule.mark as i32);
        asm.st_imm(R7, MUST, rule.must as i32);
        asm.st_imm(R7, RULE_ID, rule.id as i32);
        asm.mov_imm(R0, 0);
        asm.exit();
        asm.label(&fail);
    }

    asm.source(0, "fallback");
    asm.st_imm(R7, OUTBOUND, plan.fallback as i32);
    asm.st_imm(R7, MARK, 0);
    asm.st_imm(R7, MUST, 0);
    asm.st_imm(R7, RULE_ID, u32::MAX as i32);
    asm.mov_imm(R0, 0);
    asm.exit();
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
    pass: &str,
    fail: &str,
    fds: &RoutingMapFds,
    rule: usize,
    condition_index: usize,
) -> anyhow::Result<()> {
    let truth = format!("condition_{rule}_{condition_index}_truth");
    if condition.not {
        emit_predicate(
            asm,
            &condition.predicate,
            fail,
            &truth,
            fds,
            rule,
            condition_index,
        )?;
    } else {
        emit_predicate(
            asm,
            &condition.predicate,
            &truth,
            fail,
            fds,
            rule,
            condition_index,
        )?;
    }
    asm.label(&truth);
    asm.ja(pass);
    Ok(())
}

fn emit_predicate(
    asm: &mut Assembler,
    predicate: &KernelPredicate,
    on_true: &str,
    on_false: &str,
    fds: &RoutingMapFds,
    rule: usize,
    condition: usize,
) -> anyhow::Result<()> {
    let label = |suffix: &str| format!("pred_{rule}_{condition}_{suffix}");
    match predicate {
        KernelPredicate::Domain(id) => {
            emit_domain_bit(asm, *id, on_true, on_false);
        }
        KernelPredicate::DestinationIp(id) => {
            emit_family_map_bit(
                asm,
                *id,
                fds.destination_v4,
                fds.destination_v6,
                on_true,
                on_false,
                INPUT_DST_IP,
            );
        }
        KernelPredicate::SourceIp(id) => {
            emit_family_map_bit(
                asm,
                *id,
                fds.source_v4,
                fds.source_v6,
                on_true,
                on_false,
                INPUT_SRC_IP,
            );
        }
        KernelPredicate::Mac(id) => {
            asm.ldx_w(R0, R6, INPUT_MAC_PRESENT);
            asm.jump(BPF_JEQ, R0, 0, on_false);
            emit_lpm_bit(asm, fds.mac, *id, 128, INPUT_MAC, on_true, on_false);
        }
        KernelPredicate::DestinationPort(ranges) => {
            emit_port_ranges(
                asm,
                ranges,
                INPUT_DST_PORT,
                on_true,
                on_false,
                &label("dport"),
            );
        }
        KernelPredicate::SourcePort(ranges) => {
            emit_port_ranges(
                asm,
                ranges,
                INPUT_SRC_PORT,
                on_true,
                on_false,
                &label("sport"),
            );
        }
        KernelPredicate::Protocol(mask) => {
            emit_mask_scalar(asm, INPUT_PROTO, *mask as i32, on_true, on_false);
        }
        KernelPredicate::IpVersion(mask) => {
            emit_mask_scalar(asm, INPUT_VERSION, *mask as i32, on_true, on_false);
        }
        KernelPredicate::Dscp(values) => {
            asm.ldx_w(R0, R6, INPUT_DSCP);
            if values.is_empty() {
                asm.ja(on_false);
            } else {
                for value in values {
                    asm.jump(BPF_JEQ, R0, *value as i32, on_true);
                }
                asm.ja(on_false);
            }
        }
        KernelPredicate::ProcessName(names) => {
            emit_process_names(asm, names, on_true, on_false, &label("pname"));
        }
    }
    Ok(())
}

fn emit_mask_scalar(asm: &mut Assembler, offset: i16, mask: i32, on_true: &str, on_false: &str) {
    asm.ldx_w(R0, R6, offset);
    if mask == 0 {
        asm.ja(on_false);
    } else {
        asm.and_imm(R0, mask);
        asm.jump(BPF_JNE, R0, 0, on_true);
        asm.ja(on_false);
    }
}

fn emit_port_ranges(
    asm: &mut Assembler,
    ranges: &[crate::routing::PortRange],
    offset: i16,
    on_true: &str,
    on_false: &str,
    label_prefix: &str,
) {
    asm.ldx_w(R0, R6, offset);
    if ranges.is_empty() {
        asm.ja(on_false);
        return;
    }
    for (index, range) in ranges.iter().enumerate() {
        let next = format!("{label_prefix}_next_{index}");
        let inside = format!("{label_prefix}_inside_{index}");
        asm.jump(BPF_JGE, R0, range.start as i32, &inside);
        asm.ja(&next);
        asm.label(&inside);
        asm.jump(BPF_JGT, R0, range.end as i32, &next);
        asm.ja(on_true);
        asm.label(&next);
    }
    asm.ja(on_false);
}

fn emit_process_names(
    asm: &mut Assembler,
    names: &[Vec<u8>],
    on_true: &str,
    on_false: &str,
    prefix: &str,
) {
    if names.is_empty() {
        asm.ja(on_false);
        return;
    }
    for (name_index, bytes) in names.iter().enumerate() {
        let next_name = format!("{prefix}_next_name_{name_index}");
        asm.ldx_w(R4, R6, INPUT_PNAME_LEN);
        if bytes.is_empty() {
            asm.jump(BPF_JNE, R4, 0, on_true);
            continue;
        }
        asm.jump(
            BPF_JGE,
            R4,
            bytes.len() as i32,
            format!("{prefix}_long_{name_index}"),
        );
        asm.ja(&next_name);
        asm.label(format!("{prefix}_long_{name_index}"));
        // Input pname is bounded to 48 bytes.  Each candidate offset is
        // checked against pname_len before reading, so missing bytes never
        // become ordinary zeroes.
        for offset in 0..=(48usize.saturating_sub(bytes.len())) {
            let next = format!("{prefix}_next_{name_index}_{offset}");
            asm.jump(
                BPF_JGE,
                R4,
                (offset + bytes.len()) as i32,
                format!("{prefix}_enough_{name_index}_{offset}"),
            );
            asm.ja(&next);
            asm.label(format!("{prefix}_enough_{name_index}_{offset}"));
            for (byte_index, byte) in bytes.iter().enumerate() {
                asm.ldx_b(R5, R6, INPUT_PNAME + offset as i16 + byte_index as i16);
                asm.jump(BPF_JNE, R5, *byte as i32, &next);
            }
            asm.ja(on_true);
            asm.label(&next);
        }
        asm.label(&next_name);
    }
    asm.ja(on_false);
}

fn emit_domain_bit(asm: &mut Assembler, id: u32, on_true: &str, on_false: &str) {
    asm.jump(BPF_JEQ, R8, 0, on_false);
    asm.ldx_w(R2, R8, (id / 32 * 4) as i16);
    asm.and_imm(R2, (1u32 << (id % 32)) as i32);
    asm.jump(BPF_JNE, R2, 0, on_true);
    asm.ja(on_false);
}

fn emit_family_map_bit(
    asm: &mut Assembler,
    id: u32,
    v4_fd: i32,
    v6_fd: i32,
    on_true: &str,
    on_false: &str,
    input_offset: i16,
) {
    asm.ldx_w(R0, R6, INPUT_VERSION);
    let v4 = format!("ip_v4_{}", asm.insns.len());
    let v6 = format!("ip_v6_{}", asm.insns.len());
    asm.jump(BPF_JEQ, R0, 1, &v4);
    asm.jump(BPF_JEQ, R0, 2, &v6);
    asm.ja(on_false);
    asm.label(&v4);
    emit_lpm_bit(asm, v4_fd, id, 32, input_offset + 12, on_true, on_false);
    asm.label(&v6);
    emit_lpm_bit(asm, v6_fd, id, 128, input_offset, on_true, on_false);
}

fn emit_lpm_bit(
    asm: &mut Assembler,
    fd: i32,
    id: u32,
    prefix_len: u32,
    input_offset: i16,
    on_true: &str,
    on_false: &str,
) {
    write_key_from_input(asm, input_offset, prefix_len);
    load_map_fd(asm, fd);
    asm.mov_reg(R2, R10);
    asm.add_imm(R2, STACK_KEY as i32);
    asm.call(MAP_LOOKUP_ELEM);
    asm.jump(BPF_JEQ, R0, 0, on_false);
    asm.ldx_w(R2, R0, (id / 32 * 4) as i16);
    asm.and_imm(R2, (1u32 << (id % 32)) as i32);
    asm.jump(BPF_JNE, R2, 0, on_true);
    asm.ja(on_false);
}

fn write_key_from_input(asm: &mut Assembler, input_offset: i16, prefix_len: u32) {
    asm.st_imm(R10, STACK_KEY, prefix_len as i32);
    for index in 0..4 {
        asm.st_imm(R10, STACK_KEY + 4 + index * 4, 0);
    }
    asm.mov_reg(R2, R6);
    let words = if prefix_len == 32 { 1 } else { 4 };
    for index in 0..words {
        let offset = index as i16 * 4;
        asm.ldx_w(R3, R2, input_offset + offset);
        asm.stx_w(R10, R3, STACK_KEY + 4 + offset);
    }
}

fn write_domain_key_from_input(asm: &mut Assembler) {
    asm.mov_reg(R2, R6);
    asm.ldx_dw(R3, R2, INPUT_DST_IP);
    asm.stx_dw(R10, R3, STACK_DOMAIN_KEY);
    asm.ldx_dw(R3, R2, INPUT_DST_IP + 8);
    asm.stx_dw(R10, R3, STACK_DOMAIN_KEY + 8);
}

fn load_map_fd(asm: &mut Assembler, fd: i32) {
    asm.emit(BPF_LD | BPF_DW | BPF_IMM, R1, PSEUDO_MAP_FD, 0, fd);
    asm.emit(0, 0, 0, 0, 0);
}
