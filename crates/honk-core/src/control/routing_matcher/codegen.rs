//! Native eBPF emitter for the fixed RoutingInput/KernelRouteOutput ABI.
//!
//! The emitter produces only a function body.  The backend supplies the real
//! freplace prototype, BTF and map lifetime; R1 is `*const RoutingInput` and
//! R2 is `*mut KernelRouteOutput`.

use super::{KernelAction, KernelCondition, KernelPredicate, KernelTraceLayout, RoutingPushPlan};
use anyhow::{Context, ensure};
use aya_obj::generated::{
    BPF_ALU64, BPF_AND, BPF_B, BPF_CALL, BPF_DW, BPF_EXIT, BPF_IMM, BPF_JA, BPF_JEQ, BPF_JGE,
    BPF_JGT, BPF_JMP, BPF_JNE, BPF_JSET, BPF_K, BPF_LD, BPF_LDX, BPF_MEM, BPF_MOV, BPF_OR, BPF_ST,
    BPF_STX, BPF_W, BPF_X, bpf_insn,
};
use honk_config::types::DialMode;
use honk_ebpf_common::xdp_gateway::{
    GATEWAY_DNS_BITMAP_OFFSET, GATEWAY_DNS_READY, GATEWAY_ROUTE_NEED_DNS,
};
use honk_ebpf_common::{
    KernelRouteOutput, ROUTE_FACT_PRESENT_SHIFT, ROUTE_TRACE_COMPLETE, ROUTE_TRACE_ENABLED,
    ROUTE_TRACE_MATCHED, ROUTE_TRACE_NOT_MATCHED, ROUTE_TRACE_OVERFLOW, ROUTE_TRACE_VALUES,
    ROUTE_TRACE_VERSION, ROUTE_TRACE_WORDS, ROUTING_FACT_CAPACITY, ROUTING_FEATURE_DOMAIN,
    ROUTING_FEATURE_DOMAIN_REROUTE, ROUTING_FEATURE_PROCESS, ROUTING_INPUT_ALLOW_DIRECT_FINALITY,
    ROUTING_INPUT_MAC_PRESENT, ROUTING_MARK_KEEP, ROUTING_MARK_SET, ROUTING_PROCESS_MAX_LEN,
    RoutingDecision, RoutingInput,
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
const R9: u8 = 9;
const R10: u8 = 10;
const MAP_LOOKUP_ELEM: i32 = 1;
const BPF_INSTRUCTION_CAPACITY: usize = 1_000_000;
const PSEUDO_MAP_FD: u8 = 1;
/// Bytes of one `DomainRouting` bitmap, copied out of a map value.
const FACT_BYTES: i16 = (ROUTING_FACT_CAPACITY / 8) as i16;
/// LPM/MAC lookup key: 20 bytes written, 32 reserved.
const STACK_KEY: i16 = -(4 * FACT_BYTES) - 32;
/// Domain lookup key: the 16-byte destination address.
const STACK_DOMAIN_KEY: i16 = STACK_KEY - 16;
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
const INPUT_FLAGS: i16 = std::mem::offset_of!(RoutingInput, flags) as i16;
const OUTBOUND: i16 = std::mem::offset_of!(RoutingDecision, outbound) as i16;
const MARK: i16 = std::mem::offset_of!(RoutingDecision, mark) as i16;
const MUST: i16 = std::mem::offset_of!(RoutingDecision, must) as i16;
const DOMAIN_FINAL: i16 = std::mem::offset_of!(RoutingDecision, domain_final) as i16;
const RULE_ID: i16 = std::mem::offset_of!(RoutingDecision, rule_id) as i16;
const TRACE_FLAGS: i16 = std::mem::offset_of!(KernelRouteOutput, flags) as i16;
const MARK_KIND: i16 = std::mem::offset_of!(KernelRouteOutput, mark_kind) as i16;
const TRACE_FACT_STATE: i16 = std::mem::offset_of!(KernelRouteOutput, fact_state) as i16;
const TRACE_INPUT: i16 = std::mem::offset_of!(KernelRouteOutput, input) as i16;
const TRACE_DOMAIN: i16 = std::mem::offset_of!(KernelRouteOutput, domain_bitmap) as i16;
const TRACE_OUTCOMES: i16 = std::mem::offset_of!(KernelRouteOutput, outcomes) as i16;
const DIRECT_MARK_INDEX: i16 = std::mem::offset_of!(RoutingDecision, direct_mark_index) as i16;
const HOST_SCRATCH_END: i16 = TRACE_INPUT - STACK_DOMAIN_KEY;
const _: () = assert!(HOST_SCRATCH_END as usize <= std::mem::size_of::<KernelRouteOutput>());
const _: () =
    assert!(GATEWAY_DNS_BITMAP_OFFSET == (HOST_SCRATCH_END + FactKind::Domain.area()) as usize);

/// One lookup category. Each owns a 32-byte stack area holding its
/// `DomainRouting` bitmap once resolved: domain at [-32, -1], destination at
/// [-64, -33], source at [-96, -65], MAC at [-128, -97].
#[derive(Clone, Copy)]
enum FactKind {
    Domain,
    Destination,
    Source,
    Mac,
}

impl FactKind {
    const fn area(self) -> i16 {
        -(self as i16 + 1) * FACT_BYTES
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
    pub trace_layout: Option<KernelTraceLayout>,
}

/// Gateway function body: R1 is `RoutingInput` and R2 is caller-guarded scratch.
/// With DNS shadow, R3 is zero on the first pass and `GATEWAY_DNS_READY` with a bitmap.
/// Return 1 for proven direct, 0 for Endpoint, `GATEWAY_ROUTE_NEED_DNS` for the
/// first reachable domain predicate without a bitmap, or a negative input error.
#[derive(Debug, Clone)]
pub struct GatewayBytecode {
    pub insns: Vec<bpf_insn>,
    pub source_lines: Vec<RoutingSourceLine>,
    pub fingerprint: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct Label(usize);

struct Assembler {
    insns: Vec<bpf_insn>,
    lines: Vec<RoutingSourceLine>,
    labels: Vec<Option<usize>>,
    fixups: Vec<(usize, Label)>,
    trace_layout: Option<KernelTraceLayout>,
    host_scratch: bool,
}

impl Assembler {
    fn new() -> Self {
        Self {
            insns: Vec::new(),
            lines: Vec::new(),
            labels: Vec::new(),
            fixups: Vec::new(),
            trace_layout: None,
            host_scratch: false,
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
        let (dst, src) = if self.host_scratch {
            if dst == R10 {
                ensure!(
                    matches!(code & 7, BPF_ST | BPF_STX),
                    "unexpected Host frame-pointer destination"
                );
            }
            if src == R10 {
                ensure!(
                    code & 7 == BPF_LDX || code == (BPF_ALU64 | BPF_MOV | BPF_X),
                    "unexpected Host frame-pointer source"
                );
            }
            (
                if dst == R10 { R9 } else { dst },
                if src == R10 { R9 } else { src },
            )
        } else {
            (dst, src)
        };
        let insn = bpf_insn {
            code: code as u8,
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
            let delta = i64::try_from(target)?
                .checked_sub(i64::try_from(index)?)
                .and_then(|delta| delta.checked_sub(1))
                .context("routing jump offset overflow")?;
            self.insns[index].off = i16::try_from(delta)
                .with_context(|| format!("routing jump out of range: {index} -> {target}"))?;
        }
        Ok(RoutingBytecode {
            insns: self.insns,
            lines: self.lines,
            trace_layout: self.trace_layout,
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
    fn or_imm(&mut self, dst: u8, imm: i32) -> anyhow::Result<()> {
        self.emit(BPF_ALU64 | BPF_OR | BPF_K, dst, 0, 0, imm)?;
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
    fn call(&mut self, helper: i32) -> anyhow::Result<()> {
        self.emit(BPF_JMP | BPF_CALL, 0, 0, 0, helper)?;
        Ok(())
    }
    fn exit(&mut self) -> anyhow::Result<()> {
        self.emit(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)?;
        Ok(())
    }
}

/// Per-invocation resolved bits for the lazily evaluated categories
/// (Destination/Source/MAC). Kept in R8, which callee-saves across the
/// lookup helper; it says this call already resolved the category, not
/// that the emitter merely emitted a lookup somewhere.
/// Gateway DNS shadow reserves bit 3 for its caller-provided domain bitmap.
///
/// Outside gateway DNS shadow, the verifier must not see an initial constant:
/// with `mov 0` it is one precise value per resolution history, states
/// with different values cannot subsume each other, and every later
/// process-name chain is walked once per value: the #280 policy cost
/// 160k processed instructions that way against 54k when the mask is
/// loaded back from the decision's just-zeroed `mark` (a memory load the
/// verifier does not fold into a constant; zero at runtime). The lazily
/// resolved areas are pre-filled from fresh loads of the same field, so a
/// use verified before its resolution reads initialized stack, and the
/// stored values share no scalar id with the mask: spilling the mask
/// register itself links them and the walk splits again (133k). Measured
/// on Linux 6.12.107; a verifier that tracks memory contents through the
/// store would make the mask a constant again.
const READY: u8 = R8;

/// Emit a complete RoutingInput -> KernelRouteOutput function body.
pub fn emit_routing_program(
    plan: &RoutingPushPlan,
    fds: RoutingMapFds,
) -> anyhow::Result<RoutingBytecode> {
    emit_routing_program_inner(plan, fds, false, false, false, true)
}

/// Host callers reserve the output's unused trace payload as scratch under their busy guard.
/// This shares canonical routing while leaving no additional BPF stack frame or trace output.
pub fn emit_host_routing_program(
    plan: &RoutingPushPlan,
    fds: RoutingMapFds,
) -> anyhow::Result<RoutingBytecode> {
    emit_routing_program_inner(plan, fds, true, false, false, true)
}

/// Emit gateway classification using canonical predicates and map-backed scratch.
/// The caller supplies a complete TCP SYN/UDP input and owns the scratch busy guard.
/// Host supplies a normalized pname and length. LAN and auxiliary inputs always
/// have Missing process identity. The caller captures Rule-mode direct authority
/// in the input's ALLOW_DIRECT_FINALITY bit.
pub fn emit_gateway_routing_program(
    plan: &RoutingPushPlan,
    fds: RoutingMapFds,
    dns_shadow: bool,
    allow_process: bool,
) -> std::io::Result<GatewayBytecode> {
    let bytecode = emit_routing_program_inner(
        plan,
        fds,
        true,
        true,
        dns_shadow && plan.has_domain_rules,
        allow_process,
    )
    .map_err(std::io::Error::other)?;
    Ok(GatewayBytecode {
        insns: bytecode.insns,
        source_lines: bytecode.lines,
        fingerprint: plan.fingerprint,
    })
}

fn emit_gateway_terminal(
    asm: &mut Assembler,
    action: KernelAction,
    dial_mode: DialMode,
    dns_shadow: bool,
) -> anyhow::Result<()> {
    let direct = action.outbound == honk_ebpf_common::OutboundIndex::Direct as u8
        && !action.mark.is_some_and(|mark| mark != 0);
    if !direct {
        asm.mov_imm(R0, 0)?;
        return asm.exit();
    }
    let denied = asm.label();
    let check_port = !action.must || dns_shadow;
    let allowed = asm.label();
    if action.must && dns_shadow {
        let dns = asm.label();
        asm.jump(BPF_JSET, READY, GATEWAY_DNS_READY, dns)?;
        asm.ja(allowed)?;
        asm.bind(dns);
    }
    if !action.must {
        asm.ldx_w(R0, R6, INPUT_FLAGS)?;
        asm.and_imm(R0, ROUTING_INPUT_ALLOW_DIRECT_FINALITY as i32)?;
        asm.jump(BPF_JEQ, R0, 0, denied)?;
        let skip_domain_final = (dns_shadow && dial_mode == DialMode::Ip).then(|| asm.label());
        if dns_shadow {
            asm.jump(
                BPF_JSET,
                READY,
                GATEWAY_DNS_READY,
                skip_domain_final.unwrap_or(denied),
            )?;
        }
        asm.ldx_w(R0, R7, DOMAIN_FINAL)?;
        asm.jump(BPF_JEQ, R0, 0, denied)?;
        if let Some(skip) = skip_domain_final {
            asm.bind(skip);
        }
    }
    if check_port {
        asm.ldx_w(R0, R6, INPUT_DST_PORT)?;
        asm.jump(BPF_JEQ, R0, 53, denied)?;
    }
    asm.bind(allowed);
    asm.mov_imm(R0, 1)?;
    asm.exit()?;
    if check_port {
        asm.bind(denied);
        asm.mov_imm(R0, 0)?;
        asm.exit()?;
    }
    Ok(())
}

fn validate_map_fds(fds: &RoutingMapFds, domain: bool) -> anyhow::Result<()> {
    for (name, fd) in [
        ("destination_v4", fds.destination_v4),
        ("destination_v6", fds.destination_v6),
        ("source_v4", fds.source_v4),
        ("source_v6", fds.source_v6),
        ("mac", fds.mac),
    ] {
        ensure!(fd >= 0, "invalid {name} routing map fd {fd}");
    }
    ensure!(
        !domain || fds.domain >= 0,
        "invalid domain routing map fd {}",
        fds.domain
    );
    Ok(())
}

fn emit_routing_program_inner(
    plan: &RoutingPushPlan,
    fds: RoutingMapFds,
    host_scratch: bool,
    gateway: bool,
    dns_shadow: bool,
    allow_process: bool,
) -> anyhow::Result<RoutingBytecode> {
    validate_plan(plan)?;
    validate_map_fds(&fds, !gateway)?;

    let mut asm = Assembler::new();
    asm.host_scratch = host_scratch;
    asm.trace_layout = if host_scratch {
        None
    } else {
        plan.trace_layout()
    };
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
    if asm.host_scratch {
        asm.mov_reg(R9, R2)?;
        asm.add_imm(R9, i32::from(HOST_SCRATCH_END))?;
    }
    asm.st_imm(R7, DIRECT_MARK_INDEX, u32::MAX as i32)?;
    asm.st_imm(R7, OUTBOUND, plan.fallback.outbound as i32)?;
    asm.st_imm(R7, MARK, 0)?;
    asm.st_imm(R7, MARK_KIND, ROUTING_MARK_KEEP as i32)?;
    asm.st_imm(R7, MUST, 0)?;
    asm.st_imm(
        R7,
        DOMAIN_FINAL,
        (!plan.has_domain_rules || plan.features & ROUTING_FEATURE_DOMAIN_REROUTE == 0) as i32,
    )?;
    asm.st_imm(R7, RULE_ID, u32::MAX as i32)?;
    if dns_shadow {
        // The trusted call sites pass constants so the verifier can prune the DNS branches.
        asm.mov_reg(READY, R3)?;
    } else {
        asm.ldx_w(READY, R7, MARK)?;
    }
    for kind in [FactKind::Destination, FactKind::Source, FactKind::Mac] {
        for word in 0..FACT_BYTES / 8 {
            asm.ldx_w(R1, R7, MARK)?;
            asm.stx_dw(R10, R1, kind.area() + word * 8)?;
        }
    }
    emit_trace_init(&mut asm)?;

    if plan.has_domain_rules && !gateway {
        emit_fact_lookup(&mut asm, FactKind::Domain, &fds)?;
    }

    let domain_reroute = plan.features & ROUTING_FEATURE_DOMAIN_REROUTE != 0;
    let mut domain_prefix = false;
    let mut trace_slot = 0;
    for rule in &plan.rules {
        let rule_slot = trace_slot;
        trace_slot += 1 + rule.conditions.len();
        // BPF rejects structurally unreachable instructions before evaluating predicates.
        if rule.folded_false() {
            continue;
        }
        asm.source(rule.id + 1, rule.source.as_str());
        let fail = asm.label();
        let mut conditional = false;
        let mut missing_process = false;
        let mut domain_barrier = false;
        let conditions = rule.runtime_conditions();
        let gateway_domain = gateway
            && conditions
                .clone()
                .any(|(_, condition)| matches!(condition.predicate, KernelPredicate::Domain(_)));
        domain_prefix |= gateway_domain;
        // An unavailable domain need not defer a rule the Host process has already excluded.
        let process_first =
            gateway_domain && allow_process && plan.features & ROUTING_FEATURE_PROCESS != 0;
        let early = |(_, condition): &(usize, &KernelCondition)| {
            condition.predicate.is_port()
                || matches!(condition.predicate, KernelPredicate::ProcessName(_))
        };
        let conditions = process_first
            .then(|| conditions.clone().filter(early))
            .into_iter()
            .flatten()
            .chain(conditions.filter(|condition| !process_first || !early(condition)));
        for (rank, (_, condition)) in conditions.enumerate() {
            domain_prefix |= matches!(condition.predicate, KernelPredicate::Domain(_));
            if gateway {
                match condition.predicate {
                    KernelPredicate::Domain(_) => {
                        if dns_shadow {
                            let ready = asm.label();
                            asm.jump(BPF_JSET, READY, GATEWAY_DNS_READY, ready)?;
                            asm.mov_imm(R0, GATEWAY_ROUTE_NEED_DNS)?;
                            asm.exit()?;
                            asm.bind(ready);
                        } else {
                            domain_barrier = true;
                            break;
                        }
                    }
                    KernelPredicate::ProcessName(_) if !allow_process => {
                        if !condition.not {
                            asm.ja(fail)?;
                            conditional = true;
                            missing_process = true;
                            break;
                        }
                        continue;
                    }
                    _ => {}
                }
            }
            let pass = asm.label();
            if plan.trace_enabled {
                let missed = asm.label();
                emit_condition(&mut asm, condition, pass, missed, &fds)?;
                asm.bind(missed);
                emit_trace_outcome(&mut asm, rule_slot + 1 + rank, ROUTE_TRACE_NOT_MATCHED)?;
                asm.ja(fail)?;
            } else {
                emit_condition(&mut asm, condition, pass, fail, &fds)?;
            }
            conditional = true;
            asm.bind(pass);
            emit_trace_outcome(&mut asm, rule_slot + 1 + rank, ROUTE_TRACE_MATCHED)?;
        }
        if domain_barrier {
            // Current domain facts cannot prove that a future sniffed domain will miss.
            asm.mov_imm(R0, 0)?;
            asm.exit()?;
        } else if !missing_process {
            emit_trace_outcome(&mut asm, rule_slot, ROUTE_TRACE_MATCHED)?;
            emit_action(
                &mut asm,
                rule.action,
                Some(rule.id),
                domain_reroute && !domain_prefix,
            )?;
            emit_trace_or(&mut asm, TRACE_FLAGS, ROUTE_TRACE_COMPLETE)?;
            if gateway {
                emit_gateway_terminal(&mut asm, rule.action, plan.dial_mode, dns_shadow)?;
            } else {
                asm.mov_imm(R0, 0)?;
                asm.exit()?;
            }
        }
        if !conditional {
            return asm.finish();
        }
        asm.bind(fail);
        emit_trace_outcome(&mut asm, rule_slot, ROUTE_TRACE_NOT_MATCHED)?;
    }

    // Keep the prologue's zero MARK available to seed lazy fact areas.
    asm.source(0, "fallback");
    emit_trace_outcome(&mut asm, trace_slot, ROUTE_TRACE_MATCHED)?;
    emit_action(
        &mut asm,
        plan.fallback,
        None,
        domain_reroute && !domain_prefix,
    )?;
    emit_trace_or(&mut asm, TRACE_FLAGS, ROUTE_TRACE_COMPLETE)?;
    if gateway {
        emit_gateway_terminal(&mut asm, plan.fallback, plan.dial_mode, dns_shadow)?;
    } else {
        asm.mov_imm(R0, 0)?;
        asm.exit()?;
    }
    asm.finish()
}

fn emit_action(
    asm: &mut Assembler,
    action: KernelAction,
    rule_id: Option<u32>,
    refine_direct_finality: bool,
) -> anyhow::Result<()> {
    if refine_direct_finality
        && action.outbound == honk_ebpf_common::OutboundIndex::Direct as u8
        && !action.must
    {
        let not_final = asm.label();
        asm.ldx_w(R0, R6, INPUT_FLAGS)?;
        asm.and_imm(R0, ROUTING_INPUT_ALLOW_DIRECT_FINALITY as i32)?;
        asm.jump(BPF_JEQ, R0, 0, not_final)?;
        asm.st_imm(R7, DOMAIN_FINAL, 1)?;
        asm.bind(not_final);
    }
    if rule_id.is_some() {
        asm.st_imm(R7, OUTBOUND, action.outbound as i32)?;
    }
    asm.st_imm(R7, MARK, action.mark.unwrap_or(0) as i32)?;
    asm.st_imm(
        R7,
        MARK_KIND,
        if action.mark.is_some() {
            ROUTING_MARK_SET
        } else {
            ROUTING_MARK_KEEP
        } as i32,
    )?;
    if rule_id.is_some() || action.must {
        asm.st_imm(R7, MUST, action.must as i32)?;
    }
    if let Some(id) = rule_id {
        asm.st_imm(R7, RULE_ID, id as i32)?;
    }
    if rule_id.is_some() || action.direct_mark_index.is_some() {
        asm.st_imm(
            R7,
            DIRECT_MARK_INDEX,
            action.direct_mark_index.map_or(u32::MAX, u32::from) as i32,
        )?;
    }
    Ok(())
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
) -> anyhow::Result<()> {
    let on_true = if condition.not { fail } else { pass };
    let on_false = if condition.not { pass } else { fail };
    emit_predicate(asm, &condition.predicate, on_true, on_false, fds)
}

fn emit_trace_init(asm: &mut Assembler) -> anyhow::Result<()> {
    if asm.trace_layout.is_none() {
        return Ok(());
    }
    let disabled = asm.label();
    asm.ldx_w(R9, R7, TRACE_FLAGS)?;
    asm.and_imm(R9, ROUTE_TRACE_ENABLED as i32)?;
    asm.jump(BPF_JEQ, R9, 0, disabled)?;
    asm.st_imm(
        R7,
        TRACE_FLAGS,
        (ROUTE_TRACE_VERSION | ROUTE_TRACE_ENABLED) as i32,
    )?;
    asm.st_imm(R7, TRACE_FACT_STATE, 0)?;
    for word in 0..ROUTE_TRACE_WORDS {
        asm.st_imm(R7, TRACE_OUTCOMES + (word * 4) as i16, 0)?;
    }
    for word in 0..FACT_BYTES / 4 {
        asm.st_imm(R7, TRACE_DOMAIN + word * 4, 0)?;
    }
    for word in 0..std::mem::size_of::<RoutingInput>() / 4 {
        asm.ldx_w(R1, R6, (word * 4) as i16)?;
        asm.stx_w(R7, R1, TRACE_INPUT + (word * 4) as i16)?;
    }
    asm.bind(disabled);
    Ok(())
}

/// Every site is reached at most once. OR preserves adjacent two-bit values;
/// a capture budget miss records loss, never short-circuits the routing code.
fn emit_trace_outcome(asm: &mut Assembler, slot: usize, result: u32) -> anyhow::Result<()> {
    if slot >= ROUTE_TRACE_VALUES {
        emit_trace_or(asm, TRACE_FLAGS, ROUTE_TRACE_OVERFLOW)
    } else {
        emit_trace_or(
            asm,
            TRACE_OUTCOMES + (slot / 16 * 4) as i16,
            result << (slot % 16 * 2),
        )
    }
}

fn emit_trace_or(asm: &mut Assembler, offset: i16, bits: u32) -> anyhow::Result<()> {
    if asm.trace_layout.is_none() {
        return Ok(());
    }
    let disabled = asm.label();
    asm.jump(BPF_JEQ, R9, 0, disabled)?;
    asm.ldx_w(R1, R7, offset)?;
    asm.or_imm(R1, bits as i32)?;
    asm.stx_w(R7, R1, offset)?;
    asm.bind(disabled);
    Ok(())
}

fn emit_trace_domain(asm: &mut Assembler) -> anyhow::Result<()> {
    if asm.trace_layout.is_none() {
        return Ok(());
    }
    let disabled = asm.label();
    asm.jump(BPF_JEQ, R9, 0, disabled)?;
    for word in 0..FACT_BYTES / 8 {
        asm.ldx_dw(R1, R10, FactKind::Domain.area() + word * 8)?;
        asm.stx_dw(R7, R1, TRACE_DOMAIN + word * 8)?;
    }
    asm.bind(disabled);
    Ok(())
}

/// Test one bit of a lazily resolved category. The READY bit is set only
/// after the lookup wrote all 32 bytes of the area, so a resolved
/// all-zeros bitmap is never re-looked-up. Each use site carries its own
/// guard, so a later rule still resolves a category an earlier rule
/// skipped.
///
/// The guard tests the mask register itself with `jset`: the verifier
/// refines that bit on both edges (known one on the skip edge, known zero
/// then set by the `or` on the resolve edge), so the two paths agree on it
/// at the bit test and can merge. Copying the mask into R0 and testing the
/// copy leaves the register unrefined on the skip edge, and the join keeps
/// two states (82k against 54k for the #280 policy, Linux 6.12.107).
fn emit_fact_bit_lazy(
    asm: &mut Assembler,
    kind: FactKind,
    id: u32,
    on_true: Label,
    on_false: Label,
    fds: &RoutingMapFds,
) -> anyhow::Result<()> {
    let resolved = asm.label();
    let bit = 1i32 << (kind as u8 - 1);
    asm.jump(BPF_JSET, READY, bit, resolved)?;
    emit_fact_lookup(asm, kind, fds)?;
    asm.or_imm(READY, bit)?;
    asm.bind(resolved);
    emit_fact_bit(asm, kind, id, on_true, on_false)
}

fn emit_predicate(
    asm: &mut Assembler,
    predicate: &KernelPredicate,
    on_true: Label,
    on_false: Label,
    fds: &RoutingMapFds,
) -> anyhow::Result<()> {
    match predicate {
        KernelPredicate::Domain(id) => {
            emit_fact_bit(asm, FactKind::Domain, *id, on_true, on_false)?;
        }
        KernelPredicate::DestinationIp(id) => {
            emit_fact_bit_lazy(asm, FactKind::Destination, *id, on_true, on_false, fds)?;
        }
        KernelPredicate::SourceIp(id) => {
            emit_fact_bit_lazy(asm, FactKind::Source, *id, on_true, on_false, fds)?;
        }
        KernelPredicate::Mac(id) => {
            emit_fact_bit_lazy(asm, FactKind::Mac, *id, on_true, on_false, fds)?;
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
            for value in values {
                asm.jump(BPF_JEQ, R0, *value as i32, on_true)?;
            }
            asm.ja(on_false)?;
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
    asm.and_imm(R0, mask)?;
    asm.jump(BPF_JNE, R0, 0, on_true)?;
    asm.ja(on_false)?;
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

/// Test one bit of a resolved category. The area holds the bitmap or zeros,
/// so a missing entry fails every bit test without a pointer check.
fn emit_fact_bit(
    asm: &mut Assembler,
    kind: FactKind,
    id: u32,
    on_true: Label,
    on_false: Label,
) -> anyhow::Result<()> {
    asm.ldx_w(R2, R10, kind.area() + (id / 32 * 4) as i16)?;
    asm.and_imm(R2, (1u32 << (id % 32)) as i32)?;
    asm.jump(BPF_JNE, R2, 0, on_true)?;
    asm.ja(on_false)?;
    Ok(())
}

/// Look the category up and copy its bitmap into the stack area; zero the
/// area when the input has no such fact or the map has no entry. R0 to R5
/// are clobbered; no pointer into the map value survives.
///
/// Branch layout matters to the verifier: at an unresolved conditional it
/// explores the fall-through first, so a copy from a map value (unknown
/// scalars) sits on the fall-through at every split and the zero fill on
/// the jump target. A recorded imprecise scalar can subsume the zero-fill
/// path; a zero fill recorded first becomes precise once a bit test on it
/// is predictable, and a precise zero cannot subsume an unknown. Measured
/// on Linux 6.12 with the IPv4/IPv6 dispatch the other way round the #280
/// policy cost four times as much.
fn emit_fact_lookup(
    asm: &mut Assembler,
    kind: FactKind,
    fds: &RoutingMapFds,
) -> anyhow::Result<()> {
    let absent = asm.label();
    let lookup = asm.label();
    let done = asm.label();
    let key = match kind {
        FactKind::Domain => STACK_DOMAIN_KEY,
        _ => STACK_KEY,
    };
    match kind {
        FactKind::Domain => {
            write_domain_key_from_input(asm)?;
            load_map_fd(asm, fds.domain)?;
        }
        FactKind::Mac => {
            asm.ldx_w(R0, R6, INPUT_FLAGS)?;
            asm.and_imm(R0, ROUTING_INPUT_MAC_PRESENT as i32)?;
            asm.jump(BPF_JEQ, R0, 0, absent)?;
            write_key_from_input(asm, INPUT_MAC, 128)?;
            load_map_fd(asm, fds.mac)?;
        }
        FactKind::Destination | FactKind::Source => {
            let (v4_fd, v6_fd, input_offset) = match kind {
                FactKind::Destination => (fds.destination_v4, fds.destination_v6, INPUT_DST_IP),
                _ => (fds.source_v4, fds.source_v6, INPUT_SRC_IP),
            };
            let v6 = asm.label();
            asm.ldx_w(R0, R6, INPUT_VERSION)?;
            asm.jump(BPF_JNE, R0, 1, v6)?;
            write_key_from_input(asm, input_offset + 12, 32)?;
            load_map_fd(asm, v4_fd)?;
            asm.ja(lookup)?;
            asm.bind(v6);
            asm.jump(BPF_JNE, R0, 2, absent)?;
            write_key_from_input(asm, input_offset, 128)?;
            load_map_fd(asm, v6_fd)?;
        }
    }
    asm.bind(lookup);
    asm.mov_reg(R2, R10)?;
    asm.add_imm(R2, key as i32)?;
    asm.call(MAP_LOOKUP_ELEM)?;
    asm.jump(BPF_JEQ, R0, 0, absent)?;
    if matches!(kind, FactKind::Domain) {
        asm.st_imm(R7, DOMAIN_FINAL, 1)?;
    }
    for word in 0..FACT_BYTES / 8 {
        asm.ldx_dw(R1, R0, word * 8)?;
        asm.stx_dw(R10, R1, kind.area() + word * 8)?;
    }
    emit_trace_or(
        asm,
        TRACE_FACT_STATE,
        (1 << kind as u32) << ROUTE_FACT_PRESENT_SHIFT,
    )?;
    asm.ja(done)?;
    asm.bind(absent);
    asm.mov_imm(R1, 0)?;
    for word in 0..FACT_BYTES / 8 {
        asm.stx_dw(R10, R1, kind.area() + word * 8)?;
    }
    asm.bind(done);
    emit_trace_or(asm, TRACE_FACT_STATE, 1 << kind as u32)?;
    if matches!(kind, FactKind::Domain) {
        emit_trace_domain(asm)?;
    }
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
    asm.ldx_dw(R3, R6, INPUT_DST_IP)?;
    asm.stx_dw(R10, R3, STACK_DOMAIN_KEY)?;
    asm.ldx_dw(R3, R6, INPUT_DST_IP + 8)?;
    asm.stx_dw(R10, R3, STACK_DOMAIN_KEY + 8)?;
    Ok(())
}

fn load_map_fd(asm: &mut Assembler, fd: i32) -> anyhow::Result<()> {
    asm.emit(BPF_LD | BPF_DW | BPF_IMM, R1, PSEUDO_MAP_FD, 0, fd)?;
    asm.emit(0, 0, 0, 0, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests;
