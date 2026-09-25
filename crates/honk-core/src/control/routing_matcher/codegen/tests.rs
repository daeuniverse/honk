use super::*;
use crate::routing::Router;
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_config::types::DialMode;
use serde_json::json;

fn fields(insn: &bpf_insn) -> (u32, u8, u8, i16, i32) {
    (
        insn.code as u32,
        insn.dst_reg(),
        insn.src_reg(),
        insn.off,
        insn.imm,
    )
}

fn jump_target(insns: &[bpf_insn], index: usize) -> usize {
    (index as isize + 1 + insns[index].off as isize) as usize
}

fn rule(condition: serde_json::Value, outbound: &str) -> RoutingRule {
    RoutingRule {
        name: String::new(),
        condition: serde_json::from_value::<RoutingCondition>(condition).unwrap(),
        outbound: RoutingOutbound::Simple(outbound.into()),
        priority: 0,
        must: false,
        mark: 0,
    }
}

fn emit(rules: &[RoutingRule]) -> RoutingBytecode {
    let router = Router::new(rules, "direct").unwrap();
    let ids = std::collections::HashMap::from([("direct".to_string(), 0u8), ("proxy".into(), 1)]);
    let plan = RoutingPushPlan::compile(&router, &ids, DialMode::Ip).unwrap();
    let fds = RoutingMapFds {
        destination_v4: 11,
        destination_v6: 12,
        source_v4: 13,
        source_v6: 14,
        mac: 15,
        domain: 16,
    };
    emit_routing_program(&plan, fds).unwrap()
}

fn lookups(bytecode: &RoutingBytecode) -> Vec<usize> {
    bytecode
        .insns
        .iter()
        .enumerate()
        .filter(|(_, insn)| {
            insn.code as u32 == BPF_JMP | BPF_CALL
                && insn.src_reg() == 0
                && insn.imm == MAP_LOOKUP_ELEM
        })
        .map(|(index, _)| index)
        .collect()
}

/// First instruction of the rule with this id (source lines carry id + 1).
fn rule_start(bytecode: &RoutingBytecode, id: u32) -> usize {
    bytecode
        .lines
        .iter()
        .find(|line| line.line == id + 1)
        .map(|line| line.insn_offset as usize)
        .expect("rule source line")
}

#[test]
fn domain_lookup_stays_in_the_prologue_before_ports() {
    let bytecode = emit(&[rule(
        json!({"port": ["443"], "domain_suffix": ["example.com"]}),
        "proxy",
    )]);
    let calls = lookups(&bytecode);
    assert_eq!(calls.len(), 1);
    assert!(
        bytecode.insns[..calls[0]]
            .iter()
            .any(|insn| fields(insn) == (BPF_LDX | BPF_W | BPF_MEM, READY, R7, MARK, 0))
    );
    let start = rule_start(&bytecode, 0);
    assert!(calls[0] < start);
    assert_eq!(
        fields(&bytecode.insns[start]),
        (BPF_LDX | BPF_W | BPF_MEM, R0, R6, INPUT_DST_PORT, 0)
    );
}

// The readiness mask and the unresolved areas are loaded back from the
// decision's mark, zeroed just before and not written in between, never
// set as constants; each area word comes from its own load.
#[test]
fn readiness_mask_and_lazy_areas_start_as_verifier_unknown_zeros() {
    let bytecode = emit(&[rule(json!({"ip": ["203.0.113.0/24"]}), "proxy")]);
    let insns = &bytecode.insns;
    let zeroed = insns
        .iter()
        .position(|insn| fields(insn) == (BPF_ST | BPF_W | BPF_MEM, R7, 0, MARK, 0))
        .unwrap();
    let mask = zeroed + 4;
    assert!(insns[zeroed + 1..mask].iter().all(|insn| {
        insn.code as u32 == BPF_ST | BPF_W | BPF_MEM && insn.dst_reg() == R7 && insn.off != MARK
    }));
    assert_eq!(
        fields(&insns[mask]),
        (BPF_LDX | BPF_W | BPF_MEM, READY, R7, MARK, 0)
    );
    let mut index = mask + 1;
    for area in [-64, -96, -128] {
        for offset in [0, 8, 16, 24] {
            assert_eq!(
                fields(&insns[index]),
                (BPF_LDX | BPF_W | BPF_MEM, R1, R7, MARK, 0)
            );
            assert_eq!(
                fields(&insns[index + 1]),
                (BPF_STX | BPF_DW | BPF_MEM, R10, R1, area + offset, 0)
            );
            index += 2;
        }
    }
    assert_eq!(index, rule_start(&bytecode, 0));
    assert!(!insns.iter().any(|insn| {
        insn.code as u32 == BPF_ALU64 | BPF_MOV | BPF_K && insn.dst_reg() == READY
    }));
}

#[test]
fn lazy_fact_guard_publishes_its_bit_after_copy_and_zero_paths() {
    let fds = RoutingMapFds {
        destination_v4: 11,
        destination_v6: 12,
        source_v4: 13,
        source_v6: 14,
        mac: 15,
        domain: 16,
    };
    for (kind, bit, area) in [
        (FactKind::Destination, 1, -64),
        (FactKind::Source, 2, -96),
        (FactKind::Mac, 4, -128),
    ] {
        let mut asm = Assembler::new();
        let pass = asm.label();
        let fail = asm.label();
        emit_fact_bit_lazy(&mut asm, kind, 255, pass, fail, &fds).unwrap();
        asm.bind(pass);
        asm.mov_imm(R0, 0).unwrap();
        asm.exit().unwrap();
        asm.bind(fail);
        asm.mov_imm(R0, 1).unwrap();
        asm.exit().unwrap();
        let bytecode = asm.finish().unwrap();
        let insns = &bytecode.insns;
        // The guard tests the mask register itself; the resolution follows
        // on the fall-through and publishes the bit before the bit test.
        let resolved = jump_target(insns, 0);
        assert_eq!(
            fields(&insns[0]),
            (
                BPF_JMP | BPF_JSET | BPF_K,
                READY,
                0,
                (resolved - 1) as i16,
                bit
            )
        );
        let calls = lookups(&bytecode);
        assert_eq!(calls.len(), 1);
        let copy = calls[0] + 2;
        let absent = jump_target(insns, calls[0] + 1);
        let publish = absent + 5;
        assert_eq!(jump_target(insns, copy + 8), publish);
        assert_eq!(
            fields(&insns[publish]),
            (BPF_ALU64 | BPF_OR | BPF_K, READY, 0, 0, bit)
        );
        assert_eq!(publish + 1, resolved);
        assert_eq!(
            fields(&insns[resolved]),
            (BPF_LDX | BPF_W | BPF_MEM, R2, R10, area + 28, 0)
        );
        assert_eq!(insns[resolved + 3].code as u32, BPF_JMP | BPF_JA);
        assert_eq!(jump_target(insns, resolved + 2), resolved + 4);
        assert_eq!(jump_target(insns, resolved + 3), resolved + 6);
    }
}

// The verifier explores fall-through first, so it must copy unknown map scalars
// before visiting the absent path's zeros.
#[test]
fn fact_lookup_copies_or_zeros_its_stack_area_before_rejoining() {
    let fds = RoutingMapFds {
        destination_v4: 11,
        destination_v6: 12,
        source_v4: 13,
        source_v6: 14,
        mac: 15,
        domain: 16,
    };
    for (kind, area) in [
        (FactKind::Domain, -32),
        (FactKind::Destination, -64),
        (FactKind::Source, -96),
        (FactKind::Mac, -128),
    ] {
        let mut asm = Assembler::new();
        emit_fact_lookup(&mut asm, kind, &fds).unwrap();
        let bytecode = asm.finish().unwrap();
        let insns = &bytecode.insns;
        let calls = lookups(&bytecode);
        assert_eq!(calls.len(), 1);
        let call = calls[0];
        let mut copy = call + 2;
        if matches!(kind, FactKind::Domain) {
            assert_eq!(
                fields(&insns[copy]),
                (BPF_ST | BPF_W | BPF_MEM, R7, 0, DOMAIN_FINAL, 1)
            );
            copy += 1;
        }
        let absent = copy + 9;
        assert_eq!(
            fields(&insns[call + 1]),
            (
                BPF_JMP | BPF_JEQ | BPF_K,
                R0,
                0,
                (absent - call - 2) as i16,
                0
            )
        );
        for (word, offset) in [0, 8, 16, 24].into_iter().enumerate() {
            assert_eq!(
                fields(&insns[copy + word * 2]),
                (BPF_LDX | BPF_DW | BPF_MEM, R1, R0, offset, 0)
            );
            assert_eq!(
                fields(&insns[copy + word * 2 + 1]),
                (BPF_STX | BPF_DW | BPF_MEM, R10, R1, area + offset, 0)
            );
            assert_eq!(
                fields(&insns[absent + 1 + word]),
                (BPF_STX | BPF_DW | BPF_MEM, R10, R1, area + offset, 0)
            );
        }
        assert_eq!(
            fields(&insns[absent]),
            (BPF_ALU64 | BPF_MOV | BPF_K, R1, 0, 0, 0)
        );
        assert_eq!(fields(&insns[copy + 8]), (BPF_JMP | BPF_JA, 0, 0, 5, 0));
        assert_eq!(insns.len(), absent + 5);
    }
}

#[test]
fn complete_positive_and_negative_ports_precede_ip_facts() {
    let bytecode = emit(&[
        rule(
            json!({
                "ip": ["203.0.113.0/24"], "source_ip": ["198.51.100.0/24"],
                "port": ["80", "443-445"], "source_port": ["1024-2048", "4096"],
                "not": {"port": ["81", "444"], "source_port": ["1500-1600", "2000"]}
            }),
            "proxy",
        ),
        rule(json!({"ip": ["192.0.2.0/24"]}), "direct"),
    ]);
    let insns = &bytecode.insns;
    let fail = rule_start(&bytecode, 1);
    let mut start = rule_start(&bytecode, 0);
    let ports = [
        (INPUT_DST_PORT, &[(80, 80), (443, 445)], false),
        (INPUT_SRC_PORT, &[(1024, 2048), (4096, 4096)], false),
        (INPUT_DST_PORT, &[(81, 81), (444, 444)], true),
        (INPUT_SRC_PORT, &[(1500, 1600), (2000, 2000)], true),
    ];
    for (offset, ranges, negated) in ports {
        assert_eq!(
            fields(&insns[start]),
            (BPF_LDX | BPF_W | BPF_MEM, R0, R6, offset, 0)
        );
        let next = start + 2 + 4 * ranges.len();
        for (index, &(low, high)) in ranges.iter().enumerate() {
            let range = start + 1 + 4 * index;
            assert_eq!(
                fields(&insns[range]),
                (BPF_JMP | BPF_JGE | BPF_K, R0, 0, 1, low)
            );
            assert_eq!(fields(&insns[range + 1]), (BPF_JMP | BPF_JA, 0, 0, 2, 0));
            assert_eq!(
                fields(&insns[range + 2]),
                (BPF_JMP | BPF_JGT | BPF_K, R0, 0, 1, high)
            );
            assert_eq!(insns[range + 3].code as u32, BPF_JMP | BPF_JA);
            assert_eq!(
                jump_target(insns, range + 3),
                if negated { fail } else { next }
            );
        }
        assert_eq!(insns[next - 1].code as u32, BPF_JMP | BPF_JA);
        assert_eq!(
            jump_target(insns, next - 1),
            if negated { next } else { fail }
        );
        start = next;
    }
    let (code, dst, _, _, imm) = fields(&insns[start]);
    assert_eq!((code, dst, imm), (BPF_JMP | BPF_JSET | BPF_K, READY, 1));
    assert!(lookups(&bytecode)[0] > start);
}

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
