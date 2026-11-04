//! Kernels before 6.6 round every BPF-to-BPF frame to 32 bytes (later JITs
//! use 16) and reject any call chain whose total exceeds 512 bytes. This
//! checks the shipped object against the stricter rounding without a kernel.

use std::collections::{BTreeSet, HashMap, HashSet};

const MAX_BPF_STACK: u32 = 512;
const PRE_6_6_ROUNDING: u32 = 32;
const CALL: u8 = 0x85;
const PSEUDO_CALL: u8 = 1;
const REG_FP: u8 = 10;
const CLASS_MASK: u8 = 0x07;
const CLASS_LDX: u8 = 0x01;
const CLASS_ST: u8 = 0x02;
const CLASS_STX: u8 = 0x03;
const ALU64_ADD_K: u8 = 0x07;
const ALU64_MOV_X: u8 = 0xbf;

/// Deepest stack byte each subprogram touches, from frame-pointer loads,
/// stores and `rX = r10; rX += -n` address arithmetic.
fn frame_depth(insns: &[aya_obj::generated::bpf_insn]) -> u32 {
    let mut depth = 0u32;
    let mut fp_copies: HashSet<u8> = HashSet::new();
    for insn in insns {
        let (dst, src, class) = (insn.dst_reg(), insn.src_reg(), insn.code & CLASS_MASK);
        let frame_offset = match class {
            CLASS_LDX if src == REG_FP => Some(i32::from(insn.off)),
            CLASS_ST | CLASS_STX if dst == REG_FP => Some(i32::from(insn.off)),
            _ if insn.code == ALU64_ADD_K && fp_copies.contains(&dst) => Some(insn.imm),
            _ => None,
        };
        if let Some(offset) = frame_offset.filter(|offset| *offset < 0) {
            depth = depth.max(offset.unsigned_abs());
        }
        if insn.code == ALU64_MOV_X && src == REG_FP {
            fp_copies.insert(dst);
        } else if class != CLASS_ST && class != CLASS_STX && insn.code != CALL {
            fp_copies.remove(&dst);
        }
    }
    depth
}

fn deepest(
    subprog: usize,
    frames: &[u32],
    calls: &[BTreeSet<usize>],
    memo: &mut HashMap<usize, u32>,
) -> u32 {
    if let Some(depth) = memo.get(&subprog) {
        return *depth;
    }
    let own = frames[subprog].max(1).div_ceil(PRE_6_6_ROUNDING) * PRE_6_6_ROUNDING;
    let callees = calls[subprog]
        .iter()
        .map(|callee| deepest(*callee, frames, calls, memo))
        .max()
        .unwrap_or(0);
    memo.insert(subprog, own + callees);
    own + callees
}

#[test]
fn every_program_fits_the_pre_6_6_stack_rounding() {
    let mut object = aya_obj::Object::parse(crate::DEFAULT_BPF_OBJECT).expect("parse object");
    let text_sections = object
        .functions
        .keys()
        .map(|(section, _)| *section)
        .collect();
    object
        .relocate_calls(&text_sections)
        .expect("link subprograms");
    let mut checked = 0;
    for (name, program) in &object.programs {
        let function = &object.functions[&program.function_key()];
        let insns = &function.instructions;
        let mut starts: Vec<usize> = function
            .func_info
            .func_info
            .iter()
            .map(|info| info.insn_off as usize)
            .collect();
        starts.sort_unstable();
        starts.dedup();
        assert_eq!(starts.first(), Some(&0), "{name}: no entry subprogram");
        let subprog_of = |pc: usize| starts.partition_point(|start| *start <= pc) - 1;
        let ranges: Vec<(usize, usize)> = starts
            .iter()
            .enumerate()
            .map(|(index, start)| {
                (
                    *start,
                    starts.get(index + 1).copied().unwrap_or(insns.len()),
                )
            })
            .collect();
        let frames: Vec<u32> = ranges
            .iter()
            .map(|(start, end)| frame_depth(&insns[*start..*end]))
            .collect();
        let mut calls = vec![BTreeSet::new(); starts.len()];
        for (pc, insn) in insns.iter().enumerate() {
            if insn.code == CALL && insn.src_reg() == PSEUDO_CALL {
                let target = (pc as i64 + i64::from(insn.imm) + 1) as usize;
                calls[subprog_of(pc)].insert(subprog_of(target));
            }
        }
        let depth = deepest(0, &frames, &calls, &mut HashMap::new());
        assert!(
            depth <= MAX_BPF_STACK,
            "{name}: deepest call chain needs {depth} bytes with 32-byte frames (frames {frames:?})"
        );
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} programs were checked");
}
