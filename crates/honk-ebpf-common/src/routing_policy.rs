//! Stable ABI between the static TC callers and generated routing functions.

pub const ROUTING_POLICY_ROOT_NAME: &str = "ROUTING_POLICY_ROOT";
pub const ROUTING_SLOT_NAMES: [&str; 2] = ["honk_route_slot0", "honk_route_slot1"];
pub const ROUTING_FEATURE_DOMAIN: u32 = 1;
pub const ROUTING_FEATURE_DOMAIN_REROUTE: u32 = 1 << 1;
pub const ROUTING_FEATURE_PROCESS: u32 = 1 << 2;
pub const ROUTING_PROCESS_MAX_LEN: usize = 48;
pub const ROUTING_FACT_CAPACITY: usize = 256;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoutingInput {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub mac: [u8; 16],
    pub pname: [u8; ROUTING_PROCESS_MAX_LEN],
    pub src_port: u32,
    pub dst_port: u32,
    pub l4proto: u32,
    pub ip_version: u32,
    pub dscp: u32,
    pub is_wan: u32,
    pub pname_len: u32,
    pub mac_present: u32,
}

impl Default for RoutingInput {
    fn default() -> Self {
        // All fields admit every bit pattern; zero also initializes ABI padding.
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoutingDecision {
    pub outbound: u32,
    pub mark: u32,
    pub must: u32,
    pub domain_final: u32,
    pub rule_id: u32,
}

impl Default for RoutingDecision {
    fn default() -> Self {
        Self {
            outbound: crate::OutboundIndex::Block as u32,
            mark: 0,
            must: 0,
            domain_final: 0,
            rule_id: u32::MAX,
        }
    }
}

impl RoutingDecision {
    /// Preserve an unresolved direct decision as a userspace routing request.
    #[inline(always)]
    pub fn handoff_outbound(&self) -> u8 {
        if self.outbound == crate::OutboundIndex::Direct as u32
            && self.must == 0
            && self.domain_final == 0
        {
            crate::OutboundIndex::ControlPlaneRouting as u8
        } else {
            self.outbound as u8
        }
    }
}

#[cfg(test)]
#[test]
fn unresolved_direct_handoff_keeps_sniffing_authority() {
    use crate::OutboundIndex::{Block, ControlPlaneRouting, Direct, UserBase};
    for (outbound, must, domain_final, expected) in [
        (Direct, 0, 0, ControlPlaneRouting),
        (Direct, 0, 1, Direct),
        (Direct, 1, 0, Direct),
        (Block, 0, 0, Block),
        (UserBase, 0, 0, UserBase),
    ] {
        let decision = RoutingDecision {
            outbound: outbound as u32,
            must,
            domain_final,
            ..Default::default()
        };
        assert_eq!(decision.handoff_outbound(), expected as u8);
    }
}

/// Result written by the optional real-kernel routing differential fixture.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoutingTestResult {
    pub status: i32,
    pub decision: RoutingDecision,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoutingPolicyDescriptor {
    pub slot: u32,
    pub features: u32,
    pub generation: u64,
    pub domain_map_id: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<RoutingInput>() == 128);
const _: () = assert!(core::mem::size_of::<RoutingDecision>() == 20);
const _: () = assert!(core::mem::size_of::<RoutingPolicyDescriptor>() == 24);
const _: () = assert!(core::mem::size_of::<RoutingTestResult>() == 24);
const _: () = assert!(core::mem::align_of::<RoutingTestResult>() == 4);
const _: () = assert!(core::mem::offset_of!(RoutingTestResult, status) == 0);
const _: () = assert!(core::mem::offset_of!(RoutingTestResult, decision) == 4);
const _: () = assert!(core::mem::align_of::<RoutingInput>() == 4);
const _: () = assert!(core::mem::offset_of!(RoutingInput, src_ip) == 0);
const _: () = assert!(core::mem::offset_of!(RoutingInput, dst_ip) == 16);
const _: () = assert!(core::mem::offset_of!(RoutingInput, mac) == 32);
const _: () = assert!(core::mem::offset_of!(RoutingInput, pname) == 48);
const _: () = assert!(core::mem::offset_of!(RoutingInput, src_port) == 96);
const _: () = assert!(core::mem::offset_of!(RoutingInput, dst_port) == 100);
const _: () = assert!(core::mem::offset_of!(RoutingInput, l4proto) == 104);
const _: () = assert!(core::mem::offset_of!(RoutingInput, ip_version) == 108);
const _: () = assert!(core::mem::offset_of!(RoutingInput, dscp) == 112);
const _: () = assert!(core::mem::offset_of!(RoutingInput, is_wan) == 116);
const _: () = assert!(core::mem::offset_of!(RoutingInput, pname_len) == 120);
const _: () = assert!(core::mem::offset_of!(RoutingInput, mac_present) == 124);
const _: () = assert!(core::mem::align_of::<RoutingDecision>() == 4);
const _: () = assert!(core::mem::offset_of!(RoutingDecision, outbound) == 0);
const _: () = assert!(core::mem::offset_of!(RoutingDecision, mark) == 4);
const _: () = assert!(core::mem::offset_of!(RoutingDecision, must) == 8);
const _: () = assert!(core::mem::offset_of!(RoutingDecision, domain_final) == 12);
const _: () = assert!(core::mem::offset_of!(RoutingDecision, rule_id) == 16);
const _: () = assert!(core::mem::align_of::<RoutingPolicyDescriptor>() == 8);
const _: () = assert!(core::mem::offset_of!(RoutingPolicyDescriptor, slot) == 0);
const _: () = assert!(core::mem::offset_of!(RoutingPolicyDescriptor, features) == 4);
const _: () = assert!(core::mem::offset_of!(RoutingPolicyDescriptor, generation) == 8);
const _: () = assert!(core::mem::offset_of!(RoutingPolicyDescriptor, domain_map_id) == 16);
const _: () = assert!(core::mem::offset_of!(RoutingPolicyDescriptor, reserved) == 20);

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RoutingInput {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RoutingDecision {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RoutingPolicyDescriptor {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RoutingTestResult {}

/// Canonicalize the fixed process-name handoff without allocation.
///
/// This is the bounded equivalent of the host handoff's
/// `String::from_utf8_lossy(bytes).trim()`: NUL terminates the fixed field,
/// malformed UTF-8 emits U+FFFD, and leading/trailing Unicode whitespace is
/// removed. The input scan is capped at the ABI width so callers cannot turn
/// this datapath helper into an unbounded loop.
#[inline(always)]
pub fn normalize_process_name(input: &[u8], output: &mut [u8; ROUTING_PROCESS_MAX_LEN]) -> usize {
    output.fill(0);
    let mut state = ProcessNameNormalizer::default();
    while state.advance(input, output) {}
    state.normalized_len()
}

#[derive(Default)]
pub struct ProcessNameNormalizer {
    pos: usize,
    written: usize,
    trimmed: usize,
}

impl ProcessNameNormalizer {
    #[inline(always)]
    pub fn normalized_len(&self) -> usize {
        self.trimmed.min(ROUTING_PROCESS_MAX_LEN)
    }

    /// Decode one code point so BPF can bound iteration without enumerating every string.
    #[inline(always)]
    pub fn advance(&mut self, input: &[u8], output: &mut [u8; ROUTING_PROCESS_MAX_LEN]) -> bool {
        let limit = input.len().min(crate::TASK_COMM_LEN);
        let pos = self.pos;
        let written = self.written;
        if pos >= limit || written > output.len() || unsafe { *input.as_ptr().add(pos) } == 0 {
            return false;
        }
        let (codepoint, consumed) = decode_lossy(input, pos, limit);
        let whitespace = is_unicode_whitespace(codepoint);
        if written != 0 || !whitespace {
            let length = if codepoint == 0xFFFD { 3 } else { consumed };
            if written + length > output.len() {
                return false;
            }
            unsafe {
                if codepoint == 0xFFFD {
                    write_name_byte(output, written, 0xEF);
                    write_name_byte(output, written + 1, 0xBF);
                    write_name_byte(output, written + 2, 0xBD);
                } else {
                    write_name_byte(output, written, read_name_byte(input, pos));
                    if consumed > 1 {
                        write_name_byte(output, written + 1, read_name_byte(input, pos + 1));
                    }
                    if consumed > 2 {
                        write_name_byte(output, written + 2, read_name_byte(input, pos + 2));
                    }
                    if consumed > 3 {
                        write_name_byte(output, written + 3, read_name_byte(input, pos + 3));
                    }
                }
            }
            self.written = written + length;
            if !whitespace {
                self.trimmed = self.written;
            }
        }
        self.pos = pos + consumed;
        true
    }
}

#[inline(always)]
fn is_unicode_whitespace(codepoint: u32) -> bool {
    // Keep the overwhelmingly common comm/argv0 path to one range test and
    // one small match. The remaining values are Unicode White_Space, exactly
    // what `str::trim` uses on the host.
    if codepoint < 0x80 {
        return matches!(codepoint, 0x09..=0x0D | 0x20);
    }
    matches!(
        codepoint,
        0x85 | 0xA0 | 0x1680 | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000
    )
}

#[inline(always)]
fn decode_lossy(input: &[u8], pos: usize, limit: usize) -> (u32, usize) {
    // The caller maintains pos < limit <= input.len().
    let first = unsafe { read_name_byte(input, pos) };
    if first < 0x80 {
        return (first as u32, 1);
    }
    let width = match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return (0xFFFD, 1),
    };
    if pos + 1 >= limit {
        return (0xFFFD, limit - pos);
    }
    let second = unsafe { read_name_byte(input, pos + 1) };
    let second_valid = match first {
        0xE0 => (0xA0..=0xBF).contains(&second),
        0xED => (0x80..=0x9F).contains(&second),
        0xF0 => (0x90..=0xBF).contains(&second),
        0xF4 => (0x80..=0x8F).contains(&second),
        _ => second & 0xC0 == 0x80,
    };
    if !second_valid {
        return (0xFFFD, 1);
    }
    let mut codepoint = (((first & (0x7F >> width)) as u32) << 6) | (second & 0x3F) as u32;
    if width == 2 {
        return (codepoint, 2);
    }
    if pos + 2 >= limit {
        return (0xFFFD, limit - pos);
    }
    let third = unsafe { read_name_byte(input, pos + 2) };
    if third & 0xC0 != 0x80 {
        return (0xFFFD, 2);
    }
    codepoint = (codepoint << 6) | (third & 0x3F) as u32;
    if width == 3 {
        return (codepoint, 3);
    }
    if pos + 3 >= limit {
        return (0xFFFD, limit - pos);
    }
    let fourth = unsafe { read_name_byte(input, pos + 3) };
    if fourth & 0xC0 != 0x80 {
        return (0xFFFD, 3);
    }
    ((codepoint << 6) | (fourth & 0x3F) as u32, 4)
}

// Retain bounded absolute offsets: BPF cannot refine an already-derived pointer.
#[inline(always)]
unsafe fn read_name_byte(input: &[u8], offset: usize) -> u8 {
    let offset = unsafe { core::ptr::read_volatile(&offset) } & (crate::TASK_COMM_LEN - 1);
    unsafe { *input.as_ptr().add(offset) }
}

#[inline(always)]
unsafe fn write_name_byte(output: &mut [u8; ROUTING_PROCESS_MAX_LEN], offset: usize, byte: u8) {
    // Linux 6.12 does not bound BPF_MOD results; check before deriving the pointer.
    let offset = unsafe { core::ptr::read_volatile(&offset) };
    if offset < ROUTING_PROCESS_MAX_LEN {
        unsafe { *output.as_mut_ptr().add(offset) = byte };
    }
}

#[cfg(test)]
mod normalization_tests {
    extern crate std;

    use super::{ROUTING_PROCESS_MAX_LEN, normalize_process_name};
    use std::vec::Vec;

    fn normalized(input: &[u8]) -> Vec<u8> {
        let mut output = [0u8; ROUTING_PROCESS_MAX_LEN];
        let len = normalize_process_name(input, &mut output);
        output[..len].to_vec()
    }

    #[test]
    fn trims_ascii_and_stops_at_nul() {
        assert_eq!(normalized(b"  curl  \0ignored"), b"curl");
    }

    #[test]
    fn trims_unicode_whitespace_without_allocating_in_helper() {
        assert_eq!(normalized("\u{2003}名\u{00a0}".as_bytes()), "名".as_bytes());
    }

    #[test]
    fn replaces_invalid_utf8_like_std_lossy() {
        assert_eq!(normalized(&[b' ', 0xFF, b' ']), "�".as_bytes());
    }

    #[test]
    fn missing_and_whitespace_only_metadata_are_empty() {
        assert!(normalized(b"").is_empty());
        assert!(normalized(" \t\u{2003}".as_bytes()).is_empty());
    }

    #[test]
    fn incomplete_sequence_is_one_replacement() {
        assert_eq!(normalized(&[0xE2, 0x82]), "�".as_bytes());
    }

    #[test]
    fn replacement_bytes_fill_the_entire_output_capacity() {
        let input = [0xff; crate::TASK_COMM_LEN];
        let expected = "�".repeat(crate::TASK_COMM_LEN);
        assert_eq!(normalized(&input), expected.as_bytes());
        assert_eq!(expected.len(), ROUTING_PROCESS_MAX_LEN);
    }

    #[test]
    fn bounded_handoff_normalization_matches_std() {
        fn check(input: &[u8]) {
            let input = &input[..input.len().min(crate::TASK_COMM_LEN)];
            let end = input
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(input.len());
            let expected = std::string::String::from_utf8_lossy(&input[..end]);
            assert_eq!(normalized(input), expected.trim().as_bytes(), "{input:x?}");
        }
        for first in 0..=255 {
            for second in 0..=255 {
                check(&[first, second]);
            }
        }
        let mut state = 1u64;
        for _ in 0..4096 {
            let mut input = [0u8; crate::TASK_COMM_LEN];
            for byte in &mut input {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (state >> 32) as u8;
            }
            check(&input);
        }
        check(&[0xf0, 0x90, 0x80, 0x80]);
        check(&[0xf4, 0x8f, 0xbf, 0xbf]);
        check(&[0xed, 0xa0, 0x80]);
    }
}
