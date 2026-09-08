//! Synchronous compiled routing facade for the eBPF data plane.
//!
//! The static TC programs own packet parsing and policy enforcement.  They
//! hand a fixed POD input to exactly one generation-selected extension slot;
//! there is deliberately no interpreter or fallback evaluator here.

#[cfg(feature = "routing-test")]
use aya_ebpf::bindings::__sk_buff;

use aya_ebpf_cty::c_long;
#[cfg(feature = "routing-test")]
use honk_ebpf_common::RoutingTestResult;
use honk_ebpf_common::{
    L4ProtoType, ROUTING_FEATURE_PROCESS, ROUTING_PROCESS_MAX_LEN, RoutingDecision, RoutingInput,
};

use crate::{
    errno::{EFAULT, EINVAL, ENOEXEC},
    maps::ROUTING_POLICY_ROOT,
};

pub const OUTBOUND_DIRECT: u8 = 0x0;
pub const OUTBOUND_BLOCK: u8 = 0x1;
pub const OUTBOUND_CONTROL_PLANE_ROUTING: u8 = 0xFD;

/// Both extension targets share the documented two-pointer POD ABI. Generated
/// code uses only the normalized input and writes the complete decision.
///
/// # Safety
/// Non-null input must be readable and output writable for their ABI types.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn honk_route_slot0(
    _input: *const RoutingInput,
    _decision: *mut RoutingDecision,
) -> i32 {
    if _input.is_null() || _decision.is_null() {
        return -EFAULT;
    }
    // Keep the full input and output ABI live under LLVM's interprocedural optimization.
    unsafe {
        for word in 0..32 {
            let _ = core::ptr::read_volatile(_input.cast::<u32>().add(word));
        }
        core::ptr::write_volatile(_decision, RoutingDecision::default());
        core::ptr::read_volatile(core::ptr::addr_of!(ROUTING_SLOT0_ERROR))
    }
}

/// # Safety
/// Non-null input must be readable and output writable for their ABI types.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn honk_route_slot1(
    _input: *const RoutingInput,
    _decision: *mut RoutingDecision,
) -> i32 {
    if _input.is_null() || _decision.is_null() {
        return -EFAULT;
    }
    unsafe {
        for word in 0..32 {
            let _ = core::ptr::read_volatile(_input.cast::<u32>().add(word));
        }
        core::ptr::write_volatile(_decision, RoutingDecision::default());
        core::ptr::read_volatile(core::ptr::addr_of!(ROUTING_SLOT1_ERROR))
    }
}

#[unsafe(no_mangle)]
pub static mut ROUTING_SLOT0_ERROR: i32 = -ENOEXEC;
#[unsafe(no_mangle)]
pub static mut ROUTING_SLOT1_ERROR: i32 = -(ENOEXEC + 1);

/// # Safety
/// Non-null pointers must address valid, non-overlapping state and byte arrays.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn honk_normalize_process_step(
    state: *mut honk_ebpf_common::routing_policy::ProcessNameNormalizer,
    input: *const [u8; 16],
    output: *mut [u8; ROUTING_PROCESS_MAX_LEN],
) -> i32 {
    if state.is_null() || input.is_null() || output.is_null() {
        return 1;
    }
    let advance = unsafe { (*state).advance(&*input, &mut *output) };
    i32::from(!advance)
}

// Verify Unicode decoding independently rather than multiplying WAN parser states.
/// # Safety
/// Non-null input and output must address valid, non-overlapping byte arrays.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn honk_normalize_process_name(
    input: *const [u8; 16],
    output: *mut [u8; ROUTING_PROCESS_MAX_LEN],
) -> u32 {
    if input.is_null() || output.is_null() {
        return 0;
    }
    unsafe { (*output).fill(0) };
    let mut state = Default::default();
    for _ in 0..16 {
        if unsafe { honk_normalize_process_step(&mut state, input, output) } != 0 {
            break;
        }
    }
    state.normalized_len() as u32
}

/// Evaluate one input against the committed descriptor and slot. Production
/// supplies raw fixed-width pname metadata; the optional differential target
/// supplies an already-canonical input and reaches this same root/slot path.
#[inline(always)]
fn evaluate_policy(
    input: &mut RoutingInput,
    pname: Option<&[u8; 16]>,
    input_is_canonical: bool,
    decision: &mut RoutingDecision,
) -> i32 {
    let zero = 0u32;
    let Some(descriptor) = ROUTING_POLICY_ROOT.get_value(0, &zero) else {
        return -EFAULT;
    };

    if !input_is_canonical {
        // Process facts are meaningful only for WAN packets and only in
        // policies that contain process predicates. Canonicalization is gated
        // here so ordinary production routes pay no UTF-8 scan cost.
        if input.is_wan != 0
            && descriptor.features & ROUTING_FEATURE_PROCESS != 0
            && let Some(pname) = pname
        {
            input.pname_len = unsafe { honk_normalize_process_name(pname, &mut input.pname) };
        } else {
            input.pname = [0; ROUTING_PROCESS_MAX_LEN];
            input.pname_len = 0;
        }
    }

    let status = match descriptor.slot {
        0 => unsafe { honk_route_slot0(input, decision) },
        1 => unsafe { honk_route_slot1(input, decision) },
        _ => -EINVAL,
    };
    // The replacement, not the visible stub body, determines these bytes.
    *decision = unsafe {
        RoutingDecision {
            outbound: core::ptr::read_volatile(core::ptr::addr_of!(decision.outbound)),
            mark: core::ptr::read_volatile(core::ptr::addr_of!(decision.mark)),
            must: core::ptr::read_volatile(core::ptr::addr_of!(decision.must)),
            domain_final: core::ptr::read_volatile(core::ptr::addr_of!(decision.domain_final)),
            rule_id: core::ptr::read_volatile(core::ptr::addr_of!(decision.rule_id)),
        }
    };
    if status == 0
        && input.dst_port == 53
        && (input.l4proto == L4ProtoType::Tcp as u32 || input.l4proto == L4ProtoType::Udp as u32)
        && decision.must == 0
    {
        // DNS ownership is a static datapath concern: every successful
        // non-must TCP/UDP policy result is handed to userspace with its mark
        // intact. LAN takes its earlier DNS fast path; WAN relies on this.
        decision.outbound = OUTBOUND_CONTROL_PLANE_ROUTING as u32;
    }
    status
}

/// Invoke the committed policy for a production routing miss.
#[inline(always)]
pub fn route(
    input: &mut RoutingInput,
    pname: Option<&[u8; 16]>,
) -> Result<RoutingDecision, c_long> {
    let mut decision = RoutingDecision::default();
    let status = evaluate_policy(input, pname, false, &mut decision);
    if status == 0 {
        Ok(decision)
    } else if status < 0 {
        Err(status as c_long)
    } else {
        Err(-(EINVAL as c_long))
    }
}

/// Test-run-only classifier for real generated-policy differential checks.
#[cfg(feature = "routing-test")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn routing_test(_ctx: *mut __sk_buff) -> c_long {
    let mut decision = RoutingDecision::default();
    let status = match crate::maps::ROUTING_TEST_INPUT.get(0) {
        Some(input) => {
            let mut input = *input;
            evaluate_policy(&mut input, None, true, &mut decision)
        }
        None => -EFAULT,
    };
    let result = RoutingTestResult { status, decision };
    if crate::maps::ROUTING_TEST_OUTPUT.set(0, result, 0).is_ok() {
        crate::action::TC_ACT_OK
    } else {
        crate::action::TC_ACT_SHOT
    }
}

/// Build the fixed input used by both LAN and WAN routing paths.
///
/// Addresses are copied as wire bytes. Ports are host-order integers. The
/// six-byte MAC occupies the final six bytes of the canonical 16-byte key;
/// `mac_present` distinguishes a real L2 fact from an absent L3 header.
#[inline(always)]
pub fn build_input(
    input: &mut RoutingInput,
    tuples: &honk_ebpf_common::redirect_need::Tuples,
    mac: Option<&[u8; 6]>,
    l4proto: u8,
    ip_version: u8,
    is_wan: bool,
) {
    *input = RoutingInput::default();
    input.src_ip = *tuples.five.src_ip.as_bytes();
    input.dst_ip = *tuples.five.dst_ip.as_bytes();
    input.src_port = tuples.five.src_port as u32;
    input.dst_port = tuples.five.dst_port as u32;
    input.l4proto = l4proto as u32;
    input.ip_version = ip_version as u32;
    input.dscp = tuples.dscp as u32;
    input.is_wan = is_wan as u32;
    if let Some(mac) = mac {
        input.mac[10..].copy_from_slice(mac);
        input.mac_present = 1;
    }
}
