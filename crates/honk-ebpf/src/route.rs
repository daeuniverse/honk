//! Synchronous compiled routing facade for the eBPF data plane.
//!
//! The static TC programs own packet parsing and policy enforcement.  They
//! hand a fixed POD input to exactly one generation-selected extension slot;
//! there is deliberately no interpreter or fallback evaluator here.

#[cfg(feature = "routing-test")]
use aya_ebpf::bindings::__sk_buff;

use aya_ebpf_cty::c_long;
use honk_ebpf_common::{
    DATAPATH_FLAG_OFFLOAD_RULE_DIRECT, DATAPATH_FLAG_TRACE_ENABLED, L4ProtoType,
    ROUTE_TRACE_AMBIGUOUS, ROUTE_TRACE_DNS_OVERRIDE, ROUTE_TRACE_ENABLED, ROUTE_TRACE_LOST,
    ROUTE_TRACE_VERSION, ROUTING_FEATURE_PROCESS, ROUTING_INPUT_ALLOW_DIRECT_FINALITY,
    ROUTING_INPUT_MAC_PRESENT, ROUTING_PROCESS_MAX_LEN, RoutingDecision, RoutingInput,
};
use honk_ebpf_common::{KernelRouteOutput, KernelRouteWitness};

use crate::{
    errno::{EFAULT, EINVAL, ENOEXEC},
    maps::ROUTING_POLICY_ROOT,
};

pub const OUTBOUND_DIRECT: u8 = 0x0;
pub const OUTBOUND_BLOCK: u8 = 0x1;
pub const OUTBOUND_CONTROL_PLANE_ROUTING: u8 = 0xFD;

/// 32-bit words of the decision prefix and of the whole map-backed output.
const DECISION_WORDS: usize = core::mem::size_of::<RoutingDecision>() / 4;
const OUTPUT_WORDS: usize = core::mem::size_of::<KernelRouteOutput>() / 4;

/// Both extension targets share the documented two-pointer POD ABI. Generated
/// code uses only the normalized input and writes the complete decision.
///
/// # Safety
/// Non-null input must be readable and output writable for their ABI types.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn honk_route_slot0(
    _input: *const RoutingInput,
    _decision: *mut KernelRouteOutput,
) -> i32 {
    if _input.is_null() || _decision.is_null() {
        return -EFAULT;
    }
    // Keep the full input and output ABI live under LLVM's interprocedural optimization.
    unsafe {
        for word in 0..32 {
            let _ = core::ptr::read_volatile(_input.cast::<u32>().add(word));
        }
        for word in 0..DECISION_WORDS {
            let pointer = _decision.cast::<u32>().add(word);
            core::ptr::write_volatile(pointer, core::ptr::read_volatile(pointer));
        }
        if core::ptr::read_volatile(core::ptr::addr_of!((*_decision).flags)) & 1 != 0 {
            for word in DECISION_WORDS..OUTPUT_WORDS {
                let pointer = _decision.cast::<u32>().add(word);
                core::ptr::write_volatile(pointer, core::ptr::read_volatile(pointer));
            }
        }
        core::ptr::read_volatile(core::ptr::addr_of!(ROUTING_SLOT0_ERROR))
    }
}

/// # Safety
/// Non-null input must be readable and output writable for their ABI types.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn honk_route_slot1(
    _input: *const RoutingInput,
    _decision: *mut KernelRouteOutput,
) -> i32 {
    if _input.is_null() || _decision.is_null() {
        return -EFAULT;
    }
    unsafe {
        for word in 0..32 {
            let _ = core::ptr::read_volatile(_input.cast::<u32>().add(word));
        }
        for word in 0..DECISION_WORDS {
            let pointer = _decision.cast::<u32>().add(word);
            core::ptr::write_volatile(pointer, core::ptr::read_volatile(pointer));
        }
        if core::ptr::read_volatile(core::ptr::addr_of!((*_decision).flags)) & 1 != 0 {
            for word in DECISION_WORDS..OUTPUT_WORDS {
                let pointer = _decision.cast::<u32>().add(word);
                core::ptr::write_volatile(pointer, core::ptr::read_volatile(pointer));
            }
        }
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
    flags: u32,
    output: &mut KernelRouteOutput,
) -> (i32, RoutingDecision, u64) {
    let zero = 0u32;
    output.flags = 0;
    let Some(descriptor) = ROUTING_POLICY_ROOT.get_value(0, &zero) else {
        return (-EFAULT, RoutingDecision::default(), 0);
    };
    let generation = descriptor.generation;
    let policy_id = descriptor.trace_policy;
    let trace_enabled = policy_id != 0 && flags & DATAPATH_FLAG_TRACE_ENABLED != 0;
    if !input_is_canonical {
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
    if trace_enabled {
        output.flags = ROUTE_TRACE_VERSION | ROUTE_TRACE_ENABLED;
    }
    input.flags = (input.flags & ROUTING_INPUT_MAC_PRESENT)
        | if flags & DATAPATH_FLAG_OFFLOAD_RULE_DIRECT != 0 {
            ROUTING_INPUT_ALLOW_DIRECT_FINALITY
        } else {
            0
        };
    let status = match descriptor.slot {
        0 => unsafe { honk_route_slot0(input, output) },
        1 => unsafe { honk_route_slot1(input, output) },
        _ => -EINVAL,
    };
    // freplace writes are opaque to LLVM; retain the replacement's whole output.
    unsafe {
        for word in 0..DECISION_WORDS {
            let pointer = core::ptr::from_mut(output).cast::<u32>().add(word);
            core::ptr::write_volatile(pointer, core::ptr::read_volatile(pointer));
        }
        if trace_enabled {
            for word in DECISION_WORDS..OUTPUT_WORDS {
                let pointer = core::ptr::from_mut(output).cast::<u32>().add(word);
                core::ptr::write_volatile(pointer, core::ptr::read_volatile(pointer));
            }
        }
    }
    if trace_enabled {
        output.generation = generation;
        output.policy_id = policy_id;
    }
    let mut decision = output.decision;
    if status == 0
        && input.dst_port == 53
        && (input.l4proto == L4ProtoType::Tcp as u32 || input.l4proto == L4ProtoType::Udp as u32)
        && decision.must == 0
    {
        decision.outbound = OUTBOUND_CONTROL_PLANE_ROUTING as u32;
        if trace_enabled {
            output.flags |= ROUTE_TRACE_DNS_OVERRIDE;
        }
    }
    (status, decision, generation)
}

/// Invoke the committed policy and return its decision and descriptor generation.
#[inline(always)]
pub fn route(
    input: &mut RoutingInput,
    pname: Option<&[u8; 16]>,
    flags: u32,
    output: &mut KernelRouteOutput,
) -> Result<(RoutingDecision, u64), c_long> {
    let (status, decision, generation) = evaluate_policy(input, pname, false, flags, output);
    if status == 0 {
        Ok((decision, generation))
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
    let Some(result) = crate::maps::ROUTING_TEST_OUTPUT.get_ptr_mut(0) else {
        return crate::action::TC_ACT_SHOT;
    };
    let result = unsafe { &mut *result };
    let Some(input) = crate::maps::ROUTING_TEST_INPUT.get_ptr_mut(0) else {
        result.status = -EFAULT;
        return crate::action::TC_ACT_OK;
    };
    let (status, decision, _) = evaluate_policy(
        unsafe { &mut *input },
        None,
        true,
        crate::maps::datapath_flags(),
        &mut result.trace,
    );
    result.status = status;
    result.decision = decision;
    crate::action::TC_ACT_OK
}

/// Publish the same invocation before any handoff/cache reference becomes visible.
#[inline(always)]
pub fn capture(
    witness: &mut KernelRouteWitness,
    tuple: &honk_ebpf_common::TuplesKey,
    token: u32,
    ambiguous: bool,
) -> u32 {
    if witness.output.flags & ROUTE_TRACE_ENABLED == 0 {
        return 0;
    }
    if witness.output.policy_id == u32::MAX {
        return ROUTE_TRACE_LOST;
    }
    let Some(sequence) = crate::maps::ROUTE_TRACE_SEQUENCE.get_ptr_mut(0) else {
        return ROUTE_TRACE_LOST;
    };
    let sequence = unsafe { &mut *sequence };
    unsafe { aya_ebpf_bindings::helpers::bpf_spin_lock(&mut sequence.lock) };
    let id = if sequence.next >= ROUTE_TRACE_LOST - 1 {
        ROUTE_TRACE_LOST
    } else {
        sequence.next += 1;
        sequence.next
    };
    unsafe { aya_ebpf_bindings::helpers::bpf_spin_unlock(&mut sequence.lock) };
    if id == ROUTE_TRACE_LOST {
        return id;
    }
    // Copy the initialized tuple padding as well as its fields.
    unsafe { core::ptr::copy_nonoverlapping(tuple, &mut witness.tuple, 1) };
    witness.capture_id = id;
    witness.decision_token = token;
    witness.observed_ns = unsafe { aya_ebpf_bindings::helpers::bpf_ktime_get_ns() };
    if ambiguous {
        witness.output.flags |= ROUTE_TRACE_AMBIGUOUS;
    }
    if crate::maps::ROUTE_TRACE_MAP
        .insert(&id, &*witness, 1)
        .is_err()
    {
        ROUTE_TRACE_LOST
    } else {
        id
    }
}

#[inline(always)]
pub fn captured_generation(trace_id: u32) -> u64 {
    if trace_id == 0 || trace_id == ROUTE_TRACE_LOST {
        return 0;
    }
    crate::maps::ROUTE_TRACE_MAP
        .get_ptr(&trace_id)
        .map_or(0, |value| unsafe { (*value).output.generation })
}

/// Build the fixed input used by both LAN and WAN routing paths.
///
/// Addresses are copied as wire bytes. Ports are host-order integers. The
/// six-byte MAC occupies the final six bytes of the canonical 16-byte key;
/// the MAC-presence flag distinguishes a real L2 fact from an absent L3 header.
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
        input.flags = ROUTING_INPUT_MAC_PRESENT;
    }
}
