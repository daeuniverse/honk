use super::*;
use aya_obj::generated::bpf_func_id;

// Stable __sk_buff UAPI offsets for SCHED_CLS direct packet access.
const SKB_LEN: i16 = 0;
const SKB_PROTOCOL: i16 = 16;
const SKB_IFINDEX: i16 = 40;
pub(super) const SKB_DATA: i16 = 76;
pub(super) const SKB_DATA_END: i16 = 80;
const SKB_GSO_SIZE: i16 = 176;
pub(super) const SKB_PULL_DATA: i32 = bpf_func_id::BPF_FUNC_skb_pull_data as i32;
const TARGET_IFINDEX: i16 = -280;
pub(super) const TCX_NEXT: i32 = -1;
pub(super) const TCX_DROP: i32 = 2;

#[derive(Clone, Copy)]
pub(super) struct Ingress {
    devices: RawFd,
    gate: RawFd,
    realms: RawFd,
    pub(super) scratch: RawFd,
    realm: u32,
}

impl Ingress {
    pub(super) fn new(pair: &crate::AuxDevicePair, maps: &GatewayMaps, realm: u32) -> Self {
        Self {
            devices: pair.device_fd(),
            gate: pair.gate_fd(),
            realms: maps.realms.as_raw_fd(),
            scratch: pair.scratch_fd(),
            realm,
        }
    }

    pub(super) fn prologue(self, b: &mut GatewayBuilder, foreign: Target, stale: Target) {
        b.zero(REALM, 16);
        self.authorize(b, foreign, stale);
        b.word(KEY, self.realm as i32);
        b.word(FRAGMENT, self.realm as i32);
        b.word(FRAG_STATE, 0);
        b.word(IS_QUOTE, 0);
        b.word(L2_LEN, 0);
        b.load(LDX_W, 0, 9, SKB_LEN);
        b.store(STX_W, 10, FULL_LEN, 0);
        b.load(LDX_W, 7, 9, SKB_DATA_END);
        b.load(LDX_W, 5, 9, SKB_PROTOCOL);
        b.emit(BE16, 5, 0, 0, 16);
    }

    pub(super) fn authorize(self, b: &mut GatewayBuilder, foreign: Target, stale: Target) {
        use crate::bpf::tcx_aux::{INNER_SLOT, OUTER_SLOT};

        // An attachment racing numeric ifindex reuse has no authority on its new device.
        b.word(INDEX, OUTER_SLOT);
        b.lookup(self.devices, INDEX);
        b.jump(JEQ_K, 0, 0, 0, foreign);
        b.load(LDX_W, 1, 0, 0);
        b.jump(JEQ_K, 1, 0, 0, foreign);
        b.load(LDX_W, 0, 9, SKB_IFINDEX);
        b.jump(JNE_X, 0, 1, 0, foreign);
        b.store(STX_W, 10, REALM, 0);
        b.lookup(self.realms, REALM);
        b.jump(JEQ_K, 0, 0, 0, stale);
        b.load(LDX_W, 0, 0, 0);
        b.jump(JNE32_K, 0, 0, self.realm as i32, stale);
        b.word(INDEX, INNER_SLOT);
        b.lookup(self.devices, INDEX);
        b.jump(JEQ_K, 0, 0, 0, stale);
        b.load(LDX_W, 0, 0, 0);
        b.jump(JEQ_K, 0, 0, 0, stale);
        b.store(STX_W, 10, TARGET_IFINDEX, 0);
        b.word(INDEX, 0);
        b.lookup(self.gate, INDEX);
        b.jump(JEQ_K, 0, 0, 0, stale);
        b.load(LDX_W, 0, 0, 0);
        b.jump(JNE_K, 0, 0, 1, stale);
    }

    pub(super) fn after_policy(self, b: &mut GatewayBuilder, stale: Target) {
        b.store(STX_DW, 10, VALUE, 0);
        self.authorize(b, stale, stale);
        b.load(LDX_DW, 0, 10, VALUE);
    }

    pub(super) fn redirect(b: &mut GatewayBuilder) {
        b.load(LDX_W, 1, 10, TARGET_IFINDEX);
        b.imm(2, 0);
        b.helper(bpf_func_id::BPF_FUNC_redirect as i32);
        b.emit(EXIT, 0, 0, 0, 0);
    }
}

pub(super) fn check_endpoint_gso(b: &mut GatewayBuilder, bad: Target) {
    let done = b.target();
    b.load(LDX_W, 0, 10, VERDICT);
    b.jump(JEQ_K, 0, 0, VERDICT_PASS, done);
    b.load(LDX_W, 0, 9, SKB_GSO_SIZE);
    b.jump(JEQ_K, 0, 0, 0, done);
    // The private TUN negotiates TCP GSO. Its kernel egress segments UDP GSO before
    // delivery to the FD. Neither format represents a fragmented or quoted outer packet.
    b.jump(JGE_K, 0, 0, i32::from(u16::MAX), bad);
    for slot in [FRAG_STATE, IS_QUOTE] {
        b.load(LDX_W, 0, 10, slot);
        b.jump(JNE_K, 0, 0, 0, bad);
    }
    b.bind(done);
}

pub(super) fn special_ipv6(b: &mut GatewayBuilder, pass: Target) {
    b.load(LDX_B, 0, 6, 24);
    b.jump(JEQ_K, 0, 0, 0xff, pass);
    for offset in [8, 24] {
        b.load(LDX_H, 0, 6, offset);
        b.emit(BE16, 0, 0, 0, 16);
        b.emit(AND_K, 0, 0, 0, 0xffc0);
        b.jump(JEQ_K, 0, 0, 0xfe80, pass);
    }
}

#[cfg(all(test, target_endian = "little"))]
mod tests;
