use super::*;
use crate::capture::GeneralCapture;
use honk_ebpf_common::xdp::{
    HIDDEN_VLAN, INLINE_VLAN, METADATA_LEN, METADATA_VERSION, RX_VLAN_CHECKED,
};

const ST_H: u8 = 0x6a;
const STX_H: u8 = 0x6b;
const JEQ32_K: u8 = 0x16;
const OR_K: u8 = 0x47;

fn patch(b: &mut Builder, at: usize) {
    b.program.insns[at].off = (b.program.len - at - 1) as i16;
}

fn forward(b: &mut Builder, code: u8, dst: u8, src: u8, imm: i32) -> usize {
    b.emit(Insn::new(code, dst, src, 0, imm))
}

/// Linux v6.12 net/core/filter.c sk_lookup(): tuple lookup uses dev_net,
/// dev->ifindex and dev_sdif, but performs no local-route lookup. Wildcard
/// listeners can match transit. A mark is socket identity, never an skb mark.
/// Therefore only exact connected, marked sockets escape; wildcard sockets,
/// fragments, IPv4 options and IPv6 extension-header replies require an uncaptured uplink.
fn own_socket(b: &mut Builder, ipv6: bool, mark: u32) {
    let address_words = if ipv6 { 8 } else { 2 };
    let address_offset = if ipv6 { 8 } else { 12 };
    for word in 0..address_words {
        b.emit(Insn::new(LDX_W, 0, 6, address_offset + word * 4, 0));
        b.emit(Insn::new(STX_W, 10, 0, -112 + word * 4, 0));
    }
    // r2 is the transport pointer, r5 the IP protocol.
    b.emit(Insn::new(LDX_W, 0, 2, 0, 0));
    b.emit(Insn::new(STX_W, 10, 0, -112 + address_words * 4, 0));
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
    b.emit(Insn::new(ADD_K, 2, 0, 0, -112));
    b.emit(Insn::new(MOV_K, 3, 0, 0, if ipv6 { 36 } else { 12 }));
    b.emit(Insn::new(MOV_K, 4, 0, 0, -1));
    b.emit(Insn::new(MOV_X, 0, 5, 0, 0));
    b.emit(Insn::new(MOV_K, 5, 0, 0, 0));
    let udp = forward(b, JEQ_K, 0, 0, 17);
    b.emit(Insn::new(CALL, 0, 0, 0, 84));
    let checked = forward(b, JA, 0, 0, 0);
    patch(b, udp);
    b.emit(Insn::new(CALL, 0, 0, 0, 85));
    patch(b, checked);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Selected);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    let mut rejected = [0usize; 12];
    let mut rejected_count = 0;
    b.emit(Insn::new(LDX_W, 1, 6, 16, 0));
    rejected[rejected_count] = forward(b, JNE32_K, 1, 0, mark as i32);
    rejected_count += 1;
    // Exact addresses reject wildcard, transparent listener and sk_lookup
    // redirection results that are not this packet's connected socket.
    for word in 0..address_words {
        let words_per_address = address_words / 2;
        let socket_offset = if word < words_per_address {
            if ipv6 { 56 + word * 4 } else { 52 }
        } else if ipv6 {
            28 + (word - words_per_address) * 4
        } else {
            24
        };
        b.emit(Insn::new(LDX_W, 1, 6, socket_offset, 0));
        b.emit(Insn::new(LDX_W, 2, 10, -112 + word * 4, 0));
        rejected[rejected_count] = forward(b, JNE_X, 1, 2, 0);
        rejected_count += 1;
    }
    let ports = -112 + address_words * 4;
    b.emit(Insn::new(LDX_H, 1, 6, 48, 0));
    b.emit(Insn::new(LDX_H, 2, 10, ports, 0));
    rejected[rejected_count] = forward(b, JNE_X, 1, 2, 0);
    rejected_count += 1;
    rejected[rejected_count] = forward(b, JEQ_K, 1, 0, 0);
    rejected_count += 1;
    b.emit(Insn::new(LDX_W, 1, 6, 44, 0));
    b.emit(Insn::new(LDX_H, 2, 10, ports + 2, 0));
    b.emit(Insn::new(BE16, 2, 0, 0, 16));
    rejected[rejected_count] = forward(b, JNE_X, 1, 2, 0);
    rejected_count += 1;
    b.emit(Insn::new(MOV_X, 1, 6, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 86));
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    for &at in &rejected[..rejected_count] {
        patch(b, at);
    }
    b.emit(Insn::new(MOV_X, 1, 6, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 86));
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Selected);
}

fn selected(
    b: &mut Builder,
    queues: u32,
    counters: RawFd,
    xsks: RawFd,
    data: bool,
    metadata: bool,
) {
    b.label(Label::Selected);
    b.jump(Insn::new(JGE_K, 8, 0, 0, queues as i32), Label::Drop);
    if data && metadata {
        b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
        b.emit(Insn::new(MOV_K, 2, 0, 0, -(METADATA_LEN as i32)));
        b.emit(Insn::new(CALL, 0, 0, 0, 54));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::CountDrop);
        b.emit(Insn::new(LDX_W, 6, 9, 8, 0));
        b.emit(Insn::new(LDX_W, 7, 9, 0, 0));
        b.bound(METADATA_LEN as i32, Label::CountDrop);
        for offset in (0..METADATA_LEN as i16).step_by(4) {
            b.emit(Insn::new(LDX_W, 0, 10, -64 + offset, 0));
            b.emit(Insn::new(STX_W, 6, 0, offset, 0));
        }
    }
    b.emit(Insn::new(STX_W, 10, 8, -4, 0));
    b.count(counters);
    if data {
        b.map_fd(xsks);
        b.emit(Insn::new(MOV_X, 2, 8, 0, 0));
        b.emit(Insn::new(MOV_K, 3, 0, 0, XDP_DROP));
        b.emit(Insn::new(CALL, 0, 0, 0, 51));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    }
    if data && metadata {
        b.label(Label::CountDrop);
        b.emit(Insn::new(ST_W, 10, 0, -4, (queues + 3) as i32));
        b.count(counters);
    }
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, XDP_DROP));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::Pass);
    b.emit(Insn::new(MOV_K, 0, 0, 0, XDP_PASS));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
}

pub(super) fn build(
    capture: &GeneralCapture,
    ipv4_broadcasts: &[std::net::Ipv4Addr],
    queues: u32,
    counters: RawFd,
    xsks: RawFd,
    data: bool,
    vlan_kfunc: Option<u32>,
) -> io::Result<Program> {
    validate_queues(queues)?;
    if ipv4_broadcasts.len() > crate::topology::MAX_BROADCASTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many native broadcast destinations",
        ));
    }
    if capture.vlan_metadata != vlan_kfunc.is_some() || vlan_kfunc == Some(0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing RX VLAN kfunc authority",
        ));
    }
    let mut b = Builder::new();
    // BPF_F_XDP_HAS_FRAGS: headers are required in the linear head; payload is
    // redirected intact, including all non-linear fragments, without a copy.
    b.program.flags = 1 << 5;
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    if vlan_kfunc.is_some() {
        b.program.flags |= 1 << 6; // BPF_F_XDP_DEV_BOUND_ONLY, not hardware offload.
        b.program.ifindex = capture.authority.ifindex;
    }
    b.emit(Insn::new(LDX_W, 8, 9, 16, 0));
    b.emit(Insn::new(LDX_W, 0, 9, 12, 0));
    b.jump(
        Insn::new(JNE32_K, 0, 0, 0, capture.authority.ifindex as i32),
        Label::Drop,
    );
    if let Some(kfunc) = vlan_kfunc {
        for offset in (-64..-32).step_by(4) {
            b.emit(Insn::new(ST_W, 10, 0, offset, 0));
        }
        b.emit(Insn::new(ST_H, 10, 0, -64, i32::from(METADATA_VERSION)));
        b.emit(Insn::new(ST_H, 10, 0, -62, METADATA_LEN as i32));
        b.emit(Insn::new(STX_W, 10, 8, -56, 0));
        b.emit(Insn::new(STX_W, 10, 0, -52, 0));
        b.emit(Insn::new(ST_W, 10, 0, -120, 0));
        b.emit(Insn::new(ST_W, 10, 0, -60, RX_VLAN_CHECKED as i32));
        b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
        b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
        b.emit(Insn::new(ADD_K, 2, 0, 0, -120));
        b.emit(Insn::new(MOV_X, 3, 10, 0, 0));
        b.emit(Insn::new(ADD_K, 3, 0, 0, -118));
        // vmlinux BTF ID: BPF_PSEUDO_KFUNC_CALL=2, off=0 needs no fd_array.
        b.emit(Insn::new(CALL, 0, 2, 0, kfunc as i32));
        let absent = forward(&mut b, JEQ32_K, 0, 0, -libc::ENODATA);
        b.jump(Insn::new(JNE32_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(LDX_H, 0, 10, -120, 0));
        b.emit(Insn::new(BE16, 0, 0, 0, 16));
        let dot1q = forward(&mut b, JEQ_K, 0, 0, 0x8100);
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0x88a8), Label::Drop);
        patch(&mut b, dot1q);
        b.emit(Insn::new(STX_H, 10, 0, -120, 0));
        b.emit(Insn::new(
            ST_W,
            10,
            0,
            -60,
            (RX_VLAN_CHECKED | HIDDEN_VLAN) as i32,
        ));
        patch(&mut b, absent);
    }
    b.emit(Insn::new(LDX_W, 6, 9, 0, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 4, 0));
    b.bound(14, Label::Drop);
    b.emit(Insn::new(LDX_B, 0, 6, 0, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 1));
    b.emit(Insn::new(STX_W, 10, 0, -124, 0));
    b.emit(Insn::new(LDX_H, 5, 6, 12, 0));
    b.emit(Insn::new(BE16, 5, 0, 0, 16));
    b.emit(Insn::new(ADD_K, 6, 0, 0, 14));
    if vlan_kfunc.is_some() {
        b.emit(Insn::new(MOV_K, 4, 0, 0, 14));
    }
    for tag in 0..2 {
        let vlan = forward(&mut b, JEQ_K, 5, 0, 0x8100);
        let skip = forward(&mut b, JNE_K, 5, 0, 0x88a8);
        patch(&mut b, vlan);
        b.bound(4, Label::Drop);
        if vlan_kfunc.is_some() {
            b.emit(Insn::new(LDX_W, 0, 10, -60, 0));
            b.emit(Insn::new(OR_K, 0, 0, 0, INLINE_VLAN as i32));
            b.emit(Insn::new(STX_W, 10, 0, -60, 0));
            b.emit(Insn::new(STX_H, 10, 5, -40 + tag * 2, 0));
            b.emit(Insn::new(LDX_H, 0, 6, 0, 0));
            b.emit(Insn::new(BE16, 0, 0, 0, 16));
            b.emit(Insn::new(STX_H, 10, 0, -44 + tag * 2, 0));
        }
        b.emit(Insn::new(LDX_H, 5, 6, 2, 0));
        b.emit(Insn::new(BE16, 5, 0, 0, 16));
        b.emit(Insn::new(ADD_K, 6, 0, 0, 4));
        if vlan_kfunc.is_some() {
            b.emit(Insn::new(ADD_K, 4, 0, 0, 4));
        }
        patch(&mut b, skip);
    }
    if vlan_kfunc.is_some() {
        b.emit(Insn::new(STX_H, 10, 4, -48, 0));
        b.emit(Insn::new(STX_H, 10, 5, -46, 0));
        b.emit(Insn::new(MOV_X, 3, 4, 0, 0));
        b.emit(Insn::new(ADD_K, 3, 0, 0, -14));
        b.emit(Insn::new(RSH_K, 3, 0, 0, 2));
        b.emit(Insn::new(STX_H, 10, 3, -34, 0));
        b.emit(Insn::new(LDX_W, 0, 10, -60, 0));
        b.emit(Insn::new(AND_K, 0, 0, 0, HIDDEN_VLAN as i32));
        let absent = forward(&mut b, JEQ_K, 0, 0, 0);
        b.jump(Insn::new(JGT_K, 4, 0, 0, 18), Label::Drop);
        for offset in [-44, -40] {
            b.emit(Insn::new(LDX_H, 0, 10, offset, 0));
            b.emit(Insn::new(STX_H, 10, 0, offset + 2, 0));
        }
        b.emit(Insn::new(LDX_H, 0, 10, -120, 0));
        b.emit(Insn::new(STX_H, 10, 0, -40, 0));
        // The kfunc's TPID is BE, but its complete PCP/DEI/VID TCI is host order.
        b.emit(Insn::new(LDX_H, 0, 10, -118, 0));
        b.emit(Insn::new(STX_H, 10, 0, -44, 0));
        b.emit(Insn::new(ADD_K, 3, 0, 0, 1));
        patch(&mut b, absent);
        b.emit(Insn::new(STX_H, 10, 3, -36, 0));
    }
    b.jump(Insn::new(JEQ_K, 5, 0, 0, 0x8100), Label::Drop);
    b.jump(Insn::new(JEQ_K, 5, 0, 0, 0x88a8), Label::Drop);
    b.jump(Insn::new(JEQ_K, 5, 0, 0, 0x0806), Label::Pass);
    b.jump(Insn::new(JEQ_K, 5, 0, 0, 0x0800), Label::Ipv4);
    b.jump(Insn::new(JEQ_K, 5, 0, 0, 0x86dd), Label::Ipv6);
    // Group MACs exempt only non-IP traffic; IP destinations own their bypass.
    b.emit(Insn::new(LDX_W, 0, 10, -124, 0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Pass);
    // Unknown unicast L2 protocols are not a hidden host bypass.
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
    b.label(Label::Ipv4);
    b.bound(20, Label::Drop);
    b.emit(Insn::new(LDX_B, 0, 6, 0, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0xf0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0x40), Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 6, 16, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Pass);
    b.jump(Insn::new(JEQ32_K, 0, 0, 0, -1), Label::Pass);
    for address in ipv4_broadcasts {
        b.jump(
            Insn::new(
                JEQ32_K,
                0,
                0,
                0,
                u32::from_ne_bytes(address.octets()) as i32,
            ),
            Label::Pass,
        );
    }
    b.emit(Insn::new(LDX_B, 0, 6, 16, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0xf0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0xe0), Label::Pass);
    for offset in [12, 16] {
        b.emit(Insn::new(LDX_H, 0, 6, offset, 0));
        b.jump(
            Insn::new(
                JEQ_K,
                0,
                0,
                0,
                u16::from_be((honk_ebpf_common::DAE0_IPV4_NET >> 16) as u16) as i32,
            ),
            Label::Drop,
        );
    }
    // Linux may locally deliver L3-unicast in a group frame. It must not borrow
    // an otherwise matching marked socket's native exemption.
    b.emit(Insn::new(LDX_W, 0, 10, -124, 0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Selected);
    b.emit(Insn::new(LDX_H, 0, 6, 6, 0));
    b.jump(
        Insn::new(JSET_K, 0, 0, 0, u16::from_be(0x3fff) as i32),
        Label::Selected,
    );
    b.emit(Insn::new(LDX_B, 5, 6, 9, 0));
    let tcp = forward(&mut b, JEQ_K, 5, 0, 6);
    b.jump(Insn::new(JNE_K, 5, 0, 0, 17), Label::Selected);
    patch(&mut b, tcp);
    b.emit(Insn::new(LDX_B, 0, 6, 0, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 15));
    b.jump(Insn::new(JLT_K, 0, 0, 0, 5), Label::Drop);
    b.jump(Insn::new(JNE_K, 0, 0, 0, 5), Label::Selected);
    b.emit(Insn::new(LSH_K, 0, 0, 0, 2));
    b.emit(Insn::new(MOV_X, 2, 6, 0, 0));
    b.emit(Insn::new(ADD_X, 2, 0, 0, 0));
    b.emit(Insn::new(MOV_X, 0, 2, 0, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, 4));
    b.jump(Insn::new(JGT_X, 0, 7, 0, 0), Label::Selected);
    own_socket(&mut b, false, capture.bypass_mark);
    b.label(Label::Ipv6);
    b.bound(40, Label::Drop);
    b.emit(Insn::new(LDX_B, 0, 6, 0, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0xf0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0x60), Label::Drop);
    b.emit(Insn::new(LDX_B, 0, 6, 24, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0xff), Label::Pass);
    for offset in [8, 24] {
        let prefix = honk_ebpf_common::DAE0_IPV6_PREFIX_HI;
        b.emit(Insn::new(LDX_W, 0, 6, offset, 0));
        let other = forward(
            &mut b,
            JNE32_K,
            0,
            0,
            u32::from_be((prefix >> 32) as u32) as i32,
        );
        b.emit(Insn::new(LDX_W, 0, 6, offset + 4, 0));
        b.jump(
            Insn::new(JEQ32_K, 0, 0, 0, u32::from_be(prefix as u32) as i32),
            Label::Drop,
        );
        patch(&mut b, other);
    }
    b.emit(Insn::new(LDX_B, 5, 6, 6, 0));
    let not_icmp = forward(&mut b, JNE_K, 5, 0, 58);
    b.bound(44, Label::Drop);
    b.emit(Insn::new(LDX_B, 0, 6, 40, 0));
    b.jump(Insn::new(JLT_K, 0, 0, 0, 133), Label::Selected);
    b.jump(Insn::new(JGT_K, 0, 0, 0, 137), Label::Selected);
    b.emit(Insn::new(LDX_B, 0, 6, 7, 0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 255), Label::Drop);
    b.emit(Insn::new(LDX_B, 0, 6, 41, 0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    patch(&mut b, not_icmp);
    let tcp = forward(&mut b, JEQ_K, 5, 0, 6);
    b.jump(Insn::new(JNE_K, 5, 0, 0, 17), Label::Selected);
    patch(&mut b, tcp);
    b.emit(Insn::new(LDX_W, 0, 10, -124, 0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Selected);
    b.bound(44, Label::Selected);
    b.emit(Insn::new(MOV_X, 2, 6, 0, 0));
    b.emit(Insn::new(ADD_K, 2, 0, 0, 40));
    own_socket(&mut b, true, capture.bypass_mark);
    selected(&mut b, queues, counters, xsks, data, capture.vlan_metadata);
    b.finish()
}

#[cfg(test)]
mod tests;
