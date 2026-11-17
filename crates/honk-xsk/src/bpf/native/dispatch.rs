use super::*;

pub(in crate::bpf) fn build(
    capture: &GeneralCapture,
    broadcasts: &[Ipv4Addr],
    programs: RawFd,
) -> io::Result<Program> {
    if !capture.authority.is_valid() || broadcasts.len() > crate::topology::MAX_BROADCASTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid native TC dispatcher authority",
        ));
    }
    let mut a = Asm::new();
    let drop = a.label();
    let pass = a.label();
    let v4 = a.label();
    let v6 = a.label();
    let selected = a.label();
    a.mov(9, 1);
    a.emit(LDX_W, 0, 9, 36, 0);
    a.jump(JNE32_K, 0, 0, capture.authority.ifindex as i32, drop);
    a.emit(LDX_W, 0, 9, 20, 0);
    a.jump(JNE_K, 0, 0, 0, drop);
    a.emit(LDX_W, 6, 9, 76, 0);
    a.emit(LDX_W, 7, 9, 80, 0);
    a.bound(14, drop);
    a.emit(LDX_B, 0, 6, 0, 0);
    a.emit(AND_K, 0, 0, 0, 1);
    a.emit(STX_W, 10, 0, -124, 0);
    a.emit(LDX_H, 5, 6, 12, 0);
    a.emit(BE16, 5, 0, 0, 16);
    a.emit(ADD_K, 6, 0, 0, 14);
    a.jump(JEQ_K, 5, 0, 0x8100, drop);
    a.jump(JEQ_K, 5, 0, 0x88a8, drop);
    a.jump(JEQ_K, 5, 0, 0x0806, pass);
    a.jump(JEQ_K, 5, 0, 0x0800, v4);
    a.jump(JEQ_K, 5, 0, 0x86dd, v6);
    a.emit(LDX_W, 0, 10, -124, 0);
    a.jump(JNE_K, 0, 0, 0, pass);
    a.go(drop);
    a.bind(v4);
    a.bound(20, drop);
    a.emit(LDX_B, 0, 6, 0, 0);
    a.emit(AND_K, 0, 0, 0, 0xf0);
    a.jump(JNE_K, 0, 0, 0x40, drop);
    a.emit(LDX_W, 0, 6, 16, 0);
    a.jump(JEQ_K, 0, 0, 0, pass);
    a.jump(JEQ32_K, 0, 0, -1, pass);
    for address in broadcasts {
        a.jump(
            JEQ32_K,
            0,
            0,
            u32::from_ne_bytes(address.octets()) as i32,
            pass,
        );
    }
    a.emit(LDX_B, 0, 6, 16, 0);
    a.emit(AND_K, 0, 0, 0, 0xf0);
    a.jump(JEQ_K, 0, 0, 0xe0, pass);
    for offset in [12, 16] {
        a.emit(LDX_H, 0, 6, offset, 0);
        a.jump(
            JEQ_K,
            0,
            0,
            i32::from(((honk_ebpf_common::DAE0_IPV4_NET >> 16) as u16).to_be()),
            drop,
        );
    }
    a.emit(LDX_W, 0, 10, -124, 0);
    a.jump(JNE_K, 0, 0, 0, selected);
    a.emit(LDX_H, 0, 6, 6, 0);
    a.jump(JSET_K, 0, 0, i32::from(0x3fff_u16.to_be()), selected);
    a.emit(LDX_B, 5, 6, 9, 0);
    let tcp4 = a.label();
    a.jump(JEQ_K, 5, 0, 6, tcp4);
    a.jump(JNE_K, 5, 0, 17, selected);
    a.bind(tcp4);
    a.emit(LDX_B, 0, 6, 0, 0);
    a.emit(AND_K, 0, 0, 0, 15);
    a.jump(JLT_K, 0, 0, 5, drop);
    a.jump(JNE_K, 0, 0, 5, selected);
    a.ptr(2, 6, 20);
    a.mov(0, 2);
    a.emit(ADD_K, 0, 0, 0, 4);
    a.jump(JGT_X, 0, 7, 0, selected);
    general::own_socket(&mut a.b, false, capture.bypass_mark);
    a.bind(v6);
    a.bound(40, drop);
    a.emit(LDX_B, 0, 6, 0, 0);
    a.emit(AND_K, 0, 0, 0, 0xf0);
    a.jump(JNE_K, 0, 0, 0x60, drop);
    a.emit(LDX_B, 0, 6, 24, 0);
    a.jump(JEQ_K, 0, 0, 0xff, pass);
    for offset in [8, 24] {
        let next = a.label();
        let prefix = honk_ebpf_common::DAE0_IPV6_PREFIX_HI;
        a.emit(LDX_W, 0, 6, offset, 0);
        a.jump(JNE32_K, 0, 0, ((prefix >> 32) as u32).to_be() as i32, next);
        a.emit(LDX_W, 0, 6, offset + 4, 0);
        a.jump(JEQ32_K, 0, 0, (prefix as u32).to_be() as i32, drop);
        a.bind(next);
    }
    a.emit(LDX_B, 5, 6, 6, 0);
    let not_icmp = a.label();
    a.jump(JNE_K, 5, 0, 58, not_icmp);
    a.bound(44, drop);
    a.emit(LDX_B, 0, 6, 40, 0);
    a.jump(JLT_K, 0, 0, 133, selected);
    a.jump(JGT_K, 0, 0, 137, selected);
    a.emit(LDX_B, 0, 6, 7, 0);
    a.jump(JNE_K, 0, 0, 255, drop);
    a.emit(LDX_B, 0, 6, 41, 0);
    a.jump(JNE_K, 0, 0, 0, drop);
    a.go(pass);
    a.bind(not_icmp);
    let tcp6 = a.label();
    a.jump(JEQ_K, 5, 0, 6, tcp6);
    a.jump(JNE_K, 5, 0, 17, selected);
    a.bind(tcp6);
    a.emit(LDX_W, 0, 10, -124, 0);
    a.jump(JNE_K, 0, 0, 0, selected);
    a.bound(44, selected);
    a.ptr(2, 6, 40);
    general::own_socket(&mut a.b, true, capture.bypass_mark);
    a.bind(selected);
    a.b.label(Label::Selected);
    a.b.map_fd(programs);
    a.mov(2, 1);
    a.mov(1, 9);
    a.emit(MOV_K, 3, 0, 0, 1);
    a.emit(CALL, 0, 0, 0, 12);
    a.bind(drop);
    a.exit(2);
    a.bind(pass);
    a.b.label(Label::Pass);
    a.exit(0);
    a.finish()
}
