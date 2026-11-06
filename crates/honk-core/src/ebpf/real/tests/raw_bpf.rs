use aya_obj::generated::{bpf_attr, bpf_cmd::BPF_PROG_LOAD, bpf_prog_type};
use std::os::fd::{FromRawFd, OwnedFd};

pub(super) const MOV64_REG: u8 = 0xbf;
pub(super) const MOV64_IMM: u8 = 0xb7;
pub(super) const ADD64_IMM: u8 = 0x07;
pub(super) const CALL: u8 = 0x85;
pub(super) const EXIT: u8 = 0x95;

pub(super) fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut raw = [0; 8];
    raw[0] = code;
    raw[1] = dst | (src << 4);
    raw[2..4].copy_from_slice(&off.to_ne_bytes());
    raw[4..].copy_from_slice(&imm.to_ne_bytes());
    raw
}

/// `BPF_PROG_LOAD` of hand-assembled instructions.
pub(super) fn load_program(
    prog_type: bpf_prog_type,
    insns: &[[u8; 8]],
) -> std::io::Result<OwnedFd> {
    let insns = insns.concat();
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_3.prog_type = prog_type as u32;
    attr.__bindgen_anon_3.insn_cnt = (insns.len() / 8) as u32;
    attr.__bindgen_anon_3.insns = insns.as_ptr() as u64;
    attr.__bindgen_anon_3.license = c"GPL".as_ptr() as u64;
    let fd = unsafe { super::syscall::bpf_syscall(BPF_PROG_LOAD as libc::c_long, &mut attr) }
        .map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}
