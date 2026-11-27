pub(crate) mod btf;
pub(crate) mod syscall;

use aya::programs::{CgroupSock, CgroupSockAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PnameCaptureMode {
    Argv0,
    Comm,
}

/// Load the actual selected capture pair before attaching either program.
pub(crate) fn load_pair(bpf: &mut aya::Ebpf, sock_name: &str, sock_addr_name: &str) -> bool {
    let sock_ok = bpf
        .program_mut(sock_name)
        .and_then(|program| {
            let program: &mut CgroupSock = program.try_into().ok()?;
            program.load().ok()
        })
        .is_some();
    if !sock_ok {
        return false;
    }
    bpf.program_mut(sock_addr_name)
        .and_then(|program| {
            let program: &mut CgroupSockAddr = program.try_into().ok()?;
            program.load().ok()
        })
        .is_some()
}
