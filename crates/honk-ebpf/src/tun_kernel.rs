//! Scalar socket-object discriminators remain inside the kernel identity bank.

use core::{ffi::c_void, mem::size_of, ptr};

/// Copy pointer bits through a checked read; never publish a verifier pointer.
#[inline(always)]
pub(crate) fn socket_address(socket: *const c_void) -> Option<u64> {
    if socket.is_null() {
        return None;
    }
    let mut address = 0u64;
    let ret = unsafe {
        aya_ebpf_bindings::helpers::bpf_probe_read_kernel(
            ptr::from_mut(&mut address).cast(),
            size_of::<u64>() as u32,
            ptr::from_ref(&socket).cast(),
        )
    };
    (ret == 0 && address != 0).then_some(address)
}
