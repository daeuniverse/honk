//! Process capture precedes this TUN-only operation allowance in host_identity.

use aya_ebpf::programs::SockAddrContext;

#[inline(always)]
pub(crate) fn admit_connect(_: &SockAddrContext) -> i32 {
    1
}
