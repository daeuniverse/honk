//! TEMPORARY placeholder for agent B's module (same names); replaced on merge.
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reject {
    HostUnreachable,
    AdminProhibited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpEmit {
    Sent(usize),
    Suppressed,
    TooSmall,
}

#[derive(Default)]
pub(crate) struct IcmpOut;

impl IcmpOut {
    pub(crate) fn emit(&mut self, _: Instant, _: Reject, _: &[u8], _: &mut [u8]) -> IcmpEmit {
        IcmpEmit::Suppressed
    }
}
