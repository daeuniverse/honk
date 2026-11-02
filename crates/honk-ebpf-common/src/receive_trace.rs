//! Exact metadata for one serialized, owned UDP receive syscall.

pub const RECEIVE_TRACE_BATCH_SIZE: usize = 8;
pub const RECEIVE_TRACE_SOCKETS: u32 = 256;
pub const RECEIVE_TRACE_VALID: u32 = 1;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ReceiveTracePacket {
    pub priority: u32,
    pub mark: u32,
    pub length: u32,
    pub valid: u32,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ReceiveTraceBatch {
    pub epoch: u64,
    pub owner: u64,
    pub active: u32,
    pub count: u32,
    pub depth: u32,
    pub lost: u32,
    pub candidate: ReceiveTracePacket,
    pub packets: [ReceiveTracePacket; RECEIVE_TRACE_BATCH_SIZE],
}

const _: () = assert!(core::mem::size_of::<ReceiveTracePacket>() == 16);
const _: () = assert!(core::mem::size_of::<ReceiveTraceBatch>() == 176);
const _: () = assert!(core::mem::offset_of!(ReceiveTraceBatch, packets) == 48);

const _: () = {
    use core::mem::size_of;
    assert!(size_of::<ReceiveTracePacket>() == 4 * 4);
    assert!(
        size_of::<ReceiveTraceBatch>()
            == 8 + 8
                + 4 * 4
                + size_of::<ReceiveTracePacket>()
                + size_of::<[ReceiveTracePacket; RECEIVE_TRACE_BATCH_SIZE]>()
    );
};

// SAFETY: Packet and batch leaves are only integers. The field-size sums
// include candidate and every packet, excluding implicit and nested padding.
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for ReceiveTracePacket {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for ReceiveTraceBatch {}
