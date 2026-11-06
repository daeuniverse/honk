//! Linux AF_XDP capture, all-queue devices and fail-closed attachment ownership.
//!
//! One owner drives each `Port`. CQ returns retained output ownership, not peer delivery.
//! UMEM mappings and their budget charges deliberately survive close and Drop until process
//! exit: socket close does not acknowledge deferred kernel/NIC pool release.
#![cfg(target_os = "linux")]

mod bpf;
mod capture;
pub mod device;
mod port;
pub mod topology;

pub use bpf::{
    Attachment, CaptureCounters, PersistentAttachment, Programs, XdpState, xdp_absent, xdp_state,
};
pub use capture::{Capture, DecodeError, DecodedPacket, GeneralCapture, Protocol, Reject};
pub use port::{
    BindMode, FRAME_SIZE, Port, PortConfig, PortCounters, RingSnapshot, SocketStats, TxSink,
};
