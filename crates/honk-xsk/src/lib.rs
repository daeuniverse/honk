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

pub use bpf::gateway::{
    AuxReaderGrace, GatewayArbitration, GatewayDnsMaps, GatewayLoad, GatewayMaps, HoldValue,
    gateway_dns_load_failure,
};
pub use bpf::{
    Attachment, AuxDevicePair, AuxGatewayProgram, AuxReturnLink, AuxTcxLink, AuxTunGuard,
    CaptureCounters, ConntrackKfuncs, OwnedXdpLink, PersistentAttachment, ProgramQueueMaps,
    Programs, SkbConntrackKfuncs, XdpState, kernel_memory_bytes, xdp_absent, xdp_state,
};
#[cfg(feature = "host")]
pub use bpf::{
    HostPrograms, HostSourceConfig, HostSourcePrograms, HostTcxAttachment, TunKernelOffsets,
    TunMaps, TunProgramConfig, TunPrograms, TunTraceTarget,
};
pub use capture::{Capture, DecodeError, DecodedPacket, GeneralCapture, Protocol, Reject};
pub use port::{
    BindMode, FRAME_SIZE, MAX_SEGMENTS, Port, PortConfig, PortCounters, RetainedRxHandle,
    RetainedRxIdentity, RingSnapshot, RxCompletion, RxDisposition, SocketStats, TxSink,
};
