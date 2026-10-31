//! Temporary issue #415 diagnostic map contract, shared by the producer and toolbox.

pub const FILTER_MAP: &str = "WAN_DIAG_CFG";
pub const SAMPLE_MAP: &str = "WAN_DIAG";

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Filter {
    pub ifindex: u32,
    pub source_port: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Sample {
    pub packets: u64,
    pub timestamp_ns: u64,
    pub socket_cookie: u64,
    pub ifindex: u32,
    pub ingress_ifindex: u32,
    pub mark: u32,
    pub protocol: u32,
    pub length: u32,
    pub parse_result: i32,
    pub link_h_len: u32,
    pub tuple_valid: u32,
    pub l4proto: u32,
    pub source_port: u32,
    pub destination_port: u32,
    pub first_byte: i32,
    pub source: [u8; 16],
    pub destination: [u8; 16],
}

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum Reason {
    ScratchUnavailable = 0,
    ParsePass = 1,
    ParseDrop = 2,
    QueueCarrierDrop = 3,
    VlanPass = 4,
    NotReadyPass = 5,
    SpecialPass = 6,
    LocalDestinationPass = 7,
    ForwardedPass = 8,
    MarkedPass = 9,
    TupleFenceDrop = 10,
    TcpAcquireDrop = 11,
    Dispatch = 12,
}

impl Reason {
    pub const ALL: [Self; 13] = [
        Self::ScratchUnavailable,
        Self::ParsePass,
        Self::ParseDrop,
        Self::QueueCarrierDrop,
        Self::VlanPass,
        Self::NotReadyPass,
        Self::SpecialPass,
        Self::LocalDestinationPass,
        Self::ForwardedPass,
        Self::MarkedPass,
        Self::TupleFenceDrop,
        Self::TcpAcquireDrop,
        Self::Dispatch,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::ScratchUnavailable => "scratch_unavailable",
            Self::ParsePass => "parse_pass",
            Self::ParseDrop => "parse_drop",
            Self::QueueCarrierDrop => "queue_carrier_drop",
            Self::VlanPass => "vlan_pass",
            Self::NotReadyPass => "not_ready_pass",
            Self::SpecialPass => "special_pass",
            Self::LocalDestinationPass => "local_destination_pass",
            Self::ForwardedPass => "forwarded_pass",
            Self::MarkedPass => "marked_pass",
            Self::TupleFenceDrop => "tuple_fence_drop",
            Self::TcpAcquireDrop => "tcp_acquire_drop",
            Self::Dispatch => "dispatch",
        }
    }
}

const _: () = assert!(core::mem::size_of::<Filter>() == 8);
const _: () = assert!(core::mem::align_of::<Filter>() == 4);
const _: () = assert!(core::mem::offset_of!(Filter, source_port) == 4);
const _: () = assert!(core::mem::align_of::<Sample>() == 8);
const _: () = assert!(core::mem::size_of::<Reason>() == 4);
const _: () = assert!(core::mem::size_of::<Sample>() == 104);
const _: () = assert!(core::mem::offset_of!(Sample, ifindex) == 24);
const _: () = assert!(core::mem::offset_of!(Sample, tuple_valid) == 52);
const _: () = assert!(core::mem::offset_of!(Sample, source) == 72);
const _: () = assert!(core::mem::offset_of!(Sample, destination) == 88);
