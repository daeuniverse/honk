// Matches the C enum dae_event_type.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaeEventType {
    Blocked = 0,         // DAE_EVENT_BLOCKED
    UdpConnOverflow = 1, // DAE_EVENT_UDP_CONN_OVERFLOW
    TcpConnOverflow = 2, // DAE_EVENT_TCP_CONN_OVERFLOW
    UdpDecisionTokenExhausted = 3,
    PnameResolve = 4, // userspace argv[0] resolution request
}

const _DAE_EVENT_TYPE_SIZE: () = assert!(core::mem::size_of::<DaeEventType>() == 4);
const _UDP_DECISION_TOKEN_EXHAUSTED_EVENT_VALUE: () =
    assert!(DaeEventType::UdpDecisionTokenExhausted as u32 == 3);
const _PNAME_RESOLVE_EVENT_VALUE: () = assert!(DaeEventType::PnameResolve as u32 == 4);

// Matches the C struct dae_event.
// Total size 72 bytes, alignment 8 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DaeEvent {
    pub timestamp: u64,  // __u64 timestamp
    pub type_: u32,      // __u32 type (underscore because `type` is a Rust keyword)
    pub pid: u32,        // __u32 pid
    pub pname: [u8; 16], // __u8 pname[16]
    pub outbound: u8,    // __u8 outbound
    pub l4proto: u8,     // __u8 l4proto
    pub pad: [u8; 2],    // __u8 pad[2]
    pub sip: [u32; 4],   // __u32 sip[4] (four u32 chunks for IPv4 or IPv6)
    pub dip: [u32; 4],   // __u32 dip[4]
    pub sport: u16,      // __u16 sport
    pub dport: u16,      // __u16 dport
}

const _DAE_EVENT_SIZE: () = assert!(core::mem::size_of::<DaeEvent>() == 72);
const _DAE_EVENT_ALIGN: () = assert!(core::mem::align_of::<DaeEvent>() == 8);
const _DAE_EVENT_TIMESTAMP_OFFSET: () = assert!(core::mem::offset_of!(DaeEvent, timestamp) == 0);
const _DAE_EVENT_TYPE_OFFSET: () = assert!(core::mem::offset_of!(DaeEvent, type_) == 8);
const _DAE_EVENT_PID_OFFSET: () = assert!(core::mem::offset_of!(DaeEvent, pid) == 12);
const _DAE_EVENT_PNAME_OFFSET: () = assert!(core::mem::offset_of!(DaeEvent, pname) == 16);
const _DAE_EVENT_OUTBOUND_OFFSET: () = assert!(core::mem::offset_of!(DaeEvent, outbound) == 32);
const _DAE_EVENT_L4PROTO_OFFSET: () = assert!(core::mem::offset_of!(DaeEvent, l4proto) == 33);
const _DAE_EVENT_SIP_OFFSET: () = assert!(core::mem::offset_of!(DaeEvent, sip) == 36);
const _DAE_EVENT_DIP_OFFSET: () = assert!(core::mem::offset_of!(DaeEvent, dip) == 52);
const _DAE_EVENT_SPORT_OFFSET: () = assert!(core::mem::offset_of!(DaeEvent, sport) == 68);
const _DAE_EVENT_DPORT_OFFSET: () = assert!(core::mem::offset_of!(DaeEvent, dport) == 70);

#[repr(C)]
#[derive(Clone, Copy)]
pub enum TcpState {
    TcpStateActive = 0,
    TcpStateClosing = 1,
}
