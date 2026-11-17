//! Native-endian XDP metadata. Static owner authority is never inferred from packet bytes.

pub const METADATA_VERSION: u16 = 2;
pub const METADATA_LEN: usize = 32;
pub const INLINE_VLAN: u32 = 1;
pub const RX_VLAN_CHECKED: u32 = 2;
pub const HIDDEN_VLAN: u32 = 4;
pub const KNOWN_FLAGS: u32 = INLINE_VLAN | RX_VLAN_CHECKED | HIDDEN_VLAN;
/// Native routing publication root. Odd epochs are open; zero and even epochs are closed.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeRoot {
    pub epoch: u64,
    pub flags: u32,
    pub reserved: u32,
}

pub const NATIVE_PUBLICATION_VERSION: u32 = 1;
pub const NATIVE_EVENT_INITIAL_STATE: u32 = 1;
pub const NATIVE_EVENT_HOOK_REGISTERED: u32 = 2;
pub const NATIVE_EVENT_WRITER_BEGIN: u32 = 3;
pub const NATIVE_EVENT_CLOSE_INTENT: u32 = 4;
pub const NATIVE_EVENT_CLOSE_STORED: u32 = 5;
pub const NATIVE_EVENT_CLOSE_DRAINED: u32 = 6;
pub const NATIVE_EVENT_WRITER_OUTCOME: u32 = 7;
pub const NATIVE_EVENT_REOPEN_INTENT: u32 = 8;
pub const NATIVE_EVENT_REOPEN_STORED: u32 = 9;
pub const NATIVE_EVENT_CLOSED_COUNTS_FINAL: u32 = 10;
pub const NATIVE_EVENT_TERMINAL_STATE: u32 = 11;
pub const NATIVE_EVENT_COLLECTION_END: u32 = 12;
// A separate kind keeps replacement milestones and program identity history in the fixed 128-byte ABI.
// Replacements reuse counter_value for the old program ID and counter_epoch for the new ID.
pub const NATIVE_EVENT_PROGRAM_REPLACED: u32 = 13;
pub const NATIVE_OUTCOME_PENDING: u32 = 0;
pub const NATIVE_OUTCOME_COMMITTED: u32 = 1;
pub const NATIVE_OUTCOME_FAILED: u32 = 2;
pub const NATIVE_EVENT_FLAG_TIMESTAMP_VALID: u32 = 1 << 0;
pub const NATIVE_EVENT_FLAG_COUNTER_VALID: u32 = 1 << 1;
pub const NATIVE_EVENT_FLAG_COUNTER_OVERFLOW: u32 = 1 << 2;
pub const NATIVE_EVENT_FLAG_OTHER_WRITERS: u32 = 1 << 3;
pub const NATIVE_EVENT_FLAG_NOT_READY: u32 = 1 << 4;
pub const NATIVE_EVENT_FLAG_CAPTURE_NOT_READY: u32 = 1 << 5;
pub const NATIVE_EVENT_FLAG_MISSING_PLAN: u32 = 1 << 6;
pub const NATIVE_EVENT_FLAG_MISSING_TARGET: u32 = 1 << 7;
pub const NATIVE_EVENT_FLAG_MISSING_SCOPE: u32 = 1 << 8;
pub const NATIVE_EVENT_KNOWN_FLAGS: u32 = (1 << 9) - 1;
pub const NATIVE_COUNTER_GENERATIONS: u32 = 256;
pub const NATIVE_COUNTER_ENTRIES: u32 = 513;
pub const NATIVE_COUNTER_FAULT_INDEX: u32 = 512;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeReason {
    Startup = 1,
    Policy = 2,
    Flags = 3,
    Ready = 4,
    CaptureReady = 5,
    ScopedDns = 6,
    Reload = 7,
    Mode = 8,
    RuntimeMaintenance = 9,
    Shutdown = 10,
    MapReadFailure = 11,
    EpochExhaustion = 12,
    OwnerDrop = 13,
    AccountingFailure = 14,
}

/// Immutable userspace publication milestone; integer fields are native endian.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativePublicationEventV1 {
    pub seq: u64,
    pub operation_id: u64,
    pub writer_id: u64,
    pub epoch_before: u64,
    pub epoch_after: u64,
    pub boottime_before_ns: u64,
    pub boottime_after_ns: u64,
    pub related_seq: u64,
    pub counter_epoch: u64,
    pub counter_value: u64,
    pub hook_id: u64,
    pub outcome: u32,
    pub kind: u32,
    pub reason: u32,
    pub flags: u32,
    pub reserved: [u8; 24],
}

impl NativePublicationEventV1 {
    pub fn is_valid(&self, version: u32) -> bool {
        version == NATIVE_PUBLICATION_VERSION
            && self.seq != 0
            && (NATIVE_EVENT_INITIAL_STATE..=NATIVE_EVENT_PROGRAM_REPLACED).contains(&self.kind)
            && self.reason <= NativeReason::AccountingFailure as u32
            && (!(self.kind == NATIVE_EVENT_WRITER_BEGIN
                || self.kind == NATIVE_EVENT_WRITER_OUTCOME)
                || self.reason != 0)
            && self.outcome <= NATIVE_OUTCOME_FAILED
            && !(matches!(
                self.kind,
                NATIVE_EVENT_CLOSE_STORED
                    | NATIVE_EVENT_CLOSE_DRAINED
                    | NATIVE_EVENT_WRITER_OUTCOME
                    | NATIVE_EVENT_REOPEN_STORED
                    | NATIVE_EVENT_CLOSED_COUNTS_FINAL
                    | NATIVE_EVENT_TERMINAL_STATE
                    | NATIVE_EVENT_COLLECTION_END
            ) && self.outcome == NATIVE_OUTCOME_PENDING)
            && self.flags & !NATIVE_EVENT_KNOWN_FLAGS == 0
            && self.reserved == [0; 24]
    }
}

/// Epoch tags and reserved bytes are initialized only while this cell is not live.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeClosedCounterV1 {
    pub epoch: u64,
    pub ordinary_drops: u64,
    pub overflow: u64,
    pub reserved: u64,
}

impl NativeClosedCounterV1 {
    pub const fn is_valid(&self, epoch: u64) -> bool {
        epoch & 1 == 0 && self.epoch == epoch && self.overflow <= 1 && self.reserved == 0
    }
}

pub const fn native_closed_counter_index(epoch: u64, hook: u32) -> Option<u32> {
    if epoch & 1 != 0 || hook > 1 {
        None
    } else {
        Some((((epoch >> 1) & (NATIVE_COUNTER_GENERATIONS as u64 - 1)) as u32) * 2 + hook)
    }
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for NativePublicationEventV1 {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for NativeClosedCounterV1 {}

const _: () = assert!(core::mem::size_of::<NativePublicationEventV1>() == 128);
const _: () = assert!(core::mem::align_of::<NativePublicationEventV1>() == 8);
const _: () = assert!(core::mem::size_of::<NativeClosedCounterV1>() == 32);
const _: () = assert!(core::mem::align_of::<NativeClosedCounterV1>() == 8);

/// Exact native tuple and projection domain; namespaces never come from packet bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct NativeKey {
    pub src_ip: [u32; 4],
    pub dst_ip: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub l4proto: u8,
    pub ip_version: u8,
    pub domain: u8,
    pub direction: u8,
    pub namespace_cookie: u64,
    pub zone: u16,
    pub zone_state: u8,
    pub reserved: [u8; 5],
}

pub const NATIVE_DOMAIN_FLOW: u8 = 0;
pub const NATIVE_DOMAIN_SOURCE: u8 = 1;
pub const NATIVE_DOMAIN_UNBOUND_SOURCE: u8 = 2;
pub const NATIVE_DIRECTION_ORIGINAL: u8 = 0;
pub const NATIVE_DIRECTION_REPLY: u8 = 1;
pub const NATIVE_ZONE_UNBOUND: u8 = 0;
pub const NATIVE_ZONE_BOUND_ACTUAL: u8 = 1;
pub const NATIVE_ZONE_TRANSIT_DEFAULT: u8 = 2;
pub const NATIVE_EXECUTOR_CAPTURE: u32 = 1;
pub const NATIVE_EXECUTOR_KERNEL: u32 = 2;
pub const NATIVE_EXECUTOR_PENDING: u32 = 3;
pub const NATIVE_PHASE_PENDING: u32 = 0;
pub const NATIVE_PHASE_CAPTURE_COMMITTED: u32 = 1;
pub const NATIVE_PHASE_ARMED: u32 = 2;
pub const NATIVE_PHASE_DRAINING: u32 = 3;
pub const NATIVE_PHASE_ACTIVE: u32 = 4;
pub const NATIVE_PHASE_CLOSING: u32 = 5;
pub const NATIVE_PHASE_SOURCE_PENDING: u32 = 6;
pub const NATIVE_OUTSTANDING_MAX: u32 = (1 << 28) - 1;
pub const NATIVE_MARK_KEEP: u32 = 0;
pub const NATIVE_MARK_SET: u32 = 1;
pub const NATIVE_CLAIM_VALUE_BYTES: usize = 72;
pub const NATIVE_CLAIM_UPDATE_INTERVAL_NS: u64 = 1_000_000_000;

pub const fn native_claim_udp_expired(last_seen_ns: u64, now_ns: u64) -> bool {
    now_ns.saturating_sub(last_seen_ns) > crate::conn::UDP_CONN_STATE_TIMEOUT_NS
}

/// Selection is one aligned word; activity and immutable owner identity are independent.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeClaim {
    pub epoch: u64,
    pub incarnation: u64,
    pub scope: u64,
    pub executor: u32,
    pub state: u32,
    pub last_seen_ns: u64,
    pub owner_cookie: u64,
    pub owner_incarnation: u64,
    pub attachment_generation: u64,
    pub mark_kind: u32,
    pub mark_value: u32,
}

pub const fn native_selection(executor: u32, phase: u32, outstanding: u32) -> Option<u64> {
    if outstanding > NATIVE_OUTSTANDING_MAX {
        return None;
    }
    let valid = match executor {
        NATIVE_EXECUTOR_PENDING => matches!(
            phase,
            NATIVE_PHASE_PENDING | NATIVE_PHASE_SOURCE_PENDING | NATIVE_PHASE_CLOSING
        ),
        NATIVE_EXECUTOR_CAPTURE => {
            matches!(phase, NATIVE_PHASE_CAPTURE_COMMITTED | NATIVE_PHASE_CLOSING)
        }
        NATIVE_EXECUTOR_KERNEL => {
            matches!(
                phase,
                NATIVE_PHASE_ARMED | NATIVE_PHASE_DRAINING | NATIVE_PHASE_CLOSING
            ) || (phase == NATIVE_PHASE_ACTIVE && outstanding == 0)
        }
        _ => false,
    };
    if valid {
        Some(executor as u64 | (((outstanding << 4) | phase) as u64) << 32)
    } else {
        None
    }
}

impl NativeKey {
    pub fn is_valid(&self) -> bool {
        self.namespace_cookie != 0
            && self.reserved == [0; 5]
            && matches!(self.ip_version, 4 | 6)
            && matches!(self.l4proto, 6 | 17)
            && self.direction <= NATIVE_DIRECTION_REPLY
            && match self.domain {
                NATIVE_DOMAIN_FLOW => {
                    matches!(
                        self.zone_state,
                        NATIVE_ZONE_BOUND_ACTUAL | NATIVE_ZONE_TRANSIT_DEFAULT
                    ) && (self.zone_state != NATIVE_ZONE_TRANSIT_DEFAULT || self.zone == 0)
                }
                NATIVE_DOMAIN_SOURCE => {
                    self.direction == NATIVE_DIRECTION_ORIGINAL
                        && (self.zone_state == NATIVE_ZONE_BOUND_ACTUAL
                            || (self.zone_state == NATIVE_ZONE_UNBOUND && self.zone == 0))
                }
                NATIVE_DOMAIN_UNBOUND_SOURCE => {
                    self.direction == NATIVE_DIRECTION_ORIGINAL
                        && self.zone_state == NATIVE_ZONE_UNBOUND
                        && self.zone == 0
                }
                _ => false,
            }
    }
}

impl NativeClaim {
    pub const fn selection(&self) -> u64 {
        self.executor as u64 | ((self.state as u64) << 32)
    }

    pub fn is_valid(&self, key: &NativeKey) -> bool {
        let phase = self.state & 15;
        key.is_valid()
            && self.epoch != 0
            && self.epoch & 1 != 0
            && self.incarnation == self.epoch
            && self.scope != 0
            && native_selection(self.executor, phase, self.state >> 4) == Some(self.selection())
            && (phase != NATIVE_PHASE_PENDING || key.domain == NATIVE_DOMAIN_FLOW)
            && (phase != NATIVE_PHASE_SOURCE_PENDING || key.domain == NATIVE_DOMAIN_UNBOUND_SOURCE)
            && (key.domain != NATIVE_DOMAIN_UNBOUND_SOURCE
                || matches!(phase, NATIVE_PHASE_SOURCE_PENDING | NATIVE_PHASE_CLOSING))
            && (key.domain == NATIVE_DOMAIN_FLOW
                || (self.owner_cookie != 0
                    && self.owner_incarnation != 0
                    && self.attachment_generation != 0))
            && match self.mark_kind {
                NATIVE_MARK_KEEP => self.mark_value == 0,
                NATIVE_MARK_SET => true,
                _ => false,
            }
    }

    pub fn is_transit(&self, key: &NativeKey) -> bool {
        self.is_valid(key)
            && key.domain == NATIVE_DOMAIN_FLOW
            && key.direction == NATIVE_DIRECTION_ORIGINAL
            && key.zone == 0
            && key.zone_state == NATIVE_ZONE_TRANSIT_DEFAULT
            && self.owner_cookie == 0
            && self.owner_incarnation == 0
            && self.attachment_generation == 0
            && self.mark_kind == NATIVE_MARK_KEEP
            && self.mark_value == 0
            && self.state & 15 != NATIVE_PHASE_SOURCE_PENDING
    }
}

/// Per-CPU native routing scratch. The busy word is a verifier-visible reentrancy guard.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeScratch {
    pub input: crate::RoutingInput,
    pub output: crate::KernelRouteOutput,
    pub busy: u32,
    pub reserved: u32,
}

pub const NATIVE_SCRATCH_BYTES: usize = core::mem::size_of::<NativeScratch>();
pub const NATIVE_IMPORT_LEN: usize = 32;
pub const NATIVE_METADATA_LEN: usize = METADATA_LEN + NATIVE_IMPORT_LEN;
pub const NATIVE_IMPORT_COUNTED: u32 = 1;

/// A producer reservation and its original, nonrenewable BOOTTIME horizon.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeImport {
    pub epoch: u64,
    pub incarnation: u64,
    pub expires_boottime_ns: u64,
    pub flags: u32,
    pub reserved: u32,
}

impl NativeImport {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; NATIVE_IMPORT_LEN] = bytes.try_into().ok()?;
        let value = Self {
            epoch: u64::from_ne_bytes(bytes[..8].try_into().ok()?),
            incarnation: u64::from_ne_bytes(bytes[8..16].try_into().ok()?),
            expires_boottime_ns: u64::from_ne_bytes(bytes[16..24].try_into().ok()?),
            flags: u32::from_ne_bytes(bytes[24..28].try_into().ok()?),
            reserved: u32::from_ne_bytes(bytes[28..32].try_into().ok()?),
        };
        (value.reserved == 0 && value.flags & !NATIVE_IMPORT_COUNTED == 0).then_some(value)
    }
}

pub const NATIVE_OP_IDLE: u32 = 0;
pub const NATIVE_OP_PREPARED: u32 = 1;
pub const NATIVE_OP_ADMITTING: u32 = 2;
pub const NATIVE_OP_ADMITTED: u32 = 3;
pub const NATIVE_OP_REDIRECTING: u32 = 4;
pub const NATIVE_OP_REDIRECT_REQUESTED: u32 = 5;
pub const NATIVE_OP_ENTERING: u32 = 6;
pub const NATIVE_OP_ENTERED: u32 = 7;
pub const NATIVE_OP_GATE_REFUSED: u32 = 8;
pub const NATIVE_OP_CLOSING: u32 = 9;

/// One flight; mutable receipt fields are published only by their phase owner.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeCapturedOperation {
    pub op_incarnation: u64,
    pub return_attachment: u64,
    pub ingress_attachment: u64,
    pub claim_epoch: u64,
    pub claim_incarnation: u64,
    pub claim_scope: u64,
    pub capture_epoch: u64,
    pub basis_epoch: u64,
    pub expires_boottime_ns: u64,
    pub routing_generation: u64,
    pub mode_revision: u64,
    pub fact_scope: u64,
    pub fact_revision: u64,
    pub fact_horizon: u64,
    pub key: NativeKey,
    pub ingress_ifindex: u32,
    pub logical_ifindex: u32,
    pub realm_index: u32,
    pub frame_length: u32,
    pub l3_offset: u32,
    pub l3_length: u32,
    pub phase: u32,
    pub flags: u32,
    pub vlan_tci: [u16; 2],
    pub vlan_proto: [u16; 2],
    pub vlan_count: u16,
    pub inline_vlan_count: u16,
    pub dscp: u8,
    pub reserved0: [u8; 3],
    pub saved_cb: [u8; 20],
    pub receipt: u32,
    pub entry_seq: u64,
    pub rx_queue: u32,
    pub reserved2: u32,
    pub reserved1: u64,
}

macro_rules! native_layout {
    ($ty:ty, $size:expr, $($field:ident = $offset:expr),+ $(,)?) => {
        const _: () = {
            assert!(core::mem::size_of::<$ty>() == $size);
            assert!(core::mem::align_of::<$ty>() == 8);
            $(assert!(core::mem::offset_of!($ty, $field) == $offset);)+
        };
    };
}
native_layout!(
    NativeKey,
    56,
    src_ip = 0,
    dst_ip = 16,
    src_port = 32,
    dst_port = 34,
    l4proto = 36,
    ip_version = 37,
    domain = 38,
    direction = 39,
    namespace_cookie = 40,
    zone = 48,
    zone_state = 50,
    reserved = 51
);
native_layout!(
    NativeClaim,
    72,
    epoch = 0,
    incarnation = 8,
    scope = 16,
    executor = 24,
    state = 28,
    last_seen_ns = 32,
    owner_cookie = 40,
    owner_incarnation = 48,
    attachment_generation = 56,
    mark_kind = 64,
    mark_value = 68
);
native_layout!(
    NativeImport,
    32,
    epoch = 0,
    incarnation = 8,
    expires_boottime_ns = 16,
    flags = 24,
    reserved = 28
);
native_layout!(
    NativeCapturedOperation,
    264,
    op_incarnation = 0,
    return_attachment = 8,
    ingress_attachment = 16,
    claim_epoch = 24,
    claim_incarnation = 32,
    claim_scope = 40,
    capture_epoch = 48,
    basis_epoch = 56,
    expires_boottime_ns = 64,
    routing_generation = 72,
    mode_revision = 80,
    fact_scope = 88,
    fact_revision = 96,
    fact_horizon = 104,
    key = 112,
    ingress_ifindex = 168,
    logical_ifindex = 172,
    realm_index = 176,
    frame_length = 180,
    l3_offset = 184,
    l3_length = 188,
    phase = 192,
    flags = 196,
    vlan_tci = 200,
    vlan_proto = 204,
    vlan_count = 208,
    inline_vlan_count = 210,
    dscp = 212,
    reserved0 = 213,
    saved_cb = 216,
    receipt = 236,
    entry_seq = 240,
    rx_queue = 248,
    reserved2 = 252,
    reserved1 = 256
);
const _: () = assert!(NATIVE_METADATA_LEN == 64);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureAuthority {
    pub namespace_cookie: u64,
    pub attachment_generation: u64,
    pub scope: u64,
    /// The actual configuration snapshot at attachment creation; zero is the initial generation.
    pub config_generation: u64,
    pub ifindex: u32,
    pub reserved: u32,
}

impl CaptureAuthority {
    pub const fn is_valid(self) -> bool {
        self.namespace_cookie != 0
            && self.attachment_generation != 0
            && self.scope != 0
            && self.ifindex != 0
            && self.reserved == 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketMetadata {
    pub version: u16,
    pub length: u16,
    pub flags: u32,
    pub rx_queue: u32,
    pub ingress_ifindex: u32,
    /// Actual bytes before IP, excluding any recovered outer tag.
    pub l2_len: u16,
    pub ether_type: u16,
    /// Logical outer-to-inner tags, including the recovered tag if present.
    pub vlan_tci: [u16; 2],
    pub vlan_proto: [u16; 2],
    pub vlan_count: u16,
    pub inline_vlan_count: u16,
}

impl PacketMetadata {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; METADATA_LEN] = bytes.try_into().ok()?;
        let u16_at = |i| u16::from_ne_bytes([bytes[i], bytes[i + 1]]);
        let u32_at = |i| u32::from_ne_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let value = Self {
            version: u16_at(0),
            length: u16_at(2),
            flags: u32_at(4),
            rx_queue: u32_at(8),
            ingress_ifindex: u32_at(12),
            l2_len: u16_at(16),
            ether_type: u16_at(18),
            vlan_tci: [u16_at(20), u16_at(22)],
            vlan_proto: [u16_at(24), u16_at(26)],
            vlan_count: u16_at(28),
            inline_vlan_count: u16_at(30),
        };
        (value.version == METADATA_VERSION
            && value.length as usize == METADATA_LEN
            && value.flags & !KNOWN_FLAGS == 0
            && value.vlan_count <= 2
            && value.inline_vlan_count <= value.vlan_count
            && value.vlan_count - value.inline_vlan_count
                == u16::from(value.flags & HIDDEN_VLAN != 0)
            && (value.flags & HIDDEN_VLAN == 0 || value.flags & RX_VLAN_CHECKED != 0)
            && (value.flags & INLINE_VLAN != 0) == (value.inline_vlan_count != 0))
            .then_some(value)
    }
}

const _: () = {
    assert!(core::mem::size_of::<NativeClaim>() == NATIVE_CLAIM_VALUE_BYTES);
    assert!(core::mem::size_of::<NativeImport>() == NATIVE_IMPORT_LEN);
    assert!(core::mem::size_of::<PacketMetadata>() == METADATA_LEN);
    assert!(core::mem::align_of::<PacketMetadata>() == 4);
    assert!(core::mem::offset_of!(PacketMetadata, version) == 0);
    assert!(core::mem::offset_of!(PacketMetadata, length) == 2);
    assert!(core::mem::offset_of!(PacketMetadata, flags) == 4);
    assert!(core::mem::offset_of!(PacketMetadata, rx_queue) == 8);
    assert!(core::mem::offset_of!(PacketMetadata, ingress_ifindex) == 12);
    assert!(core::mem::offset_of!(PacketMetadata, l2_len) == 16);
    assert!(core::mem::offset_of!(PacketMetadata, ether_type) == 18);
    assert!(core::mem::offset_of!(PacketMetadata, vlan_tci) == 20);
    assert!(core::mem::offset_of!(PacketMetadata, vlan_proto) == 24);
    assert!(core::mem::offset_of!(PacketMetadata, vlan_count) == 28);
    assert!(core::mem::offset_of!(PacketMetadata, inline_vlan_count) == 30);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_source_projection_precedes_ct_without_claiming_its_zone() {
        let source = NativeKey {
            l4proto: 17,
            ip_version: 4,
            domain: NATIVE_DOMAIN_SOURCE,
            namespace_cookie: 1,
            zone_state: NATIVE_ZONE_UNBOUND,
            ..NativeKey::default()
        };
        let claim = NativeClaim {
            epoch: 3,
            incarnation: 3,
            scope: 1,
            executor: NATIVE_EXECUTOR_KERNEL,
            state: NATIVE_PHASE_ACTIVE,
            owner_cookie: 7,
            owner_incarnation: 8,
            attachment_generation: 9,
            mark_kind: NATIVE_MARK_SET,
            mark_value: 0,
            ..NativeClaim::default()
        };
        assert!(claim.is_valid(&source));
        assert!(!claim.is_transit(&source));
        assert!(claim.is_valid(&NativeKey {
            zone_state: NATIVE_ZONE_BOUND_ACTUAL,
            zone: 17,
            ..source
        }));
        for invalid in [
            NativeKey { zone: 1, ..source },
            NativeKey {
                direction: NATIVE_DIRECTION_REPLY,
                ..source
            },
            NativeKey {
                zone_state: NATIVE_ZONE_TRANSIT_DEFAULT,
                ..source
            },
            NativeKey {
                domain: NATIVE_DOMAIN_UNBOUND_SOURCE,
                ..source
            },
        ] {
            assert!(!claim.is_valid(&invalid));
        }
        for invalid in [
            NativeClaim {
                owner_cookie: 0,
                ..claim
            },
            NativeClaim {
                owner_incarnation: 0,
                ..claim
            },
            NativeClaim {
                attachment_generation: 0,
                ..claim
            },
            NativeClaim {
                executor: NATIVE_EXECUTOR_PENDING,
                state: NATIVE_PHASE_SOURCE_PENDING,
                ..claim
            },
        ] {
            assert!(!invalid.is_valid(&source));
        }
    }

    #[test]
    fn native_v2_rejects_invalid_projection_fields() {
        let key = NativeKey {
            l4proto: 17,
            ip_version: 4,
            namespace_cookie: 1,
            zone_state: NATIVE_ZONE_TRANSIT_DEFAULT,
            ..NativeKey::default()
        };
        let claim = NativeClaim {
            epoch: 3,
            incarnation: 3,
            scope: 1,
            executor: NATIVE_EXECUTOR_PENDING,
            ..NativeClaim::default()
        };
        assert!(claim.is_transit(&key));
        for bad in [
            NativeKey { domain: 3, ..key },
            NativeKey {
                direction: 2,
                ..key
            },
            NativeKey {
                zone_state: 3,
                ..key
            },
            NativeKey {
                namespace_cookie: 0,
                ..key
            },
            NativeKey {
                zone_state: NATIVE_ZONE_UNBOUND,
                ..key
            },
            NativeKey { zone: 1, ..key },
            NativeKey {
                domain: NATIVE_DOMAIN_SOURCE,
                direction: NATIVE_DIRECTION_REPLY,
                zone_state: NATIVE_ZONE_BOUND_ACTUAL,
                ..key
            },
            NativeKey {
                domain: NATIVE_DOMAIN_UNBOUND_SOURCE,
                zone_state: NATIVE_ZONE_BOUND_ACTUAL,
                ..key
            },
            NativeKey {
                domain: NATIVE_DOMAIN_SOURCE,
                ..key
            },
            NativeKey {
                domain: NATIVE_DOMAIN_UNBOUND_SOURCE,
                direction: NATIVE_DIRECTION_REPLY,
                zone_state: NATIVE_ZONE_UNBOUND,
                ..key
            },
            NativeKey {
                domain: NATIVE_DOMAIN_UNBOUND_SOURCE,
                zone: 1,
                zone_state: NATIVE_ZONE_UNBOUND,
                ..key
            },
        ] {
            assert!(!bad.is_valid(), "{bad:?}");
            assert!(!claim.is_transit(&bad));
        }
        for index in 0..5 {
            let mut bad = key;
            bad.reserved[index] = 1;
            assert!(!bad.is_valid(), "reserved[{index}]");
        }
        for bad in [
            NativeClaim { state: 7, ..claim },
            NativeClaim {
                executor: 0,
                ..claim
            },
            NativeClaim {
                executor: NATIVE_EXECUTOR_CAPTURE,
                ..claim
            },
            NativeClaim {
                executor: NATIVE_EXECUTOR_KERNEL,
                ..claim
            },
            NativeClaim {
                mark_kind: 2,
                ..claim
            },
            NativeClaim {
                mark_value: 1,
                ..claim
            },
        ] {
            assert!(!bad.is_valid(&key), "{bad:?}");
        }
        for bad in [
            NativeClaim {
                owner_cookie: 1,
                ..claim
            },
            NativeClaim {
                owner_incarnation: 1,
                ..claim
            },
            NativeClaim {
                attachment_generation: 1,
                ..claim
            },
            NativeClaim {
                mark_kind: NATIVE_MARK_SET,
                ..claim
            },
            NativeClaim {
                mark_kind: NATIVE_MARK_SET,
                mark_value: 1,
                ..claim
            },
        ] {
            assert!(bad.is_valid(&key));
            assert!(!bad.is_transit(&key), "{bad:?}");
        }
        let source = NativeKey {
            domain: NATIVE_DOMAIN_UNBOUND_SOURCE,
            zone_state: NATIVE_ZONE_UNBOUND,
            ..key
        };
        let pending = NativeClaim {
            state: NATIVE_PHASE_SOURCE_PENDING,
            owner_cookie: 7,
            owner_incarnation: 8,
            attachment_generation: 9,
            ..claim
        };
        assert!(pending.is_valid(&source));
        assert!(!pending.is_transit(&source));
        assert!(!pending.is_valid(&key));
        let bound_source = NativeKey {
            domain: NATIVE_DOMAIN_SOURCE,
            zone_state: NATIVE_ZONE_BOUND_ACTUAL,
            ..key
        };
        assert!(bound_source.is_valid());
        assert!(!claim.is_valid(&bound_source));
        let armed_source = NativeClaim {
            executor: NATIVE_EXECUTOR_KERNEL,
            state: (1 << 4) | NATIVE_PHASE_ARMED,
            ..pending
        };
        assert!(source.is_valid());
        assert!(!armed_source.is_valid(&source));
        let reply = NativeKey {
            direction: NATIVE_DIRECTION_REPLY,
            ..key
        };
        assert!(reply.is_valid());
        assert!(claim.is_valid(&reply));
        assert!(!claim.is_transit(&reply));
        for executor in [NATIVE_EXECUTOR_CAPTURE, NATIVE_EXECUTOR_KERNEL] {
            assert!(native_selection(executor, NATIVE_PHASE_PENDING, 0).is_none());
            assert!(native_selection(executor, NATIVE_PHASE_SOURCE_PENDING, 0).is_none());
        }
        assert!(native_selection(NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ACTIVE, 1).is_none());
        assert!(
            native_selection(
                NATIVE_EXECUTOR_PENDING,
                NATIVE_PHASE_PENDING,
                NATIVE_OUTSTANDING_MAX + 1
            )
            .is_none()
        );
    }

    #[test]
    fn native_import_v2_rejects_old_extents_flags_and_reserved() {
        let mut bytes = [0u8; NATIVE_IMPORT_LEN];
        bytes[..8].copy_from_slice(&5u64.to_ne_bytes());
        bytes[8..16].copy_from_slice(&3u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&99u64.to_ne_bytes());
        for flags in [0, NATIVE_IMPORT_COUNTED] {
            bytes[24..28].copy_from_slice(&flags.to_ne_bytes());
            let import = NativeImport::decode(&bytes).unwrap();
            assert_eq!(import.flags, flags);
            assert_eq!(import.expires_boottime_ns, 99);
        }
        for length in 0..NATIVE_IMPORT_LEN {
            assert!(NativeImport::decode(&bytes[..length]).is_none(), "{length}");
        }
        assert!(NativeImport::decode(&[0; 16]).is_none());
        assert!(NativeImport::decode(&[0; 48]).is_none());
        assert!(NativeImport::decode(&[0; 64]).is_none());
        assert!(NativeImport::decode(&[0; NATIVE_IMPORT_LEN + 1]).is_none());
        bytes[24..28].copy_from_slice(&2u32.to_ne_bytes());
        assert!(NativeImport::decode(&bytes).is_none());
        bytes[24..28].copy_from_slice(&0u32.to_ne_bytes());
        for index in 28..32 {
            bytes[index] = 1;
            assert!(NativeImport::decode(&bytes).is_none(), "reserved[{index}]");
            bytes[index] = 0;
        }
        assert_eq!(NATIVE_METADATA_LEN, 64);
    }

    #[test]
    fn native_publication_v1_layout_and_validation_are_fixed() {
        macro_rules! offset {
            ($ty:ty, $($field:ident = $offset:expr),+ $(,)?) => {
                $(assert_eq!(core::mem::offset_of!($ty, $field), $offset);)+
            };
        }
        offset!(
            NativePublicationEventV1,
            seq = 0,
            operation_id = 8,
            writer_id = 16,
            epoch_before = 24,
            epoch_after = 32,
            boottime_before_ns = 40,
            boottime_after_ns = 48,
            related_seq = 56,
            counter_epoch = 64,
            counter_value = 72,
            hook_id = 80,
            outcome = 88,
            kind = 92,
            reason = 96,
            flags = 100,
            reserved = 104
        );
        offset!(
            NativeClosedCounterV1,
            epoch = 0,
            ordinary_drops = 8,
            overflow = 16,
            reserved = 24
        );
        let event = NativePublicationEventV1 {
            seq: 1,
            kind: NATIVE_EVENT_INITIAL_STATE,
            reason: NativeReason::Startup as u32,
            ..NativePublicationEventV1::default()
        };
        assert!(event.is_valid(1));
        assert!(!event.is_valid(0));
        for event in [
            NativePublicationEventV1 {
                flags: 1 << 9,
                ..event
            },
            NativePublicationEventV1 { kind: 14, ..event },
            NativePublicationEventV1 {
                reason: 15,
                ..event
            },
            NativePublicationEventV1 {
                outcome: 3,
                ..event
            },
            NativePublicationEventV1 {
                reserved: [1; 24],
                ..event
            },
            NativePublicationEventV1 {
                kind: NATIVE_EVENT_WRITER_OUTCOME,
                ..event
            },
        ] {
            assert!(!event.is_valid(1));
        }
        let counter = NativeClosedCounterV1::default();
        assert!(counter.is_valid(0));
        assert!(!counter.is_valid(2));
        assert!(
            !NativeClosedCounterV1 {
                reserved: 1,
                ..counter
            }
            .is_valid(0)
        );
        assert!(
            !NativeClosedCounterV1 {
                overflow: 2,
                ..counter
            }
            .is_valid(0)
        );
        assert_eq!(event.reserved, [0; 24]);
        assert_eq!(counter.reserved, 0);
        for epoch in [0, 2, 510, 512, u64::MAX - 1] {
            for hook in 0..2 {
                let index = native_closed_counter_index(epoch, hook).unwrap();
                assert!(index < NATIVE_COUNTER_FAULT_INDEX);
                assert_eq!(index & 1, hook);
                assert_eq!(
                    native_closed_counter_index(epoch.wrapping_add(512), hook),
                    Some(index)
                );
            }
        }
        assert_eq!(native_closed_counter_index(1, 0), None);
        assert_eq!(native_closed_counter_index(0, 2), None);
        assert_eq!(core::mem::size_of::<NativeReason>(), 4);
        assert_eq!(NativeReason::AccountingFailure as u32, 14);
    }

    #[test]
    fn native_program_replacement_event_pins_hook_program_ids_and_outcomes() {
        assert_eq!(NATIVE_EVENT_PROGRAM_REPLACED, 13);
        for outcome in [
            NATIVE_OUTCOME_PENDING,
            NATIVE_OUTCOME_COMMITTED,
            NATIVE_OUTCOME_FAILED,
        ] {
            let event = NativePublicationEventV1 {
                seq: 7,
                operation_id: 8,
                hook_id: 9,
                counter_value: 101,
                counter_epoch: 102,
                kind: NATIVE_EVENT_PROGRAM_REPLACED,
                outcome,
                ..NativePublicationEventV1::default()
            };
            assert!(event.is_valid(NATIVE_PUBLICATION_VERSION));
            assert_eq!(event.hook_id, 9);
            assert_eq!(event.counter_value, 101);
            assert_eq!(event.counter_epoch, 102);
            assert_eq!(event.outcome, outcome);
            assert_eq!(event.reserved, [0; 24]);
            for kind in [14, u32::MAX] {
                assert!(
                    !NativePublicationEventV1 { kind, ..event }
                        .is_valid(NATIVE_PUBLICATION_VERSION)
                );
            }
        }
    }

    #[test]
    fn native_completed_event_kinds_reject_pending_outcomes() {
        for kind in [
            NATIVE_EVENT_CLOSE_STORED,
            NATIVE_EVENT_CLOSE_DRAINED,
            NATIVE_EVENT_WRITER_OUTCOME,
            NATIVE_EVENT_REOPEN_STORED,
            NATIVE_EVENT_CLOSED_COUNTS_FINAL,
            NATIVE_EVENT_TERMINAL_STATE,
            NATIVE_EVENT_COLLECTION_END,
        ] {
            let event = NativePublicationEventV1 {
                seq: 1,
                kind,
                reason: NativeReason::Policy as u32,
                ..NativePublicationEventV1::default()
            };
            assert!(!event.is_valid(NATIVE_PUBLICATION_VERSION), "kind={kind}");
            for outcome in [NATIVE_OUTCOME_COMMITTED, NATIVE_OUTCOME_FAILED] {
                assert!(
                    NativePublicationEventV1 { outcome, ..event }
                        .is_valid(NATIVE_PUBLICATION_VERSION),
                    "kind={kind} outcome={outcome}"
                );
            }
        }
    }

    #[test]
    fn native_claim_udp_expiry_uses_monotonic_activity() {
        let last_seen = 10_000_000_000;
        let timeout = crate::conn::UDP_CONN_STATE_TIMEOUT_NS;
        assert!(!native_claim_udp_expired(last_seen, last_seen - 1));
        assert!(!native_claim_udp_expired(last_seen, last_seen + timeout));
        assert!(native_claim_udp_expired(last_seen, last_seen + timeout + 1));
        assert!(!native_claim_udp_expired(
            last_seen + 2_000_000_000,
            last_seen + timeout + 1,
        ));
    }

    #[test]
    fn metadata_layout_and_version_are_fixed() {
        assert_eq!(core::mem::size_of::<PacketMetadata>(), METADATA_LEN);
        assert_eq!(core::mem::offset_of!(PacketMetadata, ingress_ifindex), 12);
        assert_eq!(core::mem::offset_of!(PacketMetadata, vlan_proto), 24);
        assert_eq!(core::mem::offset_of!(PacketMetadata, vlan_count), 28);
        assert_eq!(core::mem::offset_of!(PacketMetadata, inline_vlan_count), 30);
        assert_eq!(core::mem::size_of::<CaptureAuthority>(), 40);
        assert_eq!(core::mem::size_of::<NativeRoot>(), 16);
        assert_eq!(core::mem::size_of::<NativeKey>(), 56);
        assert_eq!(
            core::mem::size_of::<NativeClaim>(),
            NATIVE_CLAIM_VALUE_BYTES
        );
        assert_eq!(core::mem::size_of::<NativeScratch>(), 408);
        assert_eq!(core::mem::size_of::<NativeImport>(), NATIVE_IMPORT_LEN);
        let authority = CaptureAuthority {
            namespace_cookie: 1,
            attachment_generation: 2,
            scope: 3,
            config_generation: 0,
            ifindex: 4,
            reserved: 0,
        };
        assert!(authority.is_valid());
        assert!(
            !CaptureAuthority {
                attachment_generation: 0,
                ..authority
            }
            .is_valid()
        );
        let mut bytes = [0; METADATA_LEN];
        bytes[..2].copy_from_slice(&METADATA_VERSION.to_ne_bytes());
        bytes[2..4].copy_from_slice(&(METADATA_LEN as u16).to_ne_bytes());
        assert!(PacketMetadata::decode(&bytes).is_some());
        let mut old = bytes;
        old[..2].copy_from_slice(&1u16.to_ne_bytes());
        assert!(PacketMetadata::decode(&old).is_none());
        bytes[28] = 1;
        assert!(PacketMetadata::decode(&bytes).is_none());
    }
}
