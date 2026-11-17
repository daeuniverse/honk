//! Host-only, native-endian source snapshots. A packet receipt is not a transport lease.

use crate::conn::FlowMapValue;

pub const HOST_SOURCE_LOCAL: u32 = 1;
pub const HOST_PROCESS_PRESENT: u32 = 2;
pub const HOST_SOURCE_FLAGS: u32 = HOST_SOURCE_LOCAL | HOST_PROCESS_PRESENT;
pub const HOST_STAGE_TCX_EGRESS: u16 = 1;
pub const HOST_STAGE_TUN_EGRESS: u16 = 2;
pub const HOST_METADATA_VERSION: u16 = 1;
pub const HOST_METADATA_LEN: usize = 128;
pub const HOST_RETURN_LEN: usize = 40;
pub const HOST_CAPTURE_HORIZON_NS: u64 = 2_000_000_000;
pub const HOST_ID_MAX: u64 = (1 << 48) - 1;
pub const HOST_FACT_SLOTS: usize = 262_144;
pub const HOST_SOCKET_BUCKETS: usize = 8192;
pub const HOST_SOCKET_WAYS: usize = 8;
pub const HOST_SOCKET_PROCESS_PRESENT: u32 = 1;
pub const HOST_SOCKET_UNSELECTED: u32 = 0;
pub const HOST_SOCKET_CANDIDATE: u32 = 1;
pub const HOST_SOCKET_KERNEL: u32 = 2;
pub const HOST_SOCKET_TRANSITION: u32 = 4;
pub const HOST_SOCKET_ENDPOINT: u32 = 3;
pub const HOST_SOCKET_BORN_NEW: u32 = 5;
pub const HOST_REPRESENTATION_MATERIALIZED: u32 = 1;
pub const HOST_REPRESENTATION_GSO: u32 = 2;
pub const HOST_REPRESENTATION_FLAGS: u32 =
    HOST_REPRESENTATION_MATERIALIZED | HOST_REPRESENTATION_GSO;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HostSourceFacts {
    pub netns_cookie: u64,
    pub attachment: u64,
    pub socket_cookie: u64,
    pub return_generation: u64,
    pub output_ifindex: u32,
    pub skb_mark: u32,
    pub socket_mark: u32,
    pub pid: u32,
    pub pname: [u8; 16],
    pub flags: u32,
    pub stage: u16,
    pub family: u16,
    /// Frozen socket-executor selection, not a per-connect or per-packet counter.
    pub operation_incarnation: u64,
}

impl HostSourceFacts {
    pub fn is_valid(&self) -> bool {
        self.netns_cookie != 0
            && self.attachment != 0
            && self.socket_cookie != 0
            && self.return_generation != 0
            && self.output_ifindex != 0
            && self.operation_incarnation != 0
            && self.operation_incarnation <= HOST_ID_MAX
            && self.flags & HOST_SOURCE_LOCAL != 0
            && self.flags & !HOST_SOURCE_FLAGS == 0
            && matches!(self.stage, HOST_STAGE_TCX_EGRESS | HOST_STAGE_TUN_EGRESS)
            && matches!(self.family, 2 | 10)
            && (self.flags & HOST_PROCESS_PRESENT != 0 || (self.pid == 0 && self.pname == [0; 16]))
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostReceipt {
    pub id: u64,
    pub captured_ns: u64,
    pub expires_ns: u64,
}

impl HostReceipt {
    pub fn admits(self, now_ns: u64) -> bool {
        self.id != 0
            && self.id <= HOST_ID_MAX
            && self.captured_ns <= now_ns
            && self.expires_ns.checked_sub(self.captured_ns) == Some(HOST_CAPTURE_HORIZON_NS)
            && now_ns < self.expires_ns
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostPacketMetadata {
    pub magic: [u8; 4],
    pub version: u16,
    pub length: u16,
    pub receipt: HostReceipt,
    pub facts: HostSourceFacts,
    pub original_l3_len: u32,
    pub gso_size: u32,
    pub gso_segs: u32,
    pub representation: u32,
}

impl HostPacketMetadata {
    /// Decode only a complete Host envelope; authority still comes from its owned port.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; HOST_METADATA_LEN] = bytes.try_into().ok()?;
        let u16_at = |i| u16::from_ne_bytes([bytes[i], bytes[i + 1]]);
        let u32_at = |i| u32::from_ne_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let u64_at = |i| {
            u64::from_ne_bytes([
                bytes[i],
                bytes[i + 1],
                bytes[i + 2],
                bytes[i + 3],
                bytes[i + 4],
                bytes[i + 5],
                bytes[i + 6],
                bytes[i + 7],
            ])
        };
        let mut pname = [0; 16];
        pname.copy_from_slice(&bytes[80..96]);
        let value = Self {
            magic: bytes[..4].try_into().ok()?,
            version: u16_at(4),
            length: u16_at(6),
            receipt: HostReceipt {
                id: u64_at(8),
                captured_ns: u64_at(16),
                expires_ns: u64_at(24),
            },
            facts: HostSourceFacts {
                netns_cookie: u64_at(32),
                attachment: u64_at(40),
                socket_cookie: u64_at(48),
                return_generation: u64_at(56),
                output_ifindex: u32_at(64),
                skb_mark: u32_at(68),
                socket_mark: u32_at(72),
                pid: u32_at(76),
                pname,
                flags: u32_at(96),
                stage: u16_at(100),
                family: u16_at(102),
                operation_incarnation: u64_at(104),
            },
            original_l3_len: u32_at(112),
            gso_size: u32_at(116),
            gso_segs: u32_at(120),
            representation: u32_at(124),
        };
        (value.magic == *b"HXH1"
            && value.version == HOST_METADATA_VERSION
            && usize::from(value.length) == HOST_METADATA_LEN
            && value.facts.is_valid()
            && value.facts.stage == HOST_STAGE_TCX_EGRESS
            && value.representation & !HOST_REPRESENTATION_FLAGS == 0
            && value.representation & HOST_REPRESENTATION_MATERIALIZED != 0
            // Socket AF_INET6 can emit IPv4; the owned decoder checks wire-family extent.
            && value.original_l3_len >= 20)
            .then_some(value)
    }
}

/// One stable bucket entry. Socket addresses remain kernel-private cleanup discriminators.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostSocketEntry {
    pub cookie: u64,
    pub socket_address: u64,
    pub pid: u32,
    pub pname: [u8; 16],
    pub flags: u32,
    pub operation_incarnation: u64,
    pub disconnect_generation: u32,
    pub selection: u32,
    pub output_ifindex: u32,
    pub reserved: u32,
}

/// Lock-free mmap payload. Version belongs to the bucket, not any socket occupant.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostSocketPayload {
    pub version: u64,
    pub value: [HostSocketEntry; HOST_SOCKET_WAYS],
}

/// Writer serialization lives outside the filter-readable payload map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostSocketLock {
    pub lock: aya_ebpf_bindings::bindings::bpf_spin_lock,
    pub padding: u32,
}
pub type HostSequence = FlowMapValue<u64>;
pub type HostFactSlot = FlowMapValue<HostPacketMetadata>;

/// Immutable device generation, shared by source selection and the reverse terminal.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostReturnDevice {
    pub generation: u64,
    pub ifindex: u32,
    pub flags: u32,
    pub mac: [u8; 6],
    pub peer_mac: [u8; 6],
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostReturnContext {
    pub magic: [u8; 4],
    pub version: u16,
    pub length: u16,
    pub direction: u32,
    pub family: u32,
    pub attachment: u64,
    pub generation: u64,
    pub target: u32,
    pub l3_len: u32,
}

impl HostReturnContext {
    pub fn encode(self, output: &mut [u8]) -> Option<()> {
        let output = output.get_mut(..HOST_RETURN_LEN)?;
        output[..4].copy_from_slice(&self.magic);
        output[4..6].copy_from_slice(&self.version.to_ne_bytes());
        output[6..8].copy_from_slice(&self.length.to_ne_bytes());
        output[8..12].copy_from_slice(&self.direction.to_ne_bytes());
        output[12..16].copy_from_slice(&self.family.to_ne_bytes());
        output[16..24].copy_from_slice(&self.attachment.to_ne_bytes());
        output[24..32].copy_from_slice(&self.generation.to_ne_bytes());
        output[32..36].copy_from_slice(&self.target.to_ne_bytes());
        output[36..40].copy_from_slice(&self.l3_len.to_ne_bytes());
        Some(())
    }
}

// Every shared payload has explicit fields covering its complete C layout.
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for HostSourceFacts {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for HostReceipt {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for HostPacketMetadata {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for HostSocketEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for HostSocketPayload {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for HostSocketLock {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for HostSequence {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for HostFactSlot {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for HostReturnDevice {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for HostReturnContext {}

const _: () = assert!(core::mem::size_of::<HostSourceFacts>() == 80);
const _: () = assert!(core::mem::offset_of!(HostSourceFacts, pid) == 44);
const _: () = assert!(core::mem::offset_of!(HostSourceFacts, flags) == 64);
const _: () = assert!(core::mem::offset_of!(HostSourceFacts, operation_incarnation) == 72);
const _: () = assert!(core::mem::size_of::<HostReceipt>() == 24);
const _: () = assert!(core::mem::size_of::<HostPacketMetadata>() == HOST_METADATA_LEN);
const _: () = assert!(core::mem::offset_of!(HostPacketMetadata, facts) == 32);
const _: () = assert!(core::mem::offset_of!(HostPacketMetadata, original_l3_len) == 112);
const _: () = assert!(core::mem::size_of::<HostFactSlot>() == 136);
const _: () = assert!(core::mem::size_of::<HostSocketEntry>() == 64);
const _: () = assert!(core::mem::size_of::<HostSocketPayload>() == 520);
const _: () = assert!(core::mem::align_of::<HostSocketPayload>() == 8);
const _: () = assert!(core::mem::offset_of!(HostSocketPayload, version) == 0);
const _: () = assert!(core::mem::offset_of!(HostSocketPayload, value) == 8);
const _: () = assert!(core::mem::size_of::<HostSocketLock>() == 8);
const _: () = assert!(core::mem::offset_of!(HostSocketLock, lock) == 0);
const _: () = assert!(core::mem::offset_of!(HostSocketLock, padding) == 4);
const _: () = assert!(core::mem::size_of::<HostSequence>() == 16);
const _: () = assert!(core::mem::size_of::<HostReturnDevice>() == 32);
const _: () = assert!(core::mem::size_of::<HostReturnContext>() == HOST_RETURN_LEN);

/// Cold BTF-admitted offsets for the locked TCP pre-connect drain gate.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostConnectLayout {
    pub valid: u32,
    pub state: u32,
    pub lock_owned: u32,
    pub wmem_alloc: u32,
    pub refcnt: u32,
    pub write_queue_len: u32,
    pub rtx_root: u32,
    pub send_head: u32,
    pub backlog_head: u32,
    pub disconnect_generation: u32,
    pub socket_mark: u32,
    pub reserved: u32,
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for HostConnectLayout {}
const _: () = assert!(core::mem::size_of::<HostConnectLayout>() == 48);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_expiry_is_exact_and_nonwrapping() {
        let receipt = HostReceipt {
            id: HOST_ID_MAX,
            captured_ns: 10,
            expires_ns: 10 + HOST_CAPTURE_HORIZON_NS,
        };
        assert!(!receipt.admits(9));
        assert!(receipt.admits(10));
        assert!(receipt.admits(receipt.expires_ns - 1));
        assert!(!receipt.admits(receipt.expires_ns));
        assert!(
            !HostReceipt {
                id: HOST_ID_MAX + 1,
                ..receipt
            }
            .admits(10)
        );
        assert!(
            !HostReceipt {
                expires_ns: 9,
                ..receipt
            }
            .admits(10)
        );
    }

    #[test]
    fn host_metadata_does_not_accept_transit_or_missing_source() {
        assert!(HostPacketMetadata::decode(&[0; 32]).is_none());
        assert!(HostPacketMetadata::decode(&[0; HOST_METADATA_LEN]).is_none());
        assert!(!HostSourceFacts::default().is_valid());
    }

    #[test]
    fn full_host_snapshot_keeps_selection_and_receipt_independent() {
        let mut bytes = [0u8; HOST_METADATA_LEN];
        bytes[..4].copy_from_slice(b"HXH1");
        bytes[4..6].copy_from_slice(&HOST_METADATA_VERSION.to_ne_bytes());
        bytes[6..8].copy_from_slice(&(HOST_METADATA_LEN as u16).to_ne_bytes());
        for (offset, value) in [
            (8, 7u64),
            (16, 100),
            (24, 100 + HOST_CAPTURE_HORIZON_NS),
            (32, 11),
            (40, 12),
            (48, 13),
            (56, 14),
            (104, 15),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
        for (offset, value) in [
            (64, 16u32),
            (96, HOST_SOURCE_LOCAL),
            (112, 1500),
            (124, HOST_REPRESENTATION_MATERIALIZED),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        bytes[100..102].copy_from_slice(&HOST_STAGE_TCX_EGRESS.to_ne_bytes());
        bytes[102..104].copy_from_slice(&2u16.to_ne_bytes());
        let snapshot = HostPacketMetadata::decode(&bytes).unwrap();
        assert_eq!(snapshot.facts.operation_incarnation, 15);
        assert_eq!(snapshot.receipt.id, 7);
        assert!(snapshot.receipt.admits(100));
        assert!(!snapshot.receipt.admits(100 + HOST_CAPTURE_HORIZON_NS));
        assert!(snapshot.facts.is_valid());

        let tun_facts = HostSourceFacts {
            stage: HOST_STAGE_TUN_EGRESS,
            ..snapshot.facts
        };
        assert!(tun_facts.is_valid());
        bytes[100..102].copy_from_slice(&HOST_STAGE_TUN_EGRESS.to_ne_bytes());
        assert!(HostPacketMetadata::decode(&bytes).is_none());
        bytes[100..102].copy_from_slice(&HOST_STAGE_TCX_EGRESS.to_ne_bytes());

        bytes[76..80].copy_from_slice(&42u32.to_ne_bytes());
        assert!(HostPacketMetadata::decode(&bytes).is_none());
        bytes[96..100].copy_from_slice(&HOST_SOURCE_FLAGS.to_ne_bytes());
        assert_eq!(HostPacketMetadata::decode(&bytes).unwrap().facts.pid, 42);
        bytes[102..104].copy_from_slice(&10u16.to_ne_bytes());
        bytes[112..116].copy_from_slice(&28u32.to_ne_bytes());
        assert!(HostPacketMetadata::decode(&bytes).is_some());
        bytes[104..112].copy_from_slice(&(HOST_ID_MAX + 1).to_ne_bytes());
        assert!(HostPacketMetadata::decode(&bytes).is_none());
    }
}
