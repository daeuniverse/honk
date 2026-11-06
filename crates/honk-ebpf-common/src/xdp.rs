//! Native-endian XDP metadata. Static owner authority is never inferred from packet bytes.

pub const METADATA_VERSION: u16 = 2;
pub const METADATA_LEN: usize = 32;
pub const INLINE_VLAN: u32 = 1;
pub const RX_VLAN_CHECKED: u32 = 2;
pub const HIDDEN_VLAN: u32 = 4;
pub const KNOWN_FLAGS: u32 = INLINE_VLAN | RX_VLAN_CHECKED | HIDDEN_VLAN;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_layout_and_version_are_fixed() {
        assert_eq!(core::mem::size_of::<PacketMetadata>(), METADATA_LEN);
        assert_eq!(core::mem::offset_of!(PacketMetadata, ingress_ifindex), 12);
        assert_eq!(core::mem::offset_of!(PacketMetadata, vlan_proto), 24);
        assert_eq!(core::mem::offset_of!(PacketMetadata, vlan_count), 28);
        assert_eq!(core::mem::offset_of!(PacketMetadata, inline_vlan_count), 30);
        assert_eq!(core::mem::size_of::<CaptureAuthority>(), 40);
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
