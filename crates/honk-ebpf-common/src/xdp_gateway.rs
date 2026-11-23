//! Shared XDP gateway map keys and values.

use crate::{DomainRouting, KernelRouteOutput};

pub const GATEWAY_REALM_CAPACITY: u32 = 4096;
pub const GATEWAY_DNS_READY: i32 = 8;
pub const GATEWAY_ROUTE_NEED_DNS: i32 = 2;
/// Domain bitmap relative to the routing output, in the compiler's map-backed frame.
pub const GATEWAY_DNS_BITMAP_OFFSET: usize =
    core::mem::offset_of!(KernelRouteOutput, input) + 3 * size_of::<DomainRouting>() + 32 + 16;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct GatewayDnsKey {
    pub export_epoch: u64,
    pub realm_id: u32,
    pub reserved: u32,
    pub canonical_dst: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GatewayDnsValue {
    pub valid_before_mono_ns: u64,
    pub bitmap: DomainRouting,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct CaptureRealmKey {
    pub physical_ifindex: u32,
    pub vlan_count: u32,
    pub tpid: [u16; 2],
    pub vid: [u16; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct GatewayKey {
    pub realm_id: u32,
    /// IP version: 4 or 6; IPv4 addresses use the mapped IPv6 representation.
    pub family: u32,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EndpointHold {
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

pub const HOLD_REFRESH_NS: u64 = 1_000_000_000;
pub const HOLD_IDLE_NS: u64 = 30_000_000_000;
pub const FRAGMENT_TTL_NS: u64 = 30_000_000_000;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct LocalAddressKey {
    /// IP version: 4 or 6, matching GatewayKey.
    pub family: u32,
    pub address: [u8; 16],
}

impl From<core::net::IpAddr> for LocalAddressKey {
    fn from(address: core::net::IpAddr) -> Self {
        match address.to_canonical() {
            core::net::IpAddr::V4(address) => Self {
                family: 4,
                address: address.to_ipv6_mapped().octets(),
            },
            core::net::IpAddr::V6(address) => Self {
                family: 6,
                address: address.octets(),
            },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct FragmentKey {
    pub realm_id: u32,
    pub family: u32,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub id: u32,
    pub proto: u8,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FragmentVerdict {
    pub verdict: u32,
    pub reserved: u32,
    pub ktime_ns: u64,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayReason {
    PassNonTransport,
    PassLocal,
    XskEndpointHold,
    PassCtOriginal,
    PassCtReply,
    PassFragment,
    XskFragment,
    PassTcpNonSynMiss,
    PassD1,
    XskNewFlow,
    UnclassifiableHeader,
    UnknownRealm,
    HoldInsertFailed,
    CtLookupError,
    FragmentMiss,
    FragmentVerdictInsertFailed,
    IcmpQuoteUnresolved,
    D1Evaluated,
    WouldPassDns,
}

pub const GATEWAY_REASON_COUNT: u32 = GatewayReason::WouldPassDns as u32 + 1;

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<GatewayDnsKey>() == 32);
    assert!(offset_of!(GatewayDnsKey, realm_id) == 8);
    assert!(offset_of!(GatewayDnsKey, reserved) == 12);
    assert!(offset_of!(GatewayDnsKey, canonical_dst) == 16);
    assert!(size_of::<GatewayDnsValue>() == 40);
    assert!(offset_of!(GatewayDnsValue, bitmap) == 8);
    assert!(size_of::<CaptureRealmKey>() == 16);
    assert!(offset_of!(CaptureRealmKey, physical_ifindex) == 0);
    assert!(offset_of!(CaptureRealmKey, vlan_count) == 4);
    assert!(offset_of!(CaptureRealmKey, tpid) == 8);
    assert!(offset_of!(CaptureRealmKey, vid) == 12);
    assert!(size_of::<GatewayKey>() == 48);
    assert!(offset_of!(GatewayKey, realm_id) == 0);
    assert!(offset_of!(GatewayKey, family) == 4);
    assert!(offset_of!(GatewayKey, src) == 8);
    assert!(offset_of!(GatewayKey, dst) == 24);
    assert!(offset_of!(GatewayKey, sport) == 40);
    assert!(offset_of!(GatewayKey, dport) == 42);
    assert!(offset_of!(GatewayKey, proto) == 44);
    assert!(offset_of!(GatewayKey, reserved) == 45);
    assert!(size_of::<EndpointHold>() == 16);
    assert!(offset_of!(EndpointHold, last_seen_ns) == 8);
    assert!(size_of::<LocalAddressKey>() == 20);
    assert!(size_of::<FragmentKey>() == 48);
    assert!(offset_of!(FragmentKey, id) == 40);
    assert!(offset_of!(FragmentKey, proto) == 44);
    assert!(size_of::<FragmentVerdict>() == 16);
    assert!(offset_of!(FragmentVerdict, ktime_ns) == 8);
};

// SAFETY: The layout assertions exclude implicit padding; every leaf is an integer.
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for CaptureRealmKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for GatewayKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for EndpointHold {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for LocalAddressKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for FragmentKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for FragmentVerdict {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_address_keys_share_gateway_ip_version_and_mapped_v4() {
        let v4: core::net::IpAddr = "192.0.2.1".parse().unwrap();
        let key = LocalAddressKey::from(v4);
        assert_eq!(key.family, 4);
        assert_eq!(
            key.address,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 1]
        );
        assert_eq!(
            key,
            LocalAddressKey::from("::ffff:192.0.2.1".parse::<core::net::IpAddr>().unwrap())
        );
        let v6: core::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(LocalAddressKey::from(v6).family, 6);
    }
}
