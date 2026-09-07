//! BPF map utilities for honk-core.
//!
//! This module provides LPM trie helpers and common utility functions used
//! by both real and mock eBPF backends. It does not depend on `aya`
//! directly, making it usable by all backends regardless of whether real
//! eBPF support is compiled in.

pub use honk_ebpf_common::LpmKey;

/// Convert an already-validated [`ipnet::IpNet`] directly into its LPM key.
///
/// Preserve the supplied address bytes, including host bits, without a CIDR
/// string roundtrip. IPv4 keys use the mapped representation and +96 prefix.
pub fn ipnet_to_lpm_key(net: &ipnet::IpNet) -> LpmKey {
    let mut key = ip_addr_to_lpm_key(net.addr());
    key.prefix_len = match net {
        ipnet::IpNet::V4(net) => net.prefix_len() as u32 + 96,
        ipnet::IpNet::V6(net) => net.prefix_len() as u32,
    };
    key
}

/// Convert an IP address into the exact host-prefix key used by the domain
/// routing LPM map without formatting or parsing a temporary CIDR string.
pub const fn ip_addr_to_lpm_key(ip: std::net::IpAddr) -> LpmKey {
    let (prefix_len, bytes) = match ip {
        std::net::IpAddr::V4(ip) => (128, ip.to_ipv6_mapped().octets()),
        std::net::IpAddr::V6(ip) => (128, ip.octets()),
    };
    LpmKey {
        prefix_len,
        data: [
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        ],
    }
}

/// Encode an [`LpmKey`] as its raw 20-byte map-key form: the native-order
/// `prefix_len` followed by the 16-byte address data.  This matches the
/// `#[repr(C)]` layout the kernel uses for LPM trie keys and lets the
/// routing push plan and the backends use the encoding as a `HashMap` key
/// (`LpmKey` itself does not implement `Hash`/`Eq`).
pub fn lpm_key_bytes(key: &LpmKey) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0..4].copy_from_slice(&key.prefix_len.to_ne_bytes());
    for (i, word) in key.data.iter().enumerate() {
        buf[4 + i * 4..8 + i * 4].copy_from_slice(&word.to_ne_bytes());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipnet_to_lpm_key_ipv4_class_a() {
        let net = "10.0.0.0/8".parse().unwrap();
        let key = ipnet_to_lpm_key(&net);
        assert_eq!(key.prefix_len, 104); // 8 + 96
        // ::ffff:10.0.0.0 → last 4 bytes = [0x0a, 0x00, 0x00, 0x00]
        // Stored as little-endian u32 chunks so memory bytes are network order.
        assert_eq!(key.data[0], 0x00000000);
        assert_eq!(key.data[1], 0x00000000);
        assert_eq!(key.data[2], 0xffff0000);
        assert_eq!(key.data[3], 0x0000000a);
    }

    #[test]
    fn test_ipnet_to_lpm_key_ipv4_host() {
        let net = "1.2.3.4/32".parse().unwrap();
        let key = ipnet_to_lpm_key(&net);
        assert_eq!(key.prefix_len, 128); // 32 + 96
        assert_eq!(key.data[3], 0x04030201);
    }

    #[test]
    fn test_ipnet_to_lpm_key_ipv6() {
        let net = "2001:db8::/32".parse().unwrap();
        let key = ipnet_to_lpm_key(&net);
        assert_eq!(key.prefix_len, 32); // no +96 shift
        // 2001:0db8:0000:... first 4 bytes = [0x20, 0x01, 0x0d, 0xb8]
        assert_eq!(key.data[0], 0xb80d0120);
        assert_eq!(key.data[1], 0x00000000);
        assert_eq!(key.data[2], 0x00000000);
        assert_eq!(key.data[3], 0x00000000);
    }
}
