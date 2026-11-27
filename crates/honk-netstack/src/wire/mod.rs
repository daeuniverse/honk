//! Packet codecs shared by the stack: IP, TCP, UDP, ICMP and the Internet checksum.

use std::net::IpAddr;
use std::ops::Range;

pub mod checksum;
pub(crate) mod frag;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;
mod view;
pub use view::PacketView;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("malformed packet")]
    Malformed,
    #[error("bad checksum")]
    Checksum,
    #[error("fragmented packet")]
    Fragment,
    #[error("unsupported packet")]
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPacket {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dscp: u8,
    /// Upper-layer protocol after any IPv6 extension headers.
    pub proto: u8,
    pub hop_limit: u8,
    /// Upper-layer bytes within the input; excludes link-layer padding past the IP length.
    pub payload: Range<usize>,
}

pub fn parse_ip(pkt: &[u8]) -> Result<IpPacket, ParseError> {
    match pkt.first().ok_or(ParseError::Malformed)? >> 4 {
        4 => ipv4::parse(pkt),
        6 => ipv6::parse(pkt),
        _ => Err(ParseError::Unsupported),
    }
}

/// Inspect IP addresses, including fragments, without granting transport checksum validity.
pub fn packet_addresses(packet: &[u8]) -> Result<(IpAddr, IpAddr), ParseError> {
    match parse_ip(packet) {
        Ok(ip) => Ok((ip.src, ip.dst)),
        Err(ParseError::Fragment) => {
            frag::parse(packet).map(|fragment| (fragment.src, fragment.dst))
        }
        Err(error) => Err(error),
    }
}

pub fn ip_header_len(v6: bool) -> usize {
    if v6 {
        ipv6::HEADER_LEN
    } else {
        ipv4::HEADER_LEN
    }
}

/// Writes a fixed-size IP header (no options, no extension headers) and returns its length.
pub fn emit_ip_header(
    buf: &mut [u8],
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    payload_len: usize,
) -> Option<usize> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => ipv4::emit(buf, s, d, proto, payload_len),
        (IpAddr::V6(s), IpAddr::V6(d)) => ipv6::emit(buf, s, d, proto, payload_len),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::net::IpAddr;

    pub struct Rng(u64);

    impl Rng {
        pub fn new(seed: u64) -> Self {
            Self(seed | 1)
        }

        pub fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        pub fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        pub fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    pub fn naive_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u64;
        for pair in data.chunks(2) {
            let hi = u64::from(pair[0]) << 8;
            let lo = u64::from(pair.get(1).copied().unwrap_or(0));
            sum += hi | lo;
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Independent byte-level pseudo header (RFC 793 / RFC 8200 §8.1).
    pub fn pseudo_bytes(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> Vec<u8> {
        let mut v = Vec::new();
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                v.extend_from_slice(&s.octets());
                v.extend_from_slice(&d.octets());
                v.extend_from_slice(&[0, proto]);
                v.extend_from_slice(&(len as u16).to_be_bytes());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                v.extend_from_slice(&s.octets());
                v.extend_from_slice(&d.octets());
                v.extend_from_slice(&(len as u32).to_be_bytes());
                v.extend_from_slice(&[0, 0, 0, proto]);
            }
            _ => unreachable!("test family mismatch"),
        }
        v
    }

    pub fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    }

    pub fn v6(last: u16) -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last))
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn parse_ip_dispatch_and_rejects() {
        assert_eq!(parse_ip(&[]), Err(ParseError::Malformed));
        assert_eq!(parse_ip(&[0x45]), Err(ParseError::Malformed));
        assert_eq!(parse_ip(&[0x65]), Err(ParseError::Malformed));
        assert_eq!(parse_ip(&[0x05; 40]), Err(ParseError::Unsupported));
        assert_eq!(parse_ip(&[0xF0; 40]), Err(ParseError::Unsupported));
    }

    #[test]
    fn fragment_addresses_do_not_require_a_transport_header() {
        let source = v4(192, 0, 2, 1);
        let destination = v4(192, 0, 2, 2);
        let mut packet = [0; 28];
        emit_ip_header(&mut packet, source, destination, PROTO_UDP, 8).unwrap();
        assert_eq!(packet_addresses(&packet), Ok((source, destination)));
        packet[6] = 0x20;
        packet[10..12].fill(0);
        let sum = checksum::checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(parse_ip(&packet), Err(ParseError::Fragment));
        assert_eq!(packet_addresses(&packet), Ok((source, destination)));
        packet[12] ^= 1;
        assert_eq!(packet_addresses(&packet), Err(ParseError::Checksum));
    }

    #[test]
    fn emit_ip_header_rejects_bad_inputs() {
        let mut buf = [0u8; 64];
        assert_eq!(
            emit_ip_header(&mut buf, v4(1, 1, 1, 1), v6(1), PROTO_UDP, 0),
            None
        );
        assert_eq!(
            emit_ip_header(&mut buf[..19], v4(1, 1, 1, 1), v4(2, 2, 2, 2), PROTO_UDP, 0),
            None
        );
        assert_eq!(
            emit_ip_header(&mut buf[..39], v6(1), v6(2), PROTO_UDP, 0),
            None
        );
        assert_eq!(
            emit_ip_header(&mut buf, v4(1, 1, 1, 1), v4(2, 2, 2, 2), PROTO_UDP, 65_516),
            None
        );
        assert_eq!(
            emit_ip_header(&mut buf, v6(1), v6(2), PROTO_UDP, 65_536),
            None
        );
    }

    #[test]
    fn emit_then_parse_roundtrip_both_families() {
        for (src, dst) in [(v4(10, 0, 0, 1), v4(10, 0, 0, 2)), (v6(1), v6(2))] {
            let mut buf = [0u8; 100];
            let hl = emit_ip_header(&mut buf, src, dst, PROTO_TCP, 12).unwrap();
            assert_eq!(hl, ip_header_len(src.is_ipv6()));
            // Trailing link padding beyond the IP length must be excluded.
            let p = parse_ip(&buf[..hl + 12 + 6]).unwrap();
            assert_eq!(p.src, src);
            assert_eq!(p.dst, dst);
            assert_eq!(p.proto, PROTO_TCP);
            assert_eq!(p.hop_limit, 64);
            assert_eq!(p.payload, hl..hl + 12);
        }
    }
}
