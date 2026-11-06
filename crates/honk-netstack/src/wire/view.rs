//! Borrowed packet segments; headers may be staged, payload stays in backend storage.

use super::{IpPacket, ParseError, checksum::Checksum};
use std::ops::Range;

#[derive(Clone, Copy)]
enum Storage<'a> {
    One(&'a [u8]),
    Many(&'a [&'a [u8]]),
}

#[derive(Clone, Copy)]
pub struct PacketView<'a> {
    storage: Storage<'a>,
    len: usize,
}

impl<'a> PacketView<'a> {
    pub fn new(segments: &'a [&'a [u8]]) -> Result<Self, ParseError> {
        if segments.is_empty() || segments.len() > 64 {
            return Err(ParseError::Malformed);
        }
        let len = segments
            .iter()
            .try_fold(0usize, |len, segment| len.checked_add(segment.len()))
            .ok_or(ParseError::Malformed)?;
        Ok(Self {
            storage: Storage::Many(segments),
            len,
        })
    }

    pub fn from_slice(bytes: &'a [u8]) -> Self {
        Self {
            storage: Storage::One(bytes),
            len: bytes.len(),
        }
    }
    pub fn len(self) -> usize {
        self.len
    }
    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn visit(self, range: Range<usize>, mut visit: impl FnMut(&'a [u8])) -> Option<()> {
        if range.start > range.end || range.end > self.len {
            return None;
        }
        let mut start = range.start;
        let mut remaining = range.len();
        let mut part = |bytes: &'a [u8]| {
            if start >= bytes.len() {
                start -= bytes.len();
                return;
            }
            let count = remaining.min(bytes.len() - start);
            if count != 0 {
                visit(&bytes[start..start + count]);
                remaining -= count;
            }
            start = 0;
        };
        match self.storage {
            Storage::One(bytes) => part(bytes),
            Storage::Many(segments) => {
                for &bytes in segments {
                    part(bytes);
                }
            }
        }
        (remaining == 0).then_some(())
    }

    pub fn copy_to(self, range: Range<usize>, out: &mut [u8]) -> Option<()> {
        if out.len() != range.len() {
            return None;
        }
        let mut offset = 0;
        self.visit(range, |bytes| {
            out[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len();
        })
    }

    pub fn checksum(self, range: Range<usize>, mut checksum: Checksum) -> Option<u16> {
        self.visit(range, |bytes| checksum.add(bytes))?;
        Some(checksum.finish())
    }

    pub fn validate_transport(self) -> Result<IpPacket, ParseError> {
        let ip = self.parse_ip()?;
        self.transport_ports(&ip)?;
        Ok(ip)
    }

    /// Validate complete transport bounds/checksums without linearizing the payload.
    pub fn transport_ports(self, ip: &IpPacket) -> Result<Option<(u16, u16)>, ParseError> {
        if ip.src.is_ipv4() != ip.dst.is_ipv4()
            || ip.payload.start > ip.payload.end
            || ip.payload.end > self.len
        {
            return Err(ParseError::Malformed);
        }
        let mut transport = [0; 60];
        let count = ip.payload.len().min(transport.len());
        self.copy_to(
            ip.payload.start..ip.payload.start + count,
            &mut transport[..count],
        )
        .ok_or(ParseError::Malformed)?;
        let l4 = &transport[..count];
        let mut upper_len = ip.payload.len();
        let ports = match ip.proto {
            super::PROTO_TCP => {
                let (header, _) = super::tcp::parse(l4)?;
                Some((header.src_port, header.dst_port))
            }
            super::PROTO_UDP => {
                let (source, destination, payload) =
                    super::udp::parse_prefix(l4, ip.payload.len())?;
                upper_len = payload.end;
                Some((source, destination))
            }
            super::PROTO_ICMP if ip.src.is_ipv4() && l4.len() >= 8 => None,
            super::PROTO_ICMPV6 if ip.src.is_ipv6() && l4.len() >= 8 => None,
            _ => return Err(ParseError::Unsupported),
        };
        let omitted_udp = ip.proto == super::PROTO_UDP && l4[6..8] == [0, 0];
        if omitted_udp {
            if ip.src.is_ipv6() {
                return Err(ParseError::Checksum);
            }
        } else {
            let checksum = if ip.proto == super::PROTO_ICMP {
                Checksum::new()
            } else {
                Checksum::pseudo(ip.src, ip.dst, ip.proto, upper_len)
            };
            if self.checksum(ip.payload.start..ip.payload.start + upper_len, checksum) != Some(0) {
                return Err(ParseError::Checksum);
            }
        }
        Ok(ports)
    }

    pub fn parse_ip(self) -> Result<IpPacket, ParseError> {
        let mut prefix = [0; 60];
        let count = self.len.min(prefix.len());
        self.copy_to(0..count, &mut prefix[..count])
            .ok_or(ParseError::Malformed)?;
        match prefix
            .first()
            .filter(|_| count != 0)
            .ok_or(ParseError::Malformed)?
            >> 4
        {
            4 => super::ipv4::parse_prefix(&prefix[..count], self.len),
            6 => match super::ipv6::parse_prefix(&prefix[..count.min(40)], self.len) {
                Err(ParseError::Malformed) if count >= 40 && matches!(prefix[6], 0 | 43 | 60) => {
                    self.extended_ipv6(&prefix[..40])
                }
                result => result,
            },
            _ => Err(ParseError::Unsupported),
        }
    }

    // Keep the large, bounded extension scratch out of ordinary packet stack frames.
    #[inline(never)]
    fn extended_ipv6(self, base: &[u8]) -> Result<IpPacket, ParseError> {
        const MAX_HEADER: usize = 40 + 8 * 2048;
        let mut prefix = [0; MAX_HEADER];
        prefix[..40].copy_from_slice(base);
        let mut count = 40;
        loop {
            let next = (count + 8).min(self.len).min(MAX_HEADER);
            if next == count {
                return Err(ParseError::Malformed);
            }
            self.copy_to(count..next, &mut prefix[count..next])
                .ok_or(ParseError::Malformed)?;
            count = next;
            match super::ipv6::parse_prefix(&prefix[..count], self.len) {
                Err(ParseError::Malformed) => {}
                result => return result,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::testutil::*;
    use crate::wire::{self, udp};
    use std::net::SocketAddr;

    fn packet(ipv6: bool, payload: &[u8], trailing: usize) -> Vec<u8> {
        let (src, dst) = if ipv6 {
            (v6(1), v6(2))
        } else {
            (v4(192, 0, 2, 1), v4(198, 51, 100, 2))
        };
        let mut bytes = vec![0; 100 + payload.len()];
        let len = udp::emit_packet(
            &mut bytes,
            SocketAddr::new(src, 12345),
            SocketAddr::new(dst, 53),
            payload,
        )
        .unwrap();
        wire::emit_ip_header(
            &mut bytes,
            src,
            dst,
            wire::PROTO_UDP,
            8 + payload.len() + trailing,
        )
        .unwrap();
        bytes[len..len + trailing].fill(0xA7);
        bytes[len + trailing..len + trailing + 7].fill(0xD9);
        bytes.truncate(len + trailing + 7);
        bytes
    }

    fn assert_transport(bytes: &[u8], expected: Result<Option<(u16, u16)>, ParseError>) {
        let ip = wire::parse_ip(bytes).unwrap();
        let check = |view: PacketView<'_>| {
            assert_eq!(view.transport_ports(&ip), expected);
            assert_eq!(view.validate_transport(), expected.map(|_| ip.clone()));
        };
        check(PacketView::from_slice(bytes));
        for split in 0..=bytes.len() {
            let segments = [&bytes[..split], &[], &bytes[split..]];
            check(PacketView::new(&segments).unwrap());
        }
        for size in [3, 7, 11, 31, 60] {
            let segments: Vec<_> = bytes.chunks(size).collect();
            check(PacketView::new(&segments).unwrap());
        }
    }

    #[test]
    fn udp_declared_length_bounds_checksum_across_scatter_splits() {
        for v6 in [false, true] {
            for len in [0, 1, 2, 51, 52, 53, 81] {
                for trailing in [0, 5] {
                    let payload = Rng::new(len as u64 + 1).bytes(len);
                    let mut bytes = packet(v6, &payload, trailing);
                    let ip = wire::parse_ip(&bytes).unwrap();
                    let start = ip.payload.start;
                    let mut reference = pseudo_bytes(ip.src, ip.dst, wire::PROTO_UDP, 8 + len);
                    reference.extend_from_slice(&bytes[start..start + 8 + len]);
                    assert_eq!(naive_checksum(&reference), 0);
                    assert_transport(&bytes, Ok(Some((12345, 53))));
                    if trailing != 0 {
                        bytes[start + 8 + len] ^= 0x55;
                        assert_transport(&bytes, Ok(Some((12345, 53))));
                    }
                    bytes[start + 6..start + 8].fill(0);
                    assert_transport(
                        &bytes,
                        if v6 {
                            Err(ParseError::Checksum)
                        } else {
                            Ok(Some((12345, 53)))
                        },
                    );
                }
            }
        }
    }

    #[test]
    fn udp_declared_length_rejects_short_overlength_and_corrupt_payload() {
        for v6 in [false, true] {
            let bytes = packet(v6, b"abc", 5);
            assert_transport(&bytes, Ok(Some((12345, 53))));
            let ip = wire::parse_ip(&bytes).unwrap();
            for declared in (0..8).chain([ip.payload.len() + 1, ip.payload.len() + 7]) {
                let mut bad = bytes.clone();
                bad[ip.payload.start + 4..ip.payload.start + 6]
                    .copy_from_slice(&(declared as u16).to_be_bytes());
                assert_transport(&bad, Err(ParseError::Malformed));
            }
            let mut bad = bytes.clone();
            bad[ip.payload.start + 8] ^= 1;
            assert_transport(&bad, Err(ParseError::Checksum));
            for len in 0..8 {
                let mut short = bytes.clone();
                wire::emit_ip_header(&mut short, ip.src, ip.dst, wire::PROTO_UDP, len).unwrap();
                assert_transport(&short, Err(ParseError::Malformed));
            }
        }
    }
}
