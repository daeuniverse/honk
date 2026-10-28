//! IPv4 and IPv6 fragment headers: decoding one fragment and sealing a reassembled header.

use std::net::{IpAddr, Ipv4Addr};

use super::checksum::checksum;
use super::ipv6::{self, FRAGMENT_HEADER_LEN};
use super::{ParseError, ipv4};

/// One fragment of a datagram, borrowed from the received packet.
#[derive(Debug)]
pub struct Fragment<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Protocol of the reassembled datagram's upper layer (IPv6: the fragment header's next header).
    pub proto: u8,
    pub id: u32,
    /// Byte offset of `data` within the fragmentable part (a multiple of 8).
    pub offset: usize,
    pub more: bool,
    /// Header bytes before `data` as received (IPv4 header with options; IPv6 header, extension
    /// headers and the fragment header).
    pub head: &'a [u8],
    pub data: &'a [u8],
}

impl Fragment<'_> {
    pub fn is_v6(&self) -> bool {
        self.src.is_ipv6()
    }

    /// Largest fragmentable length that still fits the 16-bit length field behind `head`.
    pub fn max_total(&self) -> usize {
        if self.is_v6() {
            // The length field counts the extension headers too, but not the fixed header.
            usize::from(u16::MAX) - (self.head.len() - ipv6::HEADER_LEN - FRAGMENT_HEADER_LEN)
        } else {
            usize::from(u16::MAX) - self.head.len()
        }
    }
}

/// Decodes a fragment (IPv4 with MF or a non-zero offset; IPv6 carrying a fragment header).
/// Anything that is not a fragment is `Unsupported`.
pub fn parse(pkt: &[u8]) -> Result<Fragment<'_>, ParseError> {
    match pkt.first().ok_or(ParseError::Malformed)? >> 4 {
        4 => parse_v4(pkt),
        6 => parse_v6(pkt),
        _ => Err(ParseError::Unsupported),
    }
}

fn parse_v4(pkt: &[u8]) -> Result<Fragment<'_>, ParseError> {
    if pkt.len() < ipv4::HEADER_LEN {
        return Err(ParseError::Malformed);
    }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if ihl < ipv4::HEADER_LEN || pkt.len() < ihl || total < ihl || total > pkt.len() {
        return Err(ParseError::Malformed);
    }
    if checksum(&pkt[..ihl]) != 0 {
        return Err(ParseError::Checksum);
    }
    let field = u16::from_be_bytes([pkt[6], pkt[7]]);
    if field & 0x3FFF == 0 {
        return Err(ParseError::Unsupported);
    }
    Ok(Fragment {
        src: IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
        dst: IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
        proto: pkt[9],
        id: u32::from(u16::from_be_bytes([pkt[4], pkt[5]])),
        offset: usize::from(field & 0x1FFF) * 8,
        more: field & 0x2000 != 0,
        head: &pkt[..ihl],
        data: &pkt[ihl..total],
    })
}

fn parse_v6(pkt: &[u8]) -> Result<Fragment<'_>, ParseError> {
    if pkt.len() < ipv6::HEADER_LEN {
        return Err(ParseError::Malformed);
    }
    let end = ipv6::HEADER_LEN + usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    if end > pkt.len() || end == ipv6::HEADER_LEN {
        return Err(ParseError::Malformed);
    }
    let walk = ipv6::walk_ext_headers(pkt, ipv6::HEADER_LEN, end, pkt[6])?;
    if walk.proto != 44 {
        return Err(ParseError::Unsupported);
    }
    let h = walk.off;
    if h + FRAGMENT_HEADER_LEN > end {
        return Err(ParseError::Malformed);
    }
    let field = u16::from_be_bytes([pkt[h + 2], pkt[h + 3]]);
    let (src, dst) = ipv6::addrs(pkt);
    Ok(Fragment {
        src: IpAddr::V6(src),
        dst: IpAddr::V6(dst),
        proto: pkt[h],
        id: u32::from_be_bytes([pkt[h + 4], pkt[h + 5], pkt[h + 6], pkt[h + 7]]),
        offset: usize::from(field & 0xFFF8),
        more: field & 1 != 0,
        head: &pkt[..h + FRAGMENT_HEADER_LEN],
        data: &pkt[h + FRAGMENT_HEADER_LEN..end],
    })
}

/// Size of a complete packet after removing the fragmentation header/flags.
pub fn reassembled_len(head_len: usize, v6: bool, data_len: usize) -> Option<usize> {
    let keep = if v6 {
        head_len.checked_sub(FRAGMENT_HEADER_LEN)?
    } else {
        head_len
    };
    let minimum = if v6 {
        ipv6::HEADER_LEN
    } else {
        ipv4::HEADER_LEN
    };
    if keep < minimum || (!v6 && keep > 60) {
        return None;
    }
    let total = keep.checked_add(data_len)?;
    u16::try_from(if v6 { total - ipv6::HEADER_LEN } else { total }).ok()?;
    Some(total)
}

/// Seals a decoded fragment header and its complete payload into one exact-sized owned packet.
pub fn seal_packet(head: &[u8], v6: bool, data: &[u8]) -> Option<Box<[u8]>> {
    let total = reassembled_len(head.len(), v6, data.len())?;
    let keep = total - data.len();
    let nh_off = if v6 {
        ipv6::walk_ext_headers(head, ipv6::HEADER_LEN, keep, head[6])
            .ok()?
            .nh_off
    } else {
        0
    };
    let mut packet: Box<[u8]> = head[..keep].iter().chain(data).copied().collect();
    if v6 {
        packet[nh_off] = head[keep];
        packet[4..6].copy_from_slice(&((total - ipv6::HEADER_LEN) as u16).to_be_bytes());
    } else {
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[6..8].fill(0);
        packet[10..12].fill(0);
        let ck = checksum(&packet[..keep]);
        packet[10..12].copy_from_slice(&ck.to_be_bytes());
    }
    Some(packet)
}
