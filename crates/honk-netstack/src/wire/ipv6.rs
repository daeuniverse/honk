use std::net::{IpAddr, Ipv6Addr};

use super::{IpPacket, ParseError};

pub const HEADER_LEN: usize = 40;
const MAX_EXT_HEADERS: usize = 8;
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const ESP: u8 = 50;
const AH: u8 = 51;
const NO_NEXT: u8 = 59;
const DEST_OPTS: u8 = 60;

pub(crate) fn addrs(pkt: &[u8]) -> (Ipv6Addr, Ipv6Addr) {
    let a = |o: usize| {
        let mut b = [0u8; 16];
        b.copy_from_slice(&pkt[o..o + 16]);
        Ipv6Addr::from(b)
    };
    (a(8), a(24))
}

pub fn parse(pkt: &[u8]) -> Result<IpPacket, ParseError> {
    if pkt.len() < HEADER_LEN || pkt[0] >> 4 != 6 {
        return Err(ParseError::Malformed);
    }
    let payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    let end = HEADER_LEN + payload_len;
    if end > pkt.len() {
        return Err(ParseError::Malformed);
    }
    if payload_len == 0 && pkt[6] == HOP_BY_HOP {
        // A zero length with hop-by-hop announces a jumbo payload, which this stack never carries.
        return Err(ParseError::Unsupported);
    }
    let (off, proto) = skip_ext_headers(pkt, HEADER_LEN, end, pkt[6])?;
    let (src, dst) = addrs(pkt);
    Ok(IpPacket {
        src: IpAddr::V6(src),
        dst: IpAddr::V6(dst),
        dscp: ((pkt[0] & 0x0F) << 4 | pkt[1] >> 4) >> 2,
        proto,
        hop_limit: pkt[7],
        payload: off..end,
    })
}

/// Walks hop-by-hop/routing/destination headers inside `pkt[off..end]`; returns the offset of
/// the upper layer and its protocol number.
pub(super) fn skip_ext_headers(
    pkt: &[u8],
    off: usize,
    end: usize,
    next: u8,
) -> Result<(usize, u8), ParseError> {
    match walk_ext_headers(pkt, off, end, next)? {
        Walk {
            proto: FRAGMENT, ..
        } => Err(ParseError::Fragment),
        Walk { off, proto, .. } => Ok((off, proto)),
    }
}

/// Where [`walk_ext_headers`] stopped: `off` is the first byte of the header (or upper layer)
/// of protocol `proto`, and `nh_off` the offset of the "next header" byte that announced it.
pub(crate) struct Walk {
    pub off: usize,
    pub proto: u8,
    pub nh_off: usize,
}

/// Like [`skip_ext_headers`] but stops at a fragment header (`proto == 44`) instead of failing.
pub(crate) fn walk_ext_headers(
    pkt: &[u8],
    mut off: usize,
    end: usize,
    mut next: u8,
) -> Result<Walk, ParseError> {
    let mut seen = 0;
    let mut nh_off = 6;
    loop {
        match next {
            HOP_BY_HOP | ROUTING | DEST_OPTS => {
                seen += 1;
                if seen > MAX_EXT_HEADERS || off + 2 > end {
                    return Err(ParseError::Malformed);
                }
                let len = (usize::from(pkt[off + 1]) + 1) * 8;
                if off + len > end {
                    return Err(ParseError::Malformed);
                }
                // RFC 8200 §4.4: a host must discard a routing header with segments left.
                if next == ROUTING && pkt[off + 3] != 0 {
                    return Err(ParseError::Unsupported);
                }
                next = pkt[off];
                nh_off = off;
                off += len;
            }
            ESP | AH | NO_NEXT => return Err(ParseError::Unsupported),
            proto => return Ok(Walk { off, proto, nh_off }),
        }
    }
}

pub(crate) const FRAGMENT_HEADER_LEN: usize = 8;

/// Writes an 8-byte fragment header: `offset` in bytes (a multiple of 8).
pub(crate) fn emit_fragment_header(
    buf: &mut [u8],
    next: u8,
    offset: usize,
    more: bool,
    id: u32,
) -> Option<usize> {
    let h = buf.get_mut(..FRAGMENT_HEADER_LEN)?;
    let field = u16::try_from(offset).ok()? & 0xFFF8 | u16::from(more);
    h[0] = next;
    h[1] = 0;
    h[2..4].copy_from_slice(&field.to_be_bytes());
    h[4..8].copy_from_slice(&id.to_be_bytes());
    Some(FRAGMENT_HEADER_LEN)
}

pub fn emit(
    buf: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    proto: u8,
    payload_len: usize,
) -> Option<usize> {
    let plen = u16::try_from(payload_len).ok()?;
    let h = buf.get_mut(..HEADER_LEN)?;
    h[0..4].copy_from_slice(&[0x60, 0, 0, 0]);
    h[4..6].copy_from_slice(&plen.to_be_bytes());
    h[6] = proto;
    h[7] = 64;
    h[8..24].copy_from_slice(&src.octets());
    h[24..40].copy_from_slice(&dst.octets());
    Some(HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const DST: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

    /// `exts` are (kind, total length) pairs chained in order; the body after them is `payload`.
    fn packet(exts: &[(u8, usize)], proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for (i, &(_, len)) in exts.iter().enumerate() {
            let next = exts.get(i + 1).map_or(proto, |e| e.0);
            let mut h = vec![0u8; len];
            h[0] = next;
            h[1] = (len / 8 - 1) as u8;
            body.extend_from_slice(&h);
        }
        body.extend_from_slice(payload);
        let first = exts.first().map_or(proto, |e| e.0);
        let mut b = vec![0u8; HEADER_LEN];
        emit(&mut b, SRC, DST, first, body.len()).unwrap();
        b.extend_from_slice(&body);
        b
    }

    #[test]
    fn plain_roundtrip_and_padding() {
        let mut b = packet(&[], 6, b"segment");
        b.extend_from_slice(&[0xEE; 5]);
        let p = parse(&b).unwrap();
        assert_eq!(p.src, IpAddr::V6(SRC));
        assert_eq!(p.dst, IpAddr::V6(DST));
        assert_eq!(p.dscp, 0);
        assert_eq!(p.proto, 6);
        assert_eq!(p.hop_limit, 64);
        assert_eq!(&b[p.payload], b"segment");
    }

    #[test]
    fn dscp_excludes_ecn_and_the_flow_label() {
        for dscp in 0..=63 {
            for ecn in 0..=3 {
                let mut b = packet(&[(0, 8), (60, 8)], 6, b"data");
                let traffic_class = dscp << 2 | ecn;
                b[0] = 0x60 | traffic_class >> 4;
                b[1] = traffic_class << 4 | 0x0F;
                b[2..4].fill(0xFF);
                assert_eq!(parse(&b).unwrap().dscp, dscp);
            }
        }
    }

    #[test]
    fn empty_payload_with_upper_layer_is_fine() {
        let b = packet(&[], 17, b"");
        let p = parse(&b).unwrap();
        assert_eq!(p.payload, 40..40);
    }

    #[test]
    fn ext_header_chain_is_skipped() {
        let b = packet(&[(0, 8), (43, 24), (60, 16)], 6, b"tcp!");
        let p = parse(&b).unwrap();
        assert_eq!(p.proto, 6);
        assert_eq!(p.payload.start, 40 + 8 + 24 + 16);
        assert_eq!(&b[p.payload], b"tcp!");
    }

    #[test]
    fn fragment_header_rejected() {
        let mut b = packet(&[(0, 8)], 6, &[0; 8]);
        b[40] = 44;
        assert_eq!(parse(&b), Err(ParseError::Fragment));
        let mut b = packet(&[], 6, &[0; 8]);
        b[6] = 44;
        assert_eq!(parse(&b), Err(ParseError::Fragment));
    }

    #[test]
    fn unsupported_next_headers() {
        for nh in [50u8, 51, 59] {
            let mut b = packet(&[], 6, &[0; 8]);
            b[6] = nh;
            assert_eq!(parse(&b), Err(ParseError::Unsupported), "nh {nh}");
        }
    }

    #[test]
    fn jumbo_hop_by_hop_unsupported() {
        let mut b = packet(&[], 6, b"");
        b[6] = 0;
        assert_eq!(parse(&b), Err(ParseError::Unsupported));
    }

    #[test]
    fn overruns_are_malformed() {
        // Ext header length runs past payload_len even though the buffer has more bytes.
        let mut b = packet(&[(60, 8)], 6, &[0; 20]);
        b[41] = 5;
        b[4..6].copy_from_slice(&16u16.to_be_bytes());
        assert_eq!(parse(&b), Err(ParseError::Malformed));
        // payload_len larger than the buffer.
        let mut b = packet(&[], 6, &[0; 4]);
        b[4..6].copy_from_slice(&5u16.to_be_bytes());
        assert_eq!(parse(&b), Err(ParseError::Malformed));
        // Ext header with a single byte left.
        let mut b = packet(&[], 6, &[0]);
        b[6] = 60;
        assert_eq!(parse(&b), Err(ParseError::Malformed));
        // Ext header present but no payload at all.
        let mut b = packet(&[], 6, b"");
        b[6] = 43;
        assert_eq!(parse(&b), Err(ParseError::Malformed));
    }

    #[test]
    fn ext_header_count_bounded() {
        let ok = packet(&[(60, 8); 8], 6, b"x");
        assert_eq!(parse(&ok).unwrap().payload.start, 40 + 64);
        let too_many = packet(&[(60, 8); 9], 6, b"x");
        assert_eq!(parse(&too_many), Err(ParseError::Malformed));
    }

    #[test]
    fn routing_header_with_segments_left_is_discarded() {
        let mut b = packet(&[(43, 8)], 6, b"tcp!");
        assert_eq!(
            &b[parse(&b).unwrap().payload],
            b"tcp!",
            "segments left 0 is final delivery"
        );
        b[43] = 2;
        assert_eq!(parse(&b), Err(ParseError::Unsupported));
    }

    #[test]
    fn rejects_short_and_wrong_version() {
        assert_eq!(parse(&[0x60; 39]), Err(ParseError::Malformed));
        let mut b = packet(&[], 6, b"x");
        b[0] = 0x40;
        assert_eq!(parse(&b), Err(ParseError::Malformed));
    }

    #[test]
    fn every_prefix_is_error() {
        let b = packet(&[(0, 8), (60, 8)], 6, b"payload");
        for n in 0..b.len() {
            assert!(parse(&b[..n]).is_err(), "prefix {n}");
        }
        assert!(parse(&b).is_ok());
    }

    #[test]
    fn emit_limits() {
        let mut b = [0u8; 40];
        assert_eq!(emit(&mut b, SRC, DST, 6, 65_535), Some(40));
        assert_eq!(emit(&mut b, SRC, DST, 6, 65_536), None);
        assert_eq!(emit(&mut b[..39], SRC, DST, 6, 0), None);
    }
}
