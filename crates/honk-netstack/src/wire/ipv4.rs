use std::net::{IpAddr, Ipv4Addr};

use super::checksum::checksum;
use super::{IpPacket, ParseError};

pub const HEADER_LEN: usize = 20;
const FRAGMENT_BITS: u16 = 0x3FFF;
const DF: u16 = 0x4000;

pub fn parse(pkt: &[u8]) -> Result<IpPacket, ParseError> {
    if pkt.len() < HEADER_LEN || pkt[0] >> 4 != 4 {
        return Err(ParseError::Malformed);
    }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if ihl < HEADER_LEN || pkt.len() < ihl || total < ihl || total > pkt.len() {
        return Err(ParseError::Malformed);
    }
    if checksum(&pkt[..ihl]) != 0 {
        return Err(ParseError::Checksum);
    }
    if u16::from_be_bytes([pkt[6], pkt[7]]) & FRAGMENT_BITS != 0 {
        return Err(ParseError::Fragment);
    }
    Ok(IpPacket {
        src: IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
        dst: IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
        proto: pkt[9],
        hop_limit: pkt[8],
        payload: ihl..total,
    })
}

pub fn emit(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    payload_len: usize,
) -> Option<usize> {
    let total = u16::try_from(HEADER_LEN.checked_add(payload_len)?).ok()?;
    let h = buf.get_mut(..HEADER_LEN)?;
    h[0] = 0x45;
    h[1] = 0;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h[4..6].copy_from_slice(&[0, 0]);
    h[6..8].copy_from_slice(&DF.to_be_bytes());
    h[8] = 64;
    h[9] = proto;
    h[10..12].copy_from_slice(&[0, 0]);
    h[12..16].copy_from_slice(&src.octets());
    h[16..20].copy_from_slice(&dst.octets());
    let ck = checksum(h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    Some(HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; HEADER_LEN + payload.len()];
        emit(
            &mut b,
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(10, 4, 5, 6),
            17,
            payload.len(),
        )
        .unwrap();
        b[HEADER_LEN..].copy_from_slice(payload);
        b
    }

    fn reseal(b: &mut [u8]) {
        b[10] = 0;
        b[11] = 0;
        let ck = checksum(&b[..usize::from(b[0] & 0xF) * 4]);
        b[10..12].copy_from_slice(&ck.to_be_bytes());
    }

    #[test]
    fn roundtrip_fields() {
        let b = packet(b"hello");
        assert_eq!(b[6] & 0x40, 0x40, "DF set");
        assert_eq!(&b[4..6], &[0, 0], "id 0");
        let p = parse(&b).unwrap();
        assert_eq!(p.src, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(p.dst, IpAddr::V4(Ipv4Addr::new(10, 4, 5, 6)));
        assert_eq!(p.proto, 17);
        assert_eq!(p.hop_limit, 64);
        assert_eq!(&b[p.payload], b"hello");
    }

    #[test]
    fn trailing_padding_excluded() {
        let mut b = packet(b"abc");
        b.extend_from_slice(&[0; 10]);
        assert_eq!(parse(&b).unwrap().payload, 20..23);
    }

    #[test]
    fn options_shift_payload() {
        let mut b = vec![0u8; 24 + 2];
        b[0] = 0x46;
        b[2..4].copy_from_slice(&26u16.to_be_bytes());
        b[8] = 3;
        b[9] = 6;
        b[24..].copy_from_slice(b"hi");
        reseal(&mut b);
        let p = parse(&b).unwrap();
        assert_eq!(p.payload, 24..26);
        assert_eq!(p.hop_limit, 3);
    }

    #[test]
    fn rejects_bad_headers() {
        let good = packet(b"xy");
        let mut b = good.clone();
        b[0] = 0x44;
        assert_eq!(parse(&b), Err(ParseError::Malformed), "ihl < 5");
        let mut b = good.clone();
        b[0] = 0x4F;
        assert_eq!(parse(&b), Err(ParseError::Malformed), "ihl beyond buffer");
        let mut b = good.clone();
        b[2..4].copy_from_slice(&19u16.to_be_bytes());
        reseal(&mut b);
        assert_eq!(parse(&b), Err(ParseError::Malformed), "total < header");
        let mut b = good.clone();
        b[2..4].copy_from_slice(&23u16.to_be_bytes());
        reseal(&mut b);
        assert_eq!(parse(&b), Err(ParseError::Malformed), "total > buffer");
        let mut b = good.clone();
        b[0] = 0x65;
        assert_eq!(parse(&b), Err(ParseError::Malformed), "wrong version");
    }

    #[test]
    fn checksum_flip_detected_at_every_header_byte() {
        let good = packet(b"xy");
        for i in 0..HEADER_LEN {
            // Version/ihl/total corruption is caught as Malformed or Checksum, never accepted.
            let mut b = good.clone();
            b[i] ^= 0x01;
            assert!(parse(&b).is_err(), "byte {i}");
        }
        let mut b = good;
        b[10] ^= 0xFF;
        assert_eq!(parse(&b), Err(ParseError::Checksum));
    }

    #[test]
    fn fragments_rejected_after_checksum() {
        for bits in [0x2000u16, 0x0001, 0x2001, 0x1FFF] {
            let mut b = packet(b"xy");
            b[6..8].copy_from_slice(&(bits | DF).to_be_bytes());
            reseal(&mut b);
            assert_eq!(parse(&b), Err(ParseError::Fragment), "{bits:#x}");
            b[6] ^= 0x01;
            assert_eq!(parse(&b), Err(ParseError::Checksum), "checksum first");
        }
        let mut b = packet(b"xy");
        b[6..8].copy_from_slice(&0u16.to_be_bytes());
        reseal(&mut b);
        assert!(parse(&b).is_ok(), "DF clear alone is not a fragment");
    }

    #[test]
    fn every_prefix_is_error_or_consistent() {
        let b = packet(b"payload");
        for n in 0..b.len() {
            assert!(parse(&b[..n]).is_err(), "prefix {n}");
        }
        assert!(parse(&b).is_ok());
    }

    #[test]
    fn emit_limits() {
        let mut b = [0u8; 20];
        let a = Ipv4Addr::LOCALHOST;
        assert_eq!(emit(&mut b, a, a, 6, 65_515), Some(20));
        assert_eq!(emit(&mut b, a, a, 6, 65_516), None);
        assert_eq!(emit(&mut b, a, a, 6, usize::MAX), None);
        assert_eq!(emit(&mut b[..19], a, a, 6, 0), None);
    }
}
