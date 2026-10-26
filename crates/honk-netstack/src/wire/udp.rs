use std::net::{IpAddr, SocketAddr};
use std::ops::Range;

use super::checksum::Checksum;
use super::{PROTO_UDP, ParseError, emit_ip_header};

const HEADER_LEN: usize = 8;

pub fn parse(dgram: &[u8]) -> Result<(u16, u16, Range<usize>), ParseError> {
    if dgram.len() < HEADER_LEN {
        return Err(ParseError::Malformed);
    }
    let len = usize::from(u16::from_be_bytes([dgram[4], dgram[5]]));
    if len < HEADER_LEN || len > dgram.len() {
        return Err(ParseError::Malformed);
    }
    Ok((
        u16::from_be_bytes([dgram[0], dgram[1]]),
        u16::from_be_bytes([dgram[2], dgram[3]]),
        HEADER_LEN..len,
    ))
}

pub fn verify_checksum(src: IpAddr, dst: IpAddr, dgram: &[u8]) -> bool {
    if src.is_ipv4() != dst.is_ipv4() {
        return false;
    }
    let Ok((_, _, payload)) = parse(dgram) else {
        return false;
    };
    if dgram[6] == 0 && dgram[7] == 0 {
        return src.is_ipv4();
    }
    let mut c = Checksum::pseudo(src, dst, PROTO_UDP, payload.end);
    c.add(&dgram[..payload.end]);
    c.finish() == 0
}

pub fn emit_packet(
    out: &mut [u8],
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Option<usize> {
    let len = HEADER_LEN.checked_add(payload.len())?;
    let iplen = emit_ip_header(out, src.ip(), dst.ip(), PROTO_UDP, len)?;
    emit_datagram(out.get_mut(iplen..)?, src, dst, payload)?;
    Some(iplen + len)
}

/// Writes the UDP header, payload and checksum (no IP header); returns the datagram length.
pub(crate) fn emit_datagram(
    out: &mut [u8],
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Option<usize> {
    let len = HEADER_LEN.checked_add(payload.len())?;
    let wire_len = u16::try_from(len).ok()?;
    let dgram = out.get_mut(..len)?;
    dgram[..2].copy_from_slice(&src.port().to_be_bytes());
    dgram[2..4].copy_from_slice(&dst.port().to_be_bytes());
    dgram[4..6].copy_from_slice(&wire_len.to_be_bytes());
    dgram[6..8].fill(0);
    let mut c = Checksum::pseudo(src.ip(), dst.ip(), PROTO_UDP, len);
    let (header, data) = dgram.split_at_mut(HEADER_LEN);
    c.add(header);
    c.copy_add(data, payload);
    let sum = match c.finish() {
        0 => 0xFFFF,
        sum => sum,
    };
    header[6..8].copy_from_slice(&sum.to_be_bytes());
    Some(len)
}

/// Like [`emit_datagram`] for a USO packet: the payload is copied without being summed and the
/// checksum field holds the uncomplemented pseudo-header sum over the whole UDP length
/// (`CHECKSUM_PARTIAL`, field at UDP offset 6).
pub(crate) fn emit_datagram_partial(
    out: &mut [u8],
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Option<usize> {
    let len = HEADER_LEN.checked_add(payload.len())?;
    let wire_len = u16::try_from(len).ok()?;
    let dgram = out.get_mut(..len)?;
    dgram[..2].copy_from_slice(&src.port().to_be_bytes());
    dgram[2..4].copy_from_slice(&dst.port().to_be_bytes());
    dgram[4..6].copy_from_slice(&wire_len.to_be_bytes());
    let seed = Checksum::pseudo(src.ip(), dst.ip(), PROTO_UDP, len).fold();
    dgram[6..8].copy_from_slice(&seed.to_be_bytes());
    dgram[HEADER_LEN..].copy_from_slice(payload);
    Some(len)
}
#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::super::{ip_header_len, parse_ip};
    use super::*;

    fn pairs() -> [(SocketAddr, SocketAddr); 2] {
        [
            (
                SocketAddr::new(v4(192, 0, 2, 1), 12_345),
                SocketAddr::new(v4(198, 51, 100, 2), 53),
            ),
            (SocketAddr::new(v6(1), 12_345), SocketAddr::new(v6(2), 53)),
        ]
    }

    #[test]
    fn roundtrip_empty_odd_even_and_independent_checksum() {
        let mut rng = Rng::new(0xDADA);
        for (src, dst) in pairs() {
            for len in [0usize, 1, 2, 3, 17, 64, 255, 1000] {
                let payload = rng.bytes(len);
                let mut out = vec![0xCC; 1500];
                let n = emit_packet(&mut out, src, dst, &payload).unwrap();
                let ip = parse_ip(&out[..n]).unwrap();
                assert_eq!(ip.src, src.ip());
                assert_eq!(ip.dst, dst.ip());
                assert_eq!(ip.proto, PROTO_UDP);
                let dgram = &out[ip.payload];
                let (sport, dport, range) = parse(dgram).unwrap();
                assert_eq!(sport, src.port());
                assert_eq!(dport, dst.port());
                assert_eq!(&dgram[range], payload);
                assert!(verify_checksum(src.ip(), dst.ip(), dgram));
                let mut reference = pseudo_bytes(src.ip(), dst.ip(), PROTO_UDP, dgram.len());
                reference.extend_from_slice(dgram);
                assert_eq!(naive_checksum(&reference), 0);
                assert_eq!(out[n], 0xCC, "writes stop at packet end");
            }
        }
    }

    #[test]
    fn malformed_lengths() {
        for len in 0..HEADER_LEN {
            let mut b = [0u8; HEADER_LEN];
            b[4..6].copy_from_slice(&(len as u16).to_be_bytes());
            assert_eq!(parse(&b), Err(ParseError::Malformed), "len {len}");
            assert!(!verify_checksum(v4(1, 1, 1, 1), v4(2, 2, 2, 2), &b));
        }
        let mut b = [0u8; HEADER_LEN];
        b[4..6].copy_from_slice(&9u16.to_be_bytes());
        assert_eq!(parse(&b), Err(ParseError::Malformed));
    }

    #[test]
    fn udp_length_excludes_trailing_bytes_in_parse_and_checksum() {
        for (src, dst) in pairs() {
            let mut out = [0u8; 100];
            let n = emit_packet(&mut out, src, dst, b"abc").unwrap();
            let start = ip_header_len(src.is_ipv6());
            out[n..n + 5].copy_from_slice(&[0xFF; 5]);
            let dgram = &out[start..n + 5];
            assert_eq!(parse(dgram).unwrap().2, 8..11);
            assert!(verify_checksum(src.ip(), dst.ip(), dgram));
        }
    }

    #[test]
    fn zero_checksum_is_ipv4_only() {
        for (src, dst) in pairs() {
            let mut out = [0u8; 100];
            let n = emit_packet(&mut out, src, dst, b"abc").unwrap();
            let dgram = &mut out[ip_header_len(src.is_ipv6())..n];
            dgram[6..8].fill(0);
            assert_eq!(verify_checksum(src.ip(), dst.ip(), dgram), src.is_ipv4());
            assert!(!verify_checksum(
                src.ip(),
                if src.is_ipv4() { v6(2) } else { v4(1, 2, 3, 4) },
                dgram
            ));
        }
    }

    #[test]
    fn computed_zero_is_transmitted_as_ffff() {
        for (src, dst) in pairs() {
            let mut bytes = pseudo_bytes(src.ip(), dst.ip(), PROTO_UDP, 10);
            bytes.extend_from_slice(&src.port().to_be_bytes());
            bytes.extend_from_slice(&dst.port().to_be_bytes());
            bytes.extend_from_slice(&[0, 10, 0, 0, 0, 0]);
            let payload = naive_checksum(&bytes).to_be_bytes();
            let nbytes = bytes.len();
            bytes[nbytes - 2..].copy_from_slice(&payload);
            assert_eq!(
                naive_checksum(&bytes),
                0,
                "crafted pre-emission checksum is zero"
            );
            let mut out = [0u8; 100];
            let n = emit_packet(&mut out, src, dst, &payload).unwrap();
            let dgram = &out[ip_header_len(src.is_ipv6())..n];
            assert_eq!(&dgram[6..8], &[0xFF, 0xFF]);
            assert!(verify_checksum(src.ip(), dst.ip(), dgram));
        }
    }

    #[test]
    fn flipped_checksum_and_payload_detected() {
        for (src, dst) in pairs() {
            let mut out = [0u8; 100];
            let n = emit_packet(&mut out, src, dst, b"payload").unwrap();
            let dgram = &out[ip_header_len(src.is_ipv6())..n];
            for byte in [0, 1, 2, 3, 6, 7, 8, dgram.len() - 1] {
                let mut bad = dgram.to_vec();
                bad[byte] ^= 1;
                assert!(!verify_checksum(src.ip(), dst.ip(), &bad), "byte {byte}");
            }
        }
    }

    #[test]
    fn every_prefix_rejected_until_udp_length_fits() {
        for (src, dst) in pairs() {
            let mut out = [0u8; 100];
            let n = emit_packet(&mut out, src, dst, b"payload").unwrap();
            let dgram = &out[ip_header_len(src.is_ipv6())..n];
            for end in 0..dgram.len() {
                assert_eq!(parse(&dgram[..end]), Err(ParseError::Malformed));
                assert!(!verify_checksum(src.ip(), dst.ip(), &dgram[..end]));
            }
            assert!(parse(dgram).is_ok());
        }
    }

    #[test]
    fn emit_rejects_short_buffers_mixed_families_and_length_overflow() {
        let (src, dst) = pairs()[0];
        let mut out = [0u8; 30];
        assert_eq!(emit_packet(&mut out, src, dst, b"ab"), Some(30));
        assert_eq!(emit_packet(&mut out[..29], src, dst, b"ab"), None);
        assert_eq!(emit_packet(&mut out[..19], src, dst, &[]), None);
        assert_eq!(emit_packet(&mut out, src, pairs()[1].1, &[]), None);
        let mut out = vec![0u8; 70_000];
        let payload = vec![0u8; 65_528];
        assert_eq!(
            emit_packet(&mut out, pairs()[1].0, pairs()[1].1, &payload),
            None
        );
        // IPv4's total length has to include the IP header too.
        assert_eq!(emit_packet(&mut out, src, dst, &payload[..65_508]), None);
        assert_eq!(
            emit_packet(&mut out, src, dst, &payload[..65_507]),
            Some(65_535)
        );
        assert_eq!(
            emit_packet(&mut out, pairs()[1].0, pairs()[1].1, &payload[..65_527]),
            Some(65_575)
        );
    }
}
