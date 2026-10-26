use std::net::{IpAddr, Ipv4Addr};
use std::ops::Range;

use super::checksum::{Checksum, checksum};
use super::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, ParseError, emit_ip_header, ipv6};

const HEADER_LEN: usize = 8;
const MAX_QUOTE_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpKind {
    PacketTooBig { mtu: u32 },
    Unreachable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IcmpError {
    pub kind: IcmpKind,
    /// Embedded original packet relative to the ICMP message, not its enclosing IP packet.
    pub quoted: Range<usize>,
}

pub fn parse(src: IpAddr, dst: IpAddr, msg: &[u8]) -> Result<Option<IcmpError>, ParseError> {
    if msg.len() < HEADER_LEN || src.is_ipv4() != dst.is_ipv4() {
        return Err(ParseError::Malformed);
    }
    let sum = if src.is_ipv4() {
        checksum(msg)
    } else {
        let mut c = Checksum::pseudo(src, dst, PROTO_ICMPV6, msg.len());
        c.add(msg);
        c.finish()
    };
    if sum != 0 {
        return Err(ParseError::Checksum);
    }
    let kind = match (src.is_ipv4(), msg[0], msg[1]) {
        (true, 3, 4) => IcmpKind::PacketTooBig {
            mtu: u32::from(u16::from_be_bytes([msg[6], msg[7]])),
        },
        (true, 3, _) | (false, 1, _) => IcmpKind::Unreachable,
        (false, 2, _) => IcmpKind::PacketTooBig {
            mtu: u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]),
        },
        _ => return Ok(None),
    };
    Ok(Some(IcmpError {
        kind,
        quoted: HEADER_LEN..msg.len(),
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quoted {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    /// TCP sequence, present only if at least eight TCP bytes were quoted.
    pub seq: Option<u32>,
}

/// Best-effort decoding of a quote, which may end well before the original packet length.
pub fn parse_quoted(pkt: &[u8]) -> Option<Quoted> {
    let (src, dst, proto, off) = match pkt.first()? >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = usize::from(pkt[0] & 0x0F) * 4;
            if ihl < 20 || ihl > pkt.len() || u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1FFF != 0 {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
                IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
                pkt[9],
                ihl,
            )
        }
        6 => {
            if pkt.len() < ipv6::HEADER_LEN {
                return None;
            }
            let (off, proto) =
                ipv6::skip_ext_headers(pkt, ipv6::HEADER_LEN, pkt.len(), pkt[6]).ok()?;
            let (src, dst) = ipv6::addrs(pkt);
            (IpAddr::V6(src), IpAddr::V6(dst), proto, off)
        }
        _ => return None,
    };
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return None;
    }
    let transport = pkt.get(off..)?;
    if transport.len() < 4 {
        return None;
    }
    Some(Quoted {
        src,
        dst,
        proto,
        src_port: u16::from_be_bytes([transport[0], transport[1]]),
        dst_port: u16::from_be_bytes([transport[2], transport[3]]),
        seq: if proto == PROTO_TCP && transport.len() >= 8 {
            Some(u32::from_be_bytes([
                transport[4],
                transport[5],
                transport[6],
                transport[7],
            ]))
        } else {
            None
        },
    })
}

/// Creates PTB packets for tests and peers; quotes at most 64 bytes, with IPv4 MTUs limited to u16.
pub fn emit_packet_too_big(
    out: &mut [u8],
    src: IpAddr,
    dst: IpAddr,
    mtu: u32,
    original: &[u8],
) -> Option<usize> {
    let mtu_bytes = if src.is_ipv4() {
        let mtu = u16::try_from(mtu).ok()?;
        let [hi, lo] = mtu.to_be_bytes();
        [0, 0, hi, lo]
    } else {
        mtu.to_be_bytes()
    };
    let quote = &original[..original.len().min(MAX_QUOTE_LEN)];
    let len = HEADER_LEN + quote.len();
    let proto = if src.is_ipv4() {
        PROTO_ICMP
    } else {
        PROTO_ICMPV6
    };
    let iplen = emit_ip_header(out, src, dst, proto, len)?;
    let total = iplen + len;
    let msg = out.get_mut(iplen..total)?;
    msg[0..4].copy_from_slice(if src.is_ipv4() {
        &[3, 4, 0, 0]
    } else {
        &[2, 0, 0, 0]
    });
    msg[4..8].copy_from_slice(&mtu_bytes);
    let mut c = if src.is_ipv4() {
        Checksum::new()
    } else {
        Checksum::pseudo(src, dst, PROTO_ICMPV6, len)
    };
    let (header, body) = msg.split_at_mut(HEADER_LEN);
    c.add(header);
    c.copy_add(body, quote);
    header[2..4].copy_from_slice(&c.finish().to_be_bytes());
    Some(total)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::super::testutil::*;
    use super::super::{ip_header_len, parse_ip, tcp, udp};
    use super::*;

    fn tcp_packet(src: IpAddr, dst: IpAddr) -> Vec<u8> {
        let hdr = tcp::Header {
            src_port: 31_234,
            dst_port: 8443,
            seq: 0x1234_ABCD,
            ack: 0,
            flags: tcp::SYN,
            window: 10_000,
            urgent: 0,
            options: tcp::Options::default(),
        };
        let mut out = vec![0u8; 200];
        let n = tcp::emit_packet(&mut out, src, dst, &hdr, [&[0xAB; 80], &[]]).unwrap();
        out.truncate(n);
        out
    }

    fn pairs() -> [(IpAddr, IpAddr, IpAddr); 2] {
        [
            (v4(192, 0, 2, 1), v4(198, 51, 100, 2), v4(192, 0, 2, 254)),
            (v6(1), v6(2), v6(254)),
        ]
    }

    #[test]
    fn ptb_roundtrip_and_quoted_tcp_fields_both_families() {
        for (src, dst, router) in pairs() {
            let original = tcp_packet(src, dst);
            let mut out = [0xCC; 200];
            let n = emit_packet_too_big(&mut out, router, src, 1280, &original).unwrap();
            let ip = parse_ip(&out[..n]).unwrap();
            assert_eq!(ip.src, router);
            assert_eq!(ip.dst, src);
            assert_eq!(
                ip.proto,
                if src.is_ipv4() {
                    PROTO_ICMP
                } else {
                    PROTO_ICMPV6
                }
            );
            let msg = &out[ip.payload];
            let err = parse(router, src, msg).unwrap().unwrap();
            assert_eq!(err.kind, IcmpKind::PacketTooBig { mtu: 1280 });
            assert_eq!(err.quoted, 8..72);
            assert_eq!(&msg[err.quoted.clone()], &original[..64]);
            assert_eq!(
                parse_quoted(&msg[err.quoted]).unwrap(),
                Quoted {
                    src,
                    dst,
                    proto: PROTO_TCP,
                    src_port: 31_234,
                    dst_port: 8443,
                    seq: Some(0x1234_ABCD),
                }
            );
            let mut reference = if src.is_ipv4() {
                Vec::new()
            } else {
                pseudo_bytes(router, src, PROTO_ICMPV6, msg.len())
            };
            reference.extend_from_slice(msg);
            assert_eq!(naive_checksum(&reference), 0);
            assert_eq!(out[n], 0xCC);
        }
    }

    #[test]
    fn ptb_quotes_short_original_without_padding() {
        for (src, _, router) in pairs() {
            for len in [0usize, 1, 3, 20, 63, 64, 65] {
                let original = vec![0xAA; len];
                let mut out = [0u8; 150];
                let n = emit_packet_too_big(&mut out, router, src, 0, &original).unwrap();
                let ip = parse_ip(&out[..n]).unwrap();
                let msg = &out[ip.payload];
                let err = parse(router, src, msg).unwrap().unwrap();
                assert_eq!(err.kind, IcmpKind::PacketTooBig { mtu: 0 });
                assert_eq!(&msg[err.quoted], &original[..len.min(64)]);
            }
        }
    }

    fn seal(src: IpAddr, dst: IpAddr, msg: &mut [u8]) {
        msg[2..4].fill(0);
        let mut bytes = if src.is_ipv4() {
            Vec::new()
        } else {
            pseudo_bytes(src, dst, PROTO_ICMPV6, msg.len())
        };
        bytes.extend_from_slice(msg);
        let sum = naive_checksum(&bytes);
        msg[2..4].copy_from_slice(&sum.to_be_bytes());
    }

    #[test]
    fn unreachable_other_types_and_mtu_fields() {
        for (src, dst, _) in pairs() {
            for code in [0u8, 1, 3, 5, 13, 255] {
                let mut msg = [0u8; 12];
                msg[0] = if src.is_ipv4() { 3 } else { 1 };
                msg[1] = code;
                msg[8..].copy_from_slice(b"body");
                seal(src, dst, &mut msg);
                let err = parse(src, dst, &msg).unwrap().unwrap();
                assert_eq!(err.kind, IcmpKind::Unreachable);
                assert_eq!(&msg[err.quoted], b"body");
            }
            let mut echo = [0u8; 8];
            echo[0] = if src.is_ipv4() { 8 } else { 128 };
            seal(src, dst, &mut echo);
            assert_eq!(parse(src, dst, &echo), Ok(None));
        }
        let (src, dst, _) = pairs()[0];
        let mut msg = [3, 4, 0, 0, 0xAA, 0xBB, 0x12, 0x34];
        seal(src, dst, &mut msg);
        assert_eq!(
            parse(src, dst, &msg).unwrap().unwrap().kind,
            IcmpKind::PacketTooBig { mtu: 0x1234 }
        );
        let (src, dst, _) = pairs()[1];
        let mut msg = [2, 0, 0, 0, 0x12, 0x34, 0x56, 0x78];
        seal(src, dst, &mut msg);
        assert_eq!(
            parse(src, dst, &msg).unwrap().unwrap().kind,
            IcmpKind::PacketTooBig { mtu: 0x1234_5678 }
        );
    }

    #[test]
    fn checksum_corruption_and_pseudo_header_detected() {
        for (src, _, router) in pairs() {
            let mut out = [0u8; 200];
            let n = emit_packet_too_big(&mut out, router, src, 1400, b"quoted!").unwrap();
            let msg = &out[ip_header_len(src.is_ipv6())..n];
            for i in 0..msg.len() {
                let mut bad = msg.to_vec();
                bad[i] ^= 1;
                assert_eq!(
                    parse(router, src, &bad),
                    Err(ParseError::Checksum),
                    "byte {i}"
                );
            }
            if src.is_ipv6() {
                assert_eq!(parse(router, v6(55), msg), Err(ParseError::Checksum));
            }
        }
        assert_eq!(
            parse(v4(1, 1, 1, 1), v6(1), &[0; 8]),
            Err(ParseError::Malformed)
        );
    }

    #[test]
    fn every_message_prefix_never_panics_and_all_short_headers_fail() {
        for (src, dst, router) in pairs() {
            let original = tcp_packet(src, dst);
            let mut out = [0u8; 200];
            let n = emit_packet_too_big(&mut out, router, src, 1280, &original).unwrap();
            let msg = &out[ip_header_len(src.is_ipv6())..n];
            for end in 0..8 {
                assert_eq!(parse(router, src, &msg[..end]), Err(ParseError::Malformed));
            }
            for end in 8..msg.len() {
                let _ = parse(router, src, &msg[..end]);
            }
            for end in 0..=original.len() {
                let got = parse_quoted(&original[..end]);
                let hlen = ip_header_len(src.is_ipv6());
                if end < hlen + 4 {
                    assert_eq!(got, None, "prefix {end}");
                } else {
                    let q = got.unwrap();
                    assert_eq!(q.src_port, 31_234);
                    assert_eq!(q.dst_port, 8443);
                    assert_eq!(
                        q.seq,
                        if end >= hlen + 8 {
                            Some(0x1234_ABCD)
                        } else {
                            None
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn quoted_udp_has_ports_but_never_tcp_sequence() {
        for (src, dst, _) in pairs() {
            let mut out = [0u8; 100];
            let n = udp::emit_packet(
                &mut out,
                SocketAddr::new(src, 123),
                SocketAddr::new(dst, 456),
                b"abc",
            )
            .unwrap();
            let quoted = parse_quoted(&out[..n]).unwrap();
            assert_eq!(quoted.proto, PROTO_UDP);
            assert_eq!(quoted.src_port, 123);
            assert_eq!(quoted.dst_port, 456);
            assert_eq!(quoted.seq, None);
        }
    }

    #[test]
    fn quoted_ipv4_options_and_bogus_checksums_and_lengths_are_tolerated() {
        let (src, dst, _) = pairs()[0];
        let original = tcp_packet(src, dst);
        let mut quoted = original[..20].to_vec();
        quoted[0] = 0x46;
        quoted[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
        quoted[10..12].copy_from_slice(&[0xFF; 2]);
        quoted.extend_from_slice(&[1, 1, 1, 0]);
        quoted.extend_from_slice(&original[20..28]);
        let parsed = parse_quoted(&quoted).unwrap();
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.seq, Some(0x1234_ABCD));
        quoted[2..4].fill(0);
        assert_eq!(parse_quoted(&quoted), Some(parsed));
        quoted[0] = 0x44;
        assert_eq!(parse_quoted(&quoted), None);
        quoted[0] = 0x4F;
        assert_eq!(parse_quoted(&quoted), None);
        quoted[0] = 0x46;
        quoted[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(parse_quoted(&quoted), None);
    }

    #[test]
    fn quoted_ipv6_extension_chain_and_broken_chains() {
        let (src, dst, _) = pairs()[1];
        let original = tcp_packet(src, dst);
        let mut quoted = original[..40].to_vec();
        quoted[6] = 0;
        quoted[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
        for next in [43u8, 60, PROTO_TCP] {
            quoted.extend_from_slice(&[next, 0, 0, 0, 0, 0, 0, 0]);
        }
        quoted.extend_from_slice(&original[40..48]);
        assert_eq!(parse_quoted(&quoted).unwrap().seq, Some(0x1234_ABCD));
        for end in 0..68 {
            assert_eq!(parse_quoted(&quoted[..end]), None, "prefix {end}");
        }
        quoted[41] = 10;
        assert_eq!(parse_quoted(&quoted), None);
        for proto in [44u8, 50, 51, 59] {
            quoted[6] = proto;
            assert_eq!(parse_quoted(&quoted), None);
        }
        for n in [8usize, 9] {
            let mut chain = original[..40].to_vec();
            chain[6] = 60;
            for i in 0..n {
                chain.extend_from_slice(&[
                    if i + 1 == n { PROTO_TCP } else { 60 },
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]);
            }
            chain.extend_from_slice(&original[40..48]);
            assert_eq!(parse_quoted(&chain).is_some(), n == 8);
        }
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let mut rng = Rng::new(456);
        for len in 0..300 {
            let mut bytes = rng.bytes(len);
            for version in [0u8, 4, 6, 15] {
                if let Some(first) = bytes.first_mut() {
                    *first = (version << 4) | (*first & 0x0F);
                }
                let _ = parse_quoted(&bytes);
                let _ = parse(v4(1, 1, 1, 1), v4(2, 2, 2, 2), &bytes);
                let _ = parse(v6(1), v6(2), &bytes);
            }
        }
    }

    #[test]
    fn emit_rejects_short_buffers_mixed_family_and_unrepresentable_v4_mtu() {
        let (src, _, router) = pairs()[0];
        let mut out = [0u8; 100];
        let need = 20 + 8 + 3;
        assert_eq!(
            emit_packet_too_big(&mut out[..need], router, src, 1400, b"abc"),
            Some(need)
        );
        assert_eq!(
            emit_packet_too_big(&mut out[..need - 1], router, src, 1400, b"abc"),
            None
        );
        assert_eq!(
            emit_packet_too_big(&mut out[..19], router, src, 1400, b"abc"),
            None
        );
        assert_eq!(
            emit_packet_too_big(&mut out, router, v6(1), 1400, b"abc"),
            None
        );
        assert_eq!(
            emit_packet_too_big(&mut out, router, src, 65_536, b"abc"),
            None
        );
    }
}
