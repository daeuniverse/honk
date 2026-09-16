use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use bytes::Bytes;

use crate::netlink;

const NFQA_PACKET_HDR: u16 = 1;
const NFQA_MARK: u16 = 3;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_CAP_LEN: u16 = 13;
const NFQA_SKB_INFO: u16 = 14;
const NFQA_SKB_CSUMNOTREADY: u32 = 1;
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_AH: u8 = 51;
const IPPROTO_DSTOPTS: u8 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpTuple {
    pub client: SocketAddr,
    pub destination: SocketAddr,
}

#[derive(Debug)]
pub struct QueuedPacket {
    pub tuple: UdpTuple,
    pub payload: Bytes,
    pub mark: u32,
    pub received_at: Instant,
}

/// Both events retain the held original's verdict ownership. Rejections expose
/// only a safely identified tuple, so the owner can also retire its pending token.
#[derive(Debug)]
pub enum PacketEvent {
    Datagram(QueuedPacket),
    Rejected {
        tuple: UdpTuple,
        mark: u32,
        received_at: Instant,
        error: PacketError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("truncated nfgenmsg")]
    TruncatedNfgenmsg,
    #[error("unexpected address family {0}")]
    UnexpectedFamily(u8),
    #[error("malformed NFQA attributes: {0}")]
    MalformedAttributes(String),
    #[error("duplicate NFQA attribute {0}")]
    DuplicateAttribute(u16),
    #[error("invalid NFQA attribute {kind} length {length}")]
    InvalidAttributeLength { kind: u16, length: usize },
    #[error("missing NFQA_PACKET_HDR")]
    MissingPacketHeader,
    #[error("missing NFQA_MARK")]
    MissingMark,
    #[error("missing NFQA_PAYLOAD")]
    MissingPayload,
    #[error("NFQA_CAP_LEN {captured} does not match payload length {payload}")]
    CaptureLengthMismatch { captured: usize, payload: usize },
    #[error("malformed IPv4 packet")]
    MalformedIpv4,
    #[error("malformed IPv6 packet")]
    MalformedIpv6,
    #[error("packet is not an IP datagram")]
    NotIpDatagram,
    #[error(
        "IPv4 packet is not unfragmented UDP: protocol {protocol}, fragment field {fragment:#06x}, header length {header_length}"
    )]
    NotUdpIpv4 {
        protocol: u8,
        fragment: u16,
        header_length: usize,
    },
    #[error(
        "IPv6 packet is not unfragmented UDP: next header {next_header}, fragment field {fragment:#06x}, header offset {header_offset}"
    )]
    NotUdpIpv6 {
        next_header: u8,
        fragment: u16,
        header_offset: usize,
    },
    #[error("malformed UDP datagram")]
    MalformedUdp,
    #[error("invalid UDP checksum")]
    InvalidUdpChecksum,
}

#[derive(Debug)]
pub(crate) struct ParsedPacket {
    pub(crate) packet_id: u32,
    pub(crate) event: PacketEvent,
}

struct ParsedUdp {
    tuple: UdpTuple,
    payload_range: Result<std::ops::Range<usize>, PacketError>,
}

// Invalid queue metadata or an unidentifiable UDP header cannot safely reach
// token cleanup. Payload failures after identification are packet-local events.
pub(crate) fn parse_packet_message(
    body: Bytes,
    received_at: Instant,
) -> Result<ParsedPacket, PacketError> {
    if body.len() < netlink::NFGENMSG_LEN {
        return Err(PacketError::TruncatedNfgenmsg);
    }
    let family = body[0];
    if family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8 {
        return Err(PacketError::UnexpectedFamily(family));
    }

    let mut packet_id = None;
    let mut mark = None;
    let mut payload = None;
    let mut capture_length = None;
    let mut skb_info = None;
    for attribute in netlink::attributes(body.slice(netlink::NFGENMSG_LEN..)) {
        let attribute =
            attribute.map_err(|error| PacketError::MalformedAttributes(error.to_string()))?;
        match attribute.kind {
            NFQA_PACKET_HDR => {
                set_once(&mut packet_id, attribute.kind)?;
                if attribute.payload.len() != 7 {
                    return Err(PacketError::InvalidAttributeLength {
                        kind: attribute.kind,
                        length: attribute.payload.len(),
                    });
                }
                packet_id = Some(u32::from_be_bytes(
                    attribute.payload[..4].try_into().expect("four bytes"),
                ));
            }
            NFQA_MARK => {
                set_once(&mut mark, attribute.kind)?;
                mark = Some(be32_attribute(&attribute)?);
            }
            NFQA_PAYLOAD => {
                set_once(&mut payload, attribute.kind)?;
                payload = Some(attribute.payload);
            }
            NFQA_CAP_LEN => {
                set_once(&mut capture_length, attribute.kind)?;
                capture_length = Some(be32_attribute(&attribute)? as usize);
            }
            NFQA_SKB_INFO => {
                set_once(&mut skb_info, attribute.kind)?;
                skb_info = Some(be32_attribute(&attribute)?);
            }
            _ => {}
        }
    }

    let packet_id = packet_id.ok_or(PacketError::MissingPacketHeader)?;
    let mark = mark.ok_or(PacketError::MissingMark)?;
    let layer_three = payload.ok_or(PacketError::MissingPayload)?;
    // The kernel can copy less than the skb length, never more.
    if let Some(captured) = capture_length
        && captured < layer_three.len()
    {
        return Err(PacketError::CaptureLengthMismatch {
            captured,
            payload: layer_three.len(),
        });
    }

    let family_from_packet = layer_three
        .first()
        .map(|first| first >> 4)
        .ok_or(PacketError::NotIpDatagram)?;
    if (family == libc::AF_INET as u8 && family_from_packet != 4)
        || (family == libc::AF_INET6 as u8 && family_from_packet != 6)
    {
        return Err(PacketError::UnexpectedFamily(family));
    }
    let checksum_not_ready = skb_info.unwrap_or(0) & NFQA_SKB_CSUMNOTREADY != 0;
    let parsed = match family_from_packet {
        4 => parse_ipv4_udp(&layer_three, checksum_not_ready)?,
        6 => parse_ipv6_udp(&layer_three, checksum_not_ready)?,
        _ => return Err(PacketError::NotIpDatagram),
    };
    let payload_range = match capture_length {
        Some(captured) if captured > layer_three.len() => Err(PacketError::CaptureLengthMismatch {
            captured,
            payload: layer_three.len(),
        }),
        _ => parsed.payload_range,
    };
    let event = match payload_range {
        Ok(range) => PacketEvent::Datagram(QueuedPacket {
            tuple: parsed.tuple,
            payload: layer_three.slice(range),
            mark,
            received_at,
        }),
        Err(error) => PacketEvent::Rejected {
            tuple: parsed.tuple,
            mark,
            received_at,
            error,
        },
    };
    Ok(ParsedPacket { packet_id, event })
}

fn set_once<T>(slot: &mut Option<T>, kind: u16) -> Result<(), PacketError> {
    if slot.is_some() {
        return Err(PacketError::DuplicateAttribute(kind));
    }
    Ok(())
}

fn be32_attribute(attribute: &netlink::Attribute) -> Result<u32, PacketError> {
    if attribute.payload.len() != 4 {
        return Err(PacketError::InvalidAttributeLength {
            kind: attribute.kind,
            length: attribute.payload.len(),
        });
    }
    Ok(u32::from_be_bytes(
        attribute.payload[..4].try_into().expect("four bytes"),
    ))
}

fn parse_ipv4_udp(packet: &Bytes, checksum_not_ready: bool) -> Result<ParsedUdp, PacketError> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return Err(PacketError::MalformedIpv4);
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return Err(PacketError::MalformedIpv4);
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let protocol = packet[9];
    if fragment & 0x1fff != 0 || protocol != IPPROTO_UDP {
        return Err(PacketError::NotUdpIpv4 {
            protocol,
            fragment,
            header_length,
        });
    }
    let source = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let mut parsed = parse_udp(
        packet,
        header_length,
        total_length,
        source,
        destination,
        checksum_not_ready,
    )?;
    if fragment & 0x2000 != 0 {
        parsed.payload_range = Err(PacketError::NotUdpIpv4 {
            protocol,
            fragment,
            header_length,
        });
    } else if total_length != packet.len() {
        parsed.payload_range = Err(PacketError::MalformedIpv4);
    }
    Ok(parsed)
}

fn parse_ipv6_udp(packet: &Bytes, checksum_not_ready: bool) -> Result<ParsedUdp, PacketError> {
    if packet.len() < 48 || packet[0] >> 4 != 6 {
        return Err(PacketError::MalformedIpv6);
    }
    let payload_length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_length = 40 + payload_length;
    if payload_length == 0 {
        return Err(PacketError::MalformedIpv6);
    }
    let captured_end = total_length.min(packet.len());
    let mut fragment_error = None;

    let mut next_header = packet[6];
    let mut offset = 40usize;
    let mut extension_count = 0usize;
    while next_header != IPPROTO_UDP {
        extension_count += 1;
        if extension_count > 16 {
            return Err(PacketError::MalformedIpv6);
        }
        match next_header {
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                if offset + 2 > captured_end {
                    return Err(PacketError::MalformedIpv6);
                }
                let extension_length = (usize::from(packet[offset + 1]) + 1) * 8;
                if offset + extension_length > captured_end {
                    return Err(PacketError::MalformedIpv6);
                }
                next_header = packet[offset];
                offset += extension_length;
            }
            IPPROTO_FRAGMENT => {
                if offset + 8 > captured_end {
                    return Err(PacketError::MalformedIpv6);
                }
                let fragment = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                if fragment & 0xfff8 != 0 {
                    return Err(PacketError::NotUdpIpv6 {
                        next_header: packet[offset],
                        fragment,
                        header_offset: offset,
                    });
                }
                if fragment & 1 != 0 {
                    fragment_error = Some(PacketError::NotUdpIpv6 {
                        next_header: packet[offset],
                        fragment,
                        header_offset: offset,
                    });
                }
                next_header = packet[offset];
                offset += 8;
            }
            IPPROTO_AH => {
                if offset + 2 > captured_end {
                    return Err(PacketError::MalformedIpv6);
                }
                let extension_length = (usize::from(packet[offset + 1]) + 2) * 4;
                if offset + extension_length > captured_end {
                    return Err(PacketError::MalformedIpv6);
                }
                next_header = packet[offset];
                offset += extension_length;
            }
            _ => {
                return Err(PacketError::NotUdpIpv6 {
                    next_header,
                    fragment: 0,
                    header_offset: offset,
                });
            }
        }
    }

    let mut source = [0u8; 16];
    let mut destination = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    destination.copy_from_slice(&packet[24..40]);
    let mut parsed = parse_udp(
        packet,
        offset,
        total_length,
        IpAddr::V6(Ipv6Addr::from(source)),
        IpAddr::V6(Ipv6Addr::from(destination)),
        checksum_not_ready,
    )?;
    if let Some(error) = fragment_error {
        parsed.payload_range = Err(error);
    } else if total_length != packet.len() {
        parsed.payload_range = Err(PacketError::MalformedIpv6);
    }
    Ok(parsed)
}

fn parse_udp(
    packet: &Bytes,
    offset: usize,
    packet_end: usize,
    source: IpAddr,
    destination: IpAddr,
    checksum_not_ready: bool,
) -> Result<ParsedUdp, PacketError> {
    // Neither bytes beyond the declared IP length nor noninitial fragment data
    // may be used to invent a tuple for token cleanup.
    if offset + 8 > packet_end.min(packet.len()) {
        return Err(PacketError::MalformedUdp);
    }
    let udp_length = usize::from(u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]));
    let payload_range =
        if udp_length < 8 || offset + udp_length != packet_end || packet_end > packet.len() {
            Err(PacketError::MalformedUdp)
        } else {
            let checksum = u16::from_be_bytes([packet[offset + 6], packet[offset + 7]]);
            // Only CHECKSUM_PARTIAL lacks a completed checksum; NOTVERIFIED still
            // requires validation before consumers bypass the kernel UDP stack.
            if !checksum_not_ready
                && if checksum == 0 {
                    source.is_ipv6()
                } else {
                    udp_checksum(packet, offset, packet_end) != 0
                }
            {
                Err(PacketError::InvalidUdpChecksum)
            } else {
                Ok(offset + 8..packet_end)
            }
        };
    let source_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let destination_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    Ok(ParsedUdp {
        tuple: UdpTuple {
            client: SocketAddr::new(source, source_port),
            destination: SocketAddr::new(destination, destination_port),
        },
        payload_range,
    })
}

fn udp_checksum(packet: &[u8], offset: usize, packet_end: usize) -> u16 {
    let addresses = if packet[0] >> 4 == 4 {
        &packet[12..20]
    } else {
        &packet[8..40]
    };
    let mut sum = checksum_words(addresses)
        + u32::from(IPPROTO_UDP)
        + (packet_end - offset) as u32
        + checksum_words(&packet[offset..packet_end]);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum_words(bytes: &[u8]) -> u32 {
    let (words, remainder) = bytes.as_chunks::<2>();
    let sum: u32 = words
        .iter()
        .map(|word| u32::from(u16::from_be_bytes(*word)))
        .sum();
    sum + remainder.first().map_or(0, |byte| u32::from(*byte) << 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp(payload: &[u8]) -> Bytes {
        let length = 20 + 8 + payload.len();
        let mut packet = vec![0u8; length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[9] = IPPROTO_UDP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[203, 0, 113, 7]);
        packet[20..22].copy_from_slice(&53000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..26].copy_from_slice(&(8u16 + payload.len() as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        Bytes::from(packet)
    }

    fn ipv6_udp_with_destination_options(payload: &[u8]) -> Bytes {
        let payload_length = 8 + 8 + payload.len();
        let mut packet = vec![0u8; 40 + payload_length];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_length as u16).to_be_bytes());
        packet[6] = IPPROTO_DSTOPTS;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[40] = IPPROTO_UDP;
        packet[48..50].copy_from_slice(&1234u16.to_be_bytes());
        packet[50..52].copy_from_slice(&8443u16.to_be_bytes());
        packet[52..54].copy_from_slice(&(8u16 + payload.len() as u16).to_be_bytes());
        packet[56..].copy_from_slice(payload);
        let checksum = udp_checksum(&packet, 48, packet.len());
        let checksum = if checksum == 0 { u16::MAX } else { checksum };
        packet[54..56].copy_from_slice(&checksum.to_be_bytes());
        Bytes::from(packet)
    }

    fn nfqa_body(family: u8, mark: u32, packet: &Bytes, cap_len: Option<u32>) -> Bytes {
        let mut body = vec![family, 0, 1, 64];
        netlink::put_attribute(&mut body, NFQA_PACKET_HDR, &[0, 0, 0, 9, 0x08, 0x00, 0]);
        netlink::put_attribute_be32(&mut body, NFQA_MARK, mark);
        if let Some(cap_len) = cap_len {
            netlink::put_attribute_be32(&mut body, NFQA_CAP_LEN, cap_len);
        }
        netlink::put_attribute(&mut body, NFQA_PAYLOAD, packet);
        Bytes::from(body)
    }

    #[test]
    fn parses_ipv4_and_exposes_exact_mark_carrier() {
        let layer_three = ipv4_udp(b"hello");
        let received_at = Instant::now();
        let carrier = crate::NFQUEUE_SIGNATURE_MARK | 0x0123_4567;
        let parsed = parse_packet_message(
            nfqa_body(libc::AF_INET as u8, carrier, &layer_three, None),
            received_at,
        )
        .expect("valid IPv4 NFQA packet");
        assert_eq!(parsed.packet_id, 9);
        let PacketEvent::Datagram(packet) = parsed.event else {
            panic!("valid IPv4 datagram rejected");
        };
        assert_eq!(packet.mark, carrier);
        assert_eq!(packet.received_at, received_at);
        assert_eq!(packet.tuple.client, "10.0.0.2:53000".parse().unwrap());
        assert_eq!(packet.tuple.destination, "203.0.113.7:443".parse().unwrap());
        assert_eq!(packet.payload.as_ref(), b"hello");
    }

    #[test]
    fn parses_ipv6_udp_through_destination_options() {
        let layer_three = ipv6_udp_with_destination_options(b"quic");
        let parsed = parse_packet_message(
            nfqa_body(
                libc::AF_INET6 as u8,
                0x8000_0001,
                &layer_three,
                Some(layer_three.len() as u32),
            ),
            Instant::now(),
        )
        .expect("valid IPv6 NFQA packet");
        let PacketEvent::Datagram(packet) = parsed.event else {
            panic!("valid IPv6 datagram rejected");
        };
        assert_eq!(packet.tuple.client.port(), 1234);
        assert_eq!(packet.tuple.destination.port(), 8443);
        assert_eq!(packet.payload.as_ref(), b"quic");
    }

    #[test]
    fn checksums_cover_both_pseudoheaders_and_odd_payloads() {
        for (family, packet, udp_offset, source_offset, destination_offset, checksum) in [
            (
                libc::AF_INET as u8,
                ipv4_udp(b"hello"),
                20,
                12,
                16,
                0xa534u16,
            ),
            (
                libc::AF_INET6 as u8,
                ipv6_udp_with_destination_options(b"hello"),
                48,
                8,
                24,
                0x687au16,
            ),
        ] {
            let mut wire = packet.to_vec();
            // Independent wire checksums, including the odd final payload byte.
            wire[udp_offset + 6..udp_offset + 8].copy_from_slice(&checksum.to_be_bytes());
            let packet = Bytes::from(wire);
            let mark = crate::NFQUEUE_SIGNATURE_MARK | 7;
            let received_at = Instant::now();
            let parsed = parse_packet_message(nfqa_body(family, mark, &packet, None), received_at)
                .expect("valid checksummed packet envelope");
            let PacketEvent::Datagram(datagram) = parsed.event else {
                panic!("valid wire checksum rejected: {:?}", parsed.event);
            };
            assert_eq!(datagram.payload.as_ref(), b"hello");

            for corruption in [packet.len() - 1, source_offset, destination_offset] {
                let mut corrupted = packet.to_vec();
                corrupted[corruption] ^= 1;
                let parsed = parse_packet_message(
                    nfqa_body(family, mark, &Bytes::from(corrupted), None),
                    received_at,
                )
                .expect("bad checksum with an identified tuple is packet-local");
                assert!(matches!(
                    parsed.event,
                    PacketEvent::Rejected {
                        mark: carrier, received_at: time,
                        error: PacketError::InvalidUdpChecksum, ..
                    } if carrier == mark && time == received_at
                ));
            }
        }
    }

    #[test]
    fn zero_checksum_requires_ipv4_or_kernel_partial() {
        for (family, packet, udp_offset) in [
            (libc::AF_INET as u8, ipv4_udp(b"hello"), 20),
            (
                libc::AF_INET6 as u8,
                ipv6_udp_with_destination_options(b"hello"),
                48,
            ),
        ] {
            let mut packet = packet.to_vec();
            packet[udp_offset + 6..udp_offset + 8].fill(0);
            let packet = Bytes::from(packet);
            for partial in [false, true] {
                let mut body = nfqa_body(family, 0xc000_0001, &packet, None).to_vec();
                if partial {
                    netlink::put_attribute_be32(&mut body, NFQA_SKB_INFO, NFQA_SKB_CSUMNOTREADY);
                }
                let parsed = parse_packet_message(Bytes::from(body), Instant::now())
                    .expect("zero checksum must not terminate the queue");
                if family == libc::AF_INET as u8 || partial {
                    let PacketEvent::Datagram(datagram) = parsed.event else {
                        panic!(
                            "legal zero or unfinished checksum rejected: {:?}",
                            parsed.event
                        );
                    };
                    assert_eq!(datagram.payload.as_ref(), b"hello");
                } else {
                    assert!(matches!(
                        parsed.event,
                        PacketEvent::Rejected {
                            error: PacketError::InvalidUdpChecksum,
                            ..
                        }
                    ));
                }
            }
        }
    }

    #[test]
    fn only_checksum_partial_waives_checksum_not_length_validation() {
        for (family, packet, udp_offset) in [
            (libc::AF_INET as u8, ipv4_udp(b"hello"), 20),
            (
                libc::AF_INET6 as u8,
                ipv6_udp_with_destination_options(b"hello"),
                48,
            ),
        ] {
            let mut packet = packet.to_vec();
            packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&1u16.to_be_bytes());
            for flags in [1u32, 4, 2, 0x0100_0000] {
                let mut body =
                    nfqa_body(family, 0xc000_0001, &Bytes::copy_from_slice(&packet), None).to_vec();
                netlink::put_attribute_be32(&mut body, NFQA_SKB_INFO, flags);
                let parsed = parse_packet_message(Bytes::from(body), Instant::now()).unwrap();
                if flags == NFQA_SKB_CSUMNOTREADY {
                    let PacketEvent::Datagram(datagram) = parsed.event else {
                        panic!("kernel partial checksum rejected: {:?}", parsed.event);
                    };
                    assert_eq!(datagram.payload.as_ref(), b"hello");
                } else {
                    assert!(matches!(
                        parsed.event,
                        PacketEvent::Rejected {
                            error: PacketError::InvalidUdpChecksum,
                            ..
                        }
                    ));
                }
            }
            packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&8u16.to_be_bytes());
            let mut body = nfqa_body(family, 0xc000_0001, &Bytes::from(packet), None).to_vec();
            netlink::put_attribute_be32(&mut body, NFQA_SKB_INFO, NFQA_SKB_CSUMNOTREADY);
            assert!(matches!(
                parse_packet_message(Bytes::from(body), Instant::now())
                    .unwrap()
                    .event,
                PacketEvent::Rejected {
                    error: PacketError::MalformedUdp,
                    ..
                }
            ));
        }
    }

    #[test]
    fn malformed_checksum_metadata_is_an_envelope_error() {
        let packet = ipv4_udp(b"hello");
        let body = nfqa_body(libc::AF_INET as u8, 0xc000_0001, &packet, None);
        let mut invalid_length = body.to_vec();
        netlink::put_attribute(&mut invalid_length, NFQA_SKB_INFO, &[1]);
        assert!(matches!(
            parse_packet_message(Bytes::from(invalid_length), Instant::now()),
            Err(PacketError::InvalidAttributeLength {
                kind: NFQA_SKB_INFO,
                length: 1
            })
        ));
        let mut duplicate = body.to_vec();
        netlink::put_attribute_be32(&mut duplicate, NFQA_SKB_INFO, 0);
        netlink::put_attribute_be32(&mut duplicate, NFQA_SKB_INFO, NFQA_SKB_CSUMNOTREADY);
        assert!(matches!(
            parse_packet_message(Bytes::from(duplicate), Instant::now()),
            Err(PacketError::DuplicateAttribute(NFQA_SKB_INFO))
        ));
    }

    #[test]
    fn rejects_truncated_payload_without_inventing_missing_headers() {
        let cases = [
            (
                libc::AF_INET as u8,
                ipv4_udp(b"payload"),
                28,
                UdpTuple {
                    client: "10.0.0.2:53000".parse().unwrap(),
                    destination: "203.0.113.7:443".parse().unwrap(),
                },
            ),
            (
                libc::AF_INET6 as u8,
                ipv6_udp_with_destination_options(b"payload"),
                56,
                UdpTuple {
                    client: "[::1]:1234".parse().unwrap(),
                    destination: "[2001:db8::1]:8443".parse().unwrap(),
                },
            ),
        ];
        let mark = crate::NFQUEUE_SIGNATURE_MARK | 7;
        let received_at = Instant::now();
        for (family, packet, header_end, expected_tuple) in cases {
            let copied = packet.slice(..packet.len() - 1);
            let parsed = parse_packet_message(
                nfqa_body(family, mark, &copied, Some(packet.len() as u32)),
                received_at,
            )
            .expect("known tuple must reach the owner for token cleanup");
            assert!(matches!(
                parsed.event,
                PacketEvent::Rejected { tuple, mark: carrier, received_at: time, error:
                    PacketError::CaptureLengthMismatch { captured, payload } }
                    if tuple == expected_tuple && carrier == mark && time == received_at
                        && captured == packet.len() && payload == copied.len()
            ));
            let parsed = parse_packet_message(nfqa_body(family, mark, &copied, None), received_at)
                .expect("bad IP length is packet-local once the UDP header is known");
            assert!(matches!(
                parsed.event,
                PacketEvent::Rejected {
                    error: PacketError::MalformedIpv4 | PacketError::MalformedIpv6,
                    ..
                }
            ));
            assert!(matches!(
                parse_packet_message(
                    nfqa_body(family, mark, &packet, Some(packet.len() as u32 - 1)),
                    received_at,
                ),
                Err(PacketError::CaptureLengthMismatch { .. })
            ));

            let missing_header = packet.slice(..header_end - 1);
            assert!(matches!(
                parse_packet_message(
                    nfqa_body(family, mark, &missing_header, Some(packet.len() as u32)),
                    received_at,
                ),
                Err(PacketError::MalformedUdp)
            ));
        }
    }

    #[test]
    fn never_reads_truncated_ipv6_extensions_to_identify_a_tuple() {
        let packet = ipv6_udp_with_destination_options(b"payload");
        let copied = packet.slice(..41);
        assert!(matches!(
            parse_packet_message(
                nfqa_body(
                    libc::AF_INET6 as u8,
                    0xc000_0001,
                    &copied,
                    Some(packet.len() as u32)
                ),
                Instant::now(),
            ),
            Err(PacketError::MalformedIpv6)
        ));
    }

    #[test]
    fn rejects_first_fragments_but_never_identifies_noninitial_payload_as_udp() {
        let mut ipv6 = ipv6_udp_with_destination_options(b"payload").to_vec();
        ipv6[6] = IPPROTO_FRAGMENT;
        for (family, mut packet, fragment_offset, first, noninitial) in [
            (
                libc::AF_INET as u8,
                ipv4_udp(b"payload").to_vec(),
                6,
                0x2000u16,
                1u16,
            ),
            (libc::AF_INET6 as u8, ipv6, 42, 1u16, 8u16),
        ] {
            packet[fragment_offset..fragment_offset + 2].copy_from_slice(&first.to_be_bytes());
            let parsed = parse_packet_message(
                nfqa_body(family, 0xc000_0001, &Bytes::copy_from_slice(&packet), None),
                Instant::now(),
            )
            .expect("the initial fragment still has an identifiable UDP header");
            assert!(matches!(
                parsed.event,
                PacketEvent::Rejected {
                    error: PacketError::NotUdpIpv4 { .. } | PacketError::NotUdpIpv6 { .. },
                    ..
                }
            ));

            packet[fragment_offset..fragment_offset + 2].copy_from_slice(&noninitial.to_be_bytes());
            assert!(matches!(
                parse_packet_message(
                    nfqa_body(family, 0xc000_0001, &Bytes::from(packet), None),
                    Instant::now(),
                ),
                Err(PacketError::NotUdpIpv4 { .. } | PacketError::NotUdpIpv6 { .. })
            ));
        }
    }
}
