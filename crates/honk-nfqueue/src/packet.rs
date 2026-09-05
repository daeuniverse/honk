use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use bytes::Bytes;

use crate::netlink;

const NFQA_PACKET_HDR: u16 = 1;
const NFQA_MARK: u16 = 3;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_CAP_LEN: u16 = 13;
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
}

#[derive(Debug)]
pub(crate) struct ParsedPacket {
    pub(crate) packet_id: u32,
    pub(crate) packet: QueuedPacket,
}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PacketMessageError {
    #[error("{0}")]
    Message(#[from] PacketError),
    #[error("packet {packet_id}: {error}")]
    Packet {
        packet_id: u32,
        #[source]
        error: PacketError,
    },
}

pub(crate) fn parse_packet_message(
    body: Bytes,
    received_at: Instant,
) -> Result<ParsedPacket, PacketMessageError> {
    if body.len() < netlink::NFGENMSG_LEN {
        return Err(PacketError::TruncatedNfgenmsg.into());
    }
    let family = body[0];
    if family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8 {
        return Err(PacketError::UnexpectedFamily(family).into());
    }

    let mut packet_id = None;
    let mut mark = None;
    let mut payload = None;
    let mut capture_length = None;
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
                    }
                    .into());
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
            _ => {}
        }
    }

    let packet_id = packet_id.ok_or(PacketError::MissingPacketHeader)?;
    let mark = mark.ok_or(PacketError::MissingMark)?;
    let layer_three = payload.ok_or(PacketError::MissingPayload)?;
    if let Some(captured) = capture_length
        && captured != layer_three.len()
    {
        let error = PacketError::CaptureLengthMismatch {
            captured,
            payload: layer_three.len(),
        };
        if captured > layer_three.len() {
            return Err(PacketMessageError::Packet { packet_id, error });
        }
        return Err(error.into());
    }

    let family_from_packet = layer_three
        .first()
        .map(|first| first >> 4)
        .ok_or(PacketError::NotIpDatagram)?;
    if (family == libc::AF_INET as u8 && family_from_packet != 4)
        || (family == libc::AF_INET6 as u8 && family_from_packet != 6)
    {
        return Err(PacketError::UnexpectedFamily(family).into());
    }
    let (tuple, payload_range) = match family_from_packet {
        4 => parse_ipv4_udp(&layer_three),
        6 => parse_ipv6_udp(&layer_three),
        _ => return Err(PacketError::NotIpDatagram.into()),
    }
    .map_err(|error| PacketMessageError::Packet { packet_id, error })?;

    Ok(ParsedPacket {
        packet_id,
        packet: QueuedPacket {
            tuple,
            payload: layer_three.slice(payload_range),
            mark,
            received_at,
        },
    })
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

fn parse_ipv4_udp(packet: &Bytes) -> Result<(UdpTuple, std::ops::Range<usize>), PacketError> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return Err(PacketError::MalformedIpv4);
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return Err(PacketError::MalformedIpv4);
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length != packet.len() || total_length < header_length + 8 {
        return Err(PacketError::MalformedIpv4);
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let protocol = packet[9];
    if fragment & 0x3fff != 0 || protocol != IPPROTO_UDP {
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
    parse_udp(packet, header_length, total_length, source, destination)
}

fn parse_ipv6_udp(packet: &Bytes) -> Result<(UdpTuple, std::ops::Range<usize>), PacketError> {
    if packet.len() < 48 || packet[0] >> 4 != 6 {
        return Err(PacketError::MalformedIpv6);
    }
    let payload_length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_length = 40usize
        .checked_add(payload_length)
        .ok_or(PacketError::MalformedIpv6)?;
    if payload_length == 0 || total_length != packet.len() {
        return Err(PacketError::MalformedIpv6);
    }

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
                if offset + 2 > total_length {
                    return Err(PacketError::MalformedIpv6);
                }
                let extension_length = (usize::from(packet[offset + 1]) + 1) * 8;
                if extension_length < 8 || offset + extension_length > total_length {
                    return Err(PacketError::MalformedIpv6);
                }
                next_header = packet[offset];
                offset += extension_length;
            }
            IPPROTO_FRAGMENT => {
                if offset + 8 > total_length {
                    return Err(PacketError::MalformedIpv6);
                }
                let fragment = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                if fragment & 0xfff9 != 0 {
                    return Err(PacketError::NotUdpIpv6 {
                        next_header: packet[offset],
                        fragment,
                        header_offset: offset,
                    });
                }
                next_header = packet[offset];
                offset += 8;
            }
            IPPROTO_AH => {
                if offset + 2 > total_length {
                    return Err(PacketError::MalformedIpv6);
                }
                let extension_length = (usize::from(packet[offset + 1]) + 2) * 4;
                if extension_length < 8 || offset + extension_length > total_length {
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
    parse_udp(
        packet,
        offset,
        total_length,
        IpAddr::V6(Ipv6Addr::from(source)),
        IpAddr::V6(Ipv6Addr::from(destination)),
    )
}

fn parse_udp(
    packet: &Bytes,
    offset: usize,
    packet_end: usize,
    source: IpAddr,
    destination: IpAddr,
) -> Result<(UdpTuple, std::ops::Range<usize>), PacketError> {
    if offset + 8 > packet_end {
        return Err(PacketError::MalformedUdp);
    }
    let udp_length = usize::from(u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]));
    if udp_length < 8 || offset + udp_length != packet_end {
        return Err(PacketError::MalformedUdp);
    }
    let source_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let destination_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    Ok((
        UdpTuple {
            client: SocketAddr::new(source, source_port),
            destination: SocketAddr::new(destination, destination_port),
        },
        offset + 8..packet_end,
    ))
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
        assert_eq!(crate::NFQUEUE_SIGNATURE_MARK, 0xc000_0000);
        let carrier = crate::NFQUEUE_SIGNATURE_MARK | 0x0123_4567;
        let parsed = parse_packet_message(
            nfqa_body(libc::AF_INET as u8, carrier, &layer_three, None),
            received_at,
        )
        .expect("valid IPv4 NFQA packet");
        assert_eq!(parsed.packet_id, 9);
        assert_eq!(parsed.packet.mark, carrier);
        assert_eq!(parsed.packet.received_at, received_at);
        assert_eq!(
            parsed.packet.tuple.client,
            "10.0.0.2:53000".parse().unwrap()
        );
        assert_eq!(
            parsed.packet.tuple.destination,
            "203.0.113.7:443".parse().unwrap()
        );
        assert_eq!(parsed.packet.payload.as_ref(), b"hello");
    }

    #[test]
    fn parses_ipv6_extension_chain_without_copying_udp_payload() {
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
        assert_eq!(parsed.packet.tuple.client.port(), 1234);
        assert_eq!(parsed.packet.tuple.destination.port(), 8443);
        assert_eq!(parsed.packet.payload.as_ref(), b"quic");
    }
    #[test]
    fn rejects_cap_len_mismatch_and_fragments() {
        let layer_three = ipv4_udp(b"payload");
        let mismatch = parse_packet_message(
            nfqa_body(
                libc::AF_INET as u8,
                0x8000_0001,
                &layer_three,
                Some(layer_three.len() as u32 + 1),
            ),
            Instant::now(),
        );
        assert!(matches!(
            mismatch,
            Err(PacketMessageError::Packet {
                packet_id: 9,
                error: PacketError::CaptureLengthMismatch { .. },
            })
        ));

        let mut fragmented = layer_three.to_vec();
        fragmented[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        let fragmented = Bytes::from(fragmented);
        assert_eq!(
            parse_packet_message(
                nfqa_body(libc::AF_INET as u8, 0x8000_0001, &fragmented, None),
                Instant::now()
            )
            .unwrap_err(),
            PacketMessageError::Packet {
                packet_id: 9,
                error: PacketError::NotUdpIpv4 {
                    protocol: IPPROTO_UDP,
                    fragment: 0x2000,
                    header_length: 20,
                },
            }
        );
    }
}
