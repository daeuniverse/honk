use super::*;
use crate::{ScopeId, forward::MarkProvenance};
use std::net::SocketAddr;

fn ingress(ifindex: u32) -> Ingress {
    Ingress {
        scope: ScopeId::HOST,
        namespace: 1,
        ifindex,
        attachment: u64::from(ifindex),
        mark: MarkProvenance::BeforeSkb,
    }
}
fn tuple(source: &str, destination: &str, protocol: u8) -> Tuple {
    let source: SocketAddr = source.parse().unwrap();
    let destination: SocketAddr = destination.parse().unwrap();
    Tuple {
        source: source.ip(),
        destination: destination.ip(),
        source_port: source.port(),
        destination_port: destination.port(),
        protocol,
    }
}
fn udp(tuple: Tuple) -> Vec<u8> {
    let mut bytes = vec![0; 128];
    let len = wire::udp::emit_packet(
        &mut bytes,
        SocketAddr::new(tuple.source, tuple.source_port),
        SocketAddr::new(tuple.destination, tuple.destination_port),
        b"proof",
    )
    .unwrap();
    bytes.truncate(len);
    bytes
}
fn tcp_packet(tuple: Tuple, flags: u8, seq: u32, ack: u32) -> Vec<u8> {
    tcp_packet_data(tuple, flags, seq, ack, &[])
}
fn tcp_packet_data(tuple: Tuple, flags: u8, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 128];
    let header = tcp::Header {
        src_port: tuple.source_port,
        dst_port: tuple.destination_port,
        seq,
        ack,
        flags,
        window: 4096,
        urgent: 0,
        options: Default::default(),
    };
    let len = tcp::emit_packet(
        &mut bytes,
        tuple.source,
        tuple.destination,
        &header,
        [payload, &[]],
    )
    .unwrap();
    bytes.truncate(len);
    bytes
}
fn table() -> Firewall {
    Firewall::new(MemoryBudget::new(1024 * 1024), 8, 1).unwrap()
}
fn snat() -> SourceNat {
    SourceNat::Snat {
        address: "198.51.100.1".parse().unwrap(),
        ports: Some(PortPool {
            first: 40000,
            last: 40000,
        }),
    }
}

fn obligation(ingress: Ingress, tuple: Tuple) -> FragmentObligation {
    FragmentObligation {
        ingress,
        source: tuple.source,
        destination: tuple.destination,
        protocol: tuple.protocol,
    }
}

fn seal_ipv4(bytes: &mut [u8]) {
    let header = usize::from(bytes[0] & 15) * 4;
    bytes[10..12].fill(0);
    let checksum = wire::checksum::checksum(&bytes[..header]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn fragmentable_udp(tuple: Tuple, id: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 28 + payload.len()];
    wire::udp::emit_packet(
        &mut bytes,
        SocketAddr::new(tuple.source, tuple.source_port),
        SocketAddr::new(tuple.destination, tuple.destination_port),
        payload,
    )
    .unwrap();
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    bytes[6..8].fill(0);
    bytes[26..28].fill(0);
    seal_ipv4(&mut bytes);
    bytes
}

fn forward_datagram(
    core: &mut crate::forward::CoreForward,
    packet: crate::forward::Packet,
    mtu: u32,
    egress: u32,
    now: Instant,
) -> Vec<(Vec<u8>, crate::forward::ForwardLease)> {
    use crate::forward::{LinkPath, Prepared, Route};
    let route = Route {
        generation: 1,
        ifindex: egress,
        l2: LinkPath::untagged(egress),
        mtu,
        next_hop: packet.query().destination,
        preferred_source: None,
        source_mac: [2, 0, 0, 0, 0, 1],
        destination_mac: [2, 0, 0, 0, 0, 2],
    };
    let Prepared::Forward(mut output) = core.prepare(packet, route, 1, now).unwrap() else {
        panic!("unexpected transit refusal")
    };
    let mut fragments = Vec::new();
    while let Some(length) = output.next_len() {
        let mut bytes = vec![0; length];
        let (written, lease) = output.write_next(&mut bytes).unwrap();
        assert_eq!(written, length);
        fragments.push((bytes, lease));
    }
    fragments
}

fn quoted_error(quote: &[u8]) -> Vec<u8> {
    let destination = IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&quote[12..16]).unwrap()));
    let mut bytes = vec![0; 28 + quote.len()];
    wire::emit_ip_header(
        &mut bytes,
        "192.0.2.254".parse().unwrap(),
        destination,
        wire::PROTO_ICMP,
        8 + quote.len(),
    )
    .unwrap();
    bytes[20] = 3;
    bytes[21] = 1;
    bytes[28..].copy_from_slice(quote);
    let checksum = wire::checksum::checksum(&bytes[20..]);
    bytes[22..24].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

mod fragments;
mod native_ids;
mod ownership;
mod tcp_state;
mod translation;
