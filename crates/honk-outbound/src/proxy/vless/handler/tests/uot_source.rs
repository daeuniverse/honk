use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

// An independent UoT v2 non-connect peer: every byte is spelled out from the
// wire spec (request mode byte 0 + SOCKS5 address; packets in UoT v1 form with
// ATYP IPv4=0 / IPv6=1 / domain=2), never produced by the codec under test.
const A: &str = "198.51.100.10:5301";
const B: &str = "203.0.113.20:5302";
const C: &str = "192.0.2.30:5303";
const A_REQUEST: [u8; 8] = [0x00, 0x01, 198, 51, 100, 10, 0x14, 0xb5];
const A_ADDR: [u8; 5] = [0x00, 198, 51, 100, 10];
const B_ADDR: [u8; 5] = [0x00, 203, 0, 113, 20];
const C_ADDR: [u8; 5] = [0x00, 192, 0, 2, 30];
const C6_ADDR: [u8; 17] = [
    0x01, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x30,
];
const MAPPED_C_ADDR: [u8; 17] = [
    0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 30,
];

fn sock(address: &str) -> SocketAddr {
    address.parse().unwrap()
}

fn packet(address: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = address.to_vec();
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn domain_address(domain: &str) -> Vec<u8> {
    let mut address = vec![0x02, domain.len() as u8];
    address.extend_from_slice(domain.as_bytes());
    address
}

fn uot_pair(
    target: &str,
    domain: Option<&str>,
    request: &'static [u8],
) -> (Arc<VlessUotTransport>, tokio::io::DuplexStream) {
    let (client, server) = tokio::io::duplex(1 << 20);
    let transport = VlessUotTransport::new(
        Box::new(client),
        sock(target),
        domain,
        bytes::Bytes::from_static(request),
        Some(false),
    );
    (Arc::new(transport), server)
}

async fn read_exact(wire: &mut tokio::io::DuplexStream, len: usize) -> Vec<u8> {
    let mut buffer = vec![0; len];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        wire.read_exact(&mut buffer),
    )
    .await
    .expect("UoT bytes must arrive")
    .unwrap();
    buffer
}

async fn recv(transport: &VlessUotTransport) -> (Vec<u8>, SocketAddr) {
    let mut buffer = vec![0; u16::MAX as usize];
    let (size, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        transport.recv_packet(&mut buffer),
    )
    .await
    .expect("UoT datagram must arrive")
    .unwrap();
    buffer.truncate(size);
    (buffer, peer)
}

/// The request names the first destination once; every datagram, first or
/// later, to any destination, carries its own address.
#[tokio::test]
async fn uot_send_to_addresses_each_datagram_and_sends_the_request_once() {
    let (transport, mut wire) = uot_pair(A, None, &A_REQUEST);
    let admitted = AtomicBool::new(false);
    transport
        .send_to(sock(A), None, b"to-a", true, Some(&admitted))
        .await
        .unwrap();
    assert!(admitted.load(Ordering::Acquire));
    let first = [&A_REQUEST[..], &packet(&A_ADDR, 5301, b"to-a")].concat();
    assert_eq!(read_exact(&mut wire, first.len()).await, first);

    transport
        .send_to(sock(B), None, b"to-b", false, None)
        .await
        .unwrap();
    let second = packet(&B_ADDR, 5302, b"to-b");
    assert_eq!(read_exact(&mut wire, second.len()).await, second);

    transport
        .send_to(sock("[2001:db8::30]:5304"), None, b"to-6", false, None)
        .await
        .unwrap();
    let v6 = packet(&C6_ADDR, 5304, b"to-6");
    assert_eq!(read_exact(&mut wire, v6.len()).await, v6);

    // A name this association was not dialed by never reaches the wire; an
    // empty datagram is representable.
    transport
        .send_to(sock(C), Some("Dns.Example"), b"", false, None)
        .await
        .unwrap();
    let numeric = packet(&C_ADDR, 5303, b"");
    assert_eq!(read_exact(&mut wire, numeric.len()).await, numeric);

    // The fixed-target ordinary path uses the same frame shape.
    transport.send_packet(b"dflt").await.unwrap();
    let ordinary = packet(&A_ADDR, 5301, b"dflt");
    assert_eq!(read_exact(&mut wire, ordinary.len()).await, ordinary);
}

#[tokio::test]
async fn checked_uot_send_retains_setup_before_custody_and_completes_after_custody() {
    for free in [0, 1] {
        let (mut client, mut wire) = tokio::io::duplex(32);
        let prior = vec![0xee; 32 - free];
        client.write_all(&prior).await.unwrap();
        let transport = VlessUotTransport::new(
            Box::new(client),
            sock(A),
            None,
            bytes::Bytes::from_static(&A_REQUEST),
            Some(false),
        );
        let current = AtomicBool::new(true);
        let allowed = || current.load(Ordering::Acquire);
        let admitted = AtomicBool::new(false);
        let mut send = std::pin::pin!(transport.send_to_checked(
            sock(A),
            None,
            b"first",
            Some(&admitted),
            &allowed,
        ));
        assert!(futures_util::poll!(send.as_mut()).is_pending());
        assert_eq!(admitted.load(Ordering::Acquire), free != 0);
        current.store(false, Ordering::Release);
        assert_eq!(read_exact(&mut wire, prior.len()).await, prior);

        let mut sibling = packet(&B_ADDR, 5302, b"sibling");
        if free == 0 {
            let error = send.await.unwrap_err();
            assert_eq!(
                crate::proxy::io_packet_rejection(&error),
                Some(PacketRejection::Cancelled),
            );
            assert!(!admitted.load(Ordering::Acquire));
            sibling = [&A_REQUEST[..], &sibling].concat();
        } else {
            send.await.unwrap();
            let first = [&A_REQUEST[..], &packet(&A_ADDR, 5301, b"first")].concat();
            assert_eq!(read_exact(&mut wire, first.len()).await, first);
        }
        assert!(!transport.frame_stream_torn());
        transport
            .send_to(sock(B), None, b"sibling", false, None)
            .await
            .unwrap();
        assert_eq!(read_exact(&mut wire, sibling.len()).await, sibling);
    }
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn checked_uot_first_range_carries_confirmed_request_observation() {
    use crate::proxy::request_observation_support::{DeferringCarrier, milestones, observed};
    use crate::runtime::flow_observation::Milestone;

    let (client, mut wire) = tokio::io::duplex(64);
    let (carrier, pending) = DeferringCarrier::new(client);
    let transport = VlessUotTransport::new(
        Box::new(carrier),
        sock(A),
        None,
        bytes::Bytes::from_static(&A_REQUEST),
        Some(false),
    );
    let (observer, events) = observed();
    observer
        .scope(transport.send_to_checked(sock(A), None, b"first", None, &|| true))
        .await
        .unwrap();
    let first = [&A_REQUEST[..], &packet(&A_ADDR, 5301, b"first")].concat();
    assert_eq!(read_exact(&mut wire, first.len()).await, first);
    assert_eq!(milestones(&events.lock(), Milestone::TargetRequestSent), 0);
    let (receipt, end) = pending.lock().take().unwrap();
    assert_eq!(end, first.len() as u64);
    receipt.confirm();
    assert_eq!(milestones(&events.lock(), Milestone::TargetRequestSent), 1);
}

/// A server pins its outbound form by the first destination: the dialed name
/// is the only one a datagram may carry, so a second flow's name goes numeric.
#[tokio::test]
async fn uot_per_packet_domain_is_only_the_dialed_one() {
    let (transport, mut wire) = uot_pair(C, Some("Dns.Example"), &A_REQUEST);
    transport
        .send_to(sock(C), Some("Dns.Example"), b"dialed", false, None)
        .await
        .unwrap();
    let first = [
        &A_REQUEST[..],
        &packet(&domain_address("Dns.Example"), 5303, b"dialed"),
    ]
    .concat();
    assert_eq!(read_exact(&mut wire, first.len()).await, first);
    for (domain, payload) in [(Some("Other.Example"), &b"other"[..]), (None, b"none")] {
        transport
            .send_to(sock(C), domain, payload, false, None)
            .await
            .unwrap();
        let numeric = packet(&C_ADDR, 5303, payload);
        assert_eq!(read_exact(&mut wire, numeric.len()).await, numeric);
    }
}

#[tokio::test]
async fn uot_uplink_boundary_and_local_rejection_leave_the_stream_usable() {
    let (transport, mut wire) = uot_pair(A, None, &A_REQUEST);
    let oversized = vec![0; u16::MAX as usize + 1];
    let error = transport
        .send_to(sock(B), None, &oversized, false, None)
        .await
        .unwrap_err();
    assert!(crate::proxy::is_packet_rejection(&anyhow::Error::new(
        error
    )));

    // The rejection consumed neither the pending request nor wrote anything.
    let maximum = vec![0x5a; u16::MAX as usize];
    let sending = {
        let transport = Arc::clone(&transport);
        let maximum = maximum.clone();
        tokio::spawn(async move { transport.send_to(sock(B), None, &maximum, true, None).await })
    };
    let expected = [&A_REQUEST[..], &packet(&B_ADDR, 5302, &maximum)].concat();
    assert_eq!(read_exact(&mut wire, expected.len()).await, expected);
    sending.await.unwrap().unwrap();
}

#[tokio::test]
async fn uot_replies_keep_real_sources_across_destinations() {
    let (transport, mut wire) = uot_pair(A, None, &A_REQUEST);
    let mut reply = Vec::new();
    reply.extend(packet(&A_ADDR, 5301, b"from-a"));
    reply.extend(packet(&B_ADDR, 5302, b"from-b"));
    // Never contacted: still reported with its exact numeric source.
    reply.extend(packet(&C_ADDR, 5303, b"from-c"));
    reply.extend(packet(&C6_ADDR, 5304, b"from-c6"));
    // An IPv4-mapped IPv6 source is the IPv4 peer.
    reply.extend(packet(&MAPPED_C_ADDR, 5305, b"mapped"));
    reply.extend(packet(&C_ADDR, 5306, b""));
    wire.write_all(&reply).await.unwrap();

    for (payload, peer) in [
        (&b"from-a"[..], A),
        (b"from-b", B),
        (b"from-c", C),
        (b"from-c6", "[2001:db8::30]:5304"),
        (b"mapped", "192.0.2.30:5305"),
        (b"", "192.0.2.30:5306"),
    ] {
        assert_eq!(recv(&transport).await, (payload.to_vec(), sock(peer)));
    }
}

#[tokio::test]
async fn uot_domain_sources_project_only_the_captured_name() {
    let (transport, mut wire) = uot_pair(A, Some("Example.COM"), &A_REQUEST);
    let mut reply = Vec::new();
    // Dropped without DNS and consumed whole, payload bytes included.
    reply.extend(packet(&domain_address("other.example"), 5301, b"stranger"));
    reply.extend(packet(&domain_address("example.com"), 9999, b"wrong-port"));
    reply.extend(packet(&domain_address(""), 5301, b"empty-name"));
    // Case-insensitive match on name and port projects to the captured target.
    reply.extend(packet(&domain_address("EXAMPLE.com"), 5301, b"projected"));
    reply.extend(packet(&B_ADDR, 5302, b"numeric"));
    wire.write_all(&reply).await.unwrap();

    assert_eq!(recv(&transport).await, (b"projected".to_vec(), sock(A)));
    assert_eq!(recv(&transport).await, (b"numeric".to_vec(), sock(B)));

    // Without a captured domain every domain source is dropped.
    let (numeric, mut wire) = uot_pair(A, None, &A_REQUEST);
    wire.write_all(&packet(&domain_address("example.com"), 5301, b"x"))
        .await
        .unwrap();
    wire.write_all(&packet(&C_ADDR, 5303, b"after"))
        .await
        .unwrap();
    assert_eq!(recv(&numeric).await, (b"after".to_vec(), sock(C)));
}

#[tokio::test]
async fn uot_frames_decode_across_arbitrary_stream_splits_and_at_the_maximum() {
    let (transport, mut wire) = uot_pair(A, None, &A_REQUEST);
    let maximum = vec![0xa5; u16::MAX as usize];
    let mut reply = packet(&C_ADDR, 5303, &maximum);
    reply.extend(packet(&B_ADDR, 5302, b"tail"));
    let writer = tokio::spawn(async move {
        for chunk in reply.chunks(1021) {
            wire.write_all(chunk).await.unwrap();
        }
        wire
    });
    assert_eq!(recv(&transport).await, (maximum, sock(C)));
    assert_eq!(recv(&transport).await, (b"tail".to_vec(), sock(B)));
    drop(writer.await.unwrap());
}

#[tokio::test]
async fn uot_short_buffer_error_keeps_the_frame_and_unknown_atyp_is_terminal() {
    let (transport, mut wire) = uot_pair(A, None, &A_REQUEST);
    wire.write_all(&packet(&C_ADDR, 5303, b"payload"))
        .await
        .unwrap();
    let error = transport.recv_packet(&mut [0; 2]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(recv(&transport).await, (b"payload".to_vec(), sock(C)));

    // An unknown address type has no derivable length: the stream is lost.
    wire.write_all(&[0x03, 1, 2, 3]).await.unwrap();
    let error = transport.recv_packet(&mut [0; 8]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn dropping_a_uot_transport_closes_its_stream() {
    let (transport, mut wire) = uot_pair(A, None, &A_REQUEST);
    drop(transport);
    let mut rest = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        wire.read_to_end(&mut rest),
    )
    .await
    .expect("dropping the transport must close the carrier")
    .unwrap();
    assert!(rest.is_empty());
}

/// A frame write cancelled halfway leaves a torn frame on the shared stream;
/// a sibling destination must fail rather than append to it, even once the
/// peer drains again.
#[tokio::test]
async fn uot_cancelled_partial_write_poisons_the_shared_stream() {
    let (client, mut wire) = tokio::io::duplex(16);
    let transport = VlessUotTransport::new(
        Box::new(client),
        sock(A),
        None,
        bytes::Bytes::from_static(&A_REQUEST),
        Some(false),
    );
    let stalled = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        transport.send_to(sock(A), None, &[7; 4096], false, None),
    )
    .await;
    assert!(stalled.is_err(), "the unread stream must stall the write");
    assert!(transport.frame_stream_torn());
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut wire, &mut tokio::io::sink()).await;
    });
    let error = transport
        .send_to(sock(B), None, b"b", false, None)
        .await
        .unwrap_err();
    assert!(crate::proxy::is_frame_interrupted(&error));
}
