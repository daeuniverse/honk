use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};

/// Independent peer-side codec: addresses are spelled out byte by byte so
/// the production encoder and decoder are not what verifies each other.
fn wire_addr(peer: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match peer {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&peer.port().to_be_bytes());
    out
}

fn wire_domain(domain: &str, port: u16) -> Vec<u8> {
    let mut out = vec![0x03, domain.len() as u8];
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

fn frame(address: Vec<u8>, payload: &[u8]) -> Vec<u8> {
    let mut out = address;
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(payload);
    out
}

/// Read one frame as the server would: SOCKS5 address, length, CRLF, payload.
async fn read_frame<R: AsyncReadExt + Unpin>(server: &mut R) -> (SocketAddr, Vec<u8>) {
    let mut atyp = [0u8; 1];
    server.read_exact(&mut atyp).await.unwrap();
    let peer = match atyp[0] {
        0x01 => {
            let mut ip = [0u8; 4];
            server.read_exact(&mut ip).await.unwrap();
            let mut port = [0u8; 2];
            server.read_exact(&mut port).await.unwrap();
            SocketAddr::new(Ipv4Addr::from(ip).into(), u16::from_be_bytes(port))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            server.read_exact(&mut ip).await.unwrap();
            let mut port = [0u8; 2];
            server.read_exact(&mut port).await.unwrap();
            SocketAddr::new(Ipv6Addr::from(ip).into(), u16::from_be_bytes(port))
        }
        other => panic!("unexpected ATYP {other:#x}"),
    };
    let mut head = [0u8; 4];
    server.read_exact(&mut head).await.unwrap();
    assert_eq!(&head[2..], b"\r\n");
    let mut payload = vec![0u8; u16::from_be_bytes([head[0], head[1]]) as usize];
    server.read_exact(&mut payload).await.unwrap();
    (peer, payload)
}

fn transport_over<S: AsyncReadWrite + 'static>(
    stream: S,
    target: SocketAddr,
    domain: Option<&str>,
) -> TrojanUdpTransport {
    let (rd, wr) = tokio::io::split(Box::new(stream) as Box<dyn AsyncReadWrite>);
    TrojanUdpTransport {
        writer: tokio::sync::Mutex::new(wr),
        poison: crate::proxy::FramePoison::default(),
        reader: tokio::sync::Mutex::new(rd),
        addr_header: addr::encode_address(target, domain).unwrap(),
        domain: domain.map(Box::from),
        relay_addr: target,
        exit: None,
        tls_handoff: Some(false),
    }
}

/// send_packet frames `addr|len|CRLF|payload`; recv_packet unframes the
/// same shape back. Round-tripped over a duplex pair.
#[tokio::test]
async fn trojan_udp_transport_frame_roundtrip() {
    let (client, mut server) = tokio::io::duplex(8192);
    let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let transport = transport_over(client, target, None);

    transport.send_packet(b"hello-trojan-udp").await.unwrap();
    assert_eq!(
        read_frame(&mut server).await,
        (target, b"hello-trojan-udp".to_vec())
    );

    server
        .write_all(&frame(wire_addr(target), b"pong!"))
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"pong!");
    assert_eq!(src, target);
}

/// Two destinations share one stream; a never-contacted peer may answer
/// first; every reply keeps its own real source.
#[tokio::test]
async fn shared_stream_carries_each_destination_and_returns_real_sources() {
    let (client, mut server) = tokio::io::duplex(1 << 17);
    let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let b: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
    let c: SocketAddr = "198.51.100.9:3478".parse().unwrap();
    let mapped_c: SocketAddr = "[::ffff:198.51.100.9]:3478".parse().unwrap();
    let transport = transport_over(client, a, None);

    transport
        .send_to(a, None, b"to-a", false, None)
        .await
        .unwrap();
    transport
        .send_to(b, None, b"to-b", true, None)
        .await
        .unwrap();
    transport.send_to(b, None, b"", false, None).await.unwrap();
    let max = vec![0x5a; u16::MAX as usize];
    transport.send_to(a, None, &max, false, None).await.unwrap();
    assert_eq!(read_frame(&mut server).await, (a, b"to-a".to_vec()));
    assert_eq!(read_frame(&mut server).await, (b, b"to-b".to_vec()));
    assert_eq!(read_frame(&mut server).await, (b, Vec::new()));
    assert_eq!(read_frame(&mut server).await, (a, max));
    let too_big = vec![0u8; u16::MAX as usize + 1];
    let error = transport
        .send_to(a, None, &too_big, false, None)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let mut buf = vec![0u8; 65536];
    for (source, wire, payload) in [
        (c, wire_addr(c), &b"unsolicited"[..]),
        (c, wire_addr(mapped_c), &b"mapped"[..]),
        (a, wire_addr(a), &b"from-a"[..]),
        (b, wire_addr(b), &b""[..]),
    ] {
        server.write_all(&frame(wire, payload)).await.unwrap();
        let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!((peer, &buf[..n]), (source, payload));
    }
}

/// Only the dialed name goes on the wire: a real server pins its outbound
/// form by the first destination, so any other name is sent numerically.
#[tokio::test]
async fn per_packet_domain_is_only_the_dialed_one() {
    let (client, mut server) = tokio::io::duplex(8192);
    let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let transport = transport_over(client, a, Some("example.com"));

    transport
        .send_to(a, Some("example.com"), b"dialed", false, None)
        .await
        .unwrap();
    let expected = frame(wire_domain("example.com", 53), b"dialed");
    let mut wire = vec![0u8; expected.len()];
    server.read_exact(&mut wire).await.unwrap();
    assert_eq!(wire, expected);

    transport
        .send_to(a, Some("other.example"), b"other", false, None)
        .await
        .unwrap();
    assert_eq!(read_frame(&mut server).await, (a, b"other".to_vec()));
    transport
        .send_to(a, None, b"numeric", false, None)
        .await
        .unwrap();
    assert_eq!(read_frame(&mut server).await, (a, b"numeric".to_vec()));
}

/// A frame named by a domain other than the captured one is consumed whole
/// (even when its payload exceeds the receive buffer) and the stream stays
/// aligned for the next frame.
#[tokio::test]
async fn unrecognised_domain_frames_are_consumed_and_the_next_decodes() {
    let (client, mut server) = tokio::io::duplex(1 << 16);
    let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let transport = transport_over(client, target, Some("Example.com"));
    let numeric: SocketAddr = "203.0.113.5:9".parse().unwrap();

    let big = vec![0xee; 1000];
    let mut wire = frame(wire_domain("other.example", 443), &big);
    wire.extend(frame(wire_domain("example.com", 444), b"wrong-port"));
    wire.extend(frame(wire_domain("EXAMPLE.COM", 443), b"mine"));
    wire.extend(frame(wire_domain("other.example", 443), b""));
    wire.extend(frame(wire_addr(numeric), b"next"));
    server.write_all(&wire).await.unwrap();

    // Dropped payloads may exceed both the output buffer and discard scratch.
    let mut buf = [0u8; 8];
    let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!((peer, &buf[..n]), (target, &b"mine"[..]));
    let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!((peer, &buf[..n]), (numeric, &b"next"[..]));

    for payload in [&b"mine"[..], &b""[..]] {
        for address in [
            vec![0x03, 0, 0x01, 0xbb],
            vec![0x03, 2, 0xff, 0xfe, 0x01, 0xbb],
        ] {
            let mut wire = frame(address, b"dropped");
            wire.extend(frame(wire_domain("example.com", 443), payload));
            server.write_all(&wire).await.unwrap();

            let mut buf = [0u8; 16];
            let (n, peer) = transport
                .recv_packet(&mut buf[..payload.len()])
                .await
                .unwrap();
            assert_eq!((peer, &buf[..n]), (target, payload));
        }
    }
}

/// Without a captured domain no domain-named frame can be projected.
#[tokio::test]
async fn domain_frame_without_captured_domain_is_dropped() {
    let (client, mut server) = tokio::io::duplex(4096);
    let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let transport = transport_over(client, target, None);
    let mut wire = frame(wire_domain("example.com", 443), b"dropped");
    wire.extend(frame(wire_addr(target), b"kept"));
    server.write_all(&wire).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!((peer, &buf[..n]), (target, &b"kept"[..]));
}

/// An unknown ATYP has no derivable length: the stream cannot be realigned.
#[tokio::test]
async fn unknown_atyp_is_terminal() {
    let (client, mut server) = tokio::io::duplex(4096);
    let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let transport = transport_over(client, target, None);
    server
        .write_all(&frame(vec![0x09, 1, 2, 3, 4, 0, 53], b"x"))
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let error = transport.recv_packet(&mut buf).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn trojan_udp_requires_complete_crlf_delimiter() {
    use std::io::ErrorKind;

    let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
    for (delimiter, expected) in [
        (&b"\r"[..], ErrorKind::UnexpectedEof),
        (&b"\r!"[..], ErrorKind::InvalidData),
    ] {
        let (client, mut server) = tokio::io::duplex(64);
        let transport = transport_over(client, target, None);
        let mut wire = wire_addr(target);
        wire.extend_from_slice(&[0, 0]);
        wire.extend_from_slice(delimiter);
        server.write_all(&wire).await.unwrap();
        drop(server);

        let error = transport.recv_packet(&mut []).await.unwrap_err();
        assert_eq!(error.kind(), expected);
        assert_eq!(crate::proxy::error::hop_io_failure(&error), None);
    }
}

#[tokio::test]
async fn checked_first_frame_rechecks_zero_progress_but_finishes_after_custody() {
    let target = "192.0.2.1:53".parse().unwrap();
    let sibling = "192.0.2.2:443".parse().unwrap();
    let payload = b"first";
    for (security, carrier, free, handed_off) in [
        ("none", "tcp", 0, false),
        ("none", "tcp", 1, true),
        ("tls", "tcp", 0, true),
        ("reality", "tcp", 0, true),
        ("tls", "ws", 0, false),
        ("tls", "grpc", 0, false),
        ("tls", "grpc", 1, true),
    ] {
        let mut node = Node {
            outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
            ..Default::default()
        };
        let tls = node.tls_mut().unwrap();
        tls.enabled = security == "tls";
        tls.reality_public_key = (security == "reality").then(|| "AAA".into());
        node.transport_mut().unwrap().transport = carrier.into();
        let (mut client, mut server) = tokio::io::duplex(64);
        let prior = vec![0xee; 64 - free];
        client.write_all(&prior).await.unwrap();
        let mut transport = transport_over(client, target, None);
        transport.tls_handoff = crate::proxy::chain::native_udp_writer_handoff(&node);
        let current = AtomicBool::new(true);
        let allowed = || current.load(Ordering::Acquire);
        let admitted = AtomicBool::new(false);
        let mut send = std::pin::pin!(transport.send_to_checked(
            target,
            None,
            payload,
            Some(&admitted),
            &allowed,
        ));
        assert!(futures_util::poll!(send.as_mut()).is_pending());
        assert_eq!(admitted.load(Ordering::Acquire), handed_off);
        current.store(false, Ordering::Release);
        let mut drained = vec![0; prior.len()];
        server.read_exact(&mut drained).await.unwrap();
        assert_eq!(drained, prior);
        if handed_off {
            send.await.unwrap();
            assert_eq!(read_frame(&mut server).await, (target, payload.to_vec()));
        } else {
            let error = send.await.unwrap_err();
            assert_eq!(
                crate::proxy::io_packet_rejection(&error),
                Some(crate::proxy::PacketRejection::Cancelled)
            );
            assert!(!admitted.load(Ordering::Acquire));
        }
        assert!(!transport.frame_stream_torn());
        transport
            .send_to(sibling, None, b"sibling", false, None)
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut server).await,
            (sibling, b"sibling".to_vec())
        );
    }
}

/// Writes that stall mid-frame are never packet-local: the datagram is
/// admitted before the first byte is written and a deadline is not
/// congestion.
#[tokio::test]
async fn stalled_partial_write_is_admitted_and_not_congestion() {
    let (client, server) = tokio::io::duplex(16);
    let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let transport = transport_over(client, a, None);
    assert!(!transport.send_timeout_is_congestion());

    let admitted = AtomicBool::new(false);
    let payload = vec![7u8; 4096];
    let stalled = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        transport.send_to(a, None, &payload, false, Some(&admitted)),
    )
    .await;
    assert!(stalled.is_err(), "the unread stream must stall the write");
    assert!(admitted.load(Ordering::Acquire));
    drop(server);
}

/// A concurrent sender is refused instead of interleaving: the frame
/// boundary belongs to whoever holds the writer lock.
#[tokio::test]
async fn concurrent_sender_is_refused_while_a_frame_is_mid_write() {
    let (client, server) = tokio::io::duplex(16);
    let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let b: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
    let transport = transport_over(client, a, None);

    let payload = vec![7u8; 4096];
    let mut first = std::pin::pin!(transport.send_to(a, None, &payload, false, None));
    assert!(
        futures_util::poll!(first.as_mut()).is_pending(),
        "writer must be pending on the full stream"
    );
    let busy_admitted = AtomicBool::new(false);
    let error = transport
        .send_to(b, None, b"b", false, Some(&busy_admitted))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    assert!(!busy_admitted.load(Ordering::Acquire));
    drop(server);
}

/// A write cancelled halfway leaves a torn frame on the shared stream;
/// a sibling destination must fail rather than append to it, even when
/// the peer is draining again.
#[tokio::test]
async fn cancelled_partial_write_poisons_the_shared_stream() {
    let (client, mut server) = tokio::io::duplex(16);
    let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let b: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
    let transport = transport_over(client, a, None);
    let payload = vec![7u8; 4096];
    let stalled = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        transport.send_to(a, None, &payload, false, None),
    )
    .await;
    assert!(stalled.is_err(), "the unread stream must stall the write");
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut server, &mut tokio::io::sink()).await;
    });
    let error = transport
        .send_to(b, None, b"b", false, None)
        .await
        .unwrap_err();
    assert!(crate::proxy::is_frame_interrupted(&error));
}

/// Dropping the transport closes the logical stream.
#[tokio::test]
async fn drop_releases_the_stream() {
    let (client, mut server) = tokio::io::duplex(4096);
    let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let transport = Arc::new(transport_over(client, target, None));
    drop(transport);
    let mut byte = [0u8; 1];
    assert_eq!(server.read(&mut byte).await.unwrap(), 0);
}

/// Real loopback TCP through the production preparation: the associate
/// request names the first destination, later frames name their own, and
/// a third peer can answer first.
#[tokio::test]
async fn plain_tcp_association_serves_every_destination() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let first: SocketAddr = "93.184.216.34:53".parse().unwrap();
    let second: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
    let stranger: SocketAddr = "198.51.100.9:3478".parse().unwrap();
    let password = "udp-secret";
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 56 + 2 + 1 + 7 + 2];
        tcp.read_exact(&mut request).await.unwrap();
        let mut expected = hex_sha224(password).into_bytes();
        expected.extend_from_slice(b"\r\n\x03");
        expected.extend(wire_addr(first));
        expected.extend_from_slice(b"\r\n");
        assert_eq!(request, expected);
        assert_eq!(read_frame(&mut tcp).await, (first, b"one".to_vec()));
        assert_eq!(read_frame(&mut tcp).await, (second, b"two".to_vec()));
        let mut replies = frame(wire_addr(stranger), b"hi");
        replies.extend(frame(wire_addr(second), b"re-two"));
        tcp.write_all(&replies).await.unwrap();
        let mut eof = [0u8; 1];
        assert_eq!(tcp.read(&mut eof).await.unwrap(), 0);
    });

    let mut node = Node {
        name: "trojan-udp".into(),
        address: server_addr.ip().to_string(),
        host: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            password: Some(password.into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    node.tls_mut().unwrap().enabled = false;
    let (transport, preparation) =
        TrojanHandler::open_udp_stream(&node, None, first, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();
    preparation.commit().unwrap();
    let transport: Arc<dyn MultiTargetTransport> = transport;
    transport
        .send_to_checked(first, None, b"one", None, &|| true)
        .await
        .unwrap();
    transport
        .send_to(second, None, b"two", false, None)
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!((peer, &buf[..n]), (stranger, &b"hi"[..]));
    let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!((peer, &buf[..n]), (second, &b"re-two"[..]));
    drop(transport);
    server.await.unwrap();
}

#[tokio::test]
async fn tunneled_associate_carries_every_destination_on_the_carrier() {
    use crate::proxy::chain::{UDP_EXIT_HOP, UdpExit};

    let first: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let second: SocketAddr = "192.0.2.2:443".parse().unwrap();
    let mut node = Node {
        name: "trojan-exit".into(),
        host: "must-not-resolve.invalid".into(),
        port: 443,
        outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            password: Some("tunnel-secret".into()),
            tls: honk_config::node::TlsOptions {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    let (carrier, mut server) = tokio::io::duplex(4096);
    let handler = TrojanHandler::new();
    let dial = handler.prepare_shared_source_over(
        runtime,
        Box::new(carrier),
        first,
        None,
        TunnelDialOptions::new(std::time::Duration::from_secs(3)),
    );
    let transport = UDP_EXIT_HOP
        .scope(
            UdpExit {
                index: 1,
                tls_handoff: false,
            },
            dial,
        )
        .await
        .unwrap();

    // hex(sha224("tunnel-secret")) | CRLF | UDP ASSOCIATE | first | CRLF.
    let mut expected = b"e18a99df762a533a40db57010c34dde76778a0ca43091577bf581b2b\r\n\x03".to_vec();
    expected.extend(wire_addr(first));
    expected.extend_from_slice(b"\r\n");
    let mut request = vec![0; expected.len()];
    server.read_exact(&mut request).await.unwrap();
    assert_eq!(request, expected);

    transport
        .send_to_checked(first, None, b"one", None, &|| true)
        .await
        .unwrap();
    transport
        .send_to(second, None, b"two", false, None)
        .await
        .unwrap();
    assert_eq!(read_frame(&mut server).await, (first, b"one".to_vec()));
    assert_eq!(read_frame(&mut server).await, (second, b"two".to_vec()));

    server
        .write_all(&frame(wire_addr(second), b"reply"))
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let (len, peer) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!((&buf[..len], peer), (&b"reply"[..], second));

    let mut malformed = wire_addr(second);
    malformed.extend_from_slice(b"\0\0\r!");
    server.write_all(&malformed).await.unwrap();
    let error = transport.recv_packet(&mut buf).await.unwrap_err();
    assert_eq!(crate::proxy::error::hop_io_failure(&error), Some(1));
}
