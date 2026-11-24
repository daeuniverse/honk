use super::*;

/// Real servers piggyback the response header on the target's first
/// downstream bytes: dial must return without it, and the header must
/// not leak into the relayed stream.
#[tokio::test]
async fn test_vless_dial_lazy_response_header() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 19];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[18], CMD_TCP);
        let mut addr = [0u8; 7];
        stream.read_exact(&mut addr).await.unwrap();
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        // Response header only after the client spoke first.
        stream.write_all(b"\x00\x00pong").await.unwrap();
    });

    let node = Node {
        name: "vless-lazy".into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        ..vless_node(uuid_str)
    };
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let mut ps = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        VLessHandler::new().dial(&node, target, None, std::time::Duration::from_secs(3)),
    )
    .await
    .expect("dial must not wait for the response header")
    .unwrap();
    ps.stream.write_all(b"ping").await.unwrap();
    ps.stream.flush().await.unwrap();
    let mut out = [0u8; 4];
    ps.stream.read_exact(&mut out).await.unwrap();
    assert_eq!(&out, b"pong");

    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn direct_uot_is_lazy_and_preserves_datagrams() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (lazy_tx, lazy_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = [0; 23];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[18], CMD_TCP);
        assert_eq!(&head[19..21], &[0, 0]);
        assert_eq!(head[21], ATYP_DOMAIN);
        assert_eq!(head[22] as usize, super::super::uot::MAGIC_ADDRESS.len());
        let mut magic = vec![0; head[22] as usize];
        stream.read_exact(&mut magic).await.unwrap();
        assert_eq!(magic, super::super::uot::MAGIC_ADDRESS.as_bytes());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), stream.read_u8())
                .await
                .is_err(),
            "UoT setup must wait for the first datagram"
        );
        lazy_tx.send(()).unwrap();

        // Non-connect request, then the first datagram in UoT v1 address form.
        let mut request = [0; 8];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [0, ATYP_IPV4, 8, 8, 8, 8, 0, 53]);
        let mut packet = [0; 12];
        stream.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet, b"\0\x08\x08\x08\x08\0\x35\0\x03dns");

        let mut response = vec![0, 0];
        response.extend_from_slice(b"\0\x08\x08\x08\x08\0\x35\0\x05first");
        response.extend_from_slice(b"\0\xc0\0\x02\x09\x14\xe9\0\x06second");
        stream.write_all(&response).await.unwrap();
    });

    let mut node = Node {
        name: "vless-uot".into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        ..configured_vless_node(
            "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3",
            honk_config::node::VlessUdpEncoding::UotV2,
            honk_config::node::VlessMultiplex::Off,
        )
    };
    node.id = node.derive_id();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = VLessHandler::new()
        .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    lazy_rx.await.unwrap();
    assert_eq!(transport.relay_addr(), target);
    transport.send_packet_confirmed(b"dns").await.unwrap();

    let error = transport.recv_packet(&mut [0; 1]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    let mut output = [0; 8];
    assert_eq!(
        transport.recv_packet(&mut output).await.unwrap(),
        (5, target)
    );
    assert_eq!(&output[..5], b"first");
    assert_eq!(
        transport.recv_packet(&mut output).await.unwrap(),
        (6, "192.0.2.9:5353".parse().unwrap())
    );
    assert_eq!(&output[..6], b"second");
    server.await.unwrap();
}

#[tokio::test]
async fn auto_native_udp_is_lazy_bounded_and_preserves_frames() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (lazy_tx, lazy_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = [0; 19];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[18], 0x02);
        let mut target = [0; 7];
        stream.read_exact(&mut target).await.unwrap();
        assert_eq!(target, [0, 53, ATYP_IPV4, 8, 8, 8, 8]);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), stream.read_u8())
                .await
                .is_err(),
            "native UDP must wait for the first datagram"
        );
        lazy_tx.send(()).unwrap();

        let mut first = [0; 7];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"\0\x05first");

        let mut packet = vec![0; 2 + MAX_NATIVE_PACKET_SIZE];
        stream.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet[..2], &(MAX_NATIVE_PACKET_SIZE as u16).to_be_bytes());
        assert!(packet[2..].iter().all(|byte| *byte == 0x5a));

        let mut response = vec![0, 0];
        response.extend_from_slice(
            &super::super::uot::encode_packet(&[], super::super::uot::MAX_PACKET_SIZE).unwrap(),
        );
        response.extend_from_slice(
            &super::super::uot::encode_packet(b"answer", super::super::uot::MAX_PACKET_SIZE)
                .unwrap(),
        );
        stream.write_all(&response).await.unwrap();
    });

    let node = Node::from_share_link(&format!(
            "vless://b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3@127.0.0.1:{port}?security=none&udp=1#vless-auto"
        ))
        .unwrap();
    let vless = node.vless().unwrap();
    assert_eq!(
        vless.udp_encoding,
        honk_config::node::VlessUdpEncoding::Auto
    );
    assert_eq!(vless.udp_path(53), Some(VlessUdpPath::Native));
    assert_eq!(vless.udp_path(443), Some(VlessUdpPath::Native));
    assert_eq!(vless.udp_path(54), Some(VlessUdpPath::Xudp));

    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = VLessHandler::new()
        .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    lazy_rx.await.unwrap();
    let oversized = vec![0; MAX_NATIVE_PACKET_SIZE + 1];
    for packet in [&[][..], oversized.as_slice()] {
        let error = transport.send_packet_confirmed(packet).await.unwrap_err();
        assert!(super::super::is_packet_rejection(&anyhow::Error::new(
            error
        )));
    }
    transport
        .send_packet_checked(b"first", &|| true)
        .await
        .unwrap();
    let maximum = vec![0x5a; MAX_NATIVE_PACKET_SIZE];
    transport.send_packet_confirmed(&maximum).await.unwrap();

    assert_eq!(transport.recv_packet(&mut []).await.unwrap(), (0, target));
    let error = transport.recv_packet(&mut [0; 1]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    let mut output = [0; 8];
    assert_eq!(
        transport.recv_packet(&mut output).await.unwrap(),
        (6, target)
    );
    assert_eq!(&output[..6], b"answer");
    server.await.unwrap();
}

#[tokio::test]
async fn packet_policy_precedes_every_vless_dial_path() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handler = VLessHandler::new();
    let target: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let node = Node::from_share_link(&format!(
            "vless://b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3@127.0.0.1:{port}?flow=xtls-rprx-vision&udp=1&mux=xray&concurrency=-1&xudpConcurrency=-1&xudpProxyUDP443=reject#policy"
        ))
        .unwrap();
    let deadline = std::time::Duration::from_secs(1);
    let direct = tokio::time::timeout(
        deadline,
        handler.dial_udp_transport(&node, target, None, deadline),
    )
    .await
    .expect("VLESS target policy blocked during preflight")
    .unwrap_err();
    assert!(super::super::is_packet_rejection(&direct));

    let mut owner = crate::runtime::NodeRuntime::try_ephemeral_guarded(&node).unwrap();
    let runtime = owner.runtime();
    let runtime_error = tokio::time::timeout(
        deadline,
        handler.dial_udp_transport_runtime(Arc::clone(&runtime), target, None, deadline),
    )
    .await
    .expect("runtime VLESS target policy blocked during preflight")
    .unwrap_err();
    assert!(super::super::is_packet_rejection(&runtime_error));
    let speculative_error = tokio::time::timeout(
        deadline,
        handler.dial_udp_transport_speculative_runtime(runtime, target, None, deadline),
    )
    .await
    .expect("speculative VLESS target policy blocked during preflight")
    .unwrap_err();
    assert!(super::super::is_packet_rejection(&speculative_error));
    owner.close().await.unwrap();

    let disabled = Node::from_share_link(&format!(
        "vless://b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3@127.0.0.1:{port}?security=none&udp=0#disabled"
    ))
    .unwrap();
    let network_error = tokio::time::timeout(
        deadline,
        handler.dial_udp_transport(&disabled, "8.8.8.8:53".parse().unwrap(), None, deadline),
    )
    .await
    .expect("VLESS capability checked during preflight")
    .unwrap_err();
    assert!(!super::super::is_packet_rejection(&network_error));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "packet policy must run before opening a carrier"
    );
}

#[tokio::test]
async fn native_checked_first_datagram_refuses_without_writing_a_stale_frame() {
    use crate::proxy::chain::{UDP_EXIT_HOP, UdpExit};
    use std::sync::atomic::{AtomicBool, Ordering};

    let node = Node::from_share_link(
        "vless://b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3@192.0.2.1:443?security=none#exit",
    )
    .unwrap();
    let target = "192.0.2.2:53".parse().unwrap();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    // The valid native command fills the entire pipe before the first datagram.
    let (carrier, mut peer) = tokio::io::duplex(26);
    let handler = VLessHandler::new();
    let dial = handler.dial_udp_over(
        runtime,
        Box::new(carrier),
        target,
        None,
        crate::proxy::TunnelDialOptions::new(std::time::Duration::from_secs(1)),
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
    let current = AtomicBool::new(true);
    let allowed = || current.load(Ordering::Acquire);
    let mut first = std::pin::pin!(transport.send_packet_checked(b"stale", &allowed));
    assert!(futures_util::poll!(first.as_mut()).is_pending());
    current.store(false, Ordering::Release);
    let mut header = [0; 26];
    peer.read_exact(&mut header).await.unwrap();
    assert_eq!(header[18], CMD_UDP);
    let error = first.await.unwrap_err();
    assert_eq!(
        crate::proxy::io_packet_rejection(&error),
        Some(crate::proxy::PacketRejection::Cancelled)
    );
    transport
        .send_packet_checked(b"next", &|| true)
        .await
        .unwrap();
    let mut wire = [0; 6];
    peer.read_exact(&mut wire).await.unwrap();
    assert_eq!(&wire, b"\0\x04next");
}

#[tokio::test]
async fn connected_checked_send_cancels_before_first_byte_and_keeps_writer() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (mut client, mut wire) = tokio::io::duplex(8);
    client.write_all(b"occupied").await.unwrap();
    let node = vless_node("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3");
    let transport = VlessConnectedTransport::new(
        Box::new(client),
        "192.0.2.1:53".parse().unwrap(),
        crate::proxy::chain::native_udp_writer_handoff(&node),
    );
    let current = AtomicBool::new(true);
    let allowed = || current.load(Ordering::Acquire);
    let mut send = std::pin::pin!(transport.send_packet_checked(b"stale", &allowed));
    assert!(futures_util::poll!(send.as_mut()).is_pending());
    current.store(false, Ordering::Release);
    let mut prior = [0; 8];
    wire.read_exact(&mut prior).await.unwrap();
    assert_eq!(&prior, b"occupied");
    let error = send.await.unwrap_err();
    assert_eq!(
        crate::proxy::io_packet_rejection(&error),
        Some(crate::proxy::PacketRejection::Cancelled),
    );
    transport
        .send_packet_checked(b"next", &|| true)
        .await
        .unwrap();
    let mut frame = [0; 6];
    wire.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame, b"\0\x04next");
}

#[tokio::test]
async fn interrupted_connected_send_poison_closes_with_last_owner() {
    let (client, mut wire) = tokio::io::duplex(4);
    let target = "8.8.8.8:53".parse().unwrap();
    let transport = Arc::new(VlessConnectedTransport::new(
        Box::new(client),
        target,
        Some(false),
    ));
    let sending = {
        let transport = Arc::clone(&transport);
        tokio::spawn(async move {
            transport
                .send_packet_confirmed(&vec![0x5a; MAX_NATIVE_PACKET_SIZE])
                .await
        })
    };
    let mut length = [0; 2];
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        wire.read_exact(&mut length),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(length, (MAX_NATIVE_PACKET_SIZE as u16).to_be_bytes());
    sending.abort();
    assert!(sending.await.unwrap_err().is_cancelled());

    let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        transport.send_packet_confirmed(b"next"),
    )
    .await
    .expect("interrupted send poisoned the connected transport")
    .unwrap_err();
    assert!(crate::proxy::is_frame_interrupted(&error));
    drop(transport);
    let mut remainder = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        wire.read_to_end(&mut remainder),
    )
    .await
    .unwrap()
    .unwrap();
}

/// On a chain, `Auto` sends native UDP even on a port where a direct dial
/// picks XUDP.
#[tokio::test]
async fn tunneled_auto_udp_sends_the_native_command_over_the_carrier() {
    let node = Node::from_share_link(
        "vless://b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3@198.51.100.1:443?security=none#vless-exit",
    )
    .unwrap();
    let target: SocketAddr = "8.8.8.8:54".parse().unwrap();
    assert_eq!(
        node.vless().unwrap().udp_path(target.port()),
        Some(VlessUdpPath::Xudp)
    );
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    let (carrier, mut server) = tokio::io::duplex(4096);
    let transport = VLessHandler::new()
        .dial_udp_over(
            runtime,
            Box::new(carrier),
            target,
            None,
            crate::proxy::TunnelDialOptions::new(std::time::Duration::from_secs(3)),
        )
        .await
        .unwrap();

    let mut head = [0; 26];
    server.read_exact(&mut head).await.unwrap();
    assert_eq!(head[18], 0x02);
    assert_eq!(head[19..], [0, 54, ATYP_IPV4, 8, 8, 8, 8]);
    let empty = transport.send_packet(&[]).await.unwrap_err();
    assert_eq!(
        crate::proxy::io_packet_rejection(&empty),
        Some(crate::proxy::PacketRejection::InvalidSize)
    );
    transport.send_packet(b"ping").await.unwrap();
    let mut packet = [0; 6];
    server.read_exact(&mut packet).await.unwrap();
    assert_eq!(packet, *b"\x00\x04ping");

    server.write_all(b"\x00\x00\x00\x04pong").await.unwrap();
    let mut output = [0; 8];
    assert_eq!(
        transport.recv_packet(&mut output).await.unwrap(),
        (4, target)
    );
    assert_eq!(&output[..4], b"pong");
}
