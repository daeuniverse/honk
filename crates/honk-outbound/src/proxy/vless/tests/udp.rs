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

        let mut request = [0; 8];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [1, ATYP_IPV4, 8, 8, 8, 8, 0, 53]);
        let mut packet = [0; 5];
        stream.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet, b"\0\x03dns");

        let mut response = vec![0, 0];
        response.extend_from_slice(
            &super::super::uot::encode_packet(b"first", super::super::uot::MAX_PACKET_SIZE)
                .unwrap(),
        );
        response.extend_from_slice(
            &super::super::uot::encode_packet(b"second", super::super::uot::MAX_PACKET_SIZE)
                .unwrap(),
        );
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
        (6, target)
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
            "vless://b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3@127.0.0.1:{port}?flow=xtls-rprx-vision&udp=1#policy"
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

    let owner = crate::runtime::NodeRuntime::try_ephemeral_guarded(&node).unwrap();
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
    owner.close().await;

    let disabled = Node::from_share_link(&format!(
        "vless://b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3@127.0.0.1:{port}?security=none&udp=0#disabled"
    ))
    .unwrap();
    let network_error = tokio::time::timeout(
        deadline,
        handler.dial_udp_transport(&disabled, "8.8.8.8:53".parse().unwrap(), None, deadline),
    )
    .await
    .expect("VLESS network policy blocked during preflight")
    .unwrap_err();
    assert!(super::super::is_packet_rejection(&network_error));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "packet policy must run before opening a carrier"
    );
}

#[tokio::test]
async fn interrupted_connected_send_poison_closes_with_last_owner() {
    let (client, mut wire) = tokio::io::duplex(4);
    let target = "8.8.8.8:53".parse().unwrap();
    let transport = Arc::new(VlessConnectedTransport::new(Box::new(client), target, None));
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
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
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
