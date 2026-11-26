use super::*;

/// SOCKS5 server that, like Dante with `udp.connectdst: no` or a Xray
/// freedom outbound, forwards every destination of one client through one
/// unconnected socket and relays whatever that socket receives back with its
/// real source in the header.
struct FullConeSocks5Server {
    proxy_addr: SocketAddr,
    /// The server's single outbound socket, the source every peer sees.
    egress_addr: SocketAddr,
    associates: Arc<std::sync::atomic::AtomicUsize>,
    released: Arc<std::sync::atomic::AtomicUsize>,
    close_controls: tokio::sync::watch::Sender<bool>,
}

async fn run_full_cone_socks5_server() -> FullConeSocks5Server {
    use std::sync::atomic::AtomicUsize;
    use tokio::net::UdpSocket;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let egress = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let egress_addr = egress.local_addr().unwrap();
    let relay_reply = socks5_udp_associate_reply(relay.local_addr().unwrap());
    let associates = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));
    let (close_controls, close_rx) = tokio::sync::watch::channel(false);

    tokio::spawn({
        let associates = Arc::clone(&associates);
        let released = Arc::clone(&released);
        async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                associates.fetch_add(1, Ordering::SeqCst);
                let reply = relay_reply.clone();
                let released = Arc::clone(&released);
                let mut close_rx = close_rx.clone();
                tokio::spawn(async move {
                    let mut greeting = [0u8; 3];
                    stream.read_exact(&mut greeting).await.unwrap();
                    stream
                        .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
                        .await
                        .unwrap();
                    let mut request = [0u8; 10];
                    stream.read_exact(&mut request).await.unwrap();
                    assert_eq!(request[1], CMD_UDP_ASSOCIATE);
                    stream.write_all(&reply).await.unwrap();
                    let mut probe = [0u8; 1];
                    tokio::select! {
                        _ = close_rx.wait_for(|closed| *closed) => {}
                        _ = stream.read(&mut probe) => {}
                    }
                    drop(stream);
                    released.fetch_add(1, Ordering::SeqCst);
                });
            }
        }
    });

    tokio::spawn(async move {
        let mut client = None;
        let mut from_client = vec![0u8; 65_535];
        let mut from_peer = vec![0u8; 65_535];
        loop {
            tokio::select! {
                received = relay.recv_from(&mut from_client) => {
                    let (n, peer) = received.unwrap();
                    client = Some(peer);
                    // IPv4 requests only: RSV(2) FRAG ATYP=1 addr(4) port(2) data.
                    let packet = &from_client[..n];
                    assert_eq!(packet[..4], [0, 0, 0, ATYP_IPV4]);
                    let destination = SocketAddr::from((
                        [packet[4], packet[5], packet[6], packet[7]],
                        u16::from_be_bytes([packet[8], packet[9]]),
                    ));
                    egress.send_to(&packet[10..], destination).await.unwrap();
                }
                received = egress.recv_from(&mut from_peer) => {
                    let (n, source) = received.unwrap();
                    if let Some(client) = client {
                        relay
                            .send_to(
                                &expected_socks5_udp_datagram(source, None, 0, &from_peer[..n]),
                                client,
                            )
                            .await
                            .unwrap();
                    }
                }
            }
        }
    });

    FullConeSocks5Server {
        proxy_addr,
        egress_addr,
        associates,
        released,
        close_controls,
    }
}

/// The production dispatch path: runtime-pinned preparation, then commit.
async fn prepare_shared_test_transport(
    proxy_addr: SocketAddr,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> Arc<dyn crate::proxy::MultiTargetTransport> {
    let mut node = socks5_test_node(proxy_addr);
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    crate::proxy::ProxyRegistry::default_resolver()
        .unwrap()
        .prepare_shared_source(
            runtime,
            target,
            target_domain,
            std::time::Duration::from_secs(1),
            true,
        )
        .await
        .unwrap()
        .commit()
        .await
        .unwrap()
}

async fn recv_within(
    transport: &Arc<dyn crate::proxy::MultiTargetTransport>,
) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0u8; 1024];
    let (n, source) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        transport.recv_packet(&mut buf),
    )
    .await
    .expect("reply should arrive")
    .unwrap();
    (buf[..n].to_vec(), source)
}

async fn peer_recv(socket: &tokio::net::UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0u8; 1024];
    let (n, from) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        socket.recv_from(&mut buf),
    )
    .await
    .expect("peer should receive the datagram")
    .unwrap();
    (buf[..n].to_vec(), from)
}

#[tokio::test]
async fn socks5_one_association_serves_every_destination_and_unsolicited_peers() {
    let server = run_full_cone_socks5_server().await;
    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (a_addr, b_addr, c_addr) = (
        a.local_addr().unwrap(),
        b.local_addr().unwrap(),
        c.local_addr().unwrap(),
    );
    let transport = prepare_shared_test_transport(server.proxy_addr, a_addr, None).await;

    let admitted = AtomicBool::new(false);
    transport.send_packet(b"to-a").await.unwrap();
    transport
        .send_to(b_addr, None, b"to-b", false, Some(&admitted))
        .await
        .unwrap();
    assert!(admitted.load(Ordering::Acquire));

    // Both destinations see the one server-side mapping.
    assert_eq!(peer_recv(&a).await, (b"to-a".to_vec(), server.egress_addr));
    assert_eq!(peer_recv(&b).await, (b"to-b".to_vec(), server.egress_addr));
    assert_eq!(
        server.associates.load(Ordering::SeqCst),
        1,
        "two destinations must share one ASSOCIATE"
    );

    // A peer the client never contacted reaches the mapping and is named.
    c.send_to(b"c-first", server.egress_addr).await.unwrap();
    assert_eq!(recv_within(&transport).await, (b"c-first".to_vec(), c_addr));
    // Later replies keep their own real sources.
    b.send_to(b"b-reply", server.egress_addr).await.unwrap();
    assert_eq!(recv_within(&transport).await, (b"b-reply".to_vec(), b_addr));
    a.send_to(b"a-reply", server.egress_addr).await.unwrap();
    assert_eq!(recv_within(&transport).await, (b"a-reply".to_vec(), a_addr));

    // Dropping the transport releases the one control stream.
    drop(transport);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while server.released.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("control stream should close with the association");
}

#[tokio::test]
async fn socks5_shared_association_ends_with_its_control_stream() {
    let server = run_full_cone_socks5_server().await;
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transport =
        prepare_shared_test_transport(server.proxy_addr, peer.local_addr().unwrap(), None).await;
    server.close_controls.send(true).unwrap();

    let mut buf = [0u8; 16];
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        transport.recv_packet(&mut buf),
    )
    .await
    .expect("control EOF should wake recv_packet")
    .expect_err("control EOF should end the association");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
}

#[tokio::test]
async fn socks5_send_to_encodes_each_destination_in_its_own_header() {
    let mut server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let default: SocketAddr = "203.0.113.1:53".parse().unwrap();
    let transport = prepare_shared_test_transport(server.proxy_addr, default, None).await;

    let v6: SocketAddr = "[2001:db8::7]:5353".parse().unwrap();
    let v4: SocketAddr = "198.51.100.8:443".parse().unwrap();
    let named: SocketAddr = "192.0.2.9:8443".parse().unwrap();
    transport
        .send_to(v6, None, b"six", true, None)
        .await
        .unwrap();
    transport.send_to(v4, None, b"", false, None).await.unwrap();
    transport
        .send_to(named, Some("named.example.test"), b"name", false, None)
        .await
        .unwrap();
    transport.send_packet(b"default").await.unwrap();
    let expected = [
        expected_socks5_udp_datagram(v6, None, 0, b"six"),
        expected_socks5_udp_datagram(v4, None, 0, b""),
        // Not the dialed name: a real server pins its outbound form by the
        // first destination, so the address goes out numerically.
        expected_socks5_udp_datagram(named, None, 0, b"name"),
        expected_socks5_udp_datagram(default, None, 0, b"default"),
    ];
    for expected in expected {
        let mut buf = [0u8; 1024];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.relay.recv_from(&mut buf),
        )
        .await
        .expect("relay should receive the datagram")
        .unwrap();
        assert_eq!(&buf[..n], expected);
    }

    // Even an unencodable foreign name cannot fail the packet: only the dialed
    // name reaches the wire.
    let long = "a".repeat(usize::from(u8::MAX) + 1);
    transport
        .send_to(named, Some(&long), b"long", false, None)
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        server.relay.recv_from(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        &buf[..n],
        expected_socks5_udp_datagram(named, None, 0, b"long")
    );
    server.close_control();
}

#[tokio::test]
async fn socks5_send_to_names_only_the_dialed_destination() {
    let mut server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let dialed: SocketAddr = "203.0.113.1:443".parse().unwrap();
    let transport =
        prepare_shared_test_transport(server.proxy_addr, dialed, Some("dialed.example.test")).await;

    transport
        .send_to(dialed, Some("dialed.example.test"), b"dialed", false, None)
        .await
        .unwrap();
    transport
        .send_to(dialed, Some("other.example.test"), b"other", false, None)
        .await
        .unwrap();
    for expected in [
        expected_socks5_udp_datagram(dialed, Some("dialed.example.test"), 0, b"dialed"),
        expected_socks5_udp_datagram(dialed, None, 0, b"other"),
    ] {
        let mut buf = [0u8; 1024];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.relay.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buf[..n], expected);
    }
    server.close_control();
}

#[tokio::test]
async fn socks5_checked_send_admits_the_addressed_datagram() {
    let mut server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let dialed = "127.0.0.1:443".parse().unwrap();
    let target = "127.0.0.1:5353".parse().unwrap();
    let transport =
        prepare_shared_test_transport(server.proxy_addr, dialed, Some("dialed.example.test")).await;
    let admitted = AtomicBool::new(false);
    let checked = AtomicBool::new(false);
    let current = || {
        checked.store(true, Ordering::Release);
        true
    };

    transport
        .send_to_checked(
            target,
            Some("other.example.test"),
            b"addressed",
            Some(&admitted),
            &current,
        )
        .await
        .unwrap();
    assert!(checked.load(Ordering::Acquire));
    assert!(admitted.load(Ordering::Acquire));
    let (packet, _) = peer_recv(&server.relay).await;
    assert_eq!(
        packet,
        expected_socks5_udp_datagram(target, None, 0, b"addressed")
    );
    server.close_control();
}
