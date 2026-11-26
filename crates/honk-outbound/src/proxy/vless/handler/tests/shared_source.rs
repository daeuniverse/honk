use super::*;
use crate::proxy::{PacketRejection, is_packet_rejection};

const UUID: &str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
const A: &str = "198.51.100.10:5301";
const B: &str = "203.0.113.20:5302";
const C: &str = "192.0.2.30:5303";
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

fn sock(address: &str) -> SocketAddr {
    address.parse().unwrap()
}

/// One runtime with a single VLESS carrier credit, so a held preparation is
/// visible as `Capacity` on a second acquire.
fn runtime_for(
    port: u16,
    encoding: honk_config::node::VlessUdpEncoding,
    multiplex: honk_config::node::VlessMultiplex,
) -> (
    Arc<crate::runtime::OutboundRuntimeRegistry>,
    Arc<crate::runtime::NodeRuntime>,
) {
    let mut node = Node {
        name: "vless-shared".into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        ..configured_vless_node(UUID, encoding, multiplex)
    };
    node.id = node.derive_id();
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            std::slice::from_ref(&node),
            8,
            8,
            1,
            cfg!(feature = "flow-observation"),
            None,
        )
        .unwrap()
        .0,
    );
    let runtime = generation.get(&node.id).unwrap();
    (generation, runtime)
}

fn assert_capacity(runtime: &crate::runtime::NodeRuntime) {
    assert!(matches!(
        runtime
            .acquire_vless_carrier()
            .unwrap_err()
            .downcast_ref::<PacketRejection>(),
        Some(PacketRejection::Capacity)
    ));
}

async fn carrier_released(runtime: &crate::runtime::NodeRuntime) {
    let permit = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Ok(permit) = runtime.acquire_vless_carrier() {
                break permit;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the carrier credit must return after the association is dropped");
    drop(permit);
}

const A_REQUEST: [u8; 8] = [0x00, 0x01, 198, 51, 100, 10, 0x14, 0xb5];
const A_FIRST: [u8; 11] = [0, 198, 51, 100, 10, 0x14, 0xb5, 0, 2, b'a', b'a'];
const B_PACKET: [u8; 11] = [0, 203, 0, 113, 20, 0x14, 0xb6, 0, 2, b'b', b'b'];
const C_REPLY: [u8; 11] = [0, 192, 0, 2, 30, 0x14, 0xb7, 0, 2, b'c', b'c'];

/// Server for a shared UoT association: expects the VLESS head, the
/// non-connect request with the first datagram, then a second destination on
/// the same stream; answers with a never-contacted peer, then reports EOF.
async fn serve_uot(listener: tokio::net::TcpListener) -> bool {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut head = [0; 23];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[18], CMD_TCP);
    let mut magic = vec![0; head[22] as usize];
    stream.read_exact(&mut magic).await.unwrap();
    assert_eq!(magic, b"sp.v2.udp-over-tcp.arpa");

    let mut request = [0; 8];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(request, A_REQUEST);
    let mut first = [0; 11];
    stream.read_exact(&mut first).await.unwrap();
    assert_eq!(first, A_FIRST);
    let mut second = [0; 11];
    stream.read_exact(&mut second).await.unwrap();
    assert_eq!(second, B_PACKET);

    let mut reply = vec![0, 0];
    reply.extend_from_slice(&C_REPLY);
    stream.write_all(&reply).await.unwrap();
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.unwrap();
    rest.is_empty()
}

#[tokio::test]
async fn shared_uot_source_serves_two_destinations_and_releases_the_carrier() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_uot(listener));
    let (generation, runtime) = runtime_for(
        port,
        honk_config::node::VlessUdpEncoding::UotV2,
        honk_config::node::VlessMultiplex::Off,
    );

    let prepared = crate::proxy::ProxyRegistry::default_resolver()
        .unwrap()
        .prepare_shared_source(Arc::clone(&runtime), sock(A), None, TIMEOUT, true)
        .await
        .unwrap();
    assert_capacity(&runtime);
    let transport = prepared.commit().await.unwrap();
    // The one stream serves both destinations; the request went out once.
    transport
        .send_to_checked(sock(A), None, b"aa", None, &|| true)
        .await
        .unwrap();
    transport
        .send_to(sock(B), None, b"bb", false, None)
        .await
        .unwrap();
    let mut buffer = [0; 16];
    let (size, peer) = transport.recv_packet(&mut buffer).await.unwrap();
    assert_eq!((&buffer[..size], peer), (&b"cc"[..], sock(C)));

    drop(transport);
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("dropping the association must close the carrier")
            .unwrap()
    );
    carrier_released(&runtime).await;
    generation.shutdown().await;
}

#[tokio::test]
async fn dropped_uot_preparation_sends_nothing_and_releases_the_carrier() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = [0; 23 + 23];
        stream.read_exact(&mut head).await.unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        rest
    });
    let (generation, runtime) = runtime_for(
        port,
        honk_config::node::VlessUdpEncoding::UotV2,
        honk_config::node::VlessMultiplex::Off,
    );
    let prepared = crate::proxy::ProxyRegistry::default_resolver()
        .unwrap()
        .prepare_shared_source(Arc::clone(&runtime), sock(A), None, TIMEOUT, true)
        .await
        .unwrap();
    assert_capacity(&runtime);
    drop(prepared);
    assert!(server.await.unwrap().is_empty(), "no datagram bytes yet");
    carrier_released(&runtime).await;
    generation.shutdown().await;
}

#[tokio::test]
async fn only_explicit_uot_and_h2_paths_are_shared_for_vless() {
    assert!(
        crate::proxy::ProxyRegistry::default_resolver()
            .unwrap()
            .has_shared_source(honk_config::types::NodeProtocol::VLess)
    );
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = unused.local_addr().unwrap().port();
    for (encoding, multiplex, target) in [
        (
            honk_config::node::VlessUdpEncoding::Auto,
            honk_config::node::VlessMultiplex::Off,
            "198.51.100.10:53",
        ),
        (
            honk_config::node::VlessUdpEncoding::Native,
            honk_config::node::VlessMultiplex::Off,
            "198.51.100.10:5301",
        ),
        (
            honk_config::node::VlessUdpEncoding::Xudp,
            honk_config::node::VlessMultiplex::Off,
            "198.51.100.10:5301",
        ),
    ] {
        let (generation, runtime) = runtime_for(port, encoding, multiplex);
        let error = crate::proxy::ProxyRegistry::default_resolver()
            .unwrap()
            .prepare_shared_source(
                runtime,
                sock(target),
                None,
                std::time::Duration::from_millis(500),
                false,
            )
            .await
            .unwrap_err();
        assert!(is_packet_rejection(&error), "{encoding:?}");
        generation.shutdown().await;
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), unused.accept())
            .await
            .is_err(),
        "policy rejection must precede any carrier dial"
    );
}

async fn read_until(recv: &mut h2::RecvStream, body: &mut bytes::BytesMut, len: usize) {
    while body.len() < len {
        let data = recv.data().await.unwrap().unwrap();
        let size = data.len();
        body.extend_from_slice(&data);
        recv.flow_control().release_capacity(size).unwrap();
    }
}

/// An H2MUX server for PacketAddr streams: flags 3, then SOCKS-addressed
/// datagrams. Each accepted stream reads A's request datagram and B's, then
/// replies from a never-contacted peer.
async fn serve_h2_packet_addr(listener: tokio::net::TcpListener, streams: usize) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut head = [0; 23];
    stream.read_exact(&mut head).await.unwrap();
    let mut domain = vec![0; head[22] as usize];
    stream.read_exact(&mut domain).await.unwrap();
    assert_eq!(domain, b"sp.mux.sing-box.arpa");
    stream.write_all(&[0, 0]).await.unwrap();
    let mut preface = [0; 2];
    stream.read_exact(&mut preface).await.unwrap();

    let mut connection = h2::server::handshake(stream).await.unwrap();
    let mut handlers = tokio::task::JoinSet::new();
    for _ in 0..streams {
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        handlers.spawn(async move {
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let mut recv = request.into_body();
            let mut body = bytes::BytesMut::new();
            // flags + SOCKS5 IPv4 A, then A's datagram and B's datagram.
            read_until(&mut recv, &mut body, 9 + 11 + 11).await;
            assert_eq!(&body[..9], &[0, 3, 1, 198, 51, 100, 10, 0x14, 0xb5]);
            assert_eq!(
                &body[9..20],
                &[1, 198, 51, 100, 10, 0x14, 0xb5, 0, 2, b'a', b'a']
            );
            assert_eq!(
                &body[20..31],
                &[1, 203, 0, 113, 20, 0x14, 0xb6, 0, 2, b'b', b'b']
            );
            send.send_data(
                bytes::Bytes::from_static(&[0, 1, 192, 0, 2, 30, 0x14, 0xb7, 0, 2, b'c', b'c']),
                false,
            )
            .unwrap();
            while recv.data().await.is_some_and(|data| data.is_ok()) {}
        });
    }
    // The connection must keep being polled while the streams run.
    while !handlers.is_empty() {
        tokio::select! {
            result = handlers.join_next() => result.unwrap().unwrap(),
            stream = connection.accept() => {
                assert!(stream.is_none());
                break;
            }
        }
    }
}

#[tokio::test]
async fn shared_h2_source_publishes_on_commit_and_shares_the_pooled_carrier() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_h2_packet_addr(listener, 2));
    let (generation, runtime) = runtime_for(
        port,
        honk_config::node::VlessUdpEncoding::Auto,
        honk_config::node::VlessMultiplex::H2 { padding: false },
    );
    let pool = runtime.vless_h2_pool().unwrap();
    let first = crate::proxy::ProxyRegistry::default_resolver()
        .unwrap()
        .prepare_shared_source(Arc::clone(&runtime), sock(A), None, TIMEOUT, true)
        .await
        .unwrap();
    assert_eq!(
        pool.live_session_count(),
        0,
        "nothing published before commit"
    );
    let first = first.commit().await.unwrap();
    assert_eq!(pool.live_session_count(), 1);
    let second = crate::proxy::ProxyRegistry::default_resolver()
        .unwrap()
        .prepare_shared_source(Arc::clone(&runtime), sock(A), None, TIMEOUT, false)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert_eq!(
        pool.live_session_count(),
        1,
        "one carrier serves both sources"
    );

    for transport in [&first, &second] {
        transport
            .send_to(sock(A), None, b"aa", true, None)
            .await
            .unwrap();
        transport
            .send_to(sock(B), None, b"bb", false, None)
            .await
            .unwrap();
        let mut buffer = [0; 16];
        let (size, peer) = transport.recv_packet(&mut buffer).await.unwrap();
        assert_eq!((&buffer[..size], peer), (&b"cc"[..], sock(C)));
    }
    drop((first, second));
    generation.shutdown().await;
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .expect("H2 server must observe both streams end")
        .unwrap();
}

#[tokio::test]
async fn dropped_h2_preparation_leaves_the_pool_empty() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = [0; 23 + 20];
        stream.read_exact(&mut head).await.unwrap();
        stream.write_all(&[0, 0]).await.unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
    });
    let (generation, runtime) = runtime_for(
        port,
        honk_config::node::VlessUdpEncoding::Auto,
        honk_config::node::VlessMultiplex::H2 { padding: false },
    );
    let pool = runtime.vless_h2_pool().unwrap();
    let prepared = crate::proxy::ProxyRegistry::default_resolver()
        .unwrap()
        .prepare_shared_source(Arc::clone(&runtime), sock(A), None, TIMEOUT, true)
        .await
        .unwrap();
    assert_eq!(pool.live_session_count(), 0);
    drop(prepared);
    assert_eq!(pool.live_session_count(), 0);
    carrier_released(&runtime).await;
    generation.shutdown().await;
    server.await.unwrap();
}
