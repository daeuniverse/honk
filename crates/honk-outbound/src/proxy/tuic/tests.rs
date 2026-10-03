use super::*;
use crate::quic::testutil;
use quinn::VarInt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// AUTHENTICATE command byte (the shared `exporter_auth` writes it
/// inline; only the test server decodes it).
const CMD_AUTHENTICATE: u8 = 0x00;

const TEST_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const TEST_PASSWORD: &str = "tuic-test-password";

fn test_node(port: u16, password: &str) -> Node {
    Node {
        name: "tuic-test".to_string(),
        host: "127.0.0.1".to_string(),
        address: format!("127.0.0.1:{port}"),
        port,
        outbound: honk_config::node::OutboundConfig::Tuic(honk_config::node::TuicConfig {
            uuid: Some(TEST_UUID.to_string()),
            password: Some(password.to_string()),
            quic: honk_config::node::QuicOptions {
                tls: honk_config::node::TlsOptions {
                    skip_cert_verify: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Minimal in-process TUIC v5 server: verifies the AUTHENTICATE token
/// with the same TLS exporter, echoes CONNECT streams back, echoes UDP
/// packets back on the path they arrived (datagram or uni stream).
async fn start_server(datagrams: bool, password: &'static str) -> SocketAddr {
    start_server_with_alpn(&[b"tuic"], datagrams, password).await
}

async fn start_server_with_alpn(
    alpn: &[&[u8]],
    datagrams: bool,
    password: &'static str,
) -> SocketAddr {
    let (endpoint, addr) = testutil::server_endpoint(alpn, datagrams).unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                handle_connection(conn, password).await;
            });
        }
    });
    addr
}

async fn handle_connection(conn: quinn::Connection, password: &'static str) {
    // Uni streams: authenticate + UDP-over-stream packets.
    let uni_conn = conn.clone();
    tokio::spawn(async move {
        loop {
            let Ok(mut recv) = uni_conn.accept_uni().await else {
                break;
            };
            let conn = uni_conn.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                if read_exact(&mut recv, &mut head).await.is_err() {
                    return;
                }
                match (head[0], head[1]) {
                    (TUIC_VERSION, CMD_AUTHENTICATE) => {
                        let mut rest = [0u8; 48];
                        if read_exact(&mut recv, &mut rest).await.is_err() {
                            return;
                        }
                        let uuid: &[u8; 16] = rest[..16].try_into().unwrap();
                        let mut token = [0u8; 32];
                        if conn
                            .export_keying_material(&mut token, uuid, password.as_bytes())
                            .is_err()
                        {
                            return;
                        }
                        if token != rest[16..] {
                            conn.close(VarInt::from_u32(0xfffffff1), b"authentication failed");
                        }
                    }
                    (TUIC_VERSION, CMD_PACKET) => {
                        let Ok(msg) = read_udp_message_stream(&mut recv).await else {
                            return;
                        };
                        // Echo the packet back on a fresh uni stream.
                        let pkt = encode_udp_packet(
                            msg.session_id,
                            msg.packet_id,
                            msg.frag_total,
                            msg.frag_id,
                            &msg.addr,
                            &msg.data,
                        );
                        if let Ok(mut send) = conn.open_uni().await {
                            let _ = send.write_all(&pkt).await;
                            let _ = send.finish();
                        }
                    }
                    _ => {}
                }
            });
        }
    });
    // Bi streams: CONNECT echo.
    let bi_conn = conn.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut send, mut recv)) = bi_conn.accept_bi().await else {
                break;
            };
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                if read_exact(&mut recv, &mut head).await.is_err() {
                    return;
                }
                if head != [TUIC_VERSION, CMD_CONNECT] {
                    return;
                }
                if TuicAddr::read_from_stream(&mut recv).await.is_err() {
                    return;
                }
                let mut buf = [0u8; 8192];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) => {
                            if send.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        _ => return,
                    }
                }
            });
        }
    });
    // Datagrams: echo PACKET frames verbatim.
    loop {
        let Ok(data) = conn.read_datagram().await else {
            break;
        };
        if data.len() >= 2 && data[0] == TUIC_VERSION && data[1] == CMD_PACKET {
            let _ = conn.send_datagram(data);
        }
    }
}

#[tokio::test]
async fn test_dial_tcp_echo() {
    let server_addr = start_server(true, TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = TuicHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let mut stream = handler
        .dial(&node, target, None, Duration::from_secs(5))
        .await
        .expect("dial should succeed");
    stream.stream.write_all(b"hello tuic").await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello tuic");
}

#[tokio::test]
async fn test_dial_tcp_domain_echo() {
    let server_addr = start_server(true, TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = TuicHandler::new();
    let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

    let mut stream = handler
        .dial(&node, target, Some("example.com"), Duration::from_secs(5))
        .await
        .expect("dial should succeed");
    stream.stream.write_all(b"domain").await.unwrap();
    let mut buf = [0u8; 16];
    let n = stream.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"domain");
}

#[tokio::test]
async fn test_wrong_password_rejected() {
    let server_addr = start_server(true, TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), "wrong-password");
    let handler = TuicHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    // TUIC has no auth response, so the dial proceeds optimistically
    // (zero auth grace, sing-quic/dae parity); the rejection surfaces
    // ~1 RTT later when the server closes the connection. The
    // connectivity probe (which waits for exactly that) must say no.
    let _ = handler
        .dial(&node, target, None, Duration::from_secs(5))
        .await;
    assert!(!handler.test_connectivity(&node).await);
}

#[tokio::test]
async fn test_custom_alpn() {
    // Server only accepts `h3` (HTTP/3-camouflaged TUIC deployment).
    let server_addr = start_server_with_alpn(&[b"h3"], true, TEST_PASSWORD).await;
    let handler = TuicHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    // Share-link `alpn=h3` is honored: the handshake succeeds.
    let mut node = test_node(server_addr.port(), TEST_PASSWORD);
    node.tuic_mut().unwrap().alpn = Some("h3".to_string());
    let mut stream = handler
        .dial(&node, target, None, Duration::from_secs(5))
        .await
        .expect("matching custom ALPN should connect");
    stream.stream.write_all(b"alpn").await.unwrap();
    let mut buf = [0u8; 16];
    let n = stream.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"alpn");

    // Default ALPN (`tuic`) is rejected at the TLS layer.
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let result = handler
        .dial(&node, target, None, Duration::from_secs(5))
        .await;
    assert!(result.is_err(), "mismatched ALPN must fail the handshake");
}

#[tokio::test]
async fn test_udp_transport_native_datagram_echo() {
    let server_addr = start_server(true, TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = TuicHandler::new();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

    let transport = handler
        .dial_udp_transport(&node, target, None, Duration::from_secs(5))
        .await
        .expect("dial_udp_transport should succeed");
    assert_eq!(transport.relay_addr(), target);
    assert!(transport.send_timeout_is_congestion());
    transport.send_packet(b"dns-query").await.unwrap();
    let mut buf = [0u8; 256];
    let (n, src) = tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(src, target);
    assert_eq!(&buf[..n], b"dns-query");
}

#[tokio::test]
async fn test_udp_transport_over_stream_echo() {
    // Server without QUIC datagram support → UDP-over-stream fallback.
    let server_addr = start_server(false, TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = TuicHandler::new();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

    let transport = handler
        .dial_udp_transport(&node, target, None, Duration::from_secs(5))
        .await
        .expect("dial_udp_transport should succeed");
    assert!(!transport.send_timeout_is_congestion());
    transport.send_packet(b"stream-query").await.unwrap();
    let mut buf = [0u8; 256];
    let (n, src) = tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(src, target);
    assert_eq!(&buf[..n], b"stream-query");
}

#[tokio::test]
async fn udp_carrier_close_is_node_failure() {
    for datagrams in [true, false] {
        let server_addr = start_server(datagrams, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = TuicHandler::new();
        let client = handler.build_client(&node, None).await.unwrap();
        let timeout = Duration::from_secs(5);
        let transport = handler
            .udp_transport_via_client(
                Arc::clone(&client),
                "192.0.2.53:53".parse().unwrap(),
                None,
                timeout,
            )
            .await
            .unwrap();
        let (conn, _) = client.connection(timeout).await.unwrap();
        crate::proxy::tests::assert_udp_carrier_close_is_node_failure(conn, &*transport, timeout)
            .await;
    }
}

async fn assert_udp_roundtrip(transport: &dyn PacketTransport, payload: &[u8]) {
    transport.send_packet(payload).await.unwrap();
    let mut buf = [0u8; 256];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(&buf[..n], payload);
}

async fn assert_udp_session_id_rotation(datagrams: bool) {
    let server_addr = start_server(datagrams, TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = TuicHandler::new();
    let client = handler.build_client(&node, None).await.unwrap();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let timeout = Duration::from_secs(5);

    let old = handler
        .udp_transport_via_client(Arc::clone(&client), target, None, timeout)
        .await
        .unwrap();
    let (old_conn, old_state) = client.connection(timeout).await.unwrap();
    assert!(old_state.sessions.lock().contains_key(&0));

    old_state
        .next_session
        .store(u16::MAX.into(), Ordering::Relaxed);
    let _last = handler
        .udp_transport_via_client(Arc::clone(&client), target, None, timeout)
        .await
        .unwrap();
    assert!(old_state.sessions.lock().contains_key(&u16::MAX));

    #[cfg(feature = "flow-observation")]
    let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
    #[cfg(feature = "flow-observation")]
    let observer = {
        use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};
        let events = Arc::clone(&events);
        FlowObserver::new(
            FlowContext {
                flow_id: uuid::Uuid::new_v4(),
                generation: 1,
                attempt_id: Some(uuid::Uuid::new_v4()),
                lookup_id: None,
                dns_purpose: "proxy_server",
            },
            Arc::new(move |_, event| {
                if let FlowEvent::Session(event) = event {
                    events.lock().push((event.reason(), event.error()));
                }
            }),
        )
    };
    let fresh = handler.udp_transport_via_client(Arc::clone(&client), target, None, timeout);
    #[cfg(feature = "flow-observation")]
    let fresh = observer.scope(fresh);
    let fresh = fresh.await.unwrap();
    #[cfg(feature = "flow-observation")]
    assert_eq!(
        events.lock().as_slice(),
        [
            ("session_open_started", None),
            ("session_open_capacity", Some("capacity")),
            ("session_open_started", None),
            ("session_open_succeeded", None),
        ]
    );
    let (fresh_conn, fresh_state) = client.connection(timeout).await.unwrap();
    assert_ne!(old_conn.stable_id(), fresh_conn.stable_id());
    assert!(fresh_state.sessions.lock().contains_key(&0));

    assert_udp_roundtrip(old.as_ref(), b"old connection").await;
    assert_udp_roundtrip(fresh.as_ref(), b"fresh connection").await;
    drop(old);
    tokio::task::yield_now().await;
    assert!(!old_state.sessions.lock().contains_key(&0));
    assert!(fresh_state.sessions.lock().contains_key(&0));
    assert_udp_roundtrip(fresh.as_ref(), b"after old dissociate").await;
}

#[tokio::test]
async fn test_udp_session_ids_rotate_connections_before_reuse() {
    assert_udp_session_id_rotation(true).await;
    assert_udp_session_id_rotation(false).await;
}

#[test]
fn test_addr_codec_roundtrip() {
    let cases = [
        TuicAddr::Addr(SocksAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(93, 184, 216, 34),
            80,
        ))),
        TuicAddr::Addr(SocksAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ))),
        TuicAddr::Addr(SocksAddr::Domain("example.com".to_string(), 8080)),
        TuicAddr::None,
    ];
    for addr in cases {
        let mut buf = Vec::new();
        addr.encode(&mut buf);
        assert_eq!(buf.len(), addr.encoded_len());
        let mut cursor = &buf[..];
        let decoded = TuicAddr::decode(&mut cursor).unwrap();
        assert_eq!(decoded, addr);
        assert!(cursor.is_empty());
    }
}

#[test]
fn test_udp_message_codec_roundtrip() {
    let addr = TuicAddr::Addr(SocksAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(8, 8, 8, 8),
        53,
    )));
    let pkt = encode_udp_packet(7, 42, 1, 0, &addr, b"payload");
    assert_eq!(pkt[0], TUIC_VERSION);
    assert_eq!(pkt[1], CMD_PACKET);
    let msg = decode_udp_message(&pkt[2..]).unwrap();
    assert_eq!(msg.session_id, 7);
    assert_eq!(msg.packet_id, 42);
    assert_eq!(msg.frag_total, 1);
    assert_eq!(msg.frag_id, 0);
    assert_eq!(msg.addr, addr);
    assert_eq!(msg.data, b"payload");
}

#[test]
fn test_fragmentation_and_defrag() {
    let addr = TuicAddr::Addr(SocksAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(8, 8, 8, 8),
        53,
    )));
    let data = vec![0xabu8; 3000];
    let max = 1200;
    let frags = fragment_udp_packets(1, 99, &addr, &data, max).unwrap();
    assert_eq!(frags.len(), 3);
    assert!(frags.iter().all(|f| f.len() <= max));

    let mut defrag = Defragmenter::new(u16::MAX as usize);
    let mut out = None;
    // Feed out of order; only the last missing fragment completes it.
    for pkt in frags.iter().rev() {
        let msg = decode_udp_message(&pkt[2..]).unwrap();
        out = defrag
            .feed(msg.packet_id, msg.frag_id, msg.frag_total, msg.data)
            .or(out);
    }
    assert_eq!(out.expect("reassembled payload"), data);
}

#[test]
fn test_fragmentation_small_packet_not_fragmented() {
    let addr = TuicAddr::Addr(SocksAddr::Domain("example.com".to_string(), 443));
    let data = b"tiny";
    let frags = fragment_udp_packets(1, 1, &addr, data, 1200).unwrap();
    assert_eq!(frags.len(), 1);
    let msg = decode_udp_message(&frags[0][2..]).unwrap();
    assert_eq!(msg.frag_total, 1);
    assert_eq!(msg.addr, addr);
    assert_eq!(msg.data, data);
}
