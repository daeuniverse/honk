use super::*;
use crate::quic::testutil;
use quinn::VarInt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// AUTHENTICATE command byte (the shared `exporter_auth` writes it
/// inline; only the test server decodes it).
const CMD_AUTHENTICATE: u8 = 0x00;

const TEST_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const TEST_PASSWORD: &str = "juicity-test-password";

fn test_node(port: u16, password: &str) -> Node {
    Node {
        name: "juicity-test".to_string(),
        host: "127.0.0.1".to_string(),
        address: format!("127.0.0.1:{port}"),
        port,
        outbound: honk_config::node::OutboundConfig::Juicity(honk_config::node::JuicityConfig {
            uuid: Some(TEST_UUID.to_string()),
            password: Some(password.to_string()),
            quic: honk_config::node::QuicOptions {
                tls: honk_config::node::TlsOptions {
                    skip_cert_verify: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        }),
        ..Default::default()
    }
}

/// Minimal in-process Juicity server: verifies the AUTHENTICATE token
/// with the same TLS exporter, echoes TCP streams back, and echoes UDP
/// stream frames (`[metadata][len][payload]`) back verbatim.
async fn start_server(password: &'static str) -> SocketAddr {
    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
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

/// Uni stream: authenticate (stays open; only the first 50 bytes are the
/// auth frame).
fn authenticate(uni_conn: quinn::Connection, password: &'static str) {
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
                if head != [JUICITY_VERSION, CMD_AUTHENTICATE] {
                    return;
                }
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
            });
        }
    });
}

async fn handle_connection(conn: quinn::Connection, password: &'static str) {
    authenticate(conn.clone(), password);
    // Bi streams: TCP echo / UDP frame echo.
    loop {
        let Ok((mut send, mut recv)) = conn.accept_bi().await else {
            break;
        };
        tokio::spawn(async move {
            let mut network = [0u8; 1];
            if read_exact(&mut recv, &mut network).await.is_err() {
                return;
            }
            match network[0] {
                NETWORK_TCP => {
                    if read_peer(&mut recv).await.is_none() {
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
                }
                NETWORK_UDP => {
                    if read_peer(&mut recv).await.is_none() {
                        return;
                    }
                    loop {
                        let Some(peer) = read_peer(&mut recv).await else {
                            return;
                        };
                        let mut len = [0u8; 2];
                        if read_exact(&mut recv, &mut len).await.is_err() {
                            return;
                        }
                        let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
                        if read_exact(&mut recv, &mut payload).await.is_err() {
                            return;
                        }
                        let frame = wire_frame(&peer, &payload);
                        if send.write_all(&frame).await.is_err() {
                            return;
                        }
                    }
                }
                _ => {}
            }
        });
    }
}

#[tokio::test]
async fn test_dial_tcp_echo() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = JuicityHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let mut stream = handler
        .dial(&node, target, None, Duration::from_secs(5))
        .await
        .expect("dial should succeed");
    stream.stream.write_all(b"hello juicity").await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello juicity");
}

#[tokio::test]
async fn pmtud_follows_node_setting() {
    let addr = start_server(TEST_PASSWORD).await;
    let handler = JuicityHandler::new();
    let timeout = Duration::from_secs(5);
    for disabled in [false, true] {
        let mut node = test_node(addr.port(), TEST_PASSWORD);
        node.quic_mut().unwrap().disable_mtu_discovery = disabled;
        let client = handler.build_client(&node, None).await.unwrap();
        let stream = handler
            .dial_via_client(Arc::clone(&client), addr, None, timeout)
            .await
            .unwrap();
        let (conn, _) = client.connection(timeout).await.unwrap();
        crate::proxy::tests::assert_pmtud_after_echo(&conn, stream, disabled).await;
    }
}

#[tokio::test]
async fn test_wrong_password_rejected() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), "wrong-password");
    let handler = JuicityHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    // Optimistic auth (zero grace, tuic parity): the rejection surfaces
    // ~1 RTT later when the server closes the connection; the
    // connectivity probe (which waits for it) must say no.
    let _ = handler
        .dial(&node, target, None, Duration::from_secs(5))
        .await;
    assert!(!handler.test_connectivity(&node).await);
}

#[tokio::test]
async fn test_udp_transport_echo() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = JuicityHandler::new();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

    let transport = handler
        .dial_udp_transport(&node, target, None, Duration::from_secs(5))
        .await
        .expect("dial_udp_transport should succeed");
    assert_eq!(transport.relay_addr(), target);
    transport.send_packet(b"dns-query").await.unwrap();
    let mut small = [0u8; 4];
    let error = transport.recv_packet(&mut small).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let mut buf = [0u8; 256];
    transport.send_packet(b"dns-query").await.unwrap();
    let (n, src) = tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(src, target);
    assert_eq!(&buf[..n], b"dns-query");

    // A second datagram on the same session must work too.
    transport.send_packet(b"second").await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"second");
}

#[tokio::test]
async fn udp_carrier_close_is_node_failure() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = JuicityHandler::new();
    let client = handler.build_client(&node, None).await.unwrap();
    let timeout = Duration::from_secs(5);
    let transport = handler
        .udp_transport_via_client(
            Arc::clone(&client),
            "192.0.2.53:53".parse().unwrap(),
            None,
            timeout,
            true,
        )
        .await
        .unwrap();
    let (conn, _) = client.connection(timeout).await.unwrap();
    crate::proxy::tests::assert_udp_carrier_close_is_node_failure(conn, &*transport, timeout).await;
}

// Independent Juicity UDP stream peer. The ATYP bytes (IPv4=1, domain=3,
// IPv6=4, daeuniverse/outbound c607702d1c85 `trojanc/addr.go`) and the
// `[address][u16be length][payload]` frame are spelled out here, not taken
// from the production codec.
#[derive(Debug, Clone, PartialEq)]
enum Peer {
    Ip(SocketAddr),
    Name(&'static str, u16),
}

fn encode_peer(out: &mut Vec<u8>, peer: &Peer) {
    match peer {
        Peer::Ip(SocketAddr::V4(a)) => {
            out.push(1);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Peer::Ip(SocketAddr::V6(a)) => {
            out.push(4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Peer::Name(name, port) => {
            out.push(3);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

fn wire_frame(peer: &Peer, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_peer(&mut out, peer);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn ip(addr: &str) -> Peer {
    Peer::Ip(addr.parse().unwrap())
}

async fn read_peer(recv: &mut quinn::RecvStream) -> Option<Peer> {
    let mut atyp = [0u8; 1];
    read_exact(recv, &mut atyp).await.ok()?;
    Some(match atyp[0] {
        1 => {
            let mut b = [0u8; 6];
            read_exact(recv, &mut b).await.ok()?;
            let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Peer::Ip((ip, u16::from_be_bytes([b[4], b[5]])).into())
        }
        4 => {
            let mut b = [0u8; 18];
            read_exact(recv, &mut b).await.ok()?;
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).unwrap());
            Peer::Ip((ip, u16::from_be_bytes([b[16], b[17]])).into())
        }
        3 => {
            let mut len = [0u8; 1];
            read_exact(recv, &mut len).await.ok()?;
            let mut b = vec![0u8; len[0] as usize + 2];
            read_exact(recv, &mut b).await.ok()?;
            let name = String::from_utf8(b[..len[0] as usize].to_vec()).ok()?;
            let port = u16::from_be_bytes([b[b.len() - 2], b[b.len() - 1]]);
            Peer::Name(Box::leak(name.into_boxed_str()), port)
        }
        _ => return None,
    })
}

enum Cmd {
    Bytes(Vec<u8>),
    /// Reset the server's send side and stop the client's.
    Fail,
    /// Stop (or resume) reading frames, so QUIC flow control can stall the client.
    Pause(bool),
}

/// One accepted Juicity UDP stream as the server sees it.
struct WireStream {
    opening: Peer,
    frames: tokio::sync::mpsc::UnboundedReceiver<(Peer, Vec<u8>)>,
    cmd: tokio::sync::mpsc::UnboundedSender<Cmd>,
}

impl WireStream {
    async fn frame(&mut self) -> (Peer, Vec<u8>) {
        tokio::time::timeout(Duration::from_secs(5), self.frames.recv())
            .await
            .expect("server frame timed out")
            .expect("stream closed")
    }

    fn reply(&self, peer: &Peer, payload: &[u8]) {
        self.cmd
            .send(Cmd::Bytes(wire_frame(peer, payload)))
            .unwrap();
    }
}

async fn start_wire_server() -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<WireStream>) {
    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let (streams_tx, streams) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let streams_tx = streams_tx.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                authenticate(conn.clone(), TEST_PASSWORD);
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let streams_tx = streams_tx.clone();
                    tokio::spawn(async move {
                        let mut network = [0u8; 1];
                        read_exact(&mut recv, &mut network).await.unwrap();
                        assert_eq!(network[0], 3, "UDP network byte is sent once");
                        let opening = read_peer(&mut recv).await.unwrap();
                        let (cmd, mut cmds) = tokio::sync::mpsc::unbounded_channel();
                        let (frames_tx, frames) = tokio::sync::mpsc::unbounded_channel();
                        let _ = streams_tx.send(WireStream {
                            opening,
                            frames,
                            cmd,
                        });
                        let (pause_tx, mut pause_rx) = tokio::sync::watch::channel(false);
                        let stop = Arc::new(tokio::sync::Notify::new());
                        let stopper = Arc::clone(&stop);
                        tokio::spawn(async move {
                            while let Some(cmd) = cmds.recv().await {
                                match cmd {
                                    Cmd::Bytes(bytes) => {
                                        if send.write_all(&bytes).await.is_err() {
                                            return;
                                        }
                                    }
                                    Cmd::Fail => {
                                        let _ = send.reset(VarInt::from_u32(7));
                                        stopper.notify_one();
                                        return;
                                    }
                                    Cmd::Pause(paused) => {
                                        let _ = pause_tx.send(paused);
                                    }
                                }
                            }
                        });
                        let frames_in = async {
                            while let Some(peer) = read_peer(&mut recv).await {
                                let mut len = [0u8; 2];
                                read_exact(&mut recv, &mut len).await.unwrap();
                                let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
                                read_exact(&mut recv, &mut payload).await.unwrap();
                                let _ = frames_tx.send((peer, payload));
                                let _ = pause_rx.wait_for(|paused| !*paused).await;
                            }
                        };
                        tokio::select! {
                            _ = frames_in => {}
                            _ = stop.notified() => {}
                        }
                        let _ = recv.stop(VarInt::from_u32(7));
                    });
                }
            });
        }
    });
    (addr, streams)
}

const T: Duration = Duration::from_secs(5);

/// A source-shared transport through the node runtime, plus what keeps it alive.
async fn shared_source(
    server: SocketAddr,
    speculative: bool,
    target: SocketAddr,
    domain: Option<&str>,
) -> (
    crate::runtime::EphemeralRuntimeGuard,
    Arc<dyn MultiTargetTransport>,
) {
    let mut node = test_node(server.port(), TEST_PASSWORD);
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral_guarded(&node).unwrap();
    let transport = JuicityHandler::new()
        .prepare_udp_source(runtime.runtime(), target, domain, T, speculative)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    (runtime, transport)
}

async fn recv(transport: &dyn PacketTransport) -> (SocketAddr, Vec<u8>) {
    let mut buf = vec![0u8; 65535];
    let (n, peer) = tokio::time::timeout(T, transport.recv_packet(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    (peer, buf[..n].to_vec())
}

#[tokio::test]
async fn one_stream_carries_every_destination_and_returns_real_peers() {
    for speculative in [false, true] {
        let (server, mut streams) = start_wire_server().await;
        let a: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let b: SocketAddr = "198.51.100.2:5353".parse().unwrap();
        let c: SocketAddr = "203.0.113.9:9999".parse().unwrap();
        let (_runtime, transport) = shared_source(server, speculative, a, None).await;
        assert_eq!(transport.carrier_addr(), Some(server));
        assert!(transport.allows_full_cone_replies());

        let admitted = std::sync::atomic::AtomicBool::new(false);
        transport
            .send_to(a, None, b"to-a", false, Some(&admitted))
            .await
            .unwrap();
        assert!(admitted.load(Ordering::Acquire));
        transport
            .send_to(b, None, b"to-b", true, None)
            .await
            .unwrap();
        // The fixed-target path shares the association too.
        transport.send_packet(b"to-a-again").await.unwrap();

        let mut stream = streams.recv().await.unwrap();
        assert_eq!(stream.opening, Peer::Ip(a));
        assert_eq!(stream.frame().await, (Peer::Ip(a), b"to-a".to_vec()));
        assert_eq!(stream.frame().await, (Peer::Ip(b), b"to-b".to_vec()));
        assert_eq!(stream.frame().await, (Peer::Ip(a), b"to-a-again".to_vec()));
        assert!(streams.try_recv().is_err(), "a second stream was opened");

        // Unsolicited C first, then the contacted destinations keep their own.
        stream.reply(&Peer::Ip(c), b"from-c");
        assert_eq!(recv(&*transport).await, (c, b"from-c".to_vec()));
        stream.reply(&Peer::Ip(b), b"from-b");
        stream.reply(&Peer::Ip(a), b"from-a");
        assert_eq!(recv(&*transport).await, (b, b"from-b".to_vec()));
        assert_eq!(recv(&*transport).await, (a, b"from-a".to_vec()));

        // IPv6 destinations and replies ride the same stream; IPv4-mapped
        // sources normalize to IPv4.
        let v6: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        transport
            .send_to(v6, None, b"to-v6", false, None)
            .await
            .unwrap();
        assert_eq!(stream.frame().await, (Peer::Ip(v6), b"to-v6".to_vec()));
        let v6_peer: SocketAddr = "[2001:db8::99]:5353".parse().unwrap();
        stream.reply(&Peer::Ip(v6_peer), b"from-v6");
        assert_eq!(recv(&*transport).await, (v6_peer, b"from-v6".to_vec()));
        stream.reply(&ip("[::ffff:192.0.2.99]:4000"), b"mapped");
        assert_eq!(
            recv(&*transport).await,
            ("192.0.2.99:4000".parse().unwrap(), b"mapped".to_vec())
        );
        assert!(streams.try_recv().is_err());
    }
}

#[tokio::test]
async fn captured_domain_projects_and_unknown_domains_drop() {
    let (server, mut streams) = start_wire_server().await;
    let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let (_runtime, transport) = shared_source(server, false, target, Some("Example.test")).await;

    transport.send_packet(b"fixed").await.unwrap();
    transport
        .send_to(target, Some("Example.test"), b"named", false, None)
        .await
        .unwrap();
    transport
        .send_to(
            "198.51.100.2:443".parse().unwrap(),
            None,
            b"numeric",
            false,
            None,
        )
        .await
        .unwrap();
    let mut stream = streams.recv().await.unwrap();
    assert_eq!(stream.opening, Peer::Name("Example.test", 443));
    assert_eq!(
        stream.frame().await,
        (Peer::Name("Example.test", 443), b"fixed".to_vec())
    );
    assert_eq!(
        stream.frame().await,
        (Peer::Name("Example.test", 443), b"named".to_vec())
    );
    assert_eq!(
        stream.frame().await,
        (ip("198.51.100.2:443"), b"numeric".to_vec())
    );

    // One coalesced write: wrong port, unknown name and empty-length frames
    // are consumed whole and the next frame still decodes.
    let mut burst = Vec::new();
    burst.extend(wire_frame(&Peer::Name("example.test", 444), b"wrong-port"));
    burst.extend(wire_frame(&Peer::Name("other.test", 443), b"unknown"));
    burst.extend(wire_frame(&Peer::Name("EXAMPLE.TEST", 443), b"projected"));
    burst.extend(wire_frame(&ip("203.0.113.9:1"), b""));
    stream.cmd.send(Cmd::Bytes(burst)).unwrap();
    assert_eq!(recv(&*transport).await, (target, b"projected".to_vec()));
    assert_eq!(
        recv(&*transport).await,
        ("203.0.113.9:1".parse().unwrap(), Vec::new())
    );

    for name in [&b""[..], &[0xff, 0xfe][..]] {
        let mut burst = vec![3, name.len() as u8];
        burst.extend(name);
        burst.extend(443u16.to_be_bytes());
        burst.extend(5u16.to_be_bytes());
        burst.extend(b"stale");
        burst.extend(wire_frame(&Peer::Name("example.test", 443), b"valid"));
        stream.cmd.send(Cmd::Bytes(burst)).unwrap();
        assert_eq!(recv(&*transport).await, (target, b"valid".to_vec()));
    }
}

#[tokio::test]
async fn empty_and_maximum_datagrams_cross_the_stream() {
    let (server, mut streams) = start_wire_server().await;
    let a: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let b: SocketAddr = "198.51.100.2:53".parse().unwrap();
    let c: SocketAddr = "203.0.113.3:53".parse().unwrap();
    let (_runtime, transport) = shared_source(server, false, a, None).await;

    transport.send_to(b, None, b"", false, None).await.unwrap();
    let max = vec![0xa5u8; u16::MAX as usize];
    transport.send_to(c, None, &max, false, None).await.unwrap();
    let over = vec![0u8; u16::MAX as usize + 1];
    let error = transport
        .send_to(c, None, &over, false, None)
        .await
        .unwrap_err();
    assert_eq!(
        crate::proxy::io_packet_rejection(&error),
        Some(crate::proxy::PacketRejection::InvalidSize)
    );
    transport
        .send_to(a, None, b"after", false, None)
        .await
        .unwrap();

    let mut stream = streams.recv().await.unwrap();
    assert_eq!(stream.frame().await, (Peer::Ip(b), Vec::new()));
    assert_eq!(stream.frame().await, (Peer::Ip(c), max.clone()));
    assert_eq!(stream.frame().await, (Peer::Ip(a), b"after".to_vec()));

    stream.reply(&Peer::Ip(b), b"");
    stream.reply(&Peer::Ip(c), &max);
    assert_eq!(recv(&*transport).await, (b, Vec::new()));
    assert_eq!(recv(&*transport).await, (c, max));

    // A frame larger than the caller's buffer is packet-local.
    stream.reply(&Peer::Ip(a), b"too long for the buffer");
    stream.reply(&Peer::Ip(a), b"next");
    let error = transport.recv_packet(&mut [0u8; 4]).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(recv(&*transport).await, (a, b"next".to_vec()));
}

#[tokio::test]
async fn stream_failure_ends_the_transport() {
    let (server, mut streams) = start_wire_server().await;
    let a: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let (_runtime, transport) = shared_source(server, false, a, None).await;
    transport
        .send_to(a, None, b"hello", false, None)
        .await
        .unwrap();
    let stream = streams.recv().await.unwrap();
    // A byte that is no ATYP cannot be skipped: the parser's terminal case.
    stream.cmd.send(Cmd::Bytes(vec![9])).unwrap();
    let error = tokio::time::timeout(T, transport.recv_packet(&mut [0u8; 64]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let (server, mut streams) = start_wire_server().await;
    let (_runtime, transport) = shared_source(server, false, a, None).await;
    transport
        .send_to(a, None, b"hello", false, None)
        .await
        .unwrap();
    let stream = streams.recv().await.unwrap();
    stream.cmd.send(Cmd::Fail).unwrap();
    assert!(
        tokio::time::timeout(T, transport.recv_packet(&mut [0u8; 64]))
            .await
            .unwrap()
            .is_err()
    );
    // The server stopped reading: a later write fails instead of pretending.
    let mut failed = false;
    for _ in 0..50 {
        if transport.send_to(a, None, b"x", false, None).await.is_err() {
            failed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(failed, "writes to a stopped stream must fail");
}

/// `write_chunk` is not cancellation safe: a frame cancelled while QUIC flow
/// control holds it back may be torn, so the stalled datagram counts as
/// admitted (a terminal deadline) and a sibling destination must fail instead
/// of extending it, even once the server reads again.
#[tokio::test]
async fn cancelled_frame_write_poisons_the_shared_stream() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (server, mut streams) = start_wire_server().await;
    let a: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let b: SocketAddr = "192.0.2.2:53".parse().unwrap();
    let (_runtime, transport) = shared_source(server, false, a, None).await;
    transport
        .send_to(a, None, b"hello", false, None)
        .await
        .unwrap();
    let stream = streams.recv().await.unwrap();
    stream.cmd.send(Cmd::Pause(true)).unwrap();
    let frame = vec![0u8; 60_000];
    let admitted = AtomicBool::new(false);
    let mut stalled = false;
    for _ in 0..400 {
        admitted.store(false, Ordering::SeqCst);
        let write = transport.send_to(a, None, &frame, false, Some(&admitted));
        if tokio::time::timeout(Duration::from_millis(100), write)
            .await
            .is_err()
        {
            stalled = true;
            break;
        }
    }
    assert!(stalled, "flow control must eventually hold a frame back");
    assert!(admitted.load(Ordering::SeqCst));
    stream.cmd.send(Cmd::Pause(false)).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let error = transport
        .send_to(b, None, b"b", false, None)
        .await
        .unwrap_err();
    assert!(crate::proxy::is_frame_interrupted(&error));
}

#[tokio::test]
async fn dropping_the_transport_releases_the_stream() {
    let (server, mut streams) = start_wire_server().await;
    let node = test_node(server.port(), TEST_PASSWORD);
    let handler = JuicityHandler::new();
    let client = handler.build_client(&node, None).await.unwrap();
    let a: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let transport = handler
        .udp_transport_via_client(client, a, None, T, true)
        .await
        .unwrap();
    let open = Arc::clone(&transport.state.open);
    assert_eq!(open.load(Ordering::Relaxed), 1);
    transport.send_to(a, None, b"x", false, None).await.unwrap();
    let mut stream = streams.recv().await.unwrap();
    stream.frame().await;
    drop(transport);
    assert_eq!(open.load(Ordering::Relaxed), 0);
    // The released send side finishes the stream for the peer.
    assert!(
        tokio::time::timeout(T, stream.frames.recv())
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn request_observation_follows_each_flow() {
    use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver, Milestone};

    for speculative in [false, true] {
        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let [opener, other] = std::array::from_fn::<_, 2, _>(|_| {
            let events = Arc::clone(&events);
            FlowObserver::new(
                FlowContext {
                    flow_id: uuid::Uuid::new_v4(),
                    generation: 1,
                    attempt_id: None,
                    lookup_id: None,
                    dns_purpose: "proxy_server",
                },
                Arc::new(move |context, event| {
                    if matches!(
                        event,
                        FlowEvent::Milestone {
                            milestone: Milestone::TargetRequestSent
                        }
                    ) {
                        events.lock().push(context.flow_id);
                    }
                }),
            )
        });
        let (server, _streams) = start_wire_server().await;
        let a: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let (_runtime, transport) = {
            let prepare = shared_source(server, speculative, a, None);
            tokio::pin!(prepare);
            opener.scope(&mut prepare).await
        };
        assert!(events.lock().is_empty(), "opening publishes for no flow");
        other
            .scope(transport.send_to(a, None, b"x", false, None))
            .await
            .unwrap();
        opener
            .scope(transport.send_to(a, None, b"y", false, None))
            .await
            .unwrap();
        assert_eq!(
            events.lock().as_slice(),
            &[other.context().flow_id, opener.context().flow_id]
        );
    }
}
