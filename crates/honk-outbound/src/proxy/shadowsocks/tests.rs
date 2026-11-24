use super::*;
use crate::test_support::{
    TCP_TARGET, TCP_TARGET_HEADER, assert_legacy_bulk_echo, mock_legacy_tcp_server,
};
use std::net::{Ipv4Addr, SocketAddrV4};

#[test]
fn test_evp_bytes_to_key() {
    let key = ShadowsocksHandler::master_key("foobar", 32);
    assert_eq!(key.len(), 32);
    // MD5("foobar") == 3858f62230ac3c915f300c664312c63f, which is the first
    // block of EVP_BytesToKey output.
    assert_eq!(
        &key[..16],
        &[
            0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91, 0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12,
            0xc6, 0x3f
        ]
    );
}

#[test]
fn test_nonce_increment() {
    let mut n = [0u8; 12];
    increment_nonce(&mut n);
    assert_eq!(n, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    n[0] = 0xFF;
    increment_nonce(&mut n);
    assert_eq!(n, [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn test_cipher_conf_lookup() {
    assert!(CipherConf::for_method("aes-128-gcm").is_ok());
    assert!(CipherConf::for_method("AES-256-GCM").is_ok());
    assert!(CipherConf::for_method("chacha20-ietf-poly1305").is_ok());
    assert!(CipherConf::for_method("chacha20-poly1305").is_ok());
    assert!(CipherConf::for_method("2022-blake3-aes-128-gcm").is_ok());
    assert!(CipherConf::for_method("2022-blake3-aes-256-gcm").is_ok());
    assert!(CipherConf::for_method("2022-blake3-chacha20-poly1305").is_ok());
    assert!(CipherConf::for_method("rc4-md5").is_err());
}

#[test]
fn test_is_2022_method() {
    assert!(is_2022_method("2022-blake3-aes-128-gcm"));
    assert!(is_2022_method("2022-BLAKE3-AES-256-GCM"));
    assert!(is_2022_method("2022-blake3-chacha20-poly1305"));
    assert!(!is_2022_method("aes-256-gcm"));
    assert!(!is_2022_method("chacha20-ietf-poly1305"));
}

fn legacy_transport(socket: tokio::net::UdpSocket, target: SocketAddr) -> SsUdpTransport {
    SsUdpTransport {
        server_addr: socket.peer_addr().unwrap(),
        socket,
        crypto: tokio::sync::Mutex::new(SsUdpCrypto::Legacy(
            LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap(),
        )),
        recv_buf: tokio::sync::Mutex::new(None),
        socks: addr::encode_address(target, None).unwrap(),
        target,
        target_domain: None,
    }
}

#[test]
fn test_legacy_udp_roundtrip() {
    let crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
    let socks = addr::encode_address(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
        None,
    )
    .unwrap();
    let payload = b"\xde\xad\xbe\xef dns query";
    let packet = crypto.seal(&socks, payload).unwrap();
    // salt + tag minimum
    assert!(packet.len() > 16 + 16 + payload.len());
    let opened = crypto.open(&packet).unwrap();
    assert_eq!(opened.payload(), payload);
    assert_eq!(
        opened.peer,
        addr::SocksAddr::V4("8.8.8.8:53".parse().unwrap())
    );
}

#[tokio::test]
async fn udp_send_waits_for_cipher_instead_of_reporting_a_drop_as_success() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(server.local_addr().unwrap()).await.unwrap();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = Arc::new(legacy_transport(client, target));
    let guard = transport.crypto.lock().await;
    let sender = {
        let transport = Arc::clone(&transport);
        tokio::spawn(async move { transport.send_packet(b"retained").await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(
        !sender.is_finished(),
        "cipher contention must apply backpressure instead of returning false success"
    );

    drop(guard);
    sender.await.unwrap().unwrap();
    let mut packet = [0u8; 256];
    let received =
        tokio::time::timeout(std::time::Duration::from_secs(1), server.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
    assert!(received > b"retained".len());
}

#[tokio::test]
async fn checked_udp_send_rechecks_while_waiting_for_cipher() {
    use crate::proxy::{PacketRejection, io_packet_rejection};
    use std::task::{Context, Poll, Waker};
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(socket.local_addr().unwrap()).await.unwrap();
    let target = "127.0.0.1:53".parse().unwrap();
    let transport = legacy_transport(socket, target);
    let _cipher = transport.crypto.lock().await;
    let admitted = AtomicBool::new(false);
    let allowed = AtomicBool::new(true);
    let current = || allowed.load(Ordering::Acquire);
    let mut send = std::pin::pin!(transport.send_to_checked(
        target,
        None,
        b"waiting",
        Some(&admitted),
        &current,
    ));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(send.as_mut().poll(&mut cx).is_pending());

    allowed.store(false, Ordering::Release);
    let Poll::Ready(result) = send.as_mut().poll(&mut cx) else {
        panic!("withdrawal must settle a send waiting for the cipher");
    };
    assert_eq!(
        io_packet_rejection(&result.unwrap_err()),
        Some(PacketRejection::Cancelled)
    );
    assert!(!admitted.load(Ordering::Acquire));
}

#[test]
fn test_legacy_udp_roundtrip_chacha() {
    let crypto = LegacyUdpCrypto::new("chacha20-ietf-poly1305", "test-password").unwrap();
    let socks = addr::encode_address(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443)),
        Some("one.one"),
    )
    .unwrap();
    let payload = b"quic initial";
    let packet = crypto.seal(&socks, payload).unwrap();
    let opened = crypto.open(&packet).unwrap();
    assert_eq!(opened.payload(), payload);
    assert_eq!(opened.peer, addr::SocksAddr::Domain("one.one".into(), 443));
}

#[test]
fn test_legacy_udp_open_rejects_garbage() {
    let crypto = LegacyUdpCrypto::new("aes-256-gcm", "test-password").unwrap();
    assert!(crypto.open(&[0u8; 10]).is_err());
    let mut garbage = vec![0u8; 64];
    rand::rng().fill_bytes(&mut garbage);
    assert!(crypto.open(&garbage).is_err());
}

/// Batched seal/decrypt equivalence: any payload round-trips through
/// `seal_chunks_into` + `decrypt_chunks_in_place` in one batch.
#[test]
fn test_batched_chunk_roundtrip() {
    let cipher = AeadCipher::new("aes-128-gcm", &ShadowsocksHandler::master_key("pw", 16)).unwrap();
    for payload_len in [0usize, 1, 100, CHUNK_MAX_LEN, CHUNK_MAX_LEN + 17, 100_000] {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        let mut send_nonce = vec![0u8; 12];
        let mut sealed = Vec::new();
        seal_chunks_into(&cipher, &mut send_nonce, &payload, &mut sealed).unwrap();
        assert_eq!(
            sealed.len(),
            payload_len + payload_len.div_ceil(CHUNK_MAX_LEN) * (2 + 16 + 16)
        );

        let mut recv_nonce = vec![0u8; 12];
        let mut buf = sealed;
        let total = buf.len();
        let (out_len, carry) =
            decrypt_chunks_in_place(&cipher, &mut recv_nonce, &mut None, &mut buf, total, 16)
                .unwrap();
        assert_eq!(carry, 0, "complete batch must leave no carry");
        assert_eq!(&buf[..out_len], payload.as_slice());
    }
}

/// Split feeds: chunks spanning batch boundaries must be carried and
/// completed by the next feed.
#[test]
fn test_batched_decrypt_split_feeds() {
    let cipher = AeadCipher::new("aes-128-gcm", &ShadowsocksHandler::master_key("pw", 16)).unwrap();
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 253) as u8).collect();
    let mut send_nonce = vec![0u8; 12];
    let mut sealed = Vec::new();
    seal_chunks_into(&cipher, &mut send_nonce, &payload, &mut sealed).unwrap();

    let mut recv_nonce = vec![0u8; 12];
    let mut pending = None;
    let mut received = Vec::new();
    let mut carry_buf = vec![0u8; 0];
    // Feed in awkward slices that split len fields and chunk bodies.
    for slice_len in [1usize, 3, 7, 8192, 5, 4096, 65536] {
        let take = slice_len.min(sealed.len());
        let mut feed = carry_buf.clone();
        feed.extend_from_slice(&sealed[..take]);
        sealed.drain(..take);
        let total = feed.len();
        let (out_len, rest) =
            decrypt_chunks_in_place(&cipher, &mut recv_nonce, &mut pending, &mut feed, total, 16)
                .unwrap();
        received.extend_from_slice(&feed[..out_len]);
        carry_buf = feed[out_len..out_len + rest].to_vec();
    }
    assert!(sealed.is_empty());
    let total = carry_buf.len();
    let (out_len, rest) = decrypt_chunks_in_place(
        &cipher,
        &mut recv_nonce,
        &mut pending,
        &mut carry_buf,
        total,
        16,
    )
    .unwrap();
    received.extend_from_slice(&carry_buf[..out_len]);
    assert_eq!(rest, 0);
    assert_eq!(received, payload);
}

/// End-to-end TCP test: mock legacy-AEAD TCP server, real `dial` through
/// the inline `SsStream`, bulk data both ways (chunk boundaries crossed
/// many times).
#[tokio::test]
async fn test_dial_tcp_legacy_end_to_end() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (server, _) = listener.accept().await.unwrap();
        mock_legacy_tcp_server(server, &TCP_TARGET_HEADER).await;
    });

    let node = Node {
        name: "test-ss-tcp".into(),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some("aes-128-gcm".into()),
                password: Some("test-password".into()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let handler = ShadowsocksHandler::new();
    let target: SocketAddr = TCP_TARGET.parse().unwrap();
    let mut stream = handler
        .dial(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    assert_legacy_bulk_echo(&mut stream.stream).await;
}

#[tokio::test]
async fn legacy_tcp_relay_runs_over_a_non_tcp_stream() {
    // Large enough to hold the whole echo while the client is still writing.
    let (client, server) = tokio::io::duplex(4 << 20);
    tokio::spawn(mock_legacy_tcp_server(server, &TCP_TARGET_HEADER));

    let mut node = Node {
        name: "test-ss-tunnel".into(),
        address: "198.51.100.1:8388".into(),
        host: "must-not-resolve.invalid".into(),
        port: 8388,
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some("aes-128-gcm".into()),
                password: Some("test-password".into()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    let target: SocketAddr = TCP_TARGET.parse().unwrap();
    let mut stream = ShadowsocksHandler::new()
        .dial_over(
            runtime,
            Box::new(client),
            target,
            None,
            crate::proxy::TunnelDialOptions::new(std::time::Duration::from_secs(3)),
        )
        .await
        .unwrap();
    assert_legacy_bulk_echo(&mut stream.stream).await;
}

#[cfg(feature = "flow-observation")]
mod tunneled_request_observation {
    use super::*;
    use crate::proxy::request_observation_support::{DeferringCarrier, observed};
    use crate::runtime::flow_observation::{FlowEvent, Milestone};
    use tokio::io::AsyncReadExt;

    const METHODS: [(&str, &str); 2] = [
        ("aes-128-gcm", "test-password"),
        ("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw=="),
    ];

    fn request_sent(events: &[FlowEvent]) -> bool {
        matches!(
            events,
            [FlowEvent::Milestone {
                milestone: Milestone::TargetRequestSent
            }]
        )
    }

    async fn dial_over(
        method: &str,
        password: &str,
        carrier: Box<dyn AsyncReadWrite>,
    ) -> ProxyStream {
        let mut node = Node {
            name: "test-ss-observed-tunnel".into(),
            address: "198.51.100.1:8388".into(),
            host: "must-not-resolve.invalid".into(),
            port: 8388,
            outbound: honk_config::node::OutboundConfig::Shadowsocks(
                honk_config::node::ShadowsocksConfig {
                    encryption: Some(method.into()),
                    password: Some(password.into()),
                    ..Default::default()
                },
            ),
            ..Default::default()
        };
        node.id = node.derive_id();
        let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
        ShadowsocksHandler::new()
            .dial_over(
                runtime,
                carrier,
                "93.184.216.34:80".parse().unwrap(),
                None,
                crate::proxy::TunnelDialOptions::new(std::time::Duration::from_secs(3)),
            )
            .await
            .unwrap()
    }

    /// After `dial_over` returns, the request event is present and the peer can read the salt.
    #[tokio::test]
    async fn request_sent_follows_the_buffered_carrier_flush() {
        for (method, password) in METHODS {
            let (client, mut peer) = tokio::io::duplex(64 * 1024);
            let (observer, events) = observed();
            let _stream = observer
                .scope(dial_over(
                    method,
                    password,
                    Box::new(tokio::io::BufWriter::new(client)),
                ))
                .await;
            assert!(request_sent(&events.lock()), "{method}");
            let mut salt = [0u8; 16];
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                peer.read_exact(&mut salt),
            )
            .await
            .unwrap_or_else(|_| panic!("{method}: prologue still buffered"))
            .unwrap();
        }
    }

    #[tokio::test]
    async fn request_sent_waits_for_a_deferring_carrier() {
        for (method, password) in METHODS {
            let (client, _peer) = tokio::io::duplex(64 * 1024);
            let (carrier, request) = DeferringCarrier::new(client);
            let (observer, events) = observed();
            let _stream = observer
                .scope(dial_over(method, password, Box::new(carrier)))
                .await;
            assert!(
                events.lock().is_empty(),
                "{method}: published before delivery"
            );
            let (request, _) = request.lock().take().expect(method);
            request.confirm();
            assert!(request_sent(&events.lock()), "{method}");
        }
    }
}

/// A datagram the session cannot open is dropped; the next valid one is
/// delivered and the transport stays usable.
#[tokio::test]
async fn udp_receive_drops_an_unopenable_datagram_and_keeps_the_session() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(server.local_addr().unwrap()).await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = legacy_transport(client, target);
    let server_crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
    let wrong_key = LegacyUdpCrypto::new("aes-128-gcm", "other-password").unwrap();
    let socks = addr::encode_address(target, None).unwrap();
    // Too short, wrong key, then a valid packet.
    server.send_to(&[0u8; 8], client_addr).await.unwrap();
    server
        .send_to(&wrong_key.seal(&socks, b"forged").unwrap(), client_addr)
        .await
        .unwrap();
    server
        .send_to(
            &server_crypto.seal(&socks, b"genuine").unwrap(),
            client_addr,
        )
        .await
        .unwrap();

    let mut buf = [0u8; 1500];
    let (n, src) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        transport.recv_packet(&mut buf),
    )
    .await
    .expect("the valid datagram must be delivered after the dropped ones")
    .unwrap();
    assert_eq!(src, target);
    assert_eq!(&buf[..n], b"genuine");
}

/// End-to-end UDP test over the real framed `dial_udp_transport` path.
#[tokio::test]
async fn test_dial_udp_transport_legacy_end_to_end() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let (n, src) = server.recv_from(&mut buf).await.unwrap();
            let payload = server_crypto.open(&buf[..n]).unwrap();
            let reply: Vec<u8> = payload
                .payload()
                .iter()
                .map(|b| b.to_ascii_uppercase())
                .collect();
            let socks = addr::encode_address("8.8.8.8:53".parse().unwrap(), None).unwrap();
            let packet = server_crypto.seal(&socks, &reply).unwrap();
            server.send_to(&packet, src).await.unwrap();
        }
    });

    let node = Node {
        name: "test-ss-udp".into(),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some("aes-128-gcm".into()),
                password: Some("test-password".into()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let handler = ShadowsocksHandler::new();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = handler
        .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(transport.relay_addr(), target);

    let payload = [b'a'; 1200];
    let mut buf = [0u8; 1200];
    let (received, sent) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(biased; transport.recv_packet(&mut buf), transport.send_packet(&payload))
    })
    .await
    .expect("pending receive must not block the send that elicits its reply");
    sent.unwrap();
    let (n, src) = received.unwrap();
    assert_eq!(src, target);
    assert_eq!(&buf[..n], &[b'A'; 1200]);
}

/// Independent legacy-AEAD wire peer for the shared-association tests:
/// `salt | AEAD(HKDF-SHA1(key, salt, "ss-subkey"))(addr | payload)` with a
/// zero nonce, framed without the production UDP codec.
struct LegacyPeer {
    method: &'static str,
    key: Vec<u8>,
}

impl LegacyPeer {
    fn new(method: &'static str, password: &str) -> Self {
        use md5::{Digest, Md5};
        let key_len = if method == "aes-128-gcm" { 16 } else { 32 };
        let (mut key, mut prev) = (Vec::new(), Vec::new());
        while key.len() < key_len {
            prev.extend_from_slice(password.as_bytes());
            prev = Md5::digest(&prev).to_vec();
            key.extend_from_slice(&prev);
        }
        key.truncate(key_len);
        Self { method, key }
    }

    fn salt_len(&self) -> usize {
        self.key.len()
    }

    fn cipher(&self, salt: &[u8]) -> AeadCipher {
        let mut subkey = vec![0u8; self.key.len()];
        Hkdf::<Sha1>::new(Some(salt), &self.key)
            .expand(b"ss-subkey", &mut subkey)
            .unwrap();
        AeadCipher::new(self.method, &subkey).unwrap()
    }

    fn seal(&self, plain: &[u8]) -> Vec<u8> {
        let mut salt = vec![0u8; self.salt_len()];
        rand::rng().fill_bytes(&mut salt);
        let mut packet = salt.clone();
        packet.extend_from_slice(&self.cipher(&salt).seal(&[0u8; 12], plain).unwrap());
        packet
    }

    fn open(&self, packet: &[u8]) -> Vec<u8> {
        let (salt, sealed) = packet.split_at(self.salt_len());
        self.cipher(salt).open(&[0u8; 12], sealed).unwrap()
    }
}

/// SOCKS5 address bytes for a socket address, written by hand.
fn wire_addr(peer: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match peer {
        SocketAddr::V4(v4) => {
            out.push(1);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(4);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&peer.port().to_be_bytes());
    out
}

fn wire_domain(domain: &str, port: u16) -> Vec<u8> {
    let mut out = vec![3, domain.len() as u8];
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

const LEGACY_METHODS: [&str; 3] = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];
const PASSWORD: &str = "shared-source-password";
const STEP: std::time::Duration = std::time::Duration::from_secs(2);

fn legacy_node(server: SocketAddr, method: &str) -> Node {
    let mut node = Node {
        name: "test-ss-shared".into(),
        address: server.ip().to_string(),
        port: server.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some(method.into()),
                password: Some(PASSWORD.into()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

struct Shared {
    server: tokio::net::UdpSocket,
    peer: LegacyPeer,
    transport: Arc<dyn MultiTargetTransport>,
}

impl Shared {
    async fn new(method: &'static str, target: SocketAddr, domain: Option<&str>) -> Self {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let node = legacy_node(server.local_addr().unwrap(), method);
        let transport = Arc::new(
            ShadowsocksHandler::udp_transport(&node, target, domain, STEP)
                .await
                .unwrap(),
        );
        Self {
            server,
            peer: LegacyPeer::new(method, PASSWORD),
            transport,
        }
    }

    async fn send(&self, to: SocketAddr, domain: Option<&str>, payload: &[u8]) {
        self.transport
            .send_to(to, domain, payload, false, None)
            .await
            .unwrap();
    }

    /// The client's outer source and the decrypted `addr | payload`.
    async fn server_recv(&self) -> (SocketAddr, Vec<u8>) {
        let mut buf = vec![0u8; 65536];
        let (n, from) = tokio::time::timeout(STEP, self.server.recv_from(&mut buf))
            .await
            .expect("server datagram")
            .unwrap();
        (from, self.peer.open(&buf[..n]))
    }

    async fn reply(&self, client: SocketAddr, addr: &[u8], payload: &[u8]) {
        let plain = [addr, payload].concat();
        self.server
            .send_to(&self.peer.seal(&plain), client)
            .await
            .unwrap();
    }

    async fn client_recv(&self) -> (Vec<u8>, SocketAddr) {
        let mut buf = vec![0u8; 65536];
        let (n, from) = tokio::time::timeout(STEP, self.transport.recv_packet(&mut buf))
            .await
            .expect("client datagram")
            .unwrap();
        (buf[..n].to_vec(), from)
    }
}

/// Two destinations over one transport reach the server from one outer
/// source (one server-side mapping); a reply from a never-contacted peer
/// returns that peer, IPv4-mapped sources normalize, empty payloads survive.
#[tokio::test]
async fn legacy_udp_one_association_serves_every_destination() {
    for method in LEGACY_METHODS {
        let a: SocketAddr = "198.51.100.1:53".parse().unwrap();
        let b: SocketAddr = "[2001:db8::2]:5353".parse().unwrap();
        let c: SocketAddr = "203.0.113.9:4000".parse().unwrap();
        let c6: SocketAddr = "[2001:db8::9]:9".parse().unwrap();
        let shared = Shared::new(method, a, None).await;
        assert_eq!(
            shared.transport.carrier_addr(),
            Some(shared.server.local_addr().unwrap())
        );

        shared.send(a, None, b"to-a").await;
        shared.send(b, None, b"to-b").await;
        shared.send(a, None, b"").await;
        let (src_a, plain_a) = shared.server_recv().await;
        let (src_b, plain_b) = shared.server_recv().await;
        let (src_empty, plain_empty) = shared.server_recv().await;
        assert_eq!(src_a, src_b, "{method}: one outer source for both targets");
        assert_eq!(src_a, src_empty);
        assert_eq!(plain_a, [wire_addr(a), b"to-a".to_vec()].concat());
        assert_eq!(plain_b, [wire_addr(b), b"to-b".to_vec()].concat());
        assert_eq!(plain_empty, wire_addr(a));

        // Unsolicited peers, then the contacted ones.
        shared.reply(src_a, &wire_addr(c), b"from-c").await;
        assert_eq!(shared.client_recv().await, (b"from-c".to_vec(), c));
        shared.reply(src_a, &wire_addr(c6), b"from-c6").await;
        assert_eq!(shared.client_recv().await, (b"from-c6".to_vec(), c6));
        shared.reply(src_a, &wire_addr(b), b"from-b").await;
        assert_eq!(shared.client_recv().await, (b"from-b".to_vec(), b));
        shared.reply(src_a, &wire_addr(a), b"").await;
        assert_eq!(shared.client_recv().await, (Vec::new(), a));

        let mapped = vec![
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 7, 0x1f, 0x90,
        ];
        shared.reply(src_a, &mapped, b"mapped").await;
        let expected: SocketAddr = "192.0.2.7:8080".parse().unwrap();
        assert_eq!(shared.client_recv().await, (b"mapped".to_vec(), expected));
    }
}

/// A domain source is accepted only as the dialed domain and port, and is
/// projected to the dialed target; any other name is dropped without DNS.
#[tokio::test]
async fn legacy_udp_domain_source_projects_only_the_dialed_name() {
    let a: SocketAddr = "198.51.100.1:443".parse().unwrap();
    let c: SocketAddr = "203.0.113.9:4000".parse().unwrap();
    let shared = Shared::new("aes-256-gcm", a, Some("Example.COM")).await;

    // Default target keeps its dialed name on the wire; the same IP without
    // the name is a different destination.
    shared.transport.send_packet(b"d").await.unwrap();
    shared.send(a, None, b"ip").await;
    shared.send(a, Some("other.example"), b"other").await;
    let (src, first) = shared.server_recv().await;
    assert_eq!(
        first,
        [wire_domain("Example.COM", 443), b"d".to_vec()].concat()
    );
    assert_eq!(
        shared.server_recv().await.1,
        [wire_addr(a), b"ip".to_vec()].concat()
    );
    assert_eq!(
        shared.server_recv().await.1,
        [wire_addr(a), b"other".to_vec()].concat(),
        "a name other than the dialed one goes out numerically"
    );

    shared
        .reply(src, &wire_domain("other.example", 443), b"x")
        .await;
    shared
        .reply(src, &wire_domain("example.com", 444), b"x")
        .await;
    shared
        .reply(src, &wire_domain("example.com", 443), b"named")
        .await;
    assert_eq!(shared.client_recv().await, (b"named".to_vec(), a));
    shared
        .reply(src, &wire_domain("other.example", 443), b"x")
        .await;
    shared.reply(src, &wire_addr(c), b"after").await;
    assert_eq!(shared.client_recv().await, (b"after".to_vec(), c));

    let overlong = "d".repeat(256);
    shared.send(a, Some(&overlong), b"long").await;
    assert_eq!(
        shared.server_recv().await.1,
        [wire_addr(a), b"long".to_vec()].concat()
    );
}

/// Short, wrong-key, truncated, unknown-ATYP and bad-domain frames each
/// drop only their own datagram.
#[tokio::test]
async fn legacy_udp_bad_frames_drop_only_the_datagram() {
    let a: SocketAddr = "198.51.100.1:53".parse().unwrap();
    let shared = Shared::new("aes-128-gcm", a, None).await;
    shared.send(a, None, b"hello").await;
    let (client, _) = shared.server_recv().await;

    let wrong_key = LegacyPeer::new("aes-128-gcm", "other-password");
    let frames = [
        vec![0u8; 8],
        wrong_key.seal(&[wire_addr(a), b"x".to_vec()].concat()),
        shared.peer.seal(&[1, 1, 2]),
        shared.peer.seal(&[5, 1, 2, 3, 4, 5, 6, 7]),
        shared.peer.seal(&[3, 0, 0, 53]),
        shared.peer.seal(&[3, 2, 0xff, 0xfe, 0, 53, 1]),
        shared.peer.seal(&[]),
    ];
    for frame in &frames {
        shared.server.send_to(frame, client).await.unwrap();
    }
    shared.reply(client, &wire_addr(a), b"genuine").await;
    assert_eq!(shared.client_recv().await, (b"genuine".to_vec(), a));
}

/// The largest datagram that fits one UDP packet crosses both ways; one byte
/// more is refused without hurting the association.
#[tokio::test]
async fn legacy_udp_max_size_boundary() {
    for method in LEGACY_METHODS {
        let a: SocketAddr = "198.51.100.1:53".parse().unwrap();
        let shared = Shared::new(method, a, None).await;
        // 65507 UDP payload = salt + IPv4 address (7) + payload + tag (16).
        let max = 65507 - shared.peer.salt_len() - 7 - 16;
        let payload = vec![0x5a; max];

        shared.send(a, None, &payload).await;
        let (client, plain) = shared.server_recv().await;
        assert_eq!(plain[7..], payload[..]);
        shared.reply(client, &wire_addr(a), &payload).await;
        assert_eq!(shared.client_recv().await, (payload.clone(), a));

        let error = shared
            .transport
            .send_to(a, None, &vec![0; max + 1], false, None)
            .await
            .unwrap_err();
        assert_eq!(
            crate::proxy::io_packet_rejection(&error),
            Some(crate::proxy::PacketRejection::InvalidSize),
            "a socket size refusal is local, not a dead tunnel"
        );
        shared.send(a, None, b"alive").await;
        assert_eq!(shared.server_recv().await.1[7..], b"alive"[..]);
    }
}

/// Dropping a transport closes its socket.
#[tokio::test]
async fn legacy_udp_drop_releases_the_socket() {
    let a: SocketAddr = "198.51.100.1:53".parse().unwrap();
    let shared = Shared::new("aes-128-gcm", a, None).await;
    shared.send(a, None, b"x").await;
    let (client, _) = shared.server_recv().await;
    assert!(
        std::net::UdpSocket::bind(client).is_err(),
        "the live transport owns its source port"
    );
    let Shared { transport, .. } = shared;
    drop(transport);
    drop(std::net::UdpSocket::bind(client).expect("drop closes the transport socket"));
}

/// The core reaches Shadowsocks only through the shared-source dispatch.
#[tokio::test]
async fn shared_source_dispatch_builds_a_shadowsocks_association() {
    let registry = crate::proxy::ProxyRegistry::default_resolver().unwrap();
    assert!(registry.has_shared_source(honk_config::types::NodeProtocol::SS));
    let a: SocketAddr = "198.51.100.1:53".parse().unwrap();
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let node = legacy_node(server.local_addr().unwrap(), "aes-128-gcm");
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    let transport = registry
        .prepare_shared_source(runtime, a, None, STEP, true)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    transport.send_to(a, None, b"hi", true, None).await.unwrap();
    let mut buf = [0u8; 256];
    let (n, _) = tokio::time::timeout(STEP, server.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(n > b"hi".len());
}
