//! Interop: BoringSSL QUIC client ↔ rustls QUIC server (the same servers
//! the protocol handlers are tested against).
use super::*;
use honk_config::node::Node;

fn quic_node() -> Node {
    Node {
        outbound: honk_config::node::OutboundConfig::Hysteria2(Default::default()),
        ..Default::default()
    }
}

fn skip_verify_node() -> Node {
    let mut node = quic_node();
    node.tls_mut().unwrap().skip_cert_verify = true;
    node
}

/// Echo server: relays every accepted bi stream back to its peer.
fn spawn_echo_server(alpn: &[&[u8]]) -> std::net::SocketAddr {
    let (endpoint, addr) = crate::quic::testutil::server_endpoint(alpn, true).unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                loop {
                    match conn.accept_bi().await {
                        Ok((mut send, mut recv)) => {
                            tokio::spawn(async move {
                                if let Ok(buf) = recv.read_to_end(usize::MAX).await {
                                    let _ = send.write_all(&buf).await;
                                    let _ = send.finish();
                                }
                            });
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });
    addr
}

async fn roundtrip(node: &Node) -> anyhow::Result<Vec<u8>> {
    let addr = spawn_echo_server(&[b"h3"]);
    roundtrip_to(node, addr).await
}

/// ChaCha20-Poly1305 interop: the server is restricted to TLS 1.3
/// ChaCha20 so QUIC header protection takes the ChaCha20 path
/// (regression: the HP block counter was once passed to
/// `StreamCipherSeek::seek` as a byte offset, so every ChaCha
/// handshake against a real peer failed while same-code
/// boring↔boring pairs self-cancelled).
#[tokio::test]
async fn chacha20_handshake_and_echo() {
    let (endpoint, addr) = crate::quic::testutil::server_endpoint_chacha20(&[b"h3"], true).unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                loop {
                    match conn.accept_bi().await {
                        Ok((mut send, mut recv)) => {
                            tokio::spawn(async move {
                                if let Ok(buf) = recv.read_to_end(usize::MAX).await {
                                    let _ = send.write_all(&buf).await;
                                    let _ = send.finish();
                                }
                            });
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });
    let node = skip_verify_node();
    let cfg = crate::quic::client_config(&node, &[b"h3"], Default::default())
        .await
        .unwrap();
    let mut endpoint = crate::quic::client_endpoint(false).unwrap();
    endpoint.set_default_client_config(cfg);
    let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    // The server prefers ChaCha20; if it negotiates AES anyway this test
    // exercises nothing, so assert the suite explicitly.
    let suite = conn
        .handshake_data()
        .and_then(|d| d.downcast::<BoringHandshakeData>().ok())
        .map(|d| d.cipher_suite);
    assert_eq!(
        suite,
        Some(TLS13_CHACHA20_POLY1305_SHA256),
        "server must negotiate ChaCha20 for this test to be meaningful"
    );
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let echoed = recv.read_to_end(usize::MAX).await.unwrap();
    assert_eq!(echoed, b"ping");
}

/// A ticket cached under a rebuilt client config (post-reload SSL_CTX)
/// or rejected by the server must be evicted on handshake failure —
/// never poison every later dial until process restart. Production
/// regression: after a SIGHUP reload pointed a node at a different
/// server with the same SNI, every dial failed on the stale ticket.
#[tokio::test]
async fn rejected_ticket_is_evicted() {
    let addr = spawn_echo_server(&[b"h3"]);
    let node = Node {
        address: "127.0.0.1:0".to_string(),
        ..skip_verify_node()
    };
    let ticket_key = format!("{}|{}|{}|h3", node.host(), node.port, node.host());
    // Prime the cache under the first client config (SSL_CTX #1).
    let cfg1 = crate::quic::client_config(&node, &[b"h3"], Default::default())
        .await
        .unwrap();
    let mut endpoint = crate::quic::client_endpoint(false).unwrap();
    endpoint.set_default_client_config(cfg1);
    let conn = endpoint.connect(addr, "evict.test").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let _ = recv.read_to_end(16).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    conn.close(0u32.into(), b"done");
    assert!(SESSION_TICKETS.lock().contains_key(&ticket_key));

    // Rebuild the client config (SSL_CTX #2, as a reload would) and dial
    // twice: whatever happens with the cross-context ticket on the first
    // dial, the second must succeed — the cache can never stay poisoned.
    let cfg2 = crate::quic::client_config(&node, &[b"h3"], Default::default())
        .await
        .unwrap();
    for attempt in 0..2 {
        let mut endpoint = crate::quic::client_endpoint(false).unwrap();
        endpoint.set_default_client_config(cfg2.clone());
        match endpoint.connect(addr, "evict.test").unwrap().await {
            Ok(conn) => {
                conn.close(0u32.into(), b"done");
                if attempt == 1 {
                    return;
                }
            }
            Err(e) => {
                assert_eq!(attempt, 0, "second dial must succeed, got: {e}");
                assert!(
                    !SESSION_TICKETS.lock().contains_key(&ticket_key),
                    "rejected ticket must be evicted after the failed dial"
                );
            }
        }
    }
}

/// TLS 1.3 session resumption: a second connection to the same server
/// over a shared client config must reuse the cached session ticket.
#[tokio::test]
async fn session_resumption_reuses_ticket() {
    let addr = spawn_echo_server(&[b"h3"]);
    // Unique address: the process-global ticket cache is shared by
    // parallel tests — a collision under the same key would serve a
    // foreign ticket and break the resumption assertion.
    let node = Node {
        address: "127.0.0.1:11".to_string(),
        ..skip_verify_node()
    };
    let ticket_key = format!("{}|{}|{}|h3", node.host(), node.port, node.host());
    let cfg = crate::quic::client_config(&node, &[b"h3"], Default::default())
        .await
        .unwrap();
    for i in 0..2 {
        let mut endpoint = crate::quic::client_endpoint(false).unwrap();
        endpoint.set_default_client_config(cfg.clone());
        let conn = endpoint
            .connect(addr, "resumption.test")
            .unwrap()
            .await
            .unwrap();
        let data = conn
            .handshake_data()
            .and_then(|d| d.downcast::<BoringHandshakeData>().ok())
            .expect("handshake data");
        if i == 0 {
            assert!(
                !data.session_reused,
                "first connection must be a full handshake"
            );
        }
        // Session tickets arrive post-handshake; drive a tiny exchange
        // (and let the peer's ticket flight land) before closing.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        let _ = recv.read_to_end(16).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        conn.close(0u32.into(), b"done");
        if i == 1 {
            // The ticket flight arrives post-handshake; wait for the
            // cache to hold it instead of racing the next connection.
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if SESSION_TICKETS.lock().contains_key(&ticket_key) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("session ticket was never cached");
        }
    }
    // The cached ticket must be offered and accepted at least once.
    // Resumption is opportunistic (a server may fall back to a full
    // handshake under load), so allow one fallback attempt.
    let mut resumed = false;
    for _ in 0..2 {
        let mut endpoint = crate::quic::client_endpoint(false).unwrap();
        endpoint.set_default_client_config(cfg.clone());
        let Ok(conn) = endpoint.connect(addr, "resumption.test").unwrap().await else {
            continue;
        };
        let data = conn
            .handshake_data()
            .and_then(|d| d.downcast::<BoringHandshakeData>().ok())
            .expect("handshake data");
        resumed |= data.session_reused;
        conn.close(0u32.into(), b"done");
        if resumed {
            break;
        }
    }
    assert!(
        resumed,
        "cached ticket must resume on at least one connection"
    );
}

/// A pinSHA256 node must NOT resume a ticket cached for the same host by
/// a non-pin config — resumption skips certificate verification and
/// would silently bypass the pin.
#[tokio::test]
async fn pin_config_never_resumes_cached_ticket() {
    let addr = spawn_echo_server(&[b"h3"]);
    // Prime the cache via a non-pin connection (unique address so
    // parallel tests never share its ticket key).
    let node = Node {
        address: "127.0.0.1:12".to_string(),
        ..skip_verify_node()
    };
    let cfg = crate::quic::client_config(&node, &[b"h3"], Default::default())
        .await
        .unwrap();
    let mut endpoint = crate::quic::client_endpoint(false).unwrap();
    endpoint.set_default_client_config(cfg);
    let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let _ = recv.read_to_end(16).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    conn.close(0u32.into(), b"done");

    // Same host with the correct pin set: the handshake must succeed,
    // but it must be a full handshake — never a resumed one.
    let (config, cert_der) =
        crate::quic::testutil::server_config_with_cert(&[b"h3"], true).unwrap();
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr2 = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                loop {
                    match conn.accept_bi().await {
                        Ok((mut send, mut recv)) => {
                            tokio::spawn(async move {
                                if let Ok(buf) = recv.read_to_end(usize::MAX).await {
                                    let _ = send.write_all(&buf).await;
                                    let _ = send.finish();
                                }
                            });
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });
    let pin_bytes = boring::hash::hash(boring::hash::MessageDigest::sha256(), &cert_der).unwrap();
    let pin: String = pin_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut pinned = skip_verify_node();
    pinned.tls_mut().unwrap().pin_sha256 = Some(pin);
    let cfg = crate::quic::client_config(&pinned, &[b"h3"], Default::default())
        .await
        .unwrap();
    let mut endpoint2 = crate::quic::client_endpoint(false).unwrap();
    endpoint2.set_default_client_config(cfg);
    let conn = endpoint2
        .connect(addr2, "localhost")
        .unwrap()
        .await
        .unwrap();
    let data = conn
        .handshake_data()
        .and_then(|d| d.downcast::<BoringHandshakeData>().ok())
        .expect("handshake data");
    assert!(
        !data.session_reused,
        "pin configs must never resume (PSK would bypass the pin)"
    );
    conn.close(0u32.into(), b"done");
}

/// RFC 9001 §5.4.4 ChaCha20 HP mask against a vector captured from a live
/// quic-go handshake (offline-verified: unmasking yields pn 0..3).
#[test]
fn chacha20_header_protection_mask_vector() {
    // "quic hp" derived from server handshake traffic secret a4cbec18…f8db31.
    let hp: [u8; 32] = [
        0x1f, 0x09, 0x35, 0x02, 0x8d, 0x22, 0xc4, 0x0a, 0xbe, 0x95, 0x2b, 0x3e, 0xee, 0x3d, 0x5c,
        0x51, 0x28, 0xbc, 0x74, 0x8f, 0x94, 0x04, 0xc4, 0xbd, 0x34, 0x08, 0x99, 0x51, 0xcb, 0xdb,
        0x09, 0x4d,
    ];
    let sample: [u8; 16] = [
        0x6c, 0x43, 0x66, 0x29, 0x17, 0x1a, 0x6d, 0xe1, 0x4e, 0x3c, 0xc4, 0xec, 0xb8, 0xdc, 0xc3,
        0x97,
    ];
    let key = BoringHeaderKey::ChaCha20(hp);
    assert_eq!(key.compute_mask(&sample), [0x24, 0xa2, 0x42, 0x9a, 0xec]);
}

async fn roundtrip_to(node: &Node, addr: std::net::SocketAddr) -> anyhow::Result<Vec<u8>> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .try_init();
    let cfg = crate::quic::client_config(node, &[b"h3"], Default::default()).await?;
    let mut endpoint = crate::quic::client_endpoint(false)?;
    endpoint.set_default_client_config(cfg);
    let conn = endpoint.connect(addr, "localhost")?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"ping").await?;
    send.finish()?;
    let echoed = recv.read_to_end(usize::MAX).await?;
    Ok(echoed)
}

/// pinSHA256: the handshake succeeds when the server leaf matches the
/// pin and fails otherwise — with PKI/hostname checks fully replaced.
#[tokio::test]
async fn pin_sha256_accepts_matching_cert_and_rejects_others() {
    let (config, cert_der) =
        crate::quic::testutil::server_config_with_cert(&[b"h3"], true).unwrap();
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                loop {
                    match conn.accept_bi().await {
                        Ok((mut send, mut recv)) => {
                            tokio::spawn(async move {
                                if let Ok(buf) = recv.read_to_end(usize::MAX).await {
                                    let _ = send.write_all(&buf).await;
                                    let _ = send.finish();
                                }
                            });
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });

    use sha2::Digest as _;
    let pin_hex = sha2::Sha256::digest(&cert_der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    // Matching pin works even though the cert is self-signed and the
    // node does not skip verification.
    let mut node = quic_node();
    node.tls_mut().unwrap().pin_sha256 = Some(pin_hex);
    let echoed = roundtrip_to(&node, addr).await.unwrap();
    assert_eq!(&echoed, b"ping");

    // A mismatched pin fails the handshake.
    let mut node = quic_node();
    node.tls_mut().unwrap().pin_sha256 = Some("00".repeat(32));
    assert!(roundtrip_to(&node, addr).await.is_err());
}

/// Baseline: standard (non-Chrome) mode round-trips through a rustls server.
#[tokio::test]
async fn interop_standard_mode() {
    crate::tls::set_tls_mode("tls");
    let echoed = roundtrip(&skip_verify_node()).await.unwrap();
    assert_eq!(&echoed, b"ping");
}

#[tokio::test]
async fn interop_chrome_mode_with_ech_grease() {
    crate::tls::set_tls_mode("utls");
    let echoed = roundtrip(&skip_verify_node()).await.unwrap();
    assert_eq!(&echoed, b"ping");
}

/// Real ECH over QUIC: a server that cannot accept ECH must fail the
/// handshake (fail-closed, RFC anti-downgrade) — which also proves the
/// ECH extension really reached the wire inside the QUIC ClientHello.
#[tokio::test]
async fn ech_over_quic_fails_closed_without_server_support() {
    static ECH_CONFIG_LIST: &[u8] = include_bytes!("../../../tests/fixtures/echconfiglist");
    crate::tls::set_tls_mode("utls");
    let mut node = skip_verify_node();
    let tls = node.tls_mut().unwrap();
    tls.ech_enabled = true;
    tls.ech_config = Some(base64::engine::general_purpose::STANDARD.encode(ECH_CONFIG_LIST));
    let err = roundtrip(&node)
        .await
        .expect_err("handshake must fail when the server cannot accept ECH");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("ech") || msg.contains("ECH") || msg.contains("crypto"),
        "unexpected error: {msg}"
    );
}

/// RFC 9001 Appendix A.1 test vectors for initial-secret derivation.
#[test]
fn rfc9001_a1_initial_key_vectors() {
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(&INITIAL_SALT_V1), &dcid);
    assert_eq!(
        hex(&initial_secret),
        "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
    );

    let mut client_secret = [0u8; 32];
    hkdf_expand_label_sha256(&initial_secret, "client in", &mut client_secret);
    assert_eq!(
        hex(&client_secret),
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
    );

    let secrets = TrafficSecrets {
        suite: TLS13_AES_128_GCM_SHA256,
        secret: client_secret.to_vec(),
    };
    let mut key = [0u8; 16];
    secrets.expand_label("quic key", &mut key);
    assert_eq!(hex(&key), "1f369613dd76d5467730efcbe3b1a22d");
    let mut iv = [0u8; 12];
    secrets.expand_label("quic iv", &mut iv);
    assert_eq!(hex(&iv), "fa044b2f42a3fd3b46fb255c");
    let mut hp = [0u8; 16];
    secrets.expand_label("quic hp", &mut hp);
    assert_eq!(hex(&hp), "9f50449e04a0e810283a1e9933adedd2");
}

/// RFC 9001 Appendix A.2: full Client Initial packet protection vector.
#[test]
fn rfc9001_a2_client_initial_packet() {
    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    let secrets = TrafficSecrets {
        suite: TLS13_AES_128_GCM_SHA256,
        secret: unhex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
    };
    let header = unhex("c300000001088394c8f03e5157080000449e00000002");
    let mut payload = unhex(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868\
             04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578\
             616d706c652e636f6dff01000100000a00080006001d00170018001000070005\
             04616c706e000500050100000000003300260024001d00209370b2c9caa47fba\
             baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400\
             0d0010000e0403050306030203080408050806002d00020101001c0002400100\
             3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000\
             75300901100f088394c8f03e51570806048000ffff",
    );
    payload.resize(1162, 0);
    let mut buf = [header, payload].concat();

    let pkt = BoringPacketKey::new(&secrets).unwrap();
    pkt.encrypt(2, &mut buf, 22);
    // First 16 bytes of the protected payload are the HP sample.
    assert_eq!(&buf[22..38], &unhex("d1b1c98dd7689fb8ec11d242b123dc9b")[..]);

    let hk = BoringHeaderKey::new(&secrets).unwrap();
    hk.encrypt(18, &mut buf);
    assert_eq!(buf[0], 0xc0, "long-header first byte");
    assert_eq!(&buf[18..22], &unhex("7b9aec34")[..], "masked packet number");
}

/// AEAD round-trip across payload sizes: catches backend miscompiles
/// that only manifest on longer GHASH/assembly paths (a musl/zig-built
/// BoringSSL failed open() on 1280B packets while small ones passed).
#[test]
fn aes_gcm_payload_size_gradient() {
    let secrets = TrafficSecrets {
        suite: TLS13_AES_128_GCM_SHA256,
        secret: vec![7u8; 32],
    };
    let pkt = BoringPacketKey::new(&secrets).unwrap();
    for size in [64usize, 256, 512, 1000, 1100, 1150, 1200, 1280, 1452, 4096] {
        let header = b"hdr".to_vec();
        let payload = vec![0xabu8; size];
        // PacketKey::encrypt expects the tag space (16 bytes) to be
        // already present at the end of `buf`.
        let mut buf = [header.clone(), payload.clone(), vec![0u8; 16]].concat();
        pkt.encrypt(42, &mut buf, header.len());
        let mut protected = bytes::BytesMut::from(&buf[header.len()..]);
        pkt.decrypt(42, &buf[..header.len()], &mut protected)
            .unwrap_or_else(|_| panic!("decrypt failed at size {size}"));
        assert_eq!(&protected[..], &payload[..], "mismatch at size {size}");
    }
}

/// Cross-implementation check: encrypt with rustls initial keys, decrypt
/// with ours (and vice versa). Any key-derivation or AEAD-usage
/// divergence from rustls shows up here before live interop is attempted.
#[test]
fn cross_impl_initial_keys_match_rustls() {
    // TransportParameters has no public constructor; an empty extension
    // parses to defaults (only initial keys matter here anyway).
    let params = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();

    // rustls client session (only initial keys are used).
    let mut rustls_cfg = tokio_rustls::rustls::ClientConfig::builder_with_provider(
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
    .with_no_client_auth();
    rustls_cfg.alpn_protocols = vec![b"h3".to_vec()];
    let rustls_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
        .expect("rustls QUIC client config");
    let rustls_session =
        crypto::ClientConfig::start_session(Arc::new(rustls_crypto), 1, "localhost", &params)
            .unwrap();

    let my_cfg = Arc::new(
        BoringQuicClientConfig::new(BoringQuicOptions {
            alpn_wire: b"\x02h3".to_vec(),
            skip_cert_verify: true,
            ..Default::default()
        })
        .unwrap(),
    );
    let my_session = crypto::ClientConfig::start_session(my_cfg, 1, "localhost", &params).unwrap();

    let dcid = ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
    // QUIC initial keys are directional: the client encrypts with the
    // client secret, the server decrypts with the same secret (its
    // "remote" key). Cross-checks must pair client.local with
    // server.remote, never client.local with client.remote.
    let rustls_client = rustls_session.initial_keys(&dcid, Side::Client);
    let rustls_server = rustls_session.initial_keys(&dcid, Side::Server);
    let my_client = my_session.initial_keys(&dcid, Side::Client);
    let my_server = my_session.initial_keys(&dcid, Side::Server);

    // Packet protection: self-consistency, then cross-implementation.
    for (name, enc, dec) in [
        (
            "boring->boring",
            &my_client.packet.local,
            &my_server.packet.remote,
        ),
        (
            "rustls->rustls",
            &rustls_client.packet.local,
            &rustls_server.packet.remote,
        ),
        (
            "boring->rustls",
            &my_client.packet.local,
            &rustls_server.packet.remote,
        ),
        (
            "rustls->boring",
            &rustls_client.packet.local,
            &my_server.packet.remote,
        ),
    ] {
        let header = *b"\xc3\x00\x00\x00\x01\x08dciddddd\x00\x00\x44\x9e\x00\x00\x00\x02";
        let mut buf = header.to_vec();
        buf.extend_from_slice(b"payload-payload-payload");
        buf.resize(buf.len() + 16, 0);
        enc.encrypt(2, &mut buf, header.len());
        let mut payload = BytesMut::from(&buf[header.len()..]);
        dec.decrypt(2, &buf[..header.len()], &mut payload)
            .unwrap_or_else(|_| panic!("{name}: cross decrypt failed"));
        assert_eq!(&payload[..], b"payload-payload-payload", "{name}");
    }

    // Header protection: client.local masks, server.remote unmasks.
    for (name, enc, dec) in [
        (
            "rustls->boring",
            &rustls_client.header.local,
            &my_server.header.remote,
        ),
        (
            "boring->rustls",
            &my_client.header.local,
            &rustls_server.header.remote,
        ),
    ] {
        let mut buf = vec![0xabu8; 64];
        buf[0] = 0xc3;
        let original = buf.clone();
        enc.encrypt(18, &mut buf);
        dec.decrypt(18, &mut buf);
        assert_eq!(buf, original, "{name} HP roundtrip");
    }
}

use base64::Engine as _;

/// QUIC ECH: `start_session` with a static ECH config must not panic.
/// `set_ech_config_list` panics on invalid input, so reaching here proves
/// the ECH config is actually passed to BoringSSL (not dead code).
#[test]
fn quic_ech_static_config_reaches_ssl() {
    static ECH_CONFIG_LIST: &[u8] = include_bytes!("../../../tests/fixtures/echconfiglist");

    let params = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();
    let cfg = Arc::new(
        BoringQuicClientConfig::new(BoringQuicOptions {
            alpn_wire: b"\x02h3".to_vec(),
            skip_cert_verify: true,
            ech: Some(crate::ech_doh::Ech::Static(ECH_CONFIG_LIST.into())),
            ..Default::default()
        })
        .unwrap(),
    );
    // Would panic with "invalid ECHConfigList" if the config were not applied.
    let _session =
        crypto::ClientConfig::start_session(cfg, 0x0000_0001, "localhost", &params).unwrap();
}

/// QUIC ECH: `start_session` with a dynamic source reads the per-connection
/// cache. A published config must be picked up without rebuilding the
/// client config (the key-rotation path).
#[test]
fn quic_ech_dynamic_source_reads_cache_per_connection() {
    static ECH_CONFIG_LIST: &[u8] = include_bytes!("../../../tests/fixtures/echconfiglist");

    let source = crate::ech_doh::EchSource::Discover("quic-ech-test.invalid".to_string());
    crate::ech_doh::publish_ech_config(&source, ECH_CONFIG_LIST.to_vec());

    let params = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();
    let cfg = Arc::new(
        BoringQuicClientConfig::new(BoringQuicOptions {
            alpn_wire: b"\x02h3".to_vec(),
            skip_cert_verify: true,
            ech: Some(crate::ech_doh::Ech::Source(source.clone())),
            ..Default::default()
        })
        .unwrap(),
    );
    // Cache hit: the published config is offered without panic.
    let _session =
        crypto::ClientConfig::start_session(cfg.clone(), 0x0000_0001, "localhost", &params)
            .unwrap();

    // A second connection on the same client config re-reads the cache;
    // rotation reaches it without a rebuild.
    let _session2 =
        crypto::ClientConfig::start_session(cfg, 0x0000_0001, "localhost", &params).unwrap();
}

/// QUIC ECH negative: an invalid ECH config list must panic in
/// `start_session`. If the ECH code were dead/removed, this would not
/// panic — proving the config actually reaches BoringSSL.
#[test]
#[should_panic(expected = "invalid ECHConfigList")]
fn quic_ech_invalid_config_panics() {
    let params = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();
    let cfg = Arc::new(
        BoringQuicClientConfig::new(BoringQuicOptions {
            alpn_wire: b"\x02h3".to_vec(),
            skip_cert_verify: true,
            ech: Some(crate::ech_doh::Ech::Static(vec![0x42; 32].into())),
            ..Default::default()
        })
        .unwrap(),
    );
    let _ = crypto::ClientConfig::start_session(cfg, 0x0000_0001, "localhost", &params);
}
