use super::*;
use boring::pkey::PKey;

#[test]
fn root_store_clones_share_one_store() {
    use foreign_types::ForeignType;
    let a = root_store().unwrap();
    let b = root_store().unwrap();
    assert_eq!(a.as_ptr(), b.as_ptr());
}
use boring::ssl::{SslAcceptor, SslStream};
use std::io::Read;
use std::net::TcpListener;
use std::thread;

/// rcgen self-signed server cert (PEM) for loopback handshakes.
fn server_cert() -> (String, String) {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn spawn_server(cert_pem: &str, key_pem: &str) -> (u16, thread::JoinHandle<Vec<u8>>) {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
        .unwrap();
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut tls: SslStream<_> = acceptor.accept(stream).unwrap();
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).ok();
        buf
    });
    (port, handle)
}

async fn loopback_connect(
    node: &Node,
    chrome: bool,
    port: u16,
) -> anyhow::Result<TlsStream<tokio::net::TcpStream>> {
    set_tls_mode(if chrome { "utls" } else { "tls" });
    let connector = build_connector(node)?;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    connector.connect("localhost", tcp).await
}

fn test_node() -> Node {
    Node {
        outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            tls: honk_config::node::TlsOptions {
                skip_cert_verify: true,
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn handshake_standard_and_chrome() {
    for chrome in [false, true] {
        let (cert, key) = server_cert();
        let (port, server) = spawn_server(&cert, &key);
        let mut stream = loopback_connect(&test_node(), chrome, port)
            .await
            .unwrap_or_else(|e| panic!("chrome={chrome}: {e:?}"));
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();
        let received = server.join().unwrap();
        assert_eq!(received, b"ping", "chrome={chrome}");
    }
}

#[tokio::test]
async fn xhttp_tls_rejects_missing_h2_but_raw_tls_preserves_no_alpn() {
    use crate::proxy::transport::{MaybeTls, maybe_tls_wrap_concrete};
    use std::time::Duration;

    tokio::time::timeout(Duration::from_secs(5), async {
        for xhttp in [false, true] {
            let (cert, key) = server_cert();
            let (port, server) = spawn_server(&cert, &key);
            let mut node = test_node();
            let tls = node.tls_mut().unwrap();
            tls.enabled = true;
            tls.sni = Some("localhost".into());
            if xhttp {
                tls.alpn = vec!["h2".into()];
                let transport = node.transport_mut().unwrap();
                transport.transport = "xhttp".into();
                transport.xhttp = Some(Default::default());
            }
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let result = maybe_tls_wrap_concrete(&node, Some(tcp), Duration::from_secs(1)).await;
            if xhttp {
                let Err(error) = result else {
                    panic!("XHTTP accepted TLS without negotiated h2");
                };
                assert!(
                    error
                        .to_string()
                        .contains("XHTTP requires negotiated h2 ALPN")
                );
            } else {
                let MaybeTls::Tls(tls) = result.unwrap() else {
                    panic!("enabled TLS returned plaintext");
                };
                assert_eq!(tls.ssl().selected_alpn_protocol(), None);
                drop(tls);
            }
            assert!(server.join().unwrap().is_empty());
        }
    })
    .await
    .unwrap();
}

/// Spawn a server holding real ECH keys (boring test fixtures:
/// public_name ech.com, DHKEM-P256-SHA256).
fn spawn_ech_server(cert_pem: &str, key_pem: &str) -> (u16, thread::JoinHandle<Vec<u8>>) {
    use boring::hpke::HpkeKey;
    use boring::ssl::SslEchKeys;

    static ECH_CONFIG: &[u8] = include_bytes!("../../tests/fixtures/echconfig");
    static ECH_KEY: &[u8] = include_bytes!("../../tests/fixtures/echkey");

    // NB: boring's mozilla_intermediate/_modern set NO_TLSV1_3; ECH needs
    // TLS 1.3, so use the v5 profile (1.2+1.3) and pin 1.3.
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
        .unwrap();

    let key = HpkeKey::dhkem_p256_sha256(ECH_KEY).unwrap();
    let mut ech_keys = SslEchKeys::builder().unwrap();
    ech_keys.add_key(true, ECH_CONFIG, key).unwrap();
    acceptor.set_ech_keys(&ech_keys.build()).unwrap();

    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    acceptor
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();

    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut tls: SslStream<_> = acceptor.accept(stream).unwrap();
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).ok();
        buf
    });
    (port, handle)
}

/// Full ECH round-trip: client offers real ECH, server decrypts it,
/// `ech_accepted()` must report true.
#[tokio::test]
async fn ech_accepted_end_to_end() {
    static ECH_CONFIG_LIST: &[u8] = include_bytes!("../../tests/fixtures/echconfiglist");
    let mut node = test_node();
    let tls = node.tls_mut().unwrap();
    tls.ech_enabled = true;
    tls.ech_config = Some(general_purpose::STANDARD.encode(ECH_CONFIG_LIST));
    let (cert, key) = server_cert();
    let (port, server) = spawn_ech_server(&cert, &key);
    let mut stream = loopback_connect(&node, true, port).await.unwrap();
    assert!(stream.ssl().ech_accepted(), "ECH must be accepted");
    use tokio::io::AsyncWriteExt;
    stream.write_all(b"ok").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(server.join().unwrap(), b"ok");
}

/// Real ECH against a server with NO ECH keys fails closed
/// (`ECH_REJECTED`): BoringSSL refuses to complete a handshake whose ECH
/// offer was not confirmed, per RFC anti-downgrade rules. Proves the
/// config list is actually parsed and offered.
#[tokio::test]
async fn ech_rejected_when_server_lacks_keys() {
    static ECH_CONFIG_LIST: &[u8] = include_bytes!("../../tests/fixtures/echconfiglist");
    let mut node = test_node();
    let tls = node.tls_mut().unwrap();
    tls.ech_enabled = true;
    tls.ech_config = Some(general_purpose::STANDARD.encode(ECH_CONFIG_LIST));
    let (cert, key) = server_cert();
    let (port, _server) = spawn_server(&cert, &key);
    let err = loopback_connect(&node, true, port)
        .await
        .expect_err("handshake must fail when ECH is not accepted");
    let msg = format!("{err:?}");
    assert!(msg.contains("ECH_REJECTED"), "unexpected error: {msg}");
}

/// The urltest probe connector offers `h2,http/1.1` and honors the
/// server's pick in both directions (the probe handles either).
#[tokio::test]
async fn probe_connector_negotiates_h2_and_http1() {
    use boring::ssl::AlpnError;

    fn spawn_alpn_server(cert_pem: &str, key_pem: &str, prefer_h2: bool) -> u16 {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
            .unwrap();
        acceptor
            .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
            .unwrap();
        acceptor.set_alpn_select_callback(move |_ssl, protos| {
            let mut i = 0;
            let (mut h2, mut http11) = (None, None);
            while i < protos.len() {
                let n = protos[i] as usize;
                let p = &protos[i + 1..i + 1 + n];
                if p == b"h2" {
                    h2 = Some(p);
                }
                if p == b"http/1.1" {
                    http11 = Some(p);
                }
                i += 1 + n;
            }
            if prefer_h2 {
                h2.or(http11).ok_or(AlpnError::NOACK)
            } else {
                // h1-only server: refuses anything else.
                http11.ok_or(AlpnError::NOACK)
            }
        });
        let acceptor = acceptor.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut tls: SslStream<_> = acceptor.accept(stream).unwrap();
            let mut buf = Vec::new();
            tls.read_to_end(&mut buf).ok();
            buf
        });
        port
    }

    for chrome in [false, true] {
        set_tls_mode(if chrome { "utls" } else { "tls" });

        // h2-preferring server: probe must negotiate h2.
        let (cert, key) = server_cert();
        let port = spawn_alpn_server(&cert, &key, true);
        let connector = build_http_probe_connector(true).unwrap();
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let stream = connector.connect("localhost", tcp).await.unwrap();
        assert_eq!(
            stream.ssl().selected_alpn_protocol(),
            Some(b"h2".as_slice()),
            "chrome={chrome}: probe must take h2 when the server prefers it"
        );

        // h1-only server: probe must fall back to http/1.1.
        let (cert, key) = server_cert();
        let port = spawn_alpn_server(&cert, &key, false);
        let connector = build_http_probe_connector(true).unwrap();
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let stream = connector.connect("localhost", tcp).await.unwrap();
        assert_eq!(
            stream.ssl().selected_alpn_protocol(),
            Some(b"http/1.1".as_slice()),
            "chrome={chrome}: probe must fall back to http/1.1"
        );
    }
}

#[test]
fn decode_ech_base64_variants() {
    let raw = b"\xff\x00abc";
    for encoded in [
        general_purpose::STANDARD.encode(raw),
        general_purpose::URL_SAFE.encode(raw),
        general_purpose::URL_SAFE_NO_PAD.encode(raw),
    ] {
        assert_eq!(decode_ech_config_list(&encoded).unwrap(), raw);
    }
    assert!(decode_ech_config_list("!!!not-base64!!!").is_err());
}

/// DNS response with one HTTPS answer carrying the given ech SvcParam
/// (`None` → NODATA), for the discovery stub server.
fn https_response(query: &[u8], ech: Option<&[u8]>, ttl: u32) -> Vec<u8> {
    let mut resp = query.to_vec();
    resp[2] = 0x81;
    resp[3] = 0x80;
    let Some(ech) = ech else {
        resp[6] = 0;
        resp[7] = 0;
        return resp;
    };
    resp[6] = 0;
    resp[7] = 1;
    resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer to question
    resp.extend_from_slice(&65u16.to_be_bytes()); // TYPE HTTPS
    resp.extend_from_slice(&1u16.to_be_bytes()); // IN
    resp.extend_from_slice(&ttl.to_be_bytes());
    let mut rdata = vec![0, 1, 0]; // ServiceMode priority 1, root target name
    rdata.extend_from_slice(&5u16.to_be_bytes()); // SvcParam key ech
    rdata.extend_from_slice(&(ech.len() as u16).to_be_bytes());
    rdata.extend_from_slice(ech);
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);
    resp
}

/// Stub UDP DNS server answering every query with the canned HTTPS
/// response, counting queries. Installed via the bootstrap resolver.
async fn spawn_https_dns(
    ech: Option<Vec<u8>>,
    ttl: u32,
) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::AtomicUsize;
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count2 = count.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok((n, peer)) = server.recv_from(&mut buf).await {
            count2.fetch_add(1, Ordering::SeqCst);
            let resp = https_response(&buf[..n], ech.as_deref(), ttl);
            server.send_to(&resp, peer).await.ok();
        }
    });
    (addr, count)
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn discover_ech_config_caches_positive_and_negative() {
    use std::sync::atomic::Ordering as AOrd;
    let _lock = crate::bootstrap::GLOBAL_TEST_LOCK.lock().unwrap();

    // Positive: two lookups for the same name cost one DNS query.
    let (addr, count) = spawn_https_dns(Some(b"\x00\x01ech-bytes".to_vec()), 120).await;
    crate::bootstrap::set_global(crate::bootstrap::BootstrapResolver::parse(&format!(
        "udp://{addr}"
    )));
    let first = discover_ech_config("ech-pos-unique.test").await;
    let second = discover_ech_config("ech-pos-unique.test").await;
    assert_eq!(first.as_deref(), Some(b"\x00\x01ech-bytes".as_slice()));
    assert_eq!(second, first);
    assert_eq!(count.load(AOrd::SeqCst), 1, "second lookup must hit cache");

    // Negative: NODATA is cached too.
    let (addr, count) = spawn_https_dns(None, 120).await;
    crate::bootstrap::set_global(crate::bootstrap::BootstrapResolver::parse(&format!(
        "udp://{addr}"
    )));
    assert_eq!(discover_ech_config("ech-neg-unique.test").await, None);
    assert_eq!(discover_ech_config("ech-neg-unique.test").await, None);
    assert_eq!(
        count.load(AOrd::SeqCst),
        1,
        "negative lookup must hit cache"
    );

    // IP literals never query.
    assert_eq!(discover_ech_config("203.0.113.7").await, None);
    crate::bootstrap::set_global(None);
}

/// End-to-end: `ech_enabled` with no static config discovers the
/// ECHConfigList via DNS and completes a real ECH handshake.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn ech_discovery_end_to_end() {
    static ECH_CONFIG_LIST: &[u8] = include_bytes!("../../tests/fixtures/echconfiglist");
    let _lock = crate::bootstrap::GLOBAL_TEST_LOCK.lock().unwrap();

    let (addr, _count) = spawn_https_dns(Some(ECH_CONFIG_LIST.to_vec()), 300).await;
    crate::bootstrap::set_global(crate::bootstrap::BootstrapResolver::parse(&format!(
        "udp://{addr}"
    )));
    let mut node = test_node();
    node.tls_mut().unwrap().ech_enabled = true;
    let (cert, key) = server_cert();
    let (port, server) = spawn_ech_server(&cert, &key);
    let mut stream = loopback_connect(&node, true, port).await.unwrap();
    assert!(
        stream.ssl().ech_accepted(),
        "ECH via DNS discovery must be accepted"
    );
    use tokio::io::AsyncWriteExt;
    stream.write_all(b"ok").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(server.join().unwrap(), b"ok");
    crate::bootstrap::set_global(None);
}
