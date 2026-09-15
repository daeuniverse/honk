use boring::pkey::PKey;
use boring::ssl::{AlpnError, ExtensionType, SslAcceptor, SslMethod};
use boring::x509::X509;
use honk_config::ConfigError;
use honk_config::node::{Node, OutboundConfig, StreamTransportOptions, TlsOptions, TrojanConfig};
use parking_lot::Mutex;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

const SERVER_ALPN: &[u8] = b"\x02h2\x08http/1.1\x04acme\x04x\x02h2";
const ALPS_OLD_CODEPOINT: u16 = 0x4469;

static TLS_MODE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Default)]
struct ObservedHello {
    alpn: Option<Vec<u8>>,
    alps: Option<Vec<u8>>,
}

struct ObservedHandshake {
    hello: ObservedHello,
    selected: Option<Vec<u8>>,
}

fn server_cert() -> (String, String) {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn server_acceptor(cert: &str, key: &str) -> (SslAcceptor, Arc<Mutex<ObservedHello>>) {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_pem(cert.as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_pem(key.as_bytes()).unwrap())
        .unwrap();
    let hello = Arc::new(Mutex::new(ObservedHello::default()));
    let capture = Arc::clone(&hello);
    acceptor.set_select_certificate_callback(move |client_hello| {
        let mut observed = capture.lock();
        observed.alpn = client_hello
            .get_extension(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
            .map(<[u8]>::to_vec);
        observed.alps = client_hello
            .get_extension(ExtensionType::from(ALPS_OLD_CODEPOINT))
            .map(<[u8]>::to_vec);
        Ok(())
    });
    acceptor.set_alpn_select_callback(|_, client| {
        boring::ssl::select_next_proto(SERVER_ALPN, client).ok_or(AlpnError::NOACK)
    });
    (acceptor.build(), hello)
}

fn spawn_server(cert: &str, key: &str) -> (u16, JoinHandle<ObservedHandshake>) {
    let (acceptor, hello) = server_acceptor(cert, key);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let tls = acceptor.accept(tcp).unwrap();
        ObservedHandshake {
            selected: tls.ssl().selected_alpn_protocol().map(<[u8]>::to_vec),
            hello: std::mem::take(&mut *hello.lock()),
        }
    });
    (port, server)
}

fn node(transport: &str, alpn: &[&str]) -> Node {
    Node {
        outbound: OutboundConfig::Trojan(TrojanConfig {
            transport: StreamTransportOptions {
                transport: transport.into(),
                ..Default::default()
            },
            tls: TlsOptions {
                enabled: true,
                alpn: alpn.iter().map(|protocol| (*protocol).into()).collect(),
                skip_cert_verify: true,
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn observe(mode: &str, transport: &str, alpn: &[&str]) -> ObservedHandshake {
    let (cert, key) = server_cert();
    let (port, server) = spawn_server(&cert, &key);
    honk_outbound::tls::set_tls_mode(mode);
    let connector = honk_outbound::tls::build_connector(&node(transport, alpn)).unwrap();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    drop(connector.connect("localhost", tcp).await.unwrap());
    server.join().unwrap()
}

#[tokio::test]
async fn connector_applies_explicit_alpn_and_preserves_profile_defaults() {
    let _mode_lock = TLS_MODE_LOCK.lock().await;
    let oversized = "x".repeat(256);
    let error =
        honk_outbound::tls::build_connector(&node("tcp", &[oversized.as_str()])).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<ConfigError>(),
        Some(ConfigError::Validation(_))
    ));

    let standard_default = observe("tls", "tcp", &[]).await;
    assert_eq!(standard_default.hello.alpn, None);
    assert_eq!(standard_default.hello.alps, None);
    assert_eq!(standard_default.selected, None);

    let standard_custom = observe("tls", "tcp", &["acme"]).await;
    assert_eq!(
        standard_custom.hello.alpn.as_deref(),
        Some(b"\0\x05\x04acme".as_slice())
    );
    assert_eq!(standard_custom.hello.alps, None);
    assert_eq!(
        standard_custom.selected.as_deref(),
        Some(b"acme".as_slice())
    );

    let chrome_h2 = observe("utls", "tcp", &["h2"]).await;
    assert_eq!(
        chrome_h2.hello.alpn.as_deref(),
        Some(b"\0\x03\x02h2".as_slice())
    );
    assert_eq!(
        chrome_h2.hello.alps.as_deref(),
        Some(b"\0\x03\x02h2".as_slice())
    );
    assert_eq!(chrome_h2.selected.as_deref(), Some(b"h2".as_slice()));

    let chrome_http1 = observe("utls", "tcp", &["http/1.1"]).await;
    assert_eq!(
        chrome_http1.hello.alpn.as_deref(),
        Some(b"\0\x09\x08http/1.1".as_slice())
    );
    assert_eq!(chrome_http1.hello.alps, None);
    assert_eq!(
        chrome_http1.selected.as_deref(),
        Some(b"http/1.1".as_slice())
    );

    let chrome_h2ish = observe("utls", "tcp", &["x\u{2}h2"]).await;
    assert_eq!(
        chrome_h2ish.hello.alpn.as_deref(),
        Some(b"\0\x05\x04x\x02h2".as_slice())
    );
    assert_eq!(chrome_h2ish.hello.alps, None);
    assert_eq!(
        chrome_h2ish.selected.as_deref(),
        Some(b"x\x02h2".as_slice())
    );

    let chrome_default = observe("utls", "tcp", &[]).await;
    assert_eq!(
        chrome_default.hello.alpn.as_deref(),
        Some(b"\0\x0c\x02h2\x08http/1.1".as_slice())
    );
    assert_eq!(
        chrome_default.hello.alps.as_deref(),
        Some(b"\0\x03\x02h2".as_slice())
    );
    assert_eq!(chrome_default.selected.as_deref(), Some(b"h2".as_slice()));

    let chrome_websocket = observe("utls", "ws", &[]).await;
    assert_eq!(
        chrome_websocket.hello.alpn.as_deref(),
        Some(b"\0\x09\x08http/1.1".as_slice())
    );
    assert_eq!(chrome_websocket.hello.alps, None);
    assert_eq!(
        chrome_websocket.selected.as_deref(),
        Some(b"http/1.1".as_slice())
    );
}

#[tokio::test]
async fn trojan_grpc_tls_negotiates_h2_and_exchanges_payload() {
    use honk_outbound::proxy::{TcpOutbound, trojan::TrojanHandler};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _mode_lock = TLS_MODE_LOCK.lock().await;
    for mode in ["tls", "utls"] {
        for bare in [false, true] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let (cert, key) = server_cert();
                let (acceptor, hello) = server_acceptor(&cert, &key);
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let tls = tokio_boring::accept(&acceptor, tcp).await.unwrap();
                    assert_eq!(tls.ssl().selected_alpn_protocol(), Some(b"h2".as_slice()));
                    {
                        let hello = hello.lock();
                        assert_eq!(hello.alpn.as_deref(), Some(b"\0\x03\x02h2".as_slice()));
                        assert_eq!(
                            hello.alps.as_deref(),
                            (mode == "utls").then_some(b"\0\x03\x02h2".as_slice())
                        );
                    }
                    let mut connection = h2::server::handshake(tls).await.unwrap();
                    let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                    assert_eq!(request.method(), http::Method::POST);
                    assert_eq!(request.uri().scheme_str(), Some("https"));
                    assert_eq!(request.uri().path(), "/GunService/Tun");
                    assert_eq!(request.headers()["content-type"], "application/grpc");
                    let driver = tokio::spawn(async move {
                        while connection.accept().await.is_some() {}
                    });
                    // Empty-password Trojan CONNECT to 1.2.3.4:53, then a second gRPC message.
                    let expected = b"\0\0\0\0\x46\x0a\x44d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f\r\n\x01\x01\x01\x02\x03\x04\0\x35\r\n\0\0\0\0\x06\x0a\x04ping";
                    let mut body = request.into_body();
                    let mut received = Vec::new();
                    while received.len() < expected.len() {
                        let data = body.data().await.unwrap().unwrap();
                        received.extend_from_slice(&data);
                        body.flow_control().release_capacity(data.len()).unwrap();
                    }
                    assert_eq!(received, expected);
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut response = respond.send_response(response, false).unwrap();
                    response
                        .send_data(bytes::Bytes::from_static(b"\0\0\0\0\x06\x0a\x04pong"), true)
                        .unwrap();
                    drop(response);
                    drop(body);
                    driver.await.unwrap();
                });

                honk_outbound::tls::set_tls_mode(mode);
                let mut node = node("grpc", &[]);
                node.host = "127.0.0.1".into();
                node.port = address.port();
                node.tls_mut().unwrap().sni = Some("localhost".into());
                let target = "1.2.3.4:53".parse().unwrap();
                let handler = TrojanHandler::new();
                let mut stream = if bare {
                    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
                    handler.dial_with_tcp(&node, target, None, tcp, Duration::from_secs(5)).await
                } else {
                    handler.dial(&node, target, None, Duration::from_secs(5)).await
                }
                .unwrap();
                stream.stream.write_all(b"ping").await.unwrap();
                stream.stream.flush().await.unwrap();
                let mut reply = [0; 4];
                stream.stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"pong");
                drop(stream);
                server.await.unwrap();
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn direct_tcp_dial_rejects_ignored_alpn() {
    use honk_outbound::proxy::{TcpOutbound, trojan::TrojanHandler};
    use tokio::io::AsyncReadExt;

    let mut disabled = node("tcp", &["h2"]);
    disabled.tls_mut().unwrap().enabled = false;
    let mut reality = node("tcp", &["h2"]);
    reality.tls_mut().unwrap().reality_public_key =
        Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into());
    for node in [disabled, reality, node("grpc", &["h2"])] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tcp, peer) = tokio::join!(tokio::net::TcpStream::connect(address), listener.accept());
        let (mut peer, _) = peer.unwrap();
        let deadline = std::time::Duration::from_secs(1);
        let error = tokio::time::timeout(
            deadline,
            TrojanHandler::new().dial_with_tcp(&node, address, None, tcp.unwrap(), deadline),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ConfigError>(),
            Some(ConfigError::Validation(_))
        ));
        let received = tokio::time::timeout(deadline, peer.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            received, 0,
            "rejected configuration must send no proxy or TLS bytes"
        );
    }
}

#[tokio::test]
async fn direct_quic_config_rejects_tcp_alpn() {
    let mut quic_node = Node::from_share_link("hy2://secret@example.com:443").unwrap();
    quic_node.tls_mut().unwrap().alpn = vec!["h2".into()];
    for node in [quic_node, node("tcp", &["h2"])] {
        let error = honk_outbound::quic::client_config(&node, &[b"h3"], Default::default())
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ConfigError>(),
            Some(ConfigError::Validation(_))
        ));
    }
}
