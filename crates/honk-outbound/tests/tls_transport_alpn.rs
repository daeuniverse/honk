use boring::pkey::PKey;
use boring::ssl::{AlpnError, SslAcceptor, SslMethod, SslStream};
use boring::x509::X509;
use honk_config::node::Node;
use std::io::Read;
use std::net::TcpListener;
use tokio::io::AsyncWriteExt;

fn server_cert() -> (String, String) {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

#[tokio::test]
async fn chrome_websocket_connector_does_not_negotiate_h2() {
    let (cert, key) = server_cert();
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_pem(cert.as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_pem(key.as_bytes()).unwrap())
        .unwrap();
    acceptor.set_alpn_select_callback(|_, client| {
        boring::ssl::select_next_proto(b"\x02h2\x08http/1.1", client).ok_or(AlpnError::NOACK)
    });
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut tls: SslStream<_> = acceptor.accept(tcp).unwrap();
        let alpn = tls.ssl().selected_alpn_protocol().map(<[u8]>::to_vec);
        let mut request = Vec::new();
        tls.read_to_end(&mut request).unwrap();
        (alpn, request)
    });

    honk_outbound::tls::set_tls_mode("utls");
    let node = Node {
        transport: "ws".into(),
        skip_cert_verify: true,
        ..Default::default()
    };
    let connector = honk_outbound::tls::build_connector(&node).unwrap();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut tls = connector.connect("localhost", tcp).await.unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n")
        .await
        .unwrap();
    tls.shutdown().await.unwrap();

    let (alpn, request) = server.join().unwrap();
    assert_eq!(
        alpn.as_deref(),
        Some(b"http/1.1".as_slice()),
        "WebSocket's HTTP/1.1 upgrade must not follow an h2 negotiation"
    );
    assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
}
