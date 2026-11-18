use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslMethod, SslVersion};
use boring::x509::X509;
use honk_config::node::{Node, OutboundConfig, TlsOptions, TrojanConfig};
use honk_config::types::NodeProtocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::wrap_tunnel;
use crate::proxy::{ProxyStream, TcpOutbound, TunnelDialOptions, tunnel_unsupported};

const TIMEOUT: Duration = Duration::from_secs(5);

fn tls_node(tls: TlsOptions) -> Node {
    Node {
        name: "tunnel-node".into(),
        address: "198.51.100.1:443".into(),
        // A tunneled hop must not resolve its own server address.
        host: "must-not-resolve.invalid".into(),
        port: 443,
        outbound: OutboundConfig::Trojan(TrojanConfig {
            password: Some("secret".into()),
            tls,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn skip_verify_tls() -> TlsOptions {
    TlsOptions {
        enabled: true,
        sni: Some("localhost".into()),
        skip_cert_verify: true,
        ..Default::default()
    }
}

fn acceptor() -> SslAcceptor {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    acceptor
        .set_certificate(&X509::from_der(cert.der()).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_der(&key.serialize_der()).unwrap())
        .unwrap();
    acceptor.build()
}

async fn ping_pong(stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin)) {
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = [0; 4];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"pong");
}

async fn answer_ping(stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin)) {
    let mut request = [0; 4];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    stream.write_all(b"pong").await.unwrap();
    stream.flush().await.unwrap();
}

async fn tls_server(stream: DuplexStream) -> tokio_boring::SslStream<DuplexStream> {
    tokio_boring::accept(&acceptor(), stream).await.unwrap()
}

#[tokio::test]
async fn tls_runs_over_a_tunneled_carrier() {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut tls = tls_server(server).await;
        answer_ping(&mut tls).await;
    });

    let node = tls_node(skip_verify_tls());
    let mut stream = tokio::time::timeout(
        TIMEOUT,
        wrap_tunnel(&node, Box::new(client), TunnelDialOptions::new(TIMEOUT)),
    )
    .await
    .unwrap()
    .unwrap();
    ping_pong(&mut stream).await;
    server.await.unwrap();
}

#[tokio::test]
async fn websocket_runs_over_tls_on_a_tunneled_carrier() {
    use futures_util::{SinkExt, StreamExt};

    let (client, server) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let tls = tls_server(server).await;
        let mut ws = tokio_tungstenite::accept_async(tls).await.unwrap();
        let message = ws.next().await.unwrap().unwrap();
        assert_eq!(&message.into_data()[..], b"ping");
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            b"pong".to_vec().into(),
        ))
        .await
        .unwrap();
    });

    let mut node = tls_node(skip_verify_tls());
    let transport = node.transport_mut().unwrap();
    transport.transport = "ws".into();
    transport.ws_path = Some("/tunnel".into());
    let mut stream = tokio::time::timeout(
        TIMEOUT,
        wrap_tunnel(&node, Box::new(client), TunnelDialOptions::new(TIMEOUT)),
    )
    .await
    .unwrap()
    .unwrap();
    ping_pong(&mut stream).await;
    server.await.unwrap();
}

#[tokio::test]
async fn reality_mask_certificate_error_keeps_its_type() {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut server = server;
        // An ordinary certificate fails REALITY authentication on the client.
        if let Ok(mut tls) = tokio_boring::accept(&acceptor(), &mut server).await {
            let _ = tls.read(&mut [0; 1]).await;
        }
    });

    let server_key = PKey::generate(boring::pkey::Id::X25519).unwrap();
    let mut public = [0; 32];
    server_key.raw_public_key(&mut public).unwrap();
    let node = tls_node(TlsOptions {
        enabled: true,
        sni: Some("localhost".into()),
        reality_public_key: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public)),
        reality_short_id: Some("1919191919191919".into()),
        ..Default::default()
    });
    let error = tokio::time::timeout(
        TIMEOUT,
        wrap_tunnel(&node, Box::new(client), TunnelDialOptions::new(TIMEOUT)),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        error.is::<crate::reality::RealityMaskCertificate>(),
        "{error:#}"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn xhttp_is_refused_over_a_tunneled_carrier() {
    let (client, _server) = tokio::io::duplex(1024);
    let mut node = tls_node(skip_verify_tls());
    node.transport_mut().unwrap().transport = "xhttp".into();
    let error = wrap_tunnel(&node, Box::new(client), TunnelDialOptions::new(TIMEOUT))
        .await
        .unwrap_err();
    assert!(tunnel_unsupported(&error), "{error:#}");
}

#[tokio::test]
async fn a_protocol_without_a_stream_transport_is_refused() {
    for protocol in [NodeProtocol::SS, NodeProtocol::Hysteria2] {
        let (client, _server) = tokio::io::duplex(1024);
        let node = Node {
            outbound: OutboundConfig::from_protocol(protocol),
            ..tls_node(skip_verify_tls())
        };
        let error = wrap_tunnel(&node, Box::new(client), TunnelDialOptions::new(TIMEOUT))
            .await
            .unwrap_err();
        assert!(tunnel_unsupported(&error), "{error:#}");
        assert_eq!(
            error.to_string(),
            format!("{} cannot run over a tunneled stream", protocol.as_str())
        );
    }
}

struct DialOnly;

#[async_trait::async_trait]
impl TcpOutbound for DialOnly {
    async fn dial(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        unreachable!("a tunneled dial must not fall back to a direct dial")
    }
}

#[tokio::test]
async fn default_dial_over_refuses_the_tunnel() {
    let (client, _server) = tokio::io::duplex(1024);
    let mut node = tls_node(skip_verify_tls());
    node.id = node.derive_id();
    let runtime: Arc<_> = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    let error = DialOnly
        .dial_over(
            runtime,
            Box::new(client),
            "192.0.2.1:443".parse().unwrap(),
            None,
            TunnelDialOptions::new(TIMEOUT),
        )
        .await
        .unwrap_err();
    assert!(tunnel_unsupported(&error), "{error:#}");
    assert_eq!(
        error.to_string(),
        "trojan cannot run over a tunneled stream"
    );
}
