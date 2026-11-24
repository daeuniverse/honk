use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslMethod, SslVersion};
use boring::x509::X509;
use honk_config::node::{Node, OutboundConfig, TlsOptions, TrojanConfig};
use honk_config::types::NodeProtocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::wrap_tunnel;
use crate::group::ScoreOutcome;
use crate::proxy::{
    ProxyStream, TcpOutbound, TunnelDialOptions, TunnelUnsupported, tunnel_unsupported,
};

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

async fn tls_server(stream: DuplexStream) -> tokio_boring::SslStream<DuplexStream> {
    tokio_boring::accept(&acceptor(), stream).await.unwrap()
}

#[tokio::test]
async fn tls_runs_over_a_tunneled_carrier() {
    // A literal IP gives ECH discovery no name to query, so it is allowed.
    let ech_with_sni = |sni: &str| TlsOptions {
        ech_enabled: true,
        sni: Some(sni.into()),
        ..skip_verify_tls()
    };
    for tls in [
        skip_verify_tls(),
        ech_with_sni("127.0.0.1"),
        ech_with_sni("[::1]"),
    ] {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut tls = tls_server(server).await;
            let mut request = [0; 4];
            tls.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
        });

        let node = tls_node(tls);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WsFailureSide {
    Read,
    Flush,
}

#[derive(Debug)]
struct FailingWsCarrier {
    inner: DuplexStream,
    side: WsFailureSide,
    failure: Option<(io::Error, tokio::sync::oneshot::Sender<()>)>,
    upgraded: Arc<AtomicBool>,
}

impl FailingWsCarrier {
    fn fail(&mut self) -> Option<io::Error> {
        let (error, receipt) = self.failure.take()?;
        let _ = receipt.send(());
        Some(error)
    }
}

impl tokio::io::AsyncRead for FailingWsCarrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if self.side == WsFailureSide::Read
            && matches!(result, Poll::Ready(Ok(())))
            && buf.remaining() != 0
            && buf.filled().len() == before
            && let Some(error) = self.fail()
        {
            return Poll::Ready(Err(error));
        }
        result
    }
}

impl tokio::io::AsyncWrite for FailingWsCarrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.side == WsFailureSide::Flush
            && self.upgraded.load(Relaxed)
            && let Some(error) = self.fail()
        {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn ws_relay_failure(side: WsFailureSide, failure: io::Error, expected: ScoreOutcome) {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    tokio::time::timeout(TIMEOUT, async {
        let kind = failure.kind();
        let mut node = tls_node(TlsOptions::default());
        node.transport_mut().unwrap().transport = "ws".into();
        let (client, peer) = tokio::io::duplex(256 * 1024);
        let upgraded = Arc::new(AtomicBool::new(false));
        let (receipt, failed) = tokio::sync::oneshot::channel();
        let carrier = FailingWsCarrier {
            inner: client,
            side,
            failure: Some((failure, receipt)),
            upgraded: Arc::clone(&upgraded),
        };
        let (stream, peer) = tokio::join!(
            wrap_tunnel(&node, Box::new(carrier), TunnelDialOptions::new(TIMEOUT)),
            tokio_tungstenite::accept_async(peer),
        );
        let mut stream = stream.unwrap();
        let mut peer = peer.unwrap();
        upgraded.store(true, Relaxed);

        let payload = match side {
            WsFailureSide::Read => bytes::Bytes::from_static(b"buffered reply"),
            // Larger than the relay pipe so part of this decoded frame is still
            // held by the relay when the upload fails.
            WsFailureSide::Flush => bytes::Bytes::from(vec![0x5a; 128 * 1024]),
        };
        peer.send(Message::Binary(payload.clone())).await.unwrap();
        let mut received = Vec::new();
        match side {
            WsFailureSide::Read => peer.get_mut().shutdown().await.unwrap(),
            WsFailureSide::Flush => {
                let mut first = [0];
                stream.read_exact(&mut first).await.unwrap();
                received.extend_from_slice(&first);
                stream.write_all(b"next request").await.unwrap();
            }
        }
        failed.await.unwrap();

        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        let error = stream.read_to_end(&mut received).await.unwrap_err();
        assert_eq!(received.as_slice(), payload.as_ref());
        assert_eq!(error.kind(), kind);
        assert_eq!(ScoreOutcome::from_io_error(&error), expected);
        for error in [
            stream.write(b"later").await.unwrap_err(),
            stream
                .write_vectored(&[io::IoSlice::new(b"later")])
                .await
                .unwrap_err(),
            stream.flush().await.unwrap_err(),
        ] {
            assert_eq!(error.kind(), kind);
            assert_eq!(ScoreOutcome::from_io_error(&error), expected);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn websocket_relay_retains_lower_failures_after_delivery() {
    use crate::proxy::error::IntermediateTargetFailure;
    use crate::proxy::{NodeFailure, PacketRejection, TargetFailure};

    for side in [WsFailureSide::Read, WsFailureSide::Flush] {
        let shared = crate::SharedError::fanout(TargetFailure(anyhow::anyhow!("refused")).into());
        let expected = ScoreOutcome::SharedNodeFailure(shared.episode().unwrap());
        let kind = io::ErrorKind::ConnectionRefused;
        let failure = IntermediateTargetFailure::io(1, io::Error::new(kind, shared));
        ws_relay_failure(side, failure, expected).await;
        ws_relay_failure(
            side,
            PacketRejection::Cancelled.into(),
            ScoreOutcome::Cancelled,
        )
        .await;
        let target = TargetFailure(anyhow::anyhow!("target refused"));
        let failure = io::Error::new(kind, target);
        ws_relay_failure(side, failure, ScoreOutcome::TargetFailure).await;
        let node = NodeFailure(anyhow::anyhow!("carrier closed"));
        let failure = io::Error::new(kind, node);
        ws_relay_failure(side, failure, ScoreOutcome::NodeFailure).await;
    }
}

#[tokio::test]
async fn websocket_relay_keeps_pong_and_graceful_close() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    tokio::time::timeout(TIMEOUT, async {
        let mut node = tls_node(TlsOptions::default());
        node.transport_mut().unwrap().transport = "ws".into();
        let (client, peer) = tokio::io::duplex(4096);
        let (stream, peer) = tokio::join!(
            wrap_tunnel(&node, Box::new(client), TunnelDialOptions::new(TIMEOUT)),
            tokio_tungstenite::accept_async(peer),
        );
        let mut stream = stream.unwrap();
        let mut peer = peer.unwrap();
        let ping = bytes::Bytes::from_static(b"still here");
        peer.send(Message::Ping(ping.clone())).await.unwrap();
        assert_eq!(peer.next().await.unwrap().unwrap(), Message::Pong(ping));
        peer.send(Message::Binary(bytes::Bytes::from_static(b"reply")))
            .await
            .unwrap();
        peer.send(Message::Close(None)).await.unwrap();
        assert_eq!(peer.next().await.unwrap().unwrap(), Message::Close(None));
        drop(peer);
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(&received, b"reply");
    })
    .await
    .unwrap();
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
async fn shapes_that_need_more_than_the_carrier_are_refused() {
    let mut xhttp = tls_node(skip_verify_tls());
    xhttp.transport_mut().unwrap().transport = "xhttp".into();
    let ech_discovery = tls_node(TlsOptions {
        ech_enabled: true,
        ..skip_verify_tls()
    });
    let without_stream_transport = |protocol: NodeProtocol| Node {
        outbound: OutboundConfig::from_protocol(protocol),
        ..tls_node(skip_verify_tls())
    };
    let cases = [
        (xhttp, "xhttp"),
        (ech_discovery, "tls ech discovery"),
        (without_stream_transport(NodeProtocol::SS), "ss"),
        (
            without_stream_transport(NodeProtocol::Hysteria2),
            "hysteria2",
        ),
    ];
    for (node, reason) in cases {
        let (client, mut server) = tokio::io::duplex(1024);
        let error = tokio::time::timeout(
            TIMEOUT,
            wrap_tunnel(&node, Box::new(client), TunnelDialOptions::new(TIMEOUT)),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(tunnel_unsupported(&error), "{error:#}");
        assert_eq!(
            error.downcast_ref::<TunnelUnsupported>(),
            Some(&TunnelUnsupported(reason))
        );
        let mut written = Vec::new();
        server.read_to_end(&mut written).await.unwrap();
        assert!(written.is_empty(), "{reason} wrote to the carrier");
    }
}

#[tokio::test]
async fn websocket_upgrade_preserves_a_lower_carriers_cancellation() {
    use crate::proxy::{PacketRejection, packet_rejection};

    #[derive(Debug)]
    struct CancelledRead;
    impl tokio::io::AsyncRead for CancelledRead {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(PacketRejection::Cancelled.into()))
        }
    }

    let mut node = tls_node(TlsOptions::default());
    node.transport_mut().unwrap().transport = "ws".into();
    let carrier = tokio::io::join(CancelledRead, tokio::io::sink());
    let error = wrap_tunnel(&node, Box::new(carrier), TunnelDialOptions::new(TIMEOUT))
        .await
        .unwrap_err();
    assert_eq!(packet_rejection(&error), Some(PacketRejection::Cancelled));
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
        error.downcast_ref::<TunnelUnsupported>(),
        Some(&TunnelUnsupported("trojan"))
    );
}

#[cfg(all(feature = "rprx", feature = "flow-observation"))]
mod relayed_request {
    use futures_util::StreamExt;
    use honk_config::node::VmessConfig;

    use super::*;
    use crate::proxy::request_observation_support::{milestones, observed};
    use crate::proxy::transport::write_request;
    use crate::proxy::vmess::VmessHandler;
    use crate::runtime::flow_observation::Milestone;

    #[tokio::test]
    async fn a_masked_hop_does_not_claim_an_outer_requests_bytes() {
        use crate::proxy::request_observation_support::DeferringCarrier;
        use crate::runtime::flow_observation::{request_write, without_target_milestones};

        let (client, mut peer) = tokio::io::duplex(8);
        let (mut carrier, pending) = DeferringCarrier::new(client);
        let (observer, events) = observed();
        observer
            .scope(async {
                let nested = without_target_milestones(write_request(&mut carrier, b"last"));
                request_write(std::pin::pin!(nested)).await.unwrap();
            })
            .await;
        assert!(events.lock().is_empty(), "not delivered yet");
        let mut bytes = [0; 4];
        peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"last");
        let (request, _) = pending.lock().take().unwrap();
        request.confirm();
        assert_eq!(milestones(&events.lock(), Milestone::TargetRequestSent), 1);
    }

    fn vmess_over_websocket() -> Node {
        let mut node = Node {
            name: "vmess-ws".into(),
            address: "198.51.100.1:443".into(),
            host: "must-not-resolve.invalid".into(),
            port: 443,
            outbound: OutboundConfig::Vmess(VmessConfig {
                uuid: Some("b831381d-6324-4d53-ad4f-8cda48b30811".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let transport = node.transport_mut().unwrap();
        transport.transport = "ws".into();
        transport.ws_path = Some("/".into());
        node.id = node.derive_id();
        node
    }

    /// The last hop writes its request into a VMess hop whose relay task
    /// feeds a WebSocket bridge task, which writes to a physical connection
    /// the peer stops reading. The request counts as sent only once the
    /// physical write completes, and never if it fails.
    #[tokio::test]
    async fn request_sent_waits_for_every_relay_below_it() {
        for physical_write_completes in [true, false] {
            // Room for the WebSocket upgrade, but not for the request below.
            let (client, server) = tokio::io::duplex(4096);
            let (open, opened) = tokio::sync::oneshot::channel::<bool>();
            let peer = tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(server).await.unwrap();
                if opened.await.unwrap() {
                    while let Some(Ok(_)) = ws.next().await {}
                }
            });

            let runtime =
                crate::runtime::NodeRuntime::try_ephemeral(&vmess_over_websocket()).unwrap();
            let handler = VmessHandler::new();
            let hop = handler.dial_over(
                runtime,
                Box::new(client),
                "192.0.2.1:443".parse().unwrap(),
                None,
                TunnelDialOptions::new(TIMEOUT),
            );
            let mut hop =
                tokio::time::timeout(TIMEOUT, crate::runtime::flow_observation::without(hop))
                    .await
                    .unwrap()
                    .unwrap();

            let (observer, events) = observed();
            observer
                .scope(write_request(&mut hop.stream, &[0x42; 16 * 1024]))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(events.lock().is_empty(), "sent before the physical write");

            open.send(physical_write_completes).unwrap();
            if physical_write_completes {
                tokio::time::timeout(TIMEOUT, async {
                    while events.lock().is_empty() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .unwrap();
                let events = events.lock();
                assert_eq!(events.len(), 1, "{events:?}");
                assert_eq!(milestones(&events, Milestone::TargetRequestSent), 1);
            } else {
                // The failed physical write tears down both relays.
                let _ = tokio::time::timeout(TIMEOUT, hop.stream.read(&mut [0; 1]))
                    .await
                    .unwrap();
                assert!(
                    events.lock().is_empty(),
                    "sent after a failed physical write"
                );
            }
            peer.abort();
        }
    }
}

#[cfg(feature = "flow-observation")]
mod quic_submission;
