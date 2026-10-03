use super::*;
use tokio::io::{AsyncRead, AsyncWrite};

fn download_tls() -> (crate::marked_http::Client, tokio_rustls::TlsAcceptor) {
    use tokio_rustls::rustls::{self, pki_types::PrivatePkcs8KeyDer};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = rustls::pki_types::CertificateDer::from(cert.cert);
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    (
        crate::marked_http::Client::with_tls(client),
        tokio_rustls::TlsAcceptor::from(Arc::new(server)),
    )
}

/// A real stream whose carrier dies after the peer receives the GET.
#[derive(Debug)]
struct FailedCarrier {
    inner: tokio::io::DuplexStream,
    failed: Arc<std::sync::atomic::AtomicBool>,
}

impl AsyncRead for FailedCarrier {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if result.is_ready() && self.failed.load(std::sync::atomic::Ordering::Acquire) {
            std::task::Poll::Ready(Err(std::io::Error::other(
                honk_outbound::proxy::NodeFailure(anyhow::anyhow!("loopback proxy carrier lost")),
            )))
        } else {
            result
        }
    }
}

impl AsyncWrite for FailedCarrier {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test(start_paused = true)]
async fn completed_setup_header_stall_is_target_scoped_but_carrier_loss_is_node_scoped() {
    let (tls, acceptor) = download_tls();
    let plain = crate::marked_http::Client::plain();
    for (https, carrier) in [(false, false), (true, false), (true, true)] {
        let nodes = [("primary", 1080), ("spare", 1081)].map(|(name, port)| {
            Node::from_share_link(&format!("socks5://127.0.0.1:{port}#{name}")).unwrap()
        });
        let group = Group {
            name: "ui-score".into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        };
        let manager = GroupManager::new(std::slice::from_ref(&group), &nodes);
        let healthy = ScoreSelectionContext {
            target: Some(honk_outbound::group::ScoreTarget::domain(
                "healthy.example",
                443,
            )),
            ..ScoreSelectionContext::aggregate(
                SelectionNetwork::Tcp,
                ProbeDomain::Tcp,
                IpVersion::V4,
            )
        };
        for (node, count) in nodes.iter().zip([8, 4]) {
            for _ in 0..count {
                let seed = manager
                    .feedback_for_group_node("ui-score", node.id, healthy.clone())
                    .unwrap()
                    .start();
                seed.setup_succeeded();
                seed.first_response();
                seed.tx(1);
                seed.rx(1);
                seed.finish(ScoreOutcome::Success);
            }
        }
        assert_eq!(
            manager
                .score_verification_for_network("ui-score", SelectionNetwork::Tcp)
                .unwrap()
                .0,
            "primary"
        );
        let url = reqwest::Url::parse(if https {
            "https://localhost/ui.zip"
        } else {
            "http://localhost/ui.zip"
        })
        .unwrap();
        let failing = ScoreSelectionContext {
            target: Some(honk_outbound::group::ScoreTarget::domain("localhost", 443)),
            ..healthy.clone()
        };
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..3 {
            let (stream, peer) = tokio::io::duplex(64 * 1024);
            let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let failure = Arc::clone(&failed);
            let acceptor = acceptor.clone();
            let (received, request) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer: Box<dyn AsyncReadWrite> = if https {
                    Box::new(acceptor.accept(peer).await.unwrap())
                } else {
                    Box::new(peer)
                };
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(peer.read_u8().await.unwrap());
                }
                received.send(()).unwrap();
                if carrier {
                    failure.store(true, std::sync::atomic::Ordering::Release);
                } else {
                    // No response headers: cancellation must close the actual driver stream.
                    assert!(matches!(peer.read(&mut [0]).await, Ok(0) | Err(_)));
                }
            });
            let reporter = Some(
                manager
                    .feedback_for_group_node("ui-score", nodes[0].id, failing.clone())
                    .unwrap()
                    .start(),
            );
            let mut archive = ArchiveFile::create(&dir.path().join("ui")).unwrap();
            let error = {
                let by = tokio::time::Instant::now() + Duration::from_secs(1);
                let fetch = tokio::time::timeout_at(
                    by,
                    proxied_get(
                        if https { &tls } else { &plain },
                        Box::new(FailedCarrier {
                            inner: stream,
                            failed,
                        }),
                        &url,
                        &mut archive,
                        &reporter,
                        by,
                    ),
                );
                tokio::pin!(fetch);
                tokio::select! {
                    biased;
                    result = request => result.unwrap(),
                    _ = &mut fetch => panic!("fetch must reach the actual GET after TLS setup"),
                }
                if !carrier {
                    tokio::time::advance(Duration::from_secs(1)).await;
                }
                fetch
                    .await
                    .unwrap_or_else(|_| Err(timed_out()))
                    .err()
                    .expect("headers never arrive")
            };
            let outcome = ScoreOutcome::from_error(&error);
            assert_eq!(
                outcome,
                if carrier {
                    ScoreOutcome::NodeFailure
                } else {
                    ScoreOutcome::Timeout
                },
                "{error:#}"
            );
            reporter.as_ref().unwrap().finish(outcome);
            server.await.unwrap();
        }
        assert_eq!(
            manager
                .score_verification_for_network("ui-score", SelectionNetwork::Tcp)
                .unwrap()
                .0,
            if carrier { "spare" } else { "primary" },
            "unrelated target must survive only target-scoped faults"
        );
    }
}

#[tokio::test]
async fn download_tls_keeps_san_validation() {
    let (client, acceptor) = download_tls();
    let (stream, peer) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        assert!(acceptor.accept(peer).await.is_err());
    });
    let url = reqwest::Url::parse("https://wrong.example/ui.zip").unwrap();
    let by = tokio::time::Instant::now() + Duration::from_secs(5);
    let error = client
        .prepare_over(Box::new(stream), &url, &http::HeaderMap::new(), by)
        .await
        .err()
        .expect("trusted root must not bypass SAN validation");
    assert_eq!(error.stage, "tls_failed");
    let error = anyhow::Error::new(error);
    assert!(!ScoreOutcome::from_error(&error).is_node_failure());
    assert!(
        error.chain().any(|source| source
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            .and_then(|source| source.downcast_ref::<tokio_rustls::rustls::Error>())
            .is_some_and(|error| matches!(
                error,
                tokio_rustls::rustls::Error::InvalidCertificate(_)
            ))),
        "{error:#}"
    );
    server.await.unwrap();
}
