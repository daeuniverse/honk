use super::*;
use crate::group::ScoreOutcome;
use crate::proxy::{ProxyRegistry, node_failure, target_failure};
use crate::runtime::OutboundRuntimeRegistry;
use crate::test_support::{TCP_TARGET, assert_score_failure_scope, chain, node};
use base64::Engine as _;
use honk_config::node::{OutboundConfig, TlsOptions, TrojanConfig};

const EXIT: &str = "192.0.2.1:443";
const TIMEOUT: Duration = Duration::from_secs(5);

async fn truncate_proxy_response(endpoint: &Endpoint, checked: tokio::sync::oneshot::Receiver<()>) {
    let conn = endpoint.accept().await.unwrap().await.unwrap();
    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
    assert_eq!(
        read_varint_stream(&mut recv).await.unwrap(),
        H3_FRAME_HEADERS
    );
    let authenticated = Arc::new(AtomicBool::new(false));
    handle_auth_request(
        &mut send,
        &mut recv,
        Arc::clone(&authenticated),
        TEST_PASSWORD,
        false,
    )
    .await;
    assert!(authenticated.load(Ordering::Relaxed));

    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
    assert_eq!(
        read_varint_stream(&mut recv).await.unwrap(),
        FRAME_TYPE_TCP_REQUEST
    );
    assert_eq!(
        read_varint_stream(&mut recv).await.unwrap(),
        EXIT.len() as u64
    );
    let mut address = [0; EXIT.len()];
    read_exact(&mut recv, &mut address).await.unwrap();
    assert_eq!(&address, EXIT.as_bytes());
    let padding = read_varint_stream(&mut recv).await.unwrap();
    skip_bytes(&mut recv, padding).await.unwrap();
    let mut client_hello = [0; 2];
    read_exact(&mut recv, &mut client_hello).await.unwrap();
    assert_eq!(client_hello, [22, 3]);

    // Success status and zero message length, with the padding length missing.
    send.write_all(&[0, 0]).await.unwrap();
    send.finish().unwrap();
    // Keep the connection open so the client sees a response FIN on this stream.
    checked.await.unwrap();
}

#[tokio::test]
async fn truncated_hy2_proxy_response_survives_exit_tls_and_reality_setup() {
    let key = boring::pkey::PKey::generate(boring::pkey::Id::X25519).unwrap();
    let mut public = [0; 32];
    key.raw_public_key(&mut public).unwrap();
    let reality = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public);
    for reality_public_key in [None, Some(reality)] {
        let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
        let mut front = test_node(addr.port(), TEST_PASSWORD);
        front.id = front.derive_id();
        let handshake = if reality_public_key.is_some() {
            "REALITY"
        } else {
            "TLS"
        };
        let last = node(
            "exit",
            "192.0.2.1",
            443,
            OutboundConfig::Trojan(TrojanConfig {
                tls: TlsOptions {
                    enabled: true,
                    sni: Some("localhost".into()),
                    reality_short_id: reality_public_key
                        .as_ref()
                        .map(|_| "1919191919191919".into()),
                    reality_public_key,
                    ..Default::default()
                },
                ..Default::default()
            }),
        );
        let via = chain(&[&front, &last]);
        let id = via.id;
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(&[via.clone(), front, last]).unwrap());
        let registry = ProxyRegistry::default_resolver().unwrap();
        let (check, checked) = tokio::sync::oneshot::channel();
        let dial = async {
            let error = registry
                .dial_runtime(
                    Arc::clone(&generation),
                    id,
                    TCP_TARGET.parse().unwrap(),
                    None,
                    TIMEOUT,
                )
                .await
                .unwrap_err();
            assert!(error.to_string().starts_with(handshake), "{error:#}");
            assert!(node_failure(&error));
            assert!(!target_failure(&error));
            let outcome = ScoreOutcome::from_error(&error);
            assert_eq!(outcome, ScoreOutcome::NodeFailure);
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::UnexpectedEof,
            );
            assert_eq!(
                error.root_cause().to_string(),
                "Hysteria2 TCP response truncated",
            );
            assert_score_failure_scope(&via, &[outcome], false, 1, 1);
            check.send(()).unwrap();
        };
        tokio::time::timeout(TIMEOUT * 2, async {
            tokio::join!(dial, truncate_proxy_response(&endpoint, checked));
        })
        .await
        .expect("Hy2 entry and tunneled handshake must settle");
        generation.shutdown().await;
    }
}
