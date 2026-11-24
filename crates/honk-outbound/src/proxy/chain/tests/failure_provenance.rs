use super::*;
use crate::SharedError;
use crate::proxy::PacketRejection;
use crate::proxy::shadowsocks::{
    AeadCipher, ShadowsocksHandler, hkdf_sha1_derive, increment_nonce, seal_chunks_into,
};
use crate::test_support::assert_score_failure_scope;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::oneshot;

mod grpc;

const TROJAN_REQUEST_LEN: usize = 68;

fn assert_trojan_request(request: &[u8]) {
    assert_eq!(request.len(), TROJAN_REQUEST_LEN);
    assert_eq!(&request[56..59], b"\r\n\x01");
    assert_eq!(&request[59..66], &TCP_TARGET_HEADER);
    assert_eq!(&request[66..], b"\r\n");
}

const METHOD: &str = "aes-128-gcm";

fn cipher(master: &[u8], salt: &[u8]) -> AeadCipher {
    let mut key = [0; 16];
    hkdf_sha1_derive(master, salt, &mut key);
    AeadCipher::new(METHOD, &key).unwrap()
}

async fn read_chunk(stream: &mut TcpStream, cipher: &AeadCipher, nonce: &mut [u8]) -> Vec<u8> {
    let mut length = [0; 2 + 16];
    stream.read_exact(&mut length).await.unwrap();
    let length: [u8; 2] = cipher.open(nonce, &length).unwrap().try_into().unwrap();
    increment_nonce(nonce);
    let mut sealed = vec![0; usize::from(u16::from_be_bytes(length)) + 16];
    stream.read_exact(&mut sealed).await.unwrap();
    let body = cipher.open(nonce, &sealed).unwrap();
    increment_nonce(nonce);
    body
}

async fn write_chunk(stream: &mut TcpStream, cipher: &AeadCipher, nonce: &mut [u8], body: &[u8]) {
    let mut wire = Vec::new();
    seal_chunks_into(cipher, nonce, body, &mut wire).unwrap();
    stream.write_all(&wire).await.unwrap();
}

#[derive(Debug)]
struct RefusingIo(SharedError);

impl RefusingIo {
    fn error(&self) -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionRefused, self.0.clone())
    }
}

impl AsyncRead for RefusingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(self.error()))
    }
}

impl AsyncWrite for RefusingIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(self.error()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        assert_eq!(data.len(), 2);
        Poll::Ready(Err(self.error()))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(self.error()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(self.error()))
    }
}

fn two_carriers(error: SharedError) -> Box<dyn AsyncReadWrite> {
    let mut stream: Box<dyn AsyncReadWrite> = Box::new(RefusingIo(error));
    // A transparent protocol can reuse one wrapper, but a new codec returns
    // its own stream object. Exercise both the inner and outer I/O boundaries.
    for index in 0..2 {
        if index != 0 {
            stream = Box::new(crate::proxy::RuntimeOwnedIo::new(stream, ()));
        }
        stream = intermediate_carrier(
            index,
            Ok(ProxyStream {
                stream,
                target_addr: target(),
                target_domain: None,
            }),
            true,
        )
        .unwrap();
    }
    stream
}

#[tokio::test]
async fn intermediate_carrier_io_keeps_shared_episode_and_origin() {
    let cause = io::Error::from_raw_os_error(libc::ECONNREFUSED);
    let error = SharedError::fanout(TargetFailure(cause.into()).into());
    let expected = ScoreOutcome::SharedNodeFailure(error.episode().unwrap());
    let mut stream = two_carriers(error);
    assert!(stream.is_write_vectored());
    for error in [
        stream.read(&mut [0]).await.unwrap_err(),
        stream.write(b"a").await.unwrap_err(),
        stream
            .write_vectored(&[IoSlice::new(b"a"), IoSlice::new(b"b")])
            .await
            .unwrap_err(),
        stream.flush().await.unwrap_err(),
        stream.shutdown().await.unwrap_err(),
    ] {
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(ScoreOutcome::from_io_error(&error), expected);
        assert_eq!(dial_failure_scope(&error), DialFailureScope::Prefix(1));
        // A queued driver may retain the I/O error and a relay may add carrier context.
        let error = io::Error::new(error.kind(), Arc::new(error));
        let error = anyhow::Error::new(NodeFailure(error.into())).context("relay");
        assert_eq!(ScoreOutcome::from_error(&error), expected);
        assert_eq!(
            dial_failure_scope(error.as_ref()),
            DialFailureScope::Prefix(1)
        );
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::ECONNREFUSED),
        );
    }

    let cause = io::Error::from_raw_os_error(libc::ECONNREFUSED);
    let lower = SharedError::fanout(NodeFailure(cause.into()).into());
    let episode = lower.episode().unwrap();
    let expected = ScoreOutcome::SharedNodeFailure(episode);
    let codec = NodeFailure(io::Error::new(io::ErrorKind::ConnectionRefused, lower).into());
    let mut stream = two_carriers(SharedError::fanout(codec.into()));
    let error = stream.read_u8().await.unwrap_err();
    let borrowed = crate::proxy::retain_typed_io_error(&error).unwrap();
    assert_eq!(borrowed.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(dial_failure_scope(&borrowed), DialFailureScope::Hop(0));
    assert_eq!(
        crate::proxy::shared_failure_cause(&borrowed).and_then(SharedError::episode),
        Some(episode),
    );
    assert_eq!(ScoreOutcome::from_io_error(&borrowed), expected);
}

#[tokio::test]
async fn intermediate_carrier_io_preserves_policy_capacity_and_cancellation() {
    for (rejection, expected) in [
        (PacketRejection::Policy, ScoreOutcome::Rejected),
        (PacketRejection::InvalidSize, ScoreOutcome::Rejected),
        (PacketRejection::Capacity, ScoreOutcome::Rejected),
        (PacketRejection::Cancelled, ScoreOutcome::Cancelled),
    ] {
        let shared = SharedError::new(TargetFailure(rejection.into()).into());
        let error = two_carriers(shared).flush().await.unwrap_err();
        assert_eq!(ScoreOutcome::from_io_error(&error), expected);
        assert_eq!(crate::proxy::io_packet_rejection(&error), Some(rejection));
        assert_eq!(dial_failure_scope(&error), DialFailureScope::LocalRejection);
        let borrowed = crate::proxy::retain_typed_io_error(&error).unwrap();
        assert_eq!(borrowed.kind(), error.kind());
        assert_eq!(ScoreOutcome::from_io_error(&borrowed), expected);
        assert!(!node_failure(&error.into()));
    }
}

#[tokio::test]
async fn final_io_preserves_a_target_refusal_instead_of_inventing_a_prefix() {
    let target_refusal = TargetFailure(io::Error::from(io::ErrorKind::ConnectionRefused).into());
    let stream = Box::new(RefusingIo(SharedError::new(target_refusal.into())));
    let mut stream = hop_carrier(2, stream, true, false);
    let error = stream.read_u8().await.unwrap_err();
    assert_eq!(dial_failure_scope(&error), DialFailureScope::Target);
    assert_eq!(
        ScoreOutcome::from_io_error(&error),
        ScoreOutcome::TargetFailure
    );
}

#[tokio::test]
async fn a_final_shadowsocks_fault_after_payload_identifies_the_exit() {
    use crate::group::{OwnedTarget, RoutedTarget};

    for (corrupt, routed) in [(true, true), (true, false), (false, true)] {
        let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = socks5_relay(Vec::new(), false).await;
        let front = socks5("front", "127.0.0.1", relay.addr.port());
        let exit = shadowsocks("exit", "127.0.0.1", peer.local_addr().unwrap().port());
        let via = chain(&[&front, &exit]);
        let route = route(&front, &[&front, &exit]);
        let mut owned = OwnedTarget::node(front.clone());
        let exit_id = exit.id;
        owned.route = Some(Box::new(RoutedTarget {
            route,
            hop_names: [front.name.clone(), exit.name.clone()].into(),
        }));
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(&[via.clone(), front, exit]).unwrap());
        let registry = ProxyRegistry::default_resolver().unwrap();
        let (release, released) = oneshot::channel();
        let (check, checked) = oneshot::channel();
        let server = async {
            let (mut stream, _) = peer.accept().await.unwrap();
            let master = ShadowsocksHandler::master_key("test-password", 16);
            let mut salt = [0; 16];
            stream.read_exact(&mut salt).await.unwrap();
            let inbound = cipher(&master, &salt);
            assert_eq!(
                read_chunk(&mut stream, &inbound, &mut [0; 12]).await,
                TCP_TARGET_HEADER
            );
            let salt = [0x39; 16];
            stream.write_all(&salt).await.unwrap();
            let outbound = cipher(&master, &salt);
            let mut nonce = [0; 12];
            write_chunk(&mut stream, &outbound, &mut nonce, b"pong").await;
            released.await.unwrap();
            if corrupt {
                let mut wire = Vec::new();
                seal_chunks_into(&outbound, &mut nonce, b"bad", &mut wire).unwrap();
                wire[17] ^= 1;
                stream.write_all(&wire).await.unwrap();
            } else {
                stream.shutdown().await.unwrap();
            }
            checked.await.unwrap();
        };
        let client = async {
            let dial = if routed {
                owned.dial_ref()
            } else {
                DialRef::Node(via.id)
            };
            let mut stream = registry
                .dial_ref(
                    Arc::clone(&generation),
                    dial,
                    target(),
                    None,
                    Duration::from_secs(2),
                )
                .await
                .unwrap()
                .stream;
            let mut reply = [0; 4];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"pong");
            release.send(()).unwrap();
            let result = stream.read(&mut [0; 1]).await;
            if corrupt {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert_eq!(
                    ScoreOutcome::from_io_error(&error),
                    ScoreOutcome::NodeFailure
                );
                if routed {
                    assert_eq!(dial_failure_scope(&error), DialFailureScope::Hop(1));
                    assert_eq!(owned.failure_owner(&error.into()), Some(exit_id));
                } else {
                    assert_eq!(dial_failure_scope(&error), DialFailureScope::Unattributed);
                }
            } else {
                assert_eq!(result.unwrap(), 0);
            }
            check.send(()).unwrap();
        };
        tokio::time::timeout(Duration::from_secs(8), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        generation.shutdown().await;
    }
}

#[cfg(feature = "rprx")]
mod h2mux {
    use super::*;
    use crate::group::{OwnedTarget, RoutedTarget};
    use bytes::{Bytes, BytesMut};
    use honk_config::group_graph::{Composed, compose};
    use honk_config::node::{
        StreamTransportOptions, TlsOptions, TrojanConfig, VlessMultiplex, VmessConfig,
    };
    use tokio::sync::oneshot;

    mod websocket;

    const UUID: &str = "00000000-0000-4000-8000-000000000001";
    const NEXT_HOP: &str = "192.0.2.1";
    const NEXT_HOP_PORT: u16 = 1080;
    const MUX_SERVER: &[u8] = b"sp.mux.sing-box.arpa";
    const REFUSAL: &[u8] = b"\x01\x0bno next hop";

    #[derive(Debug, PartialEq, Eq)]
    enum FailurePhase {
        Setup,
        DeliveredStream,
        Either,
    }

    async fn accept_mux(
        mut stream: tokio::net::TcpStream,
    ) -> h2::server::Connection<tokio::net::TcpStream, Bytes> {
        let mut header = [0; 23];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0);
        assert_eq!(
            &header[1..17],
            uuid::Uuid::parse_str(UUID).unwrap().as_bytes()
        );
        assert_eq!(&header[17..], &[0, 1, 1, 188, 2, MUX_SERVER.len() as u8]);
        let mut domain = [0; MUX_SERVER.len()];
        stream.read_exact(&mut domain).await.unwrap();
        assert_eq!(&domain[..], MUX_SERVER);
        stream.write_all(&[0, 0]).await.unwrap();
        let mut preface = [0; 2];
        stream.read_exact(&mut preface).await.unwrap();
        assert_eq!(preface, [0, 2]);

        h2::server::handshake(stream).await.unwrap()
    }

    async fn refuse_next_hop(
        listener: TcpListener,
        expected_payload: &[u8],
        release: oneshot::Receiver<()>,
        reported: oneshot::Receiver<()>,
    ) {
        let (stream, _) = listener.accept().await.unwrap();
        let mut driver = accept_mux(stream).await;
        let (request, mut respond) = driver.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        let mut recv = request.into_body();
        let refusal = async {
            const CONNECT: &[u8] = &[0, 0, 1, 192, 0, 2, 1, 4, 56];
            let mut body = BytesMut::new();
            while body.len() < CONNECT.len() + expected_payload.len().max(1) {
                let data = recv.data().await.unwrap().unwrap();
                body.extend_from_slice(&data);
                recv.flow_control().release_capacity(data.len()).unwrap();
            }
            assert_eq!(&body[..CONNECT.len()], CONNECT);
            assert!(body[CONNECT.len()..].starts_with(expected_payload));
            release.await.unwrap();
            send.send_data(Bytes::from_static(REFUSAL), true).unwrap();
            reported.await.unwrap();
        };
        tokio::select! {
            biased;
            () = refusal => {}
            result = driver.accept() => panic!("unexpected second H2MUX request or closure: {result:?}"),
        }
    }

    async fn exercise(
        outbounds: &[OutboundConfig],
        payload: &[u8],
        phase: FailurePhase,
        routed: bool,
    ) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let front = node(
                "front",
                "127.0.0.1",
                listener.local_addr().unwrap().port(),
                OutboundConfig::Vless(honk_config::node::VlessConfig {
                    uuid: Some(UUID.into()),
                    multiplex: VlessMultiplex::H2 { padding: false },
                    ..Default::default()
                }),
            );
            let mut nodes = vec![front];
            nodes.extend(outbounds.iter().enumerate().map(|(index, outbound)| {
                node(
                    &format!("hop-{index}"),
                    NEXT_HOP,
                    NEXT_HOP_PORT,
                    outbound.clone(),
                )
            }));
            let via = chain(&nodes.iter().collect::<Vec<_>>());
            let id = via.id;
            let refused = nodes[1].id;
            let mut owned = OwnedTarget::node(via.clone());
            if routed {
                let front = &nodes[0];
                let exits = nodes[1..].iter().map(|node| node.id);
                let Composed::Routed(route) = compose(front.id, &[front.id], exits) else {
                    panic!("expected a route through multiple proxies");
                };
                owned = OwnedTarget::node(front.clone());
                owned.route = Some(Box::new(RoutedTarget {
                    route,
                    hop_names: nodes.iter().map(|node| node.name.clone()).collect(),
                }));
            }
            nodes.push(via);
            let generation = Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap());
            let registry = ProxyRegistry::default_resolver().unwrap();
            let (release, allow_refusal) = oneshot::channel();
            let (report, reported) = oneshot::channel();
            let client = async {
                let mut release = Some(release);
                if phase != FailurePhase::DeliveredStream {
                    release.take().unwrap().send(()).unwrap();
                }
                let dial = registry.dial_ref(
                    Arc::clone(&generation),
                    owned.dial_ref(),
                    target(),
                    None,
                    Duration::from_secs(3),
                );
                let error = match dial.await {
                    Ok(mut stream) => {
                        assert_ne!(phase, FailurePhase::Setup);
                        if let Some(release) = release {
                            release.send(()).unwrap();
                        }
                        let error = stream.stream.read_u8().await.unwrap_err();
                        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
                        assert_eq!(dial_failure_scope(&error), DialFailureScope::Prefix(1));
                        assert_eq!(
                            ScoreOutcome::from_io_error(&error),
                            ScoreOutcome::NodeFailure,
                        );
                        anyhow::Error::new(error)
                    }
                    Err(error) => {
                        assert_ne!(phase, FailurePhase::DeliveredStream, "{error:#}");
                        assert_eq!(
                            failed_hop(&error).map(|failure| (failure.hop, failure.node)),
                            routed.then_some((1, refused)),
                        );
                        error
                    }
                };
                assert_eq!(
                    dial_failure_scope(error.as_ref()),
                    DialFailureScope::Prefix(1)
                );
                assert_eq!(owned.failure_owner(&error), (!routed).then_some(id));
                assert_eq!(
                    ScoreOutcome::from_error(&error),
                    ScoreOutcome::NodeFailure,
                    "{error:#}",
                );
                assert!(format!("{error:#}").contains("no next hop"));
                report.send(()).unwrap();
            };
            tokio::join!(
                client,
                refuse_next_hop(listener, payload, allow_refusal, reported)
            );
            generation.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h2mux_refusal_during_exit_socks_greeting_counts_against_the_chain() {
        for routed in [false, true] {
            exercise(
                &[OutboundConfig::Socks5(Default::default())],
                &[5, 1, 0],
                FailurePhase::Setup,
                routed,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn h2mux_refusal_after_vmess_stream_delivery_counts_against_the_chain() {
        let vmess = OutboundConfig::Vmess(VmessConfig {
            uuid: Some(UUID.into()),
            ..Default::default()
        });
        let final_ss = shadowsocks("exit", NEXT_HOP, 1081).outbound;
        // A third hop adds a second real codec around the original refusal.
        let hops = [vmess, final_ss];
        for hops in [&hops[..1], &hops[..]] {
            for routed in [false, true] {
                exercise(hops, &[], FailurePhase::DeliveredStream, routed).await;
            }
        }
    }

    #[tokio::test]
    async fn h2mux_refusal_survives_exit_tls_and_reality_setup() {
        use base64::Engine as _;

        let key = boring::pkey::PKey::generate(boring::pkey::Id::X25519).unwrap();
        let mut public = [0; 32];
        key.raw_public_key(&mut public).unwrap();
        let reality = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public);
        for reality_public_key in [None, Some(reality)] {
            let reality_short_id = reality_public_key
                .as_ref()
                .map(|_| "1919191919191919".into());
            exercise(
                &[OutboundConfig::Trojan(TrojanConfig {
                    tls: TlsOptions {
                        enabled: true,
                        sni: Some("localhost".into()),
                        reality_public_key,
                        reality_short_id,
                        ..Default::default()
                    },
                    ..Default::default()
                })],
                &[22, 3],
                FailurePhase::Setup,
                false,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn h2mux_refusal_survives_exit_grpc_driver() {
        exercise(
            &[OutboundConfig::Trojan(TrojanConfig {
                transport: StreamTransportOptions {
                    transport: "grpc".into(),
                    ..Default::default()
                },
                ..Default::default()
            })],
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            FailurePhase::Either,
            false,
        )
        .await;
    }
}
