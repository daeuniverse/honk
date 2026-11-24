use super::*;
use crate::SharedError;
use crate::proxy::{NodeFailure, PacketRejection};
use crate::test_support::assert_score_failure_scope;
use tokio::io::AsyncWriteExt;

mod grpc;

const TROJAN_REQUEST_LEN: usize = 68;

fn assert_trojan_request(request: &[u8]) {
    assert_eq!(request.len(), TROJAN_REQUEST_LEN);
    assert_eq!(&request[56..59], b"\r\n\x01");
    assert_eq!(&request[59..66], &TCP_TARGET_HEADER);
    assert_eq!(&request[66..], b"\r\n");
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
    for index in 0..2 {
        stream = intermediate_carrier(
            index,
            Ok(ProxyStream {
                stream,
                target_addr: target(),
                target_domain: None,
            }),
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
        assert!(error.to_string().starts_with("chain hop 1 "), "{error}");
        // A queued driver may retain the I/O error and a relay may add carrier context.
        let error = io::Error::new(error.kind(), Arc::new(error));
        let error = anyhow::Error::new(NodeFailure(error.into())).context("relay");
        assert_eq!(ScoreOutcome::from_error(&error), expected);
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
    let expected = ScoreOutcome::SharedNodeFailure(lower.episode().unwrap());
    let codec = NodeFailure(io::Error::new(io::ErrorKind::ConnectionRefused, lower).into());
    let mut stream = two_carriers(SharedError::new(codec.into()));
    let error = stream.read_u8().await.unwrap_err();
    let borrowed = crate::proxy::retain_typed_io_error(&error).unwrap();
    assert_eq!(borrowed.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(ScoreOutcome::from_io_error(&borrowed), expected);
}

#[tokio::test]
async fn intermediate_carrier_io_preserves_policy_capacity_and_cancellation() {
    for (rejection, expected) in [
        (PacketRejection::Policy, ScoreOutcome::Rejected),
        (PacketRejection::Capacity, ScoreOutcome::Rejected),
        (PacketRejection::Cancelled, ScoreOutcome::Cancelled),
    ] {
        let shared = SharedError::new(TargetFailure(rejection.into()).into());
        let error = two_carriers(shared).flush().await.unwrap_err();
        assert_eq!(ScoreOutcome::from_io_error(&error), expected);
        assert_eq!(crate::proxy::io_packet_rejection(&error), Some(rejection));
        let borrowed = crate::proxy::retain_typed_io_error(&error).unwrap();
        assert_eq!(borrowed.kind(), error.kind());
        assert_eq!(ScoreOutcome::from_io_error(&borrowed), expected);
        assert!(!node_failure(&error.into()));
    }
}

#[cfg(feature = "rprx")]
mod h2mux {
    use super::*;
    use bytes::{Bytes, BytesMut};
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

    async fn exercise(outbound: OutboundConfig, payload: &[u8], phase: FailurePhase) {
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
            let last = node("last", NEXT_HOP, NEXT_HOP_PORT, outbound);
            let via = chain(&[&front, &last]);
            let id = via.id;
            let generation = Arc::new(OutboundRuntimeRegistry::build(&[via, front, last]).unwrap());
            let registry = ProxyRegistry::default_resolver().unwrap();
            let (release, allow_refusal) = oneshot::channel();
            let (report, reported) = oneshot::channel();
            let client = async {
                let mut release = Some(release);
                if phase != FailurePhase::DeliveredStream {
                    release.take().unwrap().send(()).unwrap();
                }
                let dial = registry.dial_runtime(
                    Arc::clone(&generation),
                    id,
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
                        assert_eq!(
                            ScoreOutcome::from_io_error(&error),
                            ScoreOutcome::NodeFailure,
                        );
                        anyhow::Error::new(error)
                    }
                    Err(error) => {
                        assert_ne!(phase, FailurePhase::DeliveredStream, "{error:#}");
                        error
                    }
                };
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
        exercise(
            OutboundConfig::Socks5(Default::default()),
            &[5, 1, 0],
            FailurePhase::Setup,
        )
        .await;
    }

    #[tokio::test]
    async fn h2mux_refusal_after_vmess_stream_delivery_counts_against_the_chain() {
        exercise(
            OutboundConfig::Vmess(VmessConfig {
                uuid: Some(UUID.into()),
                ..Default::default()
            }),
            &[],
            FailurePhase::DeliveredStream,
        )
        .await;
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
                OutboundConfig::Trojan(TrojanConfig {
                    tls: TlsOptions {
                        enabled: true,
                        sni: Some("localhost".into()),
                        reality_public_key,
                        reality_short_id,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                &[22, 3],
                FailurePhase::Setup,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn h2mux_refusal_survives_exit_grpc_driver() {
        exercise(
            OutboundConfig::Trojan(TrojanConfig {
                transport: StreamTransportOptions {
                    transport: "grpc".into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            FailurePhase::Either,
        )
        .await;
    }
}
