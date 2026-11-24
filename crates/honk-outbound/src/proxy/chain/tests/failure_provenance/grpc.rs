use super::*;
use bytes::{Buf, BytesMut};
use honk_config::node::{StreamTransportOptions, TrojanConfig};

const EXIT: &str = "192.0.2.1";
const PORT: u16 = 1080;
const SETTINGS: &[u8] = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00";
// HEADERS with END_HEADERS, :status 200 and content-type: application/grpc.
const RESPONSE: &[u8] = b"\x00\x00\x14\x01\x04\x00\x00\x00\x01\x88\x0f\x10\x10application/grpc";
const PONG: &[u8] = b"\x00\x00\x0b\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x06\x0a\x04pong";
const REFUSED_STREAM: &[u8] = b"\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x07";

async fn serve(
    listener: TcpListener,
    corrupt: bool,
    release: oneshot::Receiver<()>,
    checked: oneshot::Receiver<()>,
) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let master = ShadowsocksHandler::master_key("test-password", 16);
    let mut salt = [0; 16];
    stream.read_exact(&mut salt).await.unwrap();
    let inbound = cipher(&master, &salt);
    let mut read_nonce = [0; 12];
    assert_eq!(
        read_chunk(&mut stream, &inbound, &mut read_nonce).await,
        [1, 192, 0, 2, 1, 4, 56],
        "Shadowsocks entry must tunnel the gRPC exit"
    );
    let salt = [0x53; 16];
    stream.write_all(&salt).await.unwrap();
    let outbound = cipher(&master, &salt);
    let mut write_nonce = [0; 12];
    write_chunk(&mut stream, &outbound, &mut write_nonce, SETTINGS).await;

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut request = BytesMut::new();
    while request.len() < PREFACE.len() {
        request.extend_from_slice(&read_chunk(&mut stream, &inbound, &mut read_nonce).await);
    }
    assert_eq!(&request[..PREFACE.len()], PREFACE);
    request.advance(PREFACE.len());
    loop {
        while request.len() < 9 {
            request.extend_from_slice(&read_chunk(&mut stream, &inbound, &mut read_nonce).await);
        }
        let length = u32::from_be_bytes([0, request[0], request[1], request[2]]) as usize;
        while request.len() < 9 + length {
            request.extend_from_slice(&read_chunk(&mut stream, &inbound, &mut read_nonce).await);
        }
        let frame = request.split_to(9 + length);
        if frame[3] == 0 {
            assert_eq!(&frame[4..9], &[0, 0, 0, 0, 1]);
            let gun = &frame[9..];
            assert_eq!(&gun[..7], &[0, 0, 0, 0, 70, 0x0a, TROJAN_REQUEST_LEN as u8]);
            assert_trojan_request(&gun[7..]);
            break;
        }
    }
    let response = [RESPONSE, PONG].concat();
    write_chunk(&mut stream, &outbound, &mut write_nonce, &response).await;
    release.await.unwrap();
    if corrupt {
        let mut sealed = Vec::new();
        seal_chunks_into(&outbound, &mut write_nonce, b"bad", &mut sealed).unwrap();
        sealed[17] ^= 1; // Tamper the length tag without ending TCP or the HTTP/2 stream.
        stream.write_all(&sealed).await.unwrap();
    } else {
        write_chunk(&mut stream, &outbound, &mut write_nonce, REFUSED_STREAM).await;
    }
    // Leave TCP open until the client has classified the protocol failure.
    checked.await.unwrap();
}

#[tokio::test]
async fn established_grpc_retains_shadowsocks_auth_failure_and_distinguishes_stream_reset() {
    for (corrupt, routed) in [(false, false), (true, false), (true, true)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = shadowsocks("front", "127.0.0.1", listener.local_addr().unwrap().port());
        let last = node(
            "exit",
            EXIT,
            PORT,
            OutboundConfig::Trojan(TrojanConfig {
                transport: StreamTransportOptions {
                    transport: "grpc".into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
        );
        let via = chain(&[&front, &last]);
        let route = route(&front, &[&front, &last]);
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(&[via.clone(), front, last]).unwrap());
        let registry = ProxyRegistry::default_resolver().unwrap();
        let (release, released) = oneshot::channel();
        let (check, checked) = oneshot::channel();
        let client = async {
            let mut stream = registry
                .dial_ref(
                    Arc::clone(&generation),
                    if routed {
                        DialRef::Route(&route)
                    } else {
                        DialRef::Node(via.id)
                    },
                    target(),
                    None,
                    Duration::from_secs(3),
                )
                .await
                .unwrap()
                .stream;
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"pong");
            release.send(()).unwrap();
            let error = stream.read_u8().await.unwrap_err();
            let outcome = ScoreOutcome::from_io_error(&error);
            if corrupt {
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(
                    error.to_string().contains("decrypt length failed"),
                    "{error}"
                );
                assert_eq!(outcome, ScoreOutcome::NodeFailure);
                if routed {
                    assert_eq!(dial_failure_scope(&error), DialFailureScope::Hop(0));
                }
                assert_score_failure_scope(&via, &[outcome], true, 1, 1);
            } else {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
                assert_eq!(outcome, ScoreOutcome::Io(io::ErrorKind::ConnectionReset));
                assert_score_failure_scope(&via, &[outcome], true, 1, 0);
            }
            check.send(()).unwrap();
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(client, serve(listener, corrupt, released, checked));
        })
        .await
        .expect("Shadowsocks and gRPC exchange must settle");
        generation.shutdown().await;
    }
}
