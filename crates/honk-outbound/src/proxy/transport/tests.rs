use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod grpc_headers;
mod grpc_io;
mod grpc_peer;

#[test]
fn uri_path_encoding_preserves_uri_syntax() {
    for (path, expected) in [
        ("/a b", "/a%20b"),
        ("/a%20b", "/a%20b"),
        ("/proxy?ed=2048&tag=a b", "/proxy?ed=2048&tag=a%20b"),
        ("/雪/é", "/%E9%9B%AA/%C3%A9"),
        ("/plain/path", "/plain/path"),
        ("/!#$%&'()*+,-./:;=?@[]_~", "/!#$%&'()*+,-./:;=?@[]_~"),
    ] {
        assert_eq!(encode_uri_path(path).to_string(), expected, "{path:?}");
    }
}

#[test]
fn uri_path_encoding_escapes_controls_and_unsafe_punctuation() {
    for byte in (0..=31).chain([127]) {
        let path = format!("/{}", char::from(byte));
        assert_eq!(encode_uri_path(&path).to_string(), format!("/%{byte:02X}"));
    }
    assert_eq!(
        encode_uri_path("/ \"<>`{}|\\^").to_string(),
        "/%20%22%3C%3E%60%7B%7D%7C%5C%5E",
    );
}

fn transport_node(port: u16) -> Node {
    Node {
        name: "transport-node".into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            password: Some("secret".into()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_ws_transport_roundtrip() {
    for with_headers in [false, true] {
        ws_transport_roundtrip("/ws-path", "/ws-path", with_headers).await;
    }
}

#[tokio::test]
async fn ws_transport_encodes_path_and_preserves_query() {
    for (path, expected) in [
        (
            "/proxyip=proxyip.cmliussss.net, cdn-all.xn--b6gac.eu.org",
            "/proxyip=proxyip.cmliussss.net,%20cdn-all.xn--b6gac.eu.org",
        ),
        ("/existing%20path?ed=2048", "/existing%20path?ed=2048"),
        ("/雪?q=a b", "/%E9%9B%AA?q=a%20b"),
    ] {
        ws_transport_roundtrip(path, expected, true).await;
    }
}

// The accept callback's Result type (and its large Err variant) is
// dictated by tungstenite's `Callback` trait.
#[allow(clippy::result_large_err)]
async fn ws_transport_roundtrip(path: &str, expected: &str, with_headers: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();

    let server = tokio::spawn(async move {
        use futures_util::{SinkExt, StreamExt};
        let (stream, _) = listener.accept().await.unwrap();
        let mut seen_tx = Some(seen_tx);
        let callback =
            |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
             resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                let header = |name: &str| {
                    req.headers()
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string)
                };
                let host = header("host");
                let user_agent = header("user-agent");
                let x_test = header("x-test");
                if let Some(tx) = seen_tx.take() {
                    let _ = tx.send((
                        req.uri().path_and_query().unwrap().to_string(),
                        host,
                        user_agent,
                        x_test,
                    ));
                }
                Ok(resp)
            };
        let mut ws = tokio_tungstenite::accept_hdr_async(stream, callback)
            .await
            .unwrap();
        let msg = ws.next().await.unwrap().unwrap();
        assert_eq!(&msg.into_data()[..], b"ping");
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            b"pong".to_vec().into(),
        ))
        .await
        .unwrap();
    });

    let mut node = transport_node(port);
    let transport = node.transport_mut().unwrap();
    transport.transport = "ws".into();
    transport.ws_path = Some(path.into());
    transport.ws_host = Some("cdn.example.com".into());
    if with_headers {
        transport.ws_headers.insert(
            "user-agent".into(),
            "Mozilla/5.0 (X11; Linux x86_64)".into(),
        );
        transport
            .ws_headers
            .insert("x-test".into(), "ws-header".into());
    }

    let mut stream = wrap_transport(&node, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 4];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&buf, b"pong");

    let (path, host, user_agent, x_test) = seen_rx.await.unwrap();
    assert_eq!(path, expected);
    assert_eq!(host.as_deref(), Some("cdn.example.com"));
    assert_eq!(
        user_agent.as_deref(),
        with_headers.then_some("Mozilla/5.0 (X11; Linux x86_64)")
    );
    assert_eq!(x_test.as_deref(), with_headers.then_some("ws-header"));

    server.await.unwrap();
}

#[allow(clippy::result_large_err)]
#[tokio::test]
async fn vmess_json_empty_ws_host_uses_endpoint_in_handshake() {
    use base64::Engine as _;

    let payload = r#"{
            "add": "example.invalid",
            "port": 443,
            "id": "00000000-0000-0000-0000-000000000001",
            "net": "ws",
            "host": "",
            "path": "/ws"
        }"#;
    let link = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(payload),
    );
    let node = Node::from_share_link(&link).unwrap();
    let (client, server) = tokio::io::duplex(4096);
    let receive = async {
        let mut host = None;
        let callback =
            |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
             response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                host = request.headers().get("host").cloned();
                Ok(response)
            };
        let _connection = tokio_tungstenite::accept_hdr_async(server, callback)
            .await
            .unwrap();
        host.unwrap()
    };
    let (stream, host) = tokio::join!(wrap_ws(&node, Box::new(client), false), receive);
    let _stream = stream.unwrap();
    assert_eq!(host, "example.invalid");
}

#[cfg(all(feature = "rprx", feature = "flow-observation"))]
#[tokio::test(start_paused = true)]
async fn websocket_close_waits_for_the_vmess_upload_not_its_response() {
    use crate::proxy::vmess::test_support::UploadPeer;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

    tokio::time::timeout(Duration::from_secs(3), async {
        let (physical, peer) = tokio::io::duplex(512);
        let mut wire = BufReader::new(peer);
        let (vmess, mut codec) = UploadPeer::start(Box::new(physical));
        let mut header = vec![0; UploadPeer::header().len()];
        wire.read_exact(&mut header).await.unwrap();
        assert_eq!(header, UploadPeer::header());
        let ws = WebSocketStream::from_raw_socket(
            Box::new(vmess) as Box<dyn AsyncReadWrite>,
            Role::Client,
            None,
        )
        .await;
        let mut app = ObservedWs::bridge(ws, true).unwrap();
        let payload = Bytes::from(vec![0x5a; 4096]);
        app.write_all(&payload).await.unwrap();
        assert!(!wire.fill_buf().await.unwrap().is_empty());
        let mut close = Box::pin(app.shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut close)
                .await
                .is_err()
        );
        let (result, bytes) = tokio::join!(close, async {
            let mut bytes = Vec::new();
            loop {
                let chunk = codec.read_chunk(&mut wire).await;
                if chunk.is_empty() {
                    return bytes;
                }
                bytes.extend(chunk);
            }
        });
        result.unwrap(); // The peer has not sent a VMess response.
        assert_eq!(bytes.len(), 8 + payload.len() + 6);
        let mut ws =
            WebSocketStream::from_raw_socket(io::Cursor::new(bytes), Role::Server, None).await;
        assert_eq!(ws.next().await.unwrap().unwrap(), Message::Binary(payload));
        assert_eq!(ws.next().await.unwrap().unwrap(), Message::Close(None));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn websocket_close_returns_the_lower_shutdown_error() {
    use tokio::io::{AsyncWrite, DuplexStream, WriteHalf};
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

    #[derive(Debug)]
    struct ResetOnShutdown(WriteHalf<DuplexStream>);
    impl AsyncWrite for ResetOnShutdown {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, data)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from_raw_os_error(libc::ECONNRESET)))
        }
    }
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        for peer_first in [false, true] {
            // Only one byte of the six-byte masked Close fits before the peer reads.
            let (client, peer) = tokio::io::duplex(if peer_first { 1 } else { 4096 });
            let (rd, wr) = tokio::io::split(client);
            let socket: Box<dyn AsyncReadWrite> =
                Box::new(tokio::io::join(rd, ResetOnShutdown(wr)));
            let ws = WebSocketStream::from_raw_socket(socket, Role::Client, None).await;
            let mut app = ObservedWs::bridge(ws, true).unwrap();
            let mut peer = WebSocketStream::from_raw_socket(peer, Role::Server, None).await;
            if peer_first {
                peer.send(Message::Close(None)).await.unwrap();
                peer.get_mut().shutdown().await.unwrap();
                assert_eq!(app.read(&mut [0]).await.unwrap(), 0);
                assert_eq!(peer.next().await.unwrap().unwrap(), Message::Close(None));
                // The bridge has released its carrier before the application closes.
                assert_eq!(peer.get_mut().read(&mut [0]).await.unwrap(), 0);
            }
            for _ in 0..2 {
                assert_eq!(
                    app.shutdown().await.unwrap_err().raw_os_error(),
                    Some(libc::ECONNRESET)
                );
            }
            if !peer_first {
                assert_eq!(peer.next().await.unwrap().unwrap(), Message::Close(None));
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn peer_websocket_close_exposes_eof_while_grpc_upload_is_blocked() {
    use grpc_peer::*;
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (local, mut peer) = tokio::io::duplex(32 * 1024);
        let (release, released) = tokio::sync::oneshot::channel();
        let server = async {
            read_request(&mut peer).await;
            peer.write_all(&frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 1]))
                .await
                .unwrap();
            peer.write_all(&frame(HEADERS, END_HEADERS, 1, &response_headers()))
                .await
                .unwrap();
            peer.write_all(&data(&[0x82, 1, b'!'])).await.unwrap();
            loop {
                let (kind, _, stream, payload) = read_frame(&mut peer).await;
                if kind == DATA && stream == 1 {
                    assert_eq!(
                        payload,
                        [0],
                        "the one-byte window holds the rest of the Gun message"
                    );
                    break;
                }
            }
            peer.write_all(&data(&[0x88, 0])).await.unwrap();
            peer.write_all(&trailers(b"0")).await.unwrap();
            released.await.unwrap();
        };
        let client = async {
            let grpc = wrap_grpc(&grpc_node(), Box::new(local)).await.unwrap();
            let ws = WebSocketStream::from_raw_socket(grpc, Role::Client, None).await;
            let mut app = ObservedWs::bridge(ws, true).unwrap();
            assert_eq!(app.read_u8().await.unwrap(), b'!');
            app.write_all(b"unflushed upload").await.unwrap();
            // No client FIN, connection EOF, or replenishment of the upload window.
            assert_eq!(app.read(&mut [0]).await.unwrap(), 0);
            release.send(()).unwrap();
        };
        tokio::join!(client, server);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn nested_websocket_shutdown_drains_the_last_binary_and_close() {
    use crate::proxy::{TcpOutbound, TunnelDialOptions, trojan::TrojanHandler};
    use crate::runtime::NodeRuntime;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::sync::oneshot;

    async fn read_connect<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        ws: &mut tokio_tungstenite::WebSocketStream<S>,
        suffix: &[u8],
    ) -> Vec<u8> {
        let end = 56 + suffix.len();
        let mut data = Vec::new();
        while data.len() < end {
            let Message::Binary(chunk) = ws.next().await.unwrap().unwrap() else {
                panic!("expected Trojan request bytes");
            };
            data.extend_from_slice(&chunk);
        }
        assert_eq!(&data[56..end], suffix);
        data.split_off(end)
    }

    const TIMEOUT: Duration = Duration::from_secs(5);
    tokio::time::timeout(TIMEOUT, async {
        let (client, peer) = tokio::io::duplex(512);
        let (peer_ready, ready) = oneshot::channel();
        let (first_bytes, writing) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let payload = Bytes::from(vec![0x5a; 4096]);
        let expected = payload.clone();
        let outer_peer = tokio::spawn(async move {
            let mut outer = tokio_tungstenite::accept_async(BufReader::new(peer)).await.unwrap();
            let upgrade_prefix = read_connect(&mut outer, b"\r\n\x01\x01\x7f\0\0\x01\0\x50\r\n").await;
            let (mut frames, stream) = tokio::io::duplex(16 * 1024);
            frames.write_all(&upgrade_prefix).await.unwrap();
            let mut setup = std::pin::pin!(async {
                let mut nested = tokio_tungstenite::accept_async(stream).await.unwrap();
                assert!(read_connect(&mut nested, b"\r\n\x01\x01\xc0\0\x02\x01\0\x50\r\n").await.is_empty());
                nested
            });
            let mut reply = [0; 512];
            let mut nested = loop {
                tokio::select! {
                    ws = &mut setup => break ws,
                    message = outer.next() => {
                        let Message::Binary(data) = message.unwrap().unwrap() else { panic!("expected nested setup bytes"); };
                        frames.write_all(&data).await.unwrap();
                    }
                    n = frames.read(&mut reply) => {
                        let n = n.unwrap();
                        assert_ne!(n, 0, "nested handshake closed");
                        outer.send(Message::Binary(Bytes::copy_from_slice(&reply[..n]))).await.unwrap();
                    }
                }
            };
            let nested_peer = async {
                let mut received = 0;
                loop {
                    match nested.next().await.unwrap().unwrap() {
                        Message::Binary(data) => {
                            let end = received + data.len();
                            assert_eq!(expected.get(received..end), Some(data.as_ref()));
                            received = end;
                        }
                        Message::Close(None) => break,
                        other => panic!("unexpected nested frame {other:?}"),
                    }
                }
                assert_eq!(received, expected.len());
            };
            let forward = async {
                peer_ready.send(()).unwrap();
                assert_eq!(outer.get_mut().fill_buf().await.unwrap()[0], 0x82);
                first_bytes.send(()).unwrap();
                released.await.unwrap();
                loop {
                    match outer.next().await.unwrap().unwrap() {
                        Message::Binary(data) => frames.write_all(&data).await.unwrap(),
                        Message::Close(None) => break,
                        other => panic!("unexpected outer frame {other:?}"),
                    }
                }
            };
            tokio::join!(nested_peer, forward);
        });
        let mut node = transport_node(80);
        node.transport_mut().unwrap().transport = "ws".into();
        node.id = node.derive_id();
        let runtime = NodeRuntime::try_ephemeral(&node).unwrap();
        let entry = TrojanHandler.dial_over(runtime.clone(), Box::new(client),
            "127.0.0.1:80".parse().unwrap(), None, TunnelDialOptions::new(TIMEOUT)).await.unwrap();
        let mut exit = TrojanHandler.dial_over(runtime, entry.stream,
            "192.0.2.1:80".parse().unwrap(), None, TunnelDialOptions::new(TIMEOUT)).await.unwrap();
        ready.await.unwrap();
        exit.stream.write_all(&payload).await.unwrap();
        writing.await.unwrap();
        let mut closing = Box::pin(exit.stream.shutdown());
        assert!(tokio::time::timeout(Duration::from_millis(1), &mut closing).await.is_err(),
            "nested shutdown reported success with a blocked physical frame");
        release.send(()).unwrap();
        closing.await.unwrap();
        drop(exit);
        outer_peer.await.unwrap();
    }).await.unwrap();
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn websocket_request_event_waits_for_real_frame_flush() {
    use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};
    use std::sync::Arc;
    use tokio_tungstenite::tungstenite::protocol::Role;

    for fails in [false, true] {
        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let delivered = Arc::new(tokio::sync::Notify::new());
        let notify = Arc::clone(&delivered);
        let observer = FlowObserver::new(
            FlowContext {
                flow_id: uuid::Uuid::new_v4(),
                generation: 1,
                attempt_id: Some(uuid::Uuid::new_v4()),
                lookup_id: None,
                dns_purpose: "proxy_server",
            },
            Arc::new(move |_, event| {
                captured.lock().push(event);
                notify.notify_one();
            }),
        );
        let (physical, peer) = tokio::io::duplex(64);
        let websocket = tokio_tungstenite::WebSocketStream::from_raw_socket(
            Box::new(physical) as Box<dyn AsyncReadWrite>,
            Role::Client,
            None,
        )
        .await;
        let mut stream = ObservedWs::bridge(websocket, false).unwrap();
        let request = vec![0x5a; 4096];
        observer
            .scope(write_request(&mut stream, &request))
            .await
            .unwrap();
        assert!(
            events.lock().is_empty(),
            "duplex acceptance is not a WebSocket frame flush"
        );
        if fails {
            drop(peer);
            assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
            assert!(
                events.lock().is_empty(),
                "failed frame write cannot confirm a request"
            );
        } else {
            let mut peer =
                tokio_tungstenite::WebSocketStream::from_raw_socket(peer, Role::Server, None).await;
            let message = peer.next().await.unwrap().unwrap();
            assert_eq!(message.into_data().as_ref(), request.as_slice());
            delivered.notified().await;
            assert!(matches!(
                events.lock().as_slice(),
                [FlowEvent::Milestone {
                    milestone: crate::runtime::flow_observation::Milestone::TargetRequestSent
                }]
            ));
            stream.shutdown().await.unwrap();
            drop(stream);
            assert_eq!(peer.next().await.unwrap().unwrap(), Message::Close(None));
        }
    }
}

#[cfg(feature = "flow-observation")]
mod ws_lifetime {
    use super::*;
    use crate::proxy::{ProxyStream, TcpOutbound, TunnelDialOptions};
    use crate::runtime::NodeRuntime;
    use crate::runtime::flow_observation::{
        FlowContext, FlowEvent, FlowObserver, Milestone, without_target_milestones,
    };
    use std::time::Duration;
    use tokio::io::{AsyncWrite, DuplexStream, WriteHalf};
    use tokio::sync::oneshot;

    const TIMEOUT: Duration = Duration::from_secs(5);
    const CONNECT: &[u8] = &[5, 1, 0, 1, 192, 0, 2, 1, 0, 80];

    async fn blocked_connect(
        entry: Arc<NodeRuntime>,
        exit: Arc<NodeRuntime>,
        observer: &FlowObserver,
    ) -> (
        futures_util::future::BoxFuture<'static, anyhow::Result<ProxyStream>>,
        tokio_tungstenite::WebSocketStream<DuplexStream>,
        oneshot::Sender<()>,
    ) {
        let (carrier, peer, blocked, open) =
            crate::proxy::request_observation_support::gated_ws_frame(CONNECT.to_vec());
        let hop = crate::proxy::trojan::TrojanHandler.dial_over(
            entry,
            carrier,
            "127.0.0.1:1080".parse().unwrap(),
            None,
            TunnelDialOptions::new(TIMEOUT),
        );
        let (hop, peer) = tokio::join!(
            observer.scope(async { without_target_milestones(hop).await }),
            tokio_tungstenite::accept_async(peer),
        );
        let hop = hop.unwrap();
        let mut peer = peer.unwrap();
        let header = peer.next().await.unwrap().unwrap().into_data();
        assert_eq!(&header[56..], b"\r\n\x01\x01\x7f\0\0\x01\x04\x38\r\n");

        let mut dial = Box::pin(observer.scope(async move {
            crate::proxy::socks5::Socks5Handler
                .dial_over(
                    exit,
                    hop.stream,
                    "192.0.2.1:80".parse().unwrap(),
                    None,
                    TunnelDialOptions::new(TIMEOUT),
                )
                .await
        }));
        let greet = async {
            assert_eq!(
                peer.next().await.unwrap().unwrap().into_data().as_ref(),
                &[5, 1, 0]
            );
            peer.send(Message::Binary(Bytes::from_static(&[5, 0])))
                .await
                .unwrap();
            blocked.await.unwrap();
        };
        tokio::select! {
            result = &mut dial => panic!("SOCKS dial completed at the closed gate: {result:?}"),
            () = greet => {}
        }
        (dial, peer, open)
    }

    #[tokio::test]
    async fn cancelled_websocket_dial_disposes_of_its_blocked_connect() {
        let generation = Arc::new(crate::runtime::TaskOwner::production());
        let tasks = generation.task_scope();
        tokio::time::timeout(
            TIMEOUT,
            tasks.scope(async {
                let mut node = transport_node(80);
                node.transport_mut().unwrap().transport = "ws".into();
                node.id = node.derive_id();
                let entry = NodeRuntime::try_ephemeral(&node).unwrap();
                let exit = crate::test_support::socks5("exit", "127.0.0.1", 1080);
                let exit = NodeRuntime::try_ephemeral(&exit).unwrap();
                let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
                let captured = Arc::clone(&events);
                let loser = FlowObserver::new(
                    FlowContext {
                        flow_id: uuid::Uuid::new_v4(),
                        generation: 1,
                        attempt_id: Some(uuid::Uuid::new_v4()),
                        lookup_id: None,
                        dns_purpose: "proxy_server",
                    },
                    Arc::new(move |context, event| {
                        if let FlowEvent::Milestone { milestone } = event {
                            captured.lock().push((context, milestone));
                        }
                    }),
                );
                let winner = loser.with_context(FlowContext {
                    attempt_id: Some(uuid::Uuid::new_v4()),
                    ..loser.context()
                });
                let (losing_dial, mut losing_peer, release_loser) =
                    blocked_connect(entry.clone(), exit.clone(), &loser).await;
                let (winning_dial, mut winning_peer, release_winner) =
                    blocked_connect(entry.clone(), exit.clone(), &winner).await;
                assert!(events.lock().is_empty());

                drop(losing_dial);
                // On the current-thread runtime no worker has run since drop.
                let writer_dropped = release_loser.send(()).is_err();
                let mut wire = Vec::new();
                losing_peer.get_mut().read_to_end(&mut wire).await.unwrap();
                assert!(
                    wire.is_empty(),
                    "cancelled attempt sent frame bytes: {wire:?}"
                );
                assert!(writer_dropped, "lower writer outlived cancellation");
                assert!(
                    events.lock().is_empty(),
                    "cancelled CONNECT emitted a milestone"
                );

                release_winner.send(()).unwrap();
                assert_eq!(
                    winning_peer
                        .next()
                        .await
                        .unwrap()
                        .unwrap()
                        .into_data()
                        .as_ref(),
                    CONNECT
                );
                winning_peer
                    .send(Message::Binary(Bytes::from_static(&[
                        5, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                    ])))
                    .await
                    .unwrap();
                let mut tunnel = winning_dial.await.unwrap();
                tunnel.stream.write_all(b"last").await.unwrap();
                tunnel.stream.shutdown().await.unwrap();
                drop(tunnel);
                assert_eq!(
                    winning_peer
                        .next()
                        .await
                        .unwrap()
                        .unwrap()
                        .into_data()
                        .as_ref(),
                    b"last"
                );
                assert_eq!(
                    winning_peer.next().await.unwrap().unwrap(),
                    Message::Close(None)
                );
                assert_eq!(
                    events.lock().as_slice(),
                    &[
                        (winner.context(), Milestone::TargetRequestSent),
                        (winner.context(), Milestone::TargetConfirmed),
                    ]
                );
            }),
        )
        .await
        .unwrap();
        generation.close().await;
        assert!(!generation.has_failed());
    }

    #[derive(Debug)]
    struct PartialFrameWriter {
        lower: WriteHalf<DuplexStream>,
        prefix: Option<oneshot::Sender<()>>,
        pong: Option<oneshot::Sender<()>>,
        release: Option<oneshot::Receiver<()>>,
        blocked: futures_util::task::AtomicWaker,
    }

    impl AsyncWrite for PartialFrameWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.prefix.is_some() {
                // Masked CONNECT, 16 bytes in total. Accept its first half.
                assert_eq!(bytes.len(), 16);
                let n = std::task::ready!(Pin::new(&mut self.lower).poll_write(cx, &bytes[..8]))?;
                assert_eq!(n, 8);
                self.prefix.take().unwrap().send(()).unwrap();
                return Poll::Ready(Ok(n));
            }
            if self.release.is_some() {
                // Ordinary sink retries see only the eight remaining bytes.
                // Receiving the Ping wakes the bridge and tungstenite's reader
                // flushes the suffix together with its newly queued Pong.
                if bytes.len() == 8 {
                    self.blocked.register(cx.waker());
                    return Poll::Pending;
                }
                assert_eq!(&bytes[8..10], &[0x8a, 0x81]);
                if let Some(pong) = self.pong.take() {
                    pong.send(()).unwrap();
                }
                self.blocked.wake();
                if let Some(release) = &mut self.release {
                    std::task::ready!(Pin::new(release).poll(cx)).unwrap();
                }
                self.release = None;
            }
            Pin::new(&mut self.lower).poll_write(cx, bytes)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.lower).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.lower).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn websocket_reader_flushing_a_pong_preserves_the_partial_request() {
        use crate::proxy::request_observation_support::{DeferringCarrier, milestones, observed};
        use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

        for cancel in [false, true] {
            tokio::time::timeout(TIMEOUT, async {
                let (client, wire) = tokio::io::duplex(4096);
                let (read, lower) = tokio::io::split(client);
                let (prefix, partial) = oneshot::channel();
                let (pong, reader_wrote) = oneshot::channel();
                let (open, release) = oneshot::channel();
                let writer = PartialFrameWriter {
                    lower,
                    prefix: Some(prefix),
                    pong: Some(pong),
                    release: Some(release),
                    blocked: futures_util::task::AtomicWaker::new(),
                };
                let (lower, pending) = DeferringCarrier::new(tokio::io::join(read, writer));
                let ws = WebSocketStream::from_raw_socket(
                    Box::new(lower) as Box<dyn AsyncReadWrite>,
                    Role::Client,
                    None,
                )
                .await;
                let mut stream = ObservedWs::bridge(ws, true).unwrap();
                let mut peer = WebSocketStream::from_raw_socket(wire, Role::Server, None).await;
                let (observer, events) = observed();
                observer
                    .scope(write_request(&mut stream, CONNECT))
                    .await
                    .unwrap();
                partial.await.unwrap();
                let (prefix_request, prefix_end) = pending.lock().take().unwrap();
                prefix_request.confirm();
                assert!(events.lock().is_empty());

                let ping = Bytes::from_static(b"?");
                let mut open = Some(open);
                if !cancel {
                    open.take().unwrap().send(()).unwrap();
                }
                peer.send(Message::Ping(ping.clone())).await.unwrap();
                reader_wrote.await.unwrap();
                if let Some(open) = open {
                    drop(stream);
                    let _ = open.send(());
                    let mut transmitted = Vec::new();
                    peer.get_mut().read_to_end(&mut transmitted).await.unwrap();
                    assert_eq!(transmitted.len(), prefix_end as usize);
                    assert!(events.lock().is_empty());
                    return;
                }

                assert_eq!(
                    peer.next().await.unwrap().unwrap().into_data().as_ref(),
                    CONNECT
                );
                assert_eq!(peer.next().await.unwrap().unwrap(), Message::Pong(ping));
                // A later unobserved frame proves the preceding sink send has
                // finished even while its lower delivery receipt is outstanding.
                stream.write_all(b"next").await.unwrap();
                assert_eq!(
                    peer.next().await.unwrap().unwrap().into_data().as_ref(),
                    b"next"
                );
                assert!(
                    events.lock().is_empty(),
                    "prefix receipt covered an unconfirmed suffix"
                );
                let (request, end) = pending
                    .lock()
                    .take()
                    .expect("reader omitted the request from the suffix");
                assert!(end >= 16);
                request.confirm();
                assert_eq!(milestones(&events.lock(), Milestone::TargetRequestSent), 1);
            })
            .await
            .unwrap();
        }
    }
}

/// A CDN-fronted node names the edge IP as its address and the distribution
/// only in the WebSocket `Host` header; SNI must follow the header or the
/// edge answers with a certificate that cannot match the address.
#[test]
fn ws_tls_server_name_prefers_the_host_header() {
    let mut node = transport_node(443);
    node.tls_mut().unwrap().enabled = true;
    node.transport_mut().unwrap().transport = "ws".into();
    assert_eq!(node.tls_server_name(), "127.0.0.1");

    node.transport_mut().unwrap().ws_host = Some("cdn.example".into());
    assert_eq!(node.tls_server_name(), "cdn.example");

    node.transport_mut().unwrap().ws_host = Some("cdn.example:8443".into());
    assert_eq!(node.tls_server_name(), "cdn.example");

    node.transport_mut().unwrap().ws_host = Some("[2001:db8::1]:8443".into());
    assert_eq!(node.tls_server_name(), "2001:db8::1");

    node.transport_mut().unwrap().ws_host = Some(String::new());
    assert_eq!(node.tls_server_name(), "127.0.0.1");

    node.tls_mut().unwrap().sni = Some("sni.example".into());
    assert_eq!(node.tls_server_name(), "sni.example");

    node.tls_mut().unwrap().sni = None;
    node.transport_mut().unwrap().transport = "grpc".into();
    node.transport_mut().unwrap().ws_host = Some("cdn.example".into());
    assert_eq!(node.tls_server_name(), "127.0.0.1");
}
