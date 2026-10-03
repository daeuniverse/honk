use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod grpc_headers;
mod grpc_io;
mod grpc_peer;

fn transport_node(port: u16) -> Node {
    Node {
        name: "transport-node".into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
        ..Default::default()
    }
}

/// WebSocket transport: the mock server verifies the upgrade request
/// (path + Host header) and echoes one binary message.
// The accept callback's Result type (and its large Err variant) is
// dictated by tungstenite's `Callback` trait.
#[allow(clippy::result_large_err)]
#[tokio::test]
async fn test_ws_transport_roundtrip() {
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
                let host = req
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                if let Some(tx) = seen_tx.take() {
                    let _ = tx.send((req.uri().path().to_string(), host));
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
    transport.ws_path = Some("/ws-path".into());
    transport.ws_host = Some("cdn.example.com".into());

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

    let (path, host) = seen_rx.await.unwrap();
    assert_eq!(path, "/ws-path");
    assert_eq!(host.as_deref(), Some("cdn.example.com"));

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
    let (stream, host) = tokio::join!(wrap_ws(&node, Box::new(client)), receive);
    let _stream = stream.unwrap();
    assert_eq!(host, "example.invalid");
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
        let (client, server) = tokio::io::duplex(65536);
        let progress = Arc::new(parking_lot::Mutex::new(WsWriteProgress::default()));
        let bridge = tokio::spawn(ws_bridge_relay(
            websocket,
            server,
            Some(Arc::clone(&progress)),
        ));
        let mut stream = ObservedWs {
            inner: client,
            progress,
        };
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
            bridge.await.unwrap();
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
            bridge.abort();
            assert!(bridge.await.unwrap_err().is_cancelled());
        }
    }
}
