use super::*;
use crate::runtime::OutboundRuntimeRegistry;

#[tokio::test]
async fn concurrent_one_stream_opens_keep_the_first_upload_live_until_drop() {
    for mode in [XhttpMode::PacketUp, XhttpMode::StreamUp] {
        tokio::time::timeout(DEADLINE, async {
            let mut peer = Peer::with_stream_limit(32, 1).await;
            let owner = peer.runtime(mode, 32);
            let runtime = owner.runtime();
            let (opened, mut streams) = mpsc::channel(2);
            let mut clients = JoinSet::new();
            for _ in 0..2 {
                let runtime = runtime.clone();
                let opened = opened.clone();
                clients.spawn(async move {
                    let stream = open(&runtime).await;
                    opened
                        .send(stream)
                        .await
                        .unwrap_or_else(|_| panic!("stream receiver disappeared"));
                });
            }
            drop(opened);
            let mut first = streams
                .recv()
                .await
                .expect("neither concurrent open completed");
            let mut first_get = peer.next().await;
            assert_eq!(first_get.request.method(), http::Method::GET);
            let first_path = session_path(&first_get.request);
            let mut streaming = if mode == XhttpMode::StreamUp {
                Some(peer.next().await)
            } else {
                None
            };
            if let Some(upload) = &streaming {
                assert_eq!(upload.request.method(), http::Method::POST);
                assert_eq!(upload.request.uri().path(), first_path);
                assert_ne!(upload.carrier, first_get.carrier);
            }
            for (seq, payload) in [b"one", b"two"].into_iter().enumerate() {
                first.write_all(payload).await.unwrap();
                let server = async {
                    if let Some(upload) = &mut streaming {
                        assert_eq!(
                            receive(upload.request.body_mut(), payload.len()).await,
                            payload
                        );
                    } else {
                        let mut upload = peer.next().await;
                        assert_eq!(
                            upload.request.method(),
                            http::Method::POST,
                            "a competing GET took the first flow's upload carrier"
                        );
                        assert_eq!(upload.request.uri().path(), format!("{first_path}/{seq}"));
                        assert_eq!(
                            receive(upload.request.body_mut(), payload.len()).await,
                            payload
                        );
                        eof(upload.request.body_mut()).await;
                        response(&mut upload.respond, 200, true);
                    }
                };
                let ((), flushed) = tokio::join!(server, first.flush());
                flushed.unwrap();
            }
            assert!(
                streams.try_recv().is_err(),
                "two complete flows exceeded two one-stream carriers"
            );
            drop(first);
            assert_eq!(
                poll_fn(|cx| first_get.respond.poll_reset(cx))
                    .await
                    .unwrap(),
                h2::Reason::CANCEL
            );
            if let Some(upload) = &mut streaming {
                assert_eq!(
                    poll_fn(|cx| upload.respond.poll_reset(cx)).await.unwrap(),
                    h2::Reason::CANCEL
                );
            }
            let mut second = streams
                .recv()
                .await
                .expect("waiting logical open was lost after first drop");
            let mut second_get = peer.next().await;
            assert_eq!(second_get.request.method(), http::Method::GET);
            let second_path = session_path(&second_get.request);
            assert_ne!(second_path, first_path);
            let server = async {
                let mut upload = peer.next().await;
                assert_eq!(upload.request.method(), http::Method::POST);
                assert_eq!(
                    upload.request.uri().path(),
                    if mode == XhttpMode::PacketUp {
                        format!("{second_path}/0")
                    } else {
                        second_path.clone()
                    }
                );
                assert_eq!(receive(upload.request.body_mut(), 3).await, b"new");
                eof(upload.request.body_mut()).await;
                response(&mut upload.respond, 200, true);
                let mut reply = response(&mut second_get.respond, 200, false);
                send(&mut reply, Bytes::from_static(b"second-progress"), true).await;
            };
            let client = async {
                second.write_all(b"new").await.unwrap();
                second.flush().await.unwrap();
                second.shutdown().await.unwrap();
                let mut reply = Vec::new();
                second.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"second-progress");
            };
            tokio::join!(server, client);
            assert_eq!(runtime.xhttp.as_ref().unwrap().pool.live_session_count(), 2);
            drop(second);
            wait_released(&runtime).await;
            while let Some(result) = clients.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("concurrent one-stream {mode:?} flows stranded GET/upload admission")
        });
    }
}

#[tokio::test]
async fn generation_retirement_between_posts_keeps_admitted_packet_flow_usable() {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = Peer::new(32).await;
        let template = peer.runtime(XhttpMode::PacketUp, 32);
        let node = (*template.runtime().node).clone();
        drop(template);
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap());
        let runtime = generation.get(&node.id).unwrap();
        let mut stream = open(&runtime).await;
        let mut download = peer.next().await;
        let path = session_path(&download.request);
        for (seq, payload) in [b"before", b"after!"].into_iter().enumerate() {
            if seq == 1 {
                generation.retire_reusable_state().await;
                assert!(generation.is_shutdown());
                assert!(
                    runtime
                        .xhttp
                        .as_ref()
                        .unwrap()
                        .open(&runtime, None, DEADLINE)
                        .await
                        .is_err(),
                    "retired generation admitted a new logical flow"
                );
            }
            stream.write_all(payload).await.unwrap();
            let server = async {
                let mut upload = peer.next().await;
                assert_eq!(upload.request.method(), http::Method::POST);
                assert_eq!(upload.request.uri().path(), format!("{path}/{seq}"));
                assert_eq!(
                    receive(upload.request.body_mut(), payload.len()).await,
                    payload
                );
                eof(upload.request.body_mut()).await;
                response(&mut upload.respond, 200, true);
            };
            let ((), flushed) = tokio::join!(server, stream.flush());
            flushed.unwrap();
        }
        stream.shutdown().await.unwrap();
        let mut reply = response(&mut download.respond, 200, false);
        send(
            &mut reply,
            Bytes::from_static(b"retired-but-admitted"),
            true,
        )
        .await;
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"retired-but-admitted");
        assert!(
            peer.requests.try_recv().is_err(),
            "retirement replayed the admitted flow"
        );
        drop(stream);
        wait_released(&runtime).await;
        generation.shutdown().await;
    })
    .await
    .expect("runtime retirement cut off an admitted packet-up flow");
}

fn stalled_tls_node(address: std::net::SocketAddr) -> Node {
    let mut node = Node {
        name: "xhttp-stalled-tls".into(),
        address: address.ip().to_string(),
        port: address.port(),
        outbound: OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            tls: honk_config::node::TlsOptions {
                enabled: true,
                sni: Some("localhost".into()),
                skip_cert_verify: true,
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    let transport = node.transport_mut().unwrap();
    transport.transport = "xhttp".into();
    transport.xhttp = Some(XhttpOptions {
        mode: XhttpMode::StreamOne,
        ..Default::default()
    });
    node.normalize_stream_transport().unwrap();
    node.id = node.derive_id();
    node
}

async fn client_hello(tcp: &mut TcpStream) {
    let mut header = [0; 5];
    tcp.read_exact(&mut header).await.unwrap();
    assert_eq!(
        header[0], 22,
        "ordinary TLS setup must send a handshake record"
    );
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0; length];
    tcp.read_exact(&mut body).await.unwrap();
    assert_eq!(
        body.first(),
        Some(&1),
        "silent peer must stall a real ClientHello"
    );
}

async fn socket_closed(tcp: &mut TcpStream) {
    tokio::time::timeout(Duration::from_millis(500), async {
        let mut remainder = Vec::new();
        match tcp.read_to_end(&mut remainder).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("unexpected teardown read error: {error}"),
        }
    })
    .await
    .expect("cancelled/timed-out TLS setup retained its physical socket");
}

fn physical_gate() -> OutboundRuntimeRegistry {
    OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 1, 1, 1, None)
        .unwrap()
        .0
}

#[tokio::test]
async fn ordinary_tls_setup_deadline_releases_carrier_and_allows_another_physical_dial() {
    tokio::time::timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node = stalled_tls_node(listener.local_addr().unwrap());
        let owner = NodeRuntime::try_ephemeral_guarded(&node).unwrap();
        let runtime = owner.runtime();
        let gate = Arc::new(physical_gate());
        for attempt in 0..2 {
            if attempt != 0 {
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(3)).await;
                tokio::time::resume();
            }
            let mut clients = JoinSet::new();
            let runtime_owner = runtime.clone();
            let scoped_gate = gate.clone();
            clients.spawn(async move {
                scoped_gate
                    .scope_dials(runtime_owner.xhttp.as_ref().unwrap().open(
                        &runtime_owner,
                        None,
                        Duration::from_millis(100),
                    ))
                    .await
            });
            let (mut tcp, _) = listener.accept().await.unwrap();
            client_hello(&mut tcp).await;
            let result = clients.join_next().await.unwrap().unwrap();
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("silent TLS peer completed setup"),
            };
            assert!(
                error.chain().any(|cause| cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)),
                "setup must retain its factual timeout: {error:#}"
            );
            socket_closed(&mut tcp).await;
            assert_eq!(runtime.xhttp.as_ref().unwrap().pool.live_session_count(), 0);
            assert_eq!(runtime.xhttp.as_ref().unwrap().pool.metrics().streams, 0);
            let permit =
                tokio::time::timeout(Duration::from_millis(500), gate.acquire_dial_permit())
                    .await
                    .expect("TLS setup timeout retained physical admission");
            drop(permit);
        }
    })
    .await
    .expect("ordinary TLS establishment survived its deadline or poisoned the next dial");
}

#[tokio::test]
async fn cancelling_guarded_tls_setup_closes_pending_driver_and_releases_physical_admission() {
    tokio::time::timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node = stalled_tls_node(listener.local_addr().unwrap());
        let owner = NodeRuntime::try_ephemeral_guarded(&node).unwrap();
        let runtime = owner.runtime();
        let gate = Arc::new(physical_gate());
        let mut clients = JoinSet::new();
        let runtime_owner = runtime.clone();
        let scoped_gate = gate.clone();
        clients.spawn(async move {
            scoped_gate
                .scope_dials(runtime_owner.xhttp.as_ref().unwrap().open(
                    &runtime_owner,
                    None,
                    DEADLINE,
                ))
                .await
        });
        let (mut tcp, _) = listener.accept().await.unwrap();
        client_hello(&mut tcp).await;
        clients.abort_all();
        while let Some(result) = clients.join_next().await {
            assert!(result.unwrap_err().is_cancelled());
        }
        drop(owner);
        socket_closed(&mut tcp).await;
        assert!(runtime.xhttp.as_ref().unwrap().pool.is_retired());
        assert_eq!(runtime.xhttp.as_ref().unwrap().pool.live_session_count(), 0);
        let permit = tokio::time::timeout(Duration::from_millis(500), gate.acquire_dial_permit())
            .await
            .expect("cancelled guarded TLS setup retained physical admission");
        drop(permit);
    })
    .await
    .expect("guarded TLS cancellation left a pool-owned establishment alive");
}
