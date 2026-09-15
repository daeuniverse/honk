use super::*;

#[tokio::test]
async fn cancelled_mux_warm_dial_does_not_outlive_its_caller() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut node = Node {
        name: "vless-h2mux-cancel".into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        ..configured_vless_node(
            "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3",
            honk_config::node::VlessUdpEncoding::Auto,
            honk_config::node::VlessMultiplex::H2 { padding: false },
        )
    };
    node.id = node.derive_id();
    let guard = crate::runtime::NodeRuntime::try_ephemeral_guarded(&node).unwrap();
    let runtime = guard.runtime();
    let pool = Arc::new(crate::session::SessionPool::new(
        super::super::vless_mux::session_pool_config(),
    ));
    let warming = {
        let pool = Arc::clone(&pool);
        tokio::spawn(VLessHandler::warm_mux_pool(
            pool,
            move || VLessHandler::dial_h2_session(runtime, std::time::Duration::from_secs(3)),
            "retired",
        ))
    };
    let (accepted, _) = listener.accept().await.unwrap();
    warming.abort();
    assert!(warming.await.unwrap_err().is_cancelled());

    let checkout = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        pool.checkout_speculative(),
    )
    .await
    .expect("cancelled warm dial retained the pool reservation")
    .unwrap();
    assert!(matches!(checkout, SpeculativeCheckout::Detached(_)));
    drop(accepted);
    pool.shutdown();
}

#[tokio::test]
async fn cancelled_encrypted_ws_handshake_retains_credit_until_bridge_teardown() {
    use futures_util::StreamExt as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (hello_tx, hello_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let hello = ws.next().await.unwrap().unwrap();
        assert!(!hello.into_data().is_empty());
        hello_tx.send(()).unwrap();
        while ws.next().await.is_some() {}
    });

    let mut node = configured_vless_node(
        "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3",
        honk_config::node::VlessUdpEncoding::Auto,
        honk_config::node::VlessMultiplex::Off,
    );
    node.name = "vless-encrypted-ws-cancel".into();
    node.address = format!("127.0.0.1:{port}");
    node.host = "127.0.0.1".into();
    node.port = port;
    let vless = node.vless_mut().unwrap();
    vless.transport.transport = "ws".into();
    vless.encryption = Some(
        "mlkem768x25519plus.native.1rtt.100-35-35.BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
            .into(),
    );
    node.id = node.derive_id();
    let generation = crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        std::slice::from_ref(&node),
        1,
        1,
        1,
        None,
    )
    .unwrap()
    .0;
    let runtime = generation.get(&node.id).unwrap();
    let handler = VLessHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let mut dial = Box::pin(handler.dial_retained_base(
        &runtime,
        target,
        None,
        std::time::Duration::from_secs(3),
    ));
    tokio::select! {
        result = &mut dial => panic!("encrypted handshake completed before cancellation: {result:?}"),
        result = hello_rx => result.unwrap(),
    }
    drop(dial);

    let error = runtime.acquire_vless_carrier().unwrap_err();
    assert!(matches!(
        error.downcast_ref::<super::super::PacketRejection>(),
        Some(super::super::PacketRejection::Capacity)
    ));
    let reclaimed = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Ok(permit) = runtime.acquire_vless_carrier() {
                break permit;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("WebSocket bridge teardown must return its carrier credit");
    drop(reclaimed);
    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("WebSocket peer did not observe bridge teardown")
        .unwrap();
    generation.shutdown().await;
}

#[tokio::test]
async fn h2mux_tcp_and_udp_share_one_vless_carrier() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = [0; 23];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[18], CMD_TCP);
        assert_eq!(&head[19..21], &444u16.to_be_bytes());
        assert_eq!(head[21], ATYP_DOMAIN);
        let mut domain = vec![0; head[22] as usize];
        stream.read_exact(&mut domain).await.unwrap();
        assert_eq!(domain, b"sp.mux.sing-box.arpa");
        stream.write_all(&[0, 0]).await.unwrap();
        let mut mux = [0; 2];
        stream.read_exact(&mut mux).await.unwrap();
        assert_eq!(mux, [0, 2]);

        let mut connection = h2::server::handshake(stream).await.unwrap();
        let mut handlers = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            handlers.spawn(async move {
                assert_eq!(request.method(), http::Method::CONNECT);
                assert_eq!(request.uri().authority().unwrap().as_str(), "localhost");
                let mut send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let mut recv = request.into_body();
                let mut body = bytes::BytesMut::new();
                while body.len() < 9 {
                    let data = recv.data().await.unwrap().unwrap();
                    let size = data.len();
                    body.extend_from_slice(&data);
                    recv.flow_control().release_capacity(size).unwrap();
                }
                match u16::from_be_bytes([body[0], body[1]]) {
                    0 => {
                        assert_eq!(&body[2..9], &[1, 93, 184, 216, 34, 1, 187]);
                        send.send_data(bytes::Bytes::from_static(b"\0hello"), false)
                            .unwrap();
                        while body.len() < 13 {
                            let data = recv.data().await.unwrap().unwrap();
                            let size = data.len();
                            body.extend_from_slice(&data);
                            recv.flow_control().release_capacity(size).unwrap();
                        }
                        assert_eq!(&body[9..13], b"ping");
                        send.send_data(bytes::Bytes::from_static(b"pong"), true)
                            .unwrap();
                    }
                    1 => {
                        assert_eq!(&body[2..9], &[1, 8, 8, 8, 8, 0, 53]);
                        while body.len() < 14 {
                            let data = recv.data().await.unwrap().unwrap();
                            let size = data.len();
                            body.extend_from_slice(&data);
                            recv.flow_control().release_capacity(size).unwrap();
                        }
                        assert_eq!(&body[9..14], b"\0\x03dns");
                        let packet = super::super::uot::encode_packet(
                            b"answer",
                            super::super::uot::MAX_PACKET_SIZE,
                        )
                        .unwrap();
                        let mut response = bytes::BytesMut::with_capacity(1 + packet.len());
                        response.extend_from_slice(&[0]);
                        response.extend_from_slice(&packet);
                        send.send_data(response.freeze(), true).unwrap();
                    }
                    flags => panic!("unexpected mux flags {flags}"),
                }
            });
        }
        while !handlers.is_empty() {
            tokio::select! {
                result = handlers.join_next() => result.unwrap().unwrap(),
                stream = connection.accept() => assert!(stream.is_none()),
            }
        }
        while connection.accept().await.is_some() {}
    });

    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "vless-h2mux".into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        ..configured_vless_node(
            "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3",
            honk_config::node::VlessUdpEncoding::Auto,
            honk_config::node::VlessMultiplex::H2 { padding: false },
        )
    };
    let mut node = node;
    node.id = node.derive_id();
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            std::slice::from_ref(&node),
            8,
            8,
            1,
            None,
        )
        .unwrap()
        .0,
    );
    let registry = super::super::ProxyRegistry::default_resolver().unwrap();
    assert_eq!(
        registry
            .warm_session(
                Arc::clone(&generation),
                node.id,
                std::time::Duration::from_secs(3),
            )
            .await
            .unwrap(),
        super::super::WarmOutcome::Ready
    );
    assert_eq!(
        registry
            .warm_udp(
                Arc::clone(&generation),
                node.id,
                std::time::Duration::from_secs(3),
            )
            .await
            .unwrap(),
        super::super::WarmOutcome::Ready
    );
    let runtime = generation.get(&node.id).unwrap();
    let pool = runtime.vless_h2_pool().unwrap();
    assert_eq!(pool.live_session_count(), 1);
    assert!(matches!(
        runtime
            .acquire_vless_carrier()
            .unwrap_err()
            .downcast_ref::<super::super::PacketRejection>(),
        Some(super::super::PacketRejection::Capacity)
    ));
    let (replacement, moved) =
        crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            std::slice::from_ref(&node),
            8,
            8,
            1,
            Some(&generation),
        )
        .unwrap();
    assert!(moved.contains(&node.id));
    let replacement = Arc::new(replacement);
    generation.mark_moved_out(moved);
    generation.retire_reusable_state().await;
    generation.shutdown().await;
    assert_eq!(pool.live_session_count(), 1);
    let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let mut tcp = registry
        .dial_runtime(
            Arc::clone(&replacement),
            node.id,
            target,
            None,
            std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
    let mut greeting = [0; 5];
    tcp.stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"hello");
    tcp.stream.write_all(b"ping").await.unwrap();
    let mut pong = [0; 4];
    tcp.stream.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");

    let udp_target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let udp = registry
        .dial_udp_transport_runtime(
            Arc::clone(&replacement),
            node.id,
            udp_target,
            None,
            std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
    udp.send_packet_confirmed(b"dns").await.unwrap();
    let mut answer = [0; 16];
    assert_eq!(udp.recv_packet(&mut answer).await.unwrap(), (6, udp_target));
    assert_eq!(&answer[..6], b"answer");
    assert_eq!(pool.live_session_count(), 1);

    drop(udp);
    drop(tcp);
    runtime
        .release_warm(crate::runtime::WarmRetention::Selector)
        .await;
    assert!(pool.is_warm_retained());
    runtime
        .release_warm(crate::runtime::WarmRetention::Udp)
        .await;
    assert!(!pool.is_warm_retained());
    assert_eq!(pool.live_session_count(), 0);
    replacement.shutdown().await;
    let released = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Ok(permit) = runtime.acquire_vless_carrier() {
                break permit;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("carrier permit must live through and release after task teardown");
    drop(released);
    server.await.unwrap();
}

#[tokio::test]
async fn cool_c8_opens_seventeen_tcp_children_on_three_global_carriers() {
    use super::super::MuxSession as _;
    let node = cool_node("vless-cool-budget");
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            std::slice::from_ref(&node),
            8,
            8,
            3,
            None,
        )
        .unwrap()
        .0,
    );
    let runtime = generation.get(&node.id).unwrap();
    let pool = runtime.vless_shared_cool_pool().unwrap();
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let wires = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let dial = {
        let runtime = Arc::clone(&runtime);
        let dials = Arc::clone(&dials);
        let wires = Arc::clone(&wires);
        move || {
            let runtime = Arc::clone(&runtime);
            let dials = Arc::clone(&dials);
            let wires = Arc::clone(&wires);
            async move {
                let permit = runtime.acquire_vless_carrier()?;
                let (client, wire) = tokio::io::duplex(1 << 16);
                wires.lock().push(wire);
                dials.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                let carrier = RuntimeOwnedIo {
                    inner: Box::new(client),
                    _owner: permit,
                };
                Ok(super::super::vless_cool::connect(Box::new(carrier), 8))
            }
        }
    };
    let streams = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let mut streams = Vec::new();
        for port in 1_u16..=17 {
            let target = SocketAddr::from(([127, 0, 0, 1], port));
            streams.push(
                pool.open_with(dial.clone(), move |session, permit| async move {
                    session.open_stream(permit, target, None).await
                })
                .await
                .unwrap(),
            );
        }
        streams
    })
    .await
    .expect("the seventeenth child must dial a third carrier, not wait for capacity");

    assert_eq!(dials.load(std::sync::atomic::Ordering::Acquire), 3);
    assert_eq!(pool.live_session_count(), 3);
    assert!(matches!(
        runtime
            .acquire_vless_carrier()
            .unwrap_err()
            .downcast_ref::<super::super::PacketRejection>(),
        Some(super::super::PacketRejection::Capacity)
    ));

    drop(streams);
    generation.shutdown().await;
}

#[tokio::test]
async fn idle_reap_returns_carrier_credit_without_cutting_retained_or_active_sessions() {
    use crate::session::ManagedSession as _;

    let mut nodes = [
        cool_node("vless-idle-carrier"),
        cool_node("vless-retained-carrier"),
        cool_node("vless-active-carrier"),
    ];
    for (index, node) in nodes.iter_mut().enumerate() {
        node.port = 10 + index as u16;
        node.address = format!("127.0.0.1:{}", node.port);
        node.id = node.derive_id();
    }
    let registry = crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        &nodes, 8, 8, 3, None,
    )
    .unwrap()
    .0;
    let runtimes: Vec<_> = nodes
        .iter()
        .map(|node| registry.get(&node.id).unwrap())
        .collect();
    let pools: Vec<_> = runtimes
        .iter()
        .map(|runtime| runtime.vless_shared_cool_pool().unwrap())
        .collect();
    let mut peers = Vec::new();
    let mut sessions = Vec::new();
    for (runtime, pool) in runtimes.iter().zip(&pools) {
        let permit = runtime.acquire_vless_carrier().unwrap();
        let (client, peer) = tokio::io::duplex(1 << 16);
        let session = super::super::vless_cool::connect(
            Box::new(RuntimeOwnedIo {
                inner: Box::new(client),
                _owner: permit,
            }),
            8,
        );
        pool.insert(&session);
        peers.push(peer);
        sessions.push(session);
    }
    pools[1].set_warm_retained(true);
    let active_child = sessions[2].try_reserve().unwrap();

    assert_eq!(registry.reap_idle_resources(std::time::Instant::now()), 1);
    assert!(sessions[0].is_closed());
    assert!(!sessions[1].is_closed());
    assert!(!sessions[2].is_closed());
    let reclaimed = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Ok(permit) = runtimes[0].acquire_vless_carrier() {
                break permit;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("idle carrier teardown must return its lifetime credit");
    let error = runtimes[0].acquire_vless_carrier().unwrap_err();
    assert!(matches!(
        error.downcast_ref::<super::PacketRejection>(),
        Some(super::PacketRejection::Capacity)
    ));

    drop(reclaimed);
    drop(active_child);
    drop(peers);
    registry.shutdown().await;
}

#[tokio::test]
async fn idle_reap_preserves_warm_replacement_while_old_carrier_drains() {
    use super::super::MuxSession as _;
    use crate::session::ManagedSession as _;

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let pool =
            crate::session::SessionPool::new(super::super::vless_cool::session_pool_config(8));
        let (client, mut old_peer) = tokio::io::duplex(1 << 16);
        let old = super::super::vless_cool::connect(Box::new(client), 8);
        pool.insert(&old);
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let mut old_child = pool
            .open_with(
                || async { anyhow::bail!("the existing carrier must be reused") },
                |session, permit| async move { session.open_stream(permit, target, None).await },
            )
            .await
            .unwrap();
        old.begin_drain();

        let (client, mut replacement_peer) = tokio::io::duplex(1 << 16);
        let replacement = super::super::vless_cool::connect(Box::new(client), 8);
        pool.insert(&replacement);
        pool.set_warm_retained(true);
        assert_eq!(pool.reap_unretained_idle(), 0);

        let mut new_child = pool
            .open_with(
                || async { anyhow::bail!("warm replacement must avoid redial") },
                |session, permit| async move { session.open_stream(permit, target, None).await },
            )
            .await
            .unwrap();
        // Independent KEEP/DATA replies on SID 1 prove both physical carriers still serve children.
        old_peer
            .write_all(b"\x00\x04\x00\x01\x02\x01\x00\x03old")
            .await
            .unwrap();
        replacement_peer
            .write_all(b"\x00\x04\x00\x01\x02\x01\x00\x03new")
            .await
            .unwrap();
        let mut output = [0; 3];
        old_child.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"old");
        new_child.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"new");

        drop(old_child);
        drop(new_child);
        pool.shutdown();
    })
    .await
    .expect("retained replacement admission or old-child delivery stalled");
}
