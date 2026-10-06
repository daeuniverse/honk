use super::*;
use crate::proxy::WarmRequirement;

fn xhttp_node(protocol: NodeProtocol) -> Node {
    let mut node = node("xhttp", protocol);
    let transport = node.transport_mut().unwrap();
    transport.transport = "xhttp".into();
    transport.xhttp = Some(Default::default());
    node.tls_mut().unwrap().alpn = vec!["h2".into()];
    node.id = node.derive_id();
    node
}

#[tokio::test]
async fn xhttp_ownership_survives_reload_but_dns_and_ephemeral_are_independent() {
    for protocol in [
        NodeProtocol::Trojan,
        NodeProtocol::VMess,
        NodeProtocol::VLess,
    ] {
        let node = xhttp_node(protocol);
        let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let runtime = first.get(&node.id).unwrap();
        let xhttp = runtime.xhttp.as_ref().unwrap();
        assert_eq!(runtime.warm_counts(), WarmCounts::default());
        assert!(!runtime.is_warm_or_stateless_for(WarmRequirement::Session));
        assert!(!xhttp.pool.is_warm_retained());

        let cancelled = runtime.retain_warm(WarmRetention::Selector).await;
        assert!(xhttp.pool.is_warm_retained());
        drop(cancelled);
        assert!(!xhttp.pool.is_warm_retained());
        runtime.retain_warm(WarmRetention::Selector).await.commit();
        runtime.retain_warm(WarmRetention::Udp).await.commit();
        runtime.release_warm(WarmRetention::Selector).await;
        assert!(xhttp.pool.is_warm_retained());
        runtime.release_warm(WarmRetention::Udp).await;
        assert!(!xhttp.pool.is_warm_retained());

        let dns = first.fork_for_dns().unwrap();
        let dns_runtime = dns.get(&node.id).unwrap();
        let dns_xhttp = dns_runtime.xhttp.as_ref().unwrap();
        assert!(!Arc::ptr_eq(xhttp, dns_xhttp));
        let owner = NodeRuntime::try_ephemeral_guarded(&node).unwrap();
        let ephemeral = owner.runtime();
        assert!(!Arc::ptr_eq(xhttp, ephemeral.xhttp.as_ref().unwrap()));
        drop(owner);
        assert!(ephemeral.xhttp.as_ref().unwrap().pool.is_retired());
        assert!(!xhttp.pool.is_retired());

        let (successor, moved) =
            OutboundRuntimeRegistry::build_reusing(std::slice::from_ref(&node), 1, Some(&first))
                .unwrap();
        assert!(Arc::ptr_eq(&runtime, &successor.get(&node.id).unwrap()));
        first.mark_moved_out(moved);
        first.retire_reusable_state().await;
        first.shutdown().await;
        assert!(!xhttp.pool.is_retired());
        dns.retire_reusable_state().await;
        assert!(dns_xhttp.pool.is_retired());
        assert!(!xhttp.pool.is_retired());
        successor.retire_reusable_state().await;
        assert!(xhttp.pool.is_retired());
        assert!(xhttp.pool.checkout_speculative().await.is_err());
        successor.shutdown().await;
        dns.shutdown().await;
    }
}

#[tokio::test]
async fn xhttp_physical_warm_retention_maintenance_and_shutdown() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (established, mut handshakes) = tokio::sync::mpsc::channel(8);
    let peer = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (tcp, _) = accepted.unwrap();
                    let established = established.clone();
                    connections.spawn(async move {
                        if let Ok(mut connection) = h2::server::handshake(tcp).await {
                            let _ = established.send(()).await;
                            if let Some(Ok(_)) = connection.accept().await {
                                panic!("physical XHTTP warming must not send a logical request");
                            }
                        }
                    });
                }
                finished = connections.join_next(), if !connections.is_empty() => {
                    finished.unwrap().unwrap();
                }
            }
        }
    });
    let mut node = xhttp_node(NodeProtocol::VLess);
    node.host = address.ip().to_string();
    node.port = address.port();
    node.address = address.to_string();
    node.id = node.derive_id();
    let (registry, _) = OutboundRuntimeRegistry::build_reusing_with_admission(
        std::slice::from_ref(&node),
        1,
        Arc::new(tokio::sync::Semaphore::new(1)),
        1,
        Arc::new(tokio::sync::Semaphore::new(4)),
        None,
    )
    .unwrap();
    let runtime = registry.get(&node.id).unwrap();
    let carriers = runtime.vless_carriers.available_permits();
    runtime.retain_warm(WarmRetention::Selector).await.commit();
    for attempt in 0..2 {
        tokio::time::timeout(
            Duration::from_secs(3),
            crate::proxy::transport::xhttp::XhttpRuntime::warm(&runtime, Duration::from_secs(2)),
        )
        .await
        .unwrap()
        .unwrap();
        if attempt == 0 {
            tokio::time::timeout(Duration::from_secs(3), handshakes.recv())
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(runtime.warm_counts().sessions, 1);
        assert_eq!(runtime.vless_carriers.available_permits(), carriers - 1);
        assert!(runtime.is_warm_or_stateless_for(WarmRequirement::Session));
        assert_eq!(registry.reap_idle_resources(Instant::now()), 0);
    }
    runtime.release_warm(WarmRetention::Selector).await;
    assert_eq!(runtime.warm_counts().sessions, 0);
    assert!(!runtime.is_warm_or_stateless_for(WarmRequirement::Session));

    crate::proxy::transport::xhttp::XhttpRuntime::warm(&runtime, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(registry.reap_idle_resources(Instant::now()), 1);
    assert_eq!(runtime.warm_counts().sessions, 0);
    runtime.retain_warm(WarmRetention::Udp).await.commit();
    crate::proxy::transport::xhttp::XhttpRuntime::warm(&runtime, Duration::from_secs(2))
        .await
        .unwrap();
    registry.shutdown().await;
    assert_eq!(runtime.warm_counts().sessions, 0);
    assert!(
        crate::proxy::transport::xhttp::XhttpRuntime::warm(&runtime, Duration::from_secs(2))
            .await
            .is_err()
    );
    peer.abort();
    let _ = peer.await;
}

async fn h2_preparation_peer() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::Receiver<()>,
    tokio::sync::mpsc::Receiver<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (opened, open_events) = tokio::sync::mpsc::channel(8);
    let (closed, close_events) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (tcp, _) = accepted.unwrap();
                    let opened = opened.clone();
                    let closed = closed.clone();
                    children.spawn(async move {
                        if let Ok(mut connection) = h2::server::handshake(tcp).await {
                            let _ = opened.send(()).await;
                            let mut responses = Vec::new();
                            let mut requests = Vec::new();
                            while let Some(Ok((request, mut response))) = connection.accept().await {
                                requests.push(request.into_body());
                                if let Ok(stream) = response.send_response(http::Response::new(()), false) {
                                    responses.push(stream);
                                }
                            }
                        }
                        let _ = closed.send(()).await;
                    });
                }
                finished = children.join_next(), if !children.is_empty() => {
                    finished.unwrap().unwrap();
                }
            }
        }
    });
    (address, task, open_events, close_events)
}

fn xhttp_node_at(protocol: NodeProtocol, address: std::net::SocketAddr) -> Node {
    let mut node = xhttp_node(protocol);
    node.host = address.ip().to_string();
    node.port = address.port();
    node.address = address.to_string();
    node.tls_mut().unwrap().enabled = false;
    node.transport_mut().unwrap().xhttp.as_mut().unwrap().mode =
        honk_config::node::XhttpMode::StreamOne;
    node.id = node.derive_id();
    node
}

#[cfg(feature = "rprx")]
#[tokio::test]
async fn speculative_udp_publishes_only_winner_and_loser_closes_physical_carrier() {
    use crate::proxy::PacketOutbound;
    use honk_config::node::VlessUdpEncoding;
    for (encoding, source) in [
        (None, false),
        (Some(VlessUdpEncoding::Native), false),
        (Some(VlessUdpEncoding::UotV2), false),
        (Some(VlessUdpEncoding::Xudp), false),
        (Some(VlessUdpEncoding::Xudp), true),
    ] {
        let (address, peer, mut opened, mut closed) = h2_preparation_peer().await;
        let protocol = if encoding.is_some() {
            NodeProtocol::VLess
        } else {
            NodeProtocol::Trojan
        };
        let mut node = xhttp_node_at(protocol, address);
        if let Some(encoding) = encoding {
            node.vless_mut().unwrap().udp_encoding = encoding;
            node.id = node.derive_id();
        }
        let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let runtime = registry.get(&node.id).unwrap();
        let target = "127.0.0.1:53".parse().unwrap();
        for winner in [false, true] {
            let preparation = tokio::time::timeout(Duration::from_secs(3), async {
                if protocol == NodeProtocol::Trojan {
                    crate::proxy::trojan::TrojanHandler::new()
                        .dial_udp_transport_speculative_runtime(
                            runtime.clone(),
                            target,
                            None,
                            Duration::from_secs(2),
                        )
                        .await
                } else if source {
                    let prepared = crate::proxy::vless::VLessHandler::prepare_source_udp(
                        runtime.clone(),
                        target,
                        None,
                        Duration::from_secs(2),
                        [0x3a; 8],
                    )
                    .await?;
                    Ok(crate::proxy::PreparedUdpTransport::new(async move {
                        Ok(prepared.commit().await? as Arc<dyn crate::proxy::PacketTransport>)
                    }))
                } else {
                    crate::proxy::vless::VLessHandler::new()
                        .dial_udp_transport_speculative_runtime(
                            runtime.clone(),
                            target,
                            None,
                            Duration::from_secs(2),
                        )
                        .await
                }
            })
            .await
            .unwrap()
            .unwrap();
            tokio::time::timeout(Duration::from_secs(3), opened.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                runtime.warm_counts().sessions,
                0,
                "provisional physical sessions cannot be reused"
            );
            if winner {
                let transport = preparation.commit().await.unwrap();
                assert_eq!(runtime.warm_counts().sessions, 1);
                drop(transport);
                registry.shutdown().await;
            } else {
                drop(preparation);
            }
            tokio::time::timeout(Duration::from_secs(3), closed.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(runtime.warm_counts().sessions, 0);
        }
        peer.abort();
        assert!(peer.await.unwrap_err().is_cancelled());
    }
}

#[cfg(feature = "rprx")]
#[tokio::test]
async fn cancelled_speculative_udp_tls_establishment_releases_socket_and_carrier_permit() {
    use crate::proxy::PacketOutbound;
    use honk_config::node::VlessUdpEncoding;
    for encoding in [
        None,
        Some(VlessUdpEncoding::Native),
        Some(VlessUdpEncoding::UotV2),
        Some(VlessUdpEncoding::Xudp),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (seen, hello) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            assert_ne!(tcp.read(&mut bytes).await.unwrap(), 0);
            seen.send(()).unwrap();
            while tcp.read(&mut bytes).await.unwrap() != 0 {}
        });
        let protocol = if encoding.is_some() {
            NodeProtocol::VLess
        } else {
            NodeProtocol::Trojan
        };
        let mut node = xhttp_node_at(protocol, address);
        node.tls_mut().unwrap().enabled = true;
        if let Some(encoding) = encoding {
            node.vless_mut().unwrap().udp_encoding = encoding;
        }
        node.id = node.derive_id();
        let carriers = Arc::new(tokio::sync::Semaphore::new(4));
        let (registry, _) = OutboundRuntimeRegistry::build_reusing_with_admission(
            std::slice::from_ref(&node),
            1,
            Arc::new(tokio::sync::Semaphore::new(1)),
            1,
            carriers.clone(),
            None,
        )
        .unwrap();
        let runtime = registry.get(&node.id).unwrap();
        let target = "127.0.0.1:53".parse().unwrap();
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let scope = registry.dial_scope({
            let starts = starts.clone();
            move || {
                starts.fetch_add(1, Ordering::SeqCst);
            }
        });
        let mut prepare = Box::pin(scope.scope(async {
            if protocol == NodeProtocol::Trojan {
                crate::proxy::trojan::TrojanHandler::new()
                    .dial_udp_transport_speculative_runtime(
                        runtime.clone(),
                        target,
                        None,
                        Duration::from_secs(30),
                    )
                    .await
            } else {
                crate::proxy::vless::VLessHandler::new()
                    .dial_udp_transport_speculative_runtime(
                        runtime.clone(),
                        target,
                        None,
                        Duration::from_secs(30),
                    )
                    .await
            }
        }));
        tokio::select! {
            result = &mut prepare => panic!("silent TLS peer unexpectedly completed: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(3), hello) => result.unwrap().unwrap(),
        }
        assert_eq!(
            starts.load(Ordering::SeqCst),
            1,
            "physical admission must report start before TLS completes"
        );
        if protocol == NodeProtocol::VLess {
            assert_eq!(carriers.available_permits(), 3);
        }
        assert_eq!(runtime.warm_counts().sessions, 0);
        drop(prepare);
        tokio::time::timeout(Duration::from_secs(3), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(carriers.available_permits(), 4);
        assert_eq!(runtime.warm_counts().sessions, 0);
        drop(
            tokio::time::timeout(Duration::from_secs(3), registry.acquire_dial_permit())
                .await
                .unwrap(),
        );
        registry.shutdown().await;
    }
}

#[tokio::test]
async fn exhausted_xhttp_physical_admission_stays_capacity_scoped_without_start_feedback() {
    use futures_util::FutureExt;
    for speculative in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node = xhttp_node_at(NodeProtocol::Trojan, listener.local_addr().unwrap());
        let ceiling = Arc::new(tokio::sync::Semaphore::new(1));
        let occupied = ceiling.clone().acquire_owned().await.unwrap();
        let (registry, _) = OutboundRuntimeRegistry::build_reusing_with_admission(
            std::slice::from_ref(&node),
            1,
            ceiling.clone(),
            1,
            Arc::new(tokio::sync::Semaphore::new(4)),
            None,
        )
        .unwrap();
        let runtime = registry.get(&node.id).unwrap();
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let scope = registry.dial_scope({
            let starts = starts.clone();
            move || {
                starts.fetch_add(1, Ordering::SeqCst);
            }
        });
        let mut attempt = Box::pin(scope.scope(async {
            if speculative {
                crate::proxy::transport::prepare_transport_runtime(
                    &runtime,
                    None,
                    Duration::from_secs(30),
                )
                .await
            } else {
                crate::proxy::transport::wrap_transport_runtime(
                    &runtime,
                    None,
                    Duration::from_secs(30),
                )
                .await
                .map(|stream| {
                    (
                        stream,
                        crate::proxy::transport::TransportPreparation::none(),
                    )
                })
            }
        }));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                assert!(attempt.as_mut().now_or_never().is_none());
                if scope.is_waiting_for_admission() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 0);
        assert!(
            listener.accept().now_or_never().is_none(),
            "exhausted admission must not create a socket"
        );
        drop(attempt);
        registry.shutdown().await;
        tokio::time::timeout(Duration::from_secs(3), async {
            while scope.is_waiting_for_admission() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            starts.load(Ordering::SeqCst),
            0,
            "cancelled unstarted work must not publish physical-start feedback"
        );
        drop(occupied);
        drop(
            tokio::time::timeout(Duration::from_secs(3), registry.acquire_dial_permit())
                .await
                .unwrap(),
        );
    }
}

#[tokio::test]
async fn losing_xhttp_udp_preparation_preserves_shared_warm_carrier() {
    use crate::proxy::PacketOutbound;
    let (address, peer, mut opened, mut closed) = h2_preparation_peer().await;
    let node = xhttp_node_at(NodeProtocol::Trojan, address);
    let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let runtime = registry.get(&node.id).unwrap();
    runtime.retain_warm(WarmRetention::Selector).await.commit();
    crate::proxy::transport::xhttp::XhttpRuntime::warm(&runtime, Duration::from_secs(2))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), opened.recv())
        .await
        .unwrap()
        .unwrap();
    let preparation = crate::proxy::trojan::TrojanHandler::new()
        .dial_udp_transport_speculative_runtime(
            runtime.clone(),
            "127.0.0.1:53".parse().unwrap(),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(runtime.warm_counts().sessions, 1);
    drop(preparation);
    assert_eq!(runtime.warm_counts().sessions, 1);
    assert!(matches!(
        closed.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    runtime.release_warm(WarmRetention::Selector).await;
    tokio::time::timeout(Duration::from_secs(3), closed.recv())
        .await
        .unwrap()
        .unwrap();
    registry.shutdown().await;
    peer.abort();
    assert!(peer.await.unwrap_err().is_cancelled());
}

#[cfg(feature = "rprx")]
#[tokio::test]
async fn retired_xhttp_runtime_rejects_provisional_winner_without_publishing() {
    use crate::proxy::PacketOutbound;
    let (address, peer, mut opened, mut closed) = h2_preparation_peer().await;
    let node = xhttp_node_at(NodeProtocol::VLess, address);
    let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let runtime = registry.get(&node.id).unwrap();
    let preparation = crate::proxy::vless::VLessHandler::new()
        .dial_udp_transport_speculative_runtime(
            runtime.clone(),
            "127.0.0.1:53".parse().unwrap(),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), opened.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(runtime.warm_counts().sessions, 0);
    registry.retire_reusable_state().await;
    assert!(preparation.commit().await.is_err());
    tokio::time::timeout(Duration::from_secs(3), closed.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(runtime.warm_counts().sessions, 0);
    assert!(runtime.xhttp.as_ref().unwrap().pool.is_retired());
    registry.shutdown().await;
    peer.abort();
    assert!(peer.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn one_dial_credit_opens_two_limit_one_carriers_without_retaining_setup_admission() {
    use honk_config::node::XhttpMode;
    use tokio::io::AsyncWriteExt;
    for (mode, speculative) in [
        (XhttpMode::StreamUp, false),
        (XhttpMode::StreamUp, true),
        (XhttpMode::PacketUp, false),
        (XhttpMode::PacketUp, true),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (requests, mut request_events) = tokio::sync::mpsc::channel(4);
        let (received, mut payload_events) = tokio::sync::mpsc::channel(4);
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let connection_count = connections.clone();
        let peer = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted.unwrap();
                        connection_count.fetch_add(1, Ordering::SeqCst);
                        let requests = requests.clone();
                        let received = received.clone();
                        children.spawn(async move {
                            let mut connection = h2::server::Builder::new()
                                .max_concurrent_streams(1).handshake::<_, bytes::Bytes>(tcp).await.unwrap();
                            let mut responses = Vec::new();
                            let mut bodies = tokio::task::JoinSet::new();
                            loop {
                                tokio::select! {
                                    request = connection.accept() => {
                                        let Some(Ok((request, mut response))) = request else { break; };
                                        let method = request.method().clone();
                                        requests.send(method.clone()).await.unwrap();
                                        responses.push(response.send_response(http::Response::new(()), false).unwrap());
                                        let received = received.clone();
                                        bodies.spawn(async move {
                                            let mut body = request.into_body();
                                            while let Some(Ok(bytes)) = body.data().await {
                                                body.flow_control().release_capacity(bytes.len()).unwrap();
                                                if method == http::Method::POST {
                                                    received.send(bytes).await.unwrap();
                                                }
                                            }
                                        });
                                    }
                                    finished = bodies.join_next(), if !bodies.is_empty() => {
                                        finished.unwrap().unwrap();
                                    }
                                }
                            }
                        });
                    }
                    finished = children.join_next(), if !children.is_empty() => {
                        finished.unwrap().unwrap();
                    }
                }
            }
        });
        let mut node = xhttp_node_at(NodeProtocol::Trojan, address);
        node.transport_mut().unwrap().xhttp.as_mut().unwrap().mode = mode;
        node.id = node.derive_id();
        let (registry, _) = OutboundRuntimeRegistry::build_reusing_with_admission(
            std::slice::from_ref(&node),
            1,
            Arc::new(tokio::sync::Semaphore::new(1)),
            1,
            Arc::new(tokio::sync::Semaphore::new(4)),
            None,
        )
        .unwrap();
        let runtime = registry.get(&node.id).unwrap();
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let scope = registry.dial_scope({
            let starts = starts.clone();
            move || {
                starts.fetch_add(1, Ordering::SeqCst);
            }
        });
        let (mut stream, preparation) = tokio::time::timeout(
            Duration::from_secs(3),
            scope.scope(async {
                if speculative {
                    crate::proxy::transport::prepare_transport_runtime(
                        &runtime,
                        None,
                        Duration::from_secs(2),
                    )
                    .await
                } else {
                    crate::proxy::transport::wrap_transport_runtime(
                        &runtime,
                        None,
                        Duration::from_secs(2),
                    )
                    .await
                    .map(|stream| {
                        (
                            stream,
                            crate::proxy::transport::TransportPreparation::none(),
                        )
                    })
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        preparation.commit().unwrap();
        drop(
            tokio::time::timeout(Duration::from_secs(1), registry.acquire_dial_permit())
                .await
                .unwrap(),
        );
        let payload = b"independent-physical-setup-credits";
        tokio::time::timeout(Duration::from_secs(3), async {
            stream.write_all(payload).await.unwrap();
            stream.flush().await.unwrap();
        })
        .await
        .unwrap();
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), async {
            while received.len() < payload.len() {
                received.extend_from_slice(&payload_events.recv().await.unwrap());
            }
        })
        .await
        .unwrap();
        assert_eq!(received, payload);
        let mut methods = Vec::new();
        for _ in 0..2 {
            methods.push(
                tokio::time::timeout(Duration::from_secs(3), request_events.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        assert_eq!(
            methods
                .iter()
                .filter(|method| **method == http::Method::GET)
                .count(),
            1
        );
        assert_eq!(
            methods
                .iter()
                .filter(|method| **method == http::Method::POST)
                .count(),
            1
        );
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        assert_eq!(runtime.warm_counts().sessions, 2);
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        drop(
            tokio::time::timeout(Duration::from_secs(1), registry.acquire_dial_permit())
                .await
                .unwrap(),
        );
        drop(stream);
        registry.shutdown().await;
        peer.abort();
        assert!(peer.await.unwrap_err().is_cancelled());
    }
}
