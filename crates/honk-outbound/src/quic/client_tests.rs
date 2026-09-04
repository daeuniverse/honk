use super::*;

fn quic_node() -> honk_config::node::Node {
    honk_config::node::Node {
        outbound: honk_config::node::OutboundConfig::Hysteria2(Default::default()),
        ..Default::default()
    }
}

fn skip_verify_node() -> honk_config::node::Node {
    let mut node = quic_node();
    node.tls_mut().unwrap().skip_cert_verify = true;
    node
}
#[test]
fn explicit_large_mtu_enables_gso_by_default() {
    assert!(!default_gso_enabled(1252));
    assert!(default_gso_enabled(1253));
    assert!(default_gso_enabled(1452));
}

#[test]
fn gso_batches_are_bounded() {
    assert_eq!(gso_transmit_segments(false, 64), 1);
    assert_eq!(gso_transmit_segments(true, 8), 8);
    assert_eq!(gso_transmit_segments(true, 64), MAX_QUIC_GSO_SEGMENTS);
}

#[tokio::test]
async fn client_config_rejects_invalid_pin() {
    let mut node = quic_node();
    node.name = "bad-pin".to_string();
    node.tls_mut().unwrap().pin_sha256 = Some("not-a-pin".to_string());
    let error = match client_config(&node, &[b"h3"], QuicClientOptions::default()).await {
        Ok(_) => panic!("invalid pin must fail closed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("invalid tls_pin_sha256"));
}

#[tokio::test]
async fn real_quic_loser_connection_closes_when_fallback_wins() {
    let (first_server, first_addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let (second_server, second_addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let first_closed = tokio::spawn(async move {
        let connection = first_server.accept().await.unwrap().await.unwrap();
        connection.closed().await
    });
    let second_accepted =
        tokio::spawn(async move { second_server.accept().await.unwrap().await.unwrap() });
    let mut node = skip_verify_node();
    node.name = "quic-address-race".to_string();
    let config = client_config(&node, &[b"h3"], QuicClientOptions::default())
        .await
        .unwrap();
    let endpoint = client_endpoint(false).unwrap();
    let first_connection = endpoint
        .connect_with(config.clone(), first_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut first_connection = Some(first_connection);
    let addrs = [first_addr, second_addr];

    let winner = crate::address_race::race_resolved_addrs_with_stagger(
        &addrs,
        Duration::from_millis(20),
        |addr| {
            let held = (addr == first_addr).then(|| {
                first_connection
                    .take()
                    .expect("first address launched once")
            });
            let endpoint = endpoint.clone();
            let config = config.clone();
            async move {
                if let Some(connection) = held {
                    let _connection = connection;
                    return std::future::pending::<anyhow::Result<Connection>>().await;
                }
                Ok(endpoint.connect_with(config, addr, "localhost")?.await?)
            }
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(winner.remote_address(), second_addr);

    let second_connection = tokio::time::timeout(Duration::from_secs(1), second_accepted)
        .await
        .expect("winning QUIC handshake did not reach the server")
        .unwrap();
    let _closed = tokio::time::timeout(Duration::from_secs(1), first_closed)
        .await
        .expect("losing QUIC connection stayed open")
        .unwrap();
    winner.close(VarInt::from_u32(0), b"test complete");
    drop(second_connection);
    endpoint.close(VarInt::from_u32(0), b"test complete");
}

async fn test_client(port: u16) -> QuicClient<()> {
    let mut node = skip_verify_node();
    node.name = "quic-test".to_string();
    node.host = "127.0.0.1".to_string();
    node.address = format!("127.0.0.1:{port}");
    node.port = port;
    let config = client_config(&node, &[b"h3"], QuicClientOptions::default())
        .await
        .unwrap();
    QuicClient::new("127.0.0.1", port, "localhost", config)
}

fn spawn_accept_loop(endpoint: Endpoint) {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let _ = incoming.await;
            });
        }
    });
}

#[tokio::test]
async fn adaptive_profile_updates_live_connection_windows() {
    const MIB: u64 = 1 << 20;
    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let accepted = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { endpoint.accept().await.unwrap().await.unwrap() }
    });
    let mut node = skip_verify_node();
    node.host = "127.0.0.1".to_string();
    node.address = format!("127.0.0.1:{}", addr.port());
    node.port = addr.port();
    let config = client_config(
        &node,
        &[b"h3"],
        QuicClientOptions {
            stream_receive_window: Some(8 * MIB),
            conn_receive_window: Some(8 * MIB),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let profiles = Arc::new(AdaptiveFlowProfiles::default());
    let client = QuicClient::new("127.0.0.1", addr.port(), "localhost", config)
        .with_flow_control_profiles(Some(Arc::clone(&profiles)));
    let (conn, state) = client
        .connection_with(Duration::from_secs(1), |_| async {
            Ok::<(), anyhow::Error>(())
        })
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&profiles, &client.flow_control_profiles));
    assert_eq!(Arc::strong_count(&profiles), 3);
    let server = accepted.await.unwrap();
    let profile = AdaptiveFlowProfile {
        connection_receive_floor: 16 * MIB,
        stream_receive_floor: 16 * MIB,
        send_floor: 20 * MIB,
        ..Default::default()
    };

    apply_flow_control_profile(&conn, &conn.stats(), &profile);
    let stats = conn.stats().flow_control;
    assert_eq!(stats.stream_receive_window, 16 * MIB);
    assert_eq!(stats.receive_window, 16 * MIB);
    assert_eq!(stats.send_window, 20 * MIB);
    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(Arc::strong_count(&profiles), 2);
    drop(state);
    tokio::time::timeout(Duration::from_secs(2), async {
        while Arc::strong_count(&profiles) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("adaptive monitor outlived its flow state");

    conn.close(VarInt::from_u32(0), b"test complete");
    endpoint.close(VarInt::from_u32(0), b"test complete");
    drop(server);
}

#[tokio::test]
async fn closed_connection_tracking_is_pruned_while_flow_state_lives() {
    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let accepted = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { endpoint.accept().await.unwrap().await.unwrap() }
    });
    let client = test_client(addr.port()).await;
    let (conn, flow_state) = client
        .connection_with(Duration::from_secs(1), |_| async {
            Ok::<(), anyhow::Error>(())
        })
        .await
        .unwrap();
    let server = accepted.await.unwrap();
    assert_eq!(client.state.lock().await.connections.len(), 1);

    conn.close(VarInt::from_u32(0), b"test complete");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if client.state.lock().await.connections.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("closed connection remained in client tracking");

    drop(flow_state);
    client.force_close().await;
    endpoint.close(VarInt::from_u32(0), b"test complete");
    drop(server);
}

#[tokio::test]
async fn dead_warm_quic_reconnect_waits_for_limit_one() {
    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let client = Arc::new(test_client(addr.port()).await);
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
            .unwrap()
            .0,
    );
    let first_accept = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { endpoint.accept().await.unwrap().await.unwrap() }
    });
    let (first, _) = generation
        .scope_dials(client.connection_with(Duration::from_secs(1), |_| async {
            Ok::<(), anyhow::Error>(())
        }))
        .await
        .unwrap();
    let first_server = first_accept.await.unwrap();
    first.close(VarInt::from_u32(0), b"replace");
    client.invalidate(&first).await;

    let held = generation.acquire_dial_permit().await;
    let reconnect = tokio::spawn({
        let client = Arc::clone(&client);
        let generation = Arc::clone(&generation);
        async move {
            generation
                .scope_dials(client.connection_with(Duration::from_secs(1), |_| async {
                    Ok::<(), anyhow::Error>(())
                }))
                .await
        }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), endpoint.accept())
            .await
            .is_err(),
        "dead cached QUIC reconnect bypassed the physical dial limit"
    );

    drop(held);
    let incoming = tokio::time::timeout(Duration::from_secs(1), endpoint.accept())
        .await
        .expect("admitted QUIC reconnect sent no Initial")
        .expect("server endpoint closed");
    let second_accept = tokio::spawn(async move { incoming.await.unwrap() });
    let (second, _) = tokio::time::timeout(Duration::from_secs(1), reconnect)
        .await
        .expect("admitted QUIC reconnect did not finish")
        .unwrap()
        .unwrap();
    let second_server = second_accept.await.unwrap();

    second.close(VarInt::from_u32(0), b"test complete");
    client.force_close().await;
    endpoint.close(VarInt::from_u32(0), b"test complete");
    drop((first_server, second_server));
}

#[tokio::test]
async fn force_close_covers_connection_cached_by_in_flight_dial() {
    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    spawn_accept_loop(endpoint);
    let client = Arc::new(test_client(addr.port()).await);

    // Park the dial inside its setup closure: it holds the single-flight
    // state lock with the handshake already completed.
    let (setup_entered, entered) = tokio::sync::oneshot::channel::<()>();
    let (release_setup, release) = tokio::sync::oneshot::channel::<()>();
    let dial = tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            client
                .connection_with(Duration::from_secs(5), move |_conn| async move {
                    let _ = setup_entered.send(());
                    let _ = release.await;
                    Ok::<(), anyhow::Error>(())
                })
                .await
        }
    });
    entered.await.unwrap();

    let closer = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.force_close().await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !closer.is_finished(),
        "force_close must wait out the in-flight dial"
    );

    let _ = release_setup.send(());
    let (conn, _) = dial.await.unwrap().unwrap();
    closer.await.unwrap();
    assert!(
        conn.close_reason().is_some(),
        "a connection cached just before the close must still be closed"
    );
    assert!(
        client
            .connection_with(Duration::from_secs(1), |_conn| async {
                Ok::<(), anyhow::Error>(())
            })
            .await
            .is_err(),
        "a closed client rejects new dials"
    );
}

#[tokio::test]
async fn release_cached_keeps_client_reusable_for_a_fresh_connection() {
    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    spawn_accept_loop(endpoint);
    let client = test_client(addr.port()).await;
    let (first, _) = client
        .connection_with(Duration::from_secs(5), |_conn| async {
            Ok::<(), anyhow::Error>(())
        })
        .await
        .unwrap();

    client.release_cached().await;
    let state = client.state.lock().await;
    assert!(state.conn.is_none());
    assert!(!state.closed);
    drop(state);

    let (second, _) = client
        .connection_with(Duration::from_secs(5), |_conn| async {
            Ok::<(), anyhow::Error>(())
        })
        .await
        .unwrap();
    assert_ne!(first.stable_id(), second.stable_id());
    client.force_close().await;
    assert!(first.close_reason().is_some());
    assert!(second.close_reason().is_some());
}

/// A cold-node health probe dials QUIC through an ephemeral runtime;
/// closing it must deterministically close the cached connection and
/// endpoint driver (drop-alone is not relied upon).
struct ProbeClient(QuicClient<()>);
#[async_trait::async_trait]
impl crate::runtime::QuicRuntimeClient for ProbeClient {
    fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }
    async fn force_close(&self) {
        self.0.force_close().await;
    }
    async fn release_warm(&self) {
        self.0.release_cached().await;
    }
}

fn tuic_ephemeral() -> Arc<crate::runtime::NodeRuntime> {
    crate::runtime::NodeRuntime::ephemeral(&honk_config::node::Node {
        outbound: honk_config::node::OutboundConfig::Tuic(Default::default()),
        ..Default::default()
    })
}

async fn probe_client(
    runtime: &crate::runtime::NodeRuntime,
    port: u16,
) -> (Arc<ProbeClient>, quinn::Connection) {
    let crate::runtime::ProtocolRuntime::Quic(quic) = &runtime.runtime else {
        panic!("tuic runtime expected");
    };
    let client: Arc<ProbeClient> = quic
        .client(|| async { Ok(Arc::new(ProbeClient(test_client(port).await))) })
        .await
        .unwrap();
    let (conn, _) = client
        .0
        .connection_with(Duration::from_secs(5), |_conn| async {
            Ok::<(), anyhow::Error>(())
        })
        .await
        .unwrap();
    (client, conn)
}

#[tokio::test]
async fn ephemeral_runtime_close_shuts_quic_client() {
    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    spawn_accept_loop(endpoint);
    let runtime = tuic_ephemeral();
    let (_client, conn) = probe_client(&runtime, addr.port()).await;
    assert!(conn.close_reason().is_none());
    assert!(runtime.is_warm_or_stateless());

    runtime.close().await;
    assert!(
        conn.close_reason().is_some(),
        "closing the ephemeral runtime must close the probe connection"
    );
    assert!(
        !runtime.is_warm_or_stateless(),
        "a closed runtime no longer reports warm clients"
    );
}

/// A probe future dropped mid-flight (outer timeout / task abort) never
/// runs the explicit close; the guard's Drop must still close the cached
/// connection and endpoint driver.
#[tokio::test]
async fn ephemeral_guard_releases_quic_client_when_probe_is_aborted() {
    use crate::runtime::NodeRuntime;

    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    spawn_accept_loop(endpoint);
    let (conn_tx, conn_rx) = tokio::sync::oneshot::channel();
    let probe = tokio::spawn(async move {
        let guard = NodeRuntime::ephemeral_guarded(&honk_config::node::Node {
            outbound: honk_config::node::OutboundConfig::Tuic(Default::default()),
            ..Default::default()
        });
        let runtime = guard.runtime();
        let (_client, conn) = probe_client(&runtime, addr.port()).await;
        let _ = conn_tx.send(conn);
        std::future::pending::<()>().await;
    });
    let conn = conn_rx.await.unwrap();
    probe.abort();
    let _ = probe.await;

    tokio::time::timeout(Duration::from_secs(5), async {
        while conn.close_reason().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the guard Drop must drive the QUIC close after abort");
}
