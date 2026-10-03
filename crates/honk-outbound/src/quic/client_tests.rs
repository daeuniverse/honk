use super::endpoint::{MAX_QUIC_GSO_SEGMENTS, default_gso_enabled, gso_transmit_segments};
use super::flow_control::apply_flow_control_profile;
use super::*;
use std::sync::atomic::Ordering;

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

#[tokio::test]
async fn closed_proxy_stream_is_node_failure_but_end_to_end_quic_is_not() {
    use crate::group::ScoreOutcome;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let accepted = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { endpoint.accept().await.unwrap().await.unwrap() }
    });
    let client = test_client(addr.port()).await;
    let (conn, _) = client
        .connection_with(Duration::from_secs(1), |_| async { Ok(()) })
        .await
        .unwrap();
    let _server_conn = accepted.await.unwrap();
    let (_raw_send, mut raw_recv) = conn.open_bi().await.unwrap();
    let (send, recv) = conn.open_bi().await.unwrap();
    let mut stream = QuicBiStream::new(send, recv);
    conn.close(VarInt::from_u32(0), b"carrier closed");

    let raw = AsyncReadExt::read(&mut raw_recv, &mut [0])
        .await
        .unwrap_err();
    assert_eq!(
        ScoreOutcome::from_io_error(&raw),
        ScoreOutcome::Io(raw.kind())
    );
    let error = stream.read(&mut [0]).await.unwrap_err();
    assert_eq!(error.kind(), raw.kind());
    assert_eq!(
        ScoreOutcome::from_io_error(&error),
        ScoreOutcome::NodeFailure
    );
    let error = stream.write_all(b"request").await.unwrap_err();
    assert_eq!(
        ScoreOutcome::from_io_error(&error),
        ScoreOutcome::NodeFailure
    );
    let mut chunks = [bytes::Bytes::from_static(b"request")];
    let error = std::future::poll_fn(|cx| stream.poll_write_chunks(cx, &mut chunks))
        .await
        .unwrap_err();
    assert_eq!(
        ScoreOutcome::from_io_error(&error),
        ScoreOutcome::NodeFailure
    );
    endpoint.close(VarInt::from_u32(0), b"test complete");
}

#[derive(Debug, Default)]
struct TestConnState {
    open: Arc<std::sync::atomic::AtomicUsize>,
}

impl QuicConnState for TestConnState {
    fn touch(&self) {}

    fn open_counter(&self) -> &Arc<std::sync::atomic::AtomicUsize> {
        &self.open
    }

    fn enable_telemetry(&self) {}
}

async fn test_client_state(port: u16) -> QuicClient<TestConnState> {
    let mut node = skip_verify_node();
    node.name = "quic-warm-start".to_string();
    node.host = "127.0.0.1".to_string();
    node.address = format!("127.0.0.1:{port}");
    node.port = port;
    let config = client_config(&node, &[b"h3"], QuicClientOptions::default())
        .await
        .unwrap();
    QuicClient::new("127.0.0.1", port, "localhost", config)
}

#[tokio::test]
async fn warm_quic_starts_feedback_before_blocked_stream_open() {
    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let accepted = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { endpoint.accept().await.unwrap().await.unwrap() }
    });
    let client = Arc::new(test_client_state(addr.port()).await);
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
            .unwrap()
            .0,
    );
    generation
        .scope_dials(client.connection_with(Duration::from_secs(1), |_| async {
            Ok::<_, anyhow::Error>(TestConnState::default())
        }))
        .await
        .unwrap();
    let server = accepted.await.unwrap();

    let feedback_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let open_entered = Arc::new(tokio::sync::Notify::new());
    let release_open = Arc::new(tokio::sync::Notify::new());
    let task = {
        let client = Arc::clone(&client);
        let generation = Arc::clone(&generation);
        let feedback_started = Arc::clone(&feedback_started);
        let open_entered = Arc::clone(&open_entered);
        let release_open = Arc::clone(&release_open);
        tokio::spawn(async move {
            generation
                .dial_scope(move || feedback_started.store(true, Ordering::Release))
                .scope(dial_quic_stream(
                    &client,
                    |timeout| {
                        let client = Arc::clone(&client);
                        async move {
                            client
                                .connection_with(timeout, |_| async {
                                    Ok::<_, anyhow::Error>(TestConnState::default())
                                })
                                .await
                        }
                    },
                    Duration::from_secs(1),
                    move |_conn| {
                        let open_entered = Arc::clone(&open_entered);
                        let release_open = Arc::clone(&release_open);
                        async move {
                            open_entered.notify_one();
                            release_open.notified().await;
                            Err(anyhow::anyhow!("released test stream open"))
                        }
                    },
                    |_| false,
                    "test",
                ))
                .await
        })
    };

    tokio::time::timeout(Duration::from_secs(1), open_entered.notified())
        .await
        .expect("warm QUIC stream open did not start");
    assert!(feedback_started.load(Ordering::Acquire));
    release_open.notify_one();
    assert!(task.await.unwrap().is_err());
    client.force_close().await;
    drop(server);
    endpoint.close(VarInt::from_u32(0), b"test complete");
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

fn tuic_test_node() -> honk_config::node::Node {
    let mut node = honk_config::node::Node {
        name: "tuic-ephemeral".into(),
        address: "127.0.0.1:443".into(),
        host: "127.0.0.1".into(),
        port: 443,
        outbound: honk_config::node::OutboundConfig::Tuic(honk_config::node::TuicConfig {
            uuid: Some("00000000-0000-4000-8000-000000000001".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn tuic_ephemeral() -> Arc<crate::runtime::NodeRuntime> {
    crate::runtime::NodeRuntime::try_ephemeral(&tuic_test_node()).unwrap()
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
    assert!(runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session));

    runtime.close().await;
    assert!(
        conn.close_reason().is_some(),
        "closing the ephemeral runtime must close the probe connection"
    );
    assert!(
        !runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session),
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
        let guard = NodeRuntime::try_ephemeral_guarded(&tuic_test_node()).unwrap();
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

#[cfg(feature = "owned-tasks")]
#[tokio::test]
async fn native_ephemeral_close_waits_for_quic_endpoint_idle() {
    use futures_util::FutureExt as _;

    let (server_endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let peer = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        connection.closed().await;
    });
    let mut guard = crate::runtime::NodeRuntime::try_ephemeral_guarded(&tuic_test_node()).unwrap();
    let runtime = guard.runtime();
    let (client, connection) = runtime
        .scope_tasks(async { Ok(probe_client(&runtime, addr.port()).await) })
        .await
        .unwrap();
    let endpoint = client
        .0
        .state
        .lock()
        .await
        .endpoint
        .as_ref()
        .unwrap()
        .1
        .clone();
    assert!(endpoint.wait_idle().now_or_never().is_none());
    guard.close().await.unwrap();
    assert!(connection.close_reason().is_some());
    assert!(endpoint.wait_idle().now_or_never().is_some());
    peer.await.unwrap();
}

#[cfg(feature = "owned-tasks")]
#[tokio::test]
async fn native_close_drains_endpoint_from_cancelled_unpublished_handshake() {
    use futures_util::FutureExt as _;

    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut guard = crate::runtime::NodeRuntime::try_ephemeral_guarded(&tuic_test_node()).unwrap();
    let runtime = guard.runtime();
    let observed = Arc::new(parking_lot::Mutex::new(None));
    let endpoint_observed = Arc::clone(&observed);
    let client = test_client(blackhole.local_addr().unwrap().port())
        .await
        .with_endpoint_factory(move |ipv6| {
            let endpoint = client_endpoint(ipv6)?;
            *endpoint_observed.lock() = Some(endpoint.clone());
            Ok(endpoint)
        });
    let mut probe = Box::pin(runtime.scope_tasks(
        client.connection_with(Duration::from_secs(5), |_conn| async {
            Ok::<(), anyhow::Error>(())
        }),
    ));
    assert!(probe.as_mut().now_or_never().is_none());
    let endpoint = observed
        .lock()
        .clone()
        .expect("dial must create its endpoint before handshake");
    drop(probe);
    guard.close().await.unwrap();
    assert!(endpoint.wait_idle().now_or_never().is_some());
}

#[cfg(feature = "owned-tasks")]
#[tokio::test]
async fn native_production_close_drains_cancelled_quic_handshake() {
    use futures_util::FutureExt as _;

    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let node = tuic_test_node();
    let generation = crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        std::slice::from_ref(&node),
        1,
        1,
        1,
        true,
        None,
    )
    .unwrap()
    .0;
    let runtime = generation.get(&node.id).unwrap();
    let observed = Arc::new(parking_lot::Mutex::new(None));
    let endpoint_observed = Arc::clone(&observed);
    let client = runtime
        .quic_client(|| async {
            let client = test_client(blackhole.local_addr().unwrap().port())
                .await
                .with_endpoint_factory(move |ipv6| {
                    let endpoint = client_endpoint(ipv6)?;
                    *endpoint_observed.lock() = Some(endpoint.clone());
                    Ok(endpoint)
                });
            Ok(Arc::new(ProbeClient(client)))
        })
        .await
        .unwrap();
    let mut dial = Box::pin(
        client
            .0
            .connection_with(Duration::from_secs(5), |_conn| async {
                Ok::<(), anyhow::Error>(())
            }),
    );
    assert!(dial.as_mut().now_or_never().is_none());
    let endpoint = observed
        .lock()
        .clone()
        .expect("unpublished endpoint created");
    drop(dial);
    generation.shutdown().await;
    assert!(endpoint.wait_idle().now_or_never().is_some());
    assert!(
        client
            .0
            .connection_with(Duration::from_secs(5), |_conn| async {
                Ok::<(), anyhow::Error>(())
            })
            .await
            .is_err()
    );
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn observed_quic_reuse_is_not_a_physical_attempt_and_cancel_settles_once() {
    use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};
    let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let observe = |flow_id| {
        let events = Arc::clone(&events);
        FlowObserver::new(
            FlowContext {
                flow_id,
                generation: 1,
                attempt_id: Some(uuid::Uuid::new_v4()),
                lookup_id: None,
                dns_purpose: "proxy_server",
            },
            Arc::new(move |context, event| events.lock().push((context, event))),
        )
    };
    let first = observe(uuid::Uuid::new_v4());
    let second = observe(uuid::Uuid::new_v4());
    let (endpoint, address) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let accepted = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { endpoint.accept().await.unwrap().await.unwrap() }
    });
    let client = test_client(address.port()).await;
    let (connection, _) = first
        .scope(client.connection_with(Duration::from_secs(2), |_| async { Ok(()) }))
        .await
        .unwrap();
    let server = accepted.await.unwrap();
    let (reused, _) = second
        .scope(client.connection_with(Duration::from_secs(2), |_| async {
            panic!("cached connection must not run setup")
        }))
        .await
        .unwrap();
    assert_eq!(connection.stable_id(), reused.stable_id());
    {
        let events = events.lock();
        let physical: Vec<_> = events
            .iter()
            .filter_map(|(context, event)| match event {
                FlowEvent::Transport {
                    attempt_id, status, ..
                } => Some((context, attempt_id, status.as_str())),
                _ => None,
            })
            .collect();
        assert_eq!(physical.len(), 2);
        assert_eq!(physical[0].2, "started");
        assert_eq!(physical[1].2, "succeeded");
        assert_eq!(physical[0].1, physical[1].1);
        assert_ne!(Some(*physical[0].1), physical[0].0.attempt_id);
        assert!(
            physical
                .iter()
                .all(|(context, _, _)| context.flow_id == first.context().flow_id)
        );
        assert!(events.iter().any(|(context, event)| {
            context.flow_id == second.context().flow_id
                && matches!(event, FlowEvent::TransportAttached { server_addr: Some(addr), .. } if *addr == address)
        }));
        assert!(!events.iter().any(|(_, event)| matches!(
            event,
            FlowEvent::Milestone {
                milestone: crate::runtime::flow_observation::Milestone::TargetConfirmed
                    | crate::runtime::flow_observation::Milestone::TargetRequestSent
            }
        )));
    }
    connection.close(VarInt::from_u32(0), b"finished");
    drop(server);
    client.force_close().await;
    endpoint.close(VarInt::from_u32(0), b"finished");

    events.lock().clear();
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = test_client(blackhole.local_addr().unwrap().port()).await;
    let mut pending = Box::pin(
        first.scope(client.connection_with(Duration::from_secs(10), |_| async { Ok(()) })),
    );
    let mut packet = [0; 2048];
    tokio::select! {
        _ = &mut pending => panic!("blackhole handshake unexpectedly completed"),
        result = blackhole.recv(&mut packet) => { result.unwrap(); }
    }
    drop(pending);
    let physical: Vec<_> = events
        .lock()
        .iter()
        .filter_map(|(_, event)| match event {
            FlowEvent::Transport {
                attempt_id, status, ..
            } => Some((*attempt_id, status.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(physical.len(), 2);
    assert_eq!(physical[0].0, physical[1].0);
    assert_eq!((physical[0].1, physical[1].1), ("started", "cancelled"));
    client.force_close().await;
}
