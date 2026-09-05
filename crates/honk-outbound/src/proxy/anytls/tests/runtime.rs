use super::streams::spawn_echo_server;
use super::*;

#[tokio::test]
async fn runtime_udp_pool_hit_does_not_build_connector() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "runtime-udp-hit".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    let runtime = generation.get(&node.id).unwrap();
    let pool = match &runtime.runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("expected AnyTLS runtime"),
    };
    let (session, mut server) = establish_test_session("runtime-udp-hit").await;
    expect_handshake(&mut server).await;
    pool.insert(&session);
    assert!(!runtime.tls_connector_loaded());

    let handler = AnyTlsHandler::new();
    let transport = handler
        .dial_udp_transport_runtime(
            Arc::clone(&runtime),
            "127.0.0.1:53".parse().unwrap(),
            None,
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    assert!(!runtime.tls_connector_loaded());
    drop(transport);
    generation.shutdown().await;
}

/// A cold-node health probe dials through an ephemeral runtime; closing
/// it must deterministically release the session, its demux task, and
/// the underlying connection (the 797 ESTABLISHED leak: throwaway pools
/// had no owner running any close/idle reaping).
/// A probe future dropped mid-flight (outer timeout / task abort) never
/// runs the explicit close; the guard's Drop must still release the
/// session and its connection.
#[tokio::test]
async fn ephemeral_guard_releases_session_when_probe_is_aborted() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "guard-abort".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let (session, mut server) = establish_test_session("guard-abort").await;
    expect_handshake(&mut server).await;
    let probe_session = Arc::clone(&session);
    let probe = tokio::spawn(async move {
        let guard = crate::runtime::NodeRuntime::ephemeral_guarded(&node);
        let runtime = guard.runtime();
        let crate::runtime::ProtocolRuntime::AnyTls(anytls) = &runtime.runtime else {
            panic!("expected AnyTLS runtime")
        };
        anytls.pool.insert(&probe_session);
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    probe.abort();
    let _ = probe.await;

    assert!(
        session.is_closed(),
        "dropping the guard on abort must close the session"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while read_frame(&mut server).await.is_ok() {}
    })
    .await
    .expect("the connection must close on abort");
}

#[tokio::test]
async fn ephemeral_runtime_close_releases_session_and_connection() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "ephemeral-probe".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let runtime = crate::runtime::NodeRuntime::ephemeral(&node);
    assert!(runtime.is_ephemeral());
    let pool = match &runtime.runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("expected AnyTLS runtime"),
    };
    let (session, mut server) = establish_test_session("ephemeral-probe").await;
    expect_handshake(&mut server).await;
    pool.insert(&session);

    let handler = AnyTlsHandler::new();
    let stream = handler
        .dial_runtime(
            Arc::clone(&runtime),
            "8.8.8.8:53".parse().unwrap(),
            None,
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .stream;
    let (cmd, _sid, _) = read_frame(&mut server).await.unwrap();
    assert_eq!(cmd, CMD_SYN);
    let (cmd, _, _) = read_frame(&mut server).await.unwrap();
    assert_eq!(cmd, CMD_PSH);
    drop(stream);

    runtime.close().await;
    assert!(session.is_closed());
    assert_eq!(pool.live_session_count(), 0);

    tokio::time::timeout(Duration::from_secs(5), async {
        while read_frame(&mut server).await.is_ok() {}
    })
    .await
    .expect("closing the ephemeral runtime must close the connection");
}

#[tokio::test]
async fn warm_resources_flip_with_pool_session() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "warm-resources".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let generation =
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let runtime = generation.get(&node.id).unwrap();
    assert!(!runtime.is_warm_or_stateless());

    let crate::runtime::ProtocolRuntime::AnyTls(anytls) = &runtime.runtime else {
        panic!("expected AnyTLS runtime")
    };
    let (session, mut server) = establish_test_session("warm-resources").await;
    expect_handshake(&mut server).await;
    anytls.pool.insert(&session);
    assert!(runtime.is_warm_or_stateless());
    assert_eq!(runtime.warm_counts().sessions, 1);

    session.close();
    assert!(
        !runtime.is_warm_or_stateless(),
        "a closed session no longer counts as warm"
    );
    assert_eq!(runtime.warm_counts().sessions, 0);
}

#[tokio::test]
async fn runtime_dial_stays_on_captured_pool_after_registry_swap() {
    let old_node = Node {
        id: uuid::Uuid::new_v4(),
        name: "generation-node".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let old_generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&old_node)).unwrap(),
    );
    let old_runtime = old_generation.get(&old_node.id).unwrap();
    let old_pool = match &old_runtime.runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("expected AnyTLS runtime"),
    };
    let (session, mut server) = establish_test_session("captured-generation").await;
    expect_handshake(&mut server).await;
    let _addresses = spawn_echo_server(server);
    old_pool.insert(&session);

    let mut replacement_node = old_node.clone();
    replacement_node.address = "127.0.0.1:10".into();
    let replacement = crate::runtime::OutboundRuntimeRegistry::build(&[replacement_node]).unwrap();
    let replacement_pool = match &replacement.get(&old_node.id).unwrap().runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("expected AnyTLS runtime"),
    };
    let handler = AnyTlsHandler::new();

    let mut stream = handler
        .dial_runtime(
            old_runtime,
            "8.8.8.8:53".parse().unwrap(),
            None,
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .stream;
    stream.write_all(b"old-generation").await.unwrap();
    let mut echoed = vec![0; b"old-generation".len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"old-generation");
    assert!(old_pool.has_usable_session());
    assert!(!replacement_pool.has_usable_session());
    session.close();
}

#[tokio::test(start_paused = true)]
async fn runtime_retirement_drains_live_session_without_cutting_it() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "retiring-anytls".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        ..Default::default()
    };
    let generation =
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let pool = match &generation.get(&node.id).unwrap().runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("expected AnyTLS runtime"),
    };
    let (session, mut server) = establish_test_session("retiring-anytls").await;
    expect_handshake(&mut server).await;
    pool.insert(&session);
    let permit = session.try_reserve().expect("live stream permit");

    generation.begin_retirement();
    assert!(
        !session.is_closed(),
        "publication must not cut live streams"
    );
    generation.retire_reusable_state().await;
    assert_eq!(session.state(), crate::session::SessionState::Draining);
    assert!(
        !session.is_closed(),
        "pool drain must preserve live streams"
    );

    drop(permit);
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    assert!(session.is_closed(), "last stream release must finish drain");
}

#[tokio::test]
async fn uot_setup_fallback_waits_for_capacity_and_cancellation_does_not_enqueue() {
    let (session, mut server) = establish_test_session("uot-setup-capacity").await;
    expect_handshake(&mut server).await;
    let capacity = (WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED) as u32;
    let held = Arc::clone(&session.writer_q.data_permits)
        .acquire_many_owned(capacity)
        .await
        .unwrap();

    let setup = session.enqueue_confirmed_data(7, bytes::Bytes::from_static(b"setup"));
    tokio::pin!(setup);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut setup)
            .await
            .is_err(),
        "oversized first datagrams must not drop their fallback setup"
    );
    drop(held);
    tokio::time::timeout(Duration::from_secs(1), setup)
        .await
        .unwrap()
        .unwrap();
    let (cmd, sid, payload) = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut server))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (cmd, sid, payload.as_slice()),
        (CMD_PSH, 7, b"setup".as_slice())
    );

    let held = Arc::clone(&session.writer_q.data_permits)
        .acquire_many_owned(capacity)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            session.enqueue_confirmed_data(7, bytes::Bytes::from_static(b"cancelled")),
        )
        .await
        .is_err()
    );
    drop(held);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), read_frame(&mut server))
            .await
            .is_err(),
        "cancelling before capacity is acquired must not enqueue setup"
    );
    session.close();
}
#[tokio::test]
async fn warm_uses_only_its_generation_owned_runtime_pool() {
    let node = zero_idle_anytls_node("warm-anytls");
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    let runtime = generation.get(&node.id).unwrap();
    let pool = match &runtime.runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("AnyTLS node needs its own runtime"),
    };
    let (session, mut server) = establish_test_session("warm-anytls").await;
    expect_handshake(&mut server).await;

    AnyTlsHandler::warm_pool_with(Arc::clone(&runtime), move || async move { Ok(session) })
        .await
        .unwrap();
    assert!(pool.has_usable_session());

    let handler = AnyTlsHandler::new();
    handler
        .warm(
            Arc::clone(&runtime),
            Duration::from_secs(1),
            WarmRequirement::Session,
        )
        .await
        .unwrap();
    drop(server);
}

#[tokio::test]
async fn warm_shutdown_cancels_a_notify_blocked_dial_and_keeps_pool_terminal() {
    let node = zero_idle_anytls_node("shutdown-warm-anytls");
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    let runtime = generation.get(&node.id).unwrap();
    let pool = match &runtime.runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("AnyTLS node needs its own runtime"),
    };
    let dial_started = Arc::new(tokio::sync::Notify::new());
    let dial_blocked = Arc::new(tokio::sync::Notify::new());
    let warm = tokio::spawn({
        let runtime = Arc::clone(&runtime);
        let dial_started = Arc::clone(&dial_started);
        let dial_blocked = Arc::clone(&dial_blocked);
        async move {
            AnyTlsHandler::warm_pool_with(runtime, move || {
                let dial_started = Arc::clone(&dial_started);
                let dial_blocked = Arc::clone(&dial_blocked);
                async move {
                    dial_started.notify_one();
                    dial_blocked.notified().await;
                    unreachable!("the blocked warm dial must be cancelled by shutdown")
                }
            })
            .await
        }
    });

    tokio::time::timeout(Duration::from_secs(1), dial_started.notified())
        .await
        .expect("warm dial must start before its generation is shut down");
    generation.shutdown().await;
    let result = tokio::time::timeout(Duration::from_secs(1), warm)
        .await
        .expect("shutdown must unblock the warm future")
        .expect("warm task must not panic");
    assert!(result.is_err(), "terminal pool shutdown rejects the warm");
    assert!(
        !pool.has_usable_session(),
        "a cancelled dial must not leave a usable session in the pool"
    );
    assert!(
        AnyTlsHandler::warm_pool_with(Arc::clone(&runtime), || async {
            unreachable!("a terminal pool must reject before invoking a new dial")
        })
        .await
        .is_err(),
        "subsequent warm attempts must be rejected after generation shutdown"
    );
}

#[tokio::test]
async fn speculative_shared_loser_unregisters_uot_sid_synchronously() {
    let handler = AnyTlsHandler::new();
    let node = zero_idle_anytls_node("speculative-shared");
    let pool: Arc<AnyTlsPool> = Arc::new(AnyTlsPool::new());
    let (session, _server) = establish_test_session("speculative-shared").await;
    pool.insert(&session);
    let prepared = handler
        .dial_udp_transport_speculative_with(
            &node,
            Arc::clone(&pool),
            "8.8.8.8:53".parse().unwrap(),
            None,
            || async { unreachable!("a shared checkout cannot dial") },
        )
        .await
        .unwrap();
    assert_eq!(session.streams.lock().unwrap().len(), 1);

    drop(prepared);

    assert!(
        session.streams.lock().unwrap().is_empty(),
        "loser Drop must synchronously unregister its UoT stream"
    );
    assert!(
        !session.is_closed(),
        "dropping a shared speculative transport must not retire its pooled session"
    );
}

#[tokio::test]
async fn speculative_detached_winner_commits_into_captured_pool_once() {
    let handler = AnyTlsHandler::new();
    let node = zero_idle_anytls_node("speculative-detached-commit");
    let pool: Arc<AnyTlsPool> = Arc::new(AnyTlsPool::new());
    let (session, _server) = establish_test_session("speculative-detached-commit").await;
    let prepared = handler
        .dial_udp_transport_speculative_with(
            &node,
            Arc::clone(&pool),
            "8.8.8.8:53".parse().unwrap(),
            None,
            {
                let session = Arc::clone(&session);
                move || async move { Ok(session) }
            },
        )
        .await
        .unwrap();
    assert_eq!(pool.metrics().sessions, 0);
    assert_eq!(session.streams.lock().unwrap().len(), 1);

    let transport = prepared.commit().await.unwrap();
    assert_eq!(pool.metrics().sessions, 1);
    assert!(pool.has_usable_session());
    drop(transport);
    assert!(session.streams.lock().unwrap().is_empty());
    pool.shutdown();
}

#[tokio::test(start_paused = true)]
async fn late_predecessor_commit_obeys_successor_dial_limit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut node = anytls_node("late-predecessor-admission");
    node.address = address.to_string();
    node.host = address.ip().to_string();
    node.port = address.port();
    node.anytls_mut().unwrap().min_idle_session = Some(2);
    let first = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build_reusing(
            std::slice::from_ref(&node),
            1,
            None,
        )
        .unwrap()
        .0,
    );
    first.activate_background_dial_admission();
    let runtime = first.get(&node.id).unwrap();
    let pool = runtime.anytls_pool().unwrap();
    let (session, _server) = establish_test_session("late-predecessor-admission").await;
    let prepared = first
        .scope_dials(AnyTlsHandler::dial_udp_transport_speculative_for_pool_with(
            &node,
            Arc::clone(&pool),
            "8.8.8.8:53".parse().unwrap(),
            None,
            Some(runtime),
            {
                let session = Arc::clone(&session);
                move || async move { Ok(session) }
            },
        ))
        .await
        .unwrap();

    let (successor, reused) = crate::runtime::OutboundRuntimeRegistry::build_reusing(
        std::slice::from_ref(&node),
        1,
        Some(&first),
    )
    .unwrap();
    let successor = Arc::new(successor);
    successor.activate_background_dial_admission();
    first.mark_moved_out(reused);
    first.retire_reusable_state().await;
    drop(first);

    let held = successor.acquire_dial_permit().await;
    let transport = prepared.commit().await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(DEFAULT_IDLE_CHECK_INTERVAL_SECS + 1)).await;
    tokio::task::yield_now().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(1), listener.accept())
            .await
            .is_err(),
        "late commit bypassed the successor's physical-dial limit"
    );

    drop(held);
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .expect("successor admission release did not start the replacement dial")
        .unwrap();
    drop(transport);
    pool.shutdown();
}

#[tokio::test]
async fn speculative_detached_commit_fails_closed_after_generation_shutdown() {
    let handler = AnyTlsHandler::new();
    let node = zero_idle_anytls_node("speculative-detached-shutdown");
    let pool: Arc<AnyTlsPool> = Arc::new(AnyTlsPool::new());
    let (session, _server) = establish_test_session("speculative-detached-shutdown").await;
    let prepared = handler
        .dial_udp_transport_speculative_with(
            &node,
            Arc::clone(&pool),
            "8.8.8.8:53".parse().unwrap(),
            None,
            {
                let session = Arc::clone(&session);
                move || async move { Ok(session) }
            },
        )
        .await
        .unwrap();

    pool.shutdown();
    assert!(prepared.commit().await.is_err());
    assert!(session.is_closed());
    assert!(session.streams.lock().unwrap().is_empty());
    assert_eq!(pool.metrics().sessions, 0);
}

struct CancelledDial(Arc<AtomicBool>);

impl Drop for CancelledDial {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[tokio::test]
async fn speculative_udp_abort_cancels_injected_dial_without_pooling() {
    let handler = Arc::new(AnyTlsHandler::new());
    let node = zero_idle_anytls_node("speculative-abort");
    let pool: Arc<AnyTlsPool> = Arc::new(AnyTlsPool::new());
    let started = Arc::new(tokio::sync::Notify::new());
    let cancelled = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn({
        let handler = Arc::clone(&handler);
        let node = node.clone();
        let pool = Arc::clone(&pool);
        let started = Arc::clone(&started);
        let cancelled = Arc::clone(&cancelled);
        async move {
            let _ = handler
                .dial_udp_transport_speculative_with(
                    &node,
                    pool,
                    "8.8.8.8:53".parse().unwrap(),
                    None,
                    move || async move {
                        let _cancelled = CancelledDial(cancelled);
                        started.notify_one();
                        futures_util::future::pending::<anyhow::Result<Arc<AnyTlsSession>>>().await
                    },
                )
                .await;
        }
    });
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("the injected speculative dial must start");

    task.abort();
    let _ = task.await;
    assert!(
        cancelled.load(Ordering::Acquire),
        "aborting the speculative caller must drop the physical dial future"
    );
    assert_eq!(pool.metrics().sessions, 0);
    let first = pool.checkout_speculative().await.unwrap();
    let second = tokio::time::timeout(Duration::from_millis(100), pool.checkout_speculative())
        .await
        .expect("cancelled speculative work must not leave a provisional slot")
        .unwrap();
    assert!(matches!(
        first,
        crate::session::SpeculativeCheckout::Detached(_)
    ));
    assert!(matches!(
        second,
        crate::session::SpeculativeCheckout::Detached(_)
    ));
}

#[tokio::test]
async fn speculative_udp_generation_shutdown_cancels_injected_dial() {
    let handler = Arc::new(AnyTlsHandler::new());
    let node = zero_idle_anytls_node("speculative-shutdown");
    let pool: Arc<AnyTlsPool> = Arc::new(AnyTlsPool::new());
    let started = Arc::new(tokio::sync::Notify::new());
    let cancelled = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn({
        let handler = Arc::clone(&handler);
        let node = node.clone();
        let pool = Arc::clone(&pool);
        let started = Arc::clone(&started);
        let cancelled = Arc::clone(&cancelled);
        async move {
            handler
                .dial_udp_transport_speculative_with(
                    &node,
                    pool,
                    "8.8.8.8:53".parse().unwrap(),
                    None,
                    move || async move {
                        let _cancelled = CancelledDial(cancelled);
                        started.notify_one();
                        futures_util::future::pending::<anyhow::Result<Arc<AnyTlsSession>>>().await
                    },
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("the detached generation-owned dial must start");

    pool.shutdown();
    let result = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("pool shutdown must cancel the detached dial")
        .expect("speculative task must not panic");
    assert!(result.is_err());
    assert!(cancelled.load(Ordering::Acquire));
    assert_eq!(pool.metrics().sessions, 0);
}
