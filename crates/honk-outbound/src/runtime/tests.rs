use super::*;
use honk_config::types::NodeProtocol;
use std::sync::atomic::AtomicUsize;

fn node(name: &str, protocol: NodeProtocol) -> Node {
    Node {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        address: "1.2.3.4:443".to_string(),
        outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
        ..Default::default()
    }
}

fn vless_node(name: &str, mode: honk_config::node::WireMode) -> Node {
    let mut node = node(name, NodeProtocol::VLess);
    node.vless_mut().unwrap().mode = mode;
    node
}

#[test]
fn vless_registry_runtime_follows_wire_mode() {
    use honk_config::node::WireMode;
    for (mode, expected) in [
        (WireMode::Legacy, 0),
        (WireMode::UotV2, 0),
        (WireMode::Xudp, 0),
        (WireMode::H2mux, 1),
        (WireMode::H2muxPadded, 1),
        (WireMode::MuxCool, 2),
    ] {
        let node = vless_node("vless", mode);
        let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let actual = match &registry.get(&node.id).unwrap().runtime {
            ProtocolRuntime::None => 0,
            ProtocolRuntime::VlessMux(VlessMuxRuntime::H2(_)) => 1,
            ProtocolRuntime::VlessMux(VlessMuxRuntime::Cool(_)) => 2,
            _ => panic!("unexpected VLESS runtime"),
        };
        assert_eq!(actual, expected);
    }
}

#[derive(Default)]
struct FakeQuicClient {
    force_closed: AtomicBool,
    warm_released: AtomicBool,
}

#[async_trait::async_trait]
impl QuicRuntimeClient for FakeQuicClient {
    fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }

    async fn force_close(&self) {
        self.force_closed.store(true, Ordering::Release);
    }

    async fn release_warm(&self) {
        self.warm_released.store(true, Ordering::Release);
    }
}

#[test]
fn anytls_connector_is_lazy_shared_and_generation_local() {
    let node = node("anytls", NodeProtocol::AnyTLS);
    let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let first_runtime = first.get(&node.id).unwrap();
    assert!(!first_runtime.tls_connector_loaded());
    let first_connector = first_runtime.anytls_tls_connector().unwrap();
    assert!(first_runtime.tls_connector_loaded());
    let same_connector = first.get(&node.id).unwrap().anytls_tls_connector().unwrap();
    assert!(Arc::ptr_eq(&first_connector, &same_connector));

    let reloaded = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let reloaded_connector = reloaded
        .get(&node.id)
        .unwrap()
        .anytls_tls_connector()
        .unwrap();
    assert!(!Arc::ptr_eq(&first_connector, &reloaded_connector));
}

#[tokio::test]
async fn warm_retention_releases_only_after_last_owner() {
    for node in [
        node("anytls-retained", NodeProtocol::AnyTLS),
        vless_node("vless-retained", honk_config::node::WireMode::H2mux),
    ] {
        let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let runtime = registry.get(&node.id).unwrap();

        runtime.retain_warm(WarmRetention::Selector).await.commit();
        runtime.retain_warm(WarmRetention::Udp).await.commit();
        let retained = || match &runtime.runtime {
            ProtocolRuntime::AnyTls(anytls) => anytls.pool.is_warm_retained(),
            ProtocolRuntime::VlessMux(vless) => vless.is_warm_retained(),
            _ => panic!("session protocol must own a pool"),
        };
        assert!(retained());

        runtime.release_warm(WarmRetention::Selector).await;
        assert!(retained());

        runtime.release_warm(WarmRetention::Udp).await;
        assert!(!retained());
    }
}

#[test]
fn refreshed_connector_rejects_stale_reaper_sample() {
    let node = node("anytls", NodeProtocol::AnyTLS);
    let slot = TlsConnectorSlot::default();
    let first = slot.get_or_build(&node).unwrap();
    let stale_sample = slot.sample().unwrap();

    let refreshed = slot.get_or_build(&node).unwrap();
    assert!(Arc::ptr_eq(&first, &refreshed));
    assert!(!slot.evict_if_sample(stale_sample));
    assert!(slot.is_loaded());

    assert!(slot.evict_if_sample(slot.sample().unwrap()));
    assert!(!slot.is_loaded());
}

#[test]
fn reap_keeps_recent_active_ratio_and_rebuilds_evicted_connectors() {
    let nodes: Vec<_> = (0..20)
        .map(|index| node(&format!("anytls-{index}"), NodeProtocol::AnyTLS))
        .collect();
    let registry = OutboundRuntimeRegistry::build(&nodes).unwrap();
    let loaded: Vec<_> = nodes
        .iter()
        .map(|node| {
            let runtime = registry.get(&node.id).unwrap();
            let connector = runtime.anytls_tls_connector().unwrap();
            (runtime, connector)
        })
        .collect();

    assert_eq!(registry.reap_tls_connectors(Instant::now()), 12);
    assert_eq!(
        loaded
            .iter()
            .filter(|(runtime, _)| runtime.tls_connector_loaded())
            .count(),
        8
    );
    let evicted = loaded
        .iter()
        .find(|(runtime, _)| !runtime.tls_connector_loaded())
        .unwrap();
    let rebuilt = evicted.0.anytls_tls_connector().unwrap();
    assert!(!Arc::ptr_eq(&evicted.1, &rebuilt));
}

#[test]
fn reap_drops_idle_connector_even_inside_hot_ratio() {
    let node = node("anytls", NodeProtocol::AnyTLS);
    let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let runtime = registry.get(&node.id).unwrap();
    runtime.anytls_tls_connector().unwrap();
    assert_eq!(
        registry.reap_tls_connectors(Instant::now() + TLS_IDLE_RETENTION),
        1
    );
    assert!(!runtime.tls_connector_loaded());
}

#[tokio::test]
async fn warm_resources_report_session_state_only() {
    let anytls = node("anytls", NodeProtocol::AnyTLS);
    let trojan = node("trojan", NodeProtocol::Trojan);
    let tuic = node("tuic", NodeProtocol::Tuic);
    let registry =
        OutboundRuntimeRegistry::build(&[anytls.clone(), trojan.clone(), tuic.clone()]).unwrap();

    let anytls_runtime = registry.get(&anytls.id).unwrap();
    let tuic_runtime = registry.get(&tuic.id).unwrap();
    assert!(!anytls_runtime.is_warm_or_stateless());
    assert!(!tuic_runtime.is_warm_or_stateless());
    assert!(
        registry.get(&trojan.id).unwrap().is_warm_or_stateless(),
        "session-less protocols have nothing to retain either way"
    );

    struct FakeClient;
    #[async_trait::async_trait]
    impl QuicRuntimeClient for FakeClient {
        fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
            self
        }
        async fn force_close(&self) {}
        async fn release_warm(&self) {}
    }
    let ProtocolRuntime::Quic(quic) = &tuic_runtime.runtime else {
        panic!("tuic runtime expected");
    };
    quic.client(|| async { Ok(Arc::new(FakeClient)) })
        .await
        .unwrap();
    assert!(tuic_runtime.is_warm_or_stateless());
}

#[tokio::test]
async fn build_and_get_roundtrip() {
    let nodes = vec![
        node("a", NodeProtocol::AnyTLS),
        node("b", NodeProtocol::Trojan),
    ];
    let registry = OutboundRuntimeRegistry::build(&nodes).unwrap();
    assert_eq!(registry.len(), 2);
    let rt = registry.get(&nodes[0].id).unwrap();
    assert_eq!(rt.node.name, "a");
    assert!(rt.udp_capable);
    registry.shutdown().await; // terminal cleanup is idempotent
}

#[test]
fn rejects_nil_uuid() {
    let mut n = node("nil", NodeProtocol::Trojan);
    n.id = uuid::Uuid::nil();
    let err = OutboundRuntimeRegistry::build(&[n]).unwrap_err();
    assert!(matches!(err, RuntimeRegistryError::NilId(_)));
}

#[test]
fn rejects_duplicate_uuid() {
    let a = node("a", NodeProtocol::Trojan);
    let mut b = node("b", NodeProtocol::SS);
    b.id = a.id;
    let err = OutboundRuntimeRegistry::build(&[a, b]).unwrap_err();
    assert!(matches!(err, RuntimeRegistryError::DuplicateId(..)));
}

#[test]
fn explicit_dial_limit_is_generation_owned() {
    let (registry, _) = OutboundRuntimeRegistry::build_reusing(&[], 7, None).unwrap();
    assert_eq!(registry.dial_limit(), 7);
    let (minimum, _) = OutboundRuntimeRegistry::build_reusing(&[], 0, None).unwrap();
    assert_eq!(minimum.dial_limit(), 1);
}

#[tokio::test]
async fn overlapping_generations_share_the_startup_dial_ceiling() {
    let (first, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 3, 4, None).unwrap();
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(first.acquire_dial_permit().await);
    }

    let (second, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 4, 99, Some(&first)).unwrap();
    assert_eq!(second.dial_limit(), 4);
    held.push(second.acquire_dial_permit().await);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), second.acquire_dial_permit())
            .await
            .is_err()
    );

    drop(held.pop());
    tokio::time::timeout(Duration::from_millis(100), second.acquire_dial_permit())
        .await
        .expect("released process capacity must admit the successor");
}

#[tokio::test]
async fn one_dial_permit_serializes_real_tcp_fallbacks() {
    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    let first_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first_listener.local_addr().unwrap();
    let second_addr = second_listener.local_addr().unwrap();
    let addrs = [first_addr, second_addr];
    let release_first = Arc::new(tokio::sync::Notify::new());
    let first_started = Arc::new(tokio::sync::Notify::new());
    let second_started = Arc::new(tokio::sync::Notify::new());
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
            .unwrap()
            .0,
    );

    let dial = tokio::spawn({
        let release_first = Arc::clone(&release_first);
        let first_started = Arc::clone(&first_started);
        let second_started = Arc::clone(&second_started);
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        let generation = Arc::clone(&registry);
        async move {
            generation
                .scope_dials(async move {
                    crate::address_race::race_resolved_addrs_with_stagger(
                        &addrs,
                        Duration::ZERO,
                        move |addr| {
                            let release_first = Arc::clone(&release_first);
                            let first_started = Arc::clone(&first_started);
                            let second_started = Arc::clone(&second_started);
                            let active = Arc::clone(&active);
                            let peak = Arc::clone(&peak);
                            async move {
                                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                                peak.fetch_max(now, Ordering::SeqCst);
                                let _active = Active(active);
                                if addr == second_addr {
                                    second_started.notify_one();
                                }
                                let stream = tokio::net::TcpStream::connect(addr).await?;
                                if addr == first_addr {
                                    first_started.notify_one();
                                    release_first.notified().await;
                                    drop(stream);
                                    Err(std::io::Error::other("first address failed"))
                                } else {
                                    Ok(stream)
                                }
                            }
                        },
                    )
                    .await
                })
                .await
        }
    });

    first_started.notified().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), second_started.notified())
            .await
            .is_err(),
        "the fallback started without a second physical permit"
    );
    release_first.notify_one();
    let winner = dial.await.unwrap().unwrap().unwrap();
    assert_eq!(winner.peer_addr().unwrap(), second_addr);
    assert_eq!(peak.load(Ordering::SeqCst), 1);
    assert_eq!(active.load(Ordering::SeqCst), 0);

    let (mut first_server, _) = first_listener.accept().await.unwrap();
    let (second_server, _) = second_listener.accept().await.unwrap();
    use tokio::io::AsyncReadExt as _;
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(1), first_server.read(&mut byte))
        .await
        .expect("failed TCP attempt stayed open")
        .unwrap();
    assert_eq!(read, 0);
    drop((winner, second_server));
}

#[tokio::test(start_paused = true)]
async fn overlapping_generations_bound_physical_address_attempts() {
    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    let (first, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 2, 2, None).unwrap();
    let (second, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 2, 99, Some(&first)).unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let run = |generation: Arc<OutboundRuntimeRegistry>| {
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        async move {
            let addrs = [
                "192.0.2.1:443".parse().unwrap(),
                "[2001:db8::1]:443".parse().unwrap(),
            ];
            generation
                .scope_dials(crate::address_race::race_resolved_addrs_with_stagger(
                    &addrs,
                    Duration::ZERO,
                    move |addr| {
                        let active = Arc::clone(&active);
                        let peak = Arc::clone(&peak);
                        async move {
                            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                            let _active = Active(active);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            Err::<(), _>(addr)
                        }
                    },
                ))
                .await
        }
    };

    let (old_result, new_result) = tokio::join!(run(Arc::new(first)), run(Arc::new(second)));
    assert!(matches!(old_result, Some(Err(_))));
    assert!(matches!(new_result, Some(Err(_))));
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[test]
fn udp_capability_matrix() {
    let anytls = node("x", NodeProtocol::AnyTLS);
    assert!((crate::descriptor::descriptor(anytls.protocol()).supports_udp)(&anytls));
    let vmess = node("x", NodeProtocol::VMess);
    assert!(!(crate::descriptor::descriptor(vmess.protocol()).supports_udp)(&vmess));
    let hy2 = node("x", NodeProtocol::Hysteria2);
    assert!((crate::descriptor::descriptor(hy2.protocol()).supports_udp)(&hy2));
}

#[test]
fn build_reusing_reuses_unchanged_nodes_and_reports_them() {
    let unchanged = vless_node("vless", honk_config::node::WireMode::H2mux);
    let mut changed = node("tuic", NodeProtocol::Tuic);
    let first = OutboundRuntimeRegistry::build(&[unchanged.clone(), changed.clone()]).unwrap();
    let first_unchanged = first.get(&unchanged.id).unwrap();
    let first_changed = first.get(&changed.id).unwrap();

    changed.tls_mut().unwrap().sni = Some("new.example.com".to_string());
    let (second, reused) = OutboundRuntimeRegistry::build_reusing(
        &[unchanged.clone(), changed.clone()],
        64,
        Some(&first),
    )
    .unwrap();
    assert_eq!(reused, HashSet::from([unchanged.id]));
    assert!(Arc::ptr_eq(
        &first_unchanged,
        &second.get(&unchanged.id).unwrap()
    ));
    assert!(!Arc::ptr_eq(
        &first_changed,
        &second.get(&changed.id).unwrap()
    ));
}

#[tokio::test]
async fn reused_runtime_is_closed_by_the_new_owner_only_after_commit() {
    let unchanged = node("anytls", NodeProtocol::AnyTLS);
    let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&unchanged)).unwrap();
    let (second, _) =
        OutboundRuntimeRegistry::build_reusing(std::slice::from_ref(&unchanged), 64, Some(&first))
            .unwrap();

    // A build alone transfers nothing: the old generation still closes
    // the runtime if the reload aborts before the commit point.
    first.shutdown().await;
    let ProtocolRuntime::AnyTls(anytls) = &second.get(&unchanged.id).unwrap().runtime else {
        panic!("anytls runtime expected");
    };
    assert!(
        anytls.pool.is_retired(),
        "aborted reload: old generation remains the owner"
    );

    // Committed transfer: the old generation skips the moved runtime;
    // the new generation closes it as its full owner.
    let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&unchanged)).unwrap();
    let (second, reused) =
        OutboundRuntimeRegistry::build_reusing(std::slice::from_ref(&unchanged), 64, Some(&first))
            .unwrap();
    first.mark_moved_out(reused);
    first.drain_session_pools();
    first.shutdown().await;
    let ProtocolRuntime::AnyTls(anytls) = &second.get(&unchanged.id).unwrap().runtime else {
        panic!("anytls runtime expected");
    };
    assert!(
        !anytls.pool.is_retired(),
        "committed reload: old generation leaves the moved runtime alone"
    );
    second.shutdown().await;
    assert!(
        anytls.pool.is_retired(),
        "the new generation owns the reused runtime's shutdown"
    );
}

#[tokio::test]
async fn vless_mux_pools_retire_and_shut_down_with_their_generation() {
    use honk_config::node::WireMode;
    for mode in [WireMode::H2mux, WireMode::MuxCool] {
        let node = vless_node("vless", mode);
        let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let runtime = registry.get(&node.id).unwrap();
        let ProtocolRuntime::VlessMux(mux) = &runtime.runtime else {
            panic!("VLESS mux runtime expected");
        };
        registry.drain_session_pools();
        assert!(mux.is_retired());

        let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let runtime = registry.get(&node.id).unwrap();
        let ProtocolRuntime::VlessMux(mux) = &runtime.runtime else {
            panic!("VLESS mux runtime expected");
        };
        registry.shutdown().await;
        assert!(mux.is_retired());
    }
}

#[test]
fn vless_mux_runtime_reuse_is_mode_exact() {
    use honk_config::node::WireMode;
    let node = vless_node("vless-cool", WireMode::MuxCool);
    let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let (unchanged, reused) =
        OutboundRuntimeRegistry::build_reusing(std::slice::from_ref(&node), 64, Some(&first))
            .unwrap();
    assert_eq!(reused, HashSet::from([node.id]));
    assert!(Arc::ptr_eq(
        &first.get(&node.id).unwrap(),
        &unchanged.get(&node.id).unwrap()
    ));

    let mut changed = node.clone();
    changed.vless_mut().unwrap().mode = WireMode::H2mux;
    let (changed_registry, reused) =
        OutboundRuntimeRegistry::build_reusing(std::slice::from_ref(&changed), 64, Some(&first))
            .unwrap();
    assert!(reused.is_empty());
    assert!(!Arc::ptr_eq(
        &first.get(&node.id).unwrap(),
        &changed_registry.get(&node.id).unwrap()
    ));
    assert!(matches!(
        changed_registry.get(&node.id).unwrap().runtime,
        ProtocolRuntime::VlessMux(VlessMuxRuntime::H2(_))
    ));
}

#[test]
fn build_reusing_ignores_parse_timestamps() {
    let mut parsed = node("trojan", NodeProtocol::Trojan);
    parsed.tls_mut().unwrap().sni = Some("example.com".to_string());
    let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&parsed)).unwrap();
    let mut reparsed = parsed.clone();
    reparsed.created_at = chrono::Utc::now();
    reparsed.updated_at = chrono::Utc::now();
    let (second, _) =
        OutboundRuntimeRegistry::build_reusing(std::slice::from_ref(&reparsed), 64, Some(&first))
            .unwrap();
    assert!(Arc::ptr_eq(
        &first.get(&parsed.id).unwrap(),
        &second.get(&parsed.id).unwrap()
    ));
}

#[tokio::test]
async fn speculative_quic_publish_keeps_a_concurrent_incumbent() {
    let runtime = QuicRuntime::new(true);
    let incumbent: Arc<FakeQuicClient> = runtime
        .client(|| async { Ok(Arc::new(FakeQuicClient::default())) })
        .await
        .unwrap();
    let detached = Arc::new(FakeQuicClient::default());
    let detached_weak = Arc::downgrade(&detached);

    runtime.publish_client(detached).await.unwrap();

    assert!(detached_weak.upgrade().is_none());
    let selected: Arc<FakeQuicClient> = runtime
        .client(|| async { panic!("occupied slot must not rebuild") })
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&selected, &incumbent));
    assert!(!incumbent.warm_released.load(Ordering::Acquire));
}

#[tokio::test]
async fn cancelled_quic_publish_before_slot_lock_changes_nothing() {
    let runtime = Arc::new(QuicRuntime::new(true));
    let state_guard = runtime.state.lock().await;
    let detached = Arc::new(FakeQuicClient::default());
    let detached_weak = Arc::downgrade(&detached);
    let publish = tokio::spawn({
        let runtime = Arc::clone(&runtime);
        async move { runtime.publish_client(detached).await }
    });
    tokio::task::yield_now().await;

    publish.abort();
    let _ = publish.await;
    drop(state_guard);

    assert_eq!(runtime.client_count(), Some(0));
    assert!(detached_weak.upgrade().is_none());
}

#[tokio::test]
async fn cancelled_last_quic_release_still_clears_the_client_slot() {
    let node = node("tuic-release", NodeProtocol::Tuic);
    let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let runtime = registry.get(&node.id).unwrap();
    let profiles = runtime.quic_flow_control_profiles().unwrap();
    let client: Arc<FakeQuicClient> = runtime
        .quic_client(|| async { Ok(Arc::new(FakeQuicClient::default())) })
        .await
        .unwrap();
    runtime.retain_warm(WarmRetention::Selector).await.commit();
    let quic = match &runtime.runtime {
        ProtocolRuntime::Quic(quic) => quic,
        _ => panic!("TUIC node must own a QUIC runtime"),
    };
    let state_guard = quic.state.lock().await;
    let release = tokio::spawn({
        let runtime = Arc::clone(&runtime);
        async move { runtime.release_warm(WarmRetention::Selector).await }
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime.warm_retention.try_lock().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached cleanup must hold the retention lock while blocked");
    release.abort();
    let _ = release.await;
    drop(state_guard);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if quic.client_count() == Some(0) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached cleanup must clear the QUIC client slot");
    assert!(client.warm_released.load(Ordering::Acquire));
    assert!(Arc::ptr_eq(
        &profiles,
        &runtime.quic_flow_control_profiles().unwrap()
    ));
}

#[tokio::test]
async fn quic_runtime_close_covers_client_and_rejects_new_builds() {
    let runtime = QuicRuntime::new(true);
    let client: Arc<FakeQuicClient> = runtime
        .client(|| async { Ok(Arc::new(FakeQuicClient::default())) })
        .await
        .unwrap();
    runtime.force_close().await;
    assert!(client.force_closed.load(Ordering::Acquire));
    assert!(
        runtime
            .client::<FakeQuicClient, _, _>(|| async { Ok(Arc::new(FakeQuicClient::default())) })
            .await
            .is_err(),
        "a closed QUIC runtime rejects new client builds"
    );
}

#[tokio::test]
async fn retirement_is_terminal_and_shutdown_remains_idempotent() {
    let anytls = node("anytls", NodeProtocol::AnyTLS);
    let registry = OutboundRuntimeRegistry::build(&[anytls]).unwrap();
    assert!(!registry.is_shutdown());
    registry.begin_retirement();
    assert!(registry.is_shutdown());
    registry.shutdown().await;
    registry.shutdown().await;
    assert!(
        registry.is_shutdown(),
        "retirement and force shutdown remain terminal and idempotent"
    );
}
