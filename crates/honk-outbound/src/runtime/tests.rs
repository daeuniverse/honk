use super::*;
use honk_config::types::NodeProtocol;
use std::sync::atomic::AtomicUsize;
mod vless_runtime;

fn node(name: &str, protocol: NodeProtocol) -> Node {
    let host = format!("{name}.example");
    let mut outbound = honk_config::node::OutboundConfig::from_protocol(protocol);
    let credential = "00000000-0000-4000-8000-000000000001".to_string();
    match &mut outbound {
        honk_config::node::OutboundConfig::Vmess(config) => config.uuid = Some(credential.clone()),
        honk_config::node::OutboundConfig::Vless(config) => config.uuid = Some(credential.clone()),
        honk_config::node::OutboundConfig::Tuic(config) => config.uuid = Some(credential.clone()),
        honk_config::node::OutboundConfig::Juicity(config) => config.uuid = Some(credential),
        _ => {}
    }
    let mut node = Node {
        name: name.to_string(),
        address: format!("{host}:443"),
        host,
        port: 443,
        outbound,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn vless_node(name: &str, multiplex: honk_config::node::VlessMultiplex) -> Node {
    let mut node = node(name, NodeProtocol::VLess);
    node.vless_mut().unwrap().multiplex = multiplex;
    node.id = node.derive_id();
    node
}
fn canonical_node(name: &str) -> Node {
    let mut node = Node {
        name: name.to_string(),
        address: "1.2.3.4:443".to_string(),
        host: "1.2.3.4".to_string(),
        port: 443,
        outbound: honk_config::node::OutboundConfig::AnyTls(Default::default()),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}
fn assert_admission(error: RuntimeRegistryError, code: &'static str, index: usize) {
    let index = index + 1;
    let RuntimeRegistryError::Admission(error) = error else {
        panic!("expected canonical registry admission error");
    };
    assert_eq!(error.diagnostic.code, code);
    assert_eq!(
        error.diagnostic.setting.to_string(),
        format!("nodes[{index}]")
    );
    assert_eq!(
        error.diagnostic.value,
        honk_config::diagnostic::SafeValue::Ordinal(index)
    );
}

#[test]
fn registry_admission_rejects_invalid_collections() {
    let mut stale = canonical_node("stale-endpoint");
    stale.address = "5.6.7.8:8443".to_string();
    stale.host = "5.6.7.8".to_string();
    stale.port = 8443;
    assert_admission(
        OutboundRuntimeRegistry::build(&[stale]).unwrap_err(),
        "noncanonical-node-id",
        0,
    );

    let first = canonical_node("endpoint-a");
    let mut second = first.clone();
    second.name = "endpoint-b".to_string();
    second.id = uuid::Uuid::new_v4();
    assert_admission(
        OutboundRuntimeRegistry::build_reusing(&[first, second], 1, None).unwrap_err(),
        "noncanonical-node-id",
        1,
    );

    let mut intrinsic = canonical_node("invalid-endpoint");
    intrinsic.port = 0;
    assert_admission(
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[intrinsic], 1, 1, 1, None)
            .unwrap_err(),
        "invalid-config-value",
        0,
    );

    let mut nil = canonical_node("nil-id");
    nil.id = uuid::Uuid::nil();
    assert_admission(
        OutboundRuntimeRegistry::build_reusing(&[nil], 1, None).unwrap_err(),
        "nil-node-id",
        0,
    );

    let duplicate = canonical_node("same-name");
    assert_admission(
        OutboundRuntimeRegistry::build(&[duplicate.clone(), duplicate]).unwrap_err(),
        "duplicate-node-id",
        1,
    );

    let direct = honk_config::config::Config::builtin_direct_node();
    let block = honk_config::config::Config::builtin_block_node();
    assert!(OutboundRuntimeRegistry::build(&[direct.clone(), block]).is_ok());
    let mut incorrect = direct;
    incorrect.address = "127.0.0.1:1".to_string();
    incorrect.host = "127.0.0.1".to_string();
    incorrect.port = 1;
    assert_admission(
        OutboundRuntimeRegistry::build(&[incorrect]).unwrap_err(),
        "invalid-config-value",
        0,
    );
}

#[test]
fn registry_admission_rechecks_dns_fork_source_state() {
    let node = canonical_node("dns-fork");
    let mut registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let runtime = registry.nodes.get_mut(&node.id).unwrap();
    let runtime = Arc::get_mut(runtime).unwrap();
    let embedded = Arc::get_mut(&mut runtime.node).unwrap();
    embedded.address = "5.6.7.8:8443".to_string();
    embedded.host = "5.6.7.8".to_string();
    embedded.port = 8443;

    assert_admission(
        registry.fork_for_dns().unwrap_err(),
        "noncanonical-node-id",
        0,
    );
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
async fn retirement_releases_cached_non_flow_state() {
    let anytls = node("anytls-retired", NodeProtocol::AnyTLS);
    let tuic = node("tuic-retired", NodeProtocol::Tuic);
    let registry = OutboundRuntimeRegistry::build(&[anytls.clone(), tuic.clone()]).unwrap();
    let anytls_runtime = registry.get(&anytls.id).unwrap();
    anytls_runtime.anytls_tls_connector().unwrap();
    let ProtocolRuntime::AnyTls(anytls_state) = &anytls_runtime.runtime else {
        panic!("AnyTLS runtime expected");
    };
    let tuic_runtime = registry.get(&tuic.id).unwrap();
    let ProtocolRuntime::Quic(quic) = &tuic_runtime.runtime else {
        panic!("TUIC runtime expected");
    };
    let client = Arc::new(FakeQuicClient::default());
    quic.client({
        let client = Arc::clone(&client);
        || async move { Ok(client) }
    })
    .await
    .unwrap();

    registry.retire_reusable_state().await;

    assert!(anytls_state.pool.is_retired());
    assert!(!anytls_runtime.tls_connector_loaded());
    assert!(anytls_runtime.anytls_tls_connector().is_err());
    assert!(client.warm_released.load(Ordering::Acquire));
    assert_eq!(quic.client_count(), Some(0));
    assert!(!client.force_closed.load(Ordering::Acquire));
}

#[tokio::test]
async fn warm_retention_releases_only_after_last_owner() {
    for node in [
        node("anytls-retained", NodeProtocol::AnyTLS),
        vless_node(
            "vless-retained",
            honk_config::node::VlessMultiplex::H2 { padding: false },
        ),
    ] {
        let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let runtime = registry.get(&node.id).unwrap();

        runtime.retain_warm(WarmRetention::Selector).await.commit();
        runtime.retain_warm(WarmRetention::Udp).await.commit();
        let retained = || match &runtime.runtime {
            ProtocolRuntime::AnyTls(anytls) => anytls.pool.is_warm_retained(),
            ProtocolRuntime::Vless(vless) => {
                vless.pool_is_warm_retained(honk_config::node::VlessUdpPath::H2)
            }
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

    assert_eq!(registry.reap_idle_resources(Instant::now()), 12);
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
        registry.reap_idle_resources(Instant::now() + TLS_IDLE_RETENTION),
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
    assert!(!anytls_runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session));
    assert!(!tuic_runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session));
    assert!(
        registry
            .get(&trojan.id)
            .unwrap()
            .is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session),
        "session-less protocols have nothing to retain either way"
    );

    let ProtocolRuntime::Quic(quic) = &tuic_runtime.runtime else {
        panic!("tuic runtime expected");
    };
    quic.client(|| async { Ok(Arc::new(FakeQuicClient::default())) })
        .await
        .unwrap();
    assert!(tuic_runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session));
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
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 3, 4, 4, None).unwrap();
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(first.acquire_dial_permit().await);
    }

    let (second, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 4, 99, 99, Some(&first))
            .unwrap();
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
async fn dns_fork_owns_sessions_but_preserves_dial_limits() {
    let node = node("dns", NodeProtocol::AnyTLS);
    let (main, _) = OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        std::slice::from_ref(&node),
        1,
        2,
        2,
        None,
    )
    .unwrap();
    let main = Arc::new(main);
    let dns = Arc::new(main.fork_for_dns().unwrap());

    main.begin_retirement();
    assert!(!dns.is_shutdown());

    let held = main.acquire_dial_permit().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(10), dns.acquire_dial_permit())
            .await
            .is_err()
    );
    drop(held);
    let dns_permit = tokio::time::timeout(Duration::from_millis(100), dns.acquire_dial_permit())
        .await
        .expect("released generation capacity must admit DNS");
    let (successor, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 2, 2, 2, Some(&main))
            .unwrap();
    let successor_permit = successor.acquire_dial_permit().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(10), successor.acquire_dial_permit())
            .await
            .is_err()
    );
    drop(dns_permit);
    tokio::time::timeout(Duration::from_millis(100), successor.acquire_dial_permit())
        .await
        .expect("released DNS capacity must admit the successor");
    drop(successor_permit);

    let dns_runtime = dns.get(&node.id).unwrap();
    let connector = dns_runtime.anytls_tls_connector().unwrap();
    let connector_lifetime = Arc::downgrade(&connector);
    drop(connector);
    main.shutdown().await;
    assert!(!dns.is_shutdown());
    assert!(connector_lifetime.upgrade().is_some());
    let dns_pool = dns_runtime.anytls_pool().unwrap();
    assert!(!dns_pool.is_retired());
    dns.shutdown().await;
    assert!(dns_pool.is_retired());
    assert!(connector_lifetime.upgrade().is_none());
    assert!(
        dns_runtime.anytls_tls_connector().is_err(),
        "a delayed dial cannot rebuild TLS state after terminal shutdown"
    );
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
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 2, 2, 2, None).unwrap();
    let (second, _) =
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(&[], 2, 99, 99, Some(&first))
            .unwrap();
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
    let unchanged = vless_node(
        "vless",
        honk_config::node::VlessMultiplex::H2 { padding: false },
    );
    let mut changed = node("tuic", NodeProtocol::Tuic);
    let first = OutboundRuntimeRegistry::build(&[unchanged.clone(), changed.clone()]).unwrap();
    let first_unchanged = first.get(&unchanged.id).unwrap();
    let first_changed = first.get(&changed.id).unwrap();

    changed.tls_mut().unwrap().sni = Some("new.example.com".to_string());
    changed.id = changed.derive_id();
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
    first.retire_reusable_state().await;
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

#[test]
fn build_reusing_ignores_parse_timestamps() {
    let mut parsed = node("trojan", NodeProtocol::Trojan);
    parsed.tls_mut().unwrap().sni = Some("example.com".to_string());
    parsed.id = parsed.derive_id();
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

#[cfg(test)]
mod fallible_factory_tests {
    use super::*;

    #[test]
    fn try_ephemeral_rejects_nil_id_before_building() {
        let mut node = canonical_node("nil-ephemeral");
        node.id = uuid::Uuid::nil();
        assert_admission(
            NodeRuntime::try_ephemeral(&node).unwrap_err(),
            "nil-node-id",
            0,
        );
    }

    #[test]
    fn try_ephemeral_rejects_stale_id_before_cloning() {
        let mut node = canonical_node("stale-ephemeral");
        node.address = "5.6.7.8:8443".into();
        node.host = "5.6.7.8".into();
        node.port = 8443;
        assert_admission(
            NodeRuntime::try_ephemeral(&node).unwrap_err(),
            "noncanonical-node-id",
            0,
        );
    }

    #[test]
    fn try_ephemeral_rejects_intrinsic_invalidity_before_identity() {
        let mut node = canonical_node("invalid-ephemeral");
        node.port = 0;
        assert_admission(
            NodeRuntime::try_ephemeral(&node).unwrap_err(),
            "invalid-config-value",
            0,
        );
    }
}
