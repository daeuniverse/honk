use super::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use super::*;
use crate::control::udp_endpoint::UdpEndpoint;
use crate::dns::query::{IngressProfile, is_exact_dns_query, validate_exact_dns_query};
pub(super) mod support;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use support::KernelUdpReplySocketFactory;
use support::{
    FailingUdpTestReplySocketFactory, UdpTestHandler, UdpTestMode, addr, assert_udp_outbound,
    bytes_of, control_plane, dns_query_payload, serve_test_udp, serve_test_udp_to, udp_test_config,
    udp_test_forwarder, udp_test_handle, udp_test_handle_with_default_pool,
    udp_test_handle_with_reply_factory, udp_test_node,
};

mod admission;
mod diagnostics;
mod dns_tcp_ownership;
mod dns_udp_ownership;
mod health;

#[test]
fn interrupting_groups_enable_tracking_without_the_clash_api() {
    let groups = [Group {
        interrupt_connections: true,
        ..Default::default()
    }];
    let manager = GroupManager::new(&groups, &[]);
    let manager_cell = Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
        &groups,
        &[],
    ))));
    let tracker = Arc::new(ConnectionTracker::new());

    reload::install_interrupt_callback(&manager, &manager_cell, &tracker);

    assert!(tracker.is_enabled());
}

#[tokio::test]
async fn health_push_re_resolves_after_reload_writer() {
    let node = udp_test_node();
    let old_config = udp_test_config(
        "old",
        vec![node.clone()],
        vec![Group {
            name: "old".into(),
            nodes: vec![node.id],
            ..Default::default()
        }],
    );
    let new_config = udp_test_config(
        "new",
        vec![node.clone()],
        vec![
            Group {
                name: "unused".into(),
                ..Default::default()
            },
            Group {
                name: "new".into(),
                nodes: vec![node.id],
                ..Default::default()
            },
        ],
    );
    let config = Arc::new(RwLock::new(Arc::new(old_config.clone())));
    let group_manager: SharedGroupManager = Arc::new(parking_lot::RwLock::new(Arc::new(
        GroupManager::new(&old_config.groups, &old_config.nodes),
    )));
    let outbound_id_map = Arc::new(parking_lot::RwLock::new(reload::build_outbound_id_map(
        &old_config,
    )));
    let alive_set = Arc::new(AliveDialerSet::new());
    let ebpf: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(
        crate::ebpf::mock::MockEbpfBackend::new(),
    )));
    let health_publisher = Arc::new(runtime::OutboundHealthPublisher::new(
        Arc::clone(&ebpf),
        Arc::clone(&config),
        Arc::clone(&group_manager),
        Arc::clone(&outbound_id_map),
        Arc::clone(&alive_set),
    ));

    let mut config_writer = config.write().await;
    let mut backend_writer = ebpf.write().await;
    backend_writer.set_outbound_alive(2, 1, 0, false).unwrap();
    backend_writer.set_outbound_alive(3, 1, 0, false).unwrap();
    *config_writer = Arc::new(new_config.clone());
    *outbound_id_map.write() = reload::build_outbound_id_map(&new_config);
    *group_manager.write() = Arc::new(GroupManager::new(&new_config.groups, &new_config.nodes));

    let update = tokio::spawn(Arc::clone(&health_publisher).publish(node.id, 1, 0));
    tokio::task::yield_now().await;
    assert!(!update.is_finished());
    drop(config_writer);
    tokio::task::yield_now().await;
    assert!(!update.is_finished());
    drop(backend_writer);

    update.await.unwrap();
    let backend = ebpf.read().await;
    assert!(!backend.get_outbound_alive(2, 1, 0).unwrap());
    assert!(backend.get_outbound_alive(3, 1, 0).unwrap());
}

#[cfg(feature = "ebpf")]
#[test]
fn nfqueue_actor_queue_bounds_small_and_max_payloads() {
    let stats = Arc::new(StatsManager::new());
    let queue =
        NfqueueActorQueue::new(Arc::clone(&stats), Arc::new(tokio::sync::Semaphore::new(1)));
    let oldest = Instant::now() - Duration::from_millis(25);
    assert!(queue.try_enqueue(oldest, 1_200));
    assert!(queue.try_enqueue(Instant::now(), 65_507));

    let snapshot = stats.udp_snapshot().nfqueue;
    assert_eq!(snapshot.actor_queue_depth, 2);
    assert_eq!(snapshot.actor_queued_bytes, 66_707);
    assert!(snapshot.actor_oldest_age_nanos >= Duration::from_millis(25).as_nanos() as u64);

    drop(queue.dequeue(1_200));
    drop(queue.dequeue(65_507));
    let mut max_payloads = 0;
    while queue.try_enqueue(Instant::now(), 65_507) {
        max_payloads += 1;
    }
    let saturated = stats.udp_snapshot().nfqueue;
    assert!(saturated.actor_queue_depth <= NFQUEUE_INGEST_QUEUE_LEN as u64);
    assert!(saturated.actor_queued_bytes <= NFQUEUE_INGEST_BYTE_BUDGET as u64);
    assert!(max_payloads < NFQUEUE_INGEST_QUEUE_LEN);

    for _ in 0..max_payloads {
        drop(queue.dequeue(65_507));
    }
    let empty = stats.udp_snapshot().nfqueue;
    assert_eq!(empty.actor_queue_depth, 0);
    assert_eq!(empty.actor_queued_bytes, 0);
    assert_eq!(empty.actor_oldest_age_nanos, 0);
}

#[cfg(feature = "ebpf")]
#[tokio::test]
async fn nfqueue_startup_degradation_clears_config_and_effective_flag() {
    use honk_ebpf_common::{DATAPATH_FLAG_NFQ_ENABLED, DATAPATH_FLAG_NFQ_READY};

    let mut config = Config::default();
    config.global.nfqueue_enable = true;
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let writes = backend.datapath_flags_writes.clone();
    let mut control = ControlPlane::new(
        config,
        Box::new(backend),
        Router::new(&[], "direct").unwrap(),
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap();
    control.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", "Proxy"),
    )));
    control.start_datapath_flags_coordinator().unwrap();

    let mut enabled = true;
    control
        .degrade_nfqueue_startup(&mut enabled, anyhow::anyhow!("injected startup failure"))
        .await;

    assert!(!enabled);
    assert!(!control.config_handle().read().await.global.nfqueue_enable);
    control
        .datapath_flags_handle()
        .expect("datapath flags coordinator")
        .initialize(enabled, false)
        .await
        .unwrap();
    let published = writes.lock().last().copied().expect("initial flags");
    assert_eq!(
        published & (DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY),
        0
    );
}

#[cfg(feature = "ebpf")]
#[test]
fn nfqueue_actor_acquires_slow_permits_only_at_dequeue() {
    let limit = Arc::new(tokio::sync::Semaphore::new(1));
    let queue = NfqueueActorQueue::new(Arc::new(StatsManager::new()), Arc::clone(&limit));
    assert!(queue.try_enqueue(Instant::now(), 0));
    assert!(queue.try_enqueue(Instant::now(), 0));
    assert_eq!(limit.available_permits(), 1);

    let first = queue.dequeue(0).expect("first dequeued request permit");
    assert_eq!(limit.available_permits(), 0);
    drop(first);
    assert!(queue.dequeue(0).is_some());
}

#[cfg(feature = "ebpf")]
#[test]
fn nfqueue_token_retry_backoff_caps_at_thirty_seconds() {
    let mut backoff = NfqueueTokenRetryBackoff::default();
    assert_eq!(backoff.failed(), Duration::from_secs(1));
    assert_eq!(backoff.failed(), Duration::from_secs(2));
    assert_eq!(backoff.failed(), Duration::from_secs(5));
    assert_eq!(backoff.failed(), Duration::from_secs(30));
    assert_eq!(backoff.failed(), Duration::from_secs(30));
    backoff.reset();
    assert_eq!(backoff.failed(), Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn network_refresh_retry_resends_with_backoff_then_stops() {
    let (tx, mut rx) = mpsc::channel(4);
    let retry = spawn_network_refresh_retry(tx);

    for delay in [5, 15, 60] {
        tokio::time::advance(Duration::from_secs(delay)).await;
        assert!(matches!(
            rx.recv().await,
            Some(ControlCommand::NetworkChanged)
        ));
    }
    retry
        .await
        .expect("retry task stops after the backoff ladder");
}

#[tokio::test(start_paused = true)]
async fn network_refresh_retry_exits_when_control_plane_is_gone() {
    let (tx, rx) = mpsc::channel::<ControlCommand>(1);
    drop(rx);
    let retry = spawn_network_refresh_retry(tx);
    tokio::time::advance(Duration::from_secs(5)).await;
    retry.await.expect("retry task exits on a closed channel");
}

#[tokio::test(start_paused = true)]
async fn startup_failure_drops_saturated_control_receiver() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut config = Config::default();
    config.dns.bind = format!("tcp://{}", listener.local_addr().unwrap());
    let mut control_plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        Router::new(&[], "direct").unwrap(),
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap();

    let command_tx = control_plane.command_sender();
    for _ in 0..command_tx.max_capacity() {
        command_tx.send(ControlCommand::Shutdown).await.unwrap();
    }
    let mut blocked_delivery = std::pin::pin!(command_tx.send(ControlCommand::Shutdown));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut blocked_delivery)
            .await
            .is_err(),
        "the producer must be backpressured before startup fails"
    );

    control_plane
        .run()
        .await
        .expect_err("occupied dns.bind must fail startup");

    assert!(
        tokio::time::timeout(Duration::from_secs(1), blocked_delivery)
            .await
            .expect("receiver drop must wake the blocked producer")
            .is_err(),
        "the abandoned producer must observe the closed control channel"
    );
}

#[test]
fn test_build_dns_probe_query() {
    let q = build_dns_probe_query();
    assert_eq!(&q[..2], &[0x12, 0x34]); // fixed id, validated on the response
    assert_eq!(q[2], 0x01); // RD (recursion desired)
    assert_eq!(q[5], 1); // QDCOUNT = 1
    assert_eq!(&q[q.len() - 4..], &[0, 1, 0, 1]); // QTYPE A / QCLASS IN
}

#[tokio::test]
async fn test_resolve_udp_check_target() {
    let fallback: SocketAddr = "8.8.8.8:53".parse().unwrap();
    assert_eq!(resolve_udp_check_target(&[], None).await.unwrap(), fallback);
    assert_eq!(
        resolve_udp_check_target(&["   ".into()], None)
            .await
            .unwrap(),
        fallback
    );
    // Bare IP literals get the default DNS port.
    assert_eq!(
        resolve_udp_check_target(&["1.1.1.1".into()], None)
            .await
            .unwrap(),
        "1.1.1.1:53".parse().unwrap()
    );
    assert_eq!(
        resolve_udp_check_target(&["2001:4860:4860::8888".into()], None)
            .await
            .unwrap(),
        "[2001:4860:4860::8888]:53".parse().unwrap()
    );
    // Full socket addresses (v4 or bracketed v6) are kept as-is.
    assert_eq!(
        resolve_udp_check_target(&["1.1.1.1:5353".into()], None)
            .await
            .unwrap(),
        "1.1.1.1:5353".parse().unwrap()
    );
    assert_eq!(
        resolve_udp_check_target(&["[2606:4700:4700::1111]:53".into()], None)
            .await
            .unwrap(),
        "[2606:4700:4700::1111]:53".parse().unwrap()
    );
    // Literals win over domain entries anywhere in the list (poison-proof).
    assert_eq!(
        resolve_udp_check_target(&["dns.google".into(), "8.8.8.8".into()], None)
            .await
            .unwrap(),
        "8.8.8.8:53".parse().unwrap()
    );
    // host:port resolves via the system resolver ("localhost" needs no
    // external network).
    let addr = resolve_udp_check_target(&["localhost:5353".into()], None)
        .await
        .unwrap();
    assert_eq!(addr.port(), 5353);
    assert!(addr.ip().is_loopback());

    // A domain entry is resolved through the installed hook when present.
    let hook: crate::outbound::ResolveHook = std::sync::Arc::new(|host, port| {
        Box::pin(async move {
            assert_eq!(host, "dns.example");
            Ok(vec![std::net::SocketAddr::new(
                std::net::IpAddr::from([10, 9, 8, 7]),
                port,
            )])
        })
    });
    assert_eq!(
        resolve_udp_check_target(&["dns.example".into()], Some(hook))
            .await
            .unwrap(),
        "10.9.8.7:53".parse().unwrap()
    );

    let rejection: crate::outbound::ResolveHook = Arc::new(|_, _| {
        Box::pin(async {
            Err(anyhow::Error::new(
                honk_outbound::proxy::PacketRejection::Policy,
            ))
        })
    });
    let error = resolve_udp_check_target(&["denied.example:443".into()], Some(rejection))
        .await
        .expect_err("typed target rejection");
    assert!(honk_outbound::proxy::is_packet_rejection(&error));

    let failure: crate::outbound::ResolveHook =
        Arc::new(|_, _| Box::pin(async { anyhow::bail!("ordinary resolution failure") }));
    assert_eq!(
        resolve_udp_check_target(&["failed.example".into()], Some(failure))
            .await
            .unwrap(),
        fallback
    );
}

#[tokio::test]
async fn c24_dns_target_resolution_and_score_identity_agree() {
    use honk_outbound::group::ScoreTarget;
    for (value, address) in [
        ("[::1]", "[::1]:53"),
        ("[::1]:5353", "[::1]:5353"),
        ("::1", "[::1]:53"),
    ] {
        let raws = vec!["resolver.test".into(), value.into()];
        let hook: crate::outbound::ResolveHook =
            Arc::new(|_, _| Box::pin(async { Ok(Vec::new()) }));
        let resolved = resolve_udp_check_target(&raws, Some(hook)).await.unwrap();
        let expected: SocketAddr = address.parse().unwrap();
        assert_eq!(resolved, expected);
        assert_eq!(
            super::probers::udp_probe_identity(&raws, resolved),
            ScoreTarget::from(expected)
        );
    }
    let raws = vec!["resolver.test".into()];
    let hook: crate::outbound::ResolveHook = Arc::new(|host, port| {
        Box::pin(async move {
            assert_eq!((host.as_str(), port), ("resolver.test", 53));
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
        })
    });
    let resolved = resolve_udp_check_target(&raws, Some(hook)).await.unwrap();
    assert_eq!(resolved, SocketAddr::from(([127, 0, 0, 1], 53)));
    assert_eq!(
        super::probers::udp_probe_identity(&raws, resolved),
        ScoreTarget::domain("resolver.test", 53)
    );
}

#[tokio::test]
async fn quic_failure_trains_score_without_failing_dns_udp_health() {
    use honk_config::node::{Group, GroupPolicy};
    use honk_outbound::group::{ScoreTarget, SelectionNetwork};

    let node = udp_test_node();
    let mut other = node.clone();
    other.name = "udp-test-other".into();
    other.port += 1;
    other.id = other.derive_id();
    let group = Group {
        name: "score".into(),
        policy: GroupPolicy::Score,
        nodes: vec![node.id, other.id],
        ..Group::default()
    };
    let mut config = Config {
        nodes: vec![node.clone(), other.clone()],
        groups: vec![group.clone()],
        ..Config::default()
    };
    config.global.nfqueue_enable = false;
    config.global.tcp_check_url = vec!["https://quic.example.test:9443/generate_204".into()];
    let cp = control_plane(config.clone());
    let manager = cp.group_manager();
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handler = Arc::new(UdpTestHandler {
        mode: UdpTestMode::DnsResponse {
            dials: Arc::clone(&dials),
        },
    });
    let mut registry = ProxyRegistry::new();
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(node.protocol(), handler.clone())
            .with_packet(handler),
    );
    let runtime = cp.runtime_registry();
    let resolver: crate::outbound::ResolveHook = Arc::new(|_host, port| {
        Box::pin(async move { Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))]) })
    });
    let quic_target = resolve_quic_score_target(&config.global.tcp_check_url[0], Some(resolver))
        .await
        .unwrap();
    let context = probers::quic_probe_context(&quic_target);
    assert_eq!(context.network, SelectionNetwork::Udp);
    assert_eq!(context.probe_domain, ProbeDomain::DataUdp);
    assert_eq!(context.target_family, Some(IpVersion::V4));
    assert_eq!(
        context.target,
        Some(ScoreTarget::domain("quic.example.test", 9443))
    );
    assert_eq!(
        manager
            .read()
            .selection_plan_for_target("score", &context)
            .entries[0]
            .node
            .id,
        node.id
    );
    let prober = probers::ProxyUdpProber::new(
        cp.config_handle(),
        Arc::new(registry),
        runtime,
        cp.stats_handle(),
        probers::UdpDnsProbeTarget::new(vec!["127.0.0.1:53".into()], None),
        Some(quic_target),
        manager.clone(),
    );
    let mut candidate = config.clone();
    candidate.global.tcp_check_url = vec!["https://changed.example.test:9444/new".into()];
    let accepted = cp
        .reload_runtime_config(candidate, Default::default())
        .await;

    let result =
        honk_outbound::alive::UdpProber::probe_udp(&prober, &node.name, Duration::from_millis(30))
            .await;
    assert!(
        matches!(result.dns, Some(Ok(_))),
        "DNS health result: {result:?}"
    );
    assert!(
        result.data_path.is_some(),
        "Score QUIC probe must run: {result:?}"
    );
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(
        manager
            .read()
            .selection_plan_for_target("score", &context)
            .entries[0]
            .node
            .id,
        other.id
    );
    assert!(!accepted);
    assert_eq!(cp.config_handle().read().await.as_ref(), &config);
}

#[tokio::test]
async fn quic_probe_still_runs_when_dns_target_resolution_is_refused() {
    use honk_config::node::{Group, GroupPolicy};
    use honk_outbound::group::GroupManager;

    // Local DNS setup refusal must not suppress the independent Score handshake.
    let node = udp_test_node();
    let group = Group {
        name: "score".into(),
        policy: GroupPolicy::Score,
        nodes: vec![node.id],
        ..Group::default()
    };
    let config = Config {
        nodes: vec![node.clone()],
        groups: vec![group.clone()],
        ..Config::default()
    };
    let manager: SharedGroupManager = Arc::new(parking_lot::RwLock::new(Arc::new(
        GroupManager::new(&[group], std::slice::from_ref(&node)),
    )));
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handler = Arc::new(UdpTestHandler {
        mode: UdpTestMode::CountDialError {
            dials: Arc::clone(&dials),
        },
    });
    let mut registry = ProxyRegistry::new();
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(node.protocol(), handler.clone())
            .with_packet(handler),
    );
    let runtime = Arc::new(parking_lot::RwLock::new(Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
            .unwrap(),
    )));
    let resolver: crate::outbound::ResolveHook = Arc::new(|_host, port| {
        Box::pin(async move { Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))]) })
    });
    let quic_target = resolve_quic_score_target(
        "https://quic.example.test:9443/generate_204",
        Some(resolver),
    )
    .await
    .unwrap();
    let prober = probers::ProxyUdpProber::new(
        Arc::new(RwLock::new(Arc::new(config))),
        Arc::new(registry),
        runtime,
        Arc::new(StatsManager::new()),
        probers::UdpDnsProbeTarget::new(
            vec!["denied.example:53".into()],
            Some(Arc::new(|_, _| {
                Box::pin(async {
                    Err(anyhow::Error::new(
                        honk_outbound::proxy::PacketRejection::Capacity,
                    ))
                })
            })),
        ),
        Some(quic_target),
        manager.clone(),
    );

    let result =
        honk_outbound::alive::UdpProber::probe_udp(&prober, &node.name, Duration::from_millis(30))
            .await;
    assert!(result.dns.is_none(), "DNS health result: {result:?}");
    assert!(
        matches!(result.data_path, Some(Err(_))),
        "the Score QUIC probe must be attempted despite DNS initialization refusal: {result:?}"
    );
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
}

async fn ready_udp_endpoint(
    pool: &Arc<UdpEndpointPool>,
    stats: &Arc<StatsManager>,
    client: SocketAddr,
    dst: SocketAddr,
    transport: Arc<dyn honk_outbound::proxy::PacketTransport>,
    relay: SocketAddr,
) -> Arc<UdpEndpoint> {
    let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"bootstrap", slow_permit, stats) {
        crate::control::udp_endpoint::EndpointReservation::Initializing(lease) => lease,
        _ => panic!("test endpoint must reserve a fresh lease"),
    };
    let endpoint = Arc::new(UdpEndpoint::new(transport, relay, udp_test_node().id));
    let queue_rx = lease.take_queue_receiver().unwrap();
    let reply_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mut driver = pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        queue_rx,
        reply_socket,
        Arc::new(crate::outbound::AliveDialerSet::new()),
        stats.clone(),
        "test-node".into(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    driver.start(lease.take_first().unwrap()).unwrap();
    driver.wait_first_ack().await.unwrap();
    endpoint
}

#[test]
fn udp_original_dst_exact_dns_predicate_matches_controller_condition() {
    // Real query: consumed by the DNS controller.
    assert!(is_exact_dns_query(&dns_query_payload()));
    // QR bit set (response): not a query.
    let mut resp = dns_query_payload();
    resp[2] |= 0x80;
    assert!(!is_exact_dns_query(&resp));
    // Too short / garbage: not a query.
    assert!(!is_exact_dns_query(b"hello"));
    assert!(!is_exact_dns_query(&[0u8; 20])); // qdcount == 0
}

#[test]
fn strict_dns_query_accepts_complete_query_and_edns_only() {
    let query = dns_query_payload();
    assert!(is_exact_dns_query(&query));

    // A legal EDNS OPT pseudo-RR is still an exact DNS query.
    let mut edns = query.clone();
    edns[10..12].copy_from_slice(&1u16.to_be_bytes());
    edns.extend_from_slice(&[
        0x00, // root NAME
        0x00, 0x29, // TYPE OPT
        0x04, 0xd0, // UDP payload size (1232)
        0x00, 0x00, 0x00, 0x00, // extended RCODE/version/flags
        0x00, 0x00, // RDLENGTH
    ]);
    assert!(is_exact_dns_query(&edns));
    assert_eq!(
        validate_exact_dns_query(&edns).unwrap().ingress(),
        IngressProfile::Udp {
            advertised_size: 1232
        }
    );

    // A forged QDCOUNT cannot claim a second question that is not encoded.
    let mut forged_question_count = query.clone();
    forged_question_count[4..6].copy_from_slice(&2u16.to_be_bytes());
    assert!(!is_exact_dns_query(&forged_question_count));
    assert!(validate_exact_dns_query(&forged_question_count).is_none());

    // Header record counts require a complete NAME + fixed RR + RDATA.
    let mut truncated_rr = query.clone();
    truncated_rr[6..8].copy_from_slice(&1u16.to_be_bytes());
    truncated_rr.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01]);
    assert!(!is_exact_dns_query(&truncated_rr));
    let mut short_rdata = query.clone();
    short_rdata[6..8].copy_from_slice(&1u16.to_be_bytes());
    short_rdata.extend_from_slice(&[
        0xc0, 0x0c, // NAME pointer to question
        0x00, 0x01, // TYPE A
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x3c, // TTL
        0x00, 0x04, // RDLENGTH
        192, 0, // only half the claimed RDATA
    ]);
    assert!(!is_exact_dns_query(&short_rdata));

    let mut invalid_label = query.clone();
    invalid_label[12] = 0x40;
    assert!(!is_exact_dns_query(&invalid_label));
    let mut invalid_pointer = query.clone();
    invalid_pointer.truncate(12);
    invalid_pointer.extend_from_slice(&[0xc0, 0xff, 0x00, 0x01, 0x00, 0x01]);
    assert!(!is_exact_dns_query(&invalid_pointer));

    let mut trailing_junk = query;
    trailing_junk.push(0xde);
    assert!(!is_exact_dns_query(&trailing_junk));
    assert!(validate_exact_dns_query(&trailing_junk).is_none());
}

fn dns_query_with_qname(qname: &[u8]) -> Vec<u8> {
    let mut q = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q.extend_from_slice(qname);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A / QCLASS IN
    q
}

#[test]
fn strict_dns_query_enforces_expanded_name_limit_and_label_boundaries() {
    // Four 63-byte labels + root expand to 257 octets (>255) and must fail.
    let mut overlong_name = Vec::new();
    for _ in 0..4 {
        overlong_name.push(63);
        overlong_name.extend(std::iter::repeat_n(b'a', 63));
    }
    overlong_name.push(0);
    let overlong = dns_query_with_qname(&overlong_name);
    assert_eq!(overlong_name.len(), 257);
    assert!(!is_exact_dns_query(&overlong));

    // Pointer into the middle of a label is not a prior label boundary.
    // a.com qname occupies offsets 12..19 with boundaries at 12,14,18.
    let mut pointer_into_label = dns_query_payload();
    pointer_into_label[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
    pointer_into_label.extend_from_slice(&[
        0xc0, 0x0d, // pointer to offset 13 (the 'a' payload byte)
        0x00, 0x01, // TYPE A
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x3c, // TTL
        0x00, 0x04, // RDLENGTH
        192, 0, 2, 1,
    ]);
    assert!(!is_exact_dns_query(&pointer_into_label));

    // Valid suffix compression: answer owner points at the "com" label boundary.
    let mut suffix = dns_query_payload();
    suffix[6..8].copy_from_slice(&1u16.to_be_bytes());
    suffix.extend_from_slice(&[
        0xc0, 0x0e, // pointer to offset 14 (start of "com")
        0x00, 0x01, // TYPE A
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x3c, // TTL
        0x00, 0x04, // RDLENGTH
        192, 0, 2, 1,
    ]);
    assert!(is_exact_dns_query(&suffix));

    // Full-name compression onto the question owner remains accepted.
    let mut full = dns_query_payload();
    full[6..8].copy_from_slice(&1u16.to_be_bytes());
    full.extend_from_slice(&[
        0xc0, 0x0c, // pointer to question name
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 1,
    ]);
    assert!(is_exact_dns_query(&full));
}

#[test]
fn strict_dns_query_requires_forwarder_parseable_question() {
    // Root qname is wire-valid but parse_dns_question rejects empty labels.
    let root = dns_query_with_qname(&[0x00]);
    assert!(crate::dns::forwarder::parse_dns_question(&root).is_none());
    assert!(!is_exact_dns_query(&root));

    // Non-UTF8 / binary label is wire-shaped but not consumer-parseable.
    let binary = dns_query_with_qname(&[0x01, 0xff, 0x00]);
    assert!(crate::dns::forwarder::parse_dns_question(&binary).is_none());
    assert!(!is_exact_dns_query(&binary));

    // Ordinary UTF-8 name remains accepted by both.
    let ok = dns_query_payload();
    assert!(crate::dns::forwarder::parse_dns_question(&ok).is_some());
    assert!(is_exact_dns_query(&ok));
}

#[tokio::test]
async fn udp_slow_path_forwards_root_and_binary_questions() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let controller = production_dns_controller(calls.clone(), dns_response_payload());
    let dst = addr("203.0.113.53:53");

    for (client, data) in [
        (addr("127.0.0.1:34567"), dns_query_with_qname(&[0x00])),
        (
            addr("127.0.0.1:34568"),
            dns_query_with_qname(&[0x01, 0xff, 0x00]),
        ),
    ] {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let limit = Arc::new(tokio::sync::Semaphore::new(1));
        let work = begin_udp_slow_path(
            &pool,
            &stats,
            &limit,
            validate_exact_dns_query(&data).map(|validated| (controller.as_ref(), validated)),
            client,
            dst,
            &data,
        );
        let lease = match work {
            UdpSlowPathWork::Initialize(lease) => lease,
            _ => panic!("non-strict port-53 payload must take ordinary UDP forwarding"),
        };
        assert_eq!(lease.client_addr(), client);
        assert_eq!(lease.original_dst(), dst);
        assert_eq!(lease.first_payload().as_ref(), data.as_slice());
        assert_eq!(stats.udp_snapshot().slow_permit_accepted, 1);
        assert_eq!(limit.available_permits(), 0);
        drop(lease);
        assert_eq!(limit.available_permits(), 1);
    }

    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn udp_slow_path_only_forces_strict_dns_to_port_53() {
    let client = addr("10.0.0.1:12345");
    let data = dns_query_payload();
    let validated = validate_exact_dns_query(&data).unwrap();

    let dns_pool = Arc::new(UdpEndpointPool::new());
    let dns_stats = Arc::new(StatsManager::new());
    let dns_limit = Arc::new(tokio::sync::Semaphore::new(1));
    let dns = production_dns_controller(
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        dns_response_payload(),
    );
    let dns_work = begin_udp_slow_path(
        &dns_pool,
        &dns_stats,
        &dns_limit,
        Some((dns.as_ref(), validated)),
        client,
        addr("203.0.113.53:53"),
        &data,
    );
    assert!(matches!(dns_work, UdpSlowPathWork::Dns { .. }));

    let ordinary_pool = Arc::new(UdpEndpointPool::new());
    let ordinary_stats = Arc::new(StatsManager::new());
    let ordinary_limit = Arc::new(tokio::sync::Semaphore::new(1));
    let ordinary_work = begin_udp_slow_path(
        &ordinary_pool,
        &ordinary_stats,
        &ordinary_limit,
        Some((dns.as_ref(), validated)),
        client,
        addr("203.0.113.53:5353"),
        &data,
    );
    assert!(matches!(ordinary_work, UdpSlowPathWork::Initialize(_)));
}

#[tokio::test]
async fn udp_fast_path_miss_goes_slow() {
    let pool = UdpEndpointPool::new();
    let stats = StatsManager::new();
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:443");
    assert!(!udp_fast_path(&pool, &stats, b"hello", client, dst, None));
    let udp = stats.udp_snapshot();
    assert_eq!(udp.endpoint_misses, 1);
    assert_eq!(udp.endpoint_hits, 0);
}

#[tokio::test]
async fn udp_fast_path_hit_enqueues_for_the_endpoint_driver() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = proxy.local_addr().unwrap();
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:443");
    ready_udp_endpoint(
        &pool,
        &stats,
        client,
        dst,
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            proxy, echo_addr,
        )),
        echo_addr,
    )
    .await;

    let mut buf = [0u8; 64];
    // First packet was delivered through the driver start barrier.
    echo.recv_from(&mut buf).await.unwrap();
    assert!(!udp_fast_path(
        &pool,
        &stats,
        b"wrong-client",
        addr("10.0.0.2:12345"),
        dst,
        None,
    ));
    assert!(!udp_fast_path(
        &pool,
        &stats,
        b"wrong-destination",
        client,
        addr("203.0.113.2:443"),
        None,
    ));
    assert!(!udp_fast_path(
        &pool,
        &stats,
        b"wrong-client-port",
        addr("10.0.0.1:12346"),
        dst,
        None,
    ));
    assert!(!udp_fast_path(
        &pool,
        &stats,
        b"wrong-destination-port",
        client,
        addr("203.0.113.1:444"),
        None,
    ));
    assert!(udp_fast_path(&pool, &stats, b"hello", client, dst, None));
    let udp = stats.udp_snapshot();
    assert_eq!(udp.endpoint_hits, 1);
    assert_eq!(udp.endpoint_misses, 4);

    let (n, from) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"hello");
    assert_eq!(from, proxy_addr);
}

#[tokio::test]
async fn udp_fast_path_dns_goes_slow_even_with_endpoint() {
    // A real DNS query must reach the DNS controller even when an endpoint
    // driver already owns this tuple.
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    ready_udp_endpoint(
        &pool,
        &stats,
        client,
        dst,
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            proxy,
            addr("127.0.0.1:9"),
        )),
        addr("127.0.0.1:9"),
    )
    .await;

    let query = dns_query_payload();
    let validated = validate_exact_dns_query(&query).unwrap();
    assert!(!udp_fast_path(
        &pool,
        &stats,
        &query,
        client,
        dst,
        Some(validated)
    ));
    let udp = stats.udp_snapshot();
    assert_eq!(udp.endpoint_hits, 0);
    assert_eq!(udp.endpoint_misses, 0);
}

#[tokio::test]
async fn udp_fast_path_dns_shaped_non53_forwards() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.53:5353");
    ready_udp_endpoint(
        &pool,
        &stats,
        client,
        dst,
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            proxy, echo_addr,
        )),
        echo_addr,
    )
    .await;

    let mut buf = [0u8; 64];
    echo.recv_from(&mut buf).await.unwrap();
    let query = dns_query_payload();
    assert!(udp_fast_path(
        &pool,
        &stats,
        &query,
        client,
        dst,
        validate_exact_dns_query(&query),
    ));
    assert_eq!(stats.udp_snapshot().endpoint_hits, 1);

    let (n, _) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], &query);
}

#[tokio::test]
async fn udp_fast_path_non_dns_port53_forwards() {
    // Garbage to port 53 is not strict DNS, so the endpoint driver forwards it.
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    ready_udp_endpoint(
        &pool,
        &stats,
        client,
        dst,
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            proxy, echo_addr,
        )),
        echo_addr,
    )
    .await;

    let mut buf = [0u8; 64];
    echo.recv_from(&mut buf).await.unwrap();
    let garbage = [0u8; 20]; // QR=0 but qdcount=0 — not a DNS query
    assert!(udp_fast_path(&pool, &stats, &garbage, client, dst, None));
    assert_eq!(stats.udp_snapshot().endpoint_hits, 1);

    let (n, _) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], &garbage[..]);
}

#[tokio::test]
async fn udp_fast_path_drops_internal_and_broadcast() {
    let pool = UdpEndpointPool::new();
    let stats = StatsManager::new();
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:443");
    // honk-internal subnets (v4 + v6), either direction.  The v6 check
    // must match the real dae0 addresses (fd00:686f:6e6b::1/2, see the
    // DAENS_* constants in the crate root).
    assert!(udp_fast_path(
        &pool,
        &stats,
        b"hello",
        client,
        addr("169.254.0.11:8080"),
        None,
    ));
    assert!(udp_fast_path(
        &pool,
        &stats,
        b"hello",
        addr("169.254.0.1:1234"),
        dst,
        None
    ));
    assert!(udp_fast_path(
        &pool,
        &stats,
        b"hello",
        client,
        addr("[fd00:686f:6e6b::1]:8080"),
        None,
    ));
    assert!(udp_fast_path(
        &pool,
        &stats,
        b"hello",
        addr("[fd00:686f:6e6b::2]:1234"),
        dst,
        None,
    ));
    // Broadcast / multicast destinations.
    assert!(udp_fast_path(
        &pool,
        &stats,
        b"hello",
        client,
        addr("255.255.255.255:67"),
        None,
    ));
    assert!(udp_fast_path(
        &pool,
        &stats,
        b"hello",
        client,
        addr("192.168.1.255:67"),
        None,
    ));
    assert!(udp_fast_path(
        &pool,
        &stats,
        b"hello",
        client,
        addr("239.255.255.250:1900"),
        None,
    ));
    // Drops do not count as endpoint misses and nothing is pooled.
    assert!(pool.is_empty());
    let udp = stats.udp_snapshot();
    assert_eq!(udp.endpoint_hits, 0);
    assert_eq!(udp.endpoint_misses, 0);
}

#[test]
fn dae0_internal_addr_covers_real_dae0_addresses() {
    // The internal-addr check must match the actual dae0/dae0peer
    // addresses assigned by the netns setup; both sides share the
    // DAENS_*/DAE0_* constants in the crate root so they cannot drift.
    for s in [
        crate::DAENS_HOST_IPV6,
        crate::DAENS_PEER_IPV6,
        crate::DAENS_HOST_IP,
        crate::DAENS_PEER_IP,
    ] {
        let ip: std::net::IpAddr = s.parse().unwrap();
        assert!(
            is_honk_internal_addr(&ip),
            "{} must be classified as honk-internal",
            s
        );
    }
    // Other hosts inside the same subnets.
    assert!(is_honk_internal_addr(
        &"fd00:686f:6e6b::beef".parse().unwrap()
    ));
    assert!(is_honk_internal_addr(&"169.254.0.200".parse().unwrap()));
    // Outside the subnets — including fd00:dae:d000::/64, the value of
    // the old wrong DAE0_IPV6_PREFIX_HI constant that never matched the
    // real dae0 addresses.
    assert!(!is_honk_internal_addr(&"fd00:dae:d000::1".parse().unwrap()));
    assert!(!is_honk_internal_addr(&"fd00:daec::1".parse().unwrap()));
    assert!(!is_honk_internal_addr(&"192.168.0.1".parse().unwrap()));
    assert!(!is_honk_internal_addr(&"10.0.0.1".parse().unwrap()));
}

#[test]
fn subscription_merge_replaces_only_that_subscription() {
    fn node(name: &str, sub: Option<uuid::Uuid>) -> Node {
        Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            address: "127.0.0.1:1".into(),
            host: "127.0.0.1".into(),
            port: 1,
            subscription_id: sub,
            ..Default::default()
        }
    }

    let sub_a = uuid::Uuid::new_v4();
    let sub_b = uuid::Uuid::new_v4();
    let static_node = node("static", None);
    let old_a1 = node("a-old-1", Some(sub_a));
    let old_a2 = node("a-old-2", Some(sub_a));
    let b_node = node("b-1", Some(sub_b));

    let mut current = Config {
        nodes: vec![
            static_node.clone(),
            old_a1.clone(),
            old_a2.clone(),
            b_node.clone(),
        ],
        groups: vec![honk_config::node::Group {
            name: "proxy".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    // Resolve initial membership exactly like startup does; the
    // filter-less group swallows every node.
    honk_config::parser::resolve_group_filters(
        &mut current.groups,
        &current.nodes,
        &current.subscriptions,
    );
    assert_eq!(current.groups[0].nodes.len(), 4);

    let new_a1 = node("a-new-1", Some(sub_a));
    let merged = config_with_subscription_nodes(&current, sub_a, vec![new_a1.clone()]);

    // Old sub-A nodes are gone; static and other-subscription nodes stay.
    let names: Vec<&str> = merged.nodes.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, vec!["static", "b-1", "a-new-1"]);
    // Group membership was pruned of dangling IDs and re-resolved:
    // exactly the three live nodes, no stale UUIDs.
    assert_eq!(merged.groups[0].nodes.len(), 3);
    for id in &merged.groups[0].nodes {
        assert!(merged.nodes.iter().any(|n| n.id == *id));
    }
    assert!(!merged.groups[0].nodes.contains(&old_a1.id));
    assert!(!merged.groups[0].nodes.contains(&old_a2.id));

    // Re-merging the same subscription replaces instead of duplicating.
    let new_a1b = node("a-new-1", Some(sub_a));
    let remerged = config_with_subscription_nodes(&merged, sub_a, vec![new_a1b.clone()]);
    assert_eq!(remerged.nodes.len(), 3);
    assert_eq!(remerged.groups[0].nodes.len(), 3);
    assert_eq!(remerged.nodes[2].id, new_a1b.id);
}

#[test]
fn empty_subscription_merge_preserves_previous_nodes() {
    let subscription_id = uuid::Uuid::new_v4();
    let old = Node {
        id: uuid::Uuid::new_v4(),
        name: "old".into(),
        subscription_id: Some(subscription_id),
        ..Default::default()
    };
    let current = Config {
        nodes: vec![old.clone()],
        ..Default::default()
    };

    let merged = config_with_subscription_nodes(&current, subscription_id, Vec::new());

    assert_eq!(merged.nodes.len(), 1);
    assert_eq!(merged.nodes[0].id, old.id);
    assert_eq!(merged.nodes[0].name, "old");
}

#[test]
fn domain_reality_exact_match_same_family() {
    let v4: std::net::IpAddr = "104.20.22.25".parse().unwrap();
    let v6: std::net::IpAddr = "2606:4700:10::6814:1619".parse().unwrap();
    assert_eq!(
        domain_reality_outcome(v4, &[v4], &[]),
        RealityOutcome::ExactMatch
    );
    assert_eq!(
        domain_reality_outcome(v6, &[], &[v6]),
        RealityOutcome::ExactMatch
    );
}

#[test]
fn domain_reality_ipv6_conn_ipv4_only_answers_trusts_sni() {
    // tracker.m-team.cc on CF IPv6 while resolver only has A (Ipv4Only).
    let conn_v6: std::net::IpAddr = "2606:4700:10::6814:1619".parse().unwrap();
    let a1: std::net::IpAddr = "172.66.165.79".parse().unwrap();
    let a2: std::net::IpAddr = "104.20.22.25".parse().unwrap();
    assert_eq!(
        domain_reality_outcome(conn_v6, &[a1, a2], &[]),
        RealityOutcome::OtherFamilyOnly
    );
}

#[test]
fn domain_reality_same_family_wrong_ip_is_mismatch() {
    let conn: std::net::IpAddr = "1.2.3.4".parse().unwrap();
    let other: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    assert_eq!(
        domain_reality_outcome(conn, &[other], &[]),
        RealityOutcome::Mismatch
    );
    // Empty both families → mismatch (resolve returned nothing useful).
    assert_eq!(
        domain_reality_outcome(conn, &[], &[]),
        RealityOutcome::Mismatch
    );
}

fn source_routed_dns_resolver(
    source_cidr: &str,
    selected_ip: std::net::Ipv4Addr,
    fallback_ip: std::net::Ipv4Addr,
) -> anyhow::Result<(DnsResolver, Arc<std::sync::atomic::AtomicUsize>)> {
    struct SourceRoutedUpstream {
        selected_ip: std::net::Ipv4Addr,
        fallback_ip: std::net::Ipv4Addr,
        queries: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::dns::forwarder::DnsUpstreamPool for SourceRoutedUpstream {
        async fn query(&self, upstream_name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.queries
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let ip = if upstream_name == "selected" {
                self.selected_ip
            } else {
                self.fallback_ip
            };
            let mut response = raw.to_vec();
            anyhow::ensure!(response.len() >= 12, "short DNS query");
            response[2] = 0x81;
            response[3] = 0x80;
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            response.extend_from_slice(&ip.octets());
            Ok(response)
        }
    }

    let config = honk_config::dns::DnsConfig {
        strategy: honk_config::dns::DnsStrategy::Ipv4Only,
        routing: honk_config::dns::DnsRouting {
            request: honk_config::dns::DnsRequestRouting {
                rules: vec![honk_config::dns::DnsRequestRule {
                    conditions: vec![honk_config::dns::DnsCond::Sip {
                        not: false,
                        cidrs: vec![source_cidr.into()],
                    }],
                    action: honk_config::dns::DnsRequestAction::Upstream("selected".into()),
                }],
                fallback: honk_config::dns::DnsRequestAction::Upstream("fallback".into()),
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let router = Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(
        &config,
    )?);
    let queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let forwarder = Arc::new(
        crate::dns::forwarder::DnsForwarder::new(
            Arc::new(SourceRoutedUpstream {
                selected_ip,
                fallback_ip,
                queries: Arc::clone(&queries),
            }),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(1))),
            router,
        )
        .with_cache_enabled(false)
        .with_policy_from_config(&config)?,
    );
    Ok((DnsResolver::with_forwarder(&config, forwarder)?, queries))
}

fn tls_client_hello(sni: &str) -> Vec<u8> {
    let hello = crate::control::quic::test_utils::build_client_hello(Some(sni));
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    record
}

async fn store_active_tcp_flow(
    handle: &ControlPlaneHandle,
    original_dst: SocketAddr,
    client_addr: SocketAddr,
) -> anyhow::Result<()> {
    let tuples = build_tuples_key(
        original_dst.ip(),
        original_dst.port(),
        client_addr.ip(),
        client_addr.port(),
        6,
    );
    handle.ebpf.write().await.tcp_conn_state_store(
        &tuples,
        &honk_ebpf_common::conn::ConnState {
            state: honk_ebpf_common::conn::TcpState::TcpStateActive as u8,
            last_seen_ns: 1,
            ..Default::default()
        },
    )?;
    Ok(())
}

#[tokio::test]
async fn tcp_domain_reality_uses_client_source() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let original_dst = listener.local_addr()?;
    let mut config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    config.ensure_builtin_nodes();
    config.global.dial_mode = "domain".into();

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let mut handle = udp_test_handle(
        config,
        UdpTestMode::TcpHold {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        },
        1,
    );
    let (dns_resolver, _) = source_routed_dns_resolver(
        "127.0.0.42/32",
        original_dst.ip().to_string().parse()?,
        "192.0.2.1".parse()?,
    )?;
    handle.dns_resolver = Arc::new(dns_resolver);

    let client_socket = tokio::net::TcpSocket::new_v4()?;
    client_socket.bind("127.0.0.42:0".parse()?)?;
    let mut client = client_socket.connect(original_dst).await?;
    let (accepted, client_addr) = listener.accept().await?;
    store_active_tcp_flow(&handle, original_dst, client_addr).await?;
    let task_handle = handle.clone();
    let mut task =
        tokio::spawn(async move { task_handle.serve_connection(accepted, client_addr).await });
    let hello = tls_client_hello("source.test");
    client.write_all(&hello).await?;
    tokio::select! {
        _ = entered.notified() => {}
        result = &mut task => anyhow::bail!("TCP handler exited before dial: {result:?}"),
        _ = tokio::time::sleep(Duration::from_secs(5)) => anyhow::bail!("TCP dial timed out"),
    }
    release.notify_one();
    let (mut upstream, _) =
        tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;

    let tracked = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(entry) = handle.connection_tracker.snapshot().into_iter().next() {
                break entry;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(tracked.domain.as_deref(), Some("source.test"));

    let mut received = vec![0; hello.len()];
    upstream.read_exact(&mut received).await?;
    assert_eq!(received, hello);
    client.shutdown().await?;
    upstream.shutdown().await?;
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(5), task).await???;
    Ok(())
}

#[tokio::test]
async fn udp_domain_reality_uses_client_source() -> anyhow::Result<()> {
    let client = addr("192.0.2.10:53000");
    let original_dst = addr("198.51.100.20:443");
    let mut config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    config.ensure_builtin_nodes();
    config.global.dial_mode = "domain".into();
    let mut handle = udp_test_handle(config, UdpTestMode::Success, 1);
    let (dns_resolver, _) = source_routed_dns_resolver(
        "192.0.2.0/24",
        original_dst.ip().to_string().parse()?,
        "203.0.113.20".parse()?,
    )?;
    handle.dns_resolver = Arc::new(dns_resolver);

    let hello = crate::control::quic::test_utils::build_client_hello(Some("source.test"));
    let packet = crate::control::quic::test_utils::protect_initial_packet(
        b"dcid1234",
        b"",
        1,
        0,
        1,
        &crate::control::quic::test_utils::wrap_crypto_frame(0, &hello),
    );
    serve_test_udp_to(&handle, client, original_dst, &packet).await?;

    let tracked = handle
        .connection_tracker
        .snapshot()
        .into_iter()
        .next()
        .expect("ready UDP endpoint must be tracked");
    assert_eq!(tracked.domain.as_deref(), Some("source.test"));
    handle.udp_pool.remove(client, original_dst);
    Ok(())
}

#[tokio::test]
async fn udp_domain_plus_passes_sniffed_proxy_target_without_rerouting() -> anyhow::Result<()> {
    let client = addr("192.0.2.10:53000");
    let original_dst = addr("198.51.100.20:443");
    let captured = Arc::new(std::sync::Mutex::new(None));
    let mut config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    config.ensure_builtin_nodes();
    config.global.dial_mode = "domain+".into();
    let handle = udp_test_handle(
        config,
        UdpTestMode::UdpCaptureTarget(Arc::clone(&captured)),
        1,
    );

    let hello = crate::control::quic::test_utils::build_client_hello(Some("source.test"));
    let packet = crate::control::quic::test_utils::protect_initial_packet(
        b"dcid1234",
        b"",
        1,
        0,
        1,
        &crate::control::quic::test_utils::wrap_crypto_frame(0, &hello),
    );
    serve_test_udp_to(&handle, client, original_dst, &packet).await?;

    let (target, domain) = captured
        .lock()
        .expect("UDP dial target")
        .clone()
        .expect("UDP transport dial was captured");
    assert_eq!(target, original_dst);
    assert_eq!(domain.as_deref(), Some("source.test"));
    handle.udp_pool.remove(client, original_dst);
    Ok(())
}

#[tokio::test]
async fn tcp_proxy_protocols_pass_domain_without_local_resolution() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let original_dst = SocketAddr::new("127.0.0.1".parse()?, listener.local_addr()?.port());

    for protocol in [
        NodeProtocol::VMess,
        NodeProtocol::VLess,
        NodeProtocol::Hysteria2,
        NodeProtocol::Tuic,
        NodeProtocol::Juicity,
    ] {
        let name = protocol.as_str();
        let mut node = Node {
            name: name.into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
            address: "127.0.0.1".into(),
            port: 9,
            ..Default::default()
        };
        match &mut node.outbound {
            honk_config::node::OutboundConfig::Vmess(config) => {
                config.uuid = Some("12345678-1234-1234-1234-123456789abc".into());
            }
            honk_config::node::OutboundConfig::Vless(config) => {
                config.uuid = Some("12345678-1234-1234-1234-123456789abc".into());
            }
            honk_config::node::OutboundConfig::Tuic(config) => {
                config.uuid = Some("12345678-1234-1234-1234-123456789abc".into());
            }
            honk_config::node::OutboundConfig::Juicity(config) => {
                config.uuid = Some("12345678-1234-1234-1234-123456789abc".into());
            }
            _ => {}
        }
        node.id = node.derive_id();
        let mut config = udp_test_config(name, vec![node], vec![]);
        config.ensure_builtin_nodes();
        config.global.dial_mode = "domain+".into();
        let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
        let dial_target = Arc::new(std::sync::Mutex::new(None));
        let handler = Arc::new(UdpTestHandler {
            mode: UdpTestMode::TcpCaptureTarget(Arc::clone(&dial_target)),
        });
        let mut registry = ProxyRegistry::new();
        registry.register(honk_outbound::proxy::ProtocolEntry::new(protocol, handler));
        let (dns_resolver, dns_queries) = source_routed_dns_resolver(
            "127.0.0.42/32",
            "127.0.0.2".parse()?,
            "127.0.0.3".parse()?,
        )?;
        let dns_forwarder = dns_resolver.forwarder();
        let plane = ControlPlane::new(
            config,
            Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
            router,
            Arc::new(registry),
            dns_resolver,
            dns_forwarder,
        )?;
        let handle = plane.spawn_handle();

        let client_socket = tokio::net::TcpSocket::new_v4()?;
        client_socket.bind("127.0.0.42:0".parse()?)?;
        let mut client = client_socket.connect(original_dst).await?;
        let (accepted, client_addr) = listener.accept().await?;
        store_active_tcp_flow(&handle, original_dst, client_addr).await?;
        let task_handle = handle.clone();
        let task =
            tokio::spawn(async move { task_handle.serve_connection(accepted, client_addr).await });
        let hello = tls_client_hello("source.test");
        client.write_all(&hello).await?;
        let (mut upstream, _) =
            tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
        let captured = dial_target
            .lock()
            .expect("dial target")
            .clone()
            .expect("captured dial");
        assert_eq!(
            captured,
            (original_dst, Some("source.test".into())),
            "{protocol:?}"
        );

        let mut received = vec![0; hello.len()];
        upstream.read_exact(&mut received).await?;
        assert_eq!(received, hello, "{protocol:?}");
        client.shutdown().await?;
        upstream.shutdown().await?;
        drop(client);
        drop(upstream);
        tokio::time::timeout(Duration::from_secs(5), task).await???;
        assert_eq!(
            dns_queries.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "{protocol:?} resolved the target locally"
        );
    }
    Ok(())
}

#[tokio::test]
async fn tcp_idle_relay_survives_conn_state_sweep() -> anyhow::Result<()> {
    use honk_ebpf_common::conn::{ConnState, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TcpState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let original_dst = listener.local_addr()?;
    let mut client = TcpStream::connect(original_dst).await?;
    let (accepted, client_addr) = listener.accept().await?;
    let tuples = build_tuples_key(
        original_dst.ip(),
        original_dst.port(),
        client_addr.ip(),
        client_addr.port(),
        6,
    );
    let redirect_key = RedirectTuple::from_tuples(&tuples);
    let stale_timestamp = 1;
    let stale_state = ConnState {
        state: TcpState::TcpStateActive as u8,
        last_seen_ns: stale_timestamp,
        ..Default::default()
    };
    let stale_redirect = RedirectEntry {
        last_seen_ns: stale_timestamp,
        ..Default::default()
    };
    let handoff = RoutingHandoffEntry {
        last_seen_ns: stale_timestamp,
        result: RoutingResult {
            outbound: OutboundIndex::Direct as u8,
            mark: 0,
            ..Default::default()
        },
        routing_generation: 0,
    };

    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    mock.tcp_conn_state_store(&tuples, &stale_state)?;
    mock.redirect_track_store(&redirect_key, &stale_redirect)?;
    let raw_tuples: [u8; 40] = bytes_of(&tuples).try_into().expect("40-byte tuple key");
    mock.routing_handoffs.lock().insert(raw_tuples, handoff);

    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".to_string();
    config.routing.default_outbound = "direct".to_string();
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
    let plane = ControlPlane::new(
        config,
        Box::new(mock),
        router,
        Arc::new(ProxyRegistry::default_resolver()?),
        DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
        udp_test_forwarder(),
    )?;
    let handle = plane.spawn_handle();
    let handler_handle = handle.clone();
    let handler =
        tokio::spawn(async move { handler_handle.serve_connection(accepted, client_addr).await });
    let (mut upstream, _) =
        tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;

    let tracked_before = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let snapshot = handle.connection_tracker.snapshot();
            if snapshot.len() == 1 {
                break snapshot.into_iter().next().unwrap();
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let synthetic_now = TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS + stale_timestamp + 1;
    let janitor = BpfJanitor::new(handle.ebpf.clone(), handle.tcp_flow_pins.clone());
    assert_eq!(
        janitor.cleanup_conn_state_for_test(synthetic_now).await,
        (0, 1)
    );
    assert_eq!(
        janitor.cleanup_redirect_track_for_test(synthetic_now).await,
        (0, 1)
    );
    {
        let backend = handle.ebpf.read().await;
        assert!(backend.tcp_conn_state_lookup(&tuples)?.is_some());
        assert!(backend.redirect_track_lookup(&redirect_key)?.is_some());
    }

    upstream.write_all(b"S").await?;
    let mut byte = [0u8; 1];
    client.read_exact(&mut byte).await?;
    assert_eq!(&byte, b"S");

    client.write_all(b"C").await?;
    upstream.read_exact(&mut byte).await?;
    assert_eq!(&byte, b"C");
    upstream.write_all(b"R").await?;
    client.read_exact(&mut byte).await?;
    assert_eq!(&byte, b"R");

    let tracked_after = handle.connection_tracker.snapshot();
    assert_eq!(tracked_after.len(), 1);
    assert_eq!(tracked_after[0].id, tracked_before.id);
    assert_eq!(tracked_after[0].proxy, tracked_before.proxy);
    assert_eq!(tracked_after[0].chains, tracked_before.chains);

    client.shutdown().await?;
    upstream.shutdown().await?;
    drop(client);
    drop(upstream);
    let handler_result = tokio::time::timeout(Duration::from_secs(5), handler).await?;
    handler_result??;

    {
        let backend = handle.ebpf.read().await;
        assert!(backend.tcp_conn_state_lookup(&tuples)?.is_none());
        assert!(backend.redirect_track_lookup(&redirect_key)?.is_some());
    }
    assert!(handle.tcp_flow_pins.snapshot().is_empty());
    assert!(handle.connection_tracker.snapshot().is_empty());
    assert_eq!(
        janitor.cleanup_redirect_track_for_test(synthetic_now).await,
        (1, 1)
    );
    assert!(
        handle
            .ebpf
            .read()
            .await
            .redirect_track_lookup(&redirect_key)?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn tcp_dns_write_error_is_returned_without_tcp_fallthrough() -> anyhow::Result<()> {
    use honk_ebpf_common::RoutingHandoffEntry;
    use std::net::Ipv4Addr;
    use tokio::io::AsyncWriteExt;

    struct BlockingUpstream {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl crate::dns::forwarder::DnsUpstreamPool for BlockingUpstream {
        async fn query(&self, _name: &str, _raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(dns_response_payload())
        }
    }

    // Keep the required DNS port separate from the usual loopback resolver bind.
    let listener = match TcpListener::bind((Ipv4Addr::new(127, 0, 0, 2), 53)).await {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping: loopback TCP :53 bind needs privileges");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let original_dst = listener.local_addr()?;
    let mut client = TcpStream::connect(original_dst).await?;
    let (accepted, client_addr) = listener.accept().await?;
    let tuples = build_tuples_key(
        original_dst.ip(),
        original_dst.port(),
        client_addr.ip(),
        client_addr.port(),
        6,
    );

    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let raw_tuples: [u8; 40] = bytes_of(&tuples).try_into().expect("40-byte tuple key");
    backend.routing_handoffs.lock().insert(
        raw_tuples,
        RoutingHandoffEntry {
            result: RoutingResult {
                outbound: OutboundIndex::Direct as u8,
                mark: DAE_BYPASS_MARK,
                ..Default::default()
            },
            routing_generation: 0,
            ..Default::default()
        },
    );
    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.routing.default_outbound = "direct".into();
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());

    let mut plane = ControlPlane::new(
        config,
        Box::new(backend),
        router,
        Arc::new(ProxyRegistry::default_resolver()?),
        DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
        udp_test_forwarder(),
    )?;
    plane.dns_controller = production_dns_controller_with_upstream(Arc::new(BlockingUpstream {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    }));
    let handle = plane.spawn_handle();
    store_active_tcp_flow(&handle, original_dst, client_addr).await?;
    let peer = async move {
        let query = dns_query_payload();
        client
            .write_all(&(query.len() as u16).to_be_bytes())
            .await?;
        client.write_all(&query).await?;
        entered.notified().await;
        socket2::SockRef::from(&client).set_linger(Some(Duration::ZERO))?;
        drop(client);
        release.notify_one();
        Ok::<_, anyhow::Error>(())
    };
    let (result, peer_result) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(handle.serve_connection(accepted, client_addr), peer)
    })
    .await?;
    peer_result?;
    assert!(
        result.is_err(),
        "terminal DNS response I/O error must not fall through to TCP routing"
    );
    assert!(handle.stats.snapshot().is_empty());
    assert!(handle.tcp_flow_pins.snapshot().is_empty());
    Ok(())
}

#[tokio::test]
async fn tcp_ebpf_direct_offload_skips_dial_and_balances_stats() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let original_dst = listener.local_addr()?;
    let client = TcpStream::connect(original_dst).await?;
    let (accepted, client_addr) = listener.accept().await?;
    let tuples = build_tuples_key(
        original_dst.ip(),
        original_dst.port(),
        client_addr.ip(),
        client_addr.port(),
        6,
    );

    let mut backend = crate::ebpf::mock::MockEbpfBackend::new();
    backend.tcp_conn_state_store(
        &tuples,
        &honk_ebpf_common::conn::ConnState {
            state: honk_ebpf_common::conn::TcpState::TcpStateActive as u8,
            ..Default::default()
        },
    )?;
    let raw_tuples: [u8; 40] = bytes_of(&tuples).try_into().expect("40-byte tuple key");
    backend.routing_handoffs.lock().insert(
        raw_tuples,
        RoutingHandoffEntry {
            result: RoutingResult {
                outbound: OutboundIndex::Direct as u8,
                mark: DAE_BYPASS_MARK,
                ..Default::default()
            },
            routing_generation: 0,
            ..Default::default()
        },
    );

    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.routing.default_outbound = "direct".into();
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
    let plane = ControlPlane::new(
        config,
        Box::new(backend),
        router,
        Arc::new(ProxyRegistry::default_resolver()?),
        DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
        udp_test_forwarder(),
    )?;
    let handle = plane.spawn_handle();
    let task_handle = handle.clone();
    let task =
        tokio::spawn(async move { task_handle.serve_connection(accepted, client_addr).await });
    task.await??;

    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    let mut stats = handle.stats.snapshot();
    let direct = stats.remove("direct").expect("direct stats");
    assert_eq!(direct.total_conns, 1);
    assert_eq!(direct.active_conns, 0);
    assert!(handle.connection_tracker.snapshot().is_empty());
    drop(client);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn tcp_overall_dial_timeout_aborts_started_candidate() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let original_dst = listener.local_addr()?;
    let mut config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.global.connect_timeout_ms = 1;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let handle = udp_test_handle(
        config,
        UdpTestMode::TcpHold {
            entered: Arc::clone(&entered),
            release,
        },
        1,
    );
    let client = TcpStream::connect(original_dst).await?;
    let (accepted, client_addr) = listener.accept().await?;
    store_active_tcp_flow(&handle, original_dst, client_addr).await?;
    let task_handle = handle.clone();
    let task =
        tokio::spawn(async move { task_handle.serve_connection(accepted, client_addr).await });
    entered.notified().await;
    tokio::time::advance(Duration::from_secs(11)).await;
    task.await??;

    assert!(handle.connection_tracker.snapshot().is_empty());
    drop(client);
    Ok(())
}

#[tokio::test]
async fn tcp_tracker_keeps_the_dial_selection_snapshot() -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut hk = Node {
        name: "hk-140".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        address: "127.0.0.1".into(),
        port: 140,
        ..Default::default()
    };
    hk.id = hk.derive_id();
    let mut us = Node {
        name: "us-163".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        address: "127.0.0.1".into(),
        port: 163,
        ..Default::default()
    };
    us.id = us.derive_id();
    let mut config = udp_test_config(
        "devops",
        vec![hk.clone(), us.clone()],
        vec![Group {
            name: "devops".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            nodes: vec![hk.id, us.id],
            default: Some(hk.name.clone()),
            ..Default::default()
        }],
    );
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let handle = udp_test_handle(
        config,
        UdpTestMode::TcpHold {
            entered: entered.clone(),
            release: release.clone(),
        },
        1,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let original_dst = listener.local_addr()?;
    let mut client = TcpStream::connect(original_dst).await?;
    let (accepted, client_addr) = listener.accept().await?;
    let tuples = build_tuples_key(
        original_dst.ip(),
        original_dst.port(),
        client_addr.ip(),
        client_addr.port(),
        6,
    );
    handle.ebpf.write().await.tcp_conn_state_store(
        &tuples,
        &honk_ebpf_common::conn::ConnState {
            state: honk_ebpf_common::conn::TcpState::TcpStateActive as u8,
            last_seen_ns: 1,
            ..Default::default()
        },
    )?;
    let task_handle = handle.clone();
    let mut task =
        tokio::spawn(async move { task_handle.serve_connection(accepted, client_addr).await });

    tokio::select! {
        _ = entered.notified() => {}
        result = &mut task => panic!("TCP handler exited before dial: {result:?}"),
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("TCP dial did not reach the injected handler")
        }
    }
    assert_eq!(
        handle.group_manager.read().selection_chain("devops"),
        vec!["devops", "hk-140"]
    );
    handle
        .group_manager
        .read()
        .set_selector_choice("devops", "us-163");
    assert_eq!(
        handle.group_manager.read().selection_chain("devops"),
        vec!["devops", "us-163"]
    );

    release.notify_one();
    let (mut upstream, _) =
        tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
    let tracked = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(entry) = handle.connection_tracker.snapshot().into_iter().next() {
                break entry;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(tracked.proxy, "hk-140");
    assert_eq!(tracked.chains, vec!["hk-140", "devops"]);

    client.shutdown().await?;
    upstream.shutdown().await?;
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(5), task).await???;
    Ok(())
}

#[tokio::test]
async fn udp_tracker_uses_the_udp_selection_snapshot() -> anyhow::Result<()> {
    let mut tcp_node = Node {
        name: "tcp-node".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        address: "127.0.0.1".into(),
        port: 140,
        ..Default::default()
    };
    tcp_node.id = tcp_node.derive_id();
    let mut udp_node = Node {
        name: "udp-node".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        address: "127.0.0.1".into(),
        port: 163,
        ..Default::default()
    };
    udp_node.id = udp_node.derive_id();
    let config = udp_test_config(
        "traffic",
        vec![tcp_node.clone(), udp_node.clone()],
        vec![Group {
            name: "traffic".into(),
            policy: honk_config::group::GroupPolicy::URLTest,
            nodes: vec![tcp_node.id, udp_node.id],
            ..Default::default()
        }],
    );
    let handle = udp_test_handle(config, UdpTestMode::Success, 1);
    handle.alive_set.record_probe_latency(
        tcp_node.id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    handle.alive_set.record_probe_latency(
        udp_node.id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    handle.alive_set.record_probe_latency(
        tcp_node.id,
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    handle.alive_set.record_probe_latency(
        udp_node.id,
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    assert_eq!(
        handle
            .group_manager
            .read()
            .select_node_for_domain("traffic", ProbeDomain::Tcp, IpVersion::V4)
            .expect("TCP selection")
            .name,
        "tcp-node"
    );
    assert_eq!(
        handle
            .group_manager
            .read()
            .select_node_for_domain("traffic", ProbeDomain::DataUdp, IpVersion::V4)
            .expect("UDP selection")
            .name,
        "udp-node"
    );
    assert_eq!(
        handle
            .group_manager
            .read()
            .selection_chain_for_network("traffic", crate::group::SelectionNetwork::Tcp),
        vec!["traffic", "tcp-node"]
    );
    assert_eq!(
        handle
            .group_manager
            .read()
            .selection_chain_for_network("traffic", crate::group::SelectionNetwork::Udp),
        vec!["traffic", "udp-node"]
    );

    serve_test_udp(&handle).await?;
    let tracked = handle
        .connection_tracker
        .snapshot()
        .into_iter()
        .next()
        .expect("ready UDP endpoint must be tracked");
    assert_eq!(tracked.proxy, "udp-node");
    assert_eq!(tracked.chains, vec!["udp-node", "traffic"]);
    handle
        .udp_pool
        .remove(addr("10.0.0.2:53000"), addr("203.0.113.2:443"));
    Ok(())
}

#[tokio::test]
async fn udp_stats_lifecycle_no_candidate_closes_guard_and_records_error() {
    let config = udp_test_config(
        "empty",
        vec![],
        vec![Group {
            name: "empty".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            ..Default::default()
        }],
    );
    let handle = udp_test_handle(config, UdpTestMode::Success, 1);
    let stats = handle.stats.clone();

    serve_test_udp(&handle).await.unwrap();

    assert_udp_outbound(&stats, "empty", 1, 0, 1);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.route_latency.count, 1);
    assert_eq!(udp.dial_latency.count, 0);
}

#[tokio::test]
async fn udp_stats_lifecycle_dial_error_closes_guard_and_samples_dial() {
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(config, UdpTestMode::DialError, 1);
    let stats = handle.stats.clone();

    serve_test_udp(&handle).await.unwrap();

    assert_udp_outbound(&stats, "udp-test-route", 1, 0, 1);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.route_latency.count, 1);
    assert_eq!(udp.dial_latency.count, 1);
}

#[tokio::test]
async fn udp_init_lease_capacity_rejection_happens_before_route_or_send() {
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(config, UdpTestMode::Success, 0);
    let stats = handle.stats.clone();

    serve_test_udp(&handle).await.unwrap();

    assert!(stats.snapshot().is_empty());
    let udp = stats.udp_snapshot();
    assert_eq!(udp.capacity_rejections, 1);
    assert_eq!(udp.route_latency.count, 0);
}

#[tokio::test]
async fn udp_init_lease_capacity_rejection_sends_zero() {
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(config, UdpTestMode::CountSends(sends.clone()), 0);

    serve_test_udp(&handle).await.unwrap();

    assert_eq!(
        sends.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "endpoint reservation must reject at capacity before application send"
    );
}

#[tokio::test]
async fn udp_init_lease_reply_factory_failure_sends_zero() {
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle_with_reply_factory(
        config,
        UdpTestMode::CountSends(sends.clone()),
        1,
        Arc::new(FailingUdpTestReplySocketFactory),
    );

    assert!(serve_test_udp(&handle).await.is_err());

    assert_eq!(
        sends.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "anyfrom setup failure must happen before the first application send"
    );
    assert!(handle.udp_pool.is_empty());
}

#[tokio::test]
async fn udp_stats_lifecycle_first_send_error_closes_guard_and_records_error() {
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(config, UdpTestMode::SendError, 1);
    let stats = handle.stats.clone();

    assert!(serve_test_udp(&handle).await.is_err());

    assert_udp_outbound(&stats, "udp-test-route", 1, 0, 1);
}

#[tokio::test]
async fn udp_first_send_failure_does_not_replay_to_another_candidate() {
    let first = udp_test_node();
    let mut second = Node {
        name: "udp-test-second".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        address: "127.0.0.1".into(),
        port: 10,
        ..Default::default()
    };
    second.id = second.derive_id();
    let config = udp_test_config(
        "udp-group",
        vec![first.clone(), second.clone()],
        vec![Group {
            name: "udp-group".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            nodes: vec![first.id, second.id],
            ..Default::default()
        }],
    );
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handle = udp_test_handle(
        config,
        UdpTestMode::CountFirstSendError {
            dials: dials.clone(),
            sends: sends.clone(),
        },
        2,
    );

    assert!(serve_test_udp(&handle).await.is_err());

    assert_eq!(
        sends.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the selected transport receives exactly one application-send attempt"
    );
    assert_eq!(
        dials.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "an ambiguous first-send failure must not dial a later candidate"
    );
}

#[tokio::test]
async fn udp_cold_urltest_commit_failure_sends_nothing_and_fails_closed() {
    let node = udp_test_node();
    let config = udp_test_config(
        "udp-group",
        vec![node.clone()],
        vec![Group {
            name: "udp-group".into(),
            policy: honk_config::group::GroupPolicy::URLTest,
            nodes: vec![node.id],
            ..Default::default()
        }],
    );
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handle = udp_test_handle(
        config,
        UdpTestMode::PreparedCommitError {
            dials: Arc::clone(&dials),
            commits: Arc::clone(&commits),
            sends: Arc::clone(&sends),
        },
        1,
    );

    assert!(serve_test_udp(&handle).await.is_err());
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(handle.udp_pool.is_empty());
}

#[tokio::test(start_paused = true)]
async fn udp_cold_urltest_commit_obeys_the_preparation_deadline() {
    let node = udp_test_node();
    let mut config = udp_test_config(
        "udp-group",
        vec![node.clone()],
        vec![Group {
            name: "udp-group".into(),
            policy: honk_config::group::GroupPolicy::URLTest,
            nodes: vec![node.id],
            ..Default::default()
        }],
    );
    config.global.connect_timeout_ms = 1;
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let handle = udp_test_handle(
        config,
        UdpTestMode::PreparedCommitHold {
            dials: Arc::clone(&dials),
            commits: Arc::clone(&commits),
            sends: Arc::clone(&sends),
            entered: Arc::clone(&entered),
            release: Arc::new(tokio::sync::Notify::new()),
        },
        1,
    );
    let task_handle = handle.clone();
    let task = tokio::spawn(async move { serve_test_udp(&task_handle).await });

    entered.notified().await;
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 0);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("winner commit must retain the preparation deadline")
            .expect("UDP initializer task must not panic")
            .is_err()
    );
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(handle.udp_pool.is_empty());
}

#[tokio::test(start_paused = true)]
async fn udp_cold_urltest_rejects_commit_ready_after_deadline() {
    let node = udp_test_node();
    let mut config = udp_test_config(
        "udp-group",
        vec![node.clone()],
        vec![Group {
            name: "udp-group".into(),
            policy: honk_config::group::GroupPolicy::URLTest,
            nodes: vec![node.id],
            ..Default::default()
        }],
    );
    config.global.connect_timeout_ms = 1;
    let commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let handle = udp_test_handle(
        config,
        UdpTestMode::PreparedCommitHold {
            dials: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            commits: Arc::clone(&commits),
            sends: Arc::clone(&sends),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        },
        1,
    );
    let operation = serve_test_udp(&handle);
    tokio::pin!(operation);
    tokio::select! {
        result = &mut operation => panic!("commit did not wait: {result:?}"),
        _ = entered.notified() => {}
    }
    // Keep the initializer unpolled until both the deadline and commit are ready.
    tokio::time::advance(Duration::from_secs(11)).await;
    release.notify_one();

    assert!(operation.await.is_err());
    assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(handle.udp_pool.is_empty());
}

#[tokio::test]
async fn udp_authoritative_plan_bypasses_speculative_commit_hook() {
    let node = udp_test_node();
    let config = udp_test_config(
        "udp-group",
        vec![node.clone()],
        vec![Group {
            name: "udp-group".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            nodes: vec![node.id],
            ..Default::default()
        }],
    );
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handle = udp_test_handle(
        config,
        UdpTestMode::PreparedCommitError {
            dials: Arc::clone(&dials),
            commits: Arc::clone(&commits),
            sends: Arc::clone(&sends),
        },
        1,
    );

    serve_test_udp(&handle).await.unwrap();
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn udp_stats_lifecycle_slow_future_cancellation_drops_guard_without_error() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(
        config,
        UdpTestMode::Hold {
            entered: entered.clone(),
            release,
        },
        1,
    );
    let stats = handle.stats.clone();
    let task = tokio::spawn(async move { serve_test_udp(&handle).await });

    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("production slow path did not reach the injected dialer");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    assert_udp_outbound(&stats, "udp-test-route", 1, 0, 0);
}

#[tokio::test]
async fn udp_init_lease_concurrent_first_packets_make_one_reservation_and_one_dial() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(
        config,
        UdpTestMode::HoldAndCount {
            entered: entered.clone(),
            release: release.clone(),
            dials: dials.clone(),
        },
        1,
    );
    let first_handle = handle.clone();
    let first = tokio::spawn(async move { serve_test_udp(&first_handle).await });

    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("first packet did not reach the injected dialer");
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);

    serve_test_udp(&handle)
        .await
        .expect("concurrent follower must enqueue behind the reservation");
    assert_eq!(
        dials.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "concurrent first packets must not create a second initializer"
    );

    release.notify_one();
    first.await.unwrap().unwrap();
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn udp_node_dead_before_production_dial_has_zero_dials_and_sends() {
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(
        config,
        UdpTestMode::CountDialAndSend {
            dials: dials.clone(),
            sends: sends.clone(),
        },
        1,
    );

    for domain in [
        crate::outbound::ProbeDomain::DataUdp,
        crate::outbound::ProbeDomain::DnsUdp,
    ] {
        handle.alive_set.report_unavailable_forced(
            udp_test_node().id,
            domain,
            crate::outbound::IpVersion::V4,
        );
    }
    serve_test_udp(&handle).await.unwrap();

    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[tokio::test]
async fn udp_dns_udp_liveness_keeps_explicit_node_selectable_in_production() {
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(
        config,
        UdpTestMode::CountDialAndSend {
            dials: dials.clone(),
            sends: sends.clone(),
        },
        1,
    );

    handle.alive_set.report_unavailable_forced(
        udp_test_node().id,
        crate::outbound::ProbeDomain::DataUdp,
        crate::outbound::IpVersion::V4,
    );
    serve_test_udp(&handle).await.unwrap();

    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn udp_authoritative_selection_stops_after_single_candidate_dial_failure() {
    let first = udp_test_node();
    let mut second = Node {
        name: "udp-test-second".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        address: "127.0.0.1".into(),
        port: 10,
        ..Default::default()
    };
    second.id = second.derive_id();
    let config = udp_test_config(
        "udp-group",
        vec![first.clone(), second.clone()],
        vec![Group {
            name: "udp-group".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            nodes: vec![first.id, second.id],
            ..Default::default()
        }],
    );
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handle = udp_test_handle(
        config,
        UdpTestMode::CountDialError {
            dials: dials.clone(),
        },
        2,
    );

    serve_test_udp(&handle).await.unwrap();

    assert_eq!(
        dials.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "Selector is authoritative: pre-send failure does not invent a second candidate"
    );
}

#[tokio::test]
async fn udp_production_death_during_unbound_preparation_prevents_send() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let target = udp_test_node();
    let mut unrelated = Node {
        name: "health-registered-other".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        address: "127.0.0.1".into(),
        port: 10,
        ..Default::default()
    };
    unrelated.id = unrelated.derive_id();
    // Keep the selected direct node out of the health-check registration so
    // the public death transition is not hidden by the startup grace period.
    let config = udp_test_config(
        "udp-test",
        vec![target, unrelated.clone()],
        vec![Group {
            name: "unrelated-health-group".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            nodes: vec![unrelated.id],
            ..Default::default()
        }],
    );
    let handle = udp_test_handle_with_default_pool(
        config,
        UdpTestMode::HoldAndCountDialAndSend {
            entered: entered.clone(),
            release: release.clone(),
            dials: dials.clone(),
            sends: sends.clone(),
        },
    );
    let task_handle = handle.clone();
    let task = tokio::spawn(async move { serve_test_udp(&task_handle).await });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("production ProxyRegistry transport preparation must block");

    // TCP death triggers the production removal callback; both UDP domains
    // becoming unavailable ensure the scheduler's completion recheck rejects
    // the transport before it can become a winner.
    handle.alive_set.report_unavailable_forced(
        udp_test_node().id,
        crate::outbound::ProbeDomain::DataUdp,
        crate::outbound::IpVersion::V4,
    );
    handle.alive_set.report_unavailable_forced(
        udp_test_node().id,
        crate::outbound::ProbeDomain::DnsUdp,
        crate::outbound::IpVersion::V4,
    );
    handle.alive_set.mark_dead(udp_test_node().id);
    assert!(
        !handle.udp_pool.is_empty(),
        "speculative transport preparation must not bind its lease before a winner exists"
    );
    release.notify_one();
    let result = task.await.unwrap();
    assert!(result.is_ok(), "unexpected initializer result: {result:?}");
    assert!(
        handle.udp_pool.is_empty(),
        "the stale unbound initializer must retire after eligibility rejects its prepared transport"
    );
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "death during the production blocked dial must prevent application send"
    );
}

#[tokio::test]
async fn udp_stats_lifecycle_success_and_reply_eof_close_guard() {
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(config, UdpTestMode::Success, 1);
    let stats = handle.stats.clone();

    serve_test_udp(&handle).await.unwrap();
    tokio::task::yield_now().await;

    assert_udp_outbound(&stats, "udp-test-route", 1, 0, 0);
}

#[test]
fn udp_slow_admission_is_identical_for_ipv4_and_ipv6() {
    for (client, dst) in [
        (addr("10.0.0.2:53000"), addr("203.0.113.2:443")),
        (addr("[2001:db8::2]:53000"), addr("[2001:db8::3]:443")),
    ] {
        let pool = Arc::new(UdpEndpointPool::with_capacity_limit(1));
        let stats = Arc::new(StatsManager::new());
        let slow = Arc::new(tokio::sync::Semaphore::new(1));
        let lease =
            super::reserve_udp_slow_path(&pool, &stats, &slow, client, dst, b"family-symmetric")
                .expect("both listener families must admit before reserving");
        assert_eq!(pool.len(), 1);
        let udp = stats.udp_snapshot();
        assert_eq!(udp.slow_permit_accepted, 1);
        assert_eq!(udp.capacity_rejections, 0);
        assert_eq!(udp.queue_accepted, 0);
        drop(lease);
        assert!(pool.is_empty());
    }
}

#[tokio::test]
async fn udp_stats_lifecycle_slow_permit_full_rejects_without_outbound_total() {
    // Exercise the production admission helper used by the accept-loop slow
    // path. A full semaphore must bump only udp.slowPermit.rejected and must
    // never open an outbound connection counter.
    let stats = Arc::new(StatsManager::new());
    let full = Arc::new(tokio::sync::Semaphore::new(0));

    assert!(super::try_admit_udp_slow_path(&stats, &full).is_none());

    assert!(stats.snapshot().is_empty());
    let udp = stats.udp_snapshot();
    assert_eq!(udp.slow_permit_rejected, 1);
    assert_eq!(udp.slow_permit_accepted, 0);
    assert_eq!(udp.slow_permit_closed, 0);
    assert_eq!(udp.queue_accepted, 0);
    assert_eq!(udp.flow_queue_full, 0);
    assert_eq!(udp.global_payload_full, 0);
    assert_eq!(udp.queue_closed, 0);

    let open = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = super::try_admit_udp_slow_path(&stats, &open).expect("slow path should admit");
    drop(permit);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.slow_permit_accepted, 1);
    assert_eq!(udp.slow_permit_rejected, 1);
    assert!(stats.snapshot().is_empty());
}

fn production_dns_controller(
    upstream_calls: Arc<std::sync::atomic::AtomicUsize>,
    response: Vec<u8>,
) -> Arc<crate::control::dns_control::DnsController> {
    use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};

    struct CountingUpstream {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        response: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl DnsUpstreamPool for CountingUpstream {
        async fn query(&self, _name: &str, _raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.response.clone())
        }
    }

    let upstream = Arc::new(CountingUpstream {
        calls: upstream_calls,
        response,
    });
    let router =
        Arc::new(
            crate::dns::routing::DnsRouter::new_from_dns_config(
                &honk_config::dns::DnsConfig::default(),
            )
            .unwrap(),
        );
    let forwarder = Arc::new(
        DnsForwarder::new(
            upstream,
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            router,
        )
        .with_cache_enabled(false),
    );
    Arc::new(crate::control::dns_control::DnsController::new(
        forwarder,
        Arc::new(tokio::sync::RwLock::new(Box::new(
            crate::ebpf::mock::MockEbpfBackend::new(),
        ))),
        Arc::new(tokio::sync::RwLock::new(
            Router::new(&[], "direct").unwrap(),
        )),
        256,
    ))
}

fn dns_response_payload() -> Vec<u8> {
    let mut resp = dns_query_payload();
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp
}

fn production_dns_controller_with_upstream(
    upstream: Arc<dyn crate::dns::forwarder::DnsUpstreamPool>,
) -> Arc<crate::control::dns_control::DnsController> {
    let router =
        Arc::new(
            crate::dns::routing::DnsRouter::new_from_dns_config(
                &honk_config::dns::DnsConfig::default(),
            )
            .unwrap(),
        );
    let forwarder = Arc::new(
        crate::dns::forwarder::DnsForwarder::new(
            upstream,
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            router,
        )
        .with_cache_enabled(false),
    );
    Arc::new(crate::control::dns_control::DnsController::new(
        forwarder,
        Arc::new(tokio::sync::RwLock::new(Box::new(
            crate::ebpf::mock::MockEbpfBackend::new(),
        ))),
        Arc::new(tokio::sync::RwLock::new(
            Router::new(&[], "direct").unwrap(),
        )),
        256,
    ))
}

#[tokio::test]
async fn udp_dns_dispatch_registers_connection_guard_before_task_poll() {
    struct BlockingUpstream {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl crate::dns::forwarder::DnsUpstreamPool for BlockingUpstream {
        async fn query(&self, _name: &str, _raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(dns_response_payload())
        }
    }

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    let handler = Arc::new(UdpTestHandler {
        mode: UdpTestMode::Success,
    });
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Socks5,
            handler.clone(),
        )
        .with_packet(handler),
    );
    let mut plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap();
    plane.dns_controller = production_dns_controller_with_upstream(Arc::new(BlockingUpstream {
        entered: entered.clone(),
        release: release.clone(),
    }));
    let drain = Arc::new(DrainTracker::new());
    let client = addr("10.0.0.3:53000");
    let dst = addr("203.0.113.3:53");

    let state = super::UdpLoopState {
        udp_pool: Arc::clone(&plane.udp_pool),
        stats: Arc::clone(&plane.stats),
        udp_concurrency_limit: Arc::clone(&plane.udp_concurrency_limit),
        dns_controller: Arc::clone(&plane.dns_controller),
        drain: Arc::clone(&drain),
        requires_dns_route_mark: false,
        handle: plane.spawn_handle(),
    };
    let query = dns_query_payload();
    let validated = validate_exact_dns_query(&query);
    super::dispatch_udp_slow_path(&state, client, dst, &query, validated);
    assert_eq!(
        drain.active_count(),
        1,
        "DNS work must be drain-counted when the dispatcher returns, before the spawned task polls"
    );
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("production DNS controller must receive the slow-path query");

    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if drain.active_count() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("DNS task must release its ConnectionGuard after completion");

    let _held_queries: Vec<_> = (0..2048)
        .map(|_| state.dns_controller.try_admit_query(false).unwrap())
        .collect();
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let original_dst = addr("127.0.0.1:53");
    let can_reply = super::sockets::new_udp_reply_socket(original_dst).is_ok();
    for _ in 0..256 {
        super::dispatch_udp_slow_path(&state, client_addr, original_dst, &query, validated);
    }
    assert_eq!(drain.active_count(), 256, "refusals retain UDP admission");
    super::dispatch_udp_slow_path(&state, client_addr, original_dst, &query, validated);
    assert_eq!(
        drain.active_count(),
        256,
        "UDP saturation cannot spawn a refusal"
    );

    if can_reply {
        let mut response = [0u8; 512];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response))
                .await
                .expect("query saturation must return REFUSED, not silently drop")
                .unwrap();
        assert_eq!(&response[..2], &query[..2]);
        assert!(len >= 12);
        assert_eq!(response[3] & 0x0f, 5);
    } else {
        eprintln!("skipping wire reply: transparent UDP socket needs privileges");
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while drain.active_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refusals release their UDP admission and drain guards");
}

/// Production-branch DNS path with an existing Ready endpoint: the shared
/// slow-path helper must run DnsController first and must not enqueue onto
/// the proxy driver.
#[tokio::test]
async fn udp_dns_with_ready_endpoint_uses_controller_not_queue() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    ready_udp_endpoint(
        &pool,
        &stats,
        client,
        dst,
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            proxy, echo_addr,
        )),
        echo_addr,
    )
    .await;
    // Drain the bootstrap first packet from the echo socket.
    let mut buf = [0u8; 64];
    echo.recv_from(&mut buf).await.unwrap();

    let upstream_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dns = production_dns_controller(upstream_calls.clone(), dns_response_payload());
    let slow = Arc::new(tokio::sync::Semaphore::new(1));
    let query = dns_query_payload();
    let validated = validate_exact_dns_query(&query).unwrap();

    // Fast path must force DNS-shaped traffic slow even with Ready present.
    assert!(!udp_fast_path(
        &pool,
        &stats,
        &query,
        client,
        dst,
        Some(validated)
    ));

    let received_at = crate::control::udp_endpoint::queue_now().wrapping_sub(1_234);
    match super::udp_ingress::begin_udp_slow_path_at(
        &pool,
        &stats,
        &slow,
        Some((dns.as_ref(), validated)),
        client,
        dst,
        &query,
        None,
        pool.initialization_epoch(),
        received_at,
    ) {
        super::UdpSlowPathWork::Dns {
            admission,
            data,
            validated,
        } => {
            dns.handle_udp_dns_admitted(&admission, &data, client, dst, validated)
                .await;
        }
        _ => panic!("strict DNS must not enter the Ready endpoint queue"),
    }

    assert_eq!(
        upstream_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "production DnsController must run for Ready+DNS"
    );
    // No follower was enqueued onto the Ready driver.
    assert_eq!(stats.udp_snapshot().queue_accepted, 0);
    let recv = tokio::time::timeout(Duration::from_millis(50), echo.recv_from(&mut buf)).await;
    assert!(
        recv.is_err(),
        "DNS query must not be forwarded to the proxy transport"
    );
}

/// Production-branch DNS path while an Initializing entry owns the tuple:
/// controller still runs first; the Initializing queue must not grow.
#[tokio::test]
async fn udp_dns_with_initializing_endpoint_uses_controller_not_queue() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    let init_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let lease = match pool.reserve_or_enqueue(client, dst, b"bootstrap", init_permit, &stats) {
        crate::control::udp_endpoint::EndpointReservation::Initializing(lease) => lease,
        _ => panic!("DNS+Initializing fixture must reserve"),
    };
    let queue_before = stats.udp_snapshot().queue_accepted;

    let upstream_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dns = production_dns_controller(upstream_calls.clone(), dns_response_payload());
    let slow = Arc::new(tokio::sync::Semaphore::new(1));
    let query = dns_query_payload();
    let validated = validate_exact_dns_query(&query).unwrap();
    assert!(!udp_fast_path(
        &pool,
        &stats,
        &query,
        client,
        dst,
        Some(validated)
    ));
    match super::begin_udp_slow_path(
        &pool,
        &stats,
        &slow,
        Some((dns.as_ref(), validated)),
        client,
        dst,
        &query,
    ) {
        super::UdpSlowPathWork::Dns {
            admission,
            data,
            validated,
        } => {
            dns.handle_udp_dns_admitted(&admission, &data, client, dst, validated)
                .await;
        }
        _ => panic!("strict DNS must not enter the Initializing endpoint queue"),
    }

    assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        stats.udp_snapshot().queue_accepted,
        queue_before,
        "DNS must not enqueue onto the Initializing follower queue"
    );
    assert!(lease.still_initializing());
    drop(lease);
}

/// Initializing followers must not use the direct fast queue path. With a
/// zero-permit semaphore the shared dispatch helper rejects without copying
/// or queue growth; with a permit it enqueues exactly once.
#[tokio::test]
async fn udp_initializing_follower_requires_slow_permit_via_shared_helper() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let init_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let lease = match pool.reserve_or_enqueue(client, dst, b"first", init_permit, &stats) {
        crate::control::udp_endpoint::EndpointReservation::Initializing(lease) => lease,
        _ => panic!("follower fixture must initialize"),
    };

    assert!(!udp_fast_path(
        &pool,
        &stats,
        b"follower",
        client,
        dst,
        None
    ));
    assert_eq!(stats.udp_snapshot().endpoint_misses, 1);
    assert_eq!(stats.udp_snapshot().queue_accepted, 0);

    let zero = Arc::new(tokio::sync::Semaphore::new(0));
    match super::begin_udp_slow_path(&pool, &stats, &zero, None, client, dst, b"follower") {
        super::UdpSlowPathWork::Done => {}
        _ => panic!("zero slow permit must not reserve or enqueue"),
    }
    let udp = stats.udp_snapshot();
    assert_eq!(udp.slow_permit_rejected, 1);
    assert_eq!(udp.queue_accepted, 0);

    let open = Arc::new(tokio::sync::Semaphore::new(1));
    match super::begin_udp_slow_path(&pool, &stats, &open, None, client, dst, b"follower") {
        super::UdpSlowPathWork::Done => {}
        super::UdpSlowPathWork::Initialize(_) => {
            panic!("Initializing follower must enqueue, not create a second lease")
        }
        super::UdpSlowPathWork::Dns { .. } | super::UdpSlowPathWork::DnsRefused { .. } => {
            panic!("non-DNS follower must not take the DNS branch")
        }
    }
    let udp = stats.udp_snapshot();
    assert_eq!(udp.slow_permit_accepted, 1);
    assert_eq!(udp.queue_accepted, 1);
    drop(lease);
}

fn resolve_udp_score_plan(
    config: &Config,
    manager: &GroupManager,
    outbound: &str,
    ipver: IpVersion,
) -> ResolvedUdpPlan {
    resolve_udp_outbound_plan_for_target(
        config,
        manager,
        outbound,
        &crate::group::ScoreSelectionContext::aggregate(
            crate::group::SelectionNetwork::Udp,
            ProbeDomain::DataUdp,
            ipver,
        ),
    )
}

#[test]
fn resolve_selector_refusal_uses_only_explicit_final() {
    let selected = Node {
        id: uuid::Uuid::from_u128(101),
        name: "selected".into(),
        ..udp_test_node()
    };
    let sibling = Node {
        id: uuid::Uuid::from_u128(102),
        name: "sibling".into(),
        ..udp_test_node()
    };
    let selector = Group {
        name: "selector".into(),
        policy: GroupPolicy::Selector,
        nodes: vec![selected.id, sibling.id],
        default: Some(selected.name.clone()),
        ..Default::default()
    };
    let with_final = Group {
        name: "selector-final".into(),
        final_outbound: Some("block".into()),
        ..selector.clone()
    };
    let alive = Arc::new(AliveDialerSet::new());
    for ipver in [IpVersion::V4, IpVersion::V6] {
        for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
            alive.report_unavailable_forced(selected.id, domain, ipver);
        }
    }
    let config = udp_test_config(
        "direct",
        vec![selected, sibling],
        vec![selector, with_final],
    );
    let manager = GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive));
    for (network, domain) in [
        (crate::group::SelectionNetwork::Tcp, ProbeDomain::Tcp),
        (crate::group::SelectionNetwork::Udp, ProbeDomain::DataUdp),
    ] {
        let context =
            crate::group::ScoreSelectionContext::aggregate(network, domain, IpVersion::V6);
        assert!(
            super::reload::resolve_outbound_plan_for_target(
                &config, &manager, "selector", &context
            )
            .nodes
            .is_empty()
        );
        let plan = super::reload::resolve_outbound_plan_for_target(
            &config,
            &manager,
            "selector-final",
            &context,
        );
        assert_eq!(plan.mode, crate::group::SelectionPlanMode::Authoritative);
        assert_eq!(
            plan.nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["block"]
        );
        assert_eq!(plan.selection_chains, [vec!["selector-final", "block"]]);
    }
}

#[test]
fn resolve_udp_score_plan_preserves_terminal_provenance() {
    let first = Node {
        id: uuid::Uuid::new_v4(),
        name: "first".into(),
        ..udp_test_node()
    };
    let second = Node {
        id: uuid::Uuid::new_v4(),
        name: "second".into(),
        ..udp_test_node()
    };
    let cold_child = Group {
        name: "cold-child".into(),
        policy: GroupPolicy::URLTest,
        nodes: vec![first.id, second.id],
        ..Default::default()
    };
    let nested_parent = Group {
        name: "nested-parent".into(),
        policy: GroupPolicy::Selector,
        groups: vec!["cold-child".into()],
        ..Default::default()
    };
    let empty_final = Group {
        name: "empty-final".into(),
        policy: GroupPolicy::Selector,
        final_outbound: Some("cold-child".into()),
        ..Default::default()
    };
    let config = udp_test_config(
        "direct",
        vec![first.clone(), second.clone()],
        vec![cold_child, nested_parent, empty_final],
    );
    let manager = GroupManager::new(&config.groups, &config.nodes);

    let direct = resolve_udp_score_plan(&config, &manager, "direct", IpVersion::V4);
    assert_eq!(direct.mode, crate::group::SelectionPlanMode::Authoritative);
    assert_eq!(
        direct
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["direct"]
    );

    let node = resolve_udp_score_plan(&config, &manager, "first", IpVersion::V4);
    assert_eq!(node.mode, crate::group::SelectionPlanMode::Authoritative);
    assert_eq!(
        node.nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["first"]
    );

    let nested = resolve_udp_score_plan(&config, &manager, "nested-parent", IpVersion::V4);
    assert_eq!(nested.mode, crate::group::SelectionPlanMode::Authoritative);
    assert_eq!(
        nested
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["first"]
    );

    let final_plan = resolve_udp_score_plan(&config, &manager, "empty-final", IpVersion::V4);
    assert_eq!(
        final_plan.mode,
        crate::group::SelectionPlanMode::ColdUrlTest
    );
    assert_eq!(
        final_plan
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
}

#[test]
fn resolve_udp_score_plan_tracks_v4_fallback_and_final_resolution_guards() {
    let v4_only = Node {
        id: uuid::Uuid::new_v4(),
        name: "v4-only".into(),
        ..udp_test_node()
    };
    let groups = vec![
        Group {
            name: "v4-group".into(),
            policy: GroupPolicy::URLTest,
            nodes: vec![v4_only.id],
            ..Default::default()
        },
        Group {
            name: "empty".into(),
            policy: GroupPolicy::Selector,
            ..Default::default()
        },
        Group {
            name: "missing-final".into(),
            policy: GroupPolicy::Selector,
            final_outbound: Some("not-configured".into()),
            ..Default::default()
        },
        Group {
            name: "cycle-a".into(),
            policy: GroupPolicy::Selector,
            final_outbound: Some("cycle-b".into()),
            ..Default::default()
        },
        Group {
            name: "cycle-b".into(),
            policy: GroupPolicy::Selector,
            final_outbound: Some("cycle-a".into()),
            ..Default::default()
        },
    ];
    let v4_only_id = v4_only.id;
    let config = udp_test_config("direct", vec![v4_only], groups);
    let alive = Arc::new(AliveDialerSet::new());
    alive.report_unavailable_forced(v4_only_id, ProbeDomain::DataUdp, IpVersion::V6);
    alive.report_unavailable_forced(v4_only_id, ProbeDomain::DnsUdp, IpVersion::V6);
    let manager = GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive));

    let v4_fallback = resolve_udp_score_plan(&config, &manager, "v4-group", IpVersion::V6);
    assert_eq!(
        v4_fallback.mode,
        crate::group::SelectionPlanMode::ColdUrlTest
    );
    assert_eq!(v4_fallback.ipver, IpVersion::V4);
    assert_eq!(
        v4_fallback
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["v4-only"]
    );

    let empty = resolve_udp_score_plan(&config, &manager, "empty", IpVersion::V4);
    assert!(empty.nodes.is_empty());
    assert_eq!(empty.mode, crate::group::SelectionPlanMode::Authoritative);

    let missing = resolve_udp_score_plan(&config, &manager, "missing-final", IpVersion::V4);
    assert_eq!(
        missing
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["direct"]
    );

    let cycle = resolve_udp_score_plan(&config, &manager, "cycle-a", IpVersion::V4);
    assert!(
        cycle.nodes.is_empty(),
        "final cycles fail closed instead of bypassing policy"
    );
}

#[test]
fn resolve_udp_score_plan_explicit_node_falls_back_to_v4_through_final() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "v4-explicit".into(),
        ..udp_test_node()
    };
    let final_group = Group {
        name: "final-to-explicit".into(),
        policy: GroupPolicy::Selector,
        final_outbound: Some(node.name.clone()),
        ..Default::default()
    };
    let node_id = node.id;
    let config = udp_test_config("direct", vec![node], vec![final_group]);
    let alive = Arc::new(AliveDialerSet::new());
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(node_id, domain, IpVersion::V6);
    }
    let manager = GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive.clone()));

    for outbound in ["v4-explicit", "final-to-explicit"] {
        let plan = resolve_udp_score_plan(&config, &manager, outbound, IpVersion::V6);
        assert_eq!(plan.mode, crate::group::SelectionPlanMode::Authoritative);
        assert_eq!(plan.ipver, IpVersion::V4, "{outbound}");
        assert_eq!(
            plan.nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["v4-explicit"],
            "{outbound}"
        );
    }

    for outbound in ["direct", "block"] {
        let plan = resolve_udp_score_plan(&config, &manager, outbound, IpVersion::V6);
        assert_eq!(plan.ipver, IpVersion::V6, "{outbound}");
        assert_eq!(
            plan.nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            [outbound]
        );
    }

    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(node_id, domain, IpVersion::V4);
    }
    for outbound in ["v4-explicit", "final-to-explicit"] {
        assert!(
            resolve_udp_score_plan(&config, &manager, outbound, IpVersion::V6)
                .nodes
                .is_empty(),
            "{outbound} must stay empty when neither family is selectable"
        );
    }
}

#[test]
fn resolve_udp_score_plan_excludes_unselectable_explicit_node() {
    let node = udp_test_node();
    let config = udp_test_config("udp-test", vec![node], vec![]);
    let alive = Arc::new(AliveDialerSet::new());
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(udp_test_node().id, domain, IpVersion::V4);
    }
    let manager = GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive));

    let plan = resolve_udp_score_plan(&config, &manager, "udp-test", IpVersion::V4);

    assert!(plan.nodes.is_empty());
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_uses_absolute_offsets_bounds_inflight_and_drains_losers() {
    let start = tokio::time::Instant::now();
    let starts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let max_active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let release_first = Arc::new(tokio::sync::Notify::new());
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let winners = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<String> = {
        let starts = starts.clone();
        let active = active.clone();
        let max_active = max_active.clone();
        let release_first = release_first.clone();
        Arc::new(move |_: usize, node: Node| {
            let starts = starts.clone();
            let active = active.clone();
            let max_active = max_active.clone();
            let release_first = release_first.clone();
            Box::pin(async move {
                let now_active = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                max_active.fetch_max(now_active, std::sync::atomic::Ordering::SeqCst);
                starts.lock().unwrap().push((
                    node.name.clone(),
                    tokio::time::Instant::now().duration_since(start),
                ));
                match node.name.as_str() {
                    "first-error" => {
                        release_first.notified().await;
                        active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        Err(anyhow::anyhow!("scripted dial error"))
                    }
                    "winner" => {
                        active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(node.name)
                    }
                    _ => std::future::pending::<anyhow::Result<String>>().await,
                }
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|_| true),
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = errors.clone();
            Arc::new(move |_| {
                errors.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: {
            let winners = winners.clone();
            Arc::new(move || {
                winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_cancellation: {
            let cancellations = cancellations.clone();
            Arc::new(move || {
                cancellations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
    };
    let candidates = [
        "first-error",
        "loser-1",
        "loser-2",
        "winner",
        "never-started",
    ]
    .into_iter()
    .map(|name| Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        ..udp_test_node()
    })
    .collect();
    let task = tokio::spawn(prepare_udp_plan(
        crate::group::SelectionPlanMode::ColdUrlTest,
        candidates,
        tokio::time::Instant::now() + Duration::from_secs(10),
        prepare,
        callbacks,
    ));

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(50)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(80)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        starts
            .lock()
            .unwrap()
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["first-error", "loser-1", "loser-2"],
        "the fourth offset passed, but max-three in-flight blocks its start"
    );

    release_first.notify_one();
    let (winner, _) = task
        .await
        .unwrap()
        .expect("scheduler succeeds")
        .expect("the first successful preparation wins");
    assert_eq!(winner.name, "winner");
    let starts = starts.lock().unwrap();
    assert_eq!(
        starts
            .iter()
            .map(|(name, offset)| (name.as_str(), *offset))
            .collect::<Vec<_>>(),
        [
            ("first-error", Duration::ZERO),
            ("loser-1", Duration::from_millis(30)),
            ("loser-2", Duration::from_millis(80)),
            ("winner", Duration::from_millis(160)),
        ]
    );
    assert_eq!(max_active.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 4);
    assert_eq!(
        errors.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only a real dial Err changes health"
    );
    assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        cancellations.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "only started losers are cancelled"
    );
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_drain_counts_error_but_rejection_prevents_winner() {
    let release = Arc::new(tokio::sync::Notify::new());
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<String> = {
        let release = release.clone();
        Arc::new(move |_: usize, node: Node| {
            let release = release.clone();
            Box::pin(async move {
                release.notified().await;
                match node.name.as_str() {
                    "winner" => Ok(node.name),
                    "completed-error" => Err(anyhow::anyhow!("scripted dial error")),
                    "completed-rejection" => Err(anyhow::Error::new(
                        honk_outbound::proxy::PacketRejection::Policy,
                    )),
                    _ => unreachable!(),
                }
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|_| true),
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = errors.clone();
            Arc::new(move |_| {
                errors.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: Arc::new(|| {}),
        on_cancellation: {
            let cancellations = cancellations.clone();
            Arc::new(move || {
                cancellations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
    };
    let candidates = ["winner", "completed-error", "completed-rejection"]
        .into_iter()
        .map(|name| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            ..udp_test_node()
        })
        .collect();
    let task = tokio::spawn(prepare_udp_plan(
        crate::group::SelectionPlanMode::ColdUrlTest,
        candidates,
        tokio::time::Instant::now() + Duration::from_secs(10),
        prepare,
        callbacks,
    ));

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(50)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);

    release.notify_waiters();
    let error = task.await.unwrap().unwrap_err();
    assert!(honk_outbound::proxy::is_packet_rejection(&error));
    assert_eq!(errors.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_authoritative_prepares_only_the_current_node_without_delay() {
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let winners = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<String> =
        Arc::new(|_: usize, node: Node| Box::pin(async move { Ok(node.name) }));
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|_| true),
        is_eligible: Arc::new(|_| true),
        on_dial_error: Arc::new(|_| panic!("authoritative success must not report an error")),
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: {
            let winners = winners.clone();
            Arc::new(move || {
                winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_cancellation: {
            let cancellations = cancellations.clone();
            Arc::new(move || {
                cancellations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
    };
    let candidates = ["authoritative", "must-not-start"]
        .into_iter()
        .map(|name| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            ..udp_test_node()
        })
        .collect();

    let (winner, _) = prepare_udp_plan(
        crate::group::SelectionPlanMode::Authoritative,
        candidates,
        tokio::time::Instant::now() + Duration::from_secs(10),
        prepare,
        callbacks,
    )
    .await
    .expect("scheduler succeeds")
    .expect("authoritative candidate should start at offset zero");
    assert_eq!(winner.name, "authoritative");
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_authoritative_failure_preserves_fixed_metric_zeros() {
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let winners = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<()> =
        Arc::new(|_: usize, _: Node| Box::pin(async { Err(anyhow::anyhow!("dial failed")) }));
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|_| true),
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = errors.clone();
            Arc::new(move |_| {
                errors.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: {
            let winners = winners.clone();
            Arc::new(move || {
                winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_cancellation: {
            let cancellations = cancellations.clone();
            Arc::new(move || {
                cancellations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
    };
    let candidates = vec![Node {
        id: uuid::Uuid::new_v4(),
        name: "authoritative-failure".into(),
        ..udp_test_node()
    }];

    assert!(
        prepare_udp_plan(
            crate::group::SelectionPlanMode::Authoritative,
            candidates,
            tokio::time::Instant::now() + Duration::from_secs(10),
            prepare,
            callbacks,
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(errors.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_all_dial_failures_report_health_without_cancellation() {
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<()> =
        Arc::new(|_: usize, _: Node| Box::pin(async { Err(anyhow::anyhow!("dial failed")) }));
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|_| true),
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = errors.clone();
            Arc::new(move |_| {
                errors.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: Arc::new(|| {}),
        on_cancellation: {
            let cancellations = cancellations.clone();
            Arc::new(move || {
                cancellations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
    };
    let candidates = ["first", "second"]
        .into_iter()
        .map(|name| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            ..udp_test_node()
        })
        .collect();
    let task = tokio::spawn(prepare_udp_plan(
        crate::group::SelectionPlanMode::ColdUrlTest,
        candidates,
        tokio::time::Instant::now() + Duration::from_secs(10),
        prepare,
        callbacks,
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    assert!(task.await.unwrap().unwrap().is_none());
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(errors.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_rechecks_eligibility_before_accepting_prepared_transport() {
    let became_ineligible = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<String> = {
        let became_ineligible = became_ineligible.clone();
        Arc::new(move |_: usize, node: Node| {
            let became_ineligible = became_ineligible.clone();
            Box::pin(async move {
                if node.name == "became-ineligible" {
                    became_ineligible.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(node.name)
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|_| true),
        is_eligible: {
            let became_ineligible = became_ineligible.clone();
            Arc::new(move |node| {
                node.name != "became-ineligible"
                    || !became_ineligible.load(std::sync::atomic::Ordering::SeqCst)
            })
        },
        on_dial_error: Arc::new(|_| panic!("prepared success is not a dial error")),
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: Arc::new(|| {}),
        on_cancellation: Arc::new(|| {}),
    };
    let candidates = ["became-ineligible", "eligible-winner"]
        .into_iter()
        .map(|name| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            ..udp_test_node()
        })
        .collect();
    let task = tokio::spawn(prepare_udp_plan(
        crate::group::SelectionPlanMode::ColdUrlTest,
        candidates,
        tokio::time::Instant::now() + Duration::from_secs(10),
        prepare,
        callbacks,
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    let (winner, _) = task
        .await
        .unwrap()
        .expect("scheduler succeeds")
        .expect("eligible candidate should still win");
    assert_eq!(winner.name, "eligible-winner");
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
}

fn preconnect_test_node(name: &str, protocol: NodeProtocol) -> Node {
    Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        address: format!("{name}.example.com:443"),
        outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
        ..Default::default()
    }
}

fn preconnect_test_group(name: &str, policy: GroupPolicy, ids: Vec<uuid::Uuid>) -> Group {
    Group {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        policy,
        nodes: ids,
        filters: vec![],
        groups: vec![],
        default: None,
        final_outbound: None,
        check_url: None,
        check_interval: None,
        tolerance: 50,
        idle_timeout: None,
        interrupt_connections: false,
        created_at: chrono::Utc::now(),
    }
}

#[test]
fn preconnect_candidates_zero_disables_and_eligibility_is_descriptor_driven() {
    let anytls = preconnect_test_node("anytls", NodeProtocol::AnyTLS);
    let ss = preconnect_test_node("ss", NodeProtocol::SS);
    let tuic = preconnect_test_node("tuic", NodeProtocol::Tuic);
    let trojan = preconnect_test_node("trojan", NodeProtocol::Trojan);
    let hy2 = preconnect_test_node("hy2", NodeProtocol::Hysteria2);
    let direct = preconnect_test_node("direct", NodeProtocol::Direct);
    let block = preconnect_test_node("block", NodeProtocol::Block);
    let nodes = vec![anytls, ss.clone(), tuic, trojan.clone(), hy2, direct, block];
    let config = Config {
        nodes,
        ..Default::default()
    };
    let manager = GroupManager::new(&config.groups, &config.nodes);

    assert!(preconnect_candidates(&config, &manager, 0).is_empty());

    let picked = preconnect_candidates(
        &config,
        &manager,
        honk_config::config::PRECONNECT_NODE_COUNT_AUTO,
    );
    assert_eq!(
        picked.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
        vec!["ss", "trojan"],
        "AnyTLS/QUIC can never consume a pooled bare TCP; built-ins have no server"
    );
}

#[test]
fn preconnect_candidates_prefer_group_selections_then_config_order() {
    let ss = preconnect_test_node("ss", NodeProtocol::SS);
    let trojan = preconnect_test_node("trojan", NodeProtocol::Trojan);
    let vmess = preconnect_test_node("vmess", NodeProtocol::VMess);
    let config = Config {
        nodes: vec![ss, trojan.clone(), vmess],
        groups: vec![preconnect_test_group(
            "g",
            GroupPolicy::Selector,
            vec![trojan.id],
        )],
        ..Default::default()
    };
    let manager = GroupManager::new(&config.groups, &config.nodes);

    let picked = preconnect_candidates(&config, &manager, 8);
    assert_eq!(
        picked.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
        vec!["trojan", "ss", "vmess"],
        "the group's current pick leads; config order fills the rest"
    );
}

#[test]
fn preconnect_candidates_auto_caps_at_eight() {
    let nodes: Vec<_> = (0..12)
        .map(|i| preconnect_test_node(&format!("ss-{i}"), NodeProtocol::SS))
        .collect();
    let config = Config {
        nodes,
        ..Default::default()
    };
    let manager = GroupManager::new(&config.groups, &config.nodes);

    assert_eq!(
        preconnect_candidates(
            &config,
            &manager,
            honk_config::config::PRECONNECT_NODE_COUNT_AUTO
        )
        .len(),
        8
    );
    assert_eq!(
        preconnect_candidates(&config, &manager, 3).len(),
        3,
        "an explicit count smaller than the eligible set is honored"
    );
}

fn link_lifecycle_cp(backend: crate::ebpf::mock::MockEbpfBackend) -> ControlPlane {
    ControlPlane::new(
        Config::default(),
        Box::new(backend),
        Router::new(&[], "direct").unwrap(),
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap()
}

#[cfg(feature = "ebpf")]
#[tokio::test]
async fn exhausted_udp_tokens_wait_for_a_rollback_safe_generation() {
    use honk_ebpf_common::conn::{ConnState, UdpDecisionState};

    let mut backend = crate::ebpf::mock::MockEbpfBackend::new();
    backend.udp_decision_sequence_next = UDP_DECISION_SEQUENCE_MASK;
    let mut keys = Vec::new();
    for generation in 0..=UDP_DECISION_GENERATION_MASK {
        let key = connection::build_tuples_key(
            "203.0.113.1".parse().unwrap(),
            44000 + generation as u16,
            "10.0.0.1".parse().unwrap(),
            53000,
            17,
        );
        backend
            .udp_conn_state_store(
                &key,
                &ConnState {
                    state: UdpDecisionState::DirectArmed as u8,
                    decision_token: udp_decision_token(generation, 1).unwrap(),
                    ..ConnState::default()
                },
            )
            .unwrap();
        keys.push(key);
    }

    let control = link_lifecycle_cp(backend);
    assert!(!control.rotate_udp_decision_generation().await.unwrap());
    assert!(
        control
            .ebpf
            .read()
            .await
            .udp_decision_sequence_status()
            .unwrap()
            .exhausted()
    );

    control
        .ebpf
        .write()
        .await
        .udp_conn_state_remove(&keys[2])
        .unwrap();
    assert!(!control.rotate_udp_decision_generation().await.unwrap());
    control
        .ebpf
        .write()
        .await
        .udp_conn_state_remove(&keys[3])
        .unwrap();

    assert!(control.rotate_udp_decision_generation().await.unwrap());
    assert_eq!(
        control
            .ebpf
            .read()
            .await
            .udp_decision_sequence_status()
            .unwrap(),
        crate::ebpf::UdpDecisionSequenceStatus {
            next: 0,
            generation: 2,
        }
    );
    assert_eq!(control.stats.udp_snapshot().nfqueue.token_rollovers, 1);
}

/// Reload and subscription merge share `apply_runtime_config`, which only
/// rewrites maps through the live backend — datapath hooks must never be
/// detached or re-attached outside shutdown.
#[tokio::test]
async fn reload_and_merge_never_touch_ebpf_hooks() {
    use std::sync::atomic::Ordering;
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let detach = backend.detach_calls.clone();
    let dyn_attach = backend.dynamic_attach_calls.clone();
    let dyn_forget = backend.dynamic_forget_calls.clone();
    let mut cp = link_lifecycle_cp(backend);
    cp.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", "Proxy"),
    )));
    cp.start_datapath_flags_coordinator().unwrap();
    cp.initialize_datapath_flags(false, false).await.unwrap();

    let drain = DrainTracker::new();
    assert!(
        cp.apply_runtime_config(Config::default(), Default::default(), &drain)
            .await
    );
    assert!(
        cp.apply_runtime_config(Config::default(), Default::default(), &drain)
            .await
    );

    assert_eq!(
        detach.load(Ordering::Relaxed),
        0,
        "reload/merge must never detach datapath hooks"
    );
    assert_eq!(dyn_attach.load(Ordering::Relaxed), 0);
    assert_eq!(dyn_forget.load(Ordering::Relaxed), 0);
    cp.datapath_flags.as_ref().unwrap().disable().await.unwrap();
}

/// Shutdown with a flow that never finishes must still detach the hooks and
/// return in bounded time (the drain tracker caps the wait).
#[tokio::test]
async fn shutdown_detaches_hooks_and_stays_bounded_with_stuck_flow() {
    use std::sync::atomic::Ordering;
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let detach = backend.detach_calls.clone();
    let mut cp = link_lifecycle_cp(backend);

    // A flow that never finishes: the drain tracker must cap the wait.
    cp.drain_tracker.increment();
    let drain = cp.drain_tracker.clone();
    let mut removal_task = tokio::spawn(async {});

    tokio::time::timeout(Duration::from_secs(30), async {
        cp.shutdown_datapath(&drain, &mut removal_task, None)
            .await
            .unwrap();
        cp.finalize_shutdown().await.unwrap();
    })
    .await
    .expect("shutdown must stay bounded with a stuck flow");
    assert!(
        detach.load(Ordering::Relaxed) >= 1,
        "shutdown must detach the datapath hooks"
    );
}

#[tokio::test]
async fn udp_removal_worker_retires_legacy_token_zero_conn_state() {
    use honk_ebpf_common::conn::{ConnState, UdpDecisionState};
    use honk_ebpf_common::{ROUTING_META_FLAG_PUBLISHED, RoutingMeta};

    let client: SocketAddr = "10.0.0.1:53000".parse().unwrap();
    let dst: SocketAddr = "203.0.113.1:443".parse().unwrap();
    let key = connection::build_tuples_key(dst.ip(), dst.port(), client.ip(), client.port(), 17);
    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    mock.udp_conn_state_store(
        &key,
        &ConnState {
            state: UdpDecisionState::None as u8,
            decision_token: 0,
            meta: RoutingMeta {
                raw: ROUTING_META_FLAG_PUBLISHED | 2,
            },
            ..ConnState::default()
        },
    )
    .unwrap();
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(mock)));
    let pool = Arc::new(UdpEndpointPool::new());
    let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel();
    let removal_task = spawn_udp_removal_worker(
        Arc::clone(&pool),
        Arc::clone(&backend),
        Arc::new(ConnectionTracker::new()),
        fatal_tx,
    );
    let permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let lease = match pool.reserve_or_enqueue(
        client,
        dst,
        b"legacy first datagram",
        permit,
        &StatsManager::new(),
    ) {
        udp_endpoint::EndpointReservation::Initializing(lease) => lease,
        _ => panic!("expected an initializing lease"),
    };

    drop(lease);
    assert!(pool.wait_for_retirements().await);
    assert!(pool.is_empty());
    assert!(
        backend
            .read()
            .await
            .udp_conn_state_lookup(&key)
            .unwrap()
            .is_none()
    );
    assert!(fatal_rx.try_recv().is_err());

    assert!(pool.shutdown().await);
    removal_task.await.unwrap();
}

#[tokio::test]
async fn udp_removal_worker_acknowledges_superseding_token() {
    use honk_ebpf_common::conn::{ConnState, UdpDecisionState};

    let client: SocketAddr = "10.0.0.1:53000".parse().unwrap();
    let dst: SocketAddr = "203.0.113.1:443".parse().unwrap();
    let key = connection::build_tuples_key(dst.ip(), dst.port(), client.ip(), client.port(), 17);
    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    mock.udp_conn_state_store(
        &key,
        &ConnState {
            state: UdpDecisionState::Pending as u8,
            decision_token: 42,
            ..ConnState::default()
        },
    )
    .unwrap();
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(mock)));
    let pool = Arc::new(UdpEndpointPool::new());
    let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel();
    let removal_task = spawn_udp_removal_worker(
        Arc::clone(&pool),
        Arc::clone(&backend),
        Arc::new(ConnectionTracker::new()),
        fatal_tx,
    );
    let lease = match pool.reserve_owned_or_enqueue(
        client,
        dst,
        Bytes::from_static(b"held datagram"),
        41,
        None,
        Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap(),
        &StatsManager::new(),
    ) {
        udp_endpoint::EndpointReservation::Initializing(lease) => lease,
        _ => panic!("expected an initializing lease"),
    };

    drop(lease);
    assert!(pool.wait_for_retirements().await);
    assert!(pool.is_empty());
    assert_eq!(
        backend
            .read()
            .await
            .udp_conn_state_lookup(&key)
            .unwrap()
            .unwrap()
            .decision_token,
        42
    );
    assert!(fatal_rx.try_recv().is_err());

    assert!(pool.shutdown().await);
    removal_task.await.unwrap();
}

#[tokio::test]
async fn udp_removal_worker_escalates_auxiliary_token_mismatch() {
    use honk_ebpf_common::conn::{ConnState, UdpDecisionState};
    use honk_ebpf_common::{RedirectEntry, RedirectTuple};

    let client: SocketAddr = "10.0.0.1:53000".parse().unwrap();
    let dst: SocketAddr = "203.0.113.1:443".parse().unwrap();
    let key = connection::build_tuples_key(dst.ip(), dst.port(), client.ip(), client.port(), 17);
    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    mock.seed_staged_udp_flow(
        &key,
        ConnState {
            state: UdpDecisionState::Pending as u8,
            decision_token: 41,
            ..ConnState::default()
        },
    );
    mock.redirect_track_store(
        &RedirectTuple::from_tuples(&key),
        &RedirectEntry {
            decision_token: 42,
            ..RedirectEntry::default()
        },
    )
    .unwrap();
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(mock)));
    let pool = Arc::new(UdpEndpointPool::new());
    let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel();
    let removal_task = spawn_udp_removal_worker(
        Arc::clone(&pool),
        backend,
        Arc::new(ConnectionTracker::new()),
        fatal_tx,
    );
    let lease = match pool.reserve_owned_or_enqueue(
        client,
        dst,
        Bytes::from_static(b"held datagram"),
        41,
        None,
        Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap(),
        &StatsManager::new(),
    ) {
        udp_endpoint::EndpointReservation::Initializing(lease) => lease,
        _ => panic!("expected an initializing lease"),
    };

    drop(lease);
    let fatal = tokio::time::timeout(Duration::from_secs(1), fatal_rx.recv())
        .await
        .expect("auxiliary mismatch must reach supervision")
        .expect("removal fatal channel must remain open");
    assert!(fatal.to_string().contains("identity mismatch"));

    removal_task.abort();
    let _ = removal_task.await;
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn fresh_test_netns() -> std::os::fd::OwnedFd {
    std::thread::spawn(|| {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).expect("unshare test netns");
        std::fs::File::open("/proc/thread-self/ns/net")
            .expect("open test netns")
            .into()
    })
    .join()
    .expect("create test netns")
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn in_test_netns<T>(netns: &std::os::fd::OwnedFd, f: impl FnOnce() -> T) -> T {
    let current = std::fs::File::open("/proc/thread-self/ns/net").expect("open current netns");
    nix::sched::setns(netns, nix::sched::CloneFlags::CLONE_NEWNET).expect("enter test netns");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    nix::sched::setns(&current, nix::sched::CloneFlags::CLONE_NEWNET).expect("restore test netns");
    match result {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn configure_test_edge(
    netns: &std::os::fd::OwnedFd,
    interface: &str,
    address: [u8; 4],
    gateway: [u8; 4],
    ports: &[u16],
) -> Vec<std::net::UdpSocket> {
    in_test_netns(netns, || {
        let mut netlink = crate::netlink::NlSock::new().expect("edge netlink");
        let (loopback, _) = netlink.get_link("lo").expect("edge loopback");
        let (ifindex, _) = netlink.get_link(interface).expect("edge interface");
        netlink
            .set_link_up(loopback, true)
            .expect("edge loopback up");
        netlink
            .set_link_up(ifindex, true)
            .expect("edge interface up");
        netlink
            .addr_op(true, ifindex, libc::AF_INET as u8, &address, 24)
            .expect("edge address");
        netlink
            .add_route(
                libc::AF_INET as u8,
                254,
                1,
                0,
                4,
                None,
                Some(&gateway),
                Some(ifindex),
            )
            .expect("edge default route");
        ports
            .iter()
            .map(|port| {
                let socket = std::net::UdpSocket::bind(SocketAddr::from((address, *port)))
                    .expect("edge UDP bind");
                socket.set_nonblocking(true).expect("edge UDP nonblocking");
                socket
            })
            .collect()
    })
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
#[test]
#[ignore = "requires root, bpffs, nftables, and eBPF TC support"]
fn nfqueue_tc_netns_direct_proxy_contract() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        use std::os::fd::AsRawFd;

        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)?;
        let client_netns = fresh_test_netns();
        let server_netns = fresh_test_netns();
        let mut netlink = crate::netlink::NlSock::new()?;
        netlink.add_veth_pair("honk-lan0", "honk-c0")?;
        netlink.add_veth_pair("honk-wan0", "honk-s0")?;
        let (lan, _) = netlink.get_link("honk-lan0")?;
        let (client_peer, _) = netlink.get_link("honk-c0")?;
        let (wan, _) = netlink.get_link("honk-wan0")?;
        let (server_peer, _) = netlink.get_link("honk-s0")?;
        netlink.set_link_netns_fd(client_peer, &client_netns)?;
        netlink.set_link_netns_fd(server_peer, &server_netns)?;
        netlink.set_link_up(lan, true)?;
        netlink.set_link_up(wan, true)?;
        netlink.addr_op(true, lan, libc::AF_INET as u8, &[10, 70, 0, 1], 24)?;
        netlink.addr_op(true, wan, libc::AF_INET as u8, &[198, 51, 100, 1], 24)?;
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;

        let client = configure_test_edge(
            &client_netns,
            "honk-c0",
            [10, 70, 0, 2],
            [10, 70, 0, 1],
            &[0],
        )
        .pop()
        .expect("client socket");
        let mut servers = configure_test_edge(
            &server_netns,
            "honk-s0",
            [198, 51, 100, 2],
            [198, 51, 100, 1],
            &[41001, 41002],
        );
        let server_proxy = servers.pop().expect("proxy server socket");
        let server_direct = servers.pop().expect("direct server socket");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let pin_root = std::path::Path::new("/sys/fs/bpf")
                .join(format!("honk-nfq-e2e-{}", std::process::id()));
            let mut backend = crate::ebpf::real::RealEbpfBackend::load(
                crate::DEFAULT_BPF_OBJECT,
                &pin_root,
                12345,
                Some("honk-lan0"),
                "honk-wan0",
                false,
            )
            .await?;
            let tcp_listener = TcpListener::bind("0.0.0.0:0").await?;
            let udp_listener = UdpSocket::bind("0.0.0.0:0").await?;
            let udp_fds = vec![udp_listener.as_raw_fd(); 4];
            backend.publish_listener_sockets(
                tcp_listener.as_raw_fd(),
                tcp_listener.as_raw_fd(),
                &udp_fds,
                &udp_fds,
            )?;

            let proxy_socket =
                Arc::new(honk_outbound::util::udp_marked_bind("0.0.0.0:0".parse()?).await?);
            let mut registry = honk_outbound::proxy::ProxyRegistry::new();
            let handler = Arc::new(UdpTestHandler {
                mode: UdpTestMode::KernelSocket(proxy_socket),
            });
            registry.register(
                honk_outbound::proxy::ProtocolEntry::new(
                    honk_config::types::NodeProtocol::Socks5,
                    handler.clone(),
                )
                .with_packet(handler),
            );

            let node = udp_test_node();
            let group = Group {
                name: "udp-test-route".into(),
                nodes: vec![node.id],
                ..Default::default()
            };
            let mut config = udp_test_config("direct", vec![node], vec![group]);
            config.ensure_builtin_nodes();
            config.global.lan_interface = vec!["honk-lan0".into()];
            config.global.dial_mode = "domain++".into();
            config.global.wan_interface = vec!["honk-wan0".into()];
            config.global.nfqueue_enable = true;
            config
                .routing
                .rules
                .push(honk_config::routing::RoutingRule {
                    name: "domain-can-reroute".into(),
                    condition: honk_config::routing::RoutingCondition {
                        domain_suffix: vec!["never.invalid".into()],
                        ..Default::default()
                    },
                    outbound: honk_config::routing::RoutingOutbound::Simple(
                        "udp-test-route".into(),
                    ),
                    priority: 0,
                    must: false,
                    mark: 0,
                });
            config
                .routing
                .rules
                .push(honk_config::routing::RoutingRule {
                    name: "port-proxy".into(),
                    condition: honk_config::routing::RoutingCondition {
                        port: vec!["41002".into()],
                        ..Default::default()
                    },
                    outbound: honk_config::routing::RoutingOutbound::Simple(
                        "udp-test-route".into(),
                    ),
                    priority: 0,
                    must: false,
                    mark: 0,
                });
            let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
            let mut control = ControlPlane::new(
                config,
                Box::new(backend),
                router,
                Arc::new(registry),
                DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
                udp_test_forwarder(),
            )?;
            control.udp_pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
                1024,
                Arc::new(KernelUdpReplySocketFactory),
            ));
            control.set_mode_state(Arc::new(parking_lot::RwLock::new(
                crate::mode::ModeState::new("Rule", "Proxy"),
            )));
            control.start_datapath_flags_coordinator()?;
            {
                let plan = control.active_routing_plan.read().clone();
                let mut ebpf = control.ebpf.write().await;
                ebpf.publish_routing_plan(&plan, &[])?;
            }
            let sequence_ready = control.rotate_udp_decision_generation().await?;
            let mut nfqueue = control
                .start_nfqueue_runtime(true, sequence_ready)
                .await?
                .expect("enabled NFQUEUE runtime");
            nfqueue.check_startup_health().await?;
            control
                .initialize_datapath_flags(true, nfqueue.sequence_ready)
                .await?;
            nfqueue.pending.open_admission();
            control.ebpf.write().await.set_datapath_ready(true)?;
            let (removal_fatal_tx, mut removal_fatal_rx) = mpsc::unbounded_channel();
            let mut removal_task = spawn_udp_removal_worker(
                Arc::clone(&control.udp_pool),
                Arc::clone(&control.ebpf),
                Arc::clone(&control.connection_tracker),
                removal_fatal_tx,
            );

            let client = UdpSocket::from_std(client)?;
            let server_direct = UdpSocket::from_std(server_direct)?;
            let server_proxy = UdpSocket::from_std(server_proxy)?;
            let exercise = async {
                let direct_dst = SocketAddr::from(([198, 51, 100, 2], 41001));
                client.send_to(b"direct-first", direct_dst).await?;
                let mut buffer = [0u8; 128];
                let (size, source) = tokio::time::timeout(
                    Duration::from_secs(3),
                    server_direct.recv_from(&mut buffer),
                )
                .await??;
                anyhow::ensure!(&buffer[..size] == b"direct-first");
                anyhow::ensure!(source.ip() == "10.70.0.2".parse::<std::net::IpAddr>()?);
                anyhow::ensure!(
                    tokio::time::timeout(
                        Duration::from_millis(250),
                        server_direct.recv_from(&mut buffer),
                    )
                    .await
                    .is_err(),
                    "direct original arrived more than once"
                );
                let direct_stats = control.stats.udp_snapshot().nfqueue;
                anyhow::ensure!(direct_stats.direct_accepted == 1);
                anyhow::ensure!(direct_stats.proxy_copied == 0);
                let tc_status = std::process::Command::new("tc")
                    .args([
                        "filter",
                        "add",
                        "dev",
                        "honk-wan0",
                        "egress",
                        "pref",
                        "1",
                        "matchall",
                        "action",
                        "drop",
                    ])
                    .status()?;
                anyhow::ensure!(tc_status.success(), "failed to install classic TC sentinel");
                client.send_to(b"later-hook", direct_dst).await?;
                anyhow::ensure!(
                    tokio::time::timeout(
                        Duration::from_millis(25),
                        server_direct.recv_from(&mut buffer),
                    )
                    .await
                    .is_err(),
                    "honk terminated the TC chain before a later classifier"
                );
                let tc_status = std::process::Command::new("tc")
                    .args(["filter", "del", "dev", "honk-wan0", "egress", "pref", "1"])
                    .status()?;
                anyhow::ensure!(tc_status.success(), "failed to remove classic TC sentinel");

                let proxy_dst = SocketAddr::from(([198, 51, 100, 2], 41002));
                let proxy_payload = b"\x80proxy-first";
                client.send_to(proxy_payload, proxy_dst).await?;
                let (size, proxy_source) = tokio::time::timeout(
                    Duration::from_secs(3),
                    server_proxy.recv_from(&mut buffer),
                )
                .await??;
                anyhow::ensure!(&buffer[..size] == proxy_payload);
                anyhow::ensure!(proxy_source.ip() == "198.51.100.1".parse::<std::net::IpAddr>()?);
                anyhow::ensure!(
                    tokio::time::timeout(
                        Duration::from_millis(250),
                        server_proxy.recv_from(&mut buffer),
                    )
                    .await
                    .is_err(),
                    "proxy payload arrived more than once"
                );
                server_proxy.send_to(b"proxy-reply", proxy_source).await?;
                let (size, reply_source) =
                    tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buffer))
                        .await??;
                anyhow::ensure!(&buffer[..size] == b"proxy-reply");
                anyhow::ensure!(reply_source == proxy_dst);
                anyhow::ensure!(
                    tokio::time::timeout(
                        Duration::from_millis(250),
                        client.recv_from(&mut buffer),
                    )
                    .await
                    .is_err(),
                    "proxy reply arrived more than once"
                );
                let proxy_stats = control.stats.udp_snapshot().nfqueue;
                anyhow::ensure!(proxy_stats.proxy_copied == 1);
                anyhow::ensure!(proxy_stats.proxy_dropped == 1);
                anyhow::ensure!(removal_fatal_rx.try_recv().is_err());
                Ok::<_, anyhow::Error>(())
            }
            .await;

            if let Some(flags) = control.datapath_flags.as_ref() {
                let _ = flags.fence_nfqueue().await;
            }
            let _ = control.ebpf.write().await.set_datapath_ready(false);
            nfqueue.begin_pending_drain().await;
            let stats_errors_before_shutdown = control
                .stats
                .udp_snapshot()
                .nfqueue
                .kernel_stats_read_errors;
            let service_shutdown = nfqueue.shutdown_service().await;
            let pending_shutdown = nfqueue.finish_pending_drain().await;
            control.pending_udp_verdicts = None;
            let drain = Arc::clone(&control.drain_tracker);
            let datapath_shutdown = control
                .shutdown_datapath(&drain, &mut removal_task, None)
                .await;
            if let Some(flags) = control.datapath_flags.as_ref() {
                let _ = flags.disable().await;
            }
            let backend_shutdown = control.finalize_shutdown().await;
            let _ = std::fs::remove_file(pin_root.join(crate::ebpf::UDP_DECISION_SEQUENCE_MAP));
            let _ = std::fs::remove_dir(&pin_root);

            exercise?;
            service_shutdown?;
            pending_shutdown?;
            anyhow::ensure!(
                control
                    .stats
                    .udp_snapshot()
                    .nfqueue
                    .kernel_stats_read_errors
                    == stats_errors_before_shutdown,
                "stats sampler read the queue after teardown"
            );
            datapath_shutdown?;
            backend_shutdown?;
            Ok(())
        })
    })
    .join()
    .map_err(|_| anyhow::anyhow!("NFQUEUE network test thread panicked"))?
}

#[cfg(feature = "ebpf")]
struct NfqueueRuntimeFixture {
    runtime: NfqueueRuntime,
    listener_fatal_tx: tokio::sync::oneshot::Sender<honk_nfqueue::FatalError>,
    pending: Arc<nfqueue::PendingUdpVerdicts>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
}

#[cfg(feature = "ebpf")]
fn stop_waiting_task(stop: &tokio::sync::watch::Sender<bool>) -> tokio::task::JoinHandle<()> {
    let mut rx = stop.subscribe();
    tokio::spawn(async move {
        let _ = rx.changed().await;
    })
}

#[cfg(feature = "ebpf")]
fn nfqueue_runtime_fixture(
    watchdog: tokio::task::JoinHandle<()>,
    ingest_worker: tokio::task::JoinHandle<()>,
    stats_sampler: tokio::task::JoinHandle<()>,
    stop: tokio::sync::watch::Sender<bool>,
) -> NfqueueRuntimeFixture {
    let stats = Arc::new(StatsManager::new());
    let ebpf: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(
        crate::ebpf::mock::MockEbpfBackend::new(),
    )));
    let (pending, pending_fatal) = nfqueue::PendingUdpVerdicts::new(
        Arc::clone(&ebpf),
        Arc::new(UdpEndpointPool::new()),
        Arc::clone(&stats),
    );
    let pending = Arc::new(pending);
    let (listener_fatal_tx, listener_fatal) =
        tokio::sync::oneshot::channel::<honk_nfqueue::FatalError>();
    let start = tokio::time::Instant::now() + Duration::from_secs(3600);
    let token_backstop = tokio::time::interval_at(start, Duration::from_secs(3600));
    let runtime = NfqueueRuntime {
        service: None,
        listener_fatal,
        pending_fatal,
        stats,
        pending: Arc::clone(&pending),
        stop,
        watchdog: Some(watchdog),
        ingest_worker: Some(ingest_worker),
        stats_sampler: Some(stats_sampler),
        token_backstop,
        token_retry: NfqueueTokenRetryBackoff::default(),
        sequence_ready: true,
    };
    NfqueueRuntimeFixture {
        runtime,
        listener_fatal_tx,
        pending,
        ebpf,
    }
}

#[cfg(feature = "ebpf")]
#[tokio::test]
async fn nfqueue_watchdog_exit_completes_shutdown_without_double_join() {
    let (stop, _) = tokio::sync::watch::channel(false);
    let mut fixture = nfqueue_runtime_fixture(
        tokio::spawn(async {}),
        stop_waiting_task(&stop),
        stop_waiting_task(&stop),
        stop,
    );
    tokio::task::yield_now().await;
    let NfqueueRuntimeEvent::Fatal(error) = fixture.runtime.next_event(&fixture.ebpf).await else {
        panic!("watchdog exit must be fatal");
    };
    assert!(matches!(
        error.downcast_ref::<NfqueueRuntimeFatal>(),
        Some(NfqueueRuntimeFatal::Watchdog(_))
    ));
    assert!(fixture.runtime.watchdog.is_none());
    fixture
        .runtime
        .finish_pending_drain()
        .await
        .expect("shutdown after watchdog exit");
    assert!(fixture.pending.is_empty());
    assert!(!fixture.listener_fatal_tx.is_closed());
}

#[cfg(feature = "ebpf")]
#[tokio::test]
async fn nfqueue_ingest_actor_exit_completes_shutdown_without_double_join() {
    let (stop, _) = tokio::sync::watch::channel(false);
    let mut fixture = nfqueue_runtime_fixture(
        stop_waiting_task(&stop),
        tokio::spawn(async {}),
        stop_waiting_task(&stop),
        stop,
    );
    tokio::task::yield_now().await;
    let NfqueueRuntimeEvent::Fatal(error) = fixture.runtime.next_event(&fixture.ebpf).await else {
        panic!("ingest actor exit must be fatal");
    };
    assert!(matches!(
        error.downcast_ref::<NfqueueRuntimeFatal>(),
        Some(NfqueueRuntimeFatal::IngestActor(_))
    ));
    assert!(fixture.runtime.ingest_worker.is_none());
    fixture
        .runtime
        .finish_pending_drain()
        .await
        .expect("shutdown after ingest actor exit");
    assert!(fixture.pending.is_empty());
    assert!(!fixture.listener_fatal_tx.is_closed());
}

#[cfg(feature = "ebpf")]
#[tokio::test]
async fn nfqueue_stats_sampler_exit_completes_shutdown_without_double_join() {
    let (stop, _) = tokio::sync::watch::channel(false);
    let mut fixture = nfqueue_runtime_fixture(
        stop_waiting_task(&stop),
        stop_waiting_task(&stop),
        tokio::spawn(async {}),
        stop,
    );
    tokio::task::yield_now().await;
    let NfqueueRuntimeEvent::Fatal(error) = fixture.runtime.next_event(&fixture.ebpf).await else {
        panic!("stats sampler exit must be fatal");
    };
    assert!(matches!(
        error.downcast_ref::<NfqueueRuntimeFatal>(),
        Some(NfqueueRuntimeFatal::StatsSampler(_))
    ));
    assert!(fixture.runtime.stats_sampler.is_none());
    fixture
        .runtime
        .finish_pending_drain()
        .await
        .expect("shutdown after stats sampler exit");
    assert!(fixture.pending.is_empty());
    assert!(!fixture.listener_fatal_tx.is_closed());
}

/// A failed authoritative URLTest pick is retried once with the re-planned
/// replacement: node a refuses every dial, so the client flow must succeed
/// through b (invisible to the client) and a must end failure-demoted.
#[tokio::test]
async fn tcp_authoritative_dial_failure_retries_with_replacement() -> anyhow::Result<()> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Echo listener: the FIRST accepted socket is the client flow handed to
    // serve_connection (its local_addr is the flow's original destination);
    // every later socket is the proxy's relayed connection and gets echoed.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let target = listener.local_addr()?;
    let (flow_tx, flow_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut flow_tx = Some(flow_tx);
        while let Ok((mut stream, peer)) = listener.accept().await {
            if let Some(tx) = flow_tx.take() {
                let _ = tx.send((stream, peer));
                continue;
            }
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });

    // Minimal relaying SOCKS5 server: no auth, CONNECT to the requested
    // target, then pipe both ways.
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let socks_addr = socks_listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = socks_listener.accept().await {
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                if stream.read_exact(&mut head).await.is_err() || head[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; head[1] as usize];
                if stream.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if stream.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }
                let mut req = [0u8; 4];
                if stream.read_exact(&mut req).await.is_err() || req[1] != 0x01 {
                    return;
                }
                let target = match req[3] {
                    0x01 => {
                        let mut rest = [0u8; 6];
                        if stream.read_exact(&mut rest).await.is_err() {
                            return;
                        }
                        SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3])),
                            u16::from_be_bytes([rest[4], rest[5]]),
                        )
                    }
                    // The test dials only IPv4 literals.
                    _ => return,
                };
                let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await else {
                    return;
                };
                let _ = stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
            });
        }
    });

    let socks_node = |name: &str, port: u16| {
        let mut node = Node {
            name: name.into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(
                honk_config::types::NodeProtocol::Socks5,
            ),
            address: "127.0.0.1".into(),
            port,
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    };
    let node_a = socks_node("a", 1); // 127.0.0.1:1 — connection refused
    let node_b = socks_node("b", socks_addr.port());
    let group = Group {
        name: "proxy".into(),
        policy: honk_config::group::GroupPolicy::URLTest,
        nodes: vec![node_a.id, node_b.id],
        ..Default::default()
    };
    let config = udp_test_config("proxy", vec![node_a.clone(), node_b.clone()], vec![group]);
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let handle = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap()
    .spawn_handle();

    // Warm URLTest measurements: a (1ms) wins over b (50ms).
    handle.alive_set.record_probe_latency(
        node_a.id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(1),
    );
    handle.alive_set.record_probe_latency(
        node_b.id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(50),
    );
    {
        let gm = handle.group_manager.read().clone();
        let plan = gm.selection_plan_for_domain("proxy", ProbeDomain::Tcp, IpVersion::V4);
        assert_eq!(plan.nodes.first().map(|n| n.name.as_str()), Some("a"));
    }

    let mut client = tokio::net::TcpStream::connect(target).await?;
    let (flow_stream, client_addr) = flow_rx.await.expect("listener hands the flow over");
    // serve_connection adopts only flows with kernel conn-state; seed the
    // mock backend for this tuple.
    let tuples = build_tuples_key(
        target.ip(),
        target.port(),
        client_addr.ip(),
        client_addr.port(),
        6,
    );
    handle.ebpf.write().await.tcp_conn_state_store(
        &tuples,
        &honk_ebpf_common::conn::ConnState {
            state: honk_ebpf_common::conn::TcpState::TcpStateActive as u8,
            last_seen_ns: 0,
            ..Default::default()
        },
    )?;
    let serve = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.serve_connection(flow_stream, client_addr).await })
    };

    let payload = b"retry-with-replacement";
    client.write_all(payload).await?;
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed)).await??;
    assert_eq!(
        echoed, payload,
        "the flow must succeed through the replacement"
    );
    serve.abort();

    assert!(
        handle
            .alive_set
            .is_failure_demoted(node_a.id, ProbeDomain::Tcp, IpVersion::V4),
        "the refused node must carry a failure strike"
    );
    assert!(
        !handle
            .alive_set
            .is_failure_demoted(node_b.id, ProbeDomain::Tcp, IpVersion::V4),
        "the replacement node must stay clean"
    );
    Ok(())
}
