use super::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use super::*;
use crate::control::udp_endpoint::UdpEndpoint;
use crate::dns::query::{IngressProfile, is_exact_dns_query, validate_exact_dns_query};

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
        .initialize(0, enabled, false)
        .await
        .unwrap();
    let published = writes
        .lock()
        .ok()
        .and_then(|values| values.last().copied())
        .expect("initial flags");
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

#[test]
fn test_build_dns_probe_query() {
    let q = build_dns_probe_query();
    assert_eq!(&q[..2], &[0x12, 0x34]); // fixed id, validated on the response
    assert_eq!(q[2], 0x01); // RD (recursion desired)
    assert_eq!(q[5], 1); // QDCOUNT = 1
    assert_eq!(&q[q.len() - 4..], &[0, 1, 0, 1]); // QTYPE A / QCLASS IN
}

#[cfg(target_os = "linux")]
#[test]
fn udp_listener_enables_reuse_port_before_bind() {
    use std::os::fd::AsRawFd;

    let first = sockets::new_udp_listener_socket(socket2::Domain::IPV4, true).unwrap();
    let mut enabled = 0i32;
    let mut enabled_len = std::mem::size_of_val(&enabled) as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            first.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            (&mut enabled as *mut i32).cast(),
            &mut enabled_len,
        )
    };
    assert_eq!(status, 0);
    assert_eq!(enabled, 1);

    first
        .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    let addr = first.local_addr().unwrap();
    let second = sockets::new_udp_listener_socket(socket2::Domain::IPV4, true).unwrap();
    second.bind(&addr).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn udp_receive_batch_preserves_order_metadata_and_cancellation() {
    let socket = sockets::bind_tproxy_udp_listeners(SocketAddr::from(([127, 0, 0, 1], 0)), 1)
        .unwrap()
        .pop()
        .unwrap();
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Ipv4OrigDstAddr, &true)
        .unwrap();
    let local_addr = socket.local_addr().unwrap();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    for sequence in 0..9u8 {
        sender.send_to(&[sequence], local_addr).await.unwrap();
    }
    sender.send_to(&[], local_addr).await.unwrap();

    let mut batch = sockets::UdpRecvBatch::new().unwrap();
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 8);
    for index in 0..batch.len() {
        let (data, source, meta) = batch.packet(index).unwrap();
        assert_eq!(data, &[index as u8]);
        assert_eq!(source, sender_addr);
        assert_eq!(meta.original_dst_cmsg, Some(local_addr));
        assert_eq!(meta.packet_dst_ip, Some(local_addr.ip()));
        assert!(meta.packet_ifindex.is_some());
        assert_eq!(meta.local_addr, local_addr);
    }

    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch.packet(0).unwrap().0, &[8]);
    assert!(batch.packet(1).unwrap().0.is_empty());

    for sequence in 10..13u8 {
        sender.send_to(&[sequence], local_addr).await.unwrap();
    }
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 3);

    for sequence in 13..16u8 {
        sender.send_to(&[sequence], local_addr).await.unwrap();
    }
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 3);

    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch),
        )
        .await
        .is_err()
    );
    for sequence in 16..25u8 {
        sender.send_to(&[sequence], local_addr).await.unwrap();
    }
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.packet(0).unwrap().0, &[16]);
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 8);
    for index in 0..batch.len() {
        assert_eq!(batch.packet(index).unwrap().0, &[index as u8 + 17]);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn udp_receive_batch_rejects_truncated_slot_without_losing_next_packet() {
    let socket = sockets::bind_tproxy_udp_listeners(SocketAddr::from(([127, 0, 0, 1], 0)), 1)
        .unwrap()
        .pop()
        .unwrap();
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Ipv4OrigDstAddr, &true)
        .unwrap();
    let local_addr = socket.local_addr().unwrap();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(&[1, 2], local_addr).await.unwrap();
    sender.send_to(&[3], local_addr).await.unwrap();

    let mut batch = sockets::UdpRecvBatch::new_for_test(1).unwrap();
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();

    assert_eq!(batch.len(), 2);
    assert_eq!(
        batch.packet(0).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(batch.packet(1).unwrap().0, &[3]);
}
#[tokio::test]
async fn test_resolve_udp_check_target() {
    let fallback: SocketAddr = "8.8.8.8:53".parse().unwrap();
    assert_eq!(resolve_udp_check_target(&[], None).await, fallback);
    assert_eq!(
        resolve_udp_check_target(&["   ".into()], None).await,
        fallback
    );
    // Bare IP literals get the default DNS port.
    assert_eq!(
        resolve_udp_check_target(&["1.1.1.1".into()], None).await,
        "1.1.1.1:53".parse().unwrap()
    );
    assert_eq!(
        resolve_udp_check_target(&["2001:4860:4860::8888".into()], None).await,
        "[2001:4860:4860::8888]:53".parse().unwrap()
    );
    // Full socket addresses (v4 or bracketed v6) are kept as-is.
    assert_eq!(
        resolve_udp_check_target(&["1.1.1.1:5353".into()], None).await,
        "1.1.1.1:5353".parse().unwrap()
    );
    assert_eq!(
        resolve_udp_check_target(&["[2606:4700:4700::1111]:53".into()], None).await,
        "[2606:4700:4700::1111]:53".parse().unwrap()
    );
    // Literals win over domain entries anywhere in the list (poison-proof).
    assert_eq!(
        resolve_udp_check_target(&["dns.google".into(), "8.8.8.8".into()], None).await,
        "8.8.8.8:53".parse().unwrap()
    );
    // host:port resolves via the system resolver ("localhost" needs no
    // external network).
    let addr = resolve_udp_check_target(&["localhost:5353".into()], None).await;
    assert_eq!(addr.port(), 5353);
    assert!(addr.ip().is_loopback());

    // A domain entry is resolved through the installed hook when present.
    let hook: crate::outbound::ResolveHook = std::sync::Arc::new(|host, port| {
        Box::pin(async move {
            assert_eq!(host, "dns.example");
            vec![std::net::SocketAddr::new(
                std::net::IpAddr::from([10, 9, 8, 7]),
                port,
            )]
        })
    });
    assert_eq!(
        resolve_udp_check_target(&["dns.example".into()], Some(hook)).await,
        "10.9.8.7:53".parse().unwrap()
    );
}

#[tokio::test]
async fn quic_failure_trains_score_without_failing_dns_udp_health() {
    use honk_config::node::{Group, GroupPolicy};
    use honk_outbound::group::{GroupManager, ScoreTarget, SelectionNetwork};

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
    let config = Config {
        nodes: vec![node.clone(), other.clone()],
        groups: vec![group.clone()],
        ..Config::default()
    };
    let manager: SharedGroupManager = Arc::new(parking_lot::RwLock::new(Arc::new(
        GroupManager::new(&[group], &[node.clone(), other.clone()]),
    )));
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handler = Arc::new(UdpTestHandler {
        mode: UdpTestMode::DnsResponse {
            dials: Arc::clone(&dials),
        },
    });
    let mut registry = ProxyRegistry::new();
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(node.protocol, handler.clone())
            .with_packet(handler),
    );
    let runtime = Arc::new(parking_lot::RwLock::new(Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[node.clone(), other.clone()])
            .unwrap(),
    )));
    let resolver: crate::outbound::ResolveHook = Arc::new(|_host, port| {
        Box::pin(async move { vec![SocketAddr::from(([127, 0, 0, 1], port))] })
    });
    let quic_target = resolve_quic_score_target(
        "https://quic.example.test:9443/generate_204",
        Some(resolver),
    )
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
        Arc::new(RwLock::new(Arc::new(config))),
        Arc::new(registry),
        runtime,
        Arc::new(StatsManager::new()),
        "127.0.0.1:53".parse().unwrap(),
        "127.0.0.1:53".parse::<SocketAddr>().unwrap().into(),
        Some(quic_target),
        manager.clone(),
    );

    let result =
        honk_outbound::alive::UdpProber::probe_udp(&prober, &node.name, Duration::from_millis(30))
            .await;
    assert!(result.is_ok(), "DNS health result: {result:?}");
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
}

#[test]
fn extract_url_host_path_parses_all_forms() {
    // Regression: path must not leak into the Host header / DNS name.
    assert_eq!(
        extract_url_host_path("http://www.google-analytics.com/generate_204"),
        Some(("www.google-analytics.com", "/generate_204"))
    );
    assert_eq!(
        extract_url_host_path("www.google-analytics.com/generate_204"),
        Some(("www.google-analytics.com", "/generate_204"))
    );
    assert_eq!(
        extract_url_host_path("https://cp.cloudflare.com/"),
        Some(("cp.cloudflare.com", "/"))
    );
    assert_eq!(
        extract_url_host_path("http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111"),
        Some(("cp.cloudflare.com", "/"))
    );
    assert_eq!(
        extract_url_host_path("http://example.com:8080/check?q=1"),
        Some(("example.com", "/check?q=1"))
    );
    assert_eq!(
        extract_url_host_path("http://[2606:4700:4700::1111]:443/"),
        Some(("2606:4700:4700::1111", "/"))
    );
    assert_eq!(extract_url_host_path(""), None);
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A minimal DNS query payload for "a.com" (A record).
fn dns_query_payload() -> Vec<u8> {
    let mut q = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q.extend_from_slice(&[
        0x01, b'a', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]);
    q
}

fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: the returned slice borrows `value` and has its exact layout size.
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

/// Test storage has the same `cmsghdr` alignment required by `recvmsg`.
#[repr(C)]
struct AlignedTestCmsgStorage {
    _alignment: [libc::cmsghdr; 0],
    bytes: [u8; 256],
}

impl AlignedTestCmsgStorage {
    fn new() -> Self {
        // SAFETY: all-zero bytes are a valid initial representation for this
        // test-only raw control-message storage.
        unsafe { std::mem::zeroed() }
    }
}

fn cmsg_len(data_len: usize) -> usize {
    // SAFETY: libc exposes CMSG_LEN as the platform ABI macro wrapper.
    unsafe { libc::CMSG_LEN(data_len as _) as usize }
}

fn cmsg_space(data_len: usize) -> usize {
    // SAFETY: libc exposes CMSG_SPACE as the platform ABI macro wrapper.
    unsafe { libc::CMSG_SPACE(data_len as _) as usize }
}

fn append_cmsg(
    storage: &mut AlignedTestCmsgStorage,
    used: &mut usize,
    cmsg_level: libc::c_int,
    cmsg_type: libc::c_int,
    data: &[u8],
) {
    let space = cmsg_space(data.len());
    assert!(*used + space <= storage.bytes.len());
    // SAFETY: all-zero is a valid initial representation for a raw test cmsg header.
    let mut header: libc::cmsghdr = unsafe { std::mem::zeroed::<libc::cmsghdr>() };
    header.cmsg_len = cmsg_len(data.len()) as _;
    header.cmsg_level = cmsg_level;
    header.cmsg_type = cmsg_type;
    // SAFETY: `AlignedTestCmsgStorage` is explicitly cmsghdr-aligned, the
    // checked range fits storage, and the header is initialized before use.
    unsafe {
        let ptr = storage
            .bytes
            .as_mut_ptr()
            .add(*used)
            .cast::<libc::cmsghdr>();
        assert_eq!(
            ptr as usize % std::mem::align_of::<libc::cmsghdr>(),
            0,
            "test cmsg header must be naturally aligned"
        );
        std::ptr::write(ptr, header);
    }
    let data_start = *used + cmsg_len(0);
    storage.bytes[data_start..data_start + data.len()].copy_from_slice(data);
    *used += space;
}

#[test]
fn udp_original_dst_cmsg_parser_walks_aligned_ipv4_multi_cmsg() {
    let mut original: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    original.sin_family = libc::AF_INET as _;
    original.sin_port = 4444u16.to_be();
    original.sin_addr = libc::in_addr {
        s_addr: u32::from(std::net::Ipv4Addr::new(203, 0, 113, 10)).to_be(),
    };
    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::new(198, 51, 100, 53)).to_be(),
        },
    };
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );

    let (original_dst, packet_dst_ip, packet_ifindex) =
        parse_cmsg_control(&storage.bytes[..used], 0).unwrap();
    assert_eq!(original_dst, Some(addr("203.0.113.10:4444")));
    assert_eq!(
        packet_dst_ip,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            198, 51, 100, 53
        )))
    );
    assert_eq!(packet_ifindex, Some(0));
}

#[test]
fn udp_original_dst_cmsg_parser_walks_aligned_ipv6_multi_cmsg() {
    let expected_original: std::net::Ipv6Addr = "2001:db8::4444".parse().unwrap();
    let expected_packet: std::net::Ipv6Addr = "2001:db8::53".parse().unwrap();
    let mut original: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    original.sin6_family = libc::AF_INET6 as _;
    original.sin6_port = 4444u16.to_be();
    original.sin6_addr = libc::in6_addr {
        s6_addr: expected_original.octets(),
    };
    let pktinfo = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr {
            s6_addr: expected_packet.octets(),
        },
        ipi6_ifindex: 7,
    };
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IPV6,
        libc::IPV6_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IPV6,
        libc::IPV6_PKTINFO,
        bytes_of(&pktinfo),
    );

    let (original_dst, packet_dst_ip, packet_ifindex) =
        parse_cmsg_control(&storage.bytes[..used], 0).unwrap();
    assert_eq!(original_dst, Some(addr("[2001:db8::4444]:4444")));
    assert_eq!(packet_dst_ip, Some(std::net::IpAddr::V6(expected_packet)));
    assert_eq!(packet_ifindex, Some(7));
}

#[test]
fn udp_original_dst_cmsg_parser_uses_only_returned_control_length() {
    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::new(198, 51, 100, 53)).to_be(),
        },
    };
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );
    let returned_control_len = used;
    // Bytes beyond msg_controllen are not kernel-returned control data; make
    // them malformed to prove they cannot influence the parser.
    unsafe {
        // SAFETY: all-zero is a valid initial representation for a raw test cmsg header.
        let mut malformed_header: libc::cmsghdr = std::mem::zeroed::<libc::cmsghdr>();
        malformed_header.cmsg_len = 0;
        malformed_header.cmsg_level = libc::IPPROTO_IP;
        malformed_header.cmsg_type = libc::IP_PKTINFO;
        std::ptr::write(
            storage.bytes.as_mut_ptr().add(used).cast::<libc::cmsghdr>(),
            malformed_header,
        );
    }
    let malformed_len = used + cmsg_len(0);

    assert!(parse_cmsg_control(&storage.bytes[..returned_control_len], 0).is_ok());
    let error = parse_cmsg_control(&storage.bytes[..malformed_len], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_original_dst_cmsg_parser_fails_closed_on_truncation_or_ctrunc() {
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        &[0; 1],
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let error = parse_cmsg_control(&storage.bytes[..used], libc::MSG_CTRUNC).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_original_dst_cmsg_storage_has_space_for_ipv6_origdst_and_pktinfo() {
    assert!(cmsg_control_capacity_is_sufficient());
}

#[test]
fn udp_original_dst_unspecified_origdst_is_authoritative_and_fails_closed() {
    let meta = UdpRecvMeta {
        original_dst_cmsg: Some(addr("0.0.0.0:53")),
        packet_dst_ip: Some("198.51.100.53".parse().unwrap()),
        packet_ifindex: None,
        local_addr: addr("192.0.2.20:5353"),
    };

    assert!(udp_original_dst(&meta, &dns_query_payload()).is_none());
}

fn ipv4_origdst(ip: [u8; 4], port: u16) -> libc::sockaddr_in {
    let mut original: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    original.sin_family = libc::AF_INET as _;
    original.sin_port = port.to_be();
    original.sin_addr = libc::in_addr {
        s_addr: u32::from(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_be(),
    };
    original
}

fn ipv4_pktinfo(ip: [u8; 4]) -> libc::in_pktinfo {
    libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_be(),
        },
    }
}

#[test]
fn udp_original_dst_cmsg_parser_requires_exact_recognized_payload_length() {
    let original = ipv4_origdst([203, 0, 113, 10], 4444);
    let mut oversized = bytes_of(&original).to_vec();
    oversized.push(0xab);

    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        &oversized,
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let pktinfo = ipv4_pktinfo([198, 51, 100, 53]);
    let mut oversized_pkt = bytes_of(&pktinfo).to_vec();
    oversized_pkt.extend_from_slice(&[0xde, 0xad]);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        &oversized_pkt,
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_original_dst_cmsg_parser_rejects_duplicate_recognized_records() {
    // Equal ORIGDST values are still ambiguous provenance.
    let original = ipv4_origdst([203, 0, 113, 10], 4444);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    // Conflicting ORIGDST values fail closed.
    let other = ipv4_origdst([198, 51, 100, 10], 53);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&other),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    // Unspecified followed by a valid ORIGDST is still a duplicate.
    let unspecified = ipv4_origdst([0, 0, 0, 0], 53);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&unspecified),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    // Duplicate PKTINFO (equal values) is also rejected.
    let pktinfo = ipv4_pktinfo([198, 51, 100, 53]);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_original_dst_cmsg_parser_skips_unknown_cmsg_with_padding() {
    let original = ipv4_origdst([203, 0, 113, 10], 4444);
    let pktinfo = ipv4_pktinfo([198, 51, 100, 53]);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    // Unknown record with a non-aligned-looking payload still consumes CMSG_SPACE.
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        0x7fff, // not a recognized ORIGDST/PKTINFO type
        &[0x11, 0x22, 0x33],
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        0x7ffe,
        &[0xaa, 0xbb],
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );

    let (original_dst, packet_dst_ip, packet_ifindex) =
        parse_cmsg_control(&storage.bytes[..used], 0).unwrap();
    assert_eq!(original_dst, Some(addr("203.0.113.10:4444")));
    assert_eq!(
        packet_dst_ip,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            198, 51, 100, 53
        )))
    );
    assert_eq!(packet_ifindex, Some(0));
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
async fn udp_dns_controller_declines_root_and_binary_questions() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let controller = production_dns_controller(calls.clone(), dns_response_payload());
    let client = addr("127.0.0.1:34567");
    let dst = addr("203.0.113.53:53");

    let root = dns_query_with_qname(&[0x00]);
    assert!(
        !controller
            .handle_udp_dns(&root, client, dst, None)
            .await
            .unwrap(),
        "root qname must fall back to ordinary UDP"
    );

    let binary = dns_query_with_qname(&[0x01, 0xff, 0x00]);
    assert!(
        !controller
            .handle_udp_dns(&binary, client, dst, None)
            .await
            .unwrap(),
        "binary qname must fall back to ordinary UDP"
    );

    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn udp_slow_path_only_forces_strict_dns_to_port_53() {
    let client = addr("10.0.0.1:12345");
    let data = dns_query_payload();
    let validated = validate_exact_dns_query(&data).unwrap();

    let dns_pool = Arc::new(UdpEndpointPool::new());
    let dns_stats = Arc::new(StatsManager::new());
    let dns_limit = Arc::new(tokio::sync::Semaphore::new(1));
    let dns_work = begin_udp_slow_path(
        &dns_pool,
        &dns_stats,
        &dns_limit,
        client,
        addr("203.0.113.53:53"),
        &data,
        Some(validated),
    );
    assert!(matches!(
        dns_work,
        UdpSlowPathWork::DnsThenMaybeInitialize { .. }
    ));

    let ordinary_pool = Arc::new(UdpEndpointPool::new());
    let ordinary_stats = Arc::new(StatsManager::new());
    let ordinary_limit = Arc::new(tokio::sync::Semaphore::new(1));
    let ordinary_work = begin_udp_slow_path(
        &ordinary_pool,
        &ordinary_stats,
        &ordinary_limit,
        client,
        addr("203.0.113.53:5353"),
        &data,
        Some(validated),
    );
    assert!(matches!(ordinary_work, UdpSlowPathWork::Initialize(_)));
}

#[test]
fn udp_original_dst_cmsg_takes_precedence_over_other_metadata() {
    let meta = UdpRecvMeta {
        original_dst_cmsg: Some(addr("203.0.113.10:4444")),
        packet_dst_ip: Some("198.51.100.10".parse().unwrap()),
        packet_ifindex: None,
        local_addr: addr("192.0.2.10:5353"),
    };

    let destination = udp_original_dst(&meta, b"not a DNS query").unwrap();
    assert_eq!(destination.address, addr("203.0.113.10:4444"));
    assert!(destination.validated_dns.is_none());
}

#[test]
fn udp_original_dst_uses_ipv4_pktinfo_for_exact_dns_query() {
    let expected_ip = std::net::Ipv4Addr::new(198, 51, 100, 53);
    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(expected_ip).to_be(),
        },
    };
    let packet_dst_ip =
        packet_dst_ip_from_cmsg(libc::IPPROTO_IP, libc::IP_PKTINFO, bytes_of(&pktinfo));
    assert_eq!(packet_dst_ip, Some(std::net::IpAddr::V4(expected_ip)));

    let meta = UdpRecvMeta {
        original_dst_cmsg: None,
        packet_dst_ip,
        packet_ifindex: None,
        local_addr: addr("0.0.0.0:15000"),
    };
    let destination = udp_original_dst(&meta, &dns_query_payload()).unwrap();
    assert_eq!(destination.address, addr("198.51.100.53:53"));
    assert!(destination.validated_dns.is_some());
}

#[test]
fn udp_original_dst_uses_ipv6_pktinfo_for_exact_dns_query() {
    let expected_ip: std::net::Ipv6Addr = "2001:db8::53".parse().unwrap();
    let pktinfo = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr {
            s6_addr: expected_ip.octets(),
        },
        ipi6_ifindex: 0,
    };
    let packet_dst_ip =
        packet_dst_ip_from_cmsg(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, bytes_of(&pktinfo));
    assert_eq!(packet_dst_ip, Some(std::net::IpAddr::V6(expected_ip)));

    let meta = UdpRecvMeta {
        original_dst_cmsg: None,
        packet_dst_ip,
        packet_ifindex: None,
        local_addr: addr("[::]:15000"),
    };
    let destination = udp_original_dst(&meta, &dns_query_payload()).unwrap();
    assert_eq!(destination.address, addr("[2001:db8::53]:53"));
    assert!(destination.validated_dns.is_some());
}

#[test]
fn udp_original_dst_uses_non_wildcard_local_fallback() {
    let local_addr = addr("192.0.2.20:5353");
    let meta = UdpRecvMeta {
        original_dst_cmsg: None,
        packet_dst_ip: None,
        packet_ifindex: None,
        local_addr,
    };

    let destination = udp_original_dst(&meta, b"opaque UDP").unwrap();
    assert_eq!(destination.address, local_addr);
    assert!(destination.validated_dns.is_none());
    let dns_destination = udp_original_dst(&meta, &dns_query_payload()).unwrap();
    assert_eq!(dns_destination.address, local_addr);
    assert!(dns_destination.validated_dns.is_some());
}

#[test]
fn udp_original_dst_fails_closed_for_wildcard_local_without_metadata() {
    for local_addr in [addr("0.0.0.0:15000"), addr("[::]:15000")] {
        let meta = UdpRecvMeta {
            original_dst_cmsg: None,
            packet_dst_ip: None,
            packet_ifindex: None,
            local_addr,
        };
        assert!(udp_original_dst(&meta, b"opaque UDP").is_none());
    }
}

#[test]
fn udp_original_dst_does_not_rewrite_non_exact_dns_payloads() {
    let packet_meta = UdpRecvMeta {
        original_dst_cmsg: None,
        packet_dst_ip: Some("198.51.100.53".parse().unwrap()),
        packet_ifindex: None,
        local_addr: addr("0.0.0.0:15000"),
    };
    let local_fallback = addr("192.0.2.20:5353");
    let fallback_meta = UdpRecvMeta {
        original_dst_cmsg: None,
        packet_dst_ip: None,
        packet_ifindex: None,
        local_addr: local_fallback,
    };
    let mut dns_response = dns_query_payload();
    dns_response[2] |= 0x80;

    for payload in [
        dns_response.as_slice(),
        b"short".as_slice(),
        &[0u8; 20][..],
        b"random non-53 UDP payload".as_slice(),
    ] {
        assert!(!is_exact_dns_query(payload));
        assert!(udp_original_dst(&packet_meta, payload).is_none());
        let destination = udp_original_dst(&fallback_meta, payload).unwrap();
        assert_eq!(destination.address, local_fallback);
        assert!(destination.validated_dns.is_none());
    }
}

#[tokio::test]
async fn udp_fast_path_miss_goes_slow() {
    let pool = UdpEndpointPool::new();
    let stats = StatsManager::new();
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:443");
    assert!(!udp_fast_path(&pool, &stats, b"hello", client, dst, None).await);
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
    assert!(
        !udp_fast_path(
            &pool,
            &stats,
            b"wrong-client",
            addr("10.0.0.2:12345"),
            dst,
            None,
        )
        .await
    );
    assert!(
        !udp_fast_path(
            &pool,
            &stats,
            b"wrong-destination",
            client,
            addr("203.0.113.2:443"),
            None,
        )
        .await
    );
    assert!(
        !udp_fast_path(
            &pool,
            &stats,
            b"wrong-client-port",
            addr("10.0.0.1:12346"),
            dst,
            None,
        )
        .await
    );
    assert!(
        !udp_fast_path(
            &pool,
            &stats,
            b"wrong-destination-port",
            client,
            addr("203.0.113.1:444"),
            None,
        )
        .await
    );
    assert!(udp_fast_path(&pool, &stats, b"hello", client, dst, None).await);
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
    assert!(!udp_fast_path(&pool, &stats, &query, client, dst, Some(validated)).await);
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
    assert!(
        udp_fast_path(
            &pool,
            &stats,
            &query,
            client,
            dst,
            validate_exact_dns_query(&query),
        )
        .await
    );
    assert_eq!(stats.udp_snapshot().endpoint_hits, 1);

    let (n, _) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], &query);
}

#[tokio::test]
async fn udp_fast_path_non_dns_port53_forwards() {
    // Garbage to port 53 is not a DNS query: the endpoint driver forwards it,
    // exactly like the slow path does after handle_udp_dns declines.
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
    assert!(udp_fast_path(&pool, &stats, &garbage, client, dst, None).await);
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
    assert!(
        udp_fast_path(
            &pool,
            &stats,
            b"hello",
            client,
            addr("169.254.0.11:8080"),
            None,
        )
        .await
    );
    assert!(udp_fast_path(&pool, &stats, b"hello", addr("169.254.0.1:1234"), dst, None).await);
    assert!(
        udp_fast_path(
            &pool,
            &stats,
            b"hello",
            client,
            addr("[fd00:686f:6e6b::1]:8080"),
            None,
        )
        .await
    );
    assert!(
        udp_fast_path(
            &pool,
            &stats,
            b"hello",
            addr("[fd00:686f:6e6b::2]:1234"),
            dst,
            None,
        )
        .await
    );
    // Broadcast / multicast destinations.
    assert!(
        udp_fast_path(
            &pool,
            &stats,
            b"hello",
            client,
            addr("255.255.255.255:67"),
            None,
        )
        .await
    );
    assert!(
        udp_fast_path(
            &pool,
            &stats,
            b"hello",
            client,
            addr("192.168.1.255:67"),
            None,
        )
        .await
    );
    assert!(
        udp_fast_path(
            &pool,
            &stats,
            b"hello",
            client,
            addr("239.255.255.250:1900"),
            None,
        )
        .await
    );
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
) -> anyhow::Result<DnsResolver> {
    struct SourceRoutedUpstream {
        selected_ip: std::net::Ipv4Addr,
        fallback_ip: std::net::Ipv4Addr,
    }

    #[async_trait::async_trait]
    impl crate::dns::forwarder::DnsUpstreamPool for SourceRoutedUpstream {
        async fn query(&self, upstream_name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
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
    let forwarder = Arc::new(
        crate::dns::forwarder::DnsForwarder::new(
            Arc::new(SourceRoutedUpstream {
                selected_ip,
                fallback_ip,
            }),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(1))),
            router,
        )
        .with_cache_enabled(false)
        .with_policy_from_config(&config)?,
    );
    DnsResolver::with_forwarder(&config, forwarder)
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
    handle.dns_resolver = Arc::new(source_routed_dns_resolver(
        "127.0.0.42/32",
        original_dst.ip().to_string().parse()?,
        "192.0.2.1".parse()?,
    )?);

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
    handle.dns_resolver = Arc::new(source_routed_dns_resolver(
        "192.0.2.0/24",
        original_dst.ip().to_string().parse()?,
        "203.0.113.20".parse()?,
    )?);

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
async fn tcp_local_resolution_uses_client_source() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let original_dst = SocketAddr::new("127.0.0.1".parse()?, listener.local_addr()?.port());
    let mut node = Node {
        name: "local-resolve".into(),
        protocol: honk_config::types::NodeProtocol::VMess,
        address: "127.0.0.1".into(),
        port: 9,
        ..Default::default()
    };
    node.id = node.derive_id();
    let mut config = udp_test_config("local-resolve", vec![node], vec![]);
    config.ensure_builtin_nodes();
    config.global.dial_mode = "domain+".into();
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
    let dial_target = Arc::new(std::sync::Mutex::new(None));
    let handler = Arc::new(UdpTestHandler {
        mode: UdpTestMode::TcpCaptureTarget(Arc::clone(&dial_target)),
    });
    let mut registry = ProxyRegistry::new();
    registry.register(honk_outbound::proxy::ProtocolEntry::new(
        honk_config::types::NodeProtocol::VMess,
        handler,
    ));
    let dns_resolver =
        source_routed_dns_resolver("127.0.0.42/32", "127.0.0.2".parse()?, "127.0.0.3".parse()?)?;
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
    let (captured_target, captured_domain) = dial_target
        .lock()
        .expect("dial target")
        .clone()
        .expect("captured dial");
    assert_eq!(captured_domain.as_deref(), Some("source.test"));
    assert_eq!(
        captured_target,
        SocketAddr::new("127.0.0.2".parse()?, original_dst.port())
    );

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

type CapturedTcpTarget = Arc<std::sync::Mutex<Option<(SocketAddr, Option<String>)>>>;

#[derive(Debug, Clone)]
enum UdpTestMode {
    DialError,
    SendError,
    /// Records real application-send attempts made by the production
    /// PacketTransport call path.
    CountSends(Arc<std::sync::atomic::AtomicUsize>),
    /// Counts dial and send attempts while making the first application send
    /// ambiguous. A later candidate must never be tried after that send.
    CountFirstSendError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    CountDialAndSend {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    CountDialError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
    },
    PreparedCommitError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        commits: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    Success,
    DnsResponse {
        dials: Arc<std::sync::atomic::AtomicUsize>,
    },
    #[cfg(feature = "ebpf")]
    KernelSocket(Arc<UdpSocket>),
    TcpHold {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
    TcpCaptureTarget(CapturedTcpTarget),
    UdpCaptureTarget(CapturedTcpTarget),
    Hold {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
    HoldAndCount {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        dials: Arc<std::sync::atomic::AtomicUsize>,
    },
    HoldAndCountDialAndSend {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
}

#[derive(Debug)]
struct UdpTestTransport {
    mode: UdpTestMode,
    relay: SocketAddr,
    replied: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketTransport for UdpTestTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    async fn send_packet(&self, _data: &[u8]) -> std::io::Result<()> {
        match &self.mode {
            UdpTestMode::SendError => Err(std::io::Error::other("first UDP send failed")),
            UdpTestMode::CountSends(sends) => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            UdpTestMode::CountFirstSendError { sends, .. } => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(std::io::Error::other("ambiguous first UDP send failure"))
            }
            UdpTestMode::CountDialAndSend { sends, .. }
            | UdpTestMode::HoldAndCountDialAndSend { sends, .. }
            | UdpTestMode::PreparedCommitError { sends, .. } => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            #[cfg(feature = "ebpf")]
            UdpTestMode::KernelSocket(socket) => {
                socket.send_to(_data, self.relay).await?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        #[cfg(feature = "ebpf")]
        if let UdpTestMode::KernelSocket(socket) = &self.mode {
            let (size, _) = socket.recv_from(buf).await?;
            return Ok((size, self.relay));
        }
        if matches!(self.mode, UdpTestMode::DnsResponse { .. })
            && !self
                .replied
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            let response = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
            buf[..response.len()].copy_from_slice(&response);
            return Ok((response.len(), self.relay));
        }
        if matches!(self.mode, UdpTestMode::DnsResponse { .. }) {
            return std::future::pending().await;
        }
        Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    }
}

#[derive(Debug)]
struct UdpTestReplySocketFactory;

impl crate::control::udp_endpoint::UdpReplySocketFactory for UdpTestReplySocketFactory {
    fn create(&self, _original_dst: SocketAddr) -> std::io::Result<UdpSocket> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }
}

#[cfg(feature = "ebpf")]
#[derive(Debug)]
struct KernelUdpReplySocketFactory;

#[cfg(feature = "ebpf")]
impl crate::control::udp_endpoint::UdpReplySocketFactory for KernelUdpReplySocketFactory {
    fn create(&self, original_dst: SocketAddr) -> std::io::Result<UdpSocket> {
        let domain = if original_dst.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        if original_dst.is_ipv4() {
            socket.set_ip_transparent_v4(true)?;
        } else {
            socket.set_ip_transparent_v6(true)?;
        }
        socket.set_mark(DAE_BYPASS_MARK)?;
        socket.bind(&original_dst.into())?;
        UdpSocket::from_std(socket.into())
    }
}

#[derive(Debug)]
struct FailingUdpTestReplySocketFactory;

impl crate::control::udp_endpoint::UdpReplySocketFactory for FailingUdpTestReplySocketFactory {
    fn create(&self, _original_dst: SocketAddr) -> std::io::Result<UdpSocket> {
        Err(std::io::Error::other("scripted anyfrom setup failure"))
    }
}

#[derive(Debug)]
struct UdpTestHandler {
    mode: UdpTestMode,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::TcpOutbound for UdpTestHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        match &self.mode {
            UdpTestMode::TcpHold { entered, release } => {
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::TcpCaptureTarget(captured) => {
                *captured.lock().expect("dial target") =
                    Some((target, target_domain.map(str::to_owned)));
            }
            _ => anyhow::bail!("TCP dial is not used by the UDP lifecycle tests"),
        }
        let stream = TcpStream::connect(target).await?;
        Ok(honk_outbound::proxy::ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketOutbound for UdpTestHandler {
    async fn dial_udp_transport(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn honk_outbound::proxy::PacketTransport>> {
        if let UdpTestMode::UdpCaptureTarget(captured) = &self.mode {
            *captured.lock().expect("UDP dial target") =
                Some((target, target_domain.map(str::to_owned)));
        }
        match &self.mode {
            UdpTestMode::Hold { entered, release } => {
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::HoldAndCount {
                entered,
                release,
                dials,
            } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::CountFirstSendError { dials, .. }
            | UdpTestMode::CountDialAndSend { dials, .. }
            | UdpTestMode::CountDialError { dials }
            | UdpTestMode::PreparedCommitError { dials, .. } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            UdpTestMode::HoldAndCountDialAndSend {
                entered,
                release,
                dials,
                ..
            } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::DnsResponse { dials } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        }
        match &self.mode {
            UdpTestMode::DialError | UdpTestMode::CountDialError { .. } => {
                Err(anyhow::anyhow!("UDP dial failed"))
            }
            _ => Ok(Arc::new(UdpTestTransport {
                mode: self.mode.clone(),
                relay: target,
                replied: std::sync::atomic::AtomicBool::new(false),
            })),
        }
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<honk_outbound::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::PreparedUdpTransport> {
        let transport = self
            .dial_udp_transport(
                runtime.node.as_ref(),
                target,
                target_domain,
                connect_timeout,
            )
            .await?;
        if let UdpTestMode::PreparedCommitError { commits, .. } = &self.mode {
            let commits = Arc::clone(commits);
            return Ok(honk_outbound::proxy::PreparedUdpTransport::new(
                transport,
                move || async move {
                    commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Err(anyhow::anyhow!(
                        "scripted prepared transport commit failure"
                    ))
                },
            ));
        }
        Ok(honk_outbound::proxy::PreparedUdpTransport::ready(transport))
    }
}

fn udp_test_forwarder() -> Arc<crate::dns::forwarder::DnsForwarder> {
    let router = Arc::new(
        crate::dns::routing::DnsRouter::new(&honk_config::dns::DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    Arc::new(
        crate::dns::forwarder::DnsForwarder::new(
            Arc::new(crate::dns::upstream_pool::UpstreamPool::new(&[], router.clone()).unwrap()),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(1))),
            router,
        )
        .with_cache_enabled(false),
    )
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
async fn tcp_tracker_keeps_the_dial_selection_snapshot() -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut hk = Node {
        name: "hk-140".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 140,
        ..Default::default()
    };
    hk.id = hk.derive_id();
    let mut us = Node {
        name: "us-163".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
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
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 140,
        ..Default::default()
    };
    tcp_node.id = tcp_node.derive_id();
    let mut udp_node = Node {
        name: "udp-node".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
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

fn udp_test_config(default_outbound: &str, nodes: Vec<Node>, groups: Vec<Group>) -> Config {
    let mut config = Config {
        nodes,
        groups,
        ..Default::default()
    };
    config.routing.default_outbound = default_outbound.into();
    config
}

fn udp_test_node() -> Node {
    let mut node = Node {
        name: "udp-test".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 9,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn udp_test_handle(config: Config, mode: UdpTestMode, capacity: usize) -> ControlPlaneHandle {
    udp_test_handle_with_reply_factory(config, mode, capacity, Arc::new(UdpTestReplySocketFactory))
}

/// Uses ControlPlane's production endpoint pool unchanged. The blocked-dial
/// death test needs this so the callback installed during ControlPlane::new
/// owns the same pool that contains the real Initializing reservation.
fn udp_test_handle_with_default_pool(config: Config, mode: UdpTestMode) -> ControlPlaneHandle {
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    let handler = Arc::new(UdpTestHandler { mode });
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Socks5,
            handler.clone(),
        )
        .with_packet(handler),
    );
    ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap()
    .spawn_handle()
}

fn udp_test_handle_with_reply_factory(
    config: Config,
    mode: UdpTestMode,
    capacity: usize,
    reply_socket_factory: Arc<dyn crate::control::udp_endpoint::UdpReplySocketFactory>,
) -> ControlPlaneHandle {
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    let handler = Arc::new(UdpTestHandler { mode });
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Socks5,
            handler.clone(),
        )
        .with_packet(handler),
    );
    let mut control_plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap();
    control_plane.udp_pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        capacity,
        reply_socket_factory,
    ));
    control_plane.spawn_handle()
}

async fn serve_test_udp(handle: &ControlPlaneHandle) -> anyhow::Result<()> {
    serve_test_udp_to(
        handle,
        addr("10.0.0.2:53000"),
        addr("203.0.113.2:443"),
        b"UDP test packet",
    )
    .await
}

async fn serve_test_udp_to(
    handle: &ControlPlaneHandle,
    client: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> anyhow::Result<()> {
    let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .expect("test slow permit");
    let reservation =
        handle
            .udp_pool
            .reserve_or_enqueue(client, dst, payload, slow_permit, &handle.stats);
    match reservation {
        crate::control::udp_endpoint::EndpointReservation::Initializing(lease) => {
            handle.serve_udp_connection(lease).await
        }
        crate::control::udp_endpoint::EndpointReservation::Enqueued
        | crate::control::udp_endpoint::EndpointReservation::CapacityRejected
        | crate::control::udp_endpoint::EndpointReservation::QueueFull
        | crate::control::udp_endpoint::EndpointReservation::QueueClosed
        | crate::control::udp_endpoint::EndpointReservation::IdentityMismatch => Ok(()),
    }
}

fn assert_udp_outbound(
    stats: &Arc<StatsManager>,
    outbound: &str,
    total_connections: u32,
    active_connections: u32,
    errors: u32,
) {
    let snapshot = stats.snapshot();
    let actual = snapshot
        .get(outbound)
        .unwrap_or_else(|| panic!("missing outbound stats for {outbound}"));
    assert_eq!(actual.total_conns, total_connections);
    assert_eq!(actual.active_conns, active_connections);
    assert_eq!(actual.errors, errors);
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

    assert_udp_outbound(&stats, "udp-test", 1, 0, 1);
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

    assert_udp_outbound(&stats, "udp-test", 1, 0, 1);
}

#[tokio::test]
async fn udp_first_send_failure_does_not_replay_to_another_candidate() {
    let first = udp_test_node();
    let second = Node {
        id: uuid::Uuid::new_v4(),
        name: "udp-test-second".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 10,
        ..Default::default()
    };
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

    assert_udp_outbound(&stats, "udp-test", 1, 0, 0);
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
    let second = Node {
        id: uuid::Uuid::new_v4(),
        name: "udp-test-second".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 10,
        ..Default::default()
    };
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
    let unrelated = Node {
        id: uuid::Uuid::new_v4(),
        name: "health-registered-other".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 10,
        ..Default::default()
    };
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

    assert_udp_outbound(&stats, "udp-test", 1, 0, 0);
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
        dns_concurrency_limit: Arc::clone(&plane.dns_concurrency_limit),
        dns_controller: Arc::clone(&plane.dns_controller),
        drain: Arc::clone(&drain),
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
    assert!(!udp_fast_path(&pool, &stats, &query, client, dst, Some(validated)).await);

    match super::begin_udp_slow_path(&pool, &stats, &slow, client, dst, &query, Some(validated)) {
        super::UdpSlowPathWork::DnsThenMaybeInitialize {
            permit,
            data,
            validated,
        } => {
            let lease = super::complete_udp_dns_slow_path(
                super::UdpDnsSlowPathContext {
                    pool: &pool,
                    stats: &stats,
                    dns_controller: dns.as_ref(),
                    src_addr: client,
                    original_dst: dst,
                },
                permit,
                &data,
                validated,
            )
            .await;
            assert!(
                lease.is_none(),
                "DNS controller must handle the packet without reserve/enqueue"
            );
        }
        _other => panic!(
            "DNS-shaped Ready traffic must take DnsThenMaybeInitialize, got unexpected variant"
        ),
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

    assert!(!udp_fast_path(&pool, &stats, &query, client, dst, Some(validated)).await);
    match super::begin_udp_slow_path(&pool, &stats, &slow, client, dst, &query, Some(validated)) {
        super::UdpSlowPathWork::DnsThenMaybeInitialize {
            permit,
            data,
            validated,
        } => {
            let maybe_lease = super::complete_udp_dns_slow_path(
                super::UdpDnsSlowPathContext {
                    pool: &pool,
                    stats: &stats,
                    dns_controller: dns.as_ref(),
                    src_addr: client,
                    original_dst: dst,
                },
                permit,
                &data,
                validated,
            )
            .await;
            assert!(maybe_lease.is_none());
        }
        _ => panic!("DNS-shaped Initializing traffic must take DnsThenMaybeInitialize"),
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

    // Fast path must miss for Initializing — no direct enqueue, no copy.
    assert!(!udp_fast_path(&pool, &stats, b"follower", client, dst, None).await);
    assert_eq!(stats.udp_snapshot().endpoint_misses, 1);
    assert_eq!(stats.udp_snapshot().queue_accepted, 0);

    let zero = Arc::new(tokio::sync::Semaphore::new(0));
    match super::begin_udp_slow_path(&pool, &stats, &zero, client, dst, b"follower", None) {
        super::UdpSlowPathWork::Done => {}
        _ => panic!("zero slow permit must not reserve or enqueue"),
    }
    let udp = stats.udp_snapshot();
    assert_eq!(udp.slow_permit_rejected, 1);
    assert_eq!(udp.queue_accepted, 0);

    let open = Arc::new(tokio::sync::Semaphore::new(1));
    match super::begin_udp_slow_path(&pool, &stats, &open, client, dst, b"follower", None) {
        super::UdpSlowPathWork::Done => {}
        super::UdpSlowPathWork::Initialize(_) => {
            panic!("Initializing follower must enqueue, not create a second lease")
        }
        super::UdpSlowPathWork::DnsThenMaybeInitialize { .. } => {
            panic!("non-DNS follower must not take the DNS branch")
        }
    }
    let udp = stats.udp_snapshot();
    assert_eq!(udp.slow_permit_accepted, 1);
    assert_eq!(
        udp.queue_accepted, 1,
        "with a slow permit the follower enqueues exactly once"
    );
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
async fn udp_stagger_drain_reports_completed_error_without_cancelling_ready_losers() {
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
                    "completed-ok" => Ok(node.name),
                    _ => unreachable!(),
                }
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
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
    let candidates = ["winner", "completed-error", "completed-ok"]
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
    let (winner, _) = task
        .await
        .unwrap()
        .expect("the first completed success should win");
    assert_eq!(winner.name, "winner");
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
        prepare,
        callbacks,
    )
    .await
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
            prepare,
            callbacks,
        )
        .await
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
        prepare,
        callbacks,
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    assert!(task.await.unwrap().is_none());
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
        prepare,
        callbacks,
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    let (winner, _) = task
        .await
        .unwrap()
        .expect("eligible candidate should still win");
    assert_eq!(winner.name, "eligible-winner");
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
}

fn preconnect_test_node(name: &str, protocol: NodeProtocol) -> Node {
    Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        protocol,
        address: format!("{name}.example.com:443"),
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
    assert!(cp.apply_runtime_config(Config::default(), &drain).await);
    assert!(cp.apply_runtime_config(Config::default(), &drain).await);

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
                TPROXY_MARK,
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

            let mut config = udp_test_config("direct", vec![udp_test_node()], vec![]);
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
                    outbound: honk_config::routing::RoutingOutbound::Simple("udp-test".into()),
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
                    outbound: honk_config::routing::RoutingOutbound::Simple("udp-test".into()),
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
                routing_matcher::RoutingMatcherBuilder::push_plan(ebpf.as_mut(), &plan)?;
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
            protocol: honk_config::types::NodeProtocol::Socks5,
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
