use super::*;

#[tokio::test]
async fn dns_wait_timeout_remains_retryable_with_free_admission() {
    // Bootstrap DNS is process-global; isolate it from parallel core tests.
    const CHILD: &str = "HONK_DIAL_DNS_TIMEOUT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "control::connection::tcp::dial_permit_scope_tests::dns_wait_timeout_remains_retryable_with_free_admission",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("isolated DNS timeout test");
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let mut node = Node {
        name: "dns-wait".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: "pending.invalid".into(),
        port: 1080,
        ..Default::default()
    };
    node.id = node.derive_id();
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[node.clone()], 1, None)
            .unwrap()
            .0,
    );
    let control = crate::control::tests::support::control_plane(Config {
        nodes: vec![node.clone()],
        ..Default::default()
    });
    let handle = control.spawn_handle();
    let dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    honk_outbound::bootstrap::set_global(honk_outbound::bootstrap::BootstrapResolver::parse(
        &dns.local_addr().unwrap().to_string(),
    ));
    let candidates = [&node];
    let score_group = honk_config::group::Group {
        name: "score".into(),
        policy: honk_config::group::GroupPolicy::Score,
        nodes: vec![node.id],
        ..Default::default()
    };
    let manager = crate::group::GroupManager::new(&[score_group], std::slice::from_ref(&node));
    let feedback = HashMap::from([(
        node.id,
        manager
            .feedback_for_group_node(
                "score",
                node.id,
                tcp_score_context(target, None, IpVersion::V4),
            )
            .unwrap()
            .business(),
    )]);
    let (result, ()) = tokio::join!(
        handle.race_candidates(
            &candidates,
            target,
            None,
            "score",
            None,
            Duration::from_millis(100),
            tokio::time::Instant::now() + Duration::from_secs(10),
            Arc::clone(&generation),
            IpVersion::V4,
            &feedback,
            false,
        ),
        async {
            let mut packet = [0; 512];
            tokio::time::timeout(Duration::from_secs(1), dns.recv_from(&mut packet))
                .await
                .expect("the candidate must reach bootstrap DNS")
                .unwrap();
            assert_eq!(manager.score_state().root_business_starts(), 1);
            assert_eq!(
                manager
                    .score_budget_counters("score", SelectionNetwork::Tcp)
                    .business_starts,
                1
            );
            let permit =
                tokio::time::timeout(Duration::from_millis(100), generation.acquire_dial_permit())
                    .await
                    .expect("physical admission must remain available during DNS");
            drop(permit);
        }
    );
    assert!(
        matches!(result, Ok(None)),
        "DNS timeout must remain an ordinary failed attempt, not terminal Capacity"
    );
}

#[tokio::test]
async fn ready_pool_hit_does_not_wait_for_physical_dial_permit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let tcp = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let mut node = Node {
        name: "ready-socks".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        ..Default::default()
    };
    node.id = node.derive_id();
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[node.clone()], 1, None)
            .unwrap()
            .0,
    );
    let _held = generation.acquire_dial_permit().await;
    let pool = ConnectionPool::new();
    let key = ConnectionPool::ready_key(generation.generation(), node.id, target, None);
    pool.deposit_ready(
        generation.generation(),
        &key,
        crate::proxy::ProxyStream {
            stream: Box::new(tcp),
            target_addr: target,
            target_domain: None,
        },
    )
    .await;
    let registry = ProxyRegistry::default_resolver().unwrap();
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let started_on_dial = Arc::clone(&started);

    let (stream, fresh) = tokio::time::timeout(
        Duration::from_millis(100),
        ControlPlaneHandle::dial_pooled(
            &registry,
            &pool,
            &generation,
            &node,
            (target, None),
            Duration::from_secs(1),
            None,
            &generation.dial_scope(move || {
                started_on_dial.store(true, std::sync::atomic::Ordering::Release)
            }),
        ),
    )
    .await
    .expect("ready stream must bypass an exhausted physical-dial gate")
    .unwrap();
    assert!(started.load(std::sync::atomic::Ordering::Acquire));
    assert!(
        !fresh,
        "a ready-pool acquire performs no network round trip"
    );

    drop(stream);
    server.abort();
}

#[tokio::test]
async fn feedback_does_not_start_while_waiting_for_dial_admission() {
    let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let mut node = Node {
        name: "blocked-socks".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: "127.0.0.1".into(),
        port: 9,
        ..Default::default()
    };
    node.id = node.derive_id();
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[node.clone()], 1, None)
            .unwrap()
            .0,
    );
    let _held = generation.acquire_dial_permit().await;
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let started_on_dial = Arc::clone(&started);

    let result = tokio::time::timeout(
        Duration::from_millis(20),
        ControlPlaneHandle::dial_pooled(
            &ProxyRegistry::default_resolver().unwrap(),
            &ConnectionPool::new(),
            &generation,
            &node,
            (target, None),
            Duration::from_secs(1),
            None,
            &generation.dial_scope(move || {
                started_on_dial.store(true, std::sync::atomic::Ordering::Release)
            }),
        ),
    )
    .await;

    assert!(result.is_err());
    assert!(!started.load(std::sync::atomic::Ordering::Acquire));

    let mut alternate = node.clone();
    alternate.name = "alternate".into();
    alternate.port += 1;
    alternate.id = alternate.derive_id();
    let nodes = [node.clone(), alternate];
    let group = honk_config::group::Group {
        name: "score".into(),
        policy: honk_config::group::GroupPolicy::Score,
        nodes: nodes.iter().map(|node| node.id).collect(),
        ..Default::default()
    };
    let control = crate::control::tests::support::control_plane(Config {
        nodes: nodes.to_vec(),
        groups: vec![group],
        ..Default::default()
    });
    let handle = control.spawn_handle();
    let manager = handle.group_manager.read().clone();
    let context = tcp_score_context(target, None, IpVersion::V4);
    let feedback = manager.feedback_for_node(node.id, context.clone()).unwrap();
    for _ in 0..2 {
        let feedback = HashMap::from([(node.id, feedback.business())]);
        let result = handle
            .race_candidates(
                &[&node],
                target,
                None,
                "score",
                None,
                Duration::from_millis(5),
                tokio::time::Instant::now() + Duration::from_secs(1),
                Arc::clone(&generation),
                IpVersion::V4,
                &feedback,
                false,
            )
            .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("unstarted admission expiry must be terminal, not retryable"),
        };
        assert_eq!(
            honk_outbound::proxy::packet_rejection(&error),
            Some(honk_outbound::proxy::PacketRejection::Capacity)
        );
    }
    assert!(
        !handle
            .alive_set
            .is_failure_demoted(node.id, ProbeDomain::Tcp, IpVersion::V4)
    );
    assert_eq!(
        manager.selection_plan_for_target("score", &context).entries[0]
            .node
            .id,
        node.id,
        "unstarted waits must not train failure evidence or explore an alternate"
    );
}

#[test]
fn retired_runtime_errors_are_neutral() {
    let generation = honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
        .unwrap()
        .0;
    generation.begin_retirement();

    assert_eq!(
        score_runtime_outcome(&generation, &anyhow::anyhow!("retired")),
        crate::group::ScoreOutcome::Shutdown
    );
}

#[test]
fn retired_generation_dial_failures_do_not_poison_health() {
    let live_generation =
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
            .unwrap()
            .0;
    let retired_generation =
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
            .unwrap()
            .0;
    retired_generation.begin_retirement();
    let live = honk_outbound::alive::AliveDialerSet::new();
    let retired = honk_outbound::alive::AliveDialerSet::new();
    let node_id = uuid::Uuid::new_v4();

    for _ in 0..50 {
        report_dial_failure_if_current(
            &live_generation,
            &live,
            node_id,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
        report_dial_failure_if_current(
            &retired_generation,
            &retired,
            node_id,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
    }

    assert!(!live.is_alive_for(node_id, ProbeDomain::DataUdp, IpVersion::V4));
    assert!(retired.is_alive_for(node_id, ProbeDomain::DataUdp, IpVersion::V4));
}

struct HeldMarkedDirect {
    marks: tokio::sync::mpsc::UnboundedSender<u32>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::TcpOutbound for HeldMarkedDirect {
    async fn dial(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _domain: Option<&str>,
        _timeout: Duration,
    ) -> anyhow::Result<crate::proxy::ProxyStream> {
        anyhow::bail!("a routed direct flow must dial through its captured runtime")
    }

    async fn dial_runtime_marked(
        &self,
        _runtime: Arc<honk_outbound::runtime::NodeRuntime>,
        target: SocketAddr,
        _domain: Option<&str>,
        _timeout: Duration,
        mark: honk_outbound::proxy::DirectMark,
    ) -> anyhow::Result<crate::proxy::ProxyStream> {
        self.marks.send(mark.get()).unwrap();
        self.release.notified().await;
        Ok(crate::proxy::ProxyStream {
            stream: Box::new(tokio::io::duplex(1).0),
            target_addr: target,
            target_domain: None,
        })
    }
}

#[tokio::test]
async fn marked_direct_dial_skips_bare_pool_and_rejects_retired_completion() {
    let node = Config::builtin_direct_node();
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(
            std::slice::from_ref(&node),
            1,
            None,
        )
        .unwrap()
        .0,
    );
    let (marks, mut dialed) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let mut registry = ProxyRegistry::new();
    registry.register(honk_outbound::proxy::ProtocolEntry::new(
        NodeProtocol::Direct,
        Arc::new(HeldMarkedDirect {
            marks,
            release: Arc::clone(&release),
        }),
    ));
    let pool = ConnectionPool::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unmarked = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (_peer, _) = listener.accept().await.unwrap();
    assert!(
        pool.deposit_tcp(&format!("{}:{}", node.host(), node.port), unmarked)
            .await
    );
    let scope = generation.dial_scope(|| {});

    let (result, ()) = tokio::join!(
        ControlPlaneHandle::dial_pooled(
            &registry,
            &pool,
            &generation,
            &node,
            ("192.0.2.1:443".parse().unwrap(), None),
            Duration::from_secs(1),
            honk_outbound::proxy::DirectMark::new(0x321),
            &scope,
        ),
        async {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), dialed.recv())
                    .await
                    .expect("a marked direct dial must reach the registered handler"),
                Some(0x321)
            );
            generation.begin_retirement();
            release.notify_one();
        }
    );
    assert!(
        result.is_err(),
        "a direct stream completed after retirement must not be published"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires Linux CAP_NET_ADMIN or CAP_NET_RAW for real SO_MARK"]
async fn direct_race_preserves_per_flow_marks() {
    let mut config = Config::default();
    config.ensure_builtin_nodes();
    let node = config
        .nodes
        .iter()
        .find(|node| node.protocol() == NodeProtocol::Direct)
        .unwrap()
        .clone();
    let control = crate::control::tests::support::control_plane(config);
    let handle = control.spawn_handle();
    let generation = handle.runtime_registry.read().clone();
    for ip in ["127.0.0.1", "::1"] {
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(ip.parse().unwrap(), 0))
            .await
            .unwrap();
        let target = listener.local_addr().unwrap();
        let mut live = Vec::new();
        for direct_mark in [
            honk_outbound::proxy::DirectMark::new(0x321),
            honk_outbound::proxy::DirectMark::new(0x456),
            None,
        ] {
            let (stream, _, _) = handle
                .race_candidates(
                    &[&node],
                    target,
                    None,
                    "direct",
                    direct_mark,
                    Duration::from_secs(1),
                    tokio::time::Instant::now() + Duration::from_secs(2),
                    Arc::clone(&generation),
                    if target.is_ipv4() {
                        IpVersion::V4
                    } else {
                        IpVersion::V6
                    },
                    &HashMap::new(),
                    false,
                )
                .await
                .unwrap()
                .unwrap();
            let socket = stream
                .stream
                .as_ref()
                .as_any()
                .downcast_ref::<tokio::net::TcpStream>()
                .unwrap();
            assert_eq!(
                socket2::SockRef::from(socket).mark().unwrap(),
                direct_mark.map_or_else(
                    honk_outbound::util::bypass_mark,
                    honk_outbound::proxy::DirectMark::socket_mark,
                )
            );
            let (peer, _) = listener.accept().await.unwrap();
            live.push((stream, peer));
        }
        let socket = live[0]
            .0
            .stream
            .as_ref()
            .as_any()
            .downcast_ref::<tokio::net::TcpStream>()
            .unwrap();
        assert_eq!(
            socket2::SockRef::from(socket).mark().unwrap(),
            honk_ebpf_common::CLASSIFIED_MARK | 0x321
        );
    }
}
