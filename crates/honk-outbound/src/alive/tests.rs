use super::*;
use honk_config::config::{BLOCK_NODE_ID, DIRECT_NODE_ID};

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

#[test]
fn test_parse_check_literals() {
    let lits = AliveDialerSet::parse_check_literals(
        "http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111",
        80,
    );
    assert_eq!(
        lits,
        vec![
            "1.1.1.1:80".parse::<SocketAddr>().unwrap(),
            "[2606:4700:4700::1111]:80".parse::<SocketAddr>().unwrap(),
        ]
    );
    // The URL's explicit port applies to the literal fallbacks as well.
    let lits = AliveDialerSet::parse_check_literals("http://a.com:8443/,1.1.1.1", 8443);
    assert_eq!(lits, vec!["1.1.1.1:8443".parse::<SocketAddr>().unwrap()]);
    // No fallback segments → empty; garbage segments skipped.
    assert!(AliveDialerSet::parse_check_literals("http://cp.cloudflare.com", 80).is_empty());
    assert_eq!(
        AliveDialerSet::parse_check_literals("http://a.com,bogus,8.8.8.8", 80).len(),
        1
    );
}

#[test]
fn test_merge_check_addrs_dedup() {
    let resolved = vec!["1.1.1.1:80".parse::<SocketAddr>().unwrap()];
    let merged =
        AliveDialerSet::merge_check_addrs(resolved, "http://cp.cloudflare.com,1.1.1.1,8.8.8.8", 80);
    assert_eq!(merged.len(), 2); // 1.1.1.1 deduped against resolved
}

#[tokio::test]
async fn resolution_cancelled_by_shutdown_reports_stopped_checks() {
    let set = Arc::new(AliveDialerSet::new());
    let started = Arc::new(tokio::sync::Notify::new());
    let hook: ResolveHook = Arc::new({
        let started = Arc::clone(&started);
        move |_, _| {
            let started = Arc::clone(&started);
            Box::pin(async move {
                started.notify_one();
                std::future::pending().await
            })
        }
    });
    set.set_resolver(hook);
    let lookup = tokio::spawn({
        let set = Arc::clone(&set);
        async move { set.resolve_host("localhost", 80).await }
    });
    started.notified().await;
    set.shutdown_health_checks().await.unwrap();
    let error = lookup.await.unwrap().expect_err("cancelled lookup");
    assert_eq!(
        error.downcast_ref::<HealthCheckError>(),
        Some(&HealthCheckError::Stopped)
    );
}

#[tokio::test]
async fn resolver_hook_rejection_skips_system_fallback_and_health_penalty() {
    let set = AliveDialerSet::new();
    let rejection: ResolveHook = Arc::new(|_, _| {
        Box::pin(async { Err(anyhow::Error::new(crate::proxy::PacketRejection::Policy)) })
    });
    set.set_resolver(rejection);
    let error = set
        .resolve_host("localhost", 80)
        .await
        .expect_err("typed rejection");
    assert!(crate::proxy::is_packet_rejection(&error));

    let node = id(9);
    set.register_node(node, "denied".into(), Some("localhost:9".into()));
    set.node_registered_at
        .write()
        .insert(node, Instant::now() - GRACE_PERIOD);
    for _ in 0..3 {
        assert!(!set.probe_node(node, Duration::from_millis(10)).await);
    }
    assert!(set.is_alive_for(node, ProbeDomain::Tcp, IpVersion::V4));
    assert!(set.is_alive_for(node, ProbeDomain::Tcp, IpVersion::V6));

    set.set_http_probe(
        Arc::new(MockHttpProber {
            result: HttpProbeResult::WarmSuccess(Duration::from_millis(1)),
        }),
        "http://localhost,127.0.0.1".into(),
        "HEAD".into(),
    )
    .await;
    assert_eq!(
        set.check_url_ips.read().as_slice(),
        &["127.0.0.1:80".parse::<SocketAddr>().unwrap()]
    );
    *set.check_url_ips.write() = vec!["192.0.2.1:80".parse().unwrap()];
    set.refresh_check_ips().await;
    assert_eq!(
        set.check_url_ips.read().as_slice(),
        &["127.0.0.1:80".parse::<SocketAddr>().unwrap()]
    );

    let empty: ResolveHook = Arc::new(|_, _| Box::pin(async { Ok(Vec::new()) }));
    set.set_resolver(empty);
    assert!(
        set.resolve_host("localhost", 80)
            .await
            .expect("ordinary empty hook system fallback")
            .into_iter()
            .any(|address| address.ip().is_loopback())
    );
}

#[test]
fn test_alive_set_basic() {
    let set = AliveDialerSet::new();
    assert!(set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4));
    // TCP probe threshold = 3: one transient failure must not kill the
    // node; three consecutive failures do.
    set.mark_dead_for(id(1), ProbeDomain::Tcp, IpVersion::V4);
    assert!(
        set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4),
        "TCP survives one probe failure"
    );
    set.mark_dead_for(id(1), ProbeDomain::Tcp, IpVersion::V4);
    set.mark_dead_for(id(1), ProbeDomain::Tcp, IpVersion::V4);
    assert!(
        !set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4),
        "TCP dies after 3 probe failures"
    );
    // DNS UDP probe threshold = 3 — verify per-protocol thresholds
    assert!(set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
    set.mark_dead_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4);
    assert!(set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
    set.mark_dead_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4);
    assert!(set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
    set.mark_dead_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4);
    assert!(!set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
    set.mark_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4);
    assert!(set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4));
}

#[test]
fn test_alive_set_per_protocol() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:1".into()));
    assert!(set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4));
    assert!(set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
    // Use forced death to bypass grace period for registered nodes.
    set.report_unavailable_forced(id(1), ProbeDomain::Tcp, IpVersion::V4);
    assert!(!set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4));
    assert!(set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
}

#[test]
fn available_traffic_fast_path_preserves_clean_state_and_resets_dirty_state() {
    let set = AliveDialerSet::new();
    let node = id(9);
    let idx = alive_index(ProbeDomain::DataUdp, IpVersion::V4);
    set.report_available_traffic(node, ProbeDomain::DataUdp, IpVersion::V4);
    let clean = set.states.read()[&node][idx].clone();

    set.report_available_traffic(node, ProbeDomain::DataUdp, IpVersion::V4);
    let unchanged = set.states.read()[&node][idx].clone();
    assert_eq!(unchanged.cooldown_until, clean.cooldown_until);

    {
        let mut states = set.states.write();
        let state = &mut states.get_mut(&node).expect("state")[idx];
        state.traffic_failures = 1;
        state.stopped = true;
    }
    set.report_available_traffic(node, ProbeDomain::DataUdp, IpVersion::V4);
    let reset = set.states.read()[&node][idx].clone();
    assert!(reset.is_clean_alive());
}

fn idle_reg(
    name: &str,
    members: Vec<Uuid>,
    idle_timeout: Option<Duration>,
    kind: IdleGroupKind,
) -> IdleGroupRegistration {
    let recovery = if kind == IdleGroupKind::Automatic {
        members.clone()
    } else {
        Vec::new()
    };
    IdleGroupRegistration {
        name: name.to_owned(),
        members,
        idle_timeout,
        kind,
        tcp_recovery_members: recovery.clone(),
        udp_recovery_members: recovery,
    }
}

#[test]
fn group_activity_ignores_untracked_groups_and_reuses_registered_key() {
    let set = AliveDialerSet::new();
    set.mark_group_active("untracked");
    assert!(set.idle_groups.read().groups.is_empty());

    set.sync_idle_groups(&[idle_reg(
        "tracked",
        Vec::new(),
        Some(Duration::from_secs(60)),
        IdleGroupKind::Automatic,
    )]);
    set.mark_group_active("tracked");
    let first = set.idle_groups.read().groups["tracked"]
        .activity
        .last_active_ns
        .load(Ordering::Acquire);
    assert!(first > 0);
    set.mark_group_active("tracked");
    let idle = set.idle_groups.read();
    assert_eq!(idle.groups.len(), 1);
    assert!(
        idle.groups["tracked"]
            .activity
            .last_active_ns
            .load(Ordering::Acquire)
            >= first
    );
}

/// Traffic failures during the grace period must not mark a fresh node
/// dead (restart warm-up regression: mass traffic failures used to kill
/// every node seconds after startup).
#[test]
fn test_traffic_failures_ignored_during_grace() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:1".into()));
    let threshold = 50;
    for _ in 0..threshold {
        set.report_unavailable_traffic(id(1), ProbeDomain::Tcp, IpVersion::V4);
    }
    assert!(
        set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4),
        "traffic failures during grace must not kill the node"
    );
}

#[test]
fn test_probe_cooldown_backoff() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:1".into()));
    assert!(set.should_probe(id(1), ProbeDomain::Tcp, IpVersion::V4));
    // Use forced death to bypass grace period and trigger backoff.
    set.report_unavailable_forced(id(1), ProbeDomain::Tcp, IpVersion::V4);
    assert!(!set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4));
}

#[test]
fn test_network_change_bypasses_backoff_but_requires_fresh_success() {
    let set = AliveDialerSet::new();
    let node_id = id(1);
    set.register_node(node_id, "n1".into(), Some("127.0.0.1:1".into()));
    set.report_unavailable_forced(node_id, ProbeDomain::Tcp, IpVersion::V4);
    {
        let mut states = set.states.write();
        let state =
            &mut states.get_mut(&node_id).unwrap()[alive_index(ProbeDomain::Tcp, IpVersion::V4)];
        state.cooldown_until = Instant::now() + Duration::from_secs(300);
    }
    assert!(!set.is_alive_for(node_id, ProbeDomain::Tcp, IpVersion::V4));
    assert!(!set.should_probe(node_id, ProbeDomain::Tcp, IpVersion::V4));
    let mut trigger_rx = set.take_trigger_rx().expect("trigger receiver");

    set.notify_network_change();

    assert!(set.should_probe(node_id, ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(trigger_rx.try_recv(), Ok(node_id));
    assert!(!set.is_alive_for(node_id, ProbeDomain::Tcp, IpVersion::V4));
    set.record_probe_latency(
        node_id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    assert!(set.is_alive_for(node_id, ProbeDomain::Tcp, IpVersion::V4));
}

#[tokio::test]
async fn test_recovery_cycle_probes_due_dead_nodes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let set = Arc::new(AliveDialerSet::new());
    let node_id = id(2);
    set.register_node(
        node_id,
        "n2".into(),
        Some(listener.local_addr().unwrap().to_string()),
    );
    set.report_unavailable_forced(node_id, ProbeDomain::Tcp, IpVersion::V4);
    {
        let mut states = set.states.write();
        let state =
            &mut states.get_mut(&node_id).unwrap()[alive_index(ProbeDomain::Tcp, IpVersion::V4)];
        state.consecutive_successes = RECOVERY_SUCCESSES_NEEDED - 1;
        state.cooldown_until = Instant::now();
    }

    set.run_recovery_check_cycle_concurrent(Duration::from_secs(1), 1)
        .await;

    assert!(set.is_alive_for(node_id, ProbeDomain::Tcp, IpVersion::V4));
}

#[tokio::test]
async fn test_recovery_cycle_probes_due_dead_udp_nodes() {
    let set = Arc::new(AliveDialerSet::new());
    let node_id = id(3);
    set.register_node(node_id, "n3".into(), Some("127.0.0.1:1".into()));
    set.set_udp_probe(Arc::new(MockUdpProber::ok(Duration::from_millis(5))));
    set.report_unavailable_forced(node_id, ProbeDomain::DataUdp, IpVersion::V4);
    assert!(!set.is_alive_for(node_id, ProbeDomain::DataUdp, IpVersion::V4));

    set.run_recovery_check_cycle_concurrent(Duration::from_secs(1), 1)
        .await;

    assert!(set.is_alive_for(node_id, ProbeDomain::DataUdp, IpVersion::V4));
    assert!(set.is_alive_for(node_id, ProbeDomain::DnsUdp, IpVersion::V6));
}

#[tokio::test]
async fn test_periodic_cycle_tcp_cooldown_keeps_due_udp_probe() {
    for (tcp_cooling, udp_cooling) in [(true, false), (false, true), (true, true)] {
        let set = Arc::new(AliveDialerSet::new());
        let node_id = id(4);
        set.register_node(node_id, "n4".into(), Some("127.0.0.1:1".into()));
        set.set_http_probe(
            Arc::new(MockHttpProber {
                result: HttpProbeResult::WarmSuccess(Duration::from_millis(7)),
            }),
            "http://127.0.0.1/".into(),
            "HEAD".into(),
        )
        .await;
        set.set_udp_probe(Arc::new(MockUdpProber::ok(Duration::from_millis(5))));
        for (domain, cooling) in [
            (ProbeDomain::Tcp, tcp_cooling),
            (ProbeDomain::DataUdp, udp_cooling),
        ] {
            if cooling {
                set.states.write().get_mut(&node_id).unwrap()[alive_index(domain, IpVersion::V4)]
                    .cooldown_until = Instant::now() + Duration::from_secs(300);
            }
        }

        set.run_health_check_cycle_concurrent(Duration::from_secs(1), 1)
            .await;

        for (domain, cooling, latency) in [
            (ProbeDomain::Tcp, tcp_cooling, Duration::from_millis(7)),
            (ProbeDomain::DataUdp, udp_cooling, Duration::from_millis(5)),
        ] {
            let history = set.get_probe_history(node_id, domain, IpVersion::V4);
            if cooling {
                assert!(
                    history.is_empty(),
                    "{domain:?} cooldown must suppress its probe"
                );
            } else {
                assert!(
                    matches!(history.as_slice(), [record] if record.success && record.latency == Some(latency)),
                    "{domain:?} probe must publish its successful measurement"
                );
            }
        }
    }
}

#[tokio::test]
async fn test_emergency_probe_keeps_udp_cooldown() {
    let set = Arc::new(AliveDialerSet::new());
    let node_id = id(5);
    set.register_node(node_id, "n5".into(), Some("127.0.0.1:1".into()));
    set.set_http_probe(
        Arc::new(MockHttpProber {
            result: HttpProbeResult::WarmSuccess(Duration::from_millis(7)),
        }),
        "http://127.0.0.1/".into(),
        "HEAD".into(),
    )
    .await;
    set.register_idle_group("idle", &[node_id], Some(Duration::from_secs(3600)));
    for ipver in [IpVersion::V4, IpVersion::V6] {
        set.states.write().get_mut(&node_id).unwrap()[alive_index(ProbeDomain::Tcp, ipver)]
            .cooldown_until = Instant::now() + Duration::from_secs(300);
    }
    let udp_cooldown = Instant::now() + Duration::from_secs(300);
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        for ipver in [IpVersion::V4, IpVersion::V6] {
            set.states.write().get_mut(&node_id).unwrap()[alive_index(domain, ipver)]
                .cooldown_until = udp_cooldown;
        }
    }
    let owner = set.spawn_health_check_loop_concurrent(
        Duration::from_secs(3600),
        Duration::from_secs(1),
        1,
    );

    set.trigger_probe(node_id);
    assert!(set.trigger_pending.lock().contains_key(&node_id));
    tokio::time::timeout(Duration::from_secs(10), async {
        while set.trigger_pending.lock().contains_key(&node_id) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("emergency probe finishes");
    set.shutdown_health_checks().await.unwrap();
    owner.await.unwrap();

    assert_eq!(
        set.get_last_latency(node_id, ProbeDomain::Tcp, IpVersion::V4),
        Some(Duration::from_millis(7))
    );
    for ipver in [IpVersion::V4, IpVersion::V6] {
        assert!(set.should_probe(node_id, ProbeDomain::Tcp, ipver));
    }

    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        for ipver in [IpVersion::V4, IpVersion::V6] {
            assert_eq!(
                set.read_state(node_id, alive_index(domain, ipver))
                    .cooldown_until,
                udp_cooldown
            );
        }
    }
}

#[test]
fn test_idle_suspension_and_sync_remain_deadlock_free_under_contention() {
    let set = std::sync::Arc::new(AliveDialerSet::new());
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:1".into()));
    set.register_idle_group("g", &[id(1)], Some(Duration::from_secs(60)));

    let sync_set = std::sync::Arc::clone(&set);
    let syncer = std::thread::spawn(move || {
        for _ in 0..200 {
            sync_set.sync_idle_groups(&[idle_reg(
                "g",
                vec![id(1)],
                Some(Duration::from_secs(60)),
                IdleGroupKind::Automatic,
            )]);
        }
    });
    let active_set = std::sync::Arc::clone(&set);
    let activator = std::thread::spawn(move || {
        for _ in 0..200 {
            active_set.mark_group_active("g");
        }
    });
    for _ in 0..200 {
        let _ = set.is_probe_suspended(id(1));
    }
    syncer.join().unwrap();
    activator.join().unwrap();
    assert!(!set.is_probe_suspended(id(1)));
}

#[tokio::test]
async fn test_urltest_idle_suspension() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:1".into()));
    set.register_idle_group("g", &[id(1)], Some(Duration::from_millis(50)));

    // Lazy start: a never-active group is idle → probing suspended.
    assert!(set.is_group_idle("g"));
    assert!(set.is_probe_suspended(id(1)));

    set.mark_group_active("g");
    assert!(!set.is_group_idle("g"));
    assert!(!set.is_probe_suspended(id(1)));

    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(set.is_group_idle("g"));
    assert!(set.is_probe_suspended(id(1)));

    // Unregistered groups are never idle; ungrouped nodes never suspended.
    assert!(!set.is_group_idle("nope"));
    assert!(!set.is_probe_suspended(id(99)));
}

#[tokio::test]
async fn test_health_cycle_skips_idle_urltest_nodes() {
    let set = std::sync::Arc::new(AliveDialerSet::new());
    // 127.0.0.1:1 refuses connections → a probe records a failure.
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:1".into()));
    set.register_node(id(2), "n2".into(), Some("127.0.0.1:1".into()));
    set.register_idle_group("g", &[id(1)], Some(Duration::from_secs(3600)));

    // n1's group was never active → suspended → cycle never probes it.
    set.run_health_check_cycle(Duration::from_millis(200)).await;
    assert!(
        set.get_probe_history(id(1), ProbeDomain::Tcp, IpVersion::V4)
            .is_empty(),
        "idle node must not be probed"
    );
    assert!(
        !set.get_probe_history(id(2), ProbeDomain::Tcp, IpVersion::V4)
            .is_empty(),
        "ungrouped node must be probed"
    );

    set.mark_group_active("g");
    set.run_health_check_cycle(Duration::from_millis(200)).await;
    assert!(
        !set.get_probe_history(id(1), ProbeDomain::Tcp, IpVersion::V4)
            .is_empty(),
        "active node must be probed"
    );
}

#[test]
fn test_push_ebpf_uses_outbound_resolver() {
    let set = AliveDialerSet::new();
    let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls2 = calls.clone();
    set.set_ebpf_callback(Box::new(move |_node_id, o, d, ip, alive| {
        calls2.lock().unwrap().push((o, d, ip, alive));
    }));

    // No resolver installed → legacy outbound 0. TCP dies at 3 failures.
    for _ in 0..3 {
        set.mark_dead(id(1)); // Tcp×V4+V6
    }
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[(0u8, 0u32, 0u32, false), (0u8, 0u32, 1u32, false)]
    );

    // Resolver maps n2 → outbound 5; unknown nodes are skipped.
    set.set_outbound_resolver(Some(Arc::new(
        |node: Uuid| {
            if node == id(2) { Some(5u8) } else { None }
        },
    )));
    for _ in 0..3 {
        set.mark_dead(id(2));
        set.mark_dead(id(3));
    }
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[
            (0u8, 0u32, 0u32, false),
            (0u8, 0u32, 1u32, false),
            (5u8, 0u32, 0u32, false),
            (5u8, 0u32, 1u32, false),
        ]
    );
}

#[test]
fn test_sync_idle_groups_full_refresh() {
    let set = AliveDialerSet::new();
    for (i, n) in ["n1", "n2", "n3"].into_iter().enumerate() {
        set.register_node(id(i as u128 + 1), n.into(), Some("127.0.0.1:1".into()));
    }
    // Re-registering the same group is idempotent, and full refresh
    // rebuilds the node→groups index cleanly.
    set.register_idle_group("g1", &[id(1)], Some(Duration::from_secs(10)));
    set.register_idle_group("g1", &[id(1)], Some(Duration::from_secs(10)));
    set.register_idle_group("g2", &[id(2)], Some(Duration::from_secs(20)));
    set.mark_group_active("g1");

    // Reload: g1 survives with new members/timeout, g2 removed, g3 new.
    set.sync_idle_groups(&[
        idle_reg(
            "g1",
            vec![id(2), id(3)],
            Some(Duration::from_secs(30)),
            IdleGroupKind::Automatic,
        ),
        idle_reg("g3", vec![id(1)], None, IdleGroupKind::Automatic),
    ]);

    // g1 keeps its activity timestamp (not idle despite the new 30s
    // timeout because it was just active).
    assert!(!set.is_group_idle("g1"));
    // g2 is gone → treated as unregistered (never idle).
    assert!(!set.is_group_idle("g2"));
    // g3 registered with the default timeout, never active → idle.
    assert!(set.is_group_idle("g3"));

    // Node → groups index rebuilt: n1 now belongs only to g3, n2/n3 to g1.
    assert!(set.is_probe_suspended(id(1))); // g3 idle
    assert!(!set.is_probe_suspended(id(2))); // g1 active
    assert!(!set.is_probe_suspended(id(3))); // g1 active

    // Wake-up membership follows the new table.
    set.sync_idle_groups(&[idle_reg("g3", vec![id(1)], None, IdleGroupKind::Automatic)]);
    assert!(!set.is_group_idle("g1")); // removed → never idle
    assert!(!set.is_probe_suspended(id(2))); // no groups → not suspended
}
struct MockHttpProber {
    result: HttpProbeResult,
}

impl HttpProber for MockHttpProber {
    fn probe_http(
        &self,
        _node_id: Uuid,
        _addr: std::net::SocketAddr,
        _url: &str,
        _timeout: Duration,
        _cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = HttpProbeOutcome> + Send + 'static>> {
        let result = self.result.clone();
        Box::pin(async move { result.into() })
    }
}

struct DelayedHttpProber {
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    result: HttpProbeResult,
}

impl HttpProber for DelayedHttpProber {
    fn probe_http(
        &self,
        _node_id: Uuid,
        addr: std::net::SocketAddr,
        _url: &str,
        _timeout: Duration,
        cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = HttpProbeOutcome> + Send + 'static>> {
        let started = Arc::clone(&self.started);
        let release = Arc::clone(&self.release);
        let result = self.result.clone();
        Box::pin(async move {
            started.notify_one();
            if cancel.run(release.notified()).await.is_none() {
                return HttpProbeResult::Cancelled.into();
            }
            let observation = match &result {
                HttpProbeResult::WarmSuccess(latency) => Some(HealthObservation::probe(
                    ProbeDomain::Tcp,
                    HealthMeasurement::HttpHeaders,
                    if addr.is_ipv4() {
                        IpVersion::V4
                    } else {
                        IpVersion::V6
                    },
                    Some(*latency),
                    std::time::SystemTime::now(),
                )),
                _ => None,
            };
            HttpProbeOutcome {
                result,
                observation,
            }
        })
    }
}

#[tokio::test]
async fn invalid_http_check_url_falls_back_before_probe_cycles() {
    let set = AliveDialerSet::new();
    set.set_http_probe(
        Arc::new(MockHttpProber {
            result: HttpProbeResult::WarmSuccess(Duration::from_millis(1)),
        }),
        "http://".into(),
        "HEAD".into(),
    )
    .await;

    assert!(set.check_url.read().is_empty());
    assert!(set.check_url_ips.read().is_empty());
}

#[tokio::test]
async fn warm_http_probe_is_the_only_result_recorded_as_latency() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:1".into()));
    set.set_http_probe(
        Arc::new(MockHttpProber {
            result: HttpProbeResult::WarmSuccess(Duration::from_millis(42)),
        }),
        "http://127.0.0.1/".into(),
        "HEAD".into(),
    )
    .await;

    assert!(set.probe_node(id(1), Duration::from_millis(200)).await);
    assert_eq!(
        set.get_last_latency(id(1), ProbeDomain::Tcp, IpVersion::V4),
        Some(Duration::from_millis(42))
    );

    for result in [
        HttpProbeResult::SetupFailure("connect refused".into()),
        HttpProbeResult::ExchangeFailure("HTTP read failed".into()),
    ] {
        let set = AliveDialerSet::new();
        set.record_probe_latency(
            id(1),
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(42),
        );
        set.set_http_probe(
            Arc::new(MockHttpProber { result }),
            "http://127.0.0.1/".into(),
            "HEAD".into(),
        )
        .await;
        assert!(!set.probe_node(id(1), Duration::from_millis(200)).await);
        assert_eq!(
            set.get_last_real_sample(id(1), ProbeDomain::Tcp, IpVersion::V4)
                .map(|sample| sample.0),
            Some(Duration::from_millis(42)),
            "a failed health signal must not become a ranking latency"
        );
        assert!(
            !set.is_failure_demoted(id(1), ProbeDomain::Tcp, IpVersion::V4),
            "periodic probe failure must not become a dial-failure strike"
        );
    }
}

#[tokio::test]
async fn v4_only_check_url_leaves_v6_family_untouched() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:1".into()));
    // Age the node out of the registration grace period so failures count.
    set.node_registered_at
        .write()
        .insert(id(1), Instant::now() - GRACE_PERIOD);
    set.set_http_probe(
        Arc::new(MockHttpProber {
            result: HttpProbeResult::WarmSuccess(Duration::from_millis(10)),
        }),
        "http://127.0.0.1/".into(),
        "HEAD".into(),
    )
    .await;

    for _ in 0..4 {
        assert!(set.probe_node(id(1), Duration::from_millis(200)).await);
    }
    assert!(
        set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V6),
        "a v4-only check URL carries no v6 evidence; the family must stay alive (#46)"
    );
}

#[tokio::test]
async fn raw_tcp_probe_with_v4_only_node_address_leaves_v6_untouched() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:9".into()));
    set.node_registered_at
        .write()
        .insert(id(1), Instant::now() - GRACE_PERIOD);

    for _ in 0..4 {
        assert!(!set.probe_node(id(1), Duration::from_millis(100)).await);
    }
    assert!(
        !set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4),
        "real v4 connect failures must still kill the v4 family"
    );
    assert!(
        set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V6),
        "a v4-only node address carries no v6 evidence (#46)"
    );
}

struct MockUdpProber {
    result: Option<Result<Duration, String>>,
    data_path: Option<Result<Duration, String>>,
}

impl MockUdpProber {
    fn ok(latency: Duration) -> Self {
        Self {
            result: Some(Ok(latency)),
            data_path: None,
        }
    }
    fn err(msg: &str) -> Self {
        Self {
            result: Some(Err(msg.to_string())),
            data_path: None,
        }
    }
    /// DNS check target blocked, but the independent data-path handshake
    /// succeeded (the relay blocks UDP/53 yet carries UDP fine).
    fn dns_blocked_data_ok(latency: Duration) -> Self {
        Self {
            result: Some(Err("dns probe refused".to_string())),
            data_path: Some(Ok(latency)),
        }
    }
    fn dns_skipped_data_ok(latency: Duration) -> Self {
        Self {
            result: None,
            data_path: Some(Ok(latency)),
        }
    }
    fn skipped() -> Self {
        Self {
            result: None,
            data_path: None,
        }
    }
}

impl UdpProber for MockUdpProber {
    fn probe_udp(
        &self,
        _node_id: Uuid,
        _timeout: Duration,
        _cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = UdpProbeOutcome> + Send + 'static>> {
        let r = self
            .result
            .clone()
            .map(|result| result.map_err(anyhow::Error::msg));
        let data_path = self
            .data_path
            .clone()
            .map(|result| result.map_err(anyhow::Error::msg));
        Box::pin(async move {
            UdpProbeOutcome {
                dns: r,
                data_path,
                observations: [None, None],
            }
        })
    }
}

struct PendingUdpProber;

impl UdpProber for PendingUdpProber {
    fn probe_udp(
        &self,
        _node_id: Uuid,
        timeout: Duration,
        cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = UdpProbeOutcome> + Send + 'static>> {
        Box::pin(async move {
            let completed = cancel.run(tokio::time::sleep(timeout)).await;
            UdpProbeOutcome {
                dns: completed.map(|()| Err(anyhow::anyhow!("UDP probe timeout"))),
                data_path: None,
                observations: [None, None],
            }
        })
    }
}

struct CapacityUdpProber;

impl UdpProber for CapacityUdpProber {
    fn probe_udp(
        &self,
        _node_id: Uuid,
        _timeout: Duration,
        _cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = UdpProbeOutcome> + Send + 'static>> {
        Box::pin(async {
            UdpProbeOutcome {
                dns: Some(Err(crate::proxy::PacketRejection::Capacity.into())),
                data_path: Some(Err(crate::proxy::PacketRejection::Capacity.into())),
                observations: [None, None],
            }
        })
    }
}

struct DelayedUdpProber {
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl UdpProber for DelayedUdpProber {
    fn probe_udp(
        &self,
        _node_id: Uuid,
        _timeout: Duration,
        cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = UdpProbeOutcome> + Send + 'static>> {
        let started = Arc::clone(&self.started);
        let release = Arc::clone(&self.release);
        Box::pin(async move {
            started.notify_one();
            if cancel.run(release.notified()).await.is_none() {
                return UdpProbeOutcome {
                    dns: None,
                    data_path: None,
                    observations: [None, None],
                };
            }
            UdpProbeOutcome {
                dns: Some(Ok(Duration::from_millis(11))),
                data_path: None,
                observations: [
                    Some(HealthObservation::probe(
                        ProbeDomain::DnsUdp,
                        HealthMeasurement::DnsRoundTrip,
                        IpVersion::V4,
                        Some(Duration::from_millis(11)),
                        std::time::SystemTime::now(),
                    )),
                    None,
                ],
            }
        })
    }
}

#[tokio::test]
async fn local_carrier_capacity_does_not_demote_or_revive_probe_health() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "capacity".into(), Some("127.0.0.1:1".into()));
    set.node_registered_at
        .write()
        .insert(id(1), Instant::now() - GRACE_PERIOD);
    set.set_http_probe(
        Arc::new(MockHttpProber {
            result: HttpProbeResult::LocalRefusal(crate::proxy::PacketRejection::Capacity),
        }),
        "http://127.0.0.1/".into(),
        "HEAD".into(),
    )
    .await;
    set.set_udp_probe(Arc::new(CapacityUdpProber));
    for domain in [ProbeDomain::Tcp, ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
        set.mark_alive_for_latency(id(1), domain, IpVersion::V4, Duration::from_millis(7));
        for _ in 0..3 {
            set.mark_dead_for(id(1), domain, IpVersion::V6);
        }
    }
    for _ in 0..4 {
        assert!(!set.probe_node(id(1), Duration::from_millis(20)).await);
        assert!(!set.probe_node_udp(id(1), Duration::from_millis(20)).await);
    }
    for domain in [ProbeDomain::Tcp, ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
        assert!(set.is_alive_for(id(1), domain, IpVersion::V4));
        assert!(!set.is_alive_for(id(1), domain, IpVersion::V6));
        assert_eq!(
            set.get_last_latency(id(1), domain, IpVersion::V4),
            Some(Duration::from_millis(7))
        );
    }
}

#[tokio::test]
async fn removed_node_discards_collections_and_late_probe_results() {
    for re_register in [false, true] {
        let set = Arc::new(AliveDialerSet::new());
        let node = id(1);
        set.register_node(node, "same".into(), Some("127.0.0.1:1".into()));
        set.enable_health_history();
        set.record_probe_latency(
            node,
            ProbeDomain::DataUdp,
            IpVersion::V4,
            Duration::from_millis(7),
        );
        let retired_collection = Arc::downgrade(
            &set.get_or_create_collection(node, alive_index(ProbeDomain::DataUdp, IpVersion::V4)),
        );
        set.notify_check_tcp(node);
        set.notify_check_dns_udp(node);
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        set.set_udp_probe(Arc::new(DelayedUdpProber {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        }));
        let probe = tokio::spawn({
            let set = Arc::clone(&set);
            async move { set.probe_node_udp(node, Duration::from_secs(1)).await }
        });
        started.notified().await;
        set.remove_node(node);
        assert!(retired_collection.upgrade().is_none());
        assert!(!set.states.read().contains_key(&node));
        assert!(!set.collections.read().contains_key(&node));
        assert!(!set.node_registered_at.read().contains_key(&node));
        assert!(!set.last_emergency_tcp.lock().contains_key(&node));
        assert!(!set.last_emergency_udp.lock().contains_key(&node));
        assert!(!set.trigger_pending.lock().contains_key(&node));

        if re_register {
            // Identical metadata is a different registration, not the old owner.
            set.register_node(node, "same".into(), Some("127.0.0.1:1".into()));
        }
        set.record_probe_latency(
            node,
            ProbeDomain::DataUdp,
            IpVersion::V4,
            Duration::from_millis(13),
        );
        set.report_unavailable_forced(node, ProbeDomain::DataUdp, IpVersion::V4);
        let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&callbacks);
        set.set_ebpf_callback(Box::new(move |_, _, _, _, _| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }));
        let calls = Arc::clone(&callbacks);
        set.set_death_callback(Some(Box::new(move |_, _| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        })));

        release.notify_one();
        assert!(probe.await.unwrap());
        assert!(set.health_observations(node).is_empty());
        assert_eq!(set.registered_nodes().contains_key(&node), re_register);
        assert!(!set.is_alive_for(node, ProbeDomain::DataUdp, IpVersion::V4));
        assert!(set.has_udp_state(node));
        assert_eq!(
            set.get_last_latency(node, ProbeDomain::DataUdp, IpVersion::V4),
            Some(Duration::from_millis(13))
        );
        let history: Vec<_> = set
            .get_probe_history(node, ProbeDomain::DataUdp, IpVersion::V4)
            .into_iter()
            .map(|record| (record.success, record.latency))
            .collect();
        assert_eq!(
            history,
            vec![(true, Some(Duration::from_millis(13))), (false, None)]
        );
        assert!(
            set.get_probe_history(node, ProbeDomain::DnsUdp, IpVersion::V4)
                .is_empty()
        );
        assert_eq!(callbacks.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn late_http_probe_preserves_unregistered_traffic_health() {
    for result in [
        HttpProbeResult::WarmSuccess(Duration::from_millis(11)),
        HttpProbeResult::ExchangeFailure("old check failed".into()),
    ] {
        let set = Arc::new(AliveDialerSet::new());
        let node = id(1);
        set.register_node(node, "old".into(), Some("127.0.0.1:1".into()));
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        set.set_http_probe(
            Arc::new(DelayedHttpProber {
                started: Arc::clone(&started),
                release: Arc::clone(&release),
                result,
            }),
            "http://127.0.0.1/".into(),
            "HEAD".into(),
        )
        .await;
        let probe = tokio::spawn({
            let set = Arc::clone(&set);
            async move { set.probe_node(node, Duration::from_secs(1)).await }
        });
        started.notified().await;
        set.remove_node(node);
        set.record_probe_latency(
            node,
            ProbeDomain::DataUdp,
            IpVersion::V4,
            Duration::from_millis(13),
        );
        set.report_unavailable_forced(node, ProbeDomain::DataUdp, IpVersion::V4);
        for _ in 0..2 {
            set.mark_dead_for(node, ProbeDomain::Tcp, IpVersion::V4);
        }
        let deaths = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&deaths);
        set.set_death_callback(Some(Box::new(move |_, _| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        })));
        release.notify_one();
        probe.await.unwrap();
        assert!(!set.is_alive_for(node, ProbeDomain::DataUdp, IpVersion::V4));
        assert!(set.has_udp_state(node));
        assert_eq!(
            set.get_last_latency(node, ProbeDomain::DataUdp, IpVersion::V4),
            Some(Duration::from_millis(13))
        );
        assert_eq!(
            set.get_probe_history(node, ProbeDomain::Tcp, IpVersion::V4)
                .len(),
            2
        );
        assert!(set.is_alive_for(node, ProbeDomain::Tcp, IpVersion::V4));
        assert_eq!(deaths.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn late_raw_tcp_probe_preserves_replacement_health() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let set = Arc::new(AliveDialerSet::new());
    let node = id(1);
    set.register_node(node, "same".into(), Some(addr.to_string()));
    set.enable_health_history();
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    set.set_resolver(Arc::new({
        let started = Arc::clone(&started);
        let release = Arc::clone(&release);
        move |_, _| {
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            Box::pin(async move {
                started.notify_one();
                release.notified().await;
                Ok(vec![addr])
            })
        }
    }));
    let probe = tokio::spawn({
        let set = Arc::clone(&set);
        async move { set.probe_node(node, Duration::from_secs(1)).await }
    });
    started.notified().await;
    set.remove_node(node);
    set.register_node(node, "same".into(), Some(addr.to_string()));
    set.record_probe_latency(
        node,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(13),
    );
    set.report_unavailable_forced(node, ProbeDomain::DataUdp, IpVersion::V4);
    release.notify_one();
    assert!(probe.await.unwrap());
    assert!(set.health_observations(node).is_empty());
    assert!(!set.is_alive_for(node, ProbeDomain::DataUdp, IpVersion::V4));
    assert_eq!(
        set.get_last_latency(node, ProbeDomain::Tcp, IpVersion::V4),
        Some(Duration::from_millis(13))
    );
    assert_eq!(
        set.get_probe_history(node, ProbeDomain::Tcp, IpVersion::V4)
            .len(),
        1
    );
}

#[tokio::test]
async fn scheduled_udp_probe_does_not_become_an_unregistered_probe() {
    let set = Arc::new(AliveDialerSet::new());
    let node = id(1);
    set.register_node(node, "old".into(), Some("127.0.0.1:1".into()));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    set.set_http_probe(
        Arc::new(DelayedHttpProber {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
            result: HttpProbeResult::WarmSuccess(Duration::from_millis(11)),
        }),
        "http://127.0.0.1/".into(),
        "HEAD".into(),
    )
    .await;
    set.set_udp_probe(Arc::new(MockUdpProber::ok(Duration::from_millis(11))));
    let cycle = tokio::spawn({
        let set = Arc::clone(&set);
        async move { set.run_health_check_cycle(Duration::from_secs(1)).await }
    });
    started.notified().await;
    set.remove_node(node);
    set.record_probe_latency(
        node,
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(13),
    );
    set.report_unavailable_forced(node, ProbeDomain::DataUdp, IpVersion::V4);
    release.notify_one();
    cycle.await.unwrap();
    assert!(!set.is_alive_for(node, ProbeDomain::DataUdp, IpVersion::V4));
    assert_eq!(
        set.get_last_latency(node, ProbeDomain::DataUdp, IpVersion::V4),
        Some(Duration::from_millis(13))
    );
    assert_eq!(
        set.get_probe_history(node, ProbeDomain::DataUdp, IpVersion::V4)
            .len(),
        2
    );
    assert!(
        set.get_probe_history(node, ProbeDomain::DnsUdp, IpVersion::V4)
            .is_empty()
    );
}

#[test]
fn recovered_traffic_suppresses_a_pending_probe_death_notification() {
    let set = Arc::new(AliveDialerSet::new());
    let node = id(1);
    for _ in 0..2 {
        set.mark_dead_for(node, ProbeDomain::Tcp, IpVersion::V4);
    }
    let pushes = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let calls = Arc::clone(&pushes);
    set.set_ebpf_callback(Box::new(move |_, _, _, _, alive| {
        calls.lock().push(alive);
    }));
    let deaths = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = Arc::clone(&deaths);
    set.set_death_callback(Some(Box::new(move |_, _| {
        calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    })));
    let history = set.probe_history.write();
    let failure = std::thread::spawn({
        let set = Arc::clone(&set);
        move || set.mark_dead_for(node, ProbeDomain::Tcp, IpVersion::V4)
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while set.is_alive_for(node, ProbeDomain::Tcp, IpVersion::V4) {
        assert!(
            Instant::now() < deadline,
            "probe failure did not reach the history commit"
        );
        std::thread::yield_now();
    }
    set.report_available_traffic(node, ProbeDomain::Tcp, IpVersion::V4);
    drop(history);
    failure.join().unwrap();
    assert!(set.is_alive_for(node, ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(*pushes.lock(), vec![true]);
    assert_eq!(deaths.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[tokio::test]
async fn reentrant_probe_callbacks_cannot_update_replacement_registration() {
    for retire_in_resolver in [false, true] {
        let set = Arc::new(AliveDialerSet::new());
        let node = id(1);
        set.register_node(node, "same".into(), Some("127.0.0.1:1".into()));
        set.node_registered_at
            .write()
            .insert(node, Instant::now() - GRACE_PERIOD);
        for _ in 0..2 {
            set.mark_dead_for(node, ProbeDomain::DataUdp, IpVersion::V4);
        }
        let retire = {
            let set = Arc::downgrade(&set);
            move || {
                let set = set.upgrade().unwrap();
                set.remove_node(node);
                set.register_node(node, "same".into(), Some("127.0.0.1:1".into()));
                set.set_ebpf_callback(Box::new(|_, _, _, _, _| {}));
                set.set_outbound_resolver(None);
                set.record_probe_latency(
                    node,
                    ProbeDomain::DataUdp,
                    IpVersion::V4,
                    Duration::from_millis(13),
                );
                set.report_unavailable_forced(node, ProbeDomain::DataUdp, IpVersion::V4);
            }
        };
        let deaths = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&deaths);
        set.set_death_callback(Some(Box::new(move |_, _| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        })));
        let pushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&pushes);
        if retire_in_resolver {
            set.set_outbound_resolver(Some(Arc::new(move |_| {
                retire();
                Some(0)
            })));
            set.set_ebpf_callback(Box::new(move |_, _, _, _, _| {
                calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }));
        } else {
            set.set_ebpf_callback(Box::new(move |_, _, _, _, _| {
                calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                retire();
            }));
        }
        set.set_udp_probe(Arc::new(MockUdpProber::err("old failure")));
        assert!(!set.probe_node_udp(node, Duration::from_secs(1)).await);
        assert!(!set.is_alive_for(node, ProbeDomain::DataUdp, IpVersion::V4));
        assert_eq!(
            set.get_last_latency(node, ProbeDomain::DataUdp, IpVersion::V4),
            Some(Duration::from_millis(13))
        );
        assert_eq!(
            set.get_probe_history(node, ProbeDomain::DataUdp, IpVersion::V4)
                .len(),
            2
        );
        assert!(
            set.get_probe_history(node, ProbeDomain::DataUdp, IpVersion::V6)
                .is_empty()
        );
        assert!(
            set.get_probe_history(node, ProbeDomain::DnsUdp, IpVersion::V4)
                .is_empty()
        );
        assert_eq!(deaths.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(
            pushes.load(std::sync::atomic::Ordering::Relaxed),
            usize::from(!retire_in_resolver)
        );
    }
}

#[tokio::test]
async fn test_probe_node_udp_dns_blocked_but_data_path_ok_keeps_data_udp_alive() {
    let set = AliveDialerSet::new();
    // No register_node → outside the grace period, failures count
    // immediately. Probe failure threshold for the UDP domains is 3.
    set.set_udp_probe(Arc::new(MockUdpProber::dns_blocked_data_ok(
        Duration::from_millis(12),
    )));

    for _ in 0..3 {
        assert!(set.probe_node_udp(id(1), Duration::from_millis(200)).await);
    }
    for ipver in [IpVersion::V4, IpVersion::V6] {
        // The DNS check target is unreachable through the node: DnsUdp dies.
        assert!(!set.is_alive_for(id(1), ProbeDomain::DnsUdp, ipver));
        // The data path provably works: DataUdp stays alive, so the node
        // remains UDP-selectable and real traffic can flow.
        assert!(set.is_alive_for(id(1), ProbeDomain::DataUdp, ipver));
        assert_eq!(
            set.get_last_latency(id(1), ProbeDomain::DataUdp, ipver),
            Some(Duration::from_millis(12))
        );
    }
}

#[tokio::test]
async fn test_probe_node_udp_dns_skip_updates_only_measured_data_path() {
    let set = AliveDialerSet::new();
    set.set_udp_probe(Arc::new(MockUdpProber::dns_skipped_data_ok(
        Duration::from_millis(7),
    )));

    assert!(set.probe_node_udp(id(1), Duration::from_millis(20)).await);
    for ipver in [IpVersion::V4, IpVersion::V6] {
        assert_eq!(
            set.get_last_latency(id(1), ProbeDomain::DataUdp, ipver),
            Some(Duration::from_millis(7))
        );
        assert!(
            set.get_probe_history(id(1), ProbeDomain::DnsUdp, ipver)
                .is_empty()
        );
    }
}

#[tokio::test]
async fn test_probe_node_udp_success_marks_udp_domains_alive() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:1".into()));
    set.set_udp_probe(Arc::new(MockUdpProber::ok(Duration::from_millis(42))));

    assert!(!set.has_udp_state(id(1)));
    assert!(set.probe_node_udp(id(1), Duration::from_millis(200)).await);

    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        for ipver in [IpVersion::V4, IpVersion::V6] {
            assert!(
                set.is_alive_for(id(1), domain, ipver),
                "{domain:?}/{ipver:?} must be alive after a successful UDP probe"
            );
            assert_eq!(
                set.get_last_latency(id(1), domain, ipver),
                Some(Duration::from_millis(42))
            );
        }
    }
    assert!(set.has_udp_state(id(1)));
    // TCP state is untouched by the UDP probe.
    assert!(set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(
        set.get_last_latency(id(1), ProbeDomain::Tcp, IpVersion::V4),
        None
    );
}

#[tokio::test]
async fn test_probe_node_udp_failures_kill_udp_domains_only() {
    let set = AliveDialerSet::new();
    // No register_node → outside the grace period, failures count
    // immediately. Probe failure threshold for the UDP domains is 3.
    set.set_udp_probe(Arc::new(MockUdpProber::err("uot refused")));

    for i in 1..=2 {
        assert!(!set.probe_node_udp(id(1), Duration::from_millis(200)).await);
        assert!(
            set.is_alive_for(id(1), ProbeDomain::DataUdp, IpVersion::V4),
            "failure {i} must not kill DataUdp yet"
        );
        assert!(set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
    }
    assert!(!set.probe_node_udp(id(1), Duration::from_millis(200)).await);
    for ipver in [IpVersion::V4, IpVersion::V6] {
        assert!(!set.is_alive_for(id(1), ProbeDomain::DataUdp, ipver));
        assert!(!set.is_alive_for(id(1), ProbeDomain::DnsUdp, ipver));
    }
    // TCP domains are never touched by UDP probe failures.
    assert!(set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4));
    assert!(set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V6));
    assert!(set.has_udp_state(id(1)));

    // A later success revives both UDP domains immediately.
    set.set_udp_probe(Arc::new(MockUdpProber::ok(Duration::from_millis(10))));
    assert!(set.probe_node_udp(id(1), Duration::from_millis(200)).await);
    assert!(set.is_alive_for(id(1), ProbeDomain::DataUdp, IpVersion::V4));
    assert!(set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
}

#[tokio::test]
async fn test_probe_node_udp_timeout_counts_as_failure() {
    let set = AliveDialerSet::new();
    set.set_udp_probe(Arc::new(PendingUdpProber));
    assert!(!set.probe_node_udp(id(1), Duration::from_millis(20)).await);
    assert!(set.has_udp_state(id(1)));
    // One failure is below the threshold of 3 — still alive.
    assert!(set.is_alive_for(id(1), ProbeDomain::DataUdp, IpVersion::V4));
    assert!(
        !set.get_probe_history(id(1), ProbeDomain::DataUdp, IpVersion::V4)
            .is_empty()
    );
}

#[tokio::test]
async fn test_probe_node_udp_no_prober_is_noop() {
    let set = AliveDialerSet::new();
    assert!(!set.probe_node_udp(id(1), Duration::from_millis(20)).await);
    // Without an installed prober nothing is recorded, so the node
    // keeps the legacy TCP-fallback selection semantics.
    assert!(!set.has_udp_state(id(1)));
    assert!(set.is_alive_for(id(1), ProbeDomain::DataUdp, IpVersion::V4));
}

#[tokio::test]
async fn test_probe_node_udp_skipped_targets_are_neutral() {
    let set = AliveDialerSet::new();
    set.set_udp_probe(Arc::new(MockUdpProber::skipped()));

    assert!(!set.probe_node_udp(id(1), Duration::from_millis(20)).await);
    assert!(!set.has_udp_state(id(1)));
}

#[tokio::test]
async fn test_tcp_probe_failure_does_not_touch_udp() {
    let set = AliveDialerSet::new();
    // 127.0.0.1:1 refuses connections → the TCP probe fails.
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:1".into()));
    assert!(!set.probe_node(id(1), Duration::from_millis(100)).await);
    // The failure was recorded for TCP (history is written even inside
    // the registration grace period)…
    assert!(
        !set.get_probe_history(id(1), ProbeDomain::Tcp, IpVersion::V4)
            .is_empty()
    );
    // …but no UDP domain was touched.
    assert!(!set.has_udp_state(id(1)));
    assert!(set.is_alive_for(id(1), ProbeDomain::DataUdp, IpVersion::V4));
    assert!(set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
}

#[tokio::test]
async fn test_health_cycle_runs_udp_probe_after_tcp() {
    let set = std::sync::Arc::new(AliveDialerSet::new());
    set.register_node(id(1), "n1".into(), Some("127.0.0.1:1".into()));
    set.set_udp_probe(Arc::new(MockUdpProber::ok(Duration::from_millis(5))));

    set.run_health_check_cycle(Duration::from_millis(200)).await;

    // The cycle ran both probes: TCP failed (connection refused) and
    // the UDP probe succeeded through the mock.
    assert!(
        !set.get_probe_history(id(1), ProbeDomain::Tcp, IpVersion::V4)
            .is_empty()
    );
    assert_eq!(
        set.get_last_latency(id(1), ProbeDomain::DataUdp, IpVersion::V4),
        Some(Duration::from_millis(5))
    );
    assert!(set.has_udp_state(id(1)));
}

#[test]
fn test_has_udp_state_from_traffic_reports() {
    let set = AliveDialerSet::new();
    assert!(!set.has_udp_state(id(1)));
    set.report_unavailable_traffic(id(1), ProbeDomain::DataUdp, IpVersion::V4);
    assert!(set.has_udp_state(id(1)));
    // TCP-domain reports do not count as UDP state.
    let set2 = AliveDialerSet::new();
    set2.report_unavailable_traffic(id(1), ProbeDomain::Tcp, IpVersion::V4);
    assert!(!set2.has_udp_state(id(1)));
}

/// Stopped nodes (MAX_PROBE_BACKOFF_FAILURES consecutive failures) must
/// still probe once their (max_cooldown) backoff expires — permanent
/// starvation would make the recovery path unreachable and kill
/// single-member Selector groups forever.
#[test]
fn test_stopped_node_probes_on_slow_cadence_and_recovers() {
    let set = AliveDialerSet::new();
    // Unregistered → outside the grace period, failures count immediately.
    for _ in 0..10 {
        set.mark_dead(id(1));
    }
    let idx_domain = ProbeDomain::Tcp;
    assert!(set.is_probe_stopped(id(1), idx_domain, IpVersion::V4));
    // Deep backoff cooldown (300s) has not expired → no probe yet.
    assert!(!set.should_probe(id(1), idx_domain, IpVersion::V4));

    // Backdate the cooldown: a stopped node probes again on the slow
    // cadence (previously it never would).
    {
        let mut states = set.states.write();
        let entry = states.get_mut(&id(1)).unwrap();
        let idx = alive_index(idx_domain, IpVersion::V4);
        entry[idx].cooldown_until = Instant::now() - Duration::from_secs(1);
    }
    assert!(set.should_probe(id(1), idx_domain, IpVersion::V4));

    // Recovery hysteresis still applies: two consecutive successes revive
    // the node and clear the stopped flag.
    set.record_probe_latency(id(1), idx_domain, IpVersion::V4, Duration::from_millis(50));
    assert!(!set.is_alive_for(id(1), idx_domain, IpVersion::V4));
    set.record_probe_latency(id(1), idx_domain, IpVersion::V4, Duration::from_millis(50));
    assert!(set.is_alive_for(id(1), idx_domain, IpVersion::V4));
    assert!(!set.is_probe_stopped(id(1), idx_domain, IpVersion::V4));
}

/// The death callback fires on the probe-path alive→dead flip (per
/// domain/ip-version), not on repeated failures of an already-dead node.
#[test]
fn test_death_callback_fires_on_flip_only() {
    let set = AliveDialerSet::new();
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls2 = calls.clone();
    set.set_death_callback(Some(Box::new(move |node: Uuid, _name: &str| {
        calls2.lock().unwrap().push(node);
    })));

    // Unregistered → outside grace; TCP probe threshold is 3. mark_dead
    // covers both IP versions → one call per flipped (domain, ipver).
    set.mark_dead(id(1));
    assert!(
        calls.lock().unwrap().is_empty(),
        "no flip before the threshold"
    );
    set.mark_dead(id(1));
    set.mark_dead(id(1));
    assert_eq!(calls.lock().unwrap().len(), 2);

    // Already dead → no more calls for the same domains.
    set.mark_dead(id(1));
    assert_eq!(calls.lock().unwrap().len(), 2);

    // A different domain flips (UDP probe threshold is 3) → one more call.
    for _ in 0..3 {
        set.mark_dead_for(id(1), ProbeDomain::DataUdp, IpVersion::V4);
    }
    assert_eq!(calls.lock().unwrap().len(), 3);
}

/// A split UDP death must not fire the death callback while the sibling
/// UDP domain carries explicitly-alive state: purging would kill healthy
/// data-path flows. Once the sibling is dead too, the callback fires.
#[test]
fn test_death_callback_skipped_while_udp_sibling_alive() {
    let set = AliveDialerSet::new();
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls2 = calls.clone();
    set.set_death_callback(Some(Box::new(move |node: Uuid, _name: &str| {
        calls2.lock().unwrap().push(node);
    })));

    set.mark_alive_for(id(1), ProbeDomain::DataUdp, IpVersion::V4);
    for _ in 0..3 {
        set.mark_dead_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4);
    }
    assert!(!set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
    assert!(
        calls.lock().unwrap().is_empty(),
        "DnsUdp death with an explicitly-alive DataUdp must not purge"
    );

    for _ in 0..3 {
        set.mark_dead_for(id(1), ProbeDomain::DataUdp, IpVersion::V4);
    }
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "the purge fires once both UDP domains are dead"
    );
}

const HEALTH_LOG_CHILD: &str = "HONK_ALIVE_HEALTH_LOG_CHILD";

struct HealthFlipLogs {
    deaths: Arc<std::sync::atomic::AtomicUsize>,
    revivals: Arc<std::sync::atomic::AtomicUsize>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for HealthFlipLogs {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let metadata = event.metadata();
        if metadata.target() != "honk_outbound::alive::health" {
            return;
        }
        let counter = match *metadata.level() {
            tracing::Level::WARN => &self.deaths,
            tracing::Level::INFO => &self.revivals,
            _ => return,
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A death and a revival each log once, not once per failed or successful
/// report.
#[test]
fn test_health_flips_log_once() {
    if std::env::var_os(HEALTH_LOG_CHILD).is_some() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tracing_subscriber::prelude::*;
        let deaths = Arc::new(AtomicUsize::new(0));
        let revivals = Arc::new(AtomicUsize::new(0));
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(
            HealthFlipLogs {
                deaths: Arc::clone(&deaths),
                revivals: Arc::clone(&revivals),
            },
        ))
        .unwrap();
        let set = AliveDialerSet::new();
        // Unregistered → outside grace; the TCP probe threshold is 3.
        for _ in 0..5 {
            set.mark_dead_for(id(1), ProbeDomain::Tcp, IpVersion::V4);
        }
        assert!(!set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4));
        for _ in 0..2 {
            set.report_available_traffic(id(1), ProbeDomain::Tcp, IpVersion::V4);
        }
        assert!(set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4));
        assert_eq!(
            (
                deaths.load(Ordering::SeqCst),
                revivals.load(Ordering::SeqCst)
            ),
            (1, 1)
        );
        return;
    }

    // The child owns the global subscriber, so parallel tests cannot share
    // its callsite interest.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "alive::tests::test_health_flips_log_once",
            "--nocapture",
        ])
        .env(HEALTH_LOG_CHILD, "1")
        .output()
        .expect("isolated health log test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains(" 1 passed"),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Restored (persisted) delay samples seed ranking data without touching
/// liveness: an unknown node stays in its default alive state, and a
/// previously dead node stays dead.
#[test]
fn test_restore_latency_seeds_ranking_not_liveness() {
    let set = AliveDialerSet::new();
    let at = std::time::SystemTime::now();
    set.restore_latency(id(1), Duration::from_millis(88), at);

    // Ranking data present…
    assert_eq!(
        set.get_moving_average(id(1), ProbeDomain::Tcp, IpVersion::V4),
        Some(Duration::from_millis(88))
    );
    // …and visible as a real (non-synthetic) display sample.
    let (d, _t) = set
        .get_last_real_sample(id(1), ProbeDomain::Tcp, IpVersion::V4)
        .expect("restored sample");
    assert_eq!(d, Duration::from_millis(88));

    // A dead node is not revived by restoration.
    set.report_unavailable_forced(id(2), ProbeDomain::Tcp, IpVersion::V4);
    set.restore_latency(id(2), Duration::from_millis(50), at);
    assert!(!set.is_alive_for(id(2), ProbeDomain::Tcp, IpVersion::V4));
}

/// Per-(node, url) state is fully independent of the global six domains:
/// a node dead for one check URL stays alive globally and for other URLs.
#[test]
fn test_url_probe_state_independence() {
    let set = AliveDialerSet::new();
    let url_a = "http://a.example";
    let url_b = "http://b.example";

    set.record_url_probe_success("n1", url_a, Duration::from_millis(40));
    assert!(set.is_alive_for_url("n1", url_a));
    assert_eq!(
        set.get_avg_latency_for_url("n1", url_a),
        Some(Duration::from_millis(40))
    );

    // Three consecutive failures kill (TCP-probe parity) — for url_a only.
    set.record_url_probe_failure("n1", url_a);
    assert!(
        set.is_alive_for_url("n1", url_a),
        "one failure is not death"
    );
    set.record_url_probe_failure("n1", url_a);
    set.record_url_probe_failure("n1", url_a);
    assert!(!set.is_alive_for_url("n1", url_a));
    assert!(set.is_alive_for_url("n1", url_b), "other URL unaffected");
    assert!(
        set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4),
        "global TCP state unaffected"
    );

    // Recovery hysteresis: two consecutive successes.
    set.record_url_probe_success("n1", url_a, Duration::from_millis(50));
    assert!(!set.is_alive_for_url("n1", url_a));
    set.record_url_probe_success("n1", url_a, Duration::from_millis(50));
    assert!(set.is_alive_for_url("n1", url_a));
}

/// sync_group_check_urls drops registrations and prunes state for URLs
/// no longer used by any group.
#[test]
fn test_sync_group_check_urls_prunes_unused_urls() {
    let set = AliveDialerSet::new();
    let url_a = "http://a.example";
    set.sync_group_check_urls(&[("g1".into(), url_a.into())]);
    set.record_url_probe_failure("n1", url_a);
    assert!(set.has_url_state("n1", url_a));

    set.sync_group_check_urls(&[]);
    assert!(set.group_check_urls().is_empty());
    assert!(!set.has_url_state("n1", url_a), "unused URL state pruned");
}

/// block is exempt from probes — there is no liveness to measure. The
/// exemption must not touch any alive state (unknown defaults to alive).
#[tokio::test]
async fn test_block_probe_exempt() {
    let set = AliveDialerSet::new();
    set.register_node(BLOCK_NODE_ID, "block".into(), Some(String::new()));
    assert!(
        set.probe_node(BLOCK_NODE_ID, Duration::from_millis(1))
            .await
    );
    assert!(
        set.probe_node_udp(BLOCK_NODE_ID, Duration::from_millis(1))
            .await
    );
    assert!(
        set.probe_node_with_url(
            "block",
            BLOCK_NODE_ID,
            "http://x.example",
            Duration::from_millis(1),
            None,
        )
        .await
    );
    assert!(set.is_alive_for(BLOCK_NODE_ID, ProbeDomain::Tcp, IpVersion::V4));
}

/// block refuses flows by policy; those refusals must never mark it dead,
/// or a Selector choice of `block` would silently fall through to another
/// member once the strike threshold is reached.
#[test]
fn test_block_ignores_traffic_failures() {
    let set = AliveDialerSet::new();
    set.register_node(BLOCK_NODE_ID, "block".into(), Some(String::new()));
    for _ in 0..20 {
        set.report_unavailable_traffic(BLOCK_NODE_ID, ProbeDomain::Tcp, IpVersion::V4);
        set.report_unavailable_forced(BLOCK_NODE_ID, ProbeDomain::Tcp, IpVersion::V4);
        set.record_dial_failure(BLOCK_NODE_ID, ProbeDomain::Tcp, IpVersion::V4);
        set.mark_dead(BLOCK_NODE_ID);
    }
    assert!(set.is_alive_for(BLOCK_NODE_ID, ProbeDomain::Tcp, IpVersion::V4));
    assert!(set.is_alive_for(BLOCK_NODE_ID, ProbeDomain::Tcp, IpVersion::V6));
}

/// Builtins are the base layer: traffic failures (e.g. a LAN client
/// hammering unreachable P2P peers), probe deaths, forced marks, and dial
/// strikes must never change the direct liveness verdict — its death only
/// fail-closes native traffic at TC and ejects it from groups.
#[test]
fn test_direct_ignores_failure_marks() {
    let set = AliveDialerSet::new();
    set.register_node(DIRECT_NODE_ID, "direct".into(), Some(String::new()));
    // Age out of the registration grace period so non-forced failures count
    // (the incident vector was the traffic-failure threshold).
    set.node_registered_at
        .write()
        .insert(DIRECT_NODE_ID, Instant::now() - GRACE_PERIOD);
    for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        for ipver in [IpVersion::V4, IpVersion::V6] {
            for _ in 0..20 {
                set.report_unavailable_traffic(DIRECT_NODE_ID, domain, ipver);
                set.report_unavailable_forced(DIRECT_NODE_ID, domain, ipver);
                set.record_dial_failure(DIRECT_NODE_ID, domain, ipver);
                set.mark_dead_for(DIRECT_NODE_ID, domain, ipver);
            }
            set.mark_dead(DIRECT_NODE_ID);
            assert!(set.is_alive_for(DIRECT_NODE_ID, domain, ipver));
            assert!(!set.is_failure_demoted(DIRECT_NODE_ID, domain, ipver));
        }
    }
}

/// A custom-URL member whose tag died under a failing leaf recovers once
/// the member resolves to a builtin: the vacuous builtin "probe" advances
/// the (tag, url) state machine instead of leaving it dead forever.
#[tokio::test]
async fn test_builtin_leaf_probe_recovers_url_state() {
    let set = AliveDialerSet::new();
    let url = "http://check.example/";
    for _ in 0..3 {
        set.record_url_probe_failure("sub", url);
    }
    assert!(!set.is_alive_for_url("sub", url));

    assert!(
        set.probe_node_with_url("sub", DIRECT_NODE_ID, url, Duration::from_millis(1), None)
            .await
    );
    assert!(
        !set.is_alive_for_url("sub", url),
        "recovery keeps the two-success hysteresis"
    );
    assert!(
        set.probe_node_with_url("sub", DIRECT_NODE_ID, url, Duration::from_millis(1), None)
            .await
    );
    assert!(set.is_alive_for_url("sub", url));
    // No fake latency sample was recorded for the builtin.
    assert_eq!(set.get_avg_latency_for_url("sub", url), None);
}

/// direct is probed against the dedicated direct check target (bootstrap
/// resolver; default 223.5.5.5:53) instead of the proxy check URL, so the
/// clash API gets a real direct latency. Uses a loopback listener as the
/// target; per-group custom-URL and UDP probes stay exempt.
#[tokio::test]
async fn test_direct_probe_uses_direct_check_addr() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let set = AliveDialerSet::new();
    set.register_node(DIRECT_NODE_ID, "direct".into(), Some(String::new()));
    set.set_direct_check_addr(format!("127.0.0.1:{port}"));
    assert!(set.probe_node(DIRECT_NODE_ID, Duration::from_secs(2)).await);
    assert!(set.is_alive_for(DIRECT_NODE_ID, ProbeDomain::Tcp, IpVersion::V4));
    // UDP and per-group custom-URL probes remain exempt.
    assert!(
        set.probe_node_udp(DIRECT_NODE_ID, Duration::from_millis(1))
            .await
    );
    assert!(
        set.probe_node_with_url(
            "direct",
            DIRECT_NODE_ID,
            "http://x.example",
            Duration::from_millis(1),
            None,
        )
        .await
    );
}

/// Failure demotion is sticky: two consecutive dial failures add a strike
/// that only max(strikes, 2) consecutive real probe successes clear — one
/// lucky success never re-ranks a flaky node. A lone transient failure
/// leaves no strike at all.
#[test]
fn test_failure_demotion_needs_consecutive_successes() {
    let set = AliveDialerSet::new();
    let node = id(1);
    let probe_ok = |ms: u64| {
        set.record_probe_latency(
            node,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(ms),
        );
    };
    let demoted = || set.is_failure_demoted(node, ProbeDomain::Tcp, IpVersion::V4);

    probe_ok(10);
    assert!(!demoted());

    set.record_dial_failure(node, ProbeDomain::Tcp, IpVersion::V4);
    assert!(!demoted(), "a lone dial failure must not demote");
    set.record_dial_failure(node, ProbeDomain::Tcp, IpVersion::V4);
    assert!(demoted(), "two consecutive dial failures demote");
    probe_ok(10);
    assert!(demoted(), "one success must not clear the strike");
    probe_ok(10);
    assert!(!demoted(), "two consecutive successes clear it");

    // Once the failure streak is hot (no dial success intervened), further
    // failures keep striking; a fresh strike resets the clear progress, so
    // the success between the two strikes no longer counts toward the
    // clear.
    set.record_dial_failure(node, ProbeDomain::Tcp, IpVersion::V4);
    probe_ok(10);
    set.record_dial_failure(node, ProbeDomain::Tcp, IpVersion::V4);
    probe_ok(10);
    assert!(demoted(), "progress was reset by the second strike");
    probe_ok(10);
    assert!(!demoted());

    // Repeated failures cap at three strikes, so exactly three consecutive
    // probe successes clear even after many more failures.
    for _ in 0..8 {
        set.record_dial_failure(node, ProbeDomain::Tcp, IpVersion::V4);
    }
    probe_ok(10);
    probe_ok(10);
    assert!(demoted(), "the strike cap still requires three successes");
    probe_ok(10);
    assert!(!demoted());
}

/// A real dial success breaks the consecutive dial-failure streak: two
/// failures separated by a success never strike. Probe successes do NOT
/// reset the streak — a probe-alive but dial-dead node still accumulates.
#[test]
fn test_dial_success_resets_failure_streak() {
    let set = AliveDialerSet::new();
    let node = id(1);
    let demoted = || set.is_failure_demoted(node, ProbeDomain::Tcp, IpVersion::V4);

    set.record_dial_failure(node, ProbeDomain::Tcp, IpVersion::V4);
    set.report_available_traffic(node, ProbeDomain::Tcp, IpVersion::V4);
    set.record_dial_failure(node, ProbeDomain::Tcp, IpVersion::V4);
    assert!(
        !demoted(),
        "failures separated by a dial success never strike"
    );
    set.record_dial_failure(node, ProbeDomain::Tcp, IpVersion::V4);
    assert!(demoted());
}

#[test]
fn test_concurrent_dial_failures_cannot_collapse() {
    for _ in 0..64 {
        let collection = Arc::new(collection::DialerCollection::new());
        let start = Arc::new(std::sync::Barrier::new(3));
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let collection = Arc::clone(&collection);
                let start = Arc::clone(&start);
                scope.spawn(move || {
                    start.wait();
                    collection.record_dial_failure();
                });
            }
            start.wait();
        });
        assert!(
            collection.is_failure_demoted(),
            "two simultaneous failures must produce the threshold strike"
        );
    }
}

/// Real-traffic fast path: three consecutive dials far above the node's own
/// EMA demote it (synthetic strike + emergency-probe signal); mixed
/// fast/slow sequences never do.
#[test]
fn test_report_dial_latency_demotes_after_three_slow_dials() {
    let set = AliveDialerSet::new();
    let node = id(1);
    let report = |ms: u64| {
        set.report_dial_latency(
            node,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(ms),
        )
    };

    // Warmup: the EMA learns ~100ms without judging.
    assert!(!report(100));
    assert!(!report(100));
    assert!(!report(100));

    // 400ms > max(min(2×100, 100+500), 250) = 250ms → slow; two in a row are
    // not enough, the third consecutive one demotes.
    assert!(!report(400));
    assert!(!report(400));
    assert!(report(400), "third consecutive slow dial demotes");
    assert!(set.is_failure_demoted(node, ProbeDomain::Tcp, IpVersion::V4));

    // Streak resets on any fast dial: slow,slow,fast,slow,slow never
    // reaches three consecutive.
    let node2 = id(2);
    let report2 = |ms: u64| {
        set.report_dial_latency(
            node2,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(ms),
        )
    };
    report2(100);
    report2(100);
    report2(100);
    assert!(!report2(400));
    assert!(!report2(400));
    assert!(!report2(100), "fast dial resets the streak");
    assert!(!report2(400));
    assert!(!report2(400));
    assert!(!set.is_failure_demoted(node2, ProbeDomain::Tcp, IpVersion::V4));
}

/// Fast-node floor: a ~60ms-EMA incumbent roughly doubling under load
/// (~120ms dials) is normal, not degradation — the 250ms floor keeps the
/// threshold from collapsing to 2×EMA and flapping URLTest.
#[test]
fn test_report_dial_latency_floor_covers_fast_node_load_jitter() {
    let set = AliveDialerSet::new();
    let node = id(3);
    let report = |ms: u64| {
        set.report_dial_latency(
            node,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(ms),
        )
    };

    report(60);
    report(60);
    report(60);
    for _ in 0..10 {
        assert!(!report(120), "2×EMA below the 250ms floor is never slow");
    }
    assert!(!set.is_failure_demoted(node, ProbeDomain::Tcp, IpVersion::V4));

    // Real degradation past the floor still demotes in three dials.
    assert!(!report(400));
    assert!(!report(400));
    assert!(report(400));
}

/// Built-in direct/block nodes are exempt: local-egress latency is not
/// node quality.
#[test]
fn test_report_dial_latency_ignores_builtin_nodes() {
    let set = AliveDialerSet::new();
    for _ in 0..6 {
        assert!(!set.report_dial_latency(
            DIRECT_NODE_ID,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_secs(9),
        ));
        assert!(!set.report_dial_latency(
            BLOCK_NODE_ID,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_secs(9),
        ));
    }
}

#[test]
fn native_observations_exclude_legacy_and_preserve_zero_and_failures() {
    let set = AliveDialerSet::new();
    let node = id(1);
    set.register_node(node, "node".into(), Some("127.0.0.1:1".into()));
    let registration = set.registered.read().nodes.get(&node).cloned().unwrap();
    // In the past, so a later failure is not mistaken for a pre-step sample.
    let at = std::time::SystemTime::now() - Duration::from_secs(60);
    let zero = HealthObservation::probe(
        ProbeDomain::Tcp,
        HealthMeasurement::HttpHeaders,
        IpVersion::V4,
        Some(Duration::ZERO),
        at,
    );
    set.record_health_observation(node, Some(&registration), zero);
    assert!(set.health_observations(node).is_empty());
    set.enable_health_history();
    assert!(set.health_observations(node).is_empty());
    set.restore_latency(node, Duration::from_millis(8), at);
    set.record_probe_latency(
        node,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(9),
    );
    set.report_unavailable_forced(node, ProbeDomain::Tcp, IpVersion::V4);
    assert!(set.health_observations(node).is_empty());
    for _ in 0..1000 {
        set.record_health_observation(node, Some(&registration), zero);
    }
    assert_eq!(set.health_observations(node), vec![zero]);
    assert_eq!(zero.state, HealthState::Healthy);
    assert_eq!(zero.latency, Some(Duration::ZERO));
    let failed = HealthObservation::probe(
        ProbeDomain::Tcp,
        HealthMeasurement::HttpHeaders,
        IpVersion::V4,
        None,
        at + Duration::from_secs(1),
    );
    set.record_health_observation(node, Some(&registration), failed);
    set.record_health_observation(node, Some(&registration), zero);
    assert_eq!(set.health_observations(node), vec![failed]);
    assert_eq!(failed.state, HealthState::Unavailable);
    assert_eq!(failed.latency, None);
    assert_eq!(failed.error, Some("probe_failed"));
    set.remove_node(node);
    assert!(set.health_observations(node).is_empty());
}

#[tokio::test]
async fn native_udp_observations_precede_legacy_family_fanout() {
    struct QualifiedUdp;
    impl UdpProber for QualifiedUdp {
        fn probe_udp(
            &self,
            _: Uuid,
            _: Duration,
            _cancel: ProbeCancellation,
        ) -> Pin<Box<dyn Future<Output = UdpProbeOutcome> + Send + 'static>> {
            Box::pin(async {
                let at = std::time::SystemTime::now();
                UdpProbeOutcome {
                    dns: Some(Ok(Duration::from_millis(30))),
                    data_path: Some(Ok(Duration::from_millis(40))),
                    observations: [
                        Some(HealthObservation::probe(
                            ProbeDomain::DnsUdp,
                            HealthMeasurement::DnsRoundTrip,
                            IpVersion::V4,
                            Some(Duration::from_millis(3)),
                            at,
                        )),
                        Some(HealthObservation::probe(
                            ProbeDomain::DataUdp,
                            HealthMeasurement::QuicHandshake,
                            IpVersion::V6,
                            Some(Duration::from_millis(4)),
                            at,
                        )),
                    ],
                }
            })
        }
    }
    let set = AliveDialerSet::new();
    let node = id(1);
    set.register_node(node, "node".into(), Some("127.0.0.1:1".into()));
    set.enable_health_history();
    set.set_udp_probe(Arc::new(QualifiedUdp));
    assert!(set.probe_node_udp(node, Duration::from_secs(1)).await);
    let observations = set.health_observations(node);
    assert_eq!(observations.len(), 2);
    assert!(
        observations
            .iter()
            .any(|sample| sample.purpose == HealthPurpose::Dns
                && sample.ip_version == IpVersion::V4
                && sample.latency == Some(Duration::from_millis(3)))
    );
    assert!(
        observations
            .iter()
            .any(|sample| sample.purpose == HealthPurpose::Data
                && sample.ip_version == IpVersion::V6
                && sample.latency == Some(Duration::from_millis(4)))
    );
    assert_eq!(
        set.get_last_latency(node, ProbeDomain::DataUdp, IpVersion::V6),
        Some(Duration::from_millis(30))
    );
    assert_eq!(set.health_observations(node), observations);
}

#[tokio::test]
async fn native_custom_probe_retains_sampled_leaf_and_rejects_old_config() {
    for reload in [false, true] {
        let set = Arc::new(AliveDialerSet::new());
        set.enable_health_history();
        set.register_node(id(1), "old".into(), Some("127.0.0.1:1".into()));
        set.register_node(id(2), "new".into(), Some("127.0.0.1:2".into()));
        let url = "http://127.0.0.1/";
        set.sync_group_check_urls(&[("group".into(), url.into())]);
        let epoch = set.health_epoch().unwrap();
        let context = GroupProbeContext {
            group_id: id(3),
            member_id: id(4),
        };
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        set.set_http_probe(
            Arc::new(DelayedHttpProber {
                started: started.clone(),
                release: release.clone(),
                result: HttpProbeResult::WarmSuccess(Duration::from_millis(7)),
            }),
            url.into(),
            "HEAD".into(),
        )
        .await;
        let probe = tokio::spawn({
            let set = set.clone();
            async move {
                set.probe_node_with_url(
                    "sub",
                    id(1),
                    url,
                    Duration::from_secs(1),
                    Some((context, epoch)),
                )
                .await
            }
        });
        started.notified().await;
        set.set_url_member_resolver(Some(Arc::new(move |_| {
            vec![UrlProbeMember {
                tag: "sub".into(),
                leaf: id(2),
                native: Some(context),
            }]
        })));
        if reload {
            set.invalidate_group_health_observations();
        }
        release.notify_one();
        assert!(probe.await.unwrap());
        assert!(set.health_observations(id(1)).is_empty());
        assert!(set.health_observations(id(2)).is_empty());
        let samples = set.group_health_observations(id(3));
        if reload {
            assert!(samples.is_empty());
        } else {
            assert_eq!(samples.len(), 1);
            assert_eq!(samples[0].member_id, id(4));
            assert_eq!(samples[0].node_id, id(1));
            assert_eq!(
                samples[0].observation.latency,
                Some(Duration::from_millis(7))
            );
            set.remove_node(id(1));
            assert!(set.group_health_observations(id(3)).is_empty());
        }
    }
}

#[test]
fn native_group_retention_has_a_fixed_slot_bound() {
    let set = AliveDialerSet::new();
    set.enable_health_history();
    let node = id(1);
    let group = id(2);
    set.register_node(node, "node".into(), Some("127.0.0.1:1".into()));
    let registration = set.registered.read().nodes.get(&node).cloned().unwrap();
    let epoch = set.health_epoch().unwrap();
    let observation = HealthObservation::probe(
        ProbeDomain::Tcp,
        HealthMeasurement::HttpHeaders,
        IpVersion::V4,
        Some(Duration::ZERO),
        std::time::SystemTime::now(),
    );
    for member in (0..4096).chain([0, 4096]) {
        set.record_group_health_observation(
            node,
            Some(&registration),
            GroupProbeContext {
                group_id: group,
                member_id: id(member),
            },
            epoch,
            observation,
        );
    }
    let retained = set.group_health_observations(group);
    assert_eq!(retained.len(), 4096);
    assert!(retained.iter().any(|sample| sample.member_id == id(0)));
    assert!(!retained.iter().any(|sample| sample.member_id == id(1)));
    assert!(retained.iter().any(|sample| sample.member_id == id(4096)));
}

#[test]
fn native_group_publication_invalidates_evidence_before_target_sync() {
    let set = AliveDialerSet::new();
    set.enable_health_history();
    set.register_node(id(1), "node".into(), Some("127.0.0.1:1".into()));
    set.sync_group_check_urls(&[("group".into(), "http://old.example/".into())]);
    let registration = set.registered.read().nodes.get(&id(1)).cloned().unwrap();
    let context = GroupProbeContext {
        group_id: id(2),
        member_id: id(1),
    };
    let observation = HealthObservation::probe(
        ProbeDomain::Tcp,
        HealthMeasurement::HttpHeaders,
        IpVersion::V4,
        Some(Duration::ZERO),
        std::time::SystemTime::now(),
    );
    let old_epoch = set.health_epoch().unwrap();
    set.record_group_health_observation(
        id(1),
        Some(&registration),
        context,
        old_epoch,
        observation,
    );
    assert_eq!(set.group_health_observations(id(2)).len(), 1);
    set.record_health_observation(id(1), Some(&registration), observation);

    set.invalidate_group_health_observations();
    assert!(set.group_health_observations(id(2)).is_empty());
    set.record_group_health_observation(
        id(1),
        Some(&registration),
        context,
        old_epoch,
        observation,
    );
    assert!(set.group_health_observations(id(2)).is_empty());
    if let Some(epoch) = set.health_epoch() {
        set.record_group_health_observation(
            id(1),
            Some(&registration),
            context,
            epoch,
            observation,
        );
    }
    assert!(
        set.group_health_observations(id(2)).is_empty(),
        "old targets cannot acquire new observation authority"
    );
    assert_eq!(set.health_observations(id(1)), vec![observation]);
    assert_eq!(
        set.group_check_urls(),
        vec![("group".into(), "http://old.example/".into())]
    );

    set.sync_group_check_urls(&[("group".into(), "http://new.example/".into())]);
    let new_epoch = set.health_epoch().unwrap();
    set.record_group_health_observation(
        id(1),
        Some(&registration),
        context,
        new_epoch,
        observation,
    );
    assert_eq!(set.group_health_observations(id(2)).len(), 1);
}

struct JoinedSocketProbe {
    cleanup_started: Arc<tokio::sync::Notify>,
    cleanup_release: Arc<tokio::sync::Semaphore>,
    completed: tokio::sync::mpsc::UnboundedSender<Uuid>,
}

impl HttpProber for JoinedSocketProbe {
    fn probe_http(
        &self,
        node: Uuid,
        addr: SocketAddr,
        _: &str,
        _: Duration,
        cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = HttpProbeOutcome> + Send + 'static>> {
        let cleanup_started = Arc::clone(&self.cleanup_started);
        let cleanup_release = Arc::clone(&self.cleanup_release);
        let completed = self.completed.clone();
        Box::pin(async move {
            let mut children = tokio::task::JoinSet::new();
            children.spawn(async move {
                use tokio::io::AsyncReadExt;
                cancel
                    .run(async {
                        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
                        socket.read_u8().await.unwrap();
                    })
                    .await
            });
            let result = children.join_next().await.unwrap().unwrap();
            assert!(children.join_next().await.is_none());
            let result = if result.is_some() {
                HttpProbeResult::WarmSuccess(Duration::from_millis(1))
            } else {
                cleanup_started.notify_one();
                cleanup_release.acquire().await.unwrap().forget();
                HttpProbeResult::Cancelled
            };
            completed.send(node).unwrap();
            result.into()
        })
    }
}

#[tokio::test]
async fn health_shutdown_drains_nested_probe_and_stops_loop() {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(Duration::from_secs(15), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let set = Arc::new(AliveDialerSet::new());
        set.register_node(id(1), "first".into(), Some(addr.to_string()));
        set.enable_health_history();
        let ticket = set.probe_ticket(id(1));
        let sample = HealthObservation::probe(
            ProbeDomain::Tcp,
            HealthMeasurement::HttpHeaders,
            IpVersion::V4,
            Some(Duration::from_millis(7)),
            std::time::SystemTime::now(),
        );
        assert!(set.complete_probe(&ticket, None, sample));
        let context = GroupProbeContext {
            group_id: id(3),
            member_id: id(4),
        };
        assert!(set.complete_probe(&ticket, Some(context), sample));
        let cleanup_started = Arc::new(tokio::sync::Notify::new());
        let cleanup_release = Arc::new(tokio::sync::Semaphore::new(0));
        let (completed, mut completions) = tokio::sync::mpsc::unbounded_channel();
        set.set_http_probe(
            Arc::new(JoinedSocketProbe {
                cleanup_started: Arc::clone(&cleanup_started),
                cleanup_release: Arc::clone(&cleanup_release),
                completed,
            }),
            format!("http://{addr}/"),
            "HEAD".into(),
        )
        .await;
        let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        set.set_ebpf_callback(Box::new({
            let callbacks = Arc::clone(&callbacks);
            move |_, _, _, _, _| {
                callbacks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }));
        let owner = set.spawn_health_check_loop_concurrent(
            Duration::from_secs(3600),
            Duration::from_secs(30),
            1,
        );
        let (mut peer, _) = listener.accept().await.unwrap();
        set.register_node(id(2), "queued".into(), Some(addr.to_string()));
        set.trigger_probe(id(2));
        let shutdown = tokio::spawn({
            let set = Arc::clone(&set);
            async move { set.shutdown_health_checks().await }
        });
        cleanup_started.notified().await;
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        assert!(
            !shutdown.is_finished(),
            "cleanup completion is part of the ack"
        );
        assert!(!set.probe_node(id(2), Duration::from_secs(1)).await);
        cleanup_release.add_permits(1);
        shutdown.await.unwrap().unwrap();
        owner.await.unwrap();
        assert_eq!(completions.recv().await, Some(id(1)));
        assert!(
            completions.try_recv().is_err(),
            "queued triggers must not run after shutdown"
        );
        for node in [id(1), id(2)] {
            assert!(
                set.get_probe_history(node, ProbeDomain::Tcp, IpVersion::V4)
                    .is_empty()
            );
        }
        assert_eq!(callbacks.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(set.health_observations(id(1)), vec![sample]);
        assert_eq!(set.group_health_observations(id(3)).len(), 1);
        assert!(!set.complete_probe(&ticket, None, sample));
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn health_shutdown_timeout_keeps_admission_closed() {
    use futures_util::FutureExt as _;

    let set = AliveDialerSet::new();
    let permit = set.acquire_health_probe().unwrap();
    let old_cancel = permit.cancellation();
    let shutdown = set.shutdown_health_checks();
    tokio::pin!(shutdown);
    assert!(shutdown.as_mut().now_or_never().is_none());
    assert!(old_cancel.is_cancelled());
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(shutdown.as_mut().now_or_never().is_none());
    assert!(matches!(
        set.acquire_health_probe(),
        Err(HealthCheckError::Stopped)
    ));
    drop(permit);
    assert_eq!(shutdown.await, Err(HealthCheckError::DrainTimeout));
    set.shutdown_health_checks().await.unwrap();
    assert!(matches!(
        set.acquire_health_probe(),
        Err(HealthCheckError::Stopped)
    ));
}

#[tokio::test]
async fn health_external_jobs_survive_response_disconnect_and_join_on_shutdown() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let set = Arc::new(AliveDialerSet::new());
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut requests = Vec::new();
        for _ in 0..10 {
            let set = Arc::clone(&set);
            let started = started.clone();
            let completed = Arc::clone(&completed);
            requests.push(tokio::spawn(async move {
                set.run_external_probe(move |cancel| async move {
                    started.send(()).unwrap();
                    cancel.cancelled().await;
                    completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                })
                .await
            }));
            starts.recv().await.unwrap();
        }
        assert_eq!(
            set.run_external_probe(|_| async { 1 }).await,
            Err(HealthCheckError::Busy)
        );
        for request in requests {
            request.abort();
            let _ = request.await;
        }
        set.shutdown_health_checks().await.unwrap();
        assert_eq!(completed.load(std::sync::atomic::Ordering::SeqCst), 10);
        assert_eq!(
            set.run_external_probe(|_| async { 1 }).await,
            Err(HealthCheckError::Stopped)
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn health_shutdown_preserves_completed_failure_before_cancelled_retry() {
    struct RetryProbe(Arc<tokio::sync::Notify>, std::sync::atomic::AtomicUsize);
    impl HttpProber for RetryProbe {
        fn probe_http(
            &self,
            _: Uuid,
            _: SocketAddr,
            _: &str,
            _: Duration,
            cancel: ProbeCancellation,
        ) -> Pin<Box<dyn Future<Output = HttpProbeOutcome> + Send + 'static>> {
            let first = self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
            let started = Arc::clone(&self.0);
            Box::pin(async move {
                if first {
                    HttpProbeResult::ExchangeFailure("peer closed".into()).into()
                } else {
                    started.notify_one();
                    cancel.cancelled().await;
                    HttpProbeResult::Cancelled.into()
                }
            })
        }
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        let set = Arc::new(AliveDialerSet::new());
        let started = Arc::new(tokio::sync::Notify::new());
        set.register_node(id(1), "retry".into(), Some("127.0.0.1:1".into()));
        set.set_http_probe(
            Arc::new(RetryProbe(Arc::clone(&started), Default::default())),
            "http://127.0.0.1,127.0.0.2".into(),
            "HEAD".into(),
        )
        .await;
        let probe = tokio::spawn({
            let set = Arc::clone(&set);
            async move { set.probe_node(id(1), Duration::from_secs(1)).await }
        });
        started.notified().await;
        set.shutdown_health_checks().await.unwrap();
        assert!(!probe.await.unwrap());
        let history = set.get_probe_history(id(1), ProbeDomain::Tcp, IpVersion::V4);
        assert_eq!(history.len(), 1);
        assert!(!history[0].success);
    })
    .await
    .unwrap();
}

#[cfg(feature = "owned-tasks")]
#[tokio::test]
async fn health_shutdown_rejects_panicked_resolver_child() {
    let set = AliveDialerSet::new();
    set.enable_health_history();
    let permit = set.acquire_health_probe().unwrap();
    let cancel = permit.cancellation();
    let (started, receive) = tokio::sync::oneshot::channel();
    cancel
        .scope_resolution(async {
            crate::runtime::spawn_owned(async move {
                started.send(()).unwrap();
                panic!("resolver child failed");
            })
            .unwrap();
            Ok(())
        })
        .await
        .unwrap();
    receive.await.unwrap();
    drop(permit);
    assert_eq!(
        set.shutdown_health_checks().await,
        Err(HealthCheckError::WorkerFailed)
    );
    assert!(matches!(
        set.acquire_health_probe(),
        Err(HealthCheckError::WorkerFailed)
    ));
}

#[cfg(feature = "owned-tasks")]
#[tokio::test(start_paused = true)]
async fn health_shutdown_deadline_joins_blocking_resolver_before_returning_error() {
    use futures_util::FutureExt as _;
    use std::sync::atomic::{AtomicBool, Ordering};

    for panics in [false, true] {
        let set = AliveDialerSet::new();
        set.enable_health_history();
        let permit = set.acquire_health_probe().unwrap();
        let owner = set.health_resolver_tasks.lock().clone().unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let completed = Arc::new(AtomicBool::new(false));
        let child_completed = Arc::clone(&completed);
        let child = owner
            .spawn_blocking(move || {
                started.send(()).unwrap();
                let _ = released.recv();
                child_completed.store(true, Ordering::Release);
                assert!(!panics, "health resolver failed during late cleanup");
            })
            .unwrap();
        ready.await.unwrap();
        drop(permit);

        let shutdown = set.shutdown_health_checks();
        tokio::pin!(shutdown);
        assert!(shutdown.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(
            shutdown.as_mut().now_or_never().is_none(),
            "a missed deadline cannot finish before the blocking resolver joins"
        );
        assert!(!completed.load(Ordering::Acquire));
        assert!(matches!(
            set.acquire_health_probe(),
            Err(HealthCheckError::Stopped)
        ));

        release.send(()).unwrap();
        assert_eq!(
            shutdown.await,
            Err(if panics {
                HealthCheckError::WorkerFailed
            } else {
                HealthCheckError::DrainTimeout
            })
        );
        assert!(completed.load(Ordering::Acquire));
        assert!(child.is_finished());
        let expected = if panics {
            HealthCheckError::WorkerFailed
        } else {
            HealthCheckError::Stopped
        };
        assert!(matches!(set.acquire_health_probe(), Err(error) if error == expected));
    }
}

#[tokio::test]
async fn test_raw_probe_keeps_chain_health() {
    let set = AliveDialerSet::new();
    let node = Uuid::new_v4();
    set.register_node(node, "via".into(), None);
    set.set_resolver(Arc::new(|_, _| panic!("a chain has no raw TCP endpoint")));
    set.node_registered_at
        .write()
        .insert(node, Instant::now() - GRACE_PERIOD);
    let probe = || set.probe_node(node, Duration::from_millis(10));
    let families = [IpVersion::V4, IpVersion::V6];
    for _ in 0..probe_failure_threshold(ProbeDomain::Tcp) {
        assert!(probe().await);
    }
    for family in families {
        assert!(set.is_alive_for(node, ProbeDomain::Tcp, family));
        assert!(
            set.get_probe_history(node, ProbeDomain::Tcp, family)
                .is_empty()
        );
    }

    set.report_unavailable_forced(node, ProbeDomain::Tcp, IpVersion::V4);
    assert!(probe().await);
    set.report_unavailable_forced(node, ProbeDomain::Tcp, IpVersion::V6);
    assert!(!probe().await);
    for family in families {
        assert!(!set.is_alive_for(node, ProbeDomain::Tcp, family));
        assert_eq!(
            set.get_probe_history(node, ProbeDomain::Tcp, family).len(),
            1
        );
    }
}

/// Use a successful chain dial as the HTTP probe's sample.
struct GenerationDialProber {
    registry: Arc<crate::proxy::ProxyRegistry>,
    generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
}

impl HttpProber for GenerationDialProber {
    fn probe_http(
        &self,
        node_id: Uuid,
        addr: std::net::SocketAddr,
        _url: &str,
        timeout: Duration,
        _cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = HttpProbeOutcome> + Send + 'static>> {
        let registry = Arc::clone(&self.registry);
        let generation = Arc::clone(&self.generation);
        Box::pin(async move {
            match registry
                .dial_runtime(generation, node_id, addr, None, timeout)
                .await
            {
                Ok(_) => HttpProbeResult::WarmSuccess(Duration::from_millis(1)).into(),
                Err(error) => HttpProbeResult::SetupFailure(format!("{error:#}")).into(),
            }
        })
    }
}

/// Exit refusal and a subsequent successful dial are liveness evidence.
#[tokio::test]
async fn test_http_probe_moves_a_chain_between_dead_and_alive() {
    use crate::test_support::{chain, socks5, socks5_relay};
    use std::sync::atomic::Ordering;

    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let check = target.local_addr().unwrap();
    let exit = socks5_relay(Vec::new(), true).await;
    let entry = socks5_relay(Vec::new(), false).await;
    let front = socks5("front", "127.0.0.1", entry.addr.port());
    let land = socks5("land", "127.0.0.1", exit.addr.port());
    let via = chain(&[&front, &land]);
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(&[via.clone(), front, land]).unwrap(),
    );
    let set = AliveDialerSet::new();
    set.set_http_probe(
        Arc::new(GenerationDialProber {
            registry: Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
            generation,
        }),
        format!("http://{check}/"),
        "HEAD".into(),
    )
    .await;
    set.register_node(via.id, via.name.clone(), None);
    set.node_registered_at
        .write()
        .insert(via.id, Instant::now() - GRACE_PERIOD);
    let alive = || set.is_alive_for(via.id, ProbeDomain::Tcp, IpVersion::V4);
    let probe = || set.probe_node(via.id, Duration::from_secs(1));

    for _ in 0..probe_failure_threshold(ProbeDomain::Tcp) {
        assert!(!probe().await);
    }
    assert!(!alive());

    exit.refuse.store(false, Ordering::SeqCst);
    for _ in 0..RECOVERY_SUCCESSES_NEEDED {
        assert!(probe().await);
    }
    assert!(alive());

    exit.refuse.store(true, Ordering::SeqCst);
    for _ in 0..probe_failure_threshold(ProbeDomain::Tcp) {
        assert!(!probe().await);
    }
    assert!(!alive());
}

#[test]
fn test_idle_timeout_zero_suppresses_per_selection_probe_storm() {
    let set = AliveDialerSet::new();
    let zero_node = id(101);
    let timed_node = id(102);
    set.register_node(zero_node, "zero".into(), Some("127.0.0.1:1".into()));
    set.register_node(timed_node, "timed".into(), Some("127.0.0.1:1".into()));
    set.sync_idle_groups(&[
        idle_reg(
            "zero",
            vec![zero_node],
            Some(Duration::ZERO),
            IdleGroupKind::Automatic,
        ),
        idle_reg(
            "timed",
            vec![timed_node],
            Some(Duration::from_secs(60)),
            IdleGroupKind::Automatic,
        ),
    ]);
    let mut trigger_rx = set.take_trigger_rx().expect("trigger receiver");

    for _ in 0..10 {
        set.mark_group_active("zero");
    }
    assert!(set.is_group_idle("zero"));
    assert!(set.is_probe_suspended(zero_node));
    assert!(trigger_rx.try_recv().is_err());

    set.mark_group_active("timed");
    assert!(!set.is_group_idle("timed"));
    assert_eq!(trigger_rx.try_recv(), Ok(timed_node));
    set.finish_trigger_probe(timed_node);
    for _ in 0..10 {
        set.mark_group_active("timed");
    }
    assert!(trigger_rx.try_recv().is_err());
}

#[test]
fn test_set_selected_nodes_wakes_only_newly_added_idle_nodes_and_remove_cleans_up() {
    let set = Arc::new(AliveDialerSet::new());
    let (idle_a, idle_b, active_n, ungrouped) = (id(111), id(112), id(113), id(114));
    for (node, name) in [
        (idle_a, "idle_a"),
        (idle_b, "idle_b"),
        (active_n, "active_n"),
        (ungrouped, "ungrouped"),
    ] {
        set.register_node(node, name.into(), Some("127.0.0.1:1".into()));
    }
    set.sync_idle_groups(&[
        idle_reg(
            "g_idle",
            vec![idle_a, idle_b],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
        idle_reg(
            "g_active",
            vec![active_n],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
    ]);
    set.mark_group_active("g_active");

    let woken = set.set_selected_nodes(HashSet::from([idle_a, active_n, ungrouped]));
    assert_eq!(woken, vec![idle_a]);
    assert!(!set.is_probe_suspended(idle_a));
    assert!(set.is_probe_suspended(idle_b));

    let woken = set.set_selected_nodes(HashSet::from([idle_a, idle_b]));
    assert_eq!(woken, vec![idle_b]);
    assert!(!set.is_probe_suspended(idle_a));
    assert!(!set.is_probe_suspended(idle_b));

    let woken = set.set_selected_nodes(HashSet::from([idle_b]));
    assert!(woken.is_empty());
    assert!(set.is_probe_suspended(idle_a));
    assert!(!set.is_probe_suspended(idle_b));

    // Removing a selected node must drop its selected_nodes and idle_groups state.
    set.remove_node(idle_b);
    set.register_node(idle_b, "idle_b".into(), Some("127.0.0.1:1".into()));
    set.register_idle_group("g_re", &[idle_b], Some(Duration::from_secs(3600)));
    assert!(set.is_probe_suspended(idle_b));

    // Concurrent updates must stay consistent without lost writes or panics.
    let threads: Vec<_> = (0..4)
        .map(|worker| {
            let set = Arc::clone(&set);
            std::thread::spawn(move || {
                for step in 0..100 {
                    let target = if (worker + step) % 2 == 0 {
                        idle_a
                    } else {
                        idle_b
                    };
                    let _ = set.replace_selected_nodes(HashSet::from([target]));
                }
            })
        })
        .collect();
    for handle in threads {
        handle.join().unwrap();
    }
    let selected_count =
        usize::from(!set.is_probe_suspended(idle_a)) + usize::from(!set.is_probe_suspended(idle_b));
    assert_eq!(selected_count, 1);
}

struct RecordingHttpProber {
    calls: Arc<Mutex<Vec<(Uuid, String)>>>,
}

impl HttpProber for RecordingHttpProber {
    fn probe_http(
        &self,
        node_id: Uuid,
        _addr: std::net::SocketAddr,
        url: &str,
        _timeout: Duration,
        _cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = HttpProbeOutcome> + Send + 'static>> {
        self.calls.lock().push((node_id, url.to_owned()));
        Box::pin(async { HttpProbeResult::WarmSuccess(Duration::from_millis(5)).into() })
    }
}

struct RecordingUdpProber {
    calls: Arc<Mutex<Vec<Uuid>>>,
}

impl UdpProber for RecordingUdpProber {
    fn probe_udp(
        &self,
        node_id: Uuid,
        _timeout: Duration,
        _cancel: ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = UdpProbeOutcome> + Send + 'static>> {
        self.calls.lock().push(node_id);
        Box::pin(async {
            UdpProbeOutcome {
                dns: Some(Ok(Duration::from_millis(5))),
                data_path: None,
                observations: [None, None],
            }
        })
    }
}

#[tokio::test]
async fn test_idle_recovery_targets_only_unreachable_automatic_groups() {
    let set = Arc::new(AliveDialerSet::new());
    let tcp_calls = Arc::new(Mutex::new(Vec::new()));
    let udp_calls = Arc::new(Mutex::new(Vec::new()));
    set.set_http_probe(
        Arc::new(RecordingHttpProber {
            calls: Arc::clone(&tcp_calls),
        }),
        "http://127.0.0.1/".into(),
        "HEAD".into(),
    )
    .await;
    set.set_udp_probe(Arc::new(RecordingUdpProber {
        calls: Arc::clone(&udp_calls),
    }));

    let (v4_only, dns_blocked, dead_sib, alive_sib, sel_dead, all_dead) =
        (id(201), id(202), id(203), id(204), id(205), id(206));
    for (node, name) in [
        (v4_only, "v4_only"),
        (dns_blocked, "dns_blocked"),
        (dead_sib, "dead_sib"),
        (alive_sib, "alive_sib"),
        (sel_dead, "sel_dead"),
        (all_dead, "all_dead"),
    ] {
        set.register_node(node, name.into(), Some("127.0.0.1:1".into()));
    }
    set.sync_idle_groups(&[
        idle_reg(
            "g_v4",
            vec![v4_only],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
        idle_reg(
            "g_dns",
            vec![dns_blocked],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
        idle_reg(
            "g_partial",
            vec![dead_sib, alive_sib],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
        idle_reg(
            "g_sel",
            vec![sel_dead],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Selector,
        ),
        idle_reg(
            "g_dead",
            vec![all_dead],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
    ]);

    let kill_ready = |node: Uuid, domain: ProbeDomain, ipver: IpVersion| {
        set.report_unavailable_forced(node, domain, ipver);
        let mut states = set.states.write();
        let entry = &mut states.get_mut(&node).unwrap()[alive_index(domain, ipver)];
        entry.consecutive_successes = RECOVERY_SUCCESSES_NEEDED - 1;
        entry.cooldown_until = Instant::now();
    };

    // IPv4-only: V6 dead, V4 alive.
    kill_ready(v4_only, ProbeDomain::Tcp, IpVersion::V6);
    // DNS-UDP blocked: DnsUdp dead, DataUdp alive.
    kill_ready(dns_blocked, ProbeDomain::DnsUdp, IpVersion::V4);
    kill_ready(dns_blocked, ProbeDomain::DnsUdp, IpVersion::V6);
    // Partial-dead group and unselected Selector: both families dead on TCP and DataUdp.
    for node in [dead_sib, sel_dead, all_dead] {
        for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp] {
            for ipver in [IpVersion::V4, IpVersion::V6] {
                kill_ready(node, domain, ipver);
            }
        }
    }

    set.run_recovery_check_cycle_concurrent(Duration::from_secs(1), 4)
        .await;

    let probed_tcp: Vec<Uuid> = tcp_calls.lock().iter().map(|(id, _)| *id).collect();
    let probed_udp: Vec<Uuid> = udp_calls.lock().clone();
    assert_eq!(probed_tcp, vec![all_dead]);
    assert_eq!(probed_udp, vec![all_dead]);
    assert!(set.is_alive_for(all_dead, ProbeDomain::Tcp, IpVersion::V4));
    assert!(set.is_alive_for(all_dead, ProbeDomain::DataUdp, IpVersion::V4));
}

#[tokio::test]
async fn test_custom_check_url_idle_recovery_and_pinned_exemption() {
    let set = Arc::new(AliveDialerSet::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    set.set_http_probe(
        Arc::new(RecordingHttpProber {
            calls: Arc::clone(&calls),
        }),
        "http://127.0.0.1/global".into(),
        "HEAD".into(),
    )
    .await;

    let (dead_a, dead_b, part_dead, part_alive, pin_node, pin_other) =
        (id(211), id(212), id(213), id(214), id(215), id(216));
    for (node, name) in [
        (dead_a, "dead_a"),
        (dead_b, "dead_b"),
        (part_dead, "part_dead"),
        (part_alive, "part_alive"),
        (pin_node, "pin_node"),
        (pin_other, "pin_other"),
    ] {
        set.register_node(node, name.into(), Some("127.0.0.1:1".into()));
    }
    set.sync_idle_groups(&[
        idle_reg(
            "g_dead",
            vec![dead_a, dead_b],
            Some(Duration::ZERO),
            IdleGroupKind::Automatic,
        ),
        idle_reg(
            "g_partial",
            vec![part_dead, part_alive],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
        idle_reg(
            "g_pinned",
            vec![pin_node, pin_other],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
        idle_reg(
            "g_shared_unpinned",
            vec![pin_node],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
    ]);
    let (url_dead, url_partial, url_pinned, url_other) = (
        "http://127.0.0.1/dead",
        "http://127.0.0.1/partial",
        "http://127.0.0.1/pinned",
        "http://127.0.0.1/other",
    );
    set.sync_group_check_urls(&[
        ("g_dead".into(), url_dead.into()),
        ("g_partial".into(), url_partial.into()),
        ("g_pinned".into(), url_pinned.into()),
        ("g_shared_unpinned".into(), url_other.into()),
    ]);
    let member = |tag: &str, leaf: Uuid| UrlProbeMember {
        tag: tag.to_owned(),
        leaf,
        native: None,
    };
    set.set_url_member_resolver(Some(Arc::new(move |group| match group {
        "g_dead" => vec![member("dead_a", dead_a), member("dead_b", dead_b)],
        "g_partial" => vec![
            member("part_dead", part_dead),
            member("part_alive", part_alive),
        ],
        "g_pinned" => vec![member("pin_node", pin_node), member("pin_other", pin_other)],
        "g_shared_unpinned" => vec![member("pin_node", pin_node)],
        _ => Vec::new(),
    })));
    set.replace_pinned_url_members(HashMap::from([(
        "g_pinned".into(),
        HashSet::from(["pin_node".into()]),
    )]));

    // Periodic cycle probes only the pinned member in its own custom-URL group.
    set.run_health_check_cycle_concurrent(Duration::from_secs(1), 4)
        .await;
    assert_eq!(
        calls.lock().as_slice(),
        &[(pin_node, url_pinned.to_owned())]
    );
    calls.lock().clear();

    let kill_url_ready = |tag: &str, url: &str| {
        for _ in 0..probe_failure_threshold(ProbeDomain::Tcp) {
            set.record_url_probe_failure(tag, url);
        }
        let mut states = set.url_states.write();
        let entry = states.get_mut(&(tag.to_owned(), url.to_owned())).unwrap();
        entry.consecutive_successes = RECOVERY_SUCCESSES_NEEDED - 1;
        entry.cooldown_until = Instant::now();
    };
    kill_url_ready("dead_a", url_dead);
    kill_url_ready("dead_b", url_dead);
    kill_url_ready("part_dead", url_partial);
    kill_url_ready("pin_node", url_pinned);

    // Recovery revives the all-dead (idle_timeout=0) group and the dead pinned
    // member, while skipping the partial-dead idle group and unrelated group.
    set.run_recovery_check_cycle_concurrent(Duration::from_secs(1), 4)
        .await;
    let mut probed: Vec<_> = calls.lock().clone();
    probed.sort();
    let mut expected = vec![
        (dead_a, url_dead.to_owned()),
        (dead_b, url_dead.to_owned()),
        (pin_node, url_pinned.to_owned()),
    ];
    expected.sort();
    assert_eq!(probed, expected);
    assert!(set.is_alive_for_url("dead_a", url_dead));
    assert!(set.is_alive_for_url("dead_b", url_dead));
    assert!(set.is_alive_for_url("pin_node", url_pinned));
    assert!(!set.is_alive_for_url("part_dead", url_partial));
}

#[test]
fn test_notify_network_change_skips_healthy_idle_nodes_and_resets_url_backoff() {
    let set = AliveDialerSet::new();
    let mut idle_members = Vec::new();
    for index in 0..300u128 {
        let node = id(1000 + index);
        set.register_node(node, format!("idle-{index}"), Some("127.0.0.1:1".into()));
        idle_members.push(node);
    }
    let active_node = id(2001);
    let selected_node = id(2002);
    let all_dead_node = id(2003);
    for (node, name) in [
        (active_node, "active"),
        (selected_node, "selected"),
        (all_dead_node, "all_dead"),
    ] {
        set.register_node(node, name.into(), Some("127.0.0.1:1".into()));
    }
    set.sync_idle_groups(&[
        idle_reg(
            "g_idle",
            idle_members.clone(),
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
        idle_reg(
            "g_active",
            vec![active_node],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
        idle_reg(
            "g_sel",
            vec![selected_node],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Selector,
        ),
        idle_reg(
            "g_dead",
            vec![all_dead_node],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
    ]);
    set.mark_group_active("g_active");
    let _ = set.set_selected_nodes(HashSet::from([selected_node]));
    for ipver in [IpVersion::V4, IpVersion::V6] {
        set.report_unavailable_forced(all_dead_node, ProbeDomain::Tcp, ipver);
    }
    // Give both a suspended node and a custom check_url state a future backoff.
    let future = Instant::now() + Duration::from_secs(300);
    set.states.write().get_mut(&idle_members[0]).unwrap()
        [alive_index(ProbeDomain::Tcp, IpVersion::V4)]
    .cooldown_until = future;
    set.record_url_probe_failure("tag", "http://127.0.0.1/custom");
    set.url_states
        .write()
        .get_mut(&("tag".into(), "http://127.0.0.1/custom".into()))
        .unwrap()
        .cooldown_until = future;
    assert!(!set.should_probe(idle_members[0], ProbeDomain::Tcp, IpVersion::V4));
    assert!(!set.should_probe_url("tag", "http://127.0.0.1/custom"));

    let mut trigger_rx = set.take_trigger_rx().expect("trigger receiver");
    // Drain the earlier mark_group_active wake for active_node.
    while trigger_rx.try_recv().is_ok() {}
    set.finish_trigger_probe(active_node);

    set.notify_network_change();

    assert!(set.should_probe(idle_members[0], ProbeDomain::Tcp, IpVersion::V4));
    assert!(set.should_probe_url("tag", "http://127.0.0.1/custom"));
    let mut queued = HashSet::new();
    while let Ok(node) = trigger_rx.try_recv() {
        queued.insert(node);
    }
    assert_eq!(
        queued,
        HashSet::from([active_node, selected_node, all_dead_node])
    );
}

#[tokio::test(start_paused = true)]
async fn test_mark_group_active_wakes_custom_url_async_and_respects_zero_timeout_and_builtins() {
    use honk_config::config::{BLOCK_NODE_ID, DIRECT_NODE_ID};
    use std::sync::atomic::AtomicBool;

    let set = Arc::new(AliveDialerSet::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    set.set_http_probe(
        Arc::new(RecordingHttpProber {
            calls: Arc::clone(&calls),
        }),
        "http://127.0.0.1/global".into(),
        "HEAD".into(),
    )
    .await;

    let (direct_member, sub_leaf) = (id(221), id(222));

    // Direct trigger-queue check: mark_group_active must queue only non-builtin
    // members and never enqueue DIRECT_NODE_ID or BLOCK_NODE_ID.
    {
        let queue_set = AliveDialerSet::new();
        queue_set.sync_idle_groups(&[IdleGroupRegistration {
            name: "custom_auto".into(),
            members: vec![direct_member, DIRECT_NODE_ID, BLOCK_NODE_ID],
            idle_timeout: Some(Duration::from_secs(3600)),
            kind: IdleGroupKind::Automatic,
            tcp_recovery_members: vec![direct_member],
            udp_recovery_members: vec![direct_member],
        }]);
        let mut trigger_rx = queue_set.take_trigger_rx().expect("trigger receiver");
        queue_set.mark_group_active("custom_auto");
        let mut queued = Vec::new();
        while let Ok(node) = trigger_rx.try_recv() {
            queued.push(node);
        }
        assert_eq!(
            queued,
            vec![direct_member],
            "mark_group_active must queue only direct proxy members, never builtins"
        );
    }

    set.register_node(direct_member, "direct_m".into(), Some("127.0.0.1:1".into()));
    set.register_node(sub_leaf, "sub_leaf".into(), Some("127.0.0.1:1".into()));
    set.register_node(DIRECT_NODE_ID, "direct".into(), None);
    set.register_node(BLOCK_NODE_ID, "block".into(), None);

    let url = "http://127.0.0.1/custom-wake";
    set.sync_idle_groups(&[IdleGroupRegistration {
        name: "custom_auto".into(),
        members: vec![direct_member, DIRECT_NODE_ID, BLOCK_NODE_ID],
        idle_timeout: Some(Duration::from_secs(3600)),
        kind: IdleGroupKind::Automatic,
        tcp_recovery_members: vec![direct_member, sub_leaf],
        udp_recovery_members: vec![direct_member, sub_leaf],
    }]);
    set.sync_group_check_urls(&[("custom_auto".into(), url.into())]);

    let forbid_sync_resolver = Arc::new(AtomicBool::new(false));
    let resolver_flag = Arc::clone(&forbid_sync_resolver);
    set.set_url_member_resolver(Some(Arc::new(move |group| {
        assert!(
            !resolver_flag.load(Ordering::Acquire),
            "mark_group_active must never call url_member_resolver synchronously"
        );
        if group == "custom_auto" {
            vec![
                UrlProbeMember {
                    tag: "direct_m".into(),
                    leaf: direct_member,
                    native: None,
                },
                UrlProbeMember {
                    tag: "sub".into(),
                    leaf: sub_leaf,
                    native: None,
                },
            ]
        } else {
            Vec::new()
        }
    })));

    // Give subgroup custom-URL state a future cooldown before wake.
    set.record_url_probe_failure("sub", url);
    set.url_states
        .write()
        .get_mut(&("sub".into(), url.into()))
        .unwrap()
        .cooldown_until = Instant::now() + Duration::from_secs(300);
    assert!(!set.should_probe_url("sub", url));

    let loop_task = set.spawn_health_check_loop_concurrent(
        Duration::from_secs(3600),
        Duration::from_secs(1),
        2,
    );
    // Advance past initial stagger jitter while idle so periodic ticker is 3600s away.
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;
    assert!(calls.lock().is_empty());

    // Activating the group resets custom-URL cooldown and queues async wake without
    // invoking url_member_resolver synchronously or waking builtins.
    forbid_sync_resolver.store(true, Ordering::Release);
    set.mark_group_active("custom_auto");
    forbid_sync_resolver.store(false, Ordering::Release);
    assert!(set.should_probe_url("sub", url));

    let mut woke = false;
    for _ in 0..20 {
        {
            let recorded = calls.lock();
            if recorded
                .iter()
                .any(|(id, u)| *id == direct_member && u == "http://127.0.0.1/global")
                && recorded
                    .iter()
                    .any(|(id, u)| *id == direct_member && u == url)
                && recorded.iter().any(|(id, u)| *id == sub_leaf && u == url)
            {
                woke = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        woke,
        "async custom-URL wake must probe both direct and subgroup members before periodic tick"
    );

    set.shutdown_health_checks().await.unwrap();
    loop_task.await.unwrap();

    // After draining all emergency workers: each member must be probed against
    // the custom check_url exactly once (no duplicate probe bypassing hysteresis).
    {
        let recorded = calls.lock();
        assert_eq!(
            recorded
                .iter()
                .filter(|(id, u)| *id == direct_member && u == url)
                .count(),
            1,
            "direct member must be probed exactly once against custom check_url on wake"
        );
        assert_eq!(
            recorded
                .iter()
                .filter(|(id, u)| *id == sub_leaf && u == url)
                .count(),
            1,
            "subgroup member must be probed exactly once against custom check_url on wake"
        );
    }

    // Hot-reloading an active group to idle_timeout=0 clears its activity timestamp,
    // so reloading back to a positive timeout stays idle rather than resurrecting it.
    assert!(!set.is_group_idle("custom_auto"));
    set.sync_idle_groups(&[idle_reg(
        "custom_auto",
        vec![direct_member],
        Some(Duration::ZERO),
        IdleGroupKind::Automatic,
    )]);
    assert!(set.is_group_idle("custom_auto"));
    set.sync_idle_groups(&[idle_reg(
        "custom_auto",
        vec![direct_member],
        Some(Duration::from_secs(1800)),
        IdleGroupKind::Automatic,
    )]);
    assert!(set.is_group_idle("custom_auto"));
}

#[tokio::test]
async fn test_idle_recovery_matches_datapath_reachability() {
    use honk_config::config::{BLOCK_NODE_ID, DIRECT_NODE_ID};

    let set = Arc::new(AliveDialerSet::new());
    let tcp_calls = Arc::new(Mutex::new(Vec::new()));
    let udp_calls = Arc::new(Mutex::new(Vec::new()));
    set.set_http_probe(
        Arc::new(RecordingHttpProber {
            calls: Arc::clone(&tcp_calls),
        }),
        "http://127.0.0.1/".into(),
        "HEAD".into(),
    )
    .await;
    set.set_udp_probe(Arc::new(RecordingUdpProber {
        calls: Arc::clone(&udp_calls),
    }));

    let (tcp_only, udp_dead, v4_dead_v6_alive, v4_alive_v6_dead, zero_proxy, dead_direct, sub_leaf) = (
        id(231),
        id(232),
        id(233),
        id(234),
        id(235),
        id(236),
        id(237),
    );
    for (node, name) in [
        (tcp_only, "tcp_only"),
        (udp_dead, "udp_dead"),
        (v4_dead_v6_alive, "v4_dead_v6_alive"),
        (v4_alive_v6_dead, "v4_alive_v6_dead"),
        (zero_proxy, "zero_proxy"),
        (dead_direct, "dead_direct"),
        (sub_leaf, "sub_leaf"),
    ] {
        set.register_node(node, name.into(), Some("127.0.0.1:1".into()));
    }
    set.register_node(DIRECT_NODE_ID, "direct".into(), None);
    set.register_node(BLOCK_NODE_ID, "block".into(), None);

    set.sync_idle_groups(&[
        // Mixed TCP-only + UDP-capable group: UDP recovery must ignore TCP-only node.
        IdleGroupRegistration {
            name: "g_mixed".into(),
            members: vec![tcp_only, udp_dead],
            idle_timeout: Some(Duration::from_secs(3600)),
            kind: IdleGroupKind::Automatic,
            tcp_recovery_members: vec![tcp_only, udp_dead],
            udp_recovery_members: vec![udp_dead],
        },
        // IPv4-dead / IPv6-alive: TC closes (domain, V4), so V4 must recover.
        idle_reg(
            "g_v4_dead",
            vec![v4_dead_v6_alive],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
        // IPv4-alive / IPv6-dead: TC allows V6→V4 fallback, so stays silent.
        idle_reg(
            "g_v6_dead",
            vec![v4_alive_v6_dead],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
        // idle_timeout=0 with final: direct/block: builtins excluded from recovery liveness.
        IdleGroupRegistration {
            name: "g_zero_final".into(),
            members: vec![zero_proxy, DIRECT_NODE_ID, BLOCK_NODE_ID],
            idle_timeout: Some(Duration::ZERO),
            kind: IdleGroupKind::Automatic,
            tcp_recovery_members: vec![zero_proxy, DIRECT_NODE_ID],
            udp_recovery_members: vec![zero_proxy, BLOCK_NODE_ID],
        },
        // Dead direct member + alive subgroup leaf: stays silent until subgroup also dies.
        IdleGroupRegistration {
            name: "g_parent".into(),
            members: vec![dead_direct],
            idle_timeout: Some(Duration::from_secs(3600)),
            kind: IdleGroupKind::Automatic,
            tcp_recovery_members: vec![dead_direct, sub_leaf],
            udp_recovery_members: vec![dead_direct, sub_leaf],
        },
        idle_reg(
            "g_sub",
            vec![sub_leaf],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
    ]);

    let kill_ready = |node: Uuid, domain: ProbeDomain, ipver: IpVersion| {
        set.report_unavailable_forced(node, domain, ipver);
        let mut states = set.states.write();
        let entry = &mut states.get_mut(&node).unwrap()[alive_index(domain, ipver)];
        entry.consecutive_successes = RECOVERY_SUCCESSES_NEEDED - 1;
        entry.cooldown_until = Instant::now();
    };

    kill_ready(udp_dead, ProbeDomain::DataUdp, IpVersion::V4);
    kill_ready(v4_dead_v6_alive, ProbeDomain::Tcp, IpVersion::V4);
    kill_ready(v4_dead_v6_alive, ProbeDomain::DataUdp, IpVersion::V4);
    kill_ready(v4_alive_v6_dead, ProbeDomain::Tcp, IpVersion::V6);
    kill_ready(v4_alive_v6_dead, ProbeDomain::DataUdp, IpVersion::V6);
    kill_ready(zero_proxy, ProbeDomain::Tcp, IpVersion::V4);
    kill_ready(zero_proxy, ProbeDomain::DataUdp, IpVersion::V4);
    kill_ready(dead_direct, ProbeDomain::Tcp, IpVersion::V4);
    kill_ready(dead_direct, ProbeDomain::DataUdp, IpVersion::V4);

    set.run_recovery_check_cycle_concurrent(Duration::from_secs(1), 4)
        .await;

    let probed_tcp: HashSet<Uuid> = tcp_calls.lock().iter().map(|(id, _)| *id).collect();
    let probed_udp: HashSet<Uuid> = udp_calls.lock().iter().copied().collect();
    assert_eq!(probed_tcp, HashSet::from([v4_dead_v6_alive, zero_proxy]));
    assert_eq!(
        probed_udp,
        HashSet::from([udp_dead, v4_dead_v6_alive, zero_proxy])
    );
    assert!(set.is_alive_for(udp_dead, ProbeDomain::DataUdp, IpVersion::V4));
    assert!(set.is_alive_for(v4_dead_v6_alive, ProbeDomain::Tcp, IpVersion::V4));
    assert!(set.is_alive_for(zero_proxy, ProbeDomain::Tcp, IpVersion::V4));
    assert!(!set.is_alive_for(dead_direct, ProbeDomain::Tcp, IpVersion::V4));

    // Once the subgroup leaf also dies on V4, both parent's direct member and subgroup recover.
    tcp_calls.lock().clear();
    udp_calls.lock().clear();
    kill_ready(sub_leaf, ProbeDomain::Tcp, IpVersion::V4);
    kill_ready(sub_leaf, ProbeDomain::DataUdp, IpVersion::V4);
    set.run_recovery_check_cycle_concurrent(Duration::from_secs(1), 4)
        .await;
    let probed_tcp: HashSet<Uuid> = tcp_calls.lock().iter().map(|(id, _)| *id).collect();
    let probed_udp: HashSet<Uuid> = udp_calls.lock().iter().copied().collect();
    assert_eq!(probed_tcp, HashSet::from([dead_direct, sub_leaf]));
    assert_eq!(probed_udp, HashSet::from([dead_direct, sub_leaf]));
}

#[tokio::test(start_paused = true)]
async fn test_emergency_trigger_and_network_change_recover_all_dead_custom_check_url_group() {
    let set = Arc::new(AliveDialerSet::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    set.set_http_probe(
        Arc::new(RecordingHttpProber {
            calls: Arc::clone(&calls),
        }),
        "http://127.0.0.1/global".into(),
        "HEAD".into(),
    )
    .await;

    let (dead_a, dead_b, part_dead, part_alive) = (id(241), id(242), id(243), id(244));
    for (node, name) in [
        (dead_a, "dead_a"),
        (dead_b, "dead_b"),
        (part_dead, "part_dead"),
        (part_alive, "part_alive"),
    ] {
        set.register_node(node, name.into(), Some("127.0.0.1:1".into()));
    }
    let url_dead = "http://127.0.0.1/zero-all-dead";
    let url_partial = "http://127.0.0.1/partial-idle";
    set.sync_idle_groups(&[
        idle_reg(
            "g_zero_dead",
            vec![dead_a, dead_b],
            Some(Duration::ZERO),
            IdleGroupKind::Automatic,
        ),
        idle_reg(
            "g_partial",
            vec![part_dead, part_alive],
            Some(Duration::from_secs(3600)),
            IdleGroupKind::Automatic,
        ),
    ]);
    set.sync_group_check_urls(&[
        ("g_zero_dead".into(), url_dead.into()),
        ("g_partial".into(), url_partial.into()),
    ]);
    let member = |tag: &str, leaf: Uuid| UrlProbeMember {
        tag: tag.to_owned(),
        leaf,
        native: None,
    };
    set.set_url_member_resolver(Some(Arc::new(move |group| match group {
        "g_zero_dead" => vec![member("dead_a", dead_a), member("dead_b", dead_b)],
        "g_partial" => vec![
            member("part_dead", part_dead),
            member("part_alive", part_alive),
        ],
        _ => Vec::new(),
    })));

    let loop_task = set.spawn_health_check_loop_concurrent(
        Duration::from_secs(3600),
        Duration::from_secs(1),
        2,
    );
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;
    assert!(calls.lock().is_empty());

    let kill_url = |tag: &str, url: &str| {
        for _ in 0..probe_failure_threshold(ProbeDomain::Tcp) {
            set.record_url_probe_failure(tag, url);
        }
        let mut states = set.url_states.write();
        let entry = states.get_mut(&(tag.to_owned(), url.to_owned())).unwrap();
        entry.consecutive_successes = RECOVERY_SUCCESSES_NEEDED - 1;
        entry.cooldown_until = Instant::now() + Duration::from_secs(300);
    };

    // Part A: emergency trigger_probe (probe_unavailable_group path) recovers an all-dead
    // unpinned idle_timeout=0 custom-URL group, while skipping a partially-dead idle group.
    kill_url("dead_a", url_dead);
    kill_url("dead_b", url_dead);
    kill_url("part_dead", url_partial);

    set.trigger_probe(dead_a);
    set.trigger_probe(part_dead);
    let mut recovered = false;
    for _ in 0..20 {
        if set.is_alive_for_url("dead_a", url_dead) {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        recovered,
        "emergency trigger must probe all-dead unpinned idle_timeout=0 custom-URL group"
    );
    assert!(
        !calls.lock().iter().any(|(_, url)| url == url_partial),
        "emergency trigger must not probe partially-dead unpinned idle custom-URL group"
    );

    // Part B: notify_network_change immediately wakes an all-dead custom-URL group even
    // when global TCP state is alive, without waking partially-dead idle custom-URL groups.
    calls.lock().clear();
    kill_url("dead_a", url_dead);
    kill_url("dead_b", url_dead);
    set.notify_network_change();
    let mut both_recovered = false;
    for _ in 0..20 {
        if set.is_alive_for_url("dead_a", url_dead) && set.is_alive_for_url("dead_b", url_dead) {
            both_recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        both_recovered,
        "notify_network_change must immediately wake all-dead idle custom-URL groups"
    );
    assert!(
        !calls.lock().iter().any(|(_, url)| url == url_partial),
        "notify_network_change must keep partially-dead unpinned idle custom-URL groups silent"
    );

    // Part C: when both global TCP and custom check_url are dead, notify_network_change
    // wakes global TCP and custom check_url once each (no duplicate custom-URL probes).
    calls.lock().clear();
    for node in [dead_a, dead_b] {
        set.report_unavailable_forced(node, ProbeDomain::Tcp, IpVersion::V4);
    }
    kill_url("dead_a", url_dead);
    kill_url("dead_b", url_dead);
    set.notify_network_change();
    let mut both_probed = false;
    for _ in 0..20 {
        {
            let recorded = calls.lock();
            if recorded
                .iter()
                .any(|(id, u)| *id == dead_a && u == "http://127.0.0.1/global")
                && recorded
                    .iter()
                    .any(|(id, u)| *id == dead_b && u == "http://127.0.0.1/global")
                && set.is_alive_for_url("dead_a", url_dead)
                && set.is_alive_for_url("dead_b", url_dead)
            {
                both_probed = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        both_probed,
        "notify_network_change must probe both global TCP and custom check_url when both are dead"
    );

    set.shutdown_health_checks().await.unwrap();
    loop_task.await.unwrap();

    let recorded = calls.lock();
    assert_eq!(
        recorded
            .iter()
            .filter(|(id, u)| *id == dead_a && u == url_dead)
            .count(),
        1,
        "notify_network_change must probe dead_a against custom check_url exactly once"
    );
    assert_eq!(
        recorded
            .iter()
            .filter(|(id, u)| *id == dead_b && u == url_dead)
            .count(),
        1,
        "notify_network_change must probe dead_b against custom check_url exactly once"
    );
}

#[tokio::test]
async fn test_idle_activity_slot_fast_path_coarse_clock_and_generation_invalidation() {
    let set = AliveDialerSet::new();
    let n1 = id(251);
    set.register_node(n1, "n1".into(), Some("127.0.0.1:1".into()));

    // 1. Sub-second exact clock: fast path refreshes active slot without waking,
    //    then returns false once expired so slow path wakes the group.
    set.sync_idle_groups(&[idle_reg(
        "g",
        vec![n1],
        Some(Duration::from_millis(80)),
        IdleGroupKind::Automatic,
    )]);
    let mut trigger_rx = set.take_trigger_rx().expect("trigger receiver");
    let slot_exact = set.mark_group_active_slot("g").expect("registered slot");
    assert_eq!(trigger_rx.try_recv(), Ok(n1));
    set.finish_trigger_probe(n1);
    assert!(!set.is_group_idle("g"));
    assert!(set.try_touch_activity_slot(&slot_exact));
    assert!(trigger_rx.try_recv().is_err());

    // Sleep past refresh_quantum_ns (20ms) while still < timeout (80ms) to exercise CAS refresh.
    let before = slot_exact.last_active_ns.load(Ordering::Acquire);
    tokio::time::sleep(Duration::from_millis(35)).await;
    assert!(set.try_touch_activity_slot(&slot_exact));
    assert!(
        slot_exact.last_active_ns.load(Ordering::Acquire) > before,
        "CAS refresh past refresh_quantum_ns must advance last_active_ns"
    );
    assert!(!set.is_group_idle("g"));
    assert!(trigger_rx.try_recv().is_err());

    // Sleep past timeout (80ms): slot expires, fast path returns false, slow path wakes.
    tokio::time::sleep(Duration::from_millis(95)).await;
    assert!(set.is_group_idle("g"));
    assert!(!set.try_touch_activity_slot(&slot_exact));
    let _ = set.mark_group_active_slot("g");
    assert!(!set.is_group_idle("g"));
    assert_eq!(trigger_rx.try_recv(), Ok(n1));
    set.finish_trigger_probe(n1);

    // 2. Clock-domain translation across sync_idle_groups: exact (80ms) -> coarse (1800s)
    //    preserves active state and invalidates old generation handle.
    set.sync_idle_groups(&[idle_reg(
        "g",
        vec![n1],
        Some(Duration::from_secs(1800)),
        IdleGroupKind::Automatic,
    )]);
    assert!(!set.is_group_idle("g"));
    assert!(
        !set.try_touch_activity_slot(&slot_exact),
        "old generation slot must be invalidated after sync_idle_groups"
    );
    let slot_coarse = set.mark_group_active_slot("g").expect("coarse slot");
    assert!(set.try_touch_activity_slot(&slot_coarse));
    assert!(trigger_rx.try_recv().is_err());

    // 3. Coarse (1800s) -> exact (60ms) preserves fresh activity and then expires on exact clock.
    set.sync_idle_groups(&[idle_reg(
        "g",
        vec![n1],
        Some(Duration::from_millis(60)),
        IdleGroupKind::Automatic,
    )]);
    assert!(!set.is_group_idle("g"));
    assert!(!set.try_touch_activity_slot(&slot_coarse));
    tokio::time::sleep(Duration::from_millis(75)).await;
    assert!(set.is_group_idle("g"));

    // 4. Coarse clock (timeout == 1s) active -> idle transition on Linux CLOCK_MONOTONIC_COARSE.
    set.sync_idle_groups(&[idle_reg(
        "g",
        vec![n1],
        Some(Duration::from_secs(1)),
        IdleGroupKind::Automatic,
    )]);
    let slot_1s = set.mark_group_active_slot("g").expect("1s coarse slot");
    assert!(!set.is_group_idle("g"));
    assert_eq!(trigger_rx.try_recv(), Ok(n1));
    set.finish_trigger_probe(n1);
    assert!(set.try_touch_activity_slot(&slot_1s));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(set.is_group_idle("g"));
    assert!(!set.try_touch_activity_slot(&slot_1s));

    // 5. Hot-reloading to idle_timeout=0 invalidates previous slot and keeps group idle.
    let _ = set.mark_group_active_slot("g");
    assert!(!set.is_group_idle("g"));
    set.sync_idle_groups(&[idle_reg(
        "g",
        vec![n1],
        Some(Duration::ZERO),
        IdleGroupKind::Automatic,
    )]);
    assert!(set.is_group_idle("g"));
    assert!(!set.try_touch_activity_slot(&slot_1s));
    let slot_zero = set.mark_group_active_slot("g").expect("zero slot");
    assert!(set.try_touch_activity_slot(&slot_zero));
    assert!(set.is_group_idle("g"));
}
