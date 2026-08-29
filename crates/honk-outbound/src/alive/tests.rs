use super::*;
use honk_config::config::{BLOCK_NODE_ID, DIRECT_NODE_ID};

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

#[test]
fn test_parse_url_host_dae_comma_format() {
    // dae fallback-IP list: only the first segment is the URL host.
    assert_eq!(
        AliveDialerSet::parse_url_host("http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111")
            .as_deref(),
        Some("cp.cloudflare.com")
    );
    assert_eq!(
        AliveDialerSet::parse_url_host("http://1.1.1.1,8.8.8.8").as_deref(),
        Some("1.1.1.1")
    );
    assert_eq!(
        AliveDialerSet::parse_url_host("https://example.com:8443/").as_deref(),
        Some("example.com")
    );
}

#[test]
fn test_parse_url_host_strips_path_and_missing_scheme() {
    // Regression: the path must never leak into DNS resolution — this was
    // the "Name does not resolve" health-check failure.
    assert_eq!(
        AliveDialerSet::parse_url_host("http://www.google-analytics.com/generate_204").as_deref(),
        Some("www.google-analytics.com")
    );
    assert_eq!(
        AliveDialerSet::parse_url_host("www.google-analytics.com/generate_204").as_deref(),
        Some("www.google-analytics.com")
    );
    assert_eq!(
        AliveDialerSet::parse_url_host("https://example.com:8443/check?q=1#f").as_deref(),
        Some("example.com")
    );
    assert_eq!(
        AliveDialerSet::parse_url_host("http://[2606:4700:4700::1111]:443/").as_deref(),
        Some("2606:4700:4700::1111")
    );
    assert_eq!(
        AliveDialerSet::parse_url_host("[2606:4700:4700::1111]:443/path").as_deref(),
        Some("2606:4700:4700::1111")
    );
}

#[test]
fn test_parse_url_port() {
    assert_eq!(AliveDialerSet::parse_url_port("http://a.com"), 80);
    assert_eq!(AliveDialerSet::parse_url_port("https://a.com"), 443);
    assert_eq!(AliveDialerSet::parse_url_port("http://a.com:8080/"), 8080);
    assert_eq!(
        AliveDialerSet::parse_url_port("https://a.com:8443/check?q=1#f"),
        8443
    );
    assert_eq!(
        AliveDialerSet::parse_url_port("http://10.10.10.70:9043/,1.1.1.1"),
        9043
    );
    assert_eq!(
        AliveDialerSet::parse_url_port("http://[2606:4700:4700::1111]:8443/"),
        8443
    );
    assert_eq!(
        AliveDialerSet::parse_url_port("[2606:4700:4700::1111]/path"),
        80
    );
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

#[test]
fn test_alive_set_basic() {
    let set = AliveDialerSet::new();
    assert!(set.is_alive(id(1)));
    // TCP probe threshold = 3: one transient failure must not kill the
    // node; three consecutive failures do.
    set.mark_dead_for(id(1), ProbeDomain::Tcp, IpVersion::V4);
    assert!(set.is_alive(id(1)), "TCP survives one probe failure");
    set.mark_dead_for(id(1), ProbeDomain::Tcp, IpVersion::V4);
    set.mark_dead_for(id(1), ProbeDomain::Tcp, IpVersion::V4);
    assert!(!set.is_alive(id(1)), "TCP dies after 3 probe failures");
    // DNS UDP probe threshold = 3 — verify per-protocol thresholds
    assert!(set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
    set.mark_dead_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4);
    assert!(set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
    set.mark_dead_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4);
    assert!(set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
    set.mark_dead_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4);
    assert!(!set.is_alive_for(id(1), ProbeDomain::DnsUdp, IpVersion::V4));
    set.mark_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4);
    assert!(set.is_alive(id(1)));
}

#[test]
fn test_alive_set_per_protocol() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), "127.0.0.1:1".into());
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

#[test]
fn group_activity_ignores_untracked_groups_and_reuses_registered_key() {
    let set = AliveDialerSet::new();
    set.mark_group_active("untracked");
    assert!(set.group_last_active.read().is_empty());

    set.sync_urltest_groups(&[(
        "tracked".to_owned(),
        Vec::new(),
        Some(Duration::from_secs(60)),
    )]);
    set.mark_group_active("tracked");
    let first = set.group_last_active.read()["tracked"];
    set.mark_group_active("tracked");
    let active = set.group_last_active.read();
    assert_eq!(active.len(), 1);
    assert!(active["tracked"] >= first);
}

/// Traffic failures during the grace period must not mark a fresh node
/// dead (restart warm-up regression: mass traffic failures used to kill
/// every node seconds after startup).
#[test]
fn test_traffic_failures_ignored_during_grace() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), "127.0.0.1:1".into());
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
    set.register_node(id(1), "n1".into(), "127.0.0.1:1".into());
    assert!(set.should_probe(id(1), ProbeDomain::Tcp, IpVersion::V4));
    // Use forced death to bypass grace period and trigger backoff.
    set.report_unavailable_forced(id(1), ProbeDomain::Tcp, IpVersion::V4);
    assert!(!set.is_alive_for(id(1), ProbeDomain::Tcp, IpVersion::V4));
}

#[test]
fn test_network_change_bypasses_backoff_but_requires_fresh_success() {
    let set = AliveDialerSet::new();
    let node_id = id(1);
    set.register_node(node_id, "n1".into(), "127.0.0.1:1".into());
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
        listener.local_addr().unwrap().to_string(),
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
    set.register_node(node_id, "n3".into(), "127.0.0.1:1".into());
    set.set_udp_probe(Arc::new(MockUdpProber::ok(Duration::from_millis(5))));
    set.report_unavailable_forced(node_id, ProbeDomain::DataUdp, IpVersion::V4);
    assert!(!set.is_alive_for(node_id, ProbeDomain::DataUdp, IpVersion::V4));

    set.run_recovery_check_cycle_concurrent(Duration::from_secs(1), 1)
        .await;

    assert!(set.is_alive_for(node_id, ProbeDomain::DataUdp, IpVersion::V4));
    assert!(set.is_alive_for(node_id, ProbeDomain::DnsUdp, IpVersion::V6));
}

#[test]
fn test_sticky_cache_ttl() {
    let c = StickyCache::new(Duration::from_millis(10));
    c.set_sticky(
        "x".into(),
        StickyTarget {
            addr: "a:1".into(),
            protocol: "t".into(),
        },
    );
    assert!(c.get_sticky("x").is_some());
    std::thread::sleep(Duration::from_millis(20));
    assert!(c.get_sticky("x").is_none());
}

#[tokio::test]
async fn test_urltest_idle_suspension() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), "127.0.0.1:1".into());
    set.register_urltest_group("g", &[id(1)], Some(Duration::from_millis(50)));

    // Lazy start: a never-active group is idle → probing suspended.
    assert!(set.is_urltest_group_idle("g"));
    assert!(set.is_probe_suspended(id(1)));

    set.mark_group_active("g");
    assert!(!set.is_urltest_group_idle("g"));
    assert!(!set.is_probe_suspended(id(1)));

    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(set.is_urltest_group_idle("g"));
    assert!(set.is_probe_suspended(id(1)));

    // Unregistered groups are never idle; ungrouped nodes never suspended.
    assert!(!set.is_urltest_group_idle("nope"));
    assert!(!set.is_probe_suspended(id(99)));
}

#[tokio::test]
async fn test_health_cycle_skips_idle_urltest_nodes() {
    let set = std::sync::Arc::new(AliveDialerSet::new());
    // 127.0.0.1:1 refuses connections → a probe records a failure.
    set.register_node(id(1), "n1".into(), "127.0.0.1:1".into());
    set.register_node(id(2), "n2".into(), "127.0.0.1:1".into());
    set.register_urltest_group("g", &[id(1)], Some(Duration::from_secs(3600)));

    // n1's group was never active → suspended → cycle never probes it.
    set.run_health_check_cycle(Duration::from_millis(200)).await;
    assert!(
        set.get_probe_history(id(1), ProbeDomain::Tcp, IpVersion::V4)
            .is_empty(),
        "idle URLTest node must not be probed"
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
        "active URLTest node must be probed"
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
fn test_sync_urltest_groups_full_refresh() {
    let set = AliveDialerSet::new();
    for (i, n) in ["n1", "n2", "n3"].into_iter().enumerate() {
        set.register_node(id(i as u128 + 1), n.into(), "127.0.0.1:1".into());
    }
    // Re-registering the same group twice duplicates the node→groups
    // index; the full refresh must rebuild it cleanly.
    set.register_urltest_group("g1", &[id(1)], Some(Duration::from_secs(10)));
    set.register_urltest_group("g1", &[id(1)], Some(Duration::from_secs(10)));
    set.register_urltest_group("g2", &[id(2)], Some(Duration::from_secs(20)));
    set.mark_group_active("g1");

    // Reload: g1 survives with new members/timeout, g2 removed, g3 new.
    set.sync_urltest_groups(&[
        (
            "g1".into(),
            vec![id(2), id(3)],
            Some(Duration::from_secs(30)),
        ),
        ("g3".into(), vec![id(1)], None),
    ]);

    // g1 keeps its activity timestamp (not idle despite the new 30s
    // timeout because it was just active).
    assert!(!set.is_urltest_group_idle("g1"));
    // g2 is gone → treated as unregistered (never idle).
    assert!(!set.is_urltest_group_idle("g2"));
    // g3 registered with the default timeout, never active → idle.
    assert!(set.is_urltest_group_idle("g3"));

    // Node → groups index rebuilt: n1 now belongs only to g3, n2/n3 to g1.
    assert!(set.is_probe_suspended(id(1))); // g3 idle
    assert!(!set.is_probe_suspended(id(2))); // g1 active
    assert!(!set.is_probe_suspended(id(3))); // g1 active

    // Wake-up membership follows the new table.
    set.sync_urltest_groups(&[("g3".into(), vec![id(1)], None)]);
    assert!(!set.is_urltest_group_idle("g1")); // removed → never idle
    assert!(!set.is_probe_suspended(id(2))); // no groups → not suspended
}
struct MockHttpProber {
    result: HttpProbeResult,
}

impl HttpProber for MockHttpProber {
    fn probe_http(
        &self,
        _node_name: &str,
        _addr: std::net::SocketAddr,
        _url: &str,
        _timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = HttpProbeResult> + Send + 'static>> {
        let result = self.result.clone();
        Box::pin(async move { result })
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
    set.register_node(id(1), "n1".into(), "127.0.0.1:1".into());
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
    set.register_node(id(1), "n1".into(), "127.0.0.1:1".into());
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
    set.register_node(id(1), "n1".into(), "127.0.0.1:9".into());
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
    result: std::sync::Mutex<Result<Duration, String>>,
}

impl MockUdpProber {
    fn ok(latency: Duration) -> Self {
        Self {
            result: std::sync::Mutex::new(Ok(latency)),
        }
    }
    fn err(msg: &str) -> Self {
        Self {
            result: std::sync::Mutex::new(Err(msg.to_string())),
        }
    }
}

impl UdpProber for MockUdpProber {
    fn probe_udp(
        &self,
        _node_name: &str,
        _timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, String>> + Send + 'static>> {
        let r = self.result.lock().unwrap().clone();
        Box::pin(async move { r })
    }
}

struct PendingUdpProber;

impl UdpProber for PendingUdpProber {
    fn probe_udp(
        &self,
        _node_name: &str,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, String>> + Send + 'static>> {
        Box::pin(async move {
            tokio::time::sleep(timeout).await;
            Err("UDP probe timeout".into())
        })
    }
}

#[tokio::test]
async fn test_probe_node_udp_success_marks_udp_domains_alive() {
    let set = AliveDialerSet::new();
    set.register_node(id(1), "n1".into(), "127.0.0.1:1".into());
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
async fn test_tcp_probe_failure_does_not_touch_udp() {
    let set = AliveDialerSet::new();
    // 127.0.0.1:1 refuses connections → the TCP probe fails.
    set.register_node(id(1), "n1".into(), "127.0.0.1:1".into());
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
    set.register_node(id(1), "n1".into(), "127.0.0.1:1".into());
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
    set.register_node(BLOCK_NODE_ID, "block".into(), String::new());
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
            "block",
            "http://x.example",
            Duration::from_millis(1)
        )
        .await
    );
    assert!(set.is_alive_for(BLOCK_NODE_ID, ProbeDomain::Tcp, IpVersion::V4));
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
    set.register_node(DIRECT_NODE_ID, "direct".into(), String::new());
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
            "direct",
            "http://x.example",
            Duration::from_millis(1)
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
