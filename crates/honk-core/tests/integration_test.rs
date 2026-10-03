//! Cross-component integration tests using mock eBPF and loopback transports.

use honk_config::{Config, node, routing};
use honk_core::{
    control::ControlPlane,
    dns::{self, DnsResolver},
    ebpf::mock::MockEbpfBackend,
    proxy::ProxyRegistry,
    routing::{ConnectionInfo, Router},
    stats::StatsManager,
};
use std::sync::Arc;

/// Build a minimal DnsForwarder for integration tests.
fn test_dns_forwarder() -> Arc<dns::forwarder::DnsForwarder> {
    let cache = Arc::new(tokio::sync::Mutex::new(dns::cache::DnsCache::new(100)));
    let router = Arc::new(
        dns::routing::DnsRouter::new(&honk_config::dns::DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    let upstream_pool = Arc::new(
        dns::upstream_pool::UpstreamPool::new(
            &[honk_config::dns::DnsUpstream {
                name: "default".into(),
                address: "8.8.8.8:53".into(),
                protocol: honk_config::types::DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            }],
            router.clone(),
        )
        .unwrap(),
    );
    Arc::new(dns::forwarder::DnsForwarder::new(
        upstream_pool as Arc<dyn dns::forwarder::DnsUpstreamPool>,
        cache,
        router,
    ))
}
use honk_ebpf_common::OutboundIndex;
#[test]
fn test_router_empty_config() {
    let router = Router::new(&[], "direct").unwrap();
    assert_eq!(router.route_count(), 0);

    let conn = ConnectionInfo {
        domain: None,
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.168.1.100".parse().unwrap(),
        src_port: 50000,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };
    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_router_domain_suffix_routing() {
    let rules = vec![
        routing::RoutingRule {
            name: "google-via-proxy".into(),
            condition: routing::RoutingCondition {
                domain_suffix: vec!["google.com".into(), "youtube.com".into()],
                ..Default::default()
            },
            outbound: routing::RoutingOutbound::Simple("us-proxy".into()),
            priority: 0,
            must: false,
            mark: 0,
        },
        routing::RoutingRule {
            name: "china-direct".into(),
            condition: routing::RoutingCondition {
                domain_suffix: vec![".cn".into(), ".taobao.com".into()],
                ..Default::default()
            },
            outbound: routing::RoutingOutbound::Simple("direct".into()),
            priority: 10,
            must: false,
            mark: 0,
        },
    ];

    let router = Router::new(&rules, "proxy").unwrap();

    // Google should match first rule
    let google_conn = ConnectionInfo {
        domain: Some("www.google.com".into()),
        dst_ip: "142.250.80.4".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 50000,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };
    assert_eq!(router.route(&google_conn), "us-proxy");

    // Chinese site should match second rule
    let cn_conn = ConnectionInfo {
        domain: Some("www.baidu.cn".into()),
        dst_ip: "110.242.68.66".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 50001,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };
    assert_eq!(router.route(&cn_conn), "direct");

    // Unknown domain goes to default
    let unknown_conn = ConnectionInfo {
        domain: Some("example.org".into()),
        dst_ip: "93.184.216.34".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 50002,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };
    assert_eq!(router.route(&unknown_conn), "proxy");
}

#[test]
fn test_router_ip_cidr_routing() {
    let rules = vec![routing::RoutingRule {
        name: "private-direct".into(),
        condition: routing::RoutingCondition {
            ip: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
            ],
            ..Default::default()
        },
        outbound: routing::RoutingOutbound::Simple("direct".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "proxy").unwrap();

    // Private IP → direct
    let private = ConnectionInfo {
        domain: None,
        dst_ip: "192.168.1.100".parse().unwrap(),
        dst_port: 80,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 50000,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };
    assert_eq!(router.route(&private), "direct");

    // Public IP → proxy
    let public = ConnectionInfo {
        domain: None,
        dst_ip: "8.8.8.8".parse().unwrap(),
        dst_port: 53,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 50001,
        protocol: "udp",
        process_name: None,
        mac: None,
        dscp: None,
    };
    assert_eq!(router.route(&public), "proxy");
}

#[test]
fn test_config_load_and_validate() {
    let toml_str = r#"
[global]
tproxy_port = 12345
tproxy_mark = 0x08000000
log_level = "info"

[[nodes]]
name = "us-proxy"
protocol = "socks5"
address = "us.proxy.example.com"
port = 1080
transport = "tcp"
tls = false

[[nodes]]
name = "jp-proxy"
protocol = "trojan"
address = "jp.proxy.example.com"
port = 443
tls = true
sni = "jp.proxy.example.com"

[[groups]]
name = "proxy"

[routing]
default_outbound = "direct"

[[routing.rules]]
name = "google-proxy"
outbound = "proxy"
priority = 0
domain_suffix = ["google.com"]

[dns]
[[dns.upstream]]
name = "default"
address = "223.5.5.5:53"
protocol = "udp"
"#;

    let mut config: Config = toml::from_str(toml_str).unwrap();
    for node in &mut config.nodes {
        node.id = node.derive_id();
    }
    config.validate().unwrap();

    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    for (domain, expected) in [("www.google.com", "proxy"), ("example.org", "direct")] {
        let connection = ConnectionInfo {
            domain: Some(domain.into()),
            dst_ip: "192.0.2.1".parse().unwrap(),
            dst_port: 443,
            src_ip: "192.0.2.2".parse().unwrap(),
            src_port: 50000,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        };
        assert_eq!(router.route(&connection), expected);
    }
}

#[test]
fn test_stats_manager_full_workflow() {
    let mgr = std::sync::Arc::new(StatsManager::new());

    let mut us: Vec<_> = (0..10)
        .map(|_| mgr.track_connection("proxy-us", honk_core::stats::OutboundKind::Node))
        .collect();
    let _jp: Vec<_> = (0..5)
        .map(|_| mgr.track_connection("proxy-jp", honk_core::stats::OutboundKind::Node))
        .collect();
    us.truncate(8);

    mgr.record_bytes(
        "proxy-us",
        honk_core::stats::OutboundKind::Node,
        1024 * 1024,
        2048 * 1024,
    ); // 1MB up, 2MB down
    mgr.record_bytes(
        "proxy-jp",
        honk_core::stats::OutboundKind::Node,
        512 * 1024,
        256 * 1024,
    );

    mgr.record_error("proxy-jp", honk_core::stats::OutboundKind::Node);

    let snap = mgr.snapshot();

    assert_eq!(snap.len(), 2);
    assert_eq!(snap.get("proxy-us").unwrap().total_conns, 10);
    assert_eq!(snap.get("proxy-us").unwrap().active_conns, 8); // 10 - 2 closes
    assert_eq!(snap.get("proxy-us").unwrap().tx_bytes, 1024 * 1024);
    assert_eq!(snap.get("proxy-us").unwrap().rx_bytes, 2048 * 1024);
    assert_eq!(snap.get("proxy-us").unwrap().errors, 0);

    assert_eq!(snap.get("proxy-jp").unwrap().total_conns, 5);
    assert_eq!(snap.get("proxy-jp").unwrap().errors, 1);
}

#[tokio::test]
async fn test_reload_rebuilds_group_manager_preserving_choices() {
    use honk_config::group::{Group, GroupPolicy};
    use honk_config::node::Node;

    fn node(name: &str) -> Node {
        let mut node = Node {
            name: name.into(),
            address: "127.0.0.1".into(),
            port: 1,
            outbound: node::OutboundConfig::Shadowsocks(node::ShadowsocksConfig {
                password: Some(name.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    }
    fn selector(name: &str, members: &[&Node]) -> Group {
        Group {
            name: name.into(),
            policy: GroupPolicy::Selector,
            nodes: members.iter().map(|n| n.id).collect(),
            ..Default::default()
        }
    }

    let (a, b, c) = (node("a"), node("b"), node("c"));

    // v1: selector group "proxy" with a, b.
    let config_v1 = Config {
        nodes: vec![a.clone(), b.clone()],
        groups: vec![selector("proxy", &[&a, &b])],
        ..Default::default()
    };
    let cp = ControlPlane::new(
        config_v1,
        Box::new(MockEbpfBackend::new()),
        Router::new(&[], "direct").unwrap(),
        std::sync::Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        test_dns_forwarder(),
    )
    .unwrap();

    // Runtime selector choice made before the reload.
    cp.group_manager()
        .read()
        .set_selector_choice("proxy", "b", honk_outbound::group::SelectorNetworks::Both)
        .unwrap();

    // v2: "proxy" unchanged; new group "extra" with c; new URLTest
    // group "ut" with b.
    let mut ut = selector("ut", &[&b]);
    ut.policy = GroupPolicy::URLTest;
    let config_v2 = Config {
        nodes: vec![a.clone(), b.clone(), c.clone()],
        groups: vec![selector("proxy", &[&a, &b]), selector("extra", &[&c]), ut],
        ..Default::default()
    };
    *cp.config_handle().write().await = Arc::new(config_v2);
    cp.reload_group_manager().await;

    {
        let gm = cp.group_manager();
        let gm = gm.read();
        // The old runtime choice migrated to the rebuilt manager.
        assert_eq!(
            gm.get_selector_choice("proxy", honk_outbound::group::SelectionNetwork::Tcp),
            Some("b".to_string())
        );
        assert_eq!(gm.select_node("proxy").map(|n| n.name.as_str()), Some("b"));
        // The new group is selectable right after the reload.
        assert_eq!(gm.select_node("extra").map(|n| n.name.as_str()), Some("c"));
    }
    // Health-check registrations follow the new membership.
    let registered = cp.alive_set().registered_nodes();
    assert!(registered.contains_key(&a.id));
    assert!(registered.contains_key(&b.id));
    assert!(registered.contains_key(&c.id));
    // The new URLTest group is registered for idle suspension (lazy
    // start: never active → idle).
    assert!(cp.alive_set().is_urltest_group_idle("ut"));

    // v3: "proxy" shrinks to a only; "extra" and "ut" removed — the
    // stale choice for "b" and the old registrations disappear.
    let config_v3 = Config {
        nodes: vec![a.clone(), b.clone(), c.clone()],
        groups: vec![selector("proxy", &[&a])],
        ..Default::default()
    };
    *cp.config_handle().write().await = Arc::new(config_v3);
    cp.reload_group_manager().await;

    {
        let gm = cp.group_manager();
        let gm = gm.read();
        assert_eq!(
            gm.get_selector_choice("proxy", honk_outbound::group::SelectionNetwork::Tcp),
            None
        );
        assert!(gm.select_node("extra").is_none());
    }
    let registered = cp.alive_set().registered_nodes();
    assert!(registered.contains_key(&a.id));
    assert!(!registered.contains_key(&b.id));
    assert!(!registered.contains_key(&c.id));
    // Removed URLTest groups are no longer registered (never idle).
    assert!(!cp.alive_set().is_urltest_group_idle("ut"));
}

#[tokio::test]
async fn test_merge_subscription_nodes_full_pipeline() {
    use honk_config::group::{Group, GroupPolicy};
    use honk_config::node::Node;

    let sub_id = uuid::Uuid::new_v4();
    let other_sub_id = uuid::Uuid::new_v4();

    fn node(name: &str, sub: Option<uuid::Uuid>) -> Node {
        let mut node = Node {
            name: name.into(),
            address: "127.0.0.1:1080".into(),
            host: "127.0.0.1".into(),
            port: 1080,
            outbound: node::OutboundConfig::Socks5(node::Socks5Config {
                username: Some(name.into()),
                ..Default::default()
            }),
            subscription_id: sub,
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    }

    // Startup state: a static node, the subscription's previous
    // generation of nodes, and a node from another subscription.
    let static_node = node("static", None);
    let old1 = node("sub-old-1", Some(sub_id));
    let old2 = node("sub-old-2", Some(sub_id));
    let other = node("other-sub", Some(other_sub_id));
    let mut config = Config {
        nodes: vec![
            static_node.clone(),
            old1.clone(),
            old2.clone(),
            other.clone(),
        ],
        groups: vec![Group {
            name: "proxy".into(),
            policy: GroupPolicy::Selector,
            ..Default::default()
        }],
        ..Default::default()
    };
    // Startup resolves filter-based membership (filter-less group → all
    // nodes), exactly like run() does before ControlPlane::new.
    honk_config::parser::resolve_group_filters(
        &mut config.groups,
        &config.nodes,
        &config.subscriptions,
    );
    // A routing rule targeting the group, so the merge pipeline has a
    // ruleset to rebuild and push.
    config.routing.rules = vec![routing::RoutingRule {
        name: "example-via-proxy".into(),
        condition: routing::RoutingCondition {
            domain_suffix: vec!["example.com".into()],
            ..Default::default()
        },
        outbound: routing::RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];
    let rules = config.routing.rules.clone();

    let mut cp = ControlPlane::new(
        config,
        Box::new(MockEbpfBackend::new()),
        Router::new(&rules, "direct").unwrap(),
        std::sync::Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        test_dns_forwarder(),
    )
    .unwrap();
    cp.set_mode_state(std::sync::Arc::new(parking_lot::RwLock::new(
        honk_core::mode::ModeState::new("Rule", "Proxy"),
    )));
    cp.start_datapath_flags_coordinator().unwrap();
    cp.datapath_flags_handle()
        .unwrap()
        .initialize(false, false)
        .await
        .unwrap();

    // Simulate a late subscription fetch completing: two new nodes with
    // distinct canonical IDs replace the previous generation.
    let new1 = node("sub-new-1", Some(sub_id));
    let new2 = node("sub-new-2", Some(sub_id));
    cp.merge_subscription_nodes(sub_id, vec![new1.clone(), new2.clone()], Vec::new())
        .await;

    // The merged config replaces only this subscription's nodes.
    {
        let config = cp.config_handle();
        let config = config.read().await;
        let names: Vec<&str> = config.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["static", "other-sub", "sub-new-1", "sub-new-2"]);
        // Group membership was pruned of dangling UUIDs and re-resolved:
        // exactly the four live nodes.
        assert_eq!(config.groups[0].nodes.len(), 4);
        for id in &config.groups[0].nodes {
            assert!(config.nodes.iter().any(|n| n.id == *id));
        }
        assert!(!config.groups[0].nodes.contains(&old1.id));
        assert!(!config.groups[0].nodes.contains(&old2.id));
        // The routing ruleset survives the merge untouched.
        assert_eq!(config.routing.rules.len(), 1);
    }

    // The rebuilt group manager sees the new nodes and no longer selects
    // the replaced ones.
    {
        let gm = cp.group_manager();
        let gm = gm.read();
        let mut members = gm.node_names_in_group("proxy");
        members.sort();
        assert_eq!(
            members,
            vec!["other-sub", "static", "sub-new-1", "sub-new-2"]
        );
        let selected = gm.select_node("proxy").expect("group selectable");
        assert!(
            ["static", "other-sub", "sub-new-1", "sub-new-2"].contains(&selected.name.as_str())
        );
    }

    // Health checks follow the merged membership: new nodes registered,
    // replaced nodes deregistered, others untouched.
    let registered = cp.alive_set().registered_nodes();
    assert!(registered.contains_key(&new1.id));
    assert!(registered.contains_key(&new2.id));
    assert!(registered.contains_key(&static_node.id));
    assert!(registered.contains_key(&other.id));
    assert!(!registered.contains_key(&old1.id));
    assert!(!registered.contains_key(&old2.id));

    // Idempotency: re-merging the same subscription (periodic refresh
    // with the same canonical IDs) replaces instead of duplicating.
    let refresh1 = node("sub-new-1", Some(sub_id));
    let refresh2 = node("sub-new-2", Some(sub_id));
    cp.merge_subscription_nodes(sub_id, vec![refresh1, refresh2], Vec::new())
        .await;
    {
        let config = cp.config_handle();
        let config = config.read().await;
        assert_eq!(config.nodes.len(), 4);
        assert_eq!(config.groups[0].nodes.len(), 4);
    }
    let registered = cp.alive_set().registered_nodes();
    assert_eq!(registered.len(), 4);
}

#[test]
fn test_routing_edge_cases() {
    let router = Router::new(&[], "direct").unwrap();

    let conn = ConnectionInfo {
        domain: None,
        dst_ip: "8.8.8.8".parse().unwrap(),
        dst_port: 53,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 12345,
        protocol: "udp",
        process_name: None,
        mac: None,
        dscp: None,
    };
    assert_eq!(router.route(&conn), "direct");

    // Rule with no conditions → should NOT match (catch-all protection)
    let rules = vec![routing::RoutingRule {
        name: "empty-rule".into(),
        condition: routing::RoutingCondition::default(),
        outbound: routing::RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];
    let router = Router::new(&rules, "direct").unwrap();
    assert_eq!(router.route(&conn), "direct"); // Should not match empty rule
}

#[test]
fn test_outbound_index_conversions() {
    assert!(OutboundIndex::MustRules.is_reserved());
    assert!(OutboundIndex::Direct.is_reserved());
    assert!(OutboundIndex::Block.is_reserved());

    let user0 = OutboundIndex::UserBase;
    assert_eq!(user0 as u32, 2);
    assert!(!user0.is_reserved());
    assert_eq!(user0.to_user_num(), 0);
}

#[test]
fn test_daemon_reports_timer_diagnostics_on_startup_and_sighup() {
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.dae");
    let port = std::net::TcpListener::bind("[::]:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let data_dir = directory.path().join("data");
    let source = |tolerance| {
        format!(
            "global {{\n data_dir: '{}'\n tproxy_port: {port}\n nfqueue_enable: false\n \
                 store_subscribe: false\n tcp_check_url: 'http://127.0.0.1:1/'\n \
                 udp_check_dns: '127.0.0.1:53'\n \
                 check_tolerance: {tolerance}\n preconnect_node_count: 0\n}}\n \
                 node {{\n loopback: 'socks5://127.0.0.1:1'\n}}\n \
                 group {{\n proxy {{\n filter: bogus('x')\n policy: select\n }}\n}}\n \
                 routing {{\n fallback: direct\n}}\n",
            data_dir.display()
        )
    };
    std::fs::write(&path, source("1m")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_honk-core"))
        .arg("--config")
        .arg(&path)
        .arg("--mock-ebpf")
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mock daemon");
    let output = Arc::new(parking_lot::Mutex::new(String::new()));
    let pipes: [Box<dyn Read + Send>; 2] = [
        Box::new(child.stdout.take().unwrap()),
        Box::new(child.stderr.take().unwrap()),
    ];
    let readers = pipes.map(|pipe| {
        let output = output.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines() {
                let mut output = output.lock();
                match line {
                    Ok(line) => {
                        output.push_str(&line);
                        output.push('\n');
                    }
                    Err(error) => {
                        output.push_str(&format!("output read failed: {error}\n"));
                        break;
                    }
                }
            }
        })
    });
    let wait_for = |description: &str, predicate: &dyn Fn(&str) -> bool| {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if predicate(&output.lock()) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out waiting for {description}"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    let diagnostic_count = |log: &str, setting: &str| {
        log.lines()
            .filter(|line| {
                line.contains("WARN")
                    && line.contains("legacy-config-warning")
                    && line.contains(setting)
            })
            .count()
    };
    let result = (|| -> Result<([usize; 2], [usize; 2]), String> {
        wait_for("startup diagnostic", &|log| {
            diagnostic_count(log, "global.check_tolerance") >= 1
        })?;
        wait_for("Router ready", &|log| log.contains("Router ready"))?;
        let startup_diagnostics = {
            let output = output.lock();
            [
                diagnostic_count(&output, "global.check_tolerance"),
                diagnostic_count(&output, "groups[1].filter"),
            ]
        };
        // Router construction precedes the spawned SIGHUP handler; do not
        // deliver a terminating default-action signal during that window.
        wait_for("SIGHUP handler registration", &|_| {
            std::fs::read_to_string(format!("/proc/{}/status", child.id()))
                .ok()
                .and_then(|status| {
                    status.lines().find_map(|line| {
                        line.strip_prefix("SigCgt:")
                            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
                    })
                })
                .is_some_and(|mask| mask & (1 << (libc::SIGHUP - 1)) != 0)
        })?;
        std::fs::write(&path, source("2h")).map_err(|error| error.to_string())?;
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child.id() as libc::pid_t),
            nix::sys::signal::Signal::SIGHUP,
        )
        .map_err(|error| error.to_string())?;
        wait_for("SIGHUP diagnostic", &|log| {
            diagnostic_count(log, "global.check_tolerance") >= 2
        })?;
        wait_for("SIGHUP reload request 1 applied", &|log| {
            log.contains("SIGHUP reload request 1 applied")
        })?;
        let cumulative_diagnostics = {
            let output = output.lock();
            [
                diagnostic_count(&output, "global.check_tolerance"),
                diagnostic_count(&output, "groups[1].filter"),
            ]
        };
        Ok((startup_diagnostics, cumulative_diagnostics))
    })();
    let _ = child.kill();
    let status = child.wait();
    for reader in readers {
        reader.join().expect("join daemon output reader");
    }
    status.expect("reap mock daemon");
    let (startup_diagnostics, cumulative_diagnostics) = match result {
        Ok(counts) => counts,
        Err(error) => panic!("{}\n{}", error, output.lock()),
    };
    assert_eq!(
        (startup_diagnostics, cumulative_diagnostics),
        ([1, 1], [2, 2])
    );
}

#[test]
fn test_mode_command_rejects_dae_without_rewriting() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let path = directory.path().join("config.dae");
    let source = "# preserve the dae source\nglobal {\n    log_level: info\n}\n";
    std::fs::write(&path, source).expect("write dae source");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_honk-core"))
        .args([
            "--config",
            path.to_str().expect("utf-8 config path"),
            "mode",
            "direct",
        ])
        .output()
        .expect("run mode command");

    assert!(!output.status.success(), "mode unexpectedly rewrote .dae");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(".dae"),
        "unexpected mode error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
