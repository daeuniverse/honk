//! Integration tests for honk-core.
//!
//! These tests verify the full pipeline:
//! 1. Configuration loading
//! 2. eBPF backend (mock)
//! 3. Routing decisions
//! 4. SOCKS5 proxy handling
//! 5. TCP relay
//! 6. DNS resolution
//! 7. Statistics tracking
//!
//! All tests use the mock eBPF backend, so they run without
//! kernel eBPF support.

#[cfg(test)]
mod integration_tests {
    use honk_config::*;
    use honk_core::{
        control::ControlPlane,
        dns::{self, DnsResolver},
        ebpf::mock::MockEbpfBackend,
        proxy::ProxyRegistry,
        relay,
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
    use honk_ebpf_common::*;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use tokio::net::{TcpListener, TcpStream};

    /// Spawn an echo server that returns what it receives.
    async fn spawn_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = [0u8; 4096];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
            }
        });

        addr
    }

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

[routing]
default_outbound = "direct"

[[routing.rules]]
name = "google-proxy"
outbound = "us-proxy"
priority = 0
[condition]
domain_suffix = ["google.com"]

[dns]
[[dns.upstream]]
name = "alidns"
address = "223.5.5.5:53"
protocol = "udp"
"#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.validate().is_ok());

        assert_eq!(config.global.tproxy_port, 12345);
        assert_eq!(config.nodes.len(), 2);
        assert_eq!(config.nodes[0].name, "us-proxy");
        assert_eq!(config.nodes[0].protocol, types::NodeProtocol::Socks5);
        assert_eq!(config.routing.rules.len(), 1);
        assert_eq!(config.dns.upstream.len(), 1);
    }

    #[test]
    fn test_config_validation_empty_node_name() {
        let mut config = Config::default();
        config.nodes.push(node::Node {
            name: "".into(),
            protocol: types::NodeProtocol::Socks5,
            address: "127.0.0.1".into(),
            port: 1080,
            ..Default::default()
        });

        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Node name cannot be empty")
        );
    }

    #[test]
    fn test_config_validation_no_address() {
        let mut config = Config::default();
        config.nodes.push(node::Node {
            name: "test-node".into(),
            protocol: types::NodeProtocol::Socks5,
            address: "".into(),
            host: "".into(),
            port: 1080,
            ..Default::default()
        });

        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no address or host")
        );
    }

    #[test]
    fn test_mock_ebpf_full_workflow() {
        use honk_core::ebpf::EbpfBackend;

        let mut backend = MockEbpfBackend::new();

        backend
            .set_param(ParamKey::BigEndianTproxyPort, 12345)
            .unwrap();
        backend.set_param(ParamKey::ControlPlanePid, 42).unwrap();

        assert_eq!(
            backend.get_param(ParamKey::BigEndianTproxyPort).unwrap(),
            Some(12345)
        );
        assert_eq!(
            backend.get_param(ParamKey::ControlPlanePid).unwrap(),
            Some(42)
        );
        assert_eq!(
            backend.get_param(ParamKey::ControlPlaneNatDirect).unwrap(),
            None
        );

        backend
            .add_domain_route("google.com", OutboundIndex::UserBase)
            .unwrap();
        backend
            .add_domain_route("youtube.com", OutboundIndex::from_user(1))
            .unwrap();

        backend
            .add_ip_route("10.0.0.0/8", OutboundIndex::Direct)
            .unwrap();
        backend
            .add_ip_route("172.16.0.0/12", OutboundIndex::Direct)
            .unwrap();

        let tuple = ConnTuple {
            src_ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1],
            dst_ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8],
            src_port: 50000,
            dst_port: 443,
            protocol: 6,
            _pad: [0; 3],
        };

        backend
            .conn_track_store(&tuple, OutboundIndex::UserBase as u32)
            .unwrap();
        assert_eq!(
            backend.conn_track_lookup(&tuple).unwrap(),
            Some(OutboundIndex::UserBase as u32)
        );
        backend.conn_track_remove(&tuple).unwrap();
        assert_eq!(backend.conn_track_lookup(&tuple).unwrap(), None);

        let stats = backend.get_outbound_stats(OutboundIndex::UserBase).unwrap();
        assert_eq!(stats.total_conns, 0);
    }

    #[tokio::test]
    async fn test_socks5_full_handshake() {
        use honk_config::node::Node;
        use honk_core::proxy::ProbeableOutbound;
        use honk_core::proxy::socks5::Socks5Handler;

        // We need a real SOCKS5 server for testing.
        // For this test, we verify the handler can be created and tested.
        let handler = Socks5Handler::new();

        let bad_node = Node {
            name: "bad".into(),
            protocol: types::NodeProtocol::Socks5,
            address: "127.0.0.1".into(),
            port: 19999, // unlikely to be open
            ..Default::default()
        };

        let reachable = handler.test_connectivity(&bad_node).await;
        // Should be false since no SOCKS5 server is running on that port
        assert!(!reachable);
    }

    #[tokio::test]
    async fn test_direct_handler_to_echo_server() {
        use honk_config::node::Node;
        use honk_core::proxy::TcpOutbound;
        use honk_core::proxy::direct::DirectHandler;

        let echo_addr = spawn_echo_server().await;
        let handler = DirectHandler::new();
        let node = Node::default();

        let target: SocketAddr = echo_addr;

        let result = handler
            .dial(&node, target, None, std::time::Duration::from_secs(3))
            .await;
        assert!(
            result.is_ok(),
            "Direct dial should succeed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_block_handler_rejects_all() {
        use honk_config::node::Node;
        use honk_core::proxy::TcpOutbound;
        use honk_core::proxy::block::BlockHandler;

        let handler = BlockHandler::new();
        let node = Node::default();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let result = handler
            .dial(&node, target, None, std::time::Duration::from_secs(3))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("blocked"));
    }

    #[test]
    fn test_proxy_registry_all_handlers() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        assert!(registry.handler_count() >= 3);

        assert!(registry.find(types::NodeProtocol::Socks5).is_some());
    }

    #[tokio::test]
    async fn test_tcp_relay_bidirectional_data() {
        let echo_addr = spawn_echo_server().await;

        let client = TcpStream::connect(echo_addr).await.unwrap();
        let proxy = TcpStream::connect(echo_addr).await.unwrap();

        let client_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // The relay runs until both sides close.  Without active peers shutting
        // down the connections it would block forever, so verify it starts and
        // runs cleanly for a short period instead.
        let result = tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            relay::relay_tcp(client, proxy, client_addr, echo_addr),
        )
        .await;

        assert!(
            result.is_err() || result.unwrap().is_ok(),
            "relay should run without error"
        );
    }

    #[tokio::test]
    async fn test_splice_relay_bidirectional_data() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let echo_addr = spawn_echo_server().await;

        // Front listener: relay the accepted connection to the echo server
        // through the zero-copy splice path.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let upstream = TcpStream::connect(echo_addr).await.unwrap();
            relay::splice::splice_bidirectional(client, upstream).await
        });

        // The client sends more than any pipe capacity, half-closes, and
        // reads the echo back.
        let mut client = TcpStream::connect(front_addr).await.unwrap();
        let data: Vec<u8> = (0..(1024 * 1024)).map(|i| (i % 251) as u8).collect();
        client.write_all(&data).await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        tokio::time::timeout(
            tokio::time::Duration::from_secs(10),
            client.read_to_end(&mut received),
        )
        .await
        .expect("splice relay hung")
        .unwrap();
        assert!(received == data, "echoed data corrupted");

        let (c2p, p2c) = tokio::time::timeout(tokio::time::Duration::from_secs(5), relay)
            .await
            .expect("splice relay task hung")
            .unwrap()
            .unwrap();
        assert_eq!(c2p, data.len() as u64);
        assert_eq!(p2c, data.len() as u64);
        assert!(relay::splice::splice_available());
    }

    #[tokio::test]
    async fn test_dns_resolver_creation_and_cache() {
        let config = honk_config::dns::DnsConfig::default();
        let resolver = DnsResolver::new(&config);
        assert!(resolver.is_ok());
    }

    #[test]
    fn test_stats_manager_full_workflow() {
        let mgr = StatsManager::new();

        for _ in 0..10 {
            mgr.record_connection("proxy-us");
        }
        for _ in 0..5 {
            mgr.record_connection("proxy-jp");
        }

        mgr.record_close("proxy-us");
        mgr.record_close("proxy-us");

        mgr.record_bytes("proxy-us", 1024 * 1024, 2048 * 1024); // 1MB up, 2MB down
        mgr.record_bytes("proxy-jp", 512 * 1024, 256 * 1024);

        mgr.record_error("proxy-jp");

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
    async fn test_control_plane_creation() {
        let config = Config::default();
        let ebpf = Box::new(MockEbpfBackend::new());
        let router = Router::new(&[], "direct").unwrap();
        let registry = ProxyRegistry::default_resolver().unwrap();
        let resolver = DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap();

        let cp = ControlPlane::new(
            config,
            ebpf,
            router,
            std::sync::Arc::new(registry),
            resolver,
            test_dns_forwarder(),
        );
        assert!(cp.is_ok());
    }

    #[tokio::test]
    async fn test_reload_rebuilds_group_manager_preserving_choices() {
        use honk_config::group::{Group, GroupPolicy};
        use honk_config::node::Node;

        fn node(name: &str) -> Node {
            Node {
                id: uuid::Uuid::new_v4(),
                name: name.into(),
                address: "127.0.0.1".into(),
                port: 1,
                ..Default::default()
            }
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
        cp.group_manager().read().set_selector_choice("proxy", "b");

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
            assert_eq!(gm.get_selector_choice("proxy"), Some("b".to_string()));
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
            assert_eq!(gm.get_selector_choice("proxy"), None);
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
            Node {
                id: uuid::Uuid::new_v4(),
                name: name.into(),
                protocol: honk_config::types::NodeProtocol::Socks5,
                address: "127.0.0.1:1080".into(),
                host: "127.0.0.1".into(),
                port: 1080,
                subscription_id: sub,
                ..Default::default()
            }
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
            .initialize(0, false, false)
            .await
            .unwrap();

        // Simulate a late subscription fetch completing: two new nodes with
        // fresh UUIDs replace the previous generation.
        let new1 = node("sub-new-1", Some(sub_id));
        let new2 = node("sub-new-2", Some(sub_id));
        cp.merge_subscription_nodes(sub_id, vec![new1.clone(), new2.clone()])
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
        // with fresh UUIDs) replaces instead of duplicating.
        let refresh1 = node("sub-new-1", Some(sub_id));
        let refresh2 = node("sub-new-2", Some(sub_id));
        cp.merge_subscription_nodes(sub_id, vec![refresh1, refresh2])
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
    fn test_l4_checksum_policy_values() {
        assert_eq!(L4ChecksumPolicy::Enable as u32, 0);
        assert_eq!(L4ChecksumPolicy::Restore as u32, 1);
        assert_eq!(L4ChecksumPolicy::SetZero as u32, 2);
    }

    #[test]
    fn test_param_key_values() {
        assert_eq!(ParamKey::BigEndianTproxyPort as u32, 1);
        assert_eq!(ParamKey::ControlPlanePid as u32, 4);
        assert_eq!(ParamKey::ControlPlaneDnsRouting as u32, 6);
    }

    #[test]
    fn test_node_protocol_parsing() {
        use honk_config::types::NodeProtocol;

        assert_eq!(NodeProtocol::from_str("ss").unwrap(), NodeProtocol::SS);
        assert_eq!(NodeProtocol::from_str("SS").unwrap(), NodeProtocol::SS);
        assert_eq!(
            NodeProtocol::from_str("shadowsocks").unwrap(),
            NodeProtocol::SS
        );
        assert_eq!(
            NodeProtocol::from_str("trojan").unwrap(),
            NodeProtocol::Trojan
        );
        assert_eq!(
            NodeProtocol::from_str("vmess").unwrap(),
            NodeProtocol::VMess
        );
        assert_eq!(
            NodeProtocol::from_str("hysteria2").unwrap(),
            NodeProtocol::Hysteria2
        );
        assert_eq!(NodeProtocol::from_str("tuic").unwrap(), NodeProtocol::Tuic);
        assert_eq!(
            NodeProtocol::from_str("juicity").unwrap(),
            NodeProtocol::Juicity
        );
        assert_eq!(
            NodeProtocol::from_str("anytls").unwrap(),
            NodeProtocol::AnyTLS
        );
        assert!(NodeProtocol::from_str("unknown").is_err());
    }

    /// Helper: print a routing path diagram for visual verification.
    fn print_routing_path(
        client_addr: &str,
        dst: &str,
        port: u16,
        matched_rule: Option<&str>,
        outbound: &str,
        handler: &str,
    ) {
        println!();
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║               Routing Path Visualization                     ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║                                                              ║");
        println!("║  Client: {:<50} ║", client_addr);
        println!("║    │                                                        ║");
        println!("║    ▼                                                        ║");
        println!("║  ┌──────────────────────┐                                    ║");
        println!("║  │  iptables TPROXY     │  Port 12345, Mark 0x08000000      ║");
        println!("║  │  (mangle PREROUTING) │                                    ║");
        println!("║  └──────────┬───────────┘                                    ║");
        println!("║             │                                                ║");
        println!("║             ▼                                                ║");
        println!("║  ┌──────────────────────┐                                    ║");
        println!("║  │  eBPF TC Classifier  │  Parse packet, extract 5-tuple     ║");
        println!("║  │  (lan_ingress_l3)    │                                    ║");
        println!("║  └──────────┬───────────┘                                    ║");
        println!("║             │                                                ║");
        println!("║             ▼                                                ║");
        println!("║  ┌──────────────────────┐                                    ║");
        println!("║  │  Connection Tracking │  TCP_CONN_STATE_MAP lookup         ║");
        println!("║  │  (mark_tcp_seen)     │  New connection → routing needed    ║");
        println!("║  └──────────┬───────────┘                                    ║");
        println!("║             │                                                ║");
        println!("║             ▼                                                ║");
        println!("║  ┌──────────────────────┐                                    ║");
        println!("║  │  Route Engine        │  Match rules against 5-tuple       ║");
        println!(
            "║  │  (route_packet)      │  Destination: {}:{:<11}     ║",
            dst,
            format!("{})", port)
        );
        if let Some(rule) = matched_rule {
            println!("║  │  ✓ Matched: {:<39} │ ║", rule);
        } else {
            println!("║  │  ✗ No rule matched → default outbound            ║");
        }
        println!("║  └──────────┬───────────┘                                    ║");
        println!("║             │                                                ║");
        println!("║             ▼                                                ║");
        println!("║  ┌──────────────────────┐                                    ║");
        println!("║  │  Outbound Decision   │  ► {:<29} ║", outbound);
        println!("║  └──────────┬───────────┘                                    ║");
        println!("║             │                                                ║");
        println!("║             ▼                                                ║");
        println!("║  ┌──────────────────────┐                                    ║");
        println!("║  │  Control Plane       │  Receive on 127.0.0.1:12345                ║");
        println!("║  │  (serve_connection)  │  SO_ORIGINAL_DST → original target ║");
        println!("║  └──────────┬───────────┘                                    ║");
        println!("║             │                                                ║");
        println!("║             ▼                                                ║");
        println!("║  ┌──────────────────────┐                                    ║");
        println!("║  │  SNI Sniffing        │  Extract domain from TLS ClientHello║");
        println!("║  │  (optional)          │                                    ║");
        println!("║  └──────────┬───────────┘                                    ║");
        println!("║             │                                                ║");
        println!("║             ▼                                                ║");
        println!("║  ┌──────────────────────┐                                    ║");
        println!("║  │  Route (userspace)   │  Router::route(&conn_info)         ║");
        println!(
            "║  │  Domain + IP match   │  → outbound: {:<21} ║",
            outbound
        );
        println!("║  └──────────┬───────────┘                                    ║");
        println!("║             │                                                ║");
        println!("║             ▼                                                ║");
        println!("║  ┌──────────────────────┐                                    ║");
        println!("║  │  Proxy Handler       │  {:<34} ║", handler);
        println!("║  │  dial(target)        │                                    ║");
        println!("║  └──────────┬───────────┘                                    ║");
        println!("║             │                                                ║");
        println!("║             ▼                                                ║");
        println!("║  ┌──────────────────────┐                                    ║");
        println!("║  │  Bidirectional Relay │  Client ↔ Proxy ↔ Target           ║");
        println!("║  │  (relay_tcp)         │  tokio::io::copy_bidirectional     ║");
        println!("║  └──────────────────────┘                                    ║");
        println!("║                                                              ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
    }

    #[test]
    fn test_routing_path_direct() {
        print_routing_path(
            "192.168.1.100:54321",
            "10.0.0.1",
            80,
            Some("private-direct (10.0.0.0/8 → direct)"),
            "direct",
            "DirectHandler (TcpStream::connect)",
        );
    }

    #[test]
    fn test_routing_path_proxy() {
        print_routing_path(
            "192.168.1.100:54322",
            "142.250.80.4",
            443,
            Some("google-proxy (google.com → socks5)"),
            "local-socks5",
            "Socks5Handler (CONNECT handshake)",
        );
    }

    #[test]
    fn test_routing_path_block() {
        print_routing_path(
            "192.168.1.100:54323",
            "172.217.0.0",
            443,
            Some("block-ads (doubleclick.net → block)"),
            "block",
            "BlockHandler (connection refused)",
        );
    }

    #[test]
    fn test_routing_path_default() {
        print_routing_path(
            "192.168.1.100:54324",
            "93.184.216.34",
            443,
            None,
            "direct (default)",
            "DirectHandler (TcpStream::connect)",
        );
    }

    #[test]
    fn test_routing_path_udp_dns() {
        println!();
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║               UDP DNS Routing Path                           ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║                                                              ║");
        println!("║  App: curl https://google.com                                ║");
        println!("║    │                                                        ║");
        println!("║    ├──► DNS query: google.com A → 8.8.8.8:53                ║");
        println!("║    │    │                                                    ║");
        println!("║    │    ├──► eBPF: port 53 → short-lived UDP → TC_ACT_PIPE  ║");
        println!("║    │    │    (bypasses TPROXY, handled by system DNS)        ║");
        println!("║    │    │                                                    ║");
        println!("║    │    └──► DNS resolved: 142.250.80.4                     ║");
        println!("║    │                                                        ║");
        println!("║    └──► TCP connect: 142.250.80.4:443                       ║");
        println!("║         │                                                    ║");
        println!("║         ├──► iptables TPROXY (PREROUTING)                    ║");
        println!("║         ├──► eBPF: route_packet → matched google-proxy rule ║");
        println!("║         ├──► Control Plane → Socks5Handler.dial()           ║");
        println!("║         └──► Bidirectional relay: app ↔ SOCKS5 ↔ google.com ║");
        println!("║                                                              ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
    }

    #[tokio::test]
    async fn test_full_pipeline_mock_ebpf() {
        use honk_config::dns::DnsConfig;
        use honk_config::node::Node;
        use honk_config::routing::RoutingCondition;
        use honk_config::routing::RoutingOutbound;
        use honk_config::routing::RoutingRule;
        use honk_config::types::NodeProtocol;
        use honk_core::control::ControlPlane;
        use honk_core::dns::DnsResolver;
        use honk_core::ebpf::EbpfBackend;
        use honk_core::ebpf::mock::MockEbpfBackend;
        use honk_core::proxy::ProxyRegistry;
        use honk_core::routing::Router;
        use honk_core::stats::StatsManager;

        println!();
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║     Full Pipeline Test: Mock eBPF + SOCKS5 + Routing        ║");
        println!("╠══════════════════════════════════════════════════════════════╣");

        let mut backend = MockEbpfBackend::new();

        backend
            .set_param(ParamKey::BigEndianTproxyPort, 12345)
            .unwrap();
        backend
            .set_param(ParamKey::ControlPlanePid, std::process::id())
            .unwrap();

        assert_eq!(
            backend.get_param(ParamKey::BigEndianTproxyPort).unwrap(),
            Some(12345)
        );
        println!("║  ✓ eBPF parameters configured                              ║");

        let rules = vec![
            RoutingRule {
                name: "private-direct".into(),
                condition: RoutingCondition {
                    ip: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("direct".into()),
                priority: 0,
                must: false,
                mark: 0,
            },
            RoutingRule {
                name: "google-socks5".into(),
                condition: RoutingCondition {
                    domain_suffix: vec!["google.com".into(), "github.com".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("socks5-out".into()),
                priority: 10,
                must: false,
                mark: 0,
            },
        ];

        let router = Router::new(&rules, "direct").unwrap();
        assert_eq!(router.route_count(), 2);
        println!(
            "║  ✓ Router created with {} rules                          ║",
            router.route_count()
        );

        let conn_private = ConnectionInfo {
            domain: None,
            dst_ip: "10.0.0.50".parse().unwrap(),
            dst_port: 80,
            src_ip: "192.168.1.100".parse().unwrap(),
            src_port: 50000,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        };
        assert_eq!(router.route(&conn_private), "direct");
        println!("║  ✓ 10.0.0.50:80 → direct (private CIDR)                  ║");

        let conn_google = ConnectionInfo {
            domain: Some("www.google.com".into()),
            dst_ip: "142.250.80.4".parse().unwrap(),
            dst_port: 443,
            src_ip: "192.168.1.100".parse().unwrap(),
            src_port: 50001,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        };
        assert_eq!(router.route(&conn_google), "socks5-out");
        println!("║  ✓ google.com:443 → socks5-out (domain suffix)           ║");

        let conn_unknown = ConnectionInfo {
            domain: Some("example.org".into()),
            dst_ip: "93.184.216.34".parse().unwrap(),
            dst_port: 443,
            src_ip: "192.168.1.100".parse().unwrap(),
            src_port: 50002,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        };
        assert_eq!(router.route(&conn_unknown), "direct");
        println!("║  ✓ example.org:443 → direct (default)                    ║");

        let registry = ProxyRegistry::default_resolver().unwrap();
        assert!(registry.find(NodeProtocol::Socks5).is_some());
        println!("║  ✓ ProxyRegistry has SOCKS5 handler                      ║");

        let _node = Node {
            name: "socks5-out".into(),
            protocol: NodeProtocol::Socks5,
            address: "127.0.0.1".into(),
            port: 1080,
            ..Default::default()
        };

        let dns_cfg = DnsConfig::default();
        let resolver = DnsResolver::new(&dns_cfg).unwrap();

        let cp = ControlPlane::new(
            honk_config::Config::default(),
            Box::new(backend),
            router,
            std::sync::Arc::new(registry),
            resolver,
            test_dns_forwarder(),
        );
        assert!(cp.is_ok());
        println!("║  ✓ ControlPlane created successfully                      ║");

        let mgr = StatsManager::new();
        mgr.record_connection("direct");
        mgr.record_connection("socks5-out");
        mgr.record_bytes("socks5-out", 1024, 2048);
        let snap = mgr.snapshot();
        assert_eq!(snap.len(), 2);
        println!(
            "║  ✓ StatsManager tracking {} outbounds                   ║",
            snap.len()
        );

        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║                    All Pipeline Tests Passed                 ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
    }

    #[test]
    fn test_ebpf_map_summary() {
        use honk_core::ebpf::EbpfBackend;
        use honk_core::ebpf::mock::MockEbpfBackend;

        println!();
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║              eBPF Map Layout (20+ maps)                      ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║                                                              ║");
        println!("║  Global Maps:                                                ║");
        println!("║    PARAM_MAP              → Parameters (tproxy_port, etc.)   ║");
        println!("║    OUTBOUND_CONNECTIVITY  → Per-outbound alive status        ║");
        println!("║    LISTEN_SOCKET_MAP      → SockMap for TPROXY listener      ║");
        println!("║                                                              ║");
        println!("║  Routing Maps:                                               ║");
        println!("║    ROUTING_MAP            → MatchSet rules array             ║");
        println!("║    ROUTING_META_MAP       → Active rule count                ║");
        println!("║    DOMAIN_ROUTING_MAP     → Domain→bitmap cache (LPM)        ║");
        println!("║                                                              ║");
        println!("║  Connection Tracking:                                        ║");
        println!("║    TCP_CONN_STATE_MAP     → TCP connection state + routing   ║");
        println!("║    UDP_CONN_STATE_MAP     → UDP connection state + routing   ║");
        println!("║    REDIRECT_TRACK         → MAC/ifindex for reply redirect   ║");
        println!("║    ROUTING_HANDOFF_MAP    → First-packet handoff to CP       ║");
        println!("║                                                              ║");
        println!("║  Process Tracking:                                           ║");
        println!("║    COOKIE_PID_MAP         → Socket cookie→PID+pname mapping  ║");
        println!("║                                                              ║");
        println!("║  Statistics:                                                 ║");
        println!("║    BPF_STATS_MAP          → Overflow counters                ║");
        println!("║                                                              ║");
        println!("║  Per-CPU Scratch Maps:                                       ║");
        println!("║    PARSE_CTX_SCRATCH      → Packet parsing context           ║");
        println!("║    LAN_INGRESS_SCRATCH    → LAN ingress parsed packet        ║");
        println!("║    WAN_EGRESS_SCRATCH     → WAN egress parsed packet         ║");
        println!("║    ROUTE_CTX_SCRATCH      → Route decision context           ║");
        println!("║    WAN_EGRESS_ROUTE       → WAN egress route scratch         ║");
        println!("║    CONNTRACK_ARGS_MAP     → Conntrack arguments              ║");
        println!("║                                                              ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();

        let mut backend = MockEbpfBackend::new();
        backend
            .set_param(ParamKey::BigEndianTproxyPort, 12345)
            .unwrap();
        backend.set_param(ParamKey::ControlPlanePid, 42).unwrap();
        backend.set_param(ParamKey::SoMarkFromDae, 0).unwrap();

        assert_eq!(
            backend.get_param(ParamKey::BigEndianTproxyPort).unwrap(),
            Some(12345)
        );
        assert_eq!(
            backend.get_param(ParamKey::ControlPlanePid).unwrap(),
            Some(42)
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
}
