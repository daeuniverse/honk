use std::sync::Arc;

use honk_config::group::GroupPolicy;
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_outbound::group::GroupManager;
use tokio::sync::RwLock;

use super::*;
use crate::dns::forwarder::DnsUpstreamPool;
use crate::routing::Router;

fn route(ip: &str, outbound: &str) -> RoutingRule {
    RoutingRule {
        name: "dns-route".into(),
        condition: RoutingCondition {
            ip: vec![ip.into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple(outbound.into()),
        priority: 0,
        must: false,
        mark: 0,
    }
}

#[tokio::test]
async fn dns_proxy_query_survives_traffic_registry_retirement() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut node = test_node("dns-proxy");
    let address = listener.local_addr().unwrap();
    node.address = address.ip().to_string();
    node.port = address.port();
    node.outbound =
        honk_config::node::OutboundConfig::from_protocol(honk_config::types::NodeProtocol::Socks5);
    node.id = node.derive_id();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.read_exact(&mut [0; 3]).await.unwrap();
        stream.write_all(&[5, 0]).await.unwrap();
        stream.read_exact(&mut [0; 10]).await.unwrap();
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 53])
            .await
            .unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut query = vec![0; length as usize];
        stream.read_exact(&mut query).await.unwrap();
        let response = mock_dns_response(u16::from_be_bytes([query[0], query[1]]));
        stream.write_u16(response.len() as u16).await.unwrap();
        stream.write_all(&response).await.unwrap();
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    });
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
            .unwrap(),
    );
    let upstream = DnsUpstream {
        outbound: Some(node.name.clone()),
        ..make_upstream("proxy", "1.1.1.1:53", DnsProtocol::Tcp)
    };
    let pool = UpstreamPool::new_with_proxy(
        &[upstream],
        make_router(),
        Some(Arc::new(
            crate::proxy::ProxyRegistry::default_resolver().unwrap(),
        )),
        vec![node],
        vec![],
    )
    .unwrap();
    pool.set_runtime_generation(Arc::clone(&generation))
        .unwrap();

    generation.begin_retirement();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        pool.query("proxy", &mock_dns_query(123)),
    )
    .await
    .expect("retired traffic registry must not block the DNS-owned dial")
    .unwrap();
    assert_eq!(response, mock_dns_response(123));
    pool.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn resolve_dial_leaf_forced_arrow_bypasses_traffic_router() {
    let forced = test_node("forced-node");
    let routed = test_node("routed-node");
    let forced_group = test_group("force_g", GroupPolicy::Selector, vec![forced.id]);
    let routed_group = test_group("route_g", GroupPolicy::Selector, vec![routed.id]);
    let group_manager = GroupManager::new(
        &[forced_group, routed_group],
        &[forced.clone(), routed.clone()],
    )
    .into_shared();
    let traffic = Arc::new(RwLock::new(
        Router::new(&[route("8.8.8.8/32", "route_g")], "direct").unwrap(),
    ));
    let upstream = DnsUpstream {
        outbound: Some("force_g".into()),
        ..make_upstream("google", "8.8.8.8:53", DnsProtocol::Udp)
    };
    let pool = UpstreamPool::new_with_proxy(
        &[upstream],
        make_router(),
        None,
        vec![forced, routed],
        vec![],
    )
    .unwrap()
    .with_group_manager(group_manager)
    .with_traffic_router(traffic);

    let entry = pool.entries.get("google").unwrap();
    let leaf = pool.resolve_dial_leaf(entry).await.unwrap().unwrap();
    assert_eq!(leaf.name, "forced-node");
}

#[tokio::test]
async fn resolve_dial_leaf_implicit_uses_traffic_router() {
    let node = test_node("proxy-leaf");
    let group = test_group("proxy", GroupPolicy::Selector, vec![node.id]);
    let group_manager = GroupManager::new(&[group], std::slice::from_ref(&node)).into_shared();
    let traffic = Arc::new(RwLock::new(
        Router::new(&[route("8.8.8.8/32", "proxy")], "direct").unwrap(),
    ));
    let upstream = make_upstream("google", "8.8.8.8:53", DnsProtocol::Udp);
    let pool = UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![node], vec![])
        .unwrap()
        .with_group_manager(group_manager)
        .with_traffic_router(traffic);

    let entry = pool.entries.get("google").unwrap();
    let leaf = pool.resolve_dial_leaf(entry).await.unwrap().unwrap();
    assert_eq!(leaf.name, "proxy-leaf");
}

#[tokio::test]
async fn implicit_quic_routes_use_data_udp_health() {
    let node = test_node("proxy-leaf");
    let group = test_group("proxy", GroupPolicy::Score, vec![node.id]);
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    alive.report_unavailable_forced(
        node.id,
        honk_outbound::alive::ProbeDomain::DnsUdp,
        honk_outbound::alive::IpVersion::V4,
    );
    let manager = GroupManager::with_alive_set(&[group], std::slice::from_ref(&node), Some(alive))
        .into_shared();
    let traffic = Arc::new(RwLock::new(
        Router::new(
            &[RoutingRule {
                name: "udp-dns".into(),
                condition: RoutingCondition {
                    protocol: vec!["udp".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("proxy".into()),
                priority: 0,
                must: false,
                mark: 0,
            }],
            "direct",
        )
        .unwrap(),
    ));
    let upstreams = [
        make_upstream("quic", "192.0.2.53:853", DnsProtocol::Quic),
        make_upstream("h3", "192.0.2.53:443", DnsProtocol::H3),
    ];
    let pool =
        UpstreamPool::new_with_proxy(&upstreams, make_router(), None, vec![node.clone()], vec![])
            .unwrap()
            .with_group_manager(manager)
            .with_traffic_router(traffic);

    for name in ["quic", "h3"] {
        let route = pool.resolve_dial_route(&pool.entries[name]).await.unwrap();
        assert_eq!(
            route.node.as_ref().expect("UDP traffic route").node.id,
            node.id
        );
        let context = route.feedback.expect("Score feedback").context().clone();
        assert_eq!(context.network, honk_outbound::group::SelectionNetwork::Udp);
        assert_eq!(
            context.probe_domain,
            honk_outbound::alive::ProbeDomain::DataUdp
        );
    }
}

/// The proxied carrier of a plain `udp://` upstream is pooled TCP-DNS
/// (never real UDP through the node), so its selection follows TCP health:
/// a node whose `:53` UDP probe died keeps serving TCP-carried DNS.
#[tokio::test]
async fn implicit_udp_route_follows_tcp_carrier_health() {
    let node = test_node("proxy-leaf");
    let group = test_group("proxy", GroupPolicy::Score, vec![node.id]);
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    alive.report_unavailable_forced(
        node.id,
        honk_outbound::alive::ProbeDomain::DnsUdp,
        honk_outbound::alive::IpVersion::V4,
    );
    let manager = GroupManager::with_alive_set(&[group], std::slice::from_ref(&node), Some(alive))
        .into_shared();
    let traffic = Arc::new(RwLock::new(
        Router::new(
            &[RoutingRule {
                name: "udp-dns".into(),
                condition: RoutingCondition {
                    protocol: vec!["udp".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("proxy".into()),
                priority: 0,
                must: false,
                mark: 0,
            }],
            "direct",
        )
        .unwrap(),
    ));
    let upstreams = [make_upstream("udp", "192.0.2.53:53", DnsProtocol::Udp)];
    let pool =
        UpstreamPool::new_with_proxy(&upstreams, make_router(), None, vec![node.clone()], vec![])
            .unwrap()
            .with_group_manager(manager)
            .with_traffic_router(traffic);

    let route = pool.resolve_dial_route(&pool.entries["udp"]).await.unwrap();
    assert_eq!(
        route.node.as_ref().expect("TCP-carried route").node.id,
        node.id
    );
    let context = route.feedback.expect("Score feedback").context().clone();
    assert_eq!(context.network, honk_outbound::group::SelectionNetwork::Tcp);
    assert_eq!(context.probe_domain, honk_outbound::alive::ProbeDomain::Tcp);
}

#[tokio::test]
async fn resolve_dial_leaf_implicit_direct_when_route_is_direct() {
    let traffic = Arc::new(RwLock::new(
        Router::new(&[route("223.5.5.5/32", "direct")], "proxy").unwrap(),
    ));
    let upstream = make_upstream("alidns", "223.5.5.5:53", DnsProtocol::Udp);
    let pool = UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![], vec![])
        .unwrap()
        .with_traffic_router(traffic);

    let entry = pool.entries.get("alidns").unwrap();
    assert!(pool.resolve_dial_leaf(entry).await.unwrap().is_none());
}

#[tokio::test]
async fn block_routes_fail_closed() {
    use honk_config::Config;
    use honk_config::dns::DnsStrategy;
    use honk_outbound::proxy::{PacketRejection, packet_rejection};

    let block = Config::builtin_block_node();
    let direct = Config::builtin_direct_node();
    let member = Group {
        default: Some(block.name.clone()),
        ..test_group("member", GroupPolicy::Selector, vec![direct.id, block.id])
    };
    let final_group = Group {
        final_outbound: Some(block.name.clone()),
        ..test_group("terminal", GroupPolicy::Selector, vec![])
    };
    let manager = Arc::new(GroupManager::new(&[member, final_group], &[block, direct]));
    for (address, protocol, forced, routed, reason) in [
        (
            "blocked-bootstrap.test:853",
            DnsProtocol::Quic,
            Some("block"),
            "direct",
            "outbound 'block' rejected the dial",
        ),
        (
            "127.0.0.1:443",
            DnsProtocol::H3,
            None,
            "block",
            "DNS dial route selected block",
        ),
        (
            "127.0.0.1:53",
            DnsProtocol::Udp,
            Some("member"),
            "direct",
            "DNS outbound group selected block",
        ),
        (
            "127.0.0.1:53",
            DnsProtocol::Tcp,
            None,
            "terminal",
            "DNS outbound group selected block",
        ),
    ] {
        let upstream = DnsUpstream {
            outbound: forced.map(str::to_owned),
            ..make_upstream("default", address, protocol)
        };
        let router = make_router();
        let pool = Arc::new(
            UpstreamPool::new_with_proxy_and_bootstrap(
                &[upstream],
                Arc::clone(&router),
                None,
                vec![],
                vec![],
                honk_outbound::bootstrap::BootstrapResolver::parse("127.0.0.1:9"),
                DnsStrategy::Ipv4Only,
            )
            .unwrap()
            .with_socket_budget(crate::dns::transport::DnsSocketBudget::new(0))
            .with_group_manager_snapshot(Arc::clone(&manager))
            .with_traffic_router_snapshot(Arc::new(Router::new(&[], routed).unwrap())),
        );
        let forwarder = crate::dns::forwarder::DnsForwarder::new(
            Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>,
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                32,
            ))),
            router,
        )
        .with_strategy(DnsStrategy::Ipv4Only);
        let error = crate::dns::DnsService::with_forwarder(Arc::new(forwarder))
            .resolve_name_with_fallback("example.test", |_| async {
                panic!("a blocked DNS route must not fall back")
            })
            .await
            .expect_err("blocked DNS route");
        assert_eq!(packet_rejection(&error), Some(PacketRejection::Policy));
        assert!(format!("{error:#}").contains(reason), "{error:#}");
        assert_eq!(pool.lifecycle_stats(), TransportLifecycleStats::default());
        pool.close().await;
    }
}

#[tokio::test]
async fn resolve_dial_leaf_implicit_default_fallback() {
    let traffic = Arc::new(RwLock::new(Router::new(&[], "direct").unwrap()));
    let upstream = make_upstream("any", "1.1.1.1:53", DnsProtocol::Udp);
    let pool = UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![], vec![])
        .unwrap()
        .with_traffic_router(traffic);

    let entry = pool.entries.get("any").unwrap();
    assert!(pool.resolve_dial_leaf(entry).await.unwrap().is_none());
}

#[tokio::test]
async fn forced_score_route_keeps_target_and_nested_attribution() {
    let node = test_node("proxy-leaf");
    let child = test_group("child", GroupPolicy::Score, vec![node.id]);
    let mut parent = test_group("parent", GroupPolicy::Score, vec![]);
    parent.groups.push("child".into());
    let manager = Arc::new(GroupManager::new(
        &[parent, child],
        std::slice::from_ref(&node),
    ));
    let upstream = DnsUpstream {
        outbound: Some("parent".into()),
        ..make_upstream("google", "192.0.2.53:53", DnsProtocol::Udp)
    };
    let pool =
        UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![node.clone()], vec![])
            .unwrap()
            .with_group_manager_snapshot(manager);

    let route = pool
        .resolve_dial_route(&pool.entries["google"])
        .await
        .unwrap();
    assert_eq!(route.target, "192.0.2.53:53".parse().unwrap());
    assert_eq!(route.node.unwrap().node.id, node.id);
    let feedback = route.feedback.expect("score attribution");
    assert_eq!(
        feedback
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>(),
        ["parent", "child"]
    );
}

#[tokio::test]
async fn tcp_fallback_keeps_selected_score_group_chain() {
    let node = test_node("shared-leaf");
    let selected = test_group("selected", GroupPolicy::Score, vec![node.id]);
    let unrelated = test_group("unrelated", GroupPolicy::Score, vec![node.id]);
    let manager = Arc::new(GroupManager::new(
        &[selected, unrelated],
        std::slice::from_ref(&node),
    ));
    let upstream = DnsUpstream {
        outbound: Some("selected".into()),
        ..make_upstream("google", "192.0.2.53:53", DnsProtocol::Udp)
    };
    let pool = UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![node], vec![])
        .unwrap()
        .with_group_manager_snapshot(manager);
    let entry = &pool.entries["google"];
    let route = pool.resolve_dial_route(entry).await.unwrap();
    assert_eq!(
        route
            .feedback
            .as_ref()
            .unwrap()
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>(),
        ["selected"]
    );
    let _business = route.feedback.as_ref().unwrap().begin().unwrap();
    let feedback = pool.tcp_feedback_for_route(entry, &route).unwrap().unwrap();
    assert_eq!(
        feedback
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>(),
        ["selected"]
    );
    assert_eq!(
        feedback.context().network,
        honk_outbound::group::SelectionNetwork::Tcp
    );
    assert_eq!(
        feedback.context().probe_domain,
        honk_outbound::alive::ProbeDomain::Tcp
    );
}

#[tokio::test]
async fn implicit_score_route_keeps_target_and_attribution() {
    let node = test_node("proxy-leaf");
    let group = test_group("proxy", GroupPolicy::Score, vec![node.id]);
    let manager = GroupManager::new(&[group], std::slice::from_ref(&node)).into_shared();
    let traffic = Arc::new(RwLock::new(
        Router::new(&[route("192.0.2.53/32", "proxy")], "direct").unwrap(),
    ));
    let upstream = make_upstream("google", "192.0.2.53:53", DnsProtocol::Udp);
    let pool =
        UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![node.clone()], vec![])
            .unwrap()
            .with_group_manager(manager)
            .with_traffic_router(traffic);

    let route = pool
        .resolve_dial_route(&pool.entries["google"])
        .await
        .unwrap();
    assert_eq!(route.target, "192.0.2.53:53".parse().unwrap());
    assert_eq!(route.node.unwrap().node.id, node.id);
    assert_eq!(route.feedback.unwrap().attributions()[0].group, "proxy");
}

#[tokio::test]
async fn an_exit_group_without_a_group_manager_resolves_to_no_node() {
    let leaf = test_node("leaf");
    let exit = test_node("exit");
    let plain = test_group("plain", GroupPolicy::Selector, vec![leaf.id]);
    let exited = honk_config::group::Group {
        exit: Some("exit".into()),
        ..test_group("exited", GroupPolicy::Selector, vec![leaf.id])
    };
    let upstream = |name: &str, outbound: &str| DnsUpstream {
        outbound: Some(outbound.into()),
        ..make_upstream(name, "8.8.8.8:53", DnsProtocol::Udp)
    };
    let pool = UpstreamPool::new_with_proxy(
        &[upstream("plain", "plain"), upstream("exited", "exited")],
        make_router(),
        None,
        vec![leaf, exit],
        vec![plain, exited],
    )
    .unwrap();
    let plain = pool.entries.get("plain").unwrap();
    assert_eq!(
        pool.resolve_dial_leaf(plain).await.unwrap().unwrap().name,
        "leaf"
    );
    let exited = pool.entries.get("exited").unwrap();
    let error = pool.resolve_dial_leaf(exited).await.unwrap_err();
    assert!(!honk_outbound::proxy::is_packet_rejection(&error));
    assert!(error.to_string().contains("no available node"));
}

#[tokio::test]
async fn routed_and_bare_dns_slots_retire_without_splitting_waiting_lookups() {
    use honk_outbound::group::{OwnedTarget, RoutedTarget};

    use crate::dns::upstream_pool::transports::PooledTransport;

    let leaf = test_node("leaf");
    let exit = test_node("exit");
    let pool = UpstreamPool::new_with_proxy(
        &[make_upstream("tcp", "192.0.2.53:53", DnsProtocol::Tcp)],
        make_router(),
        Some(Arc::new(
            crate::proxy::ProxyRegistry::default_resolver().unwrap(),
        )),
        vec![leaf.clone(), exit.clone()],
        Vec::new(),
    )
    .unwrap();
    let entry = pool.entries.get("tcp").unwrap();
    let direct = OwnedTarget::node(leaf.clone());
    let routed = match honk_config::group_graph::compose(leaf.id, &[leaf.id], [exit.id]) {
        honk_config::group_graph::Composed::Routed(route) => OwnedTarget {
            node: leaf.clone(),
            route: Some(Box::new(RoutedTarget {
                route,
                hop_names: [leaf.name.clone(), exit.name.clone()].into(),
            })),
            collapse: honk_outbound::group::ExitCollapse::None,
        },
        other => panic!("expected a route, got {other:?}"),
    };
    let target = "127.0.0.1:53".parse().unwrap();
    let routed_transport = pool
        .get_transport(entry, Some(&routed), target)
        .await
        .unwrap();
    let routed_slot = Arc::clone(entry.transports.lock().slots.values().next().unwrap());
    let bare_transport = pool
        .get_transport(entry, Some(&direct), target)
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(&routed_transport, &bare_transport));
    drop(routed_transport);
    drop(
        pool.get_transport(entry, Some(&routed), "127.0.0.2:53".parse().unwrap())
            .await
            .unwrap(),
    );

    let (release, wait_for_release) = tokio::sync::oneshot::channel();
    let retirement = routed_slot
        .retire_idle(None, |transport| async move {
            wait_for_release.await.unwrap();
            let PooledTransport::Tcp(tcp) = transport.as_ref() else {
                unreachable!();
            };
            tcp.close().await;
        })
        .unwrap();
    let waiting = pool.get_transport(entry, Some(&routed), target);
    tokio::pin!(waiting);
    assert!(futures::poll!(waiting.as_mut()).is_pending());

    pool.reap_idle_resources();
    pool.join_retired_transports().await;
    assert_eq!(pool.reap_idle_resources(), 1);
    assert_eq!(entry.transports.lock().slots.len(), 2);

    release.send(()).unwrap();
    retirement.await;
    drop(routed_slot);
    pool.reap_idle_resources();
    let late = pool
        .get_transport(entry, Some(&routed), target)
        .await
        .unwrap();
    let queued = waiting.await.unwrap();
    assert!(Arc::ptr_eq(&late, &queued));
    assert!(Arc::ptr_eq(
        &bare_transport,
        &pool
            .get_transport(entry, Some(&direct), target)
            .await
            .unwrap(),
    ));
    drop((late, queued, bare_transport));

    pool.reap_idle_resources();
    pool.join_retired_transports().await;
    assert_eq!(pool.reap_idle_resources(), 2);
    assert!(entry.transports.lock().slots.is_empty());
    assert_eq!(
        pool.lifecycle_stats(),
        TransportLifecycleStats {
            init_count: 4,
            close_count: 4,
            tasks: 0,
        },
    );
    pool.close().await;
}

#[tokio::test]
async fn proxy_codec_fault_keeps_its_hop_through_dns_tls_and_retry() {
    use crate::test_support::socks5_relay;
    use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
    use honk_outbound::proxy::{DialFailureScope, dial_failure_scope};
    use honk_outbound::runtime::OutboundRuntimeRegistry;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let front = socks5_relay().await;
        let exit = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = exit.local_addr().unwrap();
        let front_node = Node::from_share_link(&format!("socks5://{}#front", front.addr)).unwrap();
        let exit_node =
            Node::from_share_link(&format!("ss://YWVzLTEyOC1nY206cGFzcw@{exit_addr}#exit"))
                .unwrap();
        let group = Group {
            exit: Some(exit_node.name.clone()),
            final_outbound: Some("block".into()),
            ..test_group("resolver", GroupPolicy::Fallback, vec![front_node.id])
        };
        let nodes = vec![
            front_node,
            exit_node,
            honk_config::Config::builtin_block_node(),
        ];
        let peer = async {
            for _ in 0..8 {
                let (mut socket, _) = exit.accept().await.unwrap();
                // A complete legacy AES-128-GCM salt and an invalid length record.
                socket.write_all(&[0x53; 16 + 2 + 16]).await.unwrap();
                let _ = tokio::io::copy(&mut socket, &mut tokio::io::sink()).await;
            }
        };
        let queries = async {
            for protocol in [DnsProtocol::Tls, DnsProtocol::Https] {
                let alive = Arc::new(AliveDialerSet::new());
                alive.register_node(
                    nodes[0].id,
                    nodes[0].name.clone(),
                    Some(nodes[0].address.clone()),
                );
                alive.report_unavailable_forced(nodes[0].id, ProbeDomain::Tcp, IpVersion::V6);
                let manager = Arc::new(GroupManager::with_alive_set(
                    std::slice::from_ref(&group),
                    &nodes,
                    Some(Arc::clone(&alive)),
                ));
                manager.publish_route_health();
                let pool = UpstreamPool::new_with_proxy(
                    &[DnsUpstream {
                        outbound: Some(group.name.clone()),
                        ..make_upstream("private", "[::1]:853", protocol)
                    }],
                    make_router(),
                    Some(Arc::new(
                        crate::proxy::ProxyRegistry::default_resolver().unwrap(),
                    )),
                    nodes.clone(),
                    vec![group.clone()],
                )
                .unwrap()
                .with_group_manager_snapshot(manager);
                pool.set_runtime_generation(Arc::new(
                    OutboundRuntimeRegistry::build(&nodes).unwrap(),
                ))
                .unwrap();
                for round in 0..2 {
                    let error = pool.query("private", &mock_dns_query(1)).await.unwrap_err();
                    assert_eq!(
                        dial_failure_scope(error.as_ref()),
                        DialFailureScope::Hop(1),
                        "{error:#}"
                    );
                    assert_eq!(
                        alive.is_failure_demoted(nodes[1].id, ProbeDomain::Tcp, IpVersion::V4),
                        round == 1,
                    );
                    assert!(!alive.is_failure_demoted(
                        nodes[1].id,
                        ProbeDomain::Tcp,
                        IpVersion::V6
                    ));
                    assert!(!alive.is_failure_demoted(
                        nodes[0].id,
                        ProbeDomain::Tcp,
                        IpVersion::V4
                    ));
                }
                pool.close().await;
            }
        };
        tokio::join!(peer, queries);
        assert_eq!(*front.requests.lock(), [exit_addr; 8]);
    })
    .await
    .expect("the route must retain actual codec failures through the DNS TLS adapter");
}

#[tokio::test]
async fn routed_tcp_reuse_rejects_a_previous_queries_wire_response() {
    use crate::dns::transport::{read_length_prefixed_into, write_length_prefixed};
    use crate::test_support::{socks5_chain, socks5_relay};
    use honk_outbound::runtime::OutboundRuntimeRegistry;
    use tokio::net::TcpListener;

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let front = socks5_relay().await;
        let exit = socks5_relay().await;
        let [_, front_node, exit_node] = socks5_chain(&front, &exit);
        let group = Group {
            exit: Some(exit_node.name.clone()),
            ..test_group("resolver", GroupPolicy::Fallback, vec![front_node.id])
        };
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let nodes = vec![front_node, exit_node];
        let manager = Arc::new(GroupManager::new(std::slice::from_ref(&group), &nodes));
        let generation = Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap());
        let pool = UpstreamPool::new_with_proxy(
            &[DnsUpstream {
                outbound: Some(group.name.clone()),
                ..make_upstream("private", &address.to_string(), DnsProtocol::Tcp)
            }],
            make_router(),
            Some(Arc::new(
                crate::proxy::ProxyRegistry::default_resolver().unwrap(),
            )),
            nodes,
            vec![group],
        )
        .unwrap()
        .with_group_manager_snapshot(manager);
        pool.set_runtime_generation(generation).unwrap();

        let server = async {
            let (mut reused, _) = origin.accept().await.unwrap();
            let mut query = Vec::new();
            read_length_prefixed_into(&mut reused, &mut query, None)
                .await
                .unwrap();
            let mut response = mock_dns_response(u16::from_be_bytes([query[0], query[1]]));
            write_length_prefixed(&mut reused, &response).await.unwrap();
            read_length_prefixed_into(&mut reused, &mut query, None)
                .await
                .unwrap();
            write_length_prefixed(&mut reused, &response).await.unwrap();
            let (mut replacement, _) = origin.accept().await.unwrap();
            read_length_prefixed_into(&mut replacement, &mut query, None)
                .await
                .unwrap();
            response[..2].copy_from_slice(&query[..2]);
            *response.last_mut().unwrap() = 2;
            write_length_prefixed(&mut replacement, &response)
                .await
                .unwrap();
        };
        let queried = async {
            let query = mock_dns_query(42);
            let mut expected = mock_dns_response(42);
            assert_eq!(pool.query("private", &query).await.unwrap(), expected);
            *expected.last_mut().unwrap() = 2;
            assert_eq!(pool.query("private", &query).await.unwrap(), expected);
        };
        tokio::join!(server, queried);
        assert_eq!(*exit.requests.lock(), [address; 2]);
        pool.close().await;
    })
    .await
    .expect("a duplicate from the pooled socket must be discarded before retry");
}

#[tokio::test]
async fn a_pooled_dns_reply_uses_the_query_plans_selector_revision() {
    use crate::dns::transport::{read_length_prefixed_into, write_length_prefixed};
    use crate::test_support::{socks5_chain, socks5_relay};
    use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
    use honk_outbound::group::SelectorNetworks;
    use honk_outbound::runtime::OutboundRuntimeRegistry;
    use std::time::Duration;
    use tokio::net::TcpListener;

    tokio::time::timeout(Duration::from_secs(5), async {
        let front = socks5_relay().await;
        let exit = socks5_relay().await;
        let [_, front_node, exit_node] = socks5_chain(&front, &exit);
        let group = Group {
            exit: Some(exit_node.name.clone()),
            ..test_group(
                "resolver",
                GroupPolicy::Selector,
                vec![front_node.id, exit_node.id],
            )
        };
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let exit_id = exit_node.id;
        let nodes = vec![front_node, exit_node];
        let alive = Arc::new(AliveDialerSet::new());
        let manager = Arc::new(GroupManager::with_alive_set(
            std::slice::from_ref(&group),
            &nodes,
            Some(Arc::clone(&alive)),
        ));
        manager.publish_route_health();
        let generation = Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap());
        let pool = UpstreamPool::new_with_proxy(
            &[DnsUpstream {
                outbound: Some(group.name.clone()),
                ..make_upstream("private", &address.to_string(), DnsProtocol::Tcp)
            }],
            make_router(),
            Some(Arc::new(
                crate::proxy::ProxyRegistry::default_resolver().unwrap(),
            )),
            nodes,
            vec![group],
        )
        .unwrap()
        .with_group_manager_snapshot(Arc::clone(&manager));
        pool.set_runtime_generation(generation).unwrap();

        let server = async {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut wire = Vec::new();
            for _ in 0..2 {
                read_length_prefixed_into(&mut stream, &mut wire, None)
                    .await
                    .unwrap();
                let id = u16::from_be_bytes([wire[0], wire[1]]);
                write_length_prefixed(&mut stream, &mock_dns_response(id))
                    .await
                    .unwrap();
            }
        };
        let queries = async {
            let set_pin = |member| {
                manager
                    .set_selector_choice("resolver", member, SelectorNetworks::Tcp)
                    .unwrap()
            };
            let strike = || alive.record_dial_failure(exit_id, ProbeDomain::Tcp, IpVersion::V4);
            let demoted = || alive.is_failure_demoted(exit_id, ProbeDomain::Tcp, IpVersion::V4);
            let before = set_pin("front");
            assert_eq!(
                pool.query("private", &mock_dns_query(1)).await.unwrap(),
                mock_dns_response(1),
            );
            strike();
            assert!(!demoted());

            let pause = pool.arm_admission_pause_for_test();
            let wire = mock_dns_query(2);
            let query = pool.query("private", &wire);
            tokio::pin!(query);
            tokio::select! {
                _ = pause.entered.notified() => {},
                _ = &mut query => panic!("query completed before the admission pause"),
            }
            assert!(set_pin("land") > before);
            pause.release.notify_one();
            assert_eq!(query.await.unwrap(), mock_dns_response(2));
            set_pin("front");
            strike();
            assert!(demoted(), "stale DNS success erased the prior dial failure");
        };
        tokio::join!(server, queries);
        assert_eq!(*front.requests.lock(), [exit.addr]);
        assert_eq!(*exit.requests.lock(), [address]);
        pool.close().await;
    })
    .await
    .expect("the two queries must complete through one routed TCP stream");
}

#[tokio::test]
async fn stale_dns_attempt_does_not_consume_the_current_paths_failure() {
    use crate::test_support::socks5_relay;
    use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
    use honk_outbound::group::{ScoreSelectionContext, SelectionNetwork, SelectorNetworks, Target};
    use honk_outbound::proxy::{DialFailureScope, dial_failure_scope};
    use honk_outbound::runtime::OutboundRuntimeRegistry;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SEED_STRIKES: usize = 9;
    const QUERY_DIALS: usize = 4;

    tokio::time::timeout(Duration::from_secs(5), async {
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit = socks5_relay().await;
        let front_node =
            Node::from_share_link(&format!("socks5://{}#front", front.local_addr().unwrap()))
                .unwrap();
        let exit_node = Node::from_share_link(&format!("socks5://{}#land", exit.addr)).unwrap();
        let group = Group {
            exit: Some(exit_node.name.clone()),
            final_outbound: Some("block".into()),
            ..test_group(
                "resolver",
                GroupPolicy::Selector,
                vec![front_node.id, exit_node.id],
            )
        };
        let nodes = vec![
            front_node,
            exit_node,
            honk_config::Config::builtin_block_node(),
        ];
        let alive = Arc::new(AliveDialerSet::new());
        let manager = Arc::new(GroupManager::with_alive_set(
            std::slice::from_ref(&group),
            &nodes,
            Some(Arc::clone(&alive)),
        ));
        manager.publish_route_health();
        let set_pin = |member| {
            manager
                .set_selector_choice("resolver", member, SelectorNetworks::Tcp)
                .unwrap()
        };
        let selected_revision = set_pin("front");
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let (plan, revision) = manager.dial_plan_for_target("resolver", &context, None);
        let entry = plan.entries.into_iter().next().unwrap();
        let target = &manager.own_target(Target {
            node: entry.node,
            route: entry.route,
        });
        let route = target.route().unwrap();
        assert_eq!(route.hops(), [nodes[0].id, nodes[1].id]);

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let registry = Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap());
        let generation = Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap());
        let pool = UpstreamPool::new_with_proxy(
            &[DnsUpstream {
                outbound: Some(group.name.clone()),
                ..make_upstream("private", &address.to_string(), DnsProtocol::Udp)
            }],
            make_router(),
            Some(Arc::clone(&registry)),
            nodes.clone(),
            vec![group],
        )
        .unwrap()
        .with_group_manager_snapshot(Arc::clone(&manager));
        pool.set_runtime_generation(Arc::clone(&generation))
            .unwrap();

        let peer = async {
            for _ in 0..SEED_STRIKES + QUERY_DIALS {
                let (mut stream, _) = front.accept().await.unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(request[..8], [5, 1, 0, 1, 127, 0, 0, 1]);
                assert_eq!(request[8..], exit.addr.port().to_be_bytes());
                stream
                    .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            }
        };
        let query = async {
            for _ in 0..SEED_STRIKES {
                let stamp = revision.admit();
                let error = registry
                    .dial_ref(
                        Arc::clone(&generation),
                        target.dial_ref(),
                        address,
                        None,
                        Duration::from_secs(1),
                    )
                    .await
                    .unwrap_err();
                assert_eq!(
                    dial_failure_scope(error.as_ref()),
                    DialFailureScope::Prefix(1)
                );
                assert!(manager.report_route_failure(
                    "resolver",
                    target,
                    IpVersion::V4,
                    stamp,
                    error.as_ref()
                ));
            }
            assert!(manager.route_prefix_available(route, IpVersion::V4));

            let pause = pool.arm_admission_pause_for_test();
            let wire = mock_dns_query(1);
            let query = pool.query("private", &wire);
            tokio::pin!(query);
            tokio::select! {
                _ = pause.entered.notified() => {},
                _ = &mut query => panic!("query completed before the admission pause"),
            }
            let retired = set_pin("land");
            assert!(retired > selected_revision);
            assert!(set_pin("front") > retired);
            pause.release.notify_one();
            let error = query.await.unwrap_err();
            assert_eq!(
                dial_failure_scope(error.as_ref()),
                DialFailureScope::Prefix(1)
            );
            assert!(!manager.route_prefix_available(route, IpVersion::V4));
            assert!(manager.route_prefix_available(route, IpVersion::V6));
            for node in &nodes[..2] {
                assert!(alive.is_alive_for(node.id, ProbeDomain::Tcp, IpVersion::V4));
                assert!(!alive.is_failure_demoted(node.id, ProbeDomain::Tcp, IpVersion::V4));
            }
        };
        tokio::join!(peer, query);
        assert!(exit.requests.lock().is_empty());
        pool.close().await;
    })
    .await
    .expect("nine seed strikes and four DNS dials must settle through the same prefix");
}
