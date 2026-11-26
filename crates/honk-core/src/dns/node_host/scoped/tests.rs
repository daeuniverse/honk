use super::*;
use crate::dns::{
    cache::DnsCache,
    runtime::{DnsRuntimeParts, RoutingProjectionSnapshot, RuntimeGeneration},
};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};

mod encrypted;

#[tokio::test]
async fn static_nodes_do_not_acquire_a_subscription_through_negation() {
    let explicit = server(Ipv4Addr::new(192, 0, 2, 2), false).await;
    let bootstrap = server(Ipv4Addr::new(192, 0, 2, 4), false).await;
    let mut config = honk_config::parser::parse_dae_config(&format!(
        "dns {{\n upstream {{\n explicit: 'udp://{}' -> direct\n }}\n routing {{\n request {{\n !subtag(excluded) -> explicit\n }}\n }}\n}}",
        explicit.address
    ))
    .unwrap();
    config.global.bootstrap_resolver = bootstrap.address.to_string();
    config
        .nodes
        .push(Node::from_share_link("socks5://static.node.test:443").unwrap());
    let (registry, _runtime, resources) = generation(&config, 4);
    assert_eq!(
        registry
            .resolve_node_host(config.nodes[0].id, "static.node.test")
            .await
            .unwrap(),
        [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4))]
    );
    assert!(explicit.requests.lock().is_empty());
    assert!(!bootstrap.requests.lock().is_empty());
    resources.close().await;
}

struct Server {
    address: SocketAddr,
    requests: Arc<parking_lot::Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn answer(query: &[u8], ip: Ipv4Addr, requests: &parking_lot::Mutex<Vec<String>>) -> Vec<u8> {
    let context = crate::dns::query::QueryContext::parse(query).unwrap();
    requests
        .lock()
        .push(context.qname().unwrap().to_domain_name().unwrap());
    let mut reply = crate::dns::forwarder::make_empty_response(query, &context);
    if context.qtype().unwrap().get() == 1 {
        reply[6..8].copy_from_slice(&1u16.to_be_bytes());
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
        reply.extend_from_slice(&ip.octets());
    }
    reply
}

async fn server(ip: Ipv4Addr, tcp: bool) -> Server {
    let requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let captured = Arc::clone(&requests);
    let (address, task) = if tcp {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let captured = Arc::clone(&captured);
                tokio::spawn(async move {
                    while let Ok(len) = stream.read_u16().await {
                        let mut query = vec![0; usize::from(len)];
                        stream.read_exact(&mut query).await.unwrap();
                        let response = answer(&query, ip, &captured);
                        stream.write_u16(response.len() as u16).await.unwrap();
                        stream.write_all(&response).await.unwrap();
                    }
                });
            }
        });
        (address, task)
    } else {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut query = [0; 4096];
            loop {
                let (length, peer) = socket.recv_from(&mut query).await.unwrap();
                socket
                    .send_to(&answer(&query[..length], ip, &captured), peer)
                    .await
                    .unwrap();
            }
        });
        (address, task)
    };
    Server {
        address,
        requests,
        task,
    }
}

fn provider(name: &str, yaml: &str) -> honk_config::subscription::Subscription {
    honk_config::subscription::Subscription {
        name: name.into(),
        import_dns: true,
        imported_dns: honk_config::subscription::dns::SubscriptionDns::parse(
            &serde_yaml::from_str(yaml).unwrap(),
        )
        .unwrap()
        .map(Arc::new),
        ..Default::default()
    }
}

fn generation(
    config: &Config,
    budget: usize,
) -> (
    Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    Arc<DnsRuntime>,
    Arc<ScopedDns>,
) {
    let router =
        Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(&config.dns).unwrap());
    let budget = DnsSocketBudget::new(budget);
    let pool = Arc::new(pool(config, &config.dns.upstream, Arc::clone(&router), &budget).unwrap());
    let forwarder = Arc::new(
        DnsForwarder::new(
            pool.clone(),
            Arc::new(tokio::sync::Mutex::new(DnsCache::new(8))),
            Arc::clone(&router),
        )
        .with_strategy(config.dns.strategy),
    );
    let dns = prepare(config, pool, router, &budget).unwrap();
    let registry =
        Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap());
    dns.main
        .set_runtime_generation(Arc::clone(&registry))
        .unwrap();
    let runtime = DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(1),
        forwarder,
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            1,
            Arc::new(crate::routing::Router::new(&[], "direct").unwrap()),
        )),
        outbound_runtime: Some(Arc::clone(&registry)),
        transport: dns.clone(),
    });
    bind(&registry, &runtime, Arc::clone(&dns));
    (registry, runtime, dns)
}

#[tokio::test]
async fn same_host_uses_each_node_source_and_business_query_keeps_local_dns() {
    let first = server(Ipv4Addr::new(127, 0, 0, 2), false).await;
    let second = server(Ipv4Addr::new(127, 0, 0, 3), false).await;
    let ordinary = server(Ipv4Addr::new(127, 0, 0, 4), false).await;
    let endpoint = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let endpoint2 = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 3), port))
        .await
        .unwrap();
    let mut config = Config::default();
    config.dns.strategy = DnsStrategy::Ipv4Only;
    config.global.bootstrap_resolver = ordinary.address.to_string();
    config.dns.upstream[0].address = ordinary.address.to_string();
    for (name, dns) in [("first", &first), ("second", &second)] {
        let sub = provider(name, &format!("nameserver: ['udp://{}']", dns.address));
        let mut node =
            Node::from_share_link(&format!("socks5://{name}:password@shared.node.test:{port}"))
                .unwrap();
        node.subscription_id = Some(sub.id);
        config.subscriptions.push(sub);
        config.nodes.push(node);
    }
    let (registry, runtime, resources) = generation(&config, 8);
    for (index, listener) in [endpoint, endpoint2].into_iter().enumerate() {
        let stream = registry
            .scope_node_dials(
                config.nodes[index].id,
                honk_outbound::util::connect_outbound(
                    &format!("shared.node.test:{port}"),
                    Duration::from_secs(1),
                ),
            )
            .await
            .unwrap();
        let (_, peer) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stream.peer_addr().unwrap().ip(),
            listener.local_addr().unwrap().ip()
        );
        assert!(peer.ip().is_loopback());
    }
    let service = DnsService::with_forwarder(Arc::clone(runtime.forwarder()));
    let query = build_dns_query("shared.node.test", 1);
    let reply = service.resolve(&query, Default::default()).await.unwrap();
    assert_eq!(
        extract_answer_ips(&reply),
        [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4))]
    );
    assert_eq!(*first.requests.lock(), ["shared.node.test"]);
    assert_eq!(*second.requests.lock(), ["shared.node.test"]);
    assert_eq!(*ordinary.requests.lock(), ["shared.node.test"]);
    resources.close().await;

    config.dns = honk_config::parser::parse_dae_config(&format!(
        "dns {{\n upstream {{\n explicit: 'udp://{}' -> direct\n }}\n routing {{\n request {{\n subtag(first) && qname(shared.node.test) -> explicit\n fallback: explicit\n }}\n }}\n}}",
        ordinary.address
    ))
    .unwrap()
    .dns;
    let (registry, _runtime, resources) = generation(&config, 8);
    let addresses = registry
        .resolve_node_host(config.nodes[0].id, "shared.node.test")
        .await
        .unwrap();
    assert_eq!(addresses, [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4))]);
    let addresses = registry
        .resolve_node_host(config.nodes[1].id, "shared.node.test")
        .await
        .unwrap();
    assert_eq!(addresses, [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))]);
    assert_eq!(
        first.requests.lock().len(),
        1,
        "explicit override did not query imported upstream"
    );
    resources.close().await;
}

#[tokio::test]
async fn hostname_dns_uses_imported_bootstrap_without_nested_socket_reservation() {
    let bootstrap = server(Ipv4Addr::LOCALHOST, false).await;
    let upstream = server(Ipv4Addr::new(192, 0, 2, 71), true).await;
    let sub = provider(
        "provider",
        &format!(
            "default-nameserver: ['udp://{}']\nnameserver: ['tcp://dns.provider.test:{}']\nipv6: false",
            bootstrap.address,
            upstream.address.port()
        ),
    );
    let mut node = Node::from_share_link("socks5://node.provider.test:443").unwrap();
    node.subscription_id = Some(sub.id);
    let mut config = Config::default();
    config.global.bootstrap_resolver = "127.0.0.1:9".into();
    config.subscriptions.push(sub);
    config.nodes.push(node);
    let (registry, _runtime, resources) = generation(&config, 2);
    let addresses = tokio::time::timeout(
        Duration::from_secs(2),
        registry.resolve_node_host(config.nodes[0].id, "node.provider.test"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(addresses, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 71))]);
    assert!(
        bootstrap
            .requests
            .lock()
            .iter()
            .all(|host| host == "dns.provider.test")
    );
    assert!(!bootstrap.requests.lock().is_empty());
    assert_eq!(*upstream.requests.lock(), ["node.provider.test"]);
    resources.close().await;
}

#[tokio::test]
async fn registry_hook_does_not_keep_retired_dns_resources_alive() {
    let mut config = Config::default();
    let sub = provider("provider", "nameserver: ['udp://127.0.0.1:9']");
    let mut node = Node::from_share_link("socks5://node.test:443").unwrap();
    node.subscription_id = Some(sub.id);
    config.nodes.push(node);
    config.subscriptions.push(sub);
    let (registry, runtime, resources) = generation(&config, 8);
    let weak = Arc::downgrade(&resources);
    drop(resources);
    drop(runtime);
    assert!(
        weak.upgrade().is_none(),
        "resolver hook retained its DNS transport owner"
    );
    let error = registry
        .resolve_node_host(config.nodes[0].id, "node.test")
        .await
        .unwrap_err();
    assert!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<honk_outbound::proxy::PacketRejection>()
            .is_some(),
        "expired claim must fail without bootstrap fallback: {error}"
    );
}

#[tokio::test]
async fn deduplicated_imported_pool_serves_many_policies_under_tight_socket_budget() {
    let upstream = server(Ipv4Addr::new(192, 0, 2, 91), false).await;
    let mut yaml = format!(
        "nameserver: ['udp://{}']\nipv6: false\nnameserver-policy:\n",
        upstream.address
    );
    for i in 0..100 {
        yaml.push_str(&format!(
            "  'node-{i}.provider.test': ['{}', 'UDP://{}']\n",
            upstream.address, upstream.address
        ));
    }
    let sub = provider("provider", &yaml);
    let mut config = Config::default();
    config.dns.strategy = DnsStrategy::Ipv4Only;
    for i in 0..10 {
        let mut node =
            Node::from_share_link(&format!("socks5://node-{i}.provider.test:1080")).unwrap();
        node.subscription_id = Some(sub.id);
        config.nodes.push(node);
    }
    config.subscriptions.push(sub);
    let (registry, _runtime, resources) = generation(&config, 2);
    assert_eq!(
        resources.pools.len(),
        1,
        "one provider's 100 policies must share a single deduplicated UpstreamPool"
    );
    let mut tasks = FuturesUnordered::new();
    for (i, node) in config.nodes.iter().enumerate().take(10) {
        let registry = Arc::clone(&registry);
        let id = node.id;
        let host = format!("node-{i}.provider.test");
        tasks.push(async move { registry.resolve_node_host(id, &host).await.unwrap() });
    }
    while let Some(ips) = tasks.next().await {
        assert_eq!(ips, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 91))]);
    }
    resources.close().await;
}

#[tokio::test]
async fn race_ignores_truncated_or_formerr_responses_and_preserves_capacity_rejection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let bad_tc = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_tc_addr = bad_tc.local_addr().unwrap();
    let tc_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = bad_tc.accept().await else {
                break;
            };
            let len = usize::from(stream.read_u16().await.unwrap());
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await.unwrap();
            let context = crate::dns::query::QueryContext::parse(&buf).unwrap();
            let mut reply = crate::dns::forwarder::make_empty_response(&buf, &context);
            reply[2] |= 0x02;
            reply[6..8].copy_from_slice(&1u16.to_be_bytes());
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 51, 100, 99]);
            stream.write_u16(reply.len() as u16).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        }
    });

    let bad_formerr = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bad_formerr_addr = bad_formerr.local_addr().unwrap();
    let formerr_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (len, peer) = bad_formerr.recv_from(&mut buf).await.unwrap();
            let context = crate::dns::query::QueryContext::parse(&buf[..len]).unwrap();
            let mut reply = crate::dns::forwarder::make_empty_response(&buf[..len], &context);
            reply[3] = (reply[3] & 0xf0) | 1;
            bad_formerr.send_to(&reply, peer).await.unwrap();
        }
    });

    let good_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let good_addr = good_sock.local_addr().unwrap();
    let good_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (len, peer) = good_sock.recv_from(&mut buf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
            let reqs = parking_lot::Mutex::new(Vec::new());
            let reply = answer(&buf[..len], Ipv4Addr::new(192, 0, 2, 55), &reqs);
            good_sock.send_to(&reply, peer).await.unwrap();
        }
    });

    let sub = provider(
        "provider",
        &format!(
            "nameserver: ['tcp://{bad_tc_addr}', 'udp://{bad_formerr_addr}', 'udp://{good_addr}']\nipv6: false"
        ),
    );
    let mut node = Node::from_share_link("socks5://race.provider.test:1080").unwrap();
    node.subscription_id = Some(sub.id);
    let mut config = Config::default();
    config.dns.strategy = DnsStrategy::Ipv4Only;
    config.subscriptions.push(sub);
    config.nodes.push(node);
    let (registry, _runtime, resources) = generation(&config, 8);
    let ips = registry
        .resolve_node_host(config.nodes[0].id, "race.provider.test")
        .await
        .unwrap();
    assert_eq!(ips, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))]);
    resources.close().await;
    tc_task.abort();
    formerr_task.abort();
    good_task.abort();

    let exhausted_sub = provider(
        "exhausted",
        "default-nameserver: ['127.0.0.1:53']\nnameserver: ['tcp://dns.provider.test:53']\nipv6: false",
    );
    let mut exhausted_node = Node::from_share_link("socks5://cap.provider.test:1080").unwrap();
    exhausted_node.subscription_id = Some(exhausted_sub.id);
    let mut cap_config = Config::default();
    cap_config.global.connect_timeout_ms = 50;
    cap_config.global.dns_resolve_timeout_ms = 50;
    cap_config.dns.strategy = DnsStrategy::Ipv4Only;
    cap_config.subscriptions.push(exhausted_sub);
    cap_config.nodes.push(exhausted_node);
    let (cap_registry, _cap_runtime, cap_resources) = generation(&cap_config, 0);
    let err = cap_registry
        .resolve_node_host(cap_config.nodes[0].id, "cap.provider.test")
        .await
        .unwrap_err();
    let anyhow_err = anyhow::Error::new(err);
    assert_eq!(
        honk_outbound::proxy::packet_rejection(&anyhow_err),
        Some(honk_outbound::proxy::PacketRejection::Capacity)
    );
    cap_resources.close().await;
}

#[test]
fn invalid_runtime_imported_upstream_redacts_secret_token_from_prepare_error() {
    let mut config = Config::default();
    let mut bad_dns = honk_config::subscription::dns::SubscriptionDns::parse(
        &serde_yaml::from_str("nameserver: 192.0.2.1").unwrap(),
    )
    .unwrap()
    .unwrap();
    bad_dns.nameservers[0].address = "[::1:bad/dns-query?token=secret_pool_token".into();
    config
        .subscriptions
        .push(honk_config::subscription::Subscription {
            name: "bad".into(),
            import_dns: true,
            imported_dns: Some(Arc::new(bad_dns)),
            ..Default::default()
        });
    let router =
        Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(&config.dns).unwrap());
    let budget = DnsSocketBudget::new(4);
    let main = Arc::new(pool(&config, &config.dns.upstream, Arc::clone(&router), &budget).unwrap());
    let err = prepare(&config, main, router, &budget).err().unwrap();
    assert!(!err.to_string().contains("secret_pool_token"), "{err}");

    let mut root_doh_config = Config::default();
    root_doh_config.subscriptions.push(provider(
        "root-doh",
        "nameserver: ['https://doh.pub/', 'https://[2001:db8::53]/', 'h3://dns.alidns.com/']",
    ));
    let ok_router = Arc::new(
        crate::dns::routing::DnsRouter::new_from_dns_config(&root_doh_config.dns).unwrap(),
    );
    let ok_main = Arc::new(
        pool(
            &root_doh_config,
            &root_doh_config.dns.upstream,
            Arc::clone(&ok_router),
            &budget,
        )
        .unwrap(),
    );
    assert!(prepare(&root_doh_config, ok_main, ok_router, &budget).is_ok());
}

fn generation_with_hosts(
    config: &Config,
    budget: usize,
    hosts: crate::dns::forwarder::HostsSnapshot,
) -> (
    Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    Arc<DnsRuntime>,
    Arc<ScopedDns>,
) {
    let router =
        Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(&config.dns).unwrap());
    let budget = DnsSocketBudget::new(budget);
    let pool = Arc::new(pool(config, &config.dns.upstream, Arc::clone(&router), &budget).unwrap());
    let forwarder = Arc::new(
        DnsForwarder::new(
            pool.clone(),
            Arc::new(tokio::sync::Mutex::new(DnsCache::new(8))),
            Arc::clone(&router),
        )
        .with_strategy(config.dns.strategy)
        .with_hosts_snapshot(hosts),
    );
    let dns = prepare(config, pool, router, &budget).unwrap();
    let registry =
        Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap());
    dns.main
        .set_runtime_generation(Arc::clone(&registry))
        .unwrap();
    let runtime = DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(1),
        forwarder,
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            1,
            Arc::new(crate::routing::Router::new(&[], "direct").unwrap()),
        )),
        outbound_runtime: Some(Arc::clone(&registry)),
        transport: dns.clone(),
    });
    bind(&registry, &runtime, Arc::clone(&dns));
    (registry, runtime, dns)
}

#[tokio::test]
async fn hosts_alias_addresses_apply_dns_strategy_filtering_and_ordering() {
    let dir = tempfile::tempdir().unwrap();
    let hosts_path = dir.path().join("hosts");
    std::fs::write(
        &hosts_path,
        "dual.node.test dual-target.node.test\ndual-target.node.test 192.0.2.10 2001:db8::10\nv4only.node.test v4-target.node.test\nv4-target.node.test 192.0.2.11\n",
    )
    .unwrap();

    for (strategy, expected_dual, v4only_ok) in [
        (
            DnsStrategy::PreferIpv6,
            vec![
                IpAddr::V6("2001:db8::10".parse().unwrap()),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            ],
            true,
        ),
        (
            DnsStrategy::Ipv4Only,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))],
            true,
        ),
        (
            DnsStrategy::Ipv6Only,
            vec![IpAddr::V6("2001:db8::10".parse().unwrap())],
            false,
        ),
    ] {
        let mut config = Config::default();
        config.dns.strategy = strategy;
        config.dns.hosts = vec![hosts_path.to_string_lossy().into_owned()];
        let dual_node = Node::from_share_link("socks5://dual.node.test:1080#dual").unwrap();
        let v4_node = Node::from_share_link("socks5://v4only.node.test:1080#v4").unwrap();
        let dual_id = dual_node.id;
        let v4_id = v4_node.id;
        config.nodes = vec![dual_node, v4_node];
        let hosts = crate::dns::forwarder::HostsSourceSet::load(&config.dns)
            .unwrap()
            .parse()
            .unwrap();
        let (registry, _runtime, resources) = generation_with_hosts(&config, 4, hosts);
        assert_eq!(
            registry
                .resolve_node_host(dual_id, "dual.node.test")
                .await
                .unwrap(),
            expected_dual,
            "{strategy:?}"
        );
        assert_eq!(
            registry
                .resolve_node_host(v4_id, "v4only.node.test")
                .await
                .is_ok(),
            v4only_ok,
            "{strategy:?}"
        );
        resources.close().await;
    }
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn scoped_node_lookups_publish_not_instrumented_gaps_for_policy_and_alias_decisions() {
    use crate::native_api::events::EventHub;
    use crate::observe::DnsRecorder;
    use crate::observe::flows::FlowStore;

    let explicit_srv = server(Ipv4Addr::new(192, 0, 2, 21), false).await;
    let imported_srv = server(Ipv4Addr::new(192, 0, 2, 22), false).await;
    let bootstrap_srv = server(Ipv4Addr::new(192, 0, 2, 23), false).await;

    let dir = tempfile::tempdir().unwrap();
    let hosts_path = dir.path().join("hosts");
    std::fs::write(
        &hosts_path,
        "alias-addr.node.test addr-target.node.test\naddr-target.node.test 192.0.2.24\nalias-subtag.node.test hit.private.test\nalias-subtag-miss.node.test miss.public.test\nalias-imported.node.test hit.imp.test\nalias-imported-miss.node.test miss.imp-none.test\n",
    )
    .unwrap();

    let mut config = honk_config::parser::parse_dae_config(&format!(
        "dns {{\n upstream {{\n explicit: 'udp://{}' -> direct\n }}\n routing {{\n request {{\n subtag(sub-a) && qname(suffix: private.test) -> explicit\n }}\n }}\n}}",
        explicit_srv.address
    ))
    .unwrap();
    config.global.bootstrap_resolver = bootstrap_srv.address.to_string();
    config.dns.strategy = DnsStrategy::Ipv4Only;
    config.dns.hosts = vec![hosts_path.to_string_lossy().into_owned()];

    let sub_a = honk_config::subscription::Subscription {
        name: "sub-a".into(),
        import_dns: false,
        ..Default::default()
    };
    let sub_b = provider(
        "sub-b",
        &format!(
            "nameserver-policy:\n  '+.imp.test': 'udp://{}'\n",
            imported_srv.address
        ),
    );
    let mut node_subtag_hit =
        Node::from_share_link("socks5://hit.private.test:1080#a-hit").unwrap();
    node_subtag_hit.subscription_id = Some(sub_a.id);
    let mut node_subtag_miss =
        Node::from_share_link("socks5://miss.public.test:1080#a-miss").unwrap();
    node_subtag_miss.subscription_id = Some(sub_a.id);
    let mut node_imp_hit = Node::from_share_link("socks5://hit.imp.test:1080#b-hit").unwrap();
    node_imp_hit.subscription_id = Some(sub_b.id);
    let mut node_imp_miss = Node::from_share_link("socks5://miss.other.test:1080#b-miss").unwrap();
    node_imp_miss.subscription_id = Some(sub_b.id);
    let mut node_alias_addr =
        Node::from_share_link("socks5://alias-addr.node.test:1080#alias-addr").unwrap();
    node_alias_addr.subscription_id = None;
    let mut node_alias_subtag =
        Node::from_share_link("socks5://alias-subtag.node.test:1080#alias-subtag").unwrap();
    node_alias_subtag.subscription_id = Some(sub_a.id);
    let mut node_alias_subtag_miss =
        Node::from_share_link("socks5://alias-subtag-miss.node.test:1080#alias-subtag-miss")
            .unwrap();
    node_alias_subtag_miss.subscription_id = Some(sub_a.id);
    let mut node_alias_imp =
        Node::from_share_link("socks5://alias-imported.node.test:1080#alias-imp").unwrap();
    let mut node_alias_imp_miss =
        Node::from_share_link("socks5://alias-imported-miss.node.test:1080#alias-imp-miss")
            .unwrap();
    let mut node_alias_imp_sub = provider(
        "sub-no-rule",
        &format!(
            "nameserver-policy:\n  '+.imp.test': 'udp://{}'\n",
            imported_srv.address
        ),
    );
    node_alias_imp.subscription_id = Some(node_alias_imp_sub.id);
    node_alias_imp_miss.subscription_id = Some(node_alias_imp_sub.id);
    let node_static = Node::from_share_link("socks5://static.plain.test:1080#static").unwrap();

    let subtag_hit_id = node_subtag_hit.id;
    let subtag_miss_id = node_subtag_miss.id;
    let imp_hit_id = node_imp_hit.id;
    let imp_miss_id = node_imp_miss.id;
    let alias_addr_id = node_alias_addr.id;
    let alias_subtag_id = node_alias_subtag.id;
    let alias_subtag_miss_id = node_alias_subtag_miss.id;
    let alias_imp_id = node_alias_imp.id;
    let alias_imp_miss_id = node_alias_imp_miss.id;
    let static_id = node_static.id;

    config.subscriptions = vec![sub_a, sub_b, node_alias_imp_sub.clone()];
    config.nodes = vec![
        node_subtag_hit,
        node_subtag_miss,
        node_imp_hit,
        node_imp_miss,
        node_alias_addr,
        node_alias_subtag,
        node_alias_subtag_miss,
        node_alias_imp.clone(),
        node_alias_imp_miss.clone(),
        node_static.clone(),
    ];
    let hosts = crate::dns::forwarder::HostsSourceSet::load(&config.dns)
        .unwrap()
        .parse()
        .unwrap();
    let (registry, runtime, resources) = generation_with_hosts(&config, 8, hosts.clone());

    let instance = uuid::Uuid::new_v4().to_string();
    let store = Arc::new(FlowStore::new(
        instance.clone(),
        Arc::new(EventHub::new(instance.clone())),
    ));
    let api = Arc::new(DnsRecorder::new(instance, Arc::downgrade(&store), false));
    let new_flow = || {
        let flow = Arc::new(
            store
                .begin(
                    crate::observe::vocab::Network::Tcp,
                    "127.0.0.1:31000".parse().unwrap(),
                    "192.0.2.99:443".parse().unwrap(),
                )
                .unwrap(),
        );
        let obs = flow.observer(1, None, "dial_target").unwrap();
        (flow, obs)
    };
    let assert_trace = |flow: &crate::observe::flows::FlowGuard, partial: bool, label: &str| {
        let view = store.get(flow.id()).unwrap();
        let expected = if partial { "partial" } else { "complete" };
        assert_eq!(view["trace_status"], expected, "{label}: {view:#}");
        assert_eq!(
            view["trace"]["missing"],
            if partial {
                serde_json::json!(["not_instrumented"])
            } else {
                serde_json::json!([])
            },
            "{label}: {view:#}"
        );
    };

    for (id, host, claimed, partial, label) in [
        (
            subtag_hit_id,
            "hit.private.test",
            true,
            true,
            "preflight-subtag-hit",
        ),
        (
            subtag_miss_id,
            "miss.public.test",
            false,
            true,
            "preflight-subtag-miss",
        ),
        (
            static_id,
            "static.plain.test",
            false,
            false,
            "preflight-static",
        ),
    ] {
        let (flow, obs) = new_flow();
        assert_eq!(
            obs.sync_scope(|| registry.lookup_node_host(id, host).is_some()),
            claimed,
            "{label}"
        );
        assert_trace(&flow, partial, label);
    }

    let mut no_subtag_config = Config::default();
    no_subtag_config.global.bootstrap_resolver = bootstrap_srv.address.to_string();
    no_subtag_config.dns.strategy = DnsStrategy::Ipv4Only;
    no_subtag_config.dns.hosts = vec![hosts_path.to_string_lossy().into_owned()];
    let mut node_imp_only_hit =
        Node::from_share_link("socks5://hit.imp.test:1080#only-hit").unwrap();
    node_imp_only_hit.subscription_id = Some(node_alias_imp_sub.id);
    let mut node_imp_only_miss =
        Node::from_share_link("socks5://miss.imp-none.test:1080#only-miss").unwrap();
    node_imp_only_miss.subscription_id = Some(node_alias_imp_sub.id);
    let imp_only_hit_id = node_imp_only_hit.id;
    let imp_only_miss_id = node_imp_only_miss.id;
    no_subtag_config.subscriptions = vec![std::mem::take(&mut node_alias_imp_sub)];
    no_subtag_config.nodes = vec![
        node_imp_only_hit,
        node_imp_only_miss,
        node_alias_imp,
        node_alias_imp_miss,
        node_static,
    ];
    let (no_subtag_reg, no_subtag_rt, no_subtag_res) =
        generation_with_hosts(&no_subtag_config, 8, hosts);

    for (id, host, claimed, partial, label) in [
        (
            imp_only_hit_id,
            "hit.imp.test",
            true,
            true,
            "preflight-imp-hit",
        ),
        (
            imp_only_miss_id,
            "miss.imp-none.test",
            false,
            true,
            "preflight-imp-miss",
        ),
        (
            static_id,
            "static.plain.test",
            false,
            false,
            "preflight-no-subtag-static",
        ),
    ] {
        let (flow, obs) = new_flow();
        assert_eq!(
            obs.sync_scope(|| no_subtag_reg.lookup_node_host(id, host).is_some()),
            claimed,
            "{label}"
        );
        assert_trace(&flow, partial, label);
    }

    for (reg, id, host, expected_ip, partial, label) in [
        (
            &registry,
            alias_addr_id,
            "alias-addr.node.test",
            Ipv4Addr::new(192, 0, 2, 24),
            true,
            "resolve-alias-addresses",
        ),
        (
            &registry,
            alias_subtag_id,
            "alias-subtag.node.test",
            Ipv4Addr::new(192, 0, 2, 21),
            true,
            "resolve-alias-into-subtag",
        ),
        (
            &registry,
            alias_subtag_miss_id,
            "alias-subtag-miss.node.test",
            Ipv4Addr::new(192, 0, 2, 23),
            true,
            "resolve-alias-into-subtag-miss",
        ),
        (
            &no_subtag_reg,
            alias_imp_id,
            "alias-imported.node.test",
            Ipv4Addr::new(192, 0, 2, 22),
            true,
            "resolve-alias-into-imported",
        ),
        (
            &no_subtag_reg,
            alias_imp_miss_id,
            "alias-imported-miss.node.test",
            Ipv4Addr::new(192, 0, 2, 23),
            true,
            "resolve-alias-into-imported-miss",
        ),
        (
            &registry,
            imp_hit_id,
            "hit.imp.test",
            Ipv4Addr::new(192, 0, 2, 22),
            true,
            "resolve-direct-imp-hit",
        ),
        (
            &registry,
            imp_miss_id,
            "miss.other.test",
            Ipv4Addr::new(192, 0, 2, 23),
            true,
            "resolve-direct-imp-miss",
        ),
        (
            &registry,
            static_id,
            "static.plain.test",
            Ipv4Addr::new(192, 0, 2, 23),
            false,
            "resolve-static-complete",
        ),
    ] {
        let (flow, obs) = new_flow();
        let ips = obs
            .scope(crate::observe::flows::dns::scope_api(
                Arc::downgrade(&api),
                reg.resolve_node_host(id, host),
            ))
            .await
            .unwrap();
        assert_eq!(ips, [IpAddr::V4(expected_ip)], "{label}");
        assert_trace(&flow, partial, label);
    }

    no_subtag_res.close().await;
    drop(no_subtag_rt);
    drop(no_subtag_res);

    resources.close().await;
    drop(runtime);
    drop(resources);

    let (retired_claimed_flow, retired_claimed_obs) = new_flow();
    assert!(retired_claimed_obs.sync_scope(|| {
        registry
            .lookup_node_host(subtag_hit_id, "hit.private.test")
            .is_some()
    }));
    assert_trace(&retired_claimed_flow, true, "retired-claimed");

    let (retired_static_flow, retired_static_obs) = new_flow();
    assert!(retired_static_obs.sync_scope(|| {
        registry
            .lookup_node_host(static_id, "static.plain.test")
            .is_none()
    }));
    assert_trace(&retired_static_flow, false, "retired-unclaimed");
}
