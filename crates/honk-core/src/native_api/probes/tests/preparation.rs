use super::*;
use crate::dns::forwarder::parse_dns_question;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FamilyPool {
    refusal: bool,
    response_code: u8,
    ipv6_queries: AtomicUsize,
}

#[async_trait::async_trait]
impl DnsUpstreamPool for FamilyPool {
    async fn query(&self, _: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match parse_dns_question(query).unwrap().1 {
            1 => {
                let error = if self.refusal {
                    std::io::Error::from(honk_outbound::proxy::PacketRejection::Capacity)
                } else {
                    std::io::ErrorKind::ConnectionRefused.into()
                };
                Err(anyhow::Error::new(error).context("A lookup failed"))
            }
            28 => {
                self.ipv6_queries.fetch_add(1, Ordering::SeqCst);
                let mut answer = query.to_vec();
                answer[2..4]
                    .copy_from_slice(&(0x8180 | u16::from(self.response_code)).to_be_bytes());
                answer[6..8].copy_from_slice(&1u16.to_be_bytes());
                answer.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                answer.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
                Ok(answer)
            }
            qtype => panic!("unexpected query type {qtype}"),
        }
    }
}

#[async_trait::async_trait]
impl RuntimeTransport for FamilyPool {
    async fn close(&self) {}
}

async fn family_preparation(refusal: bool, response_code: u8) {
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let node = Node::from_share_link(&format!(
        "socks5://probe.example:{}",
        listener.local_addr().unwrap().port(),
    ))
    .unwrap();
    let node_id = node.id;
    let mut config = Config::default();
    config.nodes.push(node);
    let state = state(config).await;
    let pool = Arc::new(FamilyPool {
        refusal,
        response_code,
        ipv6_queries: AtomicUsize::new(0),
    });
    publish_dns(
        &state,
        pool.clone(),
        &honk_config::dns::DnsConfig::default(),
    );
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let input = request(
        json!({"type":"node","node_id":node_id.to_string()}),
        "tcp_connect",
        json!(["tcp"]),
        "any",
    );
    let response = create(
        &state,
        http_request(&input, "family"),
        &RequestId("family".into()),
    )
    .await;
    let accepted = body(response.unwrap()).await;
    let result = terminal(&state, accepted["operation_id"].as_str().unwrap()).await;
    if refusal {
        assert_eq!(result["status"], "failed");
        assert_eq!(result["error"]["code"], "unsupported_value");
        assert_eq!(result["result"], Value::Null);
    } else {
        assert_eq!(
            result["result"]["results"][0]["error"],
            "address_unavailable"
        );
        assert_eq!(result["result"]["results"][0]["health_updated"], false);
        if response_code == 0 {
            assert_eq!(result["result"]["results"][1]["state"], "healthy");
            assert_eq!(result["result"]["results"][1]["health_updated"], true);
            let (mut socket, peer) =
                tokio::time::timeout(Duration::from_secs(1), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            assert!(peer.is_ipv6());
            assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
        } else {
            assert_eq!(
                result["result"]["results"][1]["error"],
                "address_unavailable"
            );
            assert_eq!(result["result"]["results"][1]["health_updated"], false);
        }
    }
    stop.send(true).unwrap();
    worker.await.unwrap();
    assert_eq!(pool.ipv6_queries.load(Ordering::SeqCst), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let observations = state.alive_set.health_observations(node_id);
    if refusal || response_code != 0 {
        assert!(
            observations.is_empty(),
            "unusable DNS answers cannot publish health"
        );
    } else {
        assert!(observations.iter().any(
            |sample| sample.ip_version == IpVersion::V6 && sample.state == HealthState::Healthy
        ));
        assert!(
            !observations
                .iter()
                .any(|sample| sample.ip_version == IpVersion::V4)
        );
    }
    state.dns.provider().unwrap().shutdown().await;
}

#[tokio::test]
async fn typed_dns_refusal_blocks_usable_sibling_before_dial_or_health() {
    family_preparation(true, 0).await;
}

#[tokio::test]
async fn ordinary_dns_failure_keeps_usable_sibling_and_skips_missing_family() {
    family_preparation(false, 0).await;
}

#[tokio::test]
async fn negative_dns_answer_addresses_cannot_admit_a_probe() {
    family_preparation(false, 3).await;
}

#[tokio::test]
async fn asis_dns_routing_falls_back_to_bootstrap_for_probe_targets() {
    // Control-plane setup also installs process-wide resolver hooks.
    if crate::test_support::run_exact_in_child(
        "HONK_PROBE_BOOTSTRAP_FALLBACK_CHILD",
        "native_api::probes::tests::preparation::asis_dns_routing_falls_back_to_bootstrap_for_probe_targets",
    ) {
        return;
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node = Node::from_share_link(&format!(
        "socks5://localhost:{}",
        listener.local_addr().unwrap().port(),
    ))
    .unwrap();
    let node_id = node.id;
    let mut config = Config::default();
    config.nodes.push(node);
    let state = state(config).await;
    let mut dns = honk_config::dns::DnsConfig::default();
    dns.routing.request.fallback = honk_config::dns::DnsRequestAction::AsIs;
    let pool = Arc::new(FamilyPool {
        refusal: false,
        response_code: 0,
        ipv6_queries: AtomicUsize::new(0),
    });
    publish_dns(&state, pool.clone(), &dns);
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let input = request(
        json!({"type":"node","node_id":node_id.to_string()}),
        "tcp_connect",
        json!(["tcp"]),
        "ipv4",
    );
    let response = create(
        &state,
        http_request(&input, "asis"),
        &RequestId("asis".into()),
    )
    .await;
    let accepted = body(response.unwrap()).await;
    let result = terminal(&state, accepted["operation_id"].as_str().unwrap()).await;
    assert_eq!(result["result"]["results"][0]["state"], "healthy");
    assert_eq!(result["result"]["results"][0]["health_updated"], true);
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
    stop.send(true).unwrap();
    worker.await.unwrap();
    assert_eq!(pool.ipv6_queries.load(Ordering::SeqCst), 0);
    state.dns.provider().unwrap().shutdown().await;
}

#[tokio::test]
async fn same_hostname_nodes_and_chains_keep_distinct_addresses_during_native_probe_preparation() {
    struct Resolver {
        addresses: HashMap<uuid::Uuid, IpAddr>,
        calls: Arc<parking_lot::Mutex<Vec<uuid::Uuid>>>,
    }
    impl honk_outbound::bootstrap::NodeHostResolver for Resolver {
        fn lookup(&self, _: &str) -> Option<honk_outbound::bootstrap::NodeHostLookup> {
            None
        }
        fn lookup_node(
            &self,
            node: uuid::Uuid,
            host: &str,
        ) -> Option<honk_outbound::bootstrap::NodeHostLookup> {
            let address = *self.addresses.get(&node)?;
            assert_eq!(host, "shared.node.test");
            self.calls.lock().push(node);
            Some(Box::pin(async move { Ok(vec![address]) }))
        }
    }
    let first = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
    let port = first.local_addr().unwrap().port();
    let second = tokio::net::TcpListener::bind(format!("127.0.0.3:{port}"))
        .await
        .unwrap();
    let nodes = ["first", "second"].map(|name| {
        Node::from_share_link(&format!("socks5://{name}:password@shared.node.test:{port}")).unwrap()
    });
    let registry = OutboundRuntimeRegistry::build(&nodes).unwrap();
    let calls = Arc::new(parking_lot::Mutex::new(Vec::new()));
    registry.bind_node_resolver(Arc::new(Resolver {
        addresses: [
            (nodes[0].id, first.local_addr().unwrap().ip()),
            (nodes[1].id, second.local_addr().unwrap().ip()),
        ]
        .into(),
        calls: Arc::clone(&calls),
    }));
    let mut config = Config::default();
    config.nodes.extend(nodes.clone());
    config.groups.push(
        serde_json::from_value(
            json!({"name":"root","nodes":nodes.iter().map(|node| node.id).collect::<Vec<_>>()}),
        )
        .unwrap(),
    );
    let state = state(config).await;
    *state.runtime_registry.write() = Arc::new(registry);
    let identity = state.observation.core.catalog.snapshot();
    let input = request(
        json!({"type":"group","group_id":identity.groups["root"]}),
        "tcp_connect",
        json!(["tcp"]),
        "ipv4",
    );
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let accepted = body(
        create(
            &state,
            http_request(&input, "scoped-nodes"),
            &RequestId("scoped-nodes".into()),
        )
        .await
        .unwrap(),
    )
    .await;
    let result = terminal(&state, accepted["operation_id"].as_str().unwrap()).await;
    assert_eq!(result["result"]["results"].as_array().unwrap().len(), 2);
    for row in result["result"]["results"].as_array().unwrap() {
        assert_eq!(row["state"], "healthy", "{result}");
    }
    for listener in [first, second] {
        tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
    }
    let calls = calls.lock().clone();
    assert_eq!(calls.len(), 2);
    assert!(nodes.iter().all(|node| calls.contains(&node.id)));
    stop.send(true).unwrap();
    worker.await.unwrap();
    state.dns.provider().unwrap().shutdown().await;
}

#[tokio::test]
async fn http_probe_isolates_subtag_server_dns_from_unclaimed_sibling_and_static_nodes() {
    async fn udp_dns(
        answer_ip: std::net::Ipv4Addr,
    ) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_task = Arc::clone(&hits);
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                let qtype = parse_dns_question(&buf[..len]).unwrap().1;
                let mut reply = buf[..len].to_vec();
                reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                reply[6..12].fill(0);
                if qtype == 1 {
                    hits_task.fetch_add(1, Ordering::SeqCst);
                    reply[6..8].copy_from_slice(&1u16.to_be_bytes());
                    reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    reply.extend_from_slice(&answer_ip.octets());
                }
                socket.send_to(&reply, peer).await.unwrap();
            }
        });
        (addr, hits, handle)
    }

    async fn socks5_http_relay(
        bind_ip: &str,
        port: u16,
        http_target: SocketAddr,
    ) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(format!("{bind_ip}:{port}"))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let dials = Arc::new(AtomicUsize::new(0));
        let dials_task = Arc::clone(&dials);
        let handle = tokio::spawn(async move {
            loop {
                let (mut client, _) = listener.accept().await.unwrap();
                let dials_conn = Arc::clone(&dials_task);
                tokio::spawn(async move {
                    dials_conn.fetch_add(1, Ordering::SeqCst);
                    let mut greeting = [0u8; 2];
                    if client.read_exact(&mut greeting).await.is_err() {
                        return;
                    }
                    let mut methods = vec![0u8; usize::from(greeting[1])];
                    client.read_exact(&mut methods).await.unwrap();
                    client.write_all(&[0x05, 0x00]).await.unwrap();
                    let mut head = [0u8; 4];
                    client.read_exact(&mut head).await.unwrap();
                    match head[3] {
                        0x01 => {
                            let mut skip = [0u8; 6];
                            client.read_exact(&mut skip).await.unwrap();
                        }
                        0x03 => {
                            let n = usize::from(client.read_u8().await.unwrap());
                            let mut skip = vec![0u8; n + 2];
                            client.read_exact(&mut skip).await.unwrap();
                        }
                        other => panic!("unexpected atyp {other}"),
                    }
                    let mut upstream = tokio::net::TcpStream::connect(http_target).await.unwrap();
                    client
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        (addr, dials, handle)
    }

    let check_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let check_addr = check_listener.local_addr().unwrap();
    let check_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = check_listener.accept().await.unwrap();
            tokio::spawn(async move {
                loop {
                    let mut req = Vec::new();
                    let mut byte = [0u8; 1];
                    while !req.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        req.push(byte[0]);
                    }
                    if stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });

    let (socks_a_addr, socks_a_dials, socks_a_task) =
        socks5_http_relay("127.0.0.2", 0, check_addr).await;
    let port = socks_a_addr.port();
    let (_, socks_ord_dials, socks_ord_task) =
        socks5_http_relay("127.0.0.3", port, check_addr).await;

    let (sub_a_dns_addr, sub_a_hits, sub_a_dns_task) =
        udp_dns(std::net::Ipv4Addr::new(127, 0, 0, 2)).await;
    let (ord_dns_addr, ord_hits, ord_dns_task) =
        udp_dns(std::net::Ipv4Addr::new(127, 0, 0, 3)).await;

    let mut config = honk_config::parser::parse_dae_config(&format!(
        "dns {{\n upstream {{\n  sub_a_doh: 'udp://{sub_a_dns_addr}' -> direct\n  ord_dns: 'udp://{ord_dns_addr}' -> direct\n }}\n routing {{\n  request {{\n   subtag(SubA) -> sub_a_doh\n   fallback: ord_dns\n  }}\n }}\n}}\n"
    ))
    .unwrap();
    config.global.tcp_check_url = vec![format!("http://{check_addr}/")];
    config.global.bootstrap_resolver = ord_dns_addr.to_string();
    config.dns.strategy = honk_config::dns::DnsStrategy::Ipv4Only;

    let sub_a = honk_config::subscription::Subscription {
        name: "SubA".into(),
        url: "https://a.invalid/sub".into(),
        import_dns: false,
        ..Default::default()
    };
    let sub_b = honk_config::subscription::Subscription {
        name: "SubB".into(),
        url: "https://b.invalid/sub".into(),
        import_dns: false,
        ..Default::default()
    };
    let mut node_a =
        Node::from_share_link(&format!("socks5://one:pw@shared.node.example:{port}#a")).unwrap();
    node_a.subscription_id = Some(sub_a.id);
    let mut node_b =
        Node::from_share_link(&format!("socks5://two:pw@shared.node.example:{port}#b")).unwrap();
    node_b.subscription_id = Some(sub_b.id);
    let node_static =
        Node::from_share_link(&format!("socks5://three:pw@shared.node.example:{port}#s")).unwrap();

    config.subscriptions = vec![sub_a, sub_b];
    config.nodes = vec![node_a.clone(), node_b.clone(), node_static.clone()];
    config.groups.push(
        serde_json::from_value(json!({
            "name": "root",
            "nodes": [node_a.id, node_b.id, node_static.id]
        }))
        .unwrap(),
    );

    let state = state(config.clone()).await;
    let router = Arc::new(DnsRouter::new_from_dns_config(&config.dns).unwrap());
    let budget = crate::dns::transport::DnsSocketBudget::new(16);
    let main_pool = Arc::new(
        crate::dns::upstream_pool::UpstreamPool::new_with_proxy_and_bootstrap(
            &config.dns.upstream,
            Arc::clone(&router),
            None,
            Vec::new(),
            Vec::new(),
            honk_outbound::bootstrap::BootstrapResolver::parse(&config.global.bootstrap_resolver),
            config.dns.strategy,
        )
        .unwrap()
        .with_socket_budget(budget.clone()),
    );
    let forwarder = Arc::new(
        DnsForwarder::new(
            main_pool.clone(),
            Arc::new(tokio::sync::Mutex::new(DnsCache::new(16))),
            Arc::clone(&router),
        )
        .with_strategy(config.dns.strategy)
        .with_node_hosts(crate::dns::node_host::index(&config)),
    );
    let scoped =
        crate::dns::node_host::prepare(&config, main_pool, Arc::clone(&router), &budget).unwrap();
    let registry = Arc::new(OutboundRuntimeRegistry::build(&config.nodes).unwrap());
    let provider = state.dns.provider().unwrap();
    let generation = provider.current_generation().get() + 1;
    let runtime = DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(generation),
        forwarder,
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            generation,
            Arc::new(crate::routing::Router::new(&[], "direct").unwrap()),
        )),
        outbound_runtime: Some(Arc::clone(&registry)),
        transport: scoped.clone(),
    });
    crate::dns::node_host::bind(&registry, &runtime, scoped);
    *state.runtime_registry.write() = registry;
    provider.publish(runtime);

    let identity = state.observation.core.catalog.snapshot();
    let input = request(
        json!({"type": "group", "group_id": identity.groups["root"]}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let accepted = body(
        create(
            &state,
            http_request(&input, "subtag-isolation"),
            &RequestId("subtag-isolation".into()),
        )
        .await
        .unwrap(),
    )
    .await;
    let result = terminal(&state, accepted["operation_id"].as_str().unwrap()).await;
    let rows = result["result"]["results"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{result}");
    for row in rows {
        assert_eq!(row["state"], "healthy", "{result}");
    }
    assert_eq!(sub_a_hits.load(Ordering::SeqCst), 1);
    assert!(
        ord_hits.load(Ordering::SeqCst) >= 1,
        "unclaimed sibling/static nodes leaked into sub_a_doh instead of ordinary DNS"
    );
    let a_dials = socks_a_dials.load(Ordering::SeqCst);
    let ord_dials = socks_ord_dials.load(Ordering::SeqCst);
    assert!(a_dials >= 1);
    assert_eq!(ord_dials, a_dials * 2);

    stop.send(true).unwrap();
    worker.await.unwrap();
    state.dns.provider().unwrap().shutdown().await;
    check_task.abort();
    socks_a_task.abort();
    socks_ord_task.abort();
    sub_a_dns_task.abort();
    ord_dns_task.abort();
}
