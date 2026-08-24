use super::*;

#[tokio::test]
async fn udp_overload_is_refused_while_permit_owner_is_in_flight() {
    let upstream = Arc::new(BlockingFirstUpstream {
        first_entered: Notify::new(),
        release_first: Notify::new(),
    });
    let controller = controller_with_limit(upstream.clone(), 1);
    let first_client = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind first client");
    let second_client = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind second client");
    let original_dst: SocketAddr = "127.0.0.1:53".parse().expect("original destination");
    // The reply path builds an IP_TRANSPARENT anyfrom socket bound to the
    // original destination — unprivileged runners (CI) cannot create it,
    // and the handler swallows the failure, so the REFUSED would never
    // arrive. Exercise the full path only where it can actually work.
    if crate::control::sockets::new_udp_reply_socket(original_dst).is_err() {
        eprintln!("skipping: transparent UDP reply socket needs privileges");
        return;
    }

    let first_query = query_with_txid("first.example", 0x1111);
    let first_task = {
        let controller = controller.clone();
        let client_addr = first_client.local_addr().expect("first client address");
        tokio::spawn(async move {
            controller
                .handle_udp_dns(&first_query, client_addr, original_dst, None)
                .await
        })
    };
    upstream.first_entered.notified().await;

    let second_query = query_with_txid("second.example", 0x2222);
    assert!(
        controller
            .handle_udp_dns(
                &second_query,
                second_client.local_addr().expect("second client address"),
                original_dst,
                None,
            )
            .await
            .expect("second handler")
    );
    let mut response = [0u8; 512];
    let received = tokio::time::timeout(
        Duration::from_secs(5),
        second_client.recv_from(&mut response),
    )
    .await
    .expect("overload response timeout")
    .expect("overload response")
    .0;
    assert_eq!(response[3] & 0x0f, 5);
    assert_eq!(&response[..2], &second_query[..2]);
    assert!(received >= 12);

    upstream.release_first.notify_one();
    let first_received = tokio::time::timeout(
        Duration::from_secs(5),
        first_client.recv_from(&mut response),
    )
    .await
    .expect("first response timeout")
    .expect("first response")
    .0;
    assert!(first_received >= 12);
    assert!(
        first_task
            .await
            .expect("first task")
            .expect("first handler")
    );
}

#[tokio::test]
async fn transparent_udp_routes_by_client_source() {
    struct SourceRouteUpstream {
        calls: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl DnsUpstreamPool for SourceRouteUpstream {
        async fn query(&self, name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.lock().expect("calls").push(name.to_string());
            let (domain, _) = crate::dns::forwarder::parse_dns_question(raw).expect("question");
            Ok(response_with_txid(
                &domain,
                u16::from_be_bytes([raw[0], raw[1]]),
            ))
        }
    }

    let mut config = honk_config::dns::DnsConfig::default();
    config.routing.request.rules = vec![honk_config::dns::DnsRequestRule {
        conditions: vec![honk_config::dns::DnsCond::Sip {
            not: false,
            cidrs: vec!["192.0.2.0/24".into()],
        }],
        action: honk_config::dns::DnsRequestAction::Upstream("selected".into()),
    }];
    config.routing.request.fallback =
        honk_config::dns::DnsRequestAction::Upstream("fallback".into());
    let upstream = Arc::new(SourceRouteUpstream {
        calls: std::sync::Mutex::new(Vec::new()),
    });
    let controller = controller_with_dns_config(upstream.clone(), &config);
    let query = query_with_txid("source.example", 0x5151);
    let original_dst = "127.0.0.1:53".parse().expect("destination");

    for client_addr in ["192.0.2.10:53000", "198.51.100.10:53000"] {
        assert!(
            controller
                .handle_udp_dns(
                    &query,
                    client_addr.parse().expect("client"),
                    original_dst,
                    None,
                )
                .await
                .expect("handler")
        );
    }

    assert_eq!(
        upstream.calls.lock().expect("calls").as_slice(),
        ["selected", "fallback"]
    );
}

#[tokio::test]
async fn truncated_upstream_response_is_not_cached_or_projected() {
    let query = query_with_txid("example.com", 0x5151);
    let mut truncated = a_response(&query, [192, 0, 2, 10]);
    truncated[2..4].copy_from_slice(&0x8380_u16.to_be_bytes());
    let upstream = Arc::new(SlowUpstream {
        calls: AtomicUsize::new(0),
        delay: Duration::ZERO,
        response: truncated,
    });
    let cache = Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(8)));
    let directory = tempfile::tempdir().expect("cache directory");
    let database = Arc::new(
        crate::cachedb::CacheDb::open(&honk_config::experimental::CacheFileConfig {
            enabled: true,
            path: directory
                .path()
                .join("cache.db")
                .to_string_lossy()
                .into_owned(),
            store_dns: true,
            ..Default::default()
        })
        .expect("cache database"),
    );
    let persister = crate::dns::persist::DnsCachePersister::spawn(Arc::clone(&database));
    cache.lock().await.set_persister(Some(persister.clone()));
    let forwarder = Arc::new(DnsForwarder::new(
        upstream.clone(),
        cache.clone(),
        Arc::new(
            crate::dns::routing::DnsRouter::new_from_dns_config(
                &honk_config::dns::DnsConfig::default(),
            )
            .expect("DNS router"),
        ),
    ));
    let route = honk_config::routing::RoutingRule {
        name: "dns".into(),
        condition: honk_config::routing::RoutingCondition {
            domain: vec!["example.com".into()],
            ..Default::default()
        },
        outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
        priority: 1,
        must: false,
        mark: 0,
    };
    let mut bitmap = honk_ebpf_common::DomainRouting::default();
    bitmap.bitmap[0] = 1;
    let snapshot = Arc::new(crate::dns::projection::RoutingProjectionSnapshot::new(
        1,
        Arc::new(Router::new(&[route], "direct").expect("routing matcher")),
        std::collections::HashMap::from([("dns".into(), vec![bitmap])]),
    ));
    let runtime = crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
        generation: crate::dns::runtime::RuntimeGeneration::new(1),
        forwarder,
        routing_projection: Arc::clone(&snapshot),
        outbound_runtime: None,
        transport: Arc::new(NoopRuntimeTransport),
    });
    let ebpf: Arc<tokio::sync::RwLock<Box<dyn crate::ebpf::EbpfBackend>>> = Arc::new(
        tokio::sync::RwLock::new(Box::new(crate::ebpf::mock::MockEbpfBackend::new())),
    );
    let controller = DnsController::new_with_runtime(
        Arc::new(crate::dns::runtime::DnsServiceProvider::new(runtime)),
        ebpf,
    );
    let learned_ip = "192.0.2.10".parse().expect("learned IP");
    controller.routing_projection.submit(
        Arc::clone(&snapshot),
        crate::dns::projection::ProjectionObservation::Positive {
            domain: "example.com",
            ips: &[learned_ip],
            advertised_ttl: Duration::from_secs(30),
            freshness: crate::dns::projection::ProjectionFreshness::Fresh,
        },
    );
    let projected = controller.project_routes(&snapshot);
    assert_eq!(projected.len(), 1);

    let (outcome, runtime) = controller
        .dns_service()
        .resolve_outcome_with_runtime(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Udp {
                advertised_size: 1232,
            },
        )
        .await
        .expect("truncated outcome");
    assert!(outcome.answer_ips().is_empty());
    assert!(!outcome.expiry().is_cacheable());
    controller.submit_projection(runtime.runtime(), &outcome);
    drop(runtime);

    assert!(cache.lock().await.is_empty());
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    let projected_again = controller.project_routes(&snapshot);
    assert_eq!(projected_again.len(), 1);
    assert_eq!(projected_again[0].0, projected[0].0);
    assert_eq!(projected_again[0].1.bitmap, projected[0].1.bitmap);
    persister.shutdown().await.expect("persistence shutdown");
    assert!(database.load_dns_v2().expect("persisted rows").is_empty());
    controller.shutdown(Duration::from_secs(1)).await;
}
