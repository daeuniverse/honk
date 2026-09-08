use super::*;

#[tokio::test]
async fn admitted_transparent_udp_routes_by_client_source() {
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
    let validated = crate::dns::query::validate_exact_dns_query(&query).expect("valid query");
    let original_dst = "127.0.0.1:53".parse().expect("destination");

    for client_addr in ["192.0.2.10:53000", "198.51.100.10:53000"] {
        let admission = controller
            .try_admit_query(true)
            .expect("admit transparent UDP query");
        controller
            .handle_udp_dns_admitted(
                &admission,
                &query,
                client_addr.parse().expect("client"),
                original_dst,
                validated,
            )
            .await;
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
    let snapshot = Arc::new(crate::dns::projection::RoutingProjectionSnapshot::new(
        1,
        Arc::new(Router::new(&[route], "direct").expect("routing matcher")),
    ));
    let runtime = crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
        generation: crate::dns::runtime::RuntimeGeneration::new(1),
        forwarder,
        routing_projection: Arc::clone(&snapshot),
        outbound_runtime: None,
        transport: Arc::new(NoopRuntimeTransport),
        udp_query_limit: 256,
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
        },
    );
    let projected = controller.project_routes(&snapshot);
    assert_eq!(projected.len(), 1);

    let runtime = controller.runtime_provider().acquire();
    let outcome = controller
        .dns_service()
        .resolve_outcome_with_runtime(
            &runtime,
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
