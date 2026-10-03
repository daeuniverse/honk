use super::*;

#[cfg(feature = "native-api")]
#[tokio::test]
async fn native_log_captures_transparent_udp_completion_with_full_source() {
    let query = query_with_txid("example.com", 0x1111);
    let (controller, _) = test_controller(a_response(&query, [192, 0, 2, 5]), Duration::ZERO);
    let api = Arc::new(crate::native_api::dns::DnsApi::new(
        "udp-log".into(),
        true,
        std::sync::Weak::new(),
    ));
    controller
        .dns_service()
        .attach_observer(Arc::downgrade(&api.recorder));
    let source: SocketAddr = "[2001:db8::12]:53000".parse().unwrap();
    let admission = controller.try_admit_query(true).unwrap();
    controller
        .handle_udp_dns_admitted(
            &admission,
            &query,
            source,
            "[::1]:53".parse().unwrap(),
            crate::dns::query::validate_exact_dns_query(&query).unwrap(),
        )
        .await;
    let response = api.log_for_test().page_for_test();
    let bytes = axum::body::to_bytes(response.into_body(), 262144)
        .await
        .unwrap();
    let log: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(log["total"], 1);
    assert_eq!(log["records"][0]["src"], source.to_string());
    assert_eq!(log["records"][0]["answers"][0]["data"], "192.0.2.5");
}

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
    let database = Arc::new(crate::state::cache::CacheDb::in_dir(directory.path()));
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
    let (controller, _ebpf) = projection_controller(forwarder);
    let runtime = controller.runtime_provider().try_acquire().unwrap();
    let snapshot = Arc::clone(runtime.runtime().routing_projection());
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

    let outcome = controller
        .dns_service()
        .resolve_client_outcome_with_runtime(
            &runtime,
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Udp {
                advertised_size: 1232,
            },
            None,
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
    assert!(database.load_dns().expect("persisted rows").is_empty());
    controller.shutdown(Duration::from_secs(1)).await;
}

async fn assert_uncacheable_positive_projection(
    response: Vec<u8>,
    config: &honk_config::dns::DnsConfig,
    projection_ttl: u64,
) {
    let query = query_with_txid("example.com", 0x5151);
    let ip = [192, 0, 2, 77];
    let upstream = Arc::new(SlowUpstream {
        calls: AtomicUsize::new(0),
        delay: Duration::ZERO,
        response: response.clone(),
    });
    let forwarder = Arc::new(
        DnsForwarder::new(
            upstream.clone(),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(config).unwrap()),
        )
        .with_cache_ttl(0),
    );
    let (controller, ebpf) = projection_controller(forwarder);
    for _ in 0..2 {
        let wire = controller
            .answer_query_for_test(&query, DnsRequestMeta::EMPTY, IngressProfile::Internal)
            .await;
        assert_eq!(
            wire, response,
            "projection must not rewrite the returned TTLs"
        );
    }
    assert_eq!(
        upstream.calls.load(Ordering::SeqCst),
        2,
        "must not cache the answer"
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    let entries = ebpf.read().await.projection_map_snapshot();
    assert_eq!(
        entries.len(),
        1,
        "accepted answer lost its DNS domain projection"
    );
    assert_eq!(
        entries[0].0,
        crate::ebpf::maps::lpm_key_bytes(&crate::ebpf::maps::ip_addr_to_lpm_key(ip.into()))
    );
    assert_eq!(entries[0].1.bitmap, [1, 0, 0, 0, 0, 0, 0, 0]);

    tokio::time::sleep(Duration::from_secs(projection_ttl - 1)).await;
    let retained = ebpf.read().await.projection_map_snapshot();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].0, entries[0].0);
    assert_eq!(retained[0].1.bitmap, entries[0].1.bitmap);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(ebpf.read().await.projection_map_snapshot().is_empty());
    controller.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(start_paused = true)]
async fn uncacheable_zero_ttl_answer_keeps_routing_projection() {
    let query = query_with_txid("example.com", 0x5151);
    let mut response = a_response(&query, [192, 0, 2, 77]);
    crate::dns::forwarder::rewrite_answer_ttls(&mut response, 0);
    assert_uncacheable_positive_projection(response, &Default::default(), 60).await;
}

#[tokio::test(start_paused = true)]
async fn uncacheable_zero_ttl_additional_keeps_routing_projection() {
    let query = query_with_txid("example.com", 0x5151);
    let mut response = a_response(&query, [192, 0, 2, 77]);
    crate::dns::forwarder::rewrite_answer_ttls(&mut response, 300);
    response[10..12].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 88]);
    assert_uncacheable_positive_projection(response, &Default::default(), 300).await;
}

#[tokio::test(start_paused = true)]
async fn uncacheable_fixed_zero_keeps_routing_projection() {
    let query = query_with_txid("example.com", 0x5151);
    let mut response = a_response(&query, [192, 0, 2, 77]);
    crate::dns::forwarder::rewrite_answer_ttls(&mut response, 300);
    let mut config = honk_config::dns::DnsConfig::default();
    config.fixed_domain_ttl.insert("example.com".into(), 0);
    assert_uncacheable_positive_projection(response, &config, 300).await;
}
