#[tokio::test]
async fn fixed_zero_expiry_and_caller_txid_are_visible_in_typed_outcome() {
    let mut query = build_dns_query("example.com", 1);
    query[0..2].copy_from_slice(&0x5678_u16.to_be_bytes());
    let upstream = response(&query, [4, 3, 2, 1], 30);
    let forwarder = DnsForwarder::new(
        exchange([("first", Ok(upstream))], None),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", Vec::new(), Some(0)),
    );

    let outcome = forwarder.resolve_outcome(&query).await.expect("outcome");

    assert!(!outcome.expiry().is_cacheable());
    assert_eq!(&outcome.rendered()[0..2], &0x5678_u16.to_be_bytes());
}

#[tokio::test]
async fn strict_asis_without_destination_errors_but_raw_wrapper_uses_default() {
    let query = build_dns_query("example.com", 1);
    let routing = DnsRouting {
        request: DnsRequestRouting {
            rules: Vec::new(),
            fallback: DnsRequestAction::AsIs,
        },
        ..Default::default()
    };
    let pool = exchange([("default", Ok(response(&query, [1, 2, 3, 4], 30)))], None);
    let forwarder = DnsForwarder::new(
        pool.clone(),
        Arc::new(Mutex::new(DnsCache::new(8))),
        Arc::new(DnsRouter::new(&routing).expect("router")),
    );

    let typed_error = forwarder
        .resolve_outcome(&query)
        .await
        .expect_err("typed AsIs(None) must fail");
    let raw = forwarder.resolve(&query).await.expect("legacy fallback");

    assert!(matches!(
        typed_error,
        DnsForwardError::Engine(super::EngineError::Plan(
            PlanError::MissingOriginalDestination
        ))
    ));
    assert_eq!(&raw[raw.len() - 4..], &[1, 2, 3, 4]);
    assert_eq!(pool.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ineligible_queries_bypass_cache_while_eligible_queries_reuse_it() {
    for (label, unusual) in ineligible_queries() {
        let pool = exchange(
            [
                ("first", Ok(ineligible_response(&unusual))),
                ("first", Ok(ineligible_response(&unusual))),
            ],
            None,
        );
        let forwarder = DnsForwarder::new(
            pool.clone(),
            Arc::new(Mutex::new(DnsCache::new(8))),
            router("first", Vec::new(), None),
        );

        let first = forwarder
            .resolve_outcome(&unusual)
            .await
            .unwrap_or_else(|error| panic!("{label} first exchange failed: {error}"));
        let second = forwarder
            .resolve_outcome(&unusual)
            .await
            .unwrap_or_else(|error| panic!("{label} second exchange failed: {error}"));

        assert_eq!(first.provenance(), Provenance::Upstream, "{label}");
        assert_eq!(second.provenance(), Provenance::Upstream, "{label}");
        assert_eq!(pool.calls.load(Ordering::SeqCst), 2, "{label}");
    }

    let eligible = build_dns_query("example.com", 1);
    let eligible_pool = exchange([("first", Ok(response(&eligible, [3, 3, 3, 3], 30)))], None);
    let eligible_forwarder = DnsForwarder::new(
        eligible_pool.clone(),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", Vec::new(), None),
    );
    let _ = eligible_forwarder
        .resolve_outcome(&eligible)
        .await
        .expect("eligible miss");
    let hit = eligible_forwarder
        .resolve_outcome(&eligible)
        .await
        .expect("eligible hit");

    assert_eq!(hit.provenance(), Provenance::Cache);
    assert_eq!(eligible_pool.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn identical_ineligible_queries_reach_upstream_independently_when_overlapping() {
    for (label, query) in ineligible_queries() {
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
        let release = Arc::new(Barrier::new(3));
        let forwarder = Arc::new(DnsForwarder::new(
            Arc::new(OverlapExchange {
                entered: entered_tx,
                release: Arc::clone(&release),
            }),
            Arc::new(Mutex::new(DnsCache::new(8))),
            router("first", Vec::new(), None),
        ));
        let first_forwarder = Arc::clone(&forwarder);
        let first_query = query.clone();
        let first =
            tokio::spawn(async move { first_forwarder.resolve_outcome(&first_query).await });
        let second_forwarder = Arc::clone(&forwarder);
        let second_query = query.clone();
        let second =
            tokio::spawn(async move { second_forwarder.resolve_outcome(&second_query).await });

        tokio::time::timeout(std::time::Duration::from_secs(1), entered_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("{label}: first request did not reach upstream"))
            .expect("first upstream notification");
        tokio::time::timeout(std::time::Duration::from_millis(100), entered_rx.recv())
            .await
            .unwrap_or_else(|_| {
                panic!("{label}: second request coalesced instead of reaching upstream")
            })
            .expect("second upstream notification");
        release.wait().await;

        first.await.expect("first task").expect("first response");
        second.await.expect("second task").expect("second response");
    }
}

#[tokio::test]
async fn negative_outcome_expiry_matches_insert_and_cache_hit_lifetime() {
    let query = build_dns_query("example.com", 1);
    let mut nxdomain = query.clone();
    nxdomain[0..2].copy_from_slice(&[0, 0]);
    nxdomain[2] = 0x81;
    nxdomain[3] = 0x83;
    let pool = exchange([("first", Ok(nxdomain))], None);
    let forwarder = DnsForwarder::new(
        pool.clone(),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", Vec::new(), Some(0)),
    )
    .with_cache_ttl(600);

    let inserted = forwarder
        .resolve_outcome(&query)
        .await
        .expect("negative miss");
    let hit = forwarder
        .resolve_outcome(&query)
        .await
        .expect("negative hit");

    assert_eq!(inserted.response_class(), ResponseClass::Nxdomain);
    assert_eq!(inserted.expiry().ttl(), std::time::Duration::from_secs(60));
    assert_eq!(hit.provenance(), Provenance::Cache);
    assert!(hit.expiry().is_cacheable());
    assert_eq!(hit.expiry().ttl(), std::time::Duration::from_secs(60));
    assert_eq!(pool.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn config_backed_forwarder_populates_typed_policy_identity() {
    let query = build_dns_query("example.com", 1);
    let config = DnsConfig::default();
    let forwarder = DnsForwarder::new(
        exchange([("first", Ok(response(&query, [4, 4, 4, 4], 30)))], None),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", Vec::new(), None),
    )
    .with_policy_from_config(&config)
    .expect("config policy");

    let outcome = forwarder.resolve_outcome(&query).await.expect("outcome");

    let hosts = crate::dns::forwarder::HostsSourceSet::load(&config).unwrap();
    let expected = crate::dns::policy::PolicyId::from_config_with_artifacts(
        &config,
        &hosts.fingerprint(),
        &forwarder.routing_snapshot().geo_fingerprint(),
    )
    .unwrap();
    assert_eq!(
        outcome.policy_id().map(ToString::to_string),
        Some(expected.to_string())
    );
}
