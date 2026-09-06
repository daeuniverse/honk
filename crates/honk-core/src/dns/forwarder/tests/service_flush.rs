#[tokio::test]
async fn clones_share_lazy_engine_and_policy_change_resets_it() {
    let forwarder = DnsForwarder::new(
        Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 1], 300))),
        test_cache(),
        test_router(),
    );
    let clone = forwarder.clone();

    assert!(forwarder.engine.get().is_none());
    let original = forwarder.engine().await.expect("engine") as *const DnsEngine;
    let shared = clone.engine().await.expect("shared engine") as *const DnsEngine;
    assert_eq!(original, shared);

    let policy = PolicyId::from_config(&DnsConfig::default()).expect("policy");
    let rebound = clone.with_policy_id(policy);
    assert!(rebound.engine.get().is_none());
    let rebound_engine = rebound.engine().await.expect("rebound engine") as *const DnsEngine;
    assert_ne!(original, rebound_engine);
}

#[tokio::test]
async fn explicit_ingress_profiles_do_not_share_cache_entries() {
    let upstream = Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 1], 300)));
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), test_router());
    let query = make_a_query();

    forwarder
        .resolve_with_profile(&query, IngressProfile::Internal)
        .await
        .expect("internal response");
    forwarder
        .resolve_with_profile(&query, IngressProfile::Api)
        .await
        .expect("API response");

    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn service_rejects_a_mismatched_question_before_cache_write() {
    let mut response = make_a_response([192, 0, 2, 9], 300);
    response[13..20].copy_from_slice(b"poisonx");
    let cache = test_cache();
    let service = crate::dns::DnsService::with_forwarder(Arc::new(DnsForwarder::new(
        Arc::new(MockUpstream::new(response)),
        cache.clone(),
        test_router(),
    )));

    let error = service
        .resolve(&make_a_query(), IngressProfile::Api)
        .await
        .expect_err("mismatched upstream question must fail");

    assert!(error.to_string().contains("question does not match"));
    assert!(cache.lock().await.is_empty());
}

#[tokio::test]
async fn service_flush_cancels_stalled_query_without_cache_resurrection() {
    let upstream = Arc::new(GatedUpstream {
        response: make_a_response([192, 0, 2, 1], 300),
        call_count: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let cache = test_cache();
    let service = crate::dns::DnsService::with_forwarder(Arc::new(DnsForwarder::new(
        upstream.clone(),
        cache.clone(),
        test_router(),
    )));
    let query = make_a_query();
    let resolving = {
        let service = service.clone();
        tokio::spawn(async move { service.resolve(&query, IngressProfile::Internal).await })
    };
    upstream.entered.notified().await;
    let persisted = tokio::time::timeout(std::time::Duration::from_secs(1), service.flush_cache())
        .await
        .expect("flush must complete while the query remains stalled")
        .expect("flush");
    assert!(!persisted);

    upstream.release.notify_waiters();
    let result = resolving.await.expect("resolve task");
    assert!(result.is_err(), "pre-flush query must be cancelled");
    assert!(cache.lock().await.is_empty());
}

#[tokio::test]
async fn service_flush_fences_background_refresh_memory_and_persistence() {
    use honk_config::experimental::CacheFileConfig;

    let directory = tempfile::tempdir().expect("tempdir");
    let database = Arc::new(
        crate::cachedb::CacheDb::open(
            &CacheFileConfig {
                enabled: true,
                path: directory
                    .path()
                    .join("cache.db")
                    .to_string_lossy()
                    .into_owned(),
                cache_id: String::new(),
                store_fakeip: false,
                store_dns: true,
            },
        )
        .expect("cache.db"),
    );
    let persister = crate::dns::persist::DnsCachePersister::spawn(Arc::clone(&database));
    let upstream = Arc::new(RefreshFenceUpstream {
        initial: make_a_response([192, 0, 2, 1], 1),
        refreshed: make_a_response([192, 0, 2, 2], 300),
        call_count: AtomicUsize::new(0),
        refresh_entered: tokio::sync::Notify::new(),
        refresh_release: tokio::sync::Semaphore::new(0),
    });
    let cache = test_cache();
    cache.lock().await.set_persister(Some(persister.clone()));
    let forwarder = Arc::new(DnsForwarder::new(
        upstream.clone(),
        cache.clone(),
        test_router(),
    ));
    let service = crate::dns::DnsService::with_forwarder(Arc::clone(&forwarder));
    let query = make_a_query();

    let primed = service
        .resolve(&query, IngressProfile::Internal)
        .await
        .expect("prime");
    assert!(primed.windows(4).any(|bytes| bytes == [192, 0, 2, 1]));
    let cached = service
        .resolve(&query, IngressProfile::Internal)
        .await
        .expect("near-expiry cache hit");
    assert!(cached.windows(4).any(|bytes| bytes == [192, 0, 2, 1]));
    tokio::time::timeout(Duration::from_secs(1), upstream.refresh_entered.notified())
        .await
        .expect("background refresh entered");

    let persisted = tokio::time::timeout(Duration::from_secs(1), service.flush_cache())
        .await
        .expect("flush must acknowledge while refresh remains stalled")
        .expect("flush");
    assert!(persisted);
    upstream.refresh_release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while forwarder.refresh_task_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("old refresh completes");

    assert!(cache.lock().await.is_empty());
    persister.shutdown().await.expect("persistence shutdown");
    assert!(database.load_dns_v2().expect("persisted rows").is_empty());

    let refreshed = service
        .resolve(&query, IngressProfile::Internal)
        .await
        .expect("new-epoch query");
    assert!(refreshed.windows(4).any(|bytes| bytes == [192, 0, 2, 2]));
    assert_eq!(cache.lock().await.len(), 1);
    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn cancelled_persistent_flush_reopens_cache_publication() {
    use honk_config::experimental::CacheFileConfig;

    let directory = tempfile::tempdir().expect("tempdir");
    let database = Arc::new(
        crate::cachedb::CacheDb::open(
            &CacheFileConfig {
                enabled: true,
                path: directory
                    .path()
                    .join("cache.db")
                    .to_string_lossy()
                    .into_owned(),
                cache_id: String::new(),
                store_fakeip: false,
                store_dns: true,
            },
        )
        .expect("cache.db"),
    );
    let persister = crate::dns::persist::DnsCachePersister::spawn(Arc::clone(&database));
    let cache = test_cache();
    cache.lock().await.set_persister(Some(persister.clone()));
    let service = crate::dns::DnsService::with_forwarder(Arc::new(DnsForwarder::new(
        Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 9], 300))),
        cache.clone(),
        test_router(),
    )));
    let (flush_entered, _flush_release) = persister.gate_next_flush();
    let flushing = {
        let service = service.clone();
        tokio::spawn(async move { service.flush_cache().await })
    };
    tokio::time::timeout(Duration::from_secs(1), flush_entered.notified())
        .await
        .expect("flush reached persistence acknowledgement wait");
    flushing.abort();
    assert!(
        flushing
            .await
            .expect_err("flush task cancelled")
            .is_cancelled(),
        "flush must be cancelled while persistence acknowledgement is gated"
    );

    service
        .resolve(&make_a_query(), IngressProfile::Internal)
        .await
        .expect("post-cancellation resolve");
    assert_eq!(cache.lock().await.len(), 1);
    persister.shutdown().await.expect("persistence shutdown");
    assert_eq!(database.load_dns_v2().expect("persisted rows").len(), 1);
}
