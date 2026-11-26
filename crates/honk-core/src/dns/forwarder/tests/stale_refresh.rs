use super::*;

use crate::dns::cache::{CacheKey, OperationKind};
use crate::dns::outcome::Provenance;
use crate::dns::outcome::{OutcomeStatus, ResponseClass};
use crate::dns::planner::{RequestScope, UpstreamTag};
use crate::dns::query::QueryContext;

#[tokio::test]
async fn forwarding_hot_path_is_not_serialized_by_compatibility_cache_mutex() {
    let cache = test_cache();
    let forwarder = DnsForwarder::new(
        Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 3], 300))),
        cache.clone(),
        test_router(),
    );
    let _service = forwarder.cache_service().await;
    let _compatibility_guard = cache.lock().await;

    let result = tokio::time::timeout(Duration::from_secs(1), forwarder.resolve(&make_a_query()))
        .await
        .expect("compatibility mutex must not block service")
        .expect("resolve");

    assert_eq!(&result[result.len() - 4..], &[192, 0, 2, 3]);
}

/// Fill the cache with a 1-second-TTL answer, let it expire, then
/// resolve through a failing upstream — the stale entry must be served
/// (RFC 8767) with TTLs rewritten to the configured stale reply TTL.
#[tokio::test]
async fn test_serve_stale_on_upstream_failure() {
    let response = make_a_response([93, 184, 216, 34], 1);
    let cache = test_cache();
    let query = make_a_query();
    let fwd_ok = DnsForwarder::new(
        Arc::new(MockUpstream::new(response)),
        cache.clone(),
        test_router(),
    );
    fwd_ok.resolve(&query).await.expect("initial resolve");
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    let fwd_fail = DnsForwarder::new(Arc::new(FailUpstream), cache, test_router());
    let expected_ttl = fwd_fail.stale_reply_ttl;
    let stale = fwd_fail.resolve(&query).await.expect("stale served");
    assert!(stale.windows(4).any(|w| w == [93, 184, 216, 34]));
    assert_eq!(extract_min_ttl(&stale), expected_ttl);
}

#[tokio::test]
async fn serve_stale_with_configured_reply_ttl_updates_wire_and_outcome() {
    let response = make_a_response([93, 184, 216, 34], 1);
    let cache = test_cache();
    let query = make_a_query();
    let fwd_ok = DnsForwarder::new(
        Arc::new(MockUpstream::new(response)),
        cache.clone(),
        test_router(),
    );
    fwd_ok.resolve(&query).await.expect("initial resolve");
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    let fwd_fail =
        DnsForwarder::new(Arc::new(FailUpstream), cache, test_router()).with_stale_reply_ttl(7);
    let stale = fwd_fail
        .resolve_outcome(&query)
        .await
        .expect("stale outcome");
    assert_eq!(stale.provenance(), Provenance::Stale);
    assert_eq!(extract_min_ttl(stale.rendered()), 7);
    assert_eq!(stale.expiry().ttl(), Duration::from_secs(7));
}

#[tokio::test]
async fn serve_stale_with_zero_reply_ttl_preserves_wire_and_outcome_expiry() {
    let response = make_a_response([93, 184, 216, 34], 1);
    let cache = test_cache();
    let query = make_a_query();
    let fwd_ok = DnsForwarder::new(
        Arc::new(MockUpstream::new(response)),
        cache.clone(),
        test_router(),
    );
    fwd_ok.resolve(&query).await.expect("initial resolve");
    let stored_ttl = {
        let guard = cache.lock().await;
        extract_min_ttl(&guard.positive_entries_for_test()[0].response)
    };
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    let fwd_fail =
        DnsForwarder::new(Arc::new(FailUpstream), cache, test_router()).with_stale_reply_ttl(0);
    let stale = fwd_fail
        .resolve_outcome(&query)
        .await
        .expect("stale outcome");
    assert_eq!(stale.provenance(), Provenance::Stale);
    assert_ne!(stored_ttl, 30);
    assert_eq!(extract_min_ttl(stale.rendered()), stored_ttl);
    assert_eq!(
        stale.expiry().ttl(),
        Duration::from_secs(u64::from(extract_min_ttl(stale.rendered())))
    );
}

/// A SERVFAIL answer must not shadow a recently-expired positive entry.
#[tokio::test]
async fn test_serve_stale_on_servfail() {
    let mut servfail = make_a_response([93, 184, 216, 34], 1);
    servfail[3] = 0x82; // RCODE = SERVFAIL
    let cache = test_cache();
    let query = make_a_query();
    let fwd_ok = DnsForwarder::new(
        Arc::new(MockUpstream::new(make_a_response([93, 184, 216, 34], 1))),
        cache.clone(),
        test_router(),
    );
    fwd_ok.resolve(&query).await.expect("initial resolve");
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    let fwd_fail = DnsForwarder::new(Arc::new(MockUpstream::new(servfail)), cache, test_router());
    let stale = fwd_fail.resolve(&query).await.expect("stale served");
    assert!(stale.windows(4).any(|w| w == [93, 184, 216, 34]));
}

/// Hot entries nearing expiry trigger a deduplicated background refresh.
#[tokio::test]
async fn test_stale_while_revalidate_refresh() {
    let response = make_a_response([93, 184, 216, 34], 2);
    let mock = Arc::new(MockUpstream::new(response));
    let forwarder = DnsForwarder::new(mock.clone(), test_cache(), test_router());
    let query = make_a_query();

    forwarder.resolve(&query).await.expect("initial resolve");
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

    // Wait until remaining TTL (2s) drops to the <=10% threshold.
    tokio::time::sleep(std::time::Duration::from_millis(1900)).await;
    // This lookup is a cache hit that should kick off a refresh.
    forwarder.resolve(&query).await.expect("cache hit");
    // The refresh happens in the background; poll briefly.
    let mut calls = 1;
    for _ in 0..20 {
        calls = mock.call_count.load(Ordering::SeqCst);
        if calls >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(calls, 2, "background refresh should re-query upstream");
}

#[tokio::test]
async fn background_refresh_rejects_a_mismatched_question_before_cache_write() {
    struct InvalidRefreshUpstream {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl DnsUpstreamPool for InvalidRefreshUpstream {
        async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let mut response = make_a_response(
                if call == 0 {
                    [192, 0, 2, 1]
                } else {
                    [192, 0, 2, 2]
                },
                2,
            );
            if call > 0 {
                response[13..20].copy_from_slice(b"poisonx");
            }
            Ok(response)
        }
    }

    let upstream = Arc::new(InvalidRefreshUpstream {
        calls: AtomicUsize::new(0),
    });
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), test_router());
    let service = forwarder.cache_service().await;
    let query = make_a_query();
    forwarder.resolve(&query).await.expect("prime cache");
    tokio::time::sleep(Duration::from_millis(1900)).await;

    forwarder.resolve(&query).await.expect("near-expiry hit");
    for _ in 0..20 {
        if forwarder.refresh_task_count() == 0 && upstream.calls.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    let entries = service.positive_entries_for_test();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        &entries[0].response[entries[0].response.len() - 4..],
        &[192, 0, 2, 1]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hot_near_expiry_hits_own_one_refresh_task_and_close_cleans_it() {
    const CALLERS: usize = 128;
    struct RefreshUpstream {
        response: Vec<u8>,
        calls: AtomicUsize,
        refresh_entered: tokio::sync::Notify,
    }
    #[async_trait]
    impl DnsUpstreamPool for RefreshUpstream {
        async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call > 0 {
                self.refresh_entered.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(self.response.clone())
        }
    }

    let upstream = Arc::new(RefreshUpstream {
        response: make_a_response([192, 0, 2, 10], 2),
        calls: AtomicUsize::new(0),
        refresh_entered: tokio::sync::Notify::new(),
    });
    let forwarder = Arc::new(DnsForwarder::new(
        upstream.clone(),
        test_cache(),
        test_router(),
    ));
    let flights = forwarder.singleflight();
    forwarder.resolve(&make_a_query()).await.expect("prime");

    let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
    let mut callers = tokio::task::JoinSet::new();
    for _ in 0..CALLERS {
        let forwarder = Arc::clone(&forwarder);
        let start = Arc::clone(&start);
        callers.spawn(async move {
            start.wait().await;
            forwarder.resolve(&make_a_query()).await
        });
    }
    start.wait().await;
    while let Some(joined) = callers.join_next().await {
        joined.expect("task").expect("cache hit");
    }
    upstream.refresh_entered.notified().await;

    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    assert_eq!(forwarder.refresh_task_count(), 1);
    assert_eq!(flights.active_len(), 1);
    forwarder.shutdown_background_tasks().await;
    assert_eq!(forwarder.refresh_task_count(), 0);
    assert_eq!(flights.active_len(), 0);
}

#[tokio::test]
async fn compatibility_default_scope_refresh_keeps_compatibility_planning() {
    use honk_config::dns::{DnsRequestAction, DnsRequestRouting};

    let upstream = Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 20], 2)));
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: Vec::new(),
                fallback: DnsRequestAction::AsIs,
            },
            ..Default::default()
        })
        .expect("router"),
    );
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), router);
    let query = make_a_query();

    forwarder
        .resolve(&query)
        .await
        .expect("compatibility prime");
    tokio::time::sleep(Duration::from_millis(1900)).await;
    forwarder.resolve(&query).await.expect("near-expiry hit");
    for _ in 0..20 {
        if upstream.call_count.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_selected_near_expiry_hits_share_one_refresh() {
    use honk_config::dns::{DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule};

    struct SourceRefreshUpstream {
        calls: std::sync::Mutex<Vec<String>>,
        refresh_entered: tokio::sync::Notify,
        refresh_release: tokio::sync::Semaphore,
    }

    #[async_trait]
    impl DnsUpstreamPool for SourceRefreshUpstream {
        async fn query(&self, upstream_name: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
            let refresh = {
                let mut calls = self.calls.lock().expect("calls");
                calls.push(upstream_name.to_string());
                calls.len() > 1
            };
            if refresh {
                self.refresh_entered.notify_one();
                self.refresh_release.acquire().await?.forget();
            }
            Ok(make_a_response([192, 0, 2, 30], 2))
        }
    }

    let upstream = Arc::new(SourceRefreshUpstream {
        calls: std::sync::Mutex::new(Vec::new()),
        refresh_entered: tokio::sync::Notify::new(),
        refresh_release: tokio::sync::Semaphore::new(0),
    });
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![DnsRequestRule {
                    conditions: vec![DnsCond::Sip {
                        not: false,
                        cidrs: vec!["192.0.2.0/24".into(), "203.0.113.0/24".into()],
                    }],
                    action: DnsRequestAction::Upstream("red".into()),
                }],
                fallback: DnsRequestAction::Upstream("trap".into()),
            },
            ..Default::default()
        })
        .expect("router"),
    );
    let forwarder = Arc::new(DnsForwarder::new(upstream.clone(), test_cache(), router));
    let flights = forwarder.singleflight();
    let query = make_a_query();
    forwarder
        .resolve_outcome_with_context(
            &query,
            DnsRequestMeta::new(Some("192.0.2.10".parse().expect("source")), None),
        )
        .await
        .expect("prime");
    tokio::time::sleep(Duration::from_millis(1900)).await;

    let start = Arc::new(tokio::sync::Barrier::new(3));
    let mut callers = tokio::task::JoinSet::new();
    for source in ["192.0.2.10", "203.0.113.30"] {
        let forwarder = Arc::clone(&forwarder);
        let start = Arc::clone(&start);
        let query = query.clone();
        callers.spawn(async move {
            start.wait().await;
            forwarder
                .resolve_outcome_with_context(
                    &query,
                    DnsRequestMeta::new(Some(source.parse().expect("source")), None),
                )
                .await
        });
    }
    start.wait().await;
    while let Some(result) = callers.join_next().await {
        result.expect("task").expect("cache hit");
    }
    upstream.refresh_entered.notified().await;

    assert_eq!(forwarder.refresh_task_count(), 1);
    assert_eq!(flights.active_len(), 1);
    assert_eq!(
        upstream.calls.lock().expect("calls").as_slice(),
        ["red", "red"]
    );
    upstream.refresh_release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while forwarder.refresh_task_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refresh completion");
    assert_eq!(flights.active_len(), 0);
}

#[tokio::test]
async fn stale_response_keeps_source_aware_preferred_family_projection() {
    use honk_config::dns::{DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule};

    struct StalePreferenceUpstream;

    #[async_trait]
    impl DnsUpstreamPool for StalePreferenceUpstream {
        async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(match upstream_name {
                "aaaa" => make_aaaa_response(TEST_V6, 1),
                "has-a" => make_a_response([192, 0, 2, 1], 300),
                "no-a" => {
                    let query = crate::dns::query::QueryContext::parse(raw_query).expect("query");
                    make_empty_response(raw_query, &query)
                }
                _ => panic!("unexpected upstream {upstream_name}"),
            })
        }
    }

    async fn projections(forwarder: &DnsForwarder, query: &[u8]) -> [u16; 2] {
        let mut counts = [0, 0];
        for (index, source) in ["192.0.2.10", "198.51.100.10"].into_iter().enumerate() {
            let response = forwarder
                .resolve_outcome_with_context(
                    query,
                    DnsRequestMeta::new(Some(source.parse().expect("source")), None),
                )
                .await
                .expect("response")
                .into_rendered();
            assert_eq!(response[3] & 0x0f, 0);
            counts[index] = answer_count(&response);
        }
        counts
    }

    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![
                    DnsRequestRule {
                        conditions: vec![DnsCond::Qtype {
                            not: false,
                            types: vec![28],
                        }],
                        action: DnsRequestAction::Upstream("aaaa".into()),
                    },
                    DnsRequestRule {
                        conditions: vec![
                            DnsCond::Sip {
                                not: false,
                                cidrs: vec!["192.0.2.0/24".into()],
                            },
                            DnsCond::Qtype {
                                not: false,
                                types: vec![1],
                            },
                        ],
                        action: DnsRequestAction::Upstream("has-a".into()),
                    },
                ],
                fallback: DnsRequestAction::Upstream("no-a".into()),
            },
            ..Default::default()
        })
        .expect("router"),
    );
    let cache = test_cache();
    let query = build_dns_query("example.com", 28);
    let priming = DnsForwarder::new(
        Arc::new(StalePreferenceUpstream),
        cache.clone(),
        Arc::clone(&router),
    )
    .with_strategy(DnsStrategy::PreferIpv4);
    assert_eq!(projections(&priming, &query).await, [0, 1]);
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let failing = DnsForwarder::new(Arc::new(FailUpstream), cache, router)
        .with_strategy(DnsStrategy::PreferIpv4);
    assert_eq!(projections(&failing, &query).await, [0, 1]);
}

fn resolve_cache_key(query: &[u8]) -> CacheKey {
    let parsed = QueryContext::parse(query).expect("query");
    CacheKey::new(
        &parsed,
        None,
        RequestScope::Upstream(UpstreamTag::new("default").expect("scope")),
        OperationKind::Resolve,
    )
}

async fn wait_for_refresh_start(upstream: &RefreshFenceUpstream) {
    tokio::time::timeout(Duration::from_secs(1), upstream.refresh_entered.notified())
        .await
        .expect("refresh entered");
}

async fn wait_for_refresh_completion(forwarder: &DnsForwarder) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while forwarder.refresh_task_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refresh completion");
}

#[tokio::test]
async fn refresh_nxdomain_without_soa_retires_the_refreshed_positive() {
    let query = make_a_query();
    let upstream = Arc::new(RefreshFenceUpstream {
        initial: make_a_response([192, 0, 2, 1], 1),
        refreshed: make_nxdomain_without_soa_response(&query),
        later: RefreshFenceLater::Error,
        call_count: AtomicUsize::new(0),
        refresh_entered: tokio::sync::Notify::new(),
        refresh_release: tokio::sync::Semaphore::new(0),
    });
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), test_router());
    forwarder.resolve_outcome(&query).await.expect("initial");
    let cached = forwarder.resolve_outcome(&query).await.expect("cache hit");
    assert_eq!(cached.provenance(), Provenance::Cache);
    wait_for_refresh_start(&upstream).await;
    forwarder
        .cache_service()
        .await
        .expire_positive_exact_for_test(&resolve_cache_key(&query));
    upstream.refresh_release.add_permits(1);
    wait_for_refresh_completion(&forwarder).await;

    let error = forwarder
        .resolve_outcome(&query)
        .await
        .expect_err("retired positive must not be served stale");
    assert!(matches!(error.unshared(), DnsForwardError::Exchange { .. }));
}

#[tokio::test]
async fn foreground_nxdomain_retires_expired_positive() {
    let query = make_a_query();
    let upstream = Arc::new(RefreshFenceUpstream {
        initial: make_a_response([192, 0, 2, 1], 1),
        refreshed: make_nxdomain_without_soa_response(&query),
        later: RefreshFenceLater::Error,
        call_count: AtomicUsize::new(0),
        refresh_entered: tokio::sync::Notify::new(),
        refresh_release: tokio::sync::Semaphore::new(0),
    });
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), test_router());
    forwarder.resolve_outcome(&query).await.expect("initial");
    forwarder
        .cache_service()
        .await
        .expire_positive_exact_for_test(&resolve_cache_key(&query));
    upstream.refresh_release.add_permits(1);
    let negative = forwarder.resolve_outcome(&query).await.expect("nxdomain");
    assert_eq!(negative.response_class(), ResponseClass::Nxdomain);

    let error = forwarder
        .resolve_outcome(&query)
        .await
        .expect_err("retired positive must not be served stale");
    assert!(matches!(error.unshared(), DnsForwardError::Exchange { .. }));
}

#[tokio::test]
async fn foreground_zero_ttl_positive_retires_expired_positive() {
    let query = make_a_query();
    let upstream = Arc::new(RefreshFenceUpstream {
        initial: make_a_response([192, 0, 2, 1], 1),
        refreshed: make_a_response([192, 0, 2, 2], 0),
        later: RefreshFenceLater::Error,
        call_count: AtomicUsize::new(0),
        refresh_entered: tokio::sync::Notify::new(),
        refresh_release: tokio::sync::Semaphore::new(0),
    });
    let forwarder =
        DnsForwarder::new(upstream.clone(), test_cache(), test_router()).with_cache_ttl(0);
    forwarder.resolve_outcome(&query).await.expect("initial");
    forwarder
        .cache_service()
        .await
        .expire_positive_exact_for_test(&resolve_cache_key(&query));
    upstream.refresh_release.add_permits(1);

    let replacement = forwarder
        .resolve_outcome(&query)
        .await
        .expect("zero-TTL positive");
    assert_eq!(
        replacement.answer_ips(),
        &[IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2))]
    );
    assert!(!replacement.expiry().is_cacheable());
    let error = forwarder
        .resolve_outcome(&query)
        .await
        .expect_err("superseded positive must not be served");
    assert!(matches!(error.unshared(), DnsForwardError::Exchange { .. }));
}

#[tokio::test]
async fn owning_refresh_publishes_a_changed_positive() {
    let query = make_a_query();
    let upstream = Arc::new(RefreshFenceUpstream {
        initial: make_a_response([192, 0, 2, 1], 1),
        refreshed: make_a_response([192, 0, 2, 2], 300),
        later: RefreshFenceLater::Error,
        call_count: AtomicUsize::new(0),
        refresh_entered: tokio::sync::Notify::new(),
        refresh_release: tokio::sync::Semaphore::new(0),
    });
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), test_router());

    forwarder.resolve_outcome(&query).await.expect("initial");
    let cached = forwarder.resolve_outcome(&query).await.expect("cache hit");
    assert_eq!(cached.provenance(), Provenance::Cache);
    wait_for_refresh_start(&upstream).await;
    upstream.refresh_release.add_permits(1);
    wait_for_refresh_completion(&forwarder).await;

    let changed = forwarder
        .resolve_outcome(&query)
        .await
        .expect("changed cache hit");
    assert_eq!(changed.status(), OutcomeStatus::Accepted);
    assert_eq!(changed.response_class(), ResponseClass::Positive);
    assert_eq!(changed.provenance(), Provenance::Cache);
    assert_eq!(
        changed.answer_ips(),
        &[IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2))]
    );
    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn held_refresh_does_not_overwrite_a_newer_foreground_nxdomain() {
    let query = make_a_query();
    let foreground = make_nxdomain_response(&query, 1, 1);
    let upstream = Arc::new(RefreshFenceUpstream {
        initial: make_a_response([192, 0, 2, 1], 1),
        refreshed: make_a_response([192, 0, 2, 2], 300),
        later: RefreshFenceLater::Response(foreground),
        call_count: AtomicUsize::new(0),
        refresh_entered: tokio::sync::Notify::new(),
        refresh_release: tokio::sync::Semaphore::new(0),
    });
    let cache = test_cache();
    let forwarder = DnsForwarder::new(upstream.clone(), cache.clone(), test_router());

    forwarder.resolve_outcome(&query).await.expect("initial");
    forwarder.resolve_outcome(&query).await.expect("cache hit");
    wait_for_refresh_start(&upstream).await;
    let service = forwarder.cache_service().await;
    service.expire_positive_exact_for_test(&resolve_cache_key(&query));

    let foreground = forwarder
        .resolve_outcome(&query)
        .await
        .expect("foreground nxdomain");
    assert_eq!(foreground.status(), OutcomeStatus::Accepted);
    assert_eq!(foreground.response_class(), ResponseClass::Nxdomain);
    assert_eq!(foreground.provenance(), Provenance::Upstream);
    assert_eq!(foreground.rendered()[3] & 0x0f, 3);

    upstream.refresh_release.add_permits(1);
    wait_for_refresh_completion(&forwarder).await;

    let retained = forwarder
        .resolve_outcome(&query)
        .await
        .expect("negative hit");
    assert_eq!(retained.status(), OutcomeStatus::Accepted);
    assert_eq!(retained.response_class(), ResponseClass::Nxdomain);
    assert_eq!(retained.provenance(), Provenance::Cache);
    assert_eq!(retained.rendered()[3] & 0x0f, 3);
}

#[tokio::test]
async fn held_refresh_does_not_overwrite_a_newer_foreground_positive() {
    let query = make_a_query();
    let parsed = QueryContext::parse(&query).expect("query");
    let refresh_responses = [
        make_nxdomain_response(&query, 1, 1),
        make_empty_response(&query, &parsed),
    ];

    for refresh_response in refresh_responses {
        let upstream = Arc::new(RefreshFenceUpstream {
            initial: make_a_response([192, 0, 2, 1], 1),
            refreshed: refresh_response,
            later: RefreshFenceLater::Response(make_a_response([192, 0, 2, 9], 300)),
            call_count: AtomicUsize::new(0),
            refresh_entered: tokio::sync::Notify::new(),
            refresh_release: tokio::sync::Semaphore::new(0),
        });
        let cache = test_cache();
        let forwarder = DnsForwarder::new(upstream.clone(), cache, test_router());

        forwarder.resolve_outcome(&query).await.expect("initial");
        forwarder.resolve_outcome(&query).await.expect("cache hit");
        wait_for_refresh_start(&upstream).await;
        let service = forwarder.cache_service().await;
        service.expire_positive_exact_for_test(&resolve_cache_key(&query));

        let foreground = forwarder
            .resolve_outcome(&query)
            .await
            .expect("foreground positive");
        assert_eq!(foreground.status(), OutcomeStatus::Accepted);
        assert_eq!(foreground.response_class(), ResponseClass::Positive);
        assert_eq!(foreground.provenance(), Provenance::Upstream);
        assert_eq!(
            foreground.answer_ips(),
            &[IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9))]
        );

        upstream.refresh_release.add_permits(1);
        wait_for_refresh_completion(&forwarder).await;

        let retained = forwarder
            .resolve_outcome(&query)
            .await
            .expect("positive hit");
        assert_eq!(retained.status(), OutcomeStatus::Accepted);
        assert_eq!(retained.response_class(), ResponseClass::Positive);
        assert_eq!(retained.provenance(), Provenance::Cache);
        assert_eq!(
            retained.answer_ips(),
            &[IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9))]
        );
    }
}

#[tokio::test]
async fn refresh_servfail_keeps_the_stale_positive() {
    let query = make_a_query();
    let mut servfail = make_a_response([192, 0, 2, 1], 1);
    servfail[3] = 0x82;
    let upstream = Arc::new(RefreshFenceUpstream {
        initial: make_a_response([192, 0, 2, 1], 1),
        refreshed: servfail,
        later: RefreshFenceLater::Error,
        call_count: AtomicUsize::new(0),
        refresh_entered: tokio::sync::Notify::new(),
        refresh_release: tokio::sync::Semaphore::new(0),
    });
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), test_router());

    forwarder.resolve_outcome(&query).await.expect("initial");
    forwarder.resolve_outcome(&query).await.expect("cache hit");
    wait_for_refresh_start(&upstream).await;
    let service = forwarder.cache_service().await;
    service.expire_positive_exact_for_test(&resolve_cache_key(&query));
    upstream.refresh_release.add_permits(1);
    wait_for_refresh_completion(&forwarder).await;

    let stale = forwarder
        .resolve_outcome(&query)
        .await
        .expect("stale positive");
    assert_eq!(stale.status(), OutcomeStatus::Accepted);
    assert_eq!(stale.response_class(), ResponseClass::Positive);
    assert_eq!(stale.provenance(), Provenance::Stale);
    assert_eq!(
        stale.answer_ips(),
        &[IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))]
    );
}

#[tokio::test]
async fn background_refresh_storm_leaves_foreground_singleflight_capacity() {
    struct HeldRefreshUpstream {
        primed: usize,
        calls: AtomicUsize,
        release_refresh: tokio::sync::Notify,
    }

    #[async_trait]
    impl DnsUpstreamPool for HeldRefreshUpstream {
        async fn query(&self, _: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            let (domain, _) =
                parse_dns_question(raw_query).ok_or_else(|| anyhow::anyhow!("question"))?;
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if domain.starts_with("prime-") && call >= self.primed {
                self.release_refresh.notified().await;
            }
            let mut response = make_a_response([192, 0, 2, 77], 1);
            let parsed = QueryContext::parse(raw_query).expect("query");
            let end = parsed.question_offsets().expect("offsets").end();
            let mut out = raw_query[..end].to_vec();
            out[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            out[6..8].copy_from_slice(&1_u16.to_be_bytes());
            out.extend_from_slice(&response.split_off(response.len() - 16));
            Ok(out)
        }
    }

    const PRIMED: usize = 2048;
    let upstream = Arc::new(HeldRefreshUpstream {
        primed: PRIMED,
        calls: AtomicUsize::new(0),
        release_refresh: tokio::sync::Notify::new(),
    });
    let cache = Arc::new(tokio::sync::Mutex::new(DnsCache::new(8192)));
    let forwarder = DnsForwarder::new(upstream.clone(), cache, test_router());

    let queries: Vec<_> = (0..PRIMED)
        .map(|index| build_dns_query(&format!("prime-{index}.example"), 1))
        .collect();
    for query in &queries {
        forwarder.resolve_outcome(query).await.expect("prime");
    }
    for query in &queries {
        let hit = forwarder
            .resolve_outcome(query)
            .await
            .expect("near-expiry cache hit");
        assert_eq!(hit.provenance(), Provenance::Cache);
    }

    assert!(
        forwarder.active_flights() <= crate::dns::singleflight::MAX_REFRESH_FLIGHTS,
        "refresh storm occupied {} active flights",
        forwarder.active_flights()
    );
    let cold = build_dns_query("cold-foreground.example", 1);
    let foreground = forwarder
        .resolve_outcome(&cold)
        .await
        .expect("foreground resolve must retain reserved singleflight capacity");
    assert_eq!(foreground.provenance(), Provenance::Upstream);

    upstream.release_refresh.notify_waiters();
    forwarder.shutdown_background_tasks().await;
}

#[tokio::test]
async fn background_refresh_preferred_siblings_respect_foreground_singleflight_reserve() {
    struct SiblingStormUpstream {
        aaaa_entered: AtomicUsize,
        aaaa_ready: tokio::sync::Notify,
        release_aaaa: tokio::sync::Notify,
        a_entered: AtomicUsize,
        a_progress: tokio::sync::Notify,
        release_a: tokio::sync::Notify,
    }

    #[async_trait]
    impl DnsUpstreamPool for SiblingStormUpstream {
        async fn query(&self, _: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            let (domain, qtype) =
                parse_dns_question(raw_query).ok_or_else(|| anyhow::anyhow!("question"))?;
            if domain.starts_with("prefer-") {
                if qtype == 28 {
                    let entered = self.aaaa_entered.fetch_add(1, Ordering::SeqCst) + 1;
                    if entered == 1024 {
                        self.aaaa_ready.notify_one();
                    }
                    self.release_aaaa.notified().await;
                    let mut response = make_aaaa_response(TEST_V6, 300);
                    let parsed = QueryContext::parse(raw_query).expect("query");
                    let end = parsed.question_offsets().expect("offsets").end();
                    let mut out = raw_query[..end].to_vec();
                    out[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
                    out[6..8].copy_from_slice(&1_u16.to_be_bytes());
                    out.extend_from_slice(&response.split_off(response.len() - 28));
                    return Ok(out);
                }
                if qtype == 1 {
                    self.a_entered.fetch_add(1, Ordering::SeqCst);
                    self.a_progress.notify_waiters();
                    self.release_a.notified().await;
                }
            }
            let mut response = make_a_response([192, 0, 2, 88], 300);
            let parsed = QueryContext::parse(raw_query).expect("query");
            let end = parsed.question_offsets().expect("offsets").end();
            let mut out = raw_query[..end].to_vec();
            out[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            out[6..8].copy_from_slice(&1_u16.to_be_bytes());
            out.extend_from_slice(&response.split_off(response.len() - 16));
            Ok(out)
        }
    }

    const COUNT: usize = 1024;
    let upstream = Arc::new(SiblingStormUpstream {
        aaaa_entered: AtomicUsize::new(0),
        aaaa_ready: tokio::sync::Notify::new(),
        release_aaaa: tokio::sync::Notify::new(),
        a_entered: AtomicUsize::new(0),
        a_progress: tokio::sync::Notify::new(),
        release_a: tokio::sync::Notify::new(),
    });
    let cache = Arc::new(tokio::sync::Mutex::new(DnsCache::new(8192)));
    let forwarder = DnsForwarder::new(upstream.clone(), cache, test_router())
        .with_strategy(DnsStrategy::PreferIpv4);
    let service = forwarder.cache_service().await;

    let mut aaaa_queries = Vec::with_capacity(COUNT);
    let mut a_keys = Vec::with_capacity(COUNT);
    for index in 0..COUNT {
        let domain = format!("prefer-{index}.example");
        let aaaa_query = build_dns_query(&domain, 28);
        let a_query = build_dns_query(&domain, 1);
        let mut aaaa_wire = make_aaaa_response(TEST_V6, 1);
        let aaaa_end = QueryContext::parse(&aaaa_query)
            .expect("aaaa query")
            .question_offsets()
            .expect("offsets")
            .end();
        let mut aaaa_cached = aaaa_query[..aaaa_end].to_vec();
        aaaa_cached[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        aaaa_cached[6..8].copy_from_slice(&1_u16.to_be_bytes());
        aaaa_cached.extend_from_slice(&aaaa_wire.split_off(aaaa_wire.len() - 28));
        service.put_exact(resolve_cache_key(&aaaa_query), aaaa_cached, 1, None);

        let mut a_wire = make_a_response([192, 0, 2, 1], 300);
        let a_end = QueryContext::parse(&a_query)
            .expect("a query")
            .question_offsets()
            .expect("offsets")
            .end();
        let mut a_cached = a_query[..a_end].to_vec();
        a_cached[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        a_cached[6..8].copy_from_slice(&1_u16.to_be_bytes());
        a_cached.extend_from_slice(&a_wire.split_off(a_wire.len() - 16));
        let a_key = resolve_cache_key(&a_query);
        service.put_exact(a_key.clone(), a_cached, 300, None);
        aaaa_queries.push(aaaa_query);
        a_keys.push(a_key);
    }

    for query in &aaaa_queries {
        let hit = forwarder
            .resolve_outcome(query)
            .await
            .expect("near-expiry AAAA cache hit");
        assert_eq!(hit.provenance(), Provenance::Cache);
    }
    tokio::time::timeout(Duration::from_secs(5), upstream.aaaa_ready.notified())
        .await
        .expect("all 1024 AAAA refreshes entered");

    for a_key in &a_keys {
        service.expire_positive_exact_for_test(a_key);
    }
    upstream.release_aaaa.notify_waiters();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let a_entered = upstream.a_entered.load(Ordering::SeqCst);
            let active_tasks = forwarder.refresh_task_count();
            if a_entered >= 512 && (a_entered == COUNT || active_tasks <= a_entered) {
                break;
            }
            tokio::select! {
                _ = upstream.a_progress.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
    })
    .await
    .expect("refresh sibling storm settled");

    assert!(
        forwarder.active_flights() <= crate::dns::singleflight::MAX_REFRESH_FLIGHTS,
        "refresh + preferred sibling storm occupied {} active flights",
        forwarder.active_flights()
    );
    let cold = build_dns_query("cold-foreground-prefer.example", 1);
    let foreground = forwarder
        .resolve_outcome(&cold)
        .await
        .expect("foreground resolve must retain reserved singleflight capacity");
    assert_eq!(foreground.provenance(), Provenance::Upstream);

    upstream.release_a.notify_waiters();
    forwarder.shutdown_background_tasks().await;
}
