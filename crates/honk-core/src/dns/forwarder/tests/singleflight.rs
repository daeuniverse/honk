#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identical_concurrent_queries_share_one_exchange_and_render_each_txid() {
    const CALLERS: usize = 128;
    let upstream = Arc::new(GatedUpstream {
        response: make_a_response([192, 0, 2, 1], 300),
        call_count: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let cache = test_cache();
    let forwarder = Arc::new(DnsForwarder::new(
        upstream.clone(),
        cache.clone(),
        test_router(),
    ));
    let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
    let mut tasks = tokio::task::JoinSet::new();
    for txid in 1..=CALLERS {
        let forwarder = Arc::clone(&forwarder);
        let start = Arc::clone(&start);
        tasks.spawn(async move {
            let mut query = make_a_query();
            query[0..2].copy_from_slice(
                &u16::try_from(txid)
                    .expect("caller count fits u16")
                    .to_be_bytes(),
            );
            start.wait().await;
            forwarder.resolve(&query).await
        });
    }
    start.wait().await;
    upstream.entered.notified().await;
    let flights = forwarder.singleflight();
    while flights.counters().waiters < u64::try_from(CALLERS - 1).expect("count") {
        tokio::task::yield_now().await;
    }

    upstream.release.notify_one();
    let mut txids = Vec::with_capacity(CALLERS);
    while let Some(joined) = tasks.join_next().await {
        let response = joined.expect("task").expect("resolve");
        txids.push(u16::from_be_bytes([response[0], response[1]]));
    }

    txids.sort_unstable();
    assert_eq!(
        txids,
        (1..=u16::try_from(CALLERS).expect("count")).collect::<Vec<_>>()
    );
    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 1);
    assert_eq!(flights.active_len(), 0);
}

#[tokio::test]
async fn newly_constructed_forwarder_does_not_join_predecessor_flight() {
    for (cache_enabled, fixed_ttl) in [(false, None), (true, Some(0))] {
        let fixed_ttl = fixed_ttl
            .map(|ttl| std::collections::HashMap::from([("example.com".to_string(), ttl)]))
            .unwrap_or_default();
        let router = Arc::new(
            DnsRouter::new_with_fixed_ttl(
                &DnsRouting {
                    fallback: "default".into(),
                    ..Default::default()
                },
                &fixed_ttl,
            )
            .unwrap(),
        );
        let old_upstream = Arc::new(GatedUpstream {
            response: make_a_response([192, 0, 2, 1], 300),
            call_count: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let cache = test_cache();
        let old = Arc::new(
            DnsForwarder::new(old_upstream.clone(), cache.clone(), Arc::clone(&router))
                .with_cache_enabled(cache_enabled),
        );
        let old_query = make_a_query();
        let predecessor = tokio::spawn(async move { old.resolve(&old_query).await });
        old_upstream.entered.notified().await;

        let new_upstream = Arc::new(MockUpstream::new(make_a_response([198, 51, 100, 2], 300)));
        let new = DnsForwarder::new(new_upstream.clone(), cache.clone(), router)
            .with_cache_enabled(cache_enabled);
        let response = tokio::time::timeout(Duration::from_secs(1), new.resolve(&make_a_query()))
            .await
            .expect("new generation must not await predecessor flight")
            .expect("new generation resolve");

        assert_eq!(&response[response.len() - 4..], &[198, 51, 100, 2]);
        assert_eq!(new_upstream.call_count.load(Ordering::SeqCst), 1);
        assert!(cache.lock().await.is_empty());

        old_upstream.release.notify_one();
        let response = predecessor.await.expect("predecessor task").expect("predecessor resolve");
        assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 1]);
    }
}

#[tokio::test]
async fn failed_exchange_is_shared_without_serial_waiter_retries() {
    struct FailingUpstream {
        release: tokio::sync::Semaphore,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl DnsUpstreamPool for FailingUpstream {
        async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.release.acquire().await?.forget();
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into())
        }
    }
    let upstream = Arc::new(FailingUpstream {
        release: tokio::sync::Semaphore::new(0),
        calls: AtomicUsize::new(0),
    });
    let forwarder = Arc::new(DnsForwarder::new(
        upstream.clone(),
        test_cache(),
        test_router(),
    ));
    let flights = forwarder.singleflight();
    let mut queries = tokio::task::JoinSet::new();
    for _ in 0..257 {
        let forwarder = Arc::clone(&forwarder);
        queries.spawn(async move { forwarder.resolve(&make_a_query()).await });
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while flights.counters().waiters != 256 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all followers join the failed exchange");
    upstream.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(query) = queries.join_next().await {
            let error = query.unwrap().expect_err("upstream timeout");
            assert!(error.chain().any(|cause| cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)));
        }
    })
    .await
    .expect("one failed exchange must settle every waiter");
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert_eq!(flights.active_len(), 0);
    assert!(forwarder.cache().lock().await.is_empty());

    upstream.release.add_permits(1);
    assert!(forwarder.resolve(&make_a_query()).await.is_err());
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2, "failures are not cached");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_leader_wakes_all_waiters_to_one_successor_operation() {
    const CALLERS: usize = 128;
    struct CancelUpstream {
        response: Vec<u8>,
        calls: AtomicUsize,
        first_entered: tokio::sync::Notify,
        successor_entered: tokio::sync::Notify,
        release_successor: tokio::sync::Notify,
    }
    #[async_trait]
    impl DnsUpstreamPool for CancelUpstream {
        async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                self.first_entered.notify_one();
                std::future::pending::<()>().await;
            }
            self.successor_entered.notify_one();
            self.release_successor.notified().await;
            Ok(self.response.clone())
        }
    }

    let upstream = Arc::new(CancelUpstream {
        response: make_a_response([192, 0, 2, 9], 300),
        calls: AtomicUsize::new(0),
        first_entered: tokio::sync::Notify::new(),
        successor_entered: tokio::sync::Notify::new(),
        release_successor: tokio::sync::Notify::new(),
    });
    let forwarder = Arc::new(DnsForwarder::new(
        upstream.clone(),
        test_cache(),
        test_router(),
    ));
    let flights = forwarder.singleflight();
    let mut leader_query = make_a_query();
    leader_query[0..2].copy_from_slice(&1_u16.to_be_bytes());
    let leader = {
        let forwarder = Arc::clone(&forwarder);
        tokio::spawn(async move { forwarder.resolve(&leader_query).await })
    };
    upstream.first_entered.notified().await;

    let start = Arc::new(tokio::sync::Barrier::new(CALLERS));
    let mut survivors = tokio::task::JoinSet::new();
    for txid in 2..=CALLERS {
        let forwarder = Arc::clone(&forwarder);
        let start = Arc::clone(&start);
        survivors.spawn(async move {
            let mut query = make_a_query();
            query[0..2].copy_from_slice(
                &u16::try_from(txid)
                    .expect("caller count fits u16")
                    .to_be_bytes(),
            );
            start.wait().await;
            forwarder.resolve(&query).await
        });
    }
    start.wait().await;
    while flights.counters().waiters < u64::try_from(CALLERS - 1).expect("count") {
        tokio::task::yield_now().await;
    }

    leader.abort();
    assert!(leader.await.expect_err("cancelled").is_cancelled());
    upstream.successor_entered.notified().await;
    while flights.counters().waiters
        < u64::try_from((CALLERS - 1) + (CALLERS - 2)).expect("count")
    {
        tokio::task::yield_now().await;
    }
    upstream.release_successor.notify_one();

    let mut completed = 0;
    while let Some(joined) = survivors.join_next().await {
        joined.expect("task").expect("resolve");
        completed += 1;
    }
    let counters = flights.counters();
    assert_eq!(completed, CALLERS - 1);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    assert_eq!(counters.leaders, 2);
    assert_eq!(counters.aborts, 1);
    assert_eq!(counters.retries, u64::try_from(CALLERS - 1).expect("count"));
    assert_eq!(flights.active_len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_preflight_miss_does_not_open_a_second_exchange_after_cache_publish() {
    // Given
    const CALLERS: usize = 128;
    let upstream = Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 1], 300)));
    let forwarder = Arc::new(DnsForwarder::new(
        upstream.clone(),
        test_cache(),
        test_router(),
    ));
    let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
    let mut tasks = tokio::task::JoinSet::new();
    for txid in 1..=CALLERS {
        let forwarder = Arc::clone(&forwarder);
        let start = Arc::clone(&start);
        tasks.spawn(async move {
            let mut query = make_a_query();
            query[0..2].copy_from_slice(
                &u16::try_from(txid)
                    .expect("caller count fits u16")
                    .to_be_bytes(),
            );
            start.wait().await;
            forwarder.resolve(&query).await
        });
    }
    start.wait().await;

    // When
    while let Some(joined) = tasks.join_next().await {
        joined.expect("task").expect("resolve");
    }

    // Then
    assert_eq!(
        upstream.call_count.load(Ordering::SeqCst),
        1,
        "a caller delayed after its cache miss opened a second exchange"
    );
}

struct PreferenceSourceUpstream {
    primary_calls: AtomicUsize,
    primary_entered: tokio::sync::Semaphore,
    primary_release: tokio::sync::Semaphore,
}

#[async_trait]
impl DnsUpstreamPool for PreferenceSourceUpstream {
    async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (_, qtype) = parse_dns_question(raw_query).expect("question");
        if qtype == 1 {
            self.primary_calls.fetch_add(1, Ordering::SeqCst);
            self.primary_entered.add_permits(1);
            self.primary_release.acquire().await?.forget();
            return Ok(make_a_response([192, 0, 2, 1], 300));
        }
        Ok(if upstream_name == "preferred" {
            make_aaaa_response([0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 300)
        } else {
            nodata_response("example.com", 28)
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_reusable_preference_sensitive_sources_do_not_share_a_flight() {
    use std::collections::HashMap;

    use honk_config::dns::{
        DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule, DnsStrategy,
    };

    let routing = DnsRouting {
        request: DnsRequestRouting {
            rules: vec![
                DnsRequestRule {
                    conditions: vec![DnsCond::Qtype {
                        not: false,
                        types: vec![1],
                    }],
                    action: DnsRequestAction::Upstream("shared".into()),
                },
                DnsRequestRule {
                    conditions: vec![
                        DnsCond::Sip {
                            not: false,
                            cidrs: vec!["192.0.2.0/24".into()],
                        },
                        DnsCond::Qtype {
                            not: false,
                            types: vec![28],
                        },
                    ],
                    action: DnsRequestAction::Upstream("preferred".into()),
                },
            ],
            fallback: DnsRequestAction::Upstream("default".into()),
        },
        ..Default::default()
    };

    for (cache_enabled, fixed_ttl) in [(false, None), (true, Some(0))] {
        let fixed_ttl = fixed_ttl
            .map(|ttl| HashMap::from([("example.com".to_string(), ttl)]))
            .unwrap_or_default();
        let upstream = Arc::new(PreferenceSourceUpstream {
            primary_calls: AtomicUsize::new(0),
            primary_entered: tokio::sync::Semaphore::new(0),
            primary_release: tokio::sync::Semaphore::new(0),
        });
        let router = Arc::new(
            DnsRouter::new_with_fixed_ttl(&routing, &fixed_ttl).expect("source router"),
        );
        let forwarder = Arc::new(
            DnsForwarder::new(upstream.clone(), test_cache(), router)
                .with_cache_enabled(cache_enabled)
                .with_strategy(DnsStrategy::PreferIpv6),
        );

        let mut tasks = tokio::task::JoinSet::new();
        for source in ["192.0.2.10", "198.51.100.10"] {
            let forwarder = Arc::clone(&forwarder);
            tasks.spawn(async move {
                forwarder
                    .resolve_outcome_with_context(
                        &make_a_query(),
                        DnsRequestMeta::new(Some(source.parse().expect("source")), None),
                    )
                    .await
                    .expect("resolve")
                    .into_rendered()
            });
        }

        tokio::time::timeout(
            Duration::from_secs(5),
            upstream.primary_entered.acquire_many(2),
        )
        .await
        .expect("preference-sensitive sources shared one exchange")
        .expect("entry semaphore")
        .forget();
        upstream.primary_release.add_permits(2);

        let mut answer_counts = Vec::new();
        while let Some(result) = tasks.join_next().await {
            answer_counts.push(answer_count(&result.expect("task")));
        }
        answer_counts.sort_unstable();
        assert_eq!(answer_counts, [0, 1]);
        assert_eq!(upstream.primary_calls.load(Ordering::SeqCst), 2);
    }

    for (cache_enabled, fixed_ttl) in [(false, None), (true, Some(0))] {
        let fixed_ttl = fixed_ttl
            .map(|ttl| HashMap::from([("example.com".to_string(), ttl)]))
            .unwrap_or_default();
        let upstream = Arc::new(GatedUpstream {
            response: make_a_response([192, 0, 2, 1], 300),
            call_count: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let cache = test_cache();
        let router = Arc::new(
            DnsRouter::new_with_fixed_ttl(
                &DnsRouting {
                    rules: Vec::new(),
                    fallback: "default".into(),
                    ..Default::default()
                },
                &fixed_ttl,
            )
            .expect("source-neutral router"),
        );
        let forwarder = Arc::new(
            DnsForwarder::new(upstream.clone(), cache.clone(), router)
                .with_cache_enabled(cache_enabled),
        );
        let flights = forwarder.singleflight();
        let mut tasks = tokio::task::JoinSet::new();
        for source in ["192.0.2.10", "198.51.100.10"] {
            let forwarder = Arc::clone(&forwarder);
            tasks.spawn(async move {
                forwarder
                    .resolve_outcome_with_context(
                        &make_a_query(),
                        DnsRequestMeta::new(Some(source.parse().expect("source")), None),
                    )
                    .await
                    .expect("resolve")
            });
        }
        upstream.entered.notified().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while flights.counters().waiters == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("source-neutral query did not join the shared exchange");
        upstream.release.notify_one();
        while let Some(result) = tasks.join_next().await {
            result.expect("task");
        }
        assert_eq!(upstream.call_count.load(Ordering::SeqCst), 1);
    }
}
