#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_response_requery_is_one_logical_flight() {
    use honk_config::dns::{
        DnsCond, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
        DnsResponseRule,
    };

    const CALLERS: usize = 128;
    struct RequeryUpstream {
        initial_calls: AtomicUsize,
        fallback_calls: AtomicUsize,
        initial_entered: tokio::sync::Notify,
        initial_release: tokio::sync::Notify,
        polluted: Vec<u8>,
        clean: Vec<u8>,
    }
    #[async_trait]
    impl DnsUpstreamPool for RequeryUpstream {
        async fn query(&self, upstream: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            if upstream == "fallback" {
                self.fallback_calls.fetch_add(1, Ordering::SeqCst);
                let mut response = self.clean.clone();
                response[0..2].copy_from_slice(&raw_query[0..2]);
                return Ok(response);
            }
            self.initial_calls.fetch_add(1, Ordering::SeqCst);
            self.initial_entered.notify_one();
            self.initial_release.notified().await;
            let mut response = self.polluted.clone();
            response[0..2].copy_from_slice(&raw_query[0..2]);
            Ok(response)
        }
    }

    let upstream = Arc::new(RequeryUpstream {
        initial_calls: AtomicUsize::new(0),
        fallback_calls: AtomicUsize::new(0),
        initial_entered: tokio::sync::Notify::new(),
        initial_release: tokio::sync::Notify::new(),
        polluted: make_a_response([10, 0, 0, 1], 60),
        clean: make_a_response([8, 8, 8, 8], 60),
    });
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: Vec::new(),
                fallback: DnsRequestAction::Upstream("initial".into()),
            },
            response: DnsResponseRouting {
                rules: vec![DnsResponseRule {
                    conditions: vec![DnsCond::Ip {
                        not: false,
                        cidrs: vec!["10.0.0.0/8".into()],
                        geoip: Vec::new(),
                    }],
                    action: DnsResponseAction::Upstream("fallback".into()),
                }],
                fallback: DnsResponseAction::Accept,
            },
            ..Default::default()
        })
        .expect("router"),
    );
    let cache = test_cache();
    let flights = cache.lock().await.singleflight();
    let forwarder = Arc::new(DnsForwarder::new(upstream.clone(), cache, router));
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
    upstream.initial_entered.notified().await;
    while flights.counters().waiters < u64::try_from(CALLERS - 1).expect("count") {
        tokio::task::yield_now().await;
    }

    upstream.initial_release.notify_one();
    let mut txids = Vec::with_capacity(CALLERS);
    while let Some(joined) = tasks.join_next().await {
        let response = joined.expect("task").expect("resolve");
        assert_eq!(&response[response.len() - 4..], &[8, 8, 8, 8]);
        txids.push(u16::from_be_bytes([response[0], response[1]]));
    }
    txids.sort_unstable();
    assert_eq!(
        txids,
        (1..=u16::try_from(CALLERS).expect("count")).collect::<Vec<_>>()
    );
    assert_eq!(upstream.initial_calls.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.fallback_calls.load(Ordering::SeqCst), 1);
    assert_eq!(flights.active_len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn response_requery_error_stays_unpublished_and_waiters_retry_once() {
    use honk_config::dns::{
        DnsCond, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
        DnsResponseRule,
    };

    const CALLERS: usize = 128;
    struct RetryUpstream {
        initial_calls: AtomicUsize,
        fallback_calls: AtomicUsize,
        initial_entered: tokio::sync::Notify,
        initial_release: tokio::sync::Notify,
        successor_entered: tokio::sync::Notify,
        successor_release: tokio::sync::Notify,
        polluted: Vec<u8>,
        clean: Vec<u8>,
    }
    #[async_trait]
    impl DnsUpstreamPool for RetryUpstream {
        async fn query(&self, upstream: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            if upstream == "fallback" {
                let call = self.fallback_calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    anyhow::bail!("first fallback failed");
                }
                let mut response = self.clean.clone();
                response[0..2].copy_from_slice(&raw_query[0..2]);
                return Ok(response);
            }
            let call = self.initial_calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                self.initial_entered.notify_one();
                self.initial_release.notified().await;
            } else if call == 1 {
                self.successor_entered.notify_one();
                self.successor_release.notified().await;
            }
            let mut response = self.polluted.clone();
            response[0..2].copy_from_slice(&raw_query[0..2]);
            Ok(response)
        }
    }

    let upstream = Arc::new(RetryUpstream {
        initial_calls: AtomicUsize::new(0),
        fallback_calls: AtomicUsize::new(0),
        initial_entered: tokio::sync::Notify::new(),
        initial_release: tokio::sync::Notify::new(),
        successor_entered: tokio::sync::Notify::new(),
        successor_release: tokio::sync::Notify::new(),
        polluted: make_a_response([10, 0, 0, 1], 60),
        clean: make_a_response([8, 8, 4, 4], 60),
    });
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: Vec::new(),
                fallback: DnsRequestAction::Upstream("initial".into()),
            },
            response: DnsResponseRouting {
                rules: vec![DnsResponseRule {
                    conditions: vec![DnsCond::Ip {
                        not: false,
                        cidrs: vec!["10.0.0.0/8".into()],
                        geoip: Vec::new(),
                    }],
                    action: DnsResponseAction::Upstream("fallback".into()),
                }],
                fallback: DnsResponseAction::Accept,
            },
            ..Default::default()
        })
        .expect("router"),
    );
    let forwarder = Arc::new(DnsForwarder::new(upstream.clone(), test_cache(), router));
    let service = forwarder.cache_service().await;
    let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..CALLERS {
        let forwarder = Arc::clone(&forwarder);
        let start = Arc::clone(&start);
        tasks.spawn(async move {
            start.wait().await;
            forwarder.resolve(&make_a_query()).await
        });
    }
    start.wait().await;
    upstream.initial_entered.notified().await;
    while service.flight_counters().waiters < u64::try_from(CALLERS - 1).expect("count") {
        tokio::task::yield_now().await;
    }
    upstream.initial_release.notify_one();
    upstream.successor_entered.notified().await;
    while service.flight_counters().waiters
        < u64::try_from((CALLERS - 1) + (CALLERS - 2)).expect("count")
    {
        tokio::task::yield_now().await;
    }
    upstream.successor_release.notify_one();

    let mut successes = 0;
    let mut failures = 0;
    while let Some(joined) = tasks.join_next().await {
        match joined.expect("task") {
            Ok(response) => {
                assert_eq!(&response[response.len() - 4..], &[8, 8, 4, 4]);
                successes += 1;
            }
            Err(_) => failures += 1,
        }
    }
    let counters = service.flight_counters();
    assert_eq!((successes, failures), (CALLERS - 1, 1));
    assert_eq!(upstream.initial_calls.load(Ordering::SeqCst), 2);
    assert_eq!(upstream.fallback_calls.load(Ordering::SeqCst), 2);
    assert_eq!(counters.leaders, 2);
    assert_eq!(counters.aborts, 1);
    assert_eq!(counters.retries, u64::try_from(CALLERS - 1).expect("count"));
    assert_eq!(service.active_flights(), 0);
}
