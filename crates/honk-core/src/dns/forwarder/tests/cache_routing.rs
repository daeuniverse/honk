/// RFC 2308 §5: negative TTL = min(SOA TTL, SOA MINIMUM).
#[test]
fn test_extract_soa_negative_ttl() {
    // NXDOMAIN with authority SOA (ttl=300, minimum=60).
    let mut resp = vec![
        0x00, 0x00, // ID
        0x81, 0x83, // QR + RCODE=NXDOMAIN
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x01, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    for label in ["example", "com"] {
        resp.push(label.len() as u8);
        resp.extend_from_slice(label.as_bytes());
    }
    resp.push(0);
    resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    // Authority SOA: name ptr, type SOA, class IN, ttl 300, rdata
    // root mname/rname + serial/refresh/retry/expire + minimum 60.
    resp.extend_from_slice(&[0xc0, 0x0c]);
    resp.extend_from_slice(&[0x00, 0x06, 0x00, 0x01]);
    resp.extend_from_slice(&300u32.to_be_bytes());
    let mut rdata = vec![0x00, 0x00]; // MNAME, RNAME (root)
    for v in [1u32, 7200, 3600, 1209600, 60] {
        rdata.extend_from_slice(&v.to_be_bytes());
    }
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);

    assert_eq!(extract_soa_negative_ttl(&resp, 60), 60);
    // No authority section → default.
    let plain = make_a_response([1, 1, 1, 1], 300);
    assert_eq!(extract_soa_negative_ttl(&plain, 42), 42);
}

#[tokio::test]
async fn test_cache_hit() {
    let response = make_a_response([93, 184, 216, 34], 300);
    let mock = Arc::new(MockUpstream::new(response.clone()));
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    );

    let query = make_a_query();

    let result1 = forwarder.resolve(&query).await.expect("first resolve");
    assert_eq!(result1, response);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

    let result2 = forwarder.resolve(&query).await.expect("second resolve");
    assert_eq!(result2, response);
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        1,
        "upstream should not be called again"
    );
}

#[tokio::test]
async fn test_cache_hit_rewrites_transaction_id() {
    // Build a response whose ID does not match the query ID.  The forwarder
    // must rewrite the response ID to match each query so that standard
    // resolvers (glibc/c-ares) accept cached answers.
    let mut response = make_a_response([93, 184, 216, 34], 300);
    response[0] = 0xBE;
    response[1] = 0xEF;

    let mock = Arc::new(MockUpstream::new(response.clone()));
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    );

    let mut query = make_a_query();
    query[0] = 0xAB;
    query[1] = 0xCD;

    let result1 = forwarder.resolve(&query).await.expect("first resolve");
    assert_eq!(&result1[0..2], &[0xAB, 0xCD]);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

    let result2 = forwarder.resolve(&query).await.expect("second resolve");
    assert_eq!(&result2[0..2], &[0xAB, 0xCD]);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_forward_basic() {
    let response = make_a_response([8, 8, 8, 8], 600);
    let mock = Arc::new(MockUpstream::new(response.clone()));
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    );

    let result = forwarder.resolve(&make_a_query()).await.expect("resolve");
    assert_eq!(result, response);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_routing_respects_rules() {
    let response_custom = make_a_response([10, 0, 0, 1], 300);
    let response_default = make_a_response([8, 8, 8, 8], 300);

    // Mock that returns different responses based on upstream name
    struct RoutingMock {
        custom_resp: Vec<u8>,
        default_resp: Vec<u8>,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl DnsUpstreamPool for RoutingMock {
        async fn query(&self, upstream_name: &str, _raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match upstream_name {
                "custom" => Ok(self.custom_resp.clone()),
                _ => Ok(self.default_resp.clone()),
            }
        }
    }

    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            rules: vec![DnsRule {
                domain: "full:custom.test".into(),
                upstream: "custom".into(),
            }],
            fallback: "default".into(),
            ..Default::default()
        })
        .expect("router"),
    );

    let mock = Arc::new(RoutingMock {
        custom_resp: response_custom.clone(),
        default_resp: response_default.clone(),
        calls: AtomicUsize::new(0),
    });
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        router,
    );

    let query = build_dns_query("custom.test", 1);
    let result = forwarder.resolve(&query).await.expect("resolve");
    assert_eq!(result, response_custom);

    let query2 = build_dns_query("other.test", 1);
    let result2 = forwarder.resolve(&query2).await.expect("resolve");
    assert_eq!(result2, response_default);
}

struct RoutedScopeUpstream {
    negative: bool,
    calls: std::sync::Mutex<std::collections::HashMap<String, usize>>,
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

impl RoutedScopeUpstream {
    fn calls(&self, upstream: &str) -> usize {
        self.calls
            .lock()
            .expect("calls")
            .get(upstream)
            .copied()
            .unwrap_or_default()
    }
}

#[async_trait]
impl DnsUpstreamPool for RoutedScopeUpstream {
    async fn query(&self, upstream_name: &str, _raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        *self
            .calls
            .lock()
            .expect("calls")
            .entry(upstream_name.to_string())
            .or_default() += 1;
        self.entered.add_permits(1);
        self.release.acquire().await?.forget();
        if self.negative {
            let mut response = nodata_response("example.com", 1);
            response[3] = if upstream_name == "red" { 0x83 } else { 0x82 };
            Ok(response)
        } else {
            Ok(make_a_response(
                if upstream_name == "red" {
                    [192, 0, 2, 1]
                } else {
                    [198, 51, 100, 1]
                },
                300,
            ))
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selected_scopes_partition_overlapping_positive_and_negative_queries() {
    use honk_config::dns::{
        DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule,
    };

    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![
                    DnsRequestRule {
                        conditions: vec![DnsCond::Sip {
                            not: false,
                            cidrs: vec!["192.0.2.0/24".into(), "203.0.113.0/24".into()],
                        }],
                        action: DnsRequestAction::Upstream("red".into()),
                    },
                    DnsRequestRule {
                        conditions: vec![DnsCond::Sip {
                            not: false,
                            cidrs: vec!["198.51.100.0/24".into()],
                        }],
                        action: DnsRequestAction::Upstream("blue".into()),
                    },
                ],
                fallback: DnsRequestAction::Upstream("trap".into()),
            },
            ..Default::default()
        })
        .expect("router"),
    );

    for negative in [false, true] {
        let upstream = Arc::new(RoutedScopeUpstream {
            negative,
            calls: std::sync::Mutex::new(std::collections::HashMap::new()),
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        });
        let cache = test_cache();
        let forwarder = Arc::new(DnsForwarder::new(
            upstream.clone(),
            cache.clone(),
            Arc::clone(&router),
        ));
        let flights = forwarder.singleflight();
        let sources = ["192.0.2.10", "198.51.100.20", "203.0.113.30"];
        let mut tasks = tokio::task::JoinSet::new();
        for source in sources {
            let forwarder = Arc::clone(&forwarder);
            tasks.spawn(async move {
                let response = forwarder
                    .resolve_outcome_with_context(
                        &make_a_query(),
                        DnsRequestMeta::new(Some(source.parse().expect("source")), None),
                    )
                    .await
                    .expect("resolve")
                    .into_rendered();
                (source, response)
            });
        }

        tokio::time::timeout(Duration::from_secs(5), upstream.entered.acquire_many(2))
            .await
            .expect("selected scopes shared one exchange")
            .expect("entry semaphore")
            .forget();
        tokio::time::timeout(Duration::from_secs(5), async {
            while flights.counters().waiters == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("same-scope sources did not share an exchange");
        upstream.release.add_permits(2);

        let assert_response = |source: &str, response: &[u8]| {
            let blue = source == "198.51.100.20";
            if negative {
                assert_eq!(response[3] & 0x0f, if blue { 2 } else { 3 });
            } else {
                assert_eq!(
                    &response[response.len() - 4..],
                    if blue {
                        &[198, 51, 100, 1]
                    } else {
                        &[192, 0, 2, 1]
                    }
                );
            }
        };
        while let Some(result) = tasks.join_next().await {
            let (source, response) = result.expect("task");
            assert_response(source, &response);
        }
        for source in sources {
            let response = forwarder
                .resolve_outcome_with_context(
                    &make_a_query(),
                    DnsRequestMeta::new(Some(source.parse().expect("source")), None),
                )
                .await
                .expect("cached resolve")
                .into_rendered();
            assert_response(source, &response);
        }
        assert_eq!(upstream.calls("red"), 1);
        assert_eq!(upstream.calls("blue"), 1);
        assert_eq!(upstream.calls("trap"), 0);
    }
}
