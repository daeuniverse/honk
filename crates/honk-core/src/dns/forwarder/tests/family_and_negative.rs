use super::*;
use crate::dns::outcome::{OutcomeStatus, Provenance, ResponseClass};
/// Mock upstream answering per query qtype.
struct QtypeMock {
    a: Result<Vec<u8>, honk_outbound::SharedError>,
    aaaa: Result<Vec<u8>, honk_outbound::SharedError>,
    call_count: AtomicUsize,
}

#[async_trait]
impl DnsUpstreamPool for QtypeMock {
    async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let (_, qtype) = parse_dns_question(raw_query).expect("question");
        match qtype {
            1 => self.a.clone(),
            28 => self.aaaa.clone(),
            _ => {
                let context =
                    crate::dns::query::QueryContext::parse(raw_query).expect("query context");
                Ok(make_empty_response(raw_query, &context))
            }
        }
        .map_err(anyhow::Error::new)
    }
}

fn qtype_mock(a: Vec<u8>, aaaa: Vec<u8>) -> Arc<QtypeMock> {
    Arc::new(QtypeMock {
        a: Ok(a),
        aaaa: Ok(aaaa),
        call_count: AtomicUsize::new(0),
    })
}

#[tokio::test]
async fn test_only_strategy_filters_at_request_time() {
    let mock = qtype_mock(
        make_a_response([10, 0, 0, 1], 300),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    )
    .with_strategy(DnsStrategy::Ipv4Only);

    let resp = forwarder
        .resolve(&build_dns_query("example.com", 28))
        .await
        .unwrap();
    assert_eq!(answer_count(&resp), 0, "AAAA must be answered NODATA");
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        0,
        "filtered query must never reach upstream"
    );
}

#[tokio::test]
async fn test_prefer_ipv4_suppresses_aaaa_when_a_exists() {
    let mock = qtype_mock(
        make_a_response([10, 0, 0, 1], 300),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    )
    .with_strategy(DnsStrategy::PreferIpv4);

    // Prime the A cache with real answers.
    let a_resp = forwarder.resolve(&make_a_query()).await.unwrap();
    assert!(answer_count(&a_resp) > 0);

    // AAAA is forwarded to upstream but suppressed at response time.
    let aaaa_resp = forwarder
        .resolve(&build_dns_query("example.com", 28))
        .await
        .unwrap();
    assert_eq!(
        answer_count(&aaaa_resp),
        0,
        "AAAA must be suppressed when A answers exist"
    );
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        2,
        "A + AAAA; the prefer check must hit the cache, not upstream"
    );
}

#[tokio::test]
async fn test_prefer_ipv4_returns_aaaa_when_no_a() {
    let mock = qtype_mock(
        nodata_response("example.com", 1, Some((30, 20))),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    )
    .with_strategy(DnsStrategy::PreferIpv4);

    let resp = forwarder
        .resolve(&build_dns_query("example.com", 28))
        .await
        .unwrap();
    assert_eq!(
        answer_count(&resp),
        1,
        "AAAA must be returned when no A answers exist"
    );
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        2,
        "AAAA + sibling A probe"
    );

    // Cache-hit path: AAAA and the sibling's NODATA are both cached.
    let resp2 = forwarder
        .resolve(&build_dns_query("example.com", 28))
        .await
        .unwrap();
    assert_eq!(answer_count(&resp2), 1);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_prefer_ipv4_never_probes_for_a_queries() {
    let mock = qtype_mock(
        make_a_response([10, 0, 0, 1], 300),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    )
    .with_strategy(DnsStrategy::PreferIpv4);

    let resp = forwarder.resolve(&make_a_query()).await.unwrap();
    assert_eq!(answer_count(&resp), 1);
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        1,
        "preferred qtype must not trigger a sibling probe"
    );
}

#[tokio::test]
async fn test_prefer_ipv6_suppresses_a_when_aaaa_exists() {
    let mock = qtype_mock(
        make_a_response([10, 0, 0, 1], 300),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    )
    .with_strategy(DnsStrategy::PreferIpv6);

    // Prime the AAAA cache.
    let aaaa_resp = forwarder
        .resolve(&build_dns_query("example.com", 28))
        .await
        .unwrap();
    assert!(answer_count(&aaaa_resp) > 0);

    let a_resp = forwarder.resolve(&make_a_query()).await.unwrap();
    assert_eq!(
        answer_count(&a_resp),
        0,
        "A must be suppressed when AAAA answers exist"
    );
}

#[tokio::test]
async fn preferred_family_packet_rejection_is_terminal_but_offline_falls_back() {
    use honk_outbound::proxy::{PacketRejection, packet_rejection};

    for (strategy, qtype, answer, expected_ip) in [
        (
            DnsStrategy::PreferIpv4,
            28,
            make_aaaa_response(TEST_V6, 300),
            IpAddr::from(TEST_V6),
        ),
        (
            DnsStrategy::PreferIpv6,
            1,
            make_a_response([10, 0, 0, 1], 300),
            IpAddr::from([10, 0, 0, 1]),
        ),
    ] {
        for strict in [true, false] {
            for rejection in [Some(PacketRejection::Capacity), None] {
                let source = match rejection {
                    Some(rejection) => std::io::Error::from(rejection),
                    None => std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
                };
                let failure = honk_outbound::SharedError::new(
                    DnsForwardError::Shared(Arc::new(DnsForwardError::Exchange {
                        upstream: "preferred".into(),
                        source: anyhow::Error::new(source).context("upstream dial"),
                    }))
                    .into(),
                );
                let (a, aaaa) = if qtype == 28 {
                    (Err(failure), Ok(answer.clone()))
                } else {
                    (Ok(answer.clone()), Err(failure))
                };
                let forwarder = DnsForwarder::new(
                    Arc::new(QtypeMock {
                        a,
                        aaaa,
                        call_count: AtomicUsize::new(0),
                    }),
                    test_cache(),
                    test_router(),
                )
                .with_strategy(strategy);
                let query = build_dns_query("example.com", qtype);
                let result = if strict {
                    forwarder
                        .resolve_outcome(&query)
                        .await
                        .map(|outcome| outcome.into_rendered())
                        .map_err(anyhow::Error::from)
                } else {
                    forwarder.resolve(&query).await
                };
                if let Some(rejection) = rejection {
                    let error = result.expect_err("terminal preferred-family refusal");
                    assert_eq!(packet_rejection(&error), Some(rejection));
                    assert!(error.chain().any(|cause| matches!(
                        cause.downcast_ref::<DnsForwardError>().map(DnsForwardError::unshared),
                        Some(DnsForwardError::Exchange { upstream, .. }) if upstream == "preferred"
                    )));
                } else {
                    assert_eq!(
                        extract_answer_ips(&result.expect("ordinary failure keeps other family")),
                        vec![expected_ip]
                    );
                }
            }
        }
    }
}

/// A cached NXDOMAIN must be answered as NXDOMAIN (rcode 3), never
/// upgraded to SERVFAIL — the two have opposite client semantics.
#[tokio::test]
async fn test_negative_cache_returns_nxdomain_not_servfail() {
    let query = make_a_query();
    let nx = make_nxdomain_response(&query, 30, 20);
    let mock = Arc::new(MockUpstream::new(nx));
    let cache = test_cache();
    let forwarder = DnsForwarder::new(mock.clone(), cache, test_router());

    let resp = forwarder.resolve(&query).await.expect("first nxdomain");
    assert_eq!(resp[3] & 0x0f, 3);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

    let resp2 = forwarder.resolve(&query).await.expect("cached nxdomain");
    assert_eq!(resp2[3] & 0x0f, 3, "cached negative must stay NXDOMAIN");
    assert_eq!(resp2[0..2], query[0..2], "txid must match the query");
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        1,
        "negative hit must not re-query upstream"
    );
}

#[tokio::test]
async fn nxdomain_with_fixed_zero_ttl_is_not_cached() {
    let query = make_a_query();
    let response = make_nxdomain_response(&query, 30, 20);
    let mock = Arc::new(MockUpstream::new(response));
    let fixed_ttl = std::collections::HashMap::from([("example.com".to_owned(), 0)]);
    let router = Arc::new(
        DnsRouter::new_with_fixed_ttl(&DnsRouting::default(), &fixed_ttl).expect("router"),
    );
    let forwarder = DnsForwarder::new(mock.clone(), test_cache(), router).with_cache_ttl(600);

    for _ in 0..2 {
        let outcome = forwarder.resolve_outcome(&query).await.unwrap();
        assert!(!outcome.expiry().is_cacheable());
    }
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn nxdomain_without_soa_or_zero_soa_ttl_is_not_cached() {
    let query = make_a_query();
    for response in [
        make_nxdomain_without_soa_response(&query),
        make_nxdomain_response(&query, 0, 20),
    ] {
        let mock = Arc::new(MockUpstream::new(response));
        let forwarder =
            DnsForwarder::new(mock.clone(), test_cache(), test_router()).with_cache_ttl(600);

        for _ in 0..2 {
            let outcome = forwarder.resolve_outcome(&query).await.unwrap();
            assert!(!outcome.expiry().is_cacheable());
        }
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn cache_disabled_nxdomain_preserves_shared_positive() {
    let query = make_a_query();
    let cache = test_cache();
    let positive = Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 1], 600)));
    let negative = Arc::new(MockUpstream::new(make_nxdomain_without_soa_response(
        &query,
    )));
    let cached = DnsForwarder::new(positive.clone(), cache.clone(), test_router());
    let uncached = DnsForwarder::new(negative, cache, test_router()).with_cache_enabled(false);

    let initial = cached.resolve_outcome(&query).await.unwrap();
    let outcome = uncached.resolve_outcome(&query).await.unwrap();
    assert_eq!(outcome.response_class(), ResponseClass::Nxdomain);
    let retained = cached.resolve_outcome(&query).await.unwrap();
    assert_eq!(retained.provenance(), Provenance::Cache);
    assert_eq!(retained.answer_ips(), initial.answer_ips());
    assert_eq!(positive.call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cache_disabled_zero_ttl_positive_preserves_shared_positive() {
    let query = make_a_query();
    let cache = test_cache();
    let positive = Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 1], 600)));
    let replacement = Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 2], 0)));
    let cached = DnsForwarder::new(positive.clone(), cache.clone(), test_router());
    let uncached = DnsForwarder::new(replacement, cache, test_router()).with_cache_enabled(false);

    let initial = cached.resolve_outcome(&query).await.expect("initial");
    let outcome = uncached
        .resolve_outcome(&query)
        .await
        .expect("zero-TTL positive");
    assert!(!outcome.expiry().is_cacheable());
    let retained = cached
        .resolve_outcome(&query)
        .await
        .expect("retained positive");
    assert_eq!(retained.provenance(), Provenance::Cache);
    assert_eq!(retained.answer_ips(), initial.answer_ips());
    assert_eq!(positive.call_count.load(Ordering::SeqCst), 1);
}

/// A cached SERVFAIL stays SERVFAIL (rcode 2) on later hits.
#[tokio::test]
async fn test_negative_cache_keeps_servfail_rcode() {
    let mut sf = make_a_response([93, 184, 216, 34], 1);
    sf[3] = 0x82; // QR + RA + SERVFAIL
    let mock = Arc::new(MockUpstream::new(sf));
    let cache = test_cache();
    let forwarder = DnsForwarder::new(mock.clone(), cache, test_router());
    let query = make_a_query();

    let _ = forwarder.resolve(&query).await;
    // Second hit: still rcode 2, no extra upstream call.
    let resp2 = forwarder.resolve(&query).await.expect("cached servfail");
    assert_eq!(resp2[3] & 0x0f, 2);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cached_negative_keeps_source_aware_preferred_family_projection() {
    use honk_config::dns::{DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule};

    struct NegativePreferenceUpstream {
        rcode: u8,
        calls: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DnsUpstreamPool for NegativePreferenceUpstream {
        async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("calls")
                .push(upstream_name.to_string());
            Ok(match upstream_name {
                "negative" => {
                    let mut response = if self.rcode == 3 {
                        make_nxdomain_response(raw_query, 30, 20)
                    } else {
                        nodata_response("example.com", 28, None)
                    };
                    response[3] = 0x80 | self.rcode;
                    response
                }
                "has-a" => make_a_response([192, 0, 2, 1], 300),
                "no-a" => nodata_response("example.com", 1, Some((30, 20))),
                _ => panic!("unexpected upstream {upstream_name}"),
            })
        }
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
                        action: DnsRequestAction::Upstream("negative".into()),
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
    let query = build_dns_query("example.com", 28);

    for rcode in [2, 3] {
        let upstream = Arc::new(NegativePreferenceUpstream {
            rcode,
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), Arc::clone(&router))
            .with_strategy(DnsStrategy::PreferIpv4);
        for _ in 0..2 {
            for (source, expected_rcode) in [("192.0.2.10", 0), ("198.51.100.10", rcode)] {
                let response = forwarder
                    .resolve_outcome_with_context(
                        &query,
                        DnsRequestMeta::new(Some(source.parse().expect("source")), None),
                    )
                    .await
                    .expect("negative response")
                    .into_rendered();
                assert_eq!(response[3] & 0x0f, expected_rcode);
                assert_eq!(answer_count(&response), 0);
            }
        }
        let mut calls = upstream.calls.lock().expect("calls").clone();
        calls.sort();
        assert_eq!(calls, ["has-a", "negative", "no-a"]);
    }
}

#[tokio::test]
async fn strict_preferred_family_asis_without_destination_does_not_fall_back() {
    use honk_config::dns::{DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule};

    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![DnsRequestRule {
                    conditions: vec![DnsCond::Qtype {
                        not: false,
                        types: vec![1],
                    }],
                    action: DnsRequestAction::AsIs,
                }],
                fallback: DnsRequestAction::Upstream("default".into()),
            },
            ..Default::default()
        })
        .expect("router"),
    );
    let mock = qtype_mock(
        make_a_response([10, 0, 0, 1], 300),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(mock.clone(), test_cache(), router)
        .with_strategy(DnsStrategy::PreferIpv4);

    let response = forwarder
        .resolve_outcome_with_context(
            &build_dns_query("example.com", 28),
            DnsRequestMeta::new(Some("192.0.2.10".parse().expect("source")), None),
        )
        .await
        .expect("strict response")
        .into_rendered();

    assert_eq!(answer_count(&response), 1);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn preferred_family_sibling_keeps_client_source_routing() {
    use honk_config::dns::{DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule};

    struct PreferenceUpstream {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl DnsUpstreamPool for PreferenceUpstream {
        async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(match upstream_name {
                "aaaa" => make_aaaa_response(TEST_V6, 300),
                "has-a" => make_a_response([192, 0, 2, 1], 300),
                "no-a" => {
                    let query = crate::dns::query::QueryContext::parse(raw_query).expect("query");
                    make_empty_response(raw_query, &query)
                }
                _ => panic!("unexpected upstream {upstream_name}"),
            })
        }
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
    let upstream = Arc::new(PreferenceUpstream {
        calls: AtomicUsize::new(0),
    });
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), router)
        .with_strategy(DnsStrategy::PreferIpv4);
    let query = build_dns_query("example.com", 28);

    let inside = forwarder
        .resolve_outcome_with_context(
            &query,
            DnsRequestMeta::new(Some("192.0.2.10".parse().expect("source")), None),
        )
        .await
        .expect("inside response")
        .into_rendered();
    let outside = forwarder
        .resolve_outcome_with_context(
            &query,
            DnsRequestMeta::new(Some("198.51.100.10".parse().expect("source")), None),
        )
        .await
        .expect("outside response")
        .into_rendered();

    assert_eq!(answer_count(&inside), 0);
    assert_eq!(answer_count(&outside), 1);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn nodata_soa_lifetime_uses_minimum_and_cap_not_optimistic_ttl() {
    let query = make_a_query();
    for (ttl, minimum, expected) in [(30, 20, 20), (600, 600, 300)] {
        let response = nodata_response("example.com", 1, Some((ttl, minimum)));
        let upstream = Arc::new(MockUpstream::new(response));
        let forwarder =
            DnsForwarder::new(upstream.clone(), test_cache(), test_router()).with_cache_ttl(600);
        let first = forwarder.resolve_outcome(&query).await.unwrap();
        assert_eq!(first.expiry().ttl(), Duration::from_secs(expected));
        let cached = forwarder.resolve_outcome(&query).await.unwrap();
        assert_eq!(cached.provenance(), Provenance::Cache);
        assert_eq!(upstream.call_count.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn nodata_without_soa_or_zero_soa_ttl_is_not_cached() {
    let query = make_a_query();
    for soa in [None, Some((0, 20))] {
        let upstream = Arc::new(MockUpstream::new(nodata_response("example.com", 1, soa)));
        let forwarder =
            DnsForwarder::new(upstream.clone(), test_cache(), test_router()).with_cache_ttl(600);
        for _ in 0..2 {
            let outcome = forwarder.resolve_outcome(&query).await.unwrap();
            assert!(!outcome.expiry().is_cacheable());
        }
        assert_eq!(upstream.call_count.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn nodata_fixed_ttl_overrides_missing_soa_and_negative_cap() {
    let query = make_a_query();
    let upstream = Arc::new(MockUpstream::new(nodata_response("example.com", 1, None)));
    let fixed_ttl = std::collections::HashMap::from([("example.com".to_owned(), 3600)]);
    let router = Arc::new(
        DnsRouter::new_with_fixed_ttl(&DnsRouting::default(), &fixed_ttl).expect("router"),
    );
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), router).with_cache_ttl(600);
    let first = forwarder.resolve_outcome(&query).await.unwrap();
    assert_eq!(first.expiry().ttl(), Duration::from_secs(3600));
    let cached = forwarder.resolve_outcome(&query).await.unwrap();
    assert_eq!(cached.provenance(), Provenance::Cache);
    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn nodata_response_policy_reject_caches_synthetic_for_rejected_soa_lifetime() {
    use honk_config::dns::{DnsResponseAction, DnsResponseRouting};

    let query = make_a_query();
    let routing = DnsRouting {
        response: DnsResponseRouting {
            rules: Vec::new(),
            fallback: DnsResponseAction::Reject,
        },
        ..Default::default()
    };
    let upstream = Arc::new(MockUpstream::new(nodata_response(
        "example.com",
        1,
        Some((30, 20)),
    )));
    let forwarder = DnsForwarder::new(
        upstream.clone(),
        test_cache(),
        Arc::new(DnsRouter::new(&routing).expect("router")),
    )
    .with_cache_ttl(600);
    let first = forwarder.resolve_outcome(&query).await.unwrap();
    assert_eq!(first.status(), OutcomeStatus::Rejected);
    assert_eq!(first.expiry().ttl(), Duration::from_secs(20));
    assert_eq!(first.reusable().len(), query.len());
    assert_eq!(first.reusable()[3] & 0x0f, 0);
    let cached = forwarder.resolve_outcome(&query).await.unwrap();
    assert_eq!(cached.provenance(), Provenance::Cache);
    assert_eq!(cached.reusable(), first.reusable());
    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 1);

    let positive = Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 1], 30)));
    let positive_router = Arc::new(DnsRouter::new(&routing).unwrap());
    let positive_forwarder =
        DnsForwarder::new(positive.clone(), test_cache(), positive_router).with_cache_ttl(600);
    let rejected = positive_forwarder.resolve_outcome(&query).await.unwrap();
    assert_eq!(rejected.status(), OutcomeStatus::Rejected);
    assert_eq!(rejected.expiry().ttl(), Duration::from_secs(600));
    let cached = positive_forwarder.resolve_outcome(&query).await.unwrap();
    assert_eq!(cached.provenance(), Provenance::Cache);
    assert_eq!(cached.reusable(), rejected.reusable());
    assert_eq!(positive.call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn empty_refused_response_keeps_optimistic_cache_lifetime() {
    let query = make_a_query();
    let mut response = query.clone();
    response[2] = 0x81;
    response[3] = 0x85;
    let upstream = Arc::new(MockUpstream::new(response));
    let forwarder =
        DnsForwarder::new(upstream.clone(), test_cache(), test_router()).with_cache_ttl(600);
    let first = forwarder.resolve_outcome(&query).await.unwrap();
    assert_eq!(first.expiry().ttl(), Duration::from_secs(600));
    assert_eq!(first.rendered()[3] & 0x0f, 5);
    let cached = forwarder.resolve_outcome(&query).await.unwrap();
    assert_eq!(cached.provenance(), Provenance::Cache);
    assert_eq!(cached.rendered()[3] & 0x0f, 5);
    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn zero_ttl_answer_is_not_cached_when_upstream_ttls_are_kept() {
    let query = make_a_query();
    let upstream = Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 1], 0)));
    let forwarder =
        DnsForwarder::new(upstream.clone(), test_cache(), test_router()).with_cache_ttl(0);
    let first = forwarder
        .resolve_outcome(&query)
        .await
        .expect("first answer");
    let second = forwarder
        .resolve_outcome(&query)
        .await
        .expect("second answer");
    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 2);
    assert!(!first.expiry().is_cacheable());
    assert!(!second.expiry().is_cacheable());
    assert_eq!(second.provenance(), Provenance::Upstream);
}

#[tokio::test]
async fn refused_zero_ttl_answer_keeps_legacy_cache_lifetime() {
    let query = make_a_query();
    let mut refused = make_a_response([192, 0, 2, 1], 0);
    refused[3] = 0x85;
    let upstream = Arc::new(MockUpstream::new(refused));
    let forwarder =
        DnsForwarder::new(upstream.clone(), test_cache(), test_router()).with_cache_ttl(0);

    let first = forwarder.resolve_outcome(&query).await.expect("first");
    assert_eq!(first.rendered()[3] & 0x0f, 5);
    assert_eq!(first.expiry().ttl(), Duration::from_secs(60));
    let second = forwarder.resolve_outcome(&query).await.expect("cached");
    assert_eq!(second.rendered()[3] & 0x0f, 5);
    assert_eq!(second.provenance(), Provenance::Cache);
    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn zero_ttl_root_null_additional_record_prevents_whole_wire_reuse() {
    let query = make_a_query();
    let mut response = make_a_response([192, 0, 2, 1], 300);
    response[10..12].copy_from_slice(&1_u16.to_be_bytes());
    // A root owner and empty NULL RDATA make this a valid 11-byte RR.
    response.extend_from_slice(&[0, 0, 10, 0, 1, 0, 0, 0, 0, 0, 0]);
    let upstream = Arc::new(MockUpstream::new(response.clone()));
    let forwarder =
        DnsForwarder::new(upstream.clone(), test_cache(), test_router()).with_cache_ttl(0);

    let first = forwarder
        .resolve_outcome(&query)
        .await
        .expect("first answer");
    let second = forwarder
        .resolve_outcome(&query)
        .await
        .expect("second answer");
    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 2);
    assert_eq!(first.rendered(), response);
    assert_eq!(second.rendered(), response);
    assert!(!first.expiry().is_cacheable());
    assert!(!second.expiry().is_cacheable());
}

#[tokio::test]
async fn rejected_failure_responses_keep_failure_cache_lifetimes() {
    use honk_config::dns::{DnsResponseAction, DnsResponseRouting};

    let query = make_a_query();
    let routing = DnsRouting {
        response: DnsResponseRouting {
            rules: Vec::new(),
            fallback: DnsResponseAction::Reject,
        },
        ..Default::default()
    };
    for (mut response, configured_ttl, expected_ttl) in [
        (nodata_response("example.com", 1, None), 600, 600),
        (make_a_response([192, 0, 2, 1], 0), 0, 60),
    ] {
        response[3] = 0x85;
        let upstream = Arc::new(MockUpstream::new(response));
        let forwarder = DnsForwarder::new(
            upstream.clone(),
            test_cache(),
            Arc::new(DnsRouter::new(&routing).expect("router")),
        )
        .with_cache_ttl(configured_ttl);

        let first = forwarder
            .resolve_outcome(&query)
            .await
            .expect("rejected failure");
        assert_eq!(first.status(), OutcomeStatus::Rejected);
        assert_eq!(first.expiry().ttl(), Duration::from_secs(expected_ttl));
        assert_eq!(first.rendered()[3] & 0x0f, 0);
        assert_eq!(answer_count(first.rendered()), 0);

        let cached = forwarder
            .resolve_outcome(&query)
            .await
            .expect("cached rejection");
        assert_eq!(cached.provenance(), Provenance::Cache);
        assert_eq!(cached.reusable(), first.reusable());
        assert_eq!(upstream.call_count.load(Ordering::SeqCst), 1);
    }
}
