use super::{DnsEngine, EngineError, effective_expiry};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use honk_config::dns::{
    DnsCond, DnsConfig, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
    DnsResponseRule, DnsRouting,
};
use tokio::sync::{Barrier, Mutex, mpsc};

use crate::dns::cache::{CacheKey, DnsCache, OperationKind};
use crate::dns::forwarder::{DnsForwardError, DnsForwarder, DnsUpstreamPool, build_dns_query};
use crate::dns::outcome::{OutcomeStatus, Provenance, ResponseClass};
use crate::dns::planner::{PlanError, RequestPlan};
use crate::dns::query::{DnsRequestMeta, IngressProfile};
use crate::dns::routing::DnsRouter;
#[tokio::test]
async fn real_forwarding_paths_classify_each_response() {
    let query = build_dns_query("example.com", 1);
    let positive = response(&query, [192, 0, 2, 1], 30);
    let nodata = nodata_response(&query);
    let mut nxdomain = nodata.clone();
    nxdomain[3] = 0x83;
    let mut servfail = nodata.clone();
    servfail[3] = 0x82;

    for (wire, class) in [
        (positive, ResponseClass::Positive),
        (nodata, ResponseClass::Nodata),
        (nxdomain, ResponseClass::Nxdomain),
        (servfail, ResponseClass::Servfail),
    ] {
        let forwarder = DnsForwarder::new(
            exchange([("first", Ok(wire))], None),
            Arc::new(Mutex::new(DnsCache::new(8))),
            router("first", Vec::new(), None),
        );
        let outcome = forwarder.resolve_outcome(&query).await.expect("outcome");
        assert_eq!(outcome.response_class(), class);
    }
}

#[test]
fn fixed_zero_disables_cache_instead_of_clamping_to_one() {
    // Given / When
    let expiry = effective_expiry(Some(0), 600, 30);

    // Then
    assert!(!expiry.is_cacheable());
}

#[test]
fn configured_ttl_overrides_zero_upstream_ttl() {
    let expiry = effective_expiry(None, 600, 0);
    assert!(expiry.is_cacheable());
    assert_eq!(expiry.ttl(), std::time::Duration::from_secs(600));
}
struct SequenceExchange {
    replies: StdMutex<HashMap<String, VecDeque<anyhow::Result<Vec<u8>>>>>,
    cache_probe: Option<Arc<Mutex<DnsCache>>>,
    calls: AtomicUsize,
}
#[async_trait]
impl DnsUpstreamPool for SequenceExchange {
    async fn query(&self, upstream: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(cache) = &self.cache_probe {
            assert!(
                cache.try_lock().is_ok(),
                "cache guard held at exchange await"
            );
        }
        self.replies
            .lock()
            .expect("reply lock")
            .get_mut(upstream)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| anyhow::bail!("missing reply for {upstream}"))
    }
}

fn response(query: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[0..2].copy_from_slice(&[0, 0]);
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[6..8].copy_from_slice(&1_u16.to_be_bytes());
    wire.extend_from_slice(&[
        0xc0,
        0x0c,
        0,
        1,
        0,
        1,
        ttl.to_be_bytes()[0],
        ttl.to_be_bytes()[1],
        ttl.to_be_bytes()[2],
        ttl.to_be_bytes()[3],
        0,
        4,
        ip[0],
        ip[1],
        ip[2],
        ip[3],
    ]);
    wire
}

fn router(
    initial: &str,
    response_rules: Vec<DnsResponseRule>,
    fixed_ttl: Option<u32>,
) -> Arc<DnsRouter> {
    let routing = DnsRouting {
        request: DnsRequestRouting {
            rules: Vec::new(),
            fallback: DnsRequestAction::Upstream(initial.to_owned()),
        },
        response: DnsResponseRouting {
            rules: response_rules,
            fallback: DnsResponseAction::Accept,
        },
        ..Default::default()
    };
    let fixed = fixed_ttl
        .map(|ttl| HashMap::from([("example.com".to_owned(), ttl)]))
        .unwrap_or_default();
    Arc::new(DnsRouter::new_with_fixed_ttl(&routing, &fixed).expect("router"))
}

fn exchange(
    replies: impl IntoIterator<Item = (&'static str, anyhow::Result<Vec<u8>>)>,
    cache_probe: Option<Arc<Mutex<DnsCache>>>,
) -> Arc<SequenceExchange> {
    let mut by_upstream: HashMap<String, VecDeque<anyhow::Result<Vec<u8>>>> = HashMap::new();
    for (upstream, reply) in replies {
        by_upstream
            .entry(upstream.to_owned())
            .or_default()
            .push_back(reply);
    }
    Arc::new(SequenceExchange {
        replies: StdMutex::new(by_upstream),
        cache_probe,
        calls: AtomicUsize::new(0),
    })
}

fn edns_query(version: u8, option: Option<(u16, &[u8])>) -> Vec<u8> {
    let mut query = build_dns_query("example.com", 1);
    query[10..12].copy_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0, 0, 41, 4, 208, 0, version, 0, 0]);
    let option_len = option
        .map(|(_, data)| 4_usize.saturating_add(data.len()))
        .unwrap_or_default();
    query.extend_from_slice(&(option_len as u16).to_be_bytes());
    if let Some((code, data)) = option {
        query.extend_from_slice(&code.to_be_bytes());
        query.extend_from_slice(&(data.len() as u16).to_be_bytes());
        query.extend_from_slice(data);
    }
    query
}

fn ineligible_queries() -> Vec<(&'static str, Vec<u8>)> {
    let mut non_query = build_dns_query("example.com", 1);
    non_query[2] = 0x09;
    let mut unsupported_flags = build_dns_query("example.com", 1);
    unsupported_flags[2..4].copy_from_slice(&0x0140_u16.to_be_bytes());
    vec![
        ("non-QUERY", non_query),
        ("unsupported-flags", unsupported_flags),
        ("EDNSv1", edns_query(1, None)),
        ("ECS", edns_query(0, Some((8, &[0, 1, 2, 3])))),
        ("COOKIE", edns_query(0, Some((10, &[1, 2, 3, 4])))),
        ("unknown-EDNS", edns_query(0, Some((65, &[])))),
    ]
}

fn nodata_response(query: &[u8]) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[0..2].copy_from_slice(&[0, 0]);
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire
}

fn ineligible_response(query: &[u8]) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[0..2].copy_from_slice(&[0, 0]);
    wire[2] |= 0x80;
    wire[3] |= 0x80;
    wire
}

struct OverlapExchange {
    entered: mpsc::UnboundedSender<()>,
    release: Arc<Barrier>,
}

#[async_trait]
impl DnsUpstreamPool for OverlapExchange {
    async fn query(&self, _: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.entered.send(()).expect("test receiver remains open");
        self.release.wait().await;
        let mut response = query.to_vec();
        response[0..2].copy_from_slice(&[0, 0]);
        response[2] |= 0x80;
        response[3] |= 0x80;
        Ok(response)
    }
}
#[tokio::test]
async fn typed_outcome_tracks_positive_requery_and_caller_rendering() {
    // Given
    let mut query = build_dns_query("ExAmPlE.COM", 1);
    query[0..2].copy_from_slice(&0x1234_u16.to_be_bytes());
    let first = response(&query, [10, 0, 0, 1], 30);
    let second = response(&query, [8, 8, 8, 8], 30);
    let rules = vec![DnsResponseRule {
        conditions: vec![DnsCond::Ip {
            not: false,
            cidrs: vec!["10.0.0.0/8".to_owned()],
            geoip: Vec::new(),
        }],
        action: DnsResponseAction::Upstream("second".to_owned()),
    }];
    let cache = Arc::new(Mutex::new(DnsCache::new(8)));
    let forwarder = DnsForwarder::new(
        exchange(
            [("first", Ok(first)), ("second", Ok(second))],
            Some(cache.clone()),
        ),
        cache,
        router("first", rules, None),
    );

    // When
    let outcome = forwarder.resolve_outcome(&query).await.expect("outcome");
    let cached = forwarder
        .resolve_outcome(&query)
        .await
        .expect("cached outcome");

    // Then
    assert_eq!(outcome.status(), OutcomeStatus::Accepted);
    assert_eq!(outcome.response_class(), ResponseClass::Positive);
    assert_eq!(outcome.provenance(), Provenance::Upstream);
    assert_eq!(outcome.logical_upstream(), Some("first"));
    assert_eq!(outcome.final_upstream(), Some("second"));
    assert_eq!(outcome.requery_history(), &["first", "second"]);
    assert_eq!(outcome.domain(), "example.com");
    assert_eq!(
        outcome.answer_ips(),
        &["8.8.8.8".parse::<std::net::IpAddr>().expect("IP")]
    );
    assert_eq!(cached.provenance(), Provenance::Cache);
    assert_eq!(cached.domain(), "example.com");
    assert_eq!(cached.answer_ips(), outcome.answer_ips());
    assert_eq!(&outcome.rendered()[0..2], &0x1234_u16.to_be_bytes());
    assert_eq!(
        &outcome.rendered()[outcome.rendered().len() - 4..],
        &[8, 8, 8, 8]
    );
}

#[tokio::test]
async fn typed_outcome_metadata_excludes_udp_truncated_answers() {
    let query = build_dns_query("example.com", 1);
    let mut full_response = response(&query, [192, 0, 2, 1], 30);
    let second = response(&query, [198, 51, 100, 2], 30);
    full_response[6..8].copy_from_slice(&2_u16.to_be_bytes());
    full_response.extend_from_slice(&second[second.len() - 16..]);
    let forwarder = DnsForwarder::new(
        exchange([("first", Ok(full_response))], None),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", Vec::new(), None),
    );

    let outcome = forwarder
        .resolve_outcome_with_context_and_profile(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Udp {
                advertised_size: 45,
            },
        )
        .await
        .expect("truncated outcome");

    assert_eq!(outcome.domain(), "example.com");
    assert_eq!(outcome.rendered().len(), 45);
    assert_ne!(
        u16::from_be_bytes([outcome.rendered()[2], outcome.rendered()[3]]) & 0x0200,
        0
    );
    assert_eq!(
        outcome.answer_ips(),
        &["192.0.2.1".parse::<std::net::IpAddr>().expect("IP")]
    );
}

#[tokio::test]
async fn typed_outcome_rejects_response_and_skips_exchange_for_request_reject() {
    // Given
    let routing = DnsRouting {
        request: DnsRequestRouting {
            rules: Vec::new(),
            fallback: DnsRequestAction::Reject,
        },
        ..Default::default()
    };
    let forwarder = DnsForwarder::new(
        exchange([], None),
        Arc::new(Mutex::new(DnsCache::new(8))),
        Arc::new(DnsRouter::new(&routing).expect("router")),
    );

    // When
    let outcome = forwarder
        .resolve_outcome(&build_dns_query("example.com", 1))
        .await
        .expect("reject outcome");

    // Then
    assert_eq!(outcome.status(), OutcomeStatus::Rejected);
    assert_eq!(outcome.response_class(), ResponseClass::Nodata);
    assert_eq!(outcome.provenance(), Provenance::Fresh);
}

#[tokio::test]
async fn typed_outcome_reports_malformed_response_and_requery_cycle() {
    // Given
    let query = build_dns_query("example.com", 1);
    let cycle_rules = vec![DnsResponseRule {
        conditions: vec![DnsCond::Upstream {
            not: false,
            names: vec!["first".to_owned()],
        }],
        action: DnsResponseAction::Upstream("first".to_owned()),
    }];
    let malformed = DnsForwarder::new(
        exchange([("first", Ok(vec![0, 1, 2]))], None),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", Vec::new(), None),
    );
    let cyclic = DnsForwarder::new(
        exchange([("first", Ok(response(&query, [1, 1, 1, 1], 30)))], None),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", cycle_rules, None),
    );

    // When
    let malformed_error = malformed
        .resolve_outcome(&query)
        .await
        .expect_err("malformed");
    let cycle_error = cyclic.resolve_outcome(&query).await.expect_err("cycle");

    // Then
    assert!(matches!(
        malformed_error,
        DnsForwardError::Engine(super::EngineError::Response(_))
    ));
    assert!(matches!(
        cycle_error,
        DnsForwardError::Engine(super::EngineError::Plan(PlanError::UpstreamCycle { .. }))
    ));
}

#[tokio::test]
async fn compatibility_only_cycle_response_is_not_reused_by_strict_lookup() {
    let query = build_dns_query("example.com", 1);
    let answer = response(&query, [192, 0, 2, 10], 30);
    let cycle_rules = vec![DnsResponseRule {
        conditions: vec![DnsCond::Upstream {
            not: false,
            names: vec!["first".to_owned()],
        }],
        action: DnsResponseAction::Upstream("first".to_owned()),
    }];
    let upstream = exchange([("first", Ok(answer.clone())), ("first", Ok(answer))], None);
    let forwarder = DnsForwarder::new(
        upstream.clone(),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", cycle_rules, None),
    );

    forwarder
        .resolve(&query)
        .await
        .expect("compatibility accepts the cycle terminal response");
    let strict_error = forwarder
        .resolve_outcome(&query)
        .await
        .expect_err("strict lookup must not consume a compatibility-only cache entry");

    assert!(matches!(
        strict_error,
        DnsForwardError::Engine(super::EngineError::Plan(PlanError::UpstreamCycle { .. }))
    ));
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn typed_outcome_reports_requery_depth_before_fourth_exchange() {
    // Given
    let query = build_dns_query("example.com", 1);
    let rules = [
        ("first", "second"),
        ("second", "third"),
        ("third", "fourth"),
    ]
    .into_iter()
    .map(|(from, to)| DnsResponseRule {
        conditions: vec![DnsCond::Upstream {
            not: false,
            names: vec![from.to_owned()],
        }],
        action: DnsResponseAction::Upstream(to.to_owned()),
    })
    .collect();
    let forwarder = DnsForwarder::new(
        exchange(
            [
                ("first", Ok(response(&query, [1, 1, 1, 1], 30))),
                ("second", Ok(response(&query, [2, 2, 2, 2], 30))),
                ("third", Ok(response(&query, [3, 3, 3, 3], 30))),
            ],
            None,
        ),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", rules, None),
    );

    // When
    let error = forwarder
        .resolve_outcome(&query)
        .await
        .expect_err("depth error");

    // Then
    assert!(matches!(
        error,
        DnsForwardError::Engine(super::EngineError::Plan(PlanError::DepthExceeded {
            max: 3
        }))
    ));
}

#[tokio::test]
async fn stale_outcome_covers_upstream_error_and_servfail_without_sleeping() {
    // Given
    let query = build_dns_query("example.com", 1);
    let cached = response(&query, [9, 9, 9, 9], 30);
    let cache = Arc::new(Mutex::new(DnsCache::new(8)));
    let routing = router("first", Vec::new(), None);
    let engine = super::DnsEngine::from_router(&routing, None).expect("engine");
    let prepared = engine
        .prepare(&query, DnsRequestMeta::EMPTY, IngressProfile::Internal)
        .expect("prepared");
    let RequestPlan::Exchange(scope) = prepared.plan() else {
        panic!("exchange plan");
    };
    let cache_key = CacheKey::new(
        prepared.query(),
        None,
        scope.clone(),
        OperationKind::Resolve,
    );
    cache
        .lock()
        .await
        .service()
        .insert_expired_exact_for_test(cache_key, cached, 30);
    let error_forwarder = DnsForwarder::new(
        exchange([("first", Err(anyhow::anyhow!("offline")))], None),
        cache.clone(),
        routing.clone(),
    );
    let mut servfail = response(&query, [1, 1, 1, 1], 30);
    servfail[3] = 0x82;
    let servfail_forwarder =
        DnsForwarder::new(exchange([("first", Ok(servfail))], None), cache, routing);

    // When
    let on_error = error_forwarder
        .resolve_outcome(&query)
        .await
        .expect("stale");
    let on_servfail = servfail_forwarder
        .resolve_outcome(&query)
        .await
        .expect("stale");

    // Then
    assert_eq!(on_error.provenance(), Provenance::Stale);
    assert_eq!(on_servfail.provenance(), Provenance::Stale);
    assert_eq!(
        on_error.expiry().ttl(),
        std::time::Duration::from_secs(error_forwarder.stale_reply_ttl.into())
    );
    assert_eq!(on_error.expiry(), on_servfail.expiry());
    assert_eq!(
        &on_error.rendered()[on_error.rendered().len() - 4..],
        &[9, 9, 9, 9]
    );
}

#[tokio::test]
async fn packet_rejection_does_not_serve_expired_positive() {
    use honk_outbound::proxy::{PacketRejection, packet_rejection};

    let query = build_dns_query("example.com", 1);
    let cache = Arc::new(Mutex::new(DnsCache::new(8)));
    let routing = router("first", Vec::new(), None);
    let engine = DnsEngine::from_router(&routing, None).expect("engine");
    let prepared = engine
        .prepare(&query, DnsRequestMeta::EMPTY, IngressProfile::Internal)
        .expect("prepared");
    let RequestPlan::Exchange(scope) = prepared.plan() else {
        panic!("exchange plan");
    };
    let cache_key = CacheKey::new(
        prepared.query(),
        None,
        scope.clone(),
        OperationKind::Resolve,
    );
    cache.lock().await.service().insert_expired_exact_for_test(
        cache_key,
        response(&query, [9, 9, 9, 9], 30),
        30,
    );

    for rejection in [PacketRejection::Policy, PacketRejection::Capacity] {
        for strict in [true, false] {
            let source = honk_outbound::SharedError::new(
                anyhow::Error::new(std::io::Error::from(rejection)).context("upstream dial"),
            );
            let forwarder = DnsForwarder::new(
                exchange([("first", Err(source.into()))], None),
                cache.clone(),
                routing.clone(),
            );
            let error = if strict {
                anyhow::Error::from(
                    forwarder
                        .resolve_outcome(&query)
                        .await
                        .expect_err("terminal refusal"),
                )
            } else {
                forwarder
                    .resolve(&query)
                    .await
                    .expect_err("terminal refusal")
            };
            assert_eq!(packet_rejection(&error), Some(rejection));
            assert!(matches!(
                error.downcast_ref::<DnsForwardError>().expect("forward error").unshared(),
                DnsForwardError::Exchange { upstream, .. } if upstream == "first"
            ));
        }
    }
}

#[test]
fn engine_rejects_multiple_questions_before_policy_planning() {
    let mut wire = build_dns_query("allowed.example", 1);
    let second = build_dns_query("blocked.example", 1);
    wire[4..6].copy_from_slice(&2u16.to_be_bytes());
    wire.extend_from_slice(&second[12..]);
    let router = DnsRouter::new(&DnsRouting::default()).expect("router");
    let engine = DnsEngine::from_router(&router, None).expect("engine");

    let result = engine.prepare(&wire, DnsRequestMeta::EMPTY, IngressProfile::Internal);

    assert!(matches!(result, Err(EngineError::MultipleQuestions)));
}
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
    let nxdomain = crate::dns::forwarder::make_nxdomain_response(&query, 30, 20);
    let pool = exchange([("first", Ok(nxdomain))], None);
    let forwarder = DnsForwarder::new(
        pool.clone(),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", Vec::new(), None),
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
    assert_eq!(inserted.expiry().ttl(), std::time::Duration::from_secs(20));
    assert_eq!(hit.provenance(), Provenance::Cache);
    assert!(hit.expiry().is_cacheable());
    assert_eq!(hit.expiry().ttl(), std::time::Duration::from_secs(20));
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
