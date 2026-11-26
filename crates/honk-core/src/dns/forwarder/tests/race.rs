use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use honk_config::dns::{
    DnsCond, DnsConfig, DnsRequestAction, DnsResponseAction, DnsResponseRule, DnsUpstream,
    DnsUpstreamGroup,
};
use honk_config::group::{Group, GroupPolicy};
use honk_config::node::{Node, OutboundConfig};
use honk_config::types::{DnsProtocol, NodeProtocol};
use honk_outbound::group::{GroupManager, SelectionNetwork};
use honk_outbound::proxy::{PacketRejection, is_packet_rejection, packet_rejection};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Barrier, Notify};

use super::*;
use crate::dns::cache::{CacheKey, OperationKind};
use crate::dns::endpoint::DnsEndpoint;
use crate::dns::outcome::{Provenance, ResponseClass};
use crate::dns::planner::{RequestScope, UpstreamTag};
use crate::dns::transport::{
    DialContext, DnsSocketBudget, DoqClient, insecure_quic_config, quic_server_endpoint,
    read_length_prefixed, write_length_prefixed,
};
use crate::dns::upstream_pool::UpstreamPool;

enum LegBehavior {
    Immediate(Vec<u8>),
    Delayed {
        delay: Duration,
        wire: Vec<u8>,
    },
    Hold {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        cancelled: Arc<AtomicUsize>,
        wire: Vec<u8>,
    },
    Error(fn() -> anyhow::Error),
}

struct MockRacePool {
    legs: HashMap<String, LegBehavior>,
    calls: HashMap<String, Arc<AtomicUsize>>,
}

impl MockRacePool {
    fn new(entries: impl IntoIterator<Item = (&'static str, LegBehavior)>) -> Self {
        let mut legs = HashMap::new();
        let mut calls = HashMap::new();
        for (name, behavior) in entries {
            legs.insert(name.to_owned(), behavior);
            calls.insert(name.to_owned(), Arc::new(AtomicUsize::new(0)));
        }
        Self { legs, calls }
    }

    fn call_count(&self, name: &str) -> usize {
        self.calls[name].load(Ordering::SeqCst)
    }
}

struct CancelOnDrop {
    finished: AtomicBool,
    cancelled: Arc<AtomicUsize>,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.finished.load(Ordering::SeqCst) {
            self.cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[async_trait]
impl DnsUpstreamPool for MockRacePool {
    async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let Some(behavior) = self.legs.get(upstream_name) else {
            anyhow::bail!("unknown mock upstream: {upstream_name}");
        };
        self.calls[upstream_name].fetch_add(1, Ordering::SeqCst);
        let patch = |mut wire: Vec<u8>| {
            if wire.len() >= 2 && raw_query.len() >= 2 {
                wire[..2].copy_from_slice(&raw_query[..2]);
            }
            wire
        };
        match behavior {
            LegBehavior::Immediate(wire) => Ok(patch(wire.clone())),
            LegBehavior::Delayed { delay, wire } => {
                tokio::time::sleep(*delay).await;
                Ok(patch(wire.clone()))
            }
            LegBehavior::Hold {
                entered,
                release,
                cancelled,
                wire,
            } => {
                let guard = CancelOnDrop {
                    finished: AtomicBool::new(false),
                    cancelled: Arc::clone(cancelled),
                };
                entered.notify_waiters();
                release.notified().await;
                guard.finished.store(true, Ordering::SeqCst);
                Ok(patch(wire.clone()))
            }
            LegBehavior::Error(make_err) => Err(make_err()),
        }
    }
}

fn servfail_wire(query: &[u8]) -> Vec<u8> {
    error_rcode_wire(query, 2)
}

fn error_rcode_wire(query: &[u8], rcode: u8) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[2] = 0x81;
    wire[3] = 0x80 | (rcode & 0x0f);
    wire
}

fn badvers_wire(query: &[u8]) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[10..12].copy_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0x01, 0x00, 0x00, 0x00, 0, 0]);
    wire
}

fn truncated_wire(query: &[u8]) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[2] = 0x83;
    wire[3] = 0x80;
    wire
}

fn truncated_refused_wire(query: &[u8]) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[2] = 0x83;
    wire[3] = 0x85;
    wire
}

fn dummy_upstream(name: &str) -> DnsUpstream {
    DnsUpstream {
        name: name.into(),
        address: "192.0.2.53:53".into(),
        protocol: DnsProtocol::Udp,
        tls_server_name: None,
        outbound: None,
    }
}

fn build_forwarder(config: &DnsConfig, pool: Arc<dyn DnsUpstreamPool>) -> DnsForwarder {
    let router = Arc::new(DnsRouter::new_from_dns_config(config).expect("dns router"));
    DnsForwarder::new(pool, test_cache(), router)
        .with_cache_ttl(config.cache.ttl as u32)
        .with_stale_reply_ttl(config.cache.stale_reply_ttl)
        .with_policy_from_config(config)
        .expect("policy from config")
}

#[tokio::test]
async fn race_returns_fastest_leg_and_cancels_slower_legs() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let cancelled = Arc::new(AtomicUsize::new(0));
    let pool = Arc::new(MockRacePool::new([
        (
            "slow",
            LegBehavior::Hold {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                cancelled: Arc::clone(&cancelled),
                wire: make_a_response([198, 51, 100, 1], 120),
            },
        ),
        (
            "quick",
            LegBehavior::Delayed {
                delay: Duration::from_millis(10),
                wire: make_a_response([198, 51, 100, 2], 120),
            },
        ),
    ]));

    let mut config = DnsConfig {
        upstream: vec![dummy_upstream("slow"), dummy_upstream("quick")],
        upstream_groups: vec![DnsUpstreamGroup {
            name: "fast".into(),
            upstreams: vec!["slow".into(), "quick".into()],
        }],
        ..Default::default()
    };
    config.routing.request.fallback = DnsRequestAction::Upstream("fast".into());

    let forwarder = build_forwarder(&config, Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>);
    let query = make_a_query();
    let outcome = tokio::time::timeout(
        Duration::from_millis(500),
        forwarder.resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        ),
    )
    .await
    .expect("race must not wait for slow leg")
    .expect("race succeeds");

    assert_eq!(outcome.answer_ips(), [IpAddr::from([198, 51, 100, 2])]);
    assert_eq!(outcome.logical_upstream(), Some("fast"));
    assert_eq!(outcome.final_upstream(), Some("quick"));
    assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(pool.call_count("slow"), 1);
    assert_eq!(pool.call_count("quick"), 1);

    let cached = forwarder
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("cached race answer");
    assert_eq!(cached.provenance(), Provenance::Cache);
    assert_eq!(cached.answer_ips(), [IpAddr::from([198, 51, 100, 2])]);
    assert_eq!(pool.call_count("quick"), 1);
}

#[tokio::test(start_paused = true)]
async fn race_survives_early_error_servfail_invalid_and_truncated_legs() {
    let query = make_a_query();
    let udp_ingress = IngressProfile::Udp {
        advertised_size: 512,
    };
    let pool = Arc::new(MockRacePool::new([
        (
            "err_leg",
            LegBehavior::Error(|| anyhow::anyhow!("socket reset")),
        ),
        (
            "servfail_leg",
            LegBehavior::Immediate(servfail_wire(&query)),
        ),
        ("invalid_leg", LegBehavior::Immediate(vec![0xde, 0xad])),
        (
            "truncated_leg",
            LegBehavior::Immediate(truncated_wire(&query)),
        ),
        (
            "clean_slow",
            LegBehavior::Delayed {
                delay: Duration::from_millis(40),
                wire: make_a_response([203, 0, 113, 9], 5),
            },
        ),
    ]));

    let mut config = DnsConfig {
        upstream: vec![
            dummy_upstream("err_leg"),
            dummy_upstream("servfail_leg"),
            dummy_upstream("invalid_leg"),
            dummy_upstream("truncated_leg"),
            dummy_upstream("clean_slow"),
        ],
        upstream_groups: vec![
            DnsUpstreamGroup {
                name: "all_five".into(),
                upstreams: vec![
                    "err_leg".into(),
                    "servfail_leg".into(),
                    "invalid_leg".into(),
                    "truncated_leg".into(),
                    "clean_slow".into(),
                ],
            },
            DnsUpstreamGroup {
                name: "trunc_only".into(),
                upstreams: vec![
                    "err_leg".into(),
                    "servfail_leg".into(),
                    "truncated_leg".into(),
                ],
            },
            DnsUpstreamGroup {
                name: "servfail_only".into(),
                upstreams: vec!["err_leg".into(), "servfail_leg".into()],
            },
        ],
        ..Default::default()
    };
    config.cache.ttl = 5;
    config.routing.request.fallback = DnsRequestAction::Upstream("all_five".into());

    let forwarder = build_forwarder(&config, Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>);
    let clean = forwarder
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            udp_ingress,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("clean_slow must win despite earlier error/servfail/invalid/TC=1");
    assert_eq!(clean.answer_ips(), [IpAddr::from([203, 0, 113, 9])]);
    assert_eq!(clean.final_upstream(), Some("clean_slow"));

    let trunc_opts = ResolveOptions {
        cache: CacheAccess::Normal,
        forced_upstream: Some(UpstreamTag::new("trunc_only").unwrap()),
        ..Default::default()
    };
    let trunc = forwarder
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            udp_ingress,
            &trunc_opts,
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("TC=1 leg is retained when no non-truncated leg succeeds");
    assert_ne!(trunc.rendered()[2] & 0x02, 0);
    assert_eq!(trunc.final_upstream(), Some("truncated_leg"));

    let sf_opts = ResolveOptions {
        cache: CacheAccess::Normal,
        forced_upstream: Some(UpstreamTag::new("servfail_only").unwrap()),
        ..Default::default()
    };
    let sf = forwarder
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &sf_opts,
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("SERVFAIL leg returned when no better leg succeeds");
    assert_eq!(sf.response_class(), ResponseClass::Servfail);
    assert_eq!(sf.final_upstream(), Some("servfail_leg"));

    let seed_pool = Arc::new(MockRacePool::new([
        (
            "a",
            LegBehavior::Immediate(make_a_response([198, 51, 100, 88], 1)),
        ),
        ("b", LegBehavior::Error(|| anyhow::anyhow!("down"))),
    ]));
    let mut stale_cfg = DnsConfig {
        upstream: vec![dummy_upstream("a"), dummy_upstream("b")],
        upstream_groups: vec![DnsUpstreamGroup {
            name: "stale_grp".into(),
            upstreams: vec!["a".into(), "b".into()],
        }],
        ..Default::default()
    };
    stale_cfg.cache.ttl = 1;
    stale_cfg.routing.request.fallback = DnsRequestAction::Upstream("stale_grp".into());
    let shared_cache = test_cache();
    let router = Arc::new(DnsRouter::new_from_dns_config(&stale_cfg).unwrap());
    let seed_fwd = DnsForwarder::new(seed_pool, Arc::clone(&shared_cache), Arc::clone(&router))
        .with_cache_ttl(1)
        .with_policy_from_config(&stale_cfg)
        .unwrap();
    seed_fwd
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .unwrap();
    let stale_key = CacheKey::new(
        &crate::dns::query::QueryContext::parse_with_profile(&query, IngressProfile::Internal)
            .unwrap(),
        seed_fwd.policy_id(),
        RequestScope::Upstream(UpstreamTag::new("stale_grp").unwrap()),
        OperationKind::Resolve,
    );
    seed_fwd
        .cache_service()
        .await
        .expire_positive_exact_for_test(&stale_key);

    let outage_pool = Arc::new(MockRacePool::new([
        ("a", LegBehavior::Error(|| anyhow::anyhow!("timeout"))),
        ("b", LegBehavior::Immediate(servfail_wire(&query))),
    ]));
    let outage_fwd = DnsForwarder::new(outage_pool, shared_cache, router)
        .with_cache_ttl(1)
        .with_policy_from_config(&stale_cfg)
        .unwrap();
    let stale = outage_fwd
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("expired positive entry must serve stale on race outage");
    assert_eq!(stale.provenance(), Provenance::Stale);
    assert_eq!(stale.answer_ips(), [IpAddr::from([198, 51, 100, 88])]);
}

#[tokio::test(start_paused = true)]
async fn race_rejects_fast_refused_notimp_formerr_and_badvers_when_valid_leg_succeeds() {
    let query = make_a_query();
    let udp_ingress = IngressProfile::Udp {
        advertised_size: 512,
    };
    let pool = Arc::new(MockRacePool::new([
        (
            "formerr_leg",
            LegBehavior::Immediate(error_rcode_wire(&query, 1)),
        ),
        (
            "notimp_leg",
            LegBehavior::Immediate(error_rcode_wire(&query, 4)),
        ),
        (
            "refused_leg",
            LegBehavior::Immediate(error_rcode_wire(&query, 5)),
        ),
        ("badvers_leg", LegBehavior::Immediate(badvers_wire(&query))),
        (
            "trunc_refused_leg",
            LegBehavior::Immediate(truncated_refused_wire(&query)),
        ),
        (
            "servfail_leg",
            LegBehavior::Immediate(servfail_wire(&query)),
        ),
        (
            "err_leg",
            LegBehavior::Error(|| anyhow::anyhow!("connection reset")),
        ),
        (
            "trunc_noerror_slow",
            LegBehavior::Delayed {
                delay: Duration::from_millis(20),
                wire: truncated_wire(&query),
            },
        ),
        (
            "nxdomain_slow",
            LegBehavior::Delayed {
                delay: Duration::from_millis(40),
                wire: error_rcode_wire(&query, 3),
            },
        ),
        (
            "valid_slow",
            LegBehavior::Delayed {
                delay: Duration::from_millis(40),
                wire: make_a_response([203, 0, 113, 42], 60),
            },
        ),
    ]));

    let mut config = DnsConfig {
        upstream: vec![
            dummy_upstream("formerr_leg"),
            dummy_upstream("notimp_leg"),
            dummy_upstream("refused_leg"),
            dummy_upstream("badvers_leg"),
            dummy_upstream("trunc_refused_leg"),
            dummy_upstream("servfail_leg"),
            dummy_upstream("err_leg"),
            dummy_upstream("trunc_noerror_slow"),
            dummy_upstream("nxdomain_slow"),
            dummy_upstream("valid_slow"),
        ],
        upstream_groups: vec![
            DnsUpstreamGroup {
                name: "errors_vs_noerror".into(),
                upstreams: vec![
                    "formerr_leg".into(),
                    "notimp_leg".into(),
                    "refused_leg".into(),
                    "badvers_leg".into(),
                    "trunc_refused_leg".into(),
                    "valid_slow".into(),
                ],
            },
            DnsUpstreamGroup {
                name: "badvers_vs_nxdomain".into(),
                upstreams: vec![
                    "badvers_leg".into(),
                    "refused_leg".into(),
                    "nxdomain_slow".into(),
                ],
            },
            DnsUpstreamGroup {
                name: "trunc_noerror_vs_trunc_refused".into(),
                upstreams: vec!["trunc_refused_leg".into(), "trunc_noerror_slow".into()],
            },
            DnsUpstreamGroup {
                name: "servfail_vs_refused".into(),
                upstreams: vec!["refused_leg".into(), "servfail_leg".into()],
            },
            DnsUpstreamGroup {
                name: "refused_only".into(),
                upstreams: vec!["err_leg".into(), "refused_leg".into()],
            },
        ],
        ..Default::default()
    };
    config.cache.ttl = 60;
    config.routing.request.fallback = DnsRequestAction::Upstream("errors_vs_noerror".into());

    let forwarder = build_forwarder(&config, Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>);
    let won = forwarder
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            udp_ingress,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("slower NOERROR leg must beat fast FORMERR/NOTIMP/REFUSED/BADVERS legs");
    assert_eq!(won.answer_ips(), [IpAddr::from([203, 0, 113, 42])]);
    assert_eq!(won.final_upstream(), Some("valid_slow"));

    let cached = forwarder
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            udp_ingress,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("positive cache must hold valid_slow answer rather than REFUSED/BADVERS");
    assert_eq!(cached.provenance(), Provenance::Cache);
    assert_eq!(cached.answer_ips(), [IpAddr::from([203, 0, 113, 42])]);

    let nxd = forwarder
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions {
                cache: CacheAccess::Normal,
                forced_upstream: Some(UpstreamTag::new("badvers_vs_nxdomain").unwrap()),
                ..Default::default()
            },
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("slower NXDOMAIN leg must beat fast extended EDNS BADVERS and REFUSED legs");
    assert_eq!(nxd.response_class(), ResponseClass::Nxdomain);
    assert_eq!(nxd.final_upstream(), Some("nxdomain_slow"));

    let trunc_won = forwarder
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            udp_ingress,
            &ResolveOptions {
                cache: CacheAccess::Normal,
                forced_upstream: Some(UpstreamTag::new("trunc_noerror_vs_trunc_refused").unwrap()),
                ..Default::default()
            },
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("TC=1 NOERROR must beat TC=1 REFUSED");
    assert_eq!(trunc_won.final_upstream(), Some("trunc_noerror_slow"));
    assert_eq!(trunc_won.rendered()[3] & 0x0f, 0);

    let sf_won = forwarder
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions {
                cache: CacheAccess::Normal,
                forced_upstream: Some(UpstreamTag::new("servfail_vs_refused").unwrap()),
                ..Default::default()
            },
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("SERVFAIL fallback must take precedence over REFUSED");
    assert_eq!(sf_won.response_class(), ResponseClass::Servfail);
    assert_eq!(sf_won.final_upstream(), Some("servfail_leg"));

    let ref_only = forwarder
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions {
                cache: CacheAccess::Bypass,
                forced_upstream: Some(UpstreamTag::new("refused_only").unwrap()),
                ..Default::default()
            },
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("REFUSED leg is returned as fallback when no better leg succeeds");
    assert_eq!(ref_only.final_upstream(), Some("refused_leg"));
    assert_eq!(ref_only.rendered()[3] & 0x0f, 5);

    let seed_pool = Arc::new(MockRacePool::new([
        (
            "a",
            LegBehavior::Immediate(make_a_response([198, 51, 100, 99], 1)),
        ),
        ("b", LegBehavior::Error(|| anyhow::anyhow!("down"))),
    ]));
    let mut stale_cfg = DnsConfig {
        upstream: vec![dummy_upstream("a"), dummy_upstream("b")],
        upstream_groups: vec![DnsUpstreamGroup {
            name: "stale_refused_sf".into(),
            upstreams: vec!["a".into(), "b".into()],
        }],
        ..Default::default()
    };
    stale_cfg.cache.ttl = 1;
    stale_cfg.routing.request.fallback = DnsRequestAction::Upstream("stale_refused_sf".into());
    let shared_cache = test_cache();
    let router = Arc::new(DnsRouter::new_from_dns_config(&stale_cfg).unwrap());
    let seed_fwd = DnsForwarder::new(seed_pool, Arc::clone(&shared_cache), Arc::clone(&router))
        .with_cache_ttl(1)
        .with_policy_from_config(&stale_cfg)
        .unwrap();
    seed_fwd
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .unwrap();
    let stale_key = CacheKey::new(
        &crate::dns::query::QueryContext::parse_with_profile(&query, IngressProfile::Internal)
            .unwrap(),
        seed_fwd.policy_id(),
        RequestScope::Upstream(UpstreamTag::new("stale_refused_sf").unwrap()),
        OperationKind::Resolve,
    );
    seed_fwd
        .cache_service()
        .await
        .expire_positive_exact_for_test(&stale_key);

    let outage_pool = Arc::new(MockRacePool::new([
        ("a", LegBehavior::Immediate(error_rcode_wire(&query, 5))),
        ("b", LegBehavior::Immediate(servfail_wire(&query))),
    ]));
    let outage_fwd = DnsForwarder::new(outage_pool, shared_cache, router)
        .with_cache_ttl(1)
        .with_policy_from_config(&stale_cfg)
        .unwrap();
    let stale = outage_fwd
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("expired positive entry must serve stale when legs return REFUSED + SERVFAIL");
    assert_eq!(stale.provenance(), Provenance::Stale);
    assert_eq!(stale.answer_ips(), [IpAddr::from([198, 51, 100, 99])]);
}

#[tokio::test]
async fn race_all_fail_propagates_error_and_preserves_packet_rejection() {
    let query = make_a_query();
    let shared_cache = test_cache();
    let mut config = DnsConfig {
        upstream: vec![dummy_upstream("cap_err"), dummy_upstream("io_err")],
        upstream_groups: vec![DnsUpstreamGroup {
            name: "both_fail".into(),
            upstreams: vec!["cap_err".into(), "io_err".into()],
        }],
        ..Default::default()
    };
    config.cache.ttl = 1;
    config.routing.request.fallback = DnsRequestAction::Upstream("both_fail".into());
    let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());

    let seed_pool = Arc::new(MockRacePool::new([
        (
            "io_err",
            LegBehavior::Immediate(make_a_response([192, 0, 2, 44], 1)),
        ),
        ("cap_err", LegBehavior::Error(|| anyhow::anyhow!("unused"))),
    ]));
    let seed_fwd = DnsForwarder::new(seed_pool, Arc::clone(&shared_cache), Arc::clone(&router))
        .with_cache_ttl(1)
        .with_policy_from_config(&config)
        .unwrap();
    seed_fwd
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .unwrap();
    let key = CacheKey::new(
        &crate::dns::query::QueryContext::parse_with_profile(&query, IngressProfile::Internal)
            .unwrap(),
        seed_fwd.policy_id(),
        RequestScope::Upstream(UpstreamTag::new("both_fail").unwrap()),
        OperationKind::Resolve,
    );
    seed_fwd
        .cache_service()
        .await
        .expire_positive_exact_for_test(&key);

    let rejection_pool = Arc::new(MockRacePool::new([
        (
            "io_err",
            LegBehavior::Error(|| anyhow::anyhow!("network unreachable")),
        ),
        (
            "cap_err",
            LegBehavior::Error(|| {
                anyhow::Error::new(PacketRejection::Capacity).context("socket budget exhausted")
            }),
        ),
    ]));
    let rejection_fwd = DnsForwarder::new(rejection_pool, shared_cache, router)
        .with_cache_ttl(1)
        .with_policy_from_config(&config)
        .unwrap();
    let err = rejection_fwd
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .expect_err("all-fail race with PacketRejection must fail without serving stale");
    let anyhow_err = anyhow::Error::from(err);
    assert!(is_packet_rejection(&anyhow_err), "{anyhow_err:#}");
    assert_eq!(
        packet_rejection(&anyhow_err),
        Some(PacketRejection::Capacity)
    );
}

#[tokio::test]
async fn race_response_routing_matches_winner_and_group_and_prevents_cycles() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let cancelled = Arc::new(AtomicUsize::new(0));
    let pool = Arc::new(MockRacePool::new([
        (
            "alidns",
            LegBehavior::Hold {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                cancelled: Arc::clone(&cancelled),
                wire: make_a_response([10, 0, 0, 2], 60),
            },
        ),
        (
            "dnspod",
            LegBehavior::Immediate(make_a_response([10, 0, 0, 1], 60)),
        ),
        (
            "googledns",
            LegBehavior::Immediate(make_a_response([198, 51, 100, 77], 60)),
        ),
    ]));

    let mut config = DnsConfig {
        upstream: vec![
            dummy_upstream("alidns"),
            dummy_upstream("dnspod"),
            dummy_upstream("googledns"),
        ],
        upstream_groups: vec![
            DnsUpstreamGroup {
                name: "domestic".into(),
                upstreams: vec!["alidns".into(), "dnspod".into()],
            },
            DnsUpstreamGroup {
                name: "overseas".into(),
                upstreams: vec!["dnspod".into(), "googledns".into()],
            },
        ],
        ..Default::default()
    };
    config.routing.request.fallback = DnsRequestAction::Upstream("domestic".into());
    config.routing.response.rules = vec![
        DnsResponseRule {
            conditions: vec![DnsCond::Upstream {
                not: true,
                names: vec!["domestic".into(), "overseas".into()],
            }],
            action: DnsResponseAction::Reject,
        },
        DnsResponseRule {
            conditions: vec![
                DnsCond::Upstream {
                    not: false,
                    names: vec!["domestic".into()],
                },
                DnsCond::Ip {
                    not: false,
                    cidrs: vec!["10.0.0.0/8".into()],
                    geoip: vec![],
                },
            ],
            action: DnsResponseAction::Upstream("overseas".into()),
        },
    ];
    config.routing.response.fallback = DnsResponseAction::Accept;

    let forwarder = build_forwarder(&config, Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>);
    let outcome = forwarder
        .resolve_inner(
            &make_a_query(),
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("response requery to overlapping race group succeeds");
    assert_eq!(outcome.answer_ips(), [IpAddr::from([198, 51, 100, 77])]);
    assert_eq!(outcome.logical_upstream(), Some("domestic"));
    assert_eq!(outcome.final_upstream(), Some("googledns"));
    assert_eq!(outcome.requery_history(), ["dnspod", "googledns"]);
    assert_eq!(
        pool.call_count("dnspod"),
        1,
        "already-visited dnspod must not be queried a second time during overseas race"
    );
    assert_eq!(pool.call_count("googledns"), 1);

    let mut self_cycle_cfg = config.clone();
    self_cycle_cfg.routing.response.rules = vec![DnsResponseRule {
        conditions: vec![DnsCond::Upstream {
            not: false,
            names: vec!["dnspod".into()],
        }],
        action: DnsResponseAction::Upstream("domestic".into()),
    }];
    let self_cycle_fwd = build_forwarder(
        &self_cycle_cfg,
        Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>,
    );
    let cycle_err = tokio::time::timeout(
        Duration::from_millis(200),
        self_cycle_fwd.resolve_inner(
            &make_a_query(),
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        ),
    )
    .await
    .expect("self-group cycle check must fail immediately without re-querying")
    .expect_err("self-group requery cycle must fail in strict mode");
    assert!(
        cycle_err.to_string().contains("cycle"),
        "expected cycle error, got: {cycle_err}"
    );

    let mut responder_cycle_cfg = config.clone();
    responder_cycle_cfg
        .routing
        .response
        .rules
        .push(DnsResponseRule {
            conditions: vec![DnsCond::Ip {
                not: false,
                cidrs: vec!["198.51.100.77/32".into()],
                geoip: vec![],
            }],
            action: DnsResponseAction::Upstream("googledns".into()),
        });
    let responder_cycle_fwd = build_forwarder(
        &responder_cycle_cfg,
        Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>,
    );
    let responder_cycle_err = responder_cycle_fwd
        .resolve_inner(
            &make_a_query(),
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .expect_err("requerying the winning physical responder of a race must fail with cycle");
    assert!(
        responder_cycle_err.to_string().contains("cycle"),
        "expected cycle error, got: {responder_cycle_err}"
    );

    let all_visited_pool = Arc::new(MockRacePool::new([
        (
            "a",
            LegBehavior::Immediate(make_a_response([10, 0, 0, 1], 60)),
        ),
        (
            "b",
            LegBehavior::Immediate(make_a_response([10, 0, 0, 2], 60)),
        ),
    ]));
    let mut exhausted_cfg = DnsConfig {
        upstream: vec![dummy_upstream("a"), dummy_upstream("b")],
        upstream_groups: vec![DnsUpstreamGroup {
            name: "ab".into(),
            upstreams: vec!["a".into(), "b".into()],
        }],
        ..Default::default()
    };
    exhausted_cfg.routing.request.fallback = DnsRequestAction::Upstream("a".into());
    exhausted_cfg.routing.response.rules = vec![
        DnsResponseRule {
            conditions: vec![DnsCond::Upstream {
                not: false,
                names: vec!["a".into()],
            }],
            action: DnsResponseAction::Upstream("b".into()),
        },
        DnsResponseRule {
            conditions: vec![DnsCond::Upstream {
                not: false,
                names: vec!["b".into()],
            }],
            action: DnsResponseAction::Upstream("ab".into()),
        },
    ];
    let exhausted_fwd = build_forwarder(&exhausted_cfg, all_visited_pool);
    let exhausted_err = exhausted_fwd
        .resolve_inner(
            &make_a_query(),
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .expect_err("race group with zero unvisited members must fail with cycle");
    assert!(
        exhausted_err.to_string().contains("cycle"),
        "expected cycle error, got: {exhausted_err}"
    );
}

#[tokio::test]
async fn race_charges_dns_socket_budget_per_concurrent_leg() {
    let sock1 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr1 = sock1.local_addr().unwrap();
    let addr2 = sock2.local_addr().unwrap();

    let both_arrived = Arc::new(Barrier::new(3));
    let release_slow = Arc::new(Notify::new());

    let b1 = Arc::clone(&both_arrived);
    let r1 = Arc::clone(&release_slow);
    let srv1 = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, peer) = sock1.recv_from(&mut buf).await.unwrap();
        b1.wait().await;
        r1.notified().await;
        let mut resp = make_a_response([198, 51, 100, 11], 60);
        resp[..2].copy_from_slice(&buf[..2]);
        let _ = len;
        let _ = sock1.send_to(&resp, peer).await;
    });

    let b2 = Arc::clone(&both_arrived);
    let srv2 = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (_len, peer) = sock2.recv_from(&mut buf).await.unwrap();
        b2.wait().await;
        let mut resp = make_a_response([198, 51, 100, 22], 60);
        resp[..2].copy_from_slice(&buf[..2]);
        sock2.send_to(&resp, peer).await.unwrap();
    });

    let budget = DnsSocketBudget::new(2);
    let mut config = DnsConfig {
        upstream: vec![
            DnsUpstream {
                name: "u1".into(),
                address: addr1.to_string(),
                protocol: DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            },
            DnsUpstream {
                name: "u2".into(),
                address: addr2.to_string(),
                protocol: DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            },
        ],
        upstream_groups: vec![DnsUpstreamGroup {
            name: "fast".into(),
            upstreams: vec!["u1".into(), "u2".into()],
        }],
        ..Default::default()
    };
    config.routing.request.fallback = DnsRequestAction::Upstream("fast".into());

    let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
    let pool = Arc::new(
        UpstreamPool::new(&config.upstream, Arc::clone(&router))
            .unwrap()
            .with_socket_budget(budget.clone()),
    );
    let forwarder = DnsForwarder::new(
        Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        router,
    )
    .with_socket_budget(budget.clone())
    .with_policy_from_config(&config)
    .unwrap();

    let query = make_a_query();
    let observe_budget = budget.clone();
    let observer = tokio::spawn(async move {
        both_arrived.wait().await;
        observe_budget.available_sockets()
    });

    let outcome = forwarder
        .resolve_inner(
            &query,
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        )
        .await
        .expect("real UDP race succeeds");

    let available_during_race = observer.await.unwrap();
    assert_eq!(
        available_during_race, 0,
        "both concurrent UDP race legs must hold their own DnsSocketBudget permit"
    );
    assert_eq!(outcome.final_upstream(), Some("u2"));
    assert_eq!(outcome.answer_ips(), [IpAddr::from([198, 51, 100, 22])]);

    release_slow.notify_waiters();
    pool.close().await;
    let _ = srv1.await;
    let _ = srv2.await;
    assert_eq!(budget.available_sockets(), 2);
}

struct DoqAndUdpRacePool {
    doq: Arc<DoqClient>,
    udp: Arc<UpstreamPool>,
}

#[async_trait]
impl DnsUpstreamPool for DoqAndUdpRacePool {
    async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match upstream_name {
            "slow_doq" => self.doq.exchange(raw_query, None).await,
            _ => self.udp.query(upstream_name, raw_query).await,
        }
    }
}

#[tokio::test]
async fn race_cancels_losing_doq_leg_without_retiring_ready_session_or_leaking_budget() {
    tokio::time::timeout(Duration::from_secs(6), async {
        let (endpoint, doq_addr) = quic_server_endpoint(b"doq");
        let doq_stream_seen = Arc::new(Notify::new());
        let doq_seen_srv = Arc::clone(&doq_stream_seen);
        let doq_server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send1, mut recv1) = connection.accept_bi().await.unwrap();
            let req1 = read_length_prefixed(&mut recv1, Duration::from_secs(2))
                .await
                .unwrap();
            let mut resp1 = make_a_response([198, 51, 100, 1], 60);
            resp1[..2].copy_from_slice(&req1[..2]);
            write_length_prefixed(&mut send1, &resp1).await.unwrap();
            send1.finish().unwrap();

            let (_send2, mut recv2) = connection.accept_bi().await.unwrap();
            let _req2 = read_length_prefixed(&mut recv2, Duration::from_secs(2))
                .await
                .unwrap();
            doq_seen_srv.notify_one();

            let (mut send3, mut recv3) = connection.accept_bi().await.unwrap();
            let req3 = read_length_prefixed(&mut recv3, Duration::from_secs(2))
                .await
                .unwrap();
            let mut resp3 = make_a_response([198, 51, 100, 3], 60);
            resp3[..2].copy_from_slice(&req3[..2]);
            write_length_prefixed(&mut send3, &resp3).await.unwrap();
            send3.finish().unwrap();
            connection.closed().await;
        });

        let udp_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_sock.local_addr().unwrap();
        let udp_server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_len, peer) = udp_sock.recv_from(&mut buf).await.unwrap();
            doq_stream_seen.notified().await;
            let mut resp = make_a_response([198, 51, 100, 2], 60);
            resp[..2].copy_from_slice(&buf[..2]);
            udp_sock.send_to(&resp, peer).await.unwrap();
        });

        let budget = DnsSocketBudget::new(2);
        let doq = DoqClient::with_quic_config(
            DialContext {
                endpoint: DnsEndpoint::parse(
                    &doq_addr.to_string(),
                    DnsProtocol::Quic,
                    Some("localhost"),
                )
                .unwrap(),
                query_timeout: Duration::from_secs(2),
                dial_timeout: Duration::from_secs(2),
                socket_budget: budget.clone(),
                proxy: None,
            },
            insecure_quic_config(b"doq").await,
        );

        let warm_query = make_a_query();
        let warm_resp = doq.exchange(&warm_query, None).await.unwrap();
        assert_eq!(
            extract_answer_ips(&warm_resp),
            [IpAddr::from([198, 51, 100, 1])]
        );
        assert_eq!(doq.init_count(), 1);

        let mut config = DnsConfig {
            upstream: vec![
                DnsUpstream {
                    name: "slow_doq".into(),
                    address: doq_addr.to_string(),
                    protocol: DnsProtocol::Quic,
                    tls_server_name: Some("localhost".into()),
                    outbound: None,
                },
                DnsUpstream {
                    name: "fast_udp".into(),
                    address: udp_addr.to_string(),
                    protocol: DnsProtocol::Udp,
                    tls_server_name: None,
                    outbound: None,
                },
            ],
            upstream_groups: vec![DnsUpstreamGroup {
                name: "hybrid".into(),
                upstreams: vec!["slow_doq".into(), "fast_udp".into()],
            }],
            ..Default::default()
        };
        config.routing.request.fallback = DnsRequestAction::Upstream("hybrid".into());

        let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
        let udp_pool = Arc::new(
            UpstreamPool::new(&config.upstream[1..], Arc::clone(&router))
                .unwrap()
                .with_socket_budget(budget.clone()),
        );
        let race_pool = Arc::new(DoqAndUdpRacePool {
            doq: Arc::clone(&doq),
            udp: Arc::clone(&udp_pool),
        });
        let forwarder = DnsForwarder::new(race_pool, test_cache(), router)
            .with_socket_budget(budget.clone())
            .with_policy_from_config(&config)
            .unwrap();

        let raced = forwarder
            .resolve_inner(
                &warm_query,
                DnsRequestMeta::EMPTY,
                IngressProfile::Internal,
                &ResolveOptions::default(),
                ResolveMode::Strict,
                None,
            )
            .await
            .expect("hybrid DoQ + UDP race succeeds");
        assert_eq!(raced.final_upstream(), Some("fast_udp"));
        assert_eq!(raced.answer_ips(), [IpAddr::from([198, 51, 100, 2])]);

        let reused = doq.exchange(&warm_query, None).await.unwrap();
        assert_eq!(
            extract_answer_ips(&reused),
            [IpAddr::from([198, 51, 100, 3])]
        );
        assert_eq!(doq.init_count(), 1);

        doq.close().await;
        udp_pool.close().await;
        udp_server.await.unwrap();
        doq_server.await.unwrap();
        assert_eq!(budget.available_sockets(), 2);
    })
    .await
    .expect("DoQ cancellation test timed out");
}

#[tokio::test]
async fn race_shares_single_score_business_credit_across_concurrent_legs() {
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let all_four_connected = Arc::new(Barrier::new(4));
    let socks_server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let (mut stream, _) = socks_listener.accept().await.unwrap();
            let barrier = Arc::clone(&all_four_connected);
            tasks.spawn(async move {
                stream.read_exact(&mut [0; 3]).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                let mut req = [0u8; 10];
                stream.read_exact(&mut req).await.unwrap();
                let dst_last_octet = req[7];
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 53])
                    .await
                    .unwrap();
                let len = stream.read_u16().await.unwrap();
                let mut query = vec![0u8; len as usize];
                stream.read_exact(&mut query).await.unwrap();
                barrier.wait().await;
                if dst_last_octet == 1 {
                    let mut resp = make_a_response([203, 0, 113, 55], 60);
                    resp[..2].copy_from_slice(&query[..2]);
                    stream.write_u16(resp.len() as u16).await.unwrap();
                    stream.write_all(&resp).await.unwrap();
                } else {
                    let _ = stream.read(&mut [0u8; 1]).await;
                }
            });
        }
        while tasks.join_next().await.is_some() {}
    });

    let mut node_a = Node {
        id: uuid::Uuid::new_v4(),
        name: "socks-a".into(),
        address: socks_addr.ip().to_string(),
        port: socks_addr.port(),
        outbound: OutboundConfig::from_protocol(NodeProtocol::Socks5),
        ..Default::default()
    };
    node_a.id = node_a.derive_id();

    let group = Group {
        id: uuid::Uuid::new_v4(),
        name: "score_g".into(),
        icon: None,
        policy: GroupPolicy::Score,
        nodes: vec![node_a.id],
        filters: vec![],
        groups: vec![],
        default: None,
        final_outbound: None,
        exit: None,
        check_url: None,
        check_interval: None,
        tolerance: 50,
        idle_timeout: None,
        interrupt_connections: false,
        own: Default::default(),
        created_at: chrono::Utc::now(),
    };
    let manager = Arc::new(GroupManager::new(
        std::slice::from_ref(&group),
        std::slice::from_ref(&node_a),
    ));

    let mut config = DnsConfig {
        upstream: (1..=4)
            .map(|i| DnsUpstream {
                name: format!("u{i}"),
                address: format!("198.51.100.{i}:53"),
                protocol: if i <= 2 {
                    DnsProtocol::Udp
                } else {
                    DnsProtocol::Tcp
                },
                tls_server_name: None,
                outbound: Some("score_g".into()),
            })
            .collect(),
        upstream_groups: vec![DnsUpstreamGroup {
            name: "score_race".into(),
            upstreams: vec!["u1".into(), "u2".into(), "u3".into(), "u4".into()],
        }],
        ..Default::default()
    };
    config.routing.request.fallback = DnsRequestAction::Upstream("score_race".into());

    let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node_a))
            .unwrap(),
    );
    let pool = Arc::new(
        UpstreamPool::new_with_proxy(
            &config.upstream,
            Arc::clone(&router),
            Some(Arc::new(
                crate::proxy::ProxyRegistry::default_resolver().unwrap(),
            )),
            vec![node_a],
            vec![group],
        )
        .unwrap()
        .with_group_manager_snapshot(Arc::clone(&manager)),
    );
    pool.set_runtime_generation(generation).unwrap();

    let forwarder = DnsForwarder::new(
        Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        router,
    )
    .with_policy_from_config(&config)
    .unwrap();

    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        forwarder.resolve_inner(
            &make_a_query(),
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        ),
    )
    .await
    .expect("score raced DNS query completes")
    .expect("score raced DNS query succeeds");

    assert_eq!(outcome.final_upstream(), Some("u1"));
    assert_eq!(outcome.answer_ips(), [IpAddr::from([203, 0, 113, 55])]);
    assert_eq!(
        manager.score_state().root_business_starts(),
        1,
        "one logical raced DNS query must mint at most one root Score business start"
    );
    let tcp_counters = manager.score_budget_counters("score_g", SelectionNetwork::Tcp);
    let udp_counters = manager.score_budget_counters("score_g", SelectionNetwork::Udp);
    assert_eq!(
        tcp_counters.business_starts + udp_counters.business_starts,
        1,
        "concurrent UDP and TCP legs of one logical DNS query must share a single Score business start"
    );

    pool.close().await;
    socks_server.await.unwrap();
}

#[tokio::test]
async fn race_shares_score_credit_after_physical_requery() {
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let race_barrier = Arc::new(Barrier::new(2));
    let socks_server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..3 {
            let (mut stream, _) = socks_listener.accept().await.unwrap();
            let barrier = Arc::clone(&race_barrier);
            tasks.spawn(async move {
                stream.read_exact(&mut [0; 3]).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                let mut req = [0u8; 10];
                stream.read_exact(&mut req).await.unwrap();
                let dst_last_octet = req[7];
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 53])
                    .await
                    .unwrap();
                let len = stream.read_u16().await.unwrap();
                let mut query = vec![0u8; len as usize];
                stream.read_exact(&mut query).await.unwrap();
                if dst_last_octet == 10 {
                    let mut resp = make_a_response([10, 0, 0, 1], 60);
                    resp[..2].copy_from_slice(&query[..2]);
                    stream.write_u16(resp.len() as u16).await.unwrap();
                    stream.write_all(&resp).await.unwrap();
                    return;
                }
                barrier.wait().await;
                if dst_last_octet == 1 {
                    let mut resp = make_a_response([203, 0, 113, 66], 60);
                    resp[..2].copy_from_slice(&query[..2]);
                    stream.write_u16(resp.len() as u16).await.unwrap();
                    stream.write_all(&resp).await.unwrap();
                } else {
                    let _ = stream.read(&mut [0u8; 1]).await;
                }
            });
        }
        while tasks.join_next().await.is_some() {}
    });

    let mut node_a = Node {
        id: uuid::Uuid::new_v4(),
        name: "socks-a".into(),
        address: socks_addr.ip().to_string(),
        port: socks_addr.port(),
        outbound: OutboundConfig::from_protocol(NodeProtocol::Socks5),
        ..Default::default()
    };
    node_a.id = node_a.derive_id();

    let group = Group {
        id: uuid::Uuid::new_v4(),
        name: "score_g".into(),
        icon: None,
        policy: GroupPolicy::Score,
        nodes: vec![node_a.id],
        filters: vec![],
        groups: vec![],
        default: None,
        final_outbound: None,
        exit: None,
        check_url: None,
        check_interval: None,
        tolerance: 50,
        idle_timeout: None,
        interrupt_connections: false,
        own: Default::default(),
        created_at: chrono::Utc::now(),
    };
    let manager = Arc::new(GroupManager::new(
        std::slice::from_ref(&group),
        std::slice::from_ref(&node_a),
    ));

    let mut config = DnsConfig {
        upstream: vec![
            DnsUpstream {
                name: "u0".into(),
                address: "198.51.100.10:53".into(),
                protocol: DnsProtocol::Udp,
                tls_server_name: None,
                outbound: Some("score_g".into()),
            },
            DnsUpstream {
                name: "u1".into(),
                address: "198.51.100.1:53".into(),
                protocol: DnsProtocol::Udp,
                tls_server_name: None,
                outbound: Some("score_g".into()),
            },
            DnsUpstream {
                name: "u2".into(),
                address: "198.51.100.2:53".into(),
                protocol: DnsProtocol::Tcp,
                tls_server_name: None,
                outbound: Some("score_g".into()),
            },
        ],
        upstream_groups: vec![DnsUpstreamGroup {
            name: "score_race".into(),
            upstreams: vec!["u1".into(), "u2".into()],
        }],
        ..Default::default()
    };
    config.routing.request.fallback = DnsRequestAction::Upstream("u0".into());
    config.routing.response.rules = vec![DnsResponseRule {
        conditions: vec![DnsCond::Upstream {
            not: false,
            names: vec!["u0".into()],
        }],
        action: DnsResponseAction::Upstream("score_race".into()),
    }];
    config.routing.response.fallback = DnsResponseAction::Accept;

    let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node_a))
            .unwrap(),
    );
    let pool = Arc::new(
        UpstreamPool::new_with_proxy(
            &config.upstream,
            Arc::clone(&router),
            Some(Arc::new(
                crate::proxy::ProxyRegistry::default_resolver().unwrap(),
            )),
            vec![node_a],
            vec![group],
        )
        .unwrap()
        .with_group_manager_snapshot(Arc::clone(&manager)),
    );
    pool.set_runtime_generation(generation).unwrap();

    let forwarder = DnsForwarder::new(
        Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        router,
    )
    .with_policy_from_config(&config)
    .unwrap();

    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        forwarder.resolve_inner(
            &make_a_query(),
            DnsRequestMeta::EMPTY,
            IngressProfile::Internal,
            &ResolveOptions::default(),
            ResolveMode::Strict,
            None,
        ),
    )
    .await
    .expect("physical-to-race requery completes")
    .expect("physical-to-race requery succeeds");

    assert_eq!(outcome.final_upstream(), Some("u1"));
    assert_eq!(outcome.answer_ips(), [IpAddr::from([203, 0, 113, 66])]);
    assert_eq!(
        manager.score_state().root_business_starts(),
        1,
        "physical upstream requerying a race group must share one root Score business start"
    );
    let tcp_counters = manager.score_budget_counters("score_g", SelectionNetwork::Tcp);
    let udp_counters = manager.score_budget_counters("score_g", SelectionNetwork::Udp);
    assert_eq!(
        tcp_counters.business_starts + udp_counters.business_starts,
        1,
        "physical upstream and subsequent raced legs must share one Score business start"
    );

    pool.close().await;
    socks_server.await.unwrap();
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn race_diagnostic_and_flow_observation_report_winning_upstream() {
    use crate::dns::outcome::RouteSource;
    use crate::native_api::events::EventHub;
    use crate::observe::DnsRecorder;
    use crate::observe::flows::FlowStore;

    let sock_slow = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_quick = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_slow = sock_slow.local_addr().unwrap();
    let addr_quick = sock_quick.local_addr().unwrap();
    let slow_seen = Arc::new(Notify::new());
    let slow_seen_srv = Arc::clone(&slow_seen);
    let release_slow = Arc::new(Notify::new());
    let release_slow_srv = Arc::clone(&release_slow);

    let srv_slow = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((_len, peer)) = sock_slow.recv_from(&mut buf).await {
            slow_seen_srv.notify_one();
            release_slow_srv.notified().await;
            let mut resp = make_a_response([192, 0, 2, 10], 60);
            resp[..2].copy_from_slice(&buf[..2]);
            let _ = sock_slow.send_to(&resp, peer).await;
        }
    });
    let srv_quick = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let mut first = true;
        while let Ok((_len, peer)) = sock_quick.recv_from(&mut buf).await {
            if first {
                slow_seen.notified().await;
                first = false;
            }
            let mut resp = make_a_response([192, 0, 2, 20], 60);
            resp[..2].copy_from_slice(&buf[..2]);
            sock_quick.send_to(&resp, peer).await.unwrap();
        }
    });

    let mut config = DnsConfig {
        upstream: vec![
            DnsUpstream {
                name: "slow".into(),
                address: addr_slow.to_string(),
                protocol: DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            },
            DnsUpstream {
                name: "quick".into(),
                address: addr_quick.to_string(),
                protocol: DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            },
        ],
        upstream_groups: vec![DnsUpstreamGroup {
            name: "fast".into(),
            upstreams: vec!["slow".into(), "quick".into()],
        }],
        ..Default::default()
    };
    config.routing.request.fallback = DnsRequestAction::Reject;

    let router = Arc::new(DnsRouter::new_from_dns_config(&config).unwrap());
    let pool = Arc::new(UpstreamPool::new(&config.upstream, Arc::clone(&router)).unwrap());
    let forwarder = Arc::new(
        DnsForwarder::new(
            Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            router,
        )
        .with_policy_from_config(&config)
        .unwrap(),
    );
    let service = crate::dns::DnsService::with_forwarder(Arc::clone(&forwarder));

    let instance = uuid::Uuid::new_v4().to_string();
    let store = Arc::new(FlowStore::new(
        instance.clone(),
        Arc::new(EventHub::new(instance.clone())),
    ));
    let recorder = Arc::new(DnsRecorder::new(instance, Arc::downgrade(&store), false));
    service.attach_observer(Arc::downgrade(&recorder));

    let flow = Arc::new(
        store
            .begin(
                crate::observe::vocab::Network::Tcp,
                "127.0.0.1:41000".parse().unwrap(),
                "192.0.2.20:443".parse().unwrap(),
            )
            .unwrap(),
    );
    let flow_observer = flow.observer(1, None, "dial_target").unwrap();

    let options = ResolveOptions {
        cache: CacheAccess::Bypass,
        forced_upstream: Some(UpstreamTag::new("fast").unwrap()),
        ..Default::default()
    };
    let diag_fut = service.diagnostic(
        "example.com.",
        &[1],
        &options,
        tokio::time::Instant::now() + Duration::from_secs(2),
    );
    let mut answers = flow_observer
        .scope(std::pin::pin!(diag_fut))
        .await
        .expect("diagnostic query with forced race group must succeed");
    let answer = answers.pop().unwrap();
    assert_eq!(answer.route, RouteSource::Forced);
    let outcome = answer.outcome.expect("diagnostic outcome");
    assert_eq!(outcome.logical_upstream(), Some("fast"));
    assert_eq!(outcome.final_upstream(), Some("quick"));
    assert_eq!(outcome.answer_ips(), [IpAddr::from([192, 0, 2, 20])]);

    let detail = store.get(flow.id()).unwrap();
    let dns_steps: Vec<_> = detail["trace"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["stage"] == "dns")
        .map(|step| &step["data"])
        .collect();
    assert!(
        dns_steps
            .iter()
            .any(|d| d["upstream"] == "quick" && d["status"] == "succeeded"),
        "winning leg must finish succeeded: {dns_steps:?}"
    );
    assert!(
        dns_steps
            .iter()
            .any(|d| d["upstream"] == "slow" && d["status"] == "cancelled"),
        "cancelled losing leg must finish cancelled: {dns_steps:?}"
    );

    release_slow.notify_waiters();
    srv_slow.abort();
    srv_quick.abort();
    pool.close().await;
    forwarder.shutdown_background_tasks().await;
}
