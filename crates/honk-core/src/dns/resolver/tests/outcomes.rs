use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use honk_config::dns::DnsStrategy;
use tokio::sync::{Mutex, Notify, Semaphore};

use super::{address_response, resolver_with_config, resolver_with_strategy};
use crate::dns::cache::DnsCache;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool, parse_dns_question};
use crate::dns::routing::DnsRouter;
use crate::dns::service::DnsService;

#[derive(Clone, Copy)]
enum Reply {
    Address(u32),
    Empty,
    Nxdomain,
    Failure,
}

struct ScriptedPool {
    replies: [Reply; 2],
    calls: [AtomicUsize; 2],
    entered: Notify,
    release: Option<Semaphore>,
}

impl ScriptedPool {
    fn new(ipv4: Reply, ipv6: Reply) -> Arc<Self> {
        Arc::new(Self {
            replies: [ipv4, ipv6],
            calls: [AtomicUsize::new(0), AtomicUsize::new(0)],
            entered: Notify::new(),
            release: None,
        })
    }

    fn blocked() -> Arc<Self> {
        Arc::new(Self {
            replies: [Reply::Address(300), Reply::Address(90)],
            calls: [AtomicUsize::new(0), AtomicUsize::new(0)],
            entered: Notify::new(),
            release: Some(Semaphore::new(0)),
        })
    }

    fn counts(&self) -> [usize; 2] {
        self.calls
            .each_ref()
            .map(|count| count.load(Ordering::SeqCst))
    }
}

#[async_trait]
impl DnsUpstreamPool for ScriptedPool {
    async fn query(&self, _upstream_name: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (_, qtype) = parse_dns_question(query).ok_or_else(|| anyhow::anyhow!("question"))?;
        let index = match qtype {
            1 => 0,
            28 => 1,
            other => anyhow::bail!("unexpected qtype {other}"),
        };
        if self.calls[index].fetch_add(1, Ordering::SeqCst) == 0
            && self.calls[1 - index].load(Ordering::SeqCst) > 0
        {
            self.entered.notify_waiters();
        }
        if let Some(release) = &self.release {
            release.acquire().await?.forget();
        }
        match self.replies[index] {
            Reply::Address(ttl) => Ok(address_response(query, qtype, ttl)),
            Reply::Empty => Ok(empty_response(query, false)),
            Reply::Nxdomain => Ok(empty_response(query, true)),
            Reply::Failure => anyhow::bail!("scripted {qtype} failure"),
        }
    }
}

fn empty_response(query: &[u8], nxdomain: bool) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] = 0x81;
    response[3] = if nxdomain { 0x83 } else { 0x80 };
    response
}

fn service(strategy: DnsStrategy, pool: Arc<dyn DnsUpstreamPool>) -> DnsService {
    let config = honk_config::dns::DnsConfig {
        strategy,
        ..Default::default()
    };
    let forwarder = Arc::new(
        DnsForwarder::new(
            pool,
            Arc::new(Mutex::new(DnsCache::new(32))),
            Arc::new(DnsRouter::new_from_dns_config(&config).expect("router")),
        )
        .with_strategy(config.strategy),
    );
    DnsService::with_forwarder(forwarder)
}

#[tokio::test]
async fn strategies_issue_exact_eligible_branches_and_preserve_prefer_semantics() {
    for (strategy, expected, expected_lengths) in [
        (DnsStrategy::Both, [1, 1], [1, 1]),
        (DnsStrategy::PreferIpv4, [1, 1], [1, 0]),
        (DnsStrategy::PreferIpv6, [1, 1], [0, 1]),
        (DnsStrategy::Ipv4Only, [1, 0], [1, 0]),
        (DnsStrategy::Ipv6Only, [0, 1], [0, 1]),
    ] {
        let pool = ScriptedPool::new(Reply::Address(300), Reply::Address(90));
        let resolved = resolver_with_strategy(pool.clone(), strategy)
            .resolve("example.com")
            .await
            .expect("strategy result");
        assert_eq!(pool.counts(), expected);
        assert_eq!([resolved.ipv4.len(), resolved.ipv6.len()], expected_lengths);
        assert_eq!(
            resolved.min_ttl,
            if expected_lengths[1] == 1 { 90 } else { 300 }
        );
    }
}

#[tokio::test]
async fn one_usable_family_survives_sibling_failure_or_nxdomain() {
    let ipv6_pool = ScriptedPool::new(Reply::Failure, Reply::Address(90));
    let ipv6 = resolver_with_strategy(ipv6_pool.clone(), DnsStrategy::Both)
        .resolve("example.com")
        .await
        .expect("AAAA partial success");
    assert!(ipv6.ipv4.is_empty());
    assert_eq!(ipv6.ipv6.len(), 1);
    assert_eq!(ipv6.min_ttl, 90);
    assert_eq!(ipv6_pool.counts(), [1, 1]);

    let ipv4_pool = ScriptedPool::new(Reply::Address(300), Reply::Nxdomain);
    let ipv4 = resolver_with_strategy(ipv4_pool.clone(), DnsStrategy::Both)
        .resolve("example.com")
        .await
        .expect("A partial success");
    assert_eq!(ipv4.ipv4.len(), 1);
    assert!(ipv4.ipv6.is_empty());
    assert_eq!(ipv4.min_ttl, 300);
    assert_eq!(ipv4_pool.counts(), [1, 1]);
}

#[tokio::test]
async fn fallback_runs_once_only_when_both_families_are_unusable() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fallback_calls = Arc::clone(&calls);
    let result = service(
        DnsStrategy::Both,
        ScriptedPool::new(Reply::Empty, Reply::Failure),
    )
    .resolve_name_with_fallback("example.com", move |_| async move {
        fallback_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![
            "198.51.100.8".parse::<IpAddr>().expect("IPv4"),
            "2001:db8::8".parse::<IpAddr>().expect("IPv6"),
        ])
    })
    .await
    .expect("fallback success");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!([result.ipv4.len(), result.ipv6.len()], [1, 1]);
    assert_eq!(result.min_ttl, 60);

    let error = service(
        DnsStrategy::Both,
        ScriptedPool::new(Reply::Failure, Reply::Nxdomain),
    )
    .resolve_name_with_fallback("example.com", |_| async {
        anyhow::bail!("bootstrap unavailable")
    })
    .await
    .expect_err("fallback failure");
    assert!(error.to_string().contains("bootstrap unavailable"));

    let empty = service(
        DnsStrategy::Both,
        ScriptedPool::new(Reply::Empty, Reply::Empty),
    )
    .resolve_name_with_fallback("example.com", |_| async { Ok(Vec::new()) })
    .await
    .expect_err("empty fallback");
    assert!(empty.to_string().contains("no A/AAAA records"));

    let filtered = service(
        DnsStrategy::Ipv4Only,
        ScriptedPool::new(Reply::Empty, Reply::Failure),
    )
    .resolve_name_with_fallback("example.com", |_| async {
        Ok(vec!["2001:db8::9".parse::<IpAddr>().expect("IPv6")])
    })
    .await
    .expect_err("ineligible fallback family");
    assert!(filtered.to_string().contains("no A/AAAA records"));
}

#[tokio::test]
async fn source_specific_resolution_is_strict_and_uses_sip() {
    let pool = ScriptedPool::new(Reply::Address(300), Reply::Failure);
    let mut config = honk_config::dns::DnsConfig {
        strategy: DnsStrategy::Ipv4Only,
        ..Default::default()
    };
    config.routing.request.rules = vec![honk_config::dns::DnsRequestRule {
        conditions: vec![honk_config::dns::DnsCond::Sip {
            not: false,
            cidrs: vec!["192.0.2.0/24".into()],
        }],
        action: honk_config::dns::DnsRequestAction::Upstream("default".into()),
    }];
    config.routing.request.fallback = honk_config::dns::DnsRequestAction::Reject;
    let resolver = resolver_with_config(pool.clone(), &config);

    let resolved = resolver
        .resolve_for_source("example.com", "192.0.2.10".parse().unwrap())
        .await
        .expect("matching source");
    let rejected = resolver
        .resolve_for_source("example.com", "198.51.100.10".parse().unwrap())
        .await;

    assert_eq!(resolved.ipv4, ["192.0.2.10".parse::<IpAddr>().unwrap()]);
    assert!(rejected.is_err());
    assert_eq!(pool.counts(), [1, 0]);

    config.routing.request.rules[0].action = honk_config::dns::DnsRequestAction::AsIs;
    config.routing.request.fallback =
        honk_config::dns::DnsRequestAction::Upstream("default".into());
    let asis_pool = ScriptedPool::new(Reply::Address(300), Reply::Failure);
    let asis = resolver_with_config(asis_pool.clone(), &config)
        .resolve_for_source("example.com", "192.0.2.10".parse().unwrap())
        .await;
    assert!(asis.is_err());
    assert_eq!(asis_pool.counts(), [0, 0]);
}

#[tokio::test]
async fn source_resolution_rejects_asis_from_either_family() {
    let pool = ScriptedPool::new(Reply::Address(300), Reply::Address(300));
    let mut config = honk_config::dns::DnsConfig {
        strategy: DnsStrategy::Both,
        ..Default::default()
    };
    config.routing.request.rules = vec![honk_config::dns::DnsRequestRule {
        conditions: vec![
            honk_config::dns::DnsCond::Sip {
                not: false,
                cidrs: vec!["192.0.2.0/24".into()],
            },
            honk_config::dns::DnsCond::Qtype {
                not: false,
                types: vec![1],
            },
        ],
        action: honk_config::dns::DnsRequestAction::AsIs,
    }];
    config.routing.request.fallback =
        honk_config::dns::DnsRequestAction::Upstream("default".into());

    let error = resolver_with_config(pool.clone(), &config)
        .resolve_for_source("example.com", "192.0.2.10".parse().unwrap())
        .await
        .expect_err("A asis without an original destination must fail the whole lookup");

    assert!(error.to_string().contains("original destination"));
    assert_eq!(pool.counts(), [0, 1]);
}

#[tokio::test]
async fn parent_cancellation_drops_both_flights_and_waiters() {
    let pool = ScriptedPool::blocked();
    let both_entered = pool.entered.notified();
    tokio::pin!(both_entered);
    let service = service(DnsStrategy::Both, pool.clone());
    let flights = service.forwarder().singleflight().clone();
    let lookup_service = service.clone();
    let lookup = tokio::spawn(async move { lookup_service.resolve_name("example.com").await });
    tokio::time::timeout(Duration::from_secs(1), &mut both_entered)
        .await
        .expect("both branches entered");
    assert_eq!(flights.active_len(), 2);
    lookup.abort();
    let _ = lookup.await;
    tokio::task::yield_now().await;
    assert_eq!(flights.active_len(), 0);
}

#[tokio::test]
async fn literal_ip_skips_dns_and_fallback() {
    let pool = ScriptedPool::new(Reply::Failure, Reply::Failure);
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&fallback_calls);
    let resolved = service(DnsStrategy::Both, pool.clone())
        .resolve_name_with_fallback("192.0.2.44", move |_| async move {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        })
        .await
        .expect("literal");
    assert_eq!(resolved.ipv4.len(), 1);
    assert_eq!(pool.counts(), [0, 0]);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
}
