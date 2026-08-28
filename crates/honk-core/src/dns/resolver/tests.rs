use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use async_trait::async_trait;
use tokio::sync::{Notify, Semaphore};

use super::*;
use crate::dns::forwarder::{DnsUpstreamPool, parse_dns_question};

mod outcomes;

struct ConcurrentPool {
    entered: AtomicUsize,
    both_entered: Notify,
    release: Semaphore,
}

impl ConcurrentPool {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicUsize::new(0),
            both_entered: Notify::new(),
            release: Semaphore::new(0),
        })
    }
}

#[async_trait]
impl DnsUpstreamPool for ConcurrentPool {
    async fn query(&self, _upstream_name: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.entered.fetch_add(1, Ordering::SeqCst) == 1 {
            self.both_entered.notify_one();
        }
        self.release.acquire().await?.forget();
        let (_, qtype) = parse_dns_question(query).ok_or_else(|| anyhow::anyhow!("question"))?;
        Ok(address_response(query, qtype, 120))
    }
}

pub(super) fn address_response(query: &[u8], qtype: u16, ttl: u32) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&qtype.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    match qtype {
        1 => {
            response.extend_from_slice(&4_u16.to_be_bytes());
            response.extend_from_slice(&[192, 0, 2, 10]);
        }
        28 => {
            response.extend_from_slice(&16_u16.to_be_bytes());
            response
                .extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10]);
        }
        other => unreachable!("unexpected query type {other}"),
    }
    response
}

pub(super) fn resolver_with_strategy(
    pool: Arc<dyn DnsUpstreamPool>,
    strategy: honk_config::dns::DnsStrategy,
) -> DnsResolver {
    let config = DnsConfig {
        strategy,
        ..DnsConfig::default()
    };
    resolver_with_config(pool, &config)
}

pub(super) fn resolver_with_config(
    pool: Arc<dyn DnsUpstreamPool>,
    config: &DnsConfig,
) -> DnsResolver {
    let forwarder = Arc::new(
        DnsForwarder::new(
            pool,
            Arc::new(Mutex::new(DnsCache::new(32))),
            Arc::new(DnsRouter::new_from_dns_config(config).expect("router")),
        )
        .with_strategy(config.strategy),
    );
    DnsResolver::with_forwarder(config, forwarder).expect("resolver")
}

#[test]
fn dns_config_default_has_one_upstream() {
    let config = DnsConfig::default();
    assert_eq!(config.upstream.len(), 1);
    assert_eq!(config.upstream[0].address, "223.5.5.5:53");
}

#[test]
fn resolver_can_be_created_from_default_config() {
    assert!(DnsResolver::new(&DnsConfig::default()).is_ok());
}

#[tokio::test]
async fn resolver_returns_literal_ipv4_without_upstream() {
    let resolver = DnsResolver::new(&DnsConfig::default()).expect("resolver");
    let resolved = resolver.resolve("127.0.0.1").await.expect("literal");
    assert_eq!(
        resolved.ipv4,
        vec!["127.0.0.1".parse::<IpAddr>().expect("IP")]
    );
    assert!(resolved.ipv6.is_empty());
}

#[tokio::test]
async fn resolver_groups_literal_ipv6_without_upstream() {
    let resolver = DnsResolver::new(&DnsConfig::default()).expect("resolver");
    let resolved = resolver.resolve("  2001:db8::1.  ").await.expect("literal");
    assert!(resolved.ipv4.is_empty());
    assert_eq!(
        resolved.ipv6,
        vec!["2001:db8::1".parse::<IpAddr>().expect("IP")]
    );
    assert_eq!(resolved.min_ttl, 3600);
}

#[tokio::test]
async fn parallel_strategies_enter_both_families_before_either_is_released() {
    let ipv4 = "192.0.2.10".parse::<IpAddr>().expect("IPv4");
    let ipv6 = "2001:db8::a".parse::<IpAddr>().expect("IPv6");
    for (strategy, expected_ipv4, expected_ipv6) in [
        (honk_config::dns::DnsStrategy::Both, vec![ipv4], vec![ipv6]),
        (
            honk_config::dns::DnsStrategy::PreferIpv4,
            vec![ipv4],
            Vec::new(),
        ),
        (
            honk_config::dns::DnsStrategy::PreferIpv6,
            Vec::new(),
            vec![ipv6],
        ),
    ] {
        let pool = ConcurrentPool::new();
        let both_entered = pool.both_entered.notified();
        tokio::pin!(both_entered);
        let resolver = resolver_with_strategy(pool.clone(), strategy);
        let lookup = resolver.resolve("example.com");
        tokio::pin!(lookup);

        assert!(matches!(futures::poll!(lookup.as_mut()), Poll::Pending));
        assert_eq!(pool.entered.load(Ordering::SeqCst), 2);
        assert!(matches!(
            futures::poll!(both_entered.as_mut()),
            Poll::Ready(())
        ));

        pool.release.add_permits(2);
        let resolved = lookup.await.expect("dual-family result");
        assert_eq!(resolved.ipv4, expected_ipv4);
        assert_eq!(resolved.ipv6, expected_ipv6);
        assert_eq!(resolved.min_ttl, 120);
    }
}
