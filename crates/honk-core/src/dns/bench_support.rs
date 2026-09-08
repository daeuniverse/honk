use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use honk_config::Config;
use tokio::sync::Mutex;

use super::cache::{CacheKey, DnsCache, OperationKind};
use super::forwarder::{DnsForwarder, DnsUpstreamPool};
use super::planner::{RequestScope, UpstreamTag};
use super::policy::PolicyId;
use super::projection::{ProjectionReplacementBenchmark, RoutingProjectionSnapshot};
use super::query::{IngressProfile, QueryContext};
use super::routing::DnsRouter;
use super::runtime::{
    DnsRuntime, DnsRuntimeParts, DnsServiceProvider, RuntimeGeneration, RuntimeTransport,
};
use crate::routing::Router;

pub struct CacheKeyBenchmarkInput {
    query: QueryContext,
    policy_id: PolicyId,
    scope: RequestScope,
}

impl CacheKeyBenchmarkInput {
    pub fn parse(raw_query: &[u8]) -> Self {
        let config = Config::default();
        Self {
            query: QueryContext::parse_with_profile(
                raw_query,
                IngressProfile::Udp {
                    advertised_size: 1232,
                },
            )
            .expect("benchmark query"),
            policy_id: PolicyId::from_config(&config.dns).expect("benchmark policy"),
            scope: RequestScope::Upstream(
                UpstreamTag::new("default").expect("benchmark upstream tag"),
            ),
        }
    }

    pub fn build(&self) -> usize {
        CacheKey::new(
            &self.query,
            Some(self.policy_id.clone()),
            self.scope.clone(),
            OperationKind::Resolve,
        )
        .wire_identity()
        .len()
    }
}

pub struct ProjectionBenchmark {
    replacement: ProjectionReplacementBenchmark,
}

impl ProjectionBenchmark {
    pub fn new() -> Self {
        let rule = honk_config::routing::RoutingRule {
            name: "projection-bench".to_owned(),
            condition: honk_config::routing::RoutingCondition {
                domain: vec!["projection.example".to_owned()],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("direct".to_owned()),
            priority: 1,
            must: false,
            mark: 0,
        };
        let matcher = Arc::new(Router::new(&[rule], "direct").expect("benchmark router"));
        let snapshot = Arc::new(RoutingProjectionSnapshot::new(1, matcher));
        Self {
            replacement: ProjectionReplacementBenchmark::new(
                snapshot,
                Arc::<str>::from("projection.example"),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ),
        }
    }

    pub fn replace(&mut self) -> u64 {
        self.replacement.replace()
    }
}

impl Default for ProjectionBenchmark {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RuntimeBenchmark {
    provider: Arc<DnsServiceProvider>,
    shared: RuntimeShared,
    next_generation: u64,
}

struct RuntimeShared {
    cache: Arc<Mutex<DnsCache>>,
    dns_router: Arc<DnsRouter>,
    router: Arc<Router>,
}

impl RuntimeBenchmark {
    pub fn new() -> Self {
        let config = Config::default();
        let cache = Arc::new(Mutex::new(DnsCache::new(32)));
        let dns_router =
            Arc::new(DnsRouter::new_from_dns_config(&config.dns).expect("benchmark DNS router"));
        let shared = RuntimeShared {
            cache,
            dns_router,
            router: Arc::new(
                Router::new(&config.routing.rules, &config.routing.default_outbound)
                    .expect("benchmark router"),
            ),
        };
        let initial = runtime(&shared, 1);
        Self {
            provider: Arc::new(DnsServiceProvider::new(initial)),
            shared,
            next_generation: 2,
        }
    }

    pub fn acquire_generation(&self) -> u64 {
        self.provider.acquire().runtime().generation().get()
    }

    pub fn publish_next(&mut self) {
        let replacement = runtime(&self.shared, self.next_generation);
        self.next_generation = self.next_generation.saturating_add(1);
        self.provider.prepare_publication(replacement).commit();
    }

    pub async fn shutdown(&self) {
        self.provider.shutdown().await;
    }
}

impl Default for RuntimeBenchmark {
    fn default() -> Self {
        Self::new()
    }
}

pub fn record_observability_event() {
    crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheHit);
}

/// Validate a raw UDP query and return its derived advertised size.
#[doc(hidden)]
pub fn validate_udp_query_profile(raw: &[u8]) -> u16 {
    match super::query::validate_exact_dns_query(raw)
        .expect("benchmark query")
        .ingress()
    {
        IngressProfile::Udp { advertised_size } => advertised_size,
        _ => unreachable!("validated UDP query has a UDP ingress profile"),
    }
}

pub fn observability_snapshot_checksum() -> u64 {
    let snapshot = crate::stats::dns::dns_snapshot();
    snapshot
        .cache_hit
        .wrapping_add(snapshot.cache_miss)
        .wrapping_add(snapshot.outcome_error)
}

fn runtime(shared: &RuntimeShared, generation: u64) -> Arc<DnsRuntime> {
    DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(generation),
        udp_query_limit: 256,
        forwarder: Arc::new(DnsForwarder::new(
            Arc::new(UnusedPool),
            Arc::clone(&shared.cache),
            Arc::clone(&shared.dns_router),
        )),
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            generation,
            Arc::clone(&shared.router),
        )),
        outbound_runtime: None,
        transport: Arc::new(NoopTransport),
    })
}

struct UnusedPool;

#[async_trait]
impl DnsUpstreamPool for UnusedPool {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        unreachable!("benchmark runtime does not exchange DNS")
    }
}

struct NoopTransport;

#[async_trait]
impl RuntimeTransport for NoopTransport {
    async fn close(&self) {}
}
