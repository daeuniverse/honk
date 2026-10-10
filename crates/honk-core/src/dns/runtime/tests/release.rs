use std::sync::Weak;

use super::*;
use crate::dns::runtime::{DnsPauseError, RETIREMENT_DEADLINE};
use crate::dns::upstream_pool::UpstreamPool;
use honk_outbound::runtime::OutboundRuntimeRegistry;

struct Retained {
    projection: Weak<RoutingProjectionSnapshot>,
    traffic_router: Weak<Router>,
}

impl Retained {
    fn released(&self) -> bool {
        self.projection.strong_count() == 0 && self.traffic_router.strong_count() == 0
    }
}

/// A runtime whose real upstream pool pins its own traffic-router snapshot,
/// distinct from the routing projection's router.
fn pooled_runtime(
    generation: u64,
    outbound_runtime: Option<Arc<OutboundRuntimeRegistry>>,
) -> (Arc<DnsRuntime>, Retained) {
    let config = Config::default();
    let dns_router = Arc::new(DnsRouter::new_from_dns_config(&config.dns).unwrap());
    let traffic_router = Arc::new(Router::new(&[], "direct").unwrap());
    let pool = Arc::new(
        UpstreamPool::new(&[], Arc::clone(&dns_router))
            .unwrap()
            .with_traffic_router_snapshot(Arc::clone(&traffic_router)),
    );
    let cache = Arc::new(Mutex::new(DnsCache::new(32)));
    let forwarder = Arc::new(DnsForwarder::new(pool.clone(), cache, dns_router));
    let projection = Arc::new(RoutingProjectionSnapshot::new(
        generation,
        Arc::new(Router::new(&[], "direct").unwrap()),
    ));
    let retained = Retained {
        projection: Arc::downgrade(&projection),
        traffic_router: Arc::downgrade(&traffic_router),
    };
    let runtime = DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(generation),
        udp_query_limit: 256,
        forwarder,
        routing_projection: projection,
        outbound_runtime,
        transport: pool,
    });
    (runtime, retained)
}

struct FailedTasks;

#[async_trait]
impl RuntimeTransport for FailedTasks {
    async fn close(&self) {}

    fn tasks_failed(&self) -> bool {
        true
    }
}

fn failing_runtime(
    generation: u64,
    outbound_runtime: Arc<OutboundRuntimeRegistry>,
) -> (Arc<DnsRuntime>, Retained) {
    let (mut runtime, retained) = pooled_runtime(generation, Some(outbound_runtime));
    Arc::get_mut(&mut runtime).unwrap().parts.transport = Arc::new(FailedTasks);
    (runtime, retained)
}

fn outbound() -> Arc<OutboundRuntimeRegistry> {
    Arc::new(OutboundRuntimeRegistry::build(&[]).unwrap())
}

async fn eventually(condition: impl Fn() -> bool) -> bool {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn drained_generation_releases_its_projection_and_traffic_router() {
    let (old, retained) = pooled_runtime(1, None);
    let provider = DnsServiceProvider::new(old);

    provider.publish(runtime(2, 0).0);

    assert!(eventually(|| retained.released()).await);
    assert_eq!(provider.retired_count(), 1);
    provider.shutdown().await;
}

#[tokio::test]
async fn generation_published_already_closed_is_released_at_publication() {
    let (current, retained) = pooled_runtime(1, None);
    let provider = DnsServiceProvider::new(current);
    provider.begin_pause();
    provider.finish_pause().await.unwrap();

    provider.publish(runtime(2, 0).0);

    assert!(retained.released());
    provider.shutdown().await;
}

#[tokio::test]
async fn snapshot_taken_before_release_stays_usable() {
    let (old, retained) = pooled_runtime(1, None);
    let provider = DnsServiceProvider::new(old);
    let snapshot = provider.current();

    provider.publish(runtime(2, 0).0);

    assert!(eventually(|| Arc::strong_count(&snapshot) == 1).await);
    assert!(Arc::ptr_eq(
        snapshot.routing_projection(),
        &retained.projection.upgrade().unwrap()
    ));
    assert_eq!(snapshot.generation().get(), 1);
    drop(snapshot.cache().lock().await);
    drop(snapshot);
    assert!(retained.released());
    provider.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn lease_held_past_the_deadline_delays_release_until_it_drops() {
    let (old, retained) = pooled_runtime(1, None);
    let provider = DnsServiceProvider::new(old);
    let lease = provider.try_acquire().unwrap();
    provider.publish(runtime(2, 0).0);

    tokio::time::advance(RETIREMENT_DEADLINE).await;
    lease.runtime().wait_closed().await;
    assert!(!retained.released());
    drop(lease);

    assert!(eventually(|| retained.released()).await);
    provider.shutdown().await;
}

#[tokio::test]
async fn pause_after_release_shuts_down_outbound_and_reports_cleanup_failure() {
    let old_outbound = outbound();
    let (old, retained) = failing_runtime(1, Arc::clone(&old_outbound));
    // Past a zero deadline the pause reports `Deadline` unless an entry fails.
    let provider = DnsServiceProvider::with_deadline(old, Duration::ZERO);
    provider.publish(runtime(2, 0).0);
    assert!(eventually(|| retained.released()).await);
    // Reap the failed supervisor so only the released entry can report it.
    provider.publish(runtime(3, 0).0);

    provider.begin_pause();

    assert!(matches!(
        provider.finish_pause().await,
        Err(DnsPauseError::TaskFailed)
    ));
    assert!(old_outbound.is_shutdown());
}

#[tokio::test]
async fn cap_eviction_after_release_shuts_down_outbound_and_reports_cleanup_failure() {
    let oldest_outbound = outbound();
    let (oldest, retained) = failing_runtime(0, Arc::clone(&oldest_outbound));
    let provider = DnsServiceProvider::new(oldest);
    provider.publish(runtime(1, 0).0);
    assert!(eventually(|| retained.released()).await);

    for generation in 2..=MAX_RETIRED_RUNTIMES as u64 + 1 {
        provider.publish(runtime(generation, 0).0);
    }

    assert_eq!(provider.retired_count(), MAX_RETIRED_RUNTIMES);
    assert!(oldest_outbound.is_shutdown());
    provider.begin_pause();
    assert!(matches!(
        provider.finish_pause().await,
        Err(DnsPauseError::TaskFailed)
    ));
}
