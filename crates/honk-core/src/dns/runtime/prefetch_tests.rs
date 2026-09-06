use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use honk_config::Config;
use tokio::sync::{Mutex, Notify};

use super::{
    DnsRuntime, DnsRuntimeParts, RoutingProjectionSnapshot, RuntimeGeneration, RuntimeTransport,
};
use crate::dns::cache::DnsCache;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use crate::dns::routing::DnsRouter;
use crate::routing::Router;

struct DropSignal<'a>(&'a BlockingTransport);

impl Drop for DropSignal<'_> {
    fn drop(&mut self) {
        let order = self.0.next_order.fetch_add(1, Ordering::AcqRel) + 1;
        self.0.query_drop_order.store(order, Ordering::Release);
        self.0.dropped.notify_waiters();
    }
}

#[derive(Default)]
struct BlockingTransport {
    entered: Notify,
    dropped: Notify,
    next_order: AtomicUsize,
    query_drop_order: AtomicUsize,
    close_order: AtomicUsize,
}

#[async_trait]
impl DnsUpstreamPool for BlockingTransport {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        let _drop_signal = DropSignal(self);
        self.entered.notify_one();
        std::future::pending().await
    }
}

#[async_trait]
impl RuntimeTransport for BlockingTransport {
    async fn close(&self) {
        let order = self.next_order.fetch_add(1, Ordering::AcqRel) + 1;
        self.close_order.store(order, Ordering::Release);
    }
}

fn runtime(transport: Arc<BlockingTransport>) -> Arc<DnsRuntime> {
    let mut config = Config::default();
    config.dns.routing.fallback = "default".to_owned();
    let cache = Arc::new(Mutex::new(DnsCache::new(32)));
    let router = Arc::new(
        Router::new(&config.routing.rules, &config.routing.default_outbound).expect("valid router"),
    );
    let forwarder = Arc::new(DnsForwarder::new(
        Arc::clone(&transport) as Arc<dyn DnsUpstreamPool>,
        Arc::clone(&cache),
        Arc::new(DnsRouter::new_from_dns_config(&config.dns).expect("valid DNS router")),
    ));
    DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(1),
        udp_query_limit: 256,
        forwarder,
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            1,
            router,
            Default::default(),
        )),
        outbound_runtime: None,
        transport: transport.clone(),
    })
}

#[tokio::test]
async fn retirement_joins_blocked_prefetch_before_transport_close() {
    let transport = Arc::new(BlockingTransport::default());
    let runtime = runtime(Arc::clone(&transport));
    runtime
        .forwarder()
        .prefetch(&["blocked.example".to_owned()]);
    transport.entered.notified().await;

    Arc::clone(&runtime).retire(Duration::ZERO).await;

    assert_eq!(transport.query_drop_order.load(Ordering::Acquire), 1);
    assert_eq!(transport.close_order.load(Ordering::Acquire), 2);
}

#[tokio::test(start_paused = true)]
async fn retirement_cancels_every_foreground_entry_path() {
    use crate::dns::query::{DnsRequestMeta, IngressProfile};
    use crate::dns::runtime::DnsServiceProvider;
    use crate::dns::service::DnsService;

    enum Trigger {
        Deadline,
        Capacity,
        Shutdown,
    }
    for trigger in [Trigger::Deadline, Trigger::Capacity, Trigger::Shutdown] {
        let transport = Arc::new(BlockingTransport::default());
        let old = runtime(Arc::clone(&transport));
        let provider = Arc::new(DnsServiceProvider::new(Arc::clone(&old)));
        let service = DnsService::with_provider(Arc::clone(&provider));
        let mut queries = tokio::task::JoinSet::new();
        for caller in 0..4 {
            let service = service.clone();
            queries.spawn(async move {
                let query = crate::dns::forwarder::build_dns_query("blocked.example", 1);
                match caller {
                    0 => service
                        .resolve(&query, IngressProfile::Api)
                        .await
                        .map(|_| ()),
                    1 => service
                        .resolve_outcome_with_runtime(
                            &service.provider().unwrap().acquire(),
                            &query,
                            DnsRequestMeta::EMPTY,
                            IngressProfile::Udp {
                                advertised_size: 1232,
                            },
                        )
                        .await
                        .map(|_| ()),
                    2 => service.resolve_name("blocked.example").await.map(|_| ()),
                    _ => service
                        .resolve_name_for_source("blocked.example", "192.0.2.1".parse().unwrap())
                        .await
                        .map(|_| ()),
                }
            });
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while old.lease_count() != 4 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("all foreground callers acquire their old-generation lease");
        provider.publish(runtime(Arc::new(BlockingTransport::default())));
        tokio::task::yield_now().await;
        assert_eq!(old.lease_count(), 4);
        match trigger {
            Trigger::Deadline => tokio::time::advance(super::RETIREMENT_DEADLINE).await,
            Trigger::Capacity => {
                for _ in 0..super::MAX_RETIRED_RUNTIMES {
                    provider.publish(runtime(Arc::new(BlockingTransport::default())));
                }
            }
            Trigger::Shutdown => {
                tokio::time::timeout(Duration::from_secs(1), provider.shutdown())
                    .await
                    .expect("shutdown cancels pending queries");
            }
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            while let Some(query) = queries.join_next().await {
                assert!(query.unwrap().is_err(), "retired query must fail closed");
            }
        })
        .await
        .expect("retirement must cancel every service entry path");
        assert_eq!(old.lease_count(), 0);
        let closed_lease = provider.acquire();
        tokio::time::timeout(Duration::from_secs(1), provider.shutdown())
            .await
            .expect("final shutdown joins every runtime");
        assert!(transport.query_drop_order.load(Ordering::Acquire) > 0);
        assert!(
            closed_lease
                .run(async { panic!("closed runtime must not poll a query") })
                .await
                .is_err()
        );
    }
}
