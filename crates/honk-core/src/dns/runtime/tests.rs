use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use honk_config::Config;
use honk_outbound::bootstrap::BootstrapResolver;

use super::{
    DnsRuntime, DnsRuntimeParts, DnsServiceProvider, MAX_RETIRED_RUNTIMES,
    RoutingProjectionSnapshot, RuntimeGeneration, RuntimeState, RuntimeTransport,
};
use crate::dns::cache::DnsCache;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use crate::dns::routing::DnsRouter;
use crate::routing::Router;
use tokio::sync::{Mutex, Notify};

struct UnusedPool;

#[async_trait]
impl DnsUpstreamPool for UnusedPool {
    async fn query(&self, _upstream_name: &str, _raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("test upstream is unused")
    }
}

struct LazyBootstrapPool {
    resolver: BootstrapResolver,
    entered: Option<Arc<Notify>>,
    release: Option<Arc<Notify>>,
}

#[async_trait]
impl DnsUpstreamPool for LazyBootstrapPool {
    async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        if let Some(entered) = &self.entered {
            entered.notify_one();
        }
        if let Some(release) = &self.release {
            release.notified().await;
        }
        let ip = honk_outbound::bootstrap::resolve_with(Some(self.resolver), "runtime.test")
            .await?
            .into_iter()
            .find_map(|ip| match ip {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(_) => None,
            })
            .ok_or_else(|| anyhow::anyhow!("test resolver returned no IPv4 address"))?;
        let mut response = raw_query.to_vec();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        ]);
        response.extend_from_slice(&ip.octets());
        Ok(response)
    }
}

#[async_trait]
impl RuntimeTransport for LazyBootstrapPool {
    async fn close(&self) {}
}

#[derive(Default)]
struct ObservedTransport {
    closes: AtomicUsize,
    closed: Notify,
}

#[async_trait]
impl RuntimeTransport for ObservedTransport {
    async fn close(&self) {
        self.closes.fetch_add(1, Ordering::SeqCst);
        self.closed.notify_waiters();
    }
}

fn runtime(generation: u64, route_count: usize) -> (Arc<DnsRuntime>, Arc<ObservedTransport>) {
    runtime_with_outbound(generation, route_count, None)
}

fn runtime_with_outbound(
    generation: u64,
    _route_count: usize,
    outbound_runtime: Option<Arc<honk_outbound::runtime::OutboundRuntimeRegistry>>,
) -> (Arc<DnsRuntime>, Arc<ObservedTransport>) {
    let config = Config::default();
    let dns_router =
        Arc::new(DnsRouter::new_from_dns_config(&config.dns).expect("valid default DNS config"));
    let cache = Arc::new(Mutex::new(DnsCache::new(32)));
    let forwarder = Arc::new(DnsForwarder::new(
        Arc::new(UnusedPool),
        Arc::clone(&cache),
        dns_router,
    ));
    let transport = Arc::new(ObservedTransport::default());
    let router = Arc::new(
        Router::new(&config.routing.rules, &config.routing.default_outbound)
            .expect("valid default router"),
    );
    let runtime = DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(generation),
        udp_query_limit: 256,
        forwarder,
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            generation,
            router,
            Default::default(),
        )),
        outbound_runtime,
        transport: transport.clone(),
    });
    (runtime, transport)
}

fn runtime_with_bootstrap_pool(generation: u64, pool: Arc<LazyBootstrapPool>) -> Arc<DnsRuntime> {
    let mut config = Config::default();
    config.dns.routing.fallback = "generation".to_owned();
    let dns_router =
        Arc::new(DnsRouter::new_from_dns_config(&config.dns).expect("valid test DNS config"));
    let cache = Arc::new(Mutex::new(DnsCache::new(32)));
    let forwarder = Arc::new(
        DnsForwarder::new(
            Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>,
            Arc::clone(&cache),
            dns_router,
        )
        .with_cache_enabled(false),
    );
    let router = Arc::new(
        Router::new(&config.routing.rules, &config.routing.default_outbound)
            .expect("valid default router"),
    );
    DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(generation),
        udp_query_limit: 256,
        forwarder,
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            generation,
            router,
            Default::default(),
        )),
        outbound_runtime: None,
        transport: pool,
    })
}

#[tokio::test]
async fn lazy_bootstrap_resolution_stays_pinned_to_the_runtime_lease() {
    // Given
    let old_server = spawn_bootstrap_server([192, 0, 2, 10]).await;
    let new_server = spawn_bootstrap_server([198, 51, 100, 20]).await;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let old_pool = Arc::new(LazyBootstrapPool {
        resolver: BootstrapResolver::parse(&format!("udp://{old_server}")).unwrap(),
        entered: Some(Arc::clone(&entered)),
        release: Some(Arc::clone(&release)),
    });
    let new_pool = Arc::new(LazyBootstrapPool {
        resolver: BootstrapResolver::parse(&format!("udp://{new_server}")).unwrap(),
        entered: None,
        release: None,
    });
    let provider = Arc::new(DnsServiceProvider::new(runtime_with_bootstrap_pool(
        1, old_pool,
    )));
    let old_lease = provider.acquire();
    let query = crate::dns::forwarder::build_dns_query("example.com", 1);
    let old_query = {
        let query = query.clone();
        tokio::spawn(async move { old_lease.runtime().forwarder().resolve(&query).await })
    };
    entered.notified().await;

    // When
    provider.publish(runtime_with_bootstrap_pool(2, new_pool));
    let new_lease = provider.acquire();
    let new_response = new_lease
        .runtime()
        .forwarder()
        .resolve(&query)
        .await
        .unwrap();
    release.notify_one();
    let old_response = old_query.await.unwrap().unwrap();

    // Then
    assert_eq!(&old_response[old_response.len() - 4..], &[192, 0, 2, 10]);
    assert_eq!(&new_response[new_response.len() - 4..], &[198, 51, 100, 20]);
    provider.shutdown().await;
}

async fn spawn_bootstrap_server(ip: [u8; 4]) -> std::net::SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..2 {
            let mut query = [0u8; 512];
            let (length, peer) = socket.recv_from(&mut query).await.unwrap();
            let query = &query[..length];
            let qtype = u16::from_be_bytes([query[length - 4], query[length - 3]]);
            let mut response = query.to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&u16::from(qtype == 1).to_be_bytes());
            if qtype == 1 {
                response.extend_from_slice(&[
                    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
                ]);
                response.extend_from_slice(&ip);
            }
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    address
}

#[tokio::test]
async fn publication_does_not_wait_for_old_lease_and_drop_awaits_close() {
    // Given: the old generation has an in-flight lease.
    let (old, transport) = runtime(1, 1);
    let provider = DnsServiceProvider::new(old);
    let lease = provider.acquire();
    let (new, _) = runtime(2, 2);

    // When: publication occurs while the old request remains stalled.
    provider.publish(new);

    // Then: new acquisition is immediate and old transport stays open.
    assert_eq!(provider.acquire().runtime().generation().get(), 2);
    assert_eq!(transport.closes.load(Ordering::SeqCst), 0);
    drop(lease);
    tokio::time::timeout(Duration::from_secs(1), transport.closed.notified())
        .await
        .expect("old transport closed after the lease completed");
    assert_eq!(transport.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn retirement_deadline_closes_a_stalled_generation() {
    // Given: a retired generation still has a lease.
    let before = crate::stats::dns_snapshot();
    let (old, transport) = runtime(1, 1);
    let provider = DnsServiceProvider::new(old);
    let _lease = provider.acquire();
    let (new, _) = runtime(2, 2);
    provider.publish(new);
    tokio::task::yield_now().await;

    // When: virtual time reaches the retirement deadline.
    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::task::yield_now().await;

    // Then: the old generation is forcibly closed without wall-clock sleep.
    assert_eq!(transport.closes.load(Ordering::SeqCst), 1);
    assert!(
        crate::stats::dns_snapshot()
            .delta(before)
            .runtime_retirement_timeout
            >= 1
    );
}

#[tokio::test]
async fn fifth_retirement_cancels_oldest_and_retains_four() {
    // Given: the oldest runtime is kept alive by a lease.
    let before = crate::stats::dns_snapshot();
    let oldest_outbound =
        Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap());
    let (oldest, oldest_transport) =
        runtime_with_outbound(0, 0, Some(Arc::clone(&oldest_outbound)));
    let provider = DnsServiceProvider::new(oldest);
    let oldest_lease = provider.acquire();

    // When: five replacement generations are published.
    for generation in 1..=5 {
        let (replacement, _) = runtime(generation, generation as usize);
        provider.publish(replacement);
    }

    // Then: only four retired runtimes remain and the oldest is closed.
    assert_eq!(provider.retired_count(), MAX_RETIRED_RUNTIMES);
    tokio::time::timeout(Duration::from_secs(1), oldest_transport.closed.notified())
        .await
        .expect("oldest generation closed at retirement cap");
    assert_eq!(oldest_lease.runtime().state(), RuntimeState::Closed);
    provider.shutdown().await;
    assert!(
        oldest_outbound.is_shutdown(),
        "cap eviction must force-shutdown its outbound generation"
    );
    assert!(
        crate::stats::dns_snapshot()
            .delta(before)
            .runtime_forced_close
            >= 1
    );
}

#[tokio::test]
async fn explicit_shutdown_awaits_each_generation_transport_once() {
    // Given: one retired runtime and one current runtime.
    let old_outbound =
        Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap());
    let current_outbound =
        Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap());
    let (old, old_transport) = runtime_with_outbound(1, 1, Some(Arc::clone(&old_outbound)));
    let provider = DnsServiceProvider::new(old);
    let (current, current_transport) =
        runtime_with_outbound(2, 2, Some(Arc::clone(&current_outbound)));
    provider.publish(current);

    // When: process shutdown explicitly joins the runtime supervisors.
    provider.shutdown().await;

    // Then: every generation-owned transport is closed exactly once.
    assert_eq!(old_transport.closes.load(Ordering::SeqCst), 1);
    assert_eq!(current_transport.closes.load(Ordering::SeqCst), 1);
    assert!(old_outbound.is_shutdown());
    assert!(current_outbound.is_shutdown());
}

#[tokio::test]
async fn completed_retirement_supervisors_are_reaped_during_publication() {
    let (initial, _) = runtime(0, 0);
    let provider = DnsServiceProvider::new(initial);
    let mut transports = Vec::new();

    for generation in 1..=64 {
        let (replacement, transport) = runtime(generation, generation as usize);
        provider.publish(replacement);
        transports.push(transport);
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while transports[..63]
            .iter()
            .any(|transport| transport.closes.load(Ordering::SeqCst) == 0)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retirement supervisors complete");

    // The next publication synchronously reaps completed JoinSet records,
    // then installs at most the new retirement plus cap-eviction supervisor.
    provider.publish(runtime(65, 65).0);
    assert!(provider.retired_count() <= MAX_RETIRED_RUNTIMES);
    assert!(
        provider.supervisor_count() <= 2,
        "only supervisors from the latest publication may remain"
    );
}
