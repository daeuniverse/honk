use super::*;
use crate::dns::forwarder::build_dns_query;
use crate::dns::query::IngressProfile;
use crate::dns::runtime::DnsPauseError;
use crate::dns::service::DnsService;
use crate::dns::upstream_pool::UpstreamPool;
use honk_config::dns::DnsUpstream;
use honk_config::types::DnsProtocol;
use tokio::io::AsyncReadExt;

fn wire_runtime(
    generation: u64,
    address: std::net::SocketAddr,
    protocol: DnsProtocol,
    cache: Arc<Mutex<DnsCache>>,
) -> (Arc<DnsRuntime>, Arc<UpstreamPool>) {
    let mut config = Config::default();
    config.dns.routing.fallback = "default".to_owned();
    config.dns.upstream = vec![DnsUpstream {
        name: "default".to_owned(),
        address: address.to_string(),
        protocol,
        tls_server_name: None,
        outbound: None,
    }];
    let dns_router = Arc::new(DnsRouter::new_from_dns_config(&config.dns).unwrap());
    let pool = Arc::new(UpstreamPool::new(&config.dns.upstream, Arc::clone(&dns_router)).unwrap());
    let forwarder = Arc::new(DnsForwarder::new(pool.clone(), cache, dns_router));
    let router = Arc::new(Router::new(&[], "direct").unwrap());
    (
        DnsRuntime::new(DnsRuntimeParts {
            generation: RuntimeGeneration::new(generation),
            udp_query_limit: 256,
            forwarder,
            routing_projection: Arc::new(RoutingProjectionSnapshot::new(generation, router)),
            outbound_runtime: None,
            transport: pool.clone(),
        }),
        pool,
    )
}

fn answer(query: &[u8], ip: [u8; 4]) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    response.extend_from_slice(&ip);
    response
}

#[tokio::test]
async fn pause_closes_wire_query_but_waits_for_its_lease() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (entered, wire_entered) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let size = stream.read_u16().await.unwrap();
        let mut query = vec![0; usize::from(size)];
        stream.read_exact(&mut query).await.unwrap();
        entered.send(()).unwrap();
        assert_eq!(
            stream.read(&mut [0; 1]).await.unwrap(),
            0,
            "paused DNS socket closes at peer"
        );
    });
    let cache = Arc::new(Mutex::new(DnsCache::new(32)));
    let saved = answer(&build_dns_query("saved.example", 1), [192, 0, 2, 1]);
    cache
        .lock()
        .await
        .put("saved".to_owned(), saved.clone(), 60);
    let (old, _) = wire_runtime(1, address, DnsProtocol::Tcp, Arc::clone(&cache));
    let provider = Arc::new(DnsServiceProvider::new(Arc::clone(&old)));
    let service = DnsService::with_provider(Arc::clone(&provider));
    #[cfg(feature = "native-api")]
    provider.enable_lifecycle();
    let lease = provider.try_acquire().unwrap();
    let release = Arc::new(Notify::new());
    let query_release = Arc::clone(&release);
    let (cancelled, cancellation) = tokio::sync::oneshot::channel();
    let query_service = service.clone();
    let query = tokio::spawn(async move {
        let result = query_service
            .resolve_client_outcome_with_runtime(
                &lease,
                &build_dns_query("blocked.example", 1),
                crate::dns::query::DnsRequestMeta::EMPTY,
                IngressProfile::Api,
                None,
            )
            .await;
        assert_eq!(
            honk_outbound::proxy::packet_rejection(&result.unwrap_err()),
            Some(honk_outbound::proxy::PacketRejection::Cancelled)
        );
        cancelled.send(()).unwrap();
        query_release.notified().await;
        drop(lease);
    });
    tokio::time::timeout(Duration::from_secs(2), wire_entered)
        .await
        .unwrap()
        .unwrap();
    provider.begin_pause();
    tokio::time::timeout(Duration::from_secs(2), cancellation)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
    let mut waiting = Box::pin(provider.finish_pause());
    assert!(
        futures::poll!(waiting.as_mut()).is_pending(),
        "socket closure is not lease completion"
    );
    drop(waiting);
    assert_eq!(old.lease_count(), 1);
    assert!(provider.try_acquire().is_err());
    assert!(
        service
            .resolve_name_with_fallback("paused.example", |_| async {
                panic!("paused queries must not enter bootstrap fallback");
            })
            .await
            .is_err()
    );
    assert!(
        service
            .resolve_name_for_source("paused.example", "192.0.2.1:53".parse().unwrap())
            .await
            .is_err()
    );
    #[cfg(feature = "native-api")]
    assert!(matches!(
        service
            .diagnostic(
                "paused.example",
                &[1],
                &crate::dns::forwarder::ResolveOptions::default(),
                tokio::time::Instant::now() + Duration::from_secs(1)
            )
            .await,
        Err(crate::dns::service::DiagnosticError::Unavailable)
    ));
    release.notify_one();
    query.await.unwrap();
    provider.finish_pause().await.unwrap();
    assert_eq!(old.lease_count(), 0);
    assert!(Arc::ptr_eq(&cache, &service.cache()));
    assert_eq!(
        service.cache().lock().await.get("saved").unwrap().response,
        saved
    );
    service.flush_cache().await.unwrap();
    assert!(cache.lock().await.is_empty());
}

#[tokio::test]
async fn pause_cancels_bootstrap_fallback_under_the_original_query_lease() {
    let (current, _) = runtime(1, 0);
    let provider = Arc::new(DnsServiceProvider::new(Arc::clone(&current)));
    #[cfg(feature = "native-api")]
    provider.enable_lifecycle();
    let service = DnsService::with_provider(Arc::clone(&provider));
    let entered = Arc::new(Notify::new());
    let fallback_entered = Arc::clone(&entered);
    let query = tokio::spawn(async move {
        service
            .resolve_name_with_fallback("fallback.example", |_| async move {
                fallback_entered.notify_one();
                std::future::pending::<anyhow::Result<Vec<std::net::IpAddr>>>().await
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    assert_eq!(current.lease_count(), 1);
    provider.begin_pause();
    let error = query.await.unwrap().unwrap_err();
    assert_eq!(
        honk_outbound::proxy::packet_rejection(&error),
        Some(honk_outbound::proxy::PacketRejection::Cancelled)
    );
    provider.finish_pause().await.unwrap();
    assert_eq!(current.lease_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn pause_retains_evicted_lease_cleanup_and_deadline_failure_after_wait_cancellation() {
    let transport = Arc::new(BlockingTransport::default());
    let oldest = prefetch_runtime(Arc::clone(&transport));
    let provider = DnsServiceProvider::with_deadline(Arc::clone(&oldest), Duration::from_secs(1));
    let lease = provider.try_acquire().unwrap();
    oldest
        .forwarder()
        .prefetch(&["background.example".to_owned()]);
    transport.entered.notified().await;
    for generation in 2..=6 {
        provider.publish(runtime(generation, 0).0);
    }
    provider.begin_pause();
    let mut waiting = Box::pin(provider.finish_pause());
    assert!(futures::poll!(waiting.as_mut()).is_pending());
    drop(waiting);
    tokio::time::advance(Duration::from_secs(2)).await;
    drop(lease);
    assert!(matches!(
        provider.finish_pause().await,
        Err(DnsPauseError::Deadline)
    ));
    assert_eq!(oldest.lease_count(), 0);
    assert_eq!(transport.query_drop_order.load(Ordering::Acquire), 1);
    assert_eq!(transport.close_order.load(Ordering::Acquire), 2);
    provider.shutdown().await;
}

#[tokio::test]
async fn cleanup_task_failure_does_not_acknowledge_pause() {
    struct FailedTransport;
    #[async_trait]
    impl RuntimeTransport for FailedTransport {
        async fn close(&self) {
            panic!("injected DNS transport cleanup failure");
        }
    }
    let (mut current, _) = runtime(1, 0);
    Arc::get_mut(&mut current).unwrap().parts.transport = Arc::new(FailedTransport);
    let provider = DnsServiceProvider::new(current);
    provider.begin_pause();
    assert!(matches!(
        provider.finish_pause().await,
        Err(DnsPauseError::TaskFailed)
    ));
    assert!(matches!(
        provider.finish_pause().await,
        Err(DnsPauseError::TaskFailed)
    ));
    assert!(provider.try_acquire().is_err());
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn pause_joins_started_blocking_lookup_work_after_waiter_cancellation() {
    let (current, _) = runtime(1, 0);
    let provider = DnsServiceProvider::new(Arc::clone(&current));
    provider.enable_lifecycle();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let finished = Arc::clone(&completed);
    current
        .network_tasks()
        .spawn_blocking(move || {
            entered.send(()).unwrap();
            blocked.recv().unwrap();
            finished.store(true, Ordering::Release);
        })
        .expect("live DNS owner admits blocking lookup work");
    started.await.unwrap();
    provider.begin_pause();
    let mut waiting = Box::pin(provider.finish_pause());
    assert!(futures::poll!(waiting.as_mut()).is_pending());
    drop(waiting);
    assert!(!completed.load(Ordering::Acquire));
    release.send(()).unwrap();
    provider.finish_pause().await.unwrap();
    assert!(completed.load(Ordering::Acquire));
    assert!(
        current
            .network_tasks()
            .spawn_blocking(|| {
                panic!("closed DNS owner must not start a new system lookup");
            })
            .is_none()
    );
}
