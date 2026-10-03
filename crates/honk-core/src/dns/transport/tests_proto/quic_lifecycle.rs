use super::*;

fn quic_runtime_with_fault(
    remote: SocketAddr,
    protocol: DnsProtocol,
    fault: Arc<PacketWorkerFault>,
    dial_timeout: Duration,
) -> (
    Arc<crate::dns::runtime::DnsServiceProvider>,
    Arc<UpstreamPool>,
) {
    use crate::dns::runtime::{
        DnsRuntime, DnsRuntimeParts, DnsServiceProvider, RoutingProjectionSnapshot,
        RuntimeGeneration,
    };

    let endpoint = DnsEndpoint::parse(&remote.to_string(), protocol, Some("localhost")).unwrap();
    let fixture = proxied_quic_fixture_with_fault(endpoint, Some(fault));
    let proxy = fixture.dial.proxy.unwrap();
    let upstream = DnsUpstream {
        outbound: Some(proxy.node.name.clone()),
        ..make_upstream("proxy", &remote.to_string(), protocol)
    };
    let router = empty_router();
    let pool = Arc::new(
        UpstreamPool::new_with_proxy(
            &[upstream],
            Arc::clone(&router),
            Some(proxy.registry),
            vec![proxy.node],
            vec![],
        )
        .unwrap()
        .with_timeouts(Duration::from_millis(50), dial_timeout),
    );
    pool.set_runtime_generation(proxy.generation.unwrap())
        .unwrap();
    let runtime = DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(1),
        udp_query_limit: 256,
        forwarder: Arc::new(DnsForwarder::new(
            pool.clone(),
            Arc::new(tokio::sync::Mutex::new(DnsCache::new(16))),
            router,
        )),
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            1,
            Arc::new(crate::routing::Router::new(&[], "direct").unwrap()),
        )),
        outbound_runtime: None,
        transport: pool.clone(),
    });
    let provider = Arc::new(DnsServiceProvider::new(runtime));
    #[cfg(feature = "native-api")]
    provider.enable_lifecycle();
    (provider, pool)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_and_cancelled_quic_handshakes_keep_adapter_cleanup_in_dns_pause() {
    for protocol in [DnsProtocol::Quic, DnsProtocol::H3] {
        for cancel_handshake in [false, true] {
            let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (release, blocked) = std::sync::mpsc::channel();
            let fault = Arc::new(PacketWorkerFault {
                release: parking_lot::Mutex::new(Some(blocked)),
                ..Default::default()
            });
            let timeout = if cancel_handshake {
                Duration::from_secs(60)
            } else {
                Duration::from_millis(50)
            };
            let (provider, pool) = quic_runtime_with_fault(
                peer.local_addr().unwrap(),
                protocol,
                Arc::clone(&fault),
                timeout,
            );
            let lease = provider.try_acquire().unwrap();
            let query = tokio::spawn(async move {
                lease
                    .run(std::pin::pin!(
                        pool.query("proxy", &build_dns_query("blocked.example", 1))
                    ))
                    .await
            });
            tokio::time::timeout(Duration::from_secs(2), fault.entered.notified())
                .await
                .unwrap();
            if cancel_handshake {
                provider.begin_pause();
                assert!(query.await.unwrap().is_err());
            } else {
                assert!(query.await.unwrap().unwrap().is_err());
                provider.begin_pause();
            }
            let pausing = Arc::clone(&provider);
            let mut pause = tokio::spawn(async move { pausing.finish_pause().await });
            tokio::time::timeout(Duration::from_secs(2), fault.dropping.notified())
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut pause)
                    .await
                    .is_err(),
                "pause acknowledged while an unpublished {protocol:?} worker was still releasing"
            );
            pause.abort();
            assert!(pause.await.unwrap_err().is_cancelled());
            assert!(!fault.completed.load(Ordering::Acquire));
            release.send(()).unwrap();
            provider.finish_pause().await.unwrap();
            assert!(fault.completed.load(Ordering::Acquire));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_adapter_panic_is_a_sticky_dns_pause_failure() {
    for protocol in [DnsProtocol::Quic, DnsProtocol::H3] {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fault = Arc::new(PacketWorkerFault {
            panic: std::sync::atomic::AtomicBool::new(true),
            ..Default::default()
        });
        let (provider, pool) = quic_runtime_with_fault(
            peer.local_addr().unwrap(),
            protocol,
            fault,
            Duration::from_millis(50),
        );
        let lease = provider.try_acquire().unwrap();
        assert!(
            lease
                .run(std::pin::pin!(
                    pool.query("proxy", &build_dns_query("panic.example", 1))
                ))
                .await
                .unwrap()
                .is_err()
        );
        drop(lease);
        provider.begin_pause();
        for _ in 0..2 {
            assert!(matches!(
                provider.finish_pause().await,
                Err(crate::dns::runtime::DnsPauseError::TaskFailed)
            ));
        }
    }
}
