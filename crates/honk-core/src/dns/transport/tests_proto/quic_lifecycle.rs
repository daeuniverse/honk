use super::*;
use crate::dns::transport::DnsSocketBudget;

fn quic_runtime_with_fault(
    remote: SocketAddr,
    protocol: DnsProtocol,
    fault: Arc<PacketWorkerFault>,
    dial_timeout: Duration,
    socket_budget: DnsSocketBudget,
) -> (
    Arc<crate::dns::runtime::DnsServiceProvider>,
    Arc<UpstreamPool>,
) {
    use crate::dns::runtime::{
        DnsRuntime, DnsRuntimeParts, DnsServiceProvider, RoutingProjectionSnapshot,
        RuntimeGeneration,
    };

    let endpoint = DnsEndpoint::parse(&remote.to_string(), protocol, Some("localhost")).unwrap();
    let fixture = proxied_quic_fixture_for_protocol(endpoint, NodeProtocol::Trojan, Some(fault));
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
        .with_socket_budget(socket_budget)
        .with_timeouts(Duration::from_millis(50), dial_timeout),
    );
    pool.set_runtime_generation(proxy.generation.unwrap())
        .unwrap();
    let runtime = DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(1),
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
            let budget = DnsSocketBudget::new(1);
            let (provider, pool) = quic_runtime_with_fault(
                peer.local_addr().unwrap(),
                protocol,
                Arc::clone(&fault),
                timeout,
                budget.clone(),
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
            assert_eq!(
                budget.available_proxy_streams(),
                0,
                "non-raw proxy packet setup was not logically charged"
            );
            assert_eq!(
                budget.available_sockets(),
                1,
                "non-raw proxy must not consume a nested raw socket credit"
            );
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
            assert_eq!(
                budget.available_proxy_streams(),
                0,
                "unpublished {protocol:?} released logical lease before its worker"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut pause)
                    .await
                    .is_err(),
                "pause acknowledged while an unpublished {protocol:?} worker was still releasing"
            );
            pause.abort();
            assert!(pause.await.unwrap_err().is_cancelled());
            assert!(!fault.completed.load(Ordering::Acquire));
            assert_eq!(budget.available_proxy_streams(), 0);
            release.send(()).unwrap();
            provider.finish_pause().await.unwrap();
            assert!(fault.completed.load(Ordering::Acquire));
            assert_eq!(
                budget.available_proxy_streams(),
                1,
                "joined adapter leaked its logical lease"
            );
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
        let budget = DnsSocketBudget::new(1);
        let (provider, pool) = quic_runtime_with_fault(
            peer.local_addr().unwrap(),
            protocol,
            fault,
            Duration::from_millis(50),
            budget.clone(),
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
        assert_eq!(
            budget.available_proxy_streams(),
            1,
            "panicked adapter leaked its logical lease"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_non_raw_upstream_bootstrap_shares_the_two_credit_bound() {
    for protocol in [DnsProtocol::Quic, DnsProtocol::H3] {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bootstrap = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = honk_outbound::bootstrap::BootstrapResolver::parse(&format!(
            "udp://{}",
            bootstrap.local_addr().unwrap()
        ))
        .unwrap();
        let budget = DnsSocketBudget::new(2);
        let fault = Arc::new(PacketWorkerFault::default());
        let fixture = proxied_quic_fixture_for_protocol(
            DnsEndpoint::parse(
                &peer.local_addr().unwrap().to_string(),
                protocol,
                Some("localhost"),
            )
            .unwrap(),
            NodeProtocol::Trojan,
            Some(Arc::clone(&fault)),
        );
        let mut dial = fixture.dial;
        dial.socket_budget = budget.clone();
        dial.dial_timeout = Duration::from_secs(2);
        let target = |host: &str| {
            DnsEndpoint::parse_with_resolver(
                &format!("{host}:{}", peer.local_addr().unwrap().port()),
                protocol,
                Some("localhost"),
                Some(resolver),
                honk_config::dns::DnsStrategy::Both,
            )
            .unwrap()
        };
        let endpoints = super::super::SharedQuicEndpoint::new();
        let config = insecure_quic_config(match protocol {
            DnsProtocol::Quic => b"doq",
            DnsProtocol::H3 => b"h3",
            _ => unreachable!(),
        })
        .await;
        let first_target = target("first-cold.invalid");
        let first = super::super::quic_connect_endpoint(
            &dial,
            &endpoints,
            &config,
            &first_target,
            tokio::time::Instant::now() + dial.dial_timeout,
            "cold non-raw QUIC",
        );
        let mut first = Box::pin(first);
        let mut packet = [0_u8; 512];
        let mut qtypes = Vec::with_capacity(2);
        for _ in 0..2 {
            let (length, _) = tokio::select! {
                result = &mut first => panic!("silent cold bootstrap completed: {result:?}"),
                received = tokio::time::timeout(Duration::from_secs(1), bootstrap.recv_from(&mut packet)) => {
                    received.unwrap().unwrap()
                },
            };
            assert!(packet[12..length - 4].starts_with(b"\x0afirst-cold\x07invalid\0"));
            qtypes.push(u16::from_be_bytes([packet[length - 4], packet[length - 3]]));
        }
        qtypes.sort_unstable();
        assert_eq!(qtypes, [1, 28]);
        assert_eq!(budget.available_sockets(), 0);
        assert_eq!(budget.available_proxy_streams(), 2);
        assert_eq!(fixture.runtime_dials.load(Ordering::SeqCst), 0);

        let error = super::super::quic_connect_endpoint(
            &dial,
            &endpoints,
            &config,
            &target("second-cold.invalid"),
            tokio::time::Instant::now() + Duration::from_millis(30),
            "cold non-raw QUIC",
        )
        .await
        .unwrap_err();
        assert_eq!(
            honk_outbound::proxy::packet_rejection(&error),
            Some(honk_outbound::proxy::PacketRejection::Capacity)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), bootstrap.recv_from(&mut packet))
                .await
                .is_err(),
            "capacity-blocked distinct hostname emitted a bootstrap packet"
        );
        assert_eq!(fixture.runtime_dials.load(Ordering::SeqCst), 0);
        drop(first);
        assert_eq!(budget.available_sockets(), 2);

        let next_target = target("next-cold.invalid");
        let next = super::super::quic_connect_endpoint(
            &dial,
            &endpoints,
            &config,
            &next_target,
            tokio::time::Instant::now() + dial.dial_timeout,
            "cold non-raw QUIC",
        );
        let mut next = Box::pin(next);
        for _ in 0..2 {
            let (length, source) = tokio::select! {
                result = &mut next => panic!("responsive bootstrap did not run first: {result:?}"),
                received = tokio::time::timeout(Duration::from_secs(1), bootstrap.recv_from(&mut packet)) => {
                    received.unwrap().unwrap()
                },
            };
            assert!(packet[12..length - 4].starts_with(b"\x09next-cold\x07invalid\0"));
            let qtype = u16::from_be_bytes([packet[length - 4], packet[length - 3]]);
            let mut response = packet[..length].to_vec();
            response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            response[6..8].copy_from_slice(&u16::from(qtype == 1).to_be_bytes());
            if qtype == 1 {
                response.extend_from_slice(&[
                    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 127, 0,
                    0, 1,
                ]);
            }
            bootstrap.send_to(&response, source).await.unwrap();
        }
        tokio::select! {
            result = &mut next => panic!("setup finished before packet adapter admission: {result:?}"),
            entered = tokio::time::timeout(Duration::from_secs(1), fault.entered.notified()) => {
                entered.expect("next non-raw cold setup did not open its packet adapter");
            }
        }
        assert_eq!(fixture.active.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.runtime_dials.load(Ordering::SeqCst), 1);
        assert_eq!(budget.available_proxy_streams(), 1);
        assert_eq!(budget.available_sockets(), 2);
        drop(next);
        endpoints.close().await;
        assert_eq!(fixture.active.load(Ordering::SeqCst), 0);
        assert_eq!(budget.available_proxy_streams(), 2);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_raw_quic_capacity_precedes_real_trojan_bootstrap() {
    const CHILD: &str = "HONK_DNS_TROJAN_BOOTSTRAP_GATE_CHILD";
    const NAME: &str = "dns::transport::tests_proto::quic_lifecycle::non_raw_quic_capacity_precedes_real_trojan_bootstrap";
    if crate::test_support::run_exact_in_child(CHILD, NAME) {
        return;
    }

    struct RestoreGlobal(Option<honk_outbound::bootstrap::BootstrapResolver>);
    impl Drop for RestoreGlobal {
        fn drop(&mut self) {
            honk_outbound::bootstrap::set_global(self.0);
        }
    }

    let bootstrap = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let previous = honk_outbound::bootstrap::global();
    honk_outbound::bootstrap::set_global(honk_outbound::bootstrap::BootstrapResolver::parse(
        &format!("udp://{}", bootstrap.local_addr().unwrap()),
    ));
    let _restore = RestoreGlobal(previous);
    for protocol in [DnsProtocol::Quic, DnsProtocol::H3] {
        let nodes = ["first-node.invalid", "second-node.invalid"]
            .into_iter()
            .enumerate()
            .map(|(index, host)| {
                let mut node = Node {
                    name: format!("trojan-{index}"),
                    address: format!("{host}:443"),
                    host: host.into(),
                    port: 443,
                    outbound: honk_config::node::OutboundConfig::Trojan(
                        honk_config::node::TrojanConfig {
                            password: Some("test-password".into()),
                            tls: honk_config::node::TlsOptions {
                                enabled: false,
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                    ),
                    ..Default::default()
                };
                node.id = node.derive_id();
                node
            })
            .collect::<Vec<_>>();
        let upstreams = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| DnsUpstream {
                name: format!("upstream-{index}"),
                address: "127.0.0.1:853".into(),
                protocol,
                tls_server_name: Some("localhost".into()),
                outbound: Some(node.name.clone()),
            })
            .collect::<Vec<_>>();
        let registry = Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap());
        let budget = DnsSocketBudget::new(1);
        let pool = Arc::new(
            UpstreamPool::new_with_proxy(
                &upstreams,
                empty_router(),
                Some(registry),
                nodes.clone(),
                vec![],
            )
            .unwrap()
            .with_socket_budget(budget.clone())
            .with_timeouts(Duration::from_millis(100), Duration::from_secs(1)),
        );
        pool.set_runtime_generation(Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&nodes).unwrap(),
        ))
        .unwrap();
        let query = build_dns_query("literal.example", 1);
        let first = pool.query("upstream-0", &query);
        let mut first = Box::pin(first);
        let mut packet = [0_u8; 512];
        let mut qtypes = Vec::with_capacity(2);
        for _ in 0..2 {
            let (length, _) = tokio::select! {
                result = &mut first => panic!("silent first-node bootstrap completed: {result:?}"),
                received = tokio::time::timeout(Duration::from_secs(1), bootstrap.recv_from(&mut packet)) => {
                    received.unwrap().unwrap()
                },
            };
            assert_eq!(&packet[12..length - 4], b"\x0afirst-node\x07invalid\0");
            qtypes.push(u16::from_be_bytes([packet[length - 4], packet[length - 3]]));
        }
        qtypes.sort_unstable();
        assert_eq!(qtypes, [1, 28]);
        assert_eq!(budget.available_proxy_streams(), 0);
        assert_eq!(budget.available_sockets(), 1);

        let error = pool.query("upstream-1", &query).await.unwrap_err();
        assert_eq!(
            honk_outbound::proxy::packet_rejection(&error),
            Some(honk_outbound::proxy::PacketRejection::Capacity)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), bootstrap.recv_from(&mut packet))
                .await
                .is_err(),
            "capacity-blocked second Trojan node emitted a bootstrap packet"
        );
        drop(first);
        assert_eq!(budget.available_proxy_streams(), 1);

        let second = pool.query("upstream-1", &query);
        let mut second = Box::pin(second);
        let mut qtypes = Vec::with_capacity(2);
        for _ in 0..2 {
            let (length, _) = tokio::select! {
                result = &mut second => panic!("silent second-node bootstrap completed: {result:?}"),
                received = tokio::time::timeout(Duration::from_secs(1), bootstrap.recv_from(&mut packet)) => {
                    received.unwrap().unwrap()
                },
            };
            assert_eq!(&packet[12..length - 4], b"\x0bsecond-node\x07invalid\0");
            qtypes.push(u16::from_be_bytes([packet[length - 4], packet[length - 3]]));
        }
        qtypes.sort_unstable();
        assert_eq!(qtypes, [1, 28]);
        assert_eq!(budget.available_proxy_streams(), 0);
        drop(second);
        assert_eq!(budget.available_proxy_streams(), 1);
        pool.close().await;
    }
}
