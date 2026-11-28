fn registry_test_node(name: &str, protocol: NodeProtocol) -> Node {
    if protocol == NodeProtocol::Direct {
        return honk_config::config::Config::builtin_direct_node();
    }
    if protocol == NodeProtocol::Block {
        return honk_config::config::Config::builtin_block_node();
    }
    let host = format!("{name}.example");
    let mut outbound = honk_config::node::OutboundConfig::from_protocol(protocol);
    let credential = "00000000-0000-4000-8000-000000000001".to_string();
    match &mut outbound {
        honk_config::node::OutboundConfig::Vmess(config) => config.uuid = Some(credential.clone()),
        honk_config::node::OutboundConfig::Vless(config) => config.uuid = Some(credential.clone()),
        honk_config::node::OutboundConfig::Tuic(config) => config.uuid = Some(credential.clone()),
        honk_config::node::OutboundConfig::Juicity(config) => config.uuid = Some(credential),
        _ => {}
    }
    let mut node = Node {
        name: name.into(),
        address: format!("{host}:443"),
        host,
        port: 443,
        outbound,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}
use super::*;

/// Closes the QUIC carrier under an open UDP relay and requires both directions to report node failure.
pub(super) async fn assert_udp_carrier_close_is_node_failure(
    conn: quinn::Connection,
    transport: &dyn PacketTransport,
    timeout: std::time::Duration,
) {
    conn.close(quinn::VarInt::from_u32(0), b"carrier closed");
    let error = transport.send_packet(b"query").await.unwrap_err();
    assert_eq!(
        crate::group::ScoreOutcome::from_io_error(&error),
        crate::group::ScoreOutcome::NodeFailure
    );
    let error = tokio::time::timeout(timeout, transport.recv_packet(&mut [0; 64]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        crate::group::ScoreOutcome::from_io_error(&error),
        crate::group::ScoreOutcome::NodeFailure
    );
}

pub(super) async fn assert_pmtud_after_echo(
    conn: &quinn::Connection,
    mut stream: ProxyStream,
    disabled: bool,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let acked_before = conn.stats().path.acked_ack_eliciting_packets;
    let path = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        for byte in 1..=3 {
            stream.stream.write_u8(byte).await.unwrap();
            assert_eq!(stream.stream.read_u8().await.unwrap(), byte);
        }
        // An idle connection can report zero probes; wait for peer ACK progress.
        loop {
            let path = conn.stats().path;
            if path.acked_ack_eliciting_packets > acked_before
                && (disabled || path.sent_plpmtud_probes > 0)
            {
                return path;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timed out waiting for loopback echo, ACK or MTU discovery");
    if disabled {
        assert_eq!(path.sent_plpmtud_probes, 0);
        assert_eq!(path.current_mtu, 1200);
    }
}

#[test]
fn test_registry_default_handlers() {
    let registry = ProxyRegistry::default_resolver().unwrap();
    assert!(registry.handler_count() >= 4);
    assert!(registry.find(NodeProtocol::Socks5).is_some());
    assert!(registry.find(NodeProtocol::Direct).is_some());
    assert!(registry.find(NodeProtocol::Block).is_some());
    assert!(registry.find(NodeProtocol::Trojan).is_some());
    assert!(registry.find(NodeProtocol::SS).is_some());
    assert!(registry.find(NodeProtocol::AnyTLS).is_some());
    assert!(registry.find(NodeProtocol::Hysteria2).is_some());
    #[cfg(feature = "rprx")]
    assert!(registry.find(NodeProtocol::VMess).is_some());
    assert!(registry.find(NodeProtocol::Tuic).is_some());
    assert!(registry.find(NodeProtocol::Juicity).is_some());
}
#[test]
fn packet_error_class_separates_backpressure_from_dead_tunnel() {
    for kind in [
        std::io::ErrorKind::WouldBlock,
        std::io::ErrorKind::Interrupted,
    ] {
        assert_eq!(
            packet_error_class(&std::io::Error::new(kind, "backpressure")),
            PacketErrorClass::Congestion
        );
    }
    assert_eq!(
        packet_error_class(&std::io::Error::from_raw_os_error(libc::ENOBUFS)),
        PacketErrorClass::Congestion
    );
    assert_eq!(
        packet_error_class(&std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "closed",
        )),
        PacketErrorClass::ConnectionDead
    );
    assert_eq!(
        packet_error_class(&std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "operation timeout",
        )),
        PacketErrorClass::Other
    );
    let quic_error = std::io::Error::other(quinn::SendDatagramError::ConnectionLost(
        quinn::ConnectionError::Reset,
    ));
    assert_eq!(
        packet_error_class(&quic_error),
        PacketErrorClass::ConnectionDead
    );
    let too_large = std::io::Error::other(quinn::SendDatagramError::TooLarge);
    assert_eq!(packet_error_class(&too_large), PacketErrorClass::Congestion);
    for (cause, expected) in [
        (
            quinn::SendDatagramError::ConnectionLost(quinn::ConnectionError::Reset),
            PacketErrorClass::ConnectionDead,
        ),
        (
            quinn::SendDatagramError::TooLarge,
            PacketErrorClass::Congestion,
        ),
    ] {
        let error = quic_carrier_io_error(std::io::Error::other(cause));
        let shared = crate::SharedError::new(anyhow::Error::new(error).context("carrier send"));
        let error = std::io::Error::other(std::io::Error::other(shared));
        assert_eq!(packet_error_class(&error), expected);
    }
}

#[test]
fn typed_packet_rejections_survive_io_and_anyhow_context() {
    for (rejection, kind) in [
        (
            PacketRejection::Policy,
            std::io::ErrorKind::PermissionDenied,
        ),
        (
            PacketRejection::InvalidSize,
            std::io::ErrorKind::InvalidInput,
        ),
    ] {
        let io_error = std::io::Error::from(rejection);
        assert_eq!(io_error.kind(), kind);
        assert_eq!(packet_error_class(&io_error), PacketErrorClass::Rejected);
        assert!(is_packet_rejection(
            &anyhow::Error::new(io_error).context("outer context")
        ));
        assert!(is_packet_rejection(
            &anyhow::Error::new(rejection).context("outer context")
        ));
        let nested = std::io::Error::other(std::io::Error::from(rejection));
        assert_eq!(packet_error_class(&nested), PacketErrorClass::Rejected);
        assert!(is_packet_rejection(&anyhow::Error::new(nested)));
    }
    assert_eq!(
        packet_error_class(&std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            PacketRejection::Policy,
        )),
        PacketErrorClass::Rejected
    );
    for kind in [
        std::io::ErrorKind::InvalidInput,
        std::io::ErrorKind::PermissionDenied,
    ] {
        let io_error = std::io::Error::new(kind, "untyped refusal");
        assert_eq!(packet_error_class(&io_error), PacketErrorClass::Other);
        assert!(!is_packet_rejection(&anyhow::Error::new(io_error)));
    }
}

#[test]
fn failure_provenance_survives_shared_io_context_without_losing_cause() {
    use crate::group::ScoreOutcome;
    let failure = TargetFailure(anyhow::Error::new(std::io::Error::from_raw_os_error(
        libc::ECONNREFUSED,
    )));
    let shared = crate::SharedError::new(anyhow::Error::new(failure).context("remote reply"));
    let error = std::io::Error::other(std::io::Error::other(shared));
    assert_eq!(
        ScoreOutcome::from_io_error(&error),
        ScoreOutcome::TargetFailure
    );
    let error = anyhow::Error::new(error).context("caller");
    assert!(target_failure(&error));
    assert_eq!(
        ScoreOutcome::from_error(&error),
        ScoreOutcome::TargetFailure
    );
    assert_eq!(
        error
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(libc::ECONNREFUSED)
    );

    let error = anyhow::Error::new(NodeFailure(anyhow::Error::new(
        quinn::ConnectionError::TimedOut,
    )));
    assert_eq!(ScoreOutcome::from_error(&error), ScoreOutcome::NodeFailure);
    let error = std::io::Error::from(quinn::ReadError::ConnectionLost(
        quinn::ConnectionError::TimedOut,
    ));
    let kind = error.kind();
    assert_eq!(ScoreOutcome::from_io_error(&error), ScoreOutcome::Io(kind));
    let shared = crate::SharedError::new(anyhow::Error::new(error).context("DoQ response"));
    let error = std::io::Error::new(kind, shared);
    assert_eq!(ScoreOutcome::from_io_error(&error), ScoreOutcome::Io(kind));
    assert!(!node_failure(&anyhow::Error::new(error)));

    let error = quic_carrier_io_error(std::io::Error::from(quinn::ReadError::ConnectionLost(
        quinn::ConnectionError::TimedOut,
    )));
    assert_eq!(error.kind(), kind);
    let shared = crate::SharedError::new(anyhow::Error::new(error).context("proxy carrier"));
    let error = std::io::Error::other(std::io::Error::other(shared));
    // An independently shared cause is its own failure, not a fanned-out episode.
    assert_eq!(
        ScoreOutcome::from_io_error(&error),
        ScoreOutcome::NodeFailure
    );
    assert!(matches!(
        anyhow::Error::new(error)
            .root_cause()
            .downcast_ref::<quinn::ConnectionError>(),
        Some(quinn::ConnectionError::TimedOut)
    ));
    for error in [
        std::io::Error::from(quinn::ReadError::Reset(quinn::VarInt::from_u32(0))),
        std::io::Error::from(quinn::WriteError::Stopped(quinn::VarInt::from_u32(0))),
    ] {
        let error = quic_carrier_io_error(error);
        assert_eq!(
            ScoreOutcome::from_io_error(&error),
            ScoreOutcome::Io(std::io::ErrorKind::ConnectionReset),
        );
    }
    let error = anyhow::Error::new(TargetFailure(anyhow::Error::new(
        PacketRejection::Cancelled,
    )));
    assert_eq!(ScoreOutcome::from_error(&error), ScoreOutcome::Cancelled);
    let error = anyhow::Error::new(NodeFailure(anyhow::Error::new(PacketRejection::Capacity)));
    assert_eq!(ScoreOutcome::from_error(&error), ScoreOutcome::Rejected);
    assert!(!target_failure(&anyhow::Error::new(
        std::io::Error::from_raw_os_error(libc::ECONNREFUSED)
    )));
}

/// Without the `rprx` feature a parsed VLESS/VMess node must hit the
/// ordinary no-handler refusal, never a panic.
#[cfg(not(feature = "rprx"))]
#[tokio::test]
async fn rprx_off_refuses_vless_vmess_without_handler() {
    let registry = ProxyRegistry::default_resolver().unwrap();
    for protocol in [NodeProtocol::VLess, NodeProtocol::VMess] {
        assert!(registry.find(protocol).is_none());
        let node = Node {
            outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
            ..Default::default()
        };
        let err = registry
            .dial(
                &node,
                "93.184.216.34:443".parse().unwrap(),
                None,
                Duration::from_secs(1),
            )
            .await
            .expect_err("no handler registered without rprx");
        assert!(err.to_string().contains("No handler for protocol"));
    }
}

#[test]
#[should_panic(expected = "declares UDP without a packet handler")]
fn consistency_rejects_missing_packet_implementation() {
    let direct = Arc::new(DirectHandler::new());
    ProtocolEntry::new(NodeProtocol::Direct, direct).validate_consistency();
}

#[test]
#[should_panic(expected = "generation runtime without a warm handler")]
fn consistency_rejects_missing_warm_implementation() {
    let anytls = Arc::new(AnyTlsHandler::new());
    ProtocolEntry::new(NodeProtocol::AnyTLS, anytls.clone())
        .with_packet(anytls)
        .validate_consistency();
}

#[cfg(feature = "rprx")]
#[tokio::test]
async fn vless_capability_and_policy_are_distinct_in_every_packet_registry_path() {
    let registry = ProxyRegistry::default_resolver().unwrap();
    for policy_rejected in [false, true] {
        let mut node = registry_test_node("udp-gate", NodeProtocol::VLess);
        let vless = node.vless_mut().unwrap();
        if policy_rejected {
            vless.multiplex = honk_config::node::VlessMultiplex::xray(
                -1,
                -1,
                honk_config::node::Udp443Policy::Reject,
            );
        } else {
            vless.network = Some("tcp".into());
        }
        node.id = node.derive_id();
        let target = "8.8.8.8:443".parse().unwrap();

        let error = registry
            .dial_udp_transport(&node, target, None, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert_eq!(is_packet_rejection(&error), policy_rejected);

        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        let error = registry
            .dial_udp_transport_runtime(
                Arc::clone(&generation),
                node.id,
                target,
                None,
                Duration::from_millis(10),
            )
            .await
            .unwrap_err();
        assert_eq!(is_packet_rejection(&error), policy_rejected);
        let error = registry
            .dial_udp_transport_speculative(
                generation,
                node.id,
                target,
                None,
                Duration::from_millis(10),
            )
            .await
            .unwrap_err();
        assert_eq!(is_packet_rejection(&error), policy_rejected);
    }
}

/// The built-in block node carries NodeProtocol::Block; the registry must
/// dispatch it to BlockHandler (regression: block rules silently dialed
/// direct when block shared direct's protocol marker).
#[tokio::test]
async fn test_block_node_dispatches_to_block_handler() {
    let registry = ProxyRegistry::default_resolver().unwrap();
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "block".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Block),
        ..Default::default()
    };
    let target: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let err = registry
        .dial(&node, target, None, Duration::from_secs(1))
        .await
        .expect_err("block node must not dial");
    assert!(err.to_string().contains("blocked"));
    let err = registry
        .dial_udp_transport(&node, target, None, Duration::from_secs(1))
        .await
        .expect_err("block node must not dial UDP");
    assert!(err.to_string().contains("blocked"));
}

/// Regression test for the `Box<dyn AsyncReadWrite>` method-resolution
/// trap: `as_any`/`into_any` must see the inner stream, not the Box.
#[tokio::test]
async fn test_into_tcp_stream_plain_tcp() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let ps = ProxyStream {
        stream: Box::new(tcp),
        target_addr: addr,
        target_domain: None,
    };
    assert!(
        ps.into_tcp_stream().is_ok(),
        "plain TcpStream must downcast"
    );
}

#[tokio::test]
async fn test_raw_fd_plain_tcp() {
    use std::os::unix::io::AsRawFd;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let expected = tcp.as_raw_fd();
    let ps = ProxyStream {
        stream: Box::new(tcp),
        target_addr: addr,
        target_domain: None,
    };
    assert_eq!(ps.raw_fd(), Some(expected));
}

#[tokio::test]
async fn test_raw_fd_none_for_non_tcp() {
    // A stream without a reachable socket (duplex bridge, as used by
    // the WebSocket transport) must report "cannot probe".
    let (client, _server) = tokio::io::duplex(64);
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let ps = ProxyStream {
        stream: Box::new(client),
        target_addr: addr,
        target_domain: None,
    };
    assert_eq!(ps.raw_fd(), None);
}

#[tokio::test]
async fn warm_udp_is_not_applicable_without_reusable_udp_state() {
    let mut nodes = vec![registry_test_node("direct", NodeProtocol::Direct)];
    for (name, protocol) in [
        ("socks", NodeProtocol::Socks5),
        ("ss", NodeProtocol::SS),
        ("trojan", NodeProtocol::Trojan),
    ] {
        nodes.push(registry_test_node(name, protocol));
    }
    let mut tcp_only = registry_test_node("tcp-only-anytls", NodeProtocol::AnyTLS);
    tcp_only.anytls_mut().unwrap().network = Some("tcp".into());
    tcp_only.id = tcp_only.derive_id();
    nodes.push(tcp_only);
    let generation = Arc::new(crate::runtime::OutboundRuntimeRegistry::build(&nodes).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();

    for node in &nodes {
        assert_eq!(
            registry
                .warm_udp(Arc::clone(&generation), node.id, Duration::from_secs(1))
                .await
                .unwrap(),
            WarmOutcome::NotApplicable,
            "{} must not masquerade as a warmable UDP session",
            node.name
        );
    }
}
struct RejectingWarmable;

#[async_trait]
impl WarmableOutbound for RejectingWarmable {
    async fn warm(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        _connect_timeout: Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        anyhow::bail!("warm rejected")
    }
}

struct PendingWarmable {
    started: tokio::sync::mpsc::UnboundedSender<()>,
}

#[async_trait]
impl WarmableOutbound for PendingWarmable {
    async fn warm(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        _connect_timeout: Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        self.started.send(()).unwrap();
        std::future::pending().await
    }
}

#[tokio::test]
async fn cancelled_warm_releases_only_its_inserted_retention() {
    let node = registry_test_node("cancelled-anytls", NodeProtocol::AnyTLS);
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    let runtime = generation.get(&node.id).unwrap();
    let pool = runtime.anytls_pool().unwrap();
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = ProxyRegistry::default_resolver().unwrap();
    registry
        .entries
        .iter_mut()
        .find(|entry| entry.descriptor.protocol == NodeProtocol::AnyTLS)
        .unwrap()
        .warmable = Some(Arc::new(PendingWarmable {
        started: started_tx,
    }));
    let registry = Arc::new(registry);

    let task = tokio::spawn({
        let registry = Arc::clone(&registry);
        let generation = Arc::clone(&generation);
        async move {
            registry
                .warm_session(generation, node.id, Duration::from_secs(1))
                .await
        }
    });
    started_rx.recv().await.unwrap();
    assert!(pool.is_warm_retained());
    task.abort();
    let _ = task.await;
    assert!(!pool.is_warm_retained());

    runtime
        .retain_warm(crate::runtime::WarmRetention::Selector)
        .await
        .commit();
    let task = tokio::spawn({
        let registry = Arc::clone(&registry);
        async move {
            registry
                .warm_session(generation, node.id, Duration::from_secs(1))
                .await
        }
    });
    started_rx.recv().await.unwrap();
    task.abort();
    let _ = task.await;
    assert!(pool.is_warm_retained());
    runtime
        .release_warm(crate::runtime::WarmRetention::Selector)
        .await;
}

#[tokio::test]
async fn failed_warm_releases_its_policy_retention() {
    let node = registry_test_node("failing-anytls", NodeProtocol::AnyTLS);
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    let runtime = generation.get(&node.id).unwrap();
    let pool = runtime.anytls_pool().unwrap();
    let mut registry = ProxyRegistry::default_resolver().unwrap();
    registry
        .entries
        .iter_mut()
        .find(|entry| entry.descriptor.protocol == NodeProtocol::AnyTLS)
        .unwrap()
        .warmable = Some(Arc::new(RejectingWarmable));

    let error = registry
        .warm_session(Arc::clone(&generation), node.id, Duration::from_secs(1))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("warm rejected"));
    assert!(!pool.is_warm_retained());

    runtime
        .retain_warm(crate::runtime::WarmRetention::Selector)
        .await
        .commit();
    assert!(pool.is_warm_retained());
    registry
        .warm_session(generation, node.id, Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(pool.is_warm_retained());
    runtime
        .release_warm(crate::runtime::WarmRetention::Selector)
        .await;
    assert!(!pool.is_warm_retained());
}

#[tokio::test]
async fn warm_udp_rejects_a_shutdown_generation_before_dispatch() {
    let node = registry_test_node("old-anytls", NodeProtocol::AnyTLS);
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    generation.shutdown().await;

    assert!(
        ProxyRegistry::default_resolver()
            .unwrap()
            .warm_udp(generation, node.id, Duration::from_secs(1))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn speculative_udp_rejects_a_shutdown_generation_before_dispatch() {
    let node = registry_test_node("direct", NodeProtocol::Direct);
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    generation.shutdown().await;

    assert!(
        ProxyRegistry::default_resolver()
            .unwrap()
            .dial_udp_transport_speculative(
                generation,
                node.id,
                "127.0.0.1:53".parse().unwrap(),
                None,
                Duration::from_secs(1),
            )
            .await
            .is_err()
    );
}
