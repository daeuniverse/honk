use crate::control::*;
use honk_config::node::{Group, Node, OutboundConfig};
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_config::types::NodeProtocol;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

type CapturedDatagram = (String, Vec<u8>);

#[derive(Debug)]
struct CaptureHandler {
    sent: tokio::sync::mpsc::UnboundedSender<CapturedDatagram>,
}

#[derive(Debug)]
struct CaptureTransport {
    owner: String,
    relay: SocketAddr,
    sent: tokio::sync::mpsc::UnboundedSender<CapturedDatagram>,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::TcpOutbound for CaptureHandler {
    async fn dial(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        anyhow::bail!("TCP is not used by UDP ownership tests")
    }
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketOutbound for CaptureHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn honk_outbound::proxy::PacketTransport>> {
        Ok(Arc::new(CaptureTransport {
            owner: node.name.clone(),
            relay: target,
            sent: self.sent.clone(),
        }))
    }
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketTransport for CaptureTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.sent
            .send((self.owner.clone(), data.to_vec()))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }
}

fn node(name: &str, port: u16) -> Node {
    let mut node = Node {
        name: name.into(),
        address: "127.0.0.1".into(),
        port,
        outbound: OutboundConfig::from_protocol(NodeProtocol::Socks5),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn fixture(
    handoffs: &[(SocketAddr, RoutingResult)],
) -> (
    udp_ingress::UdpLoopState,
    tokio::sync::mpsc::UnboundedReceiver<CapturedDatagram>,
    Arc<AtomicUsize>,
) {
    let alpha = node("alpha-node", 10001);
    let beta = node("beta-node", 10002);
    let mut config = Config {
        nodes: vec![alpha.clone(), beta.clone()],
        groups: vec![
            Group {
                name: "alpha".into(),
                nodes: vec![alpha.id],
                ..Default::default()
            },
            Group {
                name: "beta".into(),
                nodes: vec![beta.id],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    config.global.dial_mode = "ip".into();
    config.routing.default_outbound = "alpha".into();
    config.routing.rules.push(RoutingRule {
        name: "stale-dscp-must-not-route".into(),
        condition: RoutingCondition {
            dscp: vec!["46".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("beta".into()),
        priority: 0,
        must: false,
        mark: 0,
    });
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let (sent, received) = tokio::sync::mpsc::unbounded_channel();
    let handler = Arc::new(CaptureHandler { sent });
    let mut registry = ProxyRegistry::new();
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(NodeProtocol::Socks5, handler.clone())
            .with_packet(handler),
    );
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let routing_generation = backend.routing_policy_generation() + 1;
    for (client, result) in handoffs {
        let tuples = build_tuples_key(
            super::addr("203.0.113.53:53").ip(),
            53,
            client.ip(),
            client.port(),
            17,
        );
        let key: [u8; 40] = super::bytes_of(&tuples).try_into().expect("tuple key");
        backend.routing_handoffs.lock().insert(
            key,
            RoutingHandoffEntry {
                routing_generation,
                result: *result,
                ..Default::default()
            },
        );
    }
    let mut plane = ControlPlane::new(
        config,
        Box::new(backend),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        super::support::udp_test_forwarder(),
    )
    .unwrap();
    plane.udp_pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        8,
        Arc::new(super::support::UdpTestReplySocketFactory),
    ));
    let dns_queries = Arc::new(AtomicUsize::new(0));
    plane.dns_controller =
        super::production_dns_controller(Arc::clone(&dns_queries), super::dns_response_payload());
    let drain = Arc::new(DrainTracker::new());
    let state = udp_ingress::UdpLoopState {
        udp_pool: Arc::clone(&plane.udp_pool),
        stats: Arc::clone(&plane.stats),
        udp_concurrency_limit: Arc::clone(&plane.udp_concurrency_limit),
        dns_controller: Arc::clone(&plane.dns_controller),
        drain,
        requires_dns_route_mark: true,
        handle: plane.spawn_handle(),
    };
    (state, received, dns_queries)
}

fn recv_meta(route: Option<UdpDnsRoute>) -> sockets::UdpRecvMeta {
    let original_dst = super::addr("203.0.113.53:53");
    sockets::UdpRecvMeta {
        original_dst_cmsg: Some(original_dst),
        packet_dst_ip: Some(original_dst.ip()),
        packet_ifindex: Some(1),
        packet_mark: route.map(UdpDnsRoute::to_mark),
        local_addr: super::addr("0.0.0.0:15000"),
    }
}

async fn dispatch(
    state: &udp_ingress::UdpLoopState,
    client: SocketAddr,
    payload: &[u8],
    route: Option<UdpDnsRoute>,
) {
    state
        .dispatch_datagram_at(
            payload,
            client,
            &recv_meta(route),
            udp_endpoint::queue_now(),
        )
        .await;
}

async fn sent(
    received: &mut tokio::sync::mpsc::UnboundedReceiver<CapturedDatagram>,
) -> CapturedDatagram {
    tokio::time::timeout(Duration::from_secs(1), received.recv())
        .await
        .expect("raw UDP packet must reach its selected transport")
        .expect("capture transport must remain live")
}

#[tokio::test]
async fn marked_udp_dns_dispatches_raw_bytes_to_the_packet_owner() {
    let (state, mut received, dns_queries) = fixture(&[]);
    let generation = state.handle.ebpf.read().await.routing_policy_generation();
    let alpha = UdpDnsRoute::new(OutboundIndex::UserBase as u8, generation).unwrap();
    let beta = UdpDnsRoute::new(OutboundIndex::UserBase as u8 + 1, generation).unwrap();
    let client = super::addr("10.0.0.2:53000");
    let nonmust = UdpDnsRoute::new(OutboundIndex::ControlPlaneRouting as u8, generation).unwrap();

    dispatch(&state, client, b"not dns: alpha", Some(alpha)).await;
    assert_eq!(
        sent(&mut received).await,
        ("alpha-node".into(), b"not dns: alpha".to_vec())
    );

    dispatch(&state, client, &super::dns_query_payload(), Some(nonmust)).await;

    dispatch(&state, client, b"wrong owner", Some(beta)).await;
    dispatch(&state, client, b"accepted sentinel", Some(alpha)).await;
    assert_eq!(
        sent(&mut received).await,
        ("alpha-node".into(), b"accepted sentinel".to_vec()),
        "a rejected Ready-owner mismatch must not precede the accepted same-flow sentinel"
    );

    let beta_client = super::addr("10.0.0.3:53000");
    dispatch(&state, beta_client, b"not dns: beta", Some(beta)).await;
    assert_eq!(
        sent(&mut received).await,
        ("beta-node".into(), b"not dns: beta".to_vec())
    );

    assert!(state.udp_pool.shutdown().await);
    assert_eq!(
        dns_queries.load(Ordering::SeqCst),
        1,
        "valid nonmust DNS must be consumed by the DNS controller"
    );
}

#[tokio::test]
async fn marked_udp_dns_rejects_stale_missing_and_unknown_owners_before_send() {
    let (state, mut received, dns_queries) = fixture(&[]);
    let generation = state.handle.ebpf.read().await.routing_policy_generation();
    let stale = UdpDnsRoute::new(OutboundIndex::UserBase as u8, generation + 1).unwrap();
    let unknown = UdpDnsRoute::new(OutboundIndex::UserBase as u8 + 2, generation).unwrap();

    dispatch(&state, super::addr("10.0.0.4:53000"), b"stale", Some(stale)).await;
    dispatch(&state, super::addr("10.0.0.5:53000"), b"missing", None).await;
    dispatch(
        &state,
        super::addr("10.0.0.6:53000"),
        b"unknown",
        Some(unknown),
    )
    .await;
    assert!(
        state.udp_pool.is_empty(),
        "rejected cold packets must not reserve an initializer"
    );

    let nonmust = UdpDnsRoute::new(OutboundIndex::ControlPlaneRouting as u8, generation).unwrap();
    dispatch(
        &state,
        super::addr("10.0.0.7:53000"),
        b"malformed nonmust",
        Some(nonmust),
    )
    .await;
    assert_eq!(
        sent(&mut received).await,
        ("alpha-node".into(), b"malformed nonmust".to_vec())
    );

    assert!(state.udp_pool.shutdown().await);
    assert_eq!(dns_queries.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn marked_udp_dns_rechecks_initializer_epoch_after_config_validation() {
    let (state, mut received, dns_queries) = fixture(&[]);
    let generation = state.handle.ebpf.read().await.routing_policy_generation();
    let alpha = UdpDnsRoute::new(OutboundIndex::UserBase as u8, generation).unwrap();
    let client = super::addr("10.0.0.8:53000");
    let metadata = recv_meta(Some(alpha));
    let config_writer = state.handle.config.write().await;
    let mut dispatch_future = std::pin::pin!(state.dispatch_datagram_at(
        b"crossed reload",
        client,
        &metadata,
        udp_endpoint::queue_now(),
    ));
    {
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Future::poll(dispatch_future.as_mut(), &mut context),
            Poll::Pending
        ));
    }

    assert!(state.udp_pool.cancel_initializers_and_wait().await);
    drop(config_writer);
    dispatch_future.await;
    assert!(
        state.udp_pool.is_empty(),
        "a dispatch crossing initializer cancellation must not reserve an endpoint"
    );

    dispatch(&state, client, b"accepted after reload", Some(alpha)).await;
    assert_eq!(
        sent(&mut received).await,
        ("alpha-node".into(), b"accepted after reload".to_vec()),
        "the crossed packet must not reach transport ahead of the accepted sentinel"
    );

    assert!(state.udp_pool.shutdown().await);
    assert_eq!(dns_queries.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn malformed_controller_fallback_discards_incompatible_raw_handoff_metadata() {
    let stale_client = super::addr("10.0.0.9:53000");
    let compatible_client = super::addr("10.0.0.10:53000");
    let stale_raw = RoutingResult {
        outbound: OutboundIndex::UserBase as u8 + 1,
        must: 1,
        dscp: 46,
        ..Default::default()
    };
    let compatible_controller = RoutingResult {
        outbound: OutboundIndex::ControlPlaneRouting as u8,
        dscp: 46,
        ..Default::default()
    };
    let (state, mut received, dns_queries) = fixture(&[
        (stale_client, stale_raw),
        (compatible_client, compatible_controller),
    ]);
    let generation = state.handle.ebpf.read().await.routing_policy_generation();
    let raw_beta = UdpDnsRoute::new(OutboundIndex::UserBase as u8 + 1, generation).unwrap();
    let controller =
        UdpDnsRoute::new(OutboundIndex::ControlPlaneRouting as u8, generation).unwrap();
    let permit_count = state.udp_concurrency_limit.available_permits();
    assert_ne!(permit_count, 0);
    let held_permits = Arc::clone(&state.udp_concurrency_limit)
        .acquire_many_owned(permit_count as u32)
        .await
        .unwrap();

    dispatch(&state, stale_client, b"rejected raw beta", Some(raw_beta)).await;
    assert!(
        state.udp_pool.is_empty(),
        "the rejected raw packet must leave no endpoint owner"
    );
    drop(held_permits);

    dispatch(
        &state,
        stale_client,
        b"malformed controller fallback",
        Some(controller),
    )
    .await;
    assert_eq!(
        sent(&mut received).await,
        (
            "alpha-node".into(),
            b"malformed controller fallback".to_vec()
        ),
        "stale raw must/DSCP metadata must not own controller fallback"
    );

    dispatch(
        &state,
        compatible_client,
        b"compatible controller fallback",
        Some(controller),
    )
    .await;
    assert_eq!(
        sent(&mut received).await,
        (
            "beta-node".into(),
            b"compatible controller fallback".to_vec()
        ),
        "compatible controller metadata must remain available to normal routing"
    );

    assert!(state.udp_pool.shutdown().await);
    assert_eq!(dns_queries.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "ebpf")]
fn queued_dns_packet(client: SocketAddr, payload: &[u8], mark: u32) -> honk_nfqueue::QueuedPacket {
    honk_nfqueue::QueuedPacket {
        tuple: honk_nfqueue::UdpTuple {
            client,
            destination: super::addr("203.0.113.53:53"),
        },
        payload: bytes::Bytes::copy_from_slice(payload),
        mark,
        received_at: std::time::Instant::now(),
    }
}

#[cfg(feature = "ebpf")]
fn queued_dns_owner(
    state: &udp_ingress::UdpLoopState,
) -> (
    nfqueue::PendingUdpVerdicts,
    tokio::sync::mpsc::Receiver<nfqueue::PendingUdpFatal>,
) {
    let (pending, fatal) = nfqueue::PendingUdpVerdicts::new(
        Arc::clone(&state.handle.ebpf),
        Arc::clone(&state.udp_pool),
        Arc::clone(&state.stats),
    );
    pending.open_admission();
    (pending, fatal)
}

#[cfg(feature = "ebpf")]
async fn dispatch_queued_dns(
    state: &udp_ingress::UdpLoopState,
    pending: &nfqueue::PendingUdpVerdicts,
    packet: honk_nfqueue::QueuedPacket,
    epoch: Option<u64>,
) {
    let verdicts = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let held = nfqueue::HeldVerdict::test(1, packet.received_at, Arc::clone(&verdicts));
    pending
        .ingest_dns_held_wait(state, packet, held, epoch)
        .await;
    assert_eq!(
        *verdicts.lock(),
        vec![nfqueue::TestVerdict::Drop { id: 1 }],
        "queued DNS must drop its original exactly once, never accept it"
    );
}

#[cfg(feature = "ebpf")]
#[tokio::test]
async fn queued_dns_uses_canonical_controller_and_raw_owner() {
    let (state, mut received, dns_queries) = fixture(&[]);
    let (pending, mut fatal) = queued_dns_owner(&state);
    let generation = state.handle.ebpf.read().await.routing_policy_generation();
    let alpha = UdpDnsRoute::new(OutboundIndex::UserBase as u8, generation).unwrap();
    let beta = UdpDnsRoute::new(OutboundIndex::UserBase as u8 + 1, generation).unwrap();
    let controller =
        UdpDnsRoute::new(OutboundIndex::ControlPlaneRouting as u8, generation).unwrap();
    let client = super::addr("10.0.0.20:53000");
    let epoch = pending.admission_epoch();

    dispatch_queued_dns(
        &state,
        &pending,
        queued_dns_packet(client, b"raw queue first", alpha.to_nfqueue_mark()),
        epoch,
    )
    .await;
    assert_eq!(
        sent(&mut received).await,
        ("alpha-node".into(), b"raw queue first".to_vec())
    );
    dispatch_queued_dns(
        &state,
        &pending,
        queued_dns_packet(
            client,
            &super::dns_query_payload(),
            controller.to_nfqueue_mark(),
        ),
        epoch,
    )
    .await;
    dispatch_queued_dns(
        &state,
        &pending,
        queued_dns_packet(client, b"wrong Ready owner", beta.to_nfqueue_mark()),
        epoch,
    )
    .await;
    dispatch_queued_dns(
        &state,
        &pending,
        queued_dns_packet(client, b"same Ready owner", alpha.to_nfqueue_mark()),
        epoch,
    )
    .await;
    assert_eq!(
        sent(&mut received).await,
        ("alpha-node".into(), b"same Ready owner".to_vec())
    );
    dispatch_queued_dns(
        &state,
        &pending,
        queued_dns_packet(
            super::addr("10.0.0.21:53000"),
            b"malformed controller fallback",
            controller.to_nfqueue_mark(),
        ),
        epoch,
    )
    .await;
    assert_eq!(
        sent(&mut received).await,
        (
            "alpha-node".into(),
            b"malformed controller fallback".to_vec()
        )
    );
    assert!(state.udp_pool.shutdown().await);
    assert_eq!(dns_queries.load(Ordering::SeqCst), 1);
    assert!(matches!(
        fatal.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[cfg(feature = "ebpf")]
#[tokio::test]
async fn queued_dns_rejects_stale_carriers_and_closed_or_reopened_admission() {
    let (state, mut received, dns_queries) = fixture(&[]);
    let (pending, _fatal) = queued_dns_owner(&state);
    let generation = state.handle.ebpf.read().await.routing_policy_generation();
    let alpha = UdpDnsRoute::new(OutboundIndex::UserBase as u8, generation).unwrap();
    let stale = UdpDnsRoute::new(OutboundIndex::UserBase as u8, generation + 1).unwrap();
    let unknown = UdpDnsRoute::new(OutboundIndex::UserBase as u8 + 2, generation).unwrap();
    let client = super::addr("10.0.0.22:53000");
    let old_epoch = pending.admission_epoch();
    for mark in [
        stale.to_nfqueue_mark(),
        unknown.to_nfqueue_mark(),
        alpha.to_mark(),
    ] {
        dispatch_queued_dns(
            &state,
            &pending,
            queued_dns_packet(client, b"rejected carrier", mark),
            old_epoch,
        )
        .await;
    }
    pending.cancel_all().await;
    dispatch_queued_dns(
        &state,
        &pending,
        queued_dns_packet(client, b"closed gate", alpha.to_nfqueue_mark()),
        old_epoch,
    )
    .await;
    pending.open_admission();
    dispatch_queued_dns(
        &state,
        &pending,
        queued_dns_packet(client, b"queued before fence", alpha.to_nfqueue_mark()),
        old_epoch,
    )
    .await;
    let mut expired = queued_dns_packet(client, b"expired", alpha.to_nfqueue_mark());
    expired.received_at -= nfqueue::HARD_HOLD_TIMEOUT;
    dispatch_queued_dns(&state, &pending, expired, pending.admission_epoch()).await;
    dispatch_queued_dns(
        &state,
        &pending,
        queued_dns_packet(client, b"current admission", alpha.to_nfqueue_mark()),
        pending.admission_epoch(),
    )
    .await;
    assert_eq!(
        sent(&mut received).await,
        ("alpha-node".into(), b"current admission".to_vec()),
        "no rejected packet may precede the accepted same-flow sentinel"
    );
    assert!(state.udp_pool.shutdown().await);
    assert_eq!(dns_queries.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "ebpf")]
#[tokio::test]
async fn queued_dns_verdict_failure_cannot_send_ready_raw_or_start_controller() {
    let (state, mut received, dns_queries) = fixture(&[]);
    let (pending, mut fatal) = queued_dns_owner(&state);
    let generation = state.handle.ebpf.read().await.routing_policy_generation();
    let alpha = UdpDnsRoute::new(OutboundIndex::UserBase as u8, generation).unwrap();
    let controller =
        UdpDnsRoute::new(OutboundIndex::ControlPlaneRouting as u8, generation).unwrap();
    let client = super::addr("10.0.0.23:53000");
    dispatch(&state, client, b"ready", Some(alpha)).await;
    assert_eq!(sent(&mut received).await.1, b"ready");
    let query = super::dns_query_payload();
    for (route, payload) in [
        (alpha, b"failed raw verdict".as_slice()),
        (controller, query.as_slice()),
    ] {
        let packet = queued_dns_packet(client, payload, route.to_nfqueue_mark());
        let held = nfqueue::HeldVerdict::failure(packet.received_at);
        pending
            .ingest_dns_held_wait(&state, packet, held, pending.admission_epoch())
            .await;
        assert!(fatal.try_recv().is_ok(), "verdict ambiguity must be fatal");
    }
    dispatch(&state, client, b"sentinel after failure", Some(alpha)).await;
    assert_eq!(
        sent(&mut received).await.1,
        b"sentinel after failure",
        "a failed verdict must not publish into an already-running endpoint"
    );
    assert!(state.udp_pool.shutdown().await);
    assert_eq!(dns_queries.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "ebpf")]
#[tokio::test]
async fn queued_dns_config_wait_obeys_receipt_deadline_and_admission_drain() {
    let (state, mut received, dns_queries) = fixture(&[]);
    let (pending, _fatal) = queued_dns_owner(&state);
    let generation = state.handle.ebpf.read().await.routing_policy_generation();
    let alpha = UdpDnsRoute::new(OutboundIndex::UserBase as u8, generation).unwrap();
    let client = super::addr("10.0.0.24:53000");
    let mut packet = queued_dns_packet(client, b"blocked on config", alpha.to_nfqueue_mark());
    packet.received_at -= nfqueue::HARD_HOLD_TIMEOUT - Duration::from_millis(100);
    let writer = state.handle.config.write().await;
    let mut ingest = std::pin::pin!(dispatch_queued_dns(
        &state,
        &pending,
        packet,
        pending.admission_epoch(),
    ));
    {
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Future::poll(ingest.as_mut(), &mut context),
            Poll::Pending
        ));
    }
    let mut drain = std::pin::pin!(pending.cancel_all());
    {
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Future::poll(drain.as_mut(), &mut context),
            Poll::Pending
        ));
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(ingest, drain);
    })
    .await
    .expect("receipt deadline must release admission while config remains locked");
    drop(writer);
    pending.open_admission();
    dispatch_queued_dns(
        &state,
        &pending,
        queued_dns_packet(client, b"after drain", alpha.to_nfqueue_mark()),
        pending.admission_epoch(),
    )
    .await;
    assert_eq!(sent(&mut received).await.1, b"after drain");
    assert!(state.udp_pool.shutdown().await);
    assert_eq!(dns_queries.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn direct_dns_carrier_pins_packet_mark_not_latest_tuple_handoff() {
    use crate::control::udp_endpoint::{DatagramPayload, RawDnsRoute};
    use crate::control::udp_ingress::{UdpLoopState, UdpSlowPathWork};

    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.nfqueue_enable = false;
    config.routing.rules = [("8", 0x200), ("16", 0x300)]
        .into_iter()
        .map(|(dscp, mark)| RoutingRule {
            name: format!("mark-{mark}"),
            condition: RoutingCondition {
                dscp: vec![dscp.into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: true,
            mark,
        })
        .collect();
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let client = super::addr("10.0.0.23:53000");
    let target = super::addr("203.0.113.53:53");
    let tuples = build_tuples_key(target.ip(), target.port(), client.ip(), client.port(), 17);
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let key: [u8; 40] = super::bytes_of(&tuples).try_into().unwrap();
    backend.routing_handoffs.lock().insert(
        key,
        RoutingHandoffEntry {
            routing_generation: backend.routing_policy_generation() + 1,
            result: RoutingResult {
                outbound: OutboundIndex::Direct as u8,
                must: 1,
                mark: 0x300,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let plane = ControlPlane::new(
        config,
        Box::new(backend),
        router,
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        super::support::udp_test_forwarder(),
    )
    .unwrap();
    let state = UdpLoopState::new(&plane, true);
    let generation = state.handle.ebpf.read().await.routing_policy_generation();
    let first = UdpDnsRoute::direct(0, generation).unwrap();
    let second = UdpDnsRoute::direct(1, generation).unwrap();
    let UdpSlowPathWork::Initialize(lease) = state
        .admit_routed_dns_at(
            DatagramPayload::Borrowed(b"first"),
            client,
            target,
            first,
            udp_endpoint::queue_now(),
        )
        .await
    else {
        panic!("first direct carrier must admit its packet");
    };
    assert_eq!(lease.raw_dns_route(), Some(RawDnsRoute::Direct(0x200)));
    assert!(matches!(
        state
            .admit_routed_dns_at(
                DatagramPayload::Borrowed(b"different mark"),
                client,
                target,
                second,
                udp_endpoint::queue_now(),
            )
            .await,
        UdpSlowPathWork::Done
    ));
    assert_eq!(lease.raw_dns_route(), Some(RawDnsRoute::Direct(0x200)));
    drop(lease);
    let UdpSlowPathWork::Initialize(lease) = state
        .admit_routed_dns_at(
            DatagramPayload::Borrowed(b"next flow"),
            client,
            target,
            second,
            udp_endpoint::queue_now(),
        )
        .await
    else {
        panic!("retired tuple must accept its next direct owner");
    };
    assert_eq!(lease.raw_dns_route(), Some(RawDnsRoute::Direct(0x300)));
    drop(lease);
    for invalid in [
        UdpDnsRoute::direct(2, generation).unwrap(),
        UdpDnsRoute::direct(0, generation + 1).unwrap(),
    ] {
        assert!(matches!(
            state
                .admit_routed_dns_at(
                    DatagramPayload::Borrowed(b"invalid"),
                    client,
                    target,
                    invalid,
                    udp_endpoint::queue_now(),
                )
                .await,
            UdpSlowPathWork::Done
        ));
    }
}
