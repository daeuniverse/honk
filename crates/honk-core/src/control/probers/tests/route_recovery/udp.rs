use super::*;
use crate::control::{
    runtime::OutboundHealthPublisher,
    tests::support::UdpTestReplySocketFactory,
    udp_endpoint::{EndpointReservation, UdpEndpointPool},
};
use crate::test_support::routed_udp::{PASSWORD, Peer, dns_reply, front, trojan_peer};
use honk_config::{
    node::{OutboundConfig, TlsOptions, TrojanConfig},
    routing::{RoutingCondition, RoutingOutbound, RoutingRule},
};
use honk_outbound::{alive::UdpRouteAdmission, group::SelectorNetworks};
use std::io::ErrorKind;
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc},
};
use uuid::Uuid;

const STRIKES: usize = 50;
const DNS_HOST: &str = "udp-recovery.test";
const BUSINESS_REQUEST: &[u8] = b"business datagram";
const BUSINESS_REPLY: &[u8] = b"business reply from origin";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recovery {
    Valid,
    WrongId,
    WrongQuestion,
    WrongPeer,
    ExtendedRcode,
    Omitted,
    Empty,
    WrongFamily,
    RefusedResolution,
    OtherGeneration,
    OtherSelector,
    LaterStrike,
    Cancelled,
}

impl Recovery {
    fn targets(self, dns: SocketAddr) -> Option<Vec<String>> {
        match self {
            Self::Omitted => None,
            Self::Empty => Some(Vec::new()),
            Self::WrongFamily => Some(vec![format!("[::1]:{}", dns.port())]),
            _ => Some(vec![format!("{DNS_HOST}:{}", dns.port())]),
        }
    }

    fn sends_query(self) -> bool {
        matches!(
            self,
            Self::Valid
                | Self::WrongId
                | Self::WrongQuestion
                | Self::WrongPeer
                | Self::ExtendedRcode
                | Self::OtherGeneration
                | Self::OtherSelector
                | Self::LaterStrike
                | Self::Cancelled
        )
    }
}

async fn loopback_tcp() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

async fn loopback_udp() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

fn routing_rule(name: &str, address: SocketAddr) -> RoutingRule {
    RoutingRule {
        name: name.into(),
        condition: RoutingCondition {
            port: vec![address.port().to_string()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple(name.into()),
        priority: 0,
        must: false,
        mark: 0,
    }
}

fn selection(plane: &ControlPlane, group: &str, family: IpVersion) -> Option<OwnedTarget> {
    let managers = plane.group_manager();
    let manager = managers.read();
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Udp, ProbeDomain::DataUdp, family);
    let mut plan = manager.selection_plan_for_target_with_health_fallback(group, &context, None);
    assert!(plan.entries.len() <= 1);
    let entry = plan.entries.pop()?;
    Some(manager.own_target(Target {
        node: entry.node,
        route: entry.route,
    }))
}

async fn initialize(handle: &ControlPlaneHandle, client: SocketAddr, target: SocketAddr) {
    let permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let reservation =
        handle
            .udp_pool
            .reserve_or_enqueue(client, target, BUSINESS_REQUEST, permit, &handle.stats);
    let EndpointReservation::Initializing(lease) = reservation else {
        panic!("expected a fresh UDP initializer");
    };
    handle.serve_udp_connection(lease).await.unwrap();
}

async fn business(handle: &ControlPlaneHandle, origin: &UdpSocket) {
    let client = loopback_udp().await;
    let src = client.local_addr().unwrap();
    let dst = origin.local_addr().unwrap();
    initialize(handle, src, dst).await;
    let mut buffer = [0; 512];
    let (len, relay) = origin.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..len], BUSINESS_REQUEST);
    assert_eq!(
        origin.send_to(BUSINESS_REPLY, relay).await.unwrap(),
        BUSINESS_REPLY.len()
    );
    let (len, _) = client.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..len], BUSINESS_REPLY);
    assert!(handle.udp_pool.get(src, dst).unwrap().has_reply());
}

async fn slot(plane: &ControlPlane, group: &str, family: IpVersion) -> bool {
    let index = plane
        .active_routing_plan
        .read()
        .plan
        .group_slots
        .iter()
        .find_map(|(index, name)| (name == group).then_some(*index))
        .unwrap();
    plane
        .ebpf
        .read()
        .await
        .get_outbound_alive(index, ProbeDomain::DataUdp as u32, family as u32)
        .unwrap()
}

async fn publish_updates(
    publisher: &Arc<OutboundHealthPublisher>,
    updates: &mut mpsc::UnboundedReceiver<Option<Uuid>>,
) -> bool {
    let mut published = false;
    while let Ok(dependency) = updates.try_recv() {
        Arc::clone(publisher).publish(dependency, None).await;
        published = true;
    }
    published
}

fn capture_in_flight(manager: &GroupManager) -> (OwnedTarget, UdpRouteAdmission) {
    let context = ScoreSelectionContext::aggregate(
        SelectionNetwork::Udp,
        ProbeDomain::DataUdp,
        IpVersion::V4,
    );
    let (mut plan, revision) = manager.dial_plan_for_target("only-a", &context, None);
    assert_eq!(plan.entries.len(), 1);
    let entry = plan.entries.pop().unwrap();
    let mut target = manager.own_target(Target {
        node: entry.node,
        route: entry.route,
    });
    target.collapse = entry.collapse;
    let token = manager
        .capture_udp_route(
            &target,
            &entry.selection_chain,
            &entry.final_owners,
            revision,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        )
        .unwrap();
    (target, token)
}

fn extended_rcode(query: &[u8], reply: &mut Vec<u8>) {
    assert_eq!(reply[10..12], [0, 0]);
    reply[11] = 1;
    // OPT with extended RCODE 1 and header RCODE 0 is BADVERS (16).
    reply.extend_from_slice(&[0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0]);
    assert_eq!(crate::dns::response::response_rcode(reply).unwrap(), 16);
    let context = crate::dns::query::QueryContext::parse_with_profile(
        query,
        crate::dns::query::IngressProfile::Tcp,
    )
    .unwrap();
    crate::dns::response::ResponseTemplate::check(&context, reply).unwrap();
}

async fn check_recovery(response: Recovery) {
    let main_origin = loopback_udp().await;
    let a_origin = loopback_udp().await;
    let bare_origin = loopback_udp().await;
    let dns_origin = loopback_udp().await;
    let dns = dns_origin.local_addr().unwrap();
    let a_listener = loopback_tcp().await;
    let b_listener = loopback_tcp().await;
    let exit_listener = loopback_tcp().await;
    let exit_addr = exit_listener.local_addr().unwrap();
    let a = socks5_node(
        "front-a",
        "127.0.0.1",
        a_listener.local_addr().unwrap().port(),
    );
    let b = socks5_node(
        "front-b",
        "127.0.0.1",
        b_listener.local_addr().unwrap().port(),
    );
    let mut exit = Node {
        name: "land".into(),
        address: exit_addr.to_string(),
        host: exit_addr.ip().to_string(),
        port: exit_addr.port(),
        outbound: OutboundConfig::Trojan(TrojanConfig {
            password: Some(PASSWORD.into()),
            tls: TlsOptions {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    exit.id = exit.derive_id();
    let late = usize::from(response == Recovery::LaterStrike);
    let at_front = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let a_peer = Peer::start(a_listener, {
        let at_front = Arc::clone(&at_front);
        let release = Arc::clone(&release);
        move |stream, count| {
            let (at_front, release) = (Arc::clone(&at_front), Arc::clone(&release));
            async move {
                if late != 0 && count == STRIKES - 1 {
                    at_front.notify_one();
                    release.notified().await;
                }
                front(stream, exit_addr, count < STRIKES + late).await;
            }
        }
    });
    let b_peer = Peer::start(b_listener, move |stream, _| front(stream, exit_addr, false));
    let targets = [&main_origin, &a_origin, &bare_origin, &dns_origin]
        .map(|socket| socket.local_addr().unwrap());
    let exit_peer = Peer::start(exit_listener, move |stream, _| async move {
        trojan_peer(stream, &targets, dns).await;
    });
    let group = |name: &str, nodes, tunnel: bool| Group {
        name: name.into(),
        policy: GroupPolicy::Fallback,
        nodes,
        exit: tunnel.then(|| exit.name.clone()),
        ..Default::default()
    };
    let mut config = Config {
        groups: vec![
            group("main", vec![a.id, b.id], true),
            if response == Recovery::OtherSelector {
                Group {
                    policy: GroupPolicy::Selector,
                    default: Some(a.name.clone()),
                    ..group("only-a", vec![a.id, b.id], true)
                }
            } else {
                group("only-a", vec![a.id], true)
            },
            group("bare", vec![exit.id], false),
        ],
        nodes: vec![a.clone(), b.clone(), exit.clone()],
        ..Default::default()
    };
    config.ensure_builtin_nodes();
    config.global.tcp_check_url.clear();
    config.global.udp_check_dns = response.targets(dns);
    config.global.dial_mode = "ip".into();
    config.global.nfqueue_enable = false;
    config.global.preconnect_node_count = 0;
    config.global.udp_warm_node_count = 0;
    config.routing.default_outbound = "main".into();
    config.routing.rules = vec![
        routing_rule("only-a", targets[1]),
        routing_rule("bare", targets[2]),
    ];
    let mut plane = ControlPlane::new(
        config.clone(),
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        Router::from_config(&config.routing).unwrap(),
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&config.dns).unwrap(),
        crate::control::tests::support::udp_test_forwarder(),
    )
    .unwrap();
    plane.udp_pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        8,
        Arc::new(UdpTestReplySocketFactory),
    ));
    let handle = plane.spawn_handle();
    let retirement = TestRetirement::start(&handle);
    let alive = plane.alive_set();
    // Keep the real per-route scheduler. Disable ordinary node sockets so that
    // each front accept and resolver call measures only business or route recovery.
    alive.sync_registrations(
        [&a, &b, &exit]
            .into_iter()
            .map(|node| (node.id, (node.name.as_str(), None)))
            .collect(),
    );
    let resolutions = Arc::new(AtomicUsize::new(0));
    let requests = Arc::clone(&resolutions);
    let resolver: crate::outbound::ResolveHook = Arc::new(move |host, port| {
        let requests = Arc::clone(&requests);
        Box::pin(async move {
            assert_eq!(host, DNS_HOST);
            assert_eq!(port, dns.port());
            requests.fetch_add(1, Ordering::Relaxed);
            if response == Recovery::RefusedResolution {
                Err(honk_outbound::proxy::PacketRejection::Policy.into())
            } else {
                Ok(vec![dns])
            }
        })
    });
    let prober = ProxyHttpProber::new(
        plane.config_handle(),
        plane.proxy_registry(),
        plane.runtime_registry(),
        "HEAD".into(),
        plane.group_manager(),
    )
    .with_udp_recovery_resolver(resolver);
    alive.set_route_http_probe(Arc::new(prober));
    // Drive the real publisher from health notifications, without starting the
    // listener epoch. Slot writes still come from the admitted routing plan.
    let publisher = Arc::new(OutboundHealthPublisher::new(
        plane.ebpf_handle(),
        plane.config_handle(),
        Arc::clone(&plane.active_routing_plan),
        plane.group_manager(),
        Arc::clone(&alive),
    ));
    let (changed, mut updates) = mpsc::unbounded_channel();
    alive.set_connectivity_callback(move |dependency| {
        let _ = changed.send(dependency);
    });

    assert!(slot(&plane, "only-a", IpVersion::V4).await);
    let captured = selection(&plane, "only-a", IpVersion::V4).unwrap();
    assert_eq!(captured.route().unwrap().hops(), [a.id, exit.id]);
    assert_eq!(
        selection(&plane, "main", IpVersion::V4).unwrap().key(),
        captured.key()
    );
    let mut delayed = None;
    // Keep every source port occupied until the end of the failure run.
    let mut clients = Vec::with_capacity(STRIKES);
    for strike in 1..=STRIKES {
        if late != 0 && strike == STRIKES {
            let manager = plane.group_manager().read().clone();
            let (target, token) = capture_in_flight(&manager);
            let proxy = plane.proxy_registry();
            let generation = plane.runtime_registry().read().clone();
            delayed = Some(tokio::spawn(async move {
                let error = proxy
                    .dial_udp_route(
                        generation,
                        target.route().unwrap(),
                        targets[1],
                        None,
                        Duration::from_secs(6),
                    )
                    .await
                    .unwrap_err();
                assert_eq!(
                    dial_failure_scope(error.as_ref()),
                    DialFailureScope::Prefix(1)
                );
                assert!(manager.report_udp_route_failure(&token, error.as_ref()));
            }));
            at_front.notified().await;
        }
        let client = loopback_udp().await;
        let src = client.local_addr().unwrap();
        initialize(&handle, src, targets[1]).await;
        assert!(handle.udp_pool.get(src, targets[1]).is_none());
        assert_eq!(a_peer.count(), strike + usize::from(delayed.is_some()));
        assert_eq!(b_peer.count(), 0);
        assert_eq!(exit_peer.count(), 0);
        let selected = selection(&plane, "main", IpVersion::V4).unwrap();
        assert_eq!(selected.node.id, if strike < STRIKES { a.id } else { b.id });
        clients.push(client);
    }
    drop(clients);
    assert!(
        publish_updates(&publisher, &mut updates).await,
        "failed path emitted no slot update"
    );
    assert!(!slot(&plane, "only-a", IpVersion::V4).await);
    assert!(slot(&plane, "only-a", IpVersion::V6).await);
    assert!(slot(&plane, "main", IpVersion::V4).await);
    assert!(selection(&plane, "only-a", IpVersion::V4).is_none());
    assert_eq!(
        selection(&plane, "only-a", IpVersion::V6).unwrap().key(),
        captured.key()
    );
    assert_eq!(
        selection(&plane, "main", IpVersion::V4)
            .unwrap()
            .route()
            .unwrap()
            .hops(),
        [b.id, exit.id]
    );
    assert_eq!(
        selection(&plane, "bare", IpVersion::V4).unwrap().node.id,
        exit.id
    );
    assert!(!alive.is_failure_demoted(exit.id, ProbeDomain::DataUdp, IpVersion::V4));
    business(&handle, &main_origin).await;
    business(&handle, &bare_origin).await;
    assert_eq!(a_peer.count(), STRIKES + late);
    assert_eq!(b_peer.count(), 1);
    assert_eq!(exit_peer.count(), 2);
    publish_updates(&publisher, &mut updates).await;
    assert!(!slot(&plane, "only-a", IpVersion::V4).await);

    let cycle = tokio::spawn({
        let alive = Arc::clone(&alive);
        async move { alive.run_health_check_cycle(Duration::from_secs(3)).await }
    });
    let mut replaced_registry = None;
    if response.sends_query() {
        let mut buffer = [0; 512];
        let (len, sender) = dns_origin.recv_from(&mut buffer).await.unwrap();
        assert_eq!(a_peer.count(), STRIKES + late + 1);
        assert_eq!(b_peer.count(), 1);
        assert_eq!(exit_peer.count(), 3);
        assert!(!slot(&plane, "only-a", IpVersion::V4).await);
        let mut reply = dns_reply(&buffer[..len]);
        match response {
            Recovery::OtherGeneration => {
                // Leave the manager and ticket valid. Only the registry identity changes.
                let runtimes = plane.runtime_registry();
                let replacement = Arc::new(OutboundRuntimeRegistry::build(&config.nodes).unwrap());
                let current_manager = plane.group_manager().read().clone();
                let original = std::mem::replace(&mut *runtimes.write(), replacement);
                assert!(!original.is_shutdown());
                assert!(Arc::ptr_eq(&current_manager, &plane.group_manager().read()));
                replaced_registry = Some(original);
            }
            Recovery::OtherSelector => {
                let manager = plane.group_manager().read().clone();
                manager
                    .set_selector_choice("only-a", &b.name, SelectorNetworks::Udp)
                    .unwrap();
                assert_eq!(
                    selection(&plane, "only-a", IpVersion::V4).unwrap().node.id,
                    b.id
                );
            }
            Recovery::LaterStrike => {
                release.notify_one();
                delayed.take().unwrap().await.unwrap();
                assert!(selection(&plane, "only-a", IpVersion::V4).is_none());
            }
            Recovery::Cancelled => alive.shutdown_health_checks().await.unwrap(),
            Recovery::WrongId => reply[0] ^= 1,
            Recovery::WrongQuestion => {
                assert_eq!(reply[13], b'g');
                reply[13] = b'f';
            }
            Recovery::ExtendedRcode => extended_rcode(&buffer[..len], &mut reply),
            _ => {}
        }
        let foreign;
        let authority = if response == Recovery::WrongPeer {
            foreign = loopback_udp().await;
            assert_ne!(foreign.local_addr().unwrap(), dns);
            &foreign
        } else {
            &dns_origin
        };
        assert_eq!(
            authority.send_to(&reply, sender).await.unwrap(),
            reply.len()
        );
    }
    cycle.await.unwrap();
    if let Some(original) = replaced_registry {
        let replacement = std::mem::replace(&mut *plane.runtime_registry().write(), original);
        replacement.shutdown().await;
    }
    if response == Recovery::OtherSelector {
        plane
            .group_manager()
            .read()
            .set_selector_choice("only-a", &a.name, SelectorNetworks::Udp)
            .unwrap();
    }
    let expected_resolutions =
        usize::from(response.sends_query() || response == Recovery::RefusedResolution);
    assert_eq!(
        resolutions.load(Ordering::Relaxed),
        expected_resolutions,
        "{response:?}"
    );
    let opened = publish_updates(&publisher, &mut updates).await;
    let recovered = response == Recovery::Valid;
    if recovered {
        assert!(opened, "a successful recovery emitted no slot update");
    }
    assert_eq!(
        slot(&plane, "only-a", IpVersion::V4).await,
        recovered,
        "{response:?}"
    );
    assert!(slot(&plane, "main", IpVersion::V4).await);
    assert_eq!(
        selection(&plane, "only-a", IpVersion::V4).map(|target| target.key()),
        recovered.then(|| captured.key())
    );
    if recovered {
        assert_eq!(a_peer.count(), STRIKES + 1);
        business(&handle, &a_origin).await;
        assert_eq!(a_peer.count(), STRIKES + 2);
    }

    alive.shutdown_health_checks().await.unwrap();
    retirement.join(&handle).await.unwrap();
    plane.shutdown_runtime(None, None).await.unwrap();
    a_peer
        .finish(STRIKES + late + usize::from(response.sends_query()) + usize::from(recovered))
        .await;
    b_peer.finish(1).await;
    exit_peer
        .finish(2 + usize::from(response.sends_query()) + usize::from(recovered))
        .await;
    assert_eq!(
        dns_origin.try_recv_from(&mut [0; 512]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}

async fn check_cases(cases: &[Recovery]) {
    for &response in cases {
        tokio::time::timeout(Duration::from_secs(15), check_recovery(response))
            .await
            .unwrap_or_else(|_| panic!("UDP recovery fixture timed out for {response:?}"));
    }
}

#[tokio::test]
async fn configured_routed_udp_recovery_validates_reply_and_reopens_only_the_prefix() {
    check_cases(&[
        Recovery::Valid,
        Recovery::WrongId,
        Recovery::WrongQuestion,
        Recovery::WrongPeer,
        Recovery::ExtendedRcode,
    ])
    .await;
}

#[tokio::test]
async fn routed_udp_recovery_requires_explicit_dns_for_the_captured_family() {
    check_cases(&[
        Recovery::Omitted,
        Recovery::Empty,
        Recovery::WrongFamily,
        Recovery::RefusedResolution,
    ])
    .await;
}

#[tokio::test]
async fn stale_or_cancelled_routed_udp_recovery_keeps_the_prefix_down() {
    check_cases(&[
        Recovery::OtherGeneration,
        Recovery::OtherSelector,
        Recovery::LaterStrike,
        Recovery::Cancelled,
    ])
    .await;
}

#[tokio::test]
async fn collapsed_udp_recovery_rechecks_a_pending_native_send() {
    use honk_outbound::alive::{ProbeCancellation, RouteHttpProber};
    use honk_outbound::group::{DialKey, ExitCollapse};
    use honk_outbound::proxy::NodeFailure;

    for (withdraw, hold_reply) in [(false, false), (true, false), (true, true)] {
        let node = udp_test_node();
        let block = Config::builtin_block_node();
        let group = Group {
            name: "only-a".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![node.id, block.id],
            default: Some(node.name.clone()),
            exit: Some(node.name.clone()),
            ..Default::default()
        };
        let mut config = Config {
            nodes: vec![node.clone(), block],
            groups: vec![group],
            ..Default::default()
        };
        config.global.udp_check_dns = Some(vec!["127.0.0.1:5300".into()]);
        let alive = Arc::new(AliveDialerSet::new());
        let manager = Arc::new(GroupManager::with_alive_set(
            &config.groups,
            &config.nodes,
            Some(Arc::clone(&alive)),
        ));
        manager.publish_route_health_with_udp(config.global.udp_check_dns.as_deref());
        let failure = NodeFailure(anyhow::anyhow!("invalid native response record"));
        for _ in 0..STRIKES {
            let (target, token) = capture_in_flight(&manager);
            assert_eq!(target.collapse, ExitCollapse::Member);
            assert!(manager.report_udp_route_failure(&token, &failure));
        }
        let ticket = alive
            .take_route_probe()
            .expect("collapsed framing recovery ticket");
        assert_eq!(ticket.target(), DialKey::Node(node.id));
        let ready =
            || manager.is_node_selectable_for_domain(node.id, ProbeDomain::DataUdp, IpVersion::V4);
        assert!(!ready());

        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let sends = Arc::new(AtomicUsize::new(0));
        let native = Arc::new(UdpTestHandler {
            mode: UdpTestMode::GatedDnsResponse {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                sends: Arc::clone(&sends),
                hold_reply,
            },
        });
        let mut registry = ProxyRegistry::new();
        registry.register(ProtocolEntry::new(node.protocol(), native.clone()).with_packet(native));
        let generation = OutboundRuntimeRegistry::build(&config.nodes).unwrap();
        let prober = ProxyHttpProber::new(
            Arc::new(RwLock::new(Arc::new(config))),
            Arc::new(registry),
            Arc::new(parking_lot::RwLock::new(Arc::new(generation))),
            "HEAD".into(),
            Arc::new(parking_lot::RwLock::new(Arc::clone(&manager))),
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let probe = prober.probe_route_udp(&alive, &ticket, deadline, ProbeCancellation::default());
        let control = async {
            entered.notified().await;
            assert_eq!(sends.load(Ordering::Relaxed), usize::from(hold_reply));
            if withdraw {
                manager
                    .set_selector_choice("only-a", "block", SelectorNetworks::Udp)
                    .unwrap();
                assert!(!ticket.is_current());
            }
            release.notify_one();
        };
        tokio::time::timeout_at(deadline, async { tokio::join!(probe, control).0 })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            sends.load(Ordering::Relaxed),
            usize::from(!withdraw || hold_reply)
        );
        assert_eq!(ready(), !withdraw);
    }
}

#[derive(Debug)]
struct QueuedDnsProbe {
    peer: SocketAddr,
    requests: mpsc::Sender<Vec<u8>>,
    response: tokio::sync::Mutex<oneshot::Receiver<Vec<u8>>>,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketTransport for QueuedDnsProbe {
    fn relay_addr(&self) -> SocketAddr {
        self.peer
    }

    async fn send_packet(&self, _: &[u8]) -> std::io::Result<()> {
        panic!("composed recovery used an unchecked send");
    }

    async fn send_packet_checked(
        &self,
        query: &[u8],
        current: &(dyn Fn() -> bool + Send + Sync),
    ) -> std::io::Result<()> {
        let permit = self.requests.reserve().await.unwrap();
        if !current() {
            return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
        }
        permit.send(query.to_vec());
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let reply = (&mut *self.response.lock().await).await.unwrap();
        buf[..reply.len()].copy_from_slice(&reply);
        Ok((reply.len(), self.peer))
    }
}

#[tokio::test]
async fn composed_udp_recovery_rechecks_its_ticket_at_queue_admission() {
    use crate::dns::forwarder::{UdpProbeSend, udp_dns_probe_exchange};
    use honk_outbound::group::DialKey;
    use honk_outbound::proxy::{
        ChainHopFailure, DialRef, NodeFailure, PacketRejection, packet_rejection,
    };

    let front = udp_test_node();
    let exit = Node::from_share_link("trojan://pass@127.0.0.1:2443#terminal").unwrap();
    let block = Config::builtin_block_node();
    let group = Group {
        name: "only-a".into(),
        policy: GroupPolicy::Selector,
        nodes: vec![front.id, block.id],
        default: Some(front.name.clone()),
        exit: Some(exit.name.clone()),
        ..Default::default()
    };
    let nodes = [front, exit.clone(), block];
    let generation = OutboundRuntimeRegistry::build(&nodes).unwrap();
    let registry = ProxyRegistry::default_resolver().unwrap();
    let dns = "127.0.0.1:5300".parse::<SocketAddr>().unwrap();
    for withdraw in [false, true] {
        let alive = Arc::new(AliveDialerSet::new());
        let manager = Arc::new(GroupManager::with_alive_set(
            std::slice::from_ref(&group),
            &nodes,
            Some(Arc::clone(&alive)),
        ));
        manager.publish_route_health_with_udp(Some(&[dns.to_string()]));
        let failure = ChainHopFailure {
            hop: 1,
            node: exit.id,
            error: NodeFailure(anyhow::anyhow!("invalid terminal record")).into(),
        };
        for _ in 0..STRIKES {
            let (_, admission) = capture_in_flight(&manager);
            assert!(manager.report_udp_route_failure(&admission, &failure));
        }
        let ticket = alive.take_route_probe().expect("multi-hop recovery ticket");
        let DialKey::Route(route) = ticket.target() else {
            panic!("expected a composed target");
        };
        let dial = DialRef::Route(&route);
        let terminal = registry.udp_framing_node(&generation, dial).unwrap();
        assert_eq!(terminal.id, exit.id);
        let current = || ticket.is_current_for(&manager);
        assert!(current());

        let (requests, mut received) = mpsc::channel(1);
        let (reply, response) = oneshot::channel();
        let writer = QueuedDnsProbe {
            peer: dns,
            requests,
            response: tokio::sync::Mutex::new(response),
        };
        let credit = writer.requests.reserve().await.unwrap();
        let send = UdpProbeSend::recovery(dial, terminal.id, &current);
        let mut probe = std::pin::pin!(udp_dns_probe_exchange(&writer, send));
        assert!(futures::poll!(probe.as_mut()).is_pending());
        if withdraw {
            manager
                .set_selector_choice("only-a", "block", SelectorNetworks::Udp)
                .unwrap();
            assert!(!current());
        }
        drop(credit);
        if withdraw {
            let std::task::Poll::Ready(Err(error)) = futures::poll!(probe.as_mut()) else {
                panic!("stale recovery must stop before handing off the query");
            };
            assert_eq!(packet_rejection(&error), Some(PacketRejection::Cancelled));
        } else {
            assert!(futures::poll!(probe.as_mut()).is_pending());
            let query = received
                .try_recv()
                .expect("current recovery handed off one query");
            reply.send(dns_reply(&query)).unwrap();
            let std::task::Poll::Ready(Ok(_)) = futures::poll!(probe.as_mut()) else {
                panic!("current recovery must validate the queued DNS answer");
            };
            ticket
                .settle_udp(
                    true,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                    &honk_outbound::alive::ProbeCancellation::default(),
                )
                .notify();
        }
        assert_eq!(
            manager.is_node_selectable_for_domain(exit.id, ProbeDomain::DataUdp, IpVersion::V4),
            !withdraw,
        );
        assert!(matches!(
            received.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}
