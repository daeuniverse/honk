use super::*;
use crate::group::ScoreOutcome;
use crate::proxy::{
    DialFailureScope, DialRef, NodeFailure, ProxyRegistry, TargetFailure, dial_failure_scope,
    failed_hop, node_failure, target_failure,
};
use crate::runtime::OutboundRuntimeRegistry;
use crate::test_support::{
    TCP_TARGET as TARGET, TCP_TARGET_HEADER, assert_legacy_bulk_echo, chain,
    mock_legacy_tcp_server, node, socks5, socks5_relay,
};
use honk_config::node::OutboundConfig;
use std::sync::Mutex;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

mod failure_provenance;

fn target() -> SocketAddr {
    TARGET.parse().unwrap()
}

fn shadowsocks(name: &str, host: &str, port: u16) -> Node {
    node(
        name,
        host,
        port,
        OutboundConfig::Shadowsocks(honk_config::node::ShadowsocksConfig {
            encryption: Some("aes-128-gcm".into()),
            password: Some("test-password".into()),
            ..Default::default()
        }),
    )
}

async fn shadowsocks_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(mock_legacy_tcp_server(stream, &TCP_TARGET_HEADER));
        }
    });
    addr
}

async fn dial_chain(nodes: &[Node]) -> anyhow::Result<ProxyStream> {
    let generation = Arc::new(OutboundRuntimeRegistry::build(nodes).unwrap());
    ProxyRegistry::default_resolver()
        .unwrap()
        .dial_runtime(
            generation,
            nodes[0].id,
            target(),
            None,
            Duration::from_secs(3),
        )
        .await
}

#[tokio::test]
async fn socks5_front_carries_a_shadowsocks_exit() {
    let relay = socks5_relay(Vec::new(), false).await;
    let server = shadowsocks_server().await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = shadowsocks("land", "127.0.0.1", server.port());
    let mut stream = dial_chain(&[chain(&[&front, &land]), front, land])
        .await
        .unwrap();
    assert_legacy_bulk_echo(&mut stream.stream).await;
    assert_eq!(relay.requests(), [server.to_string()]);
    assert_eq!(stream.target_addr, target());
}

#[tokio::test]
async fn three_hops_leave_each_server_domain_to_the_hop_before() {
    let server = shadowsocks_server().await;
    let inner = socks5_relay(vec![("land.test", server)], false).await;
    let outer = socks5_relay(vec![("mid.test", inner.addr)], false).await;
    let front = socks5("front", "127.0.0.1", outer.addr.port());
    let mid = socks5("mid", "mid.test", inner.addr.port());
    let land = shadowsocks("land", "land.test", server.port());
    let mut stream = dial_chain(&[chain(&[&front, &mid, &land]), front, mid, land])
        .await
        .unwrap();
    assert_legacy_bulk_echo(&mut stream.stream).await;
    assert_eq!(
        outer.requests(),
        [format!("mid.test:{}", inner.addr.port())]
    );
    assert_eq!(inner.requests(), [format!("land.test:{}", server.port())]);
}

#[tokio::test]
async fn an_earlier_hop_target_failure_is_a_chain_failure() {
    let relay = socks5_relay(Vec::new(), true).await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = shadowsocks("land", "127.0.0.1", 9);
    let route = route(&front, &[&front, &land]);
    let generation =
        Arc::new(OutboundRuntimeRegistry::build(&[front.clone(), land.clone()]).unwrap());
    let error = dial_chain(&[chain(&[&front, &land]), front, land])
        .await
        .unwrap_err();
    assert!(!target_failure(&error), "{error:#}");
    assert!(node_failure(&error), "{error:#}");
    assert!(failed_hop(&error).is_none());
    assert_eq!(ScoreOutcome::from_error(&error), ScoreOutcome::NodeFailure);
    assert!(error.chain().any(|cause| cause.is::<TargetFailure>()));

    let error = dial_route(&generation, &route).await.unwrap_err();
    assert_eq!(
        dial_failure_scope(error.as_ref()),
        DialFailureScope::Prefix(1)
    );
    assert_eq!(
        failed_hop(&error).map(|failure| (failure.hop, failure.node)),
        Some((1, route.exit())),
    );
    assert!(error.chain().any(|cause| cause.is::<TargetFailure>()));
}

#[tokio::test]
async fn internal_refusals_charge_the_configured_chain_but_boundary_refusals_do_not() {
    use crate::group::{OwnedTarget, RoutedTarget};
    use std::sync::atomic::Ordering;

    let ingress = socks5_relay(Vec::new(), true).await;
    let middle = socks5_relay(Vec::new(), true).await;
    let front = socks5("front", "127.0.0.1", ingress.addr.port());
    let mid = socks5("mid", "127.0.0.1", middle.addr.port());
    let exit = socks5("exit", "127.0.0.1", 9);
    let configured = chain(&[&front, &mid]);
    let route = route(&configured, &[&front, &mid, &exit]);
    let standalone = OwnedTarget::node(configured.clone());
    let mut routed = OwnedTarget::node(configured.clone());
    routed.route = Some(Box::new(RoutedTarget {
        route,
        hop_names: [front.name.clone(), mid.name.clone(), exit.name.clone()].into(),
    }));
    let generation =
        Arc::new(OutboundRuntimeRegistry::build(&[configured.clone(), front, mid, exit]).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();
    for (owner_target, scope, owner) in [
        (
            &standalone,
            DialFailureScope::Prefix(1),
            Some(configured.id),
        ),
        (&routed, DialFailureScope::Prefix(1), Some(configured.id)),
        (&routed, DialFailureScope::Prefix(2), None),
    ] {
        ingress
            .refuse
            .store(scope == DialFailureScope::Prefix(1), Ordering::SeqCst);
        let error = registry
            .dial_ref(
                Arc::clone(&generation),
                owner_target.dial_ref(),
                target(),
                None,
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert_eq!(dial_failure_scope(error.as_ref()), scope);
        assert_eq!(owner_target.failure_owner(&error), owner);
    }
    assert_eq!(middle.requests(), ["127.0.0.1:9"]);
}

#[tokio::test]
async fn the_last_hop_target_failure_stays_a_target_failure() {
    let refusing = socks5_relay(Vec::new(), true).await;
    let relay = socks5_relay(Vec::new(), false).await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = socks5("land", "127.0.0.1", refusing.addr.port());
    let route = route(&front, &[&front, &land]);
    let generation =
        Arc::new(OutboundRuntimeRegistry::build(&[front.clone(), land.clone()]).unwrap());
    let error = dial_chain(&[chain(&[&front, &land]), front, land])
        .await
        .unwrap_err();
    assert!(target_failure(&error), "{error:#}");
    assert_eq!(
        ScoreOutcome::from_error(&error),
        ScoreOutcome::TargetFailure
    );
    let error = dial_route(&generation, &route).await.unwrap_err();
    assert_eq!(dial_failure_scope(error.as_ref()), DialFailureScope::Target);
    assert_eq!(failed_hop(&error).unwrap().node, route.exit());
    assert_eq!(refusing.requests(), [TARGET, TARGET]);
}

#[tokio::test]
async fn a_confirmed_socks_route_retains_splice_and_checks_generation() {
    let application = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = application.local_addr().unwrap();
    let ingress = socks5_relay(Vec::new(), false).await;
    let egress = socks5_relay(Vec::new(), false).await;
    let front = socks5("front", "127.0.0.1", ingress.addr.port());
    let exit = socks5("exit", "127.0.0.1", egress.addr.port());
    let route = route(&front, &[&front, &exit]);
    let incomplete = OutboundRuntimeRegistry::build(std::slice::from_ref(&exit)).unwrap();
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[front, exit]).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();
    let stream = registry
        .dial_ref(
            Arc::clone(&generation),
            DialRef::Route(&route),
            destination,
            None,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert!(stream.into_tcp_stream().is_ok());
    assert_eq!(egress.requests(), [destination.to_string()]);
    let exit = DialRef::Node(route.exit());
    let dial = DialRef::Route(&route);
    assert!(registry.confirms_target_on_open(&generation, exit));
    assert!(registry.confirms_target_on_open(&generation, dial));
    assert!(!registry.confirms_target_on_open(&incomplete, dial));
    generation.begin_retirement();
    assert!(!registry.confirms_target_on_open(&generation, exit));
    assert!(!registry.confirms_target_on_open(&generation, dial));
}

#[tokio::test]
async fn a_chain_without_its_generation_refuses_to_dial() {
    let fakes = Fakes::new(FakeHop::default(), FakeHop::default());
    assert!(
        fakes
            .registry()
            .dial(&fakes.via, target(), None, Duration::from_secs(1))
            .await
            .is_err()
    );
    assert!(fakes.calls().is_empty());
    assert!(matches!(
        NodeRuntime::try_ephemeral(&fakes.via),
        Err(crate::runtime::RuntimeRegistryError::Admission(error))
            if error.diagnostic.code == "invalid-chain-hop-reference"
    ));
}

fn route(leaf: &Node, hops: &[&Node]) -> honk_config::route::Route {
    let ids: Vec<_> = hops.iter().map(|hop| hop.id).collect();
    let (exit, own) = ids.split_last().unwrap();
    match honk_config::group_graph::compose(leaf.id, own, [*exit]) {
        honk_config::group_graph::Composed::Routed(route) => route,
        other => panic!("expected a route, got {other:?}"),
    }
}

async fn dial_route(
    generation: &Arc<OutboundRuntimeRegistry>,
    route: &honk_config::route::Route,
) -> anyhow::Result<ProxyStream> {
    ProxyRegistry::default_resolver()
        .unwrap()
        .dial_ref(
            Arc::clone(generation),
            crate::proxy::DialRef::Route(route),
            target(),
            None,
            Duration::from_secs(3),
        )
        .await
}

#[tokio::test]
async fn a_route_with_a_missing_hop_fails_closed() {
    let relay = socks5_relay(Vec::new(), false).await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = shadowsocks("land", "127.0.0.1", 8388);
    let generation =
        Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&front)).unwrap());
    let error = dial_route(&generation, &route(&front, &[&front, &land]))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("route is not in runtime generation"),
        "{error:#}"
    );
    generation.begin_retirement();
    let full = Arc::new(OutboundRuntimeRegistry::build(&[front.clone(), land.clone()]).unwrap());
    full.begin_retirement();
    let error = dial_route(&full, &route(&front, &[&front, &land]))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("generation is shut down"),
        "{error:#}"
    );
    assert!(relay.requests().is_empty());
}

#[tokio::test]
async fn a_full_route_cache_still_dials_uncached() {
    for entries in [0, crate::runtime::MAX_ROUTE_RUNTIMES] {
        let relay = socks5_relay(Vec::new(), false).await;
        let server = shadowsocks_server().await;
        let front = socks5("front", "127.0.0.1", relay.addr.port());
        let land = shadowsocks("land", "127.0.0.1", server.port());
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(&[front.clone(), land.clone()]).unwrap());
        let mut leaf = front.clone();
        for index in 0..entries {
            leaf.id = uuid::Uuid::from_u128(index as u128 + 1);
            generation
                .route_runtime(&route(&leaf, &[&front, &land]))
                .unwrap();
        }
        let mut stream = dial_route(&generation, &route(&front, &[&front, &land]))
            .await
            .unwrap();
        assert_legacy_bulk_echo(&mut stream.stream).await;
        assert_eq!(relay.requests(), [server.to_string()]);
    }
}

/// A dialed route stream holds its hops' resources, not the route runtime,
/// so it outlives a reload and the generation that cached the route.
#[tokio::test]
async fn a_route_flow_survives_reload_and_cache_drop() {
    let relay = socks5_relay(Vec::new(), false).await;
    let server = shadowsocks_server().await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = shadowsocks("land", "127.0.0.1", server.port());
    let nodes = [front.clone(), land.clone()];
    let old = Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap());
    let route = route(&front, &[&front, &land]);
    let mut stream = dial_route(&old, &route).await.unwrap();
    let cached = Arc::downgrade(&old.route_runtime(&route).unwrap());
    let (new, _) = OutboundRuntimeRegistry::build_reusing(&nodes, 8, Some(&old)).unwrap();
    old.begin_retirement();
    drop(old);
    assert!(cached.upgrade().is_none());
    assert_legacy_bulk_echo(&mut stream.stream).await;
    let mut again = dial_route(&Arc::new(new), &route).await.unwrap();
    assert_legacy_bulk_echo(&mut again.stream).await;
}

/// Records how the chain drives each hop and answers with a pass-through stream.
#[derive(Default)]
struct FakeHop {
    calls: Arc<Mutex<Vec<Call>>>,
    delay: Duration,
    /// Fail tunneled dials with a REALITY mask certificate while key shares are on.
    masked: bool,
    failure: Option<fn() -> anyhow::Error>,
    milestones: bool,
    /// The far ends of the streams runtime dials open, to watch them close.
    peers: Mutex<Vec<tokio::io::DuplexStream>>,
}

#[derive(Clone)]
struct Call {
    hop: String,
    runtime: std::sync::Weak<NodeRuntime>,
    target: SocketAddr,
    domain: Option<String>,
    timeout: Duration,
    key_shares: Option<bool>,
}

impl FakeHop {
    fn record(runtime: &Arc<NodeRuntime>, target: SocketAddr, domain: Option<&str>) -> Call {
        Call {
            hop: runtime.node.name.clone(),
            runtime: Arc::downgrade(runtime),
            target,
            domain: domain.map(str::to_string),
            timeout: Duration::ZERO,
            key_shares: None,
        }
    }

    async fn act(
        &self,
        mut call: Call,
        stream: Box<dyn AsyncReadWrite>,
    ) -> anyhow::Result<ProxyStream> {
        let masked = self.masked && call.key_shares == Some(true);
        let target = call.target;
        call.hop.push_str(if call.key_shares.is_some() {
            "/over"
        } else {
            "/runtime"
        });
        self.calls.lock().unwrap().push(call);
        tokio::time::sleep(self.delay).await;
        if masked {
            return Err(crate::reality::RealityMaskCertificate.into());
        }
        if let Some(failure) = self.failure {
            return Err(failure());
        }
        if self.milestones {
            use crate::runtime::flow_observation::{Milestone, milestone};
            milestone(Milestone::TransportReady);
            milestone(Milestone::TargetRequestSent);
            milestone(Milestone::TargetConfirmed);
        }
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: None,
        })
    }
}

#[async_trait]
impl TcpOutbound for FakeHop {
    async fn dial(
        &self,
        node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        panic!("hop '{}' must dial through its runtime", node.name)
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let mut call = Self::record(&runtime, target, target_domain);
        call.timeout = connect_timeout;
        let (stream, peer) = crate::runtime::admit_physical_dial(async {
            Ok::<_, anyhow::Error>(tokio::io::duplex(64))
        })
        .await?;
        self.peers.lock().unwrap().push(peer);
        self.act(call, Box::new(stream)).await
    }

    async fn dial_over(
        &self,
        runtime: Arc<NodeRuntime>,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        options: TunnelDialOptions,
    ) -> anyhow::Result<ProxyStream> {
        let mut call = Self::record(&runtime, target, target_domain);
        call.timeout = options.connect_timeout;
        call.key_shares = Some(options.reality_key_shares);
        self.act(call, carrier).await
    }
}

struct Fakes {
    generation: Arc<OutboundRuntimeRegistry>,
    via: Node,
    front: Arc<FakeHop>,
    land: Arc<FakeHop>,
}

impl Fakes {
    /// An AnyTLS front (a session protocol) and a Trojan exit at a domain.
    fn new(front: FakeHop, mut land: FakeHop) -> Self {
        land.calls = Arc::clone(&front.calls);
        let anytls = node(
            "front",
            "192.0.2.1",
            443,
            OutboundConfig::AnyTls(honk_config::node::AnyTlsConfig {
                password: Some("secret".into()),
                ..Default::default()
            }),
        );
        let trojan = node(
            "land",
            "land.example",
            443,
            OutboundConfig::Trojan(Default::default()),
        );
        let via = chain(&[&anytls, &trojan]);
        let (generation, _) =
            OutboundRuntimeRegistry::build_reusing(&[via.clone(), anytls, trojan], 1, None)
                .unwrap();
        Self {
            generation: Arc::new(generation),
            via,
            front: Arc::new(front),
            land: Arc::new(land),
        }
    }

    fn registry(&self) -> ProxyRegistry {
        let mut registry = ProxyRegistry::new();
        registry.register(ProtocolEntry::new(NodeProtocol::AnyTLS, self.front.clone()));
        registry.register(ProtocolEntry::new(NodeProtocol::Trojan, self.land.clone()));
        registry.register_chain();
        registry
    }

    fn route(&self) -> honk_config::route::Route {
        let via = self.generation.get(&self.via.id).unwrap();
        let [front, land] = via.chain_hops() else {
            panic!("expected a two-hop chain");
        };
        route(&front.node, &[&front.node, &land.node])
    }

    async fn dial(&self, connect_timeout: Duration) -> anyhow::Result<ProxyStream> {
        self.dial_ref(DialRef::Node(self.via.id), connect_timeout)
            .await
    }

    async fn dial_ref(
        &self,
        dial: DialRef<'_>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.registry()
            .dial_ref(
                Arc::clone(&self.generation),
                dial,
                target(),
                Some("example.com"),
                connect_timeout,
            )
            .await
    }

    fn calls(&self) -> Vec<Call> {
        self.front.calls.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn a_custom_socks_handler_does_not_get_stock_confirmation() {
    let custom = Arc::new(FakeHop::default());
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(NodeProtocol::Socks5, custom.clone()));
    registry.register(ProtocolEntry::new(
        NodeProtocol::Socks5,
        Arc::new(crate::proxy::socks5::Socks5Handler::new()),
    ));
    registry.register_chain();
    let front = socks5("front", "127.0.0.1", 1);
    let exit = socks5("exit", "127.0.0.1", 2);
    let route = route(&front, &[&front, &exit]);
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[front, exit]).unwrap());
    for dial in [DialRef::Node(route.exit()), DialRef::Route(&route)] {
        registry
            .dial_ref(
                Arc::clone(&generation),
                dial,
                target(),
                None,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert!(!registry.confirms_target_on_open(&generation, dial));
    }
    assert_eq!(custom.calls.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn the_front_dials_its_own_runtime_toward_the_next_server() {
    let fakes = Fakes::new(FakeHop::default(), FakeHop::default());
    fakes.dial(Duration::from_secs(1)).await.unwrap();
    let calls = fakes.calls();
    let [front, land] = calls.as_slice() else {
        panic!(
            "expected one entry dial and one exit dial, got {}",
            calls.len()
        );
    };
    let via = fakes.generation.get(&fakes.via.id).unwrap();
    let hops = via.chain_hops();
    assert!(front.runtime.ptr_eq(&Arc::downgrade(&hops[0])));
    assert!(land.runtime.ptr_eq(&Arc::downgrade(&hops[1])));
    assert_eq!(front.hop, "front/runtime");
    assert_eq!(front.domain.as_deref(), Some("land.example"));
    assert_eq!(front.target.port(), 443);
    assert_eq!(land.hop, "land/over");
    assert_eq!(
        (land.target, land.domain.as_deref()),
        (target(), Some("example.com"))
    );
}

#[tokio::test]
async fn a_reality_mask_certificate_redials_once_with_fresh_physical_credits() {
    use futures_util::FutureExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for routed in [false, true] {
        let fakes = Fakes::new(
            FakeHop::default(),
            FakeHop {
                masked: true,
                ..Default::default()
            },
        );
        let route = fakes.route();
        let dial = if routed {
            DialRef::Route(&route)
        } else {
            DialRef::Node(fakes.via.id)
        };
        let starts = Arc::new(AtomicUsize::new(0));
        let scope = fakes.generation.dial_scope({
            let starts = Arc::clone(&starts);
            move || {
                starts.fetch_add(1, Ordering::Relaxed);
            }
        });
        scope
            .scope(fakes.dial_ref(dial, Duration::from_secs(1)))
            .await
            .unwrap();
        let hops: Vec<_> = fakes
            .calls()
            .into_iter()
            .map(|call| (call.hop, call.key_shares))
            .collect();
        assert_eq!(
            hops,
            [
                ("front/runtime".to_string(), None),
                ("land/over".to_string(), Some(true)),
                ("front/runtime".to_string(), None),
                ("land/over".to_string(), Some(false)),
            ]
        );
        assert_eq!(starts.load(Ordering::Relaxed), 1);
        assert!(
            fakes
                .generation
                .acquire_dial_permit()
                .now_or_never()
                .is_some()
        );
    }
}

/// The first hop dials its server directly, where a REALITY dial has already
/// retried once, so its mask certificate ends the chain dial.
#[tokio::test]
async fn a_reality_mask_certificate_on_the_first_hop_is_not_redialed() {
    let fakes = Fakes::new(
        FakeHop {
            failure: Some(|| crate::reality::RealityMaskCertificate.into()),
            ..Default::default()
        },
        FakeHop::default(),
    );
    let error = fakes.dial(Duration::from_secs(1)).await.unwrap_err();
    assert!(
        error.is::<crate::reality::RealityMaskCertificate>(),
        "{error:#}"
    );
    let hops: Vec<_> = fakes.calls().into_iter().map(|call| call.hop).collect();
    assert_eq!(hops, ["front/runtime"]);

    let fakes = Fakes::new(
        FakeHop {
            failure: Some(|| TargetFailure(crate::reality::RealityMaskCertificate.into()).into()),
            ..Default::default()
        },
        FakeHop::default(),
    );
    let route = fakes.route();
    let error = fakes
        .dial_ref(DialRef::Route(&route), Duration::from_secs(1))
        .await
        .unwrap_err();
    assert_eq!(failed_hop(&error).unwrap().hop, 1);
    assert!(reality_mask_certificate(&error));
    assert_eq!(fakes.calls().len(), 1);
}

#[tokio::test]
async fn packet_rejections_pass_through_the_chain_unchanged() {
    let rejection: fn() -> anyhow::Error = || crate::proxy::PacketRejection::Capacity.into();
    for (front, land) in [(Some(rejection), None), (None, Some(rejection))] {
        let fakes = Fakes::new(
            FakeHop {
                failure: front,
                ..Default::default()
            },
            FakeHop {
                failure: land,
                ..Default::default()
            },
        );
        let route = fakes.route();
        for dial in [DialRef::Node(fakes.via.id), DialRef::Route(&route)] {
            let error = fakes
                .dial_ref(dial, Duration::from_secs(1))
                .await
                .unwrap_err();
            assert_eq!(
                crate::proxy::packet_rejection(&error),
                Some(crate::proxy::PacketRejection::Capacity),
                "{error:#}"
            );
            assert_eq!(
                dial_failure_scope(error.as_ref()),
                DialFailureScope::LocalRejection
            );
            assert!(!node_failure(&error), "{error:#}");
        }
    }
}

#[tokio::test]
async fn a_routed_failure_distinguishes_a_typed_hop_fault_from_ambiguous_io() {
    fn closed() -> anyhow::Error {
        io::Error::from(io::ErrorKind::UnexpectedEof).into()
    }
    let ambiguous: fn() -> anyhow::Error = closed;
    let carrier_fault: fn() -> anyhow::Error = || NodeFailure(closed()).into();
    for (hop, front, land, expected) in [
        (0, Some(ambiguous), None, DialFailureScope::Hop(0)),
        (1, None, Some(ambiguous), DialFailureScope::Unattributed),
        (1, None, Some(carrier_fault), DialFailureScope::Hop(1)),
    ] {
        let fakes = Fakes::new(
            FakeHop {
                failure: front,
                ..Default::default()
            },
            FakeHop {
                failure: land,
                ..Default::default()
            },
        );
        let route = fakes.route();
        let error = fakes
            .dial_ref(DialRef::Route(&route), Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(
            failed_hop(&error).map(|failure| (failure.hop, failure.node)),
            Some((hop, route.hops()[hop])),
            "{error:#}"
        );
        assert_eq!(dial_failure_scope(error.as_ref()), expected, "{error:#}");
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<io::Error>()
                .unwrap()
                .kind(),
            io::ErrorKind::UnexpectedEof,
        );
    }
}

/// A cancelled dial releases its carrier and leaves no transport evidence.
#[tokio::test]
async fn dropping_the_dial_after_the_first_hop_releases_everything() {
    let fakes = Fakes::new(
        FakeHop::default(),
        FakeHop {
            delay: Duration::from_secs(3600),
            ..Default::default()
        },
    );
    let runtime = fakes.generation.get(&fakes.via.id).unwrap();
    let held = || {
        runtime
            .chain_hops()
            .iter()
            .map(Arc::strong_count)
            .collect::<Vec<_>>()
    };
    let before = held();
    tokio::time::timeout(Duration::from_secs(5), async {
        let dial = fakes.dial(Duration::from_secs(1));
        tokio::pin!(dial);
        while fakes.calls().len() < 2 {
            assert!(futures_util::poll!(&mut dial).is_pending());
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut peer = fakes.front.peers.lock().unwrap().pop().unwrap();
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    assert_eq!(held(), before);
    for hop in std::iter::once(&runtime).chain(runtime.chain_hops()) {
        assert!(
            hop.transport_quality()
                .snapshot()
                .iter()
                .all(Option::is_none),
            "{}",
            hop.node.name
        );
    }
}

#[tokio::test]
async fn cancelling_a_socks_chain_releases_its_credit_while_the_parent_scope_is_alive() {
    use futures_util::FutureExt as _;

    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let entry = socks5_relay(Vec::new(), false).await;
        let front = socks5("front", "127.0.0.1", entry.addr.port());
        let exit = socks5("exit", "127.0.0.1", listener.local_addr().unwrap().port());
        let via = chain(&[&front, &exit]);
        let via_id = via.id;
        let (generation, _) = OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            &[via, front, exit],
            1,
            1,
            1,
            false,
            None,
        )
        .unwrap();
        let generation = Arc::new(generation);
        let scope = generation.dial_scope(|| {});
        let dial = tokio::spawn({
            let scope = Arc::clone(&scope);
            let generation = Arc::clone(&generation);
            async move {
                let registry = ProxyRegistry::default_resolver().unwrap();
                scope
                    .scope(registry.dial_runtime(
                        generation,
                        via_id,
                        target(),
                        None,
                        Duration::from_secs(10),
                    ))
                    .await
            }
        });
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        peer.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        assert!(generation.acquire_dial_permit().now_or_never().is_none());

        dial.abort();
        assert!(dial.await.unwrap_err().is_cancelled());
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        assert!(generation.acquire_dial_permit().now_or_never().is_some());
        assert_eq!(
            entry.requests(),
            [listener.local_addr().unwrap().to_string()]
        );
        drop(scope);
    })
    .await
    .unwrap();
}

/// Only the individual hops own sessions that can be warmed.
#[tokio::test]
async fn warming_a_chain_does_not_apply_and_leaves_its_hops_cold() {
    use crate::proxy::{WarmOutcome, WarmRequirement};

    let fakes = Fakes::new(FakeHop::default(), FakeHop::default());
    let descriptor = crate::descriptor::descriptor(NodeProtocol::Chain);
    assert!(!(descriptor.pool_bare_tcp)(&fakes.via));
    assert!(!(descriptor.pool_ready_streams)(&fakes.via));
    assert!(!descriptor.supports_warm(&fakes.via, WarmRequirement::Session));
    let outcome = ProxyRegistry::default_resolver()
        .unwrap()
        .warm_session(
            Arc::clone(&fakes.generation),
            fakes.via.id,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, WarmOutcome::NotApplicable));
    let runtime = fakes.generation.get(&fakes.via.id).unwrap();
    assert!(!runtime.chain_hops()[0].is_warm_or_stateless_for(WarmRequirement::Session));
}

#[tokio::test(start_paused = true)]
async fn later_hops_get_what_remains_of_one_chain_deadline() {
    let fakes = Fakes::new(
        FakeHop {
            delay: Duration::from_millis(250),
            ..Default::default()
        },
        FakeHop::default(),
    );
    fakes.dial(Duration::from_millis(100)).await.unwrap();
    let timeouts: Vec<_> = fakes.calls().into_iter().map(|call| call.timeout).collect();
    assert_eq!(
        timeouts,
        [Duration::from_millis(100), Duration::from_millis(50)]
    );
}

#[tokio::test(start_paused = true)]
async fn the_chain_deadline_bounds_every_hop_together() {
    let fakes = Fakes::new(
        FakeHop {
            delay: Duration::from_millis(200),
            ..Default::default()
        },
        FakeHop {
            delay: Duration::from_millis(200),
            ..Default::default()
        },
    );
    let started = Instant::now();
    let error = fakes.dial(Duration::from_millis(100)).await.unwrap_err();
    assert_eq!(started.elapsed(), Duration::from_millis(300));
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::TimedOut)
    );
}

#[tokio::test(start_paused = true)]
async fn reality_retry_uses_the_original_chain_deadline() {
    for routed in [false, true] {
        let delay = Duration::from_millis(80);
        let fakes = Fakes::new(
            FakeHop {
                delay,
                ..Default::default()
            },
            FakeHop {
                delay,
                masked: true,
                ..Default::default()
            },
        );
        let route = fakes.route();
        let dial = if routed {
            DialRef::Route(&route)
        } else {
            DialRef::Node(fakes.via.id)
        };
        let started = Instant::now();
        let error = fakes
            .dial_ref(dial, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_millis(300));
        assert_eq!(ScoreOutcome::from_error(&error), ScoreOutcome::Timeout);
        assert_eq!(
            dial_failure_scope(error.as_ref()),
            DialFailureScope::Unattributed
        );
        assert!(failed_hop(&error).is_none());
        let calls = fakes.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[3].key_shares, Some(false));
        assert_eq!(calls[3].timeout, Duration::from_millis(60));
    }
}

/// The whole chain runs inside the generation's dial scope. A generation that
/// retires while the front is still dialing gets the chain finished and then
/// dropped, front connection included, instead of handed out.
#[tokio::test(start_paused = true)]
async fn a_generation_shut_down_during_the_dial_publishes_nothing() {
    for routed in [false, true] {
        let fakes = Fakes::new(
            FakeHop {
                delay: Duration::from_millis(50),
                ..Default::default()
            },
            FakeHop::default(),
        );
        let route = fakes.route();
        let dial = if routed {
            DialRef::Route(&route)
        } else {
            DialRef::Node(fakes.via.id)
        };
        let dial = fakes.dial_ref(dial, Duration::from_secs(1));
        let shutdown = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            fakes.generation.begin_retirement();
        };
        let (result, ()) = tokio::join!(dial, shutdown);
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("shut down during dial"),
            "{error:#}"
        );
        let hops: Vec<_> = fakes.calls().into_iter().map(|call| call.hop).collect();
        assert_eq!(hops, ["front/runtime", "land/over"]);
        let mut peer = fakes.front.peers.lock().unwrap().pop().unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
}

#[cfg(feature = "flow-observation")]
async fn observed_milestones(
    land_reports: bool,
) -> Vec<crate::runtime::flow_observation::Milestone> {
    use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};

    let fakes = Fakes::new(
        FakeHop {
            milestones: true,
            ..Default::default()
        },
        FakeHop {
            milestones: land_reports,
            ..Default::default()
        },
    );
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&events);
    let observer = FlowObserver::new(
        FlowContext {
            flow_id: uuid::Uuid::nil(),
            generation: 0,
            attempt_id: None,
            lookup_id: None,
            dns_purpose: "",
        },
        Arc::new(move |_, event| {
            if let FlowEvent::Milestone { milestone } = event {
                log.lock().unwrap().push(milestone);
            }
        }),
    );
    observer
        .scope(fakes.dial(Duration::from_secs(1)))
        .await
        .unwrap();
    events.lock().unwrap().clone()
}

/// The front's transport readiness reaches the flow; its target milestones
/// describe the next hop's server and are dropped.
#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn only_the_last_hop_reports_target_milestones() {
    use crate::runtime::flow_observation::Milestone;

    assert_eq!(
        observed_milestones(false).await,
        [Milestone::TransportReady]
    );
    assert_eq!(
        observed_milestones(true).await,
        [
            Milestone::TransportReady,
            Milestone::TargetRequestSent,
            Milestone::TargetConfirmed,
        ]
    );
}

/// Shapes that require another connection must refuse before touching the carrier.
#[tokio::test]
async fn disallowed_later_hops_refuse_without_writing_to_the_carrier() {
    const UUID: &str = "00000000-0000-4000-8000-000000000001";
    let link = |link: &str| Node::from_share_link(link).unwrap();
    let rebuilt = |mut node: Node, change: &dyn Fn(&mut Node)| {
        change(&mut node);
        node.normalize_stream_transport().unwrap();
        node.id = node.derive_id();
        node
    };
    let vless = link(&format!(
        "vless://{UUID}@127.0.0.1:443?security=tls&sni=a.example"
    ));
    let mut vmess = socks5("vmess", "127.0.0.1", 443);
    vmess.outbound = OutboundConfig::Vmess(honk_config::node::VmessConfig {
        uuid: Some(UUID.into()),
        ..Default::default()
    });
    let xhttp = |node: &mut Node| node.transport_mut().unwrap().transport = "xhttp".into();
    let nodes = [
        link("trojan://secret@127.0.0.1:443?security=tls&sni=a.example&type=xhttp&path=%2Fx"),
        link("trojan://secret@127.0.0.1:443?ech=1&type=ws&host=a.example"),
        rebuilt(vmess, &xhttp),
        rebuilt(vless.clone(), &xhttp),
        rebuilt(vless.clone(), &|node| {
            node.vless_mut().unwrap().flow = Some("xtls-rprx-vision".into())
        }),
        rebuilt(vless.clone(), &|node| {
            node.vless_mut().unwrap().multiplex =
                honk_config::node::VlessMultiplex::H2 { padding: false }
        }),
        rebuilt(vless, &|node| {
            node.vless_mut().unwrap().encryption = Some("mlkem768x25519plus.native.0rtt.x".into())
        }),
        link("hysteria2://auth@127.0.0.1:443"),
        link(&format!("tuic://{UUID}:pass@127.0.0.1:443")),
        link(&format!("juicity://{UUID}:pass@127.0.0.1:443")),
        link("anytls://secret@127.0.0.1:443"),
    ];
    let registry = ProxyRegistry::default_resolver().unwrap();
    for node in nodes {
        assert!(!node.supports_tunneled_dial(), "{:?}", node.outbound);
        let protocol = node.protocol();
        let entry = registry.find(protocol);
        if !cfg!(feature = "rprx") && matches!(protocol, NodeProtocol::VLess | NodeProtocol::VMess)
        {
            assert!(entry.is_none(), "{protocol:?} was registered without rprx");
            continue;
        }
        let entry = entry.expect("missing protocol handler");
        let runtime = NodeRuntime::try_ephemeral(&node).unwrap();
        let (carrier, mut server) = tokio::io::duplex(1024);
        let dial = entry.tcp.dial_over(
            runtime,
            Box::new(carrier),
            target(),
            None,
            TunnelDialOptions::new(Duration::from_millis(100)),
        );
        let error = tokio::time::timeout(Duration::from_secs(1), dial)
            .await
            .unwrap()
            .unwrap_err();
        assert!(
            crate::proxy::tunnel_unsupported(&error),
            "{protocol:?}: {error:#}"
        );
        let mut byte = [0];
        let read = tokio::time::timeout(Duration::from_secs(1), server.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0, "{protocol:?} wrote to the carrier");
    }
}
