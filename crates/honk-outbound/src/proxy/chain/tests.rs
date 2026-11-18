use super::*;
use crate::proxy::{AsyncReadWrite, ProtocolEntry, ProxyRegistry, node_failure};
use crate::runtime::OutboundRuntimeRegistry;
use crate::test_support::{
    assert_legacy_bulk_echo, chain, mock_legacy_tcp_server, node, socks5, socks5_relay,
};
use honk_config::node::OutboundConfig;
use std::sync::Mutex;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// The Shadowsocks mock skips a 7-byte IPv4 target header.
const TARGET: &str = "93.184.216.34:80";

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
            tokio::spawn(mock_legacy_tcp_server(stream));
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
    let error = dial_chain(&[chain(&[&front, &land]), front, land])
        .await
        .unwrap_err();
    assert!(!target_failure(&error), "{error:#}");
    assert!(node_failure(&error), "{error:#}");
}

#[tokio::test]
async fn the_last_hop_target_failure_stays_a_target_failure() {
    let refusing = socks5_relay(Vec::new(), true).await;
    let relay = socks5_relay(Vec::new(), false).await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = socks5("land", "127.0.0.1", refusing.addr.port());
    let error = dial_chain(&[chain(&[&front, &land]), front, land])
        .await
        .unwrap_err();
    assert!(target_failure(&error), "{error:#}");
    assert_eq!(refusing.requests(), [TARGET]);
}

#[tokio::test]
async fn a_chain_without_its_generation_refuses_to_dial() {
    let front = socks5("front", "127.0.0.1", 1080);
    let land = shadowsocks("land", "127.0.0.1", 8388);
    let via = chain(&[&front, &land]);
    let handler = ChainHandler::new(Vec::new());
    assert!(
        handler
            .dial(&via, target(), None, Duration::from_secs(1))
            .await
            .is_err()
    );
    let runtime = NodeRuntime::try_ephemeral(&via).unwrap();
    assert!(
        handler
            .dial_runtime(runtime, target(), None, Duration::from_secs(1))
            .await
            .is_err()
    );
}

/// Records how the chain drives each hop and answers with a pass-through stream.
#[derive(Default)]
struct FakeHop {
    calls: Mutex<Vec<Call>>,
    delay: Duration,
    /// Fail tunneled dials with a REALITY mask certificate while key shares are on.
    masked: bool,
    /// Fail every dial with this error.
    failure: Option<fn() -> anyhow::Error>,
    milestones: bool,
    /// The far ends of the streams runtime dials open, to watch them close.
    peers: Mutex<Vec<tokio::io::DuplexStream>>,
}

#[derive(Clone, Debug, PartialEq)]
struct Call {
    hop: String,
    target: SocketAddr,
    domain: Option<String>,
    timeout: Duration,
    key_shares: Option<bool>,
}

impl FakeHop {
    fn record(&self, runtime: &NodeRuntime, target: SocketAddr, domain: Option<&str>) -> Call {
        Call {
            hop: runtime.node.name.clone(),
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
        let mut call = self.record(&runtime, target, target_domain);
        call.timeout = connect_timeout;
        let (stream, peer) = tokio::io::duplex(64);
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
        let mut call = self.record(&runtime, target, target_domain);
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
    fn new(front: FakeHop, land: FakeHop) -> Self {
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
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(&[via.clone(), anytls, trojan]).unwrap());
        Self {
            generation,
            via,
            front: Arc::new(front),
            land: Arc::new(land),
        }
    }

    fn handler(&self) -> ChainHandler {
        ChainHandler::new(vec![
            (
                NodeProtocol::AnyTLS,
                self.front.clone() as Arc<dyn TcpOutbound>,
            ),
            (
                NodeProtocol::Trojan,
                self.land.clone() as Arc<dyn TcpOutbound>,
            ),
        ])
    }

    async fn dial(&self, connect_timeout: Duration) -> anyhow::Result<ProxyStream> {
        self.handler()
            .dial_runtime(
                self.generation.get(&self.via.id).unwrap(),
                target(),
                Some("example.com"),
                connect_timeout,
            )
            .await
    }

    fn calls(&self) -> Vec<Call> {
        let mut calls = self.front.calls.lock().unwrap().clone();
        calls.extend(self.land.calls.lock().unwrap().iter().cloned());
        calls
    }
}

#[tokio::test]
async fn the_front_dials_its_own_runtime_toward_the_next_server() {
    let fakes = Fakes::new(FakeHop::default(), FakeHop::default());
    fakes.dial(Duration::from_secs(1)).await.unwrap();
    let second = Duration::from_secs(1);
    assert_eq!(
        fakes.calls(),
        [
            Call {
                hop: "front/runtime".into(),
                target: "0.0.0.0:443".parse().unwrap(),
                domain: Some("land.example".into()),
                timeout: second,
                key_shares: None,
            },
            Call {
                hop: "land/over".into(),
                target: target(),
                domain: Some("example.com".into()),
                timeout: second,
                key_shares: Some(true),
            },
        ]
    );
}

#[tokio::test]
async fn a_reality_mask_certificate_redials_the_chain_once_without_key_shares() {
    let fakes = Fakes::new(
        FakeHop::default(),
        FakeHop {
            masked: true,
            ..Default::default()
        },
    );
    fakes.dial(Duration::from_secs(1)).await.unwrap();
    let hops: Vec<_> = fakes
        .calls()
        .into_iter()
        .map(|call| (call.hop, call.key_shares))
        .collect();
    assert_eq!(
        hops,
        [
            ("front/runtime".to_string(), None),
            ("front/runtime".to_string(), None),
            ("land/over".to_string(), Some(true)),
            ("land/over".to_string(), Some(false)),
        ]
    );
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
    assert!(reality_mask_certificate(&error), "{error:#}");
    let hops: Vec<_> = fakes.calls().into_iter().map(|call| call.hop).collect();
    assert_eq!(hops, ["front/runtime"]);
}

/// A packet policy rejection keeps its class whichever hop raises it.
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
        let error = fakes.dial(Duration::from_secs(1)).await.unwrap_err();
        assert_eq!(
            crate::proxy::packet_rejection(&error),
            Some(crate::proxy::PacketRejection::Capacity),
            "{error:#}"
        );
        assert!(!node_failure(&error), "{error:#}");
    }
}

/// Dropping the dial once the front is up closes the front's connection and
/// returns every hop runtime it borrowed. The dial never finishes, so it
/// leaves no transport evidence for the chain or its hops.
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
        while fakes.land.calls.lock().unwrap().is_empty() {
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

/// Selector warm-up and preconnect pass over a chain: it has no session of
/// its own to warm and no bare socket to pool, and asking to warm it leaves
/// its session-protocol front cold.
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

/// The whole chain runs inside the generation's dial scope. A generation that
/// retires while the front is still dialing gets the chain finished and then
/// dropped, front connection included, instead of handed out.
#[tokio::test(start_paused = true)]
async fn a_generation_shut_down_during_the_dial_publishes_nothing() {
    let fakes = Fakes::new(
        FakeHop {
            delay: Duration::from_millis(50),
            ..Default::default()
        },
        FakeHop::default(),
    );
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(
        NodeProtocol::Chain,
        Arc::new(fakes.handler()),
    ));
    let dial = registry.dial_runtime(
        Arc::clone(&fakes.generation),
        fakes.via.id,
        target(),
        None,
        Duration::from_secs(1),
    );
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

/// `Node::supports_tunneled_dial` in honk-config decides which hops
/// `validate_assembled` accepts; every registered handler must agree with it.
#[tokio::test]
async fn tunneled_dial_support_matches_the_config_table() {
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
    let vmess = rebuilt(vmess, &|_| {});
    let xhttp = |node: &mut Node| node.transport_mut().unwrap().transport = "xhttp".into();
    let nodes = [
        link("socks5://127.0.0.1:1080"),
        link("ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:8388"),
        link("trojan://secret@127.0.0.1:443?security=tls&sni=a.example"),
        link("trojan://secret@127.0.0.1:443?security=tls&sni=a.example&type=ws&path=%2Fws"),
        link("trojan://secret@127.0.0.1:443?security=tls&sni=a.example&type=xhttp&path=%2Fx"),
        vmess.clone(),
        rebuilt(vmess, &xhttp),
        vless.clone(),
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
        // VLESS and VMess handlers exist only with the rprx feature.
        let Some(entry) = registry.find(node.protocol()) else {
            continue;
        };
        let runtime = NodeRuntime::try_ephemeral(&node).unwrap();
        let (carrier, _server) = tokio::io::duplex(1 << 16);
        let dial = entry.tcp.dial_over(
            runtime,
            Box::new(carrier),
            target(),
            None,
            TunnelDialOptions::new(Duration::from_millis(100)),
        );
        // A supported hop starts its handshake: it succeeds, fails on the
        // silent peer, or waits for it.
        let refused = matches!(
            tokio::time::timeout(Duration::from_millis(200), dial).await,
            Ok(Err(error)) if crate::proxy::tunnel_unsupported(&error)
        );
        assert_eq!(
            !refused,
            node.supports_tunneled_dial(),
            "{} {:?}",
            node.protocol().as_str(),
            node.outbound
        );
    }
}
