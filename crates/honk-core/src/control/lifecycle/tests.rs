use super::*;
use crate::control::tests::support::canonical_socks5;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WAIT: Duration = Duration::from_secs(20);

struct Fixture {
    commands: mpsc::Sender<ControlCommand>,
    phase: watch::Receiver<EnginePhase>,
    native: Arc<crate::native_api::observation::NativeObservation>,
    backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>>,
    shutdown: Arc<crate::control::ShutdownIntent>,
    task: tokio::task::JoinHandle<(ControlPlane, anyhow::Result<()>)>,
    api: crate::native_api::NativeServer,
    tproxy: SocketAddr,
    peer: tokio::net::TcpListener,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Fixture {
    async fn start_with(configure: impl FnOnce(&mut Config, SocketAddr)) -> anyhow::Result<Self> {
        let peer = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let mut config = Config::default();
        config.ensure_builtin_nodes();
        let node = canonical_socks5("peer", "127.0.0.1", peer.local_addr()?.port(), None);
        config.groups = vec![Group {
            name: "target".into(),
            nodes: vec![node.id],
            policy: honk_config::node::GroupPolicy::Fallback,
            ..Default::default()
        }];
        config.nodes.push(node);
        config.routing.default_outbound = "target".into();
        config.global.tproxy_port = free_port();
        config.global.nfqueue_enable = false;
        config.global.store_subscribe = false;
        config.experimental.cache_file.enabled = Some(false);
        config.global.dial_mode = "ip".into();
        config.global.connect_timeout_ms = 30_000;
        config.global.preconnect_node_count = 0;
        config.global.udp_warm_node_count = 0;
        config.global.check_interval_secs = 3600;
        config.global.bootstrap_resolver = "127.0.0.1:9".into();
        config.global.tcp_check_url.clear();
        config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
        let tproxy = SocketAddr::from(([127, 0, 0, 1], config.global.tproxy_port));
        let dns = SocketAddr::from(([127, 0, 0, 1], free_port()));
        config.dns.bind = format!("tcp://{dns}");
        config.dns.upstream[0].address = "127.0.0.1:9".into();
        config.dns.upstream[0].outbound = Some("direct".into());
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.allow_anonymous_loopback = true;
        configure(&mut config, peer.local_addr()?);
        let traffic_geo = crate::routing::GeoRequirements::for_traffic(&config.routing.rules);
        let dns_geo = crate::dns::routing::DnsRouter::geo_requirements(&config.dns);
        let sources = crate::routing::GeoSourceSet::load_captured(
            &traffic_geo.union(&dns_geo),
            std::path::Path::new(&config.global.data_dir),
            // Pin test inputs, not a developer's ambient DAE_LOCATION_ASSET directory.
            |path| {
                std::fs::read(
                    std::path::Path::new(&config.global.data_dir).join(path.file_name().unwrap()),
                )
                .map(Arc::from)
            },
        )?;
        let router = Router::from_config_with_geo_sources(&config.routing, &sources)?;
        let dns_router = Arc::new(crate::dns::routing::DnsRouter::new_with_geo_sources(
            &config.dns,
            &sources,
        )?);
        let proxy = Arc::new(ProxyRegistry::default_resolver()?);
        let upstream = Arc::new(
            crate::dns::upstream_pool::UpstreamPool::new_with_proxy_and_bootstrap(
                &config.dns.upstream,
                dns_router.clone(),
                Some(proxy.clone()),
                config.nodes.clone(),
                config.groups.clone(),
                honk_outbound::bootstrap::BootstrapResolver::parse(
                    &config.global.bootstrap_resolver,
                ),
                config.dns.strategy,
            )?,
        );
        let hosts = crate::dns::forwarder::HostsSourceSet::load(&config.dns)?.parse()?;
        let policy = crate::dns::policy::PolicyId::from_config_with_artifacts(
            &config.dns,
            &hosts.fingerprint(),
            &dns_router.geo_fingerprint(),
        )?;
        let forwarder = Arc::new(
            crate::dns::forwarder::DnsForwarder::new(
                upstream.clone(),
                Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                    100,
                ))),
                dns_router,
            )
            .with_configured_upstreams(&config.dns)
            .with_cache_enabled(config.dns.cache.enabled)
            .with_policy_id(policy)
            .with_hosts_snapshot(hosts),
        );
        let state = config
            .experimental
            .cache_file
            .stores_selections()
            .then(|| crate::state::StateDb::open(std::path::Path::new(&config.global.data_dir)))
            .transpose()?
            .map(Arc::new);
        let mut plane = ControlPlane::new_with_upstream_pool(
            config,
            Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
            router,
            proxy,
            forwarder,
            upstream,
        )?;
        plane.init_cache_db(state, None).await;
        plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
            crate::mode::ModeState::native(),
        )));
        plane.start_datapath_flags_coordinator()?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let state = crate::native_api::NativeState::new(
            &mut plane,
            address,
            std::time::SystemTime::now(),
            std::time::Instant::now(),
        )
        .await?;
        let phase = plane.observe_phase();
        let native = Arc::clone(&state.observation);
        let commands = plane.command_sender();
        let backend = plane.policy_backend_handle();
        let shutdown = plane.shutdown_requested.clone();
        plane.alive_set().shutdown_health_checks().await?;
        let api = crate::native_api::NativeServer::start(listener, Arc::new(state));
        let task = tokio::spawn(async move {
            let result = plane.run().await;
            (plane, result)
        });
        let fixture = Self {
            commands,
            phase,
            native,
            backend,
            shutdown,
            task,
            api,
            tproxy,
            peer,
        };
        tokio::time::timeout(WAIT, async {
            loop {
                if *fixture.phase.borrow() == EnginePhase::Running
                    && fixture.native.probes.running()
                {
                    break;
                }
                assert!(
                    !fixture.task.is_finished(),
                    "mock command owner stopped before admission"
                );
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(fixture)
    }

    async fn connect_tcp(&self) -> anyhow::Result<TcpStream> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind("127.0.0.1:0".parse()?)?;
        let client = socket.local_addr()?;
        let tuples = crate::control::connection::build_tuples_key(
            self.tproxy.ip(),
            self.tproxy.port(),
            client.ip(),
            client.port(),
            6,
        );
        self.backend
            .write()
            .await
            .tc_mut()
            .unwrap()
            .tcp_conn_state_store(
                &tuples,
                &honk_ebpf_common::ConnState {
                    state: honk_ebpf_common::conn::TcpState::TcpStateActive as u8,
                    last_seen_ns: crate::control::janitor::monotonic_now_ns()?,
                    ..Default::default()
                },
            )?;
        Ok(tokio::time::timeout(WAIT, socket.connect(self.tproxy)).await??)
    }

    async fn socks_peer(&self) -> TcpStream {
        socks_peer(&self.peer).await
    }

    async fn finish(self, failure: bool) -> ControlPlane {
        if !self.task.is_finished() {
            self.shutdown.request();
            let _ = self.commands.send(ControlCommand::Shutdown).await;
        }
        let (plane, result) = tokio::time::timeout(WAIT, self.task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            result.is_err(),
            failure,
            "unexpected lifecycle result: {result:?}"
        );
        self.api.shutdown().await;
        plane
    }
}

async fn socks_peer(listener: &tokio::net::TcpListener) -> TcpStream {
    tokio::time::timeout(WAIT, async {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hello = [0; 2];
            if stream.read_exact(&mut hello).await.is_err() {
                continue;
            }
            assert_eq!(hello[0], 5);
            let mut methods = vec![0; hello[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            return stream;
        }
    })
    .await
    .expect("timed out accepting a SOCKS greeting")
}

async fn socks_request(stream: &mut TcpStream) -> u8 {
    tokio::time::timeout(WAIT, async {
        stream.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 5);
        assert_eq!(header[2], 0);
        let length = match header[3] {
            1 => 4,
            4 => 16,
            3 => stream.read_u8().await.unwrap() as usize,
            _ => panic!("invalid SOCKS destination"),
        };
        let mut target = vec![0; length + 2];
        stream.read_exact(&mut target).await.unwrap();
        header[1]
    })
    .await
    .expect("timed out receiving the SOCKS request")
}

async fn complete_socks(stream: &mut TcpStream) {
    tokio::time::timeout(WAIT, async {
        assert_eq!(socks_request(stream).await, 1);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
    })
    .await
    .expect("timed out completing the SOCKS handshake");
}

#[tokio::test]
#[ignore = "requires transparent-listener permissions; run in the isolated lifecycle gate"]
async fn ordinary_shutdown_preserves_live_tcp_until_graceful_completion() -> anyhow::Result<()> {
    let mut fixture = Fixture::start_with(|config, _| {
        config.global.shutdown_wait_connections = true;
    })
    .await?;
    let mut client = fixture.connect_tcp().await?;
    client.write_all(b"request").await?;
    let mut peer = fixture.socks_peer().await;
    complete_socks(&mut peer).await;
    let mut request = [0; 7];
    tokio::time::timeout(WAIT, peer.read_exact(&mut request))
        .await
        .expect("timed out receiving graceful-shutdown TCP request at the SOCKS peer")?;
    assert_eq!(&request, b"request");
    fixture.shutdown.request();
    fixture.commands.send(ControlCommand::Shutdown).await?;
    tokio::time::timeout(
        WAIT,
        fixture
            .phase
            .wait_for(|phase| *phase == EnginePhase::Draining),
    )
    .await??;
    tokio::time::sleep(Duration::from_millis(100)).await;
    peer.write_all(b"final response").await?;
    let mut response = [0; 14];
    tokio::time::timeout(WAIT, client.read_exact(&mut response)).await??;
    assert_eq!(&response, b"final response");
    drop(client);
    drop(peer);
    let plane = fixture.finish(false).await;
    assert_eq!(plane.drain_tracker.active_count(), 0);
    Ok(())
}

#[cfg(all(feature = "native-api", feature = "ebpf", target_os = "linux"))]
#[tokio::test]
async fn a_socket_without_any_receive_trace_is_untraced() {
    use std::os::fd::{FromRawFd, IntoRawFd};
    // A pipe refuses `SO_RCVPRIORITY` on every kernel, and the mock backend has no eBPF trace.
    let (read, _write) = nix::unistd::pipe().unwrap();
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(read.into_raw_fd()) };
    socket.set_nonblocking(true).unwrap();
    let socket = tokio::net::UdpSocket::from_std(socket).unwrap();
    let ebpf: RwLock<Box<dyn crate::ebpf::PolicyBackend>> =
        RwLock::new(Box::new(crate::ebpf::mock::MockEbpfBackend::new()));
    let mut batch = sockets::UdpRecvBatch::new().unwrap();
    assert!(
        super::enable_receive_trace(&ebpf, &mut batch, &socket)
            .await
            .is_err()
    );
}

#[cfg(all(feature = "native-api", feature = "ebpf", target_os = "linux"))]
#[test]
fn udp_trace_is_reported_until_a_listener_generation_traces() {
    let degradations = crate::degradations::Degradations::default();
    let reason = || {
        degradations
            .get(crate::degradations::Component::UdpTrace)
            .map(|issue| issue.reason)
    };
    for (unavailable, expected) in [
        ([true, false], "ipv4_unavailable"),
        ([false, true], "ipv6_unavailable"),
        ([true, true], "unavailable"),
    ] {
        assert!(super::record_udp_trace(&degradations, unavailable));
        assert!(!super::record_udp_trace(&degradations, unavailable));
        assert_eq!(reason(), Some(expected));
    }
    super::record_udp_trace(&degradations, [false, false]);
    assert_eq!(reason(), None);
}

async fn mock_plane(backend: crate::ebpf::mock::MockEbpfBackend) -> ControlPlane {
    let plane = crate::control::tests::support::control_plane(Config::default());
    *plane.ebpf.write().await = Box::new(backend);
    plane
}

#[tokio::test]
async fn shutdown_quiesces_nfqueue_before_closing_datapath_admission() -> anyhow::Result<()> {
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let observed = backend.quiesce_datapath_ready.clone();
    let mut plane = mock_plane(backend).await;
    plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::native(),
    )));
    plane.start_datapath_flags_coordinator()?;
    plane.initialize_datapath_flags(true, true).await?;
    {
        let mut ebpf = tokio::sync::RwLockWriteGuard::map(plane.ebpf.write().await, |backend| {
            backend.tc_mut().unwrap()
        });
        ebpf.publish_listener_sockets(0, None, &[], &[])?;
        ebpf.set_datapath_ready(true)?;
    }
    plane.shutdown_runtime(None, None).await?;
    assert_eq!(
        *observed.lock(),
        [true],
        "NFQUEUE quiescence must complete while datapath admission is still closed to passthrough"
    );
    Ok(())
}

#[tokio::test]
async fn shutdown_detaches_hooks_only_after_udp_cleanup() -> anyhow::Result<()> {
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let detached = backend.detach_calls.clone();
    let mut plane = mock_plane(backend).await;
    let (release, parked) = tokio::sync::oneshot::channel::<()>();
    assert!(plane.udp_pool.spawn_slow_path(async move {
        let _ = parked.await;
    }));
    let shutdown = plane.shutdown_runtime(None, None);
    tokio::pin!(shutdown);
    tokio::select! {
        result = &mut shutdown => panic!("shutdown finished with parked UDP cleanup: {result:?}"),
        () = tokio::time::sleep(Duration::from_millis(200)) => {}
    }
    assert_eq!(
        detached.load(Ordering::Relaxed),
        0,
        "hooks must stay attached until admitted UDP ownership drains"
    );
    release.send(()).unwrap();
    shutdown.await?;
    assert_eq!(detached.load(Ordering::Relaxed), 1);
    Ok(())
}

fn wireguard_node(peer: SocketAddr) -> anyhow::Result<honk_config::node::Node> {
    use base64::Engine as _;
    use honk_config::node::{Node, OutboundConfig, WireGuardConfig, WireGuardKey};

    let key = |byte: u8| -> WireGuardKey {
        base64::engine::general_purpose::STANDARD
            .encode([byte; 32])
            .parse()
            .unwrap()
    };
    let mut node = Node {
        name: "wg-teardown".into(),
        host: "127.0.0.1".into(),
        port: peer.port(),
        outbound: OutboundConfig::WireGuard(WireGuardConfig {
            private_key: Some(key(7)),
            public_key: Some(key(8)),
            local_v4: Some("10.0.0.2".parse()?),
            ..WireGuardConfig::default()
        }),
        ..Node::default()
    };
    node.normalize_wireguard();
    node.id = node.derive_id();
    Ok(node)
}

/// A plane whose runtime generation is warming a WireGuard tunnel to `peer` (which never
/// answers), returned once the tunnel's first initiation reaches `peer` from an outer address
/// other than `known`. Warming through the plane's runtime is what puts the tunnel in the plane's
/// own registry.
async fn plane_warming_a_tunnel(
    node: &honk_config::node::Node,
    peer: &tokio::net::UdpSocket,
    known: Option<SocketAddr>,
) -> anyhow::Result<(
    ControlPlane,
    tokio::task::JoinHandle<anyhow::Result<honk_outbound::proxy::WarmOutcome>>,
    SocketAddr,
)> {
    let plane = mock_plane(crate::ebpf::mock::MockEbpfBackend::new()).await;
    let generation = Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(
        std::slice::from_ref(node),
    )?);
    *plane.runtime_registry.write() = Arc::clone(&generation);
    let proxy = ProxyRegistry::default_resolver()?;
    let id = node.id;
    let warm = tokio::spawn(async move { proxy.warm_session(generation, id, WAIT).await });
    let mut buffer = [0; 2048];
    let outer = tokio::time::timeout(WAIT, async {
        loop {
            let (_, from) = peer.recv_from(&mut buffer).await?;
            if Some(from) != known {
                return anyhow::Ok(from);
            }
        }
    })
    .await??;
    Ok((plane, warm, outer))
}

/// Whether the tunnel that owned the outer UDP port `outer` has ended and released its socket.
fn tunnel_socket_released(outer: SocketAddr) -> bool {
    std::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], outer.port()))).is_ok()
}

/// WireGuard tunnels own marked UDP sockets; the terminal teardown must close and join its plane's
/// tunnels, not leave them to idle out.
#[tokio::test]
async fn shutdown_closes_and_joins_the_planes_wireguard_tunnels() -> anyhow::Result<()> {
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let node = wireguard_node(peer.local_addr()?)?;
    let (mut plane, warm, outer) = plane_warming_a_tunnel(&node, &peer, None).await?;
    assert!(!tunnel_socket_released(outer), "the tunnel is running");
    plane.shutdown_runtime(None, None).await?;
    assert!(
        tunnel_socket_released(outer),
        "teardown left a live tunnel behind"
    );
    let _ = tokio::time::timeout(WAIT, warm).await??;
    Ok(())
}

/// Two planes (one embedder, or tests in one process) with the same WireGuard node each have their
/// own tunnel; one plane's teardown neither ends nor waits for the other's.
#[tokio::test]
async fn shutdown_leaves_another_planes_wireguard_tunnels_alone() -> anyhow::Result<()> {
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let node = wireguard_node(peer.local_addr()?)?;
    let (mut first, first_warm, first_outer) = plane_warming_a_tunnel(&node, &peer, None).await?;
    let (mut second, second_warm, second_outer) =
        plane_warming_a_tunnel(&node, &peer, Some(first_outer)).await?;
    assert_ne!(first_outer, second_outer, "one tunnel per plane");

    first.shutdown_runtime(None, None).await?;
    assert!(tunnel_socket_released(first_outer));
    assert!(
        !tunnel_socket_released(second_outer) && !second_warm.is_finished(),
        "the other plane's tunnel is still running"
    );

    second.shutdown_runtime(None, None).await?;
    assert!(tunnel_socket_released(second_outer));
    let _ = tokio::time::timeout(WAIT, async { tokio::join!(first_warm, second_warm) }).await?;
    Ok(())
}

#[cfg(feature = "clash-api")]
#[tokio::test(start_paused = true)]
async fn shutdown_waits_for_a_slow_ui_download_past_the_stage_deadline() -> anyhow::Result<()> {
    let mut plane = mock_plane(crate::ebpf::mock::MockEbpfBackend::new()).await;
    let (release, parked) = tokio::sync::oneshot::channel::<()>();
    *plane.ui_download.lock().await = Some(crate::clash_api::ui::UiDownloadTask::from_handle(
        tokio::spawn(async move {
            let _ = parked.await;
        }),
    ));
    let slot = Arc::clone(&plane.ui_download);
    let shutdown = plane.shutdown_runtime(None, None);
    tokio::pin!(shutdown);
    tokio::select! {
        result = &mut shutdown => panic!("shutdown abandoned the UI download owner: {result:?}"),
        () = tokio::time::sleep(STAGE_TIMEOUT + Duration::from_secs(1)) => {}
    }
    release.send(()).unwrap();
    shutdown.await?;
    assert!(slot.lock().await.is_none());
    Ok(())
}
