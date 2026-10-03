use super::*;
use crate::control::tests::support::canonical_socks5;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WAIT: Duration = Duration::from_secs(20);

struct Fixture {
    commands: mpsc::Sender<ControlCommand>,
    phase: watch::Receiver<EnginePhase>,
    native: Arc<crate::native_api::observation::NativeObservation>,
    backend: Arc<RwLock<Box<dyn EbpfBackend>>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
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
    async fn start() -> anyhow::Result<Self> {
        Self::start_with(|_, _| {}).await
    }

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
        let backend = plane.ebpf_handle();
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
        self.backend.write().await.tcp_conn_state_store(
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
            self.shutdown.store(true, Ordering::Release);
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
    let mut fixture = Fixture::start().await?;
    let mut client = fixture.connect_tcp().await?;
    client.write_all(b"request").await?;
    let mut peer = fixture.socks_peer().await;
    complete_socks(&mut peer).await;
    let mut request = [0; 7];
    tokio::time::timeout(WAIT, peer.read_exact(&mut request))
        .await
        .expect("timed out receiving graceful-shutdown TCP request at the SOCKS peer")?;
    assert_eq!(&request, b"request");
    fixture.shutdown.store(true, Ordering::Release);
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
    let ebpf: RwLock<Box<dyn EbpfBackend>> =
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
    let traced = || {
        degradations
            .get(crate::degradations::Component::UdpTrace)
            .is_none()
    };
    super::record_udp_trace(&degradations, true);
    assert!(!traced());
    super::record_udp_trace(&degradations, false);
    assert!(traced());
}
