use super::*;
use crate::connection_tracker::ConnectionTracker;
use honk_netstack::FlowId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime as TokioRuntime};

const WAIT: Duration = Duration::from_secs(10);

fn runtime() -> TokioRuntime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

fn run<F: Future>(runtime: &TokioRuntime, operation: F) -> F::Output {
    runtime.block_on(async { tokio::time::timeout(WAIT, operation).await.unwrap() })
}

fn with_parent<T>(parent: &TokioRuntime, operation: impl FnOnce() -> T) -> T {
    std::thread::scope(|threads| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        threads.spawn(move || {
            parent.block_on(async {
                let _ = stopped.await;
            })
        });
        let result = operation();
        drop(stop);
        result
    })
}

struct Capture {
    shared: Arc<Shared>,
    realm: PacketRealm,
    endpoints: PacketEndpoints,
    supervisor: PacketEndpointOwner,
    drivers: Vec<PacketDriver>,
    worker: Worker,
    tracker: Arc<ConnectionTracker>,
    shutdown: Arc<crate::control::ShutdownIntent>,
    _health: TcpListener,
}

impl Capture {
    async fn ready(primary: &TokioRuntime) -> Self {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let admission = Arc::new(AtomicBool::new(false));
        let (shared, [_, receiver]) = Shared::new(2, 1500, 2, &budget, admission.clone()).unwrap();
        let (realm, owners) = capture_realm(1500, 1, 16, 2, 1, &budget).unwrap();
        realm.install_admission_fence(admission).unwrap();
        assert!(
            shared
                .placements
                .set(Arc::new(Placements::new(0, &budget).unwrap()))
                .is_ok()
        );
        let mut config = Config::default();
        config.ensure_builtin_nodes();
        config.global.dial_mode = "ip".into();
        config.global.tcp_check_url.clear();
        config.global.udp_check_dns = Some(vec!["127.0.0.1:9".into()]);
        config.global.preconnect_node_count = 0;
        config.global.udp_warm_node_count = 0;
        let polling = AdaptivePoll::new(polling::PollingPublication::new(&config), None);
        let plane = crate::control::tests::support::control_plane(config);
        let health = TcpListener::bind("127.0.0.1:0").await.unwrap();
        plane
            .alive_set()
            .set_direct_check_addr(health.local_addr().unwrap().to_string());
        let shutdown = plane.shutdown_intent();
        let tracker = plane.connection_tracker();
        tracker.enable();
        let (endpoints, mut supervisor, mut drivers) = PacketEndpoints::start_driven(
            plane,
            vec![(realm.clone(), owners)],
            1,
            None,
            ScopeId::HOST,
        )
        .await
        .unwrap();
        let setup = shared.defer_secondary_ready();
        let worker = Worker::start(
            shared.clone(),
            &mut [],
            Vec::new(),
            endpoints.clone(),
            receiver,
            false,
            polling,
            budget.clone(),
            shutdown.clone(),
        )
        .unwrap();
        shared.ready(0);
        poll_fn(|cx| {
            for driver in &mut drivers {
                driver.service(cx, Instant::now());
            }
            supervisor.poll_ready(cx)
        })
        .await
        .unwrap();
        poll_fn(|cx| shared.poll_ready(cx, true)).await.unwrap();
        assert!(
            shared
                .all_ready(&mut Context::from_waker(std::task::Waker::noop()))
                .is_pending()
        );
        {
            let _entered = primary.enter();
            shared.prepare_relays(&budget).unwrap();
        }
        setup.send(()).unwrap();
        poll_fn(|cx| shared.all_ready(cx)).await.unwrap();
        Self {
            shared,
            realm,
            endpoints,
            supervisor,
            drivers,
            worker,
            tracker,
            shutdown,
            _health: health,
        }
    }

    fn activate(&self, primary: &TokioRuntime) -> anyhow::Result<()> {
        let _entered = primary.enter();
        // The fixture supplies only the final physical eligibility observation.
        self.shared.activate(
            &self.shutdown,
            &self.endpoints,
            Some(DirectProfile::Endpoint),
            std::iter::once((&self.realm, 1, true)),
        )
    }

    fn fail_before_open(&self, primary: &TokioRuntime) -> anyhow::Error {
        let _entered = primary.enter();
        let mut failure = None;
        let candidates = std::iter::once((&self.realm, 1, true)).chain(std::iter::from_fn(|| {
            // The last PF has published both bindings; the final open has not committed.
            assert!(
                self.realm
                    .owners()
                    .iter()
                    .all(PacketScope::direct_relay_published)
            );
            self.fail_secondary();
            let deadline = Instant::now() + WAIT;
            while !self.shared.is_closing() {
                assert!(
                    Instant::now() < deadline,
                    "secondary failure did not close capture"
                );
                std::thread::yield_now();
            }
            failure = Some(self.shared.check_failure().unwrap_err());
            None
        }));
        let opening = self.shared.activate(
            &self.shutdown,
            &self.endpoints,
            Some(DirectProfile::Endpoint),
            candidates,
        );
        assert!(
            opening.is_err(),
            "final admission reopened after secondary failure"
        );
        failure.expect("startup must reach its final eligibility observation")
    }

    fn receive(&self, shard: usize, packet: &[u8]) {
        let now = Instant::now();
        let ingress = Ingress {
            scope: self.realm.scope(),
            namespace: 1,
            ifindex: 2,
            attachment: 1,
            mark: MarkProvenance::BeforeSkb,
        };
        self.shared
            .physical_endpoint(
                &mut None,
                &self.endpoints,
                &self.realm,
                shard,
                ingress,
                &[packet],
                PacketView::from_slice(packet),
                &mut [],
                (now, now),
                path(),
                false,
            )
            .unwrap();
    }

    async fn output(&mut self, shard: usize) -> OutputLease {
        let scope = &self.realm.owners()[shard];
        poll_fn(|cx| {
            self.drivers[shard].service(cx, Instant::now());
            scope.poll_output(cx)
        })
        .await
        .expect("original flow output")
    }

    async fn connect(&mut self, shard: usize) -> Flow {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let client = SocketAddr::from(([192, 0, 2, 10], 41000 + shard as u16));
        self.receive(shard, &syn(client, destination));
        let synack = self.output(shard).await;
        let id = synack.flow_id().unwrap();
        let ip = wire::parse_ip(synack.packet()).unwrap();
        let (header, _) = tcp::parse(&synack.packet()[ip.payload]).unwrap();
        assert_eq!(header.flags & (tcp::SYN | tcp::ACK), tcp::SYN | tcp::ACK);
        let ack = header.seq.wrapping_add(1);
        synack.release();
        self.receive(
            shard,
            &tcp_segment(client, destination, 101, ack, tcp::ACK, &[]),
        );
        let socket = listener.accept().await.unwrap().0.into_std().unwrap();
        let source = client.to_string();
        while !self
            .tracker
            .snapshot()
            .iter()
            .any(|flow| flow.source == source)
        {
            tokio::task::yield_now().await;
        }
        Flow {
            shard,
            client,
            destination,
            id,
            ack,
            socket,
        }
    }

    fn park_secondary(&self) -> sync_channel::Sender<()> {
        let (parked, entered) = sync_channel::channel();
        let (resume, resumed) = sync_channel::channel();
        let secondary = self
            .shared
            .relays
            .get()
            .unwrap()
            .secondary
            .as_ref()
            .unwrap();
        secondary.0.get().unwrap().spawn(async move {
            parked.send(()).unwrap();
            let _ = resumed.recv_timeout(WAIT * 2);
        });
        entered.recv_timeout(WAIT).unwrap();
        resume
    }

    fn fail_secondary(&self) {
        // Coordinator-only work on queue 1 takes WorkerRuntime::run's actual error exit.
        assert!(
            self.shared
                .send(
                    1,
                    envelope(&self.shared, 1, self.realm.scope(), Instant::now())
                )
                .is_ok()
        );
    }

    async fn secondary_error(&self) -> anyhow::Error {
        self.fail_secondary();
        let error = poll_fn(|cx| self.shared.poll_quiesced(cx))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("coordinator-only ingress"));
        error
    }

    fn assert_closed(&self) {
        assert!(!self.shared.admission.load(Ordering::Acquire));
        let client = SocketAddr::from(([192, 0, 2, 11], 42001));
        let dst = SocketAddr::from(([127, 0, 0, 1], 443));
        self.receive(1, &syn(client, dst));
        assert!(!self.endpoints.retained_transport(
            self.realm.scope(),
            client,
            dst,
            wire::PROTO_TCP
        ));
    }

    async fn join_endpoints(&mut self) {
        let (_, result) = poll_fn(|cx| {
            for driver in &mut self.drivers {
                driver.service_closing(cx, Instant::now());
            }
            self.supervisor.poll_join_plane(cx)
        })
        .await
        .unwrap();
        result.unwrap();
        self.endpoints.shutdown().await.unwrap();
        assert!(self.tracker.snapshot().is_empty());
        assert!(
            self.realm
                .owners()
                .iter()
                .all(PacketScope::is_protocol_quiescent)
        );
    }
}

struct Flow {
    shard: usize,
    client: SocketAddr,
    destination: SocketAddr,
    id: FlowId,
    ack: u32,
    socket: std::net::TcpStream,
}

fn socket_open(socket: &std::path::Path) -> bool {
    std::fs::read_dir("/proc/self/fd").unwrap().any(|entry| {
        match std::fs::read_link(entry.unwrap().path()) {
            Ok(target) => target == socket,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => panic!("reading process FD: {error}"),
        }
    })
}

impl Flow {
    fn upstream_socket(&self) -> std::path::PathBuf {
        use nix::sys::socket::{SockaddrIn, getpeername, getsockname};
        let dialed_from = self.socket.peer_addr().unwrap();
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .find_map(|entry| {
                let entry = entry.unwrap();
                let fd = entry.file_name().to_str().unwrap().parse().unwrap();
                let connected = getsockname::<SockaddrIn>(fd).map(SocketAddr::from)
                    == Ok(dialed_from)
                    && getpeername::<SockaddrIn>(fd).map(SocketAddr::from) == Ok(self.destination);
                connected.then(|| std::fs::read_link(entry.path()).unwrap())
            })
            .expect("the actual upstream socket must exist before injecting failure")
    }

    async fn eof(&self) {
        let mut peer = TcpStream::from_std(self.socket.try_clone().unwrap()).unwrap();
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    }

    async fn upload(&self, capture: &Capture, fin: bool) -> TcpStream {
        let mut peer = TcpStream::from_std(self.socket.try_clone().unwrap()).unwrap();
        let byte = [b'a' + self.shard as u8];
        capture.receive(
            self.shard,
            &tcp_segment(
                self.client,
                self.destination,
                101,
                self.ack,
                tcp::ACK | if fin { tcp::FIN } else { 0 },
                &byte,
            ),
        );
        let mut received = [0];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, byte);
        if fin {
            assert_eq!(peer.read(&mut received).await.unwrap(), 0);
        }
        peer
    }

    async fn exchange(&self, capture: &mut Capture) {
        let mut peer = self.upload(capture, true).await;
        let byte = [b'0' + self.shard as u8];
        peer.write_all(&byte).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut next = self.ack;
        let mut downloaded = false;
        loop {
            let output = capture.output(self.shard).await;
            let segment = &output.packet()[wire::parse_ip(output.packet()).unwrap().payload];
            let (header, offset) = tcp::parse(segment).unwrap();
            assert_eq!(header.flags & tcp::RST, 0);
            let fin = header.flags & tcp::FIN != 0;
            let payload = &segment[offset..];
            if !payload.is_empty() || fin {
                assert_eq!(output.flow_id(), Some(self.id));
                assert_eq!(header.seq, next);
                if !payload.is_empty() {
                    assert!(!downloaded);
                    assert_eq!(payload, byte);
                    downloaded = true;
                    next = next.wrapping_add(1);
                }
                next = next.wrapping_add(u32::from(fin));
                capture.receive(
                    self.shard,
                    &tcp_segment(self.client, self.destination, 103, next, tcp::ACK, &[]),
                );
            }
            output.release();
            if fin {
                assert!(downloaded);
                break;
            }
        }
    }
}

#[test]
fn both_shards_relay_bytes_and_fin_on_their_own_runtime() {
    let (parent, primary, observer) = (runtime(), runtime(), runtime());
    let mut capture = run(&parent, Capture::ready(&primary));
    let budget = capture.realm.owners()[0].budget();
    capture.activate(&primary).unwrap();
    let first = run(&parent, capture.connect(0));
    let second = run(&parent, capture.connect(1));
    // A misplaced socket cannot exchange these bytes on either of the two parked runtimes.
    let parked = capture.park_secondary();
    run(&primary, first.exchange(&mut capture));
    parked.send(()).unwrap();
    run(&observer, second.exchange(&mut capture));
    capture.shared.begin_close();
    capture.endpoints.close();
    capture.assert_closed();
    run(&parent, capture.join_endpoints());
    run(&primary, capture.worker.join()).unwrap();
    drop(capture);
    assert_eq!(budget.used(), 0);
}

#[test]
fn secondary_error_after_ready_or_live_relay_closes_admission() {
    if crate::test_support::run_exact_in_child(
        "HONK_XDP_SECONDARY_RELAY_CHILD",
        "xdp::worker::tests::direct_relay::secondary_error_after_ready_or_live_relay_closes_admission",
    ) {
        return;
    }
    let (parent, primary, observer) = (runtime(), runtime(), runtime());
    for open in [false, true] {
        let mut capture = run(&parent, Capture::ready(&primary));
        let flow = open.then(|| {
            capture.activate(&primary).unwrap();
            let flow = run(&parent, capture.connect(1));
            drop(run(&observer, flow.upload(&capture, false)));
            flow
        });
        let upstream = flow.as_ref().map(Flow::upstream_socket);
        let error = if open {
            run(&parent, capture.secondary_error())
        } else {
            capture.fail_before_open(&primary)
        };
        capture.assert_closed();
        if let Some(flow) = &flow {
            // The primary is still parked. Only the failed secondary can finish this socket.
            run(&parent, flow.eof());
        }
        let custody = (capture.shared.clone(), capture.endpoints.clone());
        let (_, terminal) = with_parent(&parent, || {
            run(
                &primary,
                finish_coordinator(Ok((None, Err(error))), Some(&custody)),
            )
        });
        assert!(
            upstream
                .as_deref()
                .is_none_or(|socket| !socket_open(socket))
        );
        assert!(
            terminal
                .unwrap_err()
                .to_string()
                .contains("coordinator-only ingress")
        );
        assert!(capture.endpoints.is_closing());
        assert!(!capture.shared.states[1].lock().exited);
        run(&parent, capture.join_endpoints());
    }
}

#[test]
fn coordinator_unwind_waits_for_secondary_socket_and_parent_join() {
    if crate::test_support::run_exact_in_child(
        "HONK_XDP_COORDINATOR_RELAY_CHILD",
        "xdp::worker::tests::direct_relay::coordinator_unwind_waits_for_secondary_socket_and_parent_join",
    ) {
        return;
    }
    let (parent, primary, observer) = (runtime(), runtime(), runtime());
    let mut capture = run(&parent, Capture::ready(&primary));
    capture.activate(&primary).unwrap();
    let flow = run(&parent, capture.connect(1));
    drop(run(&observer, flow.upload(&capture, false)));
    let parked = capture.park_secondary();
    let upstream = flow.upstream_socket();
    let custody = (capture.shared.clone(), capture.endpoints.clone());
    let outcome =
        std::panic::catch_unwind(|| panic!("injected coordinator unwind after admission"));
    let mut terminal = std::pin::pin!(finish_coordinator(outcome, Some(&custody)));
    run(&primary, async {
        assert!(
            futures::poll!(&mut terminal).is_pending(),
            "terminal result escaped the live secondary relay"
        );
    });
    assert!(capture.endpoints.is_closing());
    capture.assert_closed();
    assert_eq!(
        flow.socket.peek(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    parked.send(()).unwrap();
    run(&observer, flow.eof());
    run(&observer, async {
        while socket_open(&upstream) {
            tokio::task::yield_now().await;
        }
    });
    run(&primary, async {
        assert!(
            futures::poll!(&mut terminal).is_pending(),
            "socket EOF preceded the shared parent's join"
        );
    });
    let (plane, result) = with_parent(&parent, || run(&primary, terminal));
    assert!(plane.is_none());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("coordinator panicked")
    );
    assert!(
        !socket_open(&upstream),
        "terminal result retained the original upstream FD"
    );
    run(&parent, capture.join_endpoints());
    run(&primary, capture.worker.join()).unwrap();
}
