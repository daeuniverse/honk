use super::*;
use crate::connection_tracker::ConnectionTracker;
use crate::control::connection::TcpFlowPins;
use crate::control::janitor::BpfJanitor;
use crate::control::retirement_worker::{RetirementPort, spawn_retirement_worker};
use crate::ebpf::{FlowExpiryHint, UdpFlowOwner, mock::MockEbpfBackend};
use honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS;

const OLD_TOKEN: u32 = 22;
const OLD_INCARNATION: u64 = 7;
const NEW_TOKEN: u32 = 23;
const NEW_INCARNATION: u64 = 8;

fn flow_key(client_port: u16) -> FlowKey {
    FlowKey::new(
        format!("192.0.2.10:{client_port}").parse().unwrap(),
        "198.51.100.20:443".parse().unwrap(),
    )
}

fn kernel_conn(state: UdpDecisionState, token: u32, incarnation: u64) -> ConnState {
    ConnState {
        incarnation,
        ..retained(token, state, ROUTING_META_FLAG_PUBLISHED)
    }
}

struct Fixture {
    backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>>,
    endpoints: Arc<UdpEndpointPool>,
    pending: Arc<PendingUdpVerdicts>,
    hints: mpsc::Sender<FlowExpiryHint>,
    fatal: mpsc::UnboundedReceiver<anyhow::Error>,
    _worker: crate::control::retirement_worker::RetirementWorker,
}

impl Fixture {
    fn new() -> Self {
        Self::with_backend(MockEbpfBackend::new())
    }

    fn with_backend(mock: MockEbpfBackend) -> Self {
        let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
            Arc::new(RwLock::new(Box::new(mock)));
        let endpoints = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let (pending, _) =
            PendingUdpVerdicts::new(Arc::clone(&backend), Arc::clone(&endpoints), stats);
        pending.open_admission();
        let port = Arc::new(RetirementPort::default());
        let (hints, receiver) = mpsc::channel(4);
        *port.hints.lock() = Some(receiver);
        let (fatal_tx, fatal) = mpsc::unbounded_channel();
        let worker = spawn_retirement_worker(
            Arc::clone(&endpoints),
            Arc::clone(&backend),
            Arc::new(ConnectionTracker::new()),
            fatal_tx,
            Arc::new(TcpFlowPins::default()),
            Arc::clone(&port),
        );
        Self {
            backend,
            endpoints,
            pending: Arc::new(pending),
            hints,
            fatal,
            _worker: worker,
        }
    }

    async fn serve(&self, key: FlowKey, incarnation: u64, kernel: ConnState) -> UdpInitLease {
        self.backend
            .write()
            .await
            .tc_mut()
            .unwrap()
            .udp_conn_state_store(&key.tuples(), &kernel)
            .unwrap();
        match self.endpoints.reserve_owned_or_enqueue_at(
            honk_datapath::ScopeId::HOST,
            key.client,
            key.destination,
            bytes::Bytes::from_static(b"old flow"),
            UdpFlowOwner::new(kernel.decision_token, Some(incarnation)).unwrap(),
            None,
            test_flow_slot(),
            Instant::now(),
            &StatsManager::new(),
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("endpoint must initialize"),
        }
    }

    async fn wait_until_endpoint_gone(&self, key: FlowKey) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self
                .endpoints
                .contains(honk_datapath::ScopeId::HOST, key.client, key.destination)
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("reclaimed flow's endpoint must be retired");
    }

    async fn stage_successor(&self, key: FlowKey) -> NfqueueIngest {
        self.backend
            .write()
            .await
            .tc_mut()
            .unwrap()
            .udp_conn_state_store(
                &key.tuples(),
                &kernel_conn(UdpDecisionState::Pending, NEW_TOKEN, NEW_INCARNATION),
            )
            .unwrap();
        let sink = Arc::new(Mutex::new(Vec::new()));
        let packet = QueuedPacket {
            tuple: UdpTuple {
                client: key.client,
                destination: key.destination,
            },
            payload: bytes::Bytes::from_static(b"uplink after kernel expiry"),
            mark: honk_ebpf_common::pack_nfqueue_mark(NEW_TOKEN).unwrap(),
            priority: None,
            received_at: Instant::now(),
        };
        self.pending
            .ingest_held_wait(
                packet,
                HeldVerdict::test(1, Instant::now(), sink),
                Some(test_flow_slot()),
            )
            .await
    }
}

#[tokio::test]
async fn kernel_reclamation_lets_a_staged_successor_initialize() {
    for from_hint in [true, false] {
        let mut fixture = Fixture::new();
        let key = flow_key(40000);
        // Aborted is expiry-eligible even on a freshly booted host.
        let state = if from_hint {
            UdpDecisionState::Aborted
        } else {
            UdpDecisionState::Proxy
        };
        let _old = fixture
            .serve(
                key,
                OLD_INCARNATION,
                kernel_conn(state, OLD_TOKEN, OLD_INCARNATION),
            )
            .await;
        if from_hint {
            fixture
                .hints
                .send(FlowExpiryHint {
                    key: key.tuples(),
                    incarnation: OLD_INCARNATION,
                })
                .await
                .unwrap();
        } else {
            BpfJanitor::new(
                Arc::clone(&fixture.backend),
                Arc::new(TcpFlowPins::default()),
            )
            .with_udp_pool(Arc::clone(&fixture.endpoints))
            .cleanup_conn_state_for_test(UDP_CONN_STATE_TIMEOUT_NS + 1)
            .await;
        }
        fixture.wait_until_endpoint_gone(key).await;
        assert!(matches!(
            fixture.stage_successor(key).await,
            NfqueueIngest::Initialize { .. }
        ));
        assert!(fixture.fatal.try_recv().is_err());
    }
}

#[tokio::test]
async fn hint_retirement_preserves_foreign_endpoint_incarnations() {
    for (kernel_incarnation, endpoint_incarnation) in [
        (NEW_INCARNATION, OLD_INCARNATION),
        (OLD_INCARNATION, NEW_INCARNATION),
    ] {
        let mut fixture = Fixture::new();
        let (foreign, sentinel) = (flow_key(40000), flow_key(40001));
        let _stale = fixture
            .serve(
                foreign,
                endpoint_incarnation,
                kernel_conn(UdpDecisionState::Aborted, OLD_TOKEN, kernel_incarnation),
            )
            .await;
        let _reclaimed = fixture
            .serve(sentinel, 9, kernel_conn(UdpDecisionState::Aborted, 31, 9))
            .await;
        for (key, incarnation) in [(foreign, OLD_INCARNATION), (sentinel, 9)] {
            fixture
                .hints
                .send(FlowExpiryHint {
                    key: key.tuples(),
                    incarnation,
                })
                .await
                .unwrap();
        }
        // Hints settle in order, so the sentinel's retirement proves the first was handled.
        fixture.wait_until_endpoint_gone(sentinel).await;
        assert!(fixture.endpoints.contains(
            honk_datapath::ScopeId::HOST,
            foreign.client,
            foreign.destination
        ));
        assert_eq!(
            fixture
                .backend
                .read()
                .await
                .tc()
                .unwrap()
                .conn_state_lookup(&foreign.tuples())
                .unwrap()
                .is_some(),
            kernel_incarnation != OLD_INCARNATION
        );
        assert!(fixture.fatal.try_recv().is_err());
    }
}

#[tokio::test]
async fn reload_after_a_terminal_commit_hands_the_flow_to_the_kernel() {
    for direct in [false, true] {
        let key = flow_key(40002);
        let kernel = kernel_conn(UdpDecisionState::Pending, OLD_TOKEN, OLD_INCARNATION);
        let mut mock = MockEbpfBackend::new();
        mock.seed_staged_udp_flow(&key.tuples(), kernel);
        let mut fixture = Fixture::with_backend(mock);
        let lease = fixture.serve(key, OLD_INCARNATION, kernel).await;
        let identity = PendingUdpVerdicts::identity_for_lease(&lease);
        fixture.pending.cells.insert(
            key,
            Arc::new(FlowCell::pending(
                identity,
                Instant::now(),
                HeldVerdict::test(1, Instant::now(), Arc::new(Mutex::new(Vec::new()))),
                Arc::clone(&fixture.pending.flow_slots)
                    .try_acquire_owned()
                    .unwrap(),
            )),
        );
        let pending = Arc::clone(&fixture.pending);
        let mut commit = Box::pin(async move {
            if direct {
                pending.activate_direct(identity, lease, 0x1200).await
            } else {
                pending.block(identity, lease).await
            }
        });
        assert!(futures::poll!(&mut commit).is_pending());
        let mut cancelling = Box::pin(fixture.endpoints.cancel_initializers_and_wait());
        assert!(futures::poll!(&mut cancelling).is_pending());
        assert!(commit.await.is_ok(), "direct={direct}");
        assert!(cancelling.await);
        fixture.wait_until_endpoint_gone(key).await;
        fixture.pending.shutdown_commit_pump().await.unwrap();
        assert!(fixture.fatal.try_recv().is_err(), "direct={direct}");
    }
}
