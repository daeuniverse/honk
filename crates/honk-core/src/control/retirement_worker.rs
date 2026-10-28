use super::connection::handoff::{TcpFlowGuard, TcpFlowPins};
use super::udp_endpoint::{EndpointRemoval, RemovalReason};
use super::*;
use crate::ebpf::{
    FlowExpiryHint, RETIRE_BATCH_CAPACITY, RetireKind, RetireOutcome, RetireRequest,
};

pub(in crate::control) type RetirementWorker =
    tokio::task::JoinHandle<Option<mpsc::Receiver<FlowExpiryHint>>>;

#[derive(Default)]
pub(in crate::control) struct RetirementPort {
    pub(in crate::control) sink: parking_lot::Mutex<Option<mpsc::Sender<TcpRetirement>>>,
    pub(in crate::control) hints: parking_lot::Mutex<Option<mpsc::Receiver<FlowExpiryHint>>>,
    pub(in crate::control) pin_errors: crate::ebpf::TcpPinErrorSink,
}

pub(in crate::control) struct TcpRetirement {
    pub(in crate::control) flow: TcpFlowGuard,
    pub(in crate::control) completion: tokio::sync::oneshot::Sender<bool>,
}

enum Retirement {
    Udp(EndpointRemoval),
    Tcp(TcpRetirement),
    Hint(FlowExpiryHint),
}

impl Retirement {
    async fn drain_io(&mut self, pool: &UdpEndpointPool) -> anyhow::Result<()> {
        match self {
            Self::Udp(removal) => anyhow::ensure!(
                pool.wait_removal_io(removal).await,
                "UDP retirement did not complete owned I/O: token={}, generation={}",
                removal.owner.token,
                removal.generation
            ),
            Self::Tcp(retirement) => retirement.flow.close_transport(),
            Self::Hint(_) => {}
        }
        Ok(())
    }

    fn release_pins(&mut self) -> anyhow::Result<()> {
        match self {
            Self::Tcp(retirement) => retirement.flow.release_pin(),
            _ => Ok(()),
        }
    }

    fn request(&self, pins: &TcpFlowPins, now_ns: Option<u64>) -> Option<RetireRequest<'static>> {
        let request = match self {
            Self::Udp(removal)
                if removal.reason == RemovalReason::UserspaceEndpointRetired
                    && removal.owner.has_kernel_capture()
                    && removal.scope == honk_datapath::ScopeId::HOST =>
            {
                RetireRequest {
                    key: connection::build_tuples_key(
                        removal.dst.ip(),
                        removal.dst.port(),
                        removal.client.ip(),
                        removal.client.port(),
                        17,
                    ),
                    kind: RetireKind::Udp {
                        token: removal.owner.token,
                        incarnation: removal.owner.incarnation(),
                        pending_only: false,
                    },
                }
            }
            Self::Tcp(retirement) => RetireRequest {
                key: retirement.flow.tuples,
                kind: RetireKind::Tcp {
                    incarnation: retirement.flow.incarnation,
                },
            },
            Self::Hint(hint) => RetireRequest {
                key: hint.key,
                kind: RetireKind::ExpiryHint {
                    incarnation: hint.incarnation,
                    now_ns: now_ns?,
                },
            },
            _ => return None,
        };
        (!pins.contains(&request.key)).then_some(request)
    }

    fn settle(
        self,
        ok: bool,
        outcome: RetireOutcome,
        pool: &UdpEndpointPool,
        tracker: &ConnectionTracker,
    ) {
        match self {
            Self::Udp(removal) => {
                if ok && let Some(id) = removal.conn_id.as_deref() {
                    tracker.remove(id);
                }
                pool.finish_removal(&removal, ok);
            }
            Self::Tcp(TcpRetirement { flow, completion }) => {
                flow.finish_retirement(ok);
                let _ = completion.send(ok);
            }
            // The endpoint's own removal already owns its tombstone, so only
            // a kernel-side reclamation of the conn needs to reach the pool.
            Self::Hint(hint) => {
                if outcome == RetireOutcome::ConnRetired {
                    pool.retire_reclaimed(&hint.key, hint.incarnation);
                }
            }
        }
    }
}

struct Slot {
    job: Retirement,
    request: Option<RetireRequest<'static>>,
    ok: bool,
    outcome: RetireOutcome,
}

impl From<Retirement> for Slot {
    fn from(job: Retirement) -> Self {
        Self {
            job,
            request: None,
            ok: true,
            outcome: RetireOutcome::NotRun,
        }
    }
}

struct Ingress {
    udp: Option<mpsc::Receiver<EndpointRemoval>>,
    tcp: Option<mpsc::Receiver<TcpRetirement>>,
    hints: Option<mpsc::Receiver<FlowExpiryHint>>,
    fatal: mpsc::UnboundedSender<anyhow::Error>,
}

impl Ingress {
    fn drained(&mut self) -> bool {
        if self
            .udp
            .as_ref()
            .is_some_and(|rx| rx.is_closed() && rx.is_empty())
        {
            self.udp = None;
        }
        if self
            .tcp
            .as_ref()
            .is_some_and(|rx| rx.is_closed() && rx.is_empty())
        {
            self.tcp = None;
        }
        let drained = self.udp.is_none() && self.tcp.is_none();
        if !drained
            && self
                .hints
                .as_ref()
                .is_some_and(|rx| rx.is_closed() && rx.is_empty())
        {
            self.hints = None;
            self.hint_closed();
        }
        drained
    }

    fn hint_closed(&self) {
        let _ = self.fatal.send(anyhow::anyhow!(
            "flow expiry hint channel closed while retirement ingress was active"
        ));
    }

    async fn next(&mut self) -> Option<Retirement> {
        loop {
            if self.drained() {
                return None;
            }
            return Some(tokio::select! {
                biased;
                removal = async { self.udp.as_mut().unwrap().recv().await }, if self.udp.is_some() => match removal {
                    Some(removal) => Retirement::Udp(removal),
                    None => { self.udp = None; continue; }
                },
                retirement = async { self.tcp.as_mut().unwrap().recv().await }, if self.tcp.is_some() => match retirement {
                    Some(retirement) => Retirement::Tcp(retirement),
                    None => { self.tcp = None; continue; }
                },
                hint = async { self.hints.as_mut().unwrap().recv().await }, if self.hints.is_some() => match hint {
                    Some(hint) => Retirement::Hint(hint),
                    None => { self.hints = None; self.hint_closed(); continue; }
                },
            });
        }
    }

    fn fill(&mut self, slots: &mut Vec<Slot>) {
        while slots.len() < RETIRE_BATCH_CAPACITY {
            let before = slots.len();
            if let Some(removal) = self.udp.as_mut().and_then(|rx| rx.try_recv().ok()) {
                slots.push(Retirement::Udp(removal).into());
            }
            if slots.len() < RETIRE_BATCH_CAPACITY
                && let Some(retirement) = self.tcp.as_mut().and_then(|rx| rx.try_recv().ok())
            {
                slots.push(Retirement::Tcp(retirement).into());
            }
            if slots.len() < RETIRE_BATCH_CAPACITY
                && !self.drained()
                && let Some(hint) = self.hints.as_mut().and_then(|rx| rx.try_recv().ok())
            {
                slots.push(Retirement::Hint(hint).into());
            }
            if slots.len() == before {
                break;
            }
        }
    }
}

/// Admitted I/O and guards stay with this joined owner after waiter cancellation.
pub(in crate::control) fn spawn_retirement_worker(
    udp_pool: Arc<UdpEndpointPool>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    tracker: Arc<ConnectionTracker>,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
    tcp_flow_pins: Arc<TcpFlowPins>,
    port: Arc<RetirementPort>,
) -> RetirementWorker {
    let (tcp_tx, tcp_rx) = mpsc::channel(1024);
    *port.sink.lock() = Some(tcp_tx);
    *port.pin_errors.lock() = Some(fatal_tx.clone());
    let retained_hints = port.hints.lock().take();
    spawn_worker(
        udp_pool,
        tracker,
        fatal_tx,
        Some((ebpf, tcp_flow_pins)),
        Some(tcp_rx),
        retained_hints,
    )
}

pub(in crate::control) fn spawn_packet_retirement_worker(
    udp_pool: Arc<UdpEndpointPool>,
    tracker: Arc<ConnectionTracker>,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
) -> RetirementWorker {
    spawn_worker(udp_pool, tracker, fatal_tx, None, None, None)
}

type KernelRetirement = (Arc<RwLock<Box<dyn EbpfBackend>>>, Arc<TcpFlowPins>);

fn spawn_worker(
    udp_pool: Arc<UdpEndpointPool>,
    tracker: Arc<ConnectionTracker>,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
    kernel: Option<KernelRetirement>,
    tcp: Option<mpsc::Receiver<TcpRetirement>>,
    retained_hints: Option<mpsc::Receiver<FlowExpiryHint>>,
) -> RetirementWorker {
    let (remove_tx, remove_rx) = mpsc::channel(1024);
    udp_pool.set_remove_sink(remove_tx);
    tokio::spawn(async move {
        let mut exit = super::runtime::CriticalTaskExit {
            name: "flow_retirement_worker",
            fatal_tx: fatal_tx.clone(),
            expected: false,
        };
        let hints = match (retained_hints, kernel.as_ref()) {
            (Some(receiver), _) => Some(receiver),
            (None, Some((backend, _))) => backend.write().await.take_expiry_hints(),
            (None, None) => None,
        };
        let mut ingress = Ingress {
            udp: Some(remove_rx),
            tcp,
            hints,
            fatal: fatal_tx.clone(),
        };
        let mut slots = Vec::with_capacity(RETIRE_BATCH_CAPACITY);
        let mut requests = Vec::with_capacity(RETIRE_BATCH_CAPACITY);
        let mut outcomes = vec![RetireOutcome::NotRun; RETIRE_BATCH_CAPACITY];
        while let Some(first) = ingress.next().await {
            slots.push(first.into());
            ingress.fill(&mut slots);
            for slot in &mut slots {
                if let Err(error) = slot.job.drain_io(&udp_pool).await {
                    slot.ok = false;
                    let _ = fatal_tx.send(error);
                }
            }
            let mut backend = match &kernel {
                Some((backend, _)) => Some(backend.write().await),
                None => None,
            };
            // Both local and native pins leave under W before checking any
            // external owner; adoption retains both under continuous backendR.
            for slot in &mut slots {
                if let Err(error) = slot.job.release_pins() {
                    slot.ok = false;
                    let _ = fatal_tx.send(error.context("TCP retirement pin release failed"));
                }
            }
            let hint_time = if slots
                .iter()
                .any(|slot| matches!(slot.job, Retirement::Hint(_)))
            {
                match super::janitor::monotonic_now_ns() {
                    Ok(now) => Some(now),
                    Err(error) => {
                        let _ =
                            fatal_tx.send(error.context("reading flow retirement expiry clock"));
                        None
                    }
                }
            } else {
                None
            };
            for slot in &mut slots {
                if slot.ok {
                    if let Some((_, pins)) = &kernel {
                        slot.request = slot.job.request(pins, hint_time);
                    } else if !matches!(&slot.job, Retirement::Udp(removal) if !removal.owner.has_kernel_capture())
                    {
                        slot.ok = false;
                        let _ = fatal_tx.send(anyhow::anyhow!(
                            "packet retirement received kernel-owned work"
                        ));
                    }
                }
            }
            requests.extend(slots.iter().filter_map(|slot| slot.request));
            let batch_ok = requests.is_empty()
                || match backend
                    .as_mut()
                    .expect("kernel requests require kernel authority")
                    .retire_batch(&requests, &mut outcomes[..requests.len()])
                {
                    Ok(_) => true,
                    Err(error) => {
                        let _ = fatal_tx.send(
                            anyhow::Error::new(error).context("flow retirement batch failed"),
                        );
                        false
                    }
                };
            drop(backend);
            for (slot, &outcome) in slots
                .iter_mut()
                .filter(|slot| slot.request.is_some())
                .zip(&outcomes)
            {
                slot.outcome = outcome;
                slot.ok = batch_ok && outcome.settled();
                if batch_ok
                    && !slot.ok
                    && (!matches!(slot.job, Retirement::Hint(_))
                        || outcome == RetireOutcome::NotRun)
                {
                    let _ = fatal_tx.send(anyhow::anyhow!(
                        "flow retirement identity mismatch or incomplete outcome: result={outcome:?}, request={:?}",
                        slot.request));
                }
            }
            for slot in slots.drain(..) {
                slot.job.settle(slot.ok, slot.outcome, &udp_pool, &tracker);
            }
            requests.clear();
            udp_pool.flush_removal_dirty();
        }
        exit.expected_stop();
        ingress.hints
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection_tracker::{
        CloseCompletion, CloseOutcome, CloseRequest, CloseSignal, ConnectionEntry,
    };
    use crate::control::connection::handoff::RetireAck;
    use crate::ebpf::{TcpPin, mock::MockEbpfBackend};
    use honk_ebpf_common::conn::{ConnState, TcpState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn packet_retirement_cannot_delete_a_coincident_kernel_flow() {
        use crate::ebpf::UdpFlowOwner;
        use honk_datapath::ScopeId;
        let client: SocketAddr = "192.0.2.1:50000".parse().unwrap();
        let dst: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let key =
            connection::build_tuples_key(dst.ip(), dst.port(), client.ip(), client.port(), 17);
        let mut backend = MockEbpfBackend::new();
        let state = ConnState {
            decision_token: 71,
            incarnation: 99,
            state: honk_ebpf_common::UdpDecisionState::Proxy as u8,
            ..Default::default()
        };
        backend.udp_conn_state_store(&key, &state).unwrap();
        let captured = backend.udp_flow_owner(71, Some(state)).unwrap();
        let mut packet = UdpFlowOwner::packet();
        packet.token = captured.token;
        packet.incarnation = captured.incarnation;
        assert!(backend.verify_udp_admission(&key, packet).is_err());
        let pins = TcpFlowPins::default();
        let foreign = ScopeId::allocate().unwrap();
        for (scope, owner, allowed) in [
            (ScopeId::HOST, packet, false),
            (foreign, packet, false),
            (foreign, captured, false),
            (ScopeId::HOST, captured, true),
        ] {
            let job = Retirement::Udp(EndpointRemoval {
                scope,
                client,
                dst,
                owner,
                generation: 1,
                conn_id: None,
                reason: RemovalReason::UserspaceEndpointRetired,
            });
            let request = job.request(&pins, None);
            assert_eq!(request.is_some(), allowed);
            if let Some(request) = request {
                let mut outcome = [RetireOutcome::NotRun];
                backend.retire_batch(&[request], &mut outcome).unwrap();
                assert_eq!(outcome[0], RetireOutcome::ConnRetired);
            }
            assert_eq!(backend.conn_state_lookup(&key).unwrap().is_some(), !allowed);
        }
    }

    #[tokio::test]
    async fn ingress_reports_closed_hints_until_real_producers_drain() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_tx, tcp_rx) = mpsc::channel(1);
        let (hint_tx, hint_rx) = mpsc::channel(1);
        let (fatal, mut errors) = mpsc::unbounded_channel();
        let mut ingress = Ingress {
            udp: Some(udp_rx),
            tcp: Some(tcp_rx),
            hints: Some(hint_rx),
            fatal,
        };
        drop(hint_tx);
        assert!(!ingress.drained());
        assert!(
            errors
                .try_recv()
                .unwrap()
                .to_string()
                .contains("flow expiry hint channel closed while retirement ingress was active")
        );
        assert!(ingress.hints.is_none());
        drop(udp_tx);
        assert!(!ingress.drained());
        assert!(
            errors.try_recv().is_err(),
            "hint closure was reported twice"
        );
        drop(tcp_tx);
        assert!(ingress.next().await.is_none());
        assert!(ingress.drained());
        assert!(errors.try_recv().is_err());
    }

    #[tokio::test]
    async fn cancelled_admitted_tcp_retirement_keeps_ownership_until_worker_join()
    -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (accepted, peer) = tokio::join!(
            listener.accept(),
            TcpStream::connect(listener.local_addr()?)
        );
        let stream = accepted?.0;
        let mut peer = peer?;
        let client: SocketAddr = "192.0.2.1:50000".parse()?;
        let destination: SocketAddr = "203.0.113.2:443".parse()?;
        let key = connection::build_tuples_key(
            destination.ip(),
            destination.port(),
            client.ip(),
            client.port(),
            6,
        );
        let mut mock = MockEbpfBackend::new();
        mock.tcp_conn_state_store(
            &key,
            &ConnState {
                state: TcpState::TcpStateActive as u8,
                incarnation: 71,
                ..ConnState::default()
            },
        )?;
        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(mock)));
        let pool = Arc::new(UdpEndpointPool::new());
        let pins = Arc::new(TcpFlowPins::default());
        let tracker = Arc::new(ConnectionTracker::new());
        let port = Arc::new(RetirementPort::default());
        let (hint_tx, hint_rx) = mpsc::channel(1);
        *port.hints.lock() = Some(hint_rx);
        let mut flow = TcpFlowGuard::new(
            stream,
            key,
            71,
            Arc::clone(&pins),
            Arc::clone(&tracker),
            Arc::clone(&port),
            TcpPin::Model,
        );
        let signal = CloseSignal::new();
        let ack = RetireAck {
            close: Some(CloseCompletion(Arc::clone(&signal))),
            ..Default::default()
        };
        let close = CloseRequest::Pending(signal);
        flow.track(ConnectionEntry {
            id: "admitted-cancellation".to_string(),
            source: client.to_string(),
            destination: destination.to_string(),
            proxy: "direct".to_string(),
            #[cfg(feature = "native-api")]
            routed_outbound: None,
            #[cfg(feature = "native-api")]
            native_flow_id: None,
            rule: "Fallback".to_string(),
            rule_payload: String::new(),
            chains: vec!["direct".to_string()],
            upload: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            download: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            start_time: std::time::Instant::now(),
            domain: None,
            network: "tcp".to_string(),
            process: None,
            process_path: None,
        });
        let locked = backend.read().await;
        let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();
        let worker = spawn_retirement_worker(
            Arc::clone(&pool),
            Arc::clone(&backend),
            Arc::clone(&tracker),
            fatal_tx,
            Arc::clone(&pins),
            Arc::clone(&port),
        );
        let sender = port.sink.lock().clone().unwrap();
        let mut retiring = Box::pin(flow.retire(ack));
        assert!(futures::poll!(&mut retiring).is_pending());
        assert_eq!(
            sender.capacity(),
            sender.max_capacity() - 1,
            "guard was admitted before cancellation"
        );
        drop(retiring);
        drop(sender);
        let mut confirmation = Box::pin(close.wait());
        assert!(
            futures::poll!(&mut confirmation).is_pending(),
            "cancelled waiter cannot fail admitted close"
        );
        assert!(pins.contains(&key));
        assert_eq!(tracker.snapshot().len(), 1);
        assert!(locked.conn_state_lookup(&key)?.is_some());
        let mut byte = [0u8; 1];
        let mut reading = Box::pin(peer.read(&mut byte));
        assert!(
            futures::poll!(&mut reading).is_pending(),
            "admitted socket must stay owned"
        );
        drop(reading);
        port.sink.lock().take();
        assert!(pool.shutdown().await.joined);
        let mut joining = worker;
        assert!(
            futures::poll!(&mut joining).is_pending(),
            "join must wait for backend exclusion"
        );
        drop(locked);
        let mut hints = tokio::time::timeout(Duration::from_secs(2), joining)
            .await??
            .expect("joined worker must return the live hint receiver");
        hint_tx.try_send(FlowExpiryHint {
            key,
            incarnation: 71,
        })?;
        assert_eq!(hints.try_recv()?.incarnation, 71);
        assert_eq!(confirmation.await, CloseOutcome::Closed);
        assert!(backend.read().await.conn_state_lookup(&key)?.is_none());
        assert!(!pins.contains(&key));
        assert!(tracker.snapshot().is_empty());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await??,
            0
        );
        assert!(fatal_rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn tcp_retirement_closes_accepted_socket_before_backend_retirement() -> anyhow::Result<()>
    {
        tcp_retirement_client_view(false).await
    }

    #[tokio::test]
    async fn tcp_retirement_resets_client_with_unread_data_before_backend_retirement()
    -> anyhow::Result<()> {
        tcp_retirement_client_view(true).await
    }

    async fn tcp_retirement_client_view(unread_client_data: bool) -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (accepted, peer) = tokio::join!(
            listener.accept(),
            TcpStream::connect(listener.local_addr()?)
        );
        let stream = accepted?.0;
        let mut peer = peer?;
        let key = connection::build_tuples_key(
            "203.0.113.2".parse()?,
            443,
            "192.0.2.1".parse()?,
            50001,
            6,
        );
        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
            Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
        let pool = Arc::new(UdpEndpointPool::new());
        let pins = Arc::new(TcpFlowPins::default());
        let port = Arc::new(RetirementPort::default());
        let (_hint_tx, hint_rx) = mpsc::channel(1);
        *port.hints.lock() = Some(hint_rx);
        let flow = TcpFlowGuard::new(
            stream,
            key,
            72,
            Arc::clone(&pins),
            Arc::new(ConnectionTracker::new()),
            Arc::clone(&port),
            TcpPin::Model,
        );
        let (fatal_tx, _fatal_rx) = mpsc::unbounded_channel();
        let worker = spawn_retirement_worker(
            Arc::clone(&pool),
            Arc::clone(&backend),
            Arc::new(ConnectionTracker::new()),
            fatal_tx,
            pins,
            Arc::clone(&port),
        );
        let held = backend.write().await;
        if unread_client_data {
            peer.write_all(b"x").await?;
        }
        let retiring = tokio::spawn(flow.retire(RetireAck::default()));
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
            .await
            .expect("client must see the close before the backend retires the flow");
        if unread_client_data {
            assert_eq!(
                read.expect_err("a full close with unread data resets the client")
                    .kind(),
                std::io::ErrorKind::ConnectionReset
            );
        } else {
            assert_eq!(read?, 0);
        }
        assert!(!retiring.is_finished());
        drop(held);
        let _ = retiring.await;
        port.sink.lock().take();
        assert!(pool.shutdown().await.joined);
        tokio::time::timeout(Duration::from_secs(2), worker).await??;
        Ok(())
    }
}
