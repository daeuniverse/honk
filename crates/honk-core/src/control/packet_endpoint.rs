//! Explicit L3 Endpoint integration, not packet capture or native continuation authority.
//!
//! The caller runs and joins `PacketEndpointOwner::run`, and retains each scope's
//! output lease through actual backend I/O. No kernel listener or hook is started.

use super::ControlPlane;
use super::connection::{ConnectionGuard, ControlPlaneHandle};
use super::dns_control::DnsUdpReply;
use super::netstack::{FlowIo, PacketOwner, PacketScope, SourceWork};
use super::task_registry::TaskRegistry;
use super::udp_endpoint::{
    DatagramPayload, EndpointReservation, FundedDatagram, RawDnsRoute, ReplySocketFd,
    UdpEndpointPool, UdpInitLease, UdpReplySocketFactory,
};
use honk_datapath::ScopeId;
use honk_netstack::{MemoryBudget, MemoryReservation, Rx, ValidatedSource};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};
use std::time::Instant;
use tokio::sync::{Notify, OwnedSemaphorePermit, mpsc};

const INGRESS_CAPACITY: usize = 64;
const MAX_SCOPES: usize = 64;
const STARTING: u8 = 0;
const READY: u8 = 1;
const CLOSING: u8 = 2;

fn report_tcp_completion(result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result
        && !error.is_cancelled()
    {
        tracing::error!(%error, "packet TCP connection task panicked");
    }
}

#[derive(Debug)]
struct Replies(Arc<[PacketScope]>);

impl UdpReplySocketFactory for Replies {
    fn create(&self, scope: ScopeId, source: SocketAddr) -> io::Result<ReplySocketFd> {
        self.0
            .iter()
            .find(|item| item.scope() == scope)
            .map(|item| ReplySocketFd::Packet(item.datagram_sender(source)))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "packet reply scope is not owned")
            })
    }

    fn uses_fd(&self) -> bool {
        false
    }
}

struct Datagram {
    scope: ScopeId,
    source: SocketAddr,
    destination: SocketAddr,
    dscp: u8,
    bytes: FundedDatagram,
    routing: Option<EndpointAdmission>,
    source_work: SourceWork,
}

#[allow(clippy::large_enum_variant)]
enum Work {
    Tcp(FlowIo, OwnedSemaphorePermit),
    Udp(Datagram),
}

struct Shared {
    scopes: Arc<[PacketScope]>,
    budget: Arc<MemoryBudget>,
    udp_pool: Arc<UdpEndpointPool>,
    tcp_slots: Arc<tokio::sync::Semaphore>,
    udp_slots: Arc<tokio::sync::Semaphore>,
    stats: Arc<crate::stats::StatsManager>,
    admission: AtomicU8,
    #[cfg(feature = "native-api")]
    capture_ready: AtomicBool,
    changed: Notify,
    closed: Arc<crate::connection_tracker::CloseSignal>,
    commands_closed: Arc<crate::connection_tracker::CloseSignal>,
    fatal_control: AtomicBool,
    supervisor_memory: std::sync::OnceLock<MemoryReservation>,
    _memory: MemoryReservation,
}

impl Shared {
    fn is_closing(&self) -> bool {
        self.admission.load(Ordering::Acquire) == CLOSING
    }

    fn close(&self) {
        self.admission.store(CLOSING, Ordering::Release);
        for scope in self.scopes.iter() {
            scope.shutdown(true);
        }
        self.changed.notify_one();
    }
}

/// An owning canonical route/config/runtime/mode decision, captured before ingress.
pub struct EndpointAdmission {
    snapshot: Box<super::connection::routing::PacketRoutingSnapshot>,
    _memory: MemoryReservation,
}

impl std::fmt::Debug for EndpointAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointAdmission").finish_non_exhaustive()
    }
}

impl EndpointAdmission {
    pub(in crate::control) fn new(
        snapshot: super::connection::routing::PacketRoutingSnapshot,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Self> {
        let bytes = size_of::<super::connection::routing::PacketRoutingSnapshot>()
            + 2 * size_of::<usize>()
            + snapshot.decision.retained_bytes()
            + snapshot.mode.name.capacity()
            + snapshot.mode_state.as_ref().map_or(0, |state| {
                state.mode.capacity() + state.global_selection().len()
            });
        #[cfg(feature = "native-api")]
        let bytes = bytes + snapshot.mode.group_id.as_ref().map_or(0, String::capacity);
        let memory = budget.reserve(bytes).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "packet routing admission memory capacity",
            )
        })?;
        Ok(Self {
            snapshot: Box::new(snapshot),
            _memory: memory,
        })
    }

    pub(in crate::control) fn into_snapshot(
        self,
    ) -> super::connection::routing::PacketRoutingSnapshot {
        let mut snapshot = *self.snapshot;
        snapshot.memory = Some(self._memory);
        snapshot
    }
}

/// A bounded ingress handle. Copies share admission, scopes and one core UDP pool.
#[derive(Clone)]
pub struct PacketEndpoints {
    shared: Arc<Shared>,
    sender: mpsc::Sender<Work>,
    initializers: mpsc::Sender<UdpInitLease>,
}

/// Join handle for the supervisor. Dropping it requests cleanup, never aborts cleanup.
pub struct PacketEndpointOwner {
    shared: Arc<Shared>,
    task: Option<tokio::task::JoinHandle<(ControlPlane, anyhow::Result<()>)>>,
}

struct EndpointRuntime {
    shared: Arc<Shared>,
    plane: ControlPlane,
    receiver: mpsc::Receiver<Work>,
    initializers: mpsc::Receiver<UdpInitLease>,
    owners: Vec<PacketOwner>,
    scope_tasks: TaskRegistry,
    tcp_tasks: TaskRegistry,
    startup: Option<tokio::sync::oneshot::Sender<()>>,
}

impl PacketEndpoints {
    /// Read-only execution ownership, including protocol/output and retirement tails.
    /// Classification does not validate a packet; receive must still verify its checksum.
    pub fn retains(
        &self,
        scope: ScopeId,
        source: SocketAddr,
        destination: SocketAddr,
        protocol: u8,
    ) -> bool {
        let Some(owned) = self
            .shared
            .scopes
            .iter()
            .find(|owned| owned.scope() == scope)
        else {
            return false;
        };
        match protocol {
            6 => owned.retains_tcp(source, destination),
            17 => self.shared.udp_pool.contains(scope, source, destination),
            _ => false,
        }
    }

    /// Includes protocol, initializer/retirement, queued work and actual output owners.
    /// Call outside the receive callback, which already holds the scope mutex.
    pub(crate) fn retains_source(&self, scope: ScopeId, address: std::net::IpAddr) -> bool {
        self.shared
            .scopes
            .iter()
            .find(|owned| owned.scope() == scope)
            .is_some_and(|owned| owned.retains_source(address))
            || self.shared.udp_pool.retains_source(scope, address)
    }

    /// Consume an unstarted control plane; no second host ingress is started beside it.
    /// `udp_capacity` is shared by every supplied scope, not multiplied per scope.
    pub async fn new(
        mut plane: ControlPlane,
        scopes: Vec<(PacketScope, PacketOwner)>,
        udp_capacity: usize,
    ) -> anyhow::Result<(Self, PacketEndpointOwner)> {
        anyhow::ensure!(
            plane.command_rx.is_some() && plane.health_task.is_none(),
            "packet endpoints require an unstarted control plane"
        );
        anyhow::ensure!(
            !scopes.is_empty() && scopes.len() <= MAX_SCOPES,
            "invalid packet scope count"
        );
        anyhow::ensure!(
            udp_capacity != 0 && udp_capacity <= plane.resource_budget.udp_endpoints,
            "invalid shared UDP endpoint capacity"
        );
        let budget = scopes[0].0.budget();
        for (index, (scope, owner)) in scopes.iter().enumerate() {
            anyhow::ensure!(
                scope.scope() != ScopeId::HOST && scope.scope() == owner.scope(),
                "packet scope owner mismatch"
            );
            anyhow::ensure!(
                Arc::ptr_eq(&budget, &scope.budget()),
                "packet scopes must share one memory ceiling"
            );
            anyhow::ensure!(
                !scopes[..index]
                    .iter()
                    .any(|(earlier, _)| earlier.scope() == scope.scope()),
                "duplicate packet scope"
            );
        }
        let mut tcp_capacity = 0usize;
        for (scope, _) in &scopes {
            tcp_capacity = tcp_capacity
                .checked_add(scope.prepare_endpoint()?)
                .ok_or_else(|| anyhow::anyhow!("packet flow capacity overflow"))?;
        }
        let scope_tasks = TaskRegistry::accounted(scopes.len(), &budget)?;
        let tcp_tasks = TaskRegistry::accounted(
            tcp_capacity.min(plane.resource_budget.elastic_tcp_flows(0, 0)),
            &budget,
        )?;
        let bytes = (INGRESS_CAPACITY + 32)
            .checked_mul(4 * (size_of::<Work>() + size_of::<UdpInitLease>()))
            .and_then(|n| {
                n.checked_add(MAX_SCOPES * (size_of::<PacketScope>() + size_of::<PacketOwner>()))
            })
            .and_then(|n| n.checked_add(size_of::<Shared>() + maintenance::COMMAND_MEMORY))
            .ok_or_else(|| anyhow::anyhow!("packet ingress capacity overflows"))?;
        let memory = budget
            .reserve(bytes)
            .ok_or_else(|| anyhow::anyhow!("packet ingress memory capacity"))?;
        let (scopes, owners): (Vec<_>, Vec<_>) = scopes.into_iter().unzip();
        let scopes: Arc<[PacketScope]> = scopes.into();
        plane.udp_pool = Arc::new(UdpEndpointPool::with_packet_reply_factory(
            udp_capacity,
            Arc::new(Replies(Arc::clone(&scopes))),
            Arc::clone(&budget),
        )?);
        plane.install_node_death_callback();
        let shared = Arc::new(Shared {
            scopes,
            budget,
            udp_pool: Arc::clone(&plane.udp_pool),
            tcp_slots: Arc::clone(&plane.concurrency_limit),
            udp_slots: Arc::clone(&plane.udp_concurrency_limit),
            stats: Arc::clone(&plane.stats),
            admission: AtomicU8::new(STARTING),
            #[cfg(feature = "native-api")]
            capture_ready: AtomicBool::new(false),
            changed: Notify::new(),
            closed: crate::connection_tracker::CloseSignal::new(),
            commands_closed: crate::connection_tracker::CloseSignal::new(),
            fatal_control: AtomicBool::new(false),
            supervisor_memory: std::sync::OnceLock::new(),
            _memory: memory,
        });
        let (sender, receiver) = mpsc::channel(INGRESS_CAPACITY);
        let (initializers, initializer_rx) = mpsc::channel(INGRESS_CAPACITY);
        let (started, ready) = tokio::sync::oneshot::channel();
        let runtime = EndpointRuntime {
            shared: Arc::clone(&shared),
            plane,
            receiver,
            initializers: initializer_rx,
            owners,
            scope_tasks,
            tcp_tasks,
            startup: Some(started),
        };
        let completed = Arc::clone(&shared.closed);
        let commands_closed = Arc::clone(&shared.commands_closed);
        let operation = async move {
            let _completion = crate::connection_tracker::CloseCompletion(Arc::clone(&completed));
            let _commands = crate::connection_tracker::CloseCompletion(commands_closed);
            let (plane, result) = runtime.run().await;
            completed.finish(result.is_ok());
            (plane, result)
        };
        let bytes = size_of_val(&operation)
            .checked_add(super::task_registry::TASK_BOOKKEEPING)
            .ok_or_else(|| anyhow::anyhow!("packet supervisor capacity overflow"))?;
        let memory = shared
            .budget
            .reserve(bytes)
            .ok_or_else(|| anyhow::anyhow!("packet supervisor memory capacity"))?;
        assert!(shared.supervisor_memory.set(memory).is_ok());
        let task = tokio::spawn(operation);
        let owner = PacketEndpointOwner {
            shared: Arc::clone(&shared),
            task: Some(task),
        };
        if ready.await.is_err() {
            return match owner.run().await {
                Err(error) => Err(error),
                Ok(()) => Err(anyhow::anyhow!("packet supervisor failed before admission")),
            };
        }
        Ok((
            Self {
                shared,
                sender,
                initializers,
            },
            owner,
        ))
    }

    /// Receive one verified IP packet. A receive batch supplies one `now` value.
    /// Queue pressure drops only that UDP datagram; established TCP still progresses.
    pub fn receive(&self, scope: ScopeId, packet: &[u8], now: Instant) -> io::Result<()> {
        self.receive_inner::<false>(scope, packet, now, None, false, |_, _| true)
            .map(|_| ())
    }

    /// Report/gate only the current validated TCP/UDP packet, including a completed
    /// reassembly. Source validity is not transport admission or kernel child proof.
    /// The callback installs reverse delivery facts before any scope output can run.
    /// `check_output` requests an atomic older-output query for a reverse-path QoS change.
    pub fn receive_with_source(
        &self,
        scope: ScopeId,
        packet: &[u8],
        now: Instant,
        check_output: bool,
        on_source: impl FnMut(ValidatedSource, bool) -> bool,
    ) -> io::Result<Option<ValidatedSource>> {
        self.receive_inner::<true>(scope, packet, now, None, check_output, on_source)
    }

    /// Admit with the execution decision captured by the canonical Core classifier.
    pub fn receive_admitted_with_source(
        &self,
        scope: ScopeId,
        packet: &[u8],
        now: Instant,
        admission: EndpointAdmission,
        check_output: bool,
        on_source: impl FnMut(ValidatedSource, bool) -> bool,
    ) -> io::Result<Option<ValidatedSource>> {
        self.receive_inner::<true>(scope, packet, now, Some(admission), check_output, on_source)
    }

    fn receive_inner<const REPORT: bool>(
        &self,
        scope: ScopeId,
        packet: &[u8],
        now: Instant,
        mut admission: Option<EndpointAdmission>,
        check_output: bool,
        on_source: impl FnMut(ValidatedSource, bool) -> bool,
    ) -> io::Result<Option<ValidatedSource>> {
        let scope = self
            .shared
            .scopes
            .iter()
            .find(|item| item.scope() == scope)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unowned packet scope"))?;
        self.shared.udp_pool.reap_tasks();
        let (rx, source) = if admission.is_some() {
            scope.receive_admitted_with_source(packet, now, &mut admission, check_output, on_source)
        } else if REPORT {
            scope.receive_with_source(packet, now, check_output, on_source)
        } else {
            (scope.receive(packet, now), None)
        };
        let result = match rx {
            Rx::Transparent {
                src,
                dst,
                dscp,
                payload,
            } => self.queue_datagram(scope.scope(), src, dst, dscp, admission.take(), |budget| {
                FundedDatagram::copy_from(&packet[payload], budget)
            }),
            Rx::TransparentOwned {
                src,
                dst,
                dscp,
                packet,
                payload,
            } => self.queue_datagram(scope.scope(), src, dst, dscp, admission.take(), |budget| {
                FundedDatagram::from_packet(packet, payload, budget)
            }),
            Rx::TransparentSplit {
                src,
                dst,
                dscp,
                payload,
                size,
            } => {
                let mut failure = None;
                for payload in packet[payload].chunks(usize::from(size)) {
                    if let Err(error) = self.queue_datagram(
                        scope.scope(),
                        src,
                        dst,
                        dscp,
                        admission.take(),
                        |budget| FundedDatagram::copy_from(payload, budget),
                    ) {
                        failure.get_or_insert(error);
                    }
                }
                failure.map_or(Ok(()), Err)
            }
            _ => Ok(()),
        };
        self.accept_ready(scope);
        result.map(|()| source)
    }

    fn queue_datagram(
        &self,
        scope: ScopeId,
        source: SocketAddr,
        destination: SocketAddr,
        dscp: u8,
        routing: Option<EndpointAdmission>,
        make: impl FnOnce(&Arc<MemoryBudget>) -> Option<FundedDatagram>,
    ) -> io::Result<()> {
        if self.shared.is_closing() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "packet endpoint admission is closed",
            ));
        }
        let permit = self.sender.try_reserve().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "packet ingress queue is full")
        })?;
        let bytes = make(&self.shared.budget).ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "packet ingress memory capacity")
        })?;
        if destination.port() != 53 {
            let pool = &self.shared.udp_pool;
            let now = super::udp_endpoint::queue_now();
            if pool
                .fast_path_enqueue_payload_at(
                    scope,
                    source,
                    destination,
                    DatagramPayload::Funded(bytes.clone()),
                    None,
                    now,
                    &self.shared.stats,
                )
                .is_some()
            {
                return Ok(());
            }
            let initializer = self.initializers.try_reserve().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "packet initializer queue is full",
                )
            })?;
            let Some(slow) = super::udp_ingress::try_admit_udp_slow_path(
                &self.shared.stats,
                &self.shared.udp_slots,
            ) else {
                return Ok(());
            };
            if let EndpointReservation::Initializing(mut lease) = pool
                .reserve_payload_or_enqueue_at(
                    scope,
                    source,
                    destination,
                    DatagramPayload::Funded(bytes),
                    None,
                    crate::ebpf::UdpFlowOwner::packet(),
                    pool.initialization_epoch(),
                    slow,
                    now,
                    &self.shared.stats,
                )
            {
                lease.packet_routing = routing.map(EndpointAdmission::into_snapshot);
                lease.packet_dscp = Some(dscp);
                initializer.send(lease);
            }
            return Ok(());
        }
        let source_work = self
            .shared
            .scopes
            .iter()
            .find(|owned| owned.scope() == scope)
            .expect("owned packet scope")
            .hold_source(source.ip())?;
        permit.send(Work::Udp(Datagram {
            scope,
            source,
            destination,
            dscp,
            routing,
            bytes,
            source_work,
        }));
        Ok(())
    }

    fn accept_ready(&self, scope: &PacketScope) {
        if self.shared.is_closing() {
            return;
        }
        for _ in 0..INGRESS_CAPACITY {
            let Ok(slot) = Arc::clone(&self.shared.tcp_slots).try_acquire_owned() else {
                break;
            };
            let Ok(permit) = self.sender.try_reserve() else {
                break;
            };
            let Some((_, flow)) = scope.poll_accept() else {
                break;
            };
            permit.send(Work::Tcp(flow, slot));
        }
    }

    /// Called by a capture owner only after every device has activated its real gate.
    /// Supervisor/UDP readiness alone is not a daemon capture-ready observation.
    pub fn capture_ready(&self) -> io::Result<()> {
        if self.shared.admission.load(Ordering::Acquire) != READY {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "packet endpoint admission is not ready",
            ));
        }
        #[cfg(feature = "native-api")]
        {
            self.shared.capture_ready.store(true, Ordering::Release);
            self.shared.changed.notify_one();
        }
        Ok(())
    }

    /// Close admission and abort protocol state before waiting for joined teardown.
    /// Exported output leases must still be released by their actual I/O consumers.
    pub fn close(&self) {
        self.shared.close();
    }

    /// Cancellation of this waiter does not detach admitted cleanup.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.close();
        let outcome =
            crate::connection_tracker::CloseRequest::Pending(Arc::clone(&self.shared.closed))
                .wait()
                .await;
        anyhow::ensure!(
            outcome == crate::connection_tracker::CloseOutcome::Closed,
            "packet endpoint cleanup failed"
        );
        Ok(())
    }
}

impl PacketEndpointOwner {
    pub async fn run(self) -> anyhow::Result<()> {
        self.join_plane().await?.1
    }

    pub(crate) async fn join_plane(mut self) -> anyhow::Result<(ControlPlane, anyhow::Result<()>)> {
        std::future::poll_fn(|cx| self.poll_join_plane(cx)).await
    }

    pub(crate) fn poll_join_plane(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<anyhow::Result<(ControlPlane, anyhow::Result<()>)>> {
        let result = std::task::ready!(
            std::pin::Pin::new(self.task.as_mut().expect("one supervisor join")).poll(cx)
        );
        self.task.take();
        std::task::Poll::Ready(result.map_err(Into::into))
    }

    pub(crate) async fn fail_control(&self) -> anyhow::Result<()> {
        self.shared.fatal_control.store(true, Ordering::Release);
        self.shared.close();
        let outcome = crate::connection_tracker::CloseRequest::Pending(Arc::clone(
            &self.shared.commands_closed,
        ))
        .wait()
        .await;
        anyhow::ensure!(
            outcome == crate::connection_tracker::CloseOutcome::Closed,
            "packet command owner stopped before command quiescence"
        );
        Ok(())
    }
}

impl Drop for PacketEndpointOwner {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.shared.close();
        }
    }
}

impl EndpointRuntime {
    async fn handle_command(
        &mut self,
        mut command: super::ControlCommand,
        authorizations: Option<&mut crate::subscription::SubscriptionAuthorizations>,
        commands: &mut Option<mpsc::Receiver<super::ControlCommand>>,
    ) -> maintenance::CommandAction {
        let mut reply = maintenance::separate_reply(&mut command);
        let mutates_runtime = matches!(
            &command,
            super::ControlCommand::ReloadConfig { .. }
                | super::ControlCommand::MergeSubscription { .. }
                | super::ControlCommand::NetworkChanged
        );
        let drain = Arc::clone(&self.plane.drain_tracker);
        let shared = Arc::clone(&self.shared);
        let plane = &mut self.plane;
        let operation = async move {
            match authorizations {
                Some(authorizations) => {
                    plane
                        .dispatch_control_command(command, &drain, authorizations)
                        .await
                }
                None => {
                    maintenance::handle_command(plane, command).await
                        == maintenance::CommandAction::Continue
                }
            }
        };
        tokio::pin!(operation);
        let continued = loop {
            if shared.is_closing()
                && let Some(commands) = commands.as_mut()
            {
                commands.close();
                if shared.fatal_control.load(Ordering::Acquire) {
                    while commands.try_recv().is_ok() {}
                }
            }
            if shared.fatal_control.load(Ordering::Acquire) {
                // Publication may already have committed: only the true result or an
                // indeterminate channel close is safe, never a fabricated rejection.
                reply.take();
            }
            tokio::select! {
                biased;
                continued = &mut operation => break continued,
                _ = shared.changed.notified() => {},
                command = async { commands.as_mut().unwrap().recv().await },
                    if shared.fatal_control.load(Ordering::Acquire) && commands.is_some() => {
                    if command.is_none() {
                        commands.take();
                        shared.commands_closed.finish(true);
                    }
                },
                Some(lease) = self.initializers.recv(), if mutates_runtime => {
                    // Reload waits for these guards, including reservations after its epoch fence.
                    drop(lease);
                    self.shared.stats.record_udp_slow_permit_closed();
                }
            }
        };
        if shared.fatal_control.load(Ordering::Acquire) {
            reply.take();
        }
        let acknowledged = reply.is_none_or(maintenance::CommandReply::forward);
        if mutates_runtime {
            while let Ok(lease) = self.initializers.try_recv() {
                drop(lease);
                self.shared.stats.record_udp_slow_permit_closed();
            }
        }
        if continued && acknowledged {
            maintenance::CommandAction::Continue
        } else {
            maintenance::CommandAction::Shutdown
        }
    }

    async fn run(mut self) -> (ControlPlane, anyhow::Result<()>) {
        let mut failure = None;
        for owner in self.owners.drain(..) {
            if let Err(error) = self.scope_tasks.spawn(owner.run(), 0) {
                failure = Some(error.into());
                break;
            }
        }
        let (xdp, mut authorizations, endpoint) = if failure.is_none() && !self.shared.is_closing()
        {
            let config = self.plane.config.read().await;
            let xdp = config
                .datapath
                .as_ref()
                .is_some_and(|datapath| datapath.backend == honk_config::datapath::Backend::Xdp);
            let authorizations = if xdp {
                match crate::subscription::SubscriptionAuthorizations::new(&config.subscriptions) {
                    Ok(authorizations) => Some(authorizations),
                    Err(error) => {
                        failure = Some(error);
                        None
                    }
                }
            } else {
                None
            };
            let endpoint = if xdp {
                config.dns.bind_endpoint().map_err(anyhow::Error::from)
            } else {
                Ok(None)
            };
            (xdp, authorizations, endpoint)
        } else {
            (false, None, Ok(None))
        };
        if xdp
            && failure.is_none()
            && !self.shared.is_closing()
            && let Err(error) = self.plane.initialize_datapath_flags(false, false).await
        {
            failure = Some(error);
        }
        let mut dns_listener = None;
        if xdp && failure.is_none() && !self.shared.is_closing() {
            let bound = endpoint.and_then(|endpoint| {
                endpoint
                    .as_ref()
                    .map(super::dns_listener::BoundDnsListener::bind)
                    .transpose()
                    .map_err(anyhow::Error::from)
            });
            match bound {
                Ok(Some(bound)) => match bound.spawn(
                    Arc::clone(&self.plane.dns_controller),
                    Arc::clone(&self.plane.concurrency_limit),
                    Arc::clone(&self.plane.stats),
                    Arc::clone(&self.plane.drain_tracker),
                    self.plane.native.clone(),
                    Arc::clone(&self.plane.diagnostics),
                ) {
                    Ok(listener) => dns_listener = Some(listener),
                    Err(error) => failure = Some(error.into()),
                },
                Ok(None) => {}
                Err(error) => failure = Some(error),
            }
        }
        let mut maintenance = if failure.is_none() && !self.shared.is_closing() {
            maintenance::start(&mut self.plane).await
        } else {
            Default::default()
        };
        #[cfg(all(test, feature = "native-api"))]
        for scope in self.shared.scopes.iter() {
            scope.startup_checkpoint().await;
        }
        let mut commands = Some(
            self.plane
                .command_rx
                .take()
                .expect("unstarted packet control receiver"),
        );
        let handle = self.plane.spawn_handle();
        let (fatal, mut failures) = mpsc::unbounded_channel();
        let removals = super::retirement_worker::spawn_packet_retirement_worker(
            Arc::clone(&self.plane.udp_pool),
            Arc::clone(&self.plane.connection_tracker),
            fatal,
        );
        if failure.is_none() && !self.shared.is_closing() {
            for scope in self.shared.scopes.iter() {
                if let Err(error) = scope.open_admission_if(|| !self.shared.is_closing()) {
                    if !self.shared.is_closing() {
                        failure = Some(error.into());
                    }
                    break;
                }
            }
        }
        #[cfg(feature = "native-api")]
        let mut running_published = false;
        // This CAS commits readiness; a later close overlaps an already-started runtime.
        if failure.is_none()
            && self
                .shared
                .admission
                .compare_exchange(STARTING, READY, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            #[cfg(feature = "native-api")]
            if !xdp {
                self.plane.publish_phase(super::EnginePhase::Running);
                running_published = true;
            }
            let _ = self.startup.take().unwrap().send(());
        } else {
            self.startup.take();
        }
        loop {
            if failure.is_some() || self.shared.is_closing() {
                break;
            }
            #[cfg(feature = "native-api")]
            if !running_published && self.shared.capture_ready.load(Ordering::Acquire) {
                self.plane.publish_phase(super::EnginePhase::Running);
                running_published = true;
            }
            tokio::select! {
                _ = self.shared.changed.notified() => {},
                command = commands.as_mut().expect("open command receiver").recv() => match command {
                    Some(command) => {
                        if self.shared.is_closing() {
                            if !self.shared.fatal_control.load(Ordering::Acquire) {
                                self.plane.shutdown_requested.store(true, Ordering::Release);
                                let _ = maintenance::handle_command(&mut self.plane, command).await;
                            }
                            break;
                        }
                        if self.handle_command(command, authorizations.as_mut(), &mut commands).await == maintenance::CommandAction::Shutdown { break; }
                    }
                    None => break,
                },
                result = self.scope_tasks.join_next(), if !self.scope_tasks.is_empty() => {
                    if !self.shared.is_closing() || !matches!(result, Some(Ok(()))) {
                        failure = Some(anyhow::anyhow!("packet scope owner exited before shutdown: {result:?}"));
                    }
                    break;
                }
                error = failures.recv() => {
                    failure = Some(error.unwrap_or_else(|| anyhow::anyhow!("packet retirement worker stopped")));
                    break;
                }
                Some(result) = self.tcp_tasks.join_next(), if !self.tcp_tasks.is_empty() => {
                    report_tcp_completion(result);
                }
                Some(lease) = self.initializers.recv() => self.dispatch_lease(&handle, lease),
                work = self.receiver.recv() => match work {
                    Some(Work::Tcp(flow, permit)) => {
                        while let Some(result) = self.tcp_tasks.try_join_next() {
                            report_tcp_completion(result);
                        }
                        self.plane.udp_pool.reap_tasks();
                        let handle = handle.clone();
                        let guard = ConnectionGuard::new(Arc::clone(&self.plane.drain_tracker));
                        let mut flow = Some(flow);
                        let admitted = self.tcp_tasks.spawn_with(|| {
                            let flow = flow.take().unwrap();
                            async move {
                                let (_permit, _guard) = (permit, guard);
                                if let Err(error) = handle.serve_packet_connection(flow).await {
                                    tracing::debug!(%error, "packet TCP endpoint ended");
                                }
                            }
                        }, crate::relay::COPY_BUFFER_MEMORY + crate::sniffing::SNIFF_MEMORY);
                        if let Err(error) = admitted {
                            flow.as_mut().unwrap().abort();
                            tracing::debug!(%error, "packet TCP task admission refused");
                        }
                    }
                    Some(Work::Udp(datagram)) => self.dispatch_datagram(&handle, datagram).await,
                    None => break,
                }
            }
        }
        self.shared.close();
        self.plane.shutdown_requested.store(true, Ordering::Release);
        self.plane.drain_tracker.start_rejecting();
        if let Some(listener) = &dns_listener {
            listener.stop_accepting();
        }
        #[cfg(feature = "native-api")]
        self.plane.publish_phase(if failure.is_some() {
            super::EnginePhase::Failed
        } else {
            super::EnginePhase::Draining
        });
        if let Some(mut commands) = commands.take() {
            commands.close();
            // Pre-close permits must relinquish their acknowledgements too.
            while let Some(command) = commands.recv().await {
                if !self.shared.fatal_control.load(Ordering::Acquire) {
                    let _ = maintenance::handle_command(&mut self.plane, command).await;
                }
            }
        }
        self.shared.commands_closed.finish(true);
        self.receiver.close();
        self.initializers.close();
        // Pre-close permits can still publish FlowIo; drain them before joining scopes.
        while self.receiver.recv().await.is_some() {}
        while self.initializers.recv().await.is_some() {}
        self.tcp_tasks.abort_all();
        while let Some(result) = self.tcp_tasks.join_next().await {
            report_tcp_completion(result);
        }
        let shutdown = self.plane.udp_pool.shutdown().await;
        if !shutdown.joined {
            failure.get_or_insert_with(|| anyhow::anyhow!("packet UDP tasks did not join"));
        }
        self.plane.retirement.sink.lock().take();
        if let Err(error) = removals.await {
            failure.get_or_insert(error.into());
        }
        while let Some(result) = self.scope_tasks.join_next().await {
            if let Err(error) = result {
                failure.get_or_insert(error.into());
            }
        }
        if let Some(listener) = &mut dns_listener
            && let Err(error) = listener.abort_and_join().await
        {
            failure.get_or_insert(error);
        }
        if let Err(error) = maintenance.abort_and_join().await {
            failure.get_or_insert(error);
        }
        let result = maintenance::shutdown(&mut self.plane, failure, Some(shutdown)).await;
        (self.plane, result)
    }

    async fn dispatch_datagram(&self, handle: &ControlPlaneHandle, datagram: Datagram) {
        let Datagram {
            scope,
            source,
            destination,
            dscp,
            bytes,
            routing,
            source_work,
        } = datagram;
        let pool = &self.plane.udp_pool;
        let epoch = pool.initialization_epoch();
        let mut raw_route = None;
        let mut packet_routing = routing.map(EndpointAdmission::into_snapshot);
        #[cfg(feature = "native-api")]
        let mut packet_observation = None;
        if destination.port() == 53 {
            #[cfg(feature = "native-api")]
            {
                packet_observation = Some(
                    super::connection::observation::ConnectionObservation::begin(
                        handle.native.as_deref(),
                        crate::observe::vocab::Network::Udp,
                        source,
                        destination,
                    ),
                );
                packet_observation.as_ref().unwrap().routing_started();
            }
            #[cfg_attr(not(feature = "native-api"), allow(unused_mut))]
            let mut snapshot = match packet_routing.take() {
                Some(snapshot) => snapshot,
                None => match handle
                    .prepare_packet_routing_snapshot(
                        source,
                        destination,
                        "udp",
                        dscp,
                        #[cfg(feature = "native-api")]
                        packet_observation.as_ref().unwrap().is_recording(),
                    )
                    .await
                {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        tracing::debug!(%error, "packet DNS policy admission failed");
                        return;
                    }
                },
            };
            if snapshot.mode.name == "block" {
                #[cfg(feature = "native-api")]
                if let Some(mut observation) = packet_observation.take() {
                    observation.routed(&mut snapshot.decision);
                    observation.finish(
                        crate::observe::vocab::ConnectionState::Blocked,
                        "packet_policy_block",
                    );
                }
                return;
            }
            if !snapshot.decision.must
                && let Some(validated) = crate::dns::query::validate_exact_dns_query(&bytes)
            {
                #[cfg(feature = "native-api")]
                let mut observation = packet_observation.take().unwrap();
                #[cfg(feature = "native-api")]
                observation.routed(&mut snapshot.decision);
                #[cfg(feature = "native-api")]
                let observer =
                    observation.observer(|| handle.diagnostics.read().generation, "client_dns");
                let sender = self
                    .shared
                    .scopes
                    .iter()
                    .find(|item| item.scope() == scope)
                    .expect("admitted scope")
                    .datagram_sender(destination);
                let dns = Arc::clone(&self.plane.dns_controller);
                let budget = Arc::clone(&self.shared.budget);
                let Some(response_memory) = budget.reserve(65536) else {
                    #[cfg(feature = "native-api")]
                    observation.finish(
                        crate::observe::vocab::ConnectionState::Failed,
                        "packet_memory_capacity",
                    );
                    return;
                };
                match dns.try_admit_packet_query(true) {
                    Ok(admission) => {
                        self.plane.stats.record_udp_slow_permit_accepted();
                        let guard = ConnectionGuard::new(Arc::clone(&self.plane.drain_tracker));
                        pool.spawn_slow_path(async move {
                            let _guard = guard;
                            let _response_memory = response_memory;
                            let _source_work = source_work;
                            let operation = dns.handle_udp_dns_admitted(
                                &admission,
                                &bytes,
                                source,
                                destination,
                                validated,
                                DnsUdpReply::Packet(&sender),
                            );
                            #[cfg(feature = "native-api")]
                            {
                                match observer {
                                    Some(observer) => observer.scope(operation).await,
                                    None => operation.await,
                                }
                                observation.finish(
                                    crate::observe::vocab::ConnectionState::Closed,
                                    "dns_query_completed",
                                );
                            }
                            #[cfg(not(feature = "native-api"))]
                            operation.await;
                        });
                    }
                    Err(error) => {
                        if let Some((runtime, permit)) = error.udp_reply {
                            self.plane.stats.record_udp_slow_permit_accepted();
                            let guard = ConnectionGuard::new(Arc::clone(&self.plane.drain_tracker));
                            pool.spawn_slow_path(async move {
                                let _guard = guard;
                                let (_response_memory, _permit) = (response_memory, permit);
                                let _source_work = source_work;
                                #[cfg(feature = "native-api")]
                                let started = Instant::now();
                                let response = crate::dns::response::build_dns_refused(&bytes);
                                let operation = async {
                                    crate::observe::flows::dns::decision(
                                        "rejected",
                                        Some("admission_refused"),
                                    );
                                    let delivery =
                                        runtime.run_reply(sender.send_to(&response, source)).await;
                                    crate::observe::flows::dns::reply_delivery(
                                        &delivery,
                                        |length| *length == response.len(),
                                        "client_send_failed",
                                    );
                                };
                                #[cfg(feature = "native-api")]
                                {
                                    let operation = std::pin::pin!(operation);
                                    let operation = crate::observe::flows::dns::client_scope(
                                        &bytes,
                                        validated.ingress(),
                                        crate::dns::query::DnsRequestMeta::new(
                                            Some(source.ip()),
                                            Some(destination),
                                        ),
                                        operation,
                                    );
                                    match observer {
                                        Some(observer) => observer.scope(operation).await,
                                        None => operation.await,
                                    }
                                    observation.finish(
                                        crate::observe::vocab::ConnectionState::Closed,
                                        "dns_query_refused",
                                    );
                                    dns.dns_service().observer.observe_client(
                                        &bytes,
                                        validated.ingress(),
                                        Some(source),
                                        None,
                                        &response,
                                        started.elapsed(),
                                    );
                                }
                                #[cfg(not(feature = "native-api"))]
                                operation.await;
                            });
                        } else {
                            self.plane.stats.record_udp_slow_permit_rejected();
                            #[cfg(feature = "native-api")]
                            observation.finish(
                                crate::observe::vocab::ConnectionState::Failed,
                                "dns_admission_refused",
                            );
                        }
                    }
                }
                return;
            }
            raw_route = Some(if snapshot.mode.name == "direct" {
                let mark = snapshot
                    .decision
                    .mark
                    .map_or(0, honk_outbound::proxy::DirectMark::get);
                if snapshot.decision.must {
                    RawDnsRoute::Direct(mark)
                } else {
                    RawDnsRoute::FallbackDirect(mark)
                }
            } else if snapshot.decision.must {
                RawDnsRoute::Group(snapshot.mode.name.clone())
            } else {
                RawDnsRoute::FallbackGroup(snapshot.mode.name.clone())
            });
            packet_routing = Some(snapshot);
        }
        if pool
            .fast_path_enqueue_payload_at(
                scope,
                source,
                destination,
                DatagramPayload::Funded(bytes.clone()),
                raw_route.as_ref().map(RawDnsRoute::as_ref),
                super::udp_endpoint::queue_now(),
                &self.plane.stats,
            )
            .is_some()
        {
            #[cfg(feature = "native-api")]
            if let Some(mut observation) = packet_observation.take() {
                observation.routed(&mut packet_routing.as_mut().unwrap().decision);
                if let Some(flow) = observation.flow() {
                    flow.mark_gap(
                        honk_outbound::runtime::flow_observation::GapReason::NotInstrumented,
                    );
                }
                observation.finish(
                    crate::observe::vocab::ConnectionState::Closed,
                    "existing_udp_endpoint",
                );
            }
            return;
        }
        let Some(permit) = super::udp_ingress::try_admit_udp_slow_path(
            &self.plane.stats,
            &self.plane.udp_concurrency_limit,
        ) else {
            return;
        };
        if let EndpointReservation::Initializing(mut lease) = pool.reserve_payload_or_enqueue_at(
            scope,
            source,
            destination,
            DatagramPayload::Funded(bytes),
            raw_route.as_ref().map(RawDnsRoute::as_ref),
            crate::ebpf::UdpFlowOwner::packet(),
            epoch,
            permit,
            super::udp_endpoint::queue_now(),
            &self.plane.stats,
        ) {
            lease.packet_routing = packet_routing;
            lease.packet_dscp = Some(dscp);
            #[cfg(feature = "native-api")]
            {
                lease.packet_observation = packet_observation.take();
            }
            self.dispatch_lease(handle, lease);
        }
    }

    fn dispatch_lease(&self, handle: &ControlPlaneHandle, lease: UdpInitLease) {
        let handle = handle.clone();
        let guard = ConnectionGuard::new(Arc::clone(&self.plane.drain_tracker));
        self.plane.udp_pool.spawn_slow_path(async move {
            let _guard = guard;
            if let Err(error) = handle.serve_udp_connection(lease).await {
                tracing::debug!(%error, "packet UDP endpoint ended");
            }
        });
    }
}

mod maintenance;

#[cfg(test)]
mod tests;
