//! Explicit L3 Endpoint integration, not packet capture or native continuation authority.
//!
//! The caller runs and joins `PacketEndpointOwner::run`, and retains each scope's
//! output lease through actual backend I/O. No kernel listener or hook is started.

use super::ControlPlane;
use super::connection::{ConnectionGuard, ControlPlaneHandle};
use super::dns_control::DnsUdpReply;
use super::dns_listener::{BoundDnsListener, PreparedDnsBind};
use super::netstack::{
    AuxiliaryWork, FlowIo, HostIngress, PacketDriver, PacketOwner, PacketRealm, PacketRealmPlan,
    PacketScope, SourceWork, TcpClaim,
};
use super::task_registry::TaskRegistry;
use super::udp_endpoint::{
    DatagramPayload, EndpointReservation, FundedDatagram, RawDnsRoute, ReplySocketFd,
    UdpEndpointPool, UdpInitLease, UdpReplySocketFactory,
};
use futures::FutureExt;
use honk_datapath::ScopeId;
use honk_ebpf_common::host::HostSourceFacts;
use honk_netstack::{MemoryBudget, MemoryReservation, Rx, RxMeta, SourceContext, ValidatedSource};
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::atomic::AtomicBool;
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};
use std::time::Instant;
use tokio::sync::{Notify, OwnedSemaphorePermit, mpsc};

const INGRESS_CAPACITY: usize = 64;
const MAX_SCOPES: usize = 64;
const MAX_OWNERS: usize = 128;
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

pub(super) async fn run_until_auxiliary_pause<F: Future>(
    auxiliary: Option<&AuxiliaryWork>,
    operation: F,
) -> Option<F::Output> {
    match auxiliary {
        Some(binding) => tokio::select! {
            biased;
            _ = binding.cancelled() => None,
            result = operation => binding.is_active().then_some(result),
        },
        None => Some(operation.await),
    }
}

#[derive(Debug)]
struct Replies(Arc<[PacketRealm]>);

impl UdpReplySocketFactory for Replies {
    fn create(
        &self,
        scope: ScopeId,
        source: SocketAddr,
        packet_source: Option<&SourceWork>,
    ) -> io::Result<ReplySocketFd> {
        let owned = self
            .0
            .iter()
            .find(|item| item.scope() == scope)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "packet reply scope is not owned")
            })?;
        match packet_source {
            Some(source_work) => {
                let exact = source_work.owner();
                if !owned.owners().iter().any(|item| item.same_owner(exact)) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "reply source belongs to another packet owner",
                    ));
                }
                if source_work
                    .plain_address()
                    .is_some_and(|address| owned.worker_for_udp(address) != exact.worker())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "UDP source does not own its fixed realm worker",
                    ));
                }
                exact
                    .datagram_sender_for(source, source_work.clone())
                    .map(ReplySocketFd::Packet)
            }
            None if !owned.owners()[0].is_host() => {
                Ok(ReplySocketFd::Packet(owned.datagram_sender(source)))
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Host reply requires source facts",
            )),
        }
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
    auxiliary: Option<AuxiliaryWork>,
}

struct QueuedInitializer {
    lease: UdpInitLease,
    auxiliary: Option<AuxiliaryWork>,
}

#[derive(Debug, thiserror::Error)]
#[error("packet endpoint admission is closed")]
struct DatagramAdmissionClosed;

enum PacketSource<'a> {
    Captured {
        context: SourceContext,
        facts: &'a HostSourceFacts,
    },
    Completed(SourceWork),
}

impl PacketSource<'_> {
    fn lineage(&self) -> Option<NonZeroU64> {
        match self {
            Self::Captured { context, .. } => Some(context.lineage),
            Self::Completed(work) => work.optional_context().map(|context| context.lineage),
        }
    }

    fn hold(self, scope: &PacketScope) -> io::Result<SourceWork> {
        match self {
            Self::Captured { facts, .. } => scope.hold_host_source(facts),
            Self::Completed(work) => Ok(work),
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum Work {
    Tcp(FlowIo, OwnedSemaphorePermit, Option<AuxiliaryWork>),
    Udp(Datagram),
}

struct Shared {
    scopes: Arc<[PacketScope]>,
    realms: Arc<[PacketRealm]>,
    budget: Arc<MemoryBudget>,
    udp_pool: Arc<UdpEndpointPool>,
    #[cfg(target_os = "linux")]
    sniffer_pool: Arc<super::packet_sniffer::PacketSnifferPool>,
    tcp_slots: Arc<tokio::sync::Semaphore>,
    udp_slots: Arc<tokio::sync::Semaphore>,
    stats: Arc<crate::stats::StatsManager>,
    admission: AtomicU8,
    shutdown: Arc<super::ShutdownIntent>,
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

    fn auxiliary_admission_open(&self) -> bool {
        self.admission.load(Ordering::Acquire) == READY && !self.shutdown.requested()
    }

    fn close(&self) {
        self.admission.store(CLOSING, Ordering::Release);
        self.shutdown.request();
        for scope in self.scopes.iter() {
            scope.shutdown(true);
        }
        self.changed.notify_one();
    }
}

/// An owning canonical route/config/runtime/mode decision, captured before ingress.
pub struct EndpointAdmission {
    snapshot: Box<super::connection::routing::PacketRoutingSnapshot>,
    pending: Option<super::core_forward::PendingEndpointAdmission>,
    _memory: MemoryReservation,
}

impl std::fmt::Debug for EndpointAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointAdmission").finish_non_exhaustive()
    }
}

impl EndpointAdmission {
    pub(in crate::control) fn source_context(&self) -> Option<SourceContext> {
        self.snapshot.source
    }

    #[cfg(test)]
    pub(in crate::control) fn captured_snapshot(
        &self,
    ) -> &super::connection::routing::PacketRoutingSnapshot {
        &self.snapshot
    }
    #[cfg(test)]
    pub(in crate::control) fn captured_snapshot_mut(
        &mut self,
    ) -> &mut super::connection::routing::PacketRoutingSnapshot {
        &mut self.snapshot
    }

    #[cfg(test)]
    pub(in crate::control) fn new(
        snapshot: super::connection::routing::PacketRoutingSnapshot,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Self> {
        Self::allocate(snapshot, budget, None)
    }

    pub(in crate::control) fn pending(
        snapshot: super::connection::routing::PacketRoutingSnapshot,
        budget: &Arc<MemoryBudget>,
        pending: super::core_forward::PendingEndpointAdmission,
    ) -> io::Result<Self> {
        Self::allocate(snapshot, budget, Some(pending))
    }

    fn allocate(
        snapshot: super::connection::routing::PacketRoutingSnapshot,
        budget: &Arc<MemoryBudget>,
        pending: Option<super::core_forward::PendingEndpointAdmission>,
    ) -> io::Result<Self> {
        let bytes = size_of::<super::connection::routing::PacketRoutingSnapshot>()
            + 2 * size_of::<usize>()
            + size_of::<Option<super::core_forward::PendingEndpointAdmission>>()
            + snapshot.decision.retained_bytes()
            + snapshot.mode.name.capacity()
            + snapshot.mode_state.as_ref().map_or(0, |state| {
                state.mode.capacity() + state.global_selection().len()
            })
            + snapshot.source_mac.as_ref().map_or(0, String::capacity);
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
            pending,
            _memory: memory,
        })
    }

    pub(in crate::control) fn commit_pending<R>(
        admission: &mut Option<Self>,
        scope: ScopeId,
        commit: impl FnOnce(&mut Option<Self>) -> R,
    ) -> io::Result<R> {
        match admission
            .as_mut()
            .and_then(|admission| admission.pending.take())
        {
            Some(pending) => {
                let result = pending.commit(scope, || commit(admission));
                if result.is_err() {
                    admission.take();
                }
                result
            }
            None => Ok(commit(admission)),
        }
    }

    pub(in crate::control) fn into_snapshot(
        self,
    ) -> super::connection::routing::PacketRoutingSnapshot {
        assert!(
            self.pending.is_none(),
            "packet policy must commit before use"
        );
        let mut snapshot = *self.snapshot;
        snapshot.memory = Some(self._memory);
        snapshot
    }
}

/// Source validity, ownership transfer and polling qualification are independent facts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketReceive {
    pub source: Option<ValidatedSource>,
    pub source_context: Option<SourceContext>,
    pub qualified_rx: bool,
    pub taken_over: bool,
}

/// A bounded ingress handle. Copies share admission, scopes and one core UDP pool.
#[derive(Clone)]
pub struct PacketEndpoints {
    shared: Arc<Shared>,
    sender: mpsc::Sender<Work>,
    initializers: mpsc::Sender<QueuedInitializer>,
}

/// Join handle for the supervisor. Dropping it requests cleanup, never aborts cleanup.
pub struct PacketEndpointOwner {
    shared: Arc<Shared>,
    task: Option<tokio::task::JoinHandle<(ControlPlane, anyhow::Result<()>)>>,
    ready: Option<tokio::sync::oneshot::Receiver<()>>,
}

struct EndpointRuntime {
    shared: Arc<Shared>,
    plane: ControlPlane,
    receiver: mpsc::Receiver<Work>,
    initializers: mpsc::Receiver<QueuedInitializer>,
    owners: Vec<PacketOwner>,
    // Driven scopes park their original owners until the device returns or abandons them.
    driven: bool,
    prepared_dns_addresses: Option<PreparedDnsBind>,
    standalone_dns_scope: ScopeId,
    scope_tasks: TaskRegistry,
    tcp_tasks: TaskRegistry,
    startup: Option<tokio::sync::oneshot::Sender<()>>,
}

async fn run_driven_scope(
    owner: PacketOwner,
    shared: Arc<Shared>,
    failed: mpsc::UnboundedSender<anyhow::Error>,
) {
    if !owner.reclaim().await {
        let _ = failed.send(anyhow::anyhow!(
            "packet scope driver abandoned its scope before finish"
        ));
        shared.close();
    }
    drop((failed, shared));
    owner.run().await;
}

impl PacketEndpoints {
    /// Claim-retirement ownership, including source-wide controller DNS work.
    /// Use `retained_transport` when deciding whether a packet already owns execution.
    pub fn retains(
        &self,
        scope: ScopeId,
        source: SocketAddr,
        destination: SocketAddr,
        protocol: u8,
    ) -> bool {
        self.retained_transport(scope, source, destination, protocol)
            || (protocol == 17
                && destination.port() == 53
                && self
                    .shared
                    .scopes
                    .iter()
                    .any(|owned| owned.scope() == scope && owned.retains_source(source.ip())))
    }

    /// Exact tuple/protocol ownership; unrelated source work never bypasses admission.
    pub(crate) fn retained_transport(
        &self,
        scope: ScopeId,
        source: SocketAddr,
        destination: SocketAddr,
        protocol: u8,
    ) -> bool {
        self.retains_with_lineage(scope, source, destination, protocol, None)
    }

    pub(crate) fn retains_with_lineage(
        &self,
        scope: ScopeId,
        source: SocketAddr,
        destination: SocketAddr,
        protocol: u8,
        packet_lineage: Option<NonZeroU64>,
    ) -> bool {
        let Some(realm) = self.realm(scope) else {
            return false;
        };
        match protocol {
            6 => realm.owners().iter().any(|owned| match packet_lineage {
                None => owned.retains_tcp(source, destination),
                Some(_) => owned.retains_tcp_with_lineage(source, destination, packet_lineage),
            }),
            17 => self
                .shared
                .udp_pool
                .contains(scope, source, destination, packet_lineage),
            _ => false,
        }
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(crate) fn retains_host_flow(
        &self,
        scope: ScopeId,
        client: SocketAddr,
        destination: SocketAddr,
        protocol: u8,
    ) -> bool {
        let Some(realm) = self.realm(scope) else {
            return true;
        };
        // A live application may hand its last obligation to Stack or an exported frame.
        (protocol == honk_netstack::wire::PROTO_UDP
            && self
                .shared
                .udp_pool
                .retains_host_udp(scope, client, destination))
            || realm
                .owners()
                .iter()
                .any(|owner| owner.retains_host_work(client, destination, protocol))
    }

    /// Includes protocol, initializer/retirement, queued work and actual output owners.
    /// Call outside the receive callback, which already holds the scope mutex.
    pub(crate) fn retains_source(&self, scope: ScopeId, address: std::net::IpAddr) -> bool {
        self.shared
            .scopes
            .iter()
            .any(|owned| owned.scope() == scope && owned.retains_source(address))
            || self.shared.udp_pool.retains_source(scope, address)
    }

    pub(crate) fn prepare_dns_bind(
        config: &honk_config::Config,
    ) -> io::Result<Option<PreparedDnsBind>> {
        config
            .dns
            .bind_endpoint()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
            .map(PreparedDnsBind::new)
            .transpose()
    }

    /// Consume an unstarted control plane; no second host ingress is started beside it.
    /// `udp_capacity` is shared by every supplied scope, not multiplied per scope.
    pub async fn new(
        plane: ControlPlane,
        scopes: Vec<(PacketScope, PacketOwner)>,
        udp_capacity: usize,
    ) -> anyhow::Result<(Self, PacketEndpointOwner)> {
        let (endpoints, mut owner, _) =
            Self::start(plane, scopes, udp_capacity, false, None, ScopeId::HOST).await?;
        std::future::poll_fn(|cx| owner.poll_ready(cx)).await?;
        Ok((endpoints, owner))
    }

    /// `new` for a capture owner that drives these scopes itself: the same validation,
    /// with one exclusive driver per scope in `scopes` order before readiness. Service
    /// them while polling `PacketEndpointOwner::poll_ready`; failed-start cleanup needs it.
    pub(crate) async fn start_driven<P: Into<PacketRealmPlan>>(
        plane: ControlPlane,
        scopes: Vec<P>,
        udp_capacity: usize,
        prepared_dns_addresses: Option<PreparedDnsBind>,
        standalone_dns_scope: ScopeId,
    ) -> anyhow::Result<(Self, PacketEndpointOwner, Vec<PacketDriver>)> {
        Self::start(
            plane,
            scopes,
            udp_capacity,
            true,
            prepared_dns_addresses,
            standalone_dns_scope,
        )
        .await
    }

    async fn start<P: Into<PacketRealmPlan>>(
        plane: ControlPlane,
        plans: Vec<P>,
        udp_capacity: usize,
        driven: bool,
        prepared_dns_addresses: Option<PreparedDnsBind>,
        standalone_dns_scope: ScopeId,
    ) -> anyhow::Result<(Self, PacketEndpointOwner, Vec<PacketDriver>)> {
        let mut scopes = Vec::new();
        let mut realms = Vec::new();
        let mut invalid_plan = None;
        for plan in plans {
            let plan = plan.into();
            match plan.realm {
                Ok(realm) => {
                    if plan.owners.len() != realm.owners().len()
                        || plan
                            .owners
                            .iter()
                            .zip(realm.owners())
                            .any(|(owner, scope)| !owner.owns(scope))
                    {
                        invalid_plan = Some(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "packet realm owner mismatch",
                        ));
                    }
                    for owner in plan.owners {
                        scopes.push((owner.packet_scope().clone(), owner));
                    }
                    realms.push(realm);
                }
                Err(error) => {
                    invalid_plan = Some(error);
                    for owner in plan.owners {
                        scopes.push((owner.packet_scope().clone(), owner));
                    }
                }
            }
        }
        if let Some(error) = invalid_plan {
            for (scope, _) in &scopes {
                scope.shutdown(true);
            }
            for (_, owner) in scopes {
                owner.shutdown().await;
            }
            return Err(error.into());
        }
        let result = Self::prepare_start(
            plane,
            &mut scopes,
            realms,
            udp_capacity,
            driven,
            prepared_dns_addresses,
            standalone_dns_scope,
        );
        if result.is_err() {
            for (scope, _) in &scopes {
                scope.shutdown(true);
            }
            for (_, owner) in scopes {
                owner.shutdown().await;
            }
        }
        result
    }

    fn prepare_start(
        mut plane: ControlPlane,
        pending_scopes: &mut Vec<(PacketScope, PacketOwner)>,
        realms: Vec<PacketRealm>,
        udp_capacity: usize,
        driven: bool,
        prepared_dns_addresses: Option<PreparedDnsBind>,
        standalone_dns_scope: ScopeId,
    ) -> anyhow::Result<(Self, PacketEndpointOwner, Vec<PacketDriver>)> {
        let scopes = &*pending_scopes;
        anyhow::ensure!(
            plane.command_rx.is_some() && plane.health_task.is_none(),
            "packet endpoints require an unstarted control plane"
        );
        anyhow::ensure!(
            !realms.is_empty() && realms.len() <= MAX_SCOPES && scopes.len() <= MAX_OWNERS,
            "invalid packet realm/owner count"
        );
        anyhow::ensure!(
            udp_capacity != 0 && udp_capacity <= plane.resource_budget.udp_endpoints,
            "invalid shared UDP endpoint capacity"
        );
        let budget = scopes[0].0.budget();
        for (index, realm) in realms.iter().enumerate() {
            anyhow::ensure!(
                !realms[..index]
                    .iter()
                    .any(|earlier| earlier.scope() == realm.scope()),
                "duplicate packet realm"
            );
            anyhow::ensure!(
                realm
                    .owners()
                    .iter()
                    .enumerate()
                    .all(|(worker, owner)| owner.scope() == realm.scope()
                        && owner.worker() == worker),
                "invalid packet realm owner partition"
            );
        }
        for (index, (scope, owner)) in scopes.iter().enumerate() {
            anyhow::ensure!(
                scope.scope() != ScopeId::HOST && owner.owns(scope),
                "packet scope owner mismatch"
            );
            anyhow::ensure!(
                Arc::ptr_eq(&budget, &scope.budget()),
                "packet scopes must share one memory ceiling"
            );
            anyhow::ensure!(
                !scopes[..index]
                    .iter()
                    .any(|(earlier, _)| earlier.same_owner(scope)),
                "duplicate packet owner"
            );
        }
        let mut tcp_capacity = 0usize;
        for (scope, _) in scopes {
            tcp_capacity = tcp_capacity
                .checked_add(scope.prepare_endpoint()?)
                .ok_or_else(|| anyhow::anyhow!("packet flow capacity overflow"))?;
        }
        tracing::debug!(
            used = budget.used(),
            limit = budget.limit(),
            scopes = scopes.len(),
            tcp_capacity,
            udp_capacity,
            "packet endpoints start: budget before registries"
        );
        let scope_tasks = TaskRegistry::accounted(scopes.len(), &budget).map_err(|error| {
            anyhow::anyhow!(
                "packet scope task registry ({} scopes): {error}",
                scopes.len()
            )
        })?;
        let tcp_task_slots = tcp_capacity.min(plane.resource_budget.elastic_tcp_flows(0, 0));
        let tcp_tasks = TaskRegistry::accounted(tcp_task_slots, &budget).map_err(|error| {
            anyhow::anyhow!(
                "packet TCP task registry ({tcp_task_slots} slots, budget {}/{}): {error}",
                budget.used(),
                budget.limit()
            )
        })?;
        let bytes = (INGRESS_CAPACITY + 32)
            .checked_mul(4 * (size_of::<Work>() + size_of::<QueuedInitializer>()))
            .and_then(|n| {
                n.checked_add(
                    MAX_OWNERS
                        * (size_of::<PacketScope>()
                            + size_of::<PacketOwner>()
                            + size_of::<PacketDriver>()),
                )
            })
            .and_then(|n| n.checked_add(size_of::<Shared>() + maintenance::COMMAND_MEMORY))
            .ok_or_else(|| anyhow::anyhow!("packet ingress capacity overflows"))?;
        let memory = budget
            .reserve(bytes)
            .ok_or_else(|| anyhow::anyhow!("packet ingress memory capacity"))?;
        let logical_scopes: Vec<_> = realms
            .iter()
            .map(|realm| realm.owners()[0].clone())
            .collect();
        plane
            .dns_controller
            .register_packet_scopes(&logical_scopes)?;
        let scopes: Arc<[PacketScope]> = scopes.iter().map(|(scope, _)| scope.clone()).collect();
        let realms: Arc<[PacketRealm]> = realms.into();
        plane.udp_pool = Arc::new(
            UdpEndpointPool::with_packet_reply_factory(
                udp_capacity,
                Arc::new(Replies(Arc::clone(&realms))),
                Arc::clone(&budget),
            )
            .map_err(|error| {
                anyhow::anyhow!(
                    "packet UDP endpoint pool ({udp_capacity} endpoints, budget {}/{}): {error}",
                    budget.used(),
                    budget.limit()
                )
            })?,
        );
        plane.install_node_death_callback();
        let shared = Arc::new(Shared {
            scopes,
            realms,
            budget,
            udp_pool: Arc::clone(&plane.udp_pool),
            #[cfg(target_os = "linux")]
            sniffer_pool: Arc::clone(&plane.sniffer_pool),
            tcp_slots: Arc::clone(&plane.concurrency_limit),
            udp_slots: Arc::clone(&plane.udp_concurrency_limit),
            stats: Arc::clone(&plane.stats),
            admission: AtomicU8::new(STARTING),
            shutdown: plane.shutdown_intent(),
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
        let mut drivers = Vec::new();
        let mut runtime = EndpointRuntime {
            shared: Arc::clone(&shared),
            plane,
            receiver,
            initializers: initializer_rx,
            owners: Vec::new(),
            driven,
            prepared_dns_addresses,
            standalone_dns_scope,
            scope_tasks,
            tcp_tasks,
            startup: Some(started),
        };
        // As with scope-task factories, fund the concrete future before taking any owner.
        fn spawn_supervisor<F>(
            shared: &Arc<Shared>,
            create: impl FnOnce() -> F,
        ) -> anyhow::Result<tokio::task::JoinHandle<F::Output>>
        where
            F: Future<Output = (ControlPlane, anyhow::Result<()>)> + Send + 'static,
        {
            let bytes = size_of::<F>()
                .checked_add(super::task_registry::TASK_BOOKKEEPING)
                .ok_or_else(|| anyhow::anyhow!("packet supervisor capacity overflow"))?;
            let memory = shared
                .budget
                .reserve(bytes)
                .ok_or_else(|| anyhow::anyhow!("packet supervisor memory capacity"))?;
            assert!(shared.supervisor_memory.set(memory).is_ok());
            Ok(tokio::spawn(create()))
        }
        let task = spawn_supervisor(&shared, || {
            runtime.owners = std::mem::take(pending_scopes)
                .into_iter()
                .map(|(_, owner)| owner)
                .collect();
            if driven {
                drivers = runtime.owners.iter().map(PacketOwner::hand_off).collect();
            }
            let completed = Arc::clone(&shared.closed);
            let commands_closed = Arc::clone(&shared.commands_closed);
            async move {
                let _completion =
                    crate::connection_tracker::CloseCompletion(Arc::clone(&completed));
                let _commands = crate::connection_tracker::CloseCompletion(commands_closed);
                let (plane, result) = runtime.run().await;
                completed.finish(result.is_ok());
                (plane, result)
            }
        })?;
        let owner = PacketEndpointOwner {
            shared: Arc::clone(&shared),
            task: Some(task),
            ready: Some(ready),
        };
        Ok((
            Self {
                shared,
                sender,
                initializers,
            },
            owner,
            drivers,
        ))
    }

    /// Receive one verified IP packet. A receive batch supplies one `now` value.
    /// Queue pressure drops only that UDP datagram; established TCP still progresses.
    pub fn receive(&self, scope: ScopeId, packet: &[u8], now: Instant) -> io::Result<()> {
        self.receive_inner::<false>(
            scope,
            (packet, RxMeta::VERIFY),
            now,
            now,
            None,
            None,
            false,
            |_, _, _, _| true,
        )
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
    ) -> io::Result<PacketReceive> {
        self.receive_with_meta_source(scope, packet, RxMeta::VERIFY, now, check_output, on_source)
    }

    /// Uses driver checksum/offload metadata without changing source gating or UDP funding.
    pub fn receive_with_meta_source(
        &self,
        scope: ScopeId,
        packet: &[u8],
        meta: RxMeta,
        now: Instant,
        check_output: bool,
        mut on_source: impl FnMut(ValidatedSource, bool) -> bool,
    ) -> io::Result<PacketReceive> {
        self.receive_inner::<true>(
            scope,
            (packet, meta),
            now,
            now,
            None,
            None,
            check_output,
            |source, _, _, pending| on_source(source, pending),
        )
    }

    /// Admit with the execution decision captured by the canonical Core classifier.
    pub fn receive_admitted_with_source(
        &self,
        scope: ScopeId,
        packet: &[u8],
        now: Instant,
        admission: EndpointAdmission,
        check_output: bool,
        mut on_source: impl FnMut(ValidatedSource, bool) -> bool,
    ) -> io::Result<PacketReceive> {
        self.receive_inner::<true>(
            scope,
            (packet, RxMeta::VERIFY),
            now,
            now,
            Some(admission),
            None,
            check_output,
            |source, _, _, pending| on_source(source, pending),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receive_host_with_source(
        &self,
        scope: ScopeId,
        packet: &[u8],
        meta: RxMeta,
        packet_now: Instant,
        ingress: &HostIngress,
        admission: Option<EndpointAdmission>,
        check_output: bool,
        mut on_source: impl FnMut(ValidatedSource, SourceContext, &HostSourceFacts, bool) -> bool,
    ) -> io::Result<PacketReceive> {
        self.receive_inner::<true>(
            scope,
            (packet, meta),
            packet_now,
            packet_now,
            admission,
            Some(ingress),
            check_output,
            |source, context, facts, pending| {
                on_source(
                    source,
                    context.expect("Host source context"),
                    facts.expect("Host source facts"),
                    pending,
                )
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn receive_inner<const REPORT: bool>(
        &self,
        scope: ScopeId,
        (packet, meta): (&[u8], RxMeta),
        now: Instant,
        service_at: Instant,
        mut admission: Option<EndpointAdmission>,
        host: Option<&HostIngress>,
        check_output: bool,
        mut on_source: impl FnMut(
            ValidatedSource,
            Option<SourceContext>,
            Option<&HostSourceFacts>,
            bool,
        ) -> bool,
    ) -> io::Result<PacketReceive> {
        if host.is_none()
            && self
                .realm(scope)
                .is_some_and(|realm| realm.owners().len() > 1)
            && matches!(
                honk_netstack::wire::parse_ip(packet),
                Err(honk_netstack::wire::ParseError::Fragment)
            )
        {
            let owner = &self.realm(scope).expect("owned realm").owners()[0];
            return match owner.reassemble_for_dispatch(packet, now, service_at) {
                Ok(Some(complete)) => self.receive_inner::<REPORT>(
                    scope,
                    (&complete, RxMeta::VERIFY),
                    complete.completion_ingress(),
                    service_at,
                    admission,
                    None,
                    check_output,
                    on_source,
                ),
                Ok(None) | Err(_) => Ok(PacketReceive::default()),
            };
        }
        let (scope, _claim) =
            self.execution_owner(scope, honk_netstack::wire::PacketView::from_slice(packet))?;
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if admission.is_some() && scope.is_gateway_host() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "gateway Host requires its own flow admission",
            ));
        }
        let auxiliary = scope.auxiliary_work()?;
        if auxiliary.is_some() && !self.shared.auxiliary_admission_open() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                DatagramAdmissionClosed,
            ));
        }
        self.shared.udp_pool.reap_tasks();
        let mut receive = |admission: &mut Option<EndpointAdmission>| -> io::Result<_> {
            Ok(if let Some(ingress) = host {
                scope.receive_host_deferred_with_source(
                    (packet, meta),
                    now,
                    ingress,
                    admission,
                    check_output,
                    |source, context, facts, pending| {
                        on_source(source, Some(context), Some(facts), pending)
                    },
                )?
            } else if admission.is_some()
                || self
                    .realm(scope.scope())
                    .is_some_and(|realm| realm.owners().len() > 1)
            {
                let (rx, received) = scope.receive_admitted_deferred_with_source(
                    packet,
                    now,
                    service_at,
                    admission,
                    check_output,
                    |source, pending| on_source(source, None, None, pending),
                );
                (rx, received, None)
            } else if REPORT {
                let (rx, received) = scope.receive_with_meta_source(
                    packet,
                    meta,
                    now,
                    check_output,
                    |source, pending| on_source(source, None, None, pending),
                );
                (rx, received, None)
            } else {
                (scope.receive(packet, now), PacketReceive::default(), None)
            })
        };
        let tcp = admission.is_some()
            && honk_netstack::wire::parse_ip(packet)
                .is_ok_and(|ip| ip.proto == honk_netstack::wire::PROTO_TCP);
        let (rx, received, completion) = if tcp {
            EndpointAdmission::commit_pending(&mut admission, scope.scope(), receive)??
        } else {
            receive(&mut admission)?
        };
        scope.after_receive();
        self.dispatch_received::<REPORT>(
            scope,
            packet,
            rx,
            received,
            completion,
            admission,
            host,
            None,
            auxiliary.as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_received<const REPORT: bool>(
        &self,
        scope: &PacketScope,
        packet: &[u8],
        rx: Rx,
        mut received: PacketReceive,
        mut completion: Option<SourceWork>,
        mut admission: Option<EndpointAdmission>,
        host: Option<&HostIngress>,
        physical: Option<&SourceWork>,
        auxiliary: Option<&AuxiliaryWork>,
    ) -> io::Result<PacketReceive> {
        if host.is_some()
            && received.source_context.is_none()
            && matches!(
                &rx,
                Rx::Transparent { .. } | Rx::TransparentOwned { .. } | Rx::TransparentSplit { .. }
            )
        {
            return Err(io::Error::other(
                "Host UDP completion lost its source context",
            ));
        }
        let captured = || {
            host.zip(received.source_context)
                .map(|(ingress, context)| PacketSource::Captured {
                    context,
                    facts: &ingress.facts,
                })
                .or_else(|| physical.cloned().map(PacketSource::Completed))
        };
        let result = match rx {
            Rx::Transparent {
                src,
                dst,
                dscp,
                payload,
            } => self.queue_datagram(
                scope,
                src,
                dst,
                dscp,
                admission.take(),
                captured(),
                auxiliary,
                |budget| FundedDatagram::copy_from(&packet[payload], budget),
            ),
            Rx::TransparentOwned {
                src,
                dst,
                dscp,
                packet,
                payload,
            } => {
                let source = match completion.take() {
                    Some(source) => Some(PacketSource::Completed(source)),
                    None if host.is_some() => {
                        return Err(io::Error::other(
                            "Host reassembly completion lost its source owner",
                        ));
                    }
                    None => physical.cloned().map(PacketSource::Completed),
                };
                self.queue_datagram(
                    scope,
                    src,
                    dst,
                    dscp,
                    admission.take(),
                    source,
                    auxiliary,
                    |budget| FundedDatagram::from_packet(packet, payload, budget),
                )
            }
            Rx::TransparentSplit {
                src,
                dst,
                dscp,
                payload,
                size,
            } => {
                let mut failure = None;
                let mut qualified = true;
                let mut taken_over = false;
                for payload in packet[payload].chunks(usize::from(size)) {
                    match self.queue_datagram(
                        scope,
                        src,
                        dst,
                        dscp,
                        admission.take(),
                        captured(),
                        auxiliary,
                        |budget| FundedDatagram::copy_from(payload, budget),
                    ) {
                        Ok((enqueued, owned)) => {
                            qualified &= enqueued;
                            taken_over |= owned;
                        }
                        Err(error) => {
                            failure.get_or_insert(error);
                        }
                    }
                }
                failure.map_or(Ok((qualified, taken_over)), Err)
            }
            _ => Ok((received.qualified_rx, received.taken_over)),
        };
        self.accept_ready(scope, auxiliary);
        result.map(|(qualified_rx, taken_over)| {
            received.qualified_rx = REPORT && qualified_rx;
            received.taken_over = taken_over;
            received
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn queue_datagram(
        &self,
        scope: &PacketScope,
        source: SocketAddr,
        destination: SocketAddr,
        dscp: u8,
        mut routing: Option<EndpointAdmission>,
        packet_source: Option<PacketSource<'_>>,
        auxiliary: Option<&AuxiliaryWork>,
        make: impl FnOnce(&Arc<MemoryBudget>) -> Option<FundedDatagram>,
    ) -> io::Result<(bool, bool)> {
        if self.shared.is_closing() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                DatagramAdmissionClosed,
            ));
        }
        if auxiliary.is_some_and(|binding| !binding.is_active()) {
            return Ok((false, false));
        }
        let permit = self.sender.try_reserve().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "packet ingress queue is full")
        })?;
        let bytes = make(&self.shared.budget).ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "packet ingress memory capacity")
        })?;
        if destination.port() != 53 {
            let packet_lineage = packet_source.as_ref().and_then(PacketSource::lineage);
            let pool = &self.shared.udp_pool;
            let now = super::udp_endpoint::queue_now();
            if let Some((reservation, _)) = pool.enqueue_bound_payload_at(
                scope.scope(),
                source,
                destination,
                DatagramPayload::Funded(bytes.clone()),
                None,
                now,
                &self.shared.stats,
                packet_lineage,
                None,
                auxiliary,
            ) {
                let enqueued = matches!(reservation, EndpointReservation::Enqueued);
                return Ok((enqueued, enqueued));
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
                return Ok((false, false));
            };
            let epoch = pool.initialization_epoch();
            if let Some((reservation, ready)) = pool.enqueue_bound_payload_at(
                scope.scope(),
                source,
                destination,
                DatagramPayload::Funded(bytes.clone()),
                None,
                now,
                &self.shared.stats,
                packet_lineage,
                Some(epoch),
                auxiliary,
            ) {
                let enqueued = matches!(reservation, EndpointReservation::Enqueued);
                return Ok((ready && enqueued, enqueued));
            }
            let packet_source = match packet_source {
                Some(source) => Some(source.hold(scope)?),
                None => Some(scope.hold_source(source.ip())?),
            };
            let retained_source = packet_source.clone();
            let reservation =
                EndpointAdmission::commit_pending(&mut routing, scope.scope(), |_| {
                    pool.reserve_payload_or_enqueue_at(
                        scope.scope(),
                        source,
                        destination,
                        DatagramPayload::Funded(bytes),
                        None,
                        crate::ebpf::UdpFlowOwner::packet(),
                        epoch,
                        slow,
                        now,
                        &self.shared.stats,
                        packet_source,
                    )
                })?;
            drop(retained_source);
            return match reservation {
                EndpointReservation::Initializing(mut lease) => {
                    lease.packet_routing = routing.map(EndpointAdmission::into_snapshot);
                    lease.packet_dscp = Some(dscp);
                    initializer.send(QueuedInitializer {
                        lease,
                        auxiliary: auxiliary.cloned(),
                    });
                    Ok((false, true))
                }
                EndpointReservation::Enqueued => Ok((false, true)),
                _ => Ok((false, false)),
            };
        }
        let source_work = match packet_source {
            Some(source) => source.hold(scope)?,
            None => scope.hold_source(source.ip())?,
        };
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        let source_work = {
            let mut work = source_work;
            work.admit_udp_process(source, destination)?;
            work
        };
        if routing
            .as_ref()
            .is_some_and(|admission| admission.source_context() != source_work.optional_context())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "packet routing source changed before DNS admission",
            ));
        }
        let datagram =
            EndpointAdmission::commit_pending(&mut routing, scope.scope(), |routing| Datagram {
                scope: scope.scope(),
                source,
                destination,
                dscp,
                routing: routing.take(),
                bytes,
                source_work,
                auxiliary: auxiliary.cloned(),
            })?;
        permit.send(Work::Udp(datagram));
        Ok((false, true))
    }

    fn accept_ready(&self, scope: &PacketScope, auxiliary: Option<&AuxiliaryWork>) {
        if self.shared.is_closing()
            || auxiliary.is_some_and(|binding| !binding.is_active())
            || !scope.has_pending_accept()
        {
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
            permit.send(Work::Tcp(flow, slot, auxiliary.cloned()));
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
        self.shared.capture_ready.store(true, Ordering::Release);
        self.shared.changed.notify_one();
        Ok(())
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.shared.is_closing()
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

    pub(crate) fn is_joined(&self) -> bool {
        self.task.is_none()
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

    /// Poll until Ready once. A failed start joins the supervisor's actual cleanup and
    /// returns its error; a driven caller keeps servicing its drivers meanwhile.
    pub(crate) fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<anyhow::Result<()>> {
        if let Some(ready) = &mut self.ready {
            let started = std::task::ready!(std::pin::Pin::new(ready).poll(cx)).is_ok();
            self.ready = None;
            if started {
                return std::task::Poll::Ready(Ok(()));
            }
        }
        std::task::Poll::Ready(Err(match std::task::ready!(self.poll_join_plane(cx)) {
            Ok((_, Err(error))) | Err(error) => error,
            Ok((_, Ok(()))) => anyhow::anyhow!("packet supervisor failed before admission"),
        }))
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
        // Before scope tasks: their wrappers report abandonment here before closing.
        let (fatal, mut failures) = mpsc::unbounded_channel();
        while !self.owners.is_empty() {
            let owners = &mut self.owners;
            let spawned = if self.driven {
                let shared = &self.shared;
                self.scope_tasks.spawn_with(
                    || {
                        run_driven_scope(
                            owners.pop().expect("unadmitted scope owner"),
                            Arc::clone(shared),
                            fatal.clone(),
                        )
                    },
                    0,
                )
            } else {
                self.scope_tasks
                    .spawn_with(|| owners.pop().expect("unadmitted scope owner").run(), 0)
            };
            if let Err(error) = spawned {
                failure = Some(error.into());
                break;
            }
        }
        let fallback_fatal = (!self.owners.is_empty()).then(|| fatal.clone());
        let (configured_packet, egress_mark, mut authorizations, endpoint) =
            if failure.is_none() && !self.shared.is_closing() {
                let config = self.plane.config.read().await;
                let backend = config.datapath.as_ref().map(|datapath| datapath.backend);
                let configured_packet = matches!(
                    backend,
                    Some(honk_config::datapath::Backend::Xdp | honk_config::datapath::Backend::Tun)
                );
                let tun = backend == Some(honk_config::datapath::Backend::Tun);
                if tun {
                    let host_facts = config
                        .datapath
                        .as_ref()
                        .and_then(|value| value.tun.as_ref())
                        .is_some_and(|tun| tun.host_facts);
                    let plain = self
                        .shared
                        .scopes
                        .iter()
                        .filter(|scope| !scope.is_host())
                        .count();
                    let host = self
                        .shared
                        .scopes
                        .iter()
                        .filter(|scope| scope.is_host())
                        .count();
                    if plain != 1
                        || host != usize::from(host_facts)
                        || !self.shared.scopes.iter().any(|scope| {
                            scope.scope() == self.standalone_dns_scope && !scope.is_host()
                        })
                    {
                        failure = Some(anyhow::anyhow!(
                            "TUN requires its plain scope and configured Host scope"
                        ));
                    }
                }
                let egress_mark = config.required_socket_mark();
                let authorizations = if configured_packet {
                    match crate::subscription::SubscriptionAuthorizations::new(
                        &config.subscriptions,
                    ) {
                        Ok(authorizations) => Some(authorizations),
                        Err(error) => {
                            failure = Some(error);
                            None
                        }
                    }
                } else {
                    None
                };
                let endpoint = if configured_packet {
                    config.dns.bind_endpoint().map_err(anyhow::Error::from)
                } else {
                    Ok(None)
                };
                (configured_packet, egress_mark, authorizations, endpoint)
            } else {
                (false, None, None, Ok(None))
            };
        let fact_scope = self.standalone_dns_scope;
        if configured_packet
            && failure.is_none()
            && !self.shared.is_closing()
            && let Err(error) = self.plane.initialize_datapath_flags(false, false).await
        {
            failure = Some(error);
        }
        let mut dns_listener = None;
        if configured_packet && failure.is_none() && !self.shared.is_closing() {
            let bound = endpoint.and_then(|endpoint| {
                let Some(endpoint) = endpoint else {
                    return Ok(None);
                };
                if let Some(mark) = egress_mark {
                    let prepared = self.prepared_dns_addresses.take().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "marked dns.bind requires addresses prepared before capture",
                        )
                    })?;
                    anyhow::ensure!(
                        prepared.endpoint == endpoint,
                        "prepared dns.bind endpoint changed"
                    );
                    BoundDnsListener::bind_prepared(&prepared, Some(mark))
                } else {
                    BoundDnsListener::bind(&endpoint, None)
                }
                .map(Some)
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
                    fact_scope,
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
            if !configured_packet {
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
            if !running_published && self.shared.capture_ready.load(Ordering::Acquire) {
                let router = self.plane.router.read().await;
                let backend = self.plane.ebpf.read().await;
                crate::ebpf::record_pname_routing(&router, &**backend, &self.plane.degradations);
                drop((backend, router));
                #[cfg(feature = "native-api")]
                self.plane.publish_phase(super::EnginePhase::Running);
                running_published = true;
            }
            tokio::select! {
                _ = self.shared.changed.notified() => {},
                command = commands.as_mut().expect("open command receiver").recv() => match command {
                    Some(command) => {
                        if self.shared.is_closing() {
                            if !self.shared.fatal_control.load(Ordering::Acquire) {
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
                Some(initializer) = self.initializers.recv() => self.dispatch_lease(&handle, initializer),
                work = self.receiver.recv() => match work {
                    Some(Work::Tcp(flow, permit, auxiliary)) => {
                        if auxiliary.as_ref().is_some_and(|binding| !binding.is_active()) {
                            drop((flow, permit, auxiliary));
                            continue;
                        }
                        while let Some(result) = self.tcp_tasks.try_join_next() {
                            report_tcp_completion(result);
                        }
                        self.plane.udp_pool.reap_tasks();
                        let guard = ConnectionGuard::new(Arc::clone(&self.plane.drain_tracker));
                        let mut auxiliary = auxiliary;
                        let owner = flow.direct_relay_runtime()
                            .filter(|_| auxiliary.is_none())
                            .and_then(|owner| owner.with_completion_credit(&self.shared.budget));
                        let mut connection = Some((handle.clone(), permit, guard, flow));
                        let buffers = crate::relay::COPY_BUFFER_MEMORY + crate::sniffing::SNIFF_MEMORY;
                        let scoped = owner.map(|owner_handle| {
                            self.tcp_tasks.spawn_scoped_with(
                                |registration| {
                                    let (handle, permit, guard, flow) = connection.take().unwrap();
                                    async move {
                                        let (_permit, _guard) = (permit, guard);
                                        if let Err(error) = handle
                                            .serve_owned_packet_connection(flow, owner_handle, registration)
                                            .await
                                        {
                                            tracing::debug!(%error, "packet TCP endpoint ended");
                                        }
                                    }
                                },
                                buffers,
                            )
                        });
                        let admitted = match scoped {
                            Some(Ok(())) => Ok(()),
                            Some(Err(error)) if error.kind() != io::ErrorKind::OutOfMemory => {
                                Err(error)
                            }
                            _ if auxiliary.is_some() => {
                                self.tcp_tasks
                                    .spawn_scoped_with(
                                        |registration| {
                                            let (handle, permit, guard, flow) = connection.take().unwrap();
                                            let auxiliary = auxiliary.take().unwrap();
                                            async move {
                                                let (_permit, _guard) = (permit, guard);
                                                if let Err(error) = handle
                                                    .serve_auxiliary_packet_connection(flow, &auxiliary, registration)
                                                    .await
                                                {
                                                    tracing::debug!(%error, "packet TCP endpoint ended");
                                                }
                                            }
                                        },
                                        buffers,
                                    )
                            }
                            _ => {
                                self.tcp_tasks
                                    .spawn_with(
                                        || {
                                            let (handle, permit, guard, flow) = connection.take().unwrap();
                                            async move {
                                                let (_permit, _guard) = (permit, guard);
                                                if let Err(error) = handle.serve_packet_connection(flow).await {
                                                    tracing::debug!(%error, "packet TCP endpoint ended");
                                                }
                                            }
                                        },
                                        buffers,
                                    )
                                    .map(drop)
                            }
                        };
                        if let Err(error) = admitted {
                            let (_, _, _, flow) = connection.as_mut().unwrap();
                            flow.abort();
                            tracing::debug!(%error, "packet TCP task admission refused");
                        }
                    }
                    Some(Work::Udp(datagram)) => self.dispatch_datagram(&handle, datagram).await,
                    None => break,
                }
            }
        }
        self.shared.close();
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
        // The supervisor is already funded; admission failure cannot drop these owners.
        // Retain opaque panic payloads until every other original owner has joined too.
        let mut panics: [Option<Box<dyn std::any::Any + Send>>; MAX_SCOPES] =
            std::array::from_fn(|_| None);
        for (index, owner) in self.owners.drain(..).enumerate() {
            let result = if self.driven {
                std::panic::AssertUnwindSafe(run_driven_scope(
                    owner,
                    Arc::clone(&self.shared),
                    fallback_fatal
                        .as_ref()
                        .expect("unadmitted scope failure channel")
                        .clone(),
                ))
                .catch_unwind()
                .await
            } else {
                std::panic::AssertUnwindSafe(owner.run())
                    .catch_unwind()
                    .await
            };
            if let Err(panic) = result {
                panics[index] = Some(panic);
                failure.get_or_insert_with(|| {
                    anyhow::anyhow!("unadmitted packet scope cleanup panicked")
                });
            }
        }
        while let Some(result) = self.scope_tasks.join_next().await {
            if let Err(error) = result {
                failure.get_or_insert(error.into());
            }
        }
        // An abandonment recorded behind a winning close is still a failed outcome.
        while let Ok(error) = failures.try_recv() {
            failure.get_or_insert(error);
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
        drop(panics);
        (self.plane, result)
    }

    async fn dispatch_datagram(&self, handle: &ControlPlaneHandle, datagram: Datagram) {
        if datagram
            .auxiliary
            .as_ref()
            .is_some_and(|binding| !binding.is_active())
        {
            return;
        }
        let Datagram {
            auxiliary,
            scope,
            source,
            destination,
            dscp,
            bytes,
            routing,
            source_work,
        } = datagram;
        let pool = &self.plane.udp_pool;
        let packet_source = Some(&source_work);
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
                if let Some((process, mark)) = source_work.packet_input() {
                    packet_observation
                        .as_mut()
                        .unwrap()
                        .packet_facts(process, dscp, mark);
                }
                packet_observation.as_ref().unwrap().routing_started();
            }
            #[cfg_attr(not(feature = "native-api"), allow(unused_mut))]
            let mut snapshot = match packet_routing.take() {
                Some(snapshot) => snapshot,
                None => {
                    let prepare = handle.prepare_packet_routing_snapshot(
                        scope,
                        source,
                        destination,
                        "udp",
                        dscp,
                        packet_source,
                        None,
                        #[cfg(feature = "native-api")]
                        packet_observation.as_ref().unwrap().is_recording(),
                    );
                    match run_until_auxiliary_pause(auxiliary.as_ref(), prepare).await {
                        Some(Ok(snapshot)) => snapshot,
                        Some(Err(error)) => {
                            tracing::debug!(%error, "packet DNS policy admission failed");
                            return;
                        }
                        None => {
                            #[cfg(feature = "native-api")]
                            finish_packet_dns(packet_observation.as_ref().unwrap(), None);
                            return;
                        }
                    }
                }
            };
            if auxiliary
                .as_ref()
                .is_some_and(|binding| !binding.is_active())
            {
                #[cfg(feature = "native-api")]
                finish_packet_dns(packet_observation.as_ref().unwrap(), None);
                return;
            }
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
                let sender = match source_work
                    .owner()
                    .datagram_sender_for(destination, source_work.clone())
                {
                    Ok(sender) => sender,
                    Err(error) => {
                        tracing::debug!(%error, "packet DNS reply source refused");
                        return;
                    }
                };
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
                let admission = dns.try_admit_packet_query(true, scope);
                if auxiliary.as_ref().is_some_and(|binding| {
                    !binding.is_active() || (admission.is_err() && dns.query_scope(scope).is_none())
                }) {
                    #[cfg(feature = "native-api")]
                    finish_packet_dns(&observation, None);
                    return;
                }
                match admission {
                    Ok(admission) => {
                        self.plane.stats.record_udp_slow_permit_accepted();
                        let guard = ConnectionGuard::new(Arc::clone(&self.plane.drain_tracker));
                        pool.spawn_slow_path(async move {
                            let operation = async move {
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
                                match observer {
                                    Some(observer) => observer.scope(operation).await,
                                    None => operation.await,
                                }
                                #[cfg(not(feature = "native-api"))]
                                operation.await;
                            };
                            let completed =
                                run_until_auxiliary_pause(auxiliary.as_ref(), operation)
                                    .await
                                    .is_some();
                            #[cfg(feature = "native-api")]
                            finish_packet_dns(
                                &observation,
                                completed.then_some("dns_query_completed"),
                            );
                            #[cfg(not(feature = "native-api"))]
                            let _ = completed;
                        });
                    }
                    Err(error) => {
                        if let Some((runtime, permit)) = error.udp_reply {
                            self.plane.stats.record_udp_slow_permit_accepted();
                            let guard = ConnectionGuard::new(Arc::clone(&self.plane.drain_tracker));
                            pool.spawn_slow_path(async move {
                                let binding = auxiliary.as_ref();
                                let operation = async move {
                                    let _guard = guard;
                                    let (_response_memory, _permit) = (response_memory, permit);
                                    let _source_work = source_work;
                                    #[cfg(feature = "native-api")]
                                    let started = Instant::now();
                                    let response = crate::dns::response::build_dns_refused(&bytes);
                                    let reply = async {
                                        crate::observe::flows::dns::decision(
                                            "rejected",
                                            Some("admission_refused"),
                                        );
                                        let delivery = runtime
                                            .run_reply(sender.send_to(&response, source))
                                            .await;
                                        if binding.is_some_and(|binding| !binding.is_active()) {
                                            crate::observe::flows::dns::delivery(
                                                "cancelled",
                                                Some("intentional_retirement"),
                                            );
                                        } else {
                                            crate::observe::flows::dns::reply_delivery(
                                                &delivery,
                                                |length| *length == response.len(),
                                                "client_send_failed",
                                            );
                                        }
                                    };
                                    #[cfg(feature = "native-api")]
                                    {
                                        let reply = std::pin::pin!(reply);
                                        let reply = crate::observe::flows::dns::client_scope(
                                            &bytes,
                                            validated.ingress(),
                                            crate::dns::query::DnsRequestMeta::new(
                                                Some(source.ip()),
                                                Some(destination),
                                            ),
                                            reply,
                                        );
                                        match observer {
                                            Some(observer) => observer.scope(reply).await,
                                            None => reply.await,
                                        }
                                        if binding.is_none_or(AuxiliaryWork::is_active) {
                                            dns.dns_service().observer.observe_client(
                                                &bytes,
                                                validated.ingress(),
                                                Some(source),
                                                None,
                                                &response,
                                                started.elapsed(),
                                            );
                                        }
                                    }
                                    #[cfg(not(feature = "native-api"))]
                                    reply.await;
                                };
                                let completed = run_until_auxiliary_pause(binding, operation)
                                    .await
                                    .is_some();
                                #[cfg(feature = "native-api")]
                                finish_packet_dns(
                                    &observation,
                                    completed.then_some("dns_query_refused"),
                                );
                                #[cfg(not(feature = "native-api"))]
                                let _ = completed;
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
                let mark = snapshot.decision.mark.unwrap_or(0);
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
            .enqueue_bound_payload_at(
                scope,
                source,
                destination,
                DatagramPayload::Funded(bytes.clone()),
                raw_route.as_ref().map(RawDnsRoute::as_ref),
                super::udp_endpoint::queue_now(),
                &self.plane.stats,
                packet_source
                    .and_then(SourceWork::optional_context)
                    .map(|source| source.lineage),
                None,
                auxiliary.as_ref(),
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
                let active = auxiliary.as_ref().is_none_or(AuxiliaryWork::is_active);
                finish_packet_dns(&observation, active.then_some("existing_udp_endpoint"));
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
            Some(source_work),
        ) {
            lease.packet_routing = packet_routing;
            lease.packet_dscp = Some(dscp);
            #[cfg(feature = "native-api")]
            {
                lease.packet_observation = packet_observation.take();
            }
            self.dispatch_lease(handle, QueuedInitializer { lease, auxiliary });
        } else {
            #[cfg(feature = "native-api")]
            if auxiliary
                .as_ref()
                .is_some_and(|binding| !binding.is_active())
                && let Some(observation) = packet_observation
            {
                finish_packet_dns(&observation, None);
            }
        }
    }

    fn dispatch_lease(&self, handle: &ControlPlaneHandle, initializer: QueuedInitializer) {
        if initializer
            .auxiliary
            .as_ref()
            .is_some_and(|binding| !binding.is_active())
        {
            #[cfg(feature = "native-api")]
            if let Some(observation) = &initializer.lease.packet_observation {
                finish_packet_dns(observation, None);
            }
            return;
        }
        let QueuedInitializer { auxiliary, lease } = initializer;
        let handle = handle.clone();
        let guard = ConnectionGuard::new(Arc::clone(&self.plane.drain_tracker));
        self.plane.udp_pool.spawn_slow_path(async move {
            let _binding = auxiliary;
            let _guard = guard;
            if let Err(error) = handle.serve_udp_connection(lease).await {
                tracing::debug!(%error, "packet UDP endpoint ended");
            }
        });
    }
}

#[cfg(feature = "native-api")]
fn finish_packet_dns(
    observation: &super::connection::observation::ConnectionObservation,
    completed: Option<&'static str>,
) {
    observation.finish(
        crate::observe::vocab::ConnectionState::Closed,
        completed.unwrap_or("intentional_retirement"),
    );
}

mod maintenance;
mod realm;

#[cfg(test)]
mod tests;
