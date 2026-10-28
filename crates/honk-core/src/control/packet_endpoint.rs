//! Explicit L3 Endpoint integration, not packet capture or native continuation authority.
//!
//! The caller runs and joins `PacketEndpointOwner::run`, and retains each scope's
//! output lease through actual backend I/O. No kernel listener or hook is started.

use super::ControlPlane;
use super::connection::{ConnectionGuard, ControlPlaneHandle};
use super::dns_control::DnsUdpReply;
use super::netstack::{FlowIo, PacketOwner, PacketScope};
use super::task_registry::TaskRegistry;
use super::udp_endpoint::{
    DatagramPayload, EndpointReservation, FundedDatagram, RawDnsRoute, ReplySocketFd,
    UdpEndpointPool, UdpReplySocketFactory,
};
use honk_datapath::ScopeId;
use honk_netstack::{MemoryBudget, MemoryReservation, Rx};
use std::io;
use std::net::SocketAddr;
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
}

enum Work {
    Tcp(FlowIo, OwnedSemaphorePermit),
    Udp(Datagram),
}

struct Shared {
    scopes: Arc<[PacketScope]>,
    budget: Arc<MemoryBudget>,
    udp_pool: Arc<UdpEndpointPool>,
    tcp_slots: Arc<tokio::sync::Semaphore>,
    admission: AtomicU8,
    changed: Notify,
    closed: Arc<crate::connection_tracker::CloseSignal>,
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
            scope.close_admission();
        }
        self.changed.notify_one();
    }
}

/// A bounded ingress handle. Copies share admission, scopes and one core UDP pool.
#[derive(Clone)]
pub struct PacketEndpoints {
    shared: Arc<Shared>,
    sender: mpsc::Sender<Work>,
}

/// Join handle for the supervisor. Dropping it requests cleanup, never aborts cleanup.
pub struct PacketEndpointOwner {
    shared: Arc<Shared>,
    task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

struct EndpointRuntime {
    shared: Arc<Shared>,
    plane: ControlPlane,
    receiver: mpsc::Receiver<Work>,
    owners: Vec<PacketOwner>,
    scope_tasks: TaskRegistry,
    tcp_tasks: TaskRegistry,
    startup: Option<tokio::sync::oneshot::Sender<()>>,
}

impl PacketEndpoints {
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
            .checked_mul(4 * size_of::<Work>())
            .and_then(|n| {
                n.checked_add(MAX_SCOPES * (size_of::<PacketScope>() + size_of::<PacketOwner>()))
            })
            .and_then(|n| n.checked_add(size_of::<Shared>()))
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
            admission: AtomicU8::new(STARTING),
            changed: Notify::new(),
            closed: crate::connection_tracker::CloseSignal::new(),
            supervisor_memory: std::sync::OnceLock::new(),
            _memory: memory,
        });
        let (sender, receiver) = mpsc::channel(INGRESS_CAPACITY);
        let (started, ready) = tokio::sync::oneshot::channel();
        let runtime = EndpointRuntime {
            shared: Arc::clone(&shared),
            plane,
            receiver,
            owners,
            scope_tasks,
            tcp_tasks,
            startup: Some(started),
        };
        let completed = Arc::clone(&shared.closed);
        let operation = async move {
            let _completion = crate::connection_tracker::CloseCompletion(Arc::clone(&completed));
            let result = runtime.run().await;
            completed.finish(result.is_ok());
            result
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
        Ok((Self { shared, sender }, owner))
    }

    /// Receive one verified IP packet. A receive batch supplies one `now` value.
    /// Queue pressure drops only that UDP datagram; established TCP still progresses.
    pub fn receive(&self, scope: ScopeId, packet: &[u8], now: Instant) -> io::Result<()> {
        let scope = self
            .shared
            .scopes
            .iter()
            .find(|item| item.scope() == scope)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unowned packet scope"))?;
        self.shared.udp_pool.reap_tasks();
        let result = match scope.receive(packet, now) {
            Rx::Transparent {
                src,
                dst,
                dscp,
                payload,
            } => self.queue_datagram(scope.scope(), src, dst, dscp, |budget| {
                FundedDatagram::copy_from(&packet[payload], budget)
            }),
            Rx::TransparentOwned {
                src,
                dst,
                dscp,
                packet,
                payload,
            } => self.queue_datagram(scope.scope(), src, dst, dscp, |budget| {
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
                    if let Err(error) =
                        self.queue_datagram(scope.scope(), src, dst, dscp, |budget| {
                            FundedDatagram::copy_from(payload, budget)
                        })
                    {
                        failure.get_or_insert(error);
                    }
                }
                failure.map_or(Ok(()), Err)
            }
            _ => Ok(()),
        };
        self.accept_ready(scope);
        result
    }

    fn queue_datagram(
        &self,
        scope: ScopeId,
        source: SocketAddr,
        destination: SocketAddr,
        dscp: u8,
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
        permit.send(Work::Udp(Datagram {
            scope,
            source,
            destination,
            dscp,
            bytes,
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

    /// Close new admission. The owner performs explicit abort and joined teardown;
    /// exported output leases must still be released by their actual I/O consumers.
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
    pub async fn run(mut self) -> anyhow::Result<()> {
        let result = self.task.as_mut().expect("one supervisor join").await?;
        self.task.take();
        result
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
    async fn run(mut self) -> anyhow::Result<()> {
        let mut failure = None;
        for owner in self.owners.drain(..) {
            if let Err(error) = self.scope_tasks.spawn(owner.run(), 0) {
                failure = Some(error.into());
                break;
            }
        }
        let mut maintenance = if failure.is_none() && !self.shared.is_closing() {
            maintenance::start(&mut self.plane).await
        } else {
            Default::default()
        };
        let mut commands = self
            .plane
            .command_rx
            .take()
            .expect("unstarted packet control receiver");
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
        // This CAS commits readiness; a later close overlaps an already-started runtime.
        if failure.is_none()
            && self
                .shared
                .admission
                .compare_exchange(STARTING, READY, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            #[cfg(feature = "native-api")]
            self.plane.publish_phase(super::EnginePhase::Running);
            let _ = self.startup.take().unwrap().send(());
        } else {
            self.startup.take();
        }
        loop {
            if failure.is_some() || self.shared.is_closing() {
                break;
            }
            tokio::select! {
                _ = self.shared.changed.notified() => {},
                command = commands.recv() => match command {
                    Some(command) => {
                        if maintenance::handle_command(&mut self.plane, command).await == maintenance::CommandAction::Shutdown { break; }
                    }
                    None => break,
                },
                result = self.scope_tasks.join_next(), if !self.scope_tasks.is_empty() => {
                    failure = Some(anyhow::anyhow!("packet scope owner exited before shutdown: {result:?}"));
                    break;
                }
                error = failures.recv() => {
                    failure = Some(error.unwrap_or_else(|| anyhow::anyhow!("packet retirement worker stopped")));
                    break;
                }
                Some(result) = self.tcp_tasks.join_next(), if !self.tcp_tasks.is_empty() => {
                    report_tcp_completion(result);
                }
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
        #[cfg(feature = "native-api")]
        self.plane.publish_phase(if failure.is_some() {
            super::EnginePhase::Failed
        } else {
            super::EnginePhase::Draining
        });
        commands.close();
        while let Ok(command) = commands.try_recv() {
            let _ = maintenance::handle_command(&mut self.plane, command).await;
        }
        self.receiver.close();
        for scope in self.shared.scopes.iter() {
            scope.close_admission();
            scope.shutdown(true);
        }
        // Pre-close permits can still publish FlowIo; drain them before joining scopes.
        while self.receiver.recv().await.is_some() {}
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
        if let Err(error) = maintenance.abort_and_join().await {
            failure.get_or_insert(error);
        }
        maintenance::shutdown(&mut self.plane, failure, Some(shutdown)).await
    }

    async fn dispatch_datagram(&self, handle: &ControlPlaneHandle, datagram: Datagram) {
        let Datagram {
            scope,
            source,
            destination,
            dscp,
            bytes,
        } = datagram;
        let pool = &self.plane.udp_pool;
        let epoch = pool.initialization_epoch();
        let mut raw_route = None;
        let mut packet_routing = None;
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
            let mut snapshot = match handle
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
            };
            if snapshot.decision.outbound == "block" {
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
                        pool.spawn_slow_path(async move {
                            let _response_memory = response_memory;
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
                            pool.spawn_slow_path(async move {
                                let (_response_memory, _permit) = (response_memory, permit);
                                let response = crate::dns::response::build_dns_refused(&bytes);
                                let _ = runtime.run_reply(sender.send_to(&response, source)).await;
                                #[cfg(feature = "native-api")]
                                observation.finish(
                                    crate::observe::vocab::ConnectionState::Closed,
                                    "dns_query_refused",
                                );
                            });
                        } else {
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
            raw_route = Some(if snapshot.decision.outbound == "direct" {
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
                RawDnsRoute::Group(snapshot.decision.outbound.clone())
            } else {
                RawDnsRoute::FallbackGroup(snapshot.decision.outbound.clone())
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
            let handle = handle.clone();
            let guard = ConnectionGuard::new(Arc::clone(&self.plane.drain_tracker));
            pool.spawn_slow_path(async move {
                let _guard = guard;
                if let Err(error) = handle.serve_udp_connection(lease).await {
                    tracing::debug!(%error, "packet UDP endpoint ended");
                }
            });
        }
    }
}

mod maintenance;

#[cfg(test)]
mod tests;
