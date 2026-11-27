//! One Linux capture owner for every selected RX queue and one routing domain.
//! Physical links are owned by FDs: exit detaches them and the kernel resumes forwarding; UMEM stays until exit.

mod aux_tasks;
mod config;
mod forward;
mod queue_io;
mod retain;
#[cfg(test)]
mod tests;

pub(crate) use config::validate_config;
#[cfg(test)]
use config::{
    admission_failure, gateway_time_namespace_issue, layout_admission_issues,
    member_admission_issues, queue_sizing, realm_worker_count,
};
use config::{device_sizing, direct_relay_eligible, prepare};
use forward::*;
use queue_io::*;
use retain::*;
pub(crate) mod gateway;
#[cfg(feature = "packet-ebpf")]
mod host_identity;
pub(crate) mod polling;
pub(crate) mod routing_input;
mod tcx_aux;
pub(crate) mod timens;
mod topology;
pub(crate) mod worker;
use crate::control::poll_budget::BusyInterval;
use polling::runtime::polling_segment_stop;
use polling::{AdaptivePoll, ContextDigest};

#[cfg(test)]
use crate::control::netstack::capture_scope;
use crate::control::{
    ControlPlane,
    core_forward::{
        CachedDecision, Decision, Execution, GeneratedError, IngressBinding, PolicyGeneration,
        PolicyRead, Requirements, RoutedCore, socket_namespace,
    },
    netstack::{
        CAPTURE_MEMORY, CAPTURE_WIDE_BULK_FRAMES, DirectRelayFence, MaterializedOutput,
        OutputLease, OutputOwner, PacketDriver, PacketRealm, PacketScope, capture_realm,
    },
    packet_endpoint::{EndpointAdmission, PacketEndpointOwner, PacketEndpoints, PacketReceive},
};
use crate::netlink::fib::{Fib, LogicalLink};
use crate::stats::xdp::{Diagnostics, Lifecycle, QueueObservation};
use anyhow::{Context as _, ensure};
use gateway::{GatewayPolicy, GatewayPublisher, GatewayReload, HoldCollector, ZoneAdmission};
use honk_config::{
    Config,
    datapath::{Backend, DirectProfile, XskMode},
};
use honk_datapath::{
    ScopeId,
    buffer::TxClass,
    forward::{
        ForwardLease, ForwardPacket, Ingress, LinkPath, MarkProvenance, Packet, Prepared, Route,
    },
};
use honk_ebpf_common::xdp::{CaptureAuthority, METADATA_LEN};
use honk_ebpf_common::xdp_gateway::LocalAddressKey;
use honk_netstack::{
    MemoryBudget, MemoryReservation,
    wire::{self, PacketView},
};
use honk_xsk::{
    BindMode, DecodedPacket, FRAME_SIZE, GeneralCapture, OwnedXdpLink, Port, PortConfig,
    PortCounters, Programs, RingSnapshot,
    device::{DeviceInfo, FeatureQuery, VlanOffload, prepare_vlan_offload, select_xsk_mode},
};
use std::{
    collections::VecDeque,
    future::poll_fn,
    io,
    net::IpAddr,
    os::fd::{AsFd, AsRawFd},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};
use tokio::io::unix::AsyncFd;
use topology::{CapturePlan, CaptureTopology, TopologyEvent};

const PENDING: usize = 64;
const PEERS: usize = 4096;
const PEER_CONFLICT_HOLD: Duration = Duration::from_secs(60);
const BATCH: usize = 32;
const DETACH_BUDGET: Duration = Duration::from_millis(100);
const LINK_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const STANDBY_LINK_CHECK: &str = "checking idle physical XDP link identity";

fn qualify_packet(count: &mut u64, unavailable: &mut bool) {
    match count.checked_add(1) {
        Some(value) => *count = value,
        None => *unavailable = true,
    }
}

fn qualify_receive(
    result: io::Result<PacketReceive>,
    count: &mut u64,
    unavailable: &mut bool,
) -> io::Result<()> {
    if result?.qualified_rx {
        qualify_packet(count, unavailable);
    }
    Ok(())
}

struct Queue {
    id: u32,
    io: QueueIo,
    observed: PortCounters,
    observed_rings: RingSnapshot,
}
struct Device {
    info: Arc<DeviceInfo>,
    capture: GeneralCapture,
    queue_maps: Arc<honk_xsk::ProgramQueueMaps>,
    programs: Option<(Programs, MemoryReservation)>,
    attachment: Option<OwnedXdpLink>,
    vlan_offload: VlanOffload,
    queues: Vec<Queue>,
    active: bool,
    metadata_checked: Instant,
    features: Option<FeatureQuery>,
    port_config: PortConfig,
    role: honk_config::datapath::InterfaceRole,
}

struct StartupDevices(Vec<Device>);

impl std::ops::Deref for StartupDevices {
    type Target = Vec<Device>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for StartupDevices {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for StartupDevices {
    fn drop(&mut self) {
        for device in self.0.iter_mut().rev() {
            if let Some(link) = device.attachment.take()
                && let Err(error) = link.detach()
            {
                tracing::error!(%error, "XDP startup link detach failed");
            }
            if let Err(error) = device.vlan_offload.restore() {
                tracing::error!(%error, "XDP startup VLAN restore failed");
            }
        }
    }
}

struct Waiting {
    packet: Packet,
    mac: [u8; 6],
    retry: Instant,
    scope: ScopeId,
    ingress_worker: usize,
    path: ReturnPath,
    ingress_at: Instant,
    cell: Option<worker::Cell>,
    peer: Option<worker::PeerHold>,
}
struct Pending {
    output: ForwardPacket,
    _cell: Option<worker::Cell>,
    _peer: Option<worker::PeerHold>,
    generation: PolicyGeneration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReturnPath {
    pub(crate) realm: u32,
    pub(crate) device: usize,
    pub(crate) mac: [u8; 6],
    pub(crate) vlan_tci: [u16; 2],
    pub(crate) vlan_proto: [u16; 2],
    pub(crate) vlan_count: u8,
}

#[cfg(test)]
struct Peer {
    scope: ScopeId,
    address: IpAddr,
    path: ReturnPath,
    last_seen: Instant,
    conflict: Option<Instant>,
}

#[cfg(test)]
#[derive(Default)]
struct PeerPolicy {
    retained: bool,
    output: bool,
    evict: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PressureCounters {
    waiting_full: u64,
    waiting_expired: u64,
    pending_full: u64,
    pending_expired: u64,
    peer_full: u64,
    core_ingress_refused: u64,
    peer_conflict: u64,
    peer_reclaimed: u64,
    endpoint_capacity: u64,
    tx_credit: u64,
    refused: bool,
    capture_rejected: u64,
}

struct Pressure {
    counters: PressureCounters,
    previous: PressureCounters,
    core: crate::control::core_forward::RefusalCounters,
    checked: Instant,
    active: bool,
}

impl Pressure {
    fn new(now: Instant) -> Self {
        Self {
            counters: Default::default(),
            previous: Default::default(),
            core: Default::default(),
            checked: now,
            active: false,
        }
    }

    fn refusing(&self, core: crate::control::core_forward::RefusalCounters) -> bool {
        self.counters.refused
            || core.core_capacity != self.core.core_capacity
            || core.nat_capacity != self.core.nat_capacity
            || core.nat_exhausted != self.core.nat_exhausted
            || core.nat_conflict != self.core.nat_conflict
    }

    fn next_deadline(&self, core: Option<&RoutedCore>) -> Option<Instant> {
        (self.active || self.refusing(core.map(RoutedCore::counters).unwrap_or_default()))
            .then_some(self.checked + Duration::from_secs(1))
    }

    fn sample(
        &mut self,
        now: Instant,
        core: Option<&RoutedCore>,
        waiting: usize,
        pending: usize,
        peers: usize,
    ) -> bool {
        if now.saturating_duration_since(self.checked) < Duration::from_secs(1) {
            return false;
        }
        self.checked = now;
        let core = core.map(RoutedCore::counters).unwrap_or_default();
        let diagnostics_changed = self.counters != self.previous || core != self.core;
        let active = self.refusing(core);
        if active && !self.active {
            tracing::warn!(counters = ?self.counters, core = ?core, waiting, pending, peers, "XDP packet pressure entered");
        } else if !active && self.active {
            tracing::info!("XDP pressure refusals quiet in the latest sampling interval");
        }
        if diagnostics_changed || active || self.active {
            tracing::debug!(counters = ?self.counters, core = ?core, waiting, pending, peers, "XDP aggregate packet pressure");
        }
        self.active = active;
        self.previous = self.counters;
        self.core = core;
        self.counters.refused = false;
        true
    }
}
#[derive(Debug, PartialEq, Eq)]
enum GeneratedAttempt {
    Idle,
    Closed,
    CpuQueuePending,
    Emitted,
}

struct Realm {
    realm_id: u32,
    members: Vec<usize>,
    ingress: Ingress,
    device: usize,
    link: LogicalLink,
    driver: PacketDriver,
    generated: Option<(usize, usize)>,
    pending: [Option<(OutputLease, ReturnPath)>; 2],
}

fn fold_capture_result(failure: &mut Option<anyhow::Error>, result: anyhow::Result<()>) {
    if let Err(error) = result {
        *failure = Some(match failure.take() {
            Some(previous) => previous.context(format!("capture close also failed: {error:#}")),
            None => error,
        });
    }
}

fn joined_plane(
    joined: anyhow::Result<(ControlPlane, anyhow::Result<()>)>,
    failure: &mut Option<anyhow::Error>,
) -> Option<ControlPlane> {
    match joined {
        Ok((plane, result)) => {
            fold_capture_result(failure, result);
            Some(plane)
        }
        Err(error) => {
            fold_capture_result(failure, Err(error));
            None
        }
    }
}

struct Runtime {
    devices: Vec<Device>,
    topology: AsyncFd<CaptureTopology>,
    topology_lost: bool,
    link_check_at: Instant,
    capture_plan: Option<CapturePlan>,
    capture_plan_memory: Option<MemoryReservation>,
    gateway: Option<Arc<GatewayPublisher>>,
    gateway_maps: Option<Arc<honk_xsk::GatewayMaps>>,
    zones: Option<ZoneAdmission>,
    links: Fib,
    local_addresses: Vec<LocalAddressKey>,
    local_memory: Option<MemoryReservation>,
    _kernel_memory: Vec<MemoryReservation>,
    hold_collector: HoldCollector,
    realm_scopes: std::collections::HashMap<u32, ScopeId>,
    admission: Arc<AtomicBool>,
    pname_support: crate::ebpf::PnameSupportCell,
    realms: Vec<Realm>,
    workers: Arc<worker::Shared>,
    worker: Option<worker::Worker>,
    inbox: tokio::sync::mpsc::Receiver<worker::Envelope>,
    endpoints: PacketEndpoints,
    core: Option<RoutedCore>,
    waiting: VecDeque<Waiting>,
    pending: VecDeque<Pending>,
    staging: Vec<u8>,
    closing: bool,
    finished: bool,
    pressure: Pressure,
    diagnostics: Arc<Diagnostics>,
    core_maintenance_checked: Instant,
    polling: AdaptivePoll,
    polling_prefix: Result<ContextDigest, &'static str>,
    polling_budget: Arc<MemoryBudget>,
    polling_affinity: Option<[u8; libc::CPU_SETSIZE as usize / 8]>,
    qualified_rx: u64,
    qualification_unavailable: bool,
    rx_device: usize,
    rx_queue: usize,
    tx_realm: usize,
    tx_class: usize,
    round_cut_short: bool,
    policy_recheck: bool,
    context_recheck: bool,
    context_revision: u64,
    _memory: Option<MemoryReservation>,
}

impl Runtime {
    fn relay_candidates(
        &self,
        direct: Option<DirectProfile>,
    ) -> impl Iterator<Item = (&PacketRealm, usize, &DeviceInfo)> {
        self.realms.iter().filter_map(move |realm| {
            let packet = self
                .endpoints
                .realm(realm.driver.scope())
                .expect("prepared physical realm");
            let info = self.devices[realm.device].info.as_ref();
            let members = realm.members.len();
            direct_relay_eligible(
                direct,
                self.workers.workers,
                packet.owners().len(),
                members,
                info.direct_relay_physical,
            )
            .then_some((packet, members, info))
        })
    }

    fn activate_capture(
        &self,
        shutdown: &crate::control::ShutdownIntent,
        direct: Option<DirectProfile>,
    ) -> anyhow::Result<()> {
        self.workers.activate(
            shutdown,
            &self.endpoints,
            direct,
            self.relay_candidates(direct)
                .map(|(packet, members, info)| (packet, members, info.supports_direct_relay_now())),
        )
    }

    fn admit_final_topology(&self) -> io::Result<CaptureTopology> {
        CaptureTopology::admit(
            self.capture_plan
                .as_ref()
                .ok_or_else(|| io::Error::other("capture plan already released"))?,
            &self.polling_budget,
        )
    }

    fn refresh_local_addresses(&mut self) -> anyhow::Result<()> {
        self.links.poll_changes()?;
        match self.links.state() {
            crate::netlink::fib::FibState::Desynchronized => {
                anyhow::bail!("XDP local address authority desynchronized")
            }
            crate::netlink::fib::FibState::Synchronizing => self.links.synchronize()?,
            crate::netlink::fib::FibState::Ready => {}
        }
        let Some(maps) = &self.gateway_maps else {
            return Ok(());
        };
        let mut addresses: Vec<_> = self
            .links
            .local_addresses()
            .map(LocalAddressKey::from)
            .collect();
        addresses.sort_unstable_by_key(|key| (key.family, key.address));
        addresses.dedup();
        if addresses != self.local_addresses {
            let bytes = honk_xsk::kernel_memory_bytes(maps.local_map_fd()?.as_fd())?;
            let memory = self
                .polling_budget
                .reserve(bytes)
                .context("gateway local map replacement capacity")?;
            maps.replace_local_addresses(&addresses)?;
            self.local_memory = Some(memory);
            self.local_addresses = addresses;
        }
        Ok(())
    }

    fn revalidate_gateway_zones(&mut self) -> io::Result<()> {
        let Some(zones) = &mut self.zones else {
            return Ok(());
        };
        let result = zones.revalidate(&self.polling_budget);
        // A notification can supply evidence before a hard inventory failure.
        if zones.notrack_seen()
            && let Some(publisher) = &self.gateway
        {
            publisher.latch_notrack();
        }
        result
    }

    fn maintain_gateway(&mut self, now: Instant) -> anyhow::Result<()> {
        if self.gateway_maps.is_none()
            || now.duration_since(self.core_maintenance_checked) < Duration::from_secs(1)
        {
            return Ok(());
        }
        self.revalidate_gateway_zones()?;
        self.refresh_local_addresses()?;
        let mut clock = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: clock_gettime initializes one timespec on success.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, clock.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: the successful syscall initialized clock.
        let clock = unsafe { clock.assume_init() };
        let now_ns = u64::try_from(clock.tv_sec)?
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(clock.tv_nsec as u64))
            .context("MONOTONIC clock overflow")?;
        if let Some(maps) = &self.gateway_maps {
            ensure!(
                maps.lookup_errors()? == 0,
                "conntrack lookup contract failure"
            );
        }
        if let Some(publisher) = &self.gateway {
            let scopes = &self.realm_scopes;
            let endpoints = &self.endpoints;
            publisher.maintain_holds(&mut self.hold_collector, now_ns, &mut |key| {
                let Some(&scope) = scopes.get(&key.realm_id) else {
                    return true;
                };
                let source = IpAddr::V6(key.src.into()).to_canonical();
                #[cfg(feature = "packet-ebpf")]
                if self
                    .gateway_maps
                    .as_ref()
                    .is_some_and(|m| m.host_realms().contains(&key.realm_id))
                {
                    return endpoints.retains_host_flow(
                        scope,
                        (source, u16::from_be(key.sport)).into(),
                        (
                            IpAddr::V6(key.dst.into()).to_canonical(),
                            u16::from_be(key.dport),
                        )
                            .into(),
                        key.proto,
                    );
                }
                endpoints.retains_source(scope, source)
            })?;
        }
        self.core_maintenance_checked = now;
        Ok(())
    }

    fn sample_queues(&self) {
        sample_queues(&self.devices, &self.diagnostics);
    }

    fn ports_ready_for_backend_teardown(&mut self) -> bool {
        let mut ready = true;
        for queue in self
            .devices
            .iter_mut()
            .flat_map(|device| &mut device.queues)
        {
            ready &= queue.io.get_mut().close().ready_for_backend_teardown();
        }
        ready
    }

    fn complete_physical_tx(&mut self, kick_until: Option<Instant>) -> io::Result<bool> {
        let queues = self
            .devices
            .iter_mut()
            .flat_map(|device| &mut device.queues);
        let mut outstanding = false;
        for queue in queues {
            let port = queue.io.get_mut();
            port.complete(release_completed)?;
            if kick_until.is_some_and(|deadline| Instant::now() < deadline) {
                port.kick_outstanding_tx()?;
            }
            outstanding |= port.counters().submitted != port.counters().completed;
        }
        Ok(outstanding)
    }

    async fn close_capture(
        &mut self,
        backend: &tokio::sync::RwLock<Box<dyn crate::ebpf::PolicyBackend>>,
    ) -> anyhow::Result<()> {
        if let Some(tasks) = self.workers.auxiliary.get() {
            tasks.stop();
        }
        let deadline = Instant::now() + DETACH_BUDGET;
        self.workers.begin_close();
        if let Some(publisher) = &self.gateway {
            publisher.stop_dns();
        }
        if self.topology_lost {
            for device in &mut self.devices {
                device.vlan_offload.abandon();
            }
        }
        *self.pname_support.write() = crate::ebpf::PnameSupport::Unavailable;
        self.closing = true;
        self.diagnostics.lifecycle(Lifecycle::Closing);
        self.policy_recheck = false;
        self.context_recheck = false;
        self.polling.leave("closing");
        let mut failure: Option<anyhow::Error> = None;
        if let Some(gateway) = &self.gateway
            && !self.topology_lost
        {
            let unregister = async {
                backend.write().await.install_gateway(None)?;
                loop {
                    match gateway.verify_attachments() {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        result => break result.map_err(Into::into),
                    }
                }
            };
            let result = tokio::time::timeout_at(deadline.into(), unregister)
                .await
                .context("gateway publisher busy at physical detach deadline")
                .and_then(|result| result);
            fold_capture_result(&mut failure, result);
        }
        if self.topology_lost {
            fold_capture_result(
                &mut failure,
                Err(anyhow::anyhow!("physical XDP topology lost before drain")),
            );
        }
        for device in &mut self.devices {
            if device.attachment.is_some() {
                let verified = device.core_link().and_then(|(link, id)| link.verify(id));
                fold_capture_result(&mut failure, verified.map_err(Into::into));
            }
            for id in &device.info.queues {
                fold_capture_result(
                    &mut failure,
                    device.queue_maps.delete_xsk(*id).map_err(Into::into),
                );
            }
            for queue in &mut device.queues {
                queue.io.get_mut().close();
            }
        }
        if failure.is_none() {
            self.workers.quiesce(deadline);
            let workers = Arc::clone(&self.workers);
            let has_worker = self.worker.is_some();
            let result = drain_before_detach(
                deadline,
                || self.complete_physical_tx(Some(deadline)),
                poll_fn(|cx| {
                    if has_worker {
                        workers.poll_quiesced(cx)
                    } else {
                        Poll::Ready(Ok(()))
                    }
                }),
            )
            .await;
            fold_capture_result(&mut failure, result);
        }
        if failure.is_some() {
            self.workers.close();
        }
        if let Some(gateway) = &self.gateway {
            fold_capture_result(&mut failure, gateway.detach_all().map_err(Into::into));
        }
        for device in self.devices.iter_mut().rev() {
            if let Some(link) = device.attachment.take() {
                fold_capture_result(&mut failure, link.detach().map_err(Into::into));
            }
            device.active = false;
        }
        self.endpoints.close();
        self.waiting.clear();
        self.pending.clear();
        for realm in &mut self.realms {
            realm.pending = [None, None];
        }
        failure.map_or(Ok(()), Err)
    }

    /// Every realm driver, including after close: their finish needs this owner too.
    fn service_scopes(&mut self, cx: &mut Context<'_>, now: Instant) -> bool {
        let mut more = false;
        for realm in &mut self.realms {
            more |= realm.driver.service(cx, now);
        }
        more
    }

    /// Drivers only, before capture is attached: a failed start's supervisor waits for their
    /// cleanup, while the old topology watch may legitimately see our own bind events.
    fn poll_scopes(
        &mut self,
        cx: &mut Context<'_>,
        timer: Pin<&mut Option<tokio::time::Sleep>>,
    ) -> Poll<()> {
        let now = Instant::now();
        let more = self.service_scopes(cx, now);
        let deadline = self.scope_deadline();
        poll_deadline(timer, if more { Some(now) } else { deadline }, now, cx)
    }

    fn scope_deadline(&self) -> Option<Instant> {
        self.realms
            .iter()
            .filter_map(|realm| realm.driver.deadline())
            .min()
    }

    /// `core` false while a publication-reader acquisition is already pending: its
    /// completion, not a due Core deadline, is what can make that work runnable.
    fn next_deadline(&self, now: Instant, core: bool) -> Option<Instant> {
        let mut deadline: Option<Instant> = None;
        let mut include = |due: Instant| {
            deadline = Some(deadline.map_or(due, |previous| previous.min(due)));
        };
        for device in &self.devices {
            for queue in &device.queues {
                let port = queue.io.get_ref();
                let retry = if self.closing {
                    port.counters().submitted != port.counters().completed
                } else {
                    port.needs_service_retry()
                };
                if retry {
                    include(now + Duration::from_millis(1));
                }
            }
            if !self.closing && device.capture.vlan_metadata {
                include(device.metadata_checked + Duration::from_secs(1));
            }
        }
        if !self.closing && !self.devices.is_empty() {
            include(self.link_check_at);
        }
        if !self.closing && self.gateway_maps.is_some() {
            include(self.core_maintenance_checked + Duration::from_secs(1));
        }
        for realm in &self.realms {
            if let Some(due) = realm.driver.deadline() {
                include(due);
            }
        }
        if self.closing {
            return deadline;
        }
        if core && let Some(due) = self.core_deadline(now) {
            include(due);
        }
        if let Some(due) = self.pressure.next_deadline(self.core.as_ref()) {
            include(due);
        }
        deadline
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Some(tasks) = self.workers.auxiliary.get() {
            tasks.stop();
        }
        self.admission.store(false, Ordering::Release);
        self.workers.close();
        *self.pname_support.write() = crate::ebpf::PnameSupport::Unavailable;
        self.diagnostics.lifecycle(Lifecycle::FailedRetained);
        if let Some(gateway) = &self.gateway {
            let _ = gateway.detach_all();
        }
        for device in &mut self.devices {
            device.vlan_offload.abandon();
            device.attachment.take();
        }
        self.endpoints.close();
        if std::thread::panicking() {
            std::mem::forget((
                std::mem::take(&mut self.devices),
                std::mem::take(&mut self.realms),
                std::mem::take(&mut self.waiting),
                std::mem::take(&mut self.pending),
                self.worker.take(),
                self._memory.take(),
                self.endpoints.clone(),
                Arc::clone(&self.workers),
            ));
        }
    }
}

impl Device {
    fn unpublished_programs(&self) -> io::Result<&Programs> {
        self.programs
            .as_ref()
            .map(|(programs, _)| programs)
            .ok_or_else(|| io::Error::other("XDP device transferred its program generation"))
    }

    fn publish_programs(
        &mut self,
        publisher: Option<&GatewayPublisher>,
        ipv4_broadcasts: &[std::net::Ipv4Addr],
    ) -> anyhow::Result<u32> {
        let programs = self.unpublished_programs()?;
        let id = programs.data_prog_id();
        self.attachment
            .as_ref()
            .context("XDP link already detached")?
            .replace(programs.discover_fd(), programs.data_fd())?;
        self.active = true;
        if let Some(publisher) = publisher {
            let queues = self
                .info
                .queues
                .last()
                .copied()
                .context("XDP queues vanished")?
                .checked_add(1)
                .context("XDP queue overflow")?;
            publisher.register(
                self.info.ifindex,
                self.attachment
                    .take()
                    .context("XDP link already detached")?,
                self.programs
                    .take()
                    .context("XDP program generation already transferred")?,
                GatewayReload {
                    capture: self.capture.clone(),
                    queues,
                    ipv4_broadcasts: ipv4_broadcasts.to_vec(),
                },
            )?;
        }
        Ok(id)
    }

    fn core_link(&self) -> io::Result<(&OwnedXdpLink, u32)> {
        let link = self
            .attachment
            .as_ref()
            .ok_or_else(|| io::Error::other("Core XDP link already detached"))?;
        let programs = self.unpublished_programs()?;
        let program = if self.active {
            programs.data_prog_id()
        } else {
            programs.discover_prog_id()
        };
        Ok((link, program))
    }
}

fn verify_link_fds(gateway: Option<&GatewayPublisher>, devices: &[Device]) -> io::Result<()> {
    if let Some(gateway) = gateway {
        return gateway.verify_link_fds();
    }
    for device in devices {
        let (link, program) = device.core_link()?;
        link.verify_fd(program)?;
    }
    Ok(())
}

fn current_topology(
    topology: &mut AsyncFd<CaptureTopology>,
    gateway: Option<&GatewayPublisher>,
    devices: &[Device],
    lost: &mut bool,
) -> io::Result<TopologyEvent> {
    let result = (|| {
        if let Some(gateway) = gateway {
            return gateway.validate_programs(|programs| {
                for &(ifindex, program) in programs {
                    topology.get_mut().expect_program(ifindex, program);
                }
                topology.get_mut().check()
            });
        }
        for device in devices {
            let (link, program) = device.core_link()?;
            link.verify(program)?;
            topology
                .get_mut()
                .expect_program(device.info.ifindex, program);
        }
        topology.get_mut().check()
    })();
    if result.is_err() {
        *lost = true;
    }
    result
}

async fn wait_capture_startup(
    workers: &worker::Shared,
    queues_only: bool,
    shutdown: &crate::control::ShutdownIntent,
    mut endpoint: impl FnMut(&mut Context<'_>) -> Poll<anyhow::Result<()>>,
    mut service: impl FnMut(&mut Context<'_>) -> Poll<()>,
) -> anyhow::Result<()> {
    let mut endpoint_ready = false;
    loop {
        tokio::select! {
            ready = poll_fn(|cx| {
                let queues = workers.poll_ready(cx, queues_only)?;
                if !endpoint_ready {
                    std::task::ready!(endpoint(cx))?;
                    endpoint_ready = true;
                }
                queues.map(Ok)
            }) => return ready,
            () = shutdown.wait() => anyhow::bail!("shutdown requested during XDP startup"),
            () = poll_fn(&mut service) => tokio::task::yield_now().await,
        }
    }
}

async fn drain_before_detach(
    deadline: Instant,
    mut outstanding: impl FnMut() -> io::Result<bool>,
    worker: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let local = async {
        while outstanding()? {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(())
    };
    // The deadline bounds retries, not an in-flight syscall. A timeout is never a CQ or an ACK.
    tokio::time::timeout_at(deadline.into(), async { tokio::try_join!(local, worker) })
        .await
        .context("physical XDP transmit/worker quiescence timed out before detach")??;
    Ok(())
}

async fn drain_transmit(
    mut complete: impl FnMut() -> io::Result<bool>,
    started: Instant,
    warned: &mut bool,
) -> io::Result<()> {
    while complete()? {
        if started.elapsed() > Duration::from_secs(10) && !*warned {
            tracing::warn!(
                "XDP terminal completion is delayed; retaining owners and UMEM until actual return"
            );
            *warned = true;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}

pub(crate) async fn join_endpoints(
    owner: &mut PacketEndpointOwner,
    mut poll_io: impl FnMut(&mut Context<'_>) -> Poll<anyhow::Result<()>>,
    started: Instant,
    warned: &mut bool,
) -> anyhow::Result<anyhow::Result<(ControlPlane, anyhow::Result<()>)>> {
    loop {
        tokio::select! {
            result = poll_fn(|cx| owner.poll_join_plane(cx)) => return Ok(result),
            result = poll_fn(&mut poll_io) => if let Err(error) = result {
                owner.fail_control().await?;
                return Err(error);
            },
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(started + Duration::from_secs(10))), if !*warned => {}
        }
        if started.elapsed() >= Duration::from_secs(10) && !*warned {
            tracing::warn!(
                "XDP terminal completion is delayed; retaining owners and UMEM until actual return"
            );
            *warned = true;
        }
        tokio::task::yield_now().await;
    }
}

/// What woke one wait of the started device owner.
enum Turn<R, J> {
    Joined(J),
    Read(R),
    Serviced(anyhow::Result<()>),
    Shutdown,
}

/// One device-owner wait. A pending policy-reader acquisition is polled beside device/scope
/// service, the supervisor join and shutdown, never ahead of them. It stays pinned in
/// `reader` across turns, keeping its place in the publication lock queue.
async fn turn<R, J>(
    mut reader: Pin<&mut Option<impl Future<Output = R>>>,
    mut join: impl FnMut(&mut Context<'_>) -> Poll<J>,
    mut service: impl FnMut(&mut Context<'_>, bool) -> Poll<anyhow::Result<()>>,
    shutdown: &crate::control::ShutdownIntent,
) -> Turn<R, J> {
    let reading = reader.is_some();
    tokio::select! {
        joined = poll_fn(&mut join) => Turn::Joined(joined),
        read = async { reader.as_mut().as_pin_mut().expect("pending policy reader").await }, if reading => {
            reader.set(None);
            Turn::Read(read)
        }
        result = poll_fn(|cx| service(cx, reading)) => Turn::Serviced(result),
        _ = shutdown.wait() => Turn::Shutdown,
    }
}

/// The production non-closing owner iteration, also used by the owned-kernel fixture.
/// Policy guards end synchronously; only then may this owner yield its executor.
async fn owner_step<'policy, R>(
    runtime: &mut Runtime,
    owner: &mut PacketEndpointOwner,
    mut reader: Pin<&mut Option<R>>,
    mut acquire: impl FnMut() -> Option<R>,
    shutdown: &crate::control::ShutdownIntent,
    mut timer: Pin<&mut Option<tokio::time::Sleep>>,
    mut notification: Pin<&mut tokio::sync::futures::OwnedNotified>,
) -> anyhow::Result<Option<anyhow::Result<(ControlPlane, anyhow::Result<()>)>>>
where
    R: Future<Output = PolicyRead<'policy>>,
{
    let mut failure = None;
    if runtime.pressure.sample(
        Instant::now(),
        runtime.core.as_ref(),
        runtime.waiting.len(),
        runtime.pending.len(),
        runtime.workers.peer_count(),
    ) {
        runtime.sample_queues();
    }
    if reader.is_none() && runtime.core.is_some() && runtime.core_due(Instant::now()) {
        reader.set(acquire());
    }
    match turn(
        reader.as_mut(),
        |cx| owner.poll_join_plane(cx),
        |cx, reading| {
            runtime.poll_service(cx, shutdown, timer.as_mut(), reading, notification.as_mut())
        },
        shutdown,
    )
    .await
    {
        Turn::Joined(result) => return Ok(Some(result)),
        Turn::Read(read) => {
            let had_clock = runtime.polling.last_clock.is_some();
            runtime.polling.boundary(0, 0);
            if runtime.polling.clock_requires_policy_recheck(had_clock) {
                runtime.policy_recheck = true;
            } else if let Err(error) = runtime.resolve(&read) {
                failure.get_or_insert(error);
            }
            drop(read);
            runtime.observe_polling_round();
        }
        Turn::Serviced(Err(error)) => {
            tracing::error!(%error, "XDP owner failed closed");
            failure = Some(error);
        }
        Turn::Serviced(Ok(())) | Turn::Shutdown => {}
    }
    if runtime.policy_recheck {
        reader.set(None);
        runtime.policy_recheck = false;
    }
    if let Some(error) = failure {
        return Err(error);
    }
    tokio::task::yield_now().await;
    Ok(None)
}

fn poll_deadline(
    mut timer: Pin<&mut Option<tokio::time::Sleep>>,
    deadline: Option<Instant>,
    now: Instant,
    cx: &mut Context<'_>,
) -> Poll<()> {
    let Some(deadline) = deadline else {
        timer.set(None);
        return Poll::Pending;
    };
    if deadline <= now {
        timer.set(None);
        return Poll::Ready(());
    }
    let deadline = tokio::time::Instant::from_std(deadline);
    if let Some(mut sleep) = timer.as_mut().as_pin_mut() {
        sleep.as_mut().reset(deadline);
    } else {
        timer.set(Some(tokio::time::sleep_until(deadline)));
    }
    timer.as_pin_mut().unwrap().poll(cx)
}

pub(crate) async fn run(
    plane: ControlPlane,
    admission: Arc<AtomicBool>,
    pname_support: crate::ebpf::PnameSupportCell,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    worker::run_coordinator(plane, admission, pname_support).await
}

async fn run_capture(
    plane: ControlPlane,
    admission: Arc<AtomicBool>,
    pname_support: crate::ebpf::PnameSupportCell,
    shared_runtime: tokio::runtime::Handle,
    capture: &mut Option<(Arc<worker::Shared>, PacketEndpoints)>,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    *pname_support.write() = crate::ebpf::PnameSupport::Unavailable;
    let config = plane.config_handle().read().await.as_ref().clone();
    let shutdown = plane.shutdown_intent();
    let backend = plane.policy_backend_handle();
    let active_routing_plan = plane.active_routing_plan_handle();
    let diagnostics_generation = plane.diagnostics_handle();
    let (polling_publication, process_polling) = plane
        .polling_runtime()
        .expect("validated XDP polling consumer");
    let notification = polling_publication.notification();
    tokio::pin!(notification);
    let prepared = match prepare(&plane, &config, Arc::clone(&admission)).await {
        Ok(prepared) => prepared,
        Err(error) => return (Some(plane), Err(error)),
    };
    let PreparedRuntime {
        devices,
        topology,
        capture_plan,
        plan_memory,
        gateway,
        gateway_maps,
        zones,
        local_addresses,
        local_memory,
        kernel_memory,
        realm_scopes,
        auxiliary,
        dns_bind,
        standalone_dns_scope,
        source_support,
        realms,
        scope_pairs,
        workers,
        inboxes,
        core,
        memory,
        staging,
        links,
        polling_prefix,
        polling_budget,
        diagnostics,
        ..
    } = prepared;
    let mut devices = StartupDevices(devices);
    plane.stats_handle().install_xdp(Arc::clone(&diagnostics));
    let (endpoints, mut owner, mut drivers) = match shared_runtime
        .spawn(PacketEndpoints::start_driven(
            plane,
            scope_pairs,
            64,
            dns_bind,
            standalone_dns_scope,
        ))
        .await
    {
        Ok(Ok(started)) => started,
        result => {
            let error = match result {
                Ok(Err(error)) => error,
                Err(error) => error.into(),
                Ok(Ok(_)) => unreachable!(),
            };
            diagnostics.lifecycle(Lifecycle::FailedRetained);
            return (None, Err(error));
        }
    };
    // The outer coordinator retains every relay registration and the endpoint close authority
    // even if the rest of capture unwinds or must retain its actual NIC owners.
    *capture = Some((Arc::clone(&workers), endpoints.clone()));
    let mut local_realms = Vec::with_capacity(realms.len());
    let mut remote_realms = Vec::with_capacity(realms.len());
    for (ingress, device, link, scope) in realms {
        for worker_index in 0..usize::from(workers.workers) {
            let Some(index) = drivers
                .iter()
                .position(|driver| driver.scope() == scope && driver.worker() == worker_index)
            else {
                continue;
            };
            let members: Vec<usize> = workers
                .placements()
                .iter()
                .filter(|placement| placement.realm.scope() == scope)
                .map(|placement| placement.device)
                .collect();
            let generated = (members.len() == 1)
                .then(|| generated_layout(link))
                .flatten();
            let realm = Realm {
                realm_id: *realm_scopes
                    .iter()
                    .find(|(_, value)| **value == scope)
                    .expect("prepared capture scope retains its realm")
                    .0,
                members,
                ingress,
                device,
                link,
                generated,
                driver: drivers.swap_remove(index),
                pending: [None, None],
            };
            if worker_index == 0 {
                local_realms.push(realm);
            } else {
                remote_realms.push(realm);
            }
        }
    }
    let realms = local_realms;
    let [inbox, remote_inbox] = inboxes;
    let mut runtime = Runtime {
        devices: std::mem::take(&mut devices.0),
        topology,
        topology_lost: false,
        capture_plan: Some(capture_plan),
        capture_plan_memory: Some(plan_memory),
        gateway,
        gateway_maps,
        zones,
        links,
        local_addresses,
        local_memory,
        _kernel_memory: kernel_memory,
        realm_scopes,
        hold_collector: HoldCollector,
        admission,
        pname_support,
        realms,
        workers: Arc::clone(&workers),
        worker: None,
        inbox,
        endpoints,
        core,
        waiting: VecDeque::with_capacity(PENDING),
        pending: VecDeque::with_capacity(PENDING),
        staging,
        closing: false,
        finished: false,
        pressure: Pressure::new(Instant::now()),
        diagnostics,
        core_maintenance_checked: Instant::now(),
        link_check_at: Instant::now() + LINK_CHECK_INTERVAL,
        polling: AdaptivePoll::new(polling_publication, process_polling),
        polling_prefix,
        polling_budget,
        polling_affinity: None,
        qualified_rx: 0,
        qualification_unavailable: false,
        rx_device: 0,
        rx_queue: 0,
        tx_realm: 0,
        tx_class: 0,
        round_cut_short: false,
        policy_recheck: false,
        context_recheck: false,
        context_revision: 0,
        _memory: Some(memory),
    };
    let direct = config
        .datapath
        .as_ref()
        .and_then(|datapath| datapath.direct);
    let relay_candidate = runtime.relay_candidates(direct).next().is_some();
    let aux_startup = runtime.start_auxiliary(auxiliary, &mut drivers, &shared_runtime);
    assert!(
        drivers.is_empty(),
        "every prepared scope has its exact service owner"
    );
    let mut relay_setup =
        (relay_candidate && workers.workers == 2).then(|| workers.defer_secondary_ready());
    if workers.workers == 2 {
        match worker::Worker::start(
            Arc::clone(&workers),
            &mut runtime.devices,
            remote_realms,
            runtime.endpoints.clone(),
            remote_inbox,
            runtime.core.is_some(),
            runtime.polling.participant(),
            Arc::clone(&runtime.polling_budget),
            Arc::clone(&shutdown),
        ) {
            Ok(worker) => runtime.worker = Some(worker),
            Err(error) => workers.failed(1, error.into()),
        }
    }
    workers.ready(0);
    let timer = None;
    tokio::pin!(timer);
    // The drivers already exist: a failed start's supervisor cleanup waits on their service.
    let startup_failure = wait_capture_startup(
        &workers,
        relay_setup.is_some(),
        &shutdown,
        |cx| owner.poll_ready(cx),
        |cx| runtime.poll_scopes(cx, timer.as_mut()),
    )
    .await
    .err();
    let activate = if startup_failure.is_some() {
        drop(aux_startup);
        Ok(())
    } else {
        async {
            runtime.revalidate_gateway_zones()?;
            let topology = runtime.admit_final_topology()?;
            ensure!(
                topology.ipv4_broadcasts() == runtime.topology.get_ref().ipv4_broadcasts(),
                "XDP broadcast classification changed before publication"
            );
            // SAFETY: the watcher owns a stable descriptor until AsyncFd drops it.
            runtime.topology = unsafe { AsyncFd::register(topology) }.map_err(io::Error::from)?;
            for device in &mut runtime.devices {
                let id = device.publish_programs(
                    runtime.gateway.as_deref(),
                    runtime.topology.get_ref().ipv4_broadcasts(),
                )?;
                runtime
                    .topology
                    .get_mut()
                    .expect_program(device.info.ifindex, id);
            }
            if let Some(publisher) = &runtime.gateway {
                let mut backend = backend.write().await;
                let plan = active_routing_plan.read().plan.clone();
                publisher.prepare_start(&plan)?;
                backend.install_gateway(Some(Arc::clone(publisher)))?;
                publisher.commit();
            }
            current_topology(
                &mut runtime.topology,
                runtime.gateway.as_deref(),
                &runtime.devices,
                &mut runtime.topology_lost,
            )?;
            runtime.rebuild_polling_context();
            *runtime.pname_support.write() = source_support;
            if relay_candidate {
                workers.prepare_relays(&runtime.polling_budget)?;
            }
            if let Some(setup) = relay_setup.take() {
                setup.send(()).map_err(|_| {
                    anyhow::anyhow!("XDP secondary stopped before relay registration")
                })?;
                poll_fn(|cx| workers.all_ready(cx)).await?;
            }
            // Mandatory startup reservations must fit before either output window grows.
            if workers.workers == 2 && !runtime.endpoints.is_closing() {
                for realm in &runtime.realms {
                    let (_, base_bulk_frames) =
                        device_sizing(runtime.devices[realm.device].info.mtu);
                    runtime
                        .endpoints
                        .realm(realm.driver.scope())
                        .expect("prepared driver retains its packet realm")
                        .widen_startup_output(base_bulk_frames);
                }
            }
            if let Some(publisher) = &runtime.gateway {
                let mut backend = backend.write().await;
                runtime.activate_capture(&shutdown, direct)?;
                backend.activate_gateway_start(
                    publisher,
                    active_routing_plan.read().plan.fingerprint,
                    diagnostics_generation.read().generation,
                )?;
            } else {
                runtime.activate_capture(&shutdown, direct)?;
            }
            runtime.activate_auxiliary(aux_startup, &shutdown).await
        }
        .await
    };
    drop(relay_setup);
    let mut failure = startup_failure.or_else(|| activate.err());
    runtime.capture_plan.take();
    runtime.capture_plan_memory.take();
    if failure.is_none() {
        runtime.diagnostics.lifecycle(Lifecycle::Active);
        tracing::info!(interfaces = runtime.devices.len(), "XDP datapath ready");
        runtime.sample_queues();
        if let Err(error) =
            libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Ready])
        {
            tracing::warn!(%error, "sd_notify readiness failed");
        }
    }
    let mut warned = false;
    // One clone of the existing registration; each acquisition yields real guards only.
    let authority = runtime.core.as_ref().map(RoutedCore::authority);
    let reader = None;
    tokio::pin!(reader);
    let joined = loop {
        if owner.is_joined() {
            // Failed endpoint readiness already collected the supervisor and its startup error.
            break Some(None);
        }
        if failure.is_some() || shutdown.requested() {
            break None;
        }
        match owner_step(
            &mut runtime,
            &mut owner,
            reader.as_mut(),
            || authority.as_ref().map(|authority| authority.read_policy()),
            &shutdown,
            timer.as_mut(),
            notification.as_mut(),
        )
        .await
        {
            Ok(Some(result)) => break Some(joined_plane(result, &mut failure)),
            Ok(None) => {}
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    };
    // Release any queued Core reader before revoking the gateway publisher.
    reader.set(None);
    let close_started = Instant::now();
    if let Err(error) = runtime.close_capture(&backend).await {
        tracing::error!(%error, "XDP capture close failed; retaining runtime and supervisor until process exit");
        fold_capture_result(&mut failure, Err(error));
        fold_capture_result(&mut failure, owner.fail_control().await);
        runtime.diagnostics.lifecycle(Lifecycle::FailedRetained);
        std::mem::forget((runtime, owner, joined));
        return (None, Err(failure.unwrap()));
    }
    let plane = match joined {
        Some(plane) => plane,
        None => match join_endpoints(
            &mut owner,
            |cx| runtime.poll_service(cx, &shutdown, timer.as_mut(), false, notification.as_mut()),
            close_started,
            &mut warned,
        )
        .await
        {
            Ok(joined) => joined_plane(joined, &mut failure),
            Err(error) => {
                tracing::error!(%error, "XDP terminal I/O failed; retaining runtime and supervisor until process exit");
                fold_capture_result(&mut failure, Err(error));
                runtime.diagnostics.lifecycle(Lifecycle::FailedRetained);
                std::mem::forget((runtime, owner));
                return (None, Err(failure.unwrap()));
            }
        },
    };
    if let Some(tasks) = workers.auxiliary.get() {
        fold_capture_result(&mut failure, tasks.join().await);
    }
    // An endpoint join cannot release Core TX leases; drain those same descriptor owners too.
    if let Err(error) = drain_transmit(
        || runtime.complete_physical_tx(None),
        close_started,
        &mut warned,
    )
    .await
    {
        tracing::error!(%error, "XDP terminal drain failed; retaining owners and UMEM until process exit");
        fold_capture_result(&mut failure, Err(error.into()));
        runtime.diagnostics.lifecycle(Lifecycle::FailedRetained);
        fold_capture_result(&mut failure, owner.fail_control().await);
        std::mem::forget((runtime, plane));
        return (None, Err(failure.unwrap()));
    }
    if let Some(worker) = &mut runtime.worker
        && let Err(error) = worker.join().await
    {
        fold_capture_result(&mut failure, Err(error));
        runtime.diagnostics.lifecycle(Lifecycle::FailedRetained);
        std::mem::forget((runtime, plane));
        return (None, Err(failure.unwrap()));
    }
    runtime.sample_queues();
    let ports_ready = runtime.ports_ready_for_backend_teardown();
    if !ports_ready {
        fold_capture_result(
            &mut failure,
            Err(anyhow::anyhow!(
                "XDP ledger did not reach terminal ownership"
            )),
        );
        runtime.diagnostics.lifecycle(Lifecycle::FailedRetained);
        std::mem::forget((runtime, plane));
        return (None, Err(failure.unwrap()));
    }
    for device in &mut runtime.devices {
        for queue in device.queues.drain(..) {
            let mut port = queue.io.into_inner();
            debug_assert!(port.close().ready_for_backend_teardown());
            port.close_socket();
        }
        if let Err(error) = device.vlan_offload.restore() {
            failure.get_or_insert(error.into());
        }
    }
    runtime.diagnostics.lifecycle(Lifecycle::Closed);
    if let Err(error) = backend.write().await.cleanup().await {
        failure.get_or_insert(error);
    }
    tracing::info!("XDP admission closed; UMEM retained until process exit");
    runtime.finished = true;
    (plane, failure.map_or(Ok(()), Err))
}

/// A realm before validated endpoint start hands it the driver of this exact scope.
type RealmPlan = (Ingress, usize, LogicalLink, ScopeId);

struct PreparedRuntime {
    devices: Vec<Device>,
    topology: AsyncFd<CaptureTopology>,
    capture_plan: CapturePlan,
    plan_memory: MemoryReservation,
    gateway: Option<Arc<GatewayPublisher>>,
    gateway_maps: Option<Arc<honk_xsk::GatewayMaps>>,
    zones: Option<ZoneAdmission>,
    local_addresses: Vec<LocalAddressKey>,
    local_memory: Option<MemoryReservation>,
    kernel_memory: Vec<MemoryReservation>,
    realm_scopes: std::collections::HashMap<u32, ScopeId>,
    auxiliary: Vec<tcx_aux::PreparedAux>,
    dns_bind: Option<crate::control::dns_listener::PreparedDnsBind>,
    standalone_dns_scope: ScopeId,
    source_support: crate::ebpf::PnameSupport,
    realms: Vec<RealmPlan>,
    workers: Arc<worker::Shared>,
    inboxes: [tokio::sync::mpsc::Receiver<worker::Envelope>; 2],
    scope_pairs: Vec<(PacketRealm, Vec<crate::control::netstack::PacketOwner>)>,
    core: Option<RoutedCore>,
    memory: MemoryReservation,
    staging: Vec<u8>,
    links: Fib,
    polling_prefix: Result<ContextDigest, &'static str>,
    polling_budget: Arc<MemoryBudget>,
    diagnostics: Arc<Diagnostics>,
}
