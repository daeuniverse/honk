//! One Linux capture owner for every selected RX queue and one routing domain.
//! Retained attachments and program pins guard selected traffic after shutdown; UMEM stays until exit.

#[cfg(feature = "ebpf")]
pub(crate) mod host;
#[cfg(feature = "ebpf")]
mod host_runtime;
pub(crate) mod polling;
pub(crate) mod worker;
use crate::control::poll_budget::BusyInterval;
#[cfg(feature = "ebpf")]
use host_runtime::{HostRuntime, PreparedHost};
use polling::runtime::polling_segment_stop;
use polling::{AdaptivePoll, ContextDigest};

#[cfg(all(target_os = "linux", any(test, feature = "ebpf")))]
use crate::control::netstack::capture_scope;
use crate::control::{
    ControlPlane,
    core_forward::{
        CachedDecision, Decision, Execution, GeneratedError, IngressBinding, PolicyGeneration,
        PolicyRead, Requirements, RoutedCore, socket_namespace,
    },
    netstack::{
        CAPTURE_MEMORY, OutputLease, OutputOwner, PacketDriver, PacketRealm, PacketScope,
        capture_realm,
    },
    packet_endpoint::{EndpointAdmission, PacketEndpointOwner, PacketEndpoints, PacketReceive},
};
use crate::netlink::fib::{Fib, LogicalLink};
use crate::stats::xdp::{Diagnostics, Lifecycle, QueueObservation};
use anyhow::{Context as _, ensure};
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
use honk_netstack::{
    MemoryBudget, MemoryReservation,
    wire::{self, PacketView},
};
use honk_xsk::{
    BindMode, DecodedPacket, FRAME_SIZE, GeneralCapture, PersistentAttachment, Port, PortConfig,
    PortCounters, Programs, RingSnapshot,
    device::{DeviceInfo, FeatureQuery},
    topology::Topology,
};
use std::{
    collections::VecDeque,
    future::poll_fn,
    io,
    net::IpAddr,
    os::fd::{AsFd, AsRawFd},
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};
use tokio::io::unix::AsyncFd;

const PENDING: usize = 64;
const PEERS: usize = 4096;
const PEER_CONFLICT_HOLD: Duration = Duration::from_secs(60);
const BATCH: usize = 32;

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

pub(crate) fn validate_config(config: &Config) -> anyhow::Result<()> {
    let Some(datapath) = config
        .datapath
        .as_ref()
        .filter(|value| value.backend == Backend::Xdp)
    else {
        return Ok(());
    };
    datapath.validate()?;
    ensure!(
        datapath.host.is_none() || cfg!(feature = "ebpf"),
        "XDP Host capture requires the built ebpf feature and actual Host runtime admission"
    );
    ensure!(
        !config.global.nfqueue_enable,
        "XDP requires global.nfqueue_enable: false; NFQUEUE is not an XDP fallback"
    );
    ensure!(
        config.global.lan_interface.is_empty() && config.global.wan_interface.is_empty(),
        "XDP interfaces and trusted LAN/WAN roles belong only in datapath.interface"
    );
    ensure!(
        config.routing.default_mark.unwrap_or(0) == 0
            && config
                .routing
                .rules
                .iter()
                .all(|rule| rule.mark.unwrap_or(0) == 0),
        "XDP cannot execute traffic mark effects"
    );
    for rule in &config.routing.rules {
        let condition = &rule.condition;
        ensure!(
            condition.mac.is_empty()
                && condition.not.mac.is_empty()
                && (datapath.host.is_some()
                    || (condition.process_name.is_empty()
                        && condition.not.process_name.is_empty())),
            "XDP routing requires Host capture for process predicates and has no per-flow MAC authority"
        );
    }
    let security_conditions = datapath
        .firewall
        .iter()
        .flat_map(|firewall| {
            firewall
                .original
                .rules
                .iter()
                .chain(&firewall.forward.rules)
                .map(|rule| &rule.condition)
        })
        .chain(datapath.nat.prerouting.iter().map(|rule| &rule.condition))
        .chain(datapath.nat.postrouting.iter().map(|rule| &rule.condition));
    for condition in security_conditions {
        ensure!(
            condition.mac.is_empty()
                && condition.not.mac.is_empty()
                && condition.process_name.is_empty()
                && condition.not.process_name.is_empty(),
            "XDP firewall/NAT cannot bind process or original-datagram MAC facts across reassembly"
        );
    }
    if datapath.direct == Some(DirectProfile::Core) {
        ensure!(
            config.global.dial_mode == "ip",
            "Core Direct requires dial_mode: ip; TCP termination is not a Core forwarding fallback"
        );
    }
    Ok(())
}

enum Retained {
    Endpoint(OutputOwner),
    Forward {
        _owner: ForwardLease,
        _peer: Option<worker::PeerHold>,
    },
    Error {
        _binding: Option<honk_datapath::firewall::BindingLease>,
        _peer: Option<worker::PeerHold>,
    },
    Generated {
        _owner: GeneratedError,
    },
}

fn release_completed(completed: &mut [Option<&mut Retained>]) {
    let mut outputs: [Option<&mut OutputOwner>; 64] = std::array::from_fn(|_| None);
    let mut count = 0;
    for owner in completed.iter_mut().filter_map(Option::take) {
        if let Retained::Endpoint(output) = owner {
            outputs[count] = Some(output);
            count += 1;
        }
    }
    OutputOwner::release_batch(&mut outputs[..count]);
}
enum QueueIo {
    Prepared(Port<Retained>),
    Registered(AsyncFd<Port<Retained>>),
}

impl QueueIo {
    fn register(self) -> io::Result<Self> {
        match self {
            Self::Prepared(port) => {
                // The socket is closed only after this registration is consumed.
                unsafe { AsyncFd::register(port) }
                    .map(Self::Registered)
                    .map_err(io::Error::from)
            }
            registered => Ok(registered),
        }
    }
    fn get_ref(&self) -> &Port<Retained> {
        match self {
            Self::Prepared(port) => port,
            Self::Registered(io) => io.get_ref(),
        }
    }
    fn get_mut(&mut self) -> &mut Port<Retained> {
        match self {
            Self::Prepared(port) => port,
            Self::Registered(io) => io.get_mut(),
        }
    }
    fn into_inner(self) -> Port<Retained> {
        match self {
            Self::Prepared(port) => port,
            Self::Registered(io) => io.into_inner(),
        }
    }
}

impl std::ops::Deref for QueueIo {
    type Target = AsyncFd<Port<Retained>>;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Registered(io) => io,
            Self::Prepared(_) => panic!("Port not registered on owner runtime"),
        }
    }
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
    programs: Arc<Programs>,
    attachment: Arc<PersistentAttachment>,
    queues: Vec<Queue>,
    active: bool,
    metadata_checked: Instant,
    features: Option<FeatureQuery>,
    port_config: PortConfig,
    role: honk_config::datapath::InterfaceRole,
}

struct Waiting {
    packet: Packet,
    mac: [u8; 6],
    retry: Instant,
    scope: ScopeId,
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
    device: usize,
    mac: [u8; 6],
    vlan_tci: [u16; 2],
    vlan_proto: [u16; 2],
    vlan_count: u8,
}

impl ReturnPath {
    fn same_identity(self, other: Self) -> bool {
        self.device == other.device
            && self.mac == other.mac
            && self.vlan_proto == other.vlan_proto
            && self.vlan_count == other.vlan_count
            && self
                .vlan_tci
                .iter()
                .zip(other.vlan_tci)
                .all(|(old, new)| old & 0x0fff == new & 0x0fff)
    }
}

struct Peer {
    scope: ScopeId,
    address: IpAddr,
    path: ReturnPath,
    #[cfg(test)]
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

fn diagnostics(
    devices: &[Device],
    budget: &Arc<MemoryBudget>,
    host: Option<QueueObservation>,
) -> io::Result<Arc<Diagnostics>> {
    Diagnostics::new(
        budget,
        devices
            .iter()
            .map(|device| device.queues.len())
            .sum::<usize>()
            + usize::from(host.is_some()),
        devices
            .iter()
            .flat_map(|device| {
                device.queues.iter().map(|queue| QueueObservation {
                    namespace: device.capture.authority.namespace_cookie,
                    attachment: device.capture.authority.attachment_generation,
                    ifindex: device.info.ifindex,
                    queue: queue.id,
                    zero_copy: queue.io.get_ref().zerocopy(),
                    ring_capacity: device.port_config.ring_size,
                    rx_frames: device.port_config.rx_frames,
                    control_frames: device.port_config.control_frames,
                    bulk_frames: device.port_config.bulk_frames,
                    sequence: 0,
                    attempted_at: None,
                    succeeded_at: None,
                    socket: None,
                    errno: None,
                    read_errors: 0,
                    rings: None,
                })
            })
            .chain(host),
    )
}

fn sample_queues(devices: &[Device], diagnostics: &Diagnostics) {
    let at = SystemTime::now();
    let mut index = 0;
    for device in devices {
        for queue in &device.queues {
            let port = queue.io.get_ref();
            let socket = port.stats();
            let rings = port.rings();
            tracing::debug!(interface = %device.info.name, queue = queue.id,
                socket = ?socket, rings = ?rings, counters = ?port.counters(),
                "XDP queue pressure");
            let queue_index = device
                .info
                .queues
                .iter()
                .position(|id| *id == queue.id)
                .expect("original queue identity");
            diagnostics.sample(index + queue_index, at, socket, rings);
        }
        index += device.info.queues.len();
    }
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
struct Realm {
    ingress: Ingress,
    device: usize,
    link: LogicalLink,
    driver: PacketDriver,
    generated: Option<(usize, usize)>,
    pending: [Option<(OutputLease, ReturnPath)>; 2],
}

fn generated_layout(link: LogicalLink) -> Option<(usize, usize)> {
    let l2_len = 14usize.checked_add(4usize.checked_mul(usize::from(link.path.vlan_count))?)?;
    let max_length = l2_len.checked_add(usize::try_from(link.mtu.max(1280)).ok()?)?;
    (max_length <= FRAME_SIZE).then_some((l2_len, max_length))
}

impl Realm {
    fn poll_outputs(
        &mut self,
        cx: &mut Context<'_>,
        class: TxClass,
        capacity: usize,
        outputs: &mut [Option<OutputLease>],
    ) -> (Poll<Option<usize>>, Option<ReturnPath>) {
        assert!(!outputs.is_empty() && outputs.len() <= BATCH);
        assert!(
            outputs.iter().all(Option::is_none),
            "empty output destination"
        );
        let class_index = match class {
            TxClass::Control => 0,
            TxClass::Bulk => 1,
        };
        if let Some((output, path)) = self.pending[class_index].take() {
            outputs[0] = Some(output);
            return (Poll::Ready(Some(1)), Some(path));
        }
        let count = outputs.len().min(capacity.max(1));
        (
            self.driver
                .poll_outputs_class(cx, class, &mut outputs[..count]),
            None,
        )
    }

    fn output_header(
        &self,
        path: ReturnPath,
        physical_ifindex: u32,
        ipv6: bool,
    ) -> io::Result<honk_datapath::forward::EthernetHeader> {
        if path.device != self.device
            || physical_ifindex != self.link.path.physical_ifindex
            || path.vlan_count != self.link.path.vlan_count
            || path.vlan_proto != self.link.path.vlan_proto
            || !path
                .vlan_tci
                .iter()
                .zip(self.link.path.vlan_tci)
                .all(|(peer, configured)| peer & 0x0fff == configured & 0x0fff)
        {
            return Err(io::Error::other(
                "Endpoint reply changed its admitted L2 identity",
            ));
        }
        return_header(path, self.link.mac, physical_ifindex, ipv6)
    }

    fn generate_output(
        &mut self,
        now: Instant,
        class: TxClass,
        physical_ifindex: u32,
        peers: &[Peer],
        frame: &mut [u8],
        emitted: &mut bool,
    ) -> io::Result<Option<(usize, Retained)>> {
        let Some((l2_len, max_length)) = self.generated else {
            return Ok(None);
        };
        let class_index = match class {
            TxClass::Control => 0,
            TxClass::Bulk => 1,
        };
        if self.pending[class_index].is_some() {
            return Ok(None);
        }
        if frame.len() != max_length {
            return Err(io::Error::other("invalid generated Endpoint reservation"));
        }
        let (l2, l3) = frame.split_at_mut(l2_len);
        let Some(owner) = self.driver.materialize_into(now, class, l3)? else {
            return Ok(None);
        };
        *emitted = true;
        let packet = &l3[..owner.len()];
        let (_, destination) = wire::packet_addresses(packet).map_err(io::Error::other)?;
        let Some(path) = owner
            .peer_hold()
            .and_then(|hold| hold.path())
            .or_else(|| peer_return_path(peers, owner.scope(), destination))
        else {
            return Ok(None);
        };
        let header = self.output_header(path, physical_ifindex, packet[0] >> 4 == 6)?;
        if header.len() != l2_len {
            return Err(io::Error::other("generated Endpoint header length changed"));
        }
        l2.copy_from_slice(&header);
        Ok(Some((l2_len + owner.len(), Retained::Endpoint(owner))))
    }
}

fn finish_transmit<T>(work: anyhow::Result<T>, kick: io::Result<()>) -> anyhow::Result<T> {
    match (work, kick) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(work), Err(kick)) => Err(work.context(kick).context("TX wakeup also failed")),
    }
}

fn fold_capture_result(failure: &mut Option<anyhow::Error>, result: anyhow::Result<()>) {
    if let Err(error) = result {
        *failure = Some(match failure.take() {
            Some(previous) => previous.context(format!("capture close also failed: {error:#}")),
            None => error,
        });
    }
}

struct Runtime {
    devices: Vec<Device>,
    topology: AsyncFd<Topology>,
    #[cfg(feature = "ebpf")]
    host: Option<HostRuntime>,
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
    fn admit_final_topology(
        &self,
        physical: &[u32],
        logical: &[u32],
        mark: u32,
    ) -> io::Result<Topology> {
        Topology::admit_after_xdp_attach(physical, logical, mark)
    }

    fn sample_queues(&self) {
        sample_queues(&self.devices, &self.diagnostics);
        #[cfg(feature = "ebpf")]
        if let Some(host) = &self.host {
            let port = host.queue.io.get_ref();
            let index = self
                .devices
                .iter()
                .map(|device| device.info.queues.len())
                .sum();
            self.diagnostics
                .sample(index, SystemTime::now(), port.stats(), port.rings());
        }
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

    fn complete_transmit(&mut self) -> io::Result<bool> {
        let queues = self
            .devices
            .iter_mut()
            .flat_map(|device| &mut device.queues);
        #[cfg(feature = "ebpf")]
        let queues = queues.chain(self.host.iter_mut().map(|host| &mut host.queue));
        let mut outstanding = false;
        for queue in queues {
            let port = queue.io.get_mut();
            port.complete(release_completed)?;
            port.kick()?;
            outstanding |= port.counters().submitted != port.counters().completed;
        }
        Ok(outstanding)
    }

    fn close_capture(&mut self) -> anyhow::Result<()> {
        self.admission.store(false, Ordering::Release);
        self.workers.close();
        *self.pname_support.write() = crate::ebpf::PnameSupport::Unavailable;
        self.closing = true;
        self.diagnostics.lifecycle(Lifecycle::Closing);
        self.policy_recheck = false;
        self.context_recheck = false;
        self.polling.leave("closing");
        let mut failure: Option<anyhow::Error> = None;
        for device in &mut self.devices {
            let result = close_device_capture_with(
                device,
                |device| {
                    if device_needs_guard(device) {
                        device.attachment.guard(&device.programs)?;
                        device.active = false;
                    }
                    Ok(())
                },
                |device| {
                    let mut failure: Option<io::Error> = None;
                    for queue in &device.info.queues {
                        if let Err(error) = device.programs.delete_xsk(*queue) {
                            failure = Some(match failure {
                                Some(previous) => {
                                    let kind = previous.kind();
                                    let message =
                                        format!("{previous}; XSK withdrawal also failed: {error}");
                                    io::Error::new(
                                        kind,
                                        anyhow::Error::new(previous).context(message),
                                    )
                                }
                                None => error,
                            });
                        }
                    }
                    failure.map_or(Ok(()), Err)
                },
            );
            fold_capture_result(&mut failure, result.map_err(Into::into));
        }
        #[cfg(feature = "ebpf")]
        if let Some(host) = &mut self.host {
            fold_capture_result(&mut failure, host.capture.close_capture());
            host.pending = [None, None];
        }
        self.endpoints.close();
        self.waiting.clear();
        self.pending.clear();
        for realm in &mut self.realms {
            realm.pending = [None, None];
        }
        failure.map_or(Ok(()), Err)
    }

    fn poll_io(
        &mut self,
        cx: &mut Context<'_>,
        interval: Option<&BusyInterval>,
        shutdown: &crate::control::ShutdownIntent,
        reading: bool,
    ) -> Poll<anyhow::Result<()>> {
        if polling_segment_stop(&self.polling, interval, shutdown, None).is_some() {
            self.round_cut_short = true;
            return Poll::Pending;
        }
        if !self.closing {
            if !self.admission.load(Ordering::Acquire) {
                return Poll::Ready(Err(anyhow::anyhow!("XDP publication admission closed")));
            }
            if let Err(error) = arm_read(&self.topology, cx) {
                return Poll::Ready(Err(error.into()));
            }
            if let Err(error) = current_topology(&mut self.topology) {
                return Poll::Ready(Err(error.into()));
            }
        }
        let now = Instant::now();
        let mut progress = self.poll_handoffs(cx, now)?;
        self.round_cut_short = false;
        let deadline = interval.and_then(|_| self.next_deadline(now, !reading));
        for realm in &mut self.realms {
            if realm.generated.is_some() {
                realm.driver.begin_turn(now);
            }
        }
        let mut finalized = [false; 64];
        let start_device = self.rx_device.min(self.devices.len().saturating_sub(1));
        'receive: for device_offset in 0..self.devices.len() {
            let device_index = (start_device + device_offset) % self.devices.len();
            let (before, remaining) = self.devices.split_at_mut(device_index);
            let (device, after) = remaining.split_first_mut().unwrap();
            if !self.closing
                && device.capture.vlan_metadata
                && let Err(error) =
                    check_metadata(&mut device.metadata_checked, now, &device.info.name, || {
                        device.programs.metadata_failures()
                    })
            {
                return Poll::Ready(Err(error));
            }
            let queue_count = device.queues.len();
            let start_queue = if device_index == start_device {
                self.rx_queue.min(queue_count.saturating_sub(1))
            } else {
                0
            };
            for queue_offset in 0..queue_count {
                if polling_segment_stop(&self.polling, interval, shutdown, deadline).is_some() {
                    self.round_cut_short = true;
                    break 'receive;
                }
                let queue_index = (start_queue + queue_offset) % queue_count;
                self.rx_queue = (queue_index + 1) % queue_count;
                self.rx_device = if self.rx_queue == 0 {
                    (device_index + 1) % (before.len() + 1 + after.len())
                } else {
                    device_index
                };
                let queue = &mut device.queues[queue_index];
                if !self.closing
                    && let Err(error) = arm_read(&queue.io, cx)
                {
                    return Poll::Ready(Err(error.into()));
                }
                let port = queue.io.get_mut();
                progress += match port.complete(release_completed) {
                    Ok(count) => count,
                    Err(error) => {
                        return Poll::Ready(Err(error.into()));
                    }
                };
                let mut backpressure = None;
                let (received, kick) = port.transmit_batch(|port| {
                    if self.closing { return Ok(0); }
                    let capture = &device.capture;
                    let core = &mut self.core;
                    let waiting = &mut self.waiting;
                    let workers = &self.workers;
                    let staging = &mut self.staging;
                    let endpoints = &self.endpoints;
                    let pressure = &mut self.pressure.counters;
                    let realms = &self.realms;
                    let qualified_rx = &mut self.qualified_rx;
                    let qualification_unavailable = &mut self.qualification_unavailable;
                    let mut failure = None;
                    let ifindex = device.info.ifindex;
                    let metadata_len = if capture.vlan_metadata { METADATA_LEN } else { 0 };
                    let received = port.receive_segments_with(BATCH, metadata_len, |segments, metadata, same_port| {
                        if failure.is_some() { return; }
                        let capture_metadata = if capture.vlan_metadata {
                            &metadata[..METADATA_LEN.min(metadata.len())]
                        } else { &[] };
                        let Ok(decoded) = capture.decode(segments, capture_metadata, queue.id) else {
                            pressure.capture_rejected = pressure.capture_rejected.saturating_add(1);
                            return;
                        };
                        if decoded.destination_mac[0] & 1 != 0 { return; }
                        let Some(realm) = realms.iter().find(|realm| realm.device == device_index && realm.link.path.vlan_count == decoded.vlan_count
                            && realm.link.path.vlan_proto == decoded.vlan_proto && realm.link.path.vlan_tci.iter().zip(decoded.vlan_tci).all(|(configured, captured)| configured & 0x0fff == captured & 0x0fff)) else { return; };
                        if decoded.destination_mac != realm.link.mac { return; }
                        let scope = realm.driver.scope();
                        let ingress = realm.ingress;
                        let path = ReturnPath { device: device_index, mac: decoded.source_mac, vlan_tci: decoded.vlan_tci, vlan_proto: decoded.vlan_proto, vlan_count: decoded.vlan_count };
                        let mut l3 = [&[][..]; 18];
                        let Some(count) = l3_segments(segments, decoded, &mut l3) else { return; };
                        let Ok(view) = PacketView::new(&l3[..count]) else { return; };
                        if let Some(core) = core && !retained_endpoint(endpoints, scope, view) {
                            let mac = mac_text(decoded.source_mac);
                            let cached = if queue.id != 0 { Ok(CachedDecision::Cold) } else { core.forward_cached(ingress, view, Some(std::str::from_utf8(&mac).unwrap()), now, |route, output| {
                                let header = route.ethernet_header(decoded.ether_type == 0x86dd).map_err(io::Error::other)?;
                                if !selected_egress(realms, route) { return Ok(None); }
                                if route.l2.physical_ifindex == ifindex {
                                    while let Some(length) = output.next_len() {
                                        same_port.transmit_with(TxClass::Bulk, header.len() + length, Retained::Forward { _owner: output.lease(), _peer: None }, |_, target| {
                                            output.write_next_segments(target, &header).map(|_| ()).ok_or_else(|| io::Error::other("Core SG materialization refused"))
                                        })?;
                                    }
                                } else {
                                    let egress = before.iter_mut().chain(after.iter_mut()).find(|device| device.info.ifindex == route.l2.physical_ifindex)
                                        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "Core egress is not a selected XDP interface"))?;
                                    let (work, kick) = egress.queues[0].io.get_mut().transmit_batch(|port| -> io::Result<()> {
                                        while let Some(length) = output.next_len() {
                                            port.transmit_with(TxClass::Bulk, header.len() + length, Retained::Forward { _owner: output.lease(), _peer: None }, |_, target| {
                                                output.write_next_segments(target, &header).map(|_| ()).ok_or_else(|| io::Error::other("Core SG materialization refused"))
                                            })?;
                                        }
                                        Ok(())
                                    });
                                    if let Err(kick) = kick {
                                        failure = finish_transmit(work.map_err(Into::into), Err(kick)).err();
                                        return Err(io::Error::other("Core egress TX wakeup failed"));
                                    }
                                    work?;
                                }
                                Ok(Some(()))
                            }) };
                            if failure.is_some() { return; }
                            match cached {
                                Ok(CachedDecision::Forwarded(())) => { qualify_packet(qualified_rx, qualification_unavailable); return; }
                                Ok(CachedDecision::Drop) => return,
                                Ok(CachedDecision::Cold) => {
                                    if waiting.len() == PENDING {
                                        pressure.waiting_full = pressure.waiting_full.saturating_add(1);
                                        pressure.refused = true;
                                        return;
                                    }
                                    let peer = if matches!(view.parse_ip(), Err(wire::ParseError::Fragment)) {
                                        if decoded.l3_len > staging.len() || view.copy_to(0..decoded.l3_len,
                                            &mut staging[..decoded.l3_len]).is_none() { return; }
                                        match workers.fragment_peer(scope, &staging[..decoded.l3_len], path) {
                                            Ok(peer) => peer,
                                            Err(_) => return,
                                        }
                                    } else { None };
                                    match core.receive_segments_with_peer_at(ingress, now, now, &l3[..count], peer.clone()) {
                                        Ok(Some((packet, peer))) => {
                                            let ingress_at = packet.received_at();
                                            let path = peer.as_ref().map(worker::PeerHold::original_path).unwrap_or(path);
                                            waiting.push_back(Waiting { packet, mac: path.mac, retry: now, scope, path, ingress_at, cell: None, peer });
                                        }
                                        Ok(None) => {}
                                        Err(error) if error.downcast_ref::<honk_datapath::forward::ForwardError>().is_some() => pressure.core_ingress_refused = pressure.core_ingress_refused.saturating_add(1),
                                        Err(error) => failure = Some(error),
                                    }
                                    return;
                                }
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                    pressure.tx_credit = pressure.tx_credit.saturating_add(1);
                                    pressure.refused = true;
                                    backpressure.get_or_insert(error);
                                    return;
                                }
                                Err(error) => { failure = Some(error.into()); return; }
                            }
                        }
                        let bytes = if count == 1 { l3[0] } else {
                            if decoded.l3_len > staging.len() { return; }
                            if view.copy_to(0..decoded.l3_len, &mut staging[..decoded.l3_len]).is_none() { return; }
                            &staging[..decoded.l3_len]
                        };
                        let result = (|| { if workers.owner(scope, bytes)?.worker() == 0 {
                            workers.endpoint(0, endpoints, scope, bytes, now, path, None, None)
                        } else {
                            workers.copy(segments, metadata).and_then(|cell| {
                                let owner = workers.owner(scope, bytes)?;
                                workers.send(1, worker::Envelope {
                                    ingress, scope, path, ingress_at: now, cell,
                                    body: None, peer: None,
                                    l3_offset: decoded.l3_offset, l3_length: decoded.l3_len,
                                    payload: worker::Payload::Endpoint { owner, admission: None } })
                                    .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
                                Ok(PacketReceive::default())
                            })
                        } })();
                        match result {
                            Ok(report) if report.qualified_rx => qualify_packet(qualified_rx, qualification_unavailable),
                            Ok(_) => {}
                            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory) => {}
                            Err(error) => failure = Some(error.into()),
                        }
                    });
                    if let Some(error) = failure {
                        return Err(match received {
                            Ok(_) => error,
                            Err(rx) => error.context(rx).context("RX also failed"),
                        });
                    }
                    received.map_err(Into::into)
                });
                let received = match (received, backpressure) {
                    (Ok(_), Some(error)) if kick.is_err() => Err(error.into()),
                    (received, _) => received,
                };
                progress += finish_transmit(received, kick)?;
            }
            self.rx_device = (device_index + 1) % (before.len() + 1 + after.len());
            self.rx_queue = 0;
        }
        #[cfg(feature = "ebpf")]
        if let Some(host) = &mut self.host {
            progress += host.poll_io(
                cx,
                now,
                self.closing,
                &self.endpoints,
                &mut self.staging,
                &mut self.pressure.counters,
                &mut self.qualified_rx,
                &mut self.qualification_unavailable,
            )?;
        }
        for realm in &mut self.realms {
            if realm.generated.is_none() && realm.driver.service(cx, now) {
                progress += 1;
            }
        }
        let mut outputs: [Option<OutputLease>; BATCH] = std::array::from_fn(|_| None);
        let start_realm = self.tx_realm.min(self.realms.len().saturating_sub(1));
        for realm_offset in 0..self.realms.len() {
            let realm_index = (start_realm + realm_offset) % self.realms.len();
            if polling_segment_stop(&self.polling, interval, shutdown, deadline).is_some() {
                self.round_cut_short = true;
                break;
            }
            let realm_count = self.realms.len();
            let realm = &mut self.realms[realm_index];
            let device = &mut self.devices[realm.device];
            let ifindex = device.info.ifindex;
            let (work, kick) = device.queues[0].io.get_mut().transmit_batch(|port| {
                let mut serviced = 0;
                let start_class = if realm_index == start_realm {
                    self.tx_class
                } else {
                    0
                };
                let mut serviced_classes = 0;
                for class_offset in 0..2 {
                    if polling_segment_stop(&self.polling, interval, shutdown, deadline).is_some() {
                        self.round_cut_short = true;
                        break;
                    }
                    let class_index = (start_class + class_offset) % 2;
                    let class = [TxClass::Control, TxClass::Bulk][class_index];
                    self.tx_class = (class_index + 1) % 2;
                    self.tx_realm = if self.tx_class == 0 {
                        (realm_index + 1) % realm_count
                    } else {
                        realm_index
                    };
                    serviced_classes += 1;
                    let mut considered = 0;
                    while considered < BATCH {
                        let capacity = if self.closing {
                            BATCH - considered
                        } else {
                            port.tx_packet_capacity(class)?
                        };
                        let (selected, pending_path) = realm.poll_outputs(
                            cx,
                            class,
                            capacity,
                            &mut outputs[..BATCH - considered],
                        );
                        let count = match selected {
                            Poll::Ready(Some(count)) => count,
                            Poll::Ready(None) if !self.closing && !self.endpoints.is_closing() => {
                                anyhow::bail!("XDP packet scope ended before endpoint close");
                            }
                            _ => {
                                let Some((_, max_length)) =
                                    realm.generated.filter(|_| !self.closing)
                                else {
                                    break;
                                };
                                let mut emitted = false;
                                let generated =
                                    port.transmit_generated(class, max_length, |frame| {
                                        realm.generate_output(
                                            now,
                                            class,
                                            ifindex,
                                            &[],
                                            frame,
                                            &mut emitted,
                                        )
                                    });
                                if emitted {
                                    considered += 1;
                                    serviced += 1;
                                }
                                match generated {
                                    Ok(true) => continue,
                                    Ok(false) if emitted => continue,
                                    Ok(false) => break,
                                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                        self.pressure.counters.tx_credit =
                                            self.pressure.counters.tx_credit.saturating_add(1);
                                        self.pressure.counters.refused = true;
                                        break;
                                    }
                                    Err(error) => return Err(error.into()),
                                }
                            }
                        };
                        considered += count;
                        let mut blocked = false;
                        for output in &mut outputs[..count] {
                            let output = output.take().expect("selected Endpoint output");
                            let Some(path) = pending_path
                                .or_else(|| output.peer_hold().and_then(|hold| hold.path()))
                            else {
                                serviced += 1;
                                continue;
                            };
                            if self.closing {
                                serviced += 1;
                                continue;
                            }
                            let header =
                                realm.output_header(path, ifindex, output.packet()[0] >> 4 == 6)?;
                            let length = header.len();
                            if count == 1
                                && !port.tx_packet_credit(class, length + output.packet().len())
                            {
                                self.pressure.counters.tx_credit =
                                    self.pressure.counters.tx_credit.saturating_add(1);
                                self.pressure.counters.refused = true;
                                realm.pending[class_index] = Some((output, path));
                                blocked = true;
                                break;
                            }
                            port.transmit_with(
                                class,
                                length + output.packet().len(),
                                Retained::Endpoint(output.into_owner()),
                                |owner, target| {
                                    let Retained::Endpoint(output) = owner else {
                                        return Err(io::Error::other("wrong endpoint TX owner"));
                                    };
                                    let packet = output.packet().ok_or_else(|| {
                                        io::Error::other("Endpoint CPU writer has no packet")
                                    })?;
                                    fill_output(target, &header[..length], packet)
                                },
                            )?;
                            serviced += 1;
                        }
                        if blocked {
                            break;
                        }
                    }
                }
                if serviced_classes == 2 {
                    self.tx_class = 0;
                    self.tx_realm = (realm_index + 1) % realm_count;
                }
                Ok(serviced)
            });
            if realm.generated.is_some() {
                realm.driver.finish_turn(cx, now);
            }
            finalized[realm_index] = true;
            progress += finish_transmit(work, kick)?;
        }
        for (index, realm) in self.realms.iter_mut().enumerate() {
            if !finalized[index] && realm.generated.is_some() {
                realm.driver.finish_turn(cx, now);
            }
        }
        if progress == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    /// Every realm driver, including after close: their finish needs this owner too.
    fn service_scopes(&mut self, cx: &mut Context<'_>, now: Instant) -> bool {
        let mut more = false;
        for realm in &mut self.realms {
            more |= realm.driver.service(cx, now);
        }
        #[cfg(feature = "ebpf")]
        if let Some(host) = &mut self.host {
            more |= host.driver.service(cx, now);
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
        let deadline = self
            .realms
            .iter()
            .filter_map(|realm| realm.driver.deadline())
            .min();
        #[cfg(feature = "ebpf")]
        let deadline = deadline
            .into_iter()
            .chain(self.host.as_ref().and_then(|host| host.driver.deadline()))
            .min();
        deadline
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
        #[cfg(feature = "ebpf")]
        if let Some(host) = &self.host {
            let port = host.queue.io.get_ref();
            if if self.closing {
                port.counters().submitted != port.counters().completed
            } else {
                port.needs_service_retry()
            } {
                include(now + Duration::from_millis(1));
            }
            if !self.closing {
                include(host.metadata_checked + Duration::from_secs(1));
            }
            if let Some(due) = host.driver.deadline() {
                include(due);
            }
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

    /// The earliest Waiting/Pending/reassembly/maintenance work, all resolved under readers.
    fn core_deadline(&self, now: Instant) -> Option<Instant> {
        let mut deadline: Option<Instant> = None;
        let mut include = |due: Instant| {
            deadline = Some(deadline.map_or(due, |previous| previous.min(due)));
        };
        for work in &self.waiting {
            include(work.retry.min(work.packet.deadline()));
        }
        for work in &self.pending {
            let route = work.output.route();
            let port = self
                .devices
                .iter()
                .find(|device| device.info.ifindex == route.l2.physical_ifindex)
                .map(|device| device.queues[0].io.get_ref());
            let runnable = !selected_egress(&self.realms, route)
                || port.is_none()
                || work.output.next_len().is_none_or(|length| {
                    port.is_some_and(|port| {
                        port.tx_packet_credit(
                            TxClass::Bulk,
                            14 + 4 * usize::from(route.l2.vlan_count) + length,
                        )
                    })
                });
            include(if runnable {
                now
            } else {
                work.output.deadline()
            });
        }
        if let Some(core) = &self.core {
            if let Some(due) = core.poll_reassembly_timeout(now) {
                include(due);
            }
            if core.has_maintenance() {
                include(self.core_maintenance_checked + Duration::from_secs(1));
            }
        }
        deadline
    }

    fn core_due(&self, now: Instant) -> bool {
        !self.closing && self.core_deadline(now).is_some_and(|due| due <= now)
    }

    /// One bounded turn under the actual router/config readers acquired beside device
    /// service; nothing here awaits, so no reader or scope lock crosses a suspension.
    fn resolve(&mut self, read: &PolicyRead<'_>) -> anyhow::Result<()> {
        current_topology(&mut self.topology)?;
        let Some(core) = &mut self.core else {
            return Ok(());
        };
        let now = Instant::now();
        for _ in 0..self.waiting.len() {
            let work = self.waiting.pop_front().unwrap();
            if now >= work.packet.deadline() {
                self.pressure.counters.waiting_expired =
                    self.pressure.counters.waiting_expired.saturating_add(1);
                self.pressure.counters.refused = true;
                continue;
            }
            if now < work.retry {
                self.waiting.push_back(work);
                continue;
            }
            if retained_endpoint(
                &self.endpoints,
                work.scope,
                PacketView::from_slice(work.packet.as_ref()),
            ) {
                if let Err(error) = qualify_receive(
                    self.workers.endpoint_packet(
                        &self.endpoints,
                        work.scope,
                        work.packet,
                        work.ingress_at,
                        work.path,
                        None,
                        work.cell,
                        work.peer,
                    ),
                    &mut self.qualified_rx,
                    &mut self.qualification_unavailable,
                ) && !matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                ) {
                    return Err(error.into());
                }
                continue;
            }
            let mac = mac_text(work.mac);
            let decision = core.decide(
                read,
                work.packet,
                Some(std::str::from_utf8(&mac).unwrap()),
                now,
            )?;
            current_topology(&mut self.topology)?;
            match decision {
                Decision::Wait(packet) => self.waiting.push_back(Waiting {
                    packet,
                    retry: now + Duration::from_millis(10),
                    mac: work.mac,
                    scope: work.scope,
                    path: work.path,
                    ingress_at: work.ingress_at,
                    cell: work.cell,
                    peer: work.peer,
                }),
                Decision::Drop | Decision::LocalInput => {}
                Decision::Endpoint(packet, admission) => {
                    if let Err(error) = qualify_receive(
                        self.workers.endpoint_packet(
                            &self.endpoints,
                            work.scope,
                            packet,
                            work.ingress_at,
                            work.path,
                            Some(admission),
                            work.cell,
                            work.peer,
                        ),
                        &mut self.qualified_rx,
                        &mut self.qualification_unavailable,
                    ) && !matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                    ) {
                        return Err(error.into());
                    }
                }
                Decision::Forward(Prepared::Forward(output), generation) => {
                    if self.pending.len() < PENDING {
                        self.pending.push_back(Pending {
                            output,
                            generation,
                            _cell: work.cell,
                            _peer: work.peer,
                        });
                    } else {
                        self.pressure.counters.pending_full =
                            self.pressure.counters.pending_full.saturating_add(1);
                        self.pressure.counters.refused = true;
                    }
                }
                Decision::Forward(Prepared::Error { packet, error }, generation) => {
                    let route = match core.error_route(&packet) {
                        Ok(route) => route,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
                        Err(error) => return Err(error.into()),
                    };
                    if let Some(route) = route
                        && selected_egress(&self.realms, route)
                        && let Some(device) = self
                            .devices
                            .iter_mut()
                            .find(|device| device.info.ifindex == route.l2.physical_ifindex)
                        && device.queues[0].io.get_ref().tx_credit(TxClass::Control)
                        && let Some(length) =
                            core.error(now, &packet, error, route, &mut self.staging)?
                    {
                        let header = match work.peer.as_ref().and_then(|peer| peer.path()) {
                            Some(path) => return_header(
                                path,
                                route.source_mac,
                                route.l2.physical_ifindex,
                                packet.ip().src.is_ipv6(),
                            )?,
                            None => route.ethernet_header(packet.ip().src.is_ipv6())?,
                        };
                        core.submit(read, route, generation, || {
                            current_topology(&mut self.topology)?;
                            if !packet.is_current(Instant::now()) {
                                return Ok(None);
                            }
                            device.queues[0]
                                .io
                                .get_mut()
                                .transmit_segments(
                                    TxClass::Control,
                                    &[&header, &self.staging[..length]],
                                    Retained::Error {
                                        _binding: packet.into_binding(),
                                        _peer: work.peer,
                                    },
                                )
                                .map(Some)
                        })?;
                    }
                }
            }
        }
        for _ in 0..self.pending.len() {
            let mut work = self.pending.pop_front().unwrap();
            if now >= work.output.deadline() {
                self.pressure.counters.pending_expired =
                    self.pressure.counters.pending_expired.saturating_add(1);
                self.pressure.counters.refused = true;
                continue;
            }
            let route = work.output.route();
            if !selected_egress(&self.realms, route) {
                continue;
            }
            let Some(device) = self
                .devices
                .iter_mut()
                .find(|device| device.info.ifindex == route.l2.physical_ifindex)
            else {
                continue;
            };
            let port = device.queues[0].io.get_mut();
            let Some(length) = work.output.next_len() else {
                continue;
            };
            let lease = work.output.lease();
            let header = route.ethernet_header(
                lease
                    .retained_packet()
                    .expect("owned forwarding cursor")
                    .ip()
                    .src
                    .is_ipv6(),
            )?;
            if !port.tx_packet_credit(TxClass::Bulk, header.len() + length) {
                self.pressure.counters.tx_credit =
                    self.pressure.counters.tx_credit.saturating_add(1);
                self.pressure.counters.refused = true;
                self.pending.push_back(work);
                continue;
            }
            let submitted = core.submit(read, route, work.generation, || {
                current_topology(&mut self.topology)?;
                if !lease
                    .retained_packet()
                    .expect("owned forwarding cursor")
                    .is_current(Instant::now())
                {
                    return Ok(None);
                }
                port.transmit_with(
                    TxClass::Bulk,
                    header.len() + length,
                    Retained::Forward {
                        _owner: lease,
                        _peer: work._peer.clone(),
                    },
                    |_, target| {
                        work.output
                            .write_next_segments(target, &header)
                            .map(|_| ())
                            .ok_or_else(|| io::Error::other("Core SG materialization refused"))
                    },
                )
                .map(Some)
            })?;
            if submitted.is_some() {
                if work.output.is_complete() {
                    qualify_packet(&mut self.qualified_rx, &mut self.qualification_unavailable);
                } else {
                    self.pending.push_back(work);
                }
            }
        }
        if let Some(error) = core.poll_reassembly_error(read, now, &mut self.staging)? {
            let route = error.route;
            if selected_egress(&self.realms, route)
                && error.peer_hold().is_none_or(|peer| peer.learned())
                && let Some(device) = self
                    .devices
                    .iter_mut()
                    .find(|device| device.info.ifindex == route.l2.physical_ifindex)
            {
                let header = match error.peer_hold().and_then(|peer| peer.path()) {
                    Some(path) => return_header(
                        path,
                        route.source_mac,
                        route.l2.physical_ifindex,
                        self.staging[0] >> 4 == 6,
                    )?,
                    None => route.ethernet_header(self.staging[0] >> 4 == 6)?,
                };
                let port = device.queues[0].io.get_mut();
                if port.tx_packet_credit(TxClass::Control, header.len() + error.len) {
                    core.submit(read, route, error.generation, || {
                        current_topology(&mut self.topology)?;
                        port.transmit_segments(
                            TxClass::Control,
                            &[&header, &self.staging[..error.len]],
                            Retained::Generated { _owner: error },
                        )
                        .map(Some)
                    })?;
                }
            }
        }
        self.core_maintenance_checked = Instant::now();
        Ok(())
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.admission.store(false, Ordering::Release);
        self.workers.close();
        *self.pname_support.write() = crate::ebpf::PnameSupport::Unavailable;
        self.diagnostics.lifecycle(Lifecycle::FailedRetained);
        for device in &self.devices {
            if device_needs_guard(device)
                && let Err(error) = device.attachment.guard(&device.programs)
            {
                tracing::error!(%error, "XDP pinned capture guard failed; socket-map misses remain drop");
            }
        }
        #[cfg(feature = "ebpf")]
        if let Some(host) = &mut self.host
            && let Err(error) = host.capture.close_capture()
        {
            tracing::error!(%error, "Host capture fence failed; retaining fail-closed source custody");
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
            #[cfg(feature = "ebpf")]
            std::mem::forget(self.host.take());
        }
    }
}

fn device_needs_guard(device: &Device) -> bool {
    device.active
}

fn close_device_capture_with<T>(
    device: &mut T,
    guard: impl FnOnce(&mut T) -> io::Result<()>,
    withdraw: impl FnOnce(&mut T) -> io::Result<()>,
) -> io::Result<()> {
    let guarded = guard(device);
    let withdrawn = withdraw(device);
    match (guarded, withdrawn) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(guard), Err(withdraw)) => {
            let kind = guard.kind();
            let message = format!("{guard}; XSK withdrawal also failed: {withdraw}");
            Err(io::Error::new(
                kind,
                anyhow::Error::new(guard).context(message),
            ))
        }
    }
}

fn l3_segments<'a>(
    segments: &[&'a [u8]],
    packet: DecodedPacket,
    output: &mut [&'a [u8]; 18],
) -> Option<usize> {
    l3_segments_at(segments, packet.l3_offset, packet.l3_len, output)
}

fn l3_segments_at<'a>(
    segments: &[&'a [u8]],
    mut skip: usize,
    mut left: usize,
    output: &mut [&'a [u8]; 18],
) -> Option<usize> {
    let mut count = 0;
    for segment in segments {
        if skip >= segment.len() {
            skip -= segment.len();
            continue;
        }
        let bytes = &segment[skip..];
        skip = 0;
        let length = bytes.len().min(left);
        if length != 0 {
            *output.get_mut(count)? = &bytes[..length];
            count += 1;
            left -= length;
        }
        if left == 0 {
            return Some(count);
        }
    }
    None
}
#[cfg(test)]
fn peer_policy(
    peers: &[Peer],
    endpoints: &PacketEndpoints,
    scope: ScopeId,
    address: IpAddr,
    path: ReturnPath,
    now: Instant,
) -> PeerPolicy {
    if let Some(peer) = peers
        .iter()
        .find(|peer| peer.scope == scope && peer.address == address)
    {
        if peer.path == path && peer.conflict.is_none() {
            return PeerPolicy::default();
        }
        return PeerPolicy {
            retained: endpoints.retains_source(scope, address),
            output: peer.path != path,
            evict: None,
        };
    }
    PeerPolicy {
        // ponytail: reclamation scans only at the fixed 4096-peer ceiling; index if measured.
        evict: (peers.len() == PEERS)
            .then(|| {
                peers
                    .iter()
                    .enumerate()
                    .filter(|(_, peer)| {
                        peer.conflict.is_none_or(|last| {
                            now.saturating_duration_since(last) >= PEER_CONFLICT_HOLD
                        }) && !endpoints.retains_source(peer.scope, peer.address)
                    })
                    .min_by_key(|(_, peer)| peer.last_seen)
                    .map(|(index, _)| index)
            })
            .flatten(),
        ..Default::default()
    }
}

#[cfg(test)]
fn remember_peer(
    peers: &mut Vec<Peer>,
    scope: ScopeId,
    source: honk_netstack::ValidatedSource,
    path: ReturnPath,
    now: Instant,
    policy: PeerPolicy,
    pressure: &mut PressureCounters,
) -> bool {
    let address = source.src.ip();
    if address.is_unspecified() || address.is_multicast() || path.mac[0] & 1 != 0 {
        return false;
    }
    if source
        .tcp_flags
        .is_some_and(|flags| flags & wire::tcp::RST != 0)
    {
        return peers
            .iter()
            .find(|peer| peer.scope == scope && peer.address == address)
            .is_none_or(|peer| peer.path.same_identity(path) && peer.conflict.is_none());
    }
    let opens = source.protocol == wire::PROTO_UDP
        || source.tcp_flags.is_some_and(|flags| {
            flags & (wire::tcp::SYN | wire::tcp::ACK | wire::tcp::RST | wire::tcp::FIN)
                == wire::tcp::SYN
        });
    if let Some(peer) = peers
        .iter_mut()
        .find(|peer| peer.scope == scope && peer.address == address)
    {
        if !peer.path.same_identity(path) || peer.conflict.is_some() {
            if !opens || policy.retained {
                pressure.peer_conflict = pressure.peer_conflict.saturating_add(1);
                pressure.refused = true;
                return false;
            }
            if !peer
                .conflict
                .is_some_and(|last| now.saturating_duration_since(last) >= PEER_CONFLICT_HOLD)
            {
                peer.conflict = Some(now);
                pressure.peer_conflict = pressure.peer_conflict.saturating_add(1);
                pressure.refused = true;
                return false;
            }
            peer.conflict = None;
        }
        if !policy.output {
            peer.path = path;
        }
        if source
            .tcp_flags
            .is_none_or(|flags| flags & wire::tcp::RST == 0)
        {
            peer.last_seen = now;
        }
        return true;
    }
    if !opens {
        return true;
    }
    let peer = Peer {
        scope,
        address,
        path,
        last_seen: now,
        conflict: None,
    };
    if peers.len() == PEERS {
        let Some(index) = policy.evict else {
            pressure.peer_full = pressure.peer_full.saturating_add(1);
            pressure.refused = true;
            return false;
        };
        peers[index] = peer;
        pressure.peer_reclaimed = pressure.peer_reclaimed.saturating_add(1);
    } else {
        peers.push(peer);
    }
    true
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn receive_endpoint(
    endpoints: &PacketEndpoints,
    peers: &mut Vec<Peer>,
    pressure: &mut PressureCounters,
    scope: ScopeId,
    packet: &[u8],
    now: Instant,
    path: ReturnPath,
    admission: Option<EndpointAdmission>,
) -> io::Result<PacketReceive> {
    let policy = match wire::parse_ip(packet) {
        Ok(ip)
            if ip.proto == wire::PROTO_TCP
                && packet[ip.payload.clone()]
                    .get(13)
                    .is_some_and(|flags| flags & wire::tcp::RST != 0) =>
        {
            PeerPolicy::default()
        }
        Ok(ip) if matches!(ip.proto, wire::PROTO_TCP | wire::PROTO_UDP) => {
            peer_policy(peers, endpoints, scope, ip.src, path, now)
        }
        Err(wire::ParseError::Fragment) => wire::packet_addresses(packet)
            .map(|(source, _)| peer_policy(peers, endpoints, scope, source, path, now))
            .unwrap_or_default(),
        _ => PeerPolicy::default(),
    };
    let check_output = policy.output;
    let mut policy = Some(policy);
    let on_source = |source, pending| {
        let mut policy = policy.take().expect("one completed source");
        policy.output = pending;
        remember_peer(peers, scope, source, path, now, policy, pressure)
    };
    let result = match admission {
        Some(admission) => endpoints.receive_admitted_with_source(
            scope,
            packet,
            now,
            admission,
            check_output,
            on_source,
        ),
        None => endpoints.receive_with_source(scope, packet, now, check_output, on_source),
    };
    if result.as_ref().is_err_and(|error| {
        matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
        )
    }) {
        pressure.endpoint_capacity = pressure.endpoint_capacity.saturating_add(1);
        pressure.refused = true;
    }
    result
}
fn retained_endpoint(endpoints: &PacketEndpoints, scope: ScopeId, view: PacketView<'_>) -> bool {
    let Ok(ip) = view.parse_ip() else {
        return false;
    };
    if matches!(ip.proto, wire::PROTO_ICMP | wire::PROTO_ICMPV6) {
        return retained_icmp(endpoints, scope, view, &ip);
    }
    if !matches!(ip.proto, 6 | 17) || ip.payload.len() < 4 {
        return false;
    }
    let mut ports = [0; 4];
    if view
        .copy_to(ip.payload.start..ip.payload.start + 4, &mut ports)
        .is_none()
    {
        return false;
    }
    endpoints.retained_transport(
        scope,
        std::net::SocketAddr::new(ip.src, u16::from_be_bytes([ports[0], ports[1]])),
        std::net::SocketAddr::new(ip.dst, u16::from_be_bytes([ports[2], ports[3]])),
        ip.proto,
    )
}

#[inline(never)]
fn retained_icmp(
    endpoints: &PacketEndpoints,
    scope: ScopeId,
    view: PacketView<'_>,
    ip: &wire::IpPacket,
) -> bool {
    if view.transport_ports(ip).is_err() || ip.payload.len() < 8 {
        return false;
    }
    let mut kind = [0; 2];
    if view
        .copy_to(ip.payload.start..ip.payload.start + 2, &mut kind)
        .is_none()
    {
        return false;
    }
    if !matches!((ip.src.is_ipv4(), kind[0]), (true, 3) | (false, 1 | 2)) {
        return false;
    }
    let mut quote = [0; 40 + 8 * 2048 + 8];
    let count = (ip.payload.len() - 8).min(quote.len());
    if view
        .copy_to(
            ip.payload.start + 8..ip.payload.start + 8 + count,
            &mut quote[..count],
        )
        .is_none()
    {
        return false;
    }
    let Some(quote) = wire::icmp::parse_quoted(&quote[..count]) else {
        return false;
    };
    quote.proto == wire::PROTO_TCP
        && quote.seq.is_some()
        && quote.src.is_ipv4() == ip.src.is_ipv4()
        && endpoints.retains(
            scope,
            std::net::SocketAddr::new(quote.dst, quote.dst_port),
            std::net::SocketAddr::new(quote.src, quote.src_port),
            quote.proto,
        )
}

#[cfg(test)]
fn endpoint_return_path(peers: &[Peer], output: &OutputLease) -> Option<ReturnPath> {
    let (_, destination) = wire::packet_addresses(output.packet()).ok()?;
    peer_return_path(peers, output.scope(), destination)
}

fn peer_return_path(peers: &[Peer], scope: ScopeId, destination: IpAddr) -> Option<ReturnPath> {
    peers
        .iter()
        .find(|peer| peer.scope == scope && peer.address == destination && peer.conflict.is_none())
        .map(|peer| peer.path)
}

fn return_header(
    path: ReturnPath,
    source: [u8; 6],
    physical_ifindex: u32,
    ipv6: bool,
) -> io::Result<honk_datapath::forward::EthernetHeader> {
    LinkPath {
        physical_ifindex,
        vlan_tci: path.vlan_tci,
        vlan_proto: path.vlan_proto,
        vlan_count: path.vlan_count,
    }
    .header(source, path.mac, ipv6)
    .map_err(io::Error::other)
}

fn current_topology(topology: &mut AsyncFd<Topology>) -> io::Result<()> {
    if topology.get_mut().check_changed()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "XDP topology authority changed; restart required",
        ));
    }
    Ok(())
}

/// Tokio takes the reader waker when it delivers readiness and a cached Ready installs none,
/// so a single clear can park an empty pass with nothing to wake it. Pending registers this
/// task (or schedules a coop-budget continuation) before the caller drains.
fn arm_read<T: AsRawFd>(io: &AsyncFd<T>, cx: &mut Context<'_>) -> io::Result<()> {
    while let Poll::Ready(ready) = io.poll_read_ready(cx) {
        ready?.clear_ready();
    }
    Ok(())
}

fn selected_egress(realms: &[Realm], route: Route) -> bool {
    realms.iter().any(|realm| {
        realm.ingress.ifindex == route.ifindex
            && realm.link.path == route.l2
            && realm.link.mac == route.source_mac
    })
}
fn fill_output(output: &mut [&mut [u8]], header: &[u8], packet: &[u8]) -> io::Result<()> {
    let parts = [header, packet];
    let view = PacketView::new(&parts).map_err(io::Error::other)?;
    let mut offset = 0;
    for segment in output {
        let end = offset + segment.len();
        view.copy_to(offset..end, segment)
            .ok_or_else(|| io::Error::other("invalid TX reservation"))?;
        offset = end;
    }
    if offset != view.len() {
        return Err(io::Error::other("short TX reservation"));
    }
    Ok(())
}
fn mac_text(mac: [u8; 6]) -> [u8; 17] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [b':'; 17];
    for (index, byte) in mac.into_iter().enumerate() {
        bytes[index * 3] = HEX[(byte >> 4) as usize];
        bytes[index * 3 + 1] = HEX[(byte & 15) as usize];
    }
    bytes
}

fn check_metadata(
    checked: &mut Instant,
    now: Instant,
    name: &str,
    read: impl FnOnce() -> io::Result<u64>,
) -> anyhow::Result<()> {
    if now.saturating_duration_since(*checked) < Duration::from_secs(1) {
        return Ok(());
    }
    *checked = now;
    let failures = read().with_context(|| format!("XDP device {name} capture metadata counter"))?;
    ensure!(
        failures == 0,
        "XDP device {name} cannot carry capture metadata (bpf_xdp_adjust_meta unsupported); capture failed closed"
    );
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
    pin_root: &Path,
    admission: Arc<AtomicBool>,
    pname_support: crate::ebpf::PnameSupportCell,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    worker::run_coordinator(plane, pin_root, admission, pname_support).await
}

async fn run_capture(
    plane: ControlPlane,
    pin_root: &Path,
    admission: Arc<AtomicBool>,
    pname_support: crate::ebpf::PnameSupportCell,
    shared_runtime: tokio::runtime::Handle,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    *pname_support.write() = crate::ebpf::PnameSupport::Unavailable;
    let config = plane.config_handle().read().await.as_ref().clone();
    let shutdown = plane.shutdown_intent();
    let backend = plane.policy_backend_handle();
    let (polling_publication, process_polling) = plane
        .polling_runtime()
        .expect("validated XDP polling consumer");
    let notification = polling_publication.notification();
    tokio::pin!(notification);
    let prepared = match prepare(&plane, &config, pin_root, Arc::clone(&admission)).await {
        Ok(prepared) => prepared,
        Err(error) => return (Some(plane), Err(error)),
    };
    #[cfg(feature = "ebpf")]
    let host = prepared.host;
    let PreparedRuntime {
        devices,
        topology,
        realms,
        scope_pairs,
        workers,
        inboxes,
        core,
        memory,
        staging,
        links: mut link_proof,
        polling_prefix,
        polling_budget,
        diagnostics,
        ..
    } = prepared;
    plane.stats_handle().install_xdp(Arc::clone(&diagnostics));
    let (endpoints, mut owner, mut drivers) = match shared_runtime
        .spawn(PacketEndpoints::start_driven(
            plane,
            scope_pairs,
            64,
            None,
            ScopeId::HOST,
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
            #[cfg(feature = "ebpf")]
            if let Some(host) = host
                && let Err(close) = host.finish()
            {
                return (
                    None,
                    Err(error
                        .context(close)
                        .context("Host unpublished teardown also failed")),
                );
            }
            return (None, Err(error));
        }
    };
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
            let realm = Realm {
                ingress,
                device,
                link,
                generated: generated_layout(link),
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
    #[cfg(feature = "ebpf")]
    let host = host.map(|host| host.start(&mut drivers));
    assert!(
        drivers.is_empty(),
        "every prepared scope has its exact service owner"
    );
    let [inbox, remote_inbox] = inboxes;
    let mut runtime = Runtime {
        devices,
        topology,
        #[cfg(feature = "ebpf")]
        host,
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
    let ready = loop {
        tokio::select! {
            ready = async {
                poll_fn(|cx| owner.poll_ready(cx)).await?;
                poll_fn(|cx| workers.all_ready(cx)).await
            } => break ready,
            () = poll_fn(|cx| runtime.poll_scopes(cx, timer.as_mut())) => tokio::task::yield_now().await,
        }
    };
    let startup_failure = ready.err();
    let activate = if startup_failure.is_some() {
        Ok(())
    } else {
        (|| -> anyhow::Result<()> {
            for device in &mut runtime.devices {
                device.attachment.replace(&device.programs)?;
                device.active = true;
            }
            // Bootstrap carrier changes precede the final uninterrupted authority.
            let indices: Vec<_> = runtime
                .devices
                .iter()
                .map(|device| device.info.ifindex)
                .collect();
            let logical: Vec<_> = runtime
                .realms
                .iter()
                .map(|realm| realm.ingress.ifindex)
                .collect();
            let topology = runtime.admit_final_topology(
                &indices,
                &logical,
                config.global.effective_so_mark(),
            )?;
            ensure!(
                topology.ipv4_broadcasts() == runtime.topology.get_ref().ipv4_broadcasts(),
                "XDP broadcast classification changed before publication"
            );
            // SAFETY: Topology keeps its owned descriptor unchanged until AsyncFd drops it.
            runtime.topology = unsafe { AsyncFd::register(topology) }.map_err(io::Error::from)?;
            for device in &runtime.devices {
                device.info.validate_current()?;
            }
            link_proof.synchronize()?;
            link_proof.validate_capture(&indices)?;
            ensure!(
                link_proof
                    .logical_links()
                    .filter(|link| indices.contains(&link.path.physical_ifindex))
                    .count()
                    == runtime.realms.len()
                    && runtime
                        .realms
                        .iter()
                        .all(|realm| link_proof.logical_links().any(|link| link == realm.link)),
                "logical capture identity changed before publication"
            );
            ensure!(
                !runtime.topology.get_mut().check_changed()?,
                "capture topology changed before publication"
            );
            runtime.rebuild_polling_context();
            #[cfg(feature = "ebpf")]
            if let Some(host) = &mut runtime.host {
                host.admit(&runtime.pname_support)?;
            }
            runtime.admission.store(true, Ordering::Release);
            runtime.endpoints.capture_ready()?;
            Ok(())
        })()
    };
    drop(link_proof);
    let mut failure = startup_failure.or_else(|| activate.err());
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
    let mut close_started = None;
    // One clone of the existing registration; each acquisition yields real guards only.
    let authority = runtime.core.as_ref().map(RoutedCore::authority);
    let reader = None;
    tokio::pin!(reader);
    let joined = loop {
        if (failure.is_some() || shutdown.requested()) && !runtime.closing {
            // Cleanup never resolves Core again; a queued reader must not stall publication.
            reader.set(None);
            if let Err(error) = runtime.close_capture() {
                failure.get_or_insert(error);
            }
            close_started = Some(Instant::now());
        }
        if runtime.closing {
            match join_endpoints(
                &mut owner,
                |cx| {
                    runtime.poll_service(
                        cx,
                        &shutdown,
                        timer.as_mut(),
                        false,
                        notification.as_mut(),
                    )
                },
                close_started.unwrap(),
                &mut warned,
            )
            .await
            {
                Ok(joined) => break joined,
                Err(error) => {
                    tracing::error!(%error, "XDP terminal I/O failed; retaining runtime and supervisor until process exit");
                    failure.get_or_insert(error);
                    runtime.diagnostics.lifecycle(Lifecycle::FailedRetained);
                    std::mem::forget((runtime, owner));
                    return (None, Err(failure.unwrap()));
                }
            }
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
            Ok(Some(result)) => break result,
            Ok(None) => {}
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    };
    if !runtime.closing
        && let Err(error) = runtime.close_capture()
    {
        failure.get_or_insert(error);
    }
    // An endpoint join cannot release Core TX leases; drain those same descriptor owners too.
    if let Err(error) = drain_transmit(
        || runtime.complete_transmit(),
        close_started.unwrap_or_else(Instant::now),
        &mut warned,
    )
    .await
    {
        tracing::error!(%error, "XDP terminal drain failed; retaining owners and UMEM until process exit");
        failure.get_or_insert(error.into());
        runtime.diagnostics.lifecycle(Lifecycle::FailedRetained);
        if let Err(error) = owner.fail_control().await {
            failure.get_or_insert(error);
        }
        std::mem::forget((runtime, joined));
        return (None, Err(failure.unwrap()));
    }
    if let Some(worker) = &mut runtime.worker
        && let Err(error) = worker.join().await
    {
        failure.get_or_insert(error);
        runtime.diagnostics.lifecycle(Lifecycle::FailedRetained);
        std::mem::forget((runtime, joined));
        return (None, Err(failure.unwrap()));
    }
    runtime.sample_queues();
    let ports_ready = runtime.ports_ready_for_backend_teardown();
    if !ports_ready {
        failure
            .get_or_insert_with(|| anyhow::anyhow!("XDP ledger did not reach terminal ownership"));
        runtime.diagnostics.lifecycle(Lifecycle::FailedRetained);
        std::mem::forget((runtime, joined));
        return (None, Err(failure.unwrap()));
    }
    for device in &mut runtime.devices {
        for queue in device.queues.drain(..) {
            let mut port = queue.io.into_inner();
            debug_assert!(port.close().ready_for_backend_teardown());
            port.close_socket();
        }
    }
    #[cfg(feature = "ebpf")]
    if let Some(host) = runtime.host.take()
        && let Err(error) = host.finish()
    {
        failure.get_or_insert(error);
    }
    runtime.diagnostics.lifecycle(Lifecycle::Closed);
    if let Err(error) = backend.write().await.cleanup().await {
        failure.get_or_insert(error);
    }
    tracing::info!("XDP admission closed; UMEM retained until process exit");
    let plane = match joined {
        Ok((plane, result)) => {
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
            Some(plane)
        }
        Err(error) => {
            failure.get_or_insert(error);
            None
        }
    };
    runtime.finished = true;
    (plane, failure.map_or(Ok(()), Err))
}

/// A realm before validated endpoint start hands it the driver of this exact scope.
type RealmPlan = (Ingress, usize, LogicalLink, ScopeId);

struct PreparedRuntime {
    devices: Vec<Device>,
    topology: AsyncFd<Topology>,
    #[cfg(feature = "ebpf")]
    host: Option<PreparedHost>,
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

#[cold]
fn device_sizing(mtu: u32) -> (PortConfig, usize) {
    // Two VLAN tags bound TX extent; RX keeps its independent SG admission.
    let single_frame = usize::try_from(mtu)
        .ok()
        .and_then(|mtu| mtu.checked_add(22))
        .is_some_and(|length| length <= FRAME_SIZE);
    let (bulk_frames, ring_size, scope_bulk_frames) = if single_frame {
        (480, 512, 256)
    } else {
        (224, 256, 128)
    };
    (
        PortConfig {
            rx_frames: 256,
            control_frames: 32,
            bulk_frames,
            ring_size,
        },
        scope_bulk_frames,
    )
}

async fn prepare(
    plane: &ControlPlane,
    config: &Config,
    pin_root: &Path,
    admission: Arc<AtomicBool>,
) -> anyhow::Result<PreparedRuntime> {
    validate_config(config)?;
    let datapath = config
        .datapath
        .as_ref()
        .context("XDP configuration missing")?;
    let metadata_len = METADATA_LEN;
    let binding_mode = match datapath.effective_xsk_mode() {
        XskMode::Copy => BindMode::Copy,
        XskMode::ZeroCopy => BindMode::ZeroCopy,
    };
    let infos: Vec<_> = datapath
        .interfaces
        .iter()
        .map(|interface| DeviceInfo::discover(&interface.name))
        .collect::<io::Result<_>>()?;
    worker::admit(datapath.effective_workers(), &infos)?;
    for info in &infos {
        let (port_config, _) = device_sizing(info.mtu);
        info.validate_port_config(binding_mode, port_config, metadata_len)
            .with_context(|| format!("XDP device {} {binding_mode:?} admission", info.name))?;
        ensure!(
            honk_xsk::xdp_absent(info.ifindex)?,
            "XDP interface already attached; stop sources, join prior owners and identify the owned guard/data/data-next and attachment format before explicit cold cleanup; stale state is not adopted"
        );
    }
    let indices: Vec<_> = infos.iter().map(|info| info.ifindex).collect();
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let extent = infos
        .iter()
        .map(|info| info.mtu as usize + 22 + metadata_len)
        .max()
        .unwrap_or(65536);
    let (workers, inboxes) = worker::Shared::new(
        datapath.effective_workers(),
        extent,
        infos.iter().map(|info| info.queues.len()).sum(),
        &budget,
        Arc::clone(&admission),
    )?;
    let polling_prefix = ContextDigest::platform(&budget);
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let namespace = socket_namespace(socket.as_fd())?;
    let mut links = Fib::new(&budget, namespace)?;
    links.synchronize()?;
    links.validate_capture(&indices)?;
    ensure!(
        links
            .logical_links()
            .filter(|link| indices.contains(&link.path.physical_ifindex))
            .all(|link| link.mtu >= 1280),
        "XDP logical MTU must be at least 1280 for packet Endpoint handoffs"
    );
    let physical_realm_count = links
        .logical_links()
        .filter(|link| indices.contains(&link.path.physical_ifindex))
        .count();
    let realm_count = physical_realm_count + usize::from(datapath.host.is_some());
    ensure!(
        (1..=64).contains(&realm_count),
        "logical capture realm capacity exceeded"
    );
    for info in &infos {
        ensure!(
            links
                .logical_links()
                .any(|link| link.ifindex == info.ifindex
                    && link.mac == info.mac
                    && link.mtu == info.mtu)
                && info
                    .upper_ifindices
                    .iter()
                    .all(
                        |index| links.logical_links().any(|link| link.ifindex == *index
                            && link.path.physical_ifindex == info.ifindex
                            && link.path.vlan_count != 0)
                    ),
            "device and canonical logical-link discovery disagree"
        );
    }
    let logical: Vec<_> = links
        .logical_links()
        .filter(|link| indices.contains(&link.path.physical_ifindex))
        .map(|link| link.ifindex)
        .collect();
    let topology = Topology::admit(&indices, &logical, config.global.effective_so_mark())?;
    // SAFETY: Topology never closes or replaces its descriptor while registered.
    let topology = unsafe { AsyncFd::register(topology) }.map_err(io::Error::from)?;
    std::fs::create_dir_all(pin_root)?;
    let metadata = std::fs::symlink_metadata(pin_root)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "XDP pin root must be a real private bpffs directory"
    );
    let max_mtu = infos.iter().map(|info| info.mtu).max().unwrap_or(65535) as usize;
    #[cfg(feature = "ebpf")]
    let host_memory = usize::from(datapath.host.is_some()) * size_of::<PreparedHost>();
    #[cfg(not(feature = "ebpf"))]
    let host_memory = 0;
    let memory = budget
        .reserve(
            max_mtu
                + 65536
                + size_of::<Runtime>()
                + size_of::<Topology>()
                + host_memory
                + PENDING * (size_of::<Waiting>() + size_of::<Pending>())
                + realm_count
                    * usize::from(datapath.effective_workers())
                    * (size_of::<Realm>()
                        + size_of::<RealmPlan>()
                        + size_of::<PacketDriver>()
                        + size_of::<(PacketScope, crate::control::netstack::PacketOwner)>()
                        + size_of::<Ingress>()
                        + size_of::<IngressBinding>())
                + infos.len() * size_of::<Device>()
                + infos
                    .iter()
                    .map(|info| {
                        info.queues.len() * size_of::<Queue>()
                            + info.name.capacity()
                            + (info.queues.capacity() + info.upper_ifindices.capacity())
                                * size_of::<u32>()
                    })
                    .sum::<usize>(),
        )
        .context("XDP metadata and staging memory capacity")?;
    tracing::debug!(
        used = budget.used(),
        limit = budget.limit(),
        realm_count,
        "XDP prepare: after metadata reservation"
    );
    let routing_scope = ScopeId::allocate().context("XDP routing domain exhausted")?;
    let mut realms = Vec::with_capacity(realm_count);
    let mut scope_pairs = Vec::with_capacity(realm_count);
    let config_generation = plane.diagnostics_handle().read().generation;
    let authority = if datapath.direct == Some(DirectProfile::Core) {
        Some(plane.core_forward_policy(Execution::MixedEndpoints).await?)
    } else {
        None
    };
    let mut devices = Vec::with_capacity(infos.len());
    for (device_index, info) in infos.into_iter().enumerate() {
        let (port_config, _) = device_sizing(info.mtu);
        let incarnation = ScopeId::allocate()
            .context("XDP attachment identity exhausted")?
            .as_u64();
        let capture = GeneralCapture {
            authority: CaptureAuthority {
                namespace_cookie: namespace,
                attachment_generation: incarnation,
                scope: routing_scope.as_u64(),
                config_generation,
                ifindex: info.ifindex,
                reserved: 0,
            },
            bypass_mark: config.global.effective_so_mark(),
            vlan_metadata: info.vlan_metadata,
        };
        let queues = info
            .queues
            .last()
            .copied()
            .unwrap()
            .checked_add(1)
            .context("XDP queue identity overflow")?;
        let programs =
            Programs::load_general(&capture, queues, topology.get_ref().ipv4_broadcasts())?;
        use std::os::unix::fs::DirBuilderExt;
        let pins = pin_root.join(format!("xdp-{}", info.ifindex));
        std::fs::DirBuilder::new().mode(0o700).create(&pins)?;
        let attachment = PersistentAttachment::create(info.ifindex, &programs, &pins)?;
        let ports =
            info.open_ports::<Retained>(binding_mode, port_config, metadata_len, &budget)?;
        ensure!(
            ports
                .iter()
                .all(|port| socket_namespace(port.as_fd())
                    .is_ok_and(|observed| observed == namespace)),
            "queue capture namespace changed"
        );
        let mut queues = Vec::with_capacity(ports.len());
        for (id, mut port) in info.queues.iter().copied().zip(ports) {
            port.refill()?;
            programs.insert_xsk(id, port.as_fd())?;
            let zero_copy = port.zerocopy();
            let observed = port.counters();
            let observed_rings = port.rings();
            queues.push(Queue {
                id,
                observed,
                observed_rings,
                io: if id % u32::from(datapath.effective_workers()) == 0 {
                    QueueIo::Prepared(port).register()?
                } else {
                    QueueIo::Prepared(port)
                },
            });
            tracing::info!(interface = %info.name, ifindex = info.ifindex, queue = id, zero_copy, vlan_metadata = capture.vlan_metadata, "XDP queue bound");
        }
        devices.push(Device {
            info: Arc::new(info),
            capture,
            programs: Arc::new(programs),
            attachment: Arc::new(attachment),
            queues,
            active: false,
            metadata_checked: Instant::now(),
            features: None,
            port_config,
            role: datapath.interfaces[device_index].role,
        });
    }
    #[cfg(feature = "ebpf")]
    let host = if let Some(host) = &datapath.host {
        let source_xdp_capacity = devices.len() * 2;
        let _source_xdp_memory = budget
            .reserve(source_xdp_capacity * size_of::<(u32, u32)>())
            .context("Host source XDP identity memory capacity")?;
        let mut source_xdp = Vec::with_capacity(source_xdp_capacity);
        for device in &devices {
            source_xdp.push((device.info.ifindex, device.programs.discover_prog_id()));
            source_xdp.push((device.info.ifindex, device.programs.data_prog_id()));
        }
        let attachment = ScopeId::allocate()
            .context("Host attachment identity exhausted")?
            .as_u64();
        let (host, scope) = PreparedHost::prepare(
            &host.interfaces,
            &source_xdp,
            CaptureAuthority {
                namespace_cookie: namespace,
                attachment_generation: attachment,
                scope: routing_scope.as_u64(),
                config_generation,
                ifindex: 0,
                reserved: 0,
            },
            config.global.effective_so_mark(),
            pin_root,
            honk_config::paths::data_dir(),
            realm_count,
            &budget,
        )?;
        tracing::debug!(
            used = budget.used(),
            "XDP prepare: after PreparedHost::prepare"
        );
        Some((host, scope))
    } else {
        None
    };
    for (device_index, device) in devices.iter().enumerate() {
        let (_, scope_bulk_frames) = device_sizing(device.info.mtu);
        for link in links
            .logical_links()
            .filter(|link| link.path.physical_ifindex == device.info.ifindex)
        {
            let ingress = Ingress {
                scope: routing_scope,
                namespace,
                ifindex: link.ifindex,
                attachment: device.capture.authority.attachment_generation,
                mark: MarkProvenance::BeforeSkb,
            };
            let (realm, owners) = capture_realm(
                link.mtu,
                realm_count,
                scope_bulk_frames,
                usize::from(datapath.effective_workers()).min(device.info.queues.len()),
                &budget,
            )?;
            realm.install_admission_fence(Arc::clone(&admission))?;
            realms.push((ingress, device_index, link, realm.scope()));
            workers.placements.lock().push(worker::Placement {
                realm: realm.clone(),
                ingress,
                device: device_index,
                link,
            });
            scope_pairs.push((realm, owners));
        }
    }
    #[cfg(feature = "ebpf")]
    let host = match host {
        Some((host, (scope, owner))) => {
            scope_pairs.push((PacketRealm::singleton(scope)?, vec![owner]));
            Some(host)
        }
        None => None,
    };
    #[cfg(feature = "ebpf")]
    let host_observation = host.as_ref().map(PreparedHost::observation);
    #[cfg(not(feature = "ebpf"))]
    let host_observation = None;
    let diagnostics = diagnostics(&devices, &budget, host_observation)?;
    *workers.diagnostics.lock() = Some(Arc::clone(&diagnostics));
    tracing::debug!(used = budget.used(), "XDP prepare: after diagnostics");
    let ingresses: Vec<_> = realms.iter().map(|(ingress, ..)| *ingress).collect();
    let core = if let Some(authority) = authority {
        let mut core = RoutedCore::new(
            authority,
            &ingresses,
            Requirements {
                execution: Execution::MixedEndpoints,
                nat: !datapath.nat.is_empty(),
                native_continuation: false,
                kernel_firewall: false,
                qdisc: false,
                skb_classification: false,
            },
            Arc::clone(&budget),
        )?;
        let bindings: Vec<_> = realms
            .iter()
            .map(|(ingress, device, _, facts)| IngressBinding {
                ingress: *ingress,
                role: datapath.interfaces[*device].role,
                facts: *facts,
            })
            .collect();
        core.set_ingress_bindings(&bindings)?;
        core.prepare_fragment_peers()?;
        Some(core)
    } else {
        None
    };
    Ok(PreparedRuntime {
        devices,
        topology,
        #[cfg(feature = "ebpf")]
        host,
        realms,
        scope_pairs,
        workers,
        inboxes,
        core,
        memory,
        staging: vec![0; max_mtu.max(65536)],
        links,
        polling_prefix,
        polling_budget: budget,
        diagnostics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    mod driven_kernel;
    mod retention;

    #[test]
    fn native_guard_observation_failure_never_skips_xsk_withdrawal() {
        for failure in [
            "strict precheck",
            "already invalidated",
            "post-ACK observation",
        ] {
            let mut calls = Vec::new();
            let result = close_device_capture_with(
                &mut calls,
                |calls| {
                    calls.push("guard");
                    Err(io::Error::new(io::ErrorKind::PermissionDenied, failure))
                },
                |calls| {
                    calls.push("XSK withdrawal");
                    Err(io::Error::other("injected XSK withdrawal failure"))
                },
            );
            let message = result.unwrap_err().to_string();
            assert!(message.contains(failure));
            assert!(message.contains("injected XSK withdrawal failure"));
            assert_eq!(calls, ["guard", "XSK withdrawal"]);
        }
    }

    #[test]
    fn capture_close_folds_later_errors_without_losing_original_cause() {
        let mut failure = None;
        fold_capture_result(
            &mut failure,
            Err(io::Error::from_raw_os_error(libc::EPERM).into()),
        );
        fold_capture_result(&mut failure, Ok(()));
        for stage in ["XSK withdrawal", "private seal", "post-guard grace"] {
            fold_capture_result(&mut failure, Err(anyhow::anyhow!(stage)));
        }
        let error = failure.unwrap();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::EPERM)
        );
        let message = format!("{error:#}");
        for stage in ["XSK withdrawal", "private seal", "post-guard grace"] {
            assert!(message.contains(stage));
        }
    }

    #[test]
    fn pressure_deadline_ends_after_the_recovery_sample() {
        let start = Instant::now();
        let mut pressure = Pressure::new(start);
        assert_eq!(pressure.next_deadline(None), None);
        pressure.counters.capture_rejected = 1;
        assert_eq!(
            pressure.next_deadline(None),
            None,
            "diagnostics do not drive polling"
        );
        pressure.counters.refused = true;
        assert_eq!(
            pressure.next_deadline(None),
            Some(start + Duration::from_secs(1))
        );
        assert!(!pressure.sample(
            start + Duration::from_secs(1) - Duration::from_nanos(1),
            None,
            0,
            0,
            0,
        ));
        assert_eq!(pressure.checked, start);
        assert!(pressure.counters.refused);
        assert!(pressure.sample(start + Duration::from_secs(1), None, 0, 0, 0));
        assert!(!pressure.sample(start + Duration::from_secs(1), None, 0, 0, 0));
        assert!(pressure.active);
        assert_eq!(
            pressure.next_deadline(None),
            Some(start + Duration::from_secs(2))
        );
        assert!(pressure.sample(start + Duration::from_secs(2), None, 0, 0, 0));
        assert!(!pressure.active);
        assert_eq!(pressure.next_deadline(None), None);
        pressure.core.core_capacity = u64::MAX;
        assert!(
            !pressure.refusing(pressure.core),
            "a saturated historic counter is not new work"
        );
    }

    #[test]
    fn qinq_realms_share_capacity_and_release_their_complete_budget() {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let scopes: Vec<_> = (0..6)
            .map(|_| capture_scope(1500, 6, 256, &budget).unwrap())
            .collect();
        drop(scopes);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn sg_l3_and_vlan_output_keep_exact_bytes() {
        let path = ReturnPath {
            device: 0,
            mac: [2; 6],
            vlan_tci: [0xa00c, 34],
            vlan_proto: [0x88a8, 0x8100],
            vlan_count: 2,
        };
        let header = return_header(path, [4; 6], 2, true).unwrap();
        let length = header.len();
        assert_eq!(length, 22);
        assert_eq!(
            &header[12..],
            &[0x88, 0xa8, 0xa0, 12, 0x81, 0, 0, 34, 0x86, 0xdd]
        );
        let payload = [7u8; 9000];
        let mut a = [0; 4096];
        let mut b = [0; 4096];
        let mut c = [0; 830];
        fill_output(&mut [&mut a, &mut b, &mut c], &header, &payload).unwrap();
        let packet = DecodedPacket {
            frame_len: length + payload.len(),
            l3_offset: length,
            l3_len: payload.len(),
            source_mac: [4; 6],
            destination_mac: [2; 6],
            ether_type: 0x86dd,
            vlan_tci: path.vlan_tci,
            vlan_proto: path.vlan_proto,
            vlan_count: 2,
            inline_vlan_count: 2,
        };
        let mut slices = [&[][..]; 18];
        let segments = [&a[..], &b[..], &c[..]];
        let count = l3_segments(&segments, packet, &mut slices).unwrap();
        let view = PacketView::new(&slices[..count]).unwrap();
        assert_eq!(view.len(), payload.len());
        view.visit(0..view.len(), |bytes| {
            assert!(bytes.iter().all(|byte| *byte == 7))
        })
        .unwrap();
        assert!(fill_output(&mut [&mut a[..8]], &header, &payload).is_err());
    }

    #[tokio::test]
    async fn cleared_stale_readiness_arms_the_next_wake() {
        let (reader, writer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.set_nonblocking(true).unwrap();
        // SAFETY: the socket keeps its descriptor unchanged until deregistration.
        let reader = unsafe { AsyncFd::register(reader) }
            .map_err(io::Error::from)
            .unwrap();
        writer.send(b"drained").unwrap();
        // A previous pass consumed the packet whose event is still cached as Ready.
        reader.readable().await.unwrap().retain_ready();
        assert_eq!(reader.get_ref().recv(&mut [0; 16]).unwrap(), 7);
        let (armed, waiting) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            let mut armed = Some(armed);
            poll_fn(|cx| {
                arm_read(&reader, cx).unwrap();
                match reader.get_ref().recv(&mut [0; 16]) {
                    Ok(_) => Poll::Ready(()),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if let Some(armed) = armed.take() {
                            let _ = armed.send(());
                        }
                        Poll::Pending
                    }
                    Err(error) => panic!("unexpected receive failure: {error}"),
                }
            })
            .await;
        });
        waiting.await.unwrap();
        writer.send(b"next").unwrap();
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("the next packet must wake the owner parked after an empty pass")
            .unwrap();
    }
}
