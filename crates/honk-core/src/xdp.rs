//! One Linux capture owner for every selected RX queue and one routing domain.
//! Physical links are owned by FDs: exit detaches them and the kernel resumes forwarding; UMEM stays until exit.

mod aux_tasks;
pub(crate) mod gateway;
#[cfg(feature = "ebpf")]
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

// Boxing retained owners would allocate on the packet output path.
#[allow(clippy::large_enum_variant)]
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
    fn register(self) -> (Self, io::Result<()>) {
        let Self::Prepared(port) = self else {
            return (self, Ok(()));
        };
        // SAFETY: the socket stays owned until this registration is consumed.
        match unsafe { AsyncFd::register(port) } {
            Ok(io) => (Self::Registered(io), Ok(())),
            Err(error) => {
                let (port, error) = error.into_parts();
                (Self::Prepared(port), Err(error))
            }
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

impl ReturnPath {
    pub(crate) fn same_identity(self, other: Self) -> bool {
        self.realm == other.realm
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

fn diagnostics(devices: &[Device], budget: &Arc<MemoryBudget>) -> io::Result<Arc<Diagnostics>> {
    Diagnostics::new(
        budget,
        devices.iter().map(|device| device.queues.len()).sum(),
        devices.iter().flat_map(|device| {
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
        }),
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
        if path.realm != self.realm_id
            || !self.members.contains(&path.device)
            || (self.members.len() == 1 && physical_ifindex != self.link.path.physical_ifindex)
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

    fn transmit_cpu_outputs(
        &mut self,
        port: &mut Port<Retained>,
        class: TxClass,
        physical_ifindex: u32,
        pending_path: Option<ReturnPath>,
        outputs: &mut [Option<OutputLease>],
    ) -> io::Result<bool> {
        let singleton = outputs.len() == 1;
        for output in outputs {
            let output = output.take().expect("selected Endpoint output");
            let Some(path) =
                pending_path.or_else(|| output.peer_hold().and_then(|hold| hold.path()))
            else {
                continue;
            };
            let header =
                self.output_header(path, physical_ifindex, output.packet()[0] >> 4 == 6)?;
            let length = header.len() + output.packet().len();
            if singleton && !port.tx_packet_credit(class, length) {
                self.pending[usize::from(class == TxClass::Bulk)] = Some((output, path));
                return Ok(false);
            }
            port.transmit_with(
                class,
                length,
                Retained::Endpoint(output.into_owner()),
                |owner, target| {
                    let Retained::Endpoint(owner) = owner else {
                        return Err(io::Error::other("wrong Endpoint TX owner"));
                    };
                    let packet = owner
                        .packet()
                        .ok_or_else(|| io::Error::other("missing Endpoint CPU packet"))?;
                    fill_output(target, &header, packet)
                },
            )?;
        }
        Ok(true)
    }

    fn generate_output(
        &mut self,
        now: Instant,
        class: TxClass,
        physical_ifindex: u32,
        #[cfg(test)] peers: &[Peer],
        frame: &mut [u8],
        attempt: &mut GeneratedAttempt,
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
        let output = match self.driver.materialize_into(now, class, l3)? {
            MaterializedOutput::Idle => return Ok(None),
            MaterializedOutput::Closed => {
                *attempt = GeneratedAttempt::Closed;
                return Ok(None);
            }
            MaterializedOutput::CpuQueuePending => {
                *attempt = GeneratedAttempt::CpuQueuePending;
                return Ok(None);
            }
            MaterializedOutput::Packet(output) => output,
        };
        *attempt = GeneratedAttempt::Emitted;
        let owner = output.owner;
        let path = output.path;
        // Plain scope fixtures supply their own peers without a physical peer hold.
        #[cfg(test)]
        let path = path.or_else(|| peer_return_path(peers, owner.scope(), output.destination));
        let Some(path) = path else {
            return Ok(None);
        };
        let header = self.output_header(path, physical_ifindex, output.ipv6)?;
        if header.len() != l2_len {
            return Err(io::Error::other("generated Endpoint header length changed"));
        }
        l2.copy_from_slice(&header);
        Ok(Some((l2_len + owner.len(), Retained::Endpoint(owner))))
    }
}

fn service_generated_output(
    realm: &mut Realm,
    port: &mut Port<Retained>,
    cx: &mut Context<'_>,
    now: Instant,
    class: TxClass,
    ifindex: u32,
    endpoints: &PacketEndpoints,
) -> anyhow::Result<(usize, bool)> {
    let class_index = usize::from(class == TxClass::Bulk);
    let (_, max_length) = realm.generated.expect("eligible generated Endpoint output");
    let mut outputs = None;
    let mut serviced = 0;
    while serviced < BATCH {
        let mut no_credit = false;
        if realm.pending[class_index].is_none() {
            let mut attempt = GeneratedAttempt::Idle;
            match port.transmit_generated(class, max_length, |frame| {
                realm.generate_output(
                    now,
                    class,
                    ifindex,
                    #[cfg(test)]
                    &[],
                    frame,
                    &mut attempt,
                )
            }) {
                Ok(_) => match attempt {
                    GeneratedAttempt::Emitted => {
                        serviced += 1;
                        continue;
                    }
                    GeneratedAttempt::Idle => break,
                    GeneratedAttempt::Closed => {
                        ensure!(
                            endpoints.is_closing(),
                            "XDP packet scope ended before endpoint close"
                        );
                        break;
                    }
                    GeneratedAttempt::CpuQueuePending => {}
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => no_credit = true,
                Err(error) => return Err(error.into()),
            }
        }
        // A conservative zero still needs a singleton check for the oldest CPU packet.
        let capacity = port.tx_packet_capacity(class)?;
        let outputs = outputs.get_or_insert_with(|| std::array::from_fn::<_, BATCH, _>(|_| None));
        let (selected, pending_path) =
            realm.poll_outputs(cx, class, capacity, &mut outputs[..BATCH - serviced]);
        let count = match selected {
            Poll::Ready(Some(count)) => count,
            Poll::Ready(None) if !endpoints.is_closing() => {
                anyhow::bail!("XDP packet scope ended before endpoint close");
            }
            _ => return Ok((serviced, no_credit)),
        };
        if !realm.transmit_cpu_outputs(port, class, ifindex, pending_path, &mut outputs[..count])? {
            return Ok((serviced, true));
        }
        serviced += count;
    }
    Ok((serviced, false))
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

fn service_member_output(
    realm: &mut Realm,
    cx: &mut Context<'_>,
    endpoints: &PacketEndpoints,
    mut submit: impl FnMut(&Realm, TxClass, ReturnPath, OutputLease) -> io::Result<Option<OutputLease>>,
) -> anyhow::Result<usize> {
    let mut serviced = 0;
    for (index, class) in [TxClass::Control, TxClass::Bulk].into_iter().enumerate() {
        for _ in 0..BATCH {
            let mut outputs = [None];
            let (selected, retained_path) = realm.poll_outputs(cx, class, 1, &mut outputs);
            match selected {
                Poll::Ready(Some(1)) => {}
                Poll::Ready(None) if !endpoints.is_closing() => {
                    anyhow::bail!("XDP packet scope ended before endpoint close")
                }
                _ => break,
            }
            let output = outputs[0].take().expect("one selected Endpoint output");
            let Some(path) =
                retained_path.or_else(|| output.peer_hold().and_then(|hold| hold.path()))
            else {
                serviced += 1;
                continue;
            };
            if let Some(output) = submit(realm, class, path, output)? {
                realm.pending[index] = Some((output, path));
                break;
            }
            serviced += 1;
        }
    }
    Ok(serviced)
}

fn submit_member_output(
    realm: &Realm,
    port: &mut Port<Retained>,
    ifindex: u32,
    class: TxClass,
    path: ReturnPath,
    output: OutputLease,
) -> io::Result<Option<OutputLease>> {
    let header = realm.output_header(path, ifindex, output.packet()[0] >> 4 == 6)?;
    let length = header.len() + output.packet().len();
    if !port.tx_packet_credit(class, length) {
        return Ok(Some(output));
    }
    port.transmit_with(
        class,
        length,
        Retained::Endpoint(output.into_owner()),
        |owner, target| {
            let Retained::Endpoint(owner) = owner else {
                return Err(io::Error::other("wrong Endpoint output owner"));
            };
            fill_output(
                target,
                &header,
                owner
                    .packet()
                    .ok_or_else(|| io::Error::other("missing Endpoint CPU packet"))?,
            )
        },
    )?;
    Ok(None)
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
                #[cfg(feature = "ebpf")]
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
                backend
                    .write()
                    .await
                    .userspace_mut()?
                    .install_gateway(None)?;
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

    fn poll_io(
        &mut self,
        cx: &mut Context<'_>,
        interval: Option<&BusyInterval>,
        shutdown: &crate::control::ShutdownIntent,
        reading: bool,
    ) -> Poll<anyhow::Result<()>> {
        let result = self.poll_io_turn(cx, interval, shutdown, reading);
        if matches!(result, Poll::Ready(Err(_))) {
            // All generated realms began before RX; an early device error can skip their TX pass.
            for realm in &mut self.realms {
                realm.driver.interrupt_turn(cx);
            }
        }
        result
    }

    fn poll_io_turn(
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
        let mut now = Instant::now();
        let mut queue_zero_batch = BATCH;
        if !self.closing {
            if !self.admission.load(Ordering::Acquire) {
                if let Some(error) = self
                    .gateway
                    .as_deref()
                    .and_then(GatewayPublisher::capture_error)
                {
                    return Poll::Ready(Err(error.into()));
                }
                return Poll::Ready(Err(anyhow::anyhow!("XDP publication admission closed")));
            }
            let readable =
                arm_read(&self.topology, cx).inspect_err(|_| self.topology_lost = true)?;
            // A Core queue-zero RX callback can submit a cached decision without visiting resolve().
            let full = readable
                || (self.core.is_some()
                    && self.devices.iter().any(|device| {
                        device.queues.first().is_some_and(|queue| {
                            queue.id == 0 && queue.io.get_ref().has_pending_rx()
                        })
                    }));
            if self.core.is_some() && !full {
                // RX arriving after this sample is still in the ring for the next checked turn.
                queue_zero_batch = 0;
            }
            if full || (!self.devices.is_empty() && now >= self.link_check_at) {
                let event = if full {
                    current_topology(
                        &mut self.topology,
                        self.gateway.as_deref(),
                        &self.devices,
                        &mut self.topology_lost,
                    )
                } else {
                    verify_link_fds(self.gateway.as_deref(), &self.devices)
                        .map(|()| TopologyEvent::Quiet)
                };
                match event {
                    Ok(TopologyEvent::AddressDirty) => {
                        if let Err(error) = self.refresh_local_addresses() {
                            for device in &mut self.devices {
                                device.vlan_offload.abandon();
                            }
                            return Poll::Ready(Err(error));
                        }
                    }
                    Ok(TopologyEvent::Quiet) => {}
                    Err(error) => {
                        self.topology_lost = true;
                        for device in &mut self.devices {
                            device.vlan_offload.abandon();
                        }
                        return Poll::Ready(Err(if full {
                            error.into()
                        } else {
                            anyhow::Error::new(error).context(STANDBY_LINK_CHECK)
                        }));
                    }
                }
                now = Instant::now();
                self.link_check_at = now + LINK_CHECK_INTERVAL;
            }
            self.maintain_gateway(now)?;
        }
        let mut progress = self.poll_handoffs(cx, now)?;
        self.round_cut_short = false;
        let deadline = interval.and_then(|_| self.next_deadline(now, !reading));
        for realm in &mut self.realms {
            if !self.closing && realm.generated.is_some() {
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
                        device.queue_maps.metadata_failures()
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
                if self.closing {
                    continue;
                }
                let mut backpressure = None;
                let (received, kick) = port.transmit_batch(|port| {
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
                    let limit = if queue.id == 0 { queue_zero_batch } else { BATCH };
                    let received = worker::receive_batch(port, limit, metadata_len, |batch, segments, metadata, same_port| {
                        if failure.is_some() { return; }
                        let capture_metadata = if capture.vlan_metadata {
                            &metadata[..METADATA_LEN.min(metadata.len())]
                        } else { &[] };
                        let Ok(decoded) = capture.decode(segments, capture_metadata, queue.id) else {
                            pressure.capture_rejected = pressure.capture_rejected.saturating_add(1);
                            batch.take();
                            return;
                        };
                        if decoded.destination_mac[0] & 1 != 0 { batch.take(); return; }
                        let Some(realm) = realms.iter().find(|realm| realm.members.contains(&device_index) && realm.link.path.vlan_count == decoded.vlan_count
                            && realm.link.path.vlan_proto == decoded.vlan_proto && realm.link.path.vlan_tci.iter().zip(decoded.vlan_tci).all(|(configured, captured)| configured & 0x0fff == captured & 0x0fff)) else { batch.take(); return; };
                        if decoded.destination_mac != realm.link.mac { batch.take(); return; }
                        let scope = realm.driver.scope();
                        let ingress = realm.ingress;
                        let path = ReturnPath { realm: realm.realm_id, device: device_index, mac: decoded.source_mac, vlan_tci: decoded.vlan_tci, vlan_proto: decoded.vlan_proto, vlan_count: decoded.vlan_count };
                        let mut l3 = [&[][..]; 18];
                        let Some(count) = l3_segments(segments, decoded, &mut l3) else { batch.take(); return; };
                        let Ok(view) = PacketView::new(&l3[..count]) else { batch.take(); return; };
                        if let Some(core) = core && !retained_endpoint(endpoints, scope, view) {
                            let cached = if queue.id != 0 { Ok(CachedDecision::Cold) } else { core.forward_cached(ingress, view, Some(decoded.source_mac), now, |route, output| {
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
                                            waiting.push_back(Waiting { packet, mac: path.mac, retry: now, scope, ingress_worker: 0, path, ingress_at, cell: None, peer });
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
                        let result = (|| {
                            let Some(owner) = realm.driver.sole_owner() else {
                                let physical = endpoints.realm(scope).ok_or_else(|| io::Error::other("unregistered physical realm"))?;
                                return workers.physical_endpoint(batch, endpoints, physical, 0, ingress, &l3[..count], view, staging, (now, Instant::now()), path, core.is_some());
                            };
                            let bytes = if count == 1 { l3[0] } else {
                                batch.take();
                                if decoded.l3_len > staging.len() || view.copy_to(0..decoded.l3_len, &mut staging[..decoded.l3_len]).is_none() { return Ok(PacketReceive::default()); }
                                &staging[..decoded.l3_len]
                            };
                            if matches!(wire::parse_ip(bytes), Err(wire::ParseError::Fragment)) {
                                batch.take();
                                return workers.endpoint_fragment(endpoints, scope, bytes, now, path);
                            }
                            // Keep the scalar pre-lock timestamp even when batch admission falls back.
                            let service_at = Instant::now();
                            if core.is_none() && count == 1
                                && let Some(report) = workers.established(batch, owner, bytes, (now, service_at), path, endpoints)
                            {
                                return Ok(report);
                            }
                            batch.take();
                            workers.receive(endpoints, owner, bytes, now, service_at, path, None)
                        })();
                        match result {
                            Ok(report) if report.qualified_rx => qualify_packet(qualified_rx, qualification_unavailable),
                            Ok(_) => {}
                            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory) => {}
                            Err(error) => { batch.take(); failure = Some(error.into()); }
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
        for realm in &mut self.realms {
            if !self.closing && realm.generated.is_none() && realm.driver.service(cx, now) {
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
            if self.closing {
                progress += usize::from(realm.driver.service_closing(cx, now));
                finalized[realm_index] = true;
                continue;
            }
            if realm.members.len() > 1 {
                let devices = &mut self.devices;
                progress += service_member_output(
                    realm,
                    cx,
                    &self.endpoints,
                    |realm, class, path, output| {
                        let device = devices
                            .get_mut(path.device)
                            .ok_or_else(|| io::Error::other("retained output member missing"))?;
                        let ifindex = device.info.ifindex;
                        let queue = device
                            .queues
                            .first_mut()
                            .ok_or_else(|| io::Error::other("retained output queue missing"))?;
                        submit_member_output(
                            realm,
                            queue.io.get_mut(),
                            ifindex,
                            class,
                            path,
                            output,
                        )
                    },
                )?;
                self.tx_realm = (realm_index + 1) % realm_count;
                continue;
            }
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
                    if realm.generated.is_some() {
                        let (count, blocked) = service_generated_output(
                            realm,
                            port,
                            cx,
                            now,
                            class,
                            ifindex,
                            &self.endpoints,
                        )?;
                        serviced += count;
                        if blocked {
                            self.pressure.counters.tx_credit =
                                self.pressure.counters.tx_credit.saturating_add(1);
                            self.pressure.counters.refused = true;
                        }
                        continue;
                    }
                    let mut considered = 0;
                    while considered < BATCH {
                        let capacity = port.tx_packet_capacity(class)?;
                        let (selected, pending_path) = realm.poll_outputs(
                            cx,
                            class,
                            capacity,
                            &mut outputs[..BATCH - considered],
                        );
                        let count = match selected {
                            Poll::Ready(Some(count)) => count,
                            Poll::Ready(None) if !self.endpoints.is_closing() => {
                                anyhow::bail!("XDP packet scope ended before endpoint close");
                            }
                            _ => break,
                        };
                        considered += count;
                        if !realm.transmit_cpu_outputs(
                            port,
                            class,
                            ifindex,
                            pending_path,
                            &mut outputs[..count],
                        )? {
                            self.pressure.counters.tx_credit =
                                self.pressure.counters.tx_credit.saturating_add(1);
                            self.pressure.counters.refused = true;
                            break;
                        }
                        serviced += count;
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
        current_topology(
            &mut self.topology,
            self.gateway.as_deref(),
            &self.devices,
            &mut self.topology_lost,
        )?;
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
                        work.ingress_worker,
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
            let decision = core.decide(read, work.packet, Some(work.mac), now)?;
            current_topology(
                &mut self.topology,
                self.gateway.as_deref(),
                &self.devices,
                &mut self.topology_lost,
            )?;
            match decision {
                Decision::Wait(packet) => self.waiting.push_back(Waiting {
                    packet,
                    retry: now + Duration::from_millis(10),
                    mac: work.mac,
                    scope: work.scope,
                    ingress_worker: work.ingress_worker,
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
                            work.ingress_worker,
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
                    current_topology(
                        &mut self.topology,
                        self.gateway.as_deref(),
                        &self.devices,
                        &mut self.topology_lost,
                    )?;
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
            current_topology(
                &mut self.topology,
                self.gateway.as_deref(),
                &self.devices,
                &mut self.topology_lost,
            )?;
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
            current_topology(
                &mut self.topology,
                self.gateway.as_deref(),
                &self.devices,
                &mut self.topology_lost,
            )?;
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

#[cfg(test)]
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

/// Tokio takes the reader waker when it delivers readiness and a cached Ready installs none,
/// so a single clear can park an empty pass with nothing to wake it. Pending registers this
/// task (or schedules a coop-budget continuation) before the caller drains.
fn arm_read<T: AsRawFd>(io: &AsyncFd<T>, cx: &mut Context<'_>) -> io::Result<bool> {
    let mut readable = false;
    while let Poll::Ready(ready) = io.poll_read_ready(cx) {
        ready?.clear_ready();
        readable = true;
    }
    Ok(readable)
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
                backend
                    .userspace_mut()?
                    .install_gateway(Some(Arc::clone(publisher)))?;
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
                backend.userspace_mut()?.activate_gateway_start(
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

#[cold]
fn device_sizing(mtu: u32) -> (PortConfig, usize) {
    queue_sizing(mtu, 0, 0)
}

#[cold]
fn queue_sizing(mtu: u32, eligible_queues: usize, remaining: usize) -> (PortConfig, usize) {
    const RX_TIER: usize = 512;
    // Two VLAN tags bound TX extent; RX keeps its independent SG admission.
    let single_frame = usize::try_from(mtu)
        .ok()
        .and_then(|mtu| mtu.checked_add(22))
        .is_some_and(|length| length <= FRAME_SIZE);
    // Leave the stack half untouched and screen for UMEM plus per-queue bookkeeping.
    // The real reservations in Port::open_device remain authoritative.
    let (rx_frames, bulk_frames, ring_size, scope_bulk_frames) = if !single_frame {
        (256, 224, 256, 128)
    } else if (1..=8).contains(&eligible_queues)
        && remaining.saturating_sub(CAPTURE_MEMORY / 2)
            >= eligible_queues * 2 * (RX_TIER + 32 + 480) * FRAME_SIZE
    {
        (RX_TIER, 480, 1024, CAPTURE_WIDE_BULK_FRAMES)
    } else {
        (256, 480, 512, CAPTURE_WIDE_BULK_FRAMES)
    };
    (
        PortConfig {
            rx_frames,
            control_frames: 32,
            bulk_frames,
            ring_size,
        },
        scope_bulk_frames,
    )
}

fn member_admission_issues(
    info: &DeviceInfo,
    port_config: PortConfig,
    requested_mode: Option<BindMode>,
    metadata_len: usize,
    absent: io::Result<bool>,
) -> [Option<(&'static str, String)>; 2] {
    let mode = select_xsk_mode(info, requested_mode, port_config, metadata_len)
        .err()
        .map(|error| ("xsk_mode", error.to_string()));
    let attachment = match absent {
        Ok(true) => None,
        Ok(false) => Some((
            "foreign_xdp",
            "XDP interface already has a foreign attachment; explicit operator cleanup is required"
                .into(),
        )),
        Err(error) => Some(("xdp_readback", error.to_string())),
    };
    [mode, attachment]
}

fn layout_admission_issues(error: &io::Error) -> [(&'static str, String); 2] {
    [
        ("capture_layout", error.to_string()),
        ("NOT_CHECKED", "member mode, foreign XDP, workers, logical MTU, uplink and topology checks depend on capture_layout".into()),
    ]
}

fn admission_failure(issues: &[(&'static str, String, String)], omitted: usize) -> String {
    use std::fmt::Write as _;
    let mut message = String::from("XDP startup admission failed");
    for (reason, device, details) in issues {
        let _ = write!(message, "\nreason={reason} device={device}: {details}");
    }
    if omitted != 0 {
        let _ = write!(message, "\nomitted={omitted}");
    }
    message
}

fn gateway_time_namespace_issue(
    offset: anyhow::Result<Option<i128>>,
) -> Option<(&'static str, String)> {
    let details = match offset {
        Ok(None | Some(0)) => return None,
        Ok(Some(offset)) => format!("nonzero monotonic namespace offset: {offset} ns"),
        Err(error) => format!("{error:#}"),
    };
    Some(("time_namespace_offset", details))
}

fn realm_worker_count(workers: usize, queues: impl Iterator<Item = usize>) -> usize {
    workers.min(queues.min().unwrap_or(0))
}

fn direct_relay_eligible(
    direct: Option<DirectProfile>,
    workers: u8,
    owners: usize,
    members: usize,
    physical: bool,
) -> bool {
    direct == Some(DirectProfile::Endpoint)
        && (1..=2).contains(&workers)
        && owners == usize::from(workers)
        && members == 1
        && physical
}

async fn prepare(
    plane: &ControlPlane,
    config: &Config,
    admission: Arc<AtomicBool>,
) -> anyhow::Result<PreparedRuntime> {
    let datapath = config
        .datapath
        .as_ref()
        .context("XDP configuration missing")?;
    let mut issues: Vec<(&'static str, String, String)> = Vec::with_capacity(256);
    let mut omitted = 0usize;
    let mut record = |reason: &'static str, device: &str, details: String| {
        if issues.len() < 256 {
            issues.push((reason, device.to_owned(), details));
        } else {
            omitted += 1;
        }
    };
    if let Err(error) = validate_config(config) {
        record("configuration", "capture", format!("{error:#}"));
    }
    let metadata_len = METADATA_LEN;
    let requested_mode = match datapath.effective_xsk_mode() {
        XskMode::Auto => None,
        XskMode::Copy => Some(BindMode::Copy),
        XskMode::ZeroCopy => Some(BindMode::ZeroCopy),
    };
    let plan = match CapturePlan::discover(&datapath.interfaces) {
        Ok(plan) => Some(plan),
        Err(error) => {
            for (reason, details) in layout_admission_issues(&error) {
                record(reason, "capture", details);
            }
            None
        }
    };
    let auxiliary_interfaces = || {
        datapath
            .interfaces
            .iter()
            .filter(|port| port.role == honk_config::datapath::InterfaceRole::L3Lan)
    };
    let lan_count = auxiliary_interfaces().count();
    let host_ports = datapath
        .host
        .as_ref()
        .map_or(&[][..], |host| host.interfaces.as_slice());
    let has_host = !host_ports.is_empty();
    let aux_count = lan_count + host_ports.len();
    let gateway_enabled = datapath.direct == Some(DirectProfile::Endpoint)
        && (has_host || !datapath.interfaces.is_empty());
    if gateway_enabled
        && let Some((reason, details)) =
            gateway_time_namespace_issue(timens::monotonic_namespace_offset())
    {
        record(reason, "namespace", details);
    }
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let dns_projection = datapath.effective_dns_projection();
    let mut zones = if gateway_enabled {
        match ZoneAdmission::read(&budget, dns_projection) {
            Ok(zones) => Some(zones),
            Err(error) => {
                record("conntrack_zones", "namespace", error.to_string());
                None
            }
        }
    } else {
        None
    };
    let conntrack = if gateway_enabled && plan.as_ref().is_some_and(|p| !p.members().is_empty()) {
        match honk_xsk::ConntrackKfuncs::read() {
            Ok(conntrack) => Some(Arc::new(conntrack)),
            Err(error) => {
                record("conntrack_btf", "namespace", error.to_string());
                None
            }
        }
    } else {
        None
    };
    let infos: Vec<_> = plan
        .as_ref()
        .map(|plan| {
            plan.members()
                .iter()
                .map(|member| member.info.clone())
                .collect()
        })
        .unwrap_or_default();
    let eligible_queues = match infos.as_slice() {
        [device]
            if gateway_enabled
                && requested_mode == Some(BindMode::ZeroCopy)
                && plan.as_ref().is_some_and(|plan| plan.realms().len() == 1) =>
        {
            device.queues.len()
        }
        _ => 0,
    };
    let physical_config = |mtu| {
        queue_sizing(
            mtu,
            eligible_queues,
            budget.limit().saturating_sub(budget.used()),
        )
        .0
    };
    let topology = if let Some(plan) = &plan {
        if gateway_enabled
            && !plan.members().is_empty()
            && let Err(error) = plan.check_gateway_defaults()
        {
            record("gateway_uplink", "namespace", error.to_string());
        }
        if let Err(error) = worker::admit(datapath.effective_workers(), &infos) {
            record("workers", "capture", format!("{error:#}"));
        }
        for info in &infos {
            for (reason, details) in member_admission_issues(
                info,
                physical_config(info.mtu),
                requested_mode,
                metadata_len,
                honk_xsk::xdp_absent(info.ifindex),
            )
            .into_iter()
            .flatten()
            {
                record(reason, &info.name, details);
            }
        }
        for realm in plan.realms().iter().filter(|realm| realm.mtu < 1280) {
            record(
                "logical_mtu",
                &realm.name,
                "logical MTU must be at least 1280".into(),
            );
        }
        match CaptureTopology::admit(plan, &budget) {
            Ok(topology) => Some(topology),
            Err(error) => {
                record("capture_topology", "capture", error.to_string());
                None
            }
        }
    } else {
        None
    };
    let realm_count = plan.as_ref().map_or(0, |plan| plan.realms().len());
    if plan.is_some() && !(1..=64).contains(&(realm_count + aux_count)) {
        record(
            "realm_capacity",
            "capture",
            "logical capture realm capacity exceeded".into(),
        );
    }
    let plan_memory = if let Some(plan) = &plan {
        match budget.reserve(plan.memory_bytes()) {
            Some(memory) => Some(memory),
            None => {
                record(
                    "capture_budget",
                    "capture",
                    "capture plan memory capacity".into(),
                );
                None
            }
        }
    } else {
        None
    };
    let extent = infos
        .iter()
        .map(|info| info.mtu as usize + 22 + metadata_len)
        .max()
        .unwrap_or(65536);
    let workers = if plan.is_some() {
        match worker::Shared::new(
            datapath.effective_workers(),
            extent,
            infos.iter().map(|info| info.queues.len()).sum(),
            &budget,
            Arc::clone(&admission),
        ) {
            Ok(workers) => Some(workers),
            Err(error) => {
                record(
                    "capture_budget",
                    "capture",
                    format!("worker handoff: {error:#}"),
                );
                None
            }
        }
    } else {
        None
    };
    let fib = (|| -> anyhow::Result<_> {
        let namespace = if has_host {
            crate::control::probe_socket_marks(config.global.effective_so_mark())?
        } else {
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
            socket_namespace(socket.as_fd())?
        };
        let mut links = Fib::new(&budget, namespace)?;
        links.synchronize()?;
        Ok((namespace, links))
    })();
    if let Err(error) = &fib {
        record("local_addresses", "namespace", format!("{error:#}"));
    }
    let max_mtu = infos.iter().map(|info| info.mtu).max().unwrap_or(65535) as usize;
    let memory = if plan.is_some() {
        let bytes = max_mtu
            + 65536
            + size_of::<Runtime>()
            + size_of::<CaptureTopology>()
            + aux_count
                * (size_of::<tcx_aux::PreparedAux>()
                    + size_of::<(PacketRealm, Vec<crate::control::netstack::PacketOwner>)>())
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
                .sum::<usize>();
        match budget.reserve(bytes) {
            Some(memory) => Some(memory),
            None => {
                record(
                    "capture_budget",
                    "capture",
                    "metadata and staging memory capacity".into(),
                );
                None
            }
        }
    } else {
        None
    };
    if !issues.is_empty() {
        anyhow::bail!(admission_failure(&issues, omitted));
    }
    let plan = plan.context("capture layout was not checked")?;
    let plan_memory = plan_memory.context("capture plan budget was not checked")?;
    let memory = memory.context("capture metadata budget was not checked")?;
    let (workers, inboxes) = workers.context("capture workers were not checked")?;
    let realm_keys = plan.realm_keys();
    let mut placements = worker::Placements::new(realm_keys.len(), &budget)?;
    let (namespace, links) = fib?;
    let topology = topology.context("capture topology was not checked")?;
    // SAFETY: the watcher keeps its descriptor until AsyncFd drops it.
    let topology = unsafe { AsyncFd::register(topology) }.map_err(io::Error::from)?;
    let polling_prefix = ContextDigest::platform(&budget);
    tracing::debug!(
        used = budget.used(),
        limit = budget.limit(),
        realm_count,
        "XDP prepare: after metadata reservation"
    );
    let routing_scope = ScopeId::allocate().context("XDP routing domain exhausted")?;
    let mut realms = Vec::with_capacity(realm_count);
    let mut scope_pairs = Vec::with_capacity(realm_count + aux_count);
    let mut auxiliary = Vec::with_capacity(aux_count);
    if aux_count != 0 {
        ensure!(
            realm_keys.len() + aux_count
                <= honk_ebpf_common::xdp_gateway::GATEWAY_REALM_CAPACITY as usize,
            "physical and auxiliary capture keys exceed the gateway realm table"
        );
        let private_names = (0..lan_count)
            .map(tcx_aux::PreparedAux::device_name)
            .chain((0..host_ports.len()).map(tcx_aux::PreparedAux::host_device_name));
        for name in private_names {
            ensure!(
                datapath.interfaces.iter().all(|port| port.name != name)
                    && !host_ports.contains(&name),
                "configured interface {name} collides with a private TUN"
            );
        }
        let tasks = aux_tasks::AuxTasks::reserve(aux_count, &budget, plane.shutdown_intent())?;
        assert!(workers.auxiliary.set(tasks).is_ok());
        for (index, port) in auxiliary_interfaces().enumerate() {
            let id = u32::try_from(plan.realms().len() + index + 1)?;
            let (aux, scope, owner) = tcx_aux::PreparedAux::new(&port.name, id, index, &budget)?;
            let realm = PacketRealm::singleton(scope)?;
            scope_pairs.push((realm, vec![owner]));
            auxiliary.push(aux);
        }
        for (index, name) in host_ports.iter().enumerate() {
            let id = u32::try_from(realm_count + lan_count + index + 1)?;
            let (aux, scope, owner) = tcx_aux::PreparedAux::new_host(
                name,
                id,
                index,
                datapath.interfaces.iter().map(|p| p.name.as_str()),
                &budget,
            )?;
            scope_pairs.push((PacketRealm::singleton(scope)?, vec![owner]));
            auxiliary.push(aux);
        }
    }
    let config_generation = plane.diagnostics_handle().read().generation;
    let authority = if datapath.direct == Some(DirectProfile::Core) {
        Some(plane.core_forward_policy(Execution::MixedEndpoints).await?)
    } else {
        None
    };
    let policy = if gateway_enabled {
        let policy = GatewayPolicy::prepare(
            &plane.active_routing_plan_handle().read().plan,
            false,
            has_host.then_some(false),
        )?;
        let charge = gateway::reserve_objects(&budget, policy.fact_fds())?;
        Some((policy, charge))
    } else {
        None
    };
    let mut local_addresses: Vec<_> = links.local_addresses().map(LocalAddressKey::from).collect();
    local_addresses.sort_unstable_by_key(|key| (key.family, key.address));
    local_addresses.dedup();
    let gateway_maps = if policy.is_some() {
        let maps = if auxiliary.is_empty() {
            honk_xsk::GatewayMaps::new(&realm_keys, &local_addresses)?
        } else {
            let mut lans = [0; honk_config::datapath::MAX_L3_LANS];
            let mut hosts = [0; 4];
            for (id, aux) in lans.iter_mut().zip(&auxiliary[..lan_count]) {
                *id = aux.realm();
            }
            for (id, aux) in hosts.iter_mut().zip(&auxiliary[lan_count..]) {
                *id = aux.realm();
            }
            honk_xsk::GatewayMaps::new_with_host(
                &realm_keys,
                &local_addresses,
                &lans[..lan_count],
                &hosts[..host_ports.len()],
            )?
        };
        Some(Arc::new(maps.account(&budget)?))
    } else {
        None
    };
    let mut kernel_memory = Vec::new();
    let mut local_memory = None;
    if let Some(maps) = &gateway_maps {
        let backend = plane.policy_backend_handle();
        maps.set_mode_flags(backend.write().await.userspace_mut()?.mode_flags())?;
        local_memory = Some(
            budget
                .reserve(honk_xsk::kernel_memory_bytes(maps.local_map_fd()?.as_fd())?)
                .context("gateway local map memory capacity")?,
        );
    }
    if let Some(zones) = &mut zones {
        zones.revalidate(&budget)?;
    }
    let dns_bind = if has_host {
        PacketEndpoints::prepare_dns_bind(config)?
    } else {
        None
    };
    let host_scope = has_host
        .then(|| ScopeId::allocate().context("Host DNS scope exhausted"))
        .transpose()?;
    let standalone_dns_scope = if has_host {
        ScopeId::allocate().context("standalone DNS scope exhausted")?
    } else {
        ScopeId::HOST
    };
    #[cfg(feature = "ebpf")]
    let (host_resources, source_support) = if has_host {
        let needs_pname = plane.active_routing_plan_handle().read().plan.features
            & honk_ebpf_common::ROUTING_FEATURE_PROCESS
            != 0;
        let identity = host_identity::HostIdentity::load(&budget, needs_pname)?;
        let support = identity.pname_support();
        let resources =
            gateway::HostResources::prepare(identity, config.global.effective_so_mark(), &budget)?;
        (Some(resources), support)
    } else {
        (None, crate::ebpf::PnameSupport::Unavailable)
    };
    #[cfg(not(feature = "ebpf"))]
    let source_support = crate::ebpf::PnameSupport::Unavailable;
    let mut devices = StartupDevices(Vec::with_capacity(infos.len()));
    for (device_index, info) in infos.into_iter().enumerate() {
        let port_config = physical_config(info.mtu);
        let binding_mode = select_xsk_mode(&info, requested_mode, port_config, metadata_len)?;
        let vlan_offload = prepare_vlan_offload(&info, &budget)?;
        // A device without a complete feature identity (virtio reports no firmware version)
        // only stays ineligible for busy polling; each polling context rebuild queries it again.
        let features = FeatureQuery::new(&info, &budget).ok();
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
            .context("XDP device has no RX queues")?
            .checked_add(1)
            .context("XDP queue identity overflow")?;
        let programs = if let (Some((policy, _)), Some(maps), Some(ct)) =
            (&policy, &gateway_maps, &conntrack)
        {
            Programs::load_general_gateway(
                &capture,
                queues,
                topology.get_ref().ipv4_broadcasts(),
                honk_xsk::GatewayLoad {
                    routing: &policy.bytecode.insns,
                    maps,
                    conntrack: Some(ct),
                    dns: None,
                    arbitration: None,
                },
            )?
        } else {
            Programs::load_general(&capture, queues, topology.get_ref().ipv4_broadcasts())?
        };
        let objects = programs.object_fds();
        kernel_memory.push(gateway::reserve_objects(
            &budget,
            objects[..2].iter().copied(),
        )?);
        let program_memory = gateway::reserve_objects(&budget, objects[2..].iter().copied())?;
        let attachment = OwnedXdpLink::create(info.ifindex, programs.discover_fd())?;
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
            let io = if id % u32::from(datapath.effective_workers()) == 0 {
                let (io, registered) = QueueIo::Prepared(port).register();
                registered?;
                io
            } else {
                QueueIo::Prepared(port)
            };
            queues.push(Queue {
                id,
                observed,
                observed_rings,
                io,
            });
            tracing::info!(interface = %info.name, ifindex = info.ifindex, queue = id, zero_copy, vlan_metadata = capture.vlan_metadata, "XDP queue bound");
        }
        devices.push(Device {
            info: Arc::new(info),
            capture,
            queue_maps: Arc::clone(programs.queue_maps()),
            programs: Some((programs, program_memory)),
            attachment: Some(attachment),
            vlan_offload,
            queues,
            active: false,
            metadata_checked: Instant::now(),
            features,
            port_config,
            role: plan
                .realms()
                .iter()
                .find(|realm| realm.realm_id == plan.members()[device_index].realm_id)
                .context("capture member role missing")?
                .role,
        });
    }
    let mut realm_scopes = std::collections::HashMap::new();
    for logical in plan.realms() {
        let members: Vec<_> = devices
            .iter()
            .enumerate()
            .filter(|(_, device)| {
                realm_keys.iter().any(|(key, id)| {
                    *id == logical.realm_id && key.physical_ifindex == device.info.ifindex
                })
            })
            .map(|(index, _)| index)
            .collect();
        let device_index = *members
            .first()
            .context("logical capture realm has no physical member")?;
        let device = &devices[device_index];
        let (_, scope_bulk_frames) = device_sizing(device.info.mtu);
        let link = LogicalLink {
            ifindex: logical.logical_ifindex,
            mtu: logical.mtu,
            mac: logical.mac,
            path: LinkPath {
                physical_ifindex: device.info.ifindex,
                vlan_tci: logical.vid,
                vlan_proto: logical.tpid,
                vlan_count: u8::try_from(logical.vlan_count)?,
            },
        };
        let ingress = Ingress {
            scope: routing_scope,
            namespace,
            ifindex: link.ifindex,
            attachment: device.capture.authority.attachment_generation,
            mark: MarkProvenance::BeforeSkb,
        };
        let worker_count = realm_worker_count(
            usize::from(datapath.effective_workers()),
            members
                .iter()
                .map(|index| devices[*index].info.queues.len()),
        );
        let (realm, owners) = capture_realm(
            link.mtu,
            realm_count,
            scope_bulk_frames,
            worker_count,
            members.len(),
            &budget,
        )?;
        realm.install_admission_fence(Arc::clone(&admission))?;
        realm_scopes.insert(logical.realm_id, realm.scope());
        realms.push((ingress, device_index, link, realm.scope()));
        for member in members {
            let mut member_link = link;
            member_link.path.physical_ifindex = devices[member].info.ifindex;
            placements.entries.push(worker::Placement {
                realm_id: logical.realm_id,
                realm: realm.clone(),
                ingress,
                device: member,
                link: member_link,
            });
        }
        scope_pairs.push((realm, owners));
    }
    // Reserve auxiliary memory first, but keep physical owners first in the ingress lookup.
    scope_pairs.rotate_left(auxiliary.len());
    for aux in &auxiliary {
        realm_scopes.insert(aux.realm(), aux.scope());
    }
    // Worker 1 takes its immutable reference before registering its queues.
    assert!(workers.placements.set(Arc::new(placements)).is_ok());
    let diagnostics = diagnostics(&devices, &budget)?;
    workers
        .diagnostics
        .set(Arc::clone(&diagnostics))
        .expect("one diagnostics owner per capture");
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
                role: devices[*device].role,
                facts: *facts,
            })
            .collect();
        core.set_ingress_bindings(&bindings)?;
        core.prepare_fragment_peers()?;
        Some(core)
    } else {
        None
    };
    let gateway = match (policy, gateway_maps.as_ref()) {
        (Some(policy), Some(maps)) => {
            let lan =
                plan.realms()
                    .iter()
                    .filter(|realm| {
                        dns_projection && realm.role == honk_config::datapath::InterfaceRole::Lan
                    })
                    .map(|realm| (realm_scopes[&realm.realm_id], realm.realm_id))
                    .chain(
                        auxiliary
                            .iter()
                            .filter(|aux| dns_projection && !aux.is_host())
                            .map(|aux| (aux.scope(), aux.realm())),
                    )
                    .chain(host_scope.filter(|_| dns_projection).map(|scope| {
                        (scope, honk_ebpf_common::xdp_gateway::GATEWAY_REALM_CAPACITY)
                    }));
            let shadow = gateway::GatewayShadow::new(
                lan,
                plane,
                Arc::clone(&diagnostics),
                Arc::clone(&admission),
                &budget,
                zones.as_ref().is_some_and(ZoneAdmission::notrack_seen),
            );
            let mut publisher = GatewayPublisher::new(
                policy,
                Arc::clone(maps),
                conntrack,
                Arc::clone(&budget),
                shadow,
                plane.active_routing_plan_handle(),
            );
            if lan_count != 0 {
                publisher.prepare_auxiliary(lan_count)?;
            }
            #[cfg(feature = "ebpf")]
            if let Some(resources) = host_resources {
                publisher.prepare_host(resources)?;
            }
            Some(Arc::new(publisher))
        }
        _ => None,
    };
    let projection = plane.packet_routing_projection();
    if lan_count != 0 {
        let mut scopes = [ScopeId::HOST; honk_config::datapath::MAX_L3_LANS];
        for (scope, aux) in scopes.iter_mut().zip(&auxiliary[..lan_count]) {
            *scope = aux.scope();
        }
        projection.register_aux_scopes(&scopes[..lan_count], &budget)?;
    }
    if let Some(shared) = host_scope {
        let mut ports = Vec::with_capacity(host_ports.len());
        for (realm, _) in &scope_pairs[realm_count + lan_count..] {
            ports.push(realm.owners()[0].clone());
        }
        projection.register_host_scopes(shared, standalone_dns_scope, &ports, &budget)?;
    }
    Ok(PreparedRuntime {
        devices: std::mem::take(&mut devices.0),
        topology,
        capture_plan: plan,
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
    fn bond_realm_workers_fit_every_member() {
        assert_eq!(realm_worker_count(2, [1, 2].into_iter()), 1);
    }

    #[test]
    fn direct_relay_requires_matching_physical_owners_and_one_endpoint_member() {
        let endpoint = Some(DirectProfile::Endpoint);
        assert!(direct_relay_eligible(endpoint, 1, 1, 1, true));
        assert!(direct_relay_eligible(endpoint, 2, 2, 1, true));
        for (profile, workers, owners, members, physical) in [
            (endpoint, 1, 1, 1, false),
            (endpoint, 2, 2, 1, false),
            (endpoint, 2, 1, 1, true),
            (endpoint, 3, 3, 1, true),
            (endpoint, 0, 0, 1, true),
            (endpoint, 2, 2, 2, true),
            (endpoint, 1, 1, 0, true),
            (Some(DirectProfile::Core), 2, 2, 1, true),
            (None, 1, 1, 1, true),
        ] {
            assert!(!direct_relay_eligible(
                profile, workers, owners, members, physical
            ));
        }
    }

    #[test]
    fn rx_capacity_preserves_small_budget_and_many_queue_admission() {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let sizing = |mtu, queues| queue_sizing(mtu, queues, budget.limit() - budget.used());
        let umem = |mtu, queues| sizing(mtu, queues).0.umem_bytes().unwrap();
        let base = 3 * 1024 * 1024;
        let (wide, scope_bulk) = sizing(1500, 8);
        wide.validate().unwrap();
        assert_eq!(
            (wide.control_frames, wide.bulk_frames, scope_bulk),
            (32, 480, 256)
        );
        assert_eq!(wide.ring_size, 1024);
        assert!(wide.rx_frames > 256 && wide.umem_bytes().unwrap() > base);
        assert_eq!(umem(9000, 1), 2 * 1024 * 1024);
        assert_eq!(umem(1500, 0), base);
        assert_eq!(umem(1500, 9), base);
        for queues in [1, 8] {
            let cutoff = CAPTURE_MEMORY / 2 + queues * 2 * wide.umem_bytes().unwrap();
            assert_eq!(queue_sizing(4074, queues, cutoff - 1).0.rx_frames, 256);
            assert_eq!(
                queue_sizing(4074, queues, cutoff).0.rx_frames,
                wide.rx_frames
            );
            assert_eq!(
                queue_sizing(4074, queues, cutoff + 1).0.rx_frames,
                wide.rx_frames
            );
            assert_eq!(queue_sizing(4075, queues, cutoff + 1).0.ring_size, 256);
        }
        let _other_owners = budget.reserve(CAPTURE_MEMORY - base).unwrap();
        let constrained = sizing(1500, 1).0;
        assert_eq!((constrained.rx_frames, constrained.ring_size), (256, 512));
        assert!(budget.reserve(wide.umem_bytes().unwrap()).is_none());
        let _port = budget.reserve(constrained.umem_bytes().unwrap()).unwrap();
        assert_eq!(budget.used(), budget.limit());
    }

    #[test]
    fn readonly_admission_reports_nonzero_gateway_time_offset() {
        assert!(gateway_time_namespace_issue(Ok(None)).is_none());
        assert!(gateway_time_namespace_issue(Ok(Some(0))).is_none());
        for offset in [-1_000_000_000, 1_000_000_000] {
            let (reason, details) = gateway_time_namespace_issue(Ok(Some(offset))).unwrap();
            let summary = admission_failure(&[(reason, "namespace".into(), details)], 0);
            assert!(summary.contains("reason=time_namespace_offset device=namespace"));
            assert!(summary.contains(&format!("{offset} ns")));
        }
    }

    #[test]
    fn readonly_admission_reports_foreign_xdp_and_mode_failure_together() {
        let info = DeviceInfo {
            name: "eth-test".into(),
            ifindex: 1,
            upper_ifindices: Vec::new(),
            queues: vec![0],
            mtu: 9000,
            mac: [2; 6],
            xdp_features: 3,
            zerocopy_max_segments: 0,
            vlan_metadata: false,
            direct_relay_physical: true,
        };
        let issues: Vec<_> = member_admission_issues(
            &info,
            device_sizing(info.mtu).0,
            Some(BindMode::ZeroCopy),
            METADATA_LEN,
            Ok(false),
        )
        .into_iter()
        .flatten()
        .map(|(reason, details)| (reason, info.name.clone(), details))
        .collect();
        let summary = admission_failure(&issues, 0);
        assert_eq!(issues.len(), 2);
        assert!(summary.contains("reason=xsk_mode device=eth-test"));
        assert!(summary.contains("reason=foreign_xdp device=eth-test"));
    }

    #[test]
    fn readonly_layout_failure_marks_dependent_checks_not_checked() {
        let issues: Vec<_> = layout_admission_issues(&io::Error::other("injected layout failure"))
            .into_iter()
            .map(|(reason, details)| (reason, "capture".into(), details))
            .collect();
        let summary = admission_failure(&issues, 0);
        assert!(summary.contains("reason=capture_layout device=capture: injected layout failure"));
        assert!(summary.contains("reason=NOT_CHECKED device=capture"));
        assert!(summary.contains("depend on capture_layout"));
        assert!(!summary.contains("reason=xsk_mode"));
        assert!(!summary.contains("reason=foreign_xdp"));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_worker_cannot_extend_the_physical_detach_budget() {
        let deadline = Instant::now() + Duration::from_millis(5);
        let result = drain_before_detach(deadline, || Ok(false), std::future::pending()).await;
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn pending_tx_cannot_extend_the_worker_deadline() {
        let deadline = Instant::now() + Duration::from_millis(5);
        let result = drain_before_detach(deadline, || Ok(true), std::future::ready(Ok(()))).await;
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some()
        );
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
            realm: 1,
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
        assert!(!arm_read(&reader, &mut Context::from_waker(std::task::Waker::noop())).unwrap());
        writer.send(b"drained").unwrap();
        // A previous pass consumed the packet whose event is still cached as Ready.
        reader.readable().await.unwrap().retain_ready();
        assert_eq!(reader.get_ref().recv(&mut [0; 16]).unwrap(), 7);
        let (armed, waiting) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            let mut armed = Some(armed);
            poll_fn(|cx| {
                if !arm_read(&reader, cx).unwrap() {
                    return Poll::Pending;
                }
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
