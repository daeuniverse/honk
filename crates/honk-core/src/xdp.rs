//! One Linux capture owner for every selected RX queue and one routing domain.
//! Pinned links remain fail-closed after shutdown; UMEM is retained until process exit.

use crate::control::{
    ControlPlane,
    core_forward::{
        CachedDecision, Decision, Execution, GeneratedError, IngressBinding, PolicyGeneration,
        PolicyRead, Requirements, RoutedCore, socket_namespace,
    },
    netstack::{OutputLease, PacketDriver, PacketScope, RuntimeLimits},
    packet_endpoint::{EndpointAdmission, PacketEndpointOwner, PacketEndpoints},
};
use crate::netlink::fib::{Fib, LogicalLink};
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
use honk_ebpf_common::xdp::CaptureAuthority;
use honk_netstack::{
    MemoryBudget, MemoryReservation,
    wire::{self, PacketView},
};
use honk_xsk::{
    BindMode, DecodedPacket, GeneralCapture, PersistentAttachment, Port, PortConfig, Programs,
    device::DeviceInfo, topology::Topology,
};
use std::{
    collections::VecDeque,
    future::poll_fn,
    io,
    net::IpAddr,
    os::fd::AsFd,
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::unix::AsyncFd;

const PENDING: usize = 64;
const PEERS: usize = 4096;
const PEER_CONFLICT_HOLD: Duration = Duration::from_secs(60);
const BATCH: usize = 32;
const MEMORY: usize = 256 << 20;

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
        !config.global.nfqueue_enable,
        "XDP requires global.nfqueue_enable: false; NFQUEUE is not an XDP fallback"
    );
    ensure!(
        config.global.lan_interface.is_empty() && config.global.wan_interface.is_empty(),
        "XDP interfaces and trusted LAN/WAN roles belong only in datapath.interface"
    );
    ensure!(
        config.routing.default_mark == 0 && config.routing.rules.iter().all(|rule| rule.mark == 0),
        "XDP cannot preserve nonzero rule marks or native skb classification"
    );
    for rule in &config.routing.rules {
        let condition = &rule.condition;
        ensure!(
            condition.process_name.is_empty()
                && condition.not.process_name.is_empty()
                && condition.mac.is_empty()
                && condition.not.mac.is_empty(),
            "XDP Endpoint routing has no process/socket or per-flow MAC authority; predicate admission refused"
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
    Endpoint(OutputLease),
    Forward {
        _owner: ForwardLease,
    },
    Error {
        _binding: Option<honk_datapath::firewall::BindingLease>,
    },
    Generated {
        _owner: GeneratedError,
    },
}

fn release_completed(completed: &mut [Option<&mut Retained>]) {
    let mut outputs: [Option<&mut OutputLease>; 64] = std::array::from_fn(|_| None);
    let mut count = 0;
    for owner in completed.iter_mut().filter_map(Option::take) {
        if let Retained::Endpoint(output) = owner {
            outputs[count] = Some(output);
            count += 1;
        }
    }
    OutputLease::release_batch(&mut outputs[..count]);
}
struct Queue {
    id: u32,
    io: AsyncFd<Port<Retained>>,
}
struct Device {
    info: DeviceInfo,
    capture: GeneralCapture,
    programs: Programs,
    attachment: PersistentAttachment,
    queues: Vec<Queue>,
    active: bool,
    metadata_checked: Instant,
}
struct Waiting {
    packet: Packet,
    mac: [u8; 6],
    retry: Instant,
    scope: ScopeId,
    path: ReturnPath,
}
struct Pending {
    output: ForwardPacket,
    generation: PolicyGeneration,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct ReturnPath {
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
    last_seen: Instant,
    conflict: Option<Instant>,
}

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
        devices: &[Device],
    ) {
        if now.saturating_duration_since(self.checked) < Duration::from_secs(1) {
            return;
        }
        self.checked = now;
        for device in devices {
            for queue in &device.queues {
                let port = queue.io.get_ref();
                tracing::debug!(interface = %device.info.name, queue = queue.id,
                    socket = ?port.stats(), rings = ?port.rings(), counters = ?port.counters(),
                    "XDP queue pressure");
            }
        }
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
    }
}
struct Realm {
    ingress: Ingress,
    device: usize,
    link: LogicalLink,
    driver: PacketDriver,
    pending: [Option<(OutputLease, ReturnPath)>; 2],
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
        if path.device != self.device {
            return Err(io::Error::other(
                "Endpoint reply belongs to another physical device",
            ));
        }
        return_header(path, self.link.mac, physical_ifindex, ipv6)
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

struct Runtime {
    devices: Vec<Device>,
    topology: AsyncFd<Topology>,
    admission: Arc<AtomicBool>,
    realms: Vec<Realm>,
    endpoints: PacketEndpoints,
    core: Option<RoutedCore>,
    waiting: VecDeque<Waiting>,
    pending: VecDeque<Pending>,
    peers: Vec<Peer>,
    staging: Vec<u8>,
    closing: bool,
    pressure: Pressure,
    core_maintenance_checked: Instant,
    _memory: MemoryReservation,
}

impl Runtime {
    fn close_capture(&mut self) -> anyhow::Result<()> {
        self.admission.store(false, Ordering::Release);
        self.closing = true;
        let mut failure = None;
        for device in &mut self.devices {
            if device.active {
                match device.attachment.guard(&device.programs) {
                    Ok(()) => device.active = false,
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
            }
            for queue in &device.queues {
                if let Err(error) = device.programs.delete_xsk(queue.id) {
                    failure.get_or_insert(error);
                }
            }
        }
        self.endpoints.close();
        self.waiting.clear();
        self.pending.clear();
        for realm in &mut self.realms {
            realm.pending = [None, None];
        }
        failure.map_or(Ok(()), |error| Err(error.into()))
    }

    fn poll_io(&mut self, cx: &mut Context<'_>) -> Poll<anyhow::Result<()>> {
        if !self.closing {
            if !self.admission.load(Ordering::Acquire) {
                return Poll::Ready(Err(anyhow::anyhow!("XDP publication admission closed")));
            }
            match self.topology.poll_read_ready(cx) {
                Poll::Ready(Ok(mut ready)) => ready.clear_ready(),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => {}
            }
            if let Err(error) = current_topology(&mut self.topology) {
                return Poll::Ready(Err(error.into()));
            }
        }
        let now = Instant::now();
        let mut progress = 0;
        for device_index in 0..self.devices.len() {
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
            for queue in &mut device.queues {
                if !self.closing {
                    match queue.io.poll_read_ready(cx) {
                        Poll::Ready(Ok(mut ready)) => ready.clear_ready(),
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Pending => {}
                    }
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
                    if self.closing {
                        return Ok(0);
                    }
                    let capture = &device.capture;
                    let core = &mut self.core;
                    let waiting = &mut self.waiting;
                    let peers = &mut self.peers;
                    let staging = &mut self.staging;
                    let endpoints = &self.endpoints;
                    let pressure = &mut self.pressure.counters;
                    let realms = &self.realms;
                    let mut failure = None;
                    let ifindex = device.info.ifindex;
                    let received = port.receive_segments_with(BATCH, capture.vlan_metadata, |segments, metadata, same_port| {
                        if failure.is_some() { return; }
                        let Ok(decoded) = capture.decode(segments, metadata, queue.id) else {
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
                            let cached = core.forward_cached(ingress, view, Some(std::str::from_utf8(&mac).unwrap()), now, |route, output| {
                                let header = route.ethernet_header(decoded.ether_type == 0x86dd).map_err(io::Error::other)?;
                                if !selected_egress(realms, route) { return Ok(None); }
                                if route.l2.physical_ifindex == ifindex {
                                    while let Some(length) = output.next_len() {
                                        same_port.transmit_with(TxClass::Bulk, header.len() + length, Retained::Forward { _owner: output.lease() }, |_, target| {
                                            output.write_next_segments(target, &header).map(|_| ()).ok_or_else(|| io::Error::other("Core SG materialization refused"))
                                        })?;
                                    }
                                } else {
                                    let egress = before.iter_mut().chain(after.iter_mut()).find(|device| device.info.ifindex == route.l2.physical_ifindex)
                                        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "Core egress is not a selected XDP interface"))?;
                                    let (work, kick) = egress.queues[0].io.get_mut().transmit_batch(|port| -> io::Result<()> {
                                        while let Some(length) = output.next_len() {
                                            port.transmit_with(TxClass::Bulk, header.len() + length, Retained::Forward { _owner: output.lease() }, |_, target| {
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
                            });
                            if failure.is_some() { return; }
                            match cached {
                                Ok(CachedDecision::Forwarded(()) | CachedDecision::Drop) => return,
                                Ok(CachedDecision::Cold) => {
                                    if waiting.len() == PENDING {
                                        pressure.waiting_full = pressure.waiting_full.saturating_add(1);
                                        pressure.refused = true;
                                        return;
                                    }
                                    match core.receive_segments(ingress, now, &l3[..count]) {
                                        Ok(Some(packet)) => waiting.push_back(Waiting { packet, mac: decoded.source_mac, retry: now, scope, path }),
                                        Ok(None) => {}
                                        Err(_) => pressure.core_ingress_refused = pressure.core_ingress_refused.saturating_add(1),
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
                        if let Err(error) = receive_endpoint(endpoints, peers, pressure, scope, bytes, now, path, None)
                            && !matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory) { failure = Some(error.into()); }
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
        }
        // The sole scope owner: timers, closes and events run here even without RX or Core
        // readers, before this turn exports their CPU outputs.
        if self.service_scopes(cx, now) {
            progress += 1;
        }
        let mut outputs: [Option<OutputLease>; BATCH] = std::array::from_fn(|_| None);
        for realm in &mut self.realms {
            let device = &mut self.devices[realm.device];
            let ifindex = device.info.ifindex;
            let (work, kick) = device.queues[0].io.get_mut().transmit_batch(|port| {
                let mut serviced = 0;
                for (class_index, class) in
                    [TxClass::Control, TxClass::Bulk].into_iter().enumerate()
                {
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
                            _ => break,
                        };
                        considered += count;
                        let mut blocked = false;
                        for output in &mut outputs[..count] {
                            let output = output.take().expect("selected Endpoint output");
                            let Some(path) =
                                pending_path.or_else(|| endpoint_return_path(&self.peers, &output))
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
                                Retained::Endpoint(output),
                                |owner, target| {
                                    let Retained::Endpoint(output) = owner else {
                                        return Err(io::Error::other("wrong endpoint TX owner"));
                                    };
                                    fill_output(target, &header[..length], output.packet())
                                },
                            )?;
                            serviced += 1;
                        }
                        if blocked {
                            break;
                        }
                    }
                }
                Ok(serviced)
            });
            progress += finish_transmit(work, kick)?;
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
        let deadline = self
            .realms
            .iter()
            .filter_map(|realm| realm.driver.deadline())
            .min();
        poll_deadline(timer, if more { Some(now) } else { deadline }, now, cx)
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

    fn poll_service(
        &mut self,
        cx: &mut Context<'_>,
        shutdown: &crate::control::ShutdownIntent,
        mut timer: Pin<&mut Option<tokio::time::Sleep>>,
        reading: bool,
    ) -> Poll<anyhow::Result<()>> {
        if let Poll::Ready(result) = self.poll_io(cx) {
            timer.set(None);
            return Poll::Ready(result);
        }
        if !self.closing && shutdown.requested() {
            timer.set(None);
            return Poll::Ready(Ok(()));
        }
        // Registration and ring/output service may create obligations absent before this poll.
        let now = Instant::now();
        poll_deadline(timer, self.next_deadline(now, !reading), now, cx).map(Ok)
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
                if let Err(error) = receive_endpoint(
                    &self.endpoints,
                    &mut self.peers,
                    &mut self.pressure.counters,
                    work.scope,
                    work.packet.as_ref(),
                    now,
                    work.path,
                    None,
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
                }),
                Decision::Drop | Decision::LocalInput => {}
                Decision::Endpoint(packet, admission) => {
                    if let Err(error) = receive_endpoint(
                        &self.endpoints,
                        &mut self.peers,
                        &mut self.pressure.counters,
                        work.scope,
                        packet.as_ref(),
                        now,
                        work.path,
                        Some(admission),
                    ) && !matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                    ) {
                        return Err(error.into());
                    }
                }
                Decision::Forward(Prepared::Forward(output), generation) => {
                    if self.pending.len() < PENDING {
                        self.pending.push_back(Pending { output, generation });
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
                        let header = route.ethernet_header(packet.ip().src.is_ipv6())?;
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
                    Retained::Forward { _owner: lease },
                    |_, target| {
                        work.output
                            .write_next_segments(target, &header)
                            .map(|_| ())
                            .ok_or_else(|| io::Error::other("Core SG materialization refused"))
                    },
                )
                .map(Some)
            })?;
            if submitted.is_some() && !work.output.is_complete() {
                self.pending.push_back(work);
            }
        }
        if let Some(error) = core.poll_reassembly_error(read, now, &mut self.staging)? {
            let route = error.route;
            if selected_egress(&self.realms, route)
                && let Some(device) = self
                    .devices
                    .iter_mut()
                    .find(|device| device.info.ifindex == route.l2.physical_ifindex)
            {
                let header = route.ethernet_header(self.staging[0] >> 4 == 6)?;
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
        self.admission.store(false, Ordering::Release);
        for device in &self.devices {
            if device.active
                && let Err(error) = device.attachment.guard(&device.programs)
            {
                tracing::error!(%error, "XDP pinned capture guard failed; socket-map misses remain drop");
            }
        }
        self.endpoints.close();
    }
}

fn l3_segments<'a>(
    segments: &[&'a [u8]],
    packet: DecodedPacket,
    output: &mut [&'a [u8]; 18],
) -> Option<usize> {
    let mut skip = packet.l3_offset;
    let mut left = packet.l3_len;
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
) -> io::Result<Option<honk_netstack::ValidatedSource>> {
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
    endpoints.retains(
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

fn endpoint_return_path(peers: &[Peer], output: &OutputLease) -> Option<ReturnPath> {
    let (_, destination) = wire::packet_addresses(output.packet()).ok()?;
    peers
        .iter()
        .find(|peer| {
            peer.scope == output.scope() && peer.address == destination && peer.conflict.is_none()
        })
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
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    let config = plane.config_handle().read().await.as_ref().clone();
    let shutdown = plane.shutdown_intent();
    let backend = plane.policy_backend_handle();
    let prepared = prepare(&plane, &config, pin_root).await;
    let (devices, topology, realms, scope_pairs, core, memory, staging, mut link_proof) =
        match prepared {
            Ok(prepared) => prepared,
            Err(error) => return (Some(plane), Err(error)),
        };
    let (endpoints, mut owner, mut drivers) =
        match PacketEndpoints::start_driven(plane, scope_pairs, 64) {
            Ok(started) => started,
            Err(error) => return (None, Err(error)),
        };
    let realms = realms
        .into_iter()
        .map(|(ingress, device, link, scope)| {
            // Installed by the exact handed-off scope identity, not by position.
            let index = drivers
                .iter()
                .position(|driver| driver.scope() == scope)
                .expect("start_driven returns one driver per validated scope");
            Realm {
                ingress,
                device,
                link,
                driver: drivers.swap_remove(index),
                pending: [None, None],
            }
        })
        .collect();
    let mut runtime = Runtime {
        devices,
        topology,
        admission,
        realms,
        endpoints,
        core,
        waiting: VecDeque::with_capacity(PENDING),
        pending: VecDeque::with_capacity(PENDING),
        peers: Vec::with_capacity(PEERS),
        staging,
        closing: false,
        pressure: Pressure::new(Instant::now()),
        core_maintenance_checked: Instant::now(),
        _memory: memory,
    };
    let timer = None;
    tokio::pin!(timer);
    // The drivers already exist: a failed start's supervisor cleanup waits on their service.
    let ready = loop {
        tokio::select! {
            ready = poll_fn(|cx| owner.poll_ready(cx)) => break ready,
            () = poll_fn(|cx| runtime.poll_scopes(cx, timer.as_mut())) => tokio::task::yield_now().await,
        }
    };
    if let Err(error) = ready {
        return (None, Err(error));
    }
    let activate = (|| -> anyhow::Result<()> {
        for device in &mut runtime.devices {
            device.attachment.replace(&device.programs)?;
            device.active = true;
        }
        // Reconcile notifications caused by our own link attachments before admitting packets.
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
        let topology = Topology::admit(&indices, &logical, config.global.effective_so_mark())?;
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
        runtime.admission.store(true, Ordering::Release);
        runtime.endpoints.capture_ready()?;
        Ok(())
    })();
    drop(link_proof);
    let mut failure = activate.err();
    if failure.is_none() {
        tracing::info!(interfaces = runtime.devices.len(), "XDP datapath ready");
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
                |cx| runtime.poll_service(cx, &shutdown, timer.as_mut(), false),
                close_started.unwrap(),
                &mut warned,
            )
            .await
            {
                Ok(joined) => break joined,
                Err(error) => {
                    tracing::error!(%error, "XDP terminal I/O failed; retaining runtime and supervisor until process exit");
                    failure.get_or_insert(error);
                    std::mem::forget((runtime, owner));
                    return (None, Err(failure.unwrap()));
                }
            }
        }
        runtime.pressure.sample(
            Instant::now(),
            runtime.core.as_ref(),
            runtime.waiting.len(),
            runtime.pending.len(),
            runtime.peers.len(),
            &runtime.devices,
        );
        if reader.is_none()
            && let Some(authority) = &authority
            && runtime.core_due(Instant::now())
        {
            reader.set(Some(authority.read_policy()));
        }
        match turn(
            reader.as_mut(),
            |cx| owner.poll_join_plane(cx),
            |cx, reading| runtime.poll_service(cx, &shutdown, timer.as_mut(), reading),
            &shutdown,
        )
        .await
        {
            Turn::Joined(result) => break result,
            // The readers drop at the end of this synchronous turn, before any await.
            Turn::Read(read) => {
                if let Err(error) = runtime.resolve(&read) {
                    failure.get_or_insert(error);
                }
            }
            Turn::Serviced(Err(error)) => {
                if failure.is_none() {
                    tracing::error!(%error, "XDP owner failed closed");
                }
                failure.get_or_insert(error);
            }
            Turn::Serviced(Ok(())) | Turn::Shutdown => {}
        }
        tokio::task::yield_now().await;
    };
    if !runtime.closing
        && let Err(error) = runtime.close_capture()
    {
        failure.get_or_insert(error);
    }
    // An endpoint join cannot release Core TX leases; drain those same descriptor owners too.
    if let Err(error) = drain_transmit(
        || {
            let mut outstanding = false;
            for device in &mut runtime.devices {
                for queue in &mut device.queues {
                    let port = queue.io.get_mut();
                    port.complete(release_completed)?;
                    port.kick()?;
                    outstanding |= port.counters().submitted != port.counters().completed;
                }
            }
            Ok(outstanding)
        },
        close_started.unwrap_or_else(Instant::now),
        &mut warned,
    )
    .await
    {
        tracing::error!(%error, "XDP terminal drain failed; retaining owners and UMEM until process exit");
        failure.get_or_insert(error.into());
        if let Err(error) = owner.fail_control().await {
            failure.get_or_insert(error);
        }
        std::mem::forget((runtime, joined));
        return (None, Err(failure.unwrap()));
    }
    for device in &mut runtime.devices {
        for queue in device.queues.drain(..) {
            let mut port = queue.io.into_inner();
            if !port.close().ready_for_backend_teardown() {
                failure.get_or_insert_with(|| {
                    anyhow::anyhow!("XDP ledger did not reach terminal ownership")
                });
            }
            port.close_socket();
        }
    }
    if let Err(error) = backend.write().await.cleanup().await {
        failure.get_or_insert(error);
    }
    tracing::info!("XDP admission closed; UMEM retained until process exit");
    match joined {
        Ok((plane, result)) => {
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
            (Some(plane), failure.map_or(Ok(()), Err))
        }
        Err(error) => (None, Err(failure.unwrap_or(error))),
    }
}

/// A realm before validated endpoint start hands it the driver of this exact scope.
type RealmPlan = (Ingress, usize, LogicalLink, ScopeId);

type PreparedRuntime = (
    Vec<Device>,
    AsyncFd<Topology>,
    Vec<RealmPlan>,
    Vec<(PacketScope, crate::control::netstack::PacketOwner)>,
    Option<RoutedCore>,
    MemoryReservation,
    Vec<u8>,
    Fib,
);

async fn prepare(
    plane: &ControlPlane,
    config: &Config,
    pin_root: &Path,
) -> anyhow::Result<PreparedRuntime> {
    validate_config(config)?;
    let datapath = config
        .datapath
        .as_ref()
        .context("XDP configuration missing")?;
    let binding_mode = match datapath.effective_xsk_mode() {
        XskMode::Copy => BindMode::Copy,
        XskMode::ZeroCopy => BindMode::ZeroCopy,
    };
    let port_config = PortConfig {
        rx_frames: 256,
        control_frames: 32,
        bulk_frames: 224,
        ring_size: 256,
    };
    let infos: Vec<_> = datapath
        .interfaces
        .iter()
        .map(|interface| DeviceInfo::discover(&interface.name))
        .collect::<io::Result<_>>()?;
    for info in &infos {
        info.validate_port_config(binding_mode, port_config)
            .with_context(|| format!("XDP device {} {binding_mode:?} admission", info.name))?;
        ensure!(
            honk_xsk::xdp_absent(info.ifindex)?,
            "XDP interface already attached; stop sources and remove only its owned stale guard before restart"
        );
    }
    let indices: Vec<_> = infos.iter().map(|info| info.ifindex).collect();
    let budget = MemoryBudget::new(MEMORY);
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
    let realm_count = links
        .logical_links()
        .filter(|link| indices.contains(&link.path.physical_ifindex))
        .count();
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
    let max_mtu = infos
        .iter()
        .map(|info| info.mtu)
        .max()
        .context("no selected interfaces")? as usize;
    let memory = budget
        .reserve(
            max_mtu
                + 65536
                + size_of::<Runtime>()
                + size_of::<Topology>()
                + PEERS * size_of::<Peer>()
                + PENDING * (size_of::<Waiting>() + size_of::<Pending>())
                + realm_count
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
    for info in infos {
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
        let programs = Programs::load_general(
            &capture,
            info.queues
                .last()
                .copied()
                .unwrap()
                .checked_add(1)
                .context("XDP queue identity overflow")?,
            topology.get_ref().ipv4_broadcasts(),
        )?;
        use std::os::unix::fs::DirBuilderExt;
        let pins = pin_root.join(format!("xdp-{}", info.ifindex));
        std::fs::DirBuilder::new().mode(0o700).create(&pins)?;
        let attachment = PersistentAttachment::create(info.ifindex, &programs, &pins)?;
        let ports = info.open_ports::<Retained>(binding_mode, port_config, &budget)?;
        ensure!(
            ports
                .iter()
                .all(|port| socket_namespace(port.as_fd())
                    .is_ok_and(|observed| observed == namespace)),
            "queue capture namespace changed"
        );
        for link in links
            .logical_links()
            .filter(|link| link.path.physical_ifindex == info.ifindex)
        {
            let ingress = Ingress {
                scope: routing_scope,
                namespace,
                ifindex: link.ifindex,
                attachment: incarnation,
                mark: MarkProvenance::BeforeSkb,
            };
            let (scope, scope_owner) = packet_scope(link.mtu, realm_count, &budget)?;
            realms.push((ingress, devices.len(), link, scope.scope()));
            scope_pairs.push((scope, scope_owner));
        }
        let mut queues = Vec::with_capacity(ports.len());
        for (id, mut port) in info.queues.iter().copied().zip(ports) {
            port.refill()?;
            programs.insert_xsk(id, port.as_fd())?;
            let zero_copy = port.zerocopy();
            queues.push(Queue {
                id,
                // SAFETY: close_socket is called only after AsyncFd::into_inner deregisters it.
                io: unsafe { AsyncFd::register(port) }.map_err(io::Error::from)?,
            });
            tracing::info!(interface = %info.name, ifindex = info.ifindex, queue = id, zero_copy, vlan_metadata = capture.vlan_metadata, "XDP queue bound");
        }
        devices.push(Device {
            info,
            capture,
            programs,
            attachment,
            queues,
            active: false,
            metadata_checked: Instant::now(),
        });
    }
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
        Some(core)
    } else {
        None
    };
    Ok((
        devices,
        topology,
        realms,
        scope_pairs,
        core,
        memory,
        vec![0; max_mtu.max(65536)],
        links,
    ))
}

fn packet_scope(
    mtu: u32,
    realms: usize,
    budget: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketScope, crate::control::netstack::PacketOwner)> {
    // ponytail: fixed per-realm partitions; rebalance only if measured tenant skew needs it.
    let slots = (4096 / realms).min(1024);
    let mut stack = honk_netstack::Config::new(rand::random());
    stack.mode = honk_netstack::Mode::Transparent {
        exclude: Default::default(),
    };
    stack.mtu = u16::try_from(mtu)?;
    stack.max_flows = slots as u32;
    stack.memory_limit = MEMORY / 2 / realms;
    Ok(PacketScope::new(
        stack,
        Arc::clone(budget),
        RuntimeLimits {
            max_slots: slots,
            control_frames: 32,
            bulk_frames: 128,
            max_waiters: 256,
        },
        Instant::now(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod driven_kernel;
    mod retention;

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
        pressure.sample(start + Duration::from_secs(1), None, 0, 0, 0, &[]);
        assert!(pressure.active);
        assert_eq!(
            pressure.next_deadline(None),
            Some(start + Duration::from_secs(2))
        );
        pressure.sample(start + Duration::from_secs(2), None, 0, 0, 0, &[]);
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
        let budget = MemoryBudget::new(MEMORY);
        let scopes: Vec<_> = (0..6)
            .map(|_| packet_scope(1500, 6, &budget).unwrap())
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
            l3_offset: length,
            l3_len: payload.len(),
            source_mac: [4; 6],
            destination_mac: [2; 6],
            ether_type: 0x86dd,
            vlan_tci: path.vlan_tci,
            vlan_proto: path.vlan_proto,
            vlan_count: 2,
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
}
