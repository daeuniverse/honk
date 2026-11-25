use super::*;
use std::sync::atomic::AtomicU64;

const WORK_CLOSED: usize = 1 << (usize::BITS - 1);

pub(super) struct Auxiliary {
    pub(super) root: Arc<MemoryBudget>,
    #[cfg(target_os = "linux")]
    prepared_mtu: u32,
    // Even stamps admit work. Closing sets the low bit; reopening always uses a new pair.
    stamp: AtomicU64,
    work: AtomicUsize,
    cancelled: Notify,
    pub(super) released: Notify,
    _memory: MemoryReservation,
}

impl Auxiliary {
    pub(super) fn close(&self) {
        self.work.fetch_or(WORK_CLOSED, Ordering::SeqCst);
        if self.stamp.fetch_or(1, Ordering::SeqCst) & 1 == 0 {
            self.cancelled.notify_waiters();
        }
    }
}

/// A queued or executing application operation from one binding. The last owner wakes drain.
#[derive(Debug)]
pub(in crate::control) struct AuxiliaryWork {
    scope: PacketScope,
    stamp: u64,
}

impl AuxiliaryWork {
    pub(in crate::control) fn is_active(&self) -> bool {
        self.scope.binding() == self.stamp
    }

    pub(in crate::control) async fn cancelled(&self) {
        let aux = self
            .scope
            .0
            .auxiliary
            .as_ref()
            .expect("auxiliary operation");
        let cancelled = aux.cancelled.notified();
        if self.is_active() {
            cancelled.await;
        }
    }
}

impl Clone for AuxiliaryWork {
    fn clone(&self) -> Self {
        let aux = self
            .scope
            .0
            .auxiliary
            .as_ref()
            .expect("auxiliary operation");
        aux.work.fetch_add(1, Ordering::SeqCst);
        Self {
            scope: self.scope.clone(),
            stamp: self.stamp,
        }
    }
}

impl Drop for AuxiliaryWork {
    fn drop(&mut self) {
        let aux = self
            .scope
            .0
            .auxiliary
            .as_ref()
            .expect("auxiliary operation");
        if aux.work.fetch_sub(1, Ordering::SeqCst) == WORK_CLOSED + 1 {
            aux.released.notify_one();
        }
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub(super) struct HostProcessBinding {
    realm: u32,
    stamp: u64,
    binding_id: u64,
    lookup: Option<crate::xdp::gateway::HostProcessLookup>,
    pub(super) udp: HostUdpInputs,
    pub(super) outputs: Box<[Option<HostOutput>]>,
    _output_memory: MemoryReservation,
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[derive(Clone, Copy)]
pub(super) struct HostOutput {
    client: IpAddr,
    destination: IpAddr,
    protocol: u8,
    ports: Option<(u16, u16)>,
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
impl HostOutput {
    pub(super) fn from_packet(
        packet: &[u8],
        fragment: Option<honk_netstack::FragmentInfo>,
    ) -> Option<Self> {
        use honk_netstack::wire;
        if let Some(reply) = wire::icmp::parse_quoted(packet) {
            return Some(Self {
                client: reply.dst,
                destination: reply.src,
                protocol: reply.proto,
                ports: Some((reply.dst_port, reply.src_port)),
            });
        }
        if let Ok(ip) = wire::parse_ip(packet) {
            if matches!(ip.proto, wire::PROTO_ICMP | wire::PROTO_ICMPV6)
                && let Some(quote) = packet[ip.payload]
                    .get(8..)
                    .and_then(wire::icmp::parse_quoted)
            {
                return Some(Self {
                    client: quote.src,
                    destination: quote.dst,
                    protocol: quote.proto,
                    ports: Some((quote.src_port, quote.dst_port)),
                });
            }
            return fragment.map(|info| Self {
                client: info.identity.src,
                destination: info.identity.dst,
                protocol: info.identity.proto,
                ports: None,
            });
        }
        // Stack only fragments generated UDP replies. Fragment zero may still expose its ports.
        let (destination, client) = wire::packet_addresses(packet).ok()?;
        let ports = honk_netstack::transit::quote_metadata(packet)
            .and_then(|quote| quote.ports)
            .map(|(src, dst)| (dst, src));
        Some(Self {
            client,
            destination,
            protocol: wire::PROTO_UDP,
            ports,
        })
    }

    fn retains(&self, client: SocketAddr, destination: SocketAddr, protocol: u8) -> bool {
        self.client == client.ip()
            && self.destination == destination.ip()
            && self.protocol == protocol
            && self
                .ports
                .is_none_or(|ports| ports == (client.port(), destination.port()))
    }
}

#[cfg(all(test, target_os = "linux", feature = "ebpf"))]
#[test]
fn exported_udp_fragment_retains_only_its_address_and_protocol_domain() {
    use honk_netstack::wire::{PROTO_TCP, PROTO_UDP};

    for (source, destination, other) in [
        ("192.0.2.1:41000", "198.51.100.1:443", "198.51.100.2:443"),
        (
            "[2001:db8::1]:41000",
            "[2001:db8::2]:443",
            "[2001:db8::3]:443",
        ),
    ] {
        let client: SocketAddr = source.parse().unwrap();
        let destination: SocketAddr = destination.parse().unwrap();
        let other = other.parse().unwrap();
        let now = Instant::now();
        let mut stack = Stack::new(config(1280, &MemoryBudget::new(4 << 20)).unwrap(), now);
        let mut packet = [0; 1280];
        let n = stack
            .udp_send_from(destination, client, &[0; 3000], &mut packet)
            .unwrap();
        let first = HostOutput::from_packet(&packet[..n], None).unwrap();
        assert!(first.retains(client, destination, PROTO_UDP));
        assert!(!first.retains(client, SocketAddr::new(destination.ip(), 444), PROTO_UDP));
        let n = stack.poll_transmit(now, &mut packet).unwrap();
        let tail = HostOutput::from_packet(&packet[..n], None).unwrap();
        assert!(tail.retains(client, destination, PROTO_UDP));
        assert!(!tail.retains(client, other, PROTO_UDP));
        assert!(!tail.retains(client, destination, PROTO_TCP));
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
struct HostUdpInput {
    client: SocketAddr,
    destination: SocketAddr,
    process: ProcessMeta,
    owners: usize,
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[derive(Default)]
pub(super) struct HostUdpInputs {
    slots: Vec<Option<HostUdpInput>>,
    _memory: Option<MemoryReservation>,
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
impl HostUdpInputs {
    // Only new initializers, controller queries and the collector walk live slots.
    fn find(&self, client: SocketAddr, destination: SocketAddr) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|entry| entry.client == client && entry.destination == destination)
        })
    }

    pub(super) fn owns(&self, index: u16, client: SocketAddr, destination: SocketAddr) -> bool {
        self.slots
            .get(usize::from(index))
            .and_then(Option::as_ref)
            .is_some_and(|entry| entry.client == client && entry.destination == destination)
    }

    pub(super) fn retain(&mut self, index: u16) -> ProcessMeta {
        let entry = self.slots[usize::from(index)]
            .as_mut()
            .expect("owned Host UDP input");
        entry.owners = entry.owners.checked_add(1).expect("bounded Host UDP work");
        entry.process
    }

    pub(super) fn release(&mut self, index: u16) {
        let slot = &mut self.slots[usize::from(index)];
        let entry = slot.as_mut().expect("owned Host UDP input");
        entry.owners -= 1;
        if entry.owners == 0 {
            *slot = None;
            while self.slots.last().is_some_and(Option::is_none) {
                self.slots.pop();
            }
        }
    }

    fn insert(&mut self, input: HostUdpInput, budget: &Arc<MemoryBudget>) -> io::Result<u16> {
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.slots.len());
        if index == self.slots.capacity() {
            let max = honk_ebpf_common::xdp_gateway::HOST_META_ENTRIES as usize;
            if index >= max {
                return Err(capacity());
            }
            let next = (index * 2).clamp(4, max);
            let memory = budget
                .reserve(next * size_of::<Option<HostUdpInput>>())
                .ok_or_else(capacity)?;
            self.slots
                .try_reserve_exact(next - index)
                .map_err(io::Error::other)?;
            self._memory = Some(memory);
        }
        if index == self.slots.len() {
            self.slots.push(Some(input));
        } else {
            self.slots[index] = Some(input);
        }
        Ok(index as u16)
    }
}

#[cfg(all(test, target_os = "linux", feature = "ebpf"))]
#[test]
fn host_udp_input_reuse_waits_for_the_last_owner() {
    let budget = MemoryBudget::new(1 << 16);
    let mut active = HostUdpInputs::default();
    let client: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
    let destination: SocketAddr = "[2001:db8::2]:53".parse().unwrap();
    let other = SocketAddr::new(destination.ip(), 443);
    let input = |pid| HostUdpInput {
        client,
        destination,
        process: ProcessMeta::test_gateway(pid, ""),
        owners: 1,
    };
    let index = active.insert(input(17), &budget).unwrap();
    assert_eq!(active.retain(index).pid, 17);
    active.release(index);
    assert_eq!(active.find(client, destination), Some(usize::from(index)));
    assert!(!active.owns(index, client, other));
    let retained = active.retain(index);
    active.release(index);
    active.release(index);
    assert!(active.find(client, destination).is_none());
    let next = active.insert(input(41), &budget).unwrap();
    assert_eq!(active.retain(next).pid, 41);
    assert_eq!(retained.pid, 17);
    active.release(next);
    active.release(next);
    drop(active);
    assert_eq!(budget.used(), 0);
}

#[cfg(all(test, target_os = "linux", feature = "ebpf"))]
#[tokio::test]
async fn shared_reply_source_releases_first_target_and_terminal_drain_clears_binding() {
    use honk_netstack::wire::PROTO_UDP;

    let budget = MemoryBudget::new(4 << 20);
    let (scope, owner) = auxiliary_scope(1280, &budget).unwrap();
    let mut driver = owner.hand_off();
    driver.resume_auxiliary(1280, || true).unwrap();
    let client: SocketAddr = "192.0.2.1:40000".parse().unwrap();
    let target: SocketAddr = "198.51.100.1:443".parse().unwrap();
    let other = SocketAddr::new(target.ip(), 444);
    {
        let mut inner = scope.0.inner.lock();
        let count = inner.frames.len();
        let mut udp = HostUdpInputs::default();
        udp.insert(
            HostUdpInput {
                client,
                destination: target,
                process: ProcessMeta::test_gateway(417, "curl"),
                owners: 0,
            },
            &scope.0.budget,
        )
        .unwrap();
        inner.host_process = Some(HostProcessBinding {
            realm: 2,
            stamp: scope.binding(),
            binding_id: 5,
            lookup: None,
            udp,
            outputs: vec![None; count].into_boxed_slice(),
            _output_memory: scope
                .0
                .budget
                .reserve(count * size_of::<Option<HostOutput>>())
                .unwrap(),
        });
    }
    let mut physical = scope
        .hold_source(client.ip())
        .unwrap()
        .with_peer(crate::xdp::routing_input::test_peer(1, 0, [2; 6], 7));
    assert!(physical.admit_udp_process(client, target).is_err());
    let shared_physical = physical.into_shared_reply_source();
    assert_eq!(shared_physical.source_mac(), Some([2; 6]));
    assert!(shared_physical.packet_input().is_none());
    drop(shared_physical);

    let mut view = scope.hold_source(client.ip()).unwrap();
    view.admit_udp_process(client, target).unwrap();
    let still_host = view
        .clone()
        .with_peer(crate::xdp::routing_input::test_peer(1, 0, [2; 6], 7));
    assert!(still_host.source_mac().is_none());
    assert_eq!(still_host.packet_input().unwrap().0.pid, 417);
    drop(still_host);
    let receiver = view.clone().into_shared_reply_source();
    assert_eq!(view.identity(), receiver.identity());
    assert!(receiver.packet_input().is_none());
    assert!(scope.retains_host_work(client, target, PROTO_UDP));
    drop(view);
    assert!(!scope.retains_host_work(client, target, PROTO_UDP));
    let sender = scope.datagram_sender(other);
    sender.send_to(b"reply", client).await.unwrap();
    let mut outputs = [None];
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        driver.poll_outputs_class(&mut cx, TxClass::Bulk, &mut outputs),
        Poll::Ready(Some(1))
    ));
    assert!(scope.retains_host_work(client, other, PROTO_UDP));
    assert!(!scope.retains_host_work(client, target, PROTO_UDP));
    drop(outputs);
    assert!(!scope.retains_host_work(client, other, PROTO_UDP));
    let last = scope.auxiliary_work().unwrap().unwrap();
    scope.shutdown(true);
    driver.service_closing(&mut cx, Instant::now());
    assert!(!driver.is_returned());
    drop(receiver);
    driver.service_closing(&mut cx, Instant::now());
    assert!(driver.is_returned());
    let mut terminal = std::pin::pin!(driver.wait_auxiliary_work());
    assert!(futures::poll!(&mut terminal).is_pending());
    assert!(scope.0.inner.lock().host_process.is_some());
    drop(last);
    terminal.await.unwrap();
    assert!(scope.0.inner.lock().host_process.is_none());
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
impl HostProcessBinding {
    pub(super) fn udp_input(
        &mut self,
        stamp: u64,
        client: SocketAddr,
        destination: SocketAddr,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<(u16, ProcessMeta)> {
        if self.stamp != stamp {
            return Err(closed());
        }
        if let Some(index) = self.udp.find(client, destination) {
            let index = index as u16;
            return Ok((index, self.udp.retain(index)));
        }
        let process = self.process(stamp, client, destination, honk_netstack::wire::PROTO_UDP)?;
        let index = self.udp.insert(
            HostUdpInput {
                client,
                destination,
                process,
                owners: 1,
            },
            budget,
        )?;
        Ok((index, process))
    }

    pub(super) fn process(
        &self,
        stamp: u64,
        source: SocketAddr,
        destination: SocketAddr,
        protocol: u8,
    ) -> io::Result<ProcessMeta> {
        use honk_ebpf_common::xdp_gateway::{GatewayKey, LocalAddressKey};

        if self.stamp != stamp {
            return Err(closed());
        }
        let src = LocalAddressKey::from(source.ip());
        let dst = LocalAddressKey::from(destination.ip());
        if src.family != dst.family {
            return Err(invalid("gateway Host tuple family mismatch"));
        }
        let key = GatewayKey {
            realm_id: self.realm,
            family: src.family,
            src: src.address,
            dst: dst.address,
            sport: source.port().to_be(),
            dport: destination.port().to_be(),
            proto: protocol,
            reserved: [0; 3],
        };
        let meta = self
            .lookup
            .as_ref()
            .ok_or_else(closed)?
            .lookup(&key, self.binding_id)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "gateway Host admission lost its hold",
                )
            })?;
        ProcessMeta::from_gateway(meta)
    }
}

impl PacketScope {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(in crate::control) fn retains_host_work(
        &self,
        client: SocketAddr,
        destination: SocketAddr,
        protocol: u8,
    ) -> bool {
        let inner = self.0.inner.lock();
        inner
            .stack
            .as_ref()
            .is_some_and(|stack| stack.retains_packet_obligation(client, destination, protocol))
            || (protocol == honk_netstack::wire::PROTO_TCP
                && inner.retains_tcp_with_lineage(client, destination, None))
            || (protocol == honk_netstack::wire::PROTO_UDP
                && inner
                    .host_process
                    .as_ref()
                    .is_some_and(|binding| binding.udp.find(client, destination).is_some()))
            || inner.host_process.as_ref().is_some_and(|binding| {
                binding
                    .outputs
                    .iter()
                    .flatten()
                    .any(|output| output.retains(client, destination, protocol))
            })
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(crate) fn install_host_process_lookup(
        &self,
        realm: u32,
        stamp: u64,
        binding_id: u64,
        lookup: crate::xdp::gateway::HostProcessLookup,
    ) -> io::Result<()> {
        let mut inner = self.0.inner.lock();
        if !self.is_auxiliary()
            || stamp == 0
            || stamp & 1 != 0
            || self.binding() != stamp
            || binding_id == 0
            || inner.aborted
            || inner.closing
            || inner.finished
            || !inner.binding_drained()
            || inner
                .host_process
                .as_ref()
                .is_some_and(|old| old.stamp == stamp || !old.udp.slots.is_empty())
        {
            return Err(invalid("invalid gateway Host process binding"));
        }
        let count = inner.frames.len();
        let output_memory = self
            .0
            .budget
            .reserve(count * size_of::<Option<HostOutput>>())
            .ok_or_else(capacity)?;
        inner.host_process = Some(HostProcessBinding {
            realm,
            stamp,
            binding_id,
            lookup: Some(lookup),
            udp: Default::default(),
            outputs: vec![None; count].into_boxed_slice(),
            _output_memory: output_memory,
        });
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub(in crate::control) fn is_gateway_host(&self) -> bool {
        self.is_auxiliary() && self.0.inner.lock().host_process.is_some()
    }

    pub(in crate::control) fn is_auxiliary(&self) -> bool {
        self.0.auxiliary.is_some()
    }

    pub(crate) fn binding(&self) -> u64 {
        self.0
            .auxiliary
            .as_ref()
            .map_or(0, |aux| aux.stamp.load(Ordering::SeqCst))
    }

    pub(in crate::control) fn auxiliary_active(&self) -> bool {
        self.binding() & 1 == 0
    }

    pub(in crate::control) fn auxiliary_work(&self) -> io::Result<Option<AuxiliaryWork>> {
        let Some(aux) = &self.0.auxiliary else {
            return Ok(None);
        };
        let stamp = self.binding();
        if stamp & 1 != 0 {
            return Err(closed());
        }
        aux.work
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < WORK_CLOSED - 1).then(|| count + 1)
            })
            .map_err(|_| closed())?;
        let work = AuxiliaryWork {
            scope: self.clone(),
            stamp,
        };
        // The increment and this recheck straddle a possible close and even a complete rebind.
        if !work.is_active() {
            return Err(closed());
        }
        Ok(Some(work))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn auxiliary_budget(&self) -> Option<&Arc<MemoryBudget>> {
        self.is_auxiliary().then_some(&self.0.budget)
    }
}

#[cfg(target_os = "linux")]
const LIMITS: RuntimeLimits = RuntimeLimits {
    max_slots: 16,
    control_frames: 2,
    bulk_frames: 6,
    max_waiters: 32,
};

#[cfg(target_os = "linux")]
fn config(mtu: u32, budget: &Arc<MemoryBudget>) -> io::Result<Config> {
    let mut cfg = Config::new(rand::random());
    cfg.mtu = u16::try_from(mtu)
        .ok()
        .filter(|&mtu| mtu >= 1280)
        .ok_or_else(|| invalid("auxiliary MTU outside 1280..=65535"))?;
    cfg.mode = Mode::Transparent {
        exclude: Default::default(),
    };
    cfg.max_flows = LIMITS.max_slots as u32;
    cfg.memory_limit = 512 << 10;
    cfg.fragment_limits.max_entries = 8;
    cfg.fragment_limits.max_bytes = 256 << 10;
    cfg.shared_budget = Some(Arc::clone(budget));
    Ok(cfg)
}

#[cfg(target_os = "linux")]
pub(crate) fn auxiliary_scope(
    mtu: u32,
    root: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketScope, PacketOwner)> {
    let budget = root.child(4 << 20).ok_or_else(capacity)?;
    let memory = budget
        .reserve(size_of::<Auxiliary>() + 2 * size_of::<usize>())
        .ok_or_else(capacity)?;
    let auxiliary = Arc::new(Auxiliary {
        root: Arc::clone(root),
        prepared_mtu: mtu,
        stamp: AtomicU64::new(1),
        work: AtomicUsize::new(WORK_CLOSED),
        cancelled: Notify::new(),
        released: Notify::new(),
        _memory: memory,
    });
    let scope = ScopeId::allocate().ok_or_else(|| invalid("scope identities exhausted"))?;
    Ok(PacketScope::new_partition(
        config(mtu, &budget)?,
        budget,
        LIMITS,
        Instant::now(),
        crate::tun::TX_CAPS,
        crate::tun::MAX_IP_BYTES,
        scope,
        0,
        1,
        None,
        false,
        Some(auxiliary),
    )?)
}

#[cfg(target_os = "linux")]
impl PacketDriver {
    pub(crate) fn is_returned(&self) -> bool {
        // The parked owner may already have reclaimed the returned right.
        let inner = self.scope.0.inner.lock();
        inner.finished && inner.rights != Rights::Driven
    }

    /// Terminal protocol return can precede the final application completion or waiter drop.
    pub(crate) async fn wait_auxiliary_work(&self) -> io::Result<()> {
        let shared = &self.scope.0;
        let aux = shared
            .auxiliary
            .as_ref()
            .ok_or_else(|| invalid("ordinary packet scope"))?;
        loop {
            let released = aux.released.notified();
            {
                let inner = shared.inner.lock();
                if !inner.finished || inner.rights == Rights::Driven {
                    return Err(invalid("packet driver has not returned"));
                }
                if inner.binding_drained() && aux.work.load(Ordering::SeqCst) == WORK_CLOSED {
                    break;
                }
            }
            released.await;
        }
        self.release_host_lookup();
        Ok(())
    }

    pub(in crate::control) fn begin_auxiliary_pause(&mut self) -> io::Result<()> {
        let shared = &self.scope.0;
        let aux = shared
            .auxiliary
            .as_ref()
            .ok_or_else(|| invalid("ordinary packet scope"))?;
        let mut inner = shared.inner.lock();
        if inner.closing || inner.rights != Rights::Driven {
            return Err(closed());
        }
        aux.close();
        inner.turn_needs_scan = None;
        inner.abort();
        let mut wakes = Shared::events(&mut inner, None);
        Shared::wake_terminal_waiters(&mut inner, WaitFor::Credit, &mut wakes);
        drop(inner);
        shared.reap();
        self.fallback = None;
        self.deadline = None;
        resume_wake_panic(wakes);
        Ok(())
    }

    pub(in crate::control) async fn drain_auxiliary(&mut self) -> io::Result<()> {
        let aux = Arc::clone(
            self.scope
                .0
                .auxiliary
                .as_ref()
                .ok_or_else(|| invalid("ordinary packet scope"))?,
        );
        loop {
            tokio::select! {
                result = poll_fn(|cx| {
                    self.service_closing(cx, Instant::now());
                    let inner = self.scope.0.inner.lock();
                    if inner.closing || inner.rights != Rights::Driven { return Poll::Ready(Err(closed())); }
                    if !inner.aborted { return Poll::Ready(Err(invalid("active auxiliary scope"))); }
                    if inner.binding_drained() && aux.work.load(Ordering::SeqCst) == WORK_CLOSED {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    }
                }) => { result?; break; },
                _ = aux.released.notified() => {},
            }
        }
        self.release_host_lookup();
        Ok(())
    }

    fn release_host_lookup(&self) {
        #[cfg(feature = "ebpf")]
        {
            let mut inner = self.scope.0.inner.lock();
            if inner.finished {
                inner.host_process.take();
            } else if let Some(binding) = &mut inner.host_process {
                debug_assert!(
                    binding.udp.slots.is_empty() && binding.outputs.iter().all(Option::is_none)
                );
                binding.lookup.take();
                binding.udp = Default::default();
            }
        }
    }

    pub(in crate::control) fn resume_auxiliary(
        &mut self,
        mtu: u32,
        admit: impl FnOnce() -> bool,
    ) -> io::Result<()> {
        let shared = &self.scope.0;
        let aux = shared
            .auxiliary
            .as_ref()
            .ok_or_else(|| invalid("ordinary packet scope"))?;
        let mut inner = shared.inner.lock();
        if inner.closing || inner.rights != Rights::Driven {
            return Err(closed());
        }
        if !inner.aborted
            || !inner.binding_drained()
            || aux.work.load(Ordering::SeqCst) != WORK_CLOSED
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "auxiliary binding still owned",
            ));
        }
        let stamp = aux
            .stamp
            .load(Ordering::SeqCst)
            .checked_add(1)
            .ok_or_else(capacity)?;
        // Only the initially prepared, never-admitted Stack can still exist here.
        // Release it before allocating a different MTU against the same grant.
        let prepared = inner.stack.take().filter(|_| aux.prepared_mtu == mtu);
        let mut stack = match prepared {
            Some(stack) => stack,
            None => Stack::new_accounted(
                config(mtu, &shared.budget)?,
                Instant::now(),
                LIMITS.max_slots,
            )
            .map_err(io::Error::other)?,
        };
        if !admit() {
            return Err(closed());
        }
        stack.set_accepting(true);
        inner.stack = Some(stack);
        inner.pending_closes = 0;
        inner.reap_pending = false;
        inner.next_tx = TxClass::Control;
        inner.aborted = false;
        aux.stamp.store(stamp, Ordering::SeqCst);
        aux.work.store(0, Ordering::SeqCst);
        self.fallback = None;
        self.deadline = None;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Inner {
    fn binding_drained(&self) -> bool {
        self.slots.iter().all(Option::is_none)
            && self.source_work.is_empty()
            && self.waiters.iter().all(Option::is_none)
            && self.queued == 0
            && self.ledger.outstanding_tx().next().is_none()
            && self.stack.as_ref().is_none_or(Stack::is_quiescent)
    }
}
