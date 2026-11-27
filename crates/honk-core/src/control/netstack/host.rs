//! Host socket identity retained through packet output and reply ownership.
use super::*;

pub(super) struct HostProcessBinding {
    realm: u32,
    stamp: u64,
    binding_id: u64,
    lookup: Option<crate::xdp::gateway::HostProcessLookup>,
    pub(super) udp: HostUdpInputs,
    pub(super) outputs: Box<[Option<HostOutput>]>,
    _output_memory: MemoryReservation,
}

#[derive(Clone, Copy)]
pub(super) struct HostOutput {
    client: IpAddr,
    destination: IpAddr,
    protocol: u8,
    ports: Option<(u16, u16)>,
}

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

#[cfg(test)]
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
        let mut stack = Stack::new(
            auxiliary::config(1280, &MemoryBudget::new(4 << 20)).unwrap(),
            now,
        );
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

struct HostUdpInput {
    client: SocketAddr,
    destination: SocketAddr,
    process: ProcessMeta,
    owners: usize,
}

#[derive(Default)]
pub(super) struct HostUdpInputs {
    slots: Vec<Option<HostUdpInput>>,
    _memory: Option<MemoryReservation>,
}

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

#[cfg(test)]
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

#[cfg(test)]
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

impl HostProcessBinding {
    pub(super) fn release_lookup(&mut self) {
        debug_assert!(self.udp.slots.is_empty() && self.outputs.iter().all(Option::is_none));
        self.lookup.take();
        self.udp = Default::default();
    }

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

    pub(in crate::control) fn is_gateway_host(&self) -> bool {
        self.is_auxiliary() && self.0.inner.lock().host_process.is_some()
    }
}
