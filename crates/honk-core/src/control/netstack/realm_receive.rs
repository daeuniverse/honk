use super::*;
#[cfg(target_os = "linux")]
use crate::xdp::worker::{PeerAuthority, PeerHold, PeerObservation, PeerPathChanged};

#[cfg(target_os = "linux")]
pub(crate) struct RealmRxBatch<'a> {
    owner: &'a PacketScope,
    inner: Option<parking_lot::MutexGuard<'a, Inner>>,
    path: crate::xdp::ReturnPath,
    service_at: Instant,
    checked: Option<PeerObservation<'a>>,
    // Indices remain pinned by the scope guard; protocol generation still gets checked on every input.
    last: Option<(usize, usize)>,
}

#[cfg(target_os = "linux")]
impl<'a> RealmRxBatch<'a> {
    /// None leaves this packet untouched for ordinary dispatch. The caller flushes before fallback.
    pub(crate) fn receive(
        batch: &mut Option<Self>,
        owner: &'a PacketScope,
        packet: &[u8],
        (ingress_at, service_at): (Instant, Instant),
        path: crate::xdp::ReturnPath,
        peers: &'a PeerAuthority,
        can_batch: impl FnOnce() -> bool,
    ) -> Option<super::super::packet_endpoint::PacketReceive> {
        Self::receive_with(
            batch,
            owner,
            packet,
            service_at,
            path,
            can_batch,
            |stack, peer, checked| {
                let (_, report) = stack.receive_reported(
                    packet,
                    ReceiveOptions::new(ingress_at, RxMeta::VERIFY)
                        .with_realm(service_at, &mut |_| false),
                    |source, _| {
                        peers
                            .confirm_tcp::<false>(
                                peer,
                                owner.scope(),
                                source,
                                path,
                                ingress_at,
                                checked,
                            )
                            .unwrap_or(false)
                    },
                );
                Ok::<_, std::convert::Infallible>(report)
            },
        )
        .transpose()
        .unwrap()
    }

    /// A moved path retries with the scalar pending-output check, after unlocking the batch.
    pub(crate) fn receive_sharded(
        batch: &mut Option<Self>,
        owner: &'a PacketScope,
        packet: &[u8],
        (ingress_at, service_at): (Instant, Instant),
        path: crate::xdp::ReturnPath,
        peers: &'a PeerAuthority,
        can_batch: impl FnOnce() -> bool,
    ) -> Result<Option<super::super::packet_endpoint::PacketReceive>, PeerPathChanged> {
        Self::receive_with(
            batch,
            owner,
            packet,
            service_at,
            path,
            can_batch,
            |stack, peer, checked| {
                stack.try_receive_realm_tcp(ingress_at, service_at, packet, |source| {
                    peers.confirm_tcp::<true>(
                        peer,
                        owner.scope(),
                        source,
                        path,
                        ingress_at,
                        checked,
                    )
                })
            },
        )
        .transpose()
    }

    fn receive_with<E>(
        batch: &mut Option<Self>,
        owner: &'a PacketScope,
        packet: &[u8],
        service_at: Instant,
        path: crate::xdp::ReturnPath,
        can_batch: impl FnOnce() -> bool,
        receive: impl FnOnce(
            &mut Stack,
            &PeerHold,
            &mut Option<PeerObservation<'a>>,
        ) -> Result<honk_netstack::ReceiveReport, E>,
    ) -> Option<Result<super::super::packet_endpoint::PacketReceive, E>> {
        use honk_netstack::wire::{self, tcp};

        if batch
            .as_ref()
            .is_some_and(|run| !run.owner.same_owner(owner) || run.path != path)
        {
            return None;
        }
        let ip = wire::parse_ip(packet).ok()?;
        if ip.proto != wire::PROTO_TCP {
            return None;
        }
        let (header, _) = tcp::parse(&packet[ip.payload]).ok()?;
        if header.flags & (tcp::SYN | tcp::FIN | tcp::RST | tcp::ACK) != tcp::ACK {
            return None;
        }
        let run = batch.get_or_insert_with(|| Self {
            owner,
            inner: Some(owner.0.inner.lock()),
            path,
            service_at,
            checked: None,
            last: None,
        });
        let inner: &mut Inner = run.inner.as_mut().expect("locked receive batch");
        // No other actor can publish a CPU frame or export a lease while this guard lives.
        // TCP schedules an output poll on every input, including pure ACKs with no wire reply.
        if run.last.is_none()
            && (inner.closing
                || inner.aborted
                || inner.finished
                || inner.closed_apps != 0
                || inner.pending_closes != 0
                || inner.queued != 0
                || inner.source_work.is_host()
                || inner.resources.is_none()
                || inner.slots.iter().all(Option::is_some))
            || inner
                .capture_admission
                .as_ref()
                .is_some_and(|gate| !gate.load(std::sync::atomic::Ordering::Acquire))
        {
            return None;
        }
        let stack = inner.stack.as_mut()?;
        if stack.has_pending_accept() || stack.poll_timeout().is_some_and(|at| at <= service_at) {
            return None;
        }
        let client = SocketAddr::new(ip.src, header.src_port);
        let destination = SocketAddr::new(ip.dst, header.dst_port);
        let admitted = |slot: &FlowSlot| {
            slot.client == client
                && slot.destination == destination
                && slot.app_open
                && slot.rx_admitted
                && !slot.retiring
                && stack.tcp_state(slot.id) == Some(honk_netstack::TcpState::Established)
        };
        let (flow_index, peer_index) = match run.last {
            Some((flow, peer)) if inner.slots[flow].as_ref().is_some_and(admitted) => (flow, peer),
            _ => {
                let flow = inner
                    .slots
                    .iter()
                    .position(|slot| slot.as_ref().is_some_and(admitted))?;
                let peer = inner.peers[..inner.peer_end].iter().position(|entry| {
                    entry.as_ref().is_some_and(|peer| {
                        peer.address() == ip.src && peer.learned() && peer.original_path() == path
                    })
                })?;
                (flow, peer)
            }
        };
        let slot = inner.slots[flow_index].as_ref().expect("pinned flow slot");
        let id = slot.id;
        let peer = inner.peers[peer_index]
            .as_ref()
            .expect("pinned physical peer");
        if !can_batch() {
            return None;
        }
        let _unwind = AdmissionUnwind(inner.capture_admission.as_deref());
        let report = match receive(stack, peer, &mut run.checked) {
            Ok(report) => report,
            Err(reason) => return Some(Err(reason)),
        };
        run.service_at = service_at;
        run.last = Some((flow_index, peer_index));
        let original =
            (report.outcome == honk_netstack::ReceiveOutcome::TcpAccepted(id)).then_some(slot);
        Some(Ok(Inner::receive_from_slot(report, original)))
    }
}

#[cfg(target_os = "linux")]
impl Drop for RealmRxBatch<'_> {
    fn drop(&mut self) {
        let mut inner = self.inner.take().expect("locked receive batch");
        if std::thread::panicking() {
            if let Some(gate) = &inner.capture_admission {
                gate.store(false, std::sync::atomic::Ordering::Release);
            }
        } else if self.last.is_some() {
            inner.advance(self.service_at);
            self.owner.0.finish_with(inner);
        }
    }
}

impl PacketScope {
    pub(in crate::control) fn after_receive(&self) {
        self.0.with(|_| ());
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn peer_hold(&self, address: IpAddr) -> Option<crate::xdp::worker::PeerHold> {
        self.0
            .inner
            .lock()
            .peers
            .iter()
            .flatten()
            .find(|peer| peer.address() == address)
            .cloned()
    }

    pub(crate) fn reassemble_for_dispatch(
        &self,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
    ) -> Result<Option<honk_netstack::OwnedPacket>, DropReason> {
        if self.worker() != 0 {
            return Err(DropReason::NotForUs);
        }
        self.0.with(|inner| {
            if inner.aborted
                || inner
                    .capture_admission
                    .as_ref()
                    .is_some_and(|admission| !admission.load(std::sync::atomic::Ordering::Acquire))
            {
                return Err(DropReason::Stale);
            }
            inner
                .stack
                .as_mut()
                .ok_or(DropReason::Stale)?
                .reassemble_for_dispatch(ingress_at, service_at, packet)
                .map(|report| report.packet)
                .map_err(|error| error.reason)
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn reassemble_for_dispatch_with_peer(
        &self,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
        peer: Option<crate::xdp::worker::PeerHold>,
    ) -> Result<
        Option<(
            honk_netstack::OwnedPacket,
            Option<crate::xdp::worker::PeerHold>,
        )>,
        DropReason,
    > {
        self.0.with(|inner| {
            inner.reassemble_for_dispatch_with_peer(packet, ingress_at, service_at, peer)
        })
    }

    #[cfg(target_os = "linux")]
    pub(in crate::control) fn receive_realm_timed(
        &self,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
        admission: &mut Option<super::super::packet_endpoint::EndpointAdmission>,
        check_output: bool,
        on_source: impl FnMut(
            honk_netstack::ValidatedSource,
            bool,
        ) -> Option<crate::xdp::worker::PeerHold>,
    ) -> io::Result<(
        Rx,
        super::super::packet_endpoint::PacketReceive,
        Option<SourceWork>,
    )> {
        self.0.with_silent(|inner| {
            inner.receive_realm_timed(
                self,
                packet,
                ingress_at,
                service_at,
                admission,
                check_output,
                on_source,
            )
        })
    }
}

impl Inner {
    #[cfg(target_os = "linux")]
    pub(super) fn reassemble_for_dispatch_with_peer(
        &mut self,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
        peer: Option<crate::xdp::worker::PeerHold>,
    ) -> Result<
        Option<(
            honk_netstack::OwnedPacket,
            Option<crate::xdp::worker::PeerHold>,
        )>,
        DropReason,
    > {
        if self.worker != 0 {
            return Err(DropReason::NotForUs);
        }
        if self.aborted
            || self
                .capture_admission
                .as_ref()
                .is_some_and(|admission| !admission.load(std::sync::atomic::Ordering::Acquire))
        {
            return Err(DropReason::Stale);
        }
        self.advance(service_at);
        self.reap_peers();
        if let Some(peer) = peer.as_ref().filter(|peer| peer.learned()) {
            if honk_netstack::wire::packet_addresses(packet)
                .ok()
                .map(|(source, _)| source)
                != Some(peer.address())
            {
                return Err(DropReason::NotForUs);
            }
            self.remember_peer(peer);
        }
        let input = packet;
        let (packet, fragment, failure) = match self
            .stack
            .as_mut()
            .ok_or(DropReason::Stale)?
            .reassemble_for_dispatch(ingress_at, service_at, packet)
        {
            Ok(report) => (report.packet, report.fragment, None),
            Err(error) => match error.fragment {
                Some(fragment) => (None, fragment, Some(error.reason)),
                None => return Err(error.reason),
            },
        };
        if fragment.incarnation.is_none() {
            return match packet {
                Some(packet) => Ok(Some((packet, peer))),
                None => match failure {
                    Some(reason) => Err(reason),
                    None => Ok(None),
                },
            };
        }
        let previous = if self.fragment_peer_count == 0 {
            None
        } else {
            self.fragment_peers.iter().position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| entry.info.incarnation == fragment.incarnation)
            })
        };
        if peer.is_none() && previous.is_none() {
            return match packet {
                Some(packet) => Ok(Some((packet, None))),
                None => match failure {
                    Some(reason) => Err(reason),
                    None => Ok(None),
                },
            };
        }
        let is_offset_zero =
            super::fragment_peer::fragment_offset_zero(&[input]).ok_or(DropReason::Malformed)?;
        let mut entry = match previous {
            Some(index) => {
                self.fragment_peer_count -= 1;
                self.fragment_peers[index]
                    .take()
                    .expect("exact fragment return snapshot")
            }
            None => FragmentPeer::new(fragment, None),
        };
        let poisoned = entry.observe(fragment, is_offset_zero, peer).is_err();
        self.reap_fragment_peers();
        if let Some(packet) = packet {
            if poisoned {
                return Err(DropReason::NotForUs);
            }
            return Ok(Some((packet, entry.peer)));
        }
        if self
            .stack
            .as_ref()
            .expect("live reassembler")
            .retains_fragment(fragment)
        {
            let cell = self
                .fragment_peers
                .iter_mut()
                .find(|cell| cell.is_none())
                .ok_or(DropReason::Capacity)?;
            *cell = Some(entry);
            self.fragment_peer_count += 1;
        }
        if poisoned {
            return Err(DropReason::NotForUs);
        }
        match failure {
            Some(reason) => Err(reason),
            None => Ok(None),
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn receive_realm_timed(
        &mut self,
        scope: &PacketScope,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
        admission: &mut Option<super::super::packet_endpoint::EndpointAdmission>,
        check_output: bool,
        mut on_source: impl FnMut(
            honk_netstack::ValidatedSource,
            bool,
        ) -> Option<crate::xdp::worker::PeerHold>,
    ) -> io::Result<(
        Rx,
        super::super::packet_endpoint::PacketReceive,
        Option<SourceWork>,
    )> {
        self.advance(service_at);
        self.drain_half_open();
        self.reap_peers();
        let pending = check_output && self.pending_source_output(packet);
        let has_peer_slot = honk_netstack::wire::packet_addresses(packet)
            .is_ok_and(|(address, _)| self.peer_cell(address).is_some());
        let mut peer = None;
        let (rx, report) = self.receive_checked(
            packet,
            RxMeta::VERIFY,
            ingress_at,
            service_at,
            Some(admission),
            |source| {
                peer = on_source(source, pending);
                if peer.as_ref().is_some_and(|peer| peer.learned()) && !has_peer_slot {
                    peer.take();
                }
                peer.is_some()
            },
        );
        if let Some(hold) = peer.as_ref().filter(|peer| peer.learned()) {
            self.remember_peer(hold);
        }
        self.advance(service_at);
        self.drain_half_open();
        // Shutdown can abort the scope as soon as this receive releases its lock.
        let physical = match &rx {
            Rx::Transparent { src, .. }
            | Rx::TransparentOwned { src, .. }
            | Rx::TransparentSplit { src, .. } => {
                let work = if scope.is_local() {
                    let Some(work) = scope.local_source_work(src.ip())? else {
                        return Ok((
                            Rx::Dropped(DropReason::Stale),
                            self.receive_result(report),
                            None,
                        ));
                    };
                    work
                } else {
                    SourceWork::plain(scope, self, src.ip())?
                };
                Some(match peer.filter(|peer| peer.learned()) {
                    Some(peer) => work.with_peer(peer),
                    None => work,
                })
            }
            _ => None,
        };
        Ok((rx, self.receive_result(report), physical))
    }
}

impl Inner {
    #[cfg(any(test, all(target_os = "linux", feature = "packet-ebpf")))]
    pub(super) fn bind_host_process(
        &mut self,
        rx: Rx,
        report: honk_netstack::ReceiveReport,
        lookup: impl FnOnce(&Self, honk_netstack::ValidatedSource) -> io::Result<ProcessMeta>,
    ) -> (Rx, super::super::packet_endpoint::PacketReceive) {
        if let honk_netstack::ReceiveOutcome::TcpNew(id) = report.outcome {
            let source = report
                .source
                .expect("new TCP admission has a validated tuple");
            match lookup(self, source) {
                Ok(process) => self.register_tcp_new(&report, &mut None, Some(process)),
                Err(error) => {
                    self.stack
                        .as_mut()
                        .expect("new TCP flow")
                        .tcp_refuse(id, honk_netstack::Refuse::Drop);
                    tracing::debug!(%error, "gateway Host TCP admission refused");
                    return (Rx::Dropped(DropReason::Stale), Default::default());
                }
            }
        }
        (rx, self.receive_result(report))
    }

    pub(super) fn register_tcp_new(
        &mut self,
        report: &honk_netstack::ReceiveReport,
        admission: &mut Option<super::super::packet_endpoint::EndpointAdmission>,
        process: Option<ProcessMeta>,
    ) {
        let honk_netstack::ReceiveOutcome::TcpNew(id) = report.outcome else {
            return;
        };
        let vacant = self.slots.iter().position(Option::is_none);
        self.bind_new_flow(id, report, Some(admission), vacant, process);
    }

    pub(super) fn receive_checked(
        &mut self,
        packet: &[u8],
        meta: RxMeta,
        ingress_at: Instant,
        service_at: Instant,
        routing: Option<&mut Option<super::super::packet_endpoint::EndpointAdmission>>,
        mut on_source: impl FnMut(honk_netstack::ValidatedSource) -> bool,
    ) -> (Rx, honk_netstack::ReceiveReport) {
        if self.aborted
            || self
                .capture_admission
                .as_ref()
                .is_some_and(|admission| !admission.load(std::sync::atomic::Ordering::Acquire))
        {
            return (Rx::Dropped(DropReason::Stale), Default::default());
        }
        if self.resources.is_none() {
            let Some(stack) = &mut self.stack else {
                return (Rx::Dropped(DropReason::Stale), Default::default());
            };
            let (rx, report) = stack.receive_reported(
                packet,
                ReceiveOptions::new(ingress_at, meta),
                |source, _| on_source(source),
            );
            if let Some(routing) = routing
                && let honk_netstack::ReceiveOutcome::TcpNew(id) = report.outcome
            {
                let vacant = self.slots.iter().position(Option::is_none);
                self.bind_new_flow(id, &report, Some(routing), vacant, None);
            }
            return (rx, report);
        }
        self.advance(service_at);
        let resources = self.resources.as_ref().expect("accounted realm resources");
        let track = resources.tracks_tcp();
        let tuple = std::cell::Cell::new(None);
        let mut claim = None;
        let mut grant = None;
        let mut vacant_flow = None;
        let Some(stack) = &mut self.stack else {
            return (Rx::Dropped(DropReason::Stale), Default::default());
        };
        let (rx, report) = {
            let _unwind = AdmissionUnwind(self.capture_admission.as_deref());
            stack.receive_reported(
                packet,
                ReceiveOptions::new(ingress_at, meta).with_realm(service_at, &mut |address| {
                    let Some(index) = self.half_open.iter().position(Option::is_none) else {
                        return false;
                    };
                    if track || routing.is_some() {
                        vacant_flow = self.slots.iter().position(Option::is_none);
                        if track && vacant_flow.is_none() {
                            return false;
                        }
                    }
                    let Some(hold) = resources.reserve(address) else {
                        return false;
                    };
                    if track {
                        let (src, dst) = tuple.get().expect("checked SYN before passive admission");
                        let Ok(reserved) = resources.reserve_tcp(self.worker, src, dst) else {
                            return false;
                        };
                        claim = reserved;
                    }
                    grant = Some((index, hold));
                    true
                }),
                |source, _| {
                    if track
                        && source
                            .tcp_flags
                            .is_some_and(|flags| flags & honk_netstack::wire::tcp::SYN != 0)
                    {
                        tuple.set(Some((source.src, source.dst)));
                    }
                    on_source(source)
                },
            )
        };
        if let honk_netstack::ReceiveOutcome::TcpNew(id) = report.outcome {
            let (index, hold) = grant.expect("realm passive open has half-open credit");
            self.half_open[index] = Some((id, hold));
            if let Some(claim) = claim {
                claim.publish(id);
            }
            if track || routing.is_some() {
                self.bind_new_flow(id, &report, routing, vacant_flow, None);
            }
        }
        (rx, report)
    }

    fn bind_new_flow(
        &mut self,
        id: FlowId,
        report: &honk_netstack::ReceiveReport,
        routing: Option<&mut Option<super::super::packet_endpoint::EndpointAdmission>>,
        vacant: Option<usize>,
        process: Option<ProcessMeta>,
    ) {
        let source = report
            .source
            .expect("new TCP admission has a validated tuple");
        let Some(index) = vacant else {
            self.stack
                .as_mut()
                .expect("live scope stack")
                .tcp_refuse(id, honk_netstack::Refuse::Drop);
            return;
        };
        self.slots[index] = Some(FlowSlot {
            id,
            client: source.src,
            destination: source.dst,
            app_open: true,
            close_pending: false,
            retiring: false,
            outputs: 0,
            rx: None,
            tx: None,
            callback: None,
            accepted: false,
            rx_admitted: false,
            routing: routing.and_then(Option::take),
            source: report.source_context,
            process,
        });
        #[cfg(target_os = "linux")]
        if let Some(indexes) = &mut self.local_slots {
            indexes.insert(id, index);
            self.local_pending.push(id);
        }
        #[cfg(target_os = "linux")]
        self.pin_local_tcp(source.src.ip());
        self.pending_routing += 1;
    }

    #[cfg(target_os = "linux")]
    pub(super) fn remember_peer(&mut self, hold: &crate::xdp::worker::PeerHold) {
        if !hold.learned() {
            return;
        }
        if let Some(index) = self.peer_cell(hold.address()) {
            if let Some(local) = &mut self.local_peers {
                local.install_peer(hold.address(), index);
            }
            self.peers[index] = Some(hold.clone());
            self.peer_end = self.peer_end.max(index + 1);
        }
    }

    pub(super) fn drain_half_open(&mut self) {
        while let Some(id) = self.stack.as_mut().and_then(Stack::poll_half_open_released) {
            if let Some(entry) = self
                .half_open
                .iter_mut()
                .find(|entry| entry.as_ref().is_some_and(|(held, _)| *held == id))
            {
                entry.take();
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn reap_peers(&mut self) {
        self.reap_fragment_peers();
        if self.local_peers.is_some() {
            return;
        }
        for peer in &mut self.peers[..self.peer_end] {
            let Some(held) = peer else { continue };
            let address = held.address();
            if !self
                .stack
                .as_ref()
                .is_some_and(|stack| stack.retains_source(address))
                && !self
                    .slots
                    .iter()
                    .flatten()
                    .any(|slot| slot.client.ip() == address)
                && !self.output_peers.contains(&Some(address))
                && !self.source_work.retains_address(address)
            {
                peer.take();
            }
        }
        while self.peer_end != 0 && self.peers[self.peer_end - 1].is_none() {
            self.peer_end -= 1;
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn reap_fragment_peers(&mut self) {
        if self.fragment_peer_count == 0 {
            return;
        }
        let stack = self.stack.as_ref();
        for entry in &mut self.fragment_peers {
            if entry
                .as_ref()
                .is_some_and(|entry| !stack.is_some_and(|stack| stack.retains_fragment(entry.info)))
            {
                entry.take();
                self.fragment_peer_count -= 1;
            }
        }
    }

    pub(super) fn transmit_accounted(
        stack: &mut Stack,
        resources: &Option<Arc<RealmResources>>,
        now: Instant,
        class: TxClass,
        output: &mut [u8],
        caps: TxCaps,
    ) -> Result<Option<(Transmit, Option<honk_netstack::FragmentInfo>)>, io::ErrorKind> {
        use honk_netstack::AccountedTransmit;
        let Some(resources) = resources else {
            return Ok(match class {
                TxClass::Control => stack.poll_control_transmit(now, output),
                TxClass::Bulk => stack.poll_transmit_with(now, output, caps),
            }
            .map(|tx| (tx, None)));
        };
        let control = class == TxClass::Control;
        let mut short = false;
        for _ in 0..3 {
            match stack.poll_transmit_accounted(now, output, control, None) {
                AccountedTransmit::Packet(tx) => {
                    return Ok(Some((tx, stack.take_fragment_output())));
                }
                AccountedTransmit::Idle => break,
                AccountedTransmit::BufferTooSmall => {
                    short = true;
                    break;
                }
                AccountedTransmit::NeedsIcmp => {
                    let mut state = resources.icmp.lock();
                    let service_at = Instant::now().max(state.1);
                    state.1 = service_at;
                    match stack.poll_transmit_accounted(
                        service_at,
                        output,
                        control,
                        Some(&mut state.0),
                    ) {
                        AccountedTransmit::Packet(tx) => {
                            return Ok(Some((tx, stack.take_fragment_output())));
                        }
                        AccountedTransmit::BufferTooSmall => short = true,
                        AccountedTransmit::Idle => {}
                        AccountedTransmit::NeedsIcmp => unreachable!("ICMP limiter supplied"),
                    }
                }
            }
        }
        if short {
            Err(io::ErrorKind::InvalidInput)
        } else {
            Ok(None)
        }
    }
}

impl PacketOwner {
    pub(crate) fn owns(&self, scope: &PacketScope) -> bool {
        self.scope.same_owner(scope)
    }
    pub(crate) fn packet_scope(&self) -> &PacketScope {
        &self.scope
    }
}

struct AdmissionUnwind<'a>(Option<&'a std::sync::atomic::AtomicBool>);
impl Drop for AdmissionUnwind<'_> {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some(admission) = self.0
        {
            admission.store(false, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod fragment_tests {
    use super::*;
    use crate::xdp::routing_input::{test_fragments, test_peer};
    use std::time::Duration;

    fn physical_scope(budget: &Arc<MemoryBudget>) -> (PacketScope, PacketOwner) {
        let (mut scopes, mut owners) =
            realm::capture_partition(1280, 1, 16, 1, 1280, TxCaps::NONE, budget, 1, false).unwrap();
        (scopes.pop().unwrap(), owners.pop().unwrap())
    }

    #[tokio::test]
    async fn realm_mixed_mac_completion_never_dispatches_and_poison_expires() {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let (scope, owner) = physical_scope(&budget);
        let now = Instant::now();
        let fragments = test_fragments();
        assert!(
            scope
                .reassemble_for_dispatch_with_peer(
                    &fragments[0],
                    now,
                    now,
                    Some(test_peer(1, 0, [2; 6], 7))
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(scope.0.inner.lock().fragment_peer_count, 1);
        assert!(
            scope
                .reassemble_for_dispatch_with_peer(
                    &fragments[1],
                    now,
                    now,
                    Some(test_peer(1, 0, [4; 6], 7))
                )
                .is_err()
        );
        let retained = budget.used();
        assert!(
            scope
                .reassemble_for_dispatch_with_peer(
                    &fragments[2],
                    now,
                    now,
                    Some(test_peer(1, 0, [2; 6], 7))
                )
                .is_err()
        );
        assert!(
            budget.used() < retained,
            "poisoned OwnedPacket is released at completion"
        );
        assert!(
            scope
                .0
                .inner
                .lock()
                .fragment_peers
                .iter()
                .all(Option::is_none)
        );
        assert_eq!(scope.0.inner.lock().fragment_peer_count, 0);
        owner.shutdown().await;

        let (scope, owner) = physical_scope(&budget);
        assert!(
            scope
                .reassemble_for_dispatch_with_peer(
                    &fragments[1],
                    now,
                    now,
                    Some(test_peer(1, 0, [2; 6], 7))
                )
                .unwrap()
                .is_none()
        );
        assert!(
            scope
                .reassemble_for_dispatch_with_peer(
                    &fragments[2],
                    now,
                    now,
                    Some(test_peer(1, 0, [4; 6], 7))
                )
                .is_err()
        );
        let retained = budget.used();
        scope.drive(now + Duration::from_secs(31));
        assert!(
            budget.used() < retained,
            "bounded reassembler reclaims pending poisoned bytes"
        );
        assert!(
            scope
                .0
                .inner
                .lock()
                .fragment_peers
                .iter()
                .all(Option::is_none)
        );
        assert_eq!(scope.0.inner.lock().fragment_peer_count, 0);
        owner.shutdown().await;
    }

    #[tokio::test]
    async fn realm_fragment_zero_selects_original_member_and_rejects_other_realms() {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let (scope, owner) = physical_scope(&budget);
        let now = Instant::now();
        let fragments = test_fragments();
        for index in [1, 0] {
            assert!(
                scope
                    .reassemble_for_dispatch_with_peer(
                        &fragments[index],
                        now,
                        now,
                        Some(test_peer(
                            1,
                            index,
                            [2; 6],
                            7 | if index == 0 { 0xa000 } else { 0 }
                        ))
                    )
                    .unwrap()
                    .is_none()
            );
        }
        let (packet, peer) = scope
            .reassemble_for_dispatch_with_peer(
                &fragments[2],
                now,
                now,
                Some(test_peer(1, 2, [2; 6], 7)),
            )
            .unwrap()
            .unwrap();
        let path = peer.unwrap().original_path();
        assert_eq!(path.device, 0);
        assert_eq!(path.vlan_tci[0], 0xa007);
        drop(packet);
        assert!(
            scope
                .reassemble_for_dispatch_with_peer(
                    &fragments[0],
                    now,
                    now,
                    Some(test_peer(1, 0, [2; 6], 7))
                )
                .unwrap()
                .is_none()
        );
        assert!(
            scope
                .reassemble_for_dispatch_with_peer(
                    &fragments[1],
                    now,
                    now,
                    Some(test_peer(2, 1, [2; 6], 7))
                )
                .is_err()
        );
        assert!(
            scope
                .reassemble_for_dispatch_with_peer(
                    &fragments[2],
                    now,
                    now,
                    Some(test_peer(1, 0, [2; 6], 7))
                )
                .is_err()
        );
        owner.shutdown().await;
    }

    #[tokio::test]
    async fn tun_fragment_completion_keeps_mac_missing() {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let (scope, owner) = capture_scope(1280, 1, 16, &budget).unwrap();
        let now = Instant::now();
        let fragments = test_fragments();
        for index in [1, 0] {
            assert!(
                scope
                    .reassemble_for_dispatch_with_peer(&fragments[index], now, now, None)
                    .unwrap()
                    .is_none()
            );
        }
        let (packet, peer) = scope
            .reassemble_for_dispatch_with_peer(&fragments[2], now, now, None)
            .unwrap()
            .unwrap();
        assert!(peer.is_none());
        drop(packet);
        owner.shutdown().await;
    }
}
