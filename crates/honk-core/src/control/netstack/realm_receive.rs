use super::*;

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
            if inner
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
        if self.worker() != 0 {
            return Err(DropReason::NotForUs);
        }
        self.0.with(|inner| {
            if inner
                .capture_admission
                .as_ref()
                .is_some_and(|admission| !admission.load(std::sync::atomic::Ordering::Acquire))
            {
                return Err(DropReason::Stale);
            }
            inner.advance(service_at);
            inner.reap_peers();
            if let Some(peer) = peer.as_ref().filter(|peer| peer.learned()) {
                if honk_netstack::wire::packet_addresses(packet)
                    .ok()
                    .map(|(source, _)| source)
                    != Some(peer.address())
                {
                    return Err(DropReason::NotForUs);
                }
                inner.remember_peer(peer);
            }
            let (packet, fragment, failure) = match inner
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
            let previous = inner.fragment_peers.iter().position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| entry.info.incarnation == fragment.incarnation)
            });
            let mut peer = peer;
            let mut entry = match previous {
                Some(index) => inner.fragment_peers[index]
                    .take()
                    .expect("exact fragment return snapshot"),
                None => FragmentPeer::new(fragment, peer.take()),
            };
            entry.observe(fragment, ingress_at, peer.take());
            inner.reap_fragment_peers();
            if let Some(packet) = packet {
                return Ok(Some((packet, entry.peer)));
            }
            if inner
                .stack
                .as_ref()
                .expect("live reassembler")
                .retains_fragment(fragment)
            {
                let cell = inner
                    .fragment_peers
                    .iter_mut()
                    .find(|cell| cell.is_none())
                    .ok_or(DropReason::Capacity)?;
                *cell = Some(entry);
            }
            match failure {
                Some(reason) => Err(reason),
                None => Ok(None),
            }
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
        mut on_source: impl FnMut(
            honk_netstack::ValidatedSource,
            bool,
        ) -> Option<crate::xdp::worker::PeerHold>,
    ) -> (
        Rx,
        super::super::packet_endpoint::PacketReceive,
        Option<crate::xdp::worker::PeerHold>,
    ) {
        self.0.with_silent(|inner| {
            inner.advance(service_at);
            inner.drain_half_open();
            inner.reap_peers();
            let pending = check_output && inner.pending_source_output(packet);
            let peer_slot =
                honk_netstack::wire::packet_addresses(packet)
                    .ok()
                    .and_then(|(address, _)| {
                        inner
                            .peers
                            .iter()
                            .position(|peer| {
                                peer.as_ref().is_some_and(|peer| peer.address() == address)
                            })
                            .or_else(|| inner.peers.iter().position(Option::is_none))
                    });
            let mut peer = None;
            let (rx, report) =
                inner.receive_checked(packet, RxMeta::VERIFY, ingress_at, service_at, |source| {
                    peer = on_source(source, pending);
                    if peer.as_ref().is_some_and(|peer| peer.learned()) && peer_slot.is_none() {
                        peer.take();
                    }
                    peer.is_some()
                });
            if let Some(hold) = peer.as_ref().filter(|peer| peer.learned()) {
                inner.remember_peer(hold);
            }
            if let honk_netstack::ReceiveOutcome::TcpNew(id) = report.outcome {
                if let Some(index) = inner.slots.iter().position(Option::is_none) {
                    let source = report.source.expect("new TCP has verified tuple");
                    inner.slots[index] = Some(FlowSlot {
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
                        routing: admission.take(),
                        source: None,
                    });
                    inner.pending_routing += 1;
                } else {
                    inner
                        .stack
                        .as_mut()
                        .expect("live realm stack")
                        .tcp_refuse(id, honk_netstack::Refuse::Drop);
                }
            }
            inner.advance(service_at);
            inner.drain_half_open();
            (rx, inner.receive_result(report), peer)
        })
    }
}

impl Inner {
    pub(super) fn receive_checked(
        &mut self,
        packet: &[u8],
        meta: RxMeta,
        ingress_at: Instant,
        service_at: Instant,
        on_source: impl FnMut(honk_netstack::ValidatedSource) -> bool,
    ) -> (Rx, honk_netstack::ReceiveReport) {
        if self
            .capture_admission
            .as_ref()
            .is_some_and(|admission| !admission.load(std::sync::atomic::Ordering::Acquire))
        {
            return (Rx::Dropped(DropReason::Stale), Default::default());
        }
        if self.resources.is_none() {
            return match &mut self.stack {
                Some(stack) => {
                    stack.receive_with_meta_tcp_admission(ingress_at, packet, meta, on_source)
                }
                None => (Rx::Dropped(DropReason::Stale), Default::default()),
            };
        }
        self.advance(service_at);
        let resources = self.resources.clone().expect("accounted realm resources");
        let vacant = self.half_open.iter().position(Option::is_none);
        let mut grant = None;
        let _unwind = AdmissionUnwind(self.capture_admission.as_deref());
        let Some(stack) = &mut self.stack else {
            return (Rx::Dropped(DropReason::Stale), Default::default());
        };
        let (rx, report) = stack.receive_with_realm_admission(
            ingress_at,
            service_at,
            packet,
            meta,
            on_source,
            |source| {
                grant = vacant.and_then(|_| resources.reserve(source));
                grant.is_some()
            },
        );
        if let honk_netstack::ReceiveOutcome::TcpNew(id) = report.outcome {
            if let Some(grant) = grant {
                self.half_open[vacant.expect("funded half-open cell")] = Some((id, grant));
            }
        }
        (rx, report)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn remember_peer(&mut self, hold: &crate::xdp::worker::PeerHold) {
        if !hold.learned() {
            return;
        }
        let index = self
            .peers
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|old| old.address() == hold.address())
            })
            .or_else(|| self.peers.iter().position(Option::is_none));
        if let Some(index) = index {
            self.peers[index] = Some(hold.clone());
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
        for peer in &mut self.peers {
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
    }

    #[cfg(target_os = "linux")]
    fn reap_fragment_peers(&mut self) {
        let stack = self.stack.as_ref();
        for entry in &mut self.fragment_peers {
            if entry
                .as_ref()
                .is_some_and(|entry| !stack.is_some_and(|stack| stack.retains_fragment(entry.info)))
            {
                entry.take();
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
    ) -> Option<(Transmit, Option<honk_netstack::FragmentInfo>)> {
        let Some(resources) = resources else {
            return match class {
                TxClass::Control => stack.poll_control_transmit(now, output),
                TxClass::Bulk => stack.poll_transmit_with(now, output, caps),
            }
            .map(|tx| (tx, None));
        };
        let control = class == TxClass::Control;
        for _ in 0..3 {
            match stack.poll_transmit_accounted(now, output, control, None) {
                honk_netstack::AccountedTransmit::Packet(tx) => {
                    return Some((tx, stack.take_fragment_output()));
                }
                honk_netstack::AccountedTransmit::Idle => return None,
                honk_netstack::AccountedTransmit::NeedsIcmp => {
                    let mut state = resources.icmp.lock();
                    let service_at = Instant::now().max(state.1);
                    state.1 = service_at;
                    if let honk_netstack::AccountedTransmit::Packet(tx) = stack
                        .poll_transmit_accounted(service_at, output, control, Some(&mut state.0))
                    {
                        return Some((tx, stack.take_fragment_output()));
                    }
                }
            }
        }
        None
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
        if std::thread::panicking() {
            if let Some(admission) = self.0 {
                admission.store(false, std::sync::atomic::Ordering::Release);
            }
        }
    }
}
