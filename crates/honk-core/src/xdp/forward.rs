use super::*;

pub(super) fn generated_layout(link: LogicalLink) -> Option<(usize, usize)> {
    let l2_len = 14usize.checked_add(4usize.checked_mul(usize::from(link.path.vlan_count))?)?;
    let max_length = l2_len.checked_add(usize::try_from(link.mtu.max(1280)).ok()?)?;
    (max_length <= FRAME_SIZE).then_some((l2_len, max_length))
}

impl Realm {
    pub(super) fn poll_outputs(
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

    pub(super) fn output_header(
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

    pub(super) fn transmit_cpu_outputs(
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

    pub(super) fn generate_output(
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

pub(super) fn service_generated_output(
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

pub(super) fn finish_transmit<T>(
    work: anyhow::Result<T>,
    kick: io::Result<()>,
) -> anyhow::Result<T> {
    match (work, kick) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(work), Err(kick)) => Err(work.context(kick).context("TX wakeup also failed")),
    }
}

pub(super) fn service_member_output(
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

pub(super) fn submit_member_output(
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

pub(super) fn selected_egress(realms: &[Realm], route: Route) -> bool {
    realms.iter().any(|realm| {
        realm.ingress.ifindex == route.ifindex
            && realm.link.path == route.l2
            && realm.link.mac == route.source_mac
    })
}

impl Runtime {
    /// The earliest Waiting/Pending/reassembly/maintenance work, all resolved under readers.
    pub(super) fn core_deadline(&self, now: Instant) -> Option<Instant> {
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

    pub(super) fn core_due(&self, now: Instant) -> bool {
        !self.closing && self.core_deadline(now).is_some_and(|due| due <= now)
    }

    /// One bounded turn under the actual router/config readers acquired beside device
    /// service; nothing here awaits, so no reader or scope lock crosses a suspension.
    pub(super) fn resolve(&mut self, read: &PolicyRead<'_>) -> anyhow::Result<()> {
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
