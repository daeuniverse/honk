use super::*;

pub(super) enum QueueIo {
    Prepared(Port<Retained>),
    Registered(AsyncFd<Port<Retained>>),
}

impl QueueIo {
    pub(super) fn register(self) -> (Self, io::Result<()>) {
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
    pub(super) fn get_ref(&self) -> &Port<Retained> {
        match self {
            Self::Prepared(port) => port,
            Self::Registered(io) => io.get_ref(),
        }
    }
    pub(super) fn get_mut(&mut self) -> &mut Port<Retained> {
        match self {
            Self::Prepared(port) => port,
            Self::Registered(io) => io.get_mut(),
        }
    }
    pub(super) fn into_inner(self) -> Port<Retained> {
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

pub(super) fn diagnostics(
    devices: &[Device],
    budget: &Arc<MemoryBudget>,
) -> io::Result<Arc<Diagnostics>> {
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

pub(super) fn sample_queues(devices: &[Device], diagnostics: &Diagnostics) {
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

pub(super) fn l3_segments<'a>(
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

/// Tokio takes the reader waker when it delivers readiness and a cached Ready installs none,
/// so a single clear can park an empty pass with nothing to wake it. Pending registers this
/// task (or schedules a coop-budget continuation) before the caller drains.
pub(super) fn arm_read<T: AsRawFd>(io: &AsyncFd<T>, cx: &mut Context<'_>) -> io::Result<bool> {
    let mut readable = false;
    while let Poll::Ready(ready) = io.poll_read_ready(cx) {
        ready?.clear_ready();
        readable = true;
    }
    Ok(readable)
}

pub(super) fn fill_output(
    output: &mut [&mut [u8]],
    header: &[u8],
    packet: &[u8],
) -> io::Result<()> {
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

impl Runtime {
    pub(super) fn poll_io(
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
}
