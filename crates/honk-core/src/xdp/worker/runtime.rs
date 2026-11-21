use super::*;

impl WorkerRuntime {
    pub(super) async fn run(&mut self) -> anyhow::Result<()> {
        for device in &mut self.devices {
            let prepared = std::mem::take(&mut device.queues);
            for queue in prepared {
                if self.shared.is_closing() {
                    device.queues.push(queue);
                    continue;
                }
                let Queue {
                    id,
                    io,
                    observed,
                    observed_rings,
                } = queue;
                let mut io = io.register()?;
                if !self.shared.is_closing() {
                    io.get_mut().refill()?;
                }
                if !self.shared.is_closing() {
                    io.get_mut().kick()?;
                }
                device.queues.push(Queue {
                    id,
                    io,
                    observed,
                    observed_rings,
                });
            }
        }
        self.shared.ready(1);
        let wake = Arc::clone(&self.shared.wake[1]);
        let notification = wake.notified();
        tokio::pin!(notification);
        let timer = None;
        tokio::pin!(timer);
        loop {
            notification.as_mut().enable();
            let serviced = poll_fn(|cx| -> Poll<anyhow::Result<bool>> {
                let (closing, stop, drain_until) = {
                    let state = self.shared.states[1].lock();
                    (self.shared.is_closing(), state.stop, state.drain.deadline())
                };
                let (mut progress, outstanding) = if closing {
                    let draining = drain_until.is_some_and(|deadline| Instant::now() < deadline);
                    let (progress, outstanding, mailbox_closed) =
                        self.poll_closing(cx, draining)?;
                    if stop && !outstanding && mailbox_closed {
                        self.close_sockets()?;
                        return Poll::Ready(Ok(false));
                    }
                    (progress, outstanding)
                } else {
                    (self.poll_service(cx)?, false)
                };
                if notification.as_mut().poll(cx).is_ready() {
                    notification.set(wake.notified());
                    progress = true;
                }
                if progress {
                    return Poll::Ready(Ok(true));
                }
                let now = Instant::now();
                let retry = if closing {
                    outstanding
                } else {
                    self.needs_service_retry()
                };
                let deadline = self
                    .next_deadline(now, retry)
                    .into_iter()
                    .chain(drain_until.filter(|&deadline| outstanding && now < deadline))
                    .min();
                poll_deadline(timer.as_mut(), deadline, now, cx).map(|()| Ok(true))
            })
            .await?;
            if !serviced {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    }

    fn poll_closing(
        &mut self,
        cx: &mut Context<'_>,
        draining: bool,
    ) -> anyhow::Result<(bool, bool, bool)> {
        let entering = !self.closing;
        if entering {
            self.closing = true;
            self.receiver.close();
            self.polling.leave("closing");
            for queue in self
                .devices
                .iter_mut()
                .flat_map(|device| &mut device.queues)
            {
                queue.io.get_mut().close();
            }
        }

        let mut progress = false;
        let mut outstanding = false;
        for queue in self
            .devices
            .iter_mut()
            .flat_map(|device| &mut device.queues)
        {
            let port = queue.io.get_mut();
            progress |= port.complete(release_completed)? != 0;
            let counters = port.counters();
            if counters.submitted != counters.completed {
                outstanding = true;
                // Check permission per attempt without holding the status lock over the syscall.
                if draining && self.shared.can_kick_outstanding() {
                    port.kick_outstanding_tx()?;
                }
            }
        }
        if draining && !outstanding {
            self.shared.acknowledge_quiescence();
        }

        let mut mailbox_closed = false;
        for _ in 0..BATCH {
            match self.receiver.poll_recv(cx) {
                Poll::Ready(Some(_)) => progress = true,
                Poll::Ready(None) => {
                    mailbox_closed = true;
                    break;
                }
                Poll::Pending => break,
            }
        }
        let now = Instant::now();
        for realm in &mut self.realms {
            if entering {
                realm.pending = [None, None];
            }
            progress |= realm.driver.service_closing(cx, now);
        }
        Ok((progress, outstanding, mailbox_closed))
    }

    fn close_sockets(&mut self) -> anyhow::Result<()> {
        for device in &self.devices {
            for queue in &device.queues {
                ensure!(
                    queue
                        .io
                        .get_ref()
                        .drain_state()
                        .ready_for_backend_teardown(),
                    "XDP worker 1 device {} queue {} ownership is not terminal",
                    device.info.name,
                    queue.id
                );
            }
        }
        for queue in self
            .devices
            .iter_mut()
            .flat_map(|device| device.queues.drain(..))
        {
            let mut port = queue.io.into_inner();
            port.close_socket();
        }
        Ok(())
    }

    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        interval: Option<&BusyInterval>,
    ) -> anyhow::Result<bool> {
        let now = Instant::now();
        self.shared.wakers[1].register(cx.waker());
        let mut progress = false;
        let deadline = interval.and_then(|_| self.next_deadline(now, self.needs_service_retry()));
        for _ in 0..BATCH {
            if self.shared.is_closing() {
                return Ok(progress);
            }
            if polling_segment_stop(&self.polling, interval, &self.shutdown, deadline).is_some() {
                break;
            }
            let mut envelope = match self.receiver.poll_recv(cx) {
                Poll::Ready(Some(envelope)) => envelope,
                _ => break,
            };
            let payload = std::mem::replace(&mut envelope.payload, Payload::Ingress);
            let (owner, admission) = match payload {
                Payload::Endpoint { owner, admission } => (owner, admission),
                _ => anyhow::bail!("worker 1 received coordinator-only ingress"),
            };
            match self.shared.receive(
                &self.endpoints,
                &owner,
                envelope.ip(),
                envelope.ingress_at,
                now,
                envelope.path,
                admission,
            ) {
                Ok(report) if report.qualified_rx => {
                    qualify_packet(&mut self.qualified_rx, &mut self.qualification_unavailable);
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                    ) => {}
                Err(error) => return Err(error.into()),
            }
            progress = true;
        }
        let start_device = self.rx_device;
        for offset in 0..self.devices.len() {
            let device_index = (start_device + offset) % self.devices.len();
            let device_count = self.devices.len();
            let device = &mut self.devices[device_index];
            let start_queue = if offset == 0 { self.rx_queue } else { 0 };
            for offset in 0..device.queues.len() {
                if self.shared.is_closing() {
                    return Ok(progress);
                }
                if polling_segment_stop(&self.polling, interval, &self.shutdown, deadline).is_some()
                {
                    break;
                }
                let queue_index = (start_queue + offset) % device.queues.len();
                self.rx_queue = (queue_index + 1) % device.queues.len();
                self.rx_device = if self.rx_queue == 0 {
                    (device_index + 1) % device_count
                } else {
                    device_index
                };
                let queue = &mut device.queues[queue_index];
                arm_read(&queue.io, cx)?;
                let port = queue.io.get_mut();
                progress |= port.complete(release_completed)? != 0;
                if self.shared.admission.load(Ordering::Acquire) && !self.shared.is_closing() {
                    let shared = &self.shared;
                    let endpoints = &self.endpoints;
                    let staging = &mut self.staging;
                    let mixed = self.mixed;
                    let qualified = &mut self.qualified_rx;
                    let unavailable = &mut self.qualification_unavailable;
                    let mut failure = None;
                    let received = receive_batch(
                        port,
                        BATCH,
                        if device.capture.vlan_metadata {
                            METADATA_LEN
                        } else {
                            0
                        },
                        |batch, segments, metadata, _| {
                            let result = (|| -> io::Result<()> {
                                let decoded =
                                    device
                                        .capture
                                        .decode(segments, metadata, queue.id)
                                        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                                let placement = shared
                                    .placements
                                    .lock()
                                    .iter()
                                    .find(|placement| {
                                        placement.device == device.index
                                            && placement.link.mac == decoded.destination_mac
                                            && placement.link.path.vlan_count == decoded.vlan_count
                                            && placement.link.path.vlan_proto == decoded.vlan_proto
                                            && placement
                                                .link
                                                .path
                                                .vlan_tci
                                                .iter()
                                                .zip(decoded.vlan_tci)
                                                .all(|(configured, captured)| {
                                                    configured & 0x0fff == captured & 0x0fff
                                                })
                                    })
                                    .cloned();
                                let Some(placement) = placement else {
                                    batch.take();
                                    return Ok(());
                                };
                                let path = ReturnPath {
                                    realm: placement.realm_id,
                                    device: device.index,
                                    mac: decoded.source_mac,
                                    vlan_tci: decoded.vlan_tci,
                                    vlan_proto: decoded.vlan_proto,
                                    vlan_count: decoded.vlan_count,
                                };
                                let mut l3 = [&[][..]; 18];
                                let count = l3_segments(segments, decoded, &mut l3)
                                    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
                                let view =
                                    PacketView::new(&l3[..count]).map_err(io::Error::other)?;
                                let worker = if mixed
                                    && !retained_endpoint(endpoints, placement.realm.scope(), view)
                                {
                                    0
                                } else {
                                    selected_worker(&placement.realm, view)
                                };
                                if worker == 1 {
                                    let bytes = if count == 1 {
                                        l3[0]
                                    } else {
                                        batch.take();
                                        view.copy_to(
                                            0..decoded.l3_len,
                                            &mut staging[..decoded.l3_len],
                                        )
                                        .ok_or_else(
                                            || io::Error::from(io::ErrorKind::InvalidData),
                                        )?;
                                        &staging[..decoded.l3_len]
                                    };
                                    let owner = endpoints
                                        .realm(placement.realm.scope())
                                        .and_then(|realm| realm.owner(1))
                                        .ok_or_else(|| {
                                            io::Error::other("unregistered physical worker")
                                        })?;
                                    if !mixed
                                        && count == 1
                                        && let Some(report) = shared.established(
                                            batch,
                                            owner,
                                            bytes,
                                            (now, now),
                                            path,
                                            endpoints,
                                        )
                                    {
                                        if report.qualified_rx {
                                            qualify_packet(qualified, unavailable);
                                        }
                                        return Ok(());
                                    }
                                    batch.take();
                                    let report = shared
                                        .receive(endpoints, owner, bytes, now, now, path, None)?;
                                    if report.qualified_rx {
                                        qualify_packet(qualified, unavailable);
                                    }
                                } else {
                                    batch.take();
                                    let cell = shared.copy(segments, metadata)?;
                                    let ip = &cell.packet()
                                        [decoded.l3_offset..decoded.l3_offset + decoded.l3_len];
                                    let peer = if matches!(
                                        wire::parse_ip(ip),
                                        Err(wire::ParseError::Fragment)
                                    ) {
                                        shared.fragment_peer(placement.realm.scope(), ip, path)?
                                    } else {
                                        None
                                    };
                                    let envelope = Envelope {
                                        ingress: placement.ingress,
                                        scope: placement.realm.scope(),
                                        path,
                                        ingress_at: now,
                                        body: None,
                                        peer,
                                        l3_offset: decoded.l3_offset,
                                        l3_length: decoded.l3_len,
                                        cell,
                                        payload: Payload::Ingress,
                                    };
                                    let _ = shared.send(0, envelope);
                                }
                                Ok(())
                            })();
                            if result.is_err() {
                                batch.take();
                            }
                            if let Err(error) = result
                                && !matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock
                                        | io::ErrorKind::OutOfMemory
                                        | io::ErrorKind::InvalidData
                                )
                            {
                                failure.get_or_insert(error);
                            }
                        },
                    );
                    progress |= received? != 0;
                    if let Some(error) = failure {
                        return Err(error.into());
                    }
                }
                if self.shared.is_closing() {
                    return Ok(progress);
                }
                port.refill()?;
                if self.shared.is_closing() {
                    return Ok(progress);
                }
                port.kick()?;
            }
        }
        let start_realm = self.tx_realm;
        for offset in 0..self.realms.len() {
            if self.shared.is_closing() {
                return Ok(progress);
            }
            if polling_segment_stop(&self.polling, interval, &self.shutdown, deadline).is_some() {
                break;
            }
            let realm_index = (start_realm + offset) % self.realms.len();
            self.tx_realm = (realm_index + 1) % self.realms.len();
            let realm = &mut self.realms[realm_index];
            if realm.members.len() > 1 {
                realm.driver.service(cx, now);
                if self.shared.is_closing() {
                    return Ok(progress);
                }
                let devices = &mut self.devices;
                progress |= service_member_output(
                    realm,
                    cx,
                    &self.endpoints,
                    |realm, class, path, output| {
                        if self.shared.is_closing() {
                            return Ok(Some(output));
                        }
                        let device = devices
                            .iter_mut()
                            .find(|device| device.index == path.device)
                            .ok_or_else(|| {
                                io::Error::other("retained worker output member missing")
                            })?;
                        let ifindex = device.info.ifindex;
                        let queue = device.queues.first_mut().ok_or_else(|| {
                            io::Error::other("retained worker output queue missing")
                        })?;
                        submit_member_output(
                            realm,
                            queue.io.get_mut(),
                            ifindex,
                            class,
                            path,
                            output,
                        )
                    },
                )? != 0;
                continue;
            }
            let device = self
                .devices
                .iter_mut()
                .find(|device| device.index == realm.device)
                .unwrap();
            let queue = device
                .queues
                .iter_mut()
                .find(|queue| queue.id == 1)
                .expect("shard 1 owns queue 1");
            progress |= service_output(
                realm,
                queue.io.get_mut(),
                cx,
                now,
                &self.endpoints,
                &self.shared,
            )? != 0;
        }
        if now.saturating_duration_since(self.sampled) >= Duration::from_secs(1) {
            self.sampled = now;
            if let Some(diagnostics) = self.shared.diagnostics.lock().as_ref() {
                let mut base = 0;
                for device in &self.devices {
                    for queue in &device.queues {
                        if self.shared.is_closing() {
                            return Ok(progress);
                        }
                        let index = device
                            .info
                            .queues
                            .iter()
                            .position(|id| *id == queue.id)
                            .expect("original queue identity");
                        let port = queue.io.get_ref();
                        diagnostics.sample(
                            base + index,
                            SystemTime::now(),
                            port.stats(),
                            port.rings(),
                        );
                    }
                    base += device.info.queues.len();
                }
            }
        }
        Ok(progress)
    }
}

fn service_output(
    realm: &mut Realm,
    port: &mut Port<Retained>,
    cx: &mut Context<'_>,
    now: Instant,
    endpoints: &PacketEndpoints,
    shared: &Shared,
) -> anyhow::Result<usize> {
    if realm.generated.is_some() {
        realm.driver.begin_turn(now);
    } else {
        realm.driver.service(cx, now);
    }
    if shared.is_closing() {
        if realm.generated.is_some() {
            realm.driver.finish_turn(cx, now);
        }
        return Ok(0);
    }
    let (work, kick) = port.transmit_batch(|port| -> anyhow::Result<usize> {
        let mut serviced = 0;
        for (class_index, class) in [TxClass::Control, TxClass::Bulk].into_iter().enumerate() {
            if shared.is_closing() {
                break;
            }
            let mut outputs: [Option<OutputLease>; BATCH] = std::array::from_fn(|_| None);
            let capacity = port.tx_packet_capacity(class)?;
            let (selected, pending_path) = realm.poll_outputs(cx, class, capacity, &mut outputs);
            let count = match selected {
                Poll::Ready(Some(count)) => count,
                Poll::Ready(None) if !endpoints.is_closing() => {
                    anyhow::bail!("worker 1 Stack ended before common close")
                }
                _ => 0,
            };
            for output in &mut outputs[..count] {
                let output = output.take().unwrap();
                let path = pending_path.or_else(|| output.peer_hold().and_then(|hold| hold.path()));
                let Some(path) = path else {
                    serviced += 1;
                    continue;
                };
                let header = realm.output_header(
                    path,
                    realm.link.path.physical_ifindex,
                    output.packet()[0] >> 4 == 6,
                )?;
                if !port.tx_packet_credit(class, header.len() + output.packet().len()) {
                    realm.pending[class_index] = Some((output, path));
                    break;
                }
                port.transmit_with(
                    class,
                    header.len() + output.packet().len(),
                    Retained::Endpoint(output.into_owner()),
                    |owner, target| {
                        let Retained::Endpoint(owner) = owner else {
                            unreachable!()
                        };
                        fill_output(
                            target,
                            &header,
                            owner
                                .packet()
                                .ok_or_else(|| io::Error::other("missing CPU packet"))?,
                        )
                    },
                )?;
                serviced += 1;
            }
            if let Some((_, max_length)) = realm.generated {
                for _ in count..BATCH {
                    let mut emitted = false;
                    let result = port.transmit_generated(class, max_length, |frame| {
                        realm.generate_output(
                            now,
                            class,
                            realm.link.path.physical_ifindex,
                            &[],
                            frame,
                            &mut emitted,
                        )
                    });
                    match result {
                        Ok(true) => serviced += 1,
                        Ok(false) if emitted => serviced += 1,
                        Ok(false) => break,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
        Ok(serviced)
    });
    if realm.generated.is_some() {
        realm.driver.finish_turn(cx, now);
    }
    finish_transmit(work, kick)
}
