use super::*;

impl WorkerRuntime {
    pub(super) async fn run(&mut self) -> anyhow::Result<()> {
        for device in &mut self.devices {
            for i in 0..device.queues.len() {
                if self.shared.is_closing() {
                    break;
                }
                // Registration takes the Port by value. Restore its original slot, including
                // on failure, before any fallible FILL or kick; the thread retains every FD.
                let queue = device.queues.swap_remove(i);
                let (io, registered) = queue.io.register();
                let last = device.queues.len();
                device.queues.push(Queue { io, ..queue });
                device.queues.swap(i, last);
                registered?;
                let port = device.queues[i].io.get_mut();
                if !self.shared.is_closing() {
                    port.refill()?;
                }
                if !self.shared.is_closing() {
                    port.kick()?;
                }
            }
        }
        let shared = Arc::clone(&self.shared);
        let setup = {
            let mut state = shared.states[1].lock();
            state.queues_registered = true;
            state.relay_setup.take()
        };
        // Keep serving even while the supervisor is starting. Its failed startup needs these
        // drivers, and optional fences must wait for the last mandatory capture reservation.
        let drive = self.drive();
        tokio::pin!(drive);
        if let Some(setup) = setup {
            shared.wake_worker(0);
            let permission = tokio::select! {
                result = &mut drive => return result,
                permission = setup => permission,
            };
            if permission.is_err() {
                return drive.await;
            }
        }
        shared.ready(1);
        drive.await
    }

    async fn drive(&mut self) -> anyhow::Result<()> {
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
                let result = poll_deadline(timer.as_mut(), deadline, now, cx).map(|()| Ok(true));
                #[cfg(test)]
                if !closing && !retry && result.is_pending() {
                    let driver_deadline = self
                        .realms
                        .iter()
                        .filter_map(|realm| realm.driver.protocol_deadline())
                        .min();
                    self.shared.secondary_test_control().note_driver_timer_wait(
                        driver_deadline,
                        timer
                            .as_ref()
                            .get_ref()
                            .as_ref()
                            .map(tokio::time::Sleep::deadline),
                        !self.needs_service_retry(),
                        self.realms
                            .iter()
                            .any(|realm| realm.pending.iter().any(Option::is_some)),
                    );
                }
                result
            })
            .await?;
            if !serviced {
                self.shared.join_secondary_relays().await;
                return self.close_sockets();
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
            match envelope.receive_endpoint(&self.shared, &self.endpoints, now) {
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
                    let placements = &self.placements.entries;
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
                                let placement = placements.iter().find(|placement| {
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
                                });
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
                                let scope = placement.realm.scope();
                                if mixed && !retained_endpoint(endpoints, scope, view) {
                                    batch.take();
                                    shared.handoff_segments(
                                        0,
                                        placement.ingress,
                                        scope,
                                        &l3[..count],
                                        now,
                                        path,
                                        Payload::Ingress,
                                        None,
                                    )?;
                                    return Ok(());
                                }
                                let report = shared.physical_endpoint(
                                    batch,
                                    endpoints,
                                    &placement.realm,
                                    1,
                                    placement.ingress,
                                    &l3[..count],
                                    view,
                                    staging,
                                    (now, now),
                                    path,
                                    mixed,
                                )?;
                                if report.qualified_rx {
                                    qualify_packet(qualified, unavailable);
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
            if let Some(diagnostics) = self.shared.diagnostics.get() {
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
            if realm.generated.is_some() {
                let ifindex = realm.link.path.physical_ifindex;
                let (count, _) =
                    service_generated_output(realm, port, cx, now, class, ifindex, endpoints)?;
                serviced += count;
                continue;
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
        }
        Ok(serviced)
    });
    if realm.generated.is_some() {
        realm.driver.finish_turn(cx, now);
    }
    finish_transmit(work, kick)
}
