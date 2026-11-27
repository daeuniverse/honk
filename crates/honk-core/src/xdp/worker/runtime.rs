use super::epoll::{TOKEN_DIRECT_BIT, WorkerEpoll};
use super::*;
use std::task::Waker;

impl WorkerRuntime {
    pub(super) fn run(
        &mut self,
        relay_runtime: &mut Option<tokio::runtime::Runtime>,
    ) -> anyhow::Result<()> {
        let watches = self.devices.iter().map(|device| device.queues.len()).sum();
        let epoll = WorkerEpoll::new(&self.polling_budget, watches)?;
        let wake = Waker::from(Arc::clone(&epoll.wake));
        let mut cx = Context::from_waker(&wake);
        for device in &mut self.devices {
            for queue in &mut device.queues {
                if self.shared.is_closing() {
                    break;
                }
                queue
                    .io
                    .watch_queue(&epoll, device.index, queue.id as usize)?;
                let port = queue.io.get_mut();
                if !self.shared.is_closing() {
                    port.refill()?;
                }
                if !self.shared.is_closing() {
                    port.kick()?;
                }
            }
        }
        self.bind_realms(&epoll, &mut cx)?;
        self.drive(&epoll, &mut cx, relay_runtime)?;
        futures::executor::block_on(self.shared.join_secondary_relays());
        self.close_sockets()
    }

    fn bind_realms(&mut self, epoll: &WorkerEpoll, cx: &mut Context<'_>) -> io::Result<()> {
        let now = Instant::now();
        for (index, realm) in self.realms.iter_mut().enumerate() {
            realm
                .driver
                .bind_worker_epoll(Arc::clone(&epoll.fd), index)?;
            realm.driver.poll_local_io_sync(cx, now)?;
        }
        Ok(())
    }

    fn drive(
        &mut self,
        epoll: &WorkerEpoll,
        cx: &mut Context<'_>,
        relay_runtime: &mut Option<tokio::runtime::Runtime>,
    ) -> anyhow::Result<()> {
        let mut setup = {
            let mut state = self.shared.states[1].lock();
            state.queues_registered = true;
            state.startup.take()
        };
        if setup.is_some() {
            // Queue registration and final driver/relay readiness have distinct startup fences.
            self.shared.wake_worker(0);
        } else {
            self.shared.ready(1);
        }
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; BATCH];
        let mut ready = 0;
        let mut turns = TurnBudget::native();
        loop {
            #[cfg(test)]
            if self
                .shared
                .close_before_secondary_drain
                .swap(false, Ordering::AcqRel)
            {
                self.shared.begin_close();
            }
            // XSK events only wake this pass since it already examines every queue.
            for event in &events[..ready] {
                let token = event.u64;
                if token & TOKEN_DIRECT_BIT != 0 {
                    let index = ((token >> 56) & 0x7f) as usize;
                    if let Some(realm) = self.realms.get_mut(index) {
                        realm.driver.direct_socket_ready(token, event.events);
                    }
                }
            }
            if epoll.wake.is_pending() {
                epoll.wake.drain()?;
            }
            // AtomicWaker::wake takes the registration. Rearm after clearing old wakes,
            // before observing close, quiesce or stop, including when already closing.
            self.shared.wakers[1].register(cx.waker());
            if let Some(permission) = &mut setup
                && let Poll::Ready(permission) = Pin::new(permission).poll(cx)
            {
                setup = None;
                if let Ok(realms) = permission {
                    if !realms.is_empty() {
                        debug_assert!(self.realms.is_empty());
                        self.realms = realms;
                        self.bind_realms(epoll, cx)?;
                    }
                    if !self.shared.is_closing() {
                        *relay_runtime = self.shared.start_secondary_relays()?;
                        self.shared.ready(1);
                    }
                }
            }

            let closing = self.shared.is_closing();
            turns.charge();
            let (progress, outstanding, drain_until) = if closing {
                let (stop, drain_until) = {
                    let state = self.shared.states[1].lock();
                    (state.stop, state.drain.deadline())
                };
                let draining = drain_until.is_some_and(|deadline| Instant::now() < deadline);
                let (progress, outstanding, mailbox_closed) = self.poll_closing(cx, draining)?;
                if stop && !outstanding && mailbox_closed {
                    return Ok(());
                }
                (progress, outstanding, drain_until)
            } else {
                (self.poll_service(cx, &mut turns)?, false, None)
            };
            if progress || epoll.wake.is_pending() {
                ready = turns.poll_events(epoll, &self.realms, &mut events)?;
                if turns.exhausted() {
                    turns = TurnBudget::native();
                }
                continue;
            }

            turns = TurnBudget::native();
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
            #[cfg(test)]
            {
                let control = self.shared.secondary_test_control();
                let wait = polling::testing::PendingWait {
                    reading: false,
                    driver_deadline: self
                        .realms
                        .iter()
                        .filter_map(|realm| realm.driver.protocol_deadline())
                        .min(),
                    armed_deadline: deadline.map(tokio::time::Instant::from_std),
                    idle_ports: !retry && !self.needs_service_retry(),
                    pending_outputs: self
                        .realms
                        .iter()
                        .any(|realm| realm.pending.iter().any(Option::is_some)),
                };
                control.note_pending(wait);
                control.note_driver_timer_wait(
                    wait.driver_deadline,
                    wait.armed_deadline,
                    !closing && wait.idle_ports,
                    wait.pending_outputs,
                );
            }
            let result = epoll.wait(deadline, now, &mut events);
            #[cfg(test)]
            self.shared.secondary_test_control().clear_pending();
            ready = result?;
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
            progress |= port.complete(|done| release_completed_on(&mut self.realms, done))? != 0;
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
            realm.driver.begin_local_turn(cx, now);
            progress |= realm.driver.poll_local_io_sync(cx, now)?;
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
        for realm in &mut self.realms {
            realm.driver.begin_local_turn(cx, now);
        }
        let result = self.poll_turn(cx, interval, now);
        for realm in &mut self.realms {
            if realm.driver.local_turn_open() {
                if result.is_err() {
                    realm.driver.interrupt_turn(cx);
                } else {
                    realm.driver.finish_turn(cx, now);
                }
            }
        }
        result
    }

    fn poll_turn(
        &mut self,
        cx: &mut Context<'_>,
        interval: Option<&BusyInterval>,
        now: Instant,
    ) -> anyhow::Result<bool> {
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
            let local = self
                .realms
                .iter_mut()
                .find(|r| r.realm_id == envelope.path.realm && r.driver.is_local())
                .map(|r| &mut r.driver);
            match envelope.receive_endpoint(&self.shared, &self.endpoints, now, local) {
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
                let port = queue.io.get_mut();
                progress |=
                    port.complete(|done| release_completed_on(&mut self.realms, done))? != 0;
                if self.shared.admission.load(Ordering::Acquire) && !self.shared.is_closing() {
                    let shared = &self.shared;
                    let endpoints = &self.endpoints;
                    let placements = &self.placements.entries;
                    let realms = &mut self.realms;
                    let staging = &mut self.staging;
                    let mixed = self.mixed;
                    let qualified = &mut self.qualified_rx;
                    let unavailable = &mut self.qualification_unavailable;
                    let mut failure = None;
                    let mut local_peer = None;
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
                                    realms
                                        .iter_mut()
                                        .find(|r| r.realm_id == path.realm && r.driver.is_local())
                                        .map(|r| &mut r.driver),
                                    &mut local_peer,
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
            progress |= realm.driver.poll_local_io_sync(cx, now)?;
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
        for class in [TxClass::Control, TxClass::Bulk] {
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
            if realm.transmit_cpu_outputs(
                port,
                class,
                realm.link.path.physical_ifindex,
                pending_path,
                &mut outputs[..count],
            )? {
                serviced += count;
            }
        }
        Ok(serviced)
    });
    if realm.generated.is_some() {
        realm.driver.finish_turn(cx, now);
    }
    finish_transmit(work, kick)
}
