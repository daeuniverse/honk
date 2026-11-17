use super::*;

impl WorkerRuntime {
    pub(super) async fn run(&mut self) -> anyhow::Result<()> {
        for device in &mut self.devices {
            let prepared = std::mem::take(&mut device.queues);
            for queue in prepared {
                let Queue {
                    id,
                    io,
                    observed,
                    observed_rings,
                } = queue;
                let mut io = io.register()?;
                io.get_mut().refill()?;
                io.get_mut().kick()?;
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
            let serviced = poll_fn(|cx| {
                self.closing = self.shared.states[1].lock().closing;
                self.stop = self.shared.states[1].lock().stop;
                let mut progress = self.poll_service(cx)?;
                if self.closing && self.stop && self.drained() {
                    for device in &mut self.devices {
                        for queue in &mut device.queues {
                            if !queue.io.get_mut().close().ready_for_backend_teardown() {
                                return Poll::Ready(Err(anyhow::anyhow!(
                                    "worker 1 Port ownership is not terminal"
                                )));
                            }
                        }
                        for queue in device.queues.drain(..) {
                            let mut port = queue.io.into_inner();
                            port.close_socket();
                        }
                    }
                    return Poll::Ready(Ok(false));
                }
                if notification.as_mut().poll(cx).is_ready() {
                    notification.set(wake.notified());
                    progress = true;
                }
                if progress {
                    return Poll::Ready(Ok(true));
                }
                let now = Instant::now();
                let deadline = self.next_deadline(now);
                poll_deadline(timer.as_mut(), deadline, now, cx).map(|()| Ok(true))
            })
            .await?;
            if !serviced {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    }

    fn drained(&self) -> bool {
        self.receiver.is_empty()
            && self
                .devices
                .iter()
                .flat_map(|device| &device.queues)
                .all(|queue| {
                    let port = queue.io.get_ref();
                    let rings = port.rings();
                    rings.rx_producer == rings.rx_consumer
                        && rings.cq_producer == rings.cq_consumer
                        && port.counters().submitted == port.counters().completed
                        && port.retained_rx_count() == 0
                        && port.rx_completion_count() == 0
                })
    }

    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        interval: Option<&BusyInterval>,
    ) -> anyhow::Result<bool> {
        let now = Instant::now();
        self.shared.wakers[1].register(cx.waker());
        let mut progress = false;
        let deadline = self.next_deadline(now);
        for _ in 0..BATCH {
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
            let mut report = PacketReceive::default();
            let mut failed = None;
            if !self.closing {
                match self.shared.receive(
                    &self.endpoints,
                    &owner,
                    envelope.ip(),
                    envelope.ingress_at,
                    now,
                    envelope.path,
                    admission,
                ) {
                    Ok(received) => report = received,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                        ) => {}
                    Err(error) => failed = Some(error),
                }
            }
            if report.qualified_rx {
                qualify_packet(&mut self.qualified_rx, &mut self.qualification_unavailable);
            }
            if let Some(error) = failed {
                return Err(error.into());
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
                if !self.closing && self.shared.admission.load(Ordering::Acquire) {
                    let shared = &self.shared;
                    let endpoints = &self.endpoints;
                    let staging = &mut self.staging;
                    let mixed = self.mixed;
                    let qualified = &mut self.qualified_rx;
                    let unavailable = &mut self.qualification_unavailable;
                    let mut failure = None;
                    let received = port.receive_segments_with(
                        BATCH,
                        if device.capture.vlan_metadata {
                            METADATA_LEN
                        } else {
                            0
                        },
                        |segments, metadata, _| {
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
                                    return Ok(());
                                };
                                let path = ReturnPath {
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
                                        view.copy_to(
                                            0..decoded.l3_len,
                                            &mut staging[..decoded.l3_len],
                                        )
                                        .ok_or_else(
                                            || io::Error::from(io::ErrorKind::InvalidData),
                                        )?;
                                        &staging[..decoded.l3_len]
                                    };
                                    let report = shared.receive(
                                        endpoints,
                                        placement.realm.owner(1).unwrap(),
                                        bytes,
                                        now,
                                        now,
                                        path,
                                        None,
                                    )?;
                                    if report.qualified_rx {
                                        qualify_packet(qualified, unavailable);
                                    }
                                } else {
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
                if self.closing {
                    progress |= port.receive_segments_with(
                        BATCH,
                        if device.capture.vlan_metadata {
                            METADATA_LEN
                        } else {
                            0
                        },
                        |_, _, _| {},
                    )? != 0;
                }
                port.refill()?;
                port.kick()?;
            }
        }
        let start_realm = self.tx_realm;
        for offset in 0..self.realms.len() {
            if polling_segment_stop(&self.polling, interval, &self.shutdown, deadline).is_some() {
                break;
            }
            let realm_index = (start_realm + offset) % self.realms.len();
            self.tx_realm = (realm_index + 1) % self.realms.len();
            let realm = &mut self.realms[realm_index];
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
                self.closing,
                &self.endpoints,
            )? != 0;
        }
        if now.saturating_duration_since(self.sampled) >= Duration::from_secs(1) {
            self.sampled = now;
            if let Some(diagnostics) = self.shared.diagnostics.lock().as_ref() {
                let mut base = 0;
                for device in &self.devices {
                    for queue in &device.queues {
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
    closing: bool,
    endpoints: &PacketEndpoints,
) -> anyhow::Result<usize> {
    if realm.generated.is_some() {
        realm.driver.begin_turn(now);
    } else {
        realm.driver.service(cx, now);
    }
    let (work, kick) = port.transmit_batch(|port| -> anyhow::Result<usize> {
        let mut serviced = 0;
        for (class_index, class) in [TxClass::Control, TxClass::Bulk].into_iter().enumerate() {
            let mut outputs: [Option<OutputLease>; BATCH] = std::array::from_fn(|_| None);
            let capacity = if closing {
                BATCH
            } else {
                port.tx_packet_capacity(class)?
            };
            let (selected, pending_path) = realm.poll_outputs(cx, class, capacity, &mut outputs);
            let count = match selected {
                Poll::Ready(Some(count)) => count,
                Poll::Ready(None) if !closing && !endpoints.is_closing() => {
                    anyhow::bail!("worker 1 Stack ended before common close")
                }
                _ => 0,
            };
            for output in &mut outputs[..count] {
                let output = output.take().unwrap();
                if closing {
                    serviced += 1;
                    continue;
                }
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
            if closing {
                continue;
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
