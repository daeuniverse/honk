use super::*;
use crate::xdp::worker::native::{Phase, RemoteOriginal, Stage};

impl Runtime {
    pub(in crate::xdp) fn service_all_native_originals(
        &mut self,
        cx: &mut Context<'_>,
        now: Instant,
    ) -> anyhow::Result<usize> {
        let mut progress = 0;
        for _ in 0..BATCH {
            let remote_active = self
                .remote_originals
                .front()
                .is_some_and(|original| !matches!(original.stage, Stage::Payload));
            let local_active = self
                .originals
                .front()
                .is_some_and(|original| !matches!(original.phase, HeldPhase::Payload(_, _)));
            let remote = remote_active
                || (!local_active
                    && !self.remote_originals.is_empty()
                    && (self.original_worker || self.originals.is_empty()));
            let count = if remote {
                let mut original = self.remote_originals.pop_front().unwrap();
                match self.advance_remote_original(&mut original, cx, now) {
                    Ok(true) => {
                        self.original_worker = false;
                        1
                    }
                    Ok(false) => {
                        self.remote_originals.push_front(original);
                        0
                    }
                    Err(error) => {
                        self.remote_originals.push_front(original);
                        return Err(error);
                    }
                }
            } else {
                let count = self.service_native_originals_limited(cx, now, 1)?;
                if count != 0 {
                    self.original_worker = true;
                }
                count
            };
            progress += count;
            if count == 0 {
                break;
            }
        }
        Ok(progress)
    }

    fn advance_remote_original(
        &mut self,
        original: &mut RemoteOriginal,
        cx: &mut Context<'_>,
        now: Instant,
    ) -> anyhow::Result<bool> {
        use crate::control::core_forward::CapturedDecision;
        let publication = self
            .native
            .as_ref()
            .cloned()
            .context("remote Native publication absent")?;
        let identity = original.imported.identity;
        let producer = original.imported.producer;
        let handle = original.handle();
        let slot = original.slot();
        match original.stage {
            Stage::Payload => {
                let claim = publication
                    .claim(&identity.key)?
                    .context("remote retained Native owner absent")?;
                ensure!(
                    identity.matches(&claim),
                    "remote retained Native owner changed"
                );
                let mut admission = None;
                let mut dispose = self.closing;
                if self.closing {
                    ensure!(
                        self.native_capture_close == NativeCaptureClose::Proven,
                        "remote Native close lacks capture/grace proof"
                    );
                } else if claim.executor != NATIVE_EXECUTOR_CAPTURE {
                    let Some(candidate) = take_candidate(&mut self.next_candidate) else {
                        anyhow::bail!("Native candidate identity exhausted");
                    };
                    let Some((basis_epoch, basis_flags)) = publication.selection_snapshot() else {
                        publication.check_original_selection()?;
                        cx.waker().wake_by_ref();
                        return Ok(false);
                    };
                    let authority = self
                        .native_policy
                        .as_ref()
                        .context("remote Native policy absent")?;
                    let read = match authority.try_read_policy() {
                        Ok(read) => read,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            cx.waker().wake_by_ref();
                            return Ok(false);
                        }
                        Err(error) => return Err(error.into()),
                    };
                    let envelope = &original.envelope;
                    let device = &self.devices[envelope.device];
                    let decoded = device
                        .capture
                        .decode(
                            &[envelope.cell.packet()],
                            if device.capture.vlan_metadata {
                                &envelope.cell.metadata()[..METADATA_LEN]
                            } else {
                                &[]
                            },
                            envelope.queue,
                        )
                        .map_err(|_| io::Error::other("remote retained envelope changed"))?;
                    let ip = PacketView::from_slice(envelope.ip())
                        .parse_ip()
                        .map_err(io::Error::other)?;
                    let view = PacketView::from_slice(envelope.ip());
                    let query = honk_datapath::forward::RouteQuery {
                        ingress: envelope.ingress,
                        source: ip.src,
                        destination: ip.dst,
                        traffic_class: ip.dscp << 2,
                        protocol: ip.proto,
                        ports: view.transport_ports(&ip).map_err(io::Error::other)?,
                    };
                    let realm_index = self
                        .realms
                        .iter()
                        .position(|realm| realm.driver.scope() == envelope.scope)
                        .context("remote Native target realm absent")?;
                    let native = NativeOriginal {
                        imported: &original.imported,
                        authority: device.capture.authority,
                        ingress: envelope.ingress,
                        facts: envelope.scope,
                        realm_index: realm_index as u32,
                        rx_queue: envelope.queue,
                        basis_epoch,
                        basis_flags,
                        candidate,
                        extent: OriginalExtent {
                            frame_length: decoded.frame_len.try_into()?,
                            l3_offset: decoded.l3_offset.try_into()?,
                            l3_length: decoded.l3_len.try_into()?,
                            vlan_tci: decoded.vlan_tci,
                            vlan_proto: decoded.vlan_proto,
                            vlan_count: decoded.vlan_count.into(),
                            inline_vlan_count: decoded.inline_vlan_count.into(),
                            dscp: ip.dscp,
                        },
                        retained_capture: self.endpoints.retains(
                            envelope.scope,
                            address(identity.key.src_ip, identity.key.src_port),
                            address(identity.key.dst_ip, identity.key.dst_port),
                            identity.key.l4proto,
                        ),
                    };
                    let decision = authority.capture_original(
                        &read,
                        query,
                        envelope.scope,
                        &native,
                        &self.polling_budget,
                    );
                    drop(read);
                    if publication.selection_epoch() != Some(basis_epoch) {
                        cx.waker().wake_by_ref();
                        return Ok(false);
                    }
                    let decision = match decision {
                        Ok(decision) => decision,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            cx.waker().wake_by_ref();
                            return Ok(false);
                        }
                        Err(error) => return Err(error.into()),
                    };
                    match decision {
                        CapturedDecision::TryNativeOriginal(basis) => {
                            match self
                                .captured
                                .as_mut()
                                .context("remote captured consumer absent")?
                                .begin_copied_original(
                                    handle,
                                    &basis,
                                    original.envelope.cell.packet(),
                                ) {
                                Ok(()) => {
                                    self.workers.native.ports[slot]
                                        .lock()
                                        .as_mut()
                                        .context("remote Port flight slot absent")?
                                        .phase = Phase::Flight;
                                    original.stage = Stage::Flight;
                                    cx.waker().wake_by_ref();
                                }
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                    cx.waker().wake_by_ref()
                                }
                                Err(error) => return Err(error.into()),
                            }
                            return Ok(false);
                        }
                        CapturedDecision::Endpoint(candidate)
                            if claim.executor == NATIVE_EXECUTOR_PENDING =>
                        {
                            match publication.commit_capture(&identity, candidate.basis()) {
                                Ok(CaptureCommit::Selected(proof)) => {
                                    admission = Some(candidate.into_admission(proof)?)
                                }
                                Ok(CaptureCommit::AlreadyCommitted) => {}
                                Err(error)
                                    if error.downcast_ref::<io::Error>().is_some_and(|error| {
                                        error.kind() == io::ErrorKind::WouldBlock
                                    }) =>
                                {
                                    cx.waker().wake_by_ref();
                                    return Ok(false);
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        CapturedDecision::Endpoint(_) | CapturedDecision::Refuse => dispose = true,
                    }
                }
                if !dispose {
                    let envelope = &mut original.envelope;
                    let owner = self.workers.owner(envelope.scope, envelope.ip())?;
                    if owner.worker() == 1 {
                        let forwarded = worker::Envelope {
                            device: envelope.device,
                            queue: envelope.queue,
                            ingress: envelope.ingress,
                            scope: envelope.scope,
                            path: envelope.path,
                            ingress_at: envelope.ingress_at,
                            cell: envelope.cell.transfer(),
                            body: None,
                            peer: envelope.peer.clone(),
                            l3_offset: envelope.l3_offset,
                            l3_length: envelope.l3_length,
                            payload: worker::Payload::NativeEndpoint {
                                owner,
                                admission,
                                slot,
                            },
                        };
                        match self.workers.send(1, forwarded) {
                            Ok(()) => {
                                original.stage = Stage::Endpoint;
                                return Ok(false);
                            }
                            Err(forwarded) => {
                                envelope.cell = forwarded.cell;
                            }
                        }
                    } else {
                        match self.workers.receive(
                            &self.endpoints,
                            &owner,
                            envelope.ip(),
                            envelope.ingress_at,
                            now,
                            envelope.path,
                            admission,
                        ) {
                            Ok(report) => {
                                original.taken_over = report.taken_over;
                                if report.qualified_rx {
                                    qualify_packet(
                                        &mut self.qualified_rx,
                                        &mut self.qualification_unavailable,
                                    );
                                }
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                                ) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                self.workers.native.ports[slot]
                    .lock()
                    .as_mut()
                    .context("remote Port custody absent")?
                    .phase = Phase::Release;
                original.stage = Stage::Releasing;
                self.workers.wake_worker(
                    original.envelope.queue as usize % usize::from(self.workers.workers),
                );
            }
            Stage::Endpoint => {
                let result = {
                    let mut port = self.workers.native.ports[slot].lock();
                    let port = port.as_mut().context("Native endpoint custody absent")?;
                    match std::mem::replace(&mut port.phase, Phase::Working) {
                        Phase::EndpointDone(cell, report) => Some((cell, report)),
                        phase => {
                            port.phase = phase;
                            None
                        }
                    }
                };
                let Some((cell, report)) = result else {
                    return Ok(false);
                };
                original.envelope.cell = cell;
                original.taken_over = report.taken_over;
                self.workers.native.ports[slot]
                    .lock()
                    .as_mut()
                    .unwrap()
                    .phase = Phase::Release;
                original.stage = Stage::Releasing;
                self.workers.wake_worker(
                    original.envelope.queue as usize % usize::from(self.workers.workers),
                );
            }
            Stage::Flight => {
                let outcome = match self
                    .captured
                    .as_mut()
                    .context("remote Native operation absent")?
                    .poll_original(cx)
                {
                    Poll::Pending => return Ok(false),
                    Poll::Ready(outcome) => outcome?,
                };
                let proof = match outcome {
                    OriginalOutcome::Transferred(proof)
                    | OriginalOutcome::RefusedBeforeTransfer(proof) => proof,
                    OriginalOutcome::Ambiguous(proof) => {
                        publication.record_ambiguous(
                            proof.identity(),
                            proof.producer(),
                            proof.handle(),
                            [
                                proof.op_incarnation(),
                                proof.return_attachment(),
                                proof.entry_seq(),
                            ],
                        );
                        original.proof = Some(proof);
                        anyhow::bail!("remote Native return lacks conclusive target entry/grace");
                    }
                };
                ensure!(
                    proof.identity() == identity
                        && proof.handle() == handle
                        && proof.producer() == producer,
                    "remote Native operation receipt belongs to another original"
                );
                original.proof = Some(proof);
                self.workers.native.ports[slot]
                    .lock()
                    .as_mut()
                    .context("remote Port custody absent")?
                    .phase = Phase::Release;
                original.stage = Stage::Releasing;
                self.workers.wake_worker(
                    original.envelope.queue as usize % usize::from(self.workers.workers),
                );
            }
            Stage::Releasing => {
                let completion = {
                    let mut port = self.workers.native.ports[slot].lock();
                    let port = port.as_mut().context("remote released Port slot absent")?;
                    let phase = std::mem::replace(&mut port.phase, Phase::Working);
                    match phase {
                        Phase::Released(completion) => completion,
                        phase => {
                            port.phase = phase;
                            return Ok(false);
                        }
                    }
                };
                original.completion = Some(if let Some(proof) = &original.proof {
                    OriginalCompletion::returned(
                        completion,
                        producer,
                        [
                            proof.op_incarnation(),
                            proof.return_attachment(),
                            proof.entry_seq(),
                        ],
                        proof.is_transferred(),
                    )
                } else {
                    OriginalCompletion::local(completion, producer, original.taken_over)
                });
                original.stage = Stage::Completing;
                cx.waker().wake_by_ref();
            }
            Stage::Completing => {
                let mut inventory = OriginalInventory {
                    first_ordered: original
                        .proof
                        .as_ref()
                        .is_some_and(OriginalProof::is_transferred)
                        || publication
                            .claim(&identity.key)?
                            .is_some_and(|claim| claim.state & 15 == NATIVE_PHASE_DRAINING),
                    ..Default::default()
                };
                for other in self
                    .originals
                    .iter()
                    .filter(|other| other.identity == identity)
                {
                    match other.phase {
                        HeldPhase::Payload(_, _) => inventory.held += 1,
                        HeldPhase::Flight(_, _) => {
                            inventory.held += 1;
                            inventory.flight = true;
                        }
                        _ => inventory.pending += 1,
                    }
                }
                self.workers
                    .native
                    .add_inventory(identity, Some(slot), &mut inventory);
                publication.finish_original(
                    &identity,
                    original
                        .completion
                        .as_mut()
                        .context("remote original completion absent")?,
                    inventory,
                )?;
                let completion = original.completion.take().unwrap().into_port()?;
                self.workers.native.ports[slot]
                    .lock()
                    .as_mut()
                    .context("remote Port completion slot absent")?
                    .phase = Phase::Complete(completion);
                original.stage = Stage::Acknowledging;
                self.workers.wake_worker(
                    original.envelope.queue as usize % usize::from(self.workers.workers),
                );
            }
            Stage::Acknowledging => {
                let mut port = self.workers.native.ports[slot].lock();
                if !port
                    .as_ref()
                    .is_some_and(|port| matches!(port.phase, Phase::Ack))
                {
                    return Ok(false);
                }
                *port = None;
                drop(port);
                if let Some(proof) = original.proof.take() {
                    self.captured.as_mut().unwrap().settle_original(proof)?;
                }
                original.acknowledge();
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Runtime {
    pub(in crate::xdp) async fn drain_all_native_originals(
        &mut self,
        shutdown: &crate::control::ShutdownIntent,
    ) -> anyhow::Result<()> {
        if self.native.is_none() {
            return Ok(());
        }
        ensure!(
            self.closing && self.native_capture_close == NativeCaptureClose::Proven,
            "Native terminal worker drain lacks closed capture proof"
        );
        self.workers.barrier(u64::MAX);
        poll_fn(|cx| {
            let observed_barrier = self.workers.drain_epoch();
            match self.poll_io(cx, None, shutdown, false) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => cx.waker().wake_by_ref(),
                Poll::Pending => {}
            }
            let local_drained = self.inbox.is_empty()
                && self.originals.is_empty()
                && self.remote_originals.is_empty()
                && self.workers.native.is_empty()
                && self
                    .devices
                    .iter()
                    .flat_map(|device| &device.queues)
                    .all(|queue| {
                        let port = queue.io.get_ref();
                        let rings = port.rings();
                        rings.rx_producer == rings.rx_consumer
                            && rings.cq_producer == rings.cq_consumer
                            && port.retained_rx_count() == 0
                            && port.rx_completion_count() == 0
                            && port.counters().submitted == port.counters().completed
                    });
            self.workers
                .note_drained(0, observed_barrier, local_drained);
            if local_drained && self.workers.both_drained(u64::MAX) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        self.drain_native_originals()
    }
}
