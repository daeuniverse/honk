use super::*;
use crate::ebpf::native::{
    CaptureCommit, ImportedOriginal, NativeClaim, NativeClaimIdentity, NativeKey, NativeOriginal,
    NativePublication, NativeReason, OriginalCompletion, OriginalExtent, OriginalInventory,
};
use honk_ebpf_common::conn::is_stateless_udp_ports;
use honk_ebpf_common::xdp::*;
pub(super) mod captured;
mod remote;
#[cfg(test)]
pub(super) use captured::CapturedFault;
pub(super) use captured::{CapturedReturn, OriginalOutcome, OriginalProof};
use std::net::SocketAddr;

pub(super) fn key(view: PacketView<'_>, authority: CaptureAuthority) -> io::Result<NativeKey> {
    if !authority.is_valid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Native capture authority",
        ));
    }
    let ip = view.parse_ip().map_err(io::Error::other)?;
    let Some((source, destination)) = view.transport_ports(&ip).map_err(io::Error::other)? else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Native import requires TCP or UDP",
        ));
    };
    Ok(NativeKey {
        src_ip: crate::ebpf::maps::ip_addr_to_lpm_key(ip.src).data,
        dst_ip: crate::ebpf::maps::ip_addr_to_lpm_key(ip.dst).data,
        src_port: source.to_be(),
        dst_port: destination.to_be(),
        l4proto: ip.proto,
        ip_version: if ip.src.is_ipv4() { 4 } else { 6 },
        domain: NATIVE_DOMAIN_FLOW,
        direction: NATIVE_DIRECTION_ORIGINAL,
        namespace_cookie: authority.namespace_cookie,
        zone: 0,
        zone_state: NATIVE_ZONE_TRANSIT_DEFAULT,
        reserved: [0; 5],
    })
}

pub(super) fn imported(
    publication: &Arc<NativePublication>,
    scope: ScopeId,
    authority: CaptureAuthority,
    view: PacketView<'_>,
    metadata: &[u8],
) -> io::Result<ImportedOriginal> {
    let denied = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Native import identity or extent",
        )
    };
    if metadata.len() != NATIVE_METADATA_LEN {
        return Err(denied());
    }
    let envelope = PacketMetadata::decode(&metadata[..METADATA_LEN]).ok_or_else(denied)?;
    if envelope.ingress_ifindex != authority.ifindex {
        return Err(denied());
    }
    let import = NativeImport::decode(&metadata[METADATA_LEN..]).ok_or_else(denied)?;
    let key = key(view, authority)?;
    let claim = publication.import_claim(&key)?.ok_or_else(denied)?;
    if !claim.is_transit(&key) || !import_matches(&claim, &import, scope.as_u64()) {
        return Err(denied());
    }
    Ok(ImportedOriginal {
        identity: NativeClaimIdentity {
            key,
            epoch: claim.epoch,
            incarnation: claim.incarnation,
            scope: claim.scope,
        },
        producer: import,
        executor: claim.executor,
        state: claim.state,
    })
}

fn import_matches(claim: &NativeClaim, import: &NativeImport, scope: u64) -> bool {
    let phase = claim.state & 15;
    let counted = import.flags == NATIVE_IMPORT_COUNTED;
    claim.scope == scope
        && claim.incarnation == import.incarnation
        && claim.epoch <= import.epoch
        && claim.epoch != 0
        && claim.epoch & 1 != 0
        && claim.incarnation == claim.epoch
        && import.epoch & 1 != 0
        && import.expires_boottime_ns != 0
        && import.reserved == 0
        && import.flags & !NATIVE_IMPORT_COUNTED == 0
        && match (claim.executor, phase) {
            (NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED) => {
                !counted || claim.state >> 4 != 0
            }
            (NATIVE_EXECUTOR_PENDING, NATIVE_PHASE_PENDING)
            | (NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ARMED | NATIVE_PHASE_DRAINING) => {
                counted && claim.state >> 4 != 0
            }
            _ => false,
        }
}

enum HeldPhase {
    Payload(honk_xsk::RetainedRxHandle, NativeImport),
    Flight(honk_xsk::RetainedRxHandle, NativeImport),
    Completing(OriginalCompletion),
    Failed(honk_xsk::RetainedRxHandle),
}
pub(super) struct HeldOriginal {
    identity: NativeClaimIdentity,
    phase: HeldPhase,
    device: u16,
    queue: u16,
    realm: u16,
}
const _: () = assert!(size_of::<HeldOriginal>() <= 192);

impl HeldOriginal {
    pub(super) fn handle(&self) -> honk_xsk::RetainedRxHandle {
        match &self.phase {
            HeldPhase::Payload(handle, _)
            | HeldPhase::Flight(handle, _)
            | HeldPhase::Failed(handle) => *handle,
            HeldPhase::Completing(completion) => completion.handle(),
        }
    }

    #[cfg(test)]
    pub(super) fn identity(&self) -> NativeClaimIdentity {
        self.identity
    }

    #[cfg(test)]
    pub(super) fn import(&self) -> Option<NativeImport> {
        match &self.phase {
            HeldPhase::Payload(_, import) | HeldPhase::Flight(_, import) => Some(*import),
            HeldPhase::Completing(completion) => Some(completion.producer()),
            HeldPhase::Failed(_) => None,
        }
    }

    #[cfg(test)]
    pub(super) fn device(&self) -> usize {
        usize::from(self.device)
    }

    #[cfg(test)]
    pub(super) fn queue(&self) -> usize {
        usize::from(self.queue)
    }

    #[cfg(test)]
    pub(super) fn realm(&self) -> usize {
        usize::from(self.realm)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn receive_originals(
    port: &mut Port<Retained>,
    capture: &GeneralCapture,
    rx_queue: u32,
    device: usize,
    queue: usize,
    realms: &[Realm],
    publication: &Arc<NativePublication>,
    originals: &mut VecDeque<HeldOriginal>,
    pressure: &mut PressureCounters,
) -> anyhow::Result<usize> {
    let remaining = originals.capacity() - originals.len();
    if remaining == 0 {
        return Ok(0);
    }
    let first_new = originals.len();
    let mut failure = None;
    let received = port.receive_segments_owned(
        BATCH.min(remaining),
        NATIVE_METADATA_LEN,
        |handle, segments, metadata, _| {
            let result = (|| -> io::Result<HeldOriginal> {
                let decoded = capture
                    .decode(
                        segments,
                        if capture.vlan_metadata {
                            &metadata[..METADATA_LEN]
                        } else {
                            &[]
                        },
                        rx_queue,
                    )
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::PermissionDenied, "Native original envelope")
                    })?;
                let realm = realms
                    .iter()
                    .position(|realm| {
                        realm.device == device
                            && realm.link.path.vlan_count == decoded.vlan_count
                            && realm.link.path.vlan_proto == decoded.vlan_proto
                            && realm.link.path.vlan_tci.iter().zip(decoded.vlan_tci).all(
                                |(configured, captured)| configured & 0x0fff == captured & 0x0fff,
                            )
                    })
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::PermissionDenied, "Native original realm")
                    })?;
                let mut l3 = [&[][..]; 18];
                let count = l3_segments(segments, decoded, &mut l3)
                    .ok_or_else(|| io::Error::other("Native original SG"))?;
                let view = PacketView::new(&l3[..count]).map_err(io::Error::other)?;
                let imported = imported(
                    publication,
                    realms[realm].driver.scope(),
                    capture.authority,
                    view,
                    metadata,
                )?;
                Ok(HeldOriginal {
                    identity: imported.identity,
                    phase: HeldPhase::Payload(handle, imported.producer),
                    device: device.try_into().map_err(io::Error::other)?,
                    queue: queue.try_into().map_err(io::Error::other)?,
                    realm: realm.try_into().map_err(io::Error::other)?,
                })
            })();
            match result {
                Ok(original) => originals.push_back(original),
                Err(error) => {
                    pressure.capture_rejected = pressure.capture_rejected.saturating_add(1);
                    failure.get_or_insert(error);
                }
            }
            honk_xsk::RxDisposition::Retain
        },
    );
    let closure = publication.finish_import_turn();
    for original in originals.iter().skip(first_new) {
        if let HeldPhase::Payload(handle, producer) = &original.phase {
            publication.record_imported(original.identity, *producer, *handle);
        }
    }
    closure?;
    let received = received?;
    if let Some(error) = failure {
        return Err(error.into());
    }
    Ok(received)
}

fn take_candidate(next: &mut u64) -> Option<u64> {
    let candidate = *next;
    if candidate == 0 {
        return None;
    }
    *next = candidate.checked_add(1)?;
    Some(candidate)
}

pub(super) fn address(words: [u32; 4], port: u16) -> SocketAddr {
    let mut bytes = [0; 16];
    for (target, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        target.copy_from_slice(&word.to_ne_bytes());
    }
    SocketAddr::new(
        std::net::Ipv6Addr::from(bytes).to_canonical(),
        u16::from_be(port),
    )
}

fn begin_native_turn(
    publication: Option<&Arc<NativePublication>>,
    writer: &mut Option<crate::ebpf::native::NativeWrite>,
    closing: bool,
    next: &mut Instant,
    now: Instant,
    maintenance_needed: impl FnOnce(&NativePublication) -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    if !closing
        && writer.is_none()
        && now >= *next
        && let Some(publication) = publication
    {
        if !maintenance_needed(publication)? {
            *next = now + Duration::from_secs(1);
            return Ok(());
        }
        // Admitted XDP execution and xdp_do_flush share RCU; drain RX/CQ after grace.
        *writer = Some(publication.write(NativeReason::RuntimeMaintenance)?);
    }
    Ok(())
}

fn finish_native_turn(
    writer: &mut Option<crate::ebpf::native::NativeWrite>,
    next: &mut Instant,
    now: Instant,
    cut_short: bool,
    rings_pending: impl FnOnce() -> bool,
    retire_claims: impl FnOnce(u64) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let Some(active) = writer.as_ref() else {
        return Ok(());
    };
    if cut_short || rings_pending() {
        return Ok(());
    }
    retire_claims(active.epoch())?;
    writer.take().unwrap().commit();
    *next = now + Duration::from_secs(1);
    Ok(())
}

fn ordinary_udp(key: &NativeKey) -> bool {
    key.l4proto == 17
        && !is_stateless_udp_ports(u16::from_be(key.src_port), u16::from_be(key.dst_port))
}

fn claim_may_retire(
    key: &NativeKey,
    claim: &NativeClaim,
    now_ns: u64,
    endpoint_retained: impl FnOnce() -> bool,
) -> bool {
    if !matches!(
        claim.executor,
        NATIVE_EXECUTOR_CAPTURE | NATIVE_EXECUTOR_KERNEL | NATIVE_EXECUTOR_PENDING
    ) {
        return true;
    }
    if claim.state >> 4 != 0
        || !matches!(
            (claim.executor, claim.state & 15),
            (NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED)
                | (NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ACTIVE)
        )
    {
        return false;
    }
    match claim.executor {
        NATIVE_EXECUTOR_CAPTURE => !endpoint_retained(),
        NATIVE_EXECUTOR_KERNEL => {
            !ordinary_udp(key) || native_claim_udp_expired(claim.last_seen_ns, now_ns)
        }
        _ => true,
    }
}

fn claim_retained(
    key: &NativeKey,
    claim: &NativeClaim,
    now_ns: u64,
    endpoint_retained: impl FnOnce() -> bool,
    kernel_owned: impl FnOnce() -> anyhow::Result<Option<bool>>,
) -> anyhow::Result<bool> {
    anyhow::ensure!(
        matches!(
            claim.executor,
            NATIVE_EXECUTOR_CAPTURE | NATIVE_EXECUTOR_KERNEL | NATIVE_EXECUTOR_PENDING
        ),
        "invalid Native ordinary executor"
    );
    if claim.state >> 4 != 0
        || !matches!(
            (claim.executor, claim.state & 15),
            (NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED)
                | (NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ACTIVE)
        )
    {
        return Ok(true);
    }
    match claim.executor {
        NATIVE_EXECUTOR_CAPTURE => Ok(endpoint_retained()),
        NATIVE_EXECUTOR_KERNEL => {
            let ordinary_udp = ordinary_udp(key);
            if ordinary_udp
                && (!native_claim_udp_expired(claim.last_seen_ns, now_ns) || endpoint_retained())
            {
                return Ok(true);
            }
            let owned = kernel_owned()?;
            Ok(if ordinary_udp {
                owned != Some(false)
            } else {
                owned.is_none()
            })
        }
        _ => anyhow::bail!("invalid Native ordinary executor"),
    }
}

fn export_native_recording(
    publication: Option<&Arc<NativePublication>>,
    final_export: bool,
    hooks_joined: bool,
    shutdown_stage: &'static str,
    failure: &mut Option<anyhow::Error>,
) {
    let Some(publication) = publication else {
        return;
    };
    let result = publication.export_recording(final_export, hooks_joined);
    result.record();
    tracing::info!(
        final_export, hooks_joined, shutdown_stage,
        shutdown_error = ?failure.as_ref(), export_error = ?result.error,
        "Native publication shutdown result"
    );
    if let Some(error) = result.error {
        *failure = Some(match failure.take() {
            Some(original) => {
                original.context(format!("Native publication export also failed: {error:#}"))
            }
            None => error,
        });
    }
}

impl Runtime {
    pub(super) fn retain_native_drop(&mut self) {
        if self.native.is_none() {
            return;
        }
        let retained = !self.originals.is_empty()
            || !self.remote_originals.is_empty()
            || !self.workers.native.is_empty()
            || self.original_outcome.is_some()
            || self
                .captured
                .as_ref()
                .is_some_and(|captured| !captured.is_idle())
            || self
                .devices
                .iter()
                .flat_map(|device| &device.queues)
                .any(|queue| {
                    let port = queue.io.get_ref();
                    port.retained_rx_count() != 0 || port.rx_completion_count() != 0
                });
        if !retained {
            return;
        }
        if let Some(captured) = &mut self.captured
            && let Err(error) = captured.seal()
        {
            tracing::error!(%error, "cancelled Native return owner remains retained");
        }
        std::mem::forget((
            std::mem::take(&mut self.devices),
            std::mem::take(&mut self.originals),
            std::mem::take(&mut self.remote_originals),
            self.original_outcome.take(),
            self.captured.take(),
            self.native.take(),
            self.native_writer.take(),
            self._original_memory.take(),
            self._memory.take(),
        ));
    }

    pub(super) fn service_native_originals(
        &mut self,
        cx: &mut Context<'_>,
        now: Instant,
    ) -> anyhow::Result<usize> {
        self.service_native_originals_limited(cx, now, BATCH)
    }

    #[cfg(test)]
    pub(super) fn service_one_native_original(
        &mut self,
        cx: &mut Context<'_>,
        now: Instant,
    ) -> anyhow::Result<usize> {
        self.service_native_originals_limited(cx, now, 1)
    }

    fn service_native_originals_limited(
        &mut self,
        cx: &mut Context<'_>,
        now: Instant,
        limit: usize,
    ) -> anyhow::Result<usize> {
        use crate::control::core_forward::CapturedDecision;
        let Some(publication) = self.native.as_ref().cloned() else {
            return Ok(0);
        };
        ensure!(
            !self.closing || self.native_capture_close == NativeCaptureClose::Proven,
            "Native original completion requires proven terminal capture"
        );
        let mut progress = 0;
        for _ in 0..limit {
            let Some(front) = self.originals.front() else {
                break;
            };
            let identity = front.identity;
            let device_index = usize::from(front.device);
            let queue_index = usize::from(front.queue);
            let realm_index = usize::from(front.realm);
            let handle = front.handle();
            if matches!(front.phase, HeldPhase::Failed(_)) {
                anyhow::bail!("Native original completion retained after ownership failure");
            }
            if matches!(front.phase, HeldPhase::Flight(_, _)) && self.original_outcome.is_none() {
                let outcome = match self
                    .captured
                    .as_mut()
                    .context("Native return operation absent")?
                    .poll_original(cx)
                {
                    Poll::Pending => break,
                    Poll::Ready(outcome) => outcome?,
                };
                match outcome {
                    OriginalOutcome::Transferred(proof)
                    | OriginalOutcome::RefusedBeforeTransfer(proof) => {
                        self.original_outcome = Some(proof)
                    }
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
                        self.original_outcome = Some(proof);
                        anyhow::bail!(
                            "Native return lacks a conclusive target entry and fresh grace"
                        );
                    }
                }
            }
            if let HeldPhase::Flight(_, producer) = &self.originals.front().unwrap().phase {
                let producer = *producer;
                let proof = self
                    .original_outcome
                    .as_ref()
                    .context("Native operation outcome absent")?;
                ensure!(
                    proof.identity() == identity
                        && proof.handle() == handle
                        && proof.producer() == producer,
                    "Native operation receipt belongs to another original"
                );
                ensure!(
                    proof.is_transferred() || proof.is_refused(),
                    "ambiguous original remains retained"
                );
                let operation = [
                    proof.op_incarnation(),
                    proof.return_attachment(),
                    proof.entry_seq(),
                ];
                let transferred = proof.is_transferred();
                let completion = self.devices[device_index].queues[queue_index]
                    .io
                    .get_mut()
                    .release_retained_rx(handle)?;
                self.originals.front_mut().unwrap().phase = HeldPhase::Completing(
                    OriginalCompletion::returned(completion, producer, operation, transferred),
                );
            }
            if matches!(
                self.originals.front().unwrap().phase,
                HeldPhase::Completing(_)
            ) {
                let first_ordered = self
                    .original_outcome
                    .as_ref()
                    .is_some_and(OriginalProof::is_transferred)
                    || publication
                        .claim(&identity.key)?
                        .is_some_and(|claim| claim.state & 15 == NATIVE_PHASE_DRAINING);
                let mut inventory = OriginalInventory {
                    first_ordered,
                    ..Default::default()
                };
                for original in self
                    .originals
                    .iter()
                    .skip(1)
                    .filter(|original| original.identity == identity)
                {
                    match original.phase {
                        HeldPhase::Payload(_, _) => inventory.held += 1,
                        HeldPhase::Flight(_, _) => {
                            inventory.held += 1;
                            inventory.flight = true;
                        }
                        HeldPhase::Completing(_) | HeldPhase::Failed(_) => inventory.pending += 1,
                    }
                }
                self.workers
                    .native
                    .add_inventory(identity, None, &mut inventory);
                if let HeldPhase::Completing(completion) =
                    &mut self.originals.front_mut().unwrap().phase
                {
                    publication.finish_original(&identity, completion, inventory)?;
                }
                let original = self.originals.front_mut().unwrap();
                let HeldPhase::Completing(completion) =
                    std::mem::replace(&mut original.phase, HeldPhase::Failed(handle))
                else {
                    unreachable!()
                };
                self.devices[device_index].queues[queue_index]
                    .io
                    .get_mut()
                    .complete_retained_rx(completion.into_port()?)?;
                if let Some(proof) = self.original_outcome.take() {
                    self.captured.as_mut().unwrap().settle_original(proof)?;
                }
                self.originals.pop_front();
                progress += 1;
                continue;
            }
            let HeldPhase::Payload(_, producer) = &self.originals.front().unwrap().phase else {
                unreachable!()
            };
            let producer = *producer;
            let claim = publication
                .claim(&identity.key)?
                .context("retained Native owner absent")?;
            ensure!(identity.matches(&claim), "retained Native owner changed");
            let mut admission = None;
            let mut dispose = self.closing;
            if !self.closing && claim.executor != NATIVE_EXECUTOR_CAPTURE {
                let Some(candidate) = take_candidate(&mut self.next_candidate) else {
                    let completion = self.devices[device_index].queues[queue_index]
                        .io
                        .get_mut()
                        .release_retained_rx(handle)?;
                    self.originals.front_mut().unwrap().phase = HeldPhase::Completing(
                        OriginalCompletion::local(completion, producer, false),
                    );
                    continue;
                };
                let Some((basis_epoch, basis_flags)) = publication.selection_snapshot() else {
                    publication.check_original_selection()?;
                    cx.waker().wake_by_ref();
                    break;
                };
                let authority = self
                    .native_policy
                    .as_ref()
                    .context("Native policy registration absent")?;
                let read = match authority.try_read_policy() {
                    Ok(read) => read,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        cx.waker().wake_by_ref();
                        break;
                    }
                    Err(error) => return Err(error.into()),
                };
                let device = &self.devices[device_index];
                let realm = &self.realms[realm_index];
                let context = device.queues[queue_index].io.get_ref().with_retained_rx(
                    handle,
                    |segments, metadata| -> io::Result<_> {
                        let decoded = device
                            .capture
                            .decode(
                                segments,
                                if device.capture.vlan_metadata {
                                    &metadata[..METADATA_LEN]
                                } else {
                                    &[]
                                },
                                device.queues[queue_index].id,
                            )
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "retained Native envelope changed",
                                )
                            })?;
                        if decoded.destination_mac != realm.link.mac
                            || decoded.destination_mac[0] & 1 != 0
                        {
                            return Ok(None);
                        }
                        let mut l3 = [&[][..]; 18];
                        let count = l3_segments(segments, decoded, &mut l3)
                            .ok_or_else(|| io::Error::other("retained Native SG"))?;
                        let view = PacketView::new(&l3[..count]).map_err(io::Error::other)?;
                        let ip = view.parse_ip().map_err(io::Error::other)?;
                        let ports = view.transport_ports(&ip).map_err(io::Error::other)?;
                        Ok(Some((
                            honk_datapath::forward::RouteQuery {
                                ingress: realm.ingress,
                                source: ip.src,
                                destination: ip.dst,
                                traffic_class: ip.dscp << 2,
                                protocol: ip.proto,
                                ports,
                            },
                            OriginalExtent {
                                frame_length: decoded
                                    .frame_len
                                    .try_into()
                                    .map_err(io::Error::other)?,
                                l3_offset: decoded
                                    .l3_offset
                                    .try_into()
                                    .map_err(io::Error::other)?,
                                l3_length: decoded.l3_len.try_into().map_err(io::Error::other)?,
                                vlan_tci: decoded.vlan_tci,
                                vlan_proto: decoded.vlan_proto,
                                vlan_count: decoded.vlan_count.into(),
                                inline_vlan_count: decoded.inline_vlan_count.into(),
                                dscp: ip.dscp,
                            },
                        )))
                    },
                )??;
                let imported = ImportedOriginal {
                    identity,
                    producer,
                    executor: claim.executor,
                    state: claim.state,
                };
                let decision = if let Some((query, extent)) = context {
                    let original = NativeOriginal {
                        imported: &imported,
                        authority: device.capture.authority,
                        ingress: realm.ingress,
                        facts: realm.driver.scope(),
                        realm_index: realm_index as u32,
                        rx_queue: device.queues[queue_index].id,
                        basis_epoch,
                        basis_flags,
                        extent,
                        candidate,
                        retained_capture: self.endpoints.retains(
                            realm.driver.scope(),
                            address(identity.key.src_ip, identity.key.src_port),
                            address(identity.key.dst_ip, identity.key.dst_port),
                            identity.key.l4proto,
                        ),
                    };
                    authority.capture_original(
                        &read,
                        query,
                        realm.driver.scope(),
                        &original,
                        &self.polling_budget,
                    )
                } else {
                    Ok(CapturedDecision::Refuse)
                };
                drop(read);
                if publication.selection_epoch() != Some(basis_epoch) {
                    continue;
                }
                let decision = match decision {
                    Ok(decision) => decision,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        cx.waker().wake_by_ref();
                        break;
                    }
                    Err(error) => return Err(error.into()),
                };
                match decision {
                    CapturedDecision::TryNativeOriginal(basis) => {
                        let port = self.devices[device_index].queues[queue_index].io.get_ref();
                        match self
                            .captured
                            .as_mut()
                            .context("Native return operation absent")?
                            .begin_original(port, handle, &basis)
                        {
                            Ok(()) => {
                                self.originals.front_mut().unwrap().phase =
                                    HeldPhase::Flight(handle, producer)
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                cx.waker().wake_by_ref();
                                break;
                            }
                            Err(error) => return Err(error.into()),
                        }
                        continue;
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
                                continue;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    CapturedDecision::Endpoint(_) | CapturedDecision::Refuse => dispose = true,
                }
            }
            let mut receive_error = None;
            let mut taken_over = false;
            if !dispose {
                let device = &self.devices[device_index];
                let realm = &self.realms[realm_index];
                let result = device.queues[queue_index].io.get_ref().with_retained_rx(
                    handle,
                    |segments, metadata| -> io::Result<Option<PacketReceive>> {
                        let decoded = device
                            .capture
                            .decode(
                                segments,
                                if device.capture.vlan_metadata {
                                    &metadata[..METADATA_LEN]
                                } else {
                                    &[]
                                },
                                device.queues[queue_index].id,
                            )
                            .map_err(|_| io::Error::other("Native takeover envelope changed"))?;
                        if decoded.destination_mac != realm.link.mac
                            || decoded.destination_mac[0] & 1 != 0
                        {
                            return Ok(None);
                        }
                        let mut l3 = [&[][..]; 18];
                        let count = l3_segments(segments, decoded, &mut l3)
                            .ok_or_else(|| io::Error::other("Native takeover SG"))?;
                        let view = PacketView::new(&l3[..count]).map_err(io::Error::other)?;
                        let bytes = if count == 1 {
                            l3[0]
                        } else {
                            if decoded.l3_len > self.staging.len()
                                || view
                                    .copy_to(0..decoded.l3_len, &mut self.staging[..decoded.l3_len])
                                    .is_none()
                            {
                                return Err(io::Error::other("Native takeover staging extent"));
                            }
                            &self.staging[..decoded.l3_len]
                        };
                        let owner = self.workers.owner(realm.driver.scope(), bytes)?;
                        self.workers
                            .receive(
                                &self.endpoints,
                                &owner,
                                bytes,
                                now,
                                now,
                                ReturnPath {
                                    device: device_index,
                                    mac: decoded.source_mac,
                                    vlan_tci: decoded.vlan_tci,
                                    vlan_proto: decoded.vlan_proto,
                                    vlan_count: decoded.vlan_count,
                                },
                                admission,
                            )
                            .map(Some)
                    },
                )?;
                taken_over = result
                    .as_ref()
                    .is_ok_and(|report| report.as_ref().is_some_and(|report| report.taken_over));
                match result {
                    Ok(Some(report)) if report.qualified_rx => {
                        qualify_packet(&mut self.qualified_rx, &mut self.qualification_unavailable)
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                        ) => {}
                    Err(error) => receive_error = Some(error),
                }
            }
            let completion = self.devices[device_index].queues[queue_index]
                .io
                .get_mut()
                .release_retained_rx(handle)?;
            self.originals.front_mut().unwrap().phase =
                HeldPhase::Completing(OriginalCompletion::local(completion, producer, taken_over));
            if let Some(error) = receive_error {
                // The completion stays in the funded slot for terminal owner service.
                return Err(error.into());
            }
        }
        Ok(progress)
    }
    pub(super) fn finalize_native_recording(&self) -> anyhow::Result<()> {
        let Some(publication) = &self.native else {
            return Ok(());
        };
        let withdrawal = withdraw_native_recording_targets(
            self.devices
                .iter()
                .filter_map(|device| device.native_target.as_ref()),
            |target| target.withdraw_recording_hooks(),
        );
        let finalized = publication.finalize_recording(withdrawal.is_ok());
        let mut failure = withdrawal.err();
        fold_capture_result(&mut failure, finalized);
        failure.map_or(Ok(()), Err)
    }

    pub(super) fn export_native_recording(
        &self,
        final_export: bool,
        hooks_joined: bool,
        shutdown_stage: &'static str,
        failure: &mut Option<anyhow::Error>,
    ) {
        export_native_recording(
            self.native.as_ref(),
            final_export,
            hooks_joined,
            shutdown_stage,
            failure,
        );
    }

    pub(super) fn begin_native_turn(&mut self, now: Instant) -> anyhow::Result<()> {
        if !self.originals.is_empty()
            || !self.remote_originals.is_empty()
            || !self.inbox.is_empty()
            || !self.workers.native.is_empty()
            || self
                .captured
                .as_ref()
                .is_some_and(|captured| !captured.is_idle())
        {
            return Ok(());
        }
        let realms = &self.realms;
        let endpoints = &self.endpoints;
        begin_native_turn(
            self.native.as_ref(),
            &mut self.native_writer,
            self.closing,
            &mut self.native_next,
            now,
            |publication| {
                let now_ns = publication.monotonic_ns()?;
                let mut host_error = None;
                let needed = publication.maintenance_needed(|key, claim| {
                    if claim.owner_cookie != 0 {
                        if endpoints.retains_host_source(
                            key.namespace_cookie,
                            claim.owner_cookie,
                            claim.owner_incarnation,
                            claim.attachment_generation,
                            address(key.src_ip, 0).ip(),
                        ) {
                            return false;
                        }
                        return match publication.host_source_may_retire(key, claim, now_ns) {
                            Ok(needed) => needed,
                            Err(error) => {
                                host_error = Some(error);
                                true
                            }
                        };
                    }
                    claim_may_retire(key, claim, now_ns, || {
                        realms
                            .iter()
                            .find(|realm| realm.driver.scope().as_u64() == claim.scope)
                            .is_some_and(|realm| {
                                endpoints.retains(
                                    realm.driver.scope(),
                                    address(key.src_ip, key.src_port),
                                    address(key.dst_ip, key.dst_port),
                                    key.l4proto,
                                )
                            })
                    })
                })?;
                if let Some(error) = host_error {
                    return Err(error.into());
                }
                Ok(needed)
            },
        )
    }
    pub(super) fn drain_native_originals(&mut self) -> anyhow::Result<()> {
        if self.native.is_none() {
            return Ok(());
        }
        ensure!(
            self.closing && self.native_capture_close == NativeCaptureClose::Proven,
            "Native original disposal requires proven terminal capture"
        );
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        for _ in 0..=self.originals.capacity() {
            let mut received = 0;
            for (device_index, device) in self.devices.iter_mut().enumerate() {
                for (queue_index, queue) in device.queues.iter_mut().enumerate() {
                    let port = queue.io.get_mut();
                    port.complete(release_completed)?;
                    received += receive_originals(
                        port,
                        &device.capture,
                        queue.id,
                        device_index,
                        queue_index,
                        &self.realms,
                        self.native.as_ref().unwrap(),
                        &mut self.originals,
                        &mut self.pressure.counters,
                    )?;
                }
            }
            let progress = self.service_native_originals(&mut cx, Instant::now())?;
            if received == 0 && progress == 0 {
                break;
            }
        }
        ensure!(
            self.originals.is_empty() && self.original_outcome.is_none(),
            "Native held originals remain after withdrawal/grace"
        );
        if let Some(captured) = &mut self.captured {
            ensure!(
                captured.finish_close()?,
                "Native private operation has unresolved custody"
            );
            let joined = captured
                .joined_receipt()
                .context("Native captured close lacks durable joined receipt")?;
            self.native.as_ref().unwrap().acknowledge_captured_join(
                joined.return_attachment,
                &joined.path,
                joined.sha256,
            )?;
        }
        for device in &self.devices {
            for queue in &device.queues {
                let port = queue.io.get_ref();
                let rings = port.rings();
                ensure!(
                    rings.rx_producer == rings.rx_consumer
                        && rings.cq_producer == rings.cq_consumer
                        && port.retained_rx_count() == 0
                        && port.rx_completion_count() == 0,
                    "Native RX chains or packet generations remain after terminal drain"
                );
            }
        }
        Ok(())
    }

    pub(super) fn finish_native_turn(
        &mut self,
        now: Instant,
        observed_barrier: u64,
    ) -> anyhow::Result<()> {
        if !self.originals.is_empty()
            || !self.remote_originals.is_empty()
            || !self.workers.native.is_empty()
            || self
                .captured
                .as_ref()
                .is_some_and(|captured| !captured.is_idle())
        {
            if let Some(writer) = self.native_writer.take() {
                writer.commit();
                self.workers.barrier(0);
            }
            return Ok(());
        }
        if let Some(writer) = &self.native_writer {
            if writer.epoch() != observed_barrier {
                return Ok(());
            }
            let drained = !self.round_cut_short
                && self.inbox.is_empty()
                && self
                    .host
                    .as_ref()
                    .is_none_or(|host| host.native_retirement_drained())
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
                    });
            self.workers.note_drained(0, observed_barrier, drained);
            if !self.workers.both_drained(writer.epoch()) {
                return Ok(());
            }
            if let Some(publication) = &self.native {
                publication.retire_host_sources(writer, |key, claim| {
                    self.endpoints.retains_host_source(
                        key.namespace_cookie,
                        claim.owner_cookie,
                        claim.owner_incarnation,
                        claim.attachment_generation,
                        address(key.src_ip, 0).ip(),
                    )
                })?;
            }
        }
        let devices = &self.devices;
        let realms = &self.realms;
        let endpoints = &self.endpoints;
        let publication = self.native.as_ref();
        let result = finish_native_turn(
            &mut self.native_writer,
            &mut self.native_next,
            now,
            self.round_cut_short,
            || {
                devices
                    .iter()
                    .flat_map(|device| &device.queues)
                    .any(|queue| {
                        let rings = queue.io.get_ref().rings();
                        rings.rx_producer != rings.rx_consumer
                            || rings.cq_producer != rings.cq_consumer
                    })
            },
            |cutoff| {
                let publication = publication.expect("writer retains Native publication");
                let claims = publication.claims()?;
                let now_ns = publication.monotonic_ns()?;
                for (key, claim) in claims {
                    if claim.epoch >= cutoff {
                        continue;
                    }
                    if claim.owner_cookie != 0 {
                        continue;
                    }
                    let realm = realms
                        .iter()
                        .find(|realm| realm.driver.scope().as_u64() == claim.scope)
                        .context("Native ordinary owner has no registered capture scope")?;
                    let retained = claim_retained(
                        &key,
                        &claim,
                        now_ns,
                        || {
                            endpoints.retains(
                                realm.driver.scope(),
                                address(key.src_ip, key.src_port),
                                address(key.dst_ip, key.dst_port),
                                key.l4proto,
                            )
                        },
                        || {
                            let target = devices[realm.device]
                                .native_target
                                .as_ref()
                                .context("Native Kernel claim has no actual gate consumer")?;
                            publication.query_claim(&key, &claim, || target.kernel_owned(&key))
                        },
                    )?;
                    if !retained {
                        publication.remove_claim(&key, &claim)?;
                    }
                }
                Ok(())
            },
        );
        if self.native_writer.is_none() {
            self.workers.barrier(0);
        }
        result
    }
}

fn withdraw_native_recording_targets<T>(
    targets: impl IntoIterator<Item = T>,
    mut withdraw: impl FnMut(T) -> io::Result<()>,
) -> anyhow::Result<()> {
    let mut failure: Option<anyhow::Error> = None;
    for target in targets {
        if let Err(error) = withdraw(target) {
            failure = Some(match failure {
                Some(previous) => {
                    previous.context(format!("Native hook withdrawal also failed: {error}"))
                }
                None => error.into(),
            });
        }
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    #[test]
    fn unknown_executor_cannot_be_retained_as_a_pending_original() {
        let error = claim_retained(
            &NativeKey::default(),
            &NativeClaim::default(),
            0,
            || panic!("unknown executor must not query Endpoint retention"),
            || panic!("unknown executor must not query Kernel ownership"),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "invalid Native ordinary executor");
    }

    #[test]
    fn native_capture_candidate_counter_never_reuses_zero_or_wraps() {
        let mut next = 1;
        assert_eq!(take_candidate(&mut next), Some(1));
        assert_eq!(take_candidate(&mut next), Some(2));
        let mut exhausted = u64::MAX;
        assert_eq!(take_candidate(&mut exhausted), None);
        assert_eq!(exhausted, u64::MAX);
        assert_eq!(take_candidate(&mut exhausted), None);
        let mut zero = 0;
        assert_eq!(take_candidate(&mut zero), None);
        assert_eq!(zero, 0);
    }

    #[test]
    fn native_import_v2_rejects_old_extents_flags_and_reserved() {
        let producer = NativeImport {
            epoch: 5,
            incarnation: 3,
            expires_boottime_ns: u64::MAX,
            flags: NATIVE_IMPORT_COUNTED,
            reserved: 0,
        };
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&producer.epoch.to_ne_bytes());
        bytes[8..16].copy_from_slice(&producer.incarnation.to_ne_bytes());
        bytes[16..24].copy_from_slice(&producer.expires_boottime_ns.to_ne_bytes());
        bytes[24..28].copy_from_slice(&producer.flags.to_ne_bytes());
        assert_eq!(NativeImport::decode(&bytes), Some(producer));
        for extent in [0, 16, 24, 31, 33, 48, 64] {
            assert!(
                NativeImport::decode(&[0u8; 64][..extent]).is_none(),
                "extent={extent}"
            );
        }
        let mut unknown_flags = bytes;
        unknown_flags[24..28].copy_from_slice(&2u32.to_ne_bytes());
        assert!(NativeImport::decode(&unknown_flags).is_none());
        let mut reserved = bytes;
        reserved[28..32].copy_from_slice(&1u32.to_ne_bytes());
        assert!(NativeImport::decode(&reserved).is_none());
        for (executor, phase) in [
            (NATIVE_EXECUTOR_PENDING, NATIVE_PHASE_PENDING),
            (NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ARMED),
            (NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_DRAINING),
        ] {
            let claim = NativeClaim {
                epoch: 3,
                incarnation: 3,
                scope: 7,
                executor,
                state: (1 << 4) | phase,
                ..Default::default()
            };
            assert!(import_matches(&claim, &producer, 7));
            assert!(!import_matches(
                &claim,
                &NativeImport {
                    flags: 0,
                    ..producer
                },
                7
            ));
            assert!(!import_matches(
                &NativeClaim {
                    state: phase,
                    ..claim
                },
                &producer,
                7
            ));
        }
        let capture = NativeClaim {
            epoch: 3,
            incarnation: 3,
            scope: 7,
            executor: NATIVE_EXECUTOR_CAPTURE,
            state: (1 << 4) | NATIVE_PHASE_CAPTURE_COMMITTED,
            ..Default::default()
        };
        assert!(import_matches(&capture, &producer, 7));
        assert!(import_matches(
            &capture,
            &NativeImport {
                flags: 0,
                ..producer
            },
            7
        ));
        assert!(!import_matches(
            &NativeClaim {
                state: NATIVE_PHASE_CAPTURE_COMMITTED,
                ..capture
            },
            &producer,
            7
        ));
        assert!(import_matches(
            &NativeClaim {
                state: NATIVE_PHASE_CAPTURE_COMMITTED,
                ..capture
            },
            &NativeImport {
                flags: 0,
                ..producer
            },
            7
        ));
        assert!(!import_matches(
            &capture,
            &NativeImport {
                expires_boottime_ns: 0,
                ..producer
            },
            7
        ));
        let active = NativeClaim {
            executor: NATIVE_EXECUTOR_KERNEL,
            state: NATIVE_PHASE_ACTIVE,
            ..capture
        };
        assert!(!import_matches(&active, &producer, 7));
        assert!(!import_matches(
            &active,
            &NativeImport {
                flags: 0,
                ..producer
            },
            7
        ));
        let source = NativeClaim {
            executor: NATIVE_EXECUTOR_PENDING,
            state: (1 << 4) | NATIVE_PHASE_SOURCE_PENDING,
            ..capture
        };
        assert!(!import_matches(&source, &producer, 7));
    }

    #[test]
    fn native_udp_idle_compares_unshifted_kernel_time() {
        use crate::ebpf::native::kernel_monotonic_ns;
        use honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS;

        let key = NativeKey {
            src_port: 45004u16.to_be(),
            dst_port: 18101u16.to_be(),
            l4proto: 17,
            ..Default::default()
        };
        let claim = NativeClaim {
            executor: NATIVE_EXECUTOR_KERNEL,
            state: NATIVE_PHASE_ACTIVE,
            last_seen_ns: 600_000_000_000,
            ..Default::default()
        };
        for offset in [-300_000_000_000i128, 0, 300_000_000_000] {
            for (age, retained) in [
                (UDP_CONN_STATE_TIMEOUT_NS, true),
                (UDP_CONN_STATE_TIMEOUT_NS + 1, false),
            ] {
                let kernel_now = claim.last_seen_ns + age;
                let local_now = u64::try_from(i128::from(kernel_now) + offset).unwrap();
                let now = kernel_monotonic_ns(local_now, offset).unwrap();
                assert_eq!(
                    claim_retained(&key, &claim, now, || false, || Ok(Some(false))).unwrap(),
                    retained,
                    "offset={offset}, age={age}",
                );
            }
        }
        assert!(kernel_monotonic_ns(1, 2).is_err());
        assert!(kernel_monotonic_ns(u64::MAX, -1).is_err());
    }

    #[test]
    fn native_import_capture_identity_ignores_mutable_activity() {
        let import = NativeImport {
            epoch: 5,
            incarnation: 3,
            expires_boottime_ns: u64::MAX,
            flags: 0,
            reserved: 0,
        };
        let claim = NativeClaim {
            epoch: 3,
            incarnation: 3,
            scope: 7,
            executor: NATIVE_EXECUTOR_CAPTURE,
            state: NATIVE_PHASE_CAPTURE_COMMITTED,
            ..Default::default()
        };
        for last_seen_ns in [0, 1, u64::MAX] {
            assert!(import_matches(
                &NativeClaim {
                    last_seen_ns,
                    ..claim
                },
                &import,
                7
            ));
        }
        for invalid in [
            NativeClaim {
                executor: NATIVE_EXECUTOR_KERNEL,
                ..claim
            },
            NativeClaim { scope: 8, ..claim },
            NativeClaim {
                incarnation: 1,
                ..claim
            },
            NativeClaim { epoch: 7, ..claim },
            NativeClaim { epoch: 0, ..claim },
            NativeClaim { epoch: 2, ..claim },
            NativeClaim {
                state: NATIVE_PHASE_CLOSING,
                ..claim
            },
        ] {
            assert!(!import_matches(&invalid, &import, 7));
        }
        assert!(!import_matches(
            &claim,
            &NativeImport { epoch: 4, ..import },
            7
        ));
    }

    #[test]
    #[ignore = "requires guest root in a disposable virtme VM private network namespace"]
    fn real_map_udp_retirement_preserves_active_owned_and_late_activity_claims() {
        use honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS;
        use std::os::unix::fs::MetadataExt;

        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert!(
            std::fs::read_to_string("/proc/cmdline")
                .unwrap()
                .contains("virtme.")
        );
        assert_ne!(
            std::fs::metadata("/proc/self/ns/net").unwrap().ino(),
            std::fs::metadata("/proc/1/ns/net").unwrap().ino()
        );
        let publication =
            NativePublication::new_with_capacity(MemoryBudget::new(8 << 20), 1).unwrap();
        publication.open_for_test().unwrap();
        let key = NativeKey {
            src_port: 45004u16.to_be(),
            dst_port: 18101u16.to_be(),
            l4proto: 17,
            ip_version: 4,
            namespace_cookie: 1,
            zone_state: NATIVE_ZONE_TRANSIT_DEFAULT,
            ..Default::default()
        };
        let now_ns = 10 * UDP_CONN_STATE_TIMEOUT_NS;
        let now = Instant::now();
        let mut next = now;
        let mut writer = None;
        let begin = |writer: &mut Option<crate::ebpf::native::NativeWrite>,
                     next: &mut Instant,
                     endpoint| {
            let now = *next;
            begin_native_turn(
                Some(&publication),
                writer,
                false,
                next,
                now,
                |publication| {
                    publication.maintenance_needed(|key, claim| {
                        claim_may_retire(key, claim, now_ns, || endpoint)
                    })
                },
            )
        };
        let epoch = publication.epoch_for_test();
        let attempts = publication.write_attempts_for_test();
        begin(&mut writer, &mut next, false).unwrap();
        assert!(writer.is_none());
        assert_eq!(publication.epoch_for_test(), epoch);
        assert_eq!(publication.write_attempts_for_test(), attempts);
        assert_eq!(next, now + Duration::from_secs(1));
        for (last_seen_ns, endpoint, owned, late, retained, queried, closes) in [
            (now_ns, false, Some(false), false, true, false, false),
            (
                now_ns - UDP_CONN_STATE_TIMEOUT_NS,
                false,
                Some(false),
                false,
                true,
                false,
                false,
            ),
            (
                now_ns - UDP_CONN_STATE_TIMEOUT_NS - 1,
                false,
                Some(false),
                false,
                false,
                true,
                true,
            ),
            (0, false, Some(true), false, true, true, true),
            (0, false, None, false, true, true, true),
            (0, true, Some(false), false, true, false, true),
            (0, false, Some(false), true, true, true, true),
        ] {
            let claim = NativeClaim {
                epoch: 1,
                incarnation: 1,
                scope: 1,
                executor: NATIVE_EXECUTOR_KERNEL,
                state: NATIVE_PHASE_ACTIVE,
                last_seen_ns,
                ..Default::default()
            };
            publication.insert_claim_for_test(&key, &claim).unwrap();
            let turn = next;
            let epoch = publication.epoch_for_test();
            let attempts = publication.write_attempts_for_test();
            begin(&mut writer, &mut next, endpoint).unwrap();
            assert_eq!(writer.is_some(), closes);
            assert_eq!(publication.epoch_for_test(), epoch + u64::from(closes));
            if closes {
                assert_eq!(publication.claims().unwrap().len(), 1);
            }
            let mut called = false;
            finish_native_turn(
                &mut writer,
                &mut next,
                turn,
                false,
                || false,
                |cutoff| {
                    for (key, snapshot) in publication.claims()? {
                        assert!(snapshot.epoch < cutoff);
                        if !claim_retained(
                            &key,
                            &snapshot,
                            now_ns,
                            || endpoint,
                            || {
                                publication.query_claim(&key, &snapshot, || {
                                    called = true;
                                    owned.ok_or_else(|| io::ErrorKind::WouldBlock.into())
                                })
                            },
                        )? {
                            if late {
                                publication.insert_claim_for_test(
                                    &key,
                                    &NativeClaim {
                                        last_seen_ns: now_ns,
                                        ..snapshot
                                    },
                                )?;
                            }
                            publication.remove_claim(&key, &snapshot)?;
                        }
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert!(writer.is_none());
            assert_eq!(
                publication.epoch_for_test(),
                epoch + if closes { 2 } else { 0 },
            );
            assert_eq!(
                publication.write_attempts_for_test(),
                attempts + usize::from(closes),
            );
            assert_eq!(next, turn + Duration::from_secs(1));
            assert_eq!(called, queried);
            let current = publication.claim(&key).unwrap();
            assert_eq!(current.is_some(), retained);
            if late {
                assert_eq!(current.unwrap().last_seen_ns, now_ns);
            }
        }

        for (retained_before, retained_after) in [(true, true), (false, false), (false, true)] {
            let claim = NativeClaim {
                epoch: 1,
                incarnation: 1,
                scope: 1,
                executor: NATIVE_EXECUTOR_CAPTURE,
                state: NATIVE_PHASE_CAPTURE_COMMITTED,
                ..Default::default()
            };
            publication.insert_claim_for_test(&key, &claim).unwrap();
            let turn = next;
            let epoch = publication.epoch_for_test();
            let attempts = publication.write_attempts_for_test();
            begin(&mut writer, &mut next, retained_before).unwrap();
            assert_eq!(writer.is_some(), !retained_before);
            finish_native_turn(
                &mut writer,
                &mut next,
                turn,
                false,
                || false,
                |_| {
                    for (key, snapshot) in publication.claims()? {
                        if !claim_retained(
                            &key,
                            &snapshot,
                            now_ns,
                            || retained_after,
                            || panic!("Capture retirement cannot query kernel ownership"),
                        )? {
                            publication.remove_claim(&key, &snapshot)?;
                        }
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert!(writer.is_none());
            assert_eq!(publication.claim(&key).unwrap().is_some(), retained_after);
            assert_eq!(
                publication.epoch_for_test(),
                epoch + if retained_before { 0 } else { 2 },
            );
            assert_eq!(
                publication.write_attempts_for_test(),
                attempts + usize::from(!retained_before),
            );
        }

        let epoch = publication.epoch_for_test();
        assert!(
            publication
                .maintenance_needed(|_, _| {
                    publication.write(NativeReason::Policy).unwrap().commit();
                    false
                })
                .unwrap()
        );
        assert_eq!(publication.epoch_for_test(), epoch + 2);

        let retained_claim = NativeClaim {
            epoch: 1,
            incarnation: 1,
            scope: 1,
            executor: NATIVE_EXECUTOR_KERNEL,
            state: NATIVE_PHASE_ACTIVE,
            ..Default::default()
        };
        publication
            .insert_claim_for_test(&key, &retained_claim)
            .unwrap();
        for _ in 0..2 {
            let turn = next;
            begin(&mut writer, &mut next, false).unwrap();
            finish_native_turn(
                &mut writer,
                &mut next,
                turn,
                false,
                || false,
                |_| {
                    for (key, claim) in publication.claims()? {
                        if !claim_retained(
                            &key,
                            &claim,
                            now_ns,
                            || false,
                            || publication.query_claim(&key, &claim, || Ok(true)),
                        )? {
                            publication.remove_claim(&key, &claim)?;
                        }
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(publication.claim(&key).unwrap(), Some(retained_claim));
        }

        let snapshot = publication.claim(&key).unwrap().unwrap();
        let active = NativeClaim {
            last_seen_ns: now_ns + 1,
            ..snapshot
        };
        let turn = next;
        begin_native_turn(
            Some(&publication),
            &mut writer,
            false,
            &mut next,
            turn,
            |publication| {
                let needed = publication.maintenance_needed(|key, claim| {
                    claim_may_retire(key, claim, now_ns, || false)
                })?;
                assert!(needed);
                publication.insert_claim_for_test(&key, &active)?;
                Ok(needed)
            },
        )
        .unwrap();
        assert!(writer.is_some());
        assert_eq!(
            publication
                .query_claim(&key, &snapshot, || {
                    panic!("late activity must invalidate the query snapshot")
                })
                .unwrap(),
            None
        );
        publication.remove_claim(&key, &snapshot).unwrap();
        assert_eq!(publication.claim(&key).unwrap(), Some(active));
        finish_native_turn(
            &mut writer,
            &mut next,
            turn,
            false,
            || false,
            |_| {
                let claims = publication.claims()?;
                assert_eq!(claims.len(), 1);
                for (key, claim) in claims {
                    assert_eq!(claim, active);
                    if !claim_retained(
                        &key,
                        &claim,
                        now_ns,
                        || false,
                        || panic!("closed rescan must observe late activity before querying"),
                    )? {
                        publication.remove_claim(&key, &claim)?;
                    }
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(writer.is_none());
        assert_eq!(publication.claim(&key).unwrap(), Some(active));
        publication.quiesce(NativeReason::Shutdown).unwrap();
        publication.retire_closed_claims().unwrap();
        assert_eq!(publication.claim(&key).unwrap(), None);
    }

    #[test]
    fn ordinary_udp_retirement_requires_expiry_no_endpoint_and_absent_kernel_owner() {
        use honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS;

        let now = 10 * UDP_CONN_STATE_TIMEOUT_NS;
        let key = NativeKey {
            src_port: 45004u16.to_be(),
            dst_port: 18101u16.to_be(),
            l4proto: 17,
            ..Default::default()
        };
        for (last_seen, endpoint, owned, retained, queried, candidate) in [
            (now, false, Some(false), true, false, false),
            (now - 1, false, Some(false), true, false, false),
            (
                now - UDP_CONN_STATE_TIMEOUT_NS,
                false,
                Some(false),
                true,
                false,
                false,
            ),
            (now + 1, false, Some(false), true, false, false),
            (
                now - UDP_CONN_STATE_TIMEOUT_NS - 1,
                false,
                Some(false),
                false,
                true,
                true,
            ),
            (0, false, Some(true), true, true, true),
            (0, false, None, true, true, true),
            (0, true, Some(false), true, false, true),
        ] {
            let claim = NativeClaim {
                epoch: 1,
                incarnation: 1,
                scope: 1,
                executor: NATIVE_EXECUTOR_KERNEL,
                state: NATIVE_PHASE_ACTIVE,
                last_seen_ns: last_seen,
                ..Default::default()
            };
            assert_eq!(
                claim_may_retire(&key, &claim, now, || {
                    panic!("Kernel preflight must not query endpoint or kernel ownership")
                }),
                candidate,
                "last_seen={last_seen}",
            );
            let mut called = false;
            assert_eq!(
                claim_retained(
                    &key,
                    &claim,
                    now,
                    || endpoint,
                    || {
                        called = true;
                        Ok(owned)
                    }
                )
                .unwrap(),
                retained,
                "last_seen={last_seen}, endpoint={endpoint}, owned={owned:?}"
            );
            assert_eq!(called, queried);
        }
        let claim = NativeClaim {
            executor: NATIVE_EXECUTOR_KERNEL,
            state: NATIVE_PHASE_ACTIVE,
            last_seen_ns: 0,
            ..Default::default()
        };
        assert!(
            claim_retained(
                &key,
                &claim,
                now,
                || false,
                || { anyhow::bail!("claim map read failed") }
            )
            .is_err()
        );
    }

    #[test]
    fn nonordinary_kernel_claims_do_not_use_udp_idle() {
        let key = NativeKey {
            src_port: 45004u16.to_be(),
            dst_port: 18101u16.to_be(),
            l4proto: 17,
            ..Default::default()
        };
        let kernel = NativeClaim {
            executor: NATIVE_EXECUTOR_KERNEL,
            state: NATIVE_PHASE_ACTIVE,
            last_seen_ns: u64::MAX,
            ..Default::default()
        };
        for key in [
            NativeKey { l4proto: 6, ..key },
            NativeKey {
                src_port: 53u16.to_be(),
                ..key
            },
            NativeKey {
                dst_port: 53u16.to_be(),
                ..key
            },
        ] {
            assert!(claim_may_retire(&key, &kernel, 0, || {
                panic!("legacy Kernel preflight stays conservative")
            }));
            for owned in [Some(false), Some(true), None] {
                assert_eq!(
                    claim_retained(
                        &key,
                        &kernel,
                        0,
                        || { panic!("nonordinary Kernel retirement keeps its previous rule") },
                        || Ok(owned)
                    )
                    .unwrap(),
                    owned.is_none()
                );
            }
        }
        let ordinary = NativeKey {
            src_port: (53u16 << 8).to_be(),
            ..key
        };
        assert!(!claim_may_retire(&ordinary, &kernel, 0, || {
            panic!("wire ports must be converted before the DNS exclusion")
        }));
        assert!(
            claim_retained(
                &ordinary,
                &kernel,
                0,
                || false,
                || { panic!("wire ports must be converted before the DNS exclusion") }
            )
            .unwrap()
        );
    }

    #[test]
    fn unknown_executor_requires_closed_retirement() {
        assert!(claim_may_retire(
            &NativeKey::default(),
            &NativeClaim::default(),
            0,
            || panic!("invalid executor must reach the closed retirement error"),
        ));
    }

    #[test]
    fn final_withdrawal_visits_native_targets_even_without_runtime_active() {
        let targets = [("selected-data", false), ("selected-guard", true)];
        let mut visited = Vec::new();
        let result = super::withdraw_native_recording_targets(targets, |(target, active)| {
            visited.push((target, active));
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                target,
            ))
        });
        assert_eq!(visited, targets);
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("selected-data"));
        assert!(error.contains("selected-guard"));
    }

    #[test]
    fn maintenance_turn_records_real_close_and_reopen_without_policy_change() {
        use honk_ebpf_common::xdp::*;
        let publication =
            NativePublication::recording_for_test(MemoryBudget::new(2 << 20)).unwrap();
        publication.write(NativeReason::Startup).unwrap().commit();
        let before = publication.epoch_for_test();
        assert_eq!(before & 1, 1);
        let now = Instant::now();
        let mut next = now;
        let mut writer = None;
        begin_native_turn(
            Some(&publication),
            &mut writer,
            false,
            &mut next,
            now,
            |_| Ok(true),
        )
        .unwrap();
        let cutoff = writer.as_ref().unwrap().epoch();
        assert_eq!(cutoff, before + 1);
        assert_eq!(publication.epoch_for_test(), cutoff);
        finish_native_turn(
            &mut writer,
            &mut next,
            now,
            false,
            || false,
            |epoch| {
                assert_eq!(epoch, cutoff);
                assert_eq!(publication.claims()?.into_iter().count(), 0);
                Ok(())
            },
        )
        .unwrap();
        assert!(writer.is_none());
        assert_eq!(publication.epoch_for_test(), cutoff + 1);
        assert_eq!(next, now + Duration::from_secs(1));
        let events = publication.recording_events_for_test();
        let maintenance: Vec<_> = events
            .iter()
            .filter(|event| event.reason == NativeReason::RuntimeMaintenance as u32)
            .collect();
        let begin = maintenance
            .iter()
            .find(|event| event.kind == NATIVE_EVENT_WRITER_BEGIN)
            .unwrap();
        let outcome = maintenance
            .iter()
            .find(|event| event.kind == NATIVE_EVENT_WRITER_OUTCOME)
            .unwrap();
        let closed = maintenance
            .iter()
            .find(|event| event.kind == NATIVE_EVENT_CLOSE_STORED)
            .unwrap();
        let drained = maintenance
            .iter()
            .find(|event| event.kind == NATIVE_EVENT_CLOSE_DRAINED)
            .unwrap();
        let reopened = maintenance
            .iter()
            .find(|event| event.kind == NATIVE_EVENT_REOPEN_STORED)
            .unwrap();
        assert_eq!(begin.writer_id, outcome.writer_id);
        assert_eq!(begin.operation_id, outcome.operation_id);
        assert_eq!(outcome.outcome, NATIVE_OUTCOME_COMMITTED);
        assert!(begin.writer_id != 0 && begin.operation_id != 0);
        assert!(begin.seq < closed.seq && closed.seq < drained.seq && drained.seq < reopened.seq);
        assert_eq!(
            (reopened.epoch_before, reopened.epoch_after),
            (cutoff, cutoff + 1)
        );
    }

    #[test]
    fn maintenance_turn_retains_actual_writer_until_cut_short_and_rx_cq_work_drains() {
        use honk_ebpf_common::xdp::*;
        for (cut_short, rx_pending, cq_pending) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let publication =
                NativePublication::recording_for_test(MemoryBudget::new(2 << 20)).unwrap();
            publication.write(NativeReason::Startup).unwrap().commit();
            let now = Instant::now();
            let mut next = now;
            let mut writer = None;
            begin_native_turn(
                Some(&publication),
                &mut writer,
                false,
                &mut next,
                now,
                |_| Ok(true),
            )
            .unwrap();
            let cutoff = writer.as_ref().unwrap().epoch();
            let before_events = publication.recording_events_for_test().len();
            begin_native_turn(
                Some(&publication),
                &mut writer,
                false,
                &mut next,
                now,
                |_| panic!("a held writer must finish without another preflight"),
            )
            .unwrap();
            assert_eq!(publication.recording_events_for_test().len(), before_events);
            finish_native_turn(
                &mut writer,
                &mut next,
                now,
                cut_short,
                || rx_pending || cq_pending,
                |_| panic!("pending maintenance cannot retire claims"),
            )
            .unwrap();
            assert!(writer.is_some());
            assert_eq!(publication.epoch_for_test(), cutoff);
            assert_eq!(next, now);
            assert!(
                !publication
                    .recording_events_for_test()
                    .iter()
                    .any(
                        |event| event.reason == NativeReason::RuntimeMaintenance as u32
                            && event.kind == NATIVE_EVENT_WRITER_OUTCOME
                    )
            );
            finish_native_turn(&mut writer, &mut next, now, false, || false, |_| Ok(())).unwrap();
            assert!(writer.is_none());
            assert_eq!(publication.epoch_for_test(), cutoff + 1);
            assert!(
                publication
                    .recording_events_for_test()
                    .iter()
                    .any(
                        |event| event.reason == NativeReason::RuntimeMaintenance as u32
                            && event.kind == NATIVE_EVENT_WRITER_OUTCOME
                            && event.outcome == NATIVE_OUTCOME_COMMITTED
                    )
            );
        }
    }

    #[test]
    fn maintenance_turn_does_not_reopen_after_claim_retirement_failure() {
        use honk_ebpf_common::xdp::*;
        let publication =
            NativePublication::recording_for_test(MemoryBudget::new(2 << 20)).unwrap();
        publication.write(NativeReason::Startup).unwrap().commit();
        let now = Instant::now();
        let mut next = now;
        let mut writer = None;
        begin_native_turn(
            Some(&publication),
            &mut writer,
            false,
            &mut next,
            now,
            |_| Ok(true),
        )
        .unwrap();
        let cutoff = writer.as_ref().unwrap().epoch();
        let error = finish_native_turn(
            &mut writer,
            &mut next,
            now,
            false,
            || false,
            |_| anyhow::bail!("injected claim retirement failure"),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "injected claim retirement failure");
        assert_eq!(publication.epoch_for_test(), cutoff);
        assert_eq!(next, now);
        drop(writer);
        assert!(
            publication
                .recording_events_for_test()
                .iter()
                .any(
                    |event| event.reason == NativeReason::RuntimeMaintenance as u32
                        && event.kind == NATIVE_EVENT_WRITER_OUTCOME
                        && event.outcome == NATIVE_OUTCOME_FAILED
                )
        );
    }

    use super::*;

    #[test]
    fn owner_key_keeps_mapped_address_and_wire_port() {
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let words = crate::ebpf::maps::ip_addr_to_lpm_key(ip).data;
        assert_eq!(address(words, 5353u16.to_be()), SocketAddr::new(ip, 5353));
    }

    #[test]
    fn retained_shutdown_exports_partial_with_original_error_at_each_named_stage() {
        for stage in [
            "terminal_io_join",
            "transmit_drain",
            "native_original_rx_drain",
        ] {
            let publication =
                NativePublication::recording_for_test(MemoryBudget::new(2 << 20)).unwrap();
            let directory = tempfile::tempdir().unwrap();
            let path = publication.initialize_export(directory.path()).unwrap();
            publication.quiesce(NativeReason::Shutdown).unwrap();
            let mut failure = Some(anyhow::anyhow!("original {stage} failure"));
            export_native_recording(Some(&publication), false, false, stage, &mut failure);
            assert_eq!(
                failure.unwrap().to_string(),
                format!("original {stage} failure")
            );
            let artifact: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(artifact["final"], false);
            assert_eq!(artifact["complete"], false);
            assert_eq!(artifact["hooks_joined"], false);
        }
    }

    #[test]
    fn retained_shutdown_export_fault_preserves_original_error_and_reports_both() {
        let publication =
            NativePublication::recording_for_test(MemoryBudget::new(2 << 20)).unwrap();
        let mut failure = Some(anyhow::anyhow!("original terminal I/O failure"));
        export_native_recording(
            Some(&publication),
            false,
            false,
            "terminal_io_join",
            &mut failure,
        );
        let error = failure.unwrap();
        assert!(format!("{error:#}").contains("Native publication export also failed"));
        assert!(format!("{error:#}").contains("Native export not initialized"));
        assert_eq!(
            error.root_cause().to_string(),
            "original terminal I/O failure"
        );
    }
}
