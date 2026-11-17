use super::*;
use crate::ebpf::native::{ImportedOriginal, NativePublication};
use honk_ebpf_common::xdp::NATIVE_METADATA_LEN;

pub(in crate::xdp) enum Phase {
    Held,
    Flight,
    Release,
    Released(honk_xsk::RxCompletion),
    Complete(honk_xsk::RxCompletion),
    Ack,
    EndpointDone(Cell, PacketReceive),
    Working,
}

pub(in crate::xdp) struct OriginalPort {
    device: usize,
    queue: u32,
    handle: honk_xsk::RetainedRxHandle,
    identity: Option<crate::ebpf::native::NativeClaimIdentity>,
    pub(in crate::xdp) phase: Phase,
}

pub(in crate::xdp) struct Slots {
    pub(in crate::xdp) publication: Mutex<Option<Arc<NativePublication>>>,
    pub(in crate::xdp) ports: [Mutex<Option<OriginalPort>>; CELLS],
}

impl Slots {
    pub(super) fn new() -> Self {
        Self {
            publication: Mutex::new(None),
            ports: std::array::from_fn(|_| Mutex::new(None)),
        }
    }

    pub(in crate::xdp) fn service_port(
        &self,
        shared: &Shared,
        device: usize,
        queue: u32,
        port: &mut Port<Retained>,
    ) -> io::Result<bool> {
        let mut progress = false;
        for slot in &self.ports {
            let action = {
                let mut slot = slot.lock();
                let Some(original) = slot
                    .as_mut()
                    .filter(|original| original.device == device && original.queue == queue)
                else {
                    continue;
                };
                match original.phase {
                    Phase::Release | Phase::Complete(_) => Some((
                        original.handle,
                        std::mem::replace(&mut original.phase, Phase::Working),
                    )),
                    _ => None,
                }
            };
            let Some((handle, action)) = action else {
                continue;
            };
            let phase = match action {
                Phase::Release => Phase::Released(port.release_retained_rx(handle)?),
                Phase::Complete(completion) => {
                    port.complete_retained_rx(completion)?;
                    Phase::Ack
                }
                _ => unreachable!(),
            };
            slot.lock()
                .as_mut()
                .expect("exact retained Port slot")
                .phase = phase;
            shared.wakers[0].wake();
            shared.wake[0].notify_one();
            progress = true;
        }
        Ok(progress)
    }

    pub(in crate::xdp) fn add_inventory(
        &self,
        identity: crate::ebpf::native::NativeClaimIdentity,
        exclude: Option<usize>,
        inventory: &mut crate::ebpf::native::OriginalInventory,
    ) {
        for (index, slot) in self.ports.iter().enumerate() {
            if exclude == Some(index) {
                continue;
            }
            let slot = slot.lock();
            let Some(original) = slot
                .as_ref()
                .filter(|original| original.identity == Some(identity))
            else {
                continue;
            };
            match original.phase {
                Phase::Held => inventory.held += 1,
                Phase::Flight => {
                    inventory.held += 1;
                    inventory.flight = true;
                }
                _ => inventory.pending += 1,
            }
        }
    }

    pub(in crate::xdp) fn is_empty(&self) -> bool {
        self.ports.iter().all(|slot| slot.lock().is_none())
    }
}

pub(in crate::xdp) fn receive_remote_originals(
    shared: &Arc<Shared>,
    device: usize,
    capture: &GeneralCapture,
    queue: u32,
    port: &mut Port<Retained>,
    now: Instant,
) -> anyhow::Result<usize> {
    let publication = shared
        .native
        .publication
        .lock()
        .clone()
        .context("remote Native publication absent")?;
    let mut received = 0;
    for _ in 0..BATCH {
        let Some(cell) = shared.pool.take() else {
            break;
        };
        let mut cell = Some(cell);
        let Ok(permit) = shared.senders[0].try_reserve() else {
            break;
        };
        let mut failure = None;
        let mut envelope = None;
        let count =
            port.receive_segments_owned(1, NATIVE_METADATA_LEN, |handle, segments, metadata, _| {
                let mut cell = cell.take().expect("one RX callback per reserved cell");
                cell.retained = true;
                *shared.native.ports[cell.slot].lock() = Some(OriginalPort {
                    device,
                    queue,
                    handle,
                    identity: None,
                    phase: Phase::Held,
                });
                let result = (|| -> anyhow::Result<Envelope> {
                    cell.copy(segments, metadata)?;
                    let decoded = capture
                        .decode(
                            segments,
                            if capture.vlan_metadata {
                                &metadata[..METADATA_LEN]
                            } else {
                                &[]
                            },
                            queue,
                        )
                        .map_err(|_| io::Error::other("remote Native envelope"))?;
                    let placement = shared
                        .placements
                        .lock()
                        .iter()
                        .find(|placement| {
                            placement.device == device
                                && placement.link.mac == decoded.destination_mac
                                && decoded.destination_mac[0] & 1 == 0
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
                        .cloned()
                        .context("remote Native realm")?;
                    let mut l3 = [&[][..]; 18];
                    let count =
                        l3_segments(segments, decoded, &mut l3).context("remote Native SG")?;
                    let view = PacketView::new(&l3[..count]).map_err(io::Error::other)?;
                    let imported = crate::xdp::native::imported(
                        &publication,
                        placement.realm.scope(),
                        capture.authority,
                        view,
                        metadata,
                    )?;
                    shared.native.ports[cell.slot]
                        .lock()
                        .as_mut()
                        .unwrap()
                        .identity = Some(imported.identity);
                    publication.record_imported(imported.identity, imported.producer, handle);
                    Ok(Envelope {
                        device,
                        queue,
                        ingress: placement.ingress,
                        scope: placement.realm.scope(),
                        path: ReturnPath {
                            device,
                            mac: decoded.source_mac,
                            vlan_tci: decoded.vlan_tci,
                            vlan_proto: decoded.vlan_proto,
                            vlan_count: decoded.vlan_count,
                        },
                        ingress_at: now,
                        cell,
                        body: None,
                        peer: None,
                        l3_offset: decoded.l3_offset,
                        l3_length: decoded.l3_len,
                        payload: Payload::Original { handle, imported },
                    })
                })();
                match result {
                    Ok(value) => envelope = Some(value),
                    Err(error) => {
                        failure = Some(error);
                    }
                }
                honk_xsk::RxDisposition::Retain
            });
        publication.finish_import_turn()?;
        received += count?;
        if let Some(error) = failure {
            return Err(error);
        }
        if let Some(envelope) = envelope {
            permit.send(envelope);
            shared.wakers[0].wake();
        } else {
            break;
        }
    }
    Ok(received)
}

pub(in crate::xdp) struct RemoteOriginal {
    pub(in crate::xdp) envelope: Envelope,
    pub(in crate::xdp) imported: ImportedOriginal,
    pub(in crate::xdp) stage: Stage,
    pub(in crate::xdp) proof: Option<crate::xdp::native::OriginalProof>,
    pub(in crate::xdp) completion: Option<crate::ebpf::native::OriginalCompletion>,
    pub(in crate::xdp) taken_over: bool,
}

pub(in crate::xdp) enum Stage {
    Payload,
    Endpoint,
    Flight,
    Releasing,
    Completing,
    Acknowledging,
}

impl RemoteOriginal {
    pub(in crate::xdp) fn new(envelope: Envelope) -> Self {
        let Payload::Original { imported, .. } = envelope.payload else {
            unreachable!()
        };
        Self {
            envelope,
            imported,
            stage: Stage::Payload,
            proof: None,
            completion: None,
            taken_over: false,
        }
    }
    pub(in crate::xdp) fn slot(&self) -> usize {
        self.envelope.cell.slot
    }
    pub(in crate::xdp) fn handle(&self) -> honk_xsk::RetainedRxHandle {
        let Payload::Original { handle, .. } = self.envelope.payload else {
            unreachable!()
        };
        handle
    }
    pub(in crate::xdp) fn acknowledge(&mut self) {
        self.envelope.cell.retained = false;
    }
}
