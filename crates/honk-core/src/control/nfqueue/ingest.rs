use super::*;

impl PendingUdpVerdicts {
    pub(in crate::control) async fn ingest_wait(
        &self,
        packet: QueuedPacket,
        guard: VerdictGuard,
        slow_permit: Option<OwnedSemaphorePermit>,
    ) -> NfqueueIngest {
        let received_at = packet.received_at;
        self.ingest_held_wait(packet, HeldVerdict::kernel(guard, received_at), slow_permit)
            .await
    }

    pub(super) async fn ingest_held_wait(
        &self,
        packet: QueuedPacket,
        held: HeldVerdict,
        slow_permit: Option<OwnedSemaphorePermit>,
    ) -> NfqueueIngest {
        self.stats.record_udp_nfqueue_received();
        let Some(decision_token) = extract_nfqueue_token(packet.mark) else {
            self.drop_one(held, DropOutcome::Other);
            return NfqueueIngest::Dropped;
        };
        let key = FlowKey::new(packet.tuple.client, packet.tuple.destination);
        let Some(_admission) = self.admission.try_enter() else {
            self.schedule_cleanup_for_key(key, decision_token);
            self.drop_one(held, DropOutcome::Cancel);
            return NfqueueIngest::Dropped;
        };
        if let Some(dashmap::mapref::entry::Entry::Occupied(occupied)) = self.cells.try_entry(key) {
            let cell = Arc::clone(occupied.get());
            if !terminal_cell_is_stale(&cell, decision_token, Instant::now()) {
                drop(occupied);
                return self.ingest_existing(
                    cell,
                    decision_token,
                    packet.payload,
                    held,
                    slow_permit,
                );
            }
        }

        let deadline = tokio::time::Instant::from_std(packet.received_at + HARD_HOLD_TIMEOUT);
        let backend = match tokio::time::timeout_at(deadline, self.ebpf.read()).await {
            Ok(backend) => backend,
            Err(_) => {
                self.reject_before_backend(&packet, held, DropOutcome::Cancel);
                return NfqueueIngest::Dropped;
            }
        };
        self.ingest_admitted_with_backend(
            packet,
            held,
            slow_permit,
            backend.as_ref(),
            key,
            decision_token,
        )
    }

    pub(in crate::control) fn reject_actor_queue(&self, packet: QueuedPacket, guard: VerdictGuard) {
        self.stats.record_udp_nfqueue_received();
        self.stats.record_udp_nfqueue_actor_queue_full();
        let received_at = packet.received_at;
        self.reject_before_backend(
            &packet,
            HeldVerdict::kernel(guard, received_at),
            DropOutcome::Other,
        );
    }

    fn reject_before_backend(
        &self,
        packet: &QueuedPacket,
        held: HeldVerdict,
        outcome: DropOutcome,
    ) {
        if let Some(decision_token) = extract_nfqueue_token(packet.mark) {
            self.schedule_cleanup_for_key(
                FlowKey::new(packet.tuple.client, packet.tuple.destination),
                decision_token,
            );
        }
        self.drop_one(held, outcome);
    }

    fn ingest_admitted_with_backend(
        &self,
        packet: QueuedPacket,
        held: HeldVerdict,
        slow_permit: Option<OwnedSemaphorePermit>,
        backend: &dyn EbpfBackend,
        key: FlowKey,
        decision_token: u32,
    ) -> NfqueueIngest {
        loop {
            let Some(entry) = self.cells.try_entry(key) else {
                self.schedule_cleanup(CleanupRequest::Token {
                    key,
                    decision_token,
                });
                drop(packet.payload);
                drop(slow_permit);
                self.drop_one(held, DropOutcome::Other);
                return NfqueueIngest::Dropped;
            };
            match entry {
                dashmap::mapref::entry::Entry::Occupied(occupied) => {
                    let cell = Arc::clone(occupied.get());
                    let stale = terminal_cell_is_stale(&cell, decision_token, Instant::now());
                    if stale {
                        occupied.remove();
                        self.stats.decrement_udp_nfqueue_active_flows();
                        self.notify_empty_if_needed();
                        continue;
                    }
                    drop(occupied);
                    return self.ingest_existing(
                        cell,
                        decision_token,
                        packet.payload,
                        held,
                        slow_permit,
                    );
                }
                dashmap::mapref::entry::Entry::Vacant(vacant) => {
                    return self.ingest_vacant(
                        vacant,
                        decision_token,
                        packet.payload,
                        held,
                        slow_permit,
                        backend,
                    );
                }
            }
        }
    }

    pub(super) fn ingest_existing(
        &self,
        cell: Arc<FlowCell>,
        decision_token: u32,
        payload: bytes::Bytes,
        held: HeldVerdict,
        slow_permit: Option<OwnedSemaphorePermit>,
    ) -> NfqueueIngest {
        if cell.identity.decision_token != decision_token {
            self.stats.record_udp_nfqueue_token_mismatch();
            self.schedule_cleanup(CleanupRequest::Token {
                key: cell.identity.key,
                decision_token,
            });
            self.drop_one(held, DropOutcome::Other);
            return NfqueueIngest::Dropped;
        }

        let mut state = cell.state.lock();
        match &mut *state {
            CellState::Pending {
                started_at,
                armed,
                cancelling,
                verdicts,
            } => {
                if verdicts.len() >= MAX_HELD_VERDICTS_PER_FLOW {
                    drop(state);
                    self.stats.record_udp_nfqueue_correlator_full();
                    self.drop_one(held, DropOutcome::Other);
                    return NfqueueIngest::Dropped;
                }
                if *armed {
                    verdicts.push_back(held);
                    drop(state);
                    drop(payload);
                    drop(slow_permit);
                    cell.changed.notify_waiters();
                    return NfqueueIngest::Queued;
                }
                if *cancelling {
                    drop(state);
                    self.drop_one(held, DropOutcome::Cancel);
                    return NfqueueIngest::Dropped;
                }
                if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                    *cancelling = true;
                    let mut stale = std::mem::take(verdicts);
                    drop(state);
                    self.schedule_cleanup(CleanupRequest::Flow(cell.identity));
                    stale.push_back(held);
                    self.drop_many(stale, DropOutcome::Cancel);
                    cell.changed.notify_waiters();
                    return NfqueueIngest::Dropped;
                }
                let Some(slow_permit) = slow_permit else {
                    drop(state);
                    self.drop_one(held, DropOutcome::Cancel);
                    return NfqueueIngest::Dropped;
                };
                let result = self.endpoints.reserve_owned_or_enqueue_at(
                    cell.identity.client(),
                    cell.identity.destination(),
                    payload,
                    decision_token,
                    Some(cell.identity.endpoint_generation),
                    slow_permit,
                    held.received_at,
                    &self.stats,
                );
                match result {
                    EndpointReservation::Enqueued => {
                        verdicts.push_back(held);
                        NfqueueIngest::Queued
                    }
                    EndpointReservation::Initializing(_) => {
                        unreachable!("an exact-generation follower cannot create an initializer")
                    }
                    EndpointReservation::IdentityMismatch => {
                        *cancelling = true;
                        drop(state);
                        self.stats.record_udp_nfqueue_token_mismatch();
                        self.schedule_cleanup(CleanupRequest::Flow(cell.identity));
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                    EndpointReservation::CapacityRejected
                    | EndpointReservation::QueueFull
                    | EndpointReservation::QueueClosed => {
                        drop(state);
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                }
            }
            CellState::ActiveDirect { final_mark, .. } => {
                let final_mark = *final_mark;
                drop(state);
                drop(payload);
                drop(slow_permit);
                self.accept_one(held, final_mark);
                NfqueueIngest::Queued
            }
            CellState::Proxy { .. } => {
                let Some(slow_permit) = slow_permit else {
                    drop(state);
                    drop(payload);
                    self.drop_one(held, DropOutcome::Other);
                    return NfqueueIngest::Dropped;
                };
                let result = self.endpoints.reserve_owned_or_enqueue_at(
                    cell.identity.client(),
                    cell.identity.destination(),
                    payload,
                    decision_token,
                    Some(cell.identity.endpoint_generation),
                    slow_permit,
                    held.received_at,
                    &self.stats,
                );
                drop(state);
                match result {
                    EndpointReservation::Enqueued => {
                        self.drop_one(held, DropOutcome::Proxy);
                        NfqueueIngest::Queued
                    }
                    EndpointReservation::IdentityMismatch => {
                        self.stats.record_udp_nfqueue_token_mismatch();
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                    EndpointReservation::Initializing(_) => {
                        unreachable!("an exact-generation proxy follower cannot initialize")
                    }
                    EndpointReservation::CapacityRejected
                    | EndpointReservation::QueueFull
                    | EndpointReservation::QueueClosed => {
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                }
            }
            CellState::Block { .. } => {
                drop(state);
                drop(payload);
                drop(slow_permit);
                self.drop_one(held, DropOutcome::Block);
                NfqueueIngest::Queued
            }
            CellState::Dead { .. } => {
                drop(state);
                drop(payload);
                drop(slow_permit);
                self.drop_one(held, DropOutcome::Cancel);
                NfqueueIngest::Dropped
            }
        }
    }

    fn ingest_vacant(
        &self,
        vacant: dashmap::mapref::entry::VacantEntry<'_, FlowKey, Arc<FlowCell>>,
        decision_token: u32,
        payload: bytes::Bytes,
        held: HeldVerdict,
        slow_permit: Option<OwnedSemaphorePermit>,
        backend: &dyn EbpfBackend,
    ) -> NfqueueIngest {
        let key = *vacant.key();
        let Ok(flow_slot) = Arc::clone(&self.flow_slots).try_acquire_owned() else {
            drop(vacant);
            self.stats.record_udp_nfqueue_correlator_full();
            self.schedule_cleanup(CleanupRequest::Token {
                key,
                decision_token,
            });
            drop(payload);
            drop(slow_permit);
            self.drop_one(held, DropOutcome::Other);
            return NfqueueIngest::Dropped;
        };
        let retained = match backend.udp_conn_state_lookup(&key.tuples()) {
            Ok(Some(state)) if state.decision_token == decision_token => retained_state(&state),
            Ok(Some(_)) | Ok(None) => {
                drop(vacant);
                self.stats.record_udp_nfqueue_token_mismatch();
                self.drop_one(held, DropOutcome::Other);
                return NfqueueIngest::Dropped;
            }
            Err(error) => {
                drop(vacant);
                self.schedule_cleanup(CleanupRequest::Token {
                    key,
                    decision_token,
                });
                self.signal_fatal(PendingUdpFatal::new("state inspection", error.to_string()));
                self.drop_one(held, DropOutcome::Other);
                return NfqueueIngest::Dropped;
            }
        };

        match retained {
            RetainedState::Pending => {
                let Some(slow_permit) = slow_permit else {
                    self.insert_dead_vacant(vacant, key, decision_token, flow_slot);
                    self.schedule_cleanup(CleanupRequest::Token {
                        key,
                        decision_token,
                    });
                    self.drop_one(held, DropOutcome::Cancel);
                    return NfqueueIngest::Dropped;
                };
                match self.endpoints.reserve_owned_or_enqueue_at(
                    key.client,
                    key.destination,
                    payload,
                    decision_token,
                    None,
                    slow_permit,
                    held.received_at,
                    &self.stats,
                ) {
                    EndpointReservation::Initializing(lease) => {
                        let identity = Self::identity_for_lease(&lease);
                        let cell = Arc::new(FlowCell::pending(
                            identity,
                            held.received_at,
                            held,
                            flow_slot,
                        ));
                        vacant.insert(cell);
                        self.stats.increment_udp_nfqueue_active_flows();
                        NfqueueIngest::Initialize { lease, identity }
                    }
                    EndpointReservation::IdentityMismatch => {
                        self.insert_dead_vacant(vacant, key, decision_token, flow_slot);
                        self.stats.record_udp_nfqueue_token_mismatch();
                        self.schedule_cleanup(CleanupRequest::Token {
                            key,
                            decision_token,
                        });
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                    EndpointReservation::Enqueued => {
                        self.insert_dead_vacant(vacant, key, decision_token, flow_slot);
                        self.schedule_cleanup(CleanupRequest::Token {
                            key,
                            decision_token,
                        });
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                    EndpointReservation::CapacityRejected
                    | EndpointReservation::QueueFull
                    | EndpointReservation::QueueClosed => {
                        self.insert_dead_vacant(vacant, key, decision_token, flow_slot);
                        self.schedule_cleanup(CleanupRequest::Token {
                            key,
                            decision_token,
                        });
                        self.drop_one(held, DropOutcome::Cancel);
                        NfqueueIngest::Dropped
                    }
                }
            }
            RetainedState::ActiveDirect(final_mark) => {
                drop(payload);
                drop(slow_permit);
                let identity = PendingUdpIdentity::new(key, decision_token, 0);
                vacant.insert(Arc::new(FlowCell::terminal(
                    identity,
                    CellState::ActiveDirect {
                        expires_at: Instant::now() + TERMINAL_GRACE,
                        final_mark,
                    },
                    flow_slot,
                )));
                self.stats.increment_udp_nfqueue_active_flows();
                self.accept_one(held, final_mark);
                NfqueueIngest::Queued
            }
            RetainedState::Proxy => {
                drop(slow_permit);
                match self.endpoints.enqueue_owned_by_token_at(
                    key.client,
                    key.destination,
                    payload,
                    decision_token,
                    held.received_at,
                    &self.stats,
                ) {
                    Ok(generation) => {
                        let identity = PendingUdpIdentity::new(key, decision_token, generation);
                        vacant.insert(Arc::new(FlowCell::terminal(
                            identity,
                            CellState::Proxy {
                                expires_at: Instant::now() + TERMINAL_GRACE,
                            },
                            flow_slot,
                        )));
                        self.stats.increment_udp_nfqueue_active_flows();
                        self.drop_one(held, DropOutcome::Proxy);
                        NfqueueIngest::Queued
                    }
                    Err(OwnedEnqueueError::IdentityMismatch) => {
                        drop(vacant);
                        self.stats.record_udp_nfqueue_token_mismatch();
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                    Err(OwnedEnqueueError::QueueFull | OwnedEnqueueError::QueueClosed) => {
                        drop(vacant);
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                }
            }
            RetainedState::Block => {
                drop(payload);
                drop(slow_permit);
                let identity = PendingUdpIdentity::new(key, decision_token, 0);
                vacant.insert(Arc::new(FlowCell::terminal(
                    identity,
                    CellState::Block {
                        expires_at: Instant::now() + TERMINAL_GRACE,
                    },
                    flow_slot,
                )));
                self.stats.increment_udp_nfqueue_active_flows();
                self.drop_one(held, DropOutcome::Block);
                NfqueueIngest::Queued
            }
            RetainedState::DirectArmed => {
                drop(payload);
                drop(slow_permit);
                drop(vacant);
                self.signal_fatal(PendingUdpFatal::new(
                    "armed reconstruction",
                    "DirectArmed state has no live correlator",
                ));
                self.drop_one(held, DropOutcome::Other);
                NfqueueIngest::Dropped
            }
            RetainedState::Reject => {
                drop(payload);
                drop(slow_permit);
                drop(vacant);
                self.stats.record_udp_nfqueue_token_mismatch();
                self.drop_one(held, DropOutcome::Other);
                NfqueueIngest::Dropped
            }
        }
    }
}

pub(super) fn retained_state(state: &honk_ebpf_common::ConnState) -> RetainedState {
    match state.state {
        value if value == UdpDecisionState::Pending as u8 => RetainedState::Pending,
        value if value == UdpDecisionState::DirectArmed as u8 => RetainedState::DirectArmed,
        value if value == UdpDecisionState::Proxy as u8 => RetainedState::Proxy,
        value if value == UdpDecisionState::Block as u8 => RetainedState::Block,
        value if value == UdpDecisionState::None as u8 => {
            let raw = unsafe { state.meta.raw };
            let outbound = raw as u8;
            let direct_rule_mark = (raw >> 8) as u32;
            if outbound == OutboundIndex::Direct as u8
                && raw & (ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD)
                    == ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD
                && !skb_mark_has_reserved_bits(direct_rule_mark)
            {
                RetainedState::ActiveDirect(direct_rule_mark | CLASSIFIED_MARK)
            } else {
                RetainedState::Reject
            }
        }
        _ => RetainedState::Reject,
    }
}
