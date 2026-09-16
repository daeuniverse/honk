use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct FlowKey {
    pub(super) client: SocketAddr,
    pub(super) destination: SocketAddr,
}

impl FlowKey {
    pub(super) const fn new(client: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            client,
            destination,
        }
    }

    pub(super) fn tuples(self) -> TuplesKey {
        build_tuples_key(
            self.destination.ip(),
            self.destination.port(),
            self.client.ip(),
            self.client.port(),
            IPPROTO_UDP,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(in crate::control) struct PendingUdpIdentity {
    pub(super) key: FlowKey,
    pub(super) decision_token: u32,
    pub(super) endpoint_generation: u64,
}

impl PendingUdpIdentity {
    pub(super) fn new(key: FlowKey, decision_token: u32, endpoint_generation: u64) -> Self {
        Self {
            key,
            decision_token,
            endpoint_generation,
        }
    }

    pub(in crate::control) const fn client(self) -> SocketAddr {
        self.key.client
    }

    pub(in crate::control) const fn destination(self) -> SocketAddr {
        self.key.destination
    }

    pub(super) fn tuples(self) -> TuplesKey {
        self.key.tuples()
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::control) enum TestVerdict {
    Accept { id: u64, mark: u32 },
    Drop { id: u64 },
}

pub(super) enum StoredVerdictGuard {
    Kernel(VerdictGuard),
    #[cfg(test)]
    Test {
        id: u64,
        sink: Arc<Mutex<Vec<TestVerdict>>>,
    },
    #[cfg(test)]
    Failure,
}

impl StoredVerdictGuard {
    pub(super) fn accept(&mut self, mark: u32) -> Result<(), String> {
        match self {
            Self::Kernel(guard) => guard.accept(mark).map_err(|error| error.to_string()),
            #[cfg(test)]
            Self::Test { id, sink } => {
                sink.lock().push(TestVerdict::Accept { id: *id, mark });
                Ok(())
            }
            #[cfg(test)]
            Self::Failure => Err("injected verdict failure".into()),
        }
    }

    pub(super) fn drop_packet(&mut self) -> Result<(), String> {
        match self {
            Self::Kernel(guard) => guard.drop_packet().map_err(|error| error.to_string()),
            #[cfg(test)]
            Self::Test { id, sink } => {
                sink.lock().push(TestVerdict::Drop { id: *id });
                Ok(())
            }
            #[cfg(test)]
            Self::Failure => Err("injected verdict failure".into()),
        }
    }
}

pub(in crate::control) struct HeldVerdict {
    pub(super) guard: StoredVerdictGuard,
    pub(super) received_at: Instant,
}

impl HeldVerdict {
    pub(super) fn kernel(guard: VerdictGuard, received_at: Instant) -> Self {
        Self {
            guard: StoredVerdictGuard::Kernel(guard),
            received_at,
        }
    }

    #[cfg(test)]
    pub(in crate::control) fn test(
        id: u64,
        received_at: Instant,
        sink: Arc<Mutex<Vec<TestVerdict>>>,
    ) -> Self {
        Self {
            guard: StoredVerdictGuard::Test { id, sink },
            received_at,
        }
    }

    #[cfg(test)]
    pub(in crate::control) fn failure(received_at: Instant) -> Self {
        Self {
            guard: StoredVerdictGuard::Failure,
            received_at,
        }
    }
}

pub(super) enum CellState {
    Pending {
        started_at: Instant,
        armed: bool,
        cancelling: bool,
        verdicts: VecDeque<HeldVerdict>,
    },
    ActiveDirect {
        expires_at: Instant,
        final_mark: u32,
    },
    Proxy {
        expires_at: Instant,
    },
    Block {
        expires_at: Instant,
    },
    Dead {
        expires_at: Instant,
    },
}

impl CellState {
    pub(super) fn terminal_expiry(&self) -> Option<Instant> {
        match self {
            Self::Pending { .. } => None,
            Self::ActiveDirect { expires_at, .. }
            | Self::Proxy { expires_at }
            | Self::Block { expires_at }
            | Self::Dead { expires_at } => Some(*expires_at),
        }
    }
}

pub(super) struct FlowCell {
    pub(super) identity: PendingUdpIdentity,
    pub(super) _flow_slot: OwnedSemaphorePermit,
    pub(super) state: Mutex<CellState>,
    pub(super) changed: Notify,
}

impl FlowCell {
    pub(super) fn pending(
        identity: PendingUdpIdentity,
        started_at: Instant,
        verdict: HeldVerdict,
        flow_slot: OwnedSemaphorePermit,
    ) -> Self {
        let mut verdicts = VecDeque::with_capacity(1);
        verdicts.push_back(verdict);
        Self {
            _flow_slot: flow_slot,
            identity,
            state: Mutex::new(CellState::Pending {
                started_at,
                armed: false,
                cancelling: false,
                verdicts,
            }),
            changed: Notify::new(),
        }
    }

    pub(super) fn terminal(
        identity: PendingUdpIdentity,
        state: CellState,
        flow_slot: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            _flow_slot: flow_slot,
            identity,
            state: Mutex::new(state),
            changed: Notify::new(),
        }
    }
}

pub(super) fn terminal_cell_is_stale(cell: &FlowCell, decision_token: u32, now: Instant) -> bool {
    cell.state
        .lock()
        .terminal_expiry()
        .is_some_and(|expiry| expiry <= now || cell.identity.decision_token != decision_token)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum CleanupRequest {
    Flow(PendingUdpIdentity),
    Token { key: FlowKey, decision_token: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RetainedState {
    Pending,
    ActiveDirect(u32),
    Proxy,
    Block,
    DirectArmed,
    Reject,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum DropOutcome {
    Proxy,
    Block,
    Cancel,
    Other,
}

#[derive(Debug)]
pub(super) struct AdmissionState {
    pub(super) open: bool,
    pub(super) epoch: u64,
    pub(super) in_flight: usize,
}

#[derive(Debug)]
pub(super) struct AdmissionGate {
    pub(super) state: Mutex<AdmissionState>,
    quiesced: Notify,
}

impl AdmissionGate {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(AdmissionState {
                open: false,
                epoch: 0,
                in_flight: 0,
            }),
            quiesced: Notify::new(),
        }
    }

    pub(super) fn open(&self) {
        let mut state = self.state.lock();
        assert_eq!(
            state.in_flight, 0,
            "NFQUEUE admission reopened before quiescence"
        );
        state.open = true;
    }

    pub(super) fn epoch(&self) -> Option<u64> {
        let state = self.state.lock();
        state.open.then_some(state.epoch)
    }

    pub(super) fn try_enter_at(&self, epoch: u64) -> Option<AdmissionTicket<'_>> {
        let ticket = self.try_enter()?;
        (ticket.epoch == epoch).then_some(ticket)
    }

    pub(super) fn try_enter(&self) -> Option<AdmissionTicket<'_>> {
        let mut state = self.state.lock();
        if !state.open {
            return None;
        }
        state.in_flight = state
            .in_flight
            .checked_add(1)
            .expect("NFQUEUE admission counter overflow");
        Some(AdmissionTicket {
            gate: self,
            epoch: state.epoch,
        })
    }

    pub(super) async fn close_and_wait(&self) {
        {
            let mut state = self.state.lock();
            if state.open {
                state.open = false;
                state.epoch = state
                    .epoch
                    .checked_add(1)
                    .expect("NFQUEUE admission epoch overflow");
            }
        }
        loop {
            let notified = self.quiesced.notified();
            if self.state.lock().in_flight == 0 {
                return;
            }
            notified.await;
        }
    }
}

pub(super) struct AdmissionTicket<'a> {
    gate: &'a AdmissionGate,
    epoch: u64,
}

impl Drop for AdmissionTicket<'_> {
    fn drop(&mut self) {
        let quiesced = {
            let mut state = self.gate.state.lock();
            debug_assert!(state.epoch == self.epoch || !state.open);
            state.in_flight = state
                .in_flight
                .checked_sub(1)
                .expect("NFQUEUE admission ticket underflow");
            state.in_flight == 0
        };
        if quiesced {
            self.gate.quiesced.notify_waiters();
        }
    }
}
