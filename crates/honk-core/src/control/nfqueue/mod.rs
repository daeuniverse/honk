//! Verdict ownership for token-bound UDP and reassembled routed DNS originals.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use honk_ebpf_common::{
    CLASSIFIED_MARK, OutboundIndex, ROUTING_META_FLAG_OFFLOAD, ROUTING_META_FLAG_PUBLISHED,
    TuplesKey, UdpDecisionState, UdpDnsRoute, extract_nfqueue_token, skb_mark_has_reserved_bits,
};
use honk_nfqueue::{QueuedPacket, UdpTuple, VerdictGuard};
use parking_lot::Mutex;
use tokio::sync::{Notify, OwnedSemaphorePermit, RwLock, Semaphore, mpsc, watch};

use super::connection::build_tuples_key;
use super::udp_endpoint::{EndpointReservation, OwnedEnqueueError, UdpEndpointPool, UdpInitLease};
use crate::ebpf::{EbpfBackend, UdpDecisionCommitResult, UdpDecisionTransition};
use crate::stats::StatsManager;

mod cell;
mod ingest;
mod transition;
pub(in crate::control) use cell::HeldVerdict;
pub(super) use cell::PendingUdpIdentity;
#[cfg(test)]
pub(in crate::control) use cell::TestVerdict;
use cell::{
    AdmissionGate, CellState, CleanupRequest, DropOutcome, FlowCell, FlowKey, RetainedState,
    terminal_cell_is_stale,
};
#[cfg(test)]
use ingest::retained_state;
pub(super) const TERMINAL_GRACE: Duration = Duration::from_millis(500);
pub(super) const WATCHDOG_INTERVAL: Duration = Duration::from_millis(100);
pub(super) const HARD_HOLD_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_SCHEDULED_CLEANUPS: usize = honk_nfqueue::QUEUE_MAXLEN as usize;
const MAX_CORRELATOR_FLOWS: usize = honk_nfqueue::QUEUE_MAXLEN as usize;
const MAX_HELD_VERDICTS_PER_FLOW: usize = 64;
const IPPROTO_UDP: u8 = 17;

const _: () = {
    assert!(honk_nfqueue::NFQUEUE_PENDING_MARK == honk_ebpf_common::NFQUEUE_PENDING_MARK);
    assert!(honk_nfqueue::NFQUEUE_SIGNATURE_MARK == honk_ebpf_common::NFQUEUE_SIGNATURE_MARK);
    assert!(honk_nfqueue::NFQUEUE_TOKEN_MASK == honk_ebpf_common::NFQUEUE_TOKEN_MASK);
};
#[derive(Debug, Clone, thiserror::Error)]
#[error("UDP NFQUEUE {operation} failed: {detail}")]
pub(super) struct PendingUdpFatal {
    operation: &'static str,
    detail: String,
}

impl PendingUdpFatal {
    fn new(operation: &'static str, detail: impl Into<String>) -> Self {
        Self {
            operation,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum PendingUdpDecisionError {
    #[error("stale UDP NFQUEUE token or endpoint generation")]
    StaleIdentity,
    #[error("UDP direct rule mark uses a reserved datapath bit")]
    ReservedDirectMark,
    #[error("UDP direct activation is already armed")]
    ArmedInProgress,
    #[error(transparent)]
    Fatal(#[from] PendingUdpFatal),
}

// The listener consumes this result immediately; keeping the sole lease inline
// avoids a second allocation on every staged UDP flow.
#[allow(clippy::large_enum_variant)]
pub(super) enum NfqueueIngest {
    Initialize {
        lease: UdpInitLease,
        identity: PendingUdpIdentity,
    },
    Queued,
    Dropped,
}

pub(super) struct PendingUdpVerdicts {
    cells: DashMap<FlowKey, Arc<FlowCell>>,
    flow_slots: Arc<Semaphore>,
    scheduled_cleanups: Mutex<HashSet<CleanupRequest>>,
    cleanup_drainer: tokio::sync::Mutex<()>,
    admission: AdmissionGate,
    empty: Notify,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    endpoints: Arc<UdpEndpointPool>,
    stats: Arc<StatsManager>,
    fatal: mpsc::Sender<PendingUdpFatal>,
}

impl PendingUdpVerdicts {
    pub(super) fn new(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        endpoints: Arc<UdpEndpointPool>,
        stats: Arc<StatsManager>,
    ) -> (Self, mpsc::Receiver<PendingUdpFatal>) {
        let (fatal, receiver) = mpsc::channel(1);
        (
            Self {
                cells: DashMap::new(),
                flow_slots: Arc::new(Semaphore::new(MAX_CORRELATOR_FLOWS)),
                scheduled_cleanups: Mutex::new(HashSet::new()),
                cleanup_drainer: tokio::sync::Mutex::new(()),
                admission: AdmissionGate::new(),
                empty: Notify::new(),
                ebpf,
                endpoints,
                stats,
                fatal,
            },
            receiver,
        )
    }

    pub(super) fn identity_for_lease(lease: &UdpInitLease) -> PendingUdpIdentity {
        PendingUdpIdentity::new(
            FlowKey::new(lease.client_addr(), lease.original_dst()),
            lease.decision_token(),
            lease.generation(),
        )
    }

    pub(super) fn open_admission(&self) {
        self.admission.open();
    }

    pub(in crate::control) fn admission_epoch(&self) -> Option<u64> {
        self.admission.epoch()
    }
}

mod watchdog;

#[cfg(test)]
mod tests;
