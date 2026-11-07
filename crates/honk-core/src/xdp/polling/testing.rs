//! Private, deadline-bounded fault controls for the real owned-VM consumer fixture.

use super::clock::ClockObservation;
use honk_config::datapath::PollMode;
use honk_xsk::{PortCounters, RingSnapshot};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::xdp) enum ClockFault {
    #[default]
    None,
    Unavailable,
    BootOffset(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::xdp) enum Point {
    Reserved,
    FeatureQuery,
}

#[derive(Clone, Debug)]
pub(in crate::xdp) struct Queue {
    pub device: String,
    pub id: u32,
    pub counters: PortCounters,
    pub rings: RingSnapshot,
}

#[derive(Clone, Debug)]
pub(in crate::xdp) struct Snapshot {
    pub mode: PollMode,
    pub high: bool,
    pub low: bool,
    pub rx_high_windows: u16,
    pub tx_high_windows: u16,
    pub busy_entries: u64,
    pub probe_rounds: u64,
    pub qualified_rx: u64,
    pub published_tx: u64,
    pub local_revision: u64,
    pub process_revision: u64,
    pub reason: &'static str,
    pub clock: Option<ClockObservation>,
    pub clock_error: Option<&'static str>,
    pub executable_sha256: Option<String>,
    pub context_sha256: Option<String>,
    pub parameter_sha256: Option<String>,
    pub queues: Vec<Queue>,
    pub cursors: (usize, usize, usize, usize),
    pub pollable: bool,
    pub waiting: usize,
    pub pending: usize,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::xdp) struct PendingWait {
    pub reading: bool,
    pub driver_deadline: Option<Instant>,
    pub armed_deadline: Option<tokio::time::Instant>,
    pub idle_ports: bool,
    pub pending_outputs: bool,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::xdp) struct Exit {
    pub reason: &'static str,
    pub probe_rounds: u64,
    pub published_packets: u64,
    pub settlement: Option<crate::control::poll_budget::PollSettlement>,
    pub start_cursors: (usize, usize, usize, usize),
    pub cursors: (usize, usize, usize, usize),
    pub start_rx: u64,
    pub rx_packets: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::xdp) struct ClockEvents {
    pub gaps: u64,
    pub offsets: u64,
    pub errors: u64,
}

#[derive(Default)]
pub(in crate::xdp) struct Control {
    clock_fault: Mutex<ClockFault>,
    armed: Mutex<Option<Arc<PauseState>>>,
    pending: Mutex<Option<PendingWait>>,
    exit: Mutex<Option<Exit>>,
    clock_events: Mutex<ClockEvents>,
    serviced_revision: std::sync::atomic::AtomicU64,
    query_errno: Mutex<Option<i32>>,
    bounded_cut: Mutex<Option<Exit>>,
    idle_high_rounds: std::sync::atomic::AtomicU64,
    idle_high_reservations: std::sync::atomic::AtomicU64,
}

struct PauseState {
    point: Point,
    deadline: Instant,
    state: Mutex<(Option<Snapshot>, bool)>,
    changed: Condvar,
}

pub(in crate::xdp) struct Pause(Arc<PauseState>);

impl Control {
    pub fn clock_fault(&self) -> ClockFault {
        *self.clock_fault.lock().unwrap()
    }

    pub fn set_clock_fault(&self, fault: ClockFault) {
        *self.clock_fault.lock().unwrap() = fault;
    }

    pub fn arm(&self, point: Point, deadline: Instant) -> Pause {
        assert!(
            deadline > Instant::now(),
            "the fixture deadline already expired"
        );
        let mut armed = self.armed.lock().unwrap();
        assert!(
            armed.is_none(),
            "one outstanding fixture rendezvous per owner"
        );
        let state = Arc::new(PauseState {
            point,
            deadline,
            state: Mutex::new((None, false)),
            changed: Condvar::new(),
        });
        *armed = Some(Arc::clone(&state));
        Pause(state)
    }

    pub fn armed(&self, point: Point) -> bool {
        self.armed
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|pause| pause.point == point)
    }

    pub fn arrive(&self, point: Point, snapshot: Snapshot) {
        let pause = {
            let mut armed = self.armed.lock().unwrap();
            if !armed.as_ref().is_some_and(|pause| pause.point == point) {
                return;
            }
            armed.take().unwrap()
        };
        let mut state = pause.state.lock().unwrap();
        state.0 = Some(snapshot);
        pause.changed.notify_all();
        while !state.1 {
            let Some(remaining) = pause.deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let (next, timeout) = pause.changed.wait_timeout(state, remaining).unwrap();
            state = next;
            if timeout.timed_out() {
                break;
            }
        }
    }

    pub fn clear_pending(&self) {
        *self.pending.lock().unwrap() = None;
    }

    pub fn note_pending(&self, wait: PendingWait) {
        *self.pending.lock().unwrap() = Some(wait);
    }

    pub fn note_exit(&self, exit: Exit) {
        *self.exit.lock().unwrap() = Some(exit);
        if exit.reason == "bounded_segment_limit"
            && exit.cursors != exit.start_cursors
            && exit.rx_packets > exit.start_rx
        {
            *self.bounded_cut.lock().unwrap() = Some(exit);
        }
    }

    pub fn last_exit(&self) -> Option<Exit> {
        *self.exit.lock().unwrap()
    }

    pub fn last_bounded_cut(&self) -> Option<Exit> {
        *self.bounded_cut.lock().unwrap()
    }

    pub fn note_clock(&self, gap: bool, offset: bool, error: bool) {
        let mut events = self.clock_events.lock().unwrap();
        events.gaps += u64::from(gap);
        events.offsets += u64::from(offset);
        events.errors += u64::from(error);
    }

    pub fn clock_events(&self) -> ClockEvents {
        *self.clock_events.lock().unwrap()
    }

    pub fn note_serviced_revision(&self, revision: u64) {
        self.serviced_revision
            .store(revision, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn serviced_revision(&self) -> u64 {
        self.serviced_revision
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn note_query_errno(&self, errno: Option<i32>) {
        *self.query_errno.lock().unwrap() = errno;
    }

    pub fn last_query_errno(&self) -> Option<i32> {
        *self.query_errno.lock().unwrap()
    }

    pub fn note_idle_high(&self, reserved: bool) {
        self.idle_high_rounds
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if reserved {
            self.idle_high_reservations
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    pub fn idle_high(&self) -> (u64, u64) {
        (
            self.idle_high_rounds
                .load(std::sync::atomic::Ordering::SeqCst),
            self.idle_high_reservations
                .load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    pub fn pending_wait(&self) -> Option<PendingWait> {
        *self.pending.lock().unwrap()
    }
}

impl Pause {
    /// The caller must be on the independent fixture controller, never the owner executor.
    pub fn wait(&self) -> anyhow::Result<Snapshot> {
        let mut state = self.0.state.lock().unwrap();
        loop {
            if let Some(snapshot) = &state.0 {
                return Ok(snapshot.clone());
            }
            let remaining = self
                .0
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "actual owner did not reach {:?} before fixture deadline",
                        self.0.point
                    )
                })?;
            let (next, timeout) = self.0.changed.wait_timeout(state, remaining).unwrap();
            state = next;
            if timeout.timed_out() && state.0.is_none() {
                anyhow::bail!(
                    "actual owner did not reach {:?} before fixture deadline",
                    self.0.point
                );
            }
        }
    }

    pub fn release(&self) {
        let mut state = self.0.state.lock().unwrap();
        state.1 = true;
        self.0.changed.notify_all();
    }
}

impl Drop for Pause {
    fn drop(&mut self) {
        self.release();
    }
}
