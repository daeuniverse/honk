//! Private observations for the real owned-VM consumer fixture.

use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub(in crate::xdp) struct PendingWait {
    pub reading: bool,
    pub driver_deadline: Option<Instant>,
    pub armed_deadline: Option<tokio::time::Instant>,
    pub idle_ports: bool,
    pub pending_outputs: bool,
}

#[derive(Default)]
pub(in crate::xdp) struct Control {
    pending: Mutex<Option<PendingWait>>,
}

impl Control {
    pub fn clear_pending(&self) {
        *self.pending.lock().unwrap() = None;
    }

    pub fn note_pending(&self, wait: PendingWait) {
        *self.pending.lock().unwrap() = Some(wait);
    }

    pub fn pending_wait(&self) -> Option<PendingWait> {
        *self.pending.lock().unwrap()
    }
}
