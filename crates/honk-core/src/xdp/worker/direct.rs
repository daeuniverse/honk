//! Each worker owns its sockets and dispatches their readiness by slot and generation.
mod observation;
mod pump;

pub(crate) use observation::{DirectAttach, DirectObserver, DirectOutcome, DirectSnapshot};
use pump::Pump;

use super::epoll::{BudgetedEpollFd, TOKEN_DIRECT_BIT, WATCH_BYTES};
use crate::control::netstack::FlowIdMap;
use crate::relay::{RelayStats, splice::DRAIN_DEADLINE};
use honk_netstack::{FlowId, MemoryReservation, Stack};
use nix::errno::Errno;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

const BATCH: usize = 64;
const READ_INTEREST: u32 = (libc::EPOLLIN | libc::EPOLLRDHUP) as u32;
const POISONED_GENERATION: u32 = 0x00ff_ffff;
const DRAIN: usize = 0;
const REPORT: usize = 1;
const REPORT_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Default)]
struct Slot {
    generation: u32,
    pump: Option<Pump>,
    // A ready entry can be reused by the next occupant of this slot.
    queued: bool,
    waiting_epoll: bool,
    epoll_out_armed: bool,
    epoll_et: bool,
    timers: [Timer; 2],
}

impl Slot {
    fn drive(
        &mut self,
        epoll: &ReactorEpoll,
        index: usize,
        stack: &mut Stack,
        now: Instant,
    ) -> anyhow::Result<bool> {
        let pump = self.pump.as_mut().expect("active Direct socket");
        let more = pump.drive(stack, now, self.epoll_et)?;
        let arm_write = pump.wants_write_epoll() && !self.epoll_out_armed;
        // Level triggering rechecks ordinary short reads. Use edge triggering for
        // terminal and credit-blocked sockets, or when adding writable interest.
        if arm_write || (!self.epoll_et && !pump.done() && pump.needs_edge_epoll()) {
            self.modify_watch(epoll, index, arm_write)
                .map_err(|error| {
                    anyhow::Error::new(error).context("updating Direct socket interest")
                })?;
        }
        Ok(more)
    }

    fn modify_watch(
        &mut self,
        epoll: &ReactorEpoll,
        index: usize,
        arm_write: bool,
    ) -> io::Result<()> {
        let pump = self.pump.as_ref().expect("active Direct socket");
        let out_armed = self.epoll_out_armed || arm_write;
        let mut event = libc::epoll_event {
            events: READ_INTEREST
                | libc::EPOLLET as u32
                | if out_armed { libc::EPOLLOUT as u32 } else { 0 },
            u64: epoll.token(self.generation, index),
        };
        epoll.control(libc::EPOLL_CTL_MOD, &pump.socket, Some(&mut event))?;
        self.epoll_et = true;
        self.epoll_out_armed = out_armed;
        Ok(())
    }
}

#[derive(Default)]
struct Timer {
    deadline: Option<Instant>,
    previous: Option<usize>,
    next: Option<usize>,
}

enum ReactorEpoll {
    Owned {
        epoll: OwnedFd,
        notification: Option<AsyncFd<OwnedFd>>,
        kernel_ready: bool,
        _credit: MemoryReservation,
    },
    Shared {
        epoll: Arc<BudgetedEpollFd>,
        realm_tag: u64,
    },
}

impl AsRawFd for ReactorEpoll {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Owned { epoll, .. } => epoll.as_raw_fd(),
            Self::Shared { epoll, .. } => epoll.as_raw_fd(),
        }
    }
}

impl ReactorEpoll {
    fn token(&self, generation: u32, index: usize) -> u64 {
        let realm_tag = match self {
            Self::Owned { .. } => 0,
            Self::Shared { realm_tag, .. } => *realm_tag,
        };
        realm_tag | (u64::from(generation) << 32) | index as u64
    }

    fn control(
        &self,
        operation: libc::c_int,
        socket: &TcpStream,
        event: Option<&mut libc::epoll_event>,
    ) -> io::Result<()> {
        let event = event.map_or(std::ptr::null_mut(), std::ptr::from_mut);
        // SAFETY: both fds are live. ADD and MOD copy the event, and DEL ignores the pointer.
        Errno::result(unsafe {
            libc::epoll_ctl(self.as_raw_fd(), operation, socket.as_raw_fd(), event)
        })?;
        Ok(())
    }
}

pub(crate) struct ServiceTurn {
    ready: usize,
    timers: usize,
    pub(crate) worked: bool,
}

pub(crate) struct DirectReactor {
    epoll: ReactorEpoll,
    epoll_waiters: usize,
    slots: Vec<Slot>,
    free: Vec<usize>,
    by_flow: FlowIdMap<usize>,
    ready: VecDeque<usize>,
    first: [Option<usize>; 2],
    last: [Option<usize>; 2],
    closed: bool,
    _credit: MemoryReservation,
    watch_credit: Option<MemoryReservation>,
}

impl DirectReactor {
    pub(crate) fn new(
        max_slots: usize,
        mut reserve: impl FnMut(usize) -> Option<MemoryReservation>,
    ) -> io::Result<Self> {
        // Each socket reserves one watch plus fd table space.
        // Two map entries per slot leave room to rehash tombstones in place at maximum
        // occupancy. Load factor and power-of-two rounding take fewer than five buckets per slot.
        let per =
            size_of::<Slot>() + 2 * size_of::<usize>() + 5 * (size_of::<(FlowId, usize)>() + 1);
        let bytes = max_slots
            .checked_mul(per)
            .and_then(|bytes| bytes.checked_add(size_of::<Self>()));
        let credit = bytes
            .filter(|_| max_slots != 0 && u32::try_from(max_slots).is_ok())
            .and_then(&mut reserve)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        let watch_credit = max_slots
            .checked_mul(WATCH_BYTES)
            .and_then(&mut reserve)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        // The standalone epoll and its optional notification share this allowance.
        let epoll_credit = reserve(1024).ok_or(io::ErrorKind::OutOfMemory)?;
        // SAFETY: epoll_create1 takes only flags; a successful result is a fresh owned fd.
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: ownership of the fresh fd is transferred exactly once.
        let epoll = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            epoll: ReactorEpoll::Owned {
                epoll,
                notification: None,
                kernel_ready: false,
                _credit: epoll_credit,
            },
            epoll_waiters: 0,
            slots: (0..max_slots).map(|_| Slot::default()).collect(),
            free: (0..max_slots).rev().collect(),
            by_flow: HashMap::with_capacity_and_hasher(2 * max_slots, Default::default()),
            ready: VecDeque::with_capacity(max_slots),
            first: [None; 2],
            last: [None; 2],
            closed: false,
            _credit: credit,
            watch_credit: Some(watch_credit),
        })
    }

    pub(crate) fn bind_worker_epoll(
        &mut self,
        epoll: Arc<BudgetedEpollFd>,
        realm_index: usize,
    ) -> io::Result<()> {
        if realm_index >= 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Direct realm index exceeds epoll token",
            ));
        }
        if self.closed
            || !matches!(self.epoll, ReactorEpoll::Owned { .. })
            || self.slots.iter().any(|slot| slot.generation != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot bind a used Direct reactor",
            ));
        }
        self.epoll = ReactorEpoll::Shared {
            epoll,
            realm_tag: TOKEN_DIRECT_BIT | ((realm_index as u64) << 56),
        };
        Ok(())
    }

    pub(crate) fn epoll_waiters(&self) -> usize {
        self.epoll_waiters
    }

    pub(crate) fn attach(
        &mut self,
        id: FlowId,
        attach: DirectAttach,
        now: Instant,
    ) -> Result<(), DirectAttach> {
        if self.closed || self.by_flow.contains_key(&id) {
            return Err(attach);
        }
        let Some(&index) = self.free.last() else {
            return Err(attach);
        };
        let slot = &mut self.slots[index];
        // DEL clears pending events, and each batch is dispatched before a slot is reused.
        let generation = if slot.generation == POISONED_GENERATION - 1 {
            1
        } else {
            slot.generation + 1
        };
        let mut event = libc::epoll_event {
            events: READ_INTEREST,
            u64: self.epoll.token(generation, index),
        };
        if let Err(error) =
            self.epoll
                .control(libc::EPOLL_CTL_ADD, &attach.socket, Some(&mut event))
        {
            tracing::debug!(%error, "Direct socket registration refused");
            return Err(attach);
        }
        self.free.pop();
        slot.generation = generation;
        slot.epoll_et = false;
        slot.pump = Some(Pump::new(id, attach, now));
        self.by_flow.insert(id, index);
        self.sync_epoll_waiter(index);
        self.enqueue(index);
        Ok(())
    }

    fn sync_epoll_waiter(&mut self, index: usize) {
        let slot = &mut self.slots[index];
        let waiting = slot.pump.as_ref().is_some_and(Pump::needs_epoll);
        if slot.waiting_epoll == waiting {
            return;
        }
        slot.waiting_epoll = waiting;
        if waiting {
            if self.epoll_waiters == 0
                && let ReactorEpoll::Owned { kernel_ready, .. } = &mut self.epoll
            {
                // The inner fd may still hold edges queued while polling was bypassed.
                *kernel_ready = true;
            }
            self.epoll_waiters += 1;
        } else {
            self.epoll_waiters -= 1;
            if self.epoll_waiters == 0
                && let ReactorEpoll::Owned { kernel_ready, .. } = &mut self.epoll
            {
                *kernel_ready = false;
            }
        }
    }

    fn enqueue(&mut self, index: usize) {
        if !std::mem::replace(&mut self.slots[index].queued, true) {
            self.ready.push_back(index);
        }
    }

    pub(crate) fn mark_ready(&mut self, id: FlowId) {
        if let Some(&index) = self.by_flow.get(&id) {
            self.enqueue(index);
        }
    }

    pub(crate) fn socket_ready(&mut self, token: u64, events: u32) {
        let index = token as u32 as usize;
        if let Some(slot) = self.slots.get_mut(index)
            && token == self.epoll.token(slot.generation, index)
            && let Some(pump) = &mut slot.pump
        {
            pump.socket_ready(events);
            self.sync_epoll_waiter(index);
            self.enqueue(index);
        }
    }

    // Bind to the runtime polling this owner, not to the startup/coordinator runtime.
    pub(crate) fn poll_ready(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        let ReactorEpoll::Owned {
            epoll,
            notification,
            kernel_ready,
            ..
        } = &mut self.epoll
        else {
            return Ok(self.has_pending_work());
        };
        if notification.is_none() {
            let fd = epoll.try_clone()?;
            // SAFETY: this owned duplicate has a stable fd for the registration's lifetime.
            let registered = unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }
                .map_err(|error| error.into_parts().1)?;
            *notification = Some(registered);
        }
        if self.epoll_waiters != 0
            && let Poll::Ready(guard) = notification
                .as_ref()
                .expect("registered epoll")
                .poll_read_ready(cx)
        {
            // service() drains the inner fd after clearing this edge. A full batch
            // self-schedules; later arrivals supply fresh edges to the outer driver.
            guard?.clear_ready();
            *kernel_ready = true;
        }
        Ok(self.has_pending_work())
    }

    pub(crate) fn has_pending_work(&self) -> bool {
        matches!(
            self.epoll,
            ReactorEpoll::Owned {
                kernel_ready: true,
                ..
            }
        ) || !self.ready.is_empty()
    }

    fn collect_events(&mut self) -> io::Result<usize> {
        let ReactorEpoll::Owned {
            epoll,
            kernel_ready,
            ..
        } = &mut self.epoll
        else {
            return Ok(0);
        };
        // The last waiter clears kernel_ready even if the epoll fd remains readable.
        if !*kernel_ready {
            return Ok(0);
        }
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; BATCH];
        let n = loop {
            // SAFETY: the array is writable for BATCH complete epoll_event records.
            let n = unsafe {
                libc::epoll_wait(epoll.as_raw_fd(), events.as_mut_ptr(), BATCH as i32, 0)
            };
            if n >= 0 {
                break n as usize;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        };
        // Processing the batch may satisfy the last waiter and clear this flag.
        *kernel_ready = n == BATCH;
        for event in &events[..n] {
            self.socket_ready(event.u64, event.events);
        }
        Ok(n)
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        [DRAIN, REPORT]
            .into_iter()
            .filter_map(|kind| self.head(kind).map(|(_, at)| at))
            .min()
    }

    fn head(&self, kind: usize) -> Option<(usize, Instant)> {
        let index = self.first[kind]?;
        Some((
            index,
            self.slots[index].timers[kind]
                .deadline
                .expect("linked Direct timer"),
        ))
    }

    // Each queue has a fixed interval. Appending renewals in service-time order keeps
    // the earliest deadline at its head without a scan or timer allocation.
    fn remove_deadline(&mut self, index: usize, kind: usize) {
        let timer = &mut self.slots[index].timers[kind];
        if timer.deadline.take().is_none() {
            return;
        }
        let (previous, next) = (timer.previous.take(), timer.next.take());
        if let Some(previous) = previous {
            self.slots[previous].timers[kind].next = next;
        } else {
            self.first[kind] = next;
        }
        if let Some(next) = next {
            self.slots[next].timers[kind].previous = previous;
        } else {
            self.last[kind] = previous;
        }
    }

    fn schedule(&mut self, index: usize, kind: usize, interval: Duration, now: Instant) {
        self.remove_deadline(index, kind);
        if let Some(last) = self.last[kind] {
            self.slots[last].timers[kind].next = Some(index);
        } else {
            self.first[kind] = Some(index);
        }
        let timer = &mut self.slots[index].timers[kind];
        timer.previous = self.last[kind].replace(index);
        timer.deadline = Some(now + interval);
    }

    fn detach(&mut self, index: usize) -> (FlowId, observation::Progress) {
        self.remove_deadline(index, DRAIN);
        self.remove_deadline(index, REPORT);
        let slot = &mut self.slots[index];
        let pump = slot.pump.take().expect("active Direct socket");
        self.by_flow.remove(&pump.id);
        // Explicitly deregister even if another subsystem kept a duplicate of the open file.
        if let Err(error) = self.epoll.control(libc::EPOLL_CTL_DEL, &pump.socket, None)
            && error.raw_os_error() != Some(libc::ENOENT)
        {
            slot.generation = POISONED_GENERATION;
            if let ReactorEpoll::Shared { epoll, .. } = &self.epoll
                && let Some(credit) = self.watch_credit.take()
            {
                epoll.retain_watch_credit(credit);
            }
            tracing::error!(%error, "failed to remove Direct socket watch");
        }
        drop(pump.socket);
        slot.epoll_out_armed = false;
        if slot.generation != POISONED_GENERATION {
            self.free.push(index);
        }
        self.sync_epoll_waiter(index);
        (pump.id, pump.progress)
    }

    fn finish(
        &mut self,
        index: usize,
        result: anyhow::Result<RelayStats>,
    ) -> (FlowId, impl FnOnce() + use<>) {
        let (id, progress) = self.detach(index);
        (id, move || progress.finish(DirectOutcome::Finished(result)))
    }

    pub(crate) fn abort(&mut self, id: FlowId) {
        if let Some(&index) = self.by_flow.get(&id) {
            self.detach(index).1.finish(DirectOutcome::Cancelled);
        }
    }

    pub(crate) fn close(&mut self) {
        if !std::mem::replace(&mut self.closed, true) {
            self.close_pumps(true);
        }
    }

    fn close_pumps(&mut self, publish_cancelled: bool) {
        self.ready.clear();
        for index in 0..self.slots.len() {
            let slot = &mut self.slots[index];
            slot.queued = false;
            if slot.pump.is_some() {
                let (_, progress) = self.detach(index);
                if publish_cancelled {
                    progress.finish(DirectOutcome::Cancelled);
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn service(&mut self, stack: &mut Stack, now: Instant) -> io::Result<bool> {
        self.service_with_finish(stack, now, |_, _| {})
    }

    #[cfg(test)]
    pub(crate) fn service_with_finish(
        &mut self,
        stack: &mut Stack,
        now: Instant,
        mut on_finish: impl FnMut(&mut Stack, FlowId),
    ) -> io::Result<bool> {
        let mut turn = self.begin_service()?;
        while let Some((id, publish)) = self.next_finished(stack, now, &mut turn) {
            on_finish(stack, id);
            publish();
        }
        Ok(turn.worked)
    }

    pub(crate) fn begin_service(&mut self) -> io::Result<ServiceTurn> {
        let events = self.collect_events()?;
        let ready = self.ready.len().min(BATCH);
        Ok(ServiceTurn {
            ready,
            timers: BATCH,
            worked: ready != 0 || events == BATCH,
        })
    }

    /// The caller closes and reaps the original flow before waking its completion task.
    pub(crate) fn next_finished(
        &mut self,
        stack: &mut Stack,
        now: Instant,
        turn: &mut ServiceTurn,
    ) -> Option<(FlowId, impl FnOnce() + use<>)> {
        while turn.ready != 0 {
            turn.ready -= 1;
            let index = self.ready.pop_front().expect("counted Direct work");
            let slot = &mut self.slots[index];
            slot.queued = false;
            let Some(pump) = &slot.pump else {
                continue;
            };
            let before = (
                pump.progress.snapshot.upload,
                pump.progress.snapshot.download,
            );
            let result = slot.drive(&self.epoll, index, stack, now);
            let pump = slot.pump.as_ref().expect("active Direct socket");
            let outcome = match result {
                Err(error) => {
                    let _ = stack.tcp_shutdown(pump.id);
                    Err(error)
                }
                Ok(_) if pump.done() => Ok(pump.stats(now)),
                Ok(more) => {
                    let after = (
                        pump.progress.snapshot.upload,
                        pump.progress.snapshot.download,
                    );
                    let progressed = before != after;
                    let renew =
                        pump.draining() && (progressed || slot.timers[DRAIN].deadline.is_none());
                    if pump.progress.observe_live && progressed {
                        if (before.0 == 0 && after.0 != 0) || (before.1 == 0 && after.1 != 0) {
                            pump.progress.publish();
                            self.remove_deadline(index, REPORT);
                        } else if slot.timers[REPORT].deadline.is_none() {
                            self.schedule(index, REPORT, REPORT_INTERVAL, now);
                        }
                    }
                    if renew {
                        // A stalled turn still owes the surviving half a full idle interval.
                        let drain_now = now.max(Instant::now());
                        self.schedule(index, DRAIN, DRAIN_DEADLINE, drain_now);
                    }
                    self.sync_epoll_waiter(index);
                    if more {
                        self.enqueue(index);
                    }
                    continue;
                }
            };
            return Some(self.finish(index, outcome));
        }
        if turn.timers != 0
            && let Some((index, at)) = self.head(DRAIN)
            && at <= now
        {
            let pump = self.slots[index]
                .pump
                .as_ref()
                .expect("draining Direct socket");
            let result = pump.finish_drain(stack, now);
            turn.timers -= 1;
            turn.worked = true;
            return Some(self.finish(index, result));
        }
        while turn.timers != 0
            && let Some((index, at)) = self.head(REPORT)
            && at <= now
        {
            self.remove_deadline(index, REPORT);
            self.slots[index]
                .pump
                .as_ref()
                .expect("pending Direct progress")
                .progress
                .publish();
            turn.timers -= 1;
            turn.worked = true;
        }
        None
    }
}

impl Drop for DirectReactor {
    fn drop(&mut self) {
        if matches!(self.epoll, ReactorEpoll::Shared { .. }) && !self.by_flow.is_empty() {
            self.close_pumps(false);
        }
    }
}

#[cfg(test)]
mod tests;
