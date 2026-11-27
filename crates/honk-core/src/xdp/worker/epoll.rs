//! One wait set for worker-owned descriptors and cross-thread task notifications.

use honk_netstack::{MemoryBudget, MemoryReservation};
use nix::errno::Errno;
use std::cell::Cell;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::Wake;
use std::time::{Duration, Instant};

const TOKEN_WAKE: u64 = 0;
pub(crate) const TOKEN_TOPOLOGY: u64 = 1;
pub(crate) const TOKEN_XSK_BASE: u64 = 1 << 62;
pub(crate) const TOKEN_DIRECT_BIT: u64 = 1 << 63;
pub(crate) const MAX_CONSECUTIVE_TURNS: usize = 16;
const DIRECT_EPOLL_TURNS: usize = 4;

// Bound Direct readiness latency separately from the general busy-turn budget.
pub(in crate::xdp) fn direct_epoll_due(turns: usize, realms: &[crate::xdp::Realm]) -> bool {
    turns.is_multiple_of(DIRECT_EPOLL_TURNS)
        && realms
            .iter()
            .any(|realm| realm.driver.direct_epoll_waiters() != 0)
}

// Direct pays for its socket watches separately at slot admission. Fixed worker watches use
// the same 256-byte epitem allowance. Each anonymous fd also has kernel and Arc storage.
pub(super) const WATCH_BYTES: usize = 256;
const FD_BYTES: usize = 1024;

const RUNNING: u8 = 0;
const WOKEN: u8 = 1;
const SLEEPING: u8 = 2;
const NOTIFIED: u8 = 3;

pub(crate) struct BudgetedEpollFd {
    fd: OwnedFd,
    credit: parking_lot::Mutex<MemoryReservation>,
}

impl BudgetedEpollFd {
    pub(crate) fn retain_watch_credit(&self, credit: MemoryReservation) {
        self.credit.lock().absorb(credit);
    }
}

impl AsRawFd for BudgetedEpollFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

pub(crate) struct WakeFd {
    fd: OwnedFd,
    state: AtomicU8,
    _credit: MemoryReservation,
}

impl WakeFd {
    fn new(budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let credit = budget.reserve(FD_BYTES).ok_or(io::ErrorKind::OutOfMemory)?;
        // SAFETY: eventfd takes an initial counter and flags and returns a fresh owned fd.
        let fd =
            Errno::result(unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) })?;
        Ok(Self {
            // SAFETY: the successful eventfd result has no other owner.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            state: AtomicU8::new(RUNNING),
            _credit: credit,
        })
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.state.load(Ordering::Acquire) != RUNNING
    }

    pub(crate) fn drain(&self) -> io::Result<()> {
        if self.state.swap(RUNNING, Ordering::SeqCst) == NOTIFIED {
            self.read_counter()?;
        }
        Ok(())
    }

    fn drain_eventfd(&self) -> io::Result<()> {
        // A delayed sleeping producer may write after the owner has already resumed.
        // Clear the state before reading so a new running wake survives the next work pass.
        self.state.swap(RUNNING, Ordering::SeqCst);
        self.read_counter()
    }

    fn try_sleep(&self) -> bool {
        self.state
            .compare_exchange(RUNNING, SLEEPING, Ordering::SeqCst, Ordering::Acquire)
            .is_ok()
    }

    fn finish_wait(&self, events: &[libc::epoll_event]) -> io::Result<bool> {
        let notified = self.state.swap(RUNNING, Ordering::AcqRel) == NOTIFIED;
        // A write from an earlier sleep can arrive after its state was acknowledged.
        if notified || events.iter().any(|event| event.u64 == TOKEN_WAKE) {
            self.read_counter()?;
        }
        Ok(notified)
    }

    fn notify_before_write(&self, before_write: impl FnOnce()) {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            let next = match state {
                RUNNING => WOKEN,
                SLEEPING => NOTIFIED,
                _ => return,
            };
            match self
                .state
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    if next == NOTIFIED {
                        before_write();
                        self.write_counter();
                    }
                    return;
                }
                Err(current) => state = current,
            }
        }
    }

    fn write_counter(&self) {
        // SAFETY: the descriptor is live and 1 is a valid eventfd increment.
        eventfd_io(|| unsafe { libc::eventfd_write(self.fd.as_raw_fd(), 1) })
            .expect("write to owned worker eventfd");
    }

    fn read_counter(&self) -> io::Result<()> {
        let mut value = 0;
        // SAFETY: the descriptor is live and the output is a writable eventfd_t.
        eventfd_io(|| unsafe { libc::eventfd_read(self.fd.as_raw_fd(), &mut value) })
    }
}

impl Wake for WakeFd {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notify_before_write(|| {});
    }
}

fn eventfd_io(mut call: impl FnMut() -> libc::c_int) -> io::Result<()> {
    loop {
        match Errno::result(call()) {
            // EAGAIN on read means already empty, on write it means already readable.
            Ok(_) | Err(Errno::EAGAIN) => return Ok(()),
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) struct WorkerEpoll {
    pub(crate) fd: Arc<BudgetedEpollFd>,
    pub(crate) wake: Arc<WakeFd>,
    free_watches: Cell<usize>,
}

impl WorkerEpoll {
    pub(crate) fn new(budget: &Arc<MemoryBudget>, max_external_watches: usize) -> io::Result<Self> {
        let watches = max_external_watches
            .checked_add(1)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        let credit = watches
            .checked_mul(WATCH_BYTES)
            .and_then(|bytes| bytes.checked_add(FD_BYTES))
            .and_then(|bytes| budget.reserve(bytes))
            .ok_or(io::ErrorKind::OutOfMemory)?;
        // SAFETY: epoll_create1 takes only flags and returns a fresh owned fd.
        let fd = Errno::result(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) })?;
        let worker = Self {
            fd: Arc::new(BudgetedEpollFd {
                // SAFETY: the successful epoll_create1 result has no other owner.
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
                credit: parking_lot::Mutex::new(credit),
            }),
            wake: Arc::new(WakeFd::new(budget)?),
            free_watches: Cell::new(watches),
        };
        worker.add_fd(worker.wake.fd.as_raw_fd(), libc::EPOLLIN as u32, TOKEN_WAKE)?;
        Ok(worker)
    }

    pub(crate) fn add_fd(&self, fd: RawFd, events: u32, token: u64) -> io::Result<()> {
        let remaining = self
            .free_watches
            .get()
            .checked_sub(1)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        let mut event = libc::epoll_event { events, u64: token };
        // SAFETY: epoll_ctl copies the initialized event before returning.
        Errno::result(unsafe {
            libc::epoll_ctl(self.fd.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &mut event)
        })?;
        self.free_watches.set(remaining);
        Ok(())
    }

    /// Removes a fixed worker watch previously registered through add_fd.
    pub(crate) fn del_fd(&self, fd: RawFd) -> io::Result<()> {
        // SAFETY: Linux ignores the event pointer for DEL.
        Errno::result(unsafe {
            libc::epoll_ctl(
                self.fd.as_raw_fd(),
                libc::EPOLL_CTL_DEL,
                fd,
                ptr::null_mut(),
            )
        })?;
        self.free_watches.set(self.free_watches.get() + 1);
        Ok(())
    }

    /// A returned wake event has already been drained. Dispatch only the other descriptors.
    pub(crate) fn wait(
        &self,
        deadline: Option<Instant>,
        mut now: Instant,
        events: &mut [libc::epoll_event],
    ) -> io::Result<usize> {
        let count = event_count(events)?;
        loop {
            let left = deadline.map(|due| due.saturating_duration_since(now));
            if !self.wake.try_sleep() {
                return Ok(0);
            }
            let timeout = ceil_millis(left);
            let result = self.wait_ms(events, count, timeout);
            let notified = self.wake.finish_wait(&events[..result.unwrap_or(0)])?;
            match result {
                // A capped timeout can expire before the absolute deadline.
                Ok(0) if timeout == i32::MAX && !notified => {}
                Ok(n) => return Ok(n),
                Err(Errno::EINTR) if notified => return Ok(0),
                Err(Errno::EINTR) => {}
                Err(error) => return Err(error.into()),
            }
            now = Instant::now();
            if deadline.is_some_and(|due| now >= due) {
                return Ok(0);
            }
        }
    }

    /// Checks readiness without arming sleep, including writes delayed from an earlier sleep.
    pub(crate) fn poll_nonblocking(&self, events: &mut [libc::epoll_event]) -> io::Result<usize> {
        let count = event_count(events)?;
        loop {
            match self.wait_ms(events, count, 0) {
                Err(Errno::EINTR) => continue,
                Ok(n) => {
                    if events[..n].iter().any(|event| event.u64 == TOKEN_WAKE) {
                        self.wake.drain_eventfd()?;
                    }
                    return Ok(n);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn wait_ms(
        &self,
        events: &mut [libc::epoll_event],
        count: i32,
        millis: i32,
    ) -> nix::Result<usize> {
        // SAFETY: count was checked against this writable slice before the retry loop.
        Errno::result(unsafe {
            libc::epoll_wait(self.fd.as_raw_fd(), events.as_mut_ptr(), count, millis)
        })
        .map(|n| n as usize)
    }
}

impl Drop for WorkerEpoll {
    fn drop(&mut self) {
        // A retained Direct owner and a task waker can each outlive the dispatch loop.
        let _ = self.del_fd(self.wake.fd.as_raw_fd());
    }
}

fn event_count(events: &[libc::epoll_event]) -> io::Result<i32> {
    if events.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    i32::try_from(events.len()).map_err(|_| io::ErrorKind::InvalidInput.into())
}

fn ceil_millis(timeout: Option<Duration>) -> i32 {
    timeout.map_or(-1, |d| {
        i32::try_from(d.as_nanos().div_ceil(1_000_000)).unwrap_or(i32::MAX)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Barrier, mpsc};
    use std::thread;

    #[test]
    fn competing_wakes_survive_eventfd_drain() {
        const PRODUCERS: usize = 4;
        const ROUNDS: usize = 256;
        let worker = WorkerEpoll::new(&MemoryBudget::new(8192), 0).unwrap();
        let wake = &worker.wake;
        let barrier = Barrier::new(PRODUCERS + 1);
        let mut missing_notification = 0;
        let mut redundant_write = 0;
        let mut missing_state = 0;
        thread::scope(|scope| {
            for _ in 0..PRODUCERS {
                scope.spawn(|| {
                    for _ in 0..ROUNDS {
                        barrier.wait();
                        wake.wake_by_ref();
                        barrier.wait();
                    }
                });
            }
            for round in 0..ROUNDS {
                let sleeping = round % 2 == 0;
                if sleeping && !wake.try_sleep() {
                    missing_state += 1;
                }
                barrier.wait();
                barrier.wait();
                // Sample the actual counter after all producers returned. Multiple sleeping
                // wakes must add exactly one, and all running wakes must leave EAGAIN.
                let counter = take_counter(wake);
                if sleeping && counter != Some(1) {
                    missing_notification += 1;
                } else if !sleeping && counter.is_some() {
                    redundant_write += 1;
                }
                if !wake.is_pending() || wake.drain().is_err() || wake.is_pending() {
                    missing_state += 1;
                }
            }
        });
        assert_eq!(
            missing_notification, 0,
            "sleeping worker missed eventfd notification"
        );
        assert_eq!(redundant_write, 0, "running wake wrote to eventfd");
        assert_eq!(missing_state, 0, "lost a competing wake during drain");
    }

    fn take_counter(wake: &WakeFd) -> Option<u64> {
        let mut count = 0;
        loop {
            // SAFETY: the fd is live and count is a writable eventfd_t.
            match Errno::result(unsafe { libc::eventfd_read(wake.fd.as_raw_fd(), &mut count) }) {
                Ok(_) => return Some(count),
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => return None,
                Err(error) => panic!("sampling eventfd: {error}"),
            }
        }
    }

    #[test]
    fn other_fd_resumes_sleep_before_delayed_notification_write() {
        let worker = WorkerEpoll::new(&MemoryBudget::new(8192), 1).unwrap();
        let (watched, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        worker
            .add_fd(watched.as_raw_fd(), libc::EPOLLIN as u32, TOKEN_TOPOLOGY)
            .unwrap();
        let mut events = [libc::epoll_event { events: 0, u64: 0 }];
        let count = thread::scope(|scope| {
            let (resumed, resume_write) = mpsc::channel::<()>();
            let wake = Arc::clone(&worker.wake);
            scope.spawn(move || {
                while wake.state.load(Ordering::Acquire) != SLEEPING {
                    thread::yield_now();
                }
                wake.notify_before_write(|| {
                    drop(peer);
                    let _ = resume_write.recv();
                });
            });
            let result = worker.wait(None, Instant::now(), &mut events);
            drop(resumed);
            result.unwrap()
        });
        assert_eq!(count, 1);
        let token = events[0].u64;
        assert_eq!(token, TOKEN_TOPOLOGY);
        worker.del_fd(watched.as_raw_fd()).unwrap();
        assert!(!worker.wake.is_pending());
        worker.wake.wake_by_ref();
        let now = Instant::now();
        assert_eq!(worker.wait(Some(now), now, &mut events).unwrap(), 0);
        worker.wake.drain().unwrap();
        // Draining the running wake does not read the stale count; epoll still sees it.
        assert_eq!(worker.poll_nonblocking(&mut events).unwrap(), 1);
        let token = events[0].u64;
        assert_eq!(token, TOKEN_WAKE);
        assert_eq!(take_counter(&worker.wake), None);
        assert_eq!(worker.poll_nonblocking(&mut events).unwrap(), 0);
    }

    #[test]
    fn blocking_wait_drains_stale_wake_with_other_ready_fd() {
        let worker = WorkerEpoll::new(&MemoryBudget::new(8192), 1).unwrap();
        let (watched, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        worker
            .add_fd(watched.as_raw_fd(), libc::EPOLLIN as u32, TOKEN_TOPOLOGY)
            .unwrap();
        drop(peer);
        assert!(worker.wake.try_sleep());
        worker
            .wake
            .notify_before_write(|| worker.wake.drain().unwrap());
        assert!(!worker.wake.is_pending());

        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];
        let now = Instant::now();
        assert_eq!(worker.wait(Some(now), now, &mut events).unwrap(), 2);
        assert!(events.iter().any(|event| event.u64 == TOKEN_WAKE));
        assert!(events.iter().any(|event| event.u64 == TOKEN_TOPOLOGY));
        assert_eq!(take_counter(&worker.wake), None);
    }

    #[test]
    fn submillisecond_deadline_rounds_up_to_one_millisecond() {
        let worker = WorkerEpoll::new(&MemoryBudget::new(8192), 1).unwrap();
        let mut events = [libc::epoll_event { events: 0, u64: 0 }];
        let interval = Duration::from_nanos(345_678);
        assert_eq!(
            ceil_millis(Some(Duration::from_nanos(1))),
            1,
            "positive submillisecond waits must round up"
        );
        assert_eq!(ceil_millis(Some(interval)), 1);
        assert_eq!(ceil_millis(Some(Duration::from_millis(1))), 1);
        assert_eq!(ceil_millis(Some(Duration::from_nanos(1_000_001))), 2);
        assert_eq!(ceil_millis(Some(Duration::ZERO)), 0);
        let longest_wait = Duration::from_millis(i32::MAX as u64);
        assert_eq!(ceil_millis(Some(longest_wait)), i32::MAX);
        let beyond_limit = longest_wait + Duration::from_nanos(1);
        assert_eq!(ceil_millis(Some(beyond_limit)), i32::MAX);
        assert_eq!(ceil_millis(Some(Duration::MAX)), i32::MAX);
        assert_eq!(ceil_millis(None), -1);
        let now = Instant::now();
        let due = now + interval;
        assert_eq!(worker.wait(Some(due), now, &mut events).unwrap(), 0);
        assert!(Instant::now() >= due);
        let (watched, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        worker
            .add_fd(watched.as_raw_fd(), libc::EPOLLIN as u32, TOKEN_TOPOLOGY)
            .unwrap();
        drop(peer);
        for interval in [Duration::ZERO, beyond_limit] {
            let now = Instant::now();
            let due = now + interval;
            assert_eq!(worker.wait(Some(due), now, &mut events).unwrap(), 1);
            let token = events[0].u64;
            assert_eq!(token, TOKEN_TOPOLOGY);
        }
    }

    #[test]
    fn fixed_watch_capacity_includes_wake_and_follows_fd_owners() {
        let budget = MemoryBudget::new(2 * FD_BYTES + 3 * WATCH_BYTES);
        assert!(WorkerEpoll::new(&budget, usize::MAX).is_err());
        assert!(WorkerEpoll::new(&budget, 3).is_err());
        assert_eq!(budget.used(), 0);
        let worker = WorkerEpoll::new(&budget, 1).unwrap();
        let shared_fd = Arc::clone(&worker.fd);
        shared_fd.retain_watch_credit(budget.reserve(WATCH_BYTES).unwrap());
        let wake = Arc::clone(&worker.wake);
        let (first, second) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(budget.used(), budget.limit());
        let add = |fd| worker.add_fd(fd, libc::EPOLLIN as u32, TOKEN_TOPOLOGY);
        assert!(add(-1).is_err());
        add(first.as_raw_fd()).unwrap();
        assert_eq!(
            add(second.as_raw_fd()).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
        assert!(worker.del_fd(second.as_raw_fd()).is_err());
        worker.del_fd(first.as_raw_fd()).unwrap();
        add(second.as_raw_fd()).unwrap();
        drop(worker);
        assert_eq!(budget.used(), budget.limit());
        drop(shared_fd);
        assert_eq!(budget.used(), FD_BYTES);
        drop(wake);
        assert_eq!(budget.used(), 0);
    }
}
