use super::*;
use crate::relay::RelayProgress;
use crate::stats::OutboundTracker;
use futures::task::AtomicWaker;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::oneshot;

pub(crate) enum DirectOutcome {
    Finished(anyhow::Result<RelayStats>),
    Cancelled,
    Fallback(TcpStream),
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DirectSnapshot {
    pub(crate) attached: bool,
    pub(crate) upload: u64,
    pub(crate) download: u64,
    pub(crate) first_upload: Option<Instant>,
    pub(crate) first_response: Option<Instant>,
    pub(crate) last_upload: Option<Instant>,
    pub(crate) last_download: Option<Instant>,
}

// The worker is the sole writer. The observation parent can sleep through any number
// of updates, including both first-byte edges, without losing their original times.
struct SharedProgress {
    origin: Instant,
    counters: [Arc<AtomicU64>; 2],
    outbound: Option<Arc<OutboundTracker>>,
    revision: AtomicU64,
    upload: AtomicU64,
    download: AtomicU64,
    first_upload: AtomicU64,
    first_response: AtomicU64,
    last_upload: AtomicU64,
    last_download: AtomicU64,
    reader: Option<AtomicWaker>,
    _credit: MemoryReservation,
}

impl SharedProgress {
    fn time(&self, encoded: u64) -> Option<Instant> {
        encoded
            .checked_sub(1)
            .map(|ns| self.origin + Duration::from_nanos(ns))
    }

    fn publish(&self, snapshot: &DirectSnapshot) {
        let encode = |time: Option<Instant>| {
            time.map_or(0, |at| {
                u64::try_from(at.saturating_duration_since(self.origin).as_nanos())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1)
            })
        };
        // AcqRel keeps the odd version ahead of all payload stores; the second
        // release publishes a coherent pair of counts and their event times.
        self.revision.fetch_add(1, Ordering::AcqRel);
        self.upload.store(snapshot.upload, Ordering::Relaxed);
        self.download.store(snapshot.download, Ordering::Relaxed);
        self.first_upload
            .store(encode(snapshot.first_upload), Ordering::Relaxed);
        self.first_response
            .store(encode(snapshot.first_response), Ordering::Relaxed);
        self.last_upload
            .store(encode(snapshot.last_upload), Ordering::Relaxed);
        self.last_download
            .store(encode(snapshot.last_download), Ordering::Relaxed);
        self.revision.fetch_add(1, Ordering::Release);
    }

    fn snapshot(&self) -> (u64, DirectSnapshot) {
        loop {
            let rev = self.revision.load(Ordering::Acquire);
            if rev & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let snapshot = DirectSnapshot {
                attached: rev != 0,
                upload: self.upload.load(Ordering::Relaxed),
                download: self.download.load(Ordering::Relaxed),
                first_upload: self.time(self.first_upload.load(Ordering::Relaxed)),
                first_response: self.time(self.first_response.load(Ordering::Relaxed)),
                last_upload: self.time(self.last_upload.load(Ordering::Relaxed)),
                last_download: self.time(self.last_download.load(Ordering::Relaxed)),
            };
            std::sync::atomic::fence(Ordering::Acquire);
            if self.revision.load(Ordering::Relaxed) == rev {
                return (rev, snapshot);
            }
        }
    }
}

pub(crate) struct DirectObserver {
    shared: Arc<SharedProgress>,
    terminal: Option<oneshot::Receiver<DirectOutcome>>,
    seen: u64,
}

impl DirectObserver {
    pub(crate) fn copy_progress(&self) -> RelayProgress {
        let [upload, download] = &self.shared.counters;
        RelayProgress {
            upload: Arc::clone(upload),
            download: Arc::clone(download),
            outbound: self.shared.outbound.clone(),
            first_response: None,
            on_transfer: None,
        }
    }

    pub(crate) fn poll_update(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(DirectSnapshot, Option<DirectOutcome>)> {
        let Some(receiver) = &mut self.terminal else {
            return Poll::Pending;
        };
        if let Some(reader) = &self.shared.reader {
            reader.register(cx.waker());
        }
        let terminal = match std::pin::Pin::new(receiver).poll(cx) {
            Poll::Ready(Ok(outcome)) => Some(outcome),
            Poll::Ready(Err(_)) => Some(DirectOutcome::Finished(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Direct owner exited before completion",
            )
            .into()))),
            Poll::Pending => None,
        };
        if terminal.is_some() {
            self.terminal = None;
        } else if self.shared.revision.load(Ordering::Acquire) == self.seen {
            return Poll::Pending;
        }
        let (rev, snapshot) = self.shared.snapshot();
        self.seen = rev;
        Poll::Ready((snapshot, terminal))
    }
}

pub(crate) struct DirectAttach {
    pub(super) socket: TcpStream,
    shared: Arc<SharedProgress>,
    terminal: oneshot::Sender<DirectOutcome>,
    observe_live: bool,
}

pub(super) struct Progress {
    shared: Arc<SharedProgress>,
    terminal: oneshot::Sender<DirectOutcome>,
    pub(super) snapshot: DirectSnapshot,
    pub(super) observe_live: bool,
}

impl DirectAttach {
    pub(crate) fn credit(
        reserve: impl FnOnce(usize) -> Option<MemoryReservation>,
    ) -> Option<MemoryReservation> {
        // The two Arc headers and the channel's shared state include both wakers.
        reserve(
            size_of::<SharedProgress>()
                + size_of::<Self>()
                + size_of::<DirectObserver>()
                + size_of::<DirectOutcome>()
                + 256,
        )
    }

    pub(crate) fn new(
        socket: TcpStream,
        progress: &RelayProgress,
        credit: MemoryReservation,
        observe_live: bool,
    ) -> (Self, DirectObserver) {
        let origin = Instant::now();
        let shared = Arc::new(SharedProgress {
            origin,
            revision: 0.into(),
            upload: 0.into(),
            download: 0.into(),
            counters: [Arc::clone(&progress.upload), Arc::clone(&progress.download)],
            outbound: progress.outbound.clone(),
            first_upload: 0.into(),
            first_response: 0.into(),
            last_upload: 0.into(),
            last_download: 0.into(),
            reader: observe_live.then(AtomicWaker::new),
            _credit: credit,
        });
        let (terminal, receiver) = oneshot::channel();
        let observer = DirectObserver {
            shared: Arc::clone(&shared),
            terminal: Some(receiver),
            seen: 0,
        };
        (
            Self {
                socket,
                shared,
                terminal,
                observe_live,
            },
            observer,
        )
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.terminal.is_closed()
    }

    pub(crate) fn reject(self) {
        let _ = self.terminal.send(DirectOutcome::Fallback(self.socket));
    }

    pub(crate) fn cancel(self) {
        drop(self.socket);
        let _ = self.terminal.send(DirectOutcome::Cancelled);
    }

    pub(super) fn accepted(self) -> (TcpStream, Progress) {
        let Self {
            socket,
            shared,
            terminal,
            observe_live,
        } = self;
        let progress = Progress {
            shared,
            terminal,
            snapshot: DirectSnapshot {
                attached: true,
                ..DirectSnapshot::default()
            },
            observe_live,
        };
        // All counters and timestamps are still at their initial values.
        progress.shared.revision.store(2, Ordering::Release);
        if let Some(reader) = &progress.shared.reader {
            reader.wake();
        }
        (socket, progress)
    }
}

impl Progress {
    pub(super) fn add(&mut self, upload: bool, n: usize, now: Instant) {
        let (total, first, last) = if upload {
            (
                &mut self.snapshot.upload,
                &mut self.snapshot.first_upload,
                &mut self.snapshot.last_upload,
            )
        } else {
            (
                &mut self.snapshot.download,
                &mut self.snapshot.first_response,
                &mut self.snapshot.last_download,
            )
        };
        *total += n as u64;
        first.get_or_insert(now);
        *last = Some(now);
        self.shared.counters[usize::from(!upload)].fetch_add(n as u64, Ordering::Relaxed);
        if let Some(outbound) = &self.shared.outbound {
            let counter = if upload {
                &outbound.tx_bytes
            } else {
                &outbound.rx_bytes
            };
            counter.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    pub(super) fn publish(&self) {
        self.shared.publish(&self.snapshot);
        if let Some(reader) = &self.shared.reader {
            reader.wake();
        }
    }

    pub(super) fn finish(self, outcome: DirectOutcome) {
        self.shared.publish(&self.snapshot);
        let _ = self.terminal.send(outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_netstack::MemoryBudget;
    use std::task::{Wake, Waker};

    #[derive(Default)]
    struct WakeCount(AtomicU64);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn quiet_attach_publishes_without_waking_unobserved_reader() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let budget = MemoryBudget::new(8192);
        for live in [false, true] {
            let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let _peer = listener.accept().unwrap();
            let counters = RelayProgress {
                upload: Arc::default(),
                download: Arc::default(),
                outbound: None,
                first_response: None,
                on_transfer: None,
            };
            let (attach, mut observer) = DirectAttach::new(
                socket,
                &counters,
                DirectAttach::credit(|bytes| budget.reserve(bytes)).unwrap(),
                live,
            );
            let count = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&count));
            let mut cx = Context::from_waker(&waker);
            assert!(observer.poll_update(&mut cx).is_pending());
            let (_socket, progress) = attach.accepted();
            assert_eq!(count.0.load(Ordering::Relaxed), u64::from(live));
            assert!(
                matches!(observer.poll_update(&mut cx), Poll::Ready((snapshot, None)) if snapshot.attached)
            );
            assert!(observer.poll_update(&mut cx).is_pending());
            progress.finish(DirectOutcome::Cancelled);
            assert_eq!(count.0.load(Ordering::Relaxed), u64::from(live) + 1);
            assert!(
                matches!(observer.poll_update(&mut cx), Poll::Ready((snapshot, Some(DirectOutcome::Cancelled))) if snapshot.attached)
            );
        }
    }
}
