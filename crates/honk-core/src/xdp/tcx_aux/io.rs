use super::Owner;
use crate::control::netstack::OutputLease;
use crate::tun::{self, BATCH};
use anyhow::{Context as _, ensure};
use honk_datapath::buffer::TxClass;
use honk_netstack::{MemoryBudget, MemoryReservation};
use std::sync::Arc;
use std::{
    io,
    os::fd::AsRawFd,
    task::{Context, Poll},
    time::Instant,
};
use tokio::io::unix::AsyncFd;

#[cfg(feature = "ebpf")]
struct InputDrain {
    cutoff: u64,
    remaining: Option<u64>,
}

pub(super) struct Records {
    rx: Box<[u8]>,
    pending: [[Option<OutputLease>; BATCH]; 2],
    first: usize,
    #[cfg(feature = "ebpf")]
    drain: Option<InputDrain>,
    #[cfg(feature = "ebpf")]
    host_reads: Option<u64>,
    _memory: MemoryReservation,
}

impl Records {
    pub(super) fn new(budget: &Arc<MemoryBudget>, name_bytes: usize) -> anyhow::Result<Box<Self>> {
        let memory = budget
            .reserve(tun::RX_BYTES + size_of::<Self>() + name_bytes)
            .context("auxiliary full vnet record and pending output capacity")?;
        Ok(Box::new(Self {
            rx: vec![0; tun::RX_BYTES].into_boxed_slice(),
            pending: std::array::from_fn(|_| std::array::from_fn(|_| None)),
            first: 0,
            #[cfg(feature = "ebpf")]
            drain: None,
            #[cfg(feature = "ebpf")]
            host_reads: None,
            _memory: memory,
        }))
    }

    pub(super) fn dispose(&mut self) {
        #[cfg(feature = "ebpf")]
        {
            self.drain = None;
            self.host_reads = None;
        }
        for lease in self.pending.iter_mut().flatten() {
            drop(lease.take());
        }
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn discard_before_host_open(
        &mut self,
        fd: std::os::fd::RawFd,
    ) -> anyhow::Result<bool> {
        let now = Instant::now();
        let mut bytes = 0;
        for attempt in 0..BATCH {
            if tun::turn_limit(attempt, bytes, now, BATCH) {
                break;
            }
            match tun::read_packet(fd, &mut self.rx) {
                Ok(0) => anyhow::bail!("EOF draining closed Host TUN"),
                Ok(length) => bytes += length,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Any records queued before the filter's installation grace are gone.
                    self.host_reads = Some(0);
                    return Ok(true);
                }
                Err(e) => return Err(e).context("draining closed Host TUN"),
            }
        }
        Ok(false)
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn draining(&self) -> bool {
        self.drain.is_some()
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn request_drain(&mut self, cutoff: u64, passed: Option<u64>) {
        // Candidates dropped between the final filter and enqueue only increase this bound.
        let remaining = self
            .host_reads
            .zip(passed)
            .and_then(|(read, passed)| passed.checked_sub(read));
        self.drain = Some(InputDrain { cutoff, remaining });
    }

    #[cfg(feature = "ebpf")]
    fn completed(&mut self, count: usize) {
        let count = count as u64;
        self.host_reads = self.host_reads.and_then(|r| r.checked_add(count));
        if let Some(drain) = &mut self.drain {
            drain.remaining = self
                .host_reads
                .and(drain.remaining)
                .map(|left| left.saturating_sub(count));
        }
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn take_drained_cutoff(&mut self) -> Option<u64> {
        self.drain
            .take_if(|drain| drain.remaining == Some(0))
            .map(|drain| drain.cutoff)
    }

    pub(super) fn service<T: AsRawFd>(
        &mut self,
        io: &AsyncFd<T>,
        owner: &mut Owner,
        cx: &mut Context<'_>,
    ) -> anyhow::Result<bool> {
        let now = Instant::now();
        let mut more = self.read(
            io,
            cx,
            now,
            || owner.open(),
            |record| {
                if let Some((packet, meta)) = tun::decode_record(record) {
                    tun::admit_packet(
                        &owner.endpoints,
                        owner.driver.scope(),
                        packet,
                        meta,
                        now,
                        |_, _| owner.open(),
                    )?;
                }
                Ok(())
            },
        )?;
        more |= owner.driver.service(cx, Instant::now());
        let mut bytes = 0;
        let mut attempts = 0;
        for offset in 0..2 {
            let class = (self.first + offset) % 2;
            let pending = &mut self.pending[class];
            if pending.iter().all(Option::is_none) {
                match owner.driver.poll_outputs_class(
                    cx,
                    [TxClass::Control, TxClass::Bulk][class],
                    pending,
                ) {
                    Poll::Ready(None) if owner.open() => {
                        anyhow::bail!("auxiliary packet driver ended before close")
                    }
                    Poll::Ready(Some(count)) => more |= count == BATCH,
                    _ => {}
                }
            }
            if pending.iter().any(Option::is_some) {
                more |= tun::poll_flush(io, cx, pending, &mut attempts, &mut bytes, now, || {
                    owner.open()
                })?;
            }
        }
        self.first ^= 1;
        owner.driver.finish_turn(cx, Instant::now());
        Ok(more)
    }

    fn read<T: AsRawFd>(
        &mut self,
        io: &AsyncFd<T>,
        cx: &mut Context<'_>,
        now: Instant,
        open: impl Fn() -> bool,
        mut admit: impl FnMut(&[u8]) -> anyhow::Result<()>,
    ) -> anyhow::Result<bool> {
        #[cfg(feature = "ebpf")]
        let probing = self.drain.is_some();
        #[cfg(not(feature = "ebpf"))]
        let probing = false;
        // Read the FD itself when proving a drain, even if the readiness cache is empty.
        let mut ready = match io.poll_read_ready(cx) {
            Poll::Ready(result) => Some(result?),
            Poll::Pending if probing => None,
            Poll::Pending => return Ok(false),
        };
        let mut bytes = 0;
        let mut attempts = 0;
        #[cfg(feature = "ebpf")]
        let mut interrupted = 0;
        while attempts < BATCH {
            if !open() {
                return Ok(false);
            }
            if tun::turn_limit(attempts, bytes, now, BATCH) {
                break;
            }
            attempts += 1;
            let length = match tun::read_packet(io.get_ref().as_raw_fd(), &mut self.rx) {
                Ok(length) => length,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    #[cfg(feature = "ebpf")]
                    {
                        interrupted += 1;
                    }
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    #[cfg(feature = "ebpf")]
                    self.completed(attempts - interrupted - 1);
                    #[cfg(feature = "ebpf")]
                    if let Some(drain) = &mut self.drain {
                        drain.remaining = Some(0);
                    }
                    if let Some(ready) = &mut ready {
                        ready.clear_ready();
                    }
                    return match io.poll_read_ready(cx) {
                        Poll::Ready(result) => result.map(|_| true).map_err(Into::into),
                        Poll::Pending => Ok(false),
                    };
                }
                Err(e) => return Err(e).context("read private TUN record"),
            };
            ensure!(
                length != 0 && length < self.rx.len(),
                "private TUN returned EOF or oversized record"
            );
            bytes += length;
            admit(&self.rx[..length])?;
        }
        #[cfg(feature = "ebpf")]
        self.completed(attempts - interrupted);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ebpf")]
    #[tokio::test]
    async fn host_input_drain_requires_completed_reads_or_fd_eagain() {
        use std::os::unix::net::UnixDatagram;

        let (reader, writer) = UnixDatagram::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        // SAFETY: reader owns its descriptor for the lifetime of the registration.
        let reader = unsafe { AsyncFd::register(reader) }.unwrap();
        let mut records = Records::new(&MemoryBudget::new(1 << 20), 0).unwrap();
        writer.send(b"before filter installation").unwrap();
        let mut cached = reader.readable().await.unwrap();
        assert!(
            records
                .discard_before_host_open(reader.get_ref().as_raw_fd())
                .unwrap()
        );
        cached.clear_ready();
        drop(cached);
        assert_eq!(records.host_reads, Some(0));
        records.request_drain(11, None);
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(reader.poll_read_ready(&mut cx).is_pending());
        writer.send(b"first").unwrap();
        assert!(
            records
                .read(
                    &reader,
                    &mut cx,
                    Instant::now(),
                    || true,
                    |record| {
                        assert_eq!(record, b"first");
                        anyhow::bail!("admission failed")
                    }
                )
                .is_err()
        );
        assert_eq!(records.take_drained_cutoff(), None);
        assert_eq!(records.host_reads, Some(0));

        records
            .read(
                &reader,
                &mut cx,
                Instant::now(),
                || true,
                |_| unreachable!(),
            )
            .unwrap();
        assert_eq!(records.take_drained_cutoff(), Some(11));
        records.dispose();
        assert_eq!(records.host_reads, None);

        records.host_reads = Some(10);
        records.request_drain(12, Some(13));
        writer.send(b"next").unwrap();
        let mut admitted = 0;
        assert!(
            records
                .read(
                    &reader,
                    &mut cx,
                    Instant::now(),
                    || true,
                    |record| {
                        assert_eq!(record, b"next");
                        writer.send(b"next").unwrap();
                        admitted += 1;
                        Ok(())
                    }
                )
                .unwrap()
        );
        assert!((3..=BATCH).contains(&admitted));
        assert_eq!(records.take_drained_cutoff(), Some(12));
        assert_eq!(records.host_reads, Some(10 + admitted as u64));
        records.request_drain(13, Some(1));
        assert_eq!(records.take_drained_cutoff(), None);
        assert_eq!(records.drain.as_ref().unwrap().remaining, None);
        assert_eq!(reader.get_ref().recv(&mut [0; 8]).unwrap(), 4);
    }

    #[test]
    fn full_record_and_both_pending_classes_must_fit_the_same_slice() {
        let names = 20;
        let bytes = tun::RX_BYTES + size_of::<Records>() + names;
        let root = MemoryBudget::new(4 << 20);
        let slice = root.child(root.limit()).unwrap();
        let other = slice.reserve(slice.limit() - bytes + 1).unwrap();
        assert!(Records::new(&slice, names).is_err());
        assert_eq!(slice.used(), slice.limit() - bytes + 1);
        drop(other);
        let io = Records::new(&slice, names).unwrap();
        assert_eq!(io.rx.len(), tun::RX_BYTES);
        assert_eq!(slice.used(), bytes);
        drop(slice);
        assert_eq!(root.used(), root.limit());
        drop(io);
        assert_eq!(root.used(), 0);
    }
}
