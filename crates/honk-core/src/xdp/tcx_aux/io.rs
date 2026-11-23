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

pub(super) struct Records {
    rx: Box<[u8]>,
    pending: [[Option<OutputLease>; BATCH]; 2],
    first: usize,
    _memory: MemoryReservation,
}

impl Records {
    pub(super) fn new(budget: &Arc<MemoryBudget>, name_bytes: usize) -> anyhow::Result<Box<Self>> {
        let memory = budget
            .reserve(tun::RX_BYTES + size_of::<Self>() + name_bytes)
            .context("L3 LAN full vnet record and pending output capacity")?;
        Ok(Box::new(Self {
            rx: vec![0; tun::RX_BYTES].into_boxed_slice(),
            pending: std::array::from_fn(|_| std::array::from_fn(|_| None)),
            first: 0,
            _memory: memory,
        }))
    }

    pub(super) fn dispose(&mut self) {
        for lease in self.pending.iter_mut().flatten() {
            drop(lease.take());
        }
    }

    pub(super) fn service<T: AsRawFd>(
        &mut self,
        io: &AsyncFd<T>,
        owner: &mut Owner,
        cx: &mut Context<'_>,
    ) -> anyhow::Result<bool> {
        let now = Instant::now();
        let mut more = self.read(io, owner, cx, now)?;
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
                        anyhow::bail!("L3 LAN packet driver ended before close")
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
        owner: &Owner,
        cx: &mut Context<'_>,
        now: Instant,
    ) -> anyhow::Result<bool> {
        let Poll::Ready(ready) = io.poll_read_ready(cx) else {
            return Ok(false);
        };
        let mut ready = ready?;
        let mut bytes = 0;
        for attempt in 0..BATCH {
            if !owner.open() {
                return Ok(false);
            }
            if tun::turn_limit(attempt, bytes, now, BATCH) {
                return Ok(true);
            }
            let length =
                match ready.try_io(|fd| tun::read_packet(fd.get_ref().as_raw_fd(), &mut self.rx)) {
                    Ok(Ok(length)) => length,
                    Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(e)) => return Err(e).context("read private TUN record"),
                    Err(_) => {
                        return match io.poll_read_ready(cx) {
                            Poll::Ready(result) => result.map(|_| true).map_err(Into::into),
                            Poll::Pending => Ok(false),
                        };
                    }
                };
            ensure!(
                length != 0 && length < self.rx.len(),
                "private TUN returned EOF or oversized record"
            );
            bytes += length;
            if let Some((packet, meta)) = tun::decode_record(&self.rx[..length]) {
                tun::admit_packet(
                    &owner.endpoints,
                    owner.driver.scope(),
                    packet,
                    meta,
                    now,
                    |_, _| owner.open(),
                )?;
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
