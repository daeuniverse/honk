use crate::control::{
    netstack::{PacketDriver, PacketRealm},
    packet_endpoint::PacketEndpoints,
};
use crate::tun::{
    BATCH, MAX_IP_BYTES, RX_BYTES, decode_record, poll_outputs, read_packet, turn_limit,
};
use anyhow::{Context as _, ensure};
use futures::task::AtomicWaker;
use honk_netstack::{MemoryBudget, MemoryReservation, OwnedPacket, RxMeta, wire};
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    io,
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};
use tokio::io::unix::AsyncFd;

const CELLS: usize = 64;
const PER_QUEUE: usize = 32;

struct Record {
    // A raw record owns its bytes. A completion moves its original funded packet and uses
    // the empty cell solely as one of the 64 global handoff credits.
    cell: Vec<u8>,
    complete: Option<OwnedPacket>,
    meta: RxMeta,
    ingress_at: Instant,
}

struct Inbox {
    records: Mutex<VecDeque<Record>>,
    ready: AtomicWaker,
    capacity_drops: std::sync::atomic::AtomicU64,
}

struct Handoffs {
    free: Mutex<Vec<Vec<u8>>>,
    inboxes: Vec<Inbox>,
    _memory: MemoryReservation,
}

impl Handoffs {
    fn send(
        &self,
        target: usize,
        raw: &[u8],
        complete: Option<OwnedPacket>,
        meta: RxMeta,
        ingress_at: Instant,
    ) {
        let inbox = &self.inboxes[target];
        let mut records = inbox.records.lock();
        let cell = if records.len() < PER_QUEUE {
            self.free.lock().pop()
        } else {
            None
        };
        if let Some(mut cell) = cell {
            cell.clear();
            cell.extend_from_slice(raw);
            let wake = records.is_empty();
            records.push_back(Record {
                cell,
                complete,
                meta,
                ingress_at,
            });
            drop(records);
            if wake {
                inbox.ready.wake();
            }
            return;
        }
        drop(records);
        let count = inbox
            .capacity_drops
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        if count == 1 {
            tracing::warn!(
                queue = target,
                capacity_drops = count,
                "TUN handoff reached capacity"
            );
        }
    }
}

impl Drop for Handoffs {
    fn drop(&mut self) {
        for (queue, inbox) in self.inboxes.iter_mut().enumerate() {
            let capacity_drops = *inbox.capacity_drops.get_mut();
            if capacity_drops != 0 {
                tracing::info!(queue, capacity_drops, "TUN handoff stopped");
            }
        }
    }
}

pub(super) struct QueueIo {
    index: usize,
    rx: Vec<u8>,
    first_group: usize,
    handoffs: Arc<Handoffs>,
}

impl QueueIo {
    pub(super) fn prepare(count: usize, budget: &Arc<MemoryBudget>) -> anyhow::Result<Vec<Self>> {
        ensure!(
            (2..=usize::from(honk_config::datapath::MAX_TUN_QUEUES)).contains(&count),
            "invalid multiqueue TUN worker count"
        );
        // count is bounded above before sizing. Include every reserved queue position even
        // though only CELLS positions across the device can hold live records at once.
        let per_queue =
            RX_BYTES + size_of::<Self>() + size_of::<Inbox>() + PER_QUEUE * size_of::<Record>();
        let bytes = count * per_queue
            + CELLS * (MAX_IP_BYTES + size_of::<Vec<u8>>())
            + size_of::<Handoffs>()
            + 2 * size_of::<usize>();
        let memory = budget
            .reserve(bytes)
            .context("TUN multiqueue buffer budget")?;
        let mut free = Vec::new();
        free.try_reserve_exact(CELLS)?;
        for _ in 0..CELLS {
            let mut cell = Vec::new();
            cell.try_reserve_exact(MAX_IP_BYTES)?;
            free.push(cell);
        }
        let mut inboxes = Vec::new();
        inboxes.try_reserve_exact(count)?;
        for _ in 0..count {
            let mut records = VecDeque::new();
            records.try_reserve_exact(PER_QUEUE)?;
            inboxes.push(Inbox {
                records: Mutex::new(records),
                ready: AtomicWaker::new(),
                capacity_drops: Default::default(),
            });
        }
        let handoffs = Arc::new(Handoffs {
            free: Mutex::new(free),
            inboxes,
            _memory: memory,
        });
        let mut workers = Vec::new();
        workers.try_reserve_exact(count)?;
        for index in 0..count {
            let mut rx = Vec::new();
            rx.try_reserve_exact(RX_BYTES)?;
            rx.resize(RX_BYTES, 0);
            workers.push(Self {
                index,
                rx,
                first_group: 0,
                handoffs: Arc::clone(&handoffs),
            });
        }
        Ok(workers)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn poll<T: AsRawFd>(
        &mut self,
        cx: &mut Context<'_>,
        io: &AsyncFd<T>,
        driver: &mut PacketDriver,
        endpoints: &PacketEndpoints,
        realm: &PacketRealm,
        admission: &AtomicBool,
        now: Instant,
    ) -> anyhow::Result<bool> {
        debug_assert_eq!(driver.worker(), self.index);
        let turn = ReceiveTurn {
            index: self.index,
            handoffs: &self.handoffs,
            realm,
            endpoints,
            admission,
        };
        if !turn.open() {
            return Ok(false);
        }
        // Independently bound each source, so a continuously full inbox or readable FD
        // cannot consume the other's turn or delay this shard's output indefinitely.
        let inbox_more = turn.drain(cx)?;
        let read_more = turn.read(io, cx, &mut self.rx, now)?;
        if !turn.open() {
            return Ok(false);
        }
        let tx_now = Instant::now();
        driver.begin_turn(tx_now);
        let write_more = poll_outputs(
            io,
            std::slice::from_mut(driver),
            &mut self.first_group,
            cx,
            tx_now,
            || turn.open(),
        )?;
        Ok(inbox_more || read_more || write_more)
    }
}

struct ReceiveTurn<'a> {
    index: usize,
    handoffs: &'a Handoffs,
    realm: &'a PacketRealm,
    endpoints: &'a PacketEndpoints,
    admission: &'a AtomicBool,
}

impl ReceiveTurn<'_> {
    fn open(&self) -> bool {
        self.admission.load(Ordering::Acquire) && !self.endpoints.is_closing()
    }

    fn read<T: AsRawFd>(
        &self,
        io: &AsyncFd<T>,
        cx: &mut Context<'_>,
        rx: &mut [u8],
        ingress_at: Instant,
    ) -> anyhow::Result<bool> {
        let mut ready = match io.poll_read_ready(cx) {
            Poll::Ready(result) => result?,
            Poll::Pending => return Ok(false),
        };
        let started = Instant::now();
        let mut bytes = 0;
        for attempt in 0..BATCH {
            if !self.open() {
                return Ok(false);
            }
            if turn_limit(attempt, bytes, started, BATCH) {
                return Ok(true);
            }
            let len = match ready.try_io(|inner| read_packet(inner.get_ref().as_raw_fd(), rx)) {
                Ok(Ok(len)) => len,
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(error).context("multiqueue TUN packet read"),
                Err(_) => {
                    // EAGAIN consumed the cached edge. Register before allowing a park.
                    return match io.poll_read_ready(cx) {
                        Poll::Ready(result) => {
                            drop(result?);
                            Ok(true)
                        }
                        Poll::Pending => Ok(false),
                    };
                }
            };
            ensure!(len != 0, "TUN packet reader reached EOF");
            ensure!(
                len < RX_BYTES,
                "TUN record exceeds vnet and ordinary IP representation"
            );
            bytes += len;
            if let Some((packet, meta)) = decode_record(&rx[..len]) {
                self.raw(packet, meta, ingress_at)?;
            }
        }
        Ok(true)
    }

    fn raw(&self, packet: &[u8], meta: RxMeta, ingress_at: Instant) -> io::Result<()> {
        // dispatch_owner maps fragments (before transport parsing) to owner zero.
        let (owner, _) = self
            .realm
            .dispatch_owner(self.index, wire::PacketView::from_slice(packet))?;
        let target = owner.worker();
        if target != self.index {
            self.handoffs.send(target, packet, None, meta, ingress_at);
            return Ok(());
        }
        if let Some(complete) = self.local(packet, meta, ingress_at)? {
            self.completed(complete)?;
        }
        Ok(())
    }

    fn local(
        &self,
        packet: &[u8],
        meta: RxMeta,
        ingress_at: Instant,
    ) -> io::Result<Option<OwnedPacket>> {
        let service_at = Instant::now();
        if self.index == 0 && matches!(wire::parse_ip(packet), Err(wire::ParseError::Fragment)) {
            return Ok(self.realm.owners()[0]
                .reassemble_for_dispatch(packet, ingress_at, service_at)
                .ok()
                .flatten());
        }
        self.admit(packet, meta, ingress_at, service_at)?;
        Ok(None)
    }

    fn completed(&self, packet: OwnedPacket) -> io::Result<()> {
        let ingress_at = packet.completion_ingress();
        let (owner, _) = self
            .realm
            .dispatch_owner(0, wire::PacketView::from_slice(&packet))?;
        if owner.worker() == 0 {
            self.admit(&packet, RxMeta::VERIFY, ingress_at, Instant::now())
        } else {
            self.handoffs.send(
                owner.worker(),
                &[],
                Some(packet),
                RxMeta::VERIFY,
                ingress_at,
            );
            Ok(())
        }
    }

    fn admit(
        &self,
        packet: &[u8],
        meta: RxMeta,
        ingress_at: Instant,
        service_at: Instant,
    ) -> io::Result<()> {
        match self.endpoints.receive_tun_on(
            &self.realm.owners()[self.index],
            packet,
            meta,
            ingress_at,
            service_at,
            |_, _| self.open(),
        ) {
            Ok(_) => Ok(()),
            Err(error)
                if !self.open()
                    || matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                    ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn drain(&self, cx: &mut Context<'_>) -> io::Result<bool> {
        let inbox = &self.handoffs.inboxes[self.index];
        let started = Instant::now();
        let mut bytes = 0;
        for attempt in 0..BATCH {
            if !self.open() {
                return Ok(false);
            }
            if turn_limit(attempt, bytes, started, BATCH) {
                return Ok(true);
            }
            let record = {
                let mut records = inbox.records.lock();
                let Some(record) = records.pop_front() else {
                    // register under the same lock as empty -> nonempty publication
                    inbox.ready.register(cx.waker());
                    return Ok(false);
                };
                record
            };
            let packet = record.complete.as_deref().unwrap_or(&record.cell);
            bytes += packet.len();
            let result = self.local(packet, record.meta, record.ingress_at);
            // The final fragment's credit is available for the second handoff even when
            // this drain started with all 64 cells occupied.
            self.handoffs.free.lock().push(record.cell);
            if let Some(complete) = result? {
                self.completed(complete)?;
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
