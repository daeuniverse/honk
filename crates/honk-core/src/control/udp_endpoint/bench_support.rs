//! Synchronous production-path harnesses for the UDP Criterion benchmark.
//!
//! These helpers exercise the production reservation and Ready fast-path
//! state machines without duplicating them. They create no socket, runtime,
//! or task; all resources are dropped and checked before a batch returns.

use super::{
    EndpointReservation, FLOW_QUEUE_CAPACITY, GLOBAL_PAYLOAD_CAPACITY, UdpEndpoint, UdpEndpointPool,
};
use crate::stats::StatsManager;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};

const BENCH_CLIENT: &str = "192.0.2.10:40000";
const BENCH_DESTINATION: &str = "198.51.100.53:5353";

#[derive(Debug)]
struct BenchPacketTransport {
    relay: SocketAddr,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketTransport for BenchPacketTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
        Err(io::Error::other("benchmark transport must not send"))
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::other("benchmark transport must not receive"))
    }
}

fn bench_addresses() -> (SocketAddr, SocketAddr) {
    (
        BENCH_CLIENT
            .parse()
            .unwrap_or_else(|error| panic!("invalid benchmark client address: {error}")),
        BENCH_DESTINATION
            .parse()
            .unwrap_or_else(|error| panic!("invalid benchmark destination address: {error}")),
    )
}

fn acquire_slow_permit(slots: &Arc<Semaphore>) -> tokio::sync::OwnedSemaphorePermit {
    slots
        .clone()
        .try_acquire_owned()
        .unwrap_or_else(|error| panic!("benchmark slow-path permit must be available: {error}"))
}

fn assert_released(pool: &UdpEndpointPool, slow_slots: &Semaphore, slow_capacity: usize) {
    assert!(
        pool.endpoints.is_empty(),
        "benchmark left a UDP mapping behind"
    );
    assert_eq!(
        pool.endpoint_slots.available_permits(),
        1,
        "benchmark leaked an endpoint slot"
    );
    assert_eq!(
        pool.global_payload_bytes.available_permits(),
        GLOBAL_PAYLOAD_CAPACITY,
        "benchmark leaked UDP payload-byte permits"
    );
    assert_eq!(
        slow_slots.available_permits(),
        slow_capacity,
        "benchmark leaked a slow-path permit"
    );
}

struct QueuedBatch {
    pool: Arc<UdpEndpointPool>,
    stats: StatsManager,
    slow_slots: Arc<Semaphore>,
    slow_capacity: usize,
    client: SocketAddr,
    destination: SocketAddr,
    receiver: mpsc::Receiver<super::QueuedDatagram>,
    enqueued_at: u32,
    _lease: super::UdpInitLease,
}

impl QueuedBatch {
    fn new(slow_capacity: usize, first: &[u8]) -> Self {
        let pool = Arc::new(UdpEndpointPool::with_capacity_limit(1));
        let stats = StatsManager::new();
        let slow_slots = Arc::new(Semaphore::new(slow_capacity));
        let (client, destination) = bench_addresses();
        let enqueued_at = super::queue_now();
        let lease = match pool.reserve_or_enqueue_at(
            client,
            destination,
            first,
            acquire_slow_permit(&slow_slots),
            enqueued_at,
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("benchmark must reserve its initial UDP mapping"),
        };
        let receiver = lease
            .take_queue_receiver()
            .unwrap_or_else(|| panic!("benchmark reservation must own a queue receiver"));
        Self {
            pool,
            stats,
            slow_slots,
            slow_capacity,
            client,
            destination,
            receiver,
            enqueued_at,
            _lease: lease,
        }
    }

    fn enqueue(&mut self, payload: &[u8]) -> EndpointReservation {
        self.pool.reserve_or_enqueue_at(
            self.client,
            self.destination,
            payload,
            acquire_slow_permit(&self.slow_slots),
            self.enqueued_at,
            &self.stats,
        )
    }
}

struct ReadyBatch {
    pool: Arc<UdpEndpointPool>,
    stats: StatsManager,
    slow_slots: Arc<Semaphore>,
    slow_capacity: usize,
    client: SocketAddr,
    destination: SocketAddr,
    receiver: mpsc::Receiver<super::QueuedDatagram>,
    enqueued_at: u32,
}

impl ReadyBatch {
    fn new(first: &[u8]) -> Self {
        let QueuedBatch {
            pool,
            stats,
            slow_slots,
            slow_capacity,
            client,
            destination,
            receiver,
            enqueued_at,
            _lease: mut lease,
        } = QueuedBatch::new(1, first);
        drop(
            lease
                .take_first()
                .unwrap_or_else(|| panic!("benchmark reservation must retain its first datagram")),
        );
        let endpoint = Arc::new(UdpEndpoint::new(
            Arc::new(BenchPacketTransport { relay: destination }),
            destination,
            uuid::Uuid::from_u128(0xbe9c4),
        ));
        assert!(
            lease.commit_ready(endpoint),
            "benchmark reservation must commit a Ready mapping"
        );
        drop(lease);
        Self {
            pool,
            stats,
            slow_slots,
            slow_capacity,
            client,
            destination,
            enqueued_at,
            receiver,
        }
    }

    fn enqueue(&self, payload: &[u8]) -> EndpointReservation {
        self.pool
            .fast_path_enqueue_at(
                self.client,
                self.destination,
                payload,
                self.enqueued_at,
                &self.stats,
            )
            .unwrap_or_else(|| panic!("benchmark Ready mapping must hit the UDP fast path"))
    }

    fn drain_one(&mut self) {
        drop(self.receiver.try_recv().unwrap_or_else(|error| {
            panic!("benchmark Ready enqueue must produce one datagram: {error}")
        }));
    }

    fn release_and_assert(self) {
        let (remove_tx, mut remove_rx) = mpsc::channel(1);
        self.pool.set_remove_sink(remove_tx);
        self.pool.remove(self.client, self.destination);
        let removal = remove_rx
            .try_recv()
            .unwrap_or_else(|error| panic!("benchmark removal must be published: {error}"));
        assert!(self.pool.complete_removal(
            removal.client,
            removal.dst,
            removal.decision_token,
            removal.generation,
        ));
        let pool = Arc::clone(&self.pool);
        let slow_slots = Arc::clone(&self.slow_slots);
        let slow_capacity = self.slow_capacity;
        drop(self);
        assert_released(&pool, &slow_slots, slow_capacity);
    }
}

/// Run one 128-byte steady-enqueue batch through the Ready fast path.
#[doc(hidden)]
pub fn steady_enqueue_128_batch(iterations: usize) {
    assert!(iterations > 0, "benchmark batch must be non-empty");
    let payload = [0xA5; 128];
    let mut batch = ReadyBatch::new(&payload);
    for _ in 0..iterations {
        assert!(matches!(
            batch.enqueue(&payload),
            EndpointReservation::Enqueued
        ));
        batch.drain_one();
    }
    assert_eq!(batch.stats.udp_snapshot().queue_accepted, iterations as u64);
    batch.release_and_assert();
}

/// Repeatedly reserve then roll back a cold mapping through its real Drop path.
#[doc(hidden)]
pub fn reserve_rollback_batch(iterations: usize) {
    assert!(iterations > 0, "benchmark batch must be non-empty");
    let pool = Arc::new(UdpEndpointPool::with_capacity_limit(1));
    let stats = StatsManager::new();
    let slow_slots = Arc::new(Semaphore::new(iterations));
    let (client, destination) = bench_addresses();
    let (remove_tx, mut remove_rx) = mpsc::channel(1);
    pool.set_remove_sink(remove_tx);
    let enqueued_at = super::queue_now();

    for _ in 0..iterations {
        let lease = match pool.reserve_or_enqueue_at(
            client,
            destination,
            b"rollback",
            acquire_slow_permit(&slow_slots),
            enqueued_at,
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("rollback benchmark must reserve a fresh mapping"),
        };
        drop(lease);
        let removal = remove_rx
            .try_recv()
            .unwrap_or_else(|error| panic!("rollback removal must be published: {error}"));
        assert!(pool.complete_removal(
            removal.client,
            removal.dst,
            removal.decision_token,
            removal.generation,
        ));
        assert_released(&pool, &slow_slots, iterations);
    }
}

/// Repeatedly take the first-reply metric after its one true result.
#[doc(hidden)]
pub fn first_reply_metric_hot_batch(iterations: usize) {
    assert!(iterations > 0, "benchmark batch must be non-empty");
    let (_, destination) = bench_addresses();
    let endpoint = UdpEndpoint::new(
        Arc::new(BenchPacketTransport { relay: destination }),
        destination,
        uuid::Uuid::from_u128(0xbe9c4),
    );
    assert!(endpoint.take_first_reply_metric().is_some());
    for _ in 0..iterations {
        assert!(endpoint.take_first_reply_metric().is_none());
    }
}

/// Prepared fixture for filling the exact 64-datagram bound and dropping newest.
#[doc(hidden)]
pub struct QueueSaturationBenchmark(QueuedBatch);

impl QueueSaturationBenchmark {
    pub fn new() -> Self {
        Self(QueuedBatch::new(FLOW_QUEUE_CAPACITY + 1, b"first"))
    }

    pub fn run(mut self) -> Self {
        for _ in 0..FLOW_QUEUE_CAPACITY - 1 {
            assert!(matches!(
                self.0.enqueue(b"follower"),
                EndpointReservation::Enqueued
            ));
        }
        assert!(matches!(
            self.0.enqueue(b"newest"),
            EndpointReservation::QueueFull
        ));

        let snapshot = self.0.stats.udp_snapshot();
        assert_eq!(snapshot.queue_accepted, (FLOW_QUEUE_CAPACITY - 1) as u64);
        assert_eq!(snapshot.flow_queue_full, 1);
        self
    }
}

impl Default for QueueSaturationBenchmark {
    fn default() -> Self {
        Self::new()
    }
}
