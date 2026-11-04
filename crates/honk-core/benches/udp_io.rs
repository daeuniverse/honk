//! Real-I/O UDP benchmark: production endpoint driver, loopback reply sockets.
//!
//! Pipeline per packet: `fast_path_enqueue_at` -> driver `send_one` ->
//! transport -> echo peer -> receive loop / source receiver -> anyfrom-style
//! reply socket -> client socket. Runtime, peers, mappings, carriers and the
//! first (flow-creating) datagram are built once per workload, outside the
//! timed region; the timed region is a fixed batch of steady-state packets
//! with a bounded in-flight window (closed loop, nothing is dropped).
//!
//! Everything runs on one current-thread runtime, so wall time per packet is
//! the summed CPU cost of the production path plus the (constant) peer. Each
//! workload also prints allocations per packet and process CPU per packet.
//!
//! Run: `cargo bench -p honk-core --features udp-bench --bench udp_io -- --save-baseline <sha>`.
//! A new transport shape adds one workload fn that builds an [`IoHarness`]
//! through an `install_*` constructor and returns a [`Workload`].

use async_trait::async_trait;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use honk_core::control::udp_endpoint::bench_support::real_io::{Enqueue, IoHarness};
use honk_outbound::proxy::{MultiTargetTransport, PacketTransport};
use nix::time::{ClockId, clock_gettime};
use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::Notify;

#[path = "udp_io/backend.rs"]
mod backend;
#[cfg(feature = "rprx")]
#[path = "udp_io/source.rs"]
mod source;

#[cfg(feature = "jemalloc")]
type Backing = tikv_jemallocator::Jemalloc;
#[cfg(not(feature = "jemalloc"))]
type Backing = std::alloc::System;

/// The shipped allocator (jemalloc by default) plus relaxed event counters.
struct Counting(Backing);

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static FREES: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

// SAFETY: every method forwards unchanged to the backing allocator.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { self.0.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { self.0.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        FREES.fetch_add(1, Ordering::Relaxed);
        unsafe { self.0.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        unsafe { self.0.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting(Backing {});

fn alloc_counters() -> [u64; 4] {
    [
        ALLOCS.load(Ordering::Relaxed),
        FREES.load(Ordering::Relaxed),
        REALLOCS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
    ]
}

/// Packets per timed iteration and per allocation pass.
const PACKETS: usize = 8192;
const PAYLOAD: usize = 128;
/// Packets in flight; below the per-flow queue capacity (64) so nothing drops.
const WINDOW: usize = 32;
const PUMP_TIMEOUT: Duration = Duration::from_secs(30);

/// Blocks a transport's sends while closed. Models one destination whose
/// send path is stuck; the driver's 5 s send timeout bounds one iteration.
#[derive(Debug, Default)]
struct Gate {
    blocked: AtomicBool,
    opened: Notify,
}

impl Gate {
    fn set_blocked(&self, blocked: bool) {
        self.blocked.store(blocked, Ordering::Release);
        if !blocked {
            self.opened.notify_waiters();
        }
    }

    async fn pass(&self) {
        while self.blocked.load(Ordering::Acquire) {
            let opened = self.opened.notified();
            if !self.blocked.load(Ordering::Acquire) {
                break;
            }
            opened.await;
        }
    }
}

/// Allocation-free in-memory echo: sends queue, `recv_packet` pops and names
/// the peer the datagram was sent to. As a `PacketTransport` that peer is the
/// fixed `relay`; as a `MultiTargetTransport` it is the per-call target.
#[derive(Debug)]
struct EchoTransport {
    relay: SocketAddr,
    queue: Mutex<VecDeque<(usize, [u8; PAYLOAD], SocketAddr)>>,
    ready: Notify,
    gate: Arc<Gate>,
}

impl EchoTransport {
    fn new(relay: SocketAddr, gate: Arc<Gate>) -> Arc<Self> {
        Arc::new(Self {
            relay,
            queue: Mutex::new(VecDeque::with_capacity(4 * WINDOW)),
            ready: Notify::new(),
            gate,
        })
    }
}

impl EchoTransport {
    /// The one send path of both trait entry points.
    async fn echo(&self, peer: SocketAddr, data: &[u8]) -> std::io::Result<()> {
        self.gate.pass().await;
        let mut packet = [0u8; PAYLOAD];
        packet
            .get_mut(..data.len())
            .ok_or_else(|| std::io::Error::other("bench packet too large"))?
            .copy_from_slice(data);
        self.queue
            .lock()
            .expect("echo queue")
            .push_back((data.len(), packet, peer));
        self.ready.notify_one();
        Ok(())
    }
}

#[async_trait]
impl MultiTargetTransport for EchoTransport {
    async fn send_to(
        &self,
        target: SocketAddr,
        _domain: Option<&str>,
        data: &[u8],
        _confirmed: bool,
        admitted: Option<&AtomicBool>,
    ) -> std::io::Result<()> {
        self.echo(target, data).await?;
        if let Some(admitted) = admitted {
            admitted.store(true, Ordering::Release);
        }
        Ok(())
    }
}

#[async_trait]
impl PacketTransport for EchoTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.echo(self.relay, data).await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        loop {
            let next = self.queue.lock().expect("echo queue").pop_front();
            if let Some((len, packet, peer)) = next {
                buf[..len].copy_from_slice(&packet[..len]);
                return Ok((len, peer));
            }
            self.ready.notified().await;
        }
    }
}

/// One built scenario: `measured` destinations are cycled for the timed
/// packets; `background` (if any) gets one extra packet per measured packet.
/// `gate` is the background destination's send gate, closed during timing and
/// opened (with its replies drained) afterwards.
struct Workload {
    name: &'static str,
    // Declared before `rt` so the pool is torn down while the runtime lives.
    harness: IoHarness,
    rt: Runtime,
    measured: Vec<usize>,
    background: Option<usize>,
    gate: Option<Arc<Gate>>,
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime")
}

async fn receive(harness: &IoHarness, wanted: &mut [(SocketAddr, usize)]) {
    let mut buf = [0u8; 2048];
    while wanted.iter().any(|(_, remaining)| *remaining > 0) {
        harness.client().readable().await.expect("client readable");
        while let Ok((_, from)) = harness.client().try_recv_from(&mut buf) {
            let slot = wanted
                .iter_mut()
                .find(|(address, _)| *address == from)
                .expect("reply from unexpected source");
            slot.1 = slot.1.saturating_sub(1);
        }
    }
}

impl Workload {
    /// Sliding-window closed loop; returns background packets admitted.
    async fn pump(&self, packets: usize) -> usize {
        let payload = [0xA5u8; PAYLOAD];
        let mut buf = [0u8; 2048];
        let background = self.background.map(|b| self.harness.target(b));
        let (mut sent, mut delivered, mut admitted) = (0usize, 0usize, 0usize);
        let mut per_destination = vec![0usize; self.measured.len()];
        while delivered < packets {
            while sent < packets && sent - delivered < WINDOW {
                let destination = self.measured[sent % self.measured.len()];
                assert_eq!(
                    self.harness.enqueue(destination, &payload),
                    Enqueue::Accepted,
                    "measured packet {sent} was not admitted"
                );
                if let Some(b) = self.background
                    && self.harness.enqueue(b, &payload) == Enqueue::Accepted
                {
                    admitted += 1;
                }
                sent += 1;
            }
            self.harness
                .client()
                .readable()
                .await
                .expect("client readable");
            while let Ok((n, from)) = self.harness.client().try_recv_from(&mut buf) {
                if Some(from) == background {
                    continue;
                }
                assert_eq!(
                    &buf[..n],
                    &payload[..],
                    "reply payload differs from the echo"
                );
                let slot = self
                    .measured
                    .iter()
                    .position(|destination| self.harness.target(*destination) == from)
                    .expect("reply from an unmeasured source");
                per_destination[slot] += 1;
                delivered += 1;
            }
        }
        let destinations = self.measured.len();
        let expected: Vec<usize> = (0..destinations)
            .map(|slot| (0..packets).filter(|n| n % destinations == slot).count())
            .collect();
        assert_eq!(
            per_destination, expected,
            "every measured destination must answer exactly its own packets"
        );
        admitted
    }

    /// One timed iteration: wall time of `pump` only.
    fn iteration(&self) -> Duration {
        if let Some(gate) = &self.gate {
            gate.set_blocked(true);
        }
        let started = Instant::now();
        let admitted = self.rt.block_on(async {
            tokio::time::timeout(PUMP_TIMEOUT, self.pump(PACKETS))
                .await
                .expect("udp_io pump timed out")
        });
        let elapsed = started.elapsed();
        if let Some(gate) = &self.gate {
            // Untimed: release the stuck destination and consume its echoes
            // so the next iteration starts from an idle association.
            gate.set_blocked(false);
            let background = self
                .harness
                .target(self.background.expect("gated background"));
            self.rt.block_on(async {
                tokio::time::timeout(
                    PUMP_TIMEOUT,
                    receive(&self.harness, &mut [(background, admitted)]),
                )
                .await
                .expect("udp_io gate drain timed out")
            });
        }
        elapsed
    }
}

fn process_cpu() -> Duration {
    let ts = clock_gettime(ClockId::CLOCK_PROCESS_CPUTIME_ID).expect("process cpu clock");
    Duration::new(ts.tv_sec() as u64, ts.tv_nsec() as u32)
}

fn bench_workload(c: &mut Criterion, workload: Workload) {
    // Warm-up and allocation pass, outside Criterion's timing.
    workload.iteration();
    let before = alloc_counters();
    workload.iteration();
    let [allocs, frees, reallocs, bytes] =
        std::array::from_fn(|i| (alloc_counters()[i] - before[i]) as f64 / PACKETS as f64);
    eprintln!(
        "udp_io/{}: allocs/pkt {allocs:.3} (frees {frees:.3}, reallocs {reallocs:.3}), bytes/pkt {bytes:.1}",
        workload.name,
    );

    let (cpu, wall, packets) = (
        Cell::new(Duration::ZERO),
        Cell::new(Duration::ZERO),
        Cell::new(0u64),
    );
    let mut group = c.benchmark_group("udp_io");
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Elements(PACKETS as u64));
    group.bench_function(workload.name, |b| {
        b.iter_custom(|iterations| {
            let cpu_before = process_cpu();
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                elapsed += workload.iteration();
            }
            cpu.set(cpu.get() + process_cpu() - cpu_before);
            wall.set(wall.get() + elapsed);
            packets.set(packets.get() + iterations * PACKETS as u64);
            elapsed
        });
    });
    group.finish();
    if packets.get() > 0 {
        // CPU includes the untimed gate drain, so it can slightly exceed wall.
        eprintln!(
            "udp_io/{}: wall {:.0} ns/pkt, process cpu {:.0} ns/pkt over {} packets",
            workload.name,
            wall.get().as_nanos() as f64 / packets.get() as f64,
            cpu.get().as_nanos() as f64 / packets.get() as f64,
            packets.get(),
        );
    }
}

fn ordinary(
    name: &'static str,
    destinations: usize,
    measured: Vec<usize>,
    background: Option<usize>,
) -> Workload {
    let rt = runtime();
    let gate = background.map(|_| Arc::new(Gate::default()));
    let harness = rt.block_on(async {
        let harness = IoHarness::new(destinations).await.expect("harness");
        for destination in 0..destinations {
            // Only the background destination's transport is gated.
            let gate = match (background, &gate) {
                (Some(b), Some(gate)) if b == destination => Arc::clone(gate),
                _ => Arc::new(Gate::default()),
            };
            harness
                .install_flow(
                    destination,
                    EchoTransport::new(harness.target(destination), gate),
                )
                .await
                .expect("install flow");
        }
        harness
    });
    Workload {
        name,
        harness,
        rt,
        measured,
        background,
        gate,
    }
}

/// One in-memory `MultiTargetTransport` shared by every destination of the
/// client source: the core `Shared` path with the ordinary workloads' echo.
fn shared_mock(name: &'static str, destinations: usize) -> Workload {
    let rt = runtime();
    let harness = rt.block_on(async {
        let mut harness = IoHarness::new(destinations).await.expect("harness");
        let transport = EchoTransport::new(harness.target(0), Arc::new(Gate::default()));
        for destination in 0..destinations {
            harness
                .install_mock_source(destination, transport.clone())
                .await
                .expect("install mock source");
        }
        harness
    });
    Workload {
        name,
        harness,
        rt,
        measured: (0..destinations).collect(),
        background: None,
        gate: None,
    }
}

fn bench_udp_io(c: &mut Criterion) {
    bench_workload(c, ordinary("ordinary_single", 1, vec![0], None));
    bench_workload(c, ordinary("ordinary_two_dest", 2, vec![0, 1], None));
    bench_workload(
        c,
        ordinary("ordinary_two_dest_b_blocked", 2, vec![0], Some(1)),
    );
    bench_workload(c, shared_mock("shared_mock_single", 1));
    bench_workload(c, shared_mock("shared_mock_two_dest", 2));
    backend::bench(c);
    #[cfg(feature = "rprx")]
    source::bench(c);
}

criterion_group!(benches, bench_udp_io);
criterion_main!(benches);
