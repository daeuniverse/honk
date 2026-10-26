//! Steady-state data movement allocates nothing: after warmup (rings, free-chunk cache and
//! descriptor capacity at their working size) in-order receive, `tcp_read`, ACK generation,
//! `tcp_write` and full-segment transmit leave the global allocation counter untouched.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use honk_netstack::wire::{self, tcp};
use honk_netstack::{Config, FlowId, Rx, Stack, TcpState};

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the test thread counts: the libtest harness thread allocates on its own schedule.
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

struct Counting;

fn count() {
    if COUNTING.get() {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: every method forwards unchanged to `System`; counting touches no allocator state.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Allocations made by `f` on this thread.
fn allocations_in(f: impl FnOnce()) -> usize {
    COUNTING.set(true);
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    f();
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    COUNTING.set(false);
    after - before
}

/// Config MTU 1420 minus IPv4 and TCP headers; no timestamps are negotiated.
const MSS: usize = 1380;
const MS: Duration = Duration::from_millis(1);
const WARMUP: usize = 400;
const MEASURED: usize = 1000;

fn remote() -> SocketAddr {
    "198.51.100.2:443".parse().unwrap()
}

struct Flow {
    stack: Stack,
    id: FlowId,
    local: SocketAddr,
    now: Instant,
    /// Next sequence number the stack will send.
    snd_nxt: u32,
    /// Next sequence number the peer will send.
    peer_next: u32,
    out: Vec<u8>,
}

impl Flow {
    /// Handshake with a 10 ms RTT, SACK and a window-scale-7 peer.
    fn connect() -> Flow {
        let mut cfg = Config::new([0x37; 32]);
        cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
        let local_ip = IpAddr::V4(cfg.local_v4.unwrap());
        let mut now = Instant::now();
        let mut stack = Stack::new(cfg, now);
        let id = stack.tcp_connect(now, remote()).unwrap();
        let mut out = vec![0u8; 2048];
        let n = stack.poll_transmit(now, &mut out).expect("SYN");
        let ip = wire::parse_ip(&out[..n]).unwrap();
        let (syn, _) = tcp::parse(&out[ip.payload.clone()]).unwrap();
        let mut flow = Flow {
            stack,
            id,
            local: SocketAddr::new(local_ip, syn.src_port),
            now,
            snd_nxt: syn.seq.wrapping_add(1),
            peer_next: 0x1020_3041,
            out,
        };
        let mut h = flow.header(flow.snd_nxt);
        h.seq = flow.peer_next.wrapping_sub(1);
        h.flags |= tcp::SYN;
        h.options.mss = Some(MSS as u16);
        h.options.wscale = Some(7);
        h.options.sack_permitted = true;
        now += 10 * MS;
        flow.now = now;
        let packet = flow.encode(&h, &[]);
        assert_eq!(flow.stack.receive(now, &packet), Rx::Consumed);
        assert_eq!(flow.stack.tcp_state(id), Some(TcpState::Established));
        assert!(flow.stack.poll_transmit(now, &mut flow.out).is_some());
        flow
    }

    fn header(&self, ack: u32) -> tcp::Header {
        tcp::Header {
            src_port: remote().port(),
            dst_port: self.local.port(),
            seq: self.peer_next,
            ack,
            flags: tcp::ACK,
            window: u16::MAX,
            urgent: 0,
            options: tcp::Options::default(),
        }
    }

    fn encode(&self, h: &tcp::Header, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; payload.len() + 128];
        let n =
            tcp::emit_packet(&mut buf, remote().ip(), self.local.ip(), h, [payload, &[]]).unwrap();
        buf.truncate(n);
        buf
    }

    /// The next in-order full segment from the peer.
    fn data_packet(&mut self, payload: &[u8]) -> Vec<u8> {
        let packet = self.encode(&self.header(self.snd_nxt), payload);
        self.peer_next = self.peer_next.wrapping_add(payload.len() as u32);
        packet
    }

    /// Pulls exactly `segments` full segments, letting time pass only for pacing gaps.
    fn send(&mut self, segments: usize) {
        let mut sent = 0;
        while sent < segments {
            if let Some(n) = self.stack.poll_transmit(self.now, &mut self.out) {
                assert_eq!(n, 40 + MSS, "a full segment");
                sent += 1;
                continue;
            }
            match self.stack.poll_timeout() {
                Some(at) if at.saturating_duration_since(self.now) <= 5 * MS => {
                    self.now = at.max(self.now);
                    self.stack.handle_timeout(self.now);
                }
                _ => panic!("transmit stalled after {sent} of {segments} segments"),
            }
        }
        self.snd_nxt = self.snd_nxt.wrapping_add((segments * MSS) as u32);
    }

    /// A cumulative ACK of everything sent so far, as the peer would send it.
    fn ack_all(&self) -> Vec<u8> {
        self.encode(&self.header(self.snd_nxt), &[])
    }

    /// Opens the congestion window to `segments` full segments with healthy slow-start rounds.
    fn grow(&mut self, segments: u32) {
        let data = vec![0xa5u8; segments as usize * MSS];
        while self.stack.tcp_stats(self.id).unwrap().cwnd < segments * MSS as u32 {
            let round = self.stack.tcp_stats(self.id).unwrap().cwnd as usize / MSS;
            assert_eq!(
                self.stack.tcp_write(self.id, &data[..round * MSS]),
                Ok(round * MSS)
            );
            self.send(round);
            self.now += 10 * MS;
            let ack = self.ack_all();
            assert_eq!(self.stack.receive(self.now, &ack), Rx::Consumed);
        }
    }
}

/// The peer streams `WARMUP + MEASURED` full segments; the stack reads them and emits ACKs.
fn receive_phase() -> usize {
    let mut f = Flow::connect();
    let payload = vec![0x5au8; MSS];
    let packets: Vec<Vec<u8>> = (0..WARMUP + MEASURED)
        .map(|_| f.data_packet(&payload))
        .collect();
    let mut read = vec![0u8; 64 * 1024];
    let mut step = |f: &mut Flow, p: &[u8]| {
        assert_eq!(f.stack.receive(f.now, p), Rx::Consumed);
        assert_eq!(f.stack.tcp_read(f.id, &mut read), Ok(MSS));
        while f.stack.poll_transmit(f.now, &mut f.out).is_some() {}
    };
    let (warm, measured) = packets.split_at(WARMUP);
    for p in warm {
        step(&mut f, p);
    }
    allocations_in(|| {
        for p in measured {
            step(&mut f, p);
        }
    })
}

/// The stack writes and transmits rounds of full segments; the peer acknowledges each round except
/// its last segment, so the flight never empties (an empty flight releases descriptor capacity).
fn transmit_phase() -> usize {
    const ROUND: usize = 50;
    const ROUNDS: usize = 60;
    const WARM_ROUNDS: usize = 20;
    let mut f = Flow::connect();
    f.grow(2 * ROUND as u32);
    let data = vec![0xa5u8; ROUND * MSS];
    let acks: Vec<Vec<u8>> = (1..=ROUNDS)
        .map(|r| {
            let ack = f.snd_nxt.wrapping_add((r * ROUND * MSS - MSS) as u32);
            f.encode(&f.header(ack), &[])
        })
        .collect();
    let round = |f: &mut Flow, ack: &[u8]| {
        assert_eq!(f.stack.tcp_write(f.id, &data), Ok(data.len()));
        f.send(ROUND);
        f.now += 10 * MS;
        assert_eq!(f.stack.receive(f.now, ack), Rx::Consumed);
        while f.stack.poll_transmit(f.now, &mut f.out).is_some() {}
    };
    let (warm, measured) = acks.split_at(WARM_ROUNDS);
    for ack in warm {
        round(&mut f, ack);
    }
    allocations_in(|| {
        for ack in measured {
            round(&mut f, ack);
        }
    })
}

// One test: the counter is process-global, so the phases must not interleave.
#[test]
fn steady_state_data_movement_allocates_nothing() {
    assert_eq!(receive_phase(), 0, "receive + tcp_read + ACK transmit");
    assert_eq!(
        transmit_phase(),
        0,
        "tcp_write + full-segment transmit + ACK receive"
    );
}
