//! Heap cost of an idle established flow (design §5.3, §11 G5): after a request/response exchange
//! with both rings drained, a flow holds no ring chunk and no descriptor storage, so the whole
//! per-flow state (Tcb, flow table, timer entry) is what remains.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use honk_netstack::wire::{self, tcp};
use honk_netstack::{Config, FlowId, Rx, Stack, TcpState};

thread_local! {
    // Only the test thread counts: the libtest harness thread allocates on its own schedule.
    static HEAP: Cell<isize> = const { Cell::new(0) };
}

struct Counting;

/// glibc `malloc` chunk size for a request: 8 bytes of header, 16-byte granularity, 32 minimum.
/// Counting what the allocator really keeps, not what was asked for.
fn resident(size: usize) -> isize {
    (size + 8).next_multiple_of(16).max(32) as isize
}

// SAFETY: every method forwards unchanged to `System`; counting touches no allocator state.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        HEAP.set(HEAP.get() + resident(layout.size()));
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        HEAP.set(HEAP.get() + resident(layout.size()));
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        HEAP.set(HEAP.get() + resident(new_size) - resident(layout.size()));
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        HEAP.set(HEAP.get() - resident(layout.size()));
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const FLOWS: usize = 1000;
const MSS: u16 = 1380;
const MS: Duration = Duration::from_millis(1);
const PAYLOAD: usize = 100;
const CHUNK: usize = 16 * 1024;

fn remote() -> SocketAddr {
    "198.51.100.2:443".parse().unwrap()
}

/// Scripted peer state of one flow.
struct Peer {
    /// Next sequence number the peer sends.
    seq: u32,
    /// Next sequence number the stack sends, i.e. what the peer acknowledges.
    ack: u32,
}

struct World {
    stack: Stack,
    ids: Vec<FlowId>,
    peers: HashMap<u16, Peer>,
    local_ip: IpAddr,
    now: Instant,
    out: Vec<u8>,
}

impl World {
    fn new() -> World {
        let mut cfg = Config::new([0x37; 32]);
        cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
        let now = Instant::now();
        World {
            local_ip: IpAddr::V4(cfg.local_v4.unwrap()),
            stack: Stack::new(cfg, now),
            // Reserved before the baseline is taken: the harness's own bookkeeping is not flow state.
            ids: Vec::with_capacity(FLOWS),
            peers: HashMap::with_capacity(FLOWS),
            now,
            out: vec![0u8; 2048],
        }
    }

    /// Every packet the stack has ready: (local port, header, payload length).
    fn drain(&mut self) -> Vec<(u16, tcp::Header, usize)> {
        let mut packets = Vec::new();
        while let Some(n) = self.stack.poll_transmit(self.now, &mut self.out) {
            let ip = wire::parse_ip(&self.out[..n]).unwrap();
            let (h, off) = tcp::parse(&self.out[ip.payload.clone()]).unwrap();
            packets.push((h.src_port, h, ip.payload.len() - off));
        }
        packets
    }

    fn deliver(&mut self, port: u16, mut h: tcp::Header, payload: &[u8]) {
        h.src_port = remote().port();
        h.dst_port = port;
        let mut buf = vec![0u8; payload.len() + 128];
        let n =
            tcp::emit_packet(&mut buf, remote().ip(), self.local_ip, &h, [payload, &[]]).unwrap();
        assert_eq!(self.stack.receive(self.now, &buf[..n]), Rx::Consumed);
    }

    fn header(seq: u32, ack: u32, flags: u8) -> tcp::Header {
        tcp::Header {
            src_port: 0,
            dst_port: 0,
            seq,
            ack,
            flags,
            window: u16::MAX,
            urgent: 0,
            options: tcp::Options::default(),
        }
    }

    fn connect_all(&mut self) {
        for _ in 0..FLOWS {
            self.ids
                .push(self.stack.tcp_connect(self.now, remote()).unwrap());
        }
        self.now += 10 * MS;
        for (port, syn, _) in self.drain() {
            assert_eq!(syn.flags & tcp::SYN, tcp::SYN);
            let isn = 0x1000_0000 + u32::from(port);
            let mut h = Self::header(isn, syn.seq.wrapping_add(1), tcp::SYN | tcp::ACK);
            h.options.mss = Some(MSS);
            h.options.wscale = Some(7);
            h.options.sack_permitted = true;
            self.peers.insert(
                port,
                Peer {
                    seq: isn.wrapping_add(1),
                    ack: syn.seq.wrapping_add(1),
                },
            );
            self.deliver(port, h, &[]);
        }
        assert_eq!(self.peers.len(), FLOWS);
        for id in &self.ids {
            assert_eq!(self.stack.tcp_state(*id), Some(TcpState::Established));
        }
        self.drain();
    }

    /// One request and one response per flow, acknowledged both ways and fully read.
    fn exchange(&mut self) {
        let request = [0x11u8; PAYLOAD];
        for id in self.ids.clone() {
            assert_eq!(self.stack.tcp_write(id, &request), Ok(PAYLOAD));
        }
        self.now += 10 * MS;
        for (port, h, len) in self.drain() {
            assert_eq!(len, PAYLOAD, "one request segment per flow");
            let peer = self.peers.get_mut(&port).unwrap();
            assert_eq!(h.seq, peer.ack);
            peer.ack = peer.ack.wrapping_add(len as u32);
        }
        self.now += 10 * MS;
        let response = [0x22u8; PAYLOAD];
        let ports: Vec<u16> = self.peers.keys().copied().collect();
        for port in ports {
            let peer = &mut self.peers.get_mut(&port).unwrap();
            let h = Self::header(peer.seq, peer.ack, tcp::ACK);
            peer.seq = peer.seq.wrapping_add(PAYLOAD as u32);
            self.deliver(port, h, &response);
        }
        let mut buf = [0u8; 4 * PAYLOAD];
        for id in self.ids.clone() {
            assert_eq!(self.stack.tcp_read(id, &mut buf), Ok(PAYLOAD));
        }
        // The stack's ACKs of the responses; the peer needs not answer them.
        self.drain();
    }

    /// Lets every delayed-ACK and similar timer run out, then empties the event queue.
    fn idle(&mut self) {
        for _ in 0..5 {
            self.now += Duration::from_secs(2);
            self.stack.handle_timeout(self.now);
            self.drain();
        }
        while self.stack.poll_event().is_some() {}
    }
}

#[test]
fn idle_established_flows_hold_no_chunks_or_descriptors() {
    let mut w = World::new();
    let baseline = HEAP.get();
    w.connect_all();
    w.exchange();
    w.idle();
    // A second round: the footprint must not depend on how often a flow was used.
    w.exchange();
    w.idle();

    let per_flow = (HEAP.get() - baseline) as f64 / FLOWS as f64;
    let stats = w.stack.stats();
    println!(
        "idle established flows: {FLOWS}, heap {:.0} B/flow, memory_allocated {} B",
        per_flow, stats.memory_allocated
    );
    // Cached free chunks are shared, not per flow; nothing else is allowed to be resident.
    assert!(
        stats.memory_allocated <= CHUNK,
        "drained rings must not keep chunks or descriptors: {} B allocated",
        stats.memory_allocated
    );
    // Protocol state and retained shared backing must fit the idle-flow budget.
    assert!(
        per_flow <= 1536.0,
        "idle flow footprint {per_flow:.0} B exceeds 1.5 KiB"
    );
}
