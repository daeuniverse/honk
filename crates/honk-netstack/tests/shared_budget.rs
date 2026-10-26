//! Several stacks of one process drawing from one `MemoryBudget` (design §5.3): the budget is
//! charged for per-flow floors and shared commitments, a retired flow or a dropped stack returns
//! its charge, and an admitted flow keeps making progress when the budget is exhausted.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use honk_netstack::wire::{self, tcp};
use honk_netstack::{Config, ConnectError, FlowId, MemoryBudget, Rx, Stack, StreamError};

const CHUNK: usize = 16 * 1024;
const MS: Duration = Duration::from_millis(1);

fn remote() -> SocketAddr {
    "198.51.100.2:443".parse().unwrap()
}

struct Side {
    stack: Stack,
    now: Instant,
    out: Vec<u8>,
}

struct Conn {
    id: FlowId,
    port: u16,
    /// Next sequence number the peer sends / the stack sends.
    peer_seq: u32,
    stack_seq: u32,
}

impl Side {
    fn new(budget: Option<&std::sync::Arc<MemoryBudget>>) -> Side {
        let mut cfg = Config::new([0x37; 32]);
        cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
        cfg.shared_budget = budget.cloned();
        let now = Instant::now();
        Side {
            stack: Stack::new(cfg, now),
            now,
            out: vec![0u8; 2048],
        }
    }

    fn packets(&mut self) -> Vec<(tcp::Header, usize)> {
        let mut packets = Vec::new();
        while let Some(n) = self.stack.poll_transmit(self.now, &mut self.out) {
            let ip = wire::parse_ip(&self.out[..n]).unwrap();
            let (h, off) = tcp::parse(&self.out[ip.payload.clone()]).unwrap();
            packets.push((h, ip.payload.len() - off));
        }
        packets
    }

    fn deliver(&mut self, c: &Conn, flags: u8, payload: &[u8]) {
        let h = tcp::Header {
            src_port: remote().port(),
            dst_port: c.port,
            seq: c.peer_seq,
            ack: c.stack_seq,
            flags,
            window: u16::MAX,
            urgent: 0,
            options: tcp::Options {
                mss: (flags & tcp::SYN != 0).then_some(1380),
                ..Default::default()
            },
        };
        let mut buf = vec![0u8; payload.len() + 128];
        let local = IpAddr::V4("192.0.2.1".parse().unwrap());
        let n = tcp::emit_packet(&mut buf, remote().ip(), local, &h, [payload, &[]]).unwrap();
        assert_eq!(self.stack.receive(self.now, &buf[..n]), Rx::Consumed);
    }

    /// Opens a flow and completes the handshake.
    fn connect(&mut self) -> Result<Conn, ConnectError> {
        let id = self.stack.tcp_connect(self.now, remote())?;
        self.now += 10 * MS;
        let (syn, _) = self.packets().remove(0);
        let mut c = Conn {
            id,
            port: syn.src_port,
            peer_seq: 0x4000_0000,
            stack_seq: syn.seq.wrapping_add(1),
        };
        self.deliver(&c, tcp::SYN | tcp::ACK, &[]);
        c.peer_seq = c.peer_seq.wrapping_add(1);
        self.packets();
        Ok(c)
    }

    fn establish_up_to(&mut self, count: usize) -> (Vec<Conn>, Option<ConnectError>) {
        let mut conns = Vec::new();
        for _ in 0..count {
            match self.connect() {
                Ok(c) => conns.push(c),
                Err(e) => return (conns, Some(e)),
            }
        }
        (conns, None)
    }

    /// The flow can still carry a request out and a response in with nothing but its floor.
    fn assert_progress(&mut self, c: &mut Conn) {
        assert_eq!(
            self.stack.tcp_write(c.id, &vec![1u8; CHUNK]),
            Ok(CHUNK),
            "the floor chunk always takes a write"
        );
        self.now += 10 * MS;
        for (h, len) in self.packets() {
            assert_eq!(h.seq, c.stack_seq);
            c.stack_seq = c.stack_seq.wrapping_add(len as u32);
        }
        self.deliver(c, tcp::ACK, &[2u8; 1000]);
        c.peer_seq = c.peer_seq.wrapping_add(1000);
        let mut buf = [0u8; 2000];
        assert_eq!(self.stack.tcp_read(c.id, &mut buf), Ok(1000));
        self.packets();
    }
}

/// What one admitted flow costs: the budget's use after the first connect.
fn floor() -> usize {
    let budget = MemoryBudget::new(usize::MAX);
    let mut side = Side::new(Some(&budget));
    side.connect().unwrap();
    budget.used()
}

#[test]
fn stacks_sharing_a_budget_cannot_exceed_it_in_sum() {
    let floor = floor();
    let budget = MemoryBudget::new(5 * floor);
    let (mut a, mut b) = (Side::new(Some(&budget)), Side::new(Some(&budget)));
    let (flows_a, stop_a) = a.establish_up_to(3);
    let (flows_b, stop_b) = b.establish_up_to(3);
    assert_eq!((flows_a.len(), stop_a), (3, None));
    assert_eq!(
        (flows_b.len(), stop_b),
        (2, Some(ConnectError::Memory)),
        "the second stack gets what the first left"
    );
    assert_eq!(budget.used(), 5 * floor);
    assert_eq!(budget.limit(), 5 * floor);
}

#[test]
fn retired_flows_and_dropped_stacks_return_their_charge() {
    let floor = floor();
    let budget = MemoryBudget::new(2 * floor);
    let mut a = Side::new(Some(&budget));
    let mut b = Side::new(Some(&budget));
    let (flows, _) = a.establish_up_to(2);
    assert_eq!(budget.used(), 2 * floor);
    assert_eq!(b.connect().err(), Some(ConnectError::Memory));

    // A retired flow returns its floor while the stack lives.
    let c = &flows[0];
    a.stack.tcp_abort(c.id);
    a.packets();
    assert_eq!(budget.used(), floor, "RST sent, flow gone");
    assert!(
        b.connect().is_ok(),
        "the freed floor is usable by the other stack"
    );
    assert_eq!(budget.used(), 2 * floor);

    // Dropping a stack returns everything it still holds, flows and all.
    drop(a);
    assert_eq!(budget.used(), floor);
    drop(b);
    assert_eq!(budget.used(), 0);
}

#[test]
fn shared_commitments_are_charged_and_exhaustion_leaves_the_floor_working() {
    let floor = floor();
    // Room for one floor plus two shared chunks.
    let budget = MemoryBudget::new(floor + 2 * CHUNK);
    let mut a = Side::new(Some(&budget));
    let c = a.connect().unwrap();
    let accepted = a.stack.tcp_write(c.id, &vec![3u8; 8 * CHUNK]).unwrap();
    assert_eq!(
        accepted,
        3 * CHUNK,
        "the free first chunk plus the two budgeted ones"
    );
    assert_eq!(budget.used(), floor + 2 * CHUNK);
    assert_eq!(
        a.stack.tcp_write(c.id, &[0u8; 1]),
        Err(StreamError::WouldBlock)
    );
    // Another stack's flow is admitted only with its own floor, and still progresses with the
    // shared remainder at zero.
    let mut b = Side::new(Some(&budget));
    assert_eq!(b.connect().err(), Some(ConnectError::Memory));
    a.packets();
    drop(a);
    assert_eq!(budget.used(), 0);

    // Exactly the floors, no shared space at all: every admitted flow still works.
    let budget = MemoryBudget::new(2 * floor);
    let mut a = Side::new(Some(&budget));
    let mut b = Side::new(Some(&budget));
    let mut ca = a.connect().unwrap();
    let mut cb = b.connect().unwrap();
    assert_eq!(budget.used(), budget.limit());
    a.assert_progress(&mut ca);
    b.assert_progress(&mut cb);
    assert_eq!(
        budget.used(),
        budget.limit(),
        "progress needed nothing beyond the floors"
    );
}
