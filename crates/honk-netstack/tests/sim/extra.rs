//! Host adapters for the termination scenarios: a packet tap that can drop what a host emits, and
//! a fleet of honk clients with distinct source addresses behind one link.

use super::AppHost;
use super::app::{Driver, Plan};
use super::engine::{Host, epoch};
use super::honk::HonkHost;
use super::honk_server::source_addr;
use honk_netstack::wire;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Wraps a host and discards every packet it emits for which `drop_if` returns true (the packet is
/// consumed from the stack, exactly as if the link lost it).
pub struct Tap<H> {
    pub host: H,
    pub drop_if: Box<dyn FnMut(&[u8]) -> bool>,
    pub dropped: u64,
}

impl<H> Tap<H> {
    pub fn new(host: H, drop_if: impl FnMut(&[u8]) -> bool + 'static) -> Self {
        Tap {
            host,
            drop_if: Box::new(drop_if),
            dropped: 0,
        }
    }
}

impl<H: Host> Host for Tap<H> {
    fn receive(&mut self, now: Instant, packet: &[u8]) {
        self.host.receive(now, packet);
    }

    fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<usize> {
        loop {
            let n = self.host.poll_transmit(now, out)?;
            if (self.drop_if)(&out[..n]) {
                self.dropped += 1;
                continue;
            }
            return Some(n);
        }
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.host.poll_timeout()
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.host.handle_timeout(now);
    }

    fn poll_app(&mut self, now: Instant) {
        self.host.poll_app(now);
    }
}

impl<H: AppHost> AppHost for Tap<H> {
    type Id = H::Id;
    fn app(&self) -> &Driver<Self::Id> {
        self.host.app()
    }
}

/// TCP flags of a packet that is TCP over IPv4/IPv6, with its payload length.
pub fn tcp_flags(packet: &[u8]) -> Option<(u8, usize)> {
    let ip = wire::parse_ip(packet).ok()?;
    if ip.proto != wire::PROTO_TCP {
        return None;
    }
    let seg = &packet[ip.payload];
    let (h, off) = wire::tcp::parse(seg).ok()?;
    Some((h.flags, seg.len() - off))
}

/// Honk clients (addresses from `source_addr`), each dialing `server:8000+i`; one wakeup serves
/// them all and the output rotates over them, so none is favoured on the wire. Source `k` appears
/// (creates its stack and dials all its flows) `k * stagger` after the start.
pub struct Fleet {
    pub clients: Vec<Option<HonkHost>>,
    plans: Vec<Plan>,
    stagger: Duration,
    server: IpAddr,
    buffer: usize,
    next: usize,
}

impl Fleet {
    /// Source `k` runs `flows[k]` flows of `base` (its flow indexes are `k * stride + i` on the
    /// server; `stride` is the largest `flows[k]`).
    pub fn new(
        flows: &[usize],
        server: IpAddr,
        buffer: usize,
        base: &Plan,
        stagger: Duration,
    ) -> Self {
        let stride = *flows.iter().max().unwrap();
        let plans = flows
            .iter()
            .enumerate()
            .map(|(k, &n)| Plan {
                flows: n,
                flow_base: k * stride,
                ..base.clone()
            })
            .collect();
        Fleet {
            clients: flows.iter().map(|_| None).collect(),
            plans,
            stagger,
            server,
            buffer,
            next: 0,
        }
    }

    pub fn start_of(&self, k: usize) -> Instant {
        epoch() + self.stagger * k as u32
    }

    pub fn live(&self) -> impl Iterator<Item = &HonkHost> {
        self.clients.iter().flatten()
    }

    pub fn finished(&self) -> bool {
        self.clients
            .iter()
            .all(|c| c.as_ref().is_some_and(|c| c.app.finished()))
    }

    pub fn close_all(&mut self) {
        for c in self.clients.iter_mut().flatten() {
            c.close_all();
        }
    }
}

impl Host for Fleet {
    fn receive(&mut self, now: Instant, packet: &[u8]) {
        let ip = wire::parse_ip(packet).expect("valid IP");
        let IpAddr::V4(a) = ip.dst else {
            panic!("fleet is IPv4")
        };
        let o = a.octets();
        let k = usize::from(o[2]) << 8 | usize::from(o[3]);
        self.clients[k]
            .as_mut()
            .expect("packet for a source that never started")
            .receive(now, packet);
    }

    fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<usize> {
        let n = self.clients.len();
        for off in 0..n {
            let k = (self.next + off) % n;
            if let Some(len) = self.clients[k]
                .as_mut()
                .and_then(|c| c.poll_transmit(now, out))
            {
                self.next = (k + 1) % n;
                return Some(len);
            }
        }
        None
    }

    fn poll_timeout(&self) -> Option<Instant> {
        let pending = (0..self.clients.len())
            .filter(|&k| self.clients[k].is_none())
            .map(|k| self.start_of(k))
            .min();
        self.live()
            .filter_map(|c| c.poll_timeout())
            .chain(pending)
            .min()
    }

    fn handle_timeout(&mut self, now: Instant) {
        for c in self.clients.iter_mut().flatten() {
            if c.poll_timeout().is_some_and(|t| t <= now) {
                c.handle_timeout(now);
            }
        }
    }

    fn poll_app(&mut self, now: Instant) {
        for k in 0..self.clients.len() {
            if self.clients[k].is_none() && self.start_of(k) <= now {
                self.clients[k] = Some(HonkHost::at(
                    source_addr(k),
                    self.server,
                    self.buffer,
                    self.plans[k].clone(),
                    now,
                ));
            }
        }
        for c in self.clients.iter_mut().flatten() {
            c.poll_app(now);
        }
    }
}
