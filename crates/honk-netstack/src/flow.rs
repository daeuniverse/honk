//! Generation-checked flow slab, RFC 6056 ports and RFC 6528 keyed identifiers.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::tcp::{TIME_WAIT, Tcb};
use crate::{FlowId, Ready};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FourTuple {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

pub enum Flow {
    Tcp(Box<Tcb>),
    Udp { port: u16 },
    TimeWait(TimeWait),
}

pub struct Slot {
    pub generation: u32,
    pub flow: Option<Flow>,
    pub ready: Ready,
    pub on_event: bool,
    pub on_tx: bool,
    pub deficit: usize,
    pub scheduled: Option<Instant>,
}

pub struct Table {
    pub slots: Vec<Slot>,
    pub tcp: HashMap<FourTuple, u32>,
    pub udp: HashMap<u16, u32>,
    pub timewait: HashMap<FourTuple, u32>,
    free: Vec<u32>,
    pub active: u32,
    pub tcp_active: u32,
}

impl Table {
    pub fn new() -> Table {
        Table {
            slots: Vec::new(),
            tcp: HashMap::new(),
            udp: HashMap::new(),
            timewait: HashMap::new(),
            free: Vec::new(),
            active: 0,
            tcp_active: 0,
        }
    }

    pub fn insert(&mut self, flow: Flow) -> FlowId {
        let idx = self.free.pop().unwrap_or_else(|| {
            let idx = self.slots.len() as u32;
            self.slots.push(Slot {
                generation: 1,
                flow: None,
                ready: Ready::default(),
                on_event: false,
                on_tx: false,
                deficit: 0,
                scheduled: None,
            });
            idx
        });
        match &flow {
            Flow::Tcp(t) => {
                self.tcp.insert(t.tuple, idx);
                self.active += 1;
                self.tcp_active += 1;
            }
            Flow::Udp { port } => {
                self.udp.insert(*port, idx);
                self.active += 1;
            }
            Flow::TimeWait(t) => {
                self.timewait.insert(t.tuple, idx);
            }
        }
        let slot = &mut self.slots[idx as usize];
        slot.flow = Some(flow);
        FlowId {
            idx,
            generation: slot.generation,
        }
    }

    pub fn get(&self, id: FlowId) -> Option<&Flow> {
        let slot = self.slots.get(id.idx as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        let flow = slot.flow.as_ref()?;
        if matches!(flow, Flow::Tcp(t) if !t.app_open) || matches!(flow, Flow::TimeWait(_)) {
            return None;
        }
        Some(flow)
    }

    pub fn get_mut(&mut self, id: FlowId) -> Option<&mut Flow> {
        let slot = self.slots.get_mut(id.idx as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        let flow = slot.flow.as_mut()?;
        if matches!(flow, Flow::Tcp(t) if !t.app_open) || matches!(flow, Flow::TimeWait(_)) {
            return None;
        }
        Some(flow)
    }

    pub fn remove(&mut self, idx: u32) -> Option<Flow> {
        let slot = &mut self.slots[idx as usize];
        let flow = slot.flow.take()?;
        match &flow {
            Flow::Tcp(t) => {
                self.tcp.remove(&t.tuple);
                self.active -= 1;
                self.tcp_active -= 1;
            }
            Flow::Udp { port } => {
                self.udp.remove(port);
                self.active -= 1;
            }
            Flow::TimeWait(t) => {
                self.timewait.remove(&t.tuple);
            }
        }
        slot.generation = slot.generation.wrapping_add(1).max(1);
        slot.on_event = false;
        slot.on_tx = false;
        slot.ready = Ready::default();
        slot.deficit = 0;
        slot.scheduled = None;
        self.free.push(idx);
        Some(flow)
    }

    pub fn compact(&mut self, idx: u32, tw: TimeWait) {
        let slot = &mut self.slots[idx as usize];
        self.tcp.remove(&tw.tuple);
        self.timewait.insert(tw.tuple, idx);
        self.active -= 1;
        self.tcp_active -= 1;
        slot.flow = Some(Flow::TimeWait(tw));
        slot.generation = slot.generation.wrapping_add(1).max(1);
        slot.ready = Ready::default();
        slot.on_event = false;
        slot.on_tx = false;
        slot.scheduled = None;
    }
}
#[cfg(feature = "fuzz-checks")]
impl Table {
    /// Recounts what `active`, `tcp_active`, the lookup maps and the free list claim.
    pub fn check(&self) {
        let (mut tcp, mut udp, mut timewait) = (0, 0, 0);
        for (i, slot) in self.slots.iter().enumerate() {
            let i = i as u32;
            match &slot.flow {
                Some(Flow::Tcp(t)) => {
                    tcp += 1;
                    assert_eq!(self.tcp.get(&t.tuple), Some(&i));
                }
                Some(Flow::Udp { port }) => {
                    udp += 1;
                    assert_eq!(self.udp.get(port), Some(&i));
                }
                Some(Flow::TimeWait(t)) => {
                    timewait += 1;
                    assert_eq!(self.timewait.get(&t.tuple), Some(&i));
                }
                None => assert!(
                    self.free.contains(&i),
                    "empty slot {i} is not on the free list"
                ),
            }
        }
        assert_eq!((self.tcp_active, self.active), (tcp, tcp + udp));
        assert_eq!(
            (self.tcp.len(), self.udp.len(), self.timewait.len()),
            (tcp as usize, udp as usize, timewait)
        );
        assert_eq!(
            self.free.len() + tcp as usize + udp as usize + timewait,
            self.slots.len()
        );
    }
}

pub struct TimeWait {
    pub tuple: FourTuple,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub max_snd_wnd: u32,
    pub ts_recent: Option<u32>,
    pub ts_offset: u32,
    pub ts_last: u32,
    pub window: u16,
    pub expiry: Instant,
    pub ack_due: bool,
}

impl TimeWait {
    pub fn from_tcb(t: &Tcb, now: Instant) -> TimeWait {
        TimeWait {
            tuple: t.tuple,
            snd_nxt: t.snd_nxt,
            rcv_nxt: t.rcv_nxt,
            max_snd_wnd: t.snd_wnd_max,
            ts_recent: t.ts_recent.map(|v| v.0),
            ts_offset: t.ts_offset,
            ts_last: t.timestamp(now),
            window: 0,
            expiry: now + TIME_WAIT,
            ack_due: false,
        }
    }

    /// RFC 6191: reuse is safe only when the peer can distinguish the new incarnation.
    pub fn reusable(&self, new_isn: u32, new_ts: u32) -> bool {
        self.ts_recent.is_some()
            && crate::tcp::seq::gt(new_ts, self.ts_last)
            && crate::tcp::seq::gt(new_isn, self.snd_nxt)
    }

    /// Whether a SYN may replace this TIME_WAIT entry (RFC 9293 §3.6.1, RFC 6191, as Linux does):
    /// its sequence number is beyond everything the old incarnation received, or its timestamp is
    /// newer; a timestamp older than the last one seen is a stray old duplicate either way.
    pub fn syn_reopens(&self, syn_seq: u32, ts: Option<u32>) -> bool {
        use crate::tcp::seq;
        match (self.ts_recent, ts) {
            (Some(recent), Some(ts)) if seq::lt(ts, recent) => false,
            (Some(recent), Some(ts)) if seq::gt(ts, recent) => true,
            _ => seq::gt(syn_seq, self.rcv_nxt),
        }
    }
}

pub struct Ports {
    counters: [u32; 256],
}

impl Ports {
    pub fn new(secret: &[u8; 32]) -> Ports {
        let hash = blake3::keyed_hash(secret, b"honk-netstack RFC6056 counters");
        let seed = u32::from_be_bytes(hash.as_bytes()[..4].try_into().unwrap_or([0; 4]));
        Ports {
            counters: std::array::from_fn(|i| seed.wrapping_add(i as u32 * 7919)),
        }
    }

    pub fn start(&mut self, secret: &[u8; 32], local: IpAddr, remote: SocketAddr) -> u16 {
        let mut hash = blake3::Hasher::new_keyed(secret);
        hash.update(b"port");
        add_ip(&mut hash, local);
        add_ip(&mut hash, remote.ip());
        hash.update(&remote.port().to_be_bytes());
        let digest = hash.finalize();
        let offset = u32::from_be_bytes(digest.as_bytes()[..4].try_into().unwrap_or([0; 4]));
        let bucket = digest.as_bytes()[4] as usize;
        let port = 32768 + offset.wrapping_add(self.counters[bucket]) % 32768;
        self.counters[bucket] = self.counters[bucket].wrapping_add(1);
        port as u16
    }
}

pub fn next_port(port: u16) -> u16 {
    if port == u16::MAX { 32768 } else { port + 1 }
}

pub fn isn(secret: &[u8; 32], tuple: FourTuple, elapsed: Duration) -> u32 {
    let mut hash = blake3::Hasher::new_keyed(secret);
    hash.update(b"isn");
    add_ip(&mut hash, tuple.local.ip());
    hash.update(&tuple.local.port().to_be_bytes());
    add_ip(&mut hash, tuple.remote.ip());
    hash.update(&tuple.remote.port().to_be_bytes());
    u32::from_be_bytes(hash.finalize().as_bytes()[..4].try_into().unwrap_or([0; 4]))
        .wrapping_add((elapsed.as_micros() / 4) as u32)
}

pub fn ts_offset(secret: &[u8; 32], local: IpAddr, remote: IpAddr) -> u32 {
    let mut hash = blake3::Hasher::new_keyed(secret);
    hash.update(b"timestamp");
    add_ip(&mut hash, local);
    add_ip(&mut hash, remote);
    u32::from_be_bytes(hash.finalize().as_bytes()[..4].try_into().unwrap_or([0; 4]))
}

fn add_ip(hash: &mut blake3::Hasher, ip: IpAddr) {
    match ip {
        IpAddr::V4(a) => {
            hash.update(&a.octets());
        }
        IpAddr::V6(a) => {
            hash.update(&a.octets());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_keyed_and_clocked() {
        let tuple = FourTuple {
            local: "192.0.2.1:32768".parse().unwrap(),
            remote: "198.51.100.2:443".parse().unwrap(),
        };
        let i = isn(&[1; 32], tuple, Duration::ZERO);
        assert_eq!(
            isn(&[1; 32], tuple, Duration::from_micros(400)),
            i.wrapping_add(100)
        );
        assert_ne!(isn(&[2; 32], tuple, Duration::ZERO), i);
        assert_ne!(
            ts_offset(&[1; 32], tuple.local.ip(), tuple.remote.ip()),
            ts_offset(&[2; 32], tuple.local.ip(), tuple.remote.ip())
        );
        let mut ports = Ports::new(&[1; 32]);
        let first = ports.start(&[1; 32], tuple.local.ip(), tuple.remote);
        assert!((32768..=65535).contains(&first));
        assert_eq!(
            ports.start(&[1; 32], tuple.local.ip(), tuple.remote),
            next_port(first)
        );
    }
}
