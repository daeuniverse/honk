//! Application drivers shared by all stack adapters. The payload is a stateless pseudo-random
//! stream keyed by direction and flow, so a duplicate, gap, reorder or cross-flow mix-up fails at
//! the byte where it occurs without retaining a second copy of the whole transfer.

use super::rng::mix;
use std::fmt::Debug;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    WouldBlock,
    Closed,
    Reset,
}

/// The small application seam an adapter provides in addition to the four packet/timer calls.
/// `connected` means the handshake has completed; `read` returns `Ok(0)` only on FIN after buffered
/// data has drained, and a nonempty `write` never returns `Ok(0)`.
pub trait StreamIo {
    type Id: Copy + Debug;
    fn connected(&self, id: Self::Id) -> bool;
    fn read(&mut self, id: Self::Id, out: &mut [u8]) -> Result<usize, StreamError>;
    fn write(&mut self, id: Self::Id, data: &[u8]) -> Result<usize, StreamError>;
    fn shutdown(&mut self, id: Self::Id) -> Result<(), StreamError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Debug)]
pub struct Plan {
    pub flows: usize,
    pub client_bytes: usize,
    pub server_bytes: usize,
    /// The request/response server cannot reply until it has received the complete request.
    pub response_after_request: bool,
    pub seed: u64,
    pub app_chunk: usize,
    /// Added to the flow index in the pattern seed, so several drivers sharing one peer keep
    /// distinct streams (a cross-source mix-up then fails at the byte where it occurs).
    pub flow_base: usize,
    /// This role holds its FIN until the peer's FIN arrived, so the peer closes first (the
    /// peer is the active closer and keeps TIME_WAIT; this role closes passively).
    pub fin_after_peer: Option<Role>,
}

impl Plan {
    pub fn upload(bytes: usize) -> Self {
        Plan {
            flows: 1,
            client_bytes: bytes,
            server_bytes: 0,
            response_after_request: false,
            seed: 0x416C_6963_6542_6F62,
            app_chunk: 16 * 1024,
            flow_base: 0,
            fin_after_peer: None,
        }
    }

    pub fn download(bytes: usize) -> Self {
        Plan {
            client_bytes: 0,
            server_bytes: bytes,
            ..Self::upload(0)
        }
    }

    pub fn request_response(request: usize, response: usize) -> Self {
        Plan {
            client_bytes: request,
            server_bytes: response,
            response_after_request: true,
            ..Self::upload(0)
        }
    }

    pub fn many_flow(flows: usize, bytes_per_flow: usize) -> Self {
        Plan {
            flows,
            ..Self::upload(bytes_per_flow)
        }
    }

    pub fn total_bytes(&self) -> usize {
        self.flows * (self.client_bytes + self.server_bytes)
    }

    fn targets(&self, role: Role) -> (usize, usize) {
        match role {
            Role::Client => (self.client_bytes, self.server_bytes),
            Role::Server => (self.server_bytes, self.client_bytes),
        }
    }

    fn pattern_seed(&self, flow: usize, sender: Role) -> u64 {
        let direction = match sender {
            Role::Client => 0x43,
            Role::Server => 0x53,
        };
        mix(self.seed ^ (((flow + self.flow_base) as u64) << 8) ^ direction)
    }
}

#[derive(Debug)]
pub struct Flow<Id> {
    pub id: Id,
    pub sent: usize,
    pub received: usize,
    pub connected: bool,
    pub shutdown: bool,
    pub fin: bool,
    pub started: Instant,
    pub completed: Option<Instant>,
}

pub struct Driver<Id> {
    pub plan: Plan,
    pub role: Role,
    pub flows: Vec<Flow<Id>>,
    scratch: Vec<u8>,
    expected: Vec<u8>,
}

impl<Id: Copy + Debug> Driver<Id> {
    pub fn new(plan: Plan, role: Role, ids: impl IntoIterator<Item = Id>, now: Instant) -> Self {
        assert!(plan.app_chunk > 0);
        let flows: Vec<_> = ids
            .into_iter()
            .map(|id| Flow {
                id,
                sent: 0,
                received: 0,
                connected: false,
                shutdown: false,
                fin: false,
                started: now,
                completed: None,
            })
            .collect();
        assert_eq!(flows.len(), plan.flows);
        Driver {
            scratch: vec![0; plan.app_chunk],
            expected: vec![0; plan.app_chunk],
            plan,
            role,
            flows,
        }
    }

    pub fn poll(&mut self, io: &mut impl StreamIo<Id = Id>, now: Instant) {
        let (send, recv) = self.plan.targets(self.role);
        let peer = match self.role {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        };
        for (i, f) in self.flows.iter_mut().enumerate() {
            f.connected |= io.connected(f.id);
            if !f.connected || f.completed.is_some() {
                continue;
            }
            while !f.fin {
                match io.read(f.id, &mut self.scratch) {
                    Ok(0) => {
                        assert_eq!(f.received, recv, "{peer:?} flow {i}: premature FIN");
                        f.fin = true;
                    }
                    Ok(n) => {
                        assert!(
                            f.received + n <= recv,
                            "{peer:?} flow {i}: excess bytes (duplicate delivery)"
                        );
                        fill_pattern(
                            &mut self.expected[..n],
                            self.plan.pattern_seed(i, peer),
                            f.received,
                        );
                        if let Some(j) = self.scratch[..n]
                            .iter()
                            .zip(&self.expected[..n])
                            .position(|(a, b)| a != b)
                        {
                            panic!(
                                "{peer:?} flow {i}: wrong byte at offset {}: {} != {} (gap, reorder or corruption)",
                                f.received + j,
                                self.scratch[j],
                                self.expected[j]
                            );
                        }
                        f.received += n;
                    }
                    Err(StreamError::WouldBlock) => break,
                    Err(e) => panic!(
                        "{peer:?} flow {i}: read failed after {} bytes: {e:?}",
                        f.received
                    ),
                }
            }
            let can_reply = !matches!(self.role, Role::Server)
                || !self.plan.response_after_request
                || f.received == recv;
            if can_reply {
                while f.sent < send {
                    let n = self.scratch.len().min(send - f.sent);
                    fill_pattern(
                        &mut self.scratch[..n],
                        self.plan.pattern_seed(i, self.role),
                        f.sent,
                    );
                    match io.write(f.id, &self.scratch[..n]) {
                        Ok(0) => panic!("write returned zero for a nonempty buffer"),
                        Ok(n) => f.sent += n,
                        Err(StreamError::WouldBlock) => break,
                        Err(e) => panic!(
                            "{:?} flow {i}: write failed after {} bytes: {e:?}",
                            self.role, f.sent
                        ),
                    }
                }
                if f.sent == send
                    && !f.shutdown
                    && (self.plan.fin_after_peer != Some(self.role) || f.fin)
                {
                    io.shutdown(f.id)
                        .expect("shutdown after the application queued all bytes");
                    f.shutdown = true;
                }
            }
            if f.shutdown && f.fin {
                f.completed = Some(now);
            }
        }
    }

    pub fn finished(&self) -> bool {
        self.flows.iter().all(|f| f.completed.is_some())
    }

    pub fn assert_finished(&self) {
        let (sent, received) = self.plan.targets(self.role);
        for (i, f) in self.flows.iter().enumerate() {
            assert_eq!(f.sent, sent, "{:?} flow {i}: bytes sent", self.role);
            assert_eq!(
                f.received, received,
                "{:?} flow {i}: bytes received",
                self.role
            );
            assert!(f.fin, "{:?} flow {i}: peer FIN not observed", self.role);
            assert!(
                f.shutdown,
                "{:?} flow {i}: local FIN not requested",
                self.role
            );
            assert!(
                f.completed.is_some(),
                "{:?} flow {i}: incomplete",
                self.role
            );
        }
    }
}

pub fn fill_pattern(out: &mut [u8], seed: u64, offset: usize) {
    let mut pos = 0;
    while pos < out.len() {
        let off = offset + pos;
        let word = mix(seed.wrapping_add((off / 8) as u64 * 0x9E37_79B9)).to_le_bytes();
        let start = off % 8;
        let n = (8 - start).min(out.len() - pos);
        out[pos..pos + n].copy_from_slice(&word[start..start + n]);
        pos += n;
    }
}

/// Jain's fairness index over per-flow goodput (1 = equal, 1/N = one nonzero flow).
pub fn jain(values: &[f64]) -> f64 {
    let sum: f64 = values.iter().sum();
    let sq: f64 = values.iter().map(|v| v * v).sum();
    if values.is_empty() || sq == 0.0 {
        0.0
    } else {
        sum * sum / (values.len() as f64 * sq)
    }
}

#[derive(Debug)]
pub struct Metrics {
    pub completion: Duration,
    pub goodput_mbps: f64,
    pub flow_goodput_mbps: Vec<f64>,
    pub jain: f64,
    pub retransmitted_bytes: u64,
    pub max_queue_bytes: usize,
}

impl Metrics {
    pub fn new<Client: Copy + Debug, Server: Copy + Debug>(
        client: &Driver<Client>,
        server: &Driver<Server>,
        completion: Duration,
        retransmitted_bytes: u64,
        max_queue_bytes: usize,
    ) -> Self {
        client.assert_finished();
        server.assert_finished();
        assert_eq!(client.flows.len(), server.flows.len());
        let bytes = client.plan.client_bytes + client.plan.server_bytes;
        let rates: Vec<_> = client
            .flows
            .iter()
            .zip(&server.flows)
            .map(|(c, s)| {
                // A zero-data peer can send FIN before the sender has drained its socket buffer.
                // Enqueue completion is not delivery: require both endpoints' completion evidence.
                let end = c.completed.unwrap().max(s.completed.unwrap());
                let duration = end - c.started;
                bytes as f64 * 8.0 / duration.as_secs_f64().max(1e-9)
            })
            .collect();
        Metrics {
            completion,
            goodput_mbps: client.plan.total_bytes() as f64 * 8.0 / completion.as_secs_f64() / 1e6,
            jain: jain(&rates),
            flow_goodput_mbps: rates.into_iter().map(|v| v / 1e6).collect(),
            retransmitted_bytes,
            max_queue_bytes,
        }
    }
}
