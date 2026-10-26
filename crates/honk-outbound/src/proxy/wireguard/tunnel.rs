//! One tunnel: a `Mutex<Inner { stack, tunn, .. }>` that application flows lock directly, plus an
//! owner task for the outer socket, decryption, transmit pulls and timers.
//!
//! Flows register their wakers under the same lock the owner uses to publish readiness, so a read
//! cannot miss data between "no data" and "waker stored". Lock holds are bounded to one batch.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::task::Waker;
use std::time::{Duration, Instant};

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use honk_netstack::{FlowId, MemoryBudget, Ready, Rx, Stack};
use parking_lot::Mutex;
use rand::RngExt as _;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

use super::registry::{AllowedIps, Registry, TunnelConfig};
use super::socket::{OuterUdp, RX_MSGS, RxBatch};
use crate::SharedError;
use crate::proxy::{NodeFailure, PacketRejection};

/// boringtun's timers have second granularity; this only bounds how late a retry fires.
const TICK: Duration = Duration::from_millis(250);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Gaps before the first two initiation resends, each measured from the previous send.
const HANDSHAKE_RESENDS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(2)];
/// boringtun's REKEY_TIMEOUT: the gap between attempts once the resends above are spent.
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// boringtun's REJECT_AFTER_TIME: past this a session no longer carries data.
const SESSION_LIFETIME: Duration = Duration::from_secs(180);
/// Packets per lock hold, in both directions.
const BATCH: usize = 64;
const MAX_OUT_PACKETS: usize = 256;
/// A full-size batch at a jumbo MTU would pin megabytes per tunnel; a few packets suffice.
const OUT_BUF_CAP: usize = 256 * 1024;
/// Smallest destination boringtun accepts for a handshake message.
const MIN_REGION: usize = 148;
const WG_OVERHEAD: usize = 32;
/// WireGuard message type of a cookie reply.
const COOKIE_REPLY: u8 = 3;
const RX_ROUNDS: usize = 4;
const UDP_QUEUE_CAP: usize = 256;

/// The tunnel or runtime that carried the flow was closed by its owner: the runtime shut down, a
/// reload replaced the tunnel's settings, or the process is stopping. Never a node failure.
#[derive(Debug, thiserror::Error)]
#[error("WireGuard runtime closed")]
pub struct RuntimeClosed;

pub(super) fn node_failure(message: &str) -> SharedError {
    SharedError::fanout(anyhow::Error::new(NodeFailure(anyhow::anyhow!(
        "{message}"
    ))))
}

#[derive(Clone)]
pub(super) enum State {
    Connecting,
    Established,
    /// Torn down with no flow or warm owner left; nothing observed it fail.
    Idle,
    /// Closed by its owner (runtime close, replaced settings, shutdown): not the node's fault.
    Closed,
    Failed(SharedError),
}

pub(super) enum Failure {
    Node(SharedError),
    Idle,
    Closed,
}

#[derive(Clone)]
pub(super) enum Forced {
    Node(SharedError),
    Closed,
}

impl Forced {
    pub(super) fn io(&self) -> io::Error {
        match self {
            Forced::Node(error) => io::Error::new(io::ErrorKind::ConnectionAborted, error.clone()),
            Forced::Closed => io::Error::new(io::ErrorKind::ConnectionAborted, RuntimeClosed),
        }
    }
}

/// Why a tunnel cannot take the operation: retry on a fresh one, surface the failure, or report
/// that its owner closed it.
pub(crate) enum Gone {
    Idle,
    Closed,
    Failed(SharedError),
}

impl Gone {
    pub(crate) fn into_error(self) -> anyhow::Error {
        match self {
            Gone::Idle => anyhow::anyhow!("WireGuard tunnel was closed while idle"),
            Gone::Closed => io::Error::new(io::ErrorKind::ConnectionAborted, RuntimeClosed).into(),
            Gone::Failed(error) => anyhow::Error::new(error),
        }
    }
}

pub(super) struct UdpQueue {
    queue: VecDeque<(SocketAddr, Vec<u8>)>,
    free: Vec<Vec<u8>>,
}

impl UdpQueue {
    fn push(&mut self, src: SocketAddr, payload: &[u8]) -> bool {
        if self.queue.len() >= UDP_QUEUE_CAP {
            return false;
        }
        let mut buf = self.free.pop().unwrap_or_default();
        buf.clear();
        buf.extend_from_slice(payload);
        self.queue.push_back((src, buf));
        true
    }

    /// Copies the oldest datagram into `out` (truncating like a UDP socket) and recycles its buffer.
    pub(super) fn pop(&mut self, out: &mut [u8]) -> Option<(usize, SocketAddr)> {
        let (src, buf) = self.queue.pop_front()?;
        let n = buf.len().min(out.len());
        out[..n].copy_from_slice(&buf[..n]);
        if self.free.len() < UDP_QUEUE_CAP {
            self.free.push(buf);
        }
        Some((n, src))
    }
}

pub(super) struct Slot {
    pub(super) rx: Option<Waker>,
    pub(super) tx: Option<Waker>,
    scope: u64,
    pub(super) forced: Option<Forced>,
    pub(super) udp: Option<UdpQueue>,
}

impl Slot {
    pub(super) fn new(scope: u64, udp: bool) -> Self {
        Self {
            rx: None,
            tx: None,
            scope,
            forced: None,
            udp: udp.then(|| UdpQueue {
                queue: VecDeque::new(),
                free: Vec::new(),
            }),
        }
    }

    fn wake(&mut self, rx: bool, tx: bool) {
        if rx && let Some(waker) = self.rx.take() {
            waker.wake();
        }
        if tx && let Some(waker) = self.tx.take() {
            waker.wake();
        }
    }
}

/// Ciphertexts waiting for the owner's batched outer send, packed back to back.
pub(super) struct OutBuf {
    buf: Vec<u8>,
    lens: Vec<u32>,
    tail: usize,
    last_seq: u64,
}

impl OutBuf {
    fn new(mtu: u16) -> Self {
        let packet = usize::from(mtu) + WG_OVERHEAD + 16;
        Self {
            buf: vec![0; (BATCH * packet).min(OUT_BUF_CAP.max(4 * packet))],
            lens: Vec::with_capacity(MAX_OUT_PACKETS),
            tail: 0,
            last_seq: 0,
        }
    }

    fn has_room(&self, need: usize) -> bool {
        self.lens.len() < MAX_OUT_PACKETS && self.buf.len() - self.tail >= need
    }

    fn is_empty(&self) -> bool {
        self.lens.is_empty()
    }

    fn clear(&mut self) {
        self.lens.clear();
        self.tail = 0;
    }

    /// Writes bytes 1..4 of the message: WARP-style reserved bytes ride in the header's zero padding.
    fn commit(&mut self, n: usize, reserved: Option<[u8; 3]>) {
        if let Some(reserved) = reserved
            && n >= 4
        {
            self.buf[self.tail + 1..self.tail + 4].copy_from_slice(&reserved);
        }
        self.lens.push(n as u32);
        self.tail += n;
    }
}

fn region_need(plaintext: usize) -> usize {
    (plaintext + WG_OVERHEAD).max(MIN_REGION)
}

pub(super) struct Inner {
    pub(super) stack: Stack,
    tunn: Tunn,
    pub(super) flows: HashMap<FlowId, Slot>,
    /// Warm claims per runtime scope.
    warm: HashMap<u64, usize>,
    /// Runtimes whose slot caches this tunnel.
    users: HashSet<u64>,
    out: OutBuf,
    ip_scratch: Vec<u8>,
    rx_scratch: Vec<u8>,
    allowed: Arc<AllowedIps>,
    reserved: Option<[u8; 3]>,
    endpoint: SocketAddr,
    /// Resolved peer addresses, tried in turn while no session exists.
    candidates: Vec<SocketAddr>,
    candidate: usize,
    /// The outer socket is IPv6 and carries IPv4 peers as mapped addresses.
    dual: bool,
    mtu: usize,
    out_seq: u64,
    want_handshake: bool,
    /// When the running initiation attempt started or last resent.
    handshake_at: Option<Instant>,
    resends: u8,
    established: bool,
    dead: bool,
    /// A runtime has closed: retire as soon as nothing uses the tunnel.
    retire_when_unused: bool,
    /// Data went out and nothing authentic has come back since.
    tx_since_rx: bool,
    /// Authenticated inner packets delivered to the stack: proof the peer is alive and routing.
    pub(super) inner_rx: u64,
    /// With no flow and no warm owner this long, the tunnel retires itself.
    idle_timeout: Duration,
    /// A session older than this is no session: the next `ready` handshakes again.
    session_lifetime: Duration,
}

pub(super) struct Shared {
    pub(super) cfg: TunnelConfig,
    pub(super) inner: Mutex<Inner>,
    /// The per-packet outbound check needs no lock: it never changes.
    pub(super) allowed: Arc<AllowedIps>,
    wake: Notify,
    pub(super) state: watch::Sender<State>,
    flushed: watch::Sender<u64>,
    dead: AtomicBool,
    pub(super) created: Instant,
    #[cfg(test)]
    pub(super) memory_limit: usize,
    /// The failure waiters of the running handshake attempt report; cleared when a new attempt
    /// starts or the session is established.
    timeout_episode: Mutex<Option<SharedError>>,
    resolve_due: AtomicBool,
}

/// A handle to a shared tunnel; cloning shares the same driver.
#[derive(Clone)]
pub(crate) struct Tunnel(pub(super) Arc<Shared>);

impl Tunnel {
    pub(crate) fn same(&self, other: &Tunnel) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Shared {
    pub(super) fn spawn(
        cfg: TunnelConfig,
        candidates: Vec<SocketAddr>,
        budget: &Arc<MemoryBudget>,
        registry: Weak<Registry>,
    ) -> anyhow::Result<(Arc<Self>, JoinHandle<()>)> {
        // A flow's window may grow to the whole shared budget, so the queue that feeds the windows
        // is sized from it, up to the socket's own cap.
        let memory_limit = budget.limit();
        let io = OuterUdp::bind(&candidates, memory_limit)?;
        let dual = io.is_v6();
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(|addr| dual || addr.is_ipv4())
            .collect();
        let endpoint = *candidates
            .first()
            .ok_or_else(|| anyhow::anyhow!("no usable WireGuard endpoint address"))?;
        let wg = &cfg.wg;
        let mtu = wg.mtu;
        let mut secret = [0u8; 32];
        rand::rng().fill(&mut secret);
        let mut stack_cfg = honk_netstack::Config::new(secret);
        stack_cfg.mtu = mtu;
        stack_cfg.local_v4 = wg.local_v4;
        stack_cfg.local_v6 = wg.local_v6;
        stack_cfg.memory_limit = memory_limit;
        stack_cfg.shared_budget = Some(Arc::clone(budget));
        let tunn = Tunn::new(
            StaticSecret::from(*wg.private_key_bytes()),
            PublicKey::from(*wg.public_key_bytes()),
            wg.preshared_key_bytes().copied(),
            wg.persistent_keepalive,
            rand::rng().random::<u32>() >> 8,
            None,
        );
        let allowed = Arc::new(AllowedIps::new(&wg.allowed_ips));
        let inner = Inner {
            stack: Stack::new(stack_cfg, Instant::now()),
            tunn,
            flows: HashMap::new(),
            warm: HashMap::new(),
            users: HashSet::new(),
            out: OutBuf::new(mtu),
            ip_scratch: vec![0; usize::from(mtu)],
            rx_scratch: vec![0; usize::from(u16::MAX) + WG_OVERHEAD],
            allowed: Arc::clone(&allowed),
            reserved: wg.reserved,
            endpoint,
            candidates,
            candidate: 0,
            dual,
            mtu: usize::from(mtu),
            out_seq: 0,
            want_handshake: false,
            handshake_at: None,
            resends: 0,
            established: false,
            dead: false,
            retire_when_unused: false,
            tx_since_rx: false,
            inner_rx: 0,
            idle_timeout: IDLE_TIMEOUT,
            session_lifetime: SESSION_LIFETIME,
        };
        let shared = Arc::new(Self {
            cfg,
            inner: Mutex::new(inner),
            allowed,
            wake: Notify::new(),
            state: watch::Sender::new(State::Connecting),
            flushed: watch::Sender::new(0),
            dead: AtomicBool::new(false),
            created: Instant::now(),
            #[cfg(test)]
            memory_limit,
            timeout_episode: Mutex::new(None),
            resolve_due: AtomicBool::new(false),
        });
        // Not scoped to any runtime's task owner: the tunnel is shared across runtimes and is
        // owned by the registry, which joins it at shutdown. The owner holds the registry only
        // weakly, so a dropped registry is not kept alive by its tunnels.
        let owner = tokio::spawn(drive(Arc::clone(&shared), io, mtu, registry));
        Ok((shared, owner))
    }

    pub(super) fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    /// Runs an application call under the lock, then wakes the owner if it produced something to send.
    pub(super) fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut guard = self.inner.lock();
        let result = f(&mut guard);
        let wake = guard.stack.take_tx_wakeup();
        drop(guard);
        if wake {
            self.wake.notify_one();
        }
        result
    }

    pub(super) fn wake_owner(&self) {
        self.wake.notify_one();
    }

    pub(super) fn fail(&self, how: Failure) {
        let mut guard = self.inner.lock();
        self.fail_locked(&mut guard, how);
    }

    fn fail_locked(&self, inner: &mut Inner, how: Failure) {
        if inner.dead {
            return;
        }
        inner.dead = true;
        let state = match how {
            Failure::Node(error) => {
                tracing::warn!(node = %self.cfg.name, "WireGuard tunnel failed: {error}");
                for slot in inner.flows.values_mut() {
                    slot.forced.get_or_insert(Forced::Node(error.clone()));
                    slot.wake(true, true);
                }
                State::Failed(error)
            }
            Failure::Closed => {
                tracing::debug!(node = %self.cfg.name, "WireGuard tunnel closed");
                for slot in inner.flows.values_mut() {
                    slot.forced.get_or_insert(Forced::Closed);
                    slot.wake(true, true);
                }
                State::Closed
            }
            Failure::Idle => {
                tracing::debug!(node = %self.cfg.name, "WireGuard tunnel retired");
                State::Idle
            }
        };
        self.dead.store(true, Ordering::Release);
        self.state.send_replace(state);
        self.flushed.send_replace(u64::MAX);
        self.wake.notify_one();
    }

    pub(super) fn close_scope(&self, scope: u64) {
        let mut guard = self.inner.lock();
        let mut touched = guard.users.remove(&scope);
        for slot in guard.flows.values_mut().filter(|slot| slot.scope == scope) {
            slot.forced.get_or_insert(Forced::Closed);
            slot.wake(true, true);
            touched = true;
        }
        if touched {
            guard.retire_when_unused = true;
            self.retire_if_unused(&mut guard);
        }
    }

    /// Retires the tunnel once a closing runtime has left it with nothing to serve.
    pub(super) fn retire_if_unused(&self, inner: &mut Inner) {
        if inner.retire_when_unused && inner.unused() {
            self.fail_locked(inner, Failure::Idle);
        }
    }

    pub(super) fn is_unused(&self) -> bool {
        self.inner.lock().unused()
    }

    /// The error a waiter reports when its own budget ran out before the handshake finished. The
    /// tunnel is not failed: boringtun keeps retrying for the other waiters.
    pub(super) fn handshake_timeout(&self) -> SharedError {
        self.resolve_due.store(true, Ordering::Release);
        self.timeout_episode
            .lock()
            .get_or_insert_with(|| node_failure("WireGuard handshake timed out"))
            .clone()
    }

    /// Whether a handshake attempt ran out of patience since the last check: the endpoint name
    /// may have moved and deserves a fresh lookup.
    pub(super) fn take_resolve_due(&self) -> bool {
        self.resolve_due.swap(false, Ordering::AcqRel)
    }

    /// Replaces the endpoint candidates of a tunnel that has no session yet. An established tunnel
    /// keeps its endpoint; a roaming or failing peer is handled by the handshake itself.
    pub(super) fn set_candidates(&self, candidates: Vec<SocketAddr>) {
        let mut guard = self.inner.lock();
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(|addr| guard.dual || addr.is_ipv4())
            .collect();
        if guard.established || candidates.is_empty() || guard.candidates == candidates {
            return;
        }
        guard.endpoint = candidates[0];
        guard.candidate = 0;
        guard.candidates = candidates;
    }

    fn rx_batch(&self, rx: &mut RxBatch, n: usize, segs: &mut Vec<Seg>) -> bool {
        for (index, meta) in rx.meta[..n].iter().enumerate() {
            let stride = meta.stride.max(1);
            let mut off = 0;
            while off < meta.len {
                let len = stride.min(meta.len - off);
                segs.push(Seg {
                    buf: index,
                    off,
                    len,
                    addr: meta.addr,
                });
                off += len;
            }
        }
        let mut alive = true;
        for chunk in segs.chunks(BATCH) {
            let now = Instant::now();
            let mut guard = self.inner.lock();
            if guard.dead {
                alive = false;
                break;
            }
            for seg in chunk {
                let data = &mut rx.bufs[seg.buf][seg.off..seg.off + seg.len];
                guard.rx_packet(now, data, seg.addr);
            }
        }
        segs.clear();
        alive
    }
}

struct Seg {
    buf: usize,
    off: usize,
    len: usize,
    addr: SocketAddr,
}

impl Inner {
    pub(super) fn dead(&self) -> bool {
        self.dead
    }

    pub(super) fn request_handshake(&mut self) {
        if !self.established {
            self.want_handshake = true;
        }
    }

    /// No flow that can still carry data, no warm owner and no runtime caching the tunnel.
    fn unused(&self) -> bool {
        self.warm.is_empty()
            && self.users.is_empty()
            && self.flows.values().all(|slot| slot.forced.is_some())
    }

    fn fresh_session(&self) -> bool {
        self.tunn
            .stats()
            .0
            .is_some_and(|age| age < self.session_lifetime)
    }

    fn rotate_endpoint(&mut self) {
        if self.candidates.len() > 1 {
            self.candidate = (self.candidate + 1) % self.candidates.len();
            self.endpoint = self.candidates[self.candidate];
        }
    }

    fn initiate(&mut self, force: bool) {
        if !self.out.has_room(MIN_REGION) {
            return;
        }
        let region = &mut self.out.buf[self.out.tail..];
        if let TunnResult::WriteToNetwork(packet) =
            self.tunn.format_handshake_initiation(region, force)
        {
            let n = packet.len();
            self.out_seq += 1;
            self.out.commit(n, self.reserved);
        }
    }

    pub(super) fn forced(&self, id: FlowId) -> Option<io::Error> {
        self.flows
            .get(&id)
            .and_then(|slot| slot.forced.as_ref())
            .map(Forced::io)
    }

    /// Encrypts `ip_scratch[..n]` into the outbound batch; returns the batch sequence a confirmed
    /// sender waits on.
    fn seal(&mut self, n: usize) -> io::Result<u64> {
        self.tx_since_rx = true;
        seal(
            &mut self.tunn,
            &mut self.out,
            &mut self.out_seq,
            self.reserved,
            &self.ip_scratch[..n],
        )
    }

    /// Serializes one datagram from the association and queues it for the owner.
    pub(super) fn udp_send(&mut self, id: FlowId, dst: SocketAddr, data: &[u8]) -> io::Result<u64> {
        if let Some(error) = self.forced(id) {
            return Err(error);
        }
        if !self.out.has_room(region_need(self.mtu)) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = self
            .stack
            .udp_send(id, dst, data, &mut self.ip_scratch)
            .map_err(|error| match error {
                honk_netstack::UdpError::TooLarge => io::Error::from(PacketRejection::InvalidSize),
                honk_netstack::UdpError::NoLocalAddress => io::Error::from(PacketRejection::Policy),
                error => io::Error::new(io::ErrorKind::NotConnected, error),
            })?;
        self.seal(n)
    }

    fn rx_packet(&mut self, now: Instant, data: &mut [u8], src: SocketAddr) {
        let Inner {
            tunn,
            stack,
            rx_scratch,
            out,
            out_seq,
            flows,
            allowed,
            reserved,
            tx_since_rx,
            inner_rx,
            endpoint,
            ..
        } = self;
        let src = SocketAddr::new(src.ip().to_canonical(), src.port());
        // The reserved bytes are not part of the Noise message; the peer's bind layer set them.
        if reserved.is_some() && data.len() > 3 {
            data[1..4].fill(0);
        }
        // Datagrams that fail to authenticate are dropped silently, like the kernel does: the
        // source address is spoofable, so a flood of junk must not be able to end the tunnel.
        let authentic = match tunn.decapsulate(Some(src.ip()), data, rx_scratch) {
            TunnResult::Err(_) => return,
            TunnResult::Done => true,
            TunnResult::WriteToNetwork(reply) => {
                // Under load boringtun answers an unauthenticated, merely mac1-valid handshake
                // with a cookie reply. That proves nothing about the sender, and our output only
                // goes to the current endpoint, so it is neither answered nor trusted.
                if reply.first() == Some(&COOKIE_REPLY) {
                    return;
                }
                push_raw(out, out_seq, *reserved, reply);
                while let TunnResult::WriteToNetwork(queued) =
                    tunn.decapsulate(None, &[], rx_scratch)
                {
                    push_raw(out, out_seq, *reserved, queued);
                }
                true
            }
            TunnResult::WriteToTunnelV4(packet, source) => {
                deliver(
                    stack,
                    flows,
                    allowed,
                    inner_rx,
                    now,
                    packet,
                    IpAddr::V4(source),
                );
                true
            }
            TunnResult::WriteToTunnelV6(packet, source) => {
                deliver(
                    stack,
                    flows,
                    allowed,
                    inner_rx,
                    now,
                    packet,
                    IpAddr::V6(source),
                );
                true
            }
        };
        if authentic {
            *tx_since_rx = false;
            *endpoint = src;
        }
    }

    /// One owner pass: timers, transmit pulls, readiness. Returns whether work remains.
    fn pump(&mut self, shared: &Shared, now: Instant, next_tick: &mut Instant) -> Pump {
        let mut pump = Pump::default();
        self.stack.handle_timeout(now);
        if now >= *next_tick {
            *next_tick = now + TICK;
            self.tick(shared, now, &mut pump);
        }
        // A request inside the running attempt does not restart it: the schedule above and
        // boringtun's timers own the retries.
        if std::mem::take(&mut self.want_handshake)
            && !self.established
            && self
                .handshake_at
                .is_none_or(|at| now.duration_since(at) >= REKEY_TIMEOUT)
        {
            self.handshake_at = Some(now);
            self.resends = 0;
            shared.timeout_episode.lock().take();
            self.initiate(false);
        }
        let mut sent = 0;
        while sent < BATCH && self.out.has_room(region_need(self.mtu)) {
            let Some(n) = self.stack.poll_transmit(now, &mut self.ip_scratch) else {
                break;
            };
            let _ = self.seal(n);
            sent += 1;
        }
        pump.more = sent == BATCH || !self.out.has_room(region_need(self.mtu));
        while let Some((id, ready)) = self.stack.poll_event() {
            if let Some(slot) = self.flows.get_mut(&id) {
                let wake_rx = ready.contains(Ready::READABLE)
                    || ready.contains(Ready::READ_CLOSED)
                    || ready.contains(Ready::ERROR);
                let wake_tx = ready.contains(Ready::WRITABLE)
                    || ready.contains(Ready::CONNECTED)
                    || ready.contains(Ready::ERROR);
                slot.wake(wake_rx, wake_tx);
            }
        }
        if !self.established && self.fresh_session() {
            self.established = true;
            self.handshake_at = None;
            shared.timeout_episode.lock().take();
            shared.state.send_replace(State::Established);
        }
        pump
    }

    fn tick(&mut self, shared: &Shared, now: Instant, pump: &mut Pump) {
        // Sessions age out silently (180 s without traffic); the next `ready` must handshake again.
        if self.established && !self.fresh_session() {
            self.established = false;
            self.handshake_at = None;
            shared.state.send_replace(State::Connecting);
        }
        // Initiation retransmissions before establishment: 1 s and 2 s after the previous send, a
        // deliberate deviation from boringtun's first retry after REKEY_TIMEOUT (5 s) so one lost
        // datagram does not fail a 3 s dial. Later retries are boringtun's own, 5 s apart, and the
        // rate stays at most one initiation per second.
        if !self.established
            && let Some(at) = self.handshake_at
            && let Some(&wait) = HANDSHAKE_RESENDS.get(usize::from(self.resends))
            && now.duration_since(at) >= wait
        {
            self.resends += 1;
            self.handshake_at = Some(now);
            self.rotate_endpoint();
            self.initiate(true);
        }
        if !self.out.has_room(MIN_REGION) {
            return;
        }
        let rotate = !self.established;
        let region = &mut self.out.buf[self.out.tail..];
        match self.tunn.update_timers(region) {
            TunnResult::WriteToNetwork(packet) => {
                let n = packet.len();
                self.out_seq += 1;
                if rotate {
                    self.rotate_endpoint();
                }
                self.out.commit(n, self.reserved);
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                // An idle tunnel's session lapses after nine minutes without anything wrong; only a
                // peer that stayed silent after we sent data (boringtun retries the handshake for 90 s) failed.
                if !self.flows.is_empty() && self.tx_since_rx {
                    pump.fatal = Some("WireGuard session expired without a new handshake");
                } else if self.established {
                    self.established = false;
                    self.handshake_at = None;
                    shared.state.send_replace(State::Connecting);
                }
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct Pump {
    more: bool,
    fatal: Option<&'static str>,
}

fn seal(
    tunn: &mut Tunn,
    out: &mut OutBuf,
    seq: &mut u64,
    reserved: Option<[u8; 3]>,
    src: &[u8],
) -> io::Result<u64> {
    let region = &mut out.buf[out.tail..];
    match tunn.encapsulate(src, region) {
        TunnResult::WriteToNetwork(packet) => {
            let n = packet.len();
            *seq += 1;
            out.commit(n, reserved);
            Ok(*seq)
        }
        // Handshake in progress: boringtun queued the packet and already scheduled the initiation.
        TunnResult::Done => Ok(*seq),
        _ => Err(io::Error::other("WireGuard could not encrypt the packet")),
    }
}

fn push_raw(out: &mut OutBuf, seq: &mut u64, reserved: Option<[u8; 3]>, bytes: &[u8]) {
    if !out.has_room(bytes.len()) {
        return;
    }
    out.buf[out.tail..out.tail + bytes.len()].copy_from_slice(bytes);
    *seq += 1;
    out.commit(bytes.len(), reserved);
}

fn deliver(
    stack: &mut Stack,
    flows: &mut HashMap<FlowId, Slot>,
    allowed: &AllowedIps,
    inner_rx: &mut u64,
    now: Instant,
    packet: &[u8],
    source: IpAddr,
) {
    // Cryptokey routing: the peer may only source addresses it is allowed to own.
    if !allowed.contains(source) {
        return;
    }
    *inner_rx += 1;
    if let Rx::Datagram { flow, src, payload } = stack.receive(now, packet)
        && let Some(slot) = flows.get_mut(&flow)
        && let Some(queue) = slot.udp.as_mut()
        && queue.push(src, &packet[payload])
    {
        slot.wake(true, false);
    }
}

/// Fails the tunnel if the owner stops for any reason, including a panic or runtime shutdown.
struct Finalize(Arc<Shared>, Weak<Registry>);

impl Drop for Finalize {
    fn drop(&mut self) {
        self.0
            .fail(Failure::Node(node_failure("WireGuard driver stopped")));
        if let Some(registry) = self.1.upgrade() {
            registry.remove(&self.0);
        }
    }
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
    )
}

async fn drive(shared: Arc<Shared>, io: OuterUdp, mtu: u16, registry: Weak<Registry>) {
    let _finalize = Finalize(Arc::clone(&shared), registry);
    let mut rx = RxBatch::new(&io, mtu);
    let mut spare = OutBuf::new(mtu);
    let mut segs: Vec<Seg> = Vec::with_capacity(RX_MSGS * BATCH);
    let mut next_tick = Instant::now() + TICK;
    let mut idle_since: Option<Instant> = None;
    loop {
        let mut rx_busy = false;
        for round in 0..RX_ROUNDS {
            match io.try_recv(&mut rx) {
                Ok(n) => {
                    if !shared.rx_batch(&mut rx, n, &mut segs) {
                        return;
                    }
                    rx_busy = round + 1 == RX_ROUNDS;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if transient(&error) => {}
                Err(error) => {
                    shared.fail(Failure::Node(node_failure(&format!(
                        "WireGuard outer socket receive failed: {error}"
                    ))));
                    return;
                }
            }
        }
        let now = Instant::now();
        let (more, deadline, endpoint) = {
            let mut guard = shared.inner.lock();
            if guard.dead {
                return;
            }
            let pump = guard.pump(&shared, now, &mut next_tick);
            if let Some(message) = pump.fatal {
                shared.fail_locked(&mut guard, Failure::Node(node_failure(message)));
                return;
            }
            let mut deadline = next_tick;
            if let Some(next) = guard.stack.poll_timeout() {
                deadline = deadline.min(next);
            }
            if guard.flows.is_empty() && guard.warm.is_empty() {
                let expires = *idle_since.get_or_insert(now) + guard.idle_timeout;
                if now >= expires {
                    shared.fail_locked(&mut guard, Failure::Idle);
                    return;
                }
                deadline = deadline.min(expires);
            } else {
                idle_since = None;
            }
            guard.out.last_seq = guard.out_seq;
            std::mem::swap(&mut guard.out, &mut spare);
            (pump.more || rx_busy, deadline, guard.endpoint)
        };
        if !spare.is_empty() {
            io.send_all(endpoint, &spare.buf[..spare.tail], &spare.lens)
                .await;
            let seq = spare.last_seq;
            shared.flushed.send_if_modified(|flushed| {
                let advance = *flushed < seq;
                if advance {
                    *flushed = seq;
                }
                advance
            });
            spare.clear();
        }
        if more {
            tokio::task::yield_now().await;
            continue;
        }
        tokio::select! {
            result = io.readable() => {
                if let Err(error) = result {
                    shared.fail(Failure::Node(node_failure(&format!(
                        "WireGuard outer socket failed: {error}"
                    ))));
                    return;
                }
            }
            () = shared.wake.notified() => {}
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
        }
    }
}

/// An RAII claim that keeps a tunnel alive without a flow (warm retention). Claims are counted per
/// scope: re-installing a tunnel into the same slot overlaps the old and new claim.
pub(crate) struct WarmHold {
    tunnel: Arc<Shared>,
    scope: u64,
}

impl Drop for WarmHold {
    fn drop(&mut self) {
        let mut guard = self.tunnel.inner.lock();
        if let Some(count) = guard.warm.get_mut(&self.scope) {
            *count -= 1;
            if *count == 0 {
                guard.warm.remove(&self.scope);
            }
        }
        self.tunnel.retire_if_unused(&mut guard);
        drop(guard);
        self.tunnel.wake_owner();
    }
}

impl Tunnel {
    pub(crate) fn is_dead(&self) -> bool {
        self.0.is_dead()
    }

    /// Whether a live session exists right now, not merely that one once did.
    pub(crate) fn is_established(&self) -> bool {
        matches!(*self.0.state.borrow(), State::Established)
    }

    pub(crate) fn endpoint(&self) -> SocketAddr {
        self.0.inner.lock().endpoint
    }

    pub(crate) fn hold(&self, scope: u64) -> Option<WarmHold> {
        let mut guard = self.0.inner.lock();
        if guard.dead {
            return None;
        }
        *guard.warm.entry(scope).or_default() += 1;
        Some(WarmHold {
            tunnel: Arc::clone(&self.0),
            scope,
        })
    }

    /// Records that the runtime `scope` caches this tunnel, so closing another runtime does not
    /// retire it from under this one.
    pub(crate) fn attach(&self, scope: u64) {
        self.0.inner.lock().users.insert(scope);
    }

    pub(crate) fn detach(&self, scope: u64) {
        self.0.inner.lock().users.remove(&scope);
    }

    /// The runtime `scope` is closing and will not use this tunnel again: with no flow, warm owner
    /// or other runtime left, retire it now instead of waiting out the idle period.
    pub(crate) fn release(&self, scope: u64) {
        let mut guard = self.0.inner.lock();
        guard.users.remove(&scope);
        guard.retire_when_unused = true;
        self.0.retire_if_unused(&mut guard);
    }

    /// Completes the handshake. A wait that times out fails only that wait: the tunnel keeps
    /// retrying for the waiters with a longer budget. Concurrent timeouts of one handshake attempt
    /// share one node-failure episode.
    pub(crate) async fn ready(&self, timeout: Duration) -> Result<(), Gone> {
        let mut state = self.0.state.subscribe();
        self.0.with(|inner| inner.request_handshake());
        self.0.wake_owner();
        let settled = tokio::time::timeout(timeout, async {
            state
                .wait_for(|state| !matches!(state, State::Connecting))
                .await
                .map(|state| state.clone())
        })
        .await;
        match settled {
            Ok(Ok(State::Established)) => Ok(()),
            Ok(Ok(State::Idle)) => Err(Gone::Idle),
            Ok(Ok(State::Closed)) => Err(Gone::Closed),
            Ok(Ok(State::Failed(error))) => Err(Gone::Failed(error)),
            _ => Err(Gone::Failed(self.0.handshake_timeout())),
        }
    }

    /// Waits until the owner has handed ciphertext sequence `seq` to the socket.
    pub(super) async fn flushed(&self, seq: u64) {
        let mut flushed = self.0.flushed.subscribe();
        let _ = flushed.wait_for(|done| *done >= seq).await;
    }
}

#[cfg(test)]
impl Tunnel {
    pub(super) fn set_idle_timeout(&self, timeout: Duration) {
        self.0.inner.lock().idle_timeout = timeout;
        self.0.wake_owner();
    }

    pub(super) fn set_session_lifetime(&self, lifetime: Duration) {
        self.0.inner.lock().session_lifetime = lifetime;
        self.0.wake_owner();
    }

    pub(super) fn flow_count(&self) -> usize {
        self.0.inner.lock().flows.len()
    }

    pub(super) fn memory_limit(&self) -> usize {
        self.0.memory_limit
    }
}
