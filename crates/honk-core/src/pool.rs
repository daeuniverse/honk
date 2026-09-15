//! TCP connection pool for proxy dials.
//!
//! Two entry kinds, both capped at 8 per key and 300s max age:
//!
//! - **Bare** — a silent pre-handshake `TcpStream` to the proxy server (60s
//!   idle TTL), keyed by the server's `"host:port"` and reused via
//!   `TcpOutbound::dial_with_tcp`. Saves the TCP connect RTT only; any queued
//!   server byte makes it unsafe to present as a fresh protocol transport.
//! - **Ready** — a fully-dialed `ProxyStream` whose protocol handshake is
//!   complete (SOCKS5 CONNECT done, Trojan TLS + request header written),
//!   reused *directly* as the data channel with no handshake at all.
//!   Idle TTL is shorter (30s): a target-bound tunnel holds more
//!   server-side state than a bare TCP connection and servers reap idle
//!   tunnels sooner.
//!
//! Ready keys are namespaced (`ready|<generation>|<node-id>|<target>`) so they
//! can never collide with bare `"host:port"` keys (`|` cannot appear in a
//! host:port pair). The key binds the proxy generation and node identity as
//! well as the target because the completed handshake committed the stream
//! to that exact credential/configuration.
//!
//! Budgets beyond the per-key cap: an explicit global FD capacity (bounded by
//! [`MAX_TOTAL_ENTRIES`]), a per-identity-per-generation ready-target
//! cardinality cap ([`MAX_READY_TARGETS_PER_NODE`]), and hot-target gating
//! ([`ConnectionPool::note_target`]) so only repeat destinations earn a
//! speculative ready deposit. Deposits are also capability-checked at the
//! call site (multiplexed handlers never deposit ready entries — their session
//! pool already owns reuse). Hit/miss/entry counters feed the clash API
//! `/stats`.
//!
//! One mutex keeps the stream total equal to the sum of non-empty entry
//! vectors and ready-target counts equal to the present ready keys. Entry,
//! target, warm-claim and hotness changes are synchronous transactions; the
//! lock is never held across an await. Removed streams are dropped after
//! unlocking, so socket teardown cannot extend the critical section.
//! Retiring a generation removes its ready namespace, target budget, warm
//! claims and hotness under that same lock; the successor starts empty and
//! late writes for the retired generation are refused. The retired-generation
//! set grows by one entry per retired generation and is never reclaimed.
//! Hotness is bounded to 4,096 keys; saturation within one live generation is
//! unchanged, and warm claims remain one per in-flight dial without a separate
//! cardinality cap.

use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{Barrier, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tracing::{debug, trace};
use uuid::Uuid;

use honk_outbound::proxy::ProxyStream;

const MAX_PER_HOST: usize = 8;
/// Global cap across all keys (bare + ready) — an FD budget, not just a
/// per-key one: deposits past it are refused.
pub(crate) const MAX_TOTAL_ENTRIES: usize = 2048;
/// Distinct ready targets per node identity and runtime generation — bounds
/// target-cardinality-driven ready pools (a scanner hitting thousands of
/// targets must not turn the pool into thousands of dialed tunnels).
const MAX_READY_TARGETS_PER_NODE: usize = 64;
/// Ready deposits are made only for "hot" targets: at least this many
/// flows to the same (generation, node, target) within [`HOT_WINDOW`]. A one-off flow
/// never triggers a speculative ready dial.
const HOT_THRESHOLD: u32 = 2;
const HOT_WINDOW: Duration = Duration::from_secs(60);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Idle TTL for Ready (handshake-completed) entries — shorter than Bare
/// because a target-bound tunnel holds more server-side state and servers
/// typically reap idle tunnels sooner.
const READY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(300);

/// A pooled connection. Each key's list holds exactly one kind: the key
/// namespaces (`"host:port"` vs `ready|...`) make mixing impossible.
enum PooledStream {
    /// Pre-handshake TCP to the proxy server; reused via `dial_with_tcp`.
    Bare(TcpStream),
    /// Fully-dialed, target-bound data channel; reused as-is.
    Ready(ProxyStream),
}

struct TimedStream {
    stream: PooledStream,
    created: Instant,
    last_used: Instant,
}

#[cfg(test)]
#[derive(Clone)]
struct PauseHook {
    name: &'static str,
    reached: Arc<Barrier>,
    resume: Arc<Barrier>,
}

#[cfg(test)]
impl PauseHook {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            reached: Arc::new(Barrier::new(2)),
            resume: Arc::new(Barrier::new(2)),
        }
    }
}

pub struct ConnectionPool {
    state: Mutex<PoolState>,
    capacity_limit: u64,
    idle_timeout: Duration,
    ready_idle_timeout: Duration,
    max_age: Duration,
    ready_hits: AtomicU64,
    ready_misses: AtomicU64,
    #[cfg(test)]
    pause_hook: StdMutex<Option<PauseHook>>,
}

#[derive(Default)]
struct PoolState {
    entries: HashMap<String, Vec<TimedStream>>,
    total: u64,
    ready_targets: HashMap<String, u32>,
    warm_dials: HashSet<String>,
    hot: HashMap<String, (u32, Instant)>,
    retired: HashSet<u64>,
}

impl PoolState {
    fn decrement_ready_target(targets: &mut HashMap<String, u32>, key: &str) {
        if key.starts_with("ready|") {
            let node = ConnectionPool::ready_node(key);
            let count = targets.get_mut(node).expect("present ready target");
            *count -= 1;
            if *count == 0 {
                targets.remove(node);
            }
        }
    }

    fn remove_empty_key(&mut self, key: &str) {
        if self.entries.get(key).is_some_and(Vec::is_empty) {
            self.entries.remove(key);
            Self::decrement_ready_target(&mut self.ready_targets, key);
        }
    }

    fn remove_matching(
        &mut self,
        mut matches: impl FnMut(&str) -> bool,
        removed: &mut Vec<TimedStream>,
    ) {
        for (key, mut list) in self.entries.extract_if(|key, _| matches(key)) {
            self.total -= list.len() as u64;
            Self::decrement_ready_target(&mut self.ready_targets, &key);
            removed.append(&mut list);
        }
    }
}

pub(crate) struct WarmDialGuard<'a> {
    pool: &'a ConnectionPool,
    key: String,
}

impl Drop for WarmDialGuard<'_> {
    fn drop(&mut self) {
        self.pool.state.lock().warm_dials.remove(&self.key);
    }
}

/// Ready-pool metrics snapshot (clash API `/stats`).
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadyPoolMetrics {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
}

fn is_bare_tcp_stream_usable(stream: &TcpStream) -> bool {
    if !matches!(
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::SocketError),
        Ok(0)
    ) {
        return false;
    }
    let mut buf = [0u8; 1];
    match nix::sys::socket::recv(
        stream.as_raw_fd(),
        &mut buf,
        nix::sys::socket::MsgFlags::MSG_PEEK | nix::sys::socket::MsgFlags::MSG_DONTWAIT,
    ) {
        Err(nix::errno::Errno::EWOULDBLOCK) => true,
        Ok(_) | Err(_) => false,
    }
}

impl ConnectionPool {
    /// Construct a max-capacity pool for tests and standalone callers.
    pub fn new() -> Self {
        Self::with_capacity_limit(MAX_TOTAL_ENTRIES)
    }

    pub(crate) fn with_capacity_limit(capacity_limit: usize) -> Self {
        Self {
            state: Mutex::new(PoolState::default()),
            capacity_limit: capacity_limit.min(MAX_TOTAL_ENTRIES) as u64,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            ready_idle_timeout: READY_IDLE_TIMEOUT,
            max_age: DEFAULT_MAX_AGE,
            ready_hits: AtomicU64::new(0),
            ready_misses: AtomicU64::new(0),
            #[cfg(test)]
            pause_hook: StdMutex::new(None),
        }
    }
    #[cfg(test)]
    fn install_pause_hook(&self, name: &'static str) -> PauseHook {
        let hook = PauseHook::new(name);
        *self.pause_hook.lock().expect("pause hook mutex poisoned") = Some(hook.clone());
        hook
    }

    #[cfg(test)]
    fn pause_at(&self, name: &'static str) {
        let hook = {
            let mut configured = self.pause_hook.lock().expect("pause hook mutex poisoned");
            if configured.as_ref().is_some_and(|hook| hook.name == name) {
                configured.take()
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            self.check_invariants();
            hook.reached.wait();
            hook.resume.wait();
            self.check_invariants();
        }
    }

    /// Record one flow to `key` (a `ready|…` key) for `generation` and report
    /// whether the target is hot enough to justify a speculative ready deposit
    /// ([`HOT_THRESHOLD`] flows within [`HOT_WINDOW`]). Retired generations
    /// cannot acquire new hotness.
    pub(crate) fn note_target(&self, generation: u64, key: &str) -> bool {
        const MAX_HOT_TARGETS: u64 = 4096;
        let mut state = self.state.lock();
        if state.retired.contains(&generation) {
            return false;
        }
        if let Some(value) = state.hot.get_mut(key) {
            if value.1.elapsed() > HOT_WINDOW {
                *value = (0, Instant::now());
            }
            value.0 += 1;
            value.0 >= HOT_THRESHOLD
        } else {
            if (state.hot.len() as u64) < MAX_HOT_TARGETS {
                state.hot.insert(key.to_owned(), (1, Instant::now()));
            }
            false
        }
    }

    /// Claim one background warming dial for this ready key. The returned
    /// guard clears the claim on drop, including cancellation and failures.
    pub(crate) fn try_begin_warm(&self, generation: u64, key: &str) -> Option<WarmDialGuard<'_>> {
        let mut state = self.state.lock();
        if state.retired.contains(&generation) || state.warm_dials.contains(key) {
            return None;
        }
        state.warm_dials.insert(key.to_owned());
        Some(WarmDialGuard {
            pool: self,
            key: key.to_owned(),
        })
    }

    #[cfg(any(test, feature = "clash-api"))]
    pub(crate) fn ready_metrics(&self) -> ReadyPoolMetrics {
        let state = self.state.lock();
        ReadyPoolMetrics {
            hits: self.ready_hits.load(Ordering::Relaxed),
            misses: self.ready_misses.load(Ordering::Relaxed),
            entries: state.total,
        }
    }

    #[cfg(test)]
    fn set_ready_idle_timeout(&mut self, timeout: Duration) {
        self.ready_idle_timeout = timeout;
    }

    /// Pool key for a Ready entry. The completed handshake binds the stream
    /// to (generation, node identity, target); with domain routing the CONNECT
    /// request carries the domain, making `domain:port` — not the resolved IP
    /// — the destination identity.
    pub(crate) fn ready_key(
        generation: u64,
        node_id: Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> String {
        match target_domain {
            Some(domain) => format!("ready|{generation}|{node_id}|{domain}:{}", target.port()),
            None => format!("ready|{generation}|{node_id}|{target}"),
        }
    }

    pub(crate) async fn acquire_tcp(&self, addr: &str) -> Option<TcpStream> {
        match self.acquire_entry(addr, false).await {
            Some(PooledStream::Bare(tcp)) => Some(tcp),
            _ => None,
        }
    }

    /// Take a Ready stream for `key`, if one is pooled, unexpired, and
    /// alive. The entry is removed from the pool: a ready stream serves
    /// exactly one connection and is never returned after use.
    pub(crate) async fn acquire_ready(&self, key: &str) -> Option<ProxyStream> {
        match self.acquire_entry(key, true).await {
            Some(PooledStream::Ready(stream)) => {
                self.ready_hits.fetch_add(1, Ordering::Relaxed);
                Some(stream)
            }
            _ => {
                self.ready_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    async fn acquire_entry(&self, addr: &str, want_ready: bool) -> Option<PooledStream> {
        #[cfg(test)]
        {
            self.pause_at("checkout_after_clone");
            self.pause_at("checkout_after_drop");
        }
        let mut removed = Vec::new();
        let mut state = self.state.lock();
        let list = state.entries.get_mut(addr)?;
        let now = Instant::now();
        let found = list.iter().rposition(|entry| {
            Self::entry_matches(entry, want_ready)
                && !self.entry_expired(entry, now)
                && Self::is_entry_alive(entry)
        });
        let acquired = if let Some(index) = found {
            let entry = list.swap_remove(index);
            trace!(
                "Pool hit ({}): {} ({} idle remaining)",
                if want_ready { "ready" } else { "bare" },
                addr,
                list.len()
            );
            state.total -= 1;
            Some(entry.stream)
        } else {
            removed.extend(list.extract_if(.., |entry| {
                self.entry_expired(entry, now) || !Self::is_entry_alive(entry)
            }));
            state.total -= removed.len() as u64;
            None
        };
        state.remove_empty_key(addr);
        drop(state);
        drop(removed);
        acquired
    }

    /// Pool a silent pre-handshake socket. Any queued server bytes make the
    /// socket unusable as a fresh protocol transport and are left unconsumed.
    /// Returns whether the socket satisfied that invariant; capacity refusal
    /// retains the historical successful-connect accounting at callers.
    pub(crate) async fn deposit_tcp(&self, addr: &str, stream: TcpStream) -> bool {
        if !is_bare_tcp_stream_usable(&stream) {
            return false;
        }
        self.deposit_entry(addr, PooledStream::Bare(stream), None)
            .await;
        true
    }

    /// Whether a live, unexpired bare-TCP entry exists for `addr`
    /// (`host:port`) — the preconnect warm gauge behind `/stats`. Dead and
    /// expired entries are removed here so a long-lived warm owner can
    /// replace them instead of eventually filling the per-host vector.
    pub(crate) fn has_live_bare_entry(&self, addr: &str) -> bool {
        let mut removed = Vec::new();
        let mut state = self.state.lock();
        let now = Instant::now();
        let Some(entries) = state.entries.get_mut(addr) else {
            return false;
        };
        removed.extend(entries.extract_if(.., |entry| {
            matches!(entry.stream, PooledStream::Bare(_))
                && (self.entry_expired(entry, now) || !Self::is_entry_alive(entry))
        }));
        let live = entries
            .iter()
            .any(|entry| matches!(entry.stream, PooledStream::Bare(_)));
        state.total -= removed.len() as u64;
        state.remove_empty_key(addr);
        drop(state);
        drop(removed);
        live
    }

    /// Deposit a fully-dialed stream under `key` (see [`ready_key`]).
    /// The stream must come straight out of `TcpOutbound::dial()` with no
    /// application reads performed, so its userspace TLS buffer (if any)
    /// is empty and the fd-level liveness probe stays accurate.
    pub(crate) async fn deposit_ready(&self, generation: u64, key: &str, stream: ProxyStream) {
        self.deposit_entry(key, PooledStream::Ready(stream), Some(generation))
            .await;
    }

    async fn deposit_entry(&self, addr: &str, stream: PooledStream, generation: Option<u64>) {
        #[cfg(test)]
        self.pause_at("deposit_before_lock");
        let mut state = self.state.lock();
        if let Some(generation) = generation
            && state.retired.contains(&generation)
        {
            debug!(
                "Pool generation {} retired; dropping ready deposit for {}",
                generation, addr
            );
            drop(state);
            return;
        }
        if state.total >= self.capacity_limit {
            debug!(
                "Pool global cap reached ({}); dropping deposit for {}",
                self.capacity_limit, addr
            );
            drop(state);
            return;
        }
        let list = state.entries.get(addr);
        if list.is_some_and(|list| list.len() >= MAX_PER_HOST) {
            debug!("Pool cap reached for {} (max={})", addr, MAX_PER_HOST);
            drop(state);
            return;
        }
        if list.is_none() && matches!(stream, PooledStream::Ready(_)) {
            let node = Self::ready_node(addr);
            let count = state.ready_targets.get(node).copied().unwrap_or(0);
            if count >= MAX_READY_TARGETS_PER_NODE as u32 {
                debug!(
                    "Ready target cardinality cap reached for {} (max={}); dropping deposit",
                    node, MAX_READY_TARGETS_PER_NODE
                );
                drop(state);
                return;
            }
            state.ready_targets.insert(node.to_owned(), count + 1);
        }
        let now = Instant::now();
        let entry = TimedStream {
            stream,
            created: now,
            last_used: now,
        };
        if let Some(list) = state.entries.get_mut(addr) {
            list.push(entry);
        } else {
            state.entries.insert(addr.to_owned(), vec![entry]);
        }
        state.total += 1;
        debug!("Pool deposit: {} ({} total pooled)", addr, state.total);
    }

    #[cfg(test)]
    fn ready_generation(key: &str) -> Option<u64> {
        key.strip_prefix("ready|")?.split_once('|')?.0.parse().ok()
    }

    fn ready_node(key: &str) -> &str {
        let after = key.strip_prefix("ready|").unwrap_or_default();
        let Some((generation, after_node)) = after.split_once('|') else {
            return "";
        };
        let Some((node_id, _target)) = after_node.split_once('|') else {
            return "";
        };
        &after[..generation.len() + 1 + node_id.len()]
    }

    /// Drop only the bare preconnect for a node. Ready streams may belong to
    /// active traffic policy and are not selector warm ownership.
    pub(crate) fn purge_bare(&self, node_addr: &str) {
        let mut state = self.state.lock();
        let removed = state.entries.remove(node_addr);
        if let Some(entries) = &removed {
            state.total -= entries.len() as u64;
            debug!(
                "Purged {} selector-warm bare connections for {}",
                entries.len(),
                node_addr
            );
        }
        drop(state);
        drop(removed);
    }

    /// Drop ready entries tied to a proxy node identity in one generation,
    /// plus its bare preconnect when the current config supplies the address.
    /// Called when the node flips alive→dead.
    pub(crate) fn purge_node(&self, node_addr: Option<&str>, generation: u64, node_id: Uuid) {
        let ready_prefix = format!("ready|{generation}|{node_id}|");
        let mut removed = Vec::new();
        let mut state = self.state.lock();
        state.remove_matching(
            |key| node_addr.is_some_and(|addr| key == addr) || key.starts_with(&ready_prefix),
            &mut removed,
        );
        drop(state);
        debug!(
            "Purged {} pooled connections for dead node {}",
            removed.len(),
            node_id
        );
        drop(removed);
    }

    /// Retire all ready-pool state for a generation. Ready streams are
    /// collected and destroyed after releasing the state lock.
    pub(crate) fn retire_generation(&self, generation: u64) {
        let ready_prefix = format!("ready|{generation}|");
        let mut removed = Vec::new();
        let mut state = self.state.lock();
        state.retired.insert(generation);
        state.remove_matching(|key| key.starts_with(&ready_prefix), &mut removed);
        state
            .warm_dials
            .retain(|key| !key.starts_with(&ready_prefix));
        state.hot.retain(|key, _| !key.starts_with(&ready_prefix));
        drop(state);
        debug!(
            "Retired generation {generation}, dropping {} ready connections",
            removed.len()
        );
        drop(removed);
    }

    pub(crate) async fn prune_expired(&self) -> usize {
        #[cfg(test)]
        self.pause_at("janitor_before_store");
        let mut removed = Vec::new();
        let mut state = self.state.lock();
        let now = Instant::now();
        let PoolState {
            entries,
            total,
            ready_targets,
            ..
        } = &mut *state;
        entries.retain(|key, list| {
            let before = removed.len();
            removed.extend(list.extract_if(.., |entry| {
                self.entry_expired(entry, now) || !Self::is_entry_alive(entry)
            }));
            *total -= (removed.len() - before) as u64;
            if list.is_empty() {
                PoolState::decrement_ready_target(ready_targets, key);
                false
            } else {
                true
            }
        });
        let remaining = state.total;
        drop(state);
        let count = removed.len();
        drop(removed);
        debug!(
            "Pruned {} expired pooled connections ({} remaining)",
            count, remaining
        );
        count
    }

    pub(crate) fn spawn_janitor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                pool.prune_expired().await;
            }
        })
    }

    fn entry_matches(entry: &TimedStream, want_ready: bool) -> bool {
        matches!(
            (&entry.stream, want_ready),
            (PooledStream::Bare(_), false) | (PooledStream::Ready(_), true)
        )
    }

    fn idle_ttl(&self, entry: &TimedStream) -> Duration {
        match &entry.stream {
            PooledStream::Bare(_) => self.idle_timeout,
            PooledStream::Ready(_) => self.ready_idle_timeout,
        }
    }

    fn entry_expired(&self, entry: &TimedStream, now: Instant) -> bool {
        now.duration_since(entry.last_used) > self.idle_ttl(entry)
            || now.duration_since(entry.created) > self.max_age
    }

    fn is_entry_alive(entry: &TimedStream) -> bool {
        match &entry.stream {
            PooledStream::Bare(tcp) => is_bare_tcp_stream_usable(tcp),
            PooledStream::Ready(stream) => Self::is_ready_stream_alive(stream),
        }
    }

    /// Liveness probe for Ready streams: `MSG_PEEK | MSG_DONTWAIT` on the
    /// underlying fd.
    ///
    /// - returns 0: the peer performed an orderly shutdown (FIN) — the
    ///   tunnel is dead; drop it and fall back to a normal dial.
    /// - returns >0: bytes are pending in the kernel receive buffer —
    ///   alive. For TLS streams this is ciphertext (a `close_notify` alert
    ///   counts as alive here — a false positive, but the first real read
    ///   then surfaces EOF, bounding the waste to one checkout).
    /// - `EAGAIN`/`EWOULDBLOCK`: nothing pending, connection open — alive.
    /// - `ECONNRESET`/`ENOTCONN`: dead.
    /// - any other error, or no extractable fd (non-TCP stream such as a
    ///   duplex bridge): conservatively treated as alive.
    ///
    /// Limitation: this peeks the SOCKET, not any userspace TLS buffer.
    /// rustls buffers decrypted plaintext once reads start, so bytes
    /// already pulled into rustls would be invisible here — and a peer FIN
    /// arriving after them would look like a dead connection even though
    /// buffered data remains. Pooled Ready streams are deposited straight
    /// out of `dial()` before any application read, so their rustls read
    /// buffer is empty by construction and fd-level peek is accurate.
    /// Never deposit a stream that has already been read from.
    fn is_ready_stream_alive(stream: &ProxyStream) -> bool {
        let Some(fd) = stream.raw_fd() else {
            // No probe possible (not a plain TCP/TLS stream) — conservatively alive.
            return true;
        };
        let mut buf = [0u8; 1];
        match nix::sys::socket::recv(
            fd,
            &mut buf,
            nix::sys::socket::MsgFlags::MSG_PEEK | nix::sys::socket::MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(0) => false,
            Ok(_) => true,
            Err(nix::errno::Errno::ECONNRESET | nix::errno::Errno::ENOTCONN) => false,
            // EAGAIN/EWOULDBLOCK (nothing to read) and anything unexpected:
            // conservatively alive.
            Err(_) => true,
        }
    }
    #[cfg(test)]
    pub(crate) fn check_invariants(&self) {
        let state = self.state.lock();
        assert!(state.total <= self.capacity_limit);
        let mut sum = 0;
        let mut targets = HashMap::new();
        for (key, list) in &state.entries {
            assert!(!list.is_empty(), "empty pool key {key}");
            assert!(list.len() <= MAX_PER_HOST);
            sum += list.len() as u64;
            let ready = key.starts_with("ready|");
            assert!(list.iter().all(|entry| Self::entry_matches(entry, ready)));
            if ready {
                let generation =
                    Self::ready_generation(key).expect("ready entry key has a generation");
                assert!(
                    !state.retired.contains(&generation),
                    "retired generation has ready entry: {key}"
                );
                *targets
                    .entry(Self::ready_node(key).to_owned())
                    .or_insert(0u32) += 1;
            }
        }
        assert_eq!(state.total, sum, "pool total disagrees with entry vectors");
        assert_eq!(state.ready_targets, targets);
        assert!(
            targets
                .values()
                .all(|count| (1..=MAX_READY_TARGETS_PER_NODE as u32).contains(count))
        );
        assert!(state.hot.len() <= 4096);
        for key in state.warm_dials.iter().chain(state.hot.keys()) {
            if let Some(generation) = Self::ready_generation(key) {
                assert!(
                    !state.retired.contains(&generation),
                    "retired generation has auxiliary state: {key}"
                );
            }
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::node::Node;
    use honk_outbound::proxy::TcpOutbound;
    use honk_outbound::proxy::socks5::Socks5Handler;
    use std::thread;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn make_ready_stream(tcp: TcpStream, target: SocketAddr) -> ProxyStream {
        ProxyStream {
            stream: Box::new(tcp),
            target_addr: target,
            target_domain: None,
        }
    }

    /// Accept one connection and hold it open (no data, no close) so the
    /// peer's liveness probes keep reporting "alive".
    async fn spawn_hold_open_listener() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    let _ = s.read(&mut buf).await;
                });
            }
        });
        addr
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    async fn wait_for_queued_byte(fd: std::os::fd::RawFd) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let mut byte = [0u8; 1];
                if matches!(
                    nix::sys::socket::recv(
                        fd,
                        &mut byte,
                        nix::sys::socket::MsgFlags::MSG_PEEK
                            | nix::sys::socket::MsgFlags::MSG_DONTWAIT,
                    ),
                    Ok(1)
                ) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("peer byte did not reach the pooled socket");
    }

    #[tokio::test]
    async fn race_last_checkout_vs_deposit() {
        let pool = Arc::new(ConnectionPool::new());
        let server = spawn_hold_open_listener().await;
        let key = server.to_string();

        let first = TcpStream::connect(server).await.unwrap();
        let first_id = first.local_addr().unwrap();
        pool.deposit_tcp(&key, first).await;
        pool.check_invariants();

        let second = TcpStream::connect(server).await.unwrap();
        let second_id = second.local_addr().unwrap();
        let hook = pool.install_pause_hook("checkout_after_drop");

        let checkout_pool = Arc::clone(&pool);
        let checkout_key = key.clone();
        let checkout = thread::spawn(move || {
            futures::executor::block_on(checkout_pool.acquire_tcp(&checkout_key))
        });
        hook.reached.wait();

        let deposit_pool = Arc::clone(&pool);
        let deposit_key = key.clone();
        let deposit = thread::spawn(move || {
            futures::executor::block_on(deposit_pool.deposit_tcp(&deposit_key, second))
        });
        deposit.join().expect("deposit thread panicked");
        hook.resume.wait();

        let checked_out = checkout
            .join()
            .expect("checkout thread panicked")
            .expect("initial stream must be checked out");
        pool.check_invariants();
        assert_eq!(
            pool.ready_metrics().entries,
            1,
            "one deposited stream remains after the two operations"
        );
        let drained = pool
            .acquire_tcp(&key)
            .await
            .expect("the deposited stream must remain reachable");
        pool.check_invariants();
        assert!(
            pool.acquire_tcp(&key).await.is_none(),
            "the drain must leave no third stream"
        );

        let mut returned = [
            checked_out.local_addr().unwrap(),
            drained.local_addr().unwrap(),
        ];
        returned.sort_unstable();
        let mut expected = [first_id, second_id];
        expected.sort_unstable();
        assert_eq!(
            returned, expected,
            "checkout and drain must return each stream exactly once"
        );
        pool.check_invariants();
    }

    #[tokio::test]
    async fn race_deposit_vs_purge() {
        let pool = Arc::new(ConnectionPool::new());
        let server = spawn_hold_open_listener().await;
        let key = server.to_string();

        let first = TcpStream::connect(server).await.unwrap();
        pool.deposit_tcp(&key, first).await;
        pool.check_invariants();
        let second = TcpStream::connect(server).await.unwrap();
        let second_id = second.local_addr().unwrap();
        let hook = pool.install_pause_hook("deposit_before_lock");

        let deposit_pool = Arc::clone(&pool);
        let deposit_key = key.clone();
        let deposit = thread::spawn(move || {
            futures::executor::block_on(deposit_pool.deposit_tcp(&deposit_key, second))
        });
        hook.reached.wait();

        let purge_pool = Arc::clone(&pool);
        let purge_key = key.clone();
        let purge = thread::spawn(move || purge_pool.purge_node(Some(&purge_key), 1, Uuid::nil()));
        purge.join().expect("purge thread panicked");
        hook.resume.wait();
        deposit.join().expect("deposit thread panicked");

        pool.check_invariants();
        let entries = pool.ready_metrics().entries;
        match pool.acquire_tcp(&key).await {
            Some(stream) => {
                pool.check_invariants();
                assert_eq!(
                    entries, 1,
                    "a reachable deposited stream must be reflected in total"
                );
                assert_eq!(stream.local_addr().unwrap(), second_id);
                assert!(
                    pool.acquire_tcp(&key).await.is_none(),
                    "the stream must be consumed exactly once"
                );
            }
            None => {
                pool.check_invariants();
                assert_eq!(entries, 0, "a purge that wins must leave no counted stream");
                let replacement = TcpStream::connect(server).await.unwrap();
                pool.deposit_tcp(&key, replacement).await;
                pool.check_invariants();
                assert!(
                    pool.acquire_tcp(&key).await.is_some(),
                    "a subsequent deposit must succeed after a winning purge"
                );
                pool.check_invariants();
                assert!(
                    pool.acquire_tcp(&key).await.is_none(),
                    "the replacement must be consumed exactly once"
                );
            }
        }
        pool.check_invariants();
    }

    #[tokio::test]
    async fn race_checkout_vs_purge() {
        let pool = Arc::new(ConnectionPool::new());
        let server = spawn_hold_open_listener().await;
        let key = server.to_string();
        let stream = TcpStream::connect(server).await.unwrap();
        let stream_id = stream.local_addr().unwrap();
        pool.deposit_tcp(&key, stream).await;
        pool.check_invariants();

        let hook = pool.install_pause_hook("checkout_after_clone");
        let checkout_pool = Arc::clone(&pool);
        let checkout_key = key.clone();
        let checkout = thread::spawn(move || {
            futures::executor::block_on(checkout_pool.acquire_tcp(&checkout_key))
        });
        hook.reached.wait();

        let purge_pool = Arc::clone(&pool);
        let purge_key = key.clone();
        let purge = thread::spawn(move || {
            let before = purge_pool.ready_metrics().entries;
            purge_pool.purge_node(Some(&purge_key), 1, Uuid::nil());
            before > purge_pool.ready_metrics().entries
        });
        let purged = purge.join().expect("purge thread panicked");
        hook.resume.wait();

        let checked_out = checkout.join().expect("checkout thread panicked");
        assert_ne!(
            checked_out.is_some(),
            purged,
            "exactly one of checkout and purge must own the stream"
        );
        pool.check_invariants();
        assert_eq!(
            pool.ready_metrics().entries,
            0,
            "checkout and purge must account for the stream exactly once"
        );
        if let Some(stream) = checked_out {
            assert_eq!(
                stream.local_addr().unwrap(),
                stream_id,
                "a successful checkout must return the original stream"
            );
        }
        assert!(
            pool.acquire_tcp(&key).await.is_none(),
            "the stream must not remain reachable after checkout or purge"
        );
        pool.check_invariants();
    }

    #[tokio::test]
    async fn race_janitor_vs_deposit() {
        let pool = Arc::new(ConnectionPool::new());
        let server = spawn_hold_open_listener().await;
        let key = server.to_string();
        pool.check_invariants();
        let hook = pool.install_pause_hook("janitor_before_store");

        let janitor_pool = Arc::clone(&pool);
        let janitor =
            thread::spawn(move || futures::executor::block_on(janitor_pool.prune_expired()));
        hook.reached.wait();

        let stream = TcpStream::connect(server).await.unwrap();
        let deposit_pool = Arc::clone(&pool);
        let deposit_key = key.clone();
        let deposit = thread::spawn(move || {
            futures::executor::block_on(deposit_pool.deposit_tcp(&deposit_key, stream))
        });
        deposit.join().expect("deposit thread panicked");
        hook.resume.wait();
        janitor.join().expect("janitor thread panicked");

        assert_eq!(
            pool.ready_metrics().entries,
            1,
            "janitor must publish the competitor's deposited stream"
        );
        pool.check_invariants();
        pool.purge_node(Some(&key), 1, Uuid::nil());
        assert_eq!(
            pool.ready_metrics().entries,
            0,
            "purging the only stream must restore an empty total"
        );
        pool.check_invariants();
    }

    #[tokio::test]
    async fn test_pool_acquire_deposit() {
        let pool = ConnectionPool::new();
        let addr = spawn_hold_open_listener().await.to_string();

        assert!(pool.acquire_tcp(&addr).await.is_none());

        let stream = TcpStream::connect(&addr).await.unwrap();
        pool.deposit_tcp(&addr, stream).await;

        let acquired = pool.acquire_tcp(&addr).await;
        assert!(acquired.is_some());
    }

    #[tokio::test]
    async fn live_bare_check_prunes_expired_entry_for_repin() {
        let mut pool = ConnectionPool::new();
        pool.idle_timeout = Duration::from_millis(20);
        let addr = spawn_hold_open_listener().await.to_string();

        let first = TcpStream::connect(&addr).await.unwrap();
        pool.deposit_tcp(&addr, first).await;
        assert!(pool.has_live_bare_entry(&addr));
        assert_eq!(pool.ready_metrics().entries, 1);
        pool.check_invariants();

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!pool.has_live_bare_entry(&addr));
        assert_eq!(pool.ready_metrics().entries, 0);
        pool.check_invariants();

        let replacement = TcpStream::connect(&addr).await.unwrap();
        pool.deposit_tcp(&addr, replacement).await;
        assert!(pool.has_live_bare_entry(&addr));
        assert_eq!(pool.ready_metrics().entries, 1);
        pool.check_invariants();
    }

    #[tokio::test]
    async fn test_pool_global_cap_refused() {
        let pool = ConnectionPool::with_capacity_limit(1);
        let addr = spawn_hold_open_listener().await.to_string();
        pool.deposit_tcp(&addr, TcpStream::connect(&addr).await.unwrap())
            .await;
        pool.check_invariants();
        pool.deposit_tcp("other:443", TcpStream::connect(&addr).await.unwrap())
            .await;
        pool.check_invariants();
        assert!(pool.acquire_tcp("other:443").await.is_none());
        pool.check_invariants();
        assert!(pool.acquire_tcp(&addr).await.is_some());
        pool.check_invariants();
    }

    #[tokio::test]
    async fn explicit_pool_capacity_is_enforced() {
        let pool = ConnectionPool::with_capacity_limit(3);
        let addr = spawn_hold_open_listener().await.to_string();
        for _ in 0..4 {
            pool.deposit_tcp(&addr, TcpStream::connect(&addr).await.unwrap())
                .await;
            pool.check_invariants();
        }
        assert_eq!(pool.ready_metrics().entries, 3);
        for _ in 0..3 {
            assert!(pool.acquire_tcp(&addr).await.is_some());
            pool.check_invariants();
        }
        assert!(pool.acquire_tcp(&addr).await.is_none());
        pool.check_invariants();
    }

    /// Phase 5: hot-target gating — the first flow is cold, the second
    /// within the window is hot, and a different target stays cold.
    #[tokio::test]
    async fn test_note_target_hot_gating() {
        let pool = ConnectionPool::new();
        let generation = 1;
        let node_id = Uuid::from_u128(1);
        let key =
            ConnectionPool::ready_key(generation, node_id, "1.2.3.4:443".parse().unwrap(), None);
        assert!(!pool.note_target(generation, &key), "first flow is cold");
        assert!(
            pool.note_target(generation, &key),
            "second flow within window is hot"
        );
        assert!(pool.note_target(generation, &key), "stays hot");
        let other =
            ConnectionPool::ready_key(generation, node_id, "5.6.7.8:443".parse().unwrap(), None);
        assert!(!pool.note_target(generation, &other));
    }

    /// Phase 5: ready deposits stop at the per-node target cardinality.
    #[tokio::test]
    async fn test_ready_target_cardinality_cap() {
        let pool = ConnectionPool::new();
        let addr = spawn_hold_open_listener().await;
        let target = addr;
        let generation = 1;
        let node_id = Uuid::from_u128(1);
        for i in 0..MAX_READY_TARGETS_PER_NODE {
            let key_target =
                SocketAddr::new(std::net::Ipv4Addr::new(10, 0, 0, i as u8 + 1).into(), 443);
            let key = ConnectionPool::ready_key(generation, node_id, key_target, None);
            let tcp = TcpStream::connect(addr).await.unwrap();
            pool.deposit_ready(generation, &key, make_ready_stream(tcp, target))
                .await;
        }
        // One more distinct target for the same identity: refused.
        let key_target = SocketAddr::new(std::net::Ipv4Addr::new(10, 9, 9, 9).into(), 443);
        let key = ConnectionPool::ready_key(generation, node_id, key_target, None);
        let tcp = TcpStream::connect(addr).await.unwrap();
        pool.deposit_ready(generation, &key, make_ready_stream(tcp, target))
            .await;
        assert!(pool.acquire_ready(&key).await.is_none());
        // The ready metrics reflect one hit attempt (the refused acquire).
        let m = pool.ready_metrics();
        assert_eq!(m.misses, 1);
    }

    #[tokio::test]
    async fn test_pool_per_host_cap() {
        let pool = ConnectionPool::new();
        let addr = spawn_hold_open_listener().await.to_string();

        for _ in 0..MAX_PER_HOST + 3 {
            if let Ok(s) = TcpStream::connect(&addr).await {
                pool.deposit_tcp(&addr, s).await;
            }
        }
        // Only MAX_PER_HOST entries are retained; the rest can be acquired
        // and then the pool is empty.
        for _ in 0..MAX_PER_HOST {
            assert!(pool.acquire_tcp(&addr).await.is_some());
        }
        assert!(pool.acquire_tcp(&addr).await.is_none());
    }

    #[tokio::test]
    async fn test_pool_ready_roundtrip() {
        let pool = ConnectionPool::new();
        let server_addr = spawn_hold_open_listener().await;
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let generation = 1;
        let node_id = Uuid::from_u128(1);
        let key = ConnectionPool::ready_key(generation, node_id, target, None);

        assert!(pool.acquire_ready(&key).await.is_none());

        let tcp = TcpStream::connect(server_addr).await.unwrap();
        pool.deposit_ready(generation, &key, make_ready_stream(tcp, target))
            .await;

        let ready = pool.acquire_ready(&key).await.expect("ready entry");
        assert_eq!(ready.target_addr, target);
        // A checkout removes the entry: a second acquire must miss.
        assert!(pool.acquire_ready(&key).await.is_none());
        drop(ready);
    }
    #[tokio::test]
    async fn test_pool_ready_key_namespacing() {
        // Ready keys are disjoint from bare keys and bind generation,
        // identity, target, and optional domain.
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let generation = 1;
        let node_id = Uuid::from_u128(1);
        let other_node_id = Uuid::from_u128(2);
        let k1 = ConnectionPool::ready_key(generation, node_id, target, None);
        let k2 = ConnectionPool::ready_key(generation, node_id, target, Some("example.com"));
        let k3 = ConnectionPool::ready_key(generation, other_node_id, target, None);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, "proxy.example:1080");
        assert!(k1.contains('|'));
    }

    #[tokio::test]
    async fn test_pool_ready_idle_ttl() {
        let mut pool = ConnectionPool::new();
        pool.set_ready_idle_timeout(Duration::from_millis(50));
        let server_addr = spawn_hold_open_listener().await;
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        // Ready entry expires after the short TTL.
        let generation = 1;
        let node_id = Uuid::from_u128(1);
        let key = ConnectionPool::ready_key(generation, node_id, target, None);
        let tcp = TcpStream::connect(server_addr).await.unwrap();
        pool.deposit_ready(generation, &key, make_ready_stream(tcp, target))
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(pool.acquire_ready(&key).await.is_none());

        // Bare entries still use the default 60s TTL and survive.
        let bare_tcp = TcpStream::connect(server_addr).await.unwrap();
        pool.deposit_tcp("server:1080", bare_tcp).await;
        assert!(pool.acquire_tcp("server:1080").await.is_some());
    }

    #[tokio::test]
    async fn test_pool_ready_dead_fin_evicted() {
        let pool = ConnectionPool::new();
        // Server accepts and immediately closes → client receives FIN.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((s, _)) = listener.accept().await {
                drop(s); // orderly FIN
            }
        });

        let tcp = TcpStream::connect(server_addr).await.unwrap();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let stream = make_ready_stream(tcp, target);

        // Wait until the FIN reaches the client kernel and the probe sees it.
        let mut saw_fin = false;
        for _ in 0..100 {
            if !ConnectionPool::is_ready_stream_alive(&stream) {
                saw_fin = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(saw_fin, "MSG_PEEK never observed the peer FIN");

        // A dead ready entry must not be handed out.
        let key = ConnectionPool::ready_key(1, Uuid::from_u128(1), target, None);
        pool.deposit_ready(1, &key, stream).await;
        assert!(pool.acquire_ready(&key).await.is_none());
    }

    #[tokio::test]
    async fn bare_pool_rejects_unsolicited_bytes_at_admission_checkout_and_warm_gauge() {
        const TLS_FATAL_ALERT: &[u8] = &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x50];
        let pool = ConnectionPool::new();

        let (checkout, mut checkout_server) = tcp_pair().await;
        let checkout_fd = checkout.as_raw_fd();
        assert!(pool.deposit_tcp("checkout", checkout).await);
        checkout_server.write_all(TLS_FATAL_ALERT).await.unwrap();
        // The peer remains open: rejection must come from the queued bytes,
        // not an orderly shutdown.
        wait_for_queued_byte(checkout_fd).await;
        assert!(
            pool.acquire_tcp("checkout").await.is_none(),
            "checkout must not expose a bare socket with queued bytes"
        );

        let (warm, mut warm_server) = tcp_pair().await;
        let warm_fd = warm.as_raw_fd();
        assert!(pool.deposit_tcp("warm", warm).await);
        warm_server.write_all(TLS_FATAL_ALERT).await.unwrap();
        wait_for_queued_byte(warm_fd).await;
        assert!(
            !pool.has_live_bare_entry("warm"),
            "the warm gauge must purge a bare socket with queued bytes"
        );

        let (admission, mut admission_server) = tcp_pair().await;
        let admission_fd = admission.as_raw_fd();
        admission_server.write_all(TLS_FATAL_ALERT).await.unwrap();
        wait_for_queued_byte(admission_fd).await;
        assert!(
            !pool.deposit_tcp("admission", admission).await,
            "pool admission must reject a bare socket with queued bytes"
        );

        let (ready, mut ready_server) = tcp_pair().await;
        let ready_fd = ready.as_raw_fd();
        let target = "192.0.2.1:443".parse().unwrap();
        let key = ConnectionPool::ready_key(1, Uuid::from_u128(1), target, None);
        pool.deposit_ready(1, &key, make_ready_stream(ready, target))
            .await;
        ready_server.write_all(b"READY").await.unwrap();
        wait_for_queued_byte(ready_fd).await;
        let mut ready = pool
            .acquire_ready(&key)
            .await
            .expect("ready streams may carry buffered target data");
        let mut payload = [0u8; 5];
        ready.stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"READY");

        assert_eq!(pool.ready_metrics().entries, 0);
        pool.check_invariants();
    }

    #[tokio::test]
    async fn test_pool_bare_dead_fin_evicted() {
        let pool = ConnectionPool::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });
        let tcp = TcpStream::connect(server_addr).await.unwrap();

        for _ in 0..100 {
            if !is_bare_tcp_stream_usable(&tcp) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !is_bare_tcp_stream_usable(&tcp),
            "MSG_PEEK never observed the peer FIN"
        );
        pool.deposit_tcp("proxy.example:1080", tcp).await;
        assert!(pool.acquire_tcp("proxy.example:1080").await.is_none());
    }

    /// End-to-end: an authenticated SOCKS5 stream pooled after a full dial is
    /// reused without repeating the greeting/CONNECT handshake.
    #[tokio::test]
    async fn test_socks5_ready_reuse_skips_handshake() {
        let fixture = ReadyIdentitySocks5Fixture::bind().await;
        let node = ready_identity_socks5_node(fixture.addr(), "a", "a", "reuse");
        let handler = Socks5Handler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let stream = handler
            .dial(&node, target, None, Duration::from_secs(3))
            .await
            .unwrap();
        let pool = ConnectionPool::new();
        let generation = 1;
        let key = ConnectionPool::ready_key(generation, node.id, target, None);
        pool.deposit_ready(generation, &key, stream).await;

        // Raw application bytes on checkout must receive the authenticated
        // fixture response, not a second SOCKS5 handshake.
        let mut reused = pool.acquire_ready(&key).await.expect("ready stream");
        reused.stream.write_all(b"PING").await.unwrap();
        let mut reply = [0u8; 3];
        tokio::time::timeout(Duration::from_secs(3), reused.stream.read_exact(&mut reply))
            .await
            .expect("SOCKS5 consumer reply timed out")
            .unwrap();
        assert_eq!(&reply, b"a:a");
        assert_eq!(fixture.observed_auths().await.len(), 1);
        pool.check_invariants();
    }

    /// A dead node's bare AND ready entries must all be purged; other
    /// nodes' entries stay.
    #[tokio::test]
    async fn test_purge_node_removes_bare_and_ready() {
        let pool = ConnectionPool::new();
        let server = spawn_hold_open_listener().await;
        let dead_addr = "dead.example:1080";
        let other_addr = "other.example:1080";
        let dead_id = Uuid::from_u128(1);
        let other_id = Uuid::from_u128(2);
        let generation = 1;
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        for (addr, node_id) in [(dead_addr, dead_id), (other_addr, other_id)] {
            let tcp = TcpStream::connect(server).await.unwrap();
            pool.deposit_tcp(addr, tcp).await;
            let key = ConnectionPool::ready_key(generation, node_id, target, None);
            let tcp = TcpStream::connect(server).await.unwrap();
            pool.deposit_ready(generation, &key, make_ready_stream(tcp, target))
                .await;
        }
        pool.purge_node(Some(dead_addr), generation, dead_id);
        assert!(pool.acquire_tcp(dead_addr).await.is_none());
        let dead_key = ConnectionPool::ready_key(generation, dead_id, target, None);
        assert!(pool.acquire_ready(&dead_key).await.is_none());
        // Other node untouched.
        assert!(pool.acquire_tcp(other_addr).await.is_some());
        let other_key = ConnectionPool::ready_key(generation, other_id, target, None);
        assert!(pool.acquire_ready(&other_key).await.is_some());
    }
    #[tokio::test]
    async fn test_dial_permits_cap_concurrent_callers() {
        use std::sync::atomic::AtomicUsize;

        let generation = Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[], 3, None)
                .unwrap()
                .0,
        );
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..12 {
            let generation = Arc::clone(&generation);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            tasks.spawn(async move {
                let _permit = generation.acquire_dial_permit().await;
                let now = active.fetch_add(1, Ordering::AcqRel) + 1;
                peak.fetch_max(now, Ordering::AcqRel);
                tokio::time::sleep(Duration::from_millis(20)).await;
                active.fetch_sub(1, Ordering::AcqRel);
            });
        }
        while tasks.join_next().await.is_some() {}
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert_eq!(peak.load(Ordering::Acquire), 3);
    }

    #[tokio::test]
    async fn test_ready_target_cap_is_atomic_under_parallel_deposits() {
        let pool = Arc::new(ConnectionPool::new());
        let server = spawn_hold_open_listener().await;
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let generation = 1;
        let node_id = Uuid::from_u128(1);
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..MAX_READY_TARGETS_PER_NODE + 16 {
            let pool = Arc::clone(&pool);
            tasks.spawn(async move {
                let key_target: SocketAddr = format!("198.51.100.{i}:443").parse().unwrap();
                let key = ConnectionPool::ready_key(generation, node_id, key_target, None);
                let tcp = TcpStream::connect(server).await.unwrap();
                pool.deposit_ready(generation, &key, make_ready_stream(tcp, target))
                    .await;
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
            pool.check_invariants();
        }
        assert_eq!(
            pool.ready_metrics().entries,
            MAX_READY_TARGETS_PER_NODE as u64
        );
        pool.purge_node(Some("node:443"), generation, node_id);
        pool.check_invariants();
        assert_eq!(pool.ready_metrics().entries, 0);
        let key_target: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let key = ConnectionPool::ready_key(generation, node_id, key_target, None);
        let tcp = TcpStream::connect(server).await.unwrap();
        pool.deposit_ready(generation, &key, make_ready_stream(tcp, target))
            .await;
        pool.check_invariants();
        assert!(pool.acquire_ready(&key).await.is_some());
        pool.check_invariants();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_total_cap_never_overshoots_under_parallel_deposits() {
        let pool = Arc::new(ConnectionPool::with_capacity_limit(4));
        let server = spawn_hold_open_listener().await;
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..32 {
            let pool = Arc::clone(&pool);
            tasks.spawn(async move {
                let stream = TcpStream::connect(server).await.unwrap();
                pool.deposit_tcp(&format!("node-{i}:443"), stream).await;
                pool.check_invariants();
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
            pool.check_invariants();
        }
        assert_eq!(pool.ready_metrics().entries, 4);
        let mut acquired = 0;
        for i in 0..32 {
            acquired += usize::from(pool.acquire_tcp(&format!("node-{i}:443")).await.is_some());
            pool.check_invariants();
        }
        assert_eq!(acquired, 4);
        assert_eq!(pool.ready_metrics().entries, 0);
    }

    #[test]
    fn test_warm_key_singleflight_and_drop_releases_claim() {
        let pool = ConnectionPool::new();
        let generation = 1;
        let node_id = Uuid::from_u128(1);
        let target: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let key = ConnectionPool::ready_key(generation, node_id, target, None);
        let guard = pool
            .try_begin_warm(generation, &key)
            .expect("first warmer owns key");
        assert!(
            pool.try_begin_warm(generation, &key).is_none(),
            "follower must not duplicate warm dial"
        );
        drop(guard);
        assert!(
            pool.try_begin_warm(generation, &key).is_some(),
            "cancelled/failed owner must release key"
        );
    }

    #[test]
    fn test_hot_map_refuses_new_keys_at_bound_without_scan() {
        let pool = ConnectionPool::new();
        let generation = 1;
        let node_id = Uuid::from_u128(1);
        for i in 0..4096 {
            let target = SocketAddr::new(
                std::net::Ipv4Addr::new(192, 0, (i / 256) as u8, (i % 256) as u8).into(),
                443,
            );
            let key = ConnectionPool::ready_key(generation, node_id, target, None);
            assert!(!pool.note_target(generation, &key));
            pool.check_invariants();
        }
        let new_target: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let new_key = ConnectionPool::ready_key(generation, node_id, new_target, None);
        assert!(!pool.note_target(generation, &new_key));
        pool.check_invariants();
        assert!(!pool.note_target(generation, &new_key));
        pool.check_invariants();
        let first_target: SocketAddr = "192.0.0.0:443".parse().unwrap();
        let first_key = ConnectionPool::ready_key(generation, node_id, first_target, None);
        assert!(pool.note_target(generation, &first_key));
        pool.check_invariants();
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ReadyIdentitySocks5Auth {
        username: String,
        password: String,
    }

    struct ReadyIdentitySocks5Fixture {
        addr: SocketAddr,
        observed: Arc<tokio::sync::Mutex<Vec<ReadyIdentitySocks5Auth>>>,
        accept_task: tokio::task::JoinHandle<()>,
    }

    impl ReadyIdentitySocks5Fixture {
        async fn bind() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let observed = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let task_observed = Arc::clone(&observed);
            let accept_task = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let Ok((stream, _)) = accepted else { break };
                            let observed = Arc::clone(&task_observed);
                            connections.spawn(async move {
                                let _ = serve_ready_identity_socks5(stream, observed).await;
                            });
                        }
                        result = connections.join_next(), if !connections.is_empty() => {
                            let _ = result;
                        }
                    }
                }
            });
            Self {
                addr,
                observed,
                accept_task,
            }
        }

        fn addr(&self) -> SocketAddr {
            self.addr
        }

        async fn observed_auths(&self) -> Vec<ReadyIdentitySocks5Auth> {
            self.observed.lock().await.clone()
        }
    }

    impl Drop for ReadyIdentitySocks5Fixture {
        fn drop(&mut self) {
            // The accept task owns a JoinSet, so aborting it also aborts all
            // connection handlers instead of leaving detached fixture tasks.
            self.accept_task.abort();
        }
    }

    async fn serve_ready_identity_socks5(
        mut stream: TcpStream,
        observed: Arc<tokio::sync::Mutex<Vec<ReadyIdentitySocks5Auth>>>,
    ) -> std::io::Result<()> {
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await?;
        if greeting[0] != 0x05 {
            return Ok(());
        }
        let mut methods = vec![0u8; greeting[1] as usize];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&0x02) {
            return Ok(());
        }
        stream.write_all(&[0x05, 0x02]).await?;

        let mut auth_header = [0u8; 2];
        stream.read_exact(&mut auth_header).await?;
        if auth_header[0] != 0x01 {
            return Ok(());
        }
        let mut username = vec![0u8; auth_header[1] as usize];
        stream.read_exact(&mut username).await?;
        let mut password_len = [0u8; 1];
        stream.read_exact(&mut password_len).await?;
        let mut password = vec![0u8; password_len[0] as usize];
        stream.read_exact(&mut password).await?;
        let username = String::from_utf8_lossy(&username).into_owned();
        let password = String::from_utf8_lossy(&password).into_owned();
        observed.lock().await.push(ReadyIdentitySocks5Auth {
            username: username.clone(),
            password: password.clone(),
        });
        stream.write_all(&[0x01, 0x00]).await?;

        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await?;
        let mut destination = match request[3] {
            0x01 => vec![0u8; 6],
            0x04 => vec![0u8; 18],
            0x03 => {
                let mut length = [0u8; 1];
                stream.read_exact(&mut length).await?;
                vec![0u8; length[0] as usize + 2]
            }
            _ => return Ok(()),
        };
        stream.read_exact(&mut destination).await?;
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        // The consumer writes a marker after either taking a pooled stream or
        // falling back to a fresh dial. Reply with the credentials authenticated
        // on this actual RFC1929 connection, making cross-identity reuse visible
        // to the consumer rather than only through a key assertion.
        let response = format!("{username}:{password}");
        loop {
            let mut marker = [0u8; 4];
            if stream.read_exact(&mut marker).await.is_err() {
                return Ok(());
            }
            if &marker != b"PING" {
                return Ok(());
            }
            stream.write_all(response.as_bytes()).await?;
        }
    }

    fn ready_identity_socks5_node(
        addr: SocketAddr,
        username: &str,
        password: &str,
        name: &str,
    ) -> Node {
        let mut node =
            Node::from_share_link(&format!("socks5://{username}:{password}@{addr}#{name}"))
                .unwrap();
        node.id = node.derive_id();
        node
    }

    fn ready_identity_trojan_node(addr: SocketAddr, sni: &str, name: &str) -> Node {
        let mut node =
            Node::from_share_link(&format!("trojan://secret@{addr}?sni={sni}#{name}")).unwrap();
        node.id = node.derive_id();
        node
    }

    #[tokio::test]
    async fn ready_identity_socks5_credentials_do_not_share() {
        let fixture = ReadyIdentitySocks5Fixture::bind().await;
        let node_a = ready_identity_socks5_node(fixture.addr(), "a", "a", "ready-a");
        let node_b = ready_identity_socks5_node(fixture.addr(), "b", "b", "ready-b");
        assert_ne!(node_a.id, node_b.id);

        let target: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let handler = Socks5Handler::new();
        let pool = ConnectionPool::new();
        let generation = 1;
        let key_a = ConnectionPool::ready_key(generation, node_a.id, target, None);
        let key_b = ConnectionPool::ready_key(generation, node_b.id, target, None);

        let stream_a = tokio::time::timeout(
            Duration::from_secs(3),
            handler.dial(&node_a, target, None, Duration::from_secs(3)),
        )
        .await
        .expect("SOCKS5 A dial timed out")
        .unwrap();
        pool.deposit_ready(generation, &key_a, stream_a).await;
        pool.check_invariants();

        // Distinct identity keys force B's physical dial when no B stream is pooled.
        let mut stream_b = match pool.acquire_ready(&key_b).await {
            Some(stream) => stream,
            None => tokio::time::timeout(
                Duration::from_secs(3),
                handler.dial(&node_b, target, None, Duration::from_secs(3)),
            )
            .await
            .expect("SOCKS5 B fallback dial timed out")
            .unwrap(),
        };
        pool.check_invariants();

        stream_b.stream.write_all(b"PING").await.unwrap();
        let mut reply = [0u8; 3];
        tokio::time::timeout(
            Duration::from_secs(3),
            stream_b.stream.read_exact(&mut reply),
        )
        .await
        .expect("SOCKS5 consumer reply timed out")
        .unwrap();
        let observed = fixture.observed_auths().await;
        assert_eq!(
            &reply, b"b:b",
            "B's consumer must use a stream authenticated as B"
        );
        assert!(
            observed
                .iter()
                .any(|auth| auth.username == "b" && auth.password == "b"),
            "the RFC1929 server did not observe B credentials: {observed:?}"
        );
        drop(stream_b);
        pool.check_invariants();
    }

    #[tokio::test]
    async fn ready_identity_trojan_sni_do_not_share() {
        let server = spawn_hold_open_listener().await;
        let node_a = ready_identity_trojan_node(server, "a.example", "trojan-a");
        let node_b = ready_identity_trojan_node(server, "b.example", "trojan-b");
        assert_ne!(node_a.id, node_b.id);
        assert_eq!(node_a.host(), node_b.host());
        assert_eq!(node_a.port, node_b.port);

        let target: SocketAddr = "192.0.2.20:443".parse().unwrap();
        let pool = ConnectionPool::new();
        let key_a = ConnectionPool::ready_key(1, node_a.id, target, None);
        let key_b = ConnectionPool::ready_key(1, node_b.id, target, None);
        let tcp = TcpStream::connect(server).await.unwrap();
        pool.deposit_ready(1, &key_a, make_ready_stream(tcp, target))
            .await;

        assert!(
            pool.acquire_ready(&key_b).await.is_none(),
            "a TCP Trojan stream for SNI A must not be consumed by SNI B"
        );
        pool.check_invariants();
    }

    #[tokio::test]
    async fn ready_identity_generation_do_not_share() {
        let server = spawn_hold_open_listener().await;
        let node = ready_identity_socks5_node(server, "same", "same", "generation");
        let target: SocketAddr = "192.0.2.30:443".parse().unwrap();
        let pool = ConnectionPool::new();
        let key_generation_one = ConnectionPool::ready_key(1, node.id, target, None);
        let key_generation_two = ConnectionPool::ready_key(2, node.id, target, None);

        let tcp = TcpStream::connect(server).await.unwrap();
        pool.deposit_ready(1, &key_generation_one, make_ready_stream(tcp, target))
            .await;
        pool.check_invariants();

        assert!(
            pool.acquire_ready(&key_generation_two).await.is_none(),
            "a generation-1 stream must not be consumed by generation 2"
        );
        pool.check_invariants();
    }

    #[tokio::test]
    async fn ready_identity_purge_a_preserves_b_same_address() {
        let server = spawn_hold_open_listener().await;
        let node_a = ready_identity_socks5_node(server, "a", "a", "purge-a");
        let node_b = ready_identity_socks5_node(server, "b", "b", "purge-b");
        assert_ne!(node_a.id, node_b.id);

        let target_a: SocketAddr = "192.0.2.40:443".parse().unwrap();
        let target_b: SocketAddr = "192.0.2.41:443".parse().unwrap();
        let pool = ConnectionPool::new();
        let generation = 1;
        let key_a = ConnectionPool::ready_key(generation, node_a.id, target_a, None);
        let key_b = ConnectionPool::ready_key(generation, node_b.id, target_b, None);

        let tcp_a = TcpStream::connect(server).await.unwrap();
        pool.deposit_ready(generation, &key_a, make_ready_stream(tcp_a, target_a))
            .await;
        pool.check_invariants();
        let tcp_b = TcpStream::connect(server).await.unwrap();
        pool.deposit_ready(generation, &key_b, make_ready_stream(tcp_b, target_b))
            .await;
        pool.check_invariants();

        let node_addr = format!("{}:{}", node_a.host(), node_a.port);
        pool.purge_node(Some(&node_addr), generation, node_a.id);
        pool.check_invariants();

        assert!(pool.acquire_ready(&key_a).await.is_none());
        pool.check_invariants();
        let survivor = pool
            .acquire_ready(&key_b)
            .await
            .expect("purging A must preserve B's same-address stream");
        assert_eq!(survivor.target_addr, target_b);
        pool.check_invariants();
    }

    #[tokio::test]
    async fn ready_identity_each_id_gets_64_target_budget() {
        let server = spawn_hold_open_listener().await;
        let node_a = ready_identity_socks5_node(server, "a", "a", "budget-a");
        let node_b = ready_identity_socks5_node(server, "b", "b", "budget-b");
        assert_ne!(node_a.id, node_b.id);
        let pool = ConnectionPool::new();

        for index in 1..=64u8 {
            let target = SocketAddr::new(std::net::Ipv4Addr::new(192, 0, 2, index).into(), 443);
            let key = ConnectionPool::ready_key(1, node_a.id, target, None);
            let tcp = TcpStream::connect(server).await.unwrap();
            pool.deposit_ready(1, &key, make_ready_stream(tcp, target))
                .await;
            pool.check_invariants();
        }
        for index in 1..=64u8 {
            let target = SocketAddr::new(std::net::Ipv4Addr::new(198, 51, 100, index).into(), 443);
            let key = ConnectionPool::ready_key(1, node_b.id, target, None);
            let tcp = TcpStream::connect(server).await.unwrap();
            pool.deposit_ready(1, &key, make_ready_stream(tcp, target))
                .await;
            pool.check_invariants();
        }

        assert_eq!(pool.ready_metrics().entries, 128);
        for index in 1..=64u8 {
            let target = SocketAddr::new(std::net::Ipv4Addr::new(192, 0, 2, index).into(), 443);
            let key = ConnectionPool::ready_key(1, node_a.id, target, None);
            assert!(
                pool.acquire_ready(&key).await.is_some(),
                "identity A lost target {target}"
            );
            pool.check_invariants();
        }
        for index in 1..=64u8 {
            let target = SocketAddr::new(std::net::Ipv4Addr::new(198, 51, 100, index).into(), 443);
            let key = ConnectionPool::ready_key(1, node_b.id, target, None);
            assert!(
                pool.acquire_ready(&key).await.is_some(),
                "identity B lost target {target}"
            );
            pool.check_invariants();
        }
    }

    #[tokio::test]
    async fn ready_retirement_clears_generation_and_preserves_successor() {
        let pool = ConnectionPool::new();
        let server = spawn_hold_open_listener().await;
        let target = "192.0.2.1:443".parse().unwrap();
        let node_id = Uuid::from_u128(1);
        let old = ConnectionPool::ready_key(1, node_id, target, None);
        let next = ConnectionPool::ready_key(2, node_id, target, None);
        for (generation, key) in [(1, &old), (2, &next)] {
            let tcp = TcpStream::connect(server).await.unwrap();
            pool.deposit_ready(generation, key, make_ready_stream(tcp, target))
                .await;
            pool.check_invariants();
            assert!(!pool.note_target(generation, key));
            pool.check_invariants();
            assert!(pool.note_target(generation, key));
            pool.check_invariants();
        }
        let old_guard = pool.try_begin_warm(1, &old).unwrap();
        pool.check_invariants();
        let next_guard = pool.try_begin_warm(2, &next).unwrap();
        pool.check_invariants();
        pool.retire_generation(1);
        pool.check_invariants();
        assert!(pool.acquire_ready(&old).await.is_none());
        pool.check_invariants();
        {
            let state = pool.state.lock();
            assert!(state.retired.contains(&1));
            assert!(!state.retired.contains(&2));
            assert!(!state.hot.contains_key(&old));
            assert!(!state.warm_dials.contains(&old));
            assert!(
                !state
                    .ready_targets
                    .contains_key(ConnectionPool::ready_node(&old))
            );
            assert!(state.hot.contains_key(&next));
            assert!(state.warm_dials.contains(&next));
        }
        assert!(pool.acquire_ready(&next).await.is_some());
        pool.check_invariants();
        drop(old_guard);
        pool.check_invariants();
        assert!(pool.try_begin_warm(2, &next).is_none());
        pool.check_invariants();
        drop(next_guard);
        pool.check_invariants();
        assert!(pool.try_begin_warm(2, &next).is_some());
        pool.check_invariants();
    }

    #[tokio::test]
    async fn ready_retirement_refuses_late_deposit() {
        let pool = ConnectionPool::new();
        let server = spawn_hold_open_listener().await;
        let target = "192.0.2.1:443".parse().unwrap();
        let generation = 1;
        let key = ConnectionPool::ready_key(generation, Uuid::from_u128(1), target, None);
        pool.retire_generation(generation);
        pool.check_invariants();
        let tcp = TcpStream::connect(server).await.unwrap();
        pool.deposit_ready(generation, &key, make_ready_stream(tcp, target))
            .await;
        pool.check_invariants();
        assert!(pool.acquire_ready(&key).await.is_none());
        pool.check_invariants();
    }

    #[test]
    fn ready_retirement_refuses_late_hotness() {
        let pool = ConnectionPool::new();
        let generation = 1;
        let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let key = ConnectionPool::ready_key(generation, Uuid::from_u128(1), target, None);
        pool.retire_generation(generation);
        pool.check_invariants();
        assert!(!pool.note_target(generation, &key));
        pool.check_invariants();
        assert!(!pool.note_target(generation, &key));
        pool.check_invariants();
        assert!(!pool.state.lock().hot.contains_key(&key));
    }

    #[test]
    fn ready_retirement_refuses_late_warm_claim() {
        let pool = ConnectionPool::new();
        let generation = 1;
        let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let key = ConnectionPool::ready_key(generation, Uuid::from_u128(1), target, None);
        pool.retire_generation(generation);
        pool.check_invariants();
        assert!(pool.try_begin_warm(generation, &key).is_none());
        pool.check_invariants();
    }
    #[test]
    fn ready_retirement_reclaims_hotness_across_seventy_generations() {
        let pool = ConnectionPool::new();
        let node_id = Uuid::from_u128(1);
        for generation in 1..=70 {
            for port in 1..=64 {
                let target = SocketAddr::from(([192, 0, 2, 1], port));
                let key = ConnectionPool::ready_key(generation, node_id, target, None);
                assert!(!pool.note_target(generation, &key));
                pool.check_invariants();
                assert!(
                    pool.note_target(generation, &key),
                    "generation {generation} must become hot"
                );
                pool.check_invariants();
            }
            pool.retire_generation(generation);
            pool.check_invariants();
        }
    }
}
