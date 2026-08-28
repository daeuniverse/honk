//! TCP connection pool for proxy dials.
//!
//! Two entry kinds, both capped at 8 per key and 300s max age:
//!
//! - **Bare** — a pre-handshake `TcpStream` to the proxy server (60s idle
//!   TTL), keyed by the server's `"host:port"` and reused via
//!   `TcpOutbound::dial_with_tcp`. Saves the TCP connect RTT only.
//! - **Ready** — a fully-dialed `ProxyStream` whose protocol handshake is
//!   complete (SOCKS5 CONNECT done, Trojan TLS + request header written),
//!   reused *directly* as the data channel with no handshake at all.
//!   Idle TTL is shorter (30s): a target-bound tunnel holds more
//!   server-side state than a bare TCP connection and servers reap idle
//!   tunnels sooner.
//!
//! Ready keys are namespaced (`ready|<node_addr>|<target>`) so they can
//! never collide with bare `"host:port"` keys (`|` cannot appear in a
//! host:port pair). The key binds BOTH the proxy node and the target
//! because the completed handshake already committed the stream to that
//! exact pair — lookup by the same pair is the only correct reuse.
//!
//! Budgets beyond the per-key cap: an explicit global FD capacity (bounded by
//! [`MAX_TOTAL_ENTRIES`]), a per-node ready-target cardinality cap
//! ([`MAX_READY_TARGETS_PER_NODE`]), and hot-target gating
//! ([`ConnectionPool::note_target`]) so only repeat destinations earn a
//! speculative ready deposit. Deposits are also capability-checked at the
//! call site (multiplexed handlers never deposit ready entries — their
//! session pool already owns reuse). Hit/miss/entry counters feed the
//! clash API `/stats`.

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tracing::{debug, trace};

use honk_outbound::proxy::ProxyStream;

const MAX_PER_HOST: usize = 8;
/// Global cap across all keys (bare + ready) — an FD budget, not just a
/// per-key one: deposits past it are refused.
pub(crate) const MAX_TOTAL_ENTRIES: usize = 2048;
/// Distinct ready targets per node — bounds target-cardinality-driven
/// ready pools (a scanner hitting thousands of hosts must not turn the
/// pool into thousands of dialed tunnels).
const MAX_READY_TARGETS_PER_NODE: usize = 64;
/// Ready deposits are made only for "hot" targets: at least this many
/// flows to the same (node, target) within [`HOT_WINDOW`]. A one-off
/// flow never triggers a speculative ready dial.
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

pub struct ConnectionPool {
    entries: DashMap<String, Arc<Mutex<Vec<TimedStream>>>>,
    total_entries: AtomicU64,
    capacity_limit: u64,
    /// Ready-key cardinality per node, updated only when a ready key enters
    /// or leaves `entries`; no deposit scans every shard.
    ready_targets: DashMap<String, Arc<AtomicU64>>,
    /// One background warmer per ready key. Followers retain the existing
    /// ready entry or wait for the next flow rather than duplicate a dial.
    warm_dials: DashMap<String, ()>,
    idle_timeout: Duration,
    ready_idle_timeout: Duration,
    max_age: Duration,
    /// Target hotness for ready-deposit gating (`ready|node|target` →
    /// (flow count, window start)). This remains strictly bounded: stale
    /// entries are reset on their next access, never reclaimed by a scan.
    hot: DashMap<String, (u32, Instant)>,
    hot_entries: AtomicU64,
    ready_hits: AtomicU64,
    ready_misses: AtomicU64,
}

pub(crate) struct WarmDialGuard<'a> {
    pool: &'a ConnectionPool,
    key: String,
}

impl Drop for WarmDialGuard<'_> {
    fn drop(&mut self) {
        self.pool.warm_dials.remove(&self.key);
    }
}

/// Ready-pool metrics snapshot (clash API `/stats`).
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadyPoolMetrics {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
}

pub(crate) fn is_tcp_stream_alive(stream: &TcpStream) -> bool {
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
        Ok(0) => false,
        Ok(_) => true,
        Err(nix::errno::Errno::ECONNRESET | nix::errno::Errno::ENOTCONN) => false,
        Err(_) => true,
    }
}

impl ConnectionPool {
    /// Construct a max-capacity pool for tests and standalone callers.
    pub fn new() -> Self {
        Self::with_capacity_limit(MAX_TOTAL_ENTRIES)
    }

    pub(crate) fn with_capacity_limit(capacity_limit: usize) -> Self {
        Self {
            entries: DashMap::new(),
            total_entries: AtomicU64::new(0),
            capacity_limit: capacity_limit.min(MAX_TOTAL_ENTRIES) as u64,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            ready_idle_timeout: READY_IDLE_TIMEOUT,
            ready_targets: DashMap::new(),
            warm_dials: DashMap::new(),
            max_age: DEFAULT_MAX_AGE,
            hot: DashMap::new(),
            hot_entries: AtomicU64::new(0),
            ready_hits: AtomicU64::new(0),
            ready_misses: AtomicU64::new(0),
        }
    }

    /// Record one flow to `key` (a `ready|…` key) and report whether the
    /// target is hot enough to justify a speculative ready deposit
    /// ([`HOT_THRESHOLD`] flows within [`HOT_WINDOW`]).
    pub(crate) fn note_target(&self, key: &str) -> bool {
        const MAX_HOT_TARGETS: u64 = 4096;
        match self.hot.entry(key.to_owned()) {
            Entry::Occupied(mut entry) => {
                let value = entry.get_mut();
                if value.1.elapsed() > HOT_WINDOW {
                    *value = (0, Instant::now());
                }
                value.0 += 1;
                value.0 >= HOT_THRESHOLD
            }
            Entry::Vacant(entry) => {
                if self
                    .hot_entries
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                        (current < MAX_HOT_TARGETS).then_some(current + 1)
                    })
                    .is_err()
                {
                    return false;
                }
                entry.insert((1, Instant::now()));
                false
            }
        }
    }

    /// Claim one background warming dial for this ready key. The returned
    /// guard clears the claim on drop, including cancellation and failures.
    pub(crate) fn try_begin_warm(&self, key: &str) -> Option<WarmDialGuard<'_>> {
        match self.warm_dials.entry(key.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(());
                Some(WarmDialGuard {
                    pool: self,
                    key: key.to_owned(),
                })
            }
            Entry::Occupied(_) => None,
        }
    }

    #[cfg(any(test, feature = "clash-api"))]
    pub(crate) fn ready_metrics(&self) -> ReadyPoolMetrics {
        ReadyPoolMetrics {
            hits: self.ready_hits.load(Ordering::Relaxed),
            misses: self.ready_misses.load(Ordering::Relaxed),
            entries: self.total_entries.load(Ordering::Relaxed),
        }
    }

    #[cfg(test)]
    fn set_ready_idle_timeout(&mut self, timeout: Duration) {
        self.ready_idle_timeout = timeout;
    }

    /// Pool key for a Ready entry. The completed handshake bound the
    /// stream to (proxy node, target), so the key contains both; with
    /// domain routing the CONNECT request carries the domain, making
    /// `domain:port` — not the resolved IP — the destination identity.
    pub(crate) fn ready_key(
        node_addr: &str,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> String {
        match target_domain {
            Some(domain) => format!("ready|{}|{}:{}", node_addr, domain, target.port()),
            None => format!("ready|{}|{}", node_addr, target),
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
        let arc = Arc::clone(&*self.entries.get(addr)?);
        let mut list = arc.lock();

        let now = Instant::now();
        let mut found_idx: Option<usize> = None;
        for (i, entry) in list.iter().rev().enumerate() {
            let idx = list.len() - 1 - i;
            if !Self::entry_matches(entry, want_ready) {
                continue;
            }
            if self.entry_expired(entry, now) {
                continue;
            }
            if Self::is_entry_alive(entry) {
                found_idx = Some(idx);
                break;
            }
        }

        match found_idx {
            Some(idx) => {
                let entry = list.swap_remove(idx);
                self.total_entries.fetch_sub(1, Ordering::Relaxed);
                trace!(
                    "Pool hit ({}): {} ({} idle remaining)",
                    if want_ready { "ready" } else { "bare" },
                    addr,
                    list.len()
                );
                if list.is_empty() {
                    drop(list);
                    if self.entries.remove(addr).is_some() && want_ready {
                        self.release_ready_target(&Self::ready_node(addr));
                    }
                }
                Some(entry.stream)
            }
            None => {
                let before = list.len();
                list.retain(|e| !self.entry_expired(e, now) && Self::is_entry_alive(e));
                let removed = before - list.len();
                if removed > 0 {
                    self.total_entries
                        .fetch_sub(removed as u64, Ordering::Relaxed);
                }
                if list.is_empty() {
                    drop(list);
                    if self.entries.remove(addr).is_some() && want_ready {
                        self.release_ready_target(&Self::ready_node(addr));
                    }
                }
                None
            }
        }
    }

    pub(crate) async fn deposit_tcp(&self, addr: &str, stream: TcpStream) {
        self.deposit_entry(addr, PooledStream::Bare(stream)).await;
    }

    /// Whether a live, unexpired bare-TCP entry exists for `addr`
    /// (`host:port`) — the preconnect warm gauge behind `/stats`. Dead and
    /// expired entries are removed here so a long-lived warm owner can
    /// replace them instead of eventually filling the per-host vector.
    pub(crate) fn has_live_bare_entry(&self, addr: &str) -> bool {
        let now = Instant::now();
        let Some(entries) = self.entries.get(addr) else {
            return false;
        };
        let mut entries = entries.lock();
        let before = entries.len();
        entries.retain(|entry| {
            !matches!(entry.stream, PooledStream::Bare(_))
                || (!self.entry_expired(entry, now) && Self::is_entry_alive(entry))
        });
        let removed = before - entries.len();
        if removed > 0 {
            self.total_entries
                .fetch_sub(removed as u64, Ordering::Relaxed);
        }
        entries
            .iter()
            .any(|entry| matches!(entry.stream, PooledStream::Bare(_)))
    }

    /// Deposit a fully-dialed stream under `key` (see [`ready_key`]).
    /// The stream must come straight out of `TcpOutbound::dial()` with no
    /// application reads performed, so its userspace TLS buffer (if any)
    /// is empty and the fd-level liveness probe stays accurate.
    pub(crate) async fn deposit_ready(&self, key: &str, stream: ProxyStream) {
        self.deposit_entry(key, PooledStream::Ready(stream)).await;
    }

    async fn deposit_entry(&self, addr: &str, stream: PooledStream) {
        let ready_node = matches!(stream, PooledStream::Ready(_)).then(|| Self::ready_node(addr));
        if !self.reserve_total() {
            debug!(
                "Pool global cap reached ({}); dropping deposit for {}",
                self.capacity_limit, addr
            );
            return;
        }

        let mut target_reserved = false;
        let arc = match self.entries.entry(addr.to_string()) {
            Entry::Occupied(entry) => Arc::clone(entry.get()),
            Entry::Vacant(entry) => {
                if let Some(node) = ready_node.as_deref() {
                    target_reserved = self.reserve_ready_target(node);
                    if !target_reserved {
                        self.total_entries.fetch_sub(1, Ordering::AcqRel);
                        debug!(
                            "Ready target cardinality cap reached for {} (max={}); dropping deposit",
                            node, MAX_READY_TARGETS_PER_NODE
                        );
                        return;
                    }
                }
                let arc = Arc::new(Mutex::new(Vec::new()));
                entry.insert(Arc::clone(&arc));
                arc
            }
        };
        let mut list = arc.lock();
        if list.len() >= MAX_PER_HOST {
            self.total_entries.fetch_sub(1, Ordering::AcqRel);
            if target_reserved {
                self.release_ready_target(ready_node.as_deref().expect("ready node"));
            }
            debug!("Pool cap reached for {} (max={})", addr, MAX_PER_HOST);
            return;
        }
        let now = Instant::now();
        let kind = match &stream {
            PooledStream::Bare(_) => "bare",
            PooledStream::Ready(_) => "ready",
        };
        list.push(TimedStream {
            stream,
            created: now,
            last_used: now,
        });
        debug!(
            "Pool deposit ({}): {} ({} total pooled)",
            kind,
            addr,
            self.total_entries.load(Ordering::Relaxed)
        );
    }

    fn reserve_total(&self) -> bool {
        self.total_entries
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.capacity_limit).then_some(current + 1)
            })
            .is_ok()
    }

    fn ready_node(key: &str) -> String {
        key.strip_prefix("ready|")
            .and_then(|rest| rest.split_once('|').map(|(node, _)| node.to_owned()))
            .unwrap_or_default()
    }

    fn reserve_ready_target(&self, node: &str) -> bool {
        let counter = Arc::clone(
            &*self
                .ready_targets
                .entry(node.to_owned())
                .or_insert_with(|| Arc::new(AtomicU64::new(0))),
        );
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(1)
                    .filter(|next| *next <= MAX_READY_TARGETS_PER_NODE as u64)
            })
            .is_ok()
    }

    fn release_ready_target(&self, node: &str) {
        if let Some(counter) = self.ready_targets.get(node) {
            let _ = counter.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            });
        }
    }

    /// Drop only the bare preconnect for a node. Ready streams may belong to
    /// active traffic policy and are not selector warm ownership.
    pub(crate) fn purge_bare(&self, node_addr: &str) {
        let Some((_, entries)) = self.entries.remove(node_addr) else {
            return;
        };
        let removed = entries.lock().len() as u64;
        if removed > 0 {
            self.total_entries.fetch_sub(removed, Ordering::Relaxed);
            debug!(
                "Purged {} selector-warm bare connections for {}",
                removed, node_addr
            );
        }
    }

    /// Drop every pooled connection tied to a proxy node: the bare
    /// `"host:port"` key plus all `ready|<node_addr>|…` entries. Called
    /// when the node flips alive→dead — a pooled-but-doomed stream must
    /// never be handed out (idle/max-age expiry would otherwise keep
    /// serving it for up to 60s).
    pub(crate) fn purge_node(&self, node_addr: &str) {
        let ready_prefix = format!("ready|{}|", node_addr);
        let mut removed = 0u64;
        self.entries.retain(|key, arc| {
            if key == node_addr || key.starts_with(&ready_prefix) {
                removed += arc.lock().len() as u64;
                false
            } else {
                true
            }
        });
        if removed > 0 {
            self.total_entries.fetch_sub(removed, Ordering::Relaxed);
            self.ready_targets.remove(node_addr);
            debug!(
                "Purged {} pooled connections for dead node {}",
                removed, node_addr
            );
        }
    }

    pub(crate) async fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let mut total_removed = 0usize;
        let total_remaining = AtomicU64::new(0);

        self.entries.retain(|addr, arc| {
            let mut list = arc.lock();
            list.retain(|e| {
                if self.entry_expired(e, now) || !Self::is_entry_alive(e) {
                    total_removed += 1;
                    false
                } else {
                    true
                }
            });
            if list.is_empty() && addr.starts_with("ready|") {
                self.release_ready_target(&Self::ready_node(addr));
            }
            total_remaining.fetch_add(list.len() as u64, Ordering::Relaxed);
            !list.is_empty()
        });

        let remaining = total_remaining.load(Ordering::Relaxed);
        self.total_entries.store(remaining, Ordering::Relaxed);
        debug!(
            "Pruned {} expired pooled connections ({} remaining)",
            total_removed, remaining
        );
        total_removed
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
            PooledStream::Bare(tcp) => is_tcp_stream_alive(tcp),
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
    use honk_config::types::NodeProtocol;
    use honk_outbound::proxy::TcpOutbound;
    use honk_outbound::proxy::socks5::Socks5Handler;
    use std::sync::atomic::AtomicUsize;
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
        assert_eq!(pool.total_entries.load(Ordering::Relaxed), 1);

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!pool.has_live_bare_entry(&addr));
        assert_eq!(pool.total_entries.load(Ordering::Relaxed), 0);

        let replacement = TcpStream::connect(&addr).await.unwrap();
        pool.deposit_tcp(&addr, replacement).await;
        assert!(pool.has_live_bare_entry(&addr));
        assert_eq!(pool.total_entries.load(Ordering::Relaxed), 1);
    }

    /// Phase 5: deposits past the global FD budget are refused.
    #[tokio::test]
    async fn test_pool_global_cap_refused() {
        let pool = ConnectionPool::new();
        let addr = spawn_hold_open_listener().await.to_string();
        pool.total_entries
            .store(MAX_TOTAL_ENTRIES as u64, Ordering::Relaxed);
        pool.deposit_tcp(&addr, TcpStream::connect(&addr).await.unwrap())
            .await;
        assert!(pool.acquire_tcp(&addr).await.is_none());
        assert_eq!(
            pool.total_entries.load(Ordering::Relaxed),
            MAX_TOTAL_ENTRIES as u64,
            "a refused deposit must not bump the counter"
        );
    }

    #[test]
    fn explicit_pool_capacity_is_enforced() {
        let pool = ConnectionPool::with_capacity_limit(3);
        assert!(pool.reserve_total());
        assert!(pool.reserve_total());
        assert!(pool.reserve_total());
        assert!(!pool.reserve_total());
        assert_eq!(pool.total_entries.load(Ordering::Acquire), 3);
    }

    /// Phase 5: hot-target gating — the first flow is cold, the second
    /// within the window is hot, and a different target stays cold.
    #[tokio::test]
    async fn test_note_target_hot_gating() {
        let pool = ConnectionPool::new();
        let key = "ready|node:443|1.2.3.4:443";
        assert!(!pool.note_target(key), "first flow is cold");
        assert!(pool.note_target(key), "second flow within window is hot");
        assert!(pool.note_target(key), "stays hot");
        assert!(!pool.note_target("ready|node:443|5.6.7.8:443"));
    }

    /// Phase 5: ready deposits stop at the per-node target cardinality.
    #[tokio::test]
    async fn test_ready_target_cardinality_cap() {
        let pool = ConnectionPool::new();
        let addr = spawn_hold_open_listener().await;
        let target = addr;
        for i in 0..MAX_READY_TARGETS_PER_NODE {
            let key = format!("ready|node:443|10.0.0.{}:443", i + 1);
            let tcp = TcpStream::connect(addr).await.unwrap();
            pool.deposit_ready(&key, make_ready_stream(tcp, target))
                .await;
        }
        // One more distinct target for the same node: refused.
        let key = "ready|node:443|10.9.9.9:443";
        let tcp = TcpStream::connect(addr).await.unwrap();
        pool.deposit_ready(key, make_ready_stream(tcp, target))
            .await;
        assert!(pool.acquire_ready(key).await.is_none());
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
        let key = ConnectionPool::ready_key("proxy.example:1080", target, None);

        assert!(pool.acquire_ready(&key).await.is_none());

        let tcp = TcpStream::connect(server_addr).await.unwrap();
        pool.deposit_ready(&key, make_ready_stream(tcp, target))
            .await;

        let ready = pool.acquire_ready(&key).await.expect("ready entry");
        assert_eq!(ready.target_addr, target);
        // A checkout removes the entry: a second acquire must miss.
        assert!(pool.acquire_ready(&key).await.is_none());
        drop(ready);
    }

    #[tokio::test]
    async fn test_pool_ready_key_namespacing() {
        // Ready keys live in a namespace disjoint from bare "host:port"
        // keys, and bind both node and target (domain-aware).
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let k1 = ConnectionPool::ready_key("proxy.example:1080", target, None);
        let k2 = ConnectionPool::ready_key("proxy.example:1080", target, Some("example.com"));
        let k3 = ConnectionPool::ready_key("other.example:1080", target, None);
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
        let key = ConnectionPool::ready_key("proxy.example:1080", target, None);
        let tcp = TcpStream::connect(server_addr).await.unwrap();
        pool.deposit_ready(&key, make_ready_stream(tcp, target))
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
        let key = ConnectionPool::ready_key("proxy.example:1080", target, None);
        pool.deposit_ready(&key, stream).await;
        assert!(pool.acquire_ready(&key).await.is_none());
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
            if !is_tcp_stream_alive(&tcp) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !is_tcp_stream_alive(&tcp),
            "MSG_PEEK never observed the peer FIN"
        );
        pool.deposit_tcp("proxy.example:1080", tcp).await;
        assert!(pool.acquire_tcp("proxy.example:1080").await.is_none());
    }

    /// End-to-end: a SOCKS5 stream pooled after a full dial is reused
    /// without repeating the greeting/CONNECT handshake.
    #[tokio::test]
    async fn test_socks5_ready_reuse_skips_handshake() {
        // Mock SOCKS5 server: counts TCP connections; per connection it
        // answers greeting + CONNECT, then requires the next 4 bytes to be
        // exactly b"PING" (any re-handshake would fail this) before
        // replying b"PONG".
        let conn_count = Arc::new(AtomicU64::new(0));
        let payload_ok = Arc::new(AtomicU64::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        {
            let conn_count = Arc::clone(&conn_count);
            let payload_ok = Arc::clone(&payload_ok);
            tokio::spawn(async move {
                loop {
                    let (mut s, _) = match listener.accept().await {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    conn_count.fetch_add(1, Ordering::Relaxed);
                    let payload_ok = Arc::clone(&payload_ok);
                    tokio::spawn(async move {
                        // Greeting: VER NMETHODS METHODS...
                        let mut hdr = [0u8; 2];
                        s.read_exact(&mut hdr).await.unwrap();
                        assert_eq!(hdr[0], 0x05);
                        let mut methods = vec![0u8; hdr[1] as usize];
                        s.read_exact(&mut methods).await.unwrap();
                        s.write_all(&[0x05, 0x00]).await.unwrap();
                        // Request: VER CMD RSV ATYP ... ADDR PORT
                        let mut req = [0u8; 4];
                        s.read_exact(&mut req).await.unwrap();
                        assert_eq!(req[0], 0x05);
                        assert_eq!(req[1], 0x01); // CONNECT
                        let skip = match req[3] {
                            0x01 => 4 + 2,
                            0x04 => 16 + 2,
                            0x03 => {
                                let mut l = [0u8; 1];
                                s.read_exact(&mut l).await.unwrap();
                                l[0] as usize + 2
                            }
                            a => panic!("bad ATYP {a}"),
                        };
                        let mut rest = vec![0u8; skip];
                        s.read_exact(&mut rest).await.unwrap();
                        // Success reply: VER REP RSV ATYP=IPv4 0.0.0.0:0
                        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await
                            .unwrap();
                        // Data phase: the next bytes must be the payload
                        // itself, not a repeated greeting.
                        let mut data = [0u8; 4];
                        match s.read_exact(&mut data).await {
                            Ok(_) if &data == b"PING" => {
                                payload_ok.fetch_add(1, Ordering::Relaxed);
                                s.write_all(b"PONG").await.unwrap();
                            }
                            _ => return, // wrong bytes: close, client assert fails
                        }
                        // Hold the tunnel open until the client hangs up.
                        let mut sink = [0u8; 64];
                        let _ = s.read(&mut sink).await;
                    });
                }
            });
        }

        let node = Node {
            name: "test".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
            address: server_addr.ip().to_string(),
            host: String::new(),
            port: server_addr.port(),
            ..Default::default()
        };
        let handler = Socks5Handler::new();
        assert!((honk_outbound::descriptor::descriptor(
            NodeProtocol::Socks5
        )
        .pool_ready_streams)(&node));
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        // Full dial (TCP + greeting + CONNECT), then pool the result.
        let stream = handler
            .dial(&node, target, None, Duration::from_secs(3))
            .await
            .unwrap();
        let pool = ConnectionPool::new();
        let node_addr = format!("{}:{}", node.host(), node.port);
        let key = ConnectionPool::ready_key(&node_addr, target, None);
        pool.deposit_ready(&key, stream).await;

        // Checkout: payload goes straight through, no handshake bytes.
        let mut reused = pool.acquire_ready(&key).await.expect("ready stream");
        reused.stream.write_all(b"PING").await.unwrap();
        let mut buf = [0u8; 4];
        reused.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PONG");

        // Exactly one TCP connection total, and its data phase saw the raw
        // payload — proving no greeting/CONNECT was sent on reuse.
        assert_eq!(conn_count.load(Ordering::Relaxed), 1);
        assert_eq!(payload_ok.load(Ordering::Relaxed), 1);
    }

    /// A dead node's bare AND ready entries must all be purged; other
    /// nodes' entries stay.
    #[tokio::test]
    async fn test_purge_node_removes_bare_and_ready() {
        let pool = ConnectionPool::new();
        let server = spawn_hold_open_listener().await;
        let dead_addr = "dead.example:1080";
        let other_addr = "other.example:1080";
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        for addr in [dead_addr, other_addr] {
            let tcp = TcpStream::connect(server).await.unwrap();
            pool.deposit_tcp(addr, tcp).await;
            let key = ConnectionPool::ready_key(addr, target, None);
            let tcp = TcpStream::connect(server).await.unwrap();
            pool.deposit_ready(&key, make_ready_stream(tcp, target))
                .await;
        }
        pool.purge_node(dead_addr);
        assert!(pool.acquire_tcp(dead_addr).await.is_none());
        assert!(
            pool.acquire_ready(&ConnectionPool::ready_key(dead_addr, target, None))
                .await
                .is_none()
        );
        // Other node untouched.
        assert!(pool.acquire_tcp(other_addr).await.is_some());
        assert!(
            pool.acquire_ready(&ConnectionPool::ready_key(other_addr, target, None))
                .await
                .is_some()
        );
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
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..MAX_READY_TARGETS_PER_NODE + 16 {
            let pool = Arc::clone(&pool);
            tasks.spawn(async move {
                let key = format!("ready|node:443|198.51.100.{i}:443");
                let tcp = TcpStream::connect(server).await.unwrap();
                pool.deposit_ready(&key, make_ready_stream(tcp, target))
                    .await;
            });
        }
        while tasks.join_next().await.is_some() {}
        assert_eq!(
            pool.ready_targets
                .get("node:443")
                .map(|count| count.load(Ordering::Acquire)),
            Some(MAX_READY_TARGETS_PER_NODE as u64),
            "parallel distinct deposits must never exceed the ready-target cap"
        );
        assert_eq!(
            pool.total_entries.load(Ordering::Acquire),
            MAX_READY_TARGETS_PER_NODE as u64
        );
    }

    #[test]
    fn stale_ready_target_release_does_not_poison_counter() {
        let pool = ConnectionPool::new();
        let node = "node:443";

        assert!(pool.reserve_ready_target(node));
        pool.release_ready_target(node);
        // A concurrent miss may finish after the checkout that removed the key.
        pool.release_ready_target(node);

        assert!(pool.reserve_ready_target(node));
        assert_eq!(
            pool.ready_targets
                .get(node)
                .map(|count| count.load(Ordering::Acquire)),
            Some(1)
        );
    }

    #[tokio::test]
    async fn test_total_cap_cas_never_overshoots_under_parallel_reservations() {
        let pool = Arc::new(ConnectionPool::new());
        pool.total_entries
            .store(MAX_TOTAL_ENTRIES as u64 - 4, Ordering::Release);
        let accepted = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let pool = Arc::clone(&pool);
            let accepted = Arc::clone(&accepted);
            tasks.spawn(async move {
                if pool.reserve_total() {
                    accepted.fetch_add(1, Ordering::AcqRel);
                }
            });
        }
        while tasks.join_next().await.is_some() {}
        assert_eq!(accepted.load(Ordering::Acquire), 4);
        assert_eq!(
            pool.total_entries.load(Ordering::Acquire),
            MAX_TOTAL_ENTRIES as u64
        );
    }

    #[test]
    fn test_warm_key_singleflight_and_drop_releases_claim() {
        let pool = ConnectionPool::new();
        let key = "ready|node:443|198.51.100.1:443";
        let guard = pool.try_begin_warm(key).expect("first warmer owns key");
        assert!(
            pool.try_begin_warm(key).is_none(),
            "follower must not duplicate warm dial"
        );
        drop(guard);
        assert!(
            pool.try_begin_warm(key).is_some(),
            "cancelled/failed owner must release key"
        );
    }

    #[test]
    fn test_hot_map_refuses_new_keys_at_bound_without_scan() {
        let pool = ConnectionPool::new();
        pool.hot_entries.store(4096, Ordering::Release);
        assert!(!pool.note_target("ready|node:443|new:443"));
        assert!(
            pool.hot.is_empty(),
            "a full hot map must not insert or scan"
        );
    }
}
