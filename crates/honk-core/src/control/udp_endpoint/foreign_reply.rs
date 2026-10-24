//! Process-wide anyfrom sockets for full-cone replies from peers other than a
//! flow's own destination.
//!
//! A reply socket is bound to the peer's address, not to a client, so every
//! ordinary endpoint and shared-source receiver can reuse one socket per peer.
//! Foreign sockets draw on the same descriptor budget as each endpoint's eager
//! primary socket and yield to it: a primary that finds the budget full closes
//! the least recently used foreign socket first.

use super::*;
use lru::LruCache;

pub(super) struct ForeignReplySockets {
    factory: Arc<dyn UdpReplySocketFactory>,
    /// Shared with primaries. The fixed 8× endpoint budget prevents teardown
    /// overlap from doubling FDs.
    slots: Arc<Semaphore>,
    /// Foreign sockets never exceed seven per endpoint of capacity.
    limit: usize,
    cache: Mutex<LruCache<SocketAddr, (Arc<ReplySocket>, tokio::time::Instant)>>,
}

impl ForeignReplySockets {
    pub(super) fn new(capacity_limit: usize, factory: Arc<dyn UdpReplySocketFactory>) -> Self {
        Self {
            factory,
            slots: Arc::new(Semaphore::new(
                capacity_limit.saturating_mul(MAX_REPLY_SOCKETS_PER_ENDPOINT),
            )),
            limit: capacity_limit.saturating_mul(MAX_REPLY_SOCKETS_PER_ENDPOINT - 1),
            cache: Mutex::new(LruCache::unbounded()),
        }
    }

    /// The eager reply socket of one endpoint, bound to its original destination.
    pub(super) fn create_primary(&self, source: SocketAddr) -> io::Result<ReplySocket> {
        self.create_with_reclaim(source)
    }

    /// Evicts until creation succeeds or nothing cached remains. An evicted
    /// socket still sending holds its permit, so reclamation must not stop at it.
    fn create_with_reclaim(&self, source: SocketAddr) -> io::Result<ReplySocket> {
        loop {
            match ReplySocket::create(self.factory.as_ref(), &self.slots, source) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && self.evict_one() => {}
                created => return created,
            }
        }
    }

    /// Returns the socket for `source`, creating it when no endpoint has one.
    /// `WouldBlock` means every descriptor is held by primaries or in-flight sends.
    pub(super) fn get(&self, source: SocketAddr) -> io::Result<Arc<ReplySocket>> {
        let now = tokio::time::Instant::now();
        if let Some((socket, used)) = self.cache.lock().get_mut(&source) {
            *used = now;
            return Ok(Arc::clone(socket));
        }
        let created = self.create_with_reclaim(source)?;
        let (socket, overflow) = {
            let mut cache = self.cache.lock();
            let socket = Arc::clone(&cache.get_or_insert(source, || (Arc::new(created), now)).0);
            let overflow = (cache.len() > self.limit)
                .then(|| cache.pop_lru())
                .flatten();
            (socket, overflow)
        };
        if overflow.is_some() {
            crate::logging::warn_throttled!(
                limit = self.limit,
                "UDP foreign reply socket pool is full; closing the least recently used socket"
            );
        }
        Ok(socket)
    }

    /// Closes the least recently used socket; false when none is cached.
    fn evict_one(&self) -> bool {
        let evicted = self.cache.lock().pop_lru();
        if evicted.is_some() {
            crate::logging::warn_throttled!(
                limit = self.limit,
                "UDP reply socket budget is full; closing the least recently used foreign socket"
            );
        }
        evicted.is_some()
    }

    /// Closes sockets no peer has used for `idle`.
    pub(super) fn prune(&self, idle: Duration) -> usize {
        let expired: Vec<_> = {
            let mut cache = self.cache.lock();
            let mut expired = Vec::new();
            while cache
                .peek_lru()
                .is_some_and(|(_, (_, used))| used.elapsed() >= idle)
            {
                expired.extend(cache.pop_lru());
            }
            expired
        };
        expired.len()
    }

    pub(super) fn clear(&self) {
        self.cache.lock().clear();
    }

    /// A one-endpoint pool for driver tests built without a `UdpEndpointPool`.
    #[cfg(test)]
    pub(super) fn for_one_endpoint() -> Arc<Self> {
        Arc::new(Self::new(1, Arc::new(SystemUdpReplySocketFactory)))
    }

    /// Cached peers, least recently used first.
    #[cfg(test)]
    pub(super) fn cached(&self) -> Vec<SocketAddr> {
        self.cache
            .lock()
            .iter()
            .rev()
            .map(|(peer, _)| *peer)
            .collect()
    }

    #[cfg(test)]
    pub(super) fn available_slots(&self) -> usize {
        self.slots.available_permits()
    }
}
