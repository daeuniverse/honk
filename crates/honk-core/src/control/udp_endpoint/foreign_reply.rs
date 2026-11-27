//! Process-wide reply transports for full-cone replies from foreign peers.
//!
//! Transports share a scope, original packet snapshot and peer address. Kernel
//! replies have no packet snapshot and share descriptor credit with eager
//! primaries, yielding their least recently used cache entries under pressure.

use super::*;
use lru::LruCache;

type CachedReply = (Arc<ReplySocket>, tokio::time::Instant);
pub(super) type ReplyKey = (ScopeId, Option<SourceContext>, SocketAddr);

pub(super) struct ForeignReplySockets {
    factory: Arc<dyn UdpReplySocketFactory>,
    /// Shared with primaries. The fixed 8× endpoint budget prevents teardown
    /// overlap from doubling FDs.
    slots: Arc<Semaphore>,
    /// Foreign sockets never exceed seven per endpoint of capacity.
    limit: usize,
    cache: Mutex<LruCache<ReplyKey, CachedReply>>,
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
    pub(super) fn create_primary(
        &self,
        scope: ScopeId,
        source: SocketAddr,
        packet_source: Option<&SourceWork>,
    ) -> io::Result<ReplySocket> {
        self.create_with_reclaim(scope, source, packet_source)
    }

    /// Evicts until creation succeeds or nothing cached remains. An evicted
    /// socket still sending holds its permit, so reclamation must not stop at it.
    fn create_with_reclaim(
        &self,
        scope: ScopeId,
        source: SocketAddr,
        packet_source: Option<&SourceWork>,
    ) -> io::Result<ReplySocket> {
        loop {
            match ReplySocket::create(
                self.factory.as_ref(),
                &self.slots,
                scope,
                source,
                packet_source,
            ) {
                Err(error)
                    if self.factory.uses_fd()
                        && error.kind() == io::ErrorKind::WouldBlock
                        && self.evict_one() => {}
                created => return created,
            }
        }
    }

    /// Returns the socket for `source`, creating it when no endpoint has one.
    /// `WouldBlock` means every descriptor is held by primaries or in-flight sends.
    pub(super) fn get(
        &self,
        scope: ScopeId,
        source: SocketAddr,
        packet_source: Option<&SourceWork>,
    ) -> io::Result<Arc<ReplySocket>> {
        let reply_source = packet_source.filter(|source| source.optional_context().is_some());
        let key = (
            scope,
            reply_source.and_then(SourceWork::optional_context),
            source,
        );
        let now = tokio::time::Instant::now();
        {
            let mut cache = self.cache.lock();
            if !packet_binding_active(packet_source) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    AuxiliaryBindingRetired,
                ));
            }
            if let Some((socket, used)) = cache.get_mut(&key) {
                *used = now;
                return Ok(Arc::clone(socket));
            }
        }
        let mut created = Some(Arc::new(self.create_with_reclaim(
            scope,
            source,
            reply_source,
        )?));
        let (socket, displaced, overflow) = {
            let mut cache = self.cache.lock();
            if !packet_binding_active(packet_source) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    AuxiliaryBindingRetired,
                ));
            }
            let (socket, displaced) = if let Some((socket, used)) = cache.get_mut(&key) {
                *used = now;
                (Arc::clone(socket), None)
            } else {
                let socket = created.take().expect("new reply socket");
                let displaced = cache.push(key, (Arc::clone(&socket), now));
                (socket, displaced)
            };
            let overflow = (cache.len() > self.limit)
                .then(|| cache.pop_lru())
                .flatten();
            (socket, displaced, overflow)
        };
        drop(created);
        drop(displaced);
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

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn clear_scope(&self, scope: ScopeId) {
        let mut cache = self.cache.lock();
        let keys: Vec<_> = cache
            .iter()
            .filter_map(|(key, _)| (key.0 == scope).then_some(*key))
            .collect();
        for key in keys {
            cache.pop(&key);
        }
    }

    pub(super) fn clear(&self) {
        let old = std::mem::replace(&mut *self.cache.lock(), LruCache::unbounded());
        drop(old);
    }

    /// A one-endpoint pool for driver tests built without a `UdpEndpointPool`.
    #[cfg(test)]
    pub(super) fn for_one_endpoint() -> Arc<Self> {
        Arc::new(Self::new(1, Arc::new(SystemUdpReplySocketFactory)))
    }

    /// Cached peers, least recently used first.
    #[cfg(test)]
    pub(super) fn cached(&self) -> Vec<(ScopeId, SocketAddr)> {
        self.cache
            .lock()
            .iter()
            .rev()
            .map(|((scope, _, source), _)| (*scope, *source))
            .collect()
    }

    #[cfg(test)]
    pub(super) fn available_slots(&self) -> usize {
        self.slots.available_permits()
    }
}
