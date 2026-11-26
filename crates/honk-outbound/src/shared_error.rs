use crate::alive::route_health::RouteFailureScope;
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cloneable failure for shared initialization waiters, preserving typed causes.
/// An `Arc<anyhow::Error>` alone becomes an opaque message when re-wrapped.
#[derive(Clone)]
pub struct SharedError(SharedCause);

#[derive(Clone)]
enum SharedCause {
    Single(Arc<anyhow::Error>),
    Fanout(Arc<SharedFailure>),
}

struct SharedFailure {
    error: anyhow::Error,
    id: u64,
    // At most one entry per route-health scope actually charged by this live cause.
    // Dropping the last delivery reference frees every claim.
    scopes: Mutex<BTreeSet<RouteFailureScope>>,
}

impl SharedError {
    pub fn new(error: anyhow::Error) -> Self {
        Self(SharedCause::Single(Arc::new(error)))
    }

    /// One failure delivered to several flows, such as a carrier's terminal cause or a dial all
    /// waiters share; its recipients report a single Score episode.
    pub fn fanout(error: anyhow::Error) -> Self {
        Self(SharedCause::Fanout(Arc::new(SharedFailure {
            error,
            id: next_episode(),
            scopes: Mutex::default(),
        })))
    }

    pub(crate) fn episode(&self) -> Option<u64> {
        match &self.0 {
            SharedCause::Single(_) => None,
            SharedCause::Fanout(cause) => Some(cause.id),
        }
    }

    pub(crate) fn claim_route_failure(&self, scope: RouteFailureScope, recovered: u64) -> bool {
        match &self.0 {
            SharedCause::Single(_) => true,
            SharedCause::Fanout(cause) => cause.id > recovered && cause.scopes.lock().insert(scope),
        }
    }

    fn error(&self) -> &anyhow::Error {
        match &self.0 {
            SharedCause::Single(error) => error,
            SharedCause::Fanout(cause) => &cause.error,
        }
    }
}

/// Shared failures, routed admissions and route-health verdicts use this sequence.
pub(crate) fn next_episode() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

impl std::fmt::Debug for SharedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.error(), formatter)
    }
}

impl std::fmt::Display for SharedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.error(), formatter)
    }
}

impl std::error::Error for SharedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error().as_ref())
    }
}
