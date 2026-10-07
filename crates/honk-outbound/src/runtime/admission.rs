//! Generation-local and process-wide physical dial admission.

use std::future::Future;
use std::sync::{Arc, LazyLock};
use std::task::Poll;

use super::{OutboundRuntimeRegistry, ProtocolRuntime};

#[derive(Clone)]
struct DialAdmission {
    generation: Arc<tokio::sync::Semaphore>,
    process: Arc<tokio::sync::Semaphore>,
}

impl DialAdmission {
    fn for_registry(registry: &OutboundRuntimeRegistry) -> Self {
        Self {
            generation: Arc::clone(&registry.dial_semaphore),
            process: Arc::clone(&registry.dial_ceiling_semaphore),
        }
    }

    fn standalone() -> Self {
        STANDALONE_DIAL_ADMISSION.clone()
    }

    fn matches_registry(&self, registry: &OutboundRuntimeRegistry) -> bool {
        Arc::ptr_eq(&self.generation, &registry.dial_semaphore)
            && Arc::ptr_eq(&self.process, &registry.dial_ceiling_semaphore)
    }

    async fn acquire(self) -> DialPermit {
        let generation = Arc::clone(&self.generation)
            .acquire_owned()
            .await
            .expect("dial semaphore is never closed");
        let process = Arc::clone(&self.process)
            .acquire_owned()
            .await
            .expect("dial ceiling semaphore is never closed");
        DialPermit {
            _generation: generation,
            _process: process,
        }
    }
}

static STANDALONE_DIAL_ADMISSION: LazyLock<DialAdmission> = LazyLock::new(|| DialAdmission {
    generation: Arc::new(tokio::sync::Semaphore::new(
        tokio::sync::Semaphore::MAX_PERMITS,
    )),
    process: Arc::new(tokio::sync::Semaphore::new(
        tokio::sync::Semaphore::MAX_PERMITS,
    )),
});

#[derive(Default)]
struct DialPermits {
    first: Option<DialPermit>,
    extra: Vec<DialPermit>,
}

#[derive(Default)]
struct Progress {
    started: bool,
    pending: usize,
    on_start: Option<Box<dyn FnOnce() + Send>>,
}

/// One logical dial's physical admission, retained permits, and start boundary.
pub struct DialScope {
    admission: DialAdmission,
    permits: parking_lot::Mutex<DialPermits>,
    progress: Arc<parking_lot::Mutex<Progress>>,
}

impl DialScope {
    fn new(admission: DialAdmission, on_start: Option<Box<dyn FnOnce() + Send>>) -> Arc<Self> {
        Arc::new(Self {
            admission,
            permits: parking_lot::Mutex::new(DialPermits::default()),
            progress: Arc::new(parking_lot::Mutex::new(Progress {
                on_start,
                ..Default::default()
            })),
        })
    }

    /// Start once before a physical attempt or a logical open on reused state.
    pub fn start(&self) {
        let callback = {
            let mut state = self.progress.lock();
            state.started = true;
            state.on_start.take()
        };
        if let Some(callback) = callback {
            callback();
        }
    }

    /// Whether an unstarted dial is currently blocked on physical admission.
    /// Snapshot before cancelling the scoped future, which removes its waiters.
    pub fn is_waiting_for_admission(&self) -> bool {
        let state = self.progress.lock();
        !state.started && state.pending > 0
    }

    /// Completed paths without a physical or logical start retain the
    /// completion fallback; cancellation never starts untouched work.
    pub async fn scope<F>(self: &Arc<Self>, future: F) -> F::Output
    where
        F: Future,
    {
        let output = DIAL_SCOPE.scope(Arc::clone(self), future).await;
        self.start();
        output
    }

    async fn acquire(&self) -> DialPermit {
        let mut acquire = std::pin::pin!(self.admission.clone().acquire());
        let mut waiter = DialWaiter {
            scope: self,
            pending: false,
        };
        std::future::poll_fn(|cx| {
            // Poll and publish under the same lock so a timeout cannot see
            // a gap between leaving admission and starting the attempt.
            let mut state = self.progress.lock();
            match acquire.as_mut().poll(cx) {
                Poll::Pending => {
                    if !waiter.pending {
                        state.pending += 1;
                        waiter.pending = true;
                    }
                    Poll::Pending
                }
                Poll::Ready(permit) => {
                    if waiter.pending {
                        state.pending -= 1;
                        waiter.pending = false;
                    }
                    state.started = true;
                    let callback = state.on_start.take();
                    drop(state);
                    if let Some(callback) = callback {
                        callback();
                    }
                    Poll::Ready(permit)
                }
            }
        })
        .await
    }
}

struct DialWaiter<'a> {
    scope: &'a DialScope,
    pending: bool,
}

impl Drop for DialWaiter<'_> {
    fn drop(&mut self) {
        if self.pending {
            self.scope.progress.lock().pending -= 1;
        }
    }
}

tokio::task_local! {
    static DIAL_SCOPE: Arc<DialScope>;
}

/// One physical proxy dial admitted by both its generation and the shared
/// process descriptor partition.
pub struct DialPermit {
    _generation: tokio::sync::OwnedSemaphorePermit,
    _process: tokio::sync::OwnedSemaphorePermit,
}

/// Captured logical operation state for spawned child work. Clones share
/// successful permits and the first-dial callback with their parent.
#[derive(Clone)]
pub(crate) struct CapturedDialScope(Arc<DialScope>);

impl CapturedDialScope {
    fn standalone() -> Self {
        Self(DialScope::new(DialAdmission::standalone(), None))
    }

    /// One physical TCP/TLS/H2 setup, with independent retained credits and the
    /// initiating operation's existing cancellation/start feedback.
    pub(crate) fn physical_setup(&self) -> Self {
        Self(Arc::new(DialScope {
            admission: self.0.admission.clone(),
            permits: parking_lot::Mutex::new(DialPermits::default()),
            progress: Arc::clone(&self.0.progress),
        }))
    }

    pub(crate) fn is_waiting_for_admission(&self) -> bool {
        self.0.is_waiting_for_admission()
    }

    pub(crate) async fn scope<F>(self, future: F) -> F::Output
    where
        F: Future,
    {
        DIAL_SCOPE.scope(self.0, future).await
    }
}

/// Reusable admission identity for autonomous dial operations. Each scoped
/// future receives its own permit-holding operation scope.
#[derive(Clone)]
pub(crate) struct CapturedDialAdmission(DialAdmission);

impl CapturedDialAdmission {
    fn standalone() -> Self {
        Self(DialAdmission::standalone())
    }

    pub(crate) async fn scope<F>(self, future: F) -> F::Output
    where
        F: Future,
    {
        DIAL_SCOPE.scope(DialScope::new(self.0, None), future).await
    }
}

pub(crate) fn capture_dial_scope() -> CapturedDialScope {
    DIAL_SCOPE
        .try_with(|scope| CapturedDialScope(Arc::clone(scope)))
        .unwrap_or_else(|_| CapturedDialScope::standalone())
}

pub(crate) fn try_capture_dial_admission() -> Option<CapturedDialAdmission> {
    DIAL_SCOPE
        .try_with(|scope| CapturedDialAdmission(scope.admission.clone()))
        .ok()
}

pub(crate) fn capture_dial_admission() -> CapturedDialAdmission {
    try_capture_dial_admission().unwrap_or_else(CapturedDialAdmission::standalone)
}

pub(crate) async fn admit_physical_dial<T, E, F>(future: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    admit_replacement_dial(future, false).await
}

/// Reuse one retained permit only after dropping a socket dialed in this scope.
/// Supplied sockets must acquire fresh admission even when siblings hold permits.
pub(crate) async fn admit_replacement_dial<T, E, F>(future: F, reuse_existing: bool) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let scope = DIAL_SCOPE.try_with(Arc::clone).ok();
    let retained = scope.as_ref().filter(|_| reuse_existing).and_then(|scope| {
        let mut held = scope.permits.lock();
        held.extra.pop().or_else(|| held.first.take())
    });
    let permit = match retained {
        Some(permit) => permit,
        None => match &scope {
            Some(scope) => scope.acquire().await,
            None => DialAdmission::standalone().acquire().await,
        },
    };
    let result = future.await;
    if result.is_ok()
        && let Some(scope) = scope
    {
        let mut held = scope.permits.lock();
        if held.first.is_none() {
            held.first = Some(permit);
        } else {
            held.extra.push(permit);
        }
    }
    result
}

/// Start the current scoped logical dial, if it has not started already.
///
/// Reused sessions and QUIC connections have no new physical admission to
/// trigger the callback before their logical open can block.
pub(crate) fn start_scoped_dial() {
    let _ = DIAL_SCOPE.try_with(|scope| scope.start());
}

impl OutboundRuntimeRegistry {
    /// Configured admission ceiling for this immutable generation.
    pub fn dial_limit(&self) -> usize {
        self.dial_limit
    }

    /// Acquire generation-local admission before the shared process gate so
    /// low configured limits cannot hoard process capacity while waiting.
    pub async fn acquire_dial_permit(&self) -> DialPermit {
        DialAdmission::for_registry(self).acquire().await
    }

    /// Bind physical attempts made by `future` to this generation's gates.
    /// Nested dispatch through the same registry keeps the existing scope.
    pub async fn scope_dials<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        if DIAL_SCOPE
            .try_with(|scope| scope.admission.matches_registry(self))
            .unwrap_or(false)
        {
            return future.await;
        }
        DIAL_SCOPE
            .scope(
                DialScope::new(DialAdmission::for_registry(self), None),
                future,
            )
            .await
    }

    /// Create a logical dial scope whose start callback fires only once.
    pub fn dial_scope<C>(&self, on_start: C) -> Arc<DialScope>
    where
        C: FnOnce() + Send + 'static,
    {
        DialScope::new(DialAdmission::for_registry(self), Some(Box::new(on_start)))
    }
    /// Rebind autonomous pooled replacement dials after this generation is
    /// published. Reused pools must stop consulting the predecessor's gate.
    pub fn activate_background_dial_admission(&self) {
        let admission = CapturedDialAdmission(DialAdmission::for_registry(self));
        for runtime in self.nodes.values() {
            if let ProtocolRuntime::AnyTls(anytls) = &runtime.runtime {
                anytls.pool.set_dial_admission(admission.clone());
            }
            if let Some(xhttp) = &runtime.xhttp {
                xhttp.set_dial_admission(admission.clone());
            }
        }
    }
}
