//! Generation-local and process-wide physical dial admission.

use std::future::Future;
use std::sync::{Arc, LazyLock};

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

type DialStart = Arc<parking_lot::Mutex<Option<Box<dyn FnOnce() + Send>>>>;

#[derive(Default)]
struct HeldDialPermits {
    first: Option<DialPermit>,
    extra: Vec<DialPermit>,
}

struct DialScope {
    admission: DialAdmission,
    held: parking_lot::Mutex<HeldDialPermits>,
    on_start: Option<DialStart>,
}

impl DialScope {
    fn new(admission: DialAdmission, on_start: Option<DialStart>) -> Arc<Self> {
        Arc::new(Self {
            admission,
            held: parking_lot::Mutex::new(HeldDialPermits::default()),
            on_start,
        })
    }

    fn start(&self) {
        let callback = self
            .on_start
            .as_ref()
            .and_then(|callback| callback.lock().take());
        if let Some(callback) = callback {
            callback();
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
    let scope = DIAL_SCOPE.try_with(Arc::clone).ok();
    let permit = match &scope {
        Some(scope) => scope.admission.clone().acquire().await,
        None => DialAdmission::standalone().acquire().await,
    };
    if let Some(scope) = &scope {
        scope.start();
    }
    let result = future.await;
    if result.is_ok()
        && let Some(scope) = scope
    {
        let mut held = scope.held.lock();
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

    /// Start at the first admitted physical attempt or at the first logical
    /// open on reused state; completed paths without either boundary retain
    /// the historical completion fallback.
    pub async fn scope_dials_with_start<F, C>(&self, future: F, on_start: C) -> F::Output
    where
        F: Future,
        C: FnOnce() + Send + 'static,
    {
        let callback: DialStart = Arc::new(parking_lot::Mutex::new(Some(Box::new(on_start))));
        let scope = DialScope::new(DialAdmission::for_registry(self), Some(callback));
        let output = DIAL_SCOPE.scope(Arc::clone(&scope), future).await;
        scope.start();
        output
    }
    /// Rebind autonomous AnyTLS replacement dials after this generation is
    /// published. Reused pools must stop consulting the predecessor's gate.
    pub fn activate_background_dial_admission(&self) {
        let admission = CapturedDialAdmission(DialAdmission::for_registry(self));
        for runtime in self.nodes.values() {
            if let ProtocolRuntime::AnyTls(anytls) = &runtime.runtime {
                anytls.pool.set_dial_admission(admission.clone());
            }
        }
    }
}
