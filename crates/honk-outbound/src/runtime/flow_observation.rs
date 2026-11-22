//! Source-owned, optional evidence for one observed business operation.

#[cfg(feature = "flow-observation")]
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "flow-observation")]
use std::sync::Arc;

use uuid::Uuid;

/// A closed wire vocabulary: `as_str` is the only spelling, and serde reuses it.
#[doc(hidden)]
#[macro_export]
macro_rules! wire_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        $vis enum $name { $($variant),+ }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }
    };
}

wire_enum! {
    /// Progress a source reports once per business context.
    pub enum Milestone {
        TransportReady => "transport_ready",
        TargetRequestSent => "target_request_sent",
        TargetConfirmed => "target_confirmed",
    }
}

#[cfg(feature = "flow-observation")]
impl Milestone {
    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

wire_enum! {
    pub enum TransportStatus {
        Started => "started",
        Succeeded => "succeeded",
        Failed => "failed",
        Cancelled => "cancelled",
    }
}

wire_enum! {
    pub enum ResolutionLocation {
        Unknown => "unknown",
        Local => "local",
        Reused => "reused",
        OriginalIp => "original_ip",
        NotApplicable => "not_applicable",
    }
}

wire_enum! {
    pub enum TransportError {
        Cancelled => "cancelled",
        Timeout => "timeout",
        ConnectionRefused => "connection_refused",
        ConnectFailed => "connect_failed",
        QuicConnectFailed => "quic_connect_failed",
        QuicConnectTimeout => "quic_connect_timeout",
        UdpSocketFailed => "udp_socket_failed",
    }
}

wire_enum! {
    /// Why evidence is incomplete; recorders fold these into trace flags.
    pub enum GapReason {
        NotInstrumented => "not_instrumented",
        StartedLate => "started_late",
        BufferOverflow => "buffer_overflow",
        Redacted => "redacted",
        SharedDialContinuesAfterWaiter => "shared_dial_continues_after_waiter",
        RetirementOwnerLost => "retirement_owner_lost",
    }
}

wire_enum! {
    /// A session-level step: each variant fixes its wire reason and error.
    pub enum SessionEvent {
        OpenStarted => "session_open_started",
        OpenSucceeded => "session_open_succeeded",
        OpenRefused => "session_open_refused",
        OpenDraining => "session_open_draining",
        OpenFailed => "session_open_failed",
        OpenCancelled => "session_open_cancelled",
        OpenCapacity => "session_open_capacity",
        DnsResponseTruncatedTcpFallback => "dns_response_truncated_tcp_fallback",
        DnsSessionReadySucceeded => "dns_session_ready_succeeded",
        DnsSessionAcquired => "dns_session_acquired",
        DnsSessionReadyFailed => "dns_session_ready_failed",
        DnsSessionReadyRefused => "dns_session_ready_failed",
        DnsSessionReadyCancelled => "dns_session_ready_cancelled",
        DnsSessionRetryStarted => "dns_session_retry_started",
    }
}

impl SessionEvent {
    pub const fn reason(self) -> &'static str {
        self.as_str()
    }

    pub const fn error(self) -> Option<&'static str> {
        match self {
            Self::OpenRefused => Some("refused"),
            Self::OpenDraining => Some("draining"),
            Self::OpenFailed => Some("session"),
            Self::OpenCancelled | Self::DnsSessionReadyCancelled => Some("cancelled"),
            Self::OpenCapacity => Some("capacity"),
            Self::DnsSessionReadyFailed => Some("upstream_failed"),
            Self::DnsSessionReadyRefused => Some("local_refusal"),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowContext {
    pub flow_id: Uuid,
    pub generation: u64,
    pub attempt_id: Option<Uuid>,
    pub lookup_id: Option<Uuid>,
    pub dns_purpose: &'static str,
}

#[cfg(feature = "flow-observation")]
#[derive(Clone)]
pub struct FlowObserver {
    context: FlowContext,
    callback: Arc<dyn Fn(FlowContext, FlowEvent) + Send + Sync>,
    milestones: Arc<std::sync::atomic::AtomicU8>,
    /// Milestones this view drops before they reach the shared once-state.
    dropped: u8,
    request_lifetime: Option<std::sync::Weak<QuicSubmissions>>,
}

#[cfg(feature = "flow-observation")]
impl std::fmt::Debug for FlowObserver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FlowObserver")
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "flow-observation")]
impl FlowObserver {
    pub fn new(
        context: FlowContext,
        callback: Arc<dyn Fn(FlowContext, FlowEvent) + Send + Sync>,
    ) -> Self {
        Self {
            context,
            callback,
            milestones: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            dropped: 0,
            request_lifetime: None,
        }
    }

    pub fn context(&self) -> FlowContext {
        self.context
    }

    pub fn with_context(&self, context: FlowContext) -> Self {
        if context == self.context {
            return self.clone();
        }
        Self {
            request_lifetime: self.request_lifetime.clone(),
            dropped: self.dropped,
            ..Self::new(context, Arc::clone(&self.callback))
        }
    }

    /// Callbacks must remain bounded, synchronous and non-reentrant, with no I/O.
    pub fn publish(&self, event: FlowEvent) {
        if let FlowEvent::Milestone { milestone } = event
            && self.dropped & milestone.bit() != 0
        {
            return;
        }
        (self.callback)(self.context, event);
    }

    pub fn milestone_once(&self, milestone: Milestone) {
        let bit = milestone.bit();
        if self.dropped & bit != 0 {
            return;
        }
        if self
            .milestones
            .fetch_or(bit, std::sync::atomic::Ordering::Relaxed)
            & bit
            == 0
        {
            (self.callback)(self.context, FlowEvent::Milestone { milestone });
        }
    }

    pub fn scope<F: Future>(&self, future: F) -> impl Future<Output = F::Output> + use<F> {
        scope(Some(self.clone()), future)
    }

    pub fn sync_scope<T>(&self, build: impl FnOnce() -> T) -> T {
        FLOW_OBSERVER.sync_scope(Some(self.clone()), build)
    }
}

#[cfg(feature = "flow-observation")]
tokio::task_local! {
    static FLOW_OBSERVER: Option<FlowObserver>;
    static SUPPRESSED: bool;
    static REQUEST_WRITE: Option<RequestWrite>;
}

#[cfg(feature = "flow-observation")]
pub fn current() -> Option<FlowObserver> {
    if is_suppressed() {
        return None;
    }
    FLOW_OBSERVER.try_with(Clone::clone).ok().flatten()
}

#[cfg(feature = "flow-observation")]
pub(crate) fn is_suppressed() -> bool {
    SUPPRESSED
        .try_with(|suppressed| *suppressed)
        .unwrap_or(false)
}

#[cfg(feature = "flow-observation")]
pub(crate) fn scope<F: Future>(
    observer: Option<FlowObserver>,
    future: F,
) -> impl Future<Output = F::Output> {
    FLOW_OBSERVER.scope(observer, future)
}

#[cfg(feature = "flow-observation")]
pub fn without<F: Future>(future: F) -> impl Future<Output = F::Output> {
    SUPPRESSED.scope(true, scope(None, future))
}

/// Run a proxy chain hop other than the last. Its target is the next hop's
/// server, so its target milestones are dropped; transport events and
/// `TransportReady` still reach the flow, deduplicated with the other hops.
#[cfg(feature = "flow-observation")]
pub(crate) fn without_target_milestones<F: Future>(future: F) -> impl Future<Output = F::Output> {
    let observer = current().map(|flow| FlowObserver {
        dropped: flow.dropped
            | Milestone::TargetRequestSent.bit()
            | Milestone::TargetConfirmed.bit(),
        ..flow
    });
    scope(observer, future)
}

#[cfg(feature = "flow-observation")]
pub fn milestone(milestone: Milestone) {
    if let Some(observer) = current() {
        observer.milestone_once(milestone);
    }
}

#[cfg(feature = "flow-observation")]
mod request;
#[cfg(all(feature = "flow-observation", test))]
pub(crate) use request::RequestDelivery;
#[cfg(feature = "flow-observation")]
pub(crate) use request::{
    DriverRequest, QuicSubmissions, RelayedPipe, RequestWrite, observe_chain_request, request_write,
};

#[expect(
    clippy::large_enum_variant,
    reason = "Synchronous callbacks avoid a separate allocation for every DNS event"
)]
#[derive(Debug)]
pub enum FlowEvent {
    Transport {
        attempt_id: Uuid,
        server_addr: Option<SocketAddr>,
        status: TransportStatus,
        resolution_location: ResolutionLocation,
        error: Option<TransportError>,
    },
    TransportAttached {
        server_addr: Option<SocketAddr>,
        resolution_location: ResolutionLocation,
    },
    Milestone {
        milestone: Milestone,
    },
    Session(SessionEvent),
    Dns(DnsLookup),
    Gap(GapReason),
}

#[derive(Clone, Debug)]
pub struct DnsLookup {
    pub lookup_id: Uuid,
    pub parent_lookup_id: Option<Uuid>,
    pub attempt_id: Option<Uuid>,
    pub purpose: &'static str,
    pub name: String,
    pub qtype: String,
    pub source: &'static str,
    pub upstream_transport: Option<&'static str>,
    pub carrier_transport: Option<&'static str>,
    pub cache: &'static str,
    pub cache_entry_id: Option<String>,
    pub upstream: Option<String>,
    pub route_evaluation_ids: Vec<String>,
    pub status: &'static str,
    pub addresses: Vec<IpAddr>,
    pub selected_ip: Option<IpAddr>,
    pub error: Option<&'static str>,
}

#[cfg(feature = "flow-observation")]
/// Lookup facts captured by this resolution operation, never recovered by name.
pub struct LookupSelection {
    observer: FlowObserver,
    lookups: Arc<parking_lot::Mutex<Vec<(FlowContext, DnsLookup)>>>,
}

#[cfg(feature = "flow-observation")]
impl LookupSelection {
    pub fn selected_ip(&self, ip: IpAddr) {
        let (selected, ambiguous) = {
            let lookups = self.lookups.lock();
            let mut matches = lookups
                .iter()
                .filter(|(_, lookup)| lookup.addresses.contains(&ip));
            let selected = matches.next();
            let ambiguous = selected.is_some_and(|(_, selected)| {
                matches.any(|(_, other)| other.lookup_id != selected.lookup_id)
            });
            (selected.cloned(), ambiguous)
        };
        if ambiguous {
            self.observer.publish(FlowEvent::Gap(
                crate::runtime::flow_observation::GapReason::NotInstrumented,
            ));
            return;
        }
        if let Some((context, mut lookup)) = selected {
            lookup.selected_ip = Some(ip);
            (self.observer.callback)(context, FlowEvent::Dns(lookup));
        }
    }
}

#[cfg(feature = "flow-observation")]
/// Preserve source identity until a consumer chooses an address from the result.
pub async fn observe_resolution<F: Future>(future: F) -> (F::Output, Option<LookupSelection>) {
    let future = std::pin::pin!(future);
    let Some(observer) = current() else {
        return (future.await, None);
    };
    let context = observer.context();
    let lookups = Arc::new(parking_lot::Mutex::new(
        Vec::<(FlowContext, DnsLookup)>::new(),
    ));
    let captured = Arc::clone(&lookups);
    let output = observer.clone();
    let mut nested = FlowObserver::new(
        context,
        Arc::new(move |source, event| {
            if let FlowEvent::Dns(lookup) = &event
                && lookup.parent_lookup_id == context.lookup_id
                && lookup.purpose == context.dns_purpose
                && lookup.selected_ip.is_none()
                && !lookup.addresses.is_empty()
            {
                let overflow = {
                    let mut captured = captured.lock();
                    if captured.len() == 4 || lookup.addresses.len() > 32 {
                        true
                    } else {
                        captured.push((source, lookup.clone()));
                        false
                    }
                };
                if overflow {
                    output.publish(FlowEvent::Gap(
                        crate::runtime::flow_observation::GapReason::BufferOverflow,
                    ));
                }
            }
            (output.callback)(source, event);
        }),
    );
    nested.dropped = observer.dropped;
    nested.request_lifetime = observer.request_lifetime.clone();
    let result = nested.scope(future).await;
    (result, Some(LookupSelection { observer, lookups }))
}

#[cfg(feature = "flow-observation")]
/// One real physical attempt. Capture before starting I/O, not before admission.
pub struct TransportAttempt {
    observer: FlowObserver,
    attempt_id: Uuid,
    server_addr: Option<SocketAddr>,
    resolution_location: ResolutionLocation,
    finished: bool,
}

#[cfg(feature = "flow-observation")]
impl TransportAttempt {
    pub fn start(
        server_addr: Option<SocketAddr>,
        resolution_location: ResolutionLocation,
    ) -> Option<Self> {
        let observer = current()?;
        let attempt = Self {
            observer,
            attempt_id: Uuid::new_v4(),
            server_addr,
            resolution_location,
            finished: false,
        };
        attempt.publish(TransportStatus::Started, None);
        Some(attempt)
    }

    pub fn finish(&mut self, status: TransportStatus, error: Option<TransportError>) {
        if !self.finished {
            self.finished = true;
            self.publish(status, error);
        }
    }

    fn publish(&self, status: TransportStatus, error: Option<TransportError>) {
        self.observer.publish(FlowEvent::Transport {
            attempt_id: self.attempt_id,
            server_addr: self.server_addr,
            status,
            resolution_location: self.resolution_location,
            error,
        });
    }
}

#[cfg(feature = "flow-observation")]
impl Drop for TransportAttempt {
    fn drop(&mut self) {
        self.finish(TransportStatus::Cancelled, Some(TransportError::Cancelled));
    }
}

/// Inert twin: uninhabited types keep `Option<_>` fields zero-sized and every
/// hook folds away, so call sites need no feature gates.
#[cfg(not(feature = "flow-observation"))]
mod inert {
    use std::future::Future;
    use std::net::{IpAddr, SocketAddr};
    use std::pin::Pin;

    use futures_util::FutureExt;

    use super::{
        FlowContext, FlowEvent, Milestone, ResolutionLocation, TransportError, TransportStatus,
    };

    #[derive(Clone, Debug)]
    pub enum FlowObserver {}

    impl FlowObserver {
        #[inline]
        pub fn context(&self) -> FlowContext {
            match *self {}
        }

        #[inline]
        pub fn with_context(&self, _context: FlowContext) -> Self {
            match *self {}
        }

        #[inline]
        pub fn publish(&self, _event: FlowEvent) {
            match *self {}
        }

        #[inline]
        pub fn milestone_once(&self, _milestone: Milestone) {
            match *self {}
        }

        #[inline]
        pub fn scope<F: Future>(&self, _future: F) -> F {
            match *self {}
        }

        #[inline]
        pub fn sync_scope<T>(&self, _build: impl FnOnce() -> T) -> T {
            match *self {}
        }
    }

    #[inline]
    pub fn current() -> Option<FlowObserver> {
        None
    }

    #[inline]
    pub(crate) fn is_suppressed() -> bool {
        false
    }

    // Only the rprx VMess relay re-scopes a captured observer in inert builds.
    #[cfg(feature = "rprx")]
    #[inline]
    pub(crate) fn scope<F: Future>(_observer: Option<FlowObserver>, future: F) -> F {
        future
    }

    #[inline]
    pub fn without<F: Future>(future: F) -> F {
        future
    }

    #[inline]
    pub(crate) fn without_target_milestones<F: Future>(future: F) -> F {
        future
    }

    #[inline]
    pub fn milestone(_milestone: Milestone) {}

    #[derive(Clone, Debug)]
    pub(crate) struct RelayedPipe;

    impl RelayedPipe {
        #[inline]
        pub(crate) const fn new() -> Self {
            Self
        }

        #[inline]
        pub(crate) fn poll_write(
            &self,
            write: impl FnOnce() -> std::task::Poll<std::io::Result<usize>>,
        ) -> std::task::Poll<std::io::Result<usize>> {
            write()
        }

        #[inline]
        pub(crate) fn take(&self, _relayed: u64) -> Option<RelayedRequest> {
            None
        }
    }

    pub(crate) enum RelayedRequest {}

    impl RelayedRequest {
        pub(crate) async fn write<F: Future>(self, _write: Pin<&mut F>) -> F::Output {
            match self {}
        }
    }

    #[derive(Debug)]
    pub(crate) struct DriverRequest;

    impl DriverRequest {
        #[inline]
        pub(crate) const fn new() -> Self {
            Self
        }

        #[inline]
        pub(crate) fn capture(&mut self) {}

        #[inline]
        pub(crate) fn drive<T>(&self, poll: impl FnOnce() -> T) -> T {
            poll()
        }

        #[inline]
        pub(crate) fn release(&mut self) {}

        #[inline]
        pub(crate) fn discard(&mut self) {}
    }

    #[inline]
    pub(crate) fn request_write<F: Future>(future: Pin<&mut F>) -> Pin<&mut F> {
        future
    }

    #[inline]
    pub(crate) fn observe_chain_request<F: Future>(future: F) -> F {
        future
    }

    pub enum LookupSelection {}

    impl LookupSelection {
        #[inline]
        pub fn selected_ip(&self, _ip: IpAddr) {
            match *self {}
        }
    }

    #[inline]
    pub fn observe_resolution<F: Future>(
        future: F,
    ) -> impl Future<Output = (F::Output, Option<LookupSelection>)> {
        future.map(|output| (output, None))
    }

    pub enum TransportAttempt {}

    impl TransportAttempt {
        #[inline]
        pub fn start(
            _server_addr: Option<SocketAddr>,
            _resolution_location: ResolutionLocation,
        ) -> Option<Self> {
            None
        }

        #[inline]
        pub fn finish(&mut self, _status: TransportStatus, _error: Option<TransportError>) {
            match *self {}
        }
    }

    const _: () = assert!(size_of::<Option<FlowObserver>>() == 0);
    const _: () = assert!(size_of::<Option<TransportAttempt>>() == 0);
    const _: () = assert!(size_of::<RelayedPipe>() == 0);
    const _: () = assert!(size_of::<DriverRequest>() == 0);
}

#[cfg(all(not(feature = "flow-observation"), feature = "rprx"))]
pub(crate) use inert::scope;
#[cfg(not(feature = "flow-observation"))]
pub(crate) use inert::{
    DriverRequest, RelayedPipe, is_suppressed, observe_chain_request, request_write,
    without_target_milestones,
};
#[cfg(not(feature = "flow-observation"))]
pub use inert::{
    FlowObserver, LookupSelection, TransportAttempt, current, milestone, observe_resolution,
    without,
};

#[cfg(all(test, feature = "flow-observation"))]
mod tests;
