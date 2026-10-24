//! UDP endpoint pool — NAT mapping and connection tracking for UDP relay.
//!
//! Each UDP "connection" (identified by client address + destination address)
//! gets a pooled endpoint that handles bidirectional forwarding and
//! NAT timeout management. Mirrors the Go `udp_endpoint_pool.go`.
//!
//! The pool is a [`DashMap`] so that per-packet lookups on the UDP fast path
//! only contend on a single shard instead of one global mutex.

#[cfg(test)]
use self::driver::TRANSPORT_SEND_TIMEOUT;
use crate::ebpf::UdpFlowOwner;
use crate::stats::{ActiveConnectionGuard, OutboundTracker, StatsManager};
use bytes::Bytes;
use dashmap::DashMap;
use honk_outbound::group::{ScoreOutcome, ScoreReporter};
use parking_lot::Mutex;
pub(in crate::control) use source::UplinkStall;
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tracing::debug;

/// How an observed UDP connection ended.
#[cfg_attr(
    not(all(feature = "native-api", feature = "ebpf")),
    allow(
        dead_code,
        reason = "builds name only the outcomes their engine paths report"
    )
)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::control) enum UdpTerminal {
    PolicyBlock,
    IntentionalRetirement,
    ReplyIdle,
    Shutdown,
    CleanupFailed,
    ClientDeliveryFailed,
    Congestion,
    DriverCancelled,
    InitializerCancelled,
    InitializerFirstPacketMissing,
    InitializerQueueMissing,
    InternalAddressSkipped,
    LocalRefusal,
    NoAvailableCandidate,
    PacketRejected,
    QuicSniffIncomplete,
    ReplyFamilyMismatch,
    ReplySocketFailed,
    SetupFailed,
    SpecialAddressSkipped,
    TimeoutAfterReply,
    TimeoutBeforeReply,
    TransportError,
    TransportTimeout,
    UdpCommitFailed,
    UdpCommitTimeout,
    UdpPrepareFailed,
    UdpPrepareTimeout,
    WinnerBindCancelled,
    WinnerIneligible,
    DriverCompleted,
    KernelHandoff,
}

#[cfg(feature = "native-api")]
impl UdpTerminal {
    fn outcome(self) -> (crate::observe::vocab::ConnectionState, &'static str) {
        use crate::observe::vocab::ConnectionState::{Blocked, Closed, Failed, Unknown};
        match self {
            Self::PolicyBlock => (Blocked, "policy_block"),
            Self::IntentionalRetirement => (Closed, "intentional_retirement"),
            Self::ReplyIdle => (Closed, "reply_idle"),
            Self::Shutdown => (Closed, "shutdown"),
            Self::CleanupFailed => (Failed, "cleanup_failed"),
            Self::ClientDeliveryFailed => (Failed, "client_delivery_failed"),
            Self::Congestion => (Failed, "congestion"),
            Self::DriverCancelled => (Failed, "driver_cancelled"),
            Self::InitializerCancelled => (Failed, "initializer_cancelled"),
            Self::InitializerFirstPacketMissing => (Failed, "initializer_first_packet_missing"),
            Self::InitializerQueueMissing => (Failed, "initializer_queue_missing"),
            Self::InternalAddressSkipped => (Failed, "internal_address_skipped"),
            Self::LocalRefusal => (Failed, "local_refusal"),
            Self::NoAvailableCandidate => (Failed, "no_available_candidate"),
            Self::PacketRejected => (Failed, "packet_rejected"),
            Self::QuicSniffIncomplete => (Failed, "quic_sniff_incomplete"),
            Self::ReplyFamilyMismatch => (Failed, "reply_family_mismatch"),
            Self::ReplySocketFailed => (Failed, "reply_socket_failed"),
            Self::SetupFailed => (Failed, "setup_failed"),
            Self::SpecialAddressSkipped => (Failed, "special_address_skipped"),
            Self::TimeoutAfterReply => (Failed, "timeout_after_reply"),
            Self::TimeoutBeforeReply => (Failed, "timeout_before_reply"),
            Self::TransportError => (Failed, "transport_error"),
            Self::TransportTimeout => (Failed, "transport_timeout"),
            Self::UdpCommitFailed => (Failed, "udp_commit_failed"),
            Self::UdpCommitTimeout => (Failed, "udp_commit_timeout"),
            Self::UdpPrepareFailed => (Failed, "udp_prepare_failed"),
            Self::UdpPrepareTimeout => (Failed, "udp_prepare_timeout"),
            Self::WinnerBindCancelled => (Failed, "winner_bind_cancelled"),
            Self::WinnerIneligible => (Failed, "winner_ineligible"),
            Self::DriverCompleted => (Unknown, "driver_completed"),
            Self::KernelHandoff => (Unknown, "kernel_handoff"),
        }
    }
}

mod admission;
#[cfg_attr(not(feature = "native-api"), path = "observation/inert.rs")]
mod observation;
mod retirement;
mod source;
#[cfg(test)]
mod source_quic_tests;
#[cfg(test)]
mod source_shared_tests;
#[cfg(all(test, feature = "rprx"))]
mod source_tests;
use retirement::{EndpointIoGuard, RetirementIo};
pub(crate) use retirement::{EndpointRemoval, RemovalReason};
pub(in crate::control) use source::{SourceAttachment, SourcePath, SourcePreparation};
use source::{SourceEndpoint, SourceOwner, SourceRetirement, SourceScope};
#[doc(hidden)]
pub mod bench_support;
#[cfg(feature = "ebpf")]
pub(in crate::control) use admission::OwnedEnqueueError;
pub(in crate::control) use admission::{
    DatagramPayload, EndpointReservation, QueuedDatagram, RawDnsRoute, UdpInitLease, queue_now,
};
use admission::{EndpointEntry, EndpointKey, FLOW_QUEUE_CAPACITY, GLOBAL_PAYLOAD_CAPACITY};
#[cfg(test)]
use admission::{ReservationGateHook, ReservationPublicationHook};

const DEFAULT_NAT_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard cap on pooled endpoints. A unique-tuple UDP flood must not be able
/// to grow the pool (and with it sockets, reply tasks and memory) without
/// bound — at the cap new mappings are refused and the datagram is dropped,
/// which UDP tolerates by design.
pub(crate) const MAX_ENDPOINTS: usize = 32_768;
/// Total reply sockets retained by one endpoint, including the eagerly-created primary.
pub(in crate::control) const MAX_REPLY_SOCKETS_PER_ENDPOINT: usize = 8;
enum EndpointTransport {
    Flow(Arc<dyn honk_outbound::proxy::PacketTransport>),
    Source(SourceEndpoint),
}

/// A pooled UDP endpoint representing one NAT mapping.
pub struct UdpEndpoint {
    transport: EndpointTransport,
    /// The relay target address (upstream proxy).
    pub relay_addr: SocketAddr,
    target_is_domain: bool,
    /// NodeId of the proxy node this endpoint dials through.
    node_id: uuid::Uuid,
    /// When this endpoint expires (monotonic nanos).
    expires_at: AtomicI64,
    /// Whether the endpoint has received at least one reply.
    has_reply: AtomicBool,
    reply_epoch: AtomicU64,
    reply_notify: Notify,
    /// Guard for the exactly-once first-reply metric.
    first_reply_recorded: AtomicBool,
    /// Bounds traffic-state lock acquisition to five times per second per endpoint.
    next_alive_report_at: AtomicI64,
    /// Creation time used for reply latency accounting.
    created_at: Instant,
    /// Reference count for active operations.
    ref_count: AtomicI64,
    /// Set when node retirement wins before a packet send starts.
    dead: AtomicBool,
    /// Serializes retirement with send and shared-reply admission.
    send_gate: Mutex<()>,
    /// Ring buffer of peers we've sent packets to (for reply validation).
    pending_reply_peers: Mutex<[(SocketAddr, bool); 8]>,
    /// Next ring position to write.
    pending_reply_next: AtomicU64,
    /// Live byte counters shared with the clash-API tracker entry.
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
    score_reporter: Option<ScoreReporter>,
    health_family: honk_outbound::alive::IpVersion,
    #[cfg(test)]
    source_reply_hook: Mutex<Option<Arc<source::ReplyAdmissionHook>>>,
    tracker_id: Mutex<Option<String>>,
    pub(in crate::control) native: observation::EndpointObservation,
    retirement: EndpointIoGuard,
}

impl UdpEndpoint {
    pub fn new(
        proxy_socket: Arc<dyn honk_outbound::proxy::PacketTransport>,
        relay_addr: SocketAddr,
        node_id: uuid::Uuid,
    ) -> Self {
        Self::new_scored(
            proxy_socket,
            relay_addr,
            false,
            node_id,
            honk_outbound::alive::IpVersion::V4,
            None,
        )
    }

    pub fn new_scored(
        proxy_socket: Arc<dyn honk_outbound::proxy::PacketTransport>,
        relay_addr: SocketAddr,
        target_is_domain: bool,
        node_id: uuid::Uuid,
        health_family: honk_outbound::alive::IpVersion,
        score_reporter: Option<ScoreReporter>,
    ) -> Self {
        Self::new_inner(
            EndpointTransport::Flow(proxy_socket),
            relay_addr,
            target_is_domain,
            node_id,
            health_family,
            score_reporter,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::control) fn new_source_scored(
        attachment: SourceAttachment,
        target: SocketAddr,
        target_domain: Option<&str>,
        reply_socket: Arc<ReplySocket>,
        flow_tracker: OutboundTracker,
        node_id: uuid::Uuid,
        health_family: honk_outbound::alive::IpVersion,
        score_reporter: Option<ScoreReporter>,
    ) -> Self {
        Self::new_inner(
            EndpointTransport::Source(SourceEndpoint::new(
                attachment,
                target,
                target_domain,
                reply_socket,
                flow_tracker,
            )),
            target,
            target_domain.is_some(),
            node_id,
            health_family,
            score_reporter,
        )
    }

    fn new_inner(
        transport: EndpointTransport,
        relay_addr: SocketAddr,
        target_is_domain: bool,
        node_id: uuid::Uuid,
        health_family: honk_outbound::alive::IpVersion,
        score_reporter: Option<ScoreReporter>,
    ) -> Self {
        let now = monotonic_nanos();
        Self {
            dead: AtomicBool::new(false),
            transport,
            relay_addr,
            target_is_domain,
            node_id,
            expires_at: AtomicI64::new(now + nanos_from_dur(DEFAULT_NAT_TIMEOUT)),
            has_reply: AtomicBool::new(false),
            reply_epoch: AtomicU64::new(0),
            reply_notify: Notify::new(),
            first_reply_recorded: AtomicBool::new(false),
            next_alive_report_at: AtomicI64::new(0),
            created_at: Instant::now(),
            ref_count: AtomicI64::new(1),
            send_gate: Mutex::new(()),
            pending_reply_peers: Mutex::new(
                [(
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                    false,
                ); 8],
            ),
            pending_reply_next: AtomicU64::new(0),
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            source_reply_hook: Mutex::new(None),
            tracker_id: Mutex::new(None),
            score_reporter,
            health_family,
            native: Default::default(),
            retirement: EndpointIoGuard(RetirementIo::new()),
        }
    }

    #[cfg(feature = "native-api")]
    fn finish_native_source(&self, retirement: SourceRetirement) {
        let outcome = match retirement {
            SourceRetirement::Neutral(ScoreOutcome::Timeout) if self.has_reply() => {
                UdpTerminal::ReplyIdle
            }
            SourceRetirement::Neutral(ScoreOutcome::Timeout) if self.native.received_reply() => {
                UdpTerminal::TimeoutAfterReply
            }
            SourceRetirement::Neutral(ScoreOutcome::Timeout) => UdpTerminal::TimeoutBeforeReply,
            SourceRetirement::Neutral(_) => UdpTerminal::IntentionalRetirement,
            SourceRetirement::Failure(
                ScoreOutcome::Timeout | ScoreOutcome::Io(io::ErrorKind::TimedOut),
            ) => UdpTerminal::TransportTimeout,
            SourceRetirement::Failure(_) => UdpTerminal::TransportError,
        };
        self.native.finish(outcome);
    }

    /// Bind the clash-API tracker entry to this endpoint: the entry shares
    /// the endpoint's atomic counters, and `conn_id` is stored for removal.
    pub fn set_tracker(&self, conn_id: String) {
        *self.tracker_id.lock() = Some(conn_id);
    }

    /// Counter clones for the tracker entry.
    pub fn byte_counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (self.upload.clone(), self.download.clone())
    }

    /// Count client→proxy bytes (lock-free).
    pub fn tracker_upload(&self, n: u64) {
        self.upload.fetch_add(n, Ordering::Relaxed);
    }

    /// Count proxy→client bytes (lock-free).
    pub fn tracker_download(&self, n: u64) {
        self.download.fetch_add(n, Ordering::Relaxed);
    }

    fn score_reply(&self, bytes: u64) {
        if let Some(reporter) = &self.score_reporter {
            reporter.first_response();
            reporter.rx(bytes);
        }
    }

    pub(crate) fn finish_score(&self, outcome: ScoreOutcome) {
        let Some(reporter) = &self.score_reporter else {
            return;
        };
        let outcome = match &self.transport {
            EndpointTransport::Source(source) if outcome != ScoreOutcome::Shutdown => {
                match source.score_retirement() {
                    Some(SourceRetirement::Neutral(_)) if self.has_reply() => ScoreOutcome::Success,
                    Some(
                        SourceRetirement::Neutral(outcome) | SourceRetirement::Failure(outcome),
                    ) => outcome,
                    None => outcome,
                }
            }
            _ => outcome,
        };
        reporter.finish(outcome);
    }

    /// Take the tracker connection id (on endpoint removal).
    pub fn take_tracker_id(&self) -> Option<String> {
        self.tracker_id.lock().take()
    }

    pub fn is_expired(&self) -> bool {
        monotonic_nanos() > self.expires_at.load(Ordering::Relaxed)
    }

    pub fn refresh(&self) {
        self.expires_at.store(
            monotonic_nanos() + nanos_from_dur(DEFAULT_NAT_TIMEOUT),
            Ordering::Relaxed,
        );
    }

    pub fn mark_reply(&self) {
        let first = !self.has_reply.swap(true, Ordering::Relaxed);
        if first && let Some(flow) = self.native.flow() {
            flow.transition(
                crate::observe::vocab::ConnectionState::Active,
                "client_delivery_succeeded",
                crate::observe::vocab::ConnectionMilestone::Unknown,
                Some(true),
            );
        }
        self.refresh();
        self.reply_epoch.fetch_add(1, Ordering::Release);
        self.reply_notify.notify_waiters();
    }

    fn take_first_reply_metric(&self) -> Option<Duration> {
        if self.first_reply_recorded.load(Ordering::Acquire) {
            return None;
        }
        (!self.first_reply_recorded.swap(true, Ordering::AcqRel)).then(|| self.created_at.elapsed())
    }

    fn take_alive_report_slot(&self) -> bool {
        let now = monotonic_nanos();
        if now < self.next_alive_report_at.load(Ordering::Relaxed) {
            return false;
        }
        self.next_alive_report_at.store(
            now + nanos_from_dur(TRAFFIC_ALIVE_REPORT_INTERVAL),
            Ordering::Relaxed,
        );
        true
    }

    pub fn has_reply(&self) -> bool {
        self.has_reply.load(Ordering::Relaxed)
    }

    pub fn release(&self) {
        self.ref_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn kill(&self) {
        // A retirement ordered before `begin_send_attempt` must prevent the
        // transport call; an attempt already admitted remains ambiguous.
        let _send_gate = self.send_gate.lock();
        if self.dead.load(Ordering::Acquire) {
            return;
        }
        match &self.transport {
            EndpointTransport::Flow(_) => self.dead.store(true, Ordering::Release),
            EndpointTransport::Source(source) => source.retire(&self.dead),
        }
    }

    fn begin_send_attempt(&self) -> io::Result<()> {
        let _send_gate = self.send_gate.lock();
        if self.dead.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "UDP endpoint was retired before transport send",
            ));
        }
        Ok(())
    }

    fn flow_transport(&self) -> Option<&dyn honk_outbound::proxy::PacketTransport> {
        match &self.transport {
            EndpointTransport::Flow(transport) => Some(transport.as_ref()),
            EndpointTransport::Source(_) => None,
        }
    }

    fn is_source(&self) -> bool {
        match &self.transport {
            EndpointTransport::Flow(_) => false,
            EndpointTransport::Source(_) => true,
        }
    }

    fn send_timeout(&self) -> Duration {
        match &self.transport {
            EndpointTransport::Flow(transport) => transport.send_timeout(),
            EndpointTransport::Source(source) => source.send_timeout(),
        }
    }

    fn send_timeout_is_congestion(&self) -> bool {
        self.packet_transport().send_timeout_is_congestion()
    }

    fn quic_path_stalled(&self) -> bool {
        self.packet_transport().quic_path_stalled()
    }

    fn packet_transport(&self) -> &dyn honk_outbound::proxy::PacketTransport {
        match &self.transport {
            EndpointTransport::Flow(transport) => transport.as_ref(),
            EndpointTransport::Source(source) => source.packet_transport(),
        }
    }

    #[cfg(test)]
    async fn send_packet(&self, data: &[u8], confirmed: bool) -> io::Result<()> {
        self.send_packet_with_admission(data, confirmed, None, &mut None)
            .await
            .map(|_| ())
    }

    async fn send_packet_with_admission<'a>(
        &'a self,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
        attempt: &mut Option<honk_outbound::proxy::QuicSendAttempt<'a>>,
    ) -> io::Result<Option<Instant>> {
        let operation = async {
            match &self.transport {
                EndpointTransport::Flow(transport) if confirmed => {
                    transport.send_packet_confirmed(data).await.map(|()| None)
                }
                EndpointTransport::Flow(transport) => {
                    transport.send_packet(data).await.map(|()| None)
                }
                EndpointTransport::Source(source) => {
                    let record_start = self.score_reporter.is_some()
                        && !data.is_empty()
                        && self.upload.load(Ordering::Relaxed) == 0;
                    source
                        .send(data, confirmed, admitted, record_start, attempt)
                        .await
                }
            }
        };
        if let Some(observer) = self.native.observer() {
            return observer.scope(operation).await;
        }
        operation.await
    }

    fn fail_source(&self, outcome: ScoreOutcome) {
        if let EndpointTransport::Source(source) = &self.transport {
            source.fail(outcome);
        }
    }

    fn source_uplink_stall(&self) -> Option<&UplinkStall> {
        match &self.transport {
            EndpointTransport::Flow(_) => None,
            EndpointTransport::Source(source) => Some(source.uplink_stall()),
        }
    }

    fn source_flow_idle_expired(&self) {
        if let EndpointTransport::Source(source) = &self.transport {
            source.flow_idle_expired();
        }
    }

    #[cfg(all(test, feature = "native-api"))]
    fn source_owner_id(&self) -> Option<u64> {
        match &self.transport {
            EndpointTransport::Source(source) => Some(source.owner_id()),
            EndpointTransport::Flow(_) => None,
        }
    }

    fn commit_source_binding(&self, endpoint_permit: OwnedSemaphorePermit) -> bool {
        match &self.transport {
            EndpointTransport::Source(source) => source.commit_binding(endpoint_permit),
            EndpointTransport::Flow(_) => {
                drop(endpoint_permit);
                false
            }
        }
    }

    fn begin_source_reply(&self, owner_id: u64) -> bool {
        match &self.transport {
            EndpointTransport::Source(source) => source.reply_admitted(owner_id),
            EndpointTransport::Flow(_) => false,
        }
    }

    fn source_reply_socket(&self) -> &Arc<ReplySocket> {
        match &self.transport {
            EndpointTransport::Source(source) => source.reply_socket(),
            EndpointTransport::Flow(_) => panic!("ordinary UDP endpoint has no source reply lease"),
        }
    }

    fn record_source_reply(&self, len: u64) {
        self.tracker_download(len);
        self.score_reply(len);
        if let EndpointTransport::Source(source) = &self.transport {
            source.record_reply(len);
        }
    }

    #[cfg(all(test, feature = "rprx"))]
    fn mark_source_send_active_for_test(&self) {
        let EndpointTransport::Source(source) = &self.transport else {
            panic!("test endpoint is not source-bound");
        };
        source.mark_send_active_for_test();
    }

    async fn wait_for_reply_after(&self, observed: u64) -> u64 {
        loop {
            let notified = self.reply_notify.notified();
            let current = self.reply_epoch.load(Ordering::Acquire);
            if current != observed {
                return current;
            }
            notified.await;
        }
    }

    pub fn ref_count(&self) -> i64 {
        self.ref_count.load(Ordering::Relaxed)
    }

    /// Record a peer we've sent a packet to (for reply validation).
    ///
    /// Stores the peer address in a ring buffer. Transports without an
    /// explicit full-cone capability accept replies only from these peers.
    pub fn record_pending_reply_peer(&self, peer: SocketAddr) {
        let mut ring = self.pending_reply_peers.lock();
        let next = self.pending_reply_next.fetch_add(1, Ordering::Relaxed) as usize % 8;
        ring[next] = (peer, true);
    }

    /// Validate that a reply peer is expected for a fixed-peer transport.
    pub fn validate_reply_peer(&self, peer: SocketAddr) -> bool {
        self.pending_reply_peers
            .lock()
            .iter()
            .any(|(addr, valid)| *valid && *addr == peer)
    }
}

/// A synchronously-created anyfrom socket. The default factory calls the
/// daens-scoped production helper so eager and lazy sockets preserve the same
/// network-namespace and source-address invariants.
pub(super) trait UdpReplySocketFactory: Send + Sync + std::fmt::Debug {
    fn create(&self, source: SocketAddr) -> io::Result<UdpSocket>;
}

pub(super) struct ReplySocket {
    socket: ReplySocketFd,
    _permit: Option<OwnedSemaphorePermit>,
}

enum ReplySocketFd {
    Bounded(UdpSocket),
    #[cfg(test)]
    Untracked(Arc<UdpSocket>),
}

impl std::ops::Deref for ReplySocket {
    type Target = UdpSocket;

    fn deref(&self) -> &Self::Target {
        match &self.socket {
            ReplySocketFd::Bounded(socket) => socket,
            #[cfg(test)]
            ReplySocketFd::Untracked(socket) => socket,
        }
    }
}

impl ReplySocket {
    fn create(
        factory: &dyn UdpReplySocketFactory,
        slots: &Arc<Semaphore>,
        source: SocketAddr,
    ) -> io::Result<Self> {
        let permit = Arc::clone(slots)
            .try_acquire_owned()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "UDP reply socket capacity"))?;
        Ok(Self {
            socket: ReplySocketFd::Bounded(factory.create(source)?),
            _permit: Some(permit),
        })
    }

    #[cfg(test)]
    fn untracked(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket: ReplySocketFd::Untracked(socket),
            _permit: None,
        }
    }
}

/// Finds or creates the reply socket for a non-primary peer, replacing the least
/// recently used one once `MAX_REPLY_SOCKETS_PER_ENDPOINT - 1` are open.
// ponytail: more interleaved unbound peers than slots recreate a socket per reply.
fn alternate_reply_socket(
    sockets: &mut Vec<(SocketAddr, ReplySocket)>,
    source: SocketAddr,
    create: impl FnOnce() -> io::Result<ReplySocket>,
) -> io::Result<&ReplySocket> {
    match sockets.iter().position(|(cached, _)| *cached == source) {
        Some(index) => sockets[index..].rotate_left(1),
        None => {
            if sockets.len() >= MAX_REPLY_SOCKETS_PER_ENDPOINT - 1 {
                // Drop first so the replacement can take its slot permit.
                sockets.remove(0);
            }
            sockets.push((source, create()?));
        }
    }
    Ok(&sockets.last().expect("reply socket cached above").1)
}

#[derive(Debug)]
struct SystemUdpReplySocketFactory;

impl UdpReplySocketFactory for SystemUdpReplySocketFactory {
    fn create(&self, source: SocketAddr) -> io::Result<UdpSocket> {
        super::new_udp_reply_socket(source)
    }
}

pub(in crate::control) struct UdpShutdown {
    pub joined: bool,
    pub graceful: bool,
}

/// Pool state is a single map entry per tuple: Initializing, Ready, or the
/// exact Retiring identity that fences reuse until cleanup is acknowledged.
pub struct UdpEndpointPool {
    endpoints: DashMap<EndpointKey, EndpointEntry>,
    endpoint_slots: Arc<Semaphore>,
    global_payload_bytes: Arc<Semaphore>,
    /// Lifetime-held across active and retiring ordinary/source reply sockets.
    /// The fixed 8× endpoint budget prevents teardown overlap from doubling FDs.
    reply_socket_slots: Arc<Semaphore>,
    sources: DashMap<SourceScope, Arc<SourceOwner>>,
    source_slots: Arc<Semaphore>,
    next_source_owner: AtomicU64,
    source_tasks: Mutex<TaskRegistry>,
    source_changed: Notify,
    /// Linearizes finalized-node binding against node-death scans. Without
    /// this gate a scan can observe an unbound initializer, then binding can
    /// publish a dead winner after the scan has passed.
    node_binding_gate: Mutex<()>,
    /// Monotonic per-reservation incarnation; used only for map ownership.
    next_generation: AtomicU64,
    /// Serializes initializer publication, cancellation bumps, and Ready
    /// commits. Reservations and commits take a map entry before this gate;
    /// cancellation takes only this gate. It is never held across await.
    initialization_epoch: Mutex<u64>,
    cancel_epoch: watch::Sender<u64>,
    active_initializers: AtomicUsize,
    initializers_empty: Notify,
    terminal: AtomicBool,
    slow_tasks: Mutex<TaskRegistry>,
    drivers: Mutex<TaskRegistry>,
    reply_socket_factory: Arc<dyn UdpReplySocketFactory>,
    /// Sink notified whenever an endpoint is removed; the control plane uses
    /// it to retire conntrack and tracker state exactly once.
    remove_sink: Mutex<Option<tokio::sync::mpsc::Sender<EndpointRemoval>>>,
    /// Bounded compensation for removals observed while the sink is full.
    removal_dirty: Mutex<HashSet<EndpointRemoval>>,
    active_retirements: AtomicUsize,
    retirements_empty: Notify,
    /// Test-only synchronous barrier at the historical publication point.
    /// It makes the cancellation linearization regression reproducible
    /// without introducing an await into reservation.
    #[cfg(test)]
    reservation_publication_hook: Mutex<Option<Arc<ReservationPublicationHook>>>,
    #[cfg(test)]
    reservation_gate_hook: Mutex<Option<Arc<ReservationGateHook>>>,
}

impl UdpEndpointPool {
    /// Construct a max-capacity pool for tests and standalone callers.
    pub fn new() -> Self {
        Self::with_capacity_limit(MAX_ENDPOINTS)
    }

    /// Construct a pool with an explicit endpoint cap.
    pub fn with_capacity_limit(capacity_limit: usize) -> Self {
        Self::with_reply_socket_factory(
            capacity_limit.min(MAX_ENDPOINTS),
            Arc::new(SystemUdpReplySocketFactory),
        )
    }

    /// Dependency injection seam for synchronous anyfrom creation. The first
    /// socket is created before the driver starts; accepted alternate reply
    /// sources use the same factory lazily in the driver.
    pub(super) fn with_reply_socket_factory(
        capacity_limit: usize,
        reply_socket_factory: Arc<dyn UdpReplySocketFactory>,
    ) -> Self {
        let (cancel_epoch, _) = watch::channel(0u64);
        Self {
            endpoints: DashMap::new(),
            endpoint_slots: Arc::new(Semaphore::new(capacity_limit)),
            global_payload_bytes: Arc::new(Semaphore::new(GLOBAL_PAYLOAD_CAPACITY)),
            reply_socket_slots: Arc::new(Semaphore::new(
                capacity_limit.saturating_mul(MAX_REPLY_SOCKETS_PER_ENDPOINT),
            )),
            sources: DashMap::new(),
            source_slots: Arc::new(Semaphore::new(capacity_limit)),
            next_source_owner: AtomicU64::new(1),
            source_tasks: Mutex::new(TaskRegistry::default()),
            source_changed: Notify::new(),
            node_binding_gate: Mutex::new(()),
            next_generation: AtomicU64::new(1),
            initialization_epoch: Mutex::new(0),
            cancel_epoch,
            active_initializers: AtomicUsize::new(0),
            initializers_empty: Notify::new(),
            terminal: AtomicBool::new(false),
            slow_tasks: Mutex::new(TaskRegistry::default()),
            drivers: Mutex::new(TaskRegistry::default()),
            reply_socket_factory,
            remove_sink: Mutex::new(None),
            removal_dirty: Mutex::new(HashSet::new()),
            active_retirements: AtomicUsize::new(0),
            retirements_empty: Notify::new(),
            #[cfg(test)]
            reservation_publication_hook: Mutex::new(None),
            #[cfg(test)]
            reservation_gate_hook: Mutex::new(None),
        }
    }

    pub(super) fn create_reply_socket(&self, source: SocketAddr) -> io::Result<ReplySocket> {
        ReplySocket::create(
            self.reply_socket_factory.as_ref(),
            &self.reply_socket_slots,
            source,
        )
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.endpoints.len()
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    #[cfg(test)]
    pub(super) fn contains(&self, client: SocketAddr, dst: SocketAddr) -> bool {
        self.endpoints.contains_key(&EndpointKey::new(client, dst))
    }

    #[cfg(test)]
    fn is_terminal(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn slow_task_count(&self) -> usize {
        self.slow_tasks.lock().tasks.len()
    }

    #[cfg(test)]
    fn driver_count(&self) -> usize {
        self.drivers.lock().tasks.len()
    }
}

impl Default for UdpEndpointPool {
    fn default() -> Self {
        Self::new()
    }
}

mod driver;

#[cfg(test)]
use driver::score_driver_outcome;
use driver::{
    DRIVER_ABORT_TIMEOUT, DRIVER_SHUTDOWN_TIMEOUT, TRAFFIC_ALIVE_REPORT_INTERVAL, TaskRegistry,
    join_registered_tasks, monotonic_nanos, nanos_from_dur,
};
#[cfg(test)]
use driver::{
    REPLY_IDLE_TIMEOUT, ReplyIdleTimeout, UdpDriverContext, UdpDriverStart, run_endpoint_driver,
};

#[cfg(test)]
mod tests;
