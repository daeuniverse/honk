use super::UdpTerminal;
use super::*;
use honk_outbound::proxy::QuicSendAttempt;

/// How long the endpoint driver waits for proxy data before giving up.
pub(super) const REPLY_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) const TRANSPORT_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Setup may consume the dynamic send deadline; queue retention still has one fixed bound.
const QUEUED_PACKET_MAX_AGE: Duration = Duration::from_secs(5);
pub(super) const TRAFFIC_ALIVE_REPORT_INTERVAL: Duration = Duration::from_millis(200);
pub(super) const DRIVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(6);
pub(super) const DRIVER_ABORT_TIMEOUT: Duration = Duration::from_secs(1);
#[derive(Debug)]
enum PacketSendFailure {
    Congestion(io::Error),
    Rejected(io::Error),
    Transport(io::Error),
}

const QUEUED_PACKET_EXPIRED: &str = "UDP packet expired in endpoint queue";

/// Marker separating receiver-idle expiry from a transport send timeout.
#[derive(Debug)]
pub(super) struct ReplyIdleTimeout;

impl std::fmt::Display for ReplyIdleTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UDP endpoint reply idle timeout")
    }
}

impl std::error::Error for ReplyIdleTimeout {}

fn is_reply_idle_timeout(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ReplyIdleTimeout>())
        .is_some()
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct LocalReplyError(#[source] io::Error);

fn local_reply_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), LocalReplyError(error))
}

fn is_local_reply_error(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<LocalReplyError>())
}

impl PacketSendFailure {
    fn into_io_error(self) -> io::Error {
        match self {
            Self::Congestion(error) => io::Error::new(io::ErrorKind::WouldBlock, error),
            Self::Rejected(error) => error,
            Self::Transport(error) => error,
        }
    }
}

fn classify_send_error(endpoint: &UdpEndpoint, error: io::Error) -> PacketSendFailure {
    match honk_outbound::proxy::packet_error_class(&error) {
        honk_outbound::proxy::PacketErrorClass::Rejected => PacketSendFailure::Rejected(error),
        honk_outbound::proxy::PacketErrorClass::Congestion => PacketSendFailure::Congestion(error),
        _ if error.kind() == io::ErrorKind::TimedOut && endpoint.send_timeout_is_congestion() => {
            PacketSendFailure::Congestion(error)
        }
        _ => PacketSendFailure::Transport(error),
    }
}

fn duplicate_send_error(error: &mut io::Error) -> io::Error {
    let kind = error.kind();
    let original = std::mem::replace(error, io::Error::from(io::ErrorKind::Other));
    let shared = honk_outbound::SharedError::new(original.into());
    *error = io::Error::new(kind, shared.clone());
    io::Error::new(kind, shared)
}

pub(super) struct TaskRegistry {
    pub(super) closed: bool,
    pub(super) tasks: tokio::task::JoinSet<()>,
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self {
            closed: false,
            tasks: tokio::task::JoinSet::new(),
        }
    }
}

async fn drain_registered_tasks(
    tasks: &mut tokio::task::JoinSet<()>,
    label: &str,
    disposition: &mut UdpShutdown,
) {
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            disposition.graceful = false;
            if !error.is_cancelled() {
                disposition.joined = false;
                debug!("UDP {} task join failed during shutdown: {}", label, error);
            }
        }
    }
}

pub(super) async fn join_registered_tasks(
    mut tasks: tokio::task::JoinSet<()>,
    label: &str,
    graceful_timeout: Duration,
    abort_first: bool,
) -> UdpShutdown {
    let mut disposition = UdpShutdown {
        joined: true,
        graceful: !abort_first,
    };
    if abort_first {
        tasks.abort_all();
    }
    if tokio::time::timeout(
        if abort_first {
            DRIVER_ABORT_TIMEOUT
        } else {
            graceful_timeout
        },
        drain_registered_tasks(&mut tasks, label, &mut disposition),
    )
    .await
    .is_err()
    {
        disposition.graceful = false;
        debug!(
            "Forcing cancellation of UDP {} tasks during shutdown",
            label
        );
        tasks.abort_all();
        if tokio::time::timeout(
            DRIVER_ABORT_TIMEOUT,
            drain_registered_tasks(&mut tasks, label, &mut disposition),
        )
        .await
        .is_err()
        {
            debug!("Timed out joining aborted UDP {} tasks", label);
            disposition.joined = false;
        }
    }
    disposition
}

pub(super) struct UdpDriverStart {
    pub(super) first: QueuedDatagram,
    pub(super) followers: Vec<QueuedDatagram>,
}

/// Channels that establish the driver barrier. The initializer creates the
/// anyfrom socket, spawns this driver, awaits `ready`, commits the map entry,
/// then transfers the retained initial flight and waits for `first_ack`.
pub(in crate::control) struct UdpDriverHandle {
    ready: Option<oneshot::Receiver<()>>,
    start: Option<oneshot::Sender<UdpDriverStart>>,
    first_ack: Option<oneshot::Receiver<io::Result<()>>>,
    /// Test-only cancellation handle; production ownership remains in the
    /// pool's driver registry until terminal shutdown joins every task.
    #[cfg(test)]
    task: Option<tokio::task::AbortHandle>,
}

/// Owns every terminal driver action. Its synchronous Drop runs after normal
/// completion, panic unwind, and Tokio task abort; token-and-generation-safe
/// retirement makes a stale driver harmless to a replacement mapping.
struct UdpDriverCleanupGuard {
    pool: Arc<UdpEndpointPool>,
    key: EndpointKey,
    generation: u64,
    decision_token: u32,
    endpoint: Arc<UdpEndpoint>,
    outcome: Option<ScoreOutcome>,
}

impl UdpDriverCleanupGuard {
    fn new(
        pool: Arc<UdpEndpointPool>,
        key: EndpointKey,
        generation: u64,
        decision_token: u32,
        endpoint: Arc<UdpEndpoint>,
    ) -> Self {
        Self {
            pool,
            key,
            generation,
            decision_token,
            endpoint,
            outcome: None,
        }
    }

    fn set_outcome(&mut self, outcome: ScoreOutcome) {
        self.outcome = Some(outcome);
    }
}

pub(super) struct UdpDriverResult {
    pub(super) result: io::Result<()>,
    pub(super) outcome: ScoreOutcome,
}

pub(in crate::control) enum DriverReplySocket {
    Bounded(Arc<ReplySocket>),
    #[cfg(test)]
    Untracked(Arc<UdpSocket>),
}

impl From<Arc<ReplySocket>> for DriverReplySocket {
    fn from(socket: Arc<ReplySocket>) -> Self {
        Self::Bounded(socket)
    }
}

#[cfg(test)]
impl From<Arc<UdpSocket>> for DriverReplySocket {
    fn from(socket: Arc<UdpSocket>) -> Self {
        Self::Untracked(socket)
    }
}

impl DriverReplySocket {
    fn into_socket(self) -> Arc<ReplySocket> {
        match self {
            Self::Bounded(socket) => socket,
            #[cfg(test)]
            Self::Untracked(socket) => Arc::new(ReplySocket::untracked(socket)),
        }
    }
}

pub(super) struct UdpDriverContext {
    pub(super) endpoint: Arc<UdpEndpoint>,
    pub(super) queue_rx: mpsc::Receiver<QueuedDatagram>,
    pub(super) reply_socket: Arc<ReplySocket>,
    pub(super) reply_socket_factory: Arc<dyn UdpReplySocketFactory>,
    pub(super) reply_socket_slots: Arc<Semaphore>,
    pub(super) client_addr: SocketAddr,
    pub(super) client_dst: SocketAddr,
    pub(super) alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    pub(super) stats: Arc<StatsManager>,
    pub(super) outbound_tracker: OutboundTracker,
    pub(super) health_family: honk_outbound::alive::IpVersion,
}

impl Drop for UdpDriverCleanupGuard {
    fn drop(&mut self) {
        self.endpoint.native.finish(UdpTerminal::DriverCancelled);
        self.endpoint
            .finish_score(if self.pool.terminal.load(Ordering::Acquire) {
                ScoreOutcome::Shutdown
            } else {
                self.outcome.unwrap_or(ScoreOutcome::Cancelled)
            });
        self.endpoint.release();
        self.pool
            .retire_if_same(self.key, self.decision_token, self.generation);
    }
}

impl UdpDriverHandle {
    pub(in crate::control) async fn wait_ready(&mut self) -> io::Result<()> {
        self.ready
            .take()
            .ok_or_else(|| io::Error::other("UDP endpoint driver ready already consumed"))?
            .await
            .map_err(|_| io::Error::other("UDP endpoint driver exited before ready"))
    }

    #[cfg(test)]
    pub(in crate::control) fn start(&mut self, first: QueuedDatagram) -> io::Result<()> {
        self.start_with_followers(first, Vec::new())
    }

    pub(in crate::control) fn start_with_followers(
        &mut self,
        first: QueuedDatagram,
        followers: Vec<QueuedDatagram>,
    ) -> io::Result<()> {
        self.start
            .take()
            .ok_or_else(|| io::Error::other("UDP endpoint driver start already consumed"))?
            .send(UdpDriverStart { first, followers })
            .map_err(|_| io::Error::other("UDP endpoint driver exited before first send"))
    }

    pub(in crate::control) async fn wait_first_ack(&mut self) -> io::Result<()> {
        self.first_ack
            .take()
            .ok_or_else(|| io::Error::other("UDP endpoint driver first ack already consumed"))?
            .await
            .map_err(|_| io::Error::other("UDP endpoint driver exited before first send"))?
    }

    #[cfg(test)]
    pub(super) fn abort(&self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub(super) fn score_driver_outcome(
    endpoint: &UdpEndpoint,
    result: &io::Result<()>,
) -> ScoreOutcome {
    if endpoint.dead.load(Ordering::Acquire) {
        return if endpoint.has_reply() {
            ScoreOutcome::Success
        } else {
            ScoreOutcome::Cancelled
        };
    }
    if let Err(error) = result
        && matches!(
            honk_outbound::proxy::packet_error_class(error),
            honk_outbound::proxy::PacketErrorClass::Rejected
        )
    {
        return ScoreOutcome::from_io_error(error);
    }
    if let Err(error) = result
        && is_local_reply_error(error)
    {
        return ScoreOutcome::Cancelled;
    }
    if endpoint.quic_path_stalled() {
        return ScoreOutcome::NodeFailure;
    }
    match result {
        Ok(()) => ScoreOutcome::Success,
        Err(error)
            if matches!(
                honk_outbound::proxy::packet_error_class(error),
                honk_outbound::proxy::PacketErrorClass::Congestion
            ) =>
        {
            ScoreOutcome::Cancelled
        }
        Err(error) if is_reply_idle_timeout(error) => {
            if endpoint.has_reply() {
                ScoreOutcome::Success
            } else {
                ScoreOutcome::Timeout
            }
        }
        Err(error) => ScoreOutcome::from_io_error(error),
    }
}

#[cfg(feature = "native-api")]
impl UdpEndpoint {
    fn finish_native_driver(&self, result: &io::Result<()>) {
        #[cfg(feature = "rprx")]
        if let EndpointTransport::Source(source) = &self.transport
            && let Some(retirement) = source.score_retirement()
        {
            self.finish_native_source(retirement);
            return;
        }
        let outcome = if self.dead.load(Ordering::Acquire) {
            UdpTerminal::IntentionalRetirement
        } else {
            match result {
                Err(error) if is_reply_idle_timeout(error) => {
                    if self.has_reply() {
                        UdpTerminal::ReplyIdle
                    } else if self.native.received_reply() {
                        UdpTerminal::TimeoutAfterReply
                    } else {
                        UdpTerminal::TimeoutBeforeReply
                    }
                }
                Err(error) => match honk_outbound::proxy::packet_error_class(error) {
                    honk_outbound::proxy::PacketErrorClass::Rejected => UdpTerminal::PacketRejected,
                    honk_outbound::proxy::PacketErrorClass::Congestion => UdpTerminal::Congestion,
                    _ if error.kind() == io::ErrorKind::TimedOut => UdpTerminal::TransportTimeout,
                    _ => UdpTerminal::TransportError,
                },
                Ok(()) => UdpTerminal::DriverCompleted,
            }
        };
        self.native.finish(outcome);
    }
}

impl UdpEndpointPool {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::control) fn spawn_driver(
        self: &Arc<Self>,
        client_addr: SocketAddr,
        client_dst: SocketAddr,
        generation: u64,
        decision_token: u32,
        endpoint: Arc<UdpEndpoint>,
        queue_rx: mpsc::Receiver<QueuedDatagram>,
        reply_socket: impl Into<DriverReplySocket>,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        stats: Arc<StatsManager>,
        outbound_tracker: OutboundTracker,
    ) -> UdpDriverHandle {
        let reply_socket = reply_socket.into().into_socket();
        let key = EndpointKey::new(client_addr, client_dst);
        let (ready_tx, ready) = oneshot::channel();
        let (start, start_rx) = oneshot::channel();
        let (first_ack_tx, first_ack) = oneshot::channel();
        let pool = Arc::clone(self);
        let mut drivers = self.drivers.lock();
        while let Some(result) = drivers.tasks.try_join_next() {
            if let Err(error) = result {
                debug!("UDP endpoint driver join failed: {}", error);
            }
        }
        if drivers.closed {
            drop(ready_tx);
            drop(start_rx);
            drop(first_ack_tx);
            return UdpDriverHandle {
                ready: Some(ready),
                start: Some(start),
                first_ack: Some(first_ack),
                #[cfg(test)]
                task: None,
            };
        }
        let mut io = endpoint.retirement.0.start_driver();
        let task = drivers.tasks.spawn(async move {
            async move {
                // Construct before every await so abort and panic take the same
                // cleanup path as an ordinary driver return.
                let mut _cleanup = UdpDriverCleanupGuard::new(
                    Arc::clone(&pool),
                    key,
                    generation,
                    decision_token,
                    Arc::clone(&endpoint),
                );
                let _ = ready_tx.send(());
                let initial = match start_rx.await {
                    Ok(initial) => initial,
                    Err(_) => return,
                };
                let driver_result = run_endpoint_driver(
                    UdpDriverContext {
                        endpoint: Arc::clone(&endpoint),
                        queue_rx,
                        reply_socket,
                        reply_socket_factory: Arc::clone(&pool.reply_socket_factory),
                        reply_socket_slots: Arc::clone(&pool.reply_socket_slots),
                        client_addr,
                        client_dst,
                        alive_set,
                        stats,
                        outbound_tracker,
                        health_family: endpoint.health_family,
                    },
                    initial,
                    first_ack_tx,
                )
                .await;
                let UdpDriverResult { result, outcome } = driver_result;
                _cleanup.set_outcome(outcome);
                if let Err(error) = result {
                    debug!(
                        "UDP endpoint driver {} -> {} stopped: {}",
                        client_addr, client_dst, error
                    );
                }
            }
            .await;
            io.completed = true;
            drop(io);
        });
        drop(drivers);
        #[cfg(not(test))]
        drop(task);
        UdpDriverHandle {
            ready: Some(ready),
            start: Some(start),
            first_ack: Some(first_ack),
            #[cfg(test)]
            task: Some(task),
        }
    }
}
pub(super) async fn run_endpoint_driver(
    context: UdpDriverContext,
    initial: UdpDriverStart,
    first_ack: oneshot::Sender<io::Result<()>>,
) -> UdpDriverResult {
    let UdpDriverContext {
        endpoint,
        queue_rx,
        reply_socket,
        reply_socket_factory,
        reply_socket_slots,
        client_addr,
        client_dst,
        alive_set,
        stats,
        outbound_tracker,
        health_family,
    } = context;
    // Sniffing may have consumed later QUIC Initial fragments from the queue.
    // Send that retained prefix before the untouched receiver queue so the
    // server sees the original flight in order without waiting for a PTO.
    let UdpDriverStart { first, followers } = initial;
    let send_timeout = tokio::time::sleep(TRANSPORT_SEND_TIMEOUT);
    tokio::pin!(send_timeout);
    if let Err(failure) = send_one(
        &endpoint,
        &stats,
        &outbound_tracker,
        send_timeout.as_mut(),
        first,
        true,
    )
    .await
    {
        let neutral = matches!(
            &failure,
            PacketSendFailure::Congestion(_) | PacketSendFailure::Rejected(_)
        );
        let mut result = Err(failure.into_io_error());
        // Health reporting can synchronously retire and mark this endpoint dead.
        let outcome = score_driver_outcome(&endpoint, &result);
        #[cfg(feature = "native-api")]
        endpoint.finish_native_driver(&result);
        if !neutral && !endpoint.is_source() && !endpoint.dead.load(Ordering::Acquire) {
            alive_set.report_unavailable_traffic(
                endpoint.node_id,
                honk_outbound::alive::ProbeDomain::DataUdp,
                health_family,
            );
        }
        let _ = first_ack.send(result.as_mut().map(|_| ()).map_err(duplicate_send_error));
        return UdpDriverResult { result, outcome };
    }

    for follower in followers {
        match send_one(
            &endpoint,
            &stats,
            &outbound_tracker,
            send_timeout.as_mut(),
            follower,
            false,
        )
        .await
        {
            Ok(()) => {}
            Err(PacketSendFailure::Congestion(error)) => {
                debug!(
                    "UDP endpoint packet dropped under send congestion: {}",
                    error
                );
            }
            Err(PacketSendFailure::Rejected(error)) => {
                let mut result = Err(error);
                let outcome = score_driver_outcome(&endpoint, &result);
                #[cfg(feature = "native-api")]
                endpoint.finish_native_driver(&result);
                let _ = first_ack.send(result.as_mut().map(|_| ()).map_err(duplicate_send_error));
                return UdpDriverResult { result, outcome };
            }
            Err(PacketSendFailure::Transport(error)) => {
                let mut result = Err(error);
                let outcome = score_driver_outcome(&endpoint, &result);
                #[cfg(feature = "native-api")]
                endpoint.finish_native_driver(&result);
                if !endpoint.is_source() && !endpoint.dead.load(Ordering::Acquire) {
                    alive_set.report_unavailable_traffic(
                        endpoint.node_id,
                        honk_outbound::alive::ProbeDomain::DataUdp,
                        health_family,
                    );
                }
                let _ = first_ack.send(result.as_mut().map(|_| ()).map_err(duplicate_send_error));
                return UdpDriverResult { result, outcome };
            }
        }
    }
    let _ = first_ack.send(Ok(()));

    let result = if endpoint.is_source() {
        send_source_followers(
            Arc::clone(&endpoint),
            queue_rx,
            Arc::clone(&stats),
            outbound_tracker.clone(),
            send_timeout.as_mut(),
        )
        .await
    } else {
        let sender = send_followers(
            Arc::clone(&endpoint),
            queue_rx,
            Arc::clone(&stats),
            outbound_tracker.clone(),
            send_timeout.as_mut(),
        );
        let receiver = receive_loop(
            Arc::clone(&endpoint),
            reply_socket,
            reply_socket_factory,
            reply_socket_slots,
            client_addr,
            client_dst,
            Arc::clone(&alive_set),
            stats,
            outbound_tracker,
        );
        tokio::pin!(sender);
        tokio::pin!(receiver);
        tokio::select! {
            result = &mut sender => result,
            result = &mut receiver => result,
        }
    };
    #[cfg(feature = "native-api")]
    endpoint.finish_native_driver(&result);
    if endpoint.is_source() && result.as_ref().err().is_some_and(is_reply_idle_timeout) {
        endpoint.source_flow_idle_expired();
    }
    // Capture the score before the error-triggered death callback can retire it.
    let outcome = score_driver_outcome(&endpoint, &result);
    if let Err(error) = &result
        && !endpoint.is_source()
        && !endpoint.dead.load(Ordering::Acquire)
        && !is_local_reply_error(error)
        && !matches!(
            honk_outbound::proxy::packet_error_class(error),
            honk_outbound::proxy::PacketErrorClass::Congestion
                | honk_outbound::proxy::PacketErrorClass::Rejected
        )
        && !(is_reply_idle_timeout(error) && endpoint.has_reply())
    {
        alive_set.report_unavailable_traffic(
            endpoint.node_id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            health_family,
        );
    }
    UdpDriverResult { result, outcome }
}

async fn send_followers(
    endpoint: Arc<UdpEndpoint>,
    mut queue_rx: mpsc::Receiver<QueuedDatagram>,
    stats: Arc<StatsManager>,
    outbound_tracker: OutboundTracker,
    mut send_timeout: std::pin::Pin<&mut tokio::time::Sleep>,
) -> io::Result<()> {
    while let Some(packet) = queue_rx.recv().await {
        match send_one(
            &endpoint,
            &stats,
            &outbound_tracker,
            send_timeout.as_mut(),
            packet,
            false,
        )
        .await
        {
            Ok(()) => {}
            Err(PacketSendFailure::Congestion(error)) => {
                debug!(
                    "UDP endpoint packet dropped under send congestion: {}",
                    error
                );
            }
            Err(PacketSendFailure::Rejected(error)) => return Err(error),
            Err(PacketSendFailure::Transport(error)) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "UDP endpoint queue closed",
    ))
}

async fn send_source_followers(
    endpoint: Arc<UdpEndpoint>,
    mut queue_rx: mpsc::Receiver<QueuedDatagram>,
    stats: Arc<StatsManager>,
    outbound_tracker: OutboundTracker,
    mut send_timeout: std::pin::Pin<&mut tokio::time::Sleep>,
) -> io::Result<()> {
    let mut reply_epoch = endpoint.reply_epoch.load(Ordering::Acquire);
    let reply_idle_timeout = tokio::time::sleep(REPLY_IDLE_TIMEOUT);
    tokio::pin!(reply_idle_timeout);
    loop {
        tokio::select! {
            packet = queue_rx.recv() => {
                let Some(packet) = packet else {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "UDP endpoint queue closed",
                    ));
                };
                match send_one(
                    &endpoint,
                    &stats,
                    &outbound_tracker,
                    send_timeout.as_mut(),
                    packet,
                    false,
                ).await {
                    Ok(()) => {}
                    Err(PacketSendFailure::Congestion(error)) => {
                        debug!("UDP endpoint packet dropped under send congestion: {}", error);
                    }
                    Err(PacketSendFailure::Rejected(error))
                    | Err(PacketSendFailure::Transport(error)) => return Err(error),
                }
            }
            changed = endpoint.wait_for_reply_after(reply_epoch) => {
                reply_epoch = changed;
                reply_idle_timeout
                    .as_mut()
                    .reset(tokio::time::Instant::now() + REPLY_IDLE_TIMEOUT);
            }
            _ = reply_idle_timeout.as_mut() => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, ReplyIdleTimeout));
            }
        }
    }
}

async fn send_one(
    endpoint: &UdpEndpoint,
    stats: &StatsManager,
    outbound_tracker: &OutboundTracker,
    mut send_timeout: std::pin::Pin<&mut tokio::time::Sleep>,
    packet: QueuedDatagram,
    first: bool,
) -> Result<(), PacketSendFailure> {
    let started = first.then(Instant::now);
    if packet.expired(QUEUED_PACKET_MAX_AGE) {
        if first {
            stats.record_udp_first_send_failure();
        }
        endpoint
            .native
            .dropped("queue_expired", Some("queue_expired"));
        return Err(PacketSendFailure::Congestion(io::Error::new(
            io::ErrorKind::TimedOut,
            QUEUED_PACKET_EXPIRED,
        )));
    }
    if let Err(error) = endpoint.begin_send_attempt() {
        endpoint
            .native
            .dropped("endpoint_retired", Some("send_cancelled"));
        return Err(PacketSendFailure::Transport(error));
    }
    let attempt = endpoint.flow_transport().map(QuicSendAttempt::new);
    let source_admitted = endpoint.is_source().then(|| AtomicBool::new(false));
    let timeout = endpoint.send_timeout().max(Duration::from_millis(1));
    send_timeout
        .as_mut()
        .reset(tokio::time::Instant::now() + timeout);
    let sent = tokio::select! {
        biased;
        result = endpoint.send_packet_with_admission(&packet.data, first, source_admitted.as_ref()) => Ok(result),
        _ = send_timeout.as_mut() => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "UDP PacketTransport send timed out",
        )),
    };
    if matches!(&sent, Ok(Ok(_)))
        && !packet.data.is_empty()
        && let Some(flow) = endpoint.native.flow()
    {
        flow.accepted_send();
    }
    let timed_out = match &sent {
        Ok(Ok(_)) => false,
        Ok(Err(error)) | Err(error) => error.kind() == io::ErrorKind::TimedOut,
    };
    let endpoint_retired = endpoint.dead.load(Ordering::Acquire);
    if let Some(attempt) = attempt {
        match &sent {
            Ok(Ok(_)) if endpoint_retired => attempt.failure(),
            Ok(Ok(_)) => attempt.success(),
            Ok(Err(_)) | Err(_) if endpoint_retired => attempt.failure(),
            Ok(Err(_)) | Err(_) if timed_out => attempt.timeout(),
            Ok(Err(_)) | Err(_) => attempt.failure(),
        }
    }
    let result = if endpoint_retired {
        Err(PacketSendFailure::Transport(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "UDP endpoint retired while sending",
        )))
    } else {
        match sent {
            Ok(Ok(started_at)) => Ok(started_at),
            Ok(Err(error)) => Err(classify_send_error(endpoint, error)),
            Err(error)
                if source_admitted
                    .as_ref()
                    .is_some_and(|admitted| !admitted.load(Ordering::Acquire)) =>
            {
                Err(PacketSendFailure::Congestion(error))
            }
            Err(error) => Err(classify_send_error(endpoint, error)),
        }
    };
    if endpoint.is_source()
        && !endpoint_retired
        && let Err(PacketSendFailure::Transport(error)) = &result
    {
        endpoint.fail_source(if is_reply_idle_timeout(error) {
            ScoreOutcome::Timeout
        } else {
            ScoreOutcome::from_io_error(error)
        });
    }
    if let Some(started) = started {
        stats.record_udp_first_send_latency(started.elapsed());
    }
    match result {
        Ok(started_at) => {
            endpoint.refresh();
            endpoint.tracker_upload(packet.data.len() as u64);
            if let Some(reporter) = &endpoint.score_reporter {
                if let Some(started_at) = started_at {
                    reporter.tx_completed(packet.data.len() as u64, started_at);
                } else {
                    reporter.tx(packet.data.len() as u64);
                }
            }
            outbound_tracker.add_bytes(packet.data.len() as u64, 0);
            Ok(())
        }
        Err(failure) => {
            endpoint.native.dropped(
                if first {
                    "first_send_failed"
                } else {
                    "send_failed"
                },
                Some(match &failure {
                    PacketSendFailure::Congestion(_) => "congestion",
                    PacketSendFailure::Rejected(_) => "packet_rejected",
                    PacketSendFailure::Transport(error)
                        if error.kind() == io::ErrorKind::TimedOut =>
                    {
                        "send_timeout"
                    }
                    PacketSendFailure::Transport(_) => "transport_error",
                }),
            );
            if first {
                stats.record_udp_first_send_failure();
            }
            Err(failure)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn receive_loop(
    endpoint: Arc<UdpEndpoint>,
    reply_socket: Arc<ReplySocket>,
    reply_socket_factory: Arc<dyn UdpReplySocketFactory>,
    reply_socket_slots: Arc<Semaphore>,
    client_addr: SocketAddr,
    client_dst: SocketAddr,
    alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    stats: Arc<StatsManager>,
    outbound_tracker: OutboundTracker,
) -> io::Result<()> {
    let ipver = endpoint.health_family;
    let transport = endpoint
        .flow_transport()
        .expect("ordinary UDP receive loop requires a PacketTransport");
    // The normal fixed-target path keeps using the pre-created socket without
    // allocating. Full-cone sources populate this small endpoint-local cache.
    let mut alternate_reply_sockets = Vec::new();
    let mut buf = [0u8; 65536];
    let reply_idle_timeout = tokio::time::sleep(REPLY_IDLE_TIMEOUT);
    tokio::pin!(reply_idle_timeout);
    loop {
        reply_idle_timeout
            .as_mut()
            .reset(tokio::time::Instant::now() + REPLY_IDLE_TIMEOUT);
        let received = tokio::select! {
            biased;
            packet = transport.recv_packet(&mut buf) => Some(packet),
            _ = reply_idle_timeout.as_mut() => None,
        };
        let (n, source) = match received {
            Some(Ok(packet)) => packet,
            Some(Err(error)) => return Err(error),
            None => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, ReplyIdleTimeout));
            }
        };
        if source != endpoint.relay_addr
            && !transport.allows_full_cone_replies()
            && !endpoint.validate_reply_peer(source)
        {
            endpoint.native.dropped("unexpected_reply_peer", None);
            debug!(
                "UDP endpoint driver rejecting unexpected reply peer {}",
                source
            );
            continue;
        }
        endpoint.native.reply_received();
        // Remote DNS may choose another address or family for the same logical peer.
        let source = if endpoint.target_is_domain {
            client_dst
        } else {
            source
        };
        if source.is_ipv4() != client_addr.is_ipv4() {
            endpoint
                .native
                .dropped("reply_family_mismatch", Some("reply_family_mismatch"));
            endpoint.native.finish(UdpTerminal::ReplyFamilyMismatch);
            return Err(local_reply_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "UDP reply source {} and client {} use different address families",
                    source, client_addr
                ),
            )));
        }
        let reply_socket = if source == client_dst {
            reply_socket.as_ref()
        } else {
            let index = match alternate_reply_sockets
                .iter()
                .position(|(cached_source, _)| *cached_source == source)
            {
                Some(index) => index,
                None => {
                    if alternate_reply_sockets.len() >= MAX_REPLY_SOCKETS_PER_ENDPOINT - 1 {
                        endpoint
                            .native
                            .dropped("reply_socket_capacity", Some("capacity"));
                        endpoint.native.finish(UdpTerminal::ReplySocketCapacity);
                        return Err(local_reply_error(io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            "UDP endpoint reply-source socket cache is full",
                        )));
                    }
                    let socket = match ReplySocket::create(
                        reply_socket_factory.as_ref(),
                        &reply_socket_slots,
                        source,
                    ) {
                        Ok(socket) => socket,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            debug!("UDP reply socket capacity exhausted for {}", source);
                            endpoint
                                .native
                                .dropped("reply_socket_capacity", Some("capacity"));
                            continue;
                        }
                        Err(error) => {
                            endpoint
                                .native
                                .dropped("reply_socket_failed", Some("reply_socket_failed"));
                            endpoint.native.finish(UdpTerminal::ReplySocketFailed);
                            return Err(local_reply_error(error));
                        }
                    };
                    alternate_reply_sockets.push((source, socket));
                    alternate_reply_sockets.len() - 1
                }
            };
            &alternate_reply_sockets[index].1
        };
        let delivered = reply_socket.send_to(&buf[..n], client_addr).await;
        if delivered.is_err() {
            endpoint
                .native
                .dropped("client_delivery_failed", Some("client_send_failed"));
            endpoint.native.finish(UdpTerminal::ClientDeliveryFailed);
        }
        delivered.map_err(local_reply_error)?;
        endpoint.mark_reply();
        if let Some(elapsed) = endpoint.take_first_reply_metric() {
            stats.record_udp_first_reply_latency(elapsed);
        }
        endpoint.tracker_download(n as u64);
        endpoint.score_reply(n as u64);
        outbound_tracker.add_bytes(0, n as u64);
        if endpoint.take_alive_report_slot() {
            alive_set.report_available_traffic(
                endpoint.node_id,
                honk_outbound::alive::ProbeDomain::DataUdp,
                ipver,
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn monotonic_nanos() -> i64 {
    // Queue expiry is second-scale; the coarse clock keeps receive-batch stamping cheap.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut ts) } == 0 {
        ts.tv_sec
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec)
    } else {
        fallback_monotonic_nanos()
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn monotonic_nanos() -> i64 {
    fallback_monotonic_nanos()
}

fn fallback_monotonic_nanos() -> i64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_nanos() as i64
}

pub(super) fn nanos_from_dur(d: Duration) -> i64 {
    d.as_nanos() as i64
}
