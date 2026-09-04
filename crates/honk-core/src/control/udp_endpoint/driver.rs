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

impl PacketSendFailure {
    fn into_io_error(self) -> io::Error {
        match self {
            Self::Congestion(error) => io::Error::new(io::ErrorKind::WouldBlock, error),
            Self::Transport(error) => error,
        }
    }
}

fn classify_send_error(
    transport: &dyn honk_outbound::proxy::PacketTransport,
    error: io::Error,
) -> PacketSendFailure {
    if matches!(
        honk_outbound::proxy::packet_error_class(&error),
        honk_outbound::proxy::PacketErrorClass::Congestion
    ) || (error.kind() == io::ErrorKind::TimedOut && transport.send_timeout_is_congestion())
    {
        PacketSendFailure::Congestion(error)
    } else {
        PacketSendFailure::Transport(error)
    }
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

async fn drain_registered_tasks(tasks: &mut tokio::task::JoinSet<()>, label: &str) -> bool {
    let mut clean = true;
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            clean = false;
            debug!("UDP {} task join failed during shutdown: {}", label, error);
        }
    }
    clean
}

pub(super) async fn join_registered_tasks(
    mut tasks: tokio::task::JoinSet<()>,
    label: &str,
    graceful_timeout: Duration,
    abort_first: bool,
) -> bool {
    if abort_first {
        tasks.abort_all();
    }
    match tokio::time::timeout(
        if abort_first {
            DRIVER_ABORT_TIMEOUT
        } else {
            graceful_timeout
        },
        drain_registered_tasks(&mut tasks, label),
    )
    .await
    {
        Ok(clean) => clean,
        Err(_) => {
            debug!(
                "Forcing cancellation of UDP {} tasks during shutdown",
                label
            );
            tasks.abort_all();
            tokio::time::timeout(
                DRIVER_ABORT_TIMEOUT,
                drain_registered_tasks(&mut tasks, label),
            )
            .await
            .unwrap_or_else(|_| {
                debug!("Timed out joining aborted UDP {} tasks", label);
                false
            })
        }
    }
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

pub(super) struct UdpDriverContext {
    pub(super) endpoint: Arc<UdpEndpoint>,
    pub(super) queue_rx: mpsc::Receiver<QueuedDatagram>,
    pub(super) reply_socket: Arc<UdpSocket>,
    pub(super) reply_socket_factory: Arc<dyn UdpReplySocketFactory>,
    pub(super) client_addr: SocketAddr,
    pub(super) client_dst: SocketAddr,
    pub(super) alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    pub(super) stats: Arc<StatsManager>,
    pub(super) outbound_tracker: OutboundTracker,
    pub(super) health_family: honk_outbound::alive::IpVersion,
}

impl Drop for UdpDriverCleanupGuard {
    fn drop(&mut self) {
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
    if endpoint.proxy_socket.quic_path_stalled() {
        return ScoreOutcome::Timeout;
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
        Err(error) => ScoreOutcome::Io(error.kind()),
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
        reply_socket: Arc<UdpSocket>,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        stats: Arc<StatsManager>,
        outbound_name: String,
    ) -> UdpDriverHandle {
        let key = EndpointKey::new(client_addr, client_dst);
        let outbound_tracker = stats.outbound_tracker(&outbound_name);
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
        let task = drivers.tasks.spawn(async move {
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
            let result = run_endpoint_driver(
                UdpDriverContext {
                    endpoint: Arc::clone(&endpoint),
                    queue_rx,
                    reply_socket,
                    reply_socket_factory: Arc::clone(&pool.reply_socket_factory),
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
            _cleanup.set_outcome(score_driver_outcome(&endpoint, &result));
            if let Err(error) = result {
                debug!(
                    "UDP endpoint driver {} -> {} stopped: {}",
                    client_addr, client_dst, error
                );
            }
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
) -> io::Result<()> {
    let UdpDriverContext {
        endpoint,
        queue_rx,
        reply_socket,
        reply_socket_factory,
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
        let congested = matches!(&failure, PacketSendFailure::Congestion(_));
        let error = failure.into_io_error();
        if !congested && !endpoint.dead.load(Ordering::Acquire) {
            alive_set.report_unavailable_traffic(
                endpoint.node_id,
                honk_outbound::alive::ProbeDomain::DataUdp,
                health_family,
            );
        }
        let _ = first_ack.send(Err(io::Error::new(error.kind(), error.to_string())));
        return Err(error);
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
            Err(PacketSendFailure::Transport(error)) => {
                if !endpoint.dead.load(Ordering::Acquire) {
                    alive_set.report_unavailable_traffic(
                        endpoint.node_id,
                        honk_outbound::alive::ProbeDomain::DataUdp,
                        health_family,
                    );
                }
                let _ = first_ack.send(Err(io::Error::new(error.kind(), error.to_string())));
                return Err(error);
            }
        }
    }
    let _ = first_ack.send(Ok(()));

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
        client_addr,
        client_dst,
        Arc::clone(&alive_set),
        stats,
        outbound_tracker,
    );
    tokio::pin!(sender);
    tokio::pin!(receiver);
    let result = tokio::select! {
        result = &mut sender => result,
        result = &mut receiver => result,
    };
    if let Err(error) = &result
        && !endpoint.dead.load(Ordering::Acquire)
        && !matches!(
            honk_outbound::proxy::packet_error_class(error),
            honk_outbound::proxy::PacketErrorClass::Congestion
        )
        && !(is_reply_idle_timeout(error) && endpoint.has_reply())
    {
        alive_set.report_unavailable_traffic(
            endpoint.node_id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            health_family,
        );
    }
    result
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
            Err(PacketSendFailure::Transport(error)) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "UDP endpoint queue closed",
    ))
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
        return Err(PacketSendFailure::Congestion(io::Error::new(
            io::ErrorKind::TimedOut,
            QUEUED_PACKET_EXPIRED,
        )));
    }
    endpoint
        .begin_send_attempt()
        .map_err(PacketSendFailure::Transport)?;
    let transport = endpoint.proxy_socket.as_ref();
    let attempt = QuicSendAttempt::new(transport);
    let timeout = transport.send_timeout().max(Duration::from_millis(1));
    send_timeout
        .as_mut()
        .reset(tokio::time::Instant::now() + timeout);
    let sent = tokio::select! {
        biased;
        result = async {
            if first {
                transport.send_packet_confirmed(&packet.data).await
            } else {
                transport.send_packet(&packet.data).await
            }
        } => Ok(result),
        _ = send_timeout.as_mut() => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "UDP PacketTransport send timed out",
        )),
    };
    let timed_out = match &sent {
        Ok(Ok(())) => false,
        Ok(Err(error)) | Err(error) => error.kind() == io::ErrorKind::TimedOut,
    };
    let endpoint_retired = endpoint.dead.load(Ordering::Acquire);
    match &sent {
        Ok(Ok(())) if endpoint_retired => attempt.failure(),
        Ok(Ok(())) => attempt.success(),
        Ok(Err(_)) | Err(_) if endpoint_retired => attempt.failure(),
        Ok(Err(_)) | Err(_) if timed_out => attempt.timeout(),
        Ok(Err(_)) | Err(_) => attempt.failure(),
    };
    let result = if endpoint_retired {
        Err(PacketSendFailure::Transport(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "UDP endpoint retired while sending",
        )))
    } else {
        match sent {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(classify_send_error(transport, error)),
            Err(error) => Err(classify_send_error(transport, error)),
        }
    };
    if let Some(started) = started {
        stats.record_udp_first_send_latency(started.elapsed());
    }
    match result {
        Ok(()) => {
            endpoint.refresh();
            endpoint.tracker_upload(packet.data.len() as u64);
            outbound_tracker.add_bytes(packet.data.len() as u64, 0);
            Ok(())
        }
        Err(failure) => {
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
    reply_socket: Arc<UdpSocket>,
    reply_socket_factory: Arc<dyn UdpReplySocketFactory>,
    client_addr: SocketAddr,
    client_dst: SocketAddr,
    alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    stats: Arc<StatsManager>,
    outbound_tracker: OutboundTracker,
) -> io::Result<()> {
    let ipver = endpoint.health_family;
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
            packet = endpoint.proxy_socket.recv_packet(&mut buf) => Some(packet),
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
            && !endpoint.proxy_socket.allows_full_cone_replies()
            && !endpoint.validate_reply_peer(source)
        {
            debug!(
                "UDP endpoint driver rejecting unexpected reply peer {}",
                source
            );
            continue;
        }
        if source.is_ipv4() != client_addr.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "UDP reply source {} and client {} use different address families",
                    source, client_addr
                ),
            ));
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
                        return Err(io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            "UDP endpoint reply-source socket cache is full",
                        ));
                    }
                    let socket = reply_socket_factory.create(source)?;
                    alternate_reply_sockets.push((source, socket));
                    alternate_reply_sockets.len() - 1
                }
            };
            &alternate_reply_sockets[index].1
        };
        reply_socket.send_to(&buf[..n], client_addr).await?;
        endpoint.mark_reply();
        if let Some(elapsed) = endpoint.take_first_reply_metric() {
            stats.record_udp_first_reply_latency(elapsed);
        }
        endpoint.tracker_download(n as u64);
        endpoint.score_first_response();
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
