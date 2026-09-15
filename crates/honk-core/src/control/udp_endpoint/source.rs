mod reply;
#[cfg(test)]
pub(super) use reply::SourceReplyTarget;
use reply::{SourceReplyDisposition, deliver_source_reply};

use super::driver::{REPLY_IDLE_TIMEOUT, TRANSPORT_SEND_TIMEOUT};
use super::*;
use honk_config::node::VlessUdpPath;
use honk_outbound::PacketTransport;
use honk_outbound::proxy::PreparedUdpTransport;
use honk_outbound::proxy::vless::{VLessHandler, VlessXudpTransport};
use honk_outbound::runtime::{NodeRuntime, OutboundRuntimeRegistry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ReplyProjection {
    ActualPeer,
    RewriteTo(SocketAddr),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::control) struct SourceScope {
    runtime: usize,
    client: SocketAddr,
    path: VlessUdpPath,
    reply: ReplyProjection,
}

impl SourceScope {
    pub(super) fn new(
        runtime: &Arc<NodeRuntime>,
        client: SocketAddr,
        path: VlessUdpPath,
        reply_destination: Option<SocketAddr>,
    ) -> Self {
        Self {
            runtime: Arc::as_ptr(runtime) as usize,
            client: normalize_socket_addr(client),
            path,
            reply: reply_destination
                .map(normalize_socket_addr)
                .map(ReplyProjection::RewriteTo)
                .unwrap_or(ReplyProjection::ActualPeer),
        }
    }
}

fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(addr) => addr
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(ip.into(), addr.port()))
            .unwrap_or(SocketAddr::V6(addr)),
        addr => addr,
    }
}

struct SourceState {
    admitting: bool,
    attachments: usize,
    bindings: usize,
}

pub(super) struct SourceOwner {
    id: u64,
    scope: SourceScope,
    transport: Arc<VlessXudpTransport>,
    _runtime: Arc<NodeRuntime>,
    state: Mutex<SourceState>,
    ready: AtomicBool,
    retire_notify: Notify,
    sent: AtomicBool,
    receive_started: AtomicBool,
    has_reply: AtomicBool,
    send_gate: tokio::sync::Mutex<()>,
    active_sender: AtomicU64,
    intentional_sender: AtomicU64,
    next_view: AtomicU64,
    receive_notify: Notify,
    next_alive_report_at: AtomicI64,
    pool: std::sync::Weak<UdpEndpointPool>,
    alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    node_id: uuid::Uuid,
    health_family: honk_outbound::alive::IpVersion,
    node_tracker: OutboundTracker,
    stats: Arc<StatsManager>,
    _source_permit: OwnedSemaphorePermit,
    #[cfg(test)]
    send_timeout_nanos: AtomicU64,
}

impl SourceOwner {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: u64,
        scope: SourceScope,
        transport: Arc<VlessXudpTransport>,
        runtime: Arc<NodeRuntime>,
        pool: &Arc<UdpEndpointPool>,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        node_id: uuid::Uuid,
        health_family: honk_outbound::alive::IpVersion,
        node_tracker: OutboundTracker,
        stats: Arc<StatsManager>,
        source_permit: OwnedSemaphorePermit,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            scope,
            transport,
            _runtime: runtime,
            state: Mutex::new(SourceState {
                admitting: true,
                attachments: 1,
                bindings: 0,
            }),
            ready: AtomicBool::new(true),
            retire_notify: Notify::new(),
            sent: AtomicBool::new(false),
            receive_started: AtomicBool::new(false),
            has_reply: AtomicBool::new(false),
            receive_notify: Notify::new(),
            next_alive_report_at: AtomicI64::new(0),
            pool: Arc::downgrade(pool),
            send_gate: tokio::sync::Mutex::new(()),
            active_sender: AtomicU64::new(0),
            intentional_sender: AtomicU64::new(0),
            next_view: AtomicU64::new(1),
            alive_set,
            node_id,
            health_family,
            node_tracker,
            stats,
            _source_permit: source_permit,
            #[cfg(test)]
            send_timeout_nanos: AtomicU64::new(0),
        })
    }

    fn attach(self: &Arc<Self>) -> Option<SourceAttachment> {
        let mut state = self.state.lock();
        if !state.admitting {
            return None;
        }
        state.attachments = state
            .attachments
            .checked_add(1)
            .expect("VLESS source attachment count overflow");
        Some(SourceAttachment {
            owner: Arc::clone(self),
            committed: false,
        })
    }

    fn commit_attachment(&self) -> bool {
        let mut state = self.state.lock();
        if !state.admitting {
            return false;
        }
        debug_assert_ne!(state.attachments, 0);
        state.attachments -= 1;
        state.bindings = state
            .bindings
            .checked_add(1)
            .expect("VLESS source binding count overflow");
        true
    }

    fn drop_attachment(&self) {
        let retire = {
            let mut state = self.state.lock();
            debug_assert_ne!(state.attachments, 0);
            state.attachments -= 1;
            if state.admitting && state.bindings == 0 && state.attachments == 0 {
                state.admitting = false;
                true
            } else {
                false
            }
        };
        if retire {
            self.signal_retiring();
        }
    }

    fn release_binding(&self) {
        let retire = {
            let mut state = self.state.lock();
            debug_assert_ne!(state.bindings, 0);
            state.bindings -= 1;
            if state.admitting && state.bindings == 0 {
                state.admitting = false;
                true
            } else {
                false
            }
        };
        if retire {
            self.signal_retiring();
        }
    }

    fn signal_retiring(&self) {
        self.ready.store(false, Ordering::Release);
        self.retire_notify.notify_waiters();
    }

    fn start_retiring(&self) -> bool {
        let changed = {
            let mut state = self.state.lock();
            if !state.admitting {
                false
            } else {
                state.admitting = false;
                true
            }
        };
        if changed {
            self.signal_retiring();
        }
        changed
    }

    fn start_retiring_without_reply(&self) -> bool {
        let changed = {
            let mut state = self.state.lock();
            if !state.admitting
                || !self.sent.load(Ordering::Acquire)
                || self.has_reply.load(Ordering::Acquire)
            {
                false
            } else {
                state.admitting = false;
                true
            }
        };
        if changed {
            self.signal_retiring();
        }
        changed
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    fn begin_receive(&self) {
        if !self.receive_started.swap(true, Ordering::AcqRel) {
            self.receive_notify.notify_waiters();
        }
    }

    fn note_sent(&self) {
        self.sent.store(true, Ordering::Release);
    }

    pub(super) fn fail(&self, outcome: ScoreOutcome) {
        if let Some(pool) = self.pool.upgrade() {
            pool.fail_source(self, outcome);
        }
    }
    #[cfg(test)]
    pub(super) fn set_send_timeout_for_test(&self, timeout: Duration) {
        self.send_timeout_nanos.store(
            u64::try_from(timeout.as_nanos()).expect("source test timeout fits u64 nanos"),
            Ordering::Release,
        );
    }

    fn mark_intentional_sender(&self, view: u64) {
        if self.active_sender.load(Ordering::Acquire) == view {
            self.intentional_sender.store(view, Ordering::Release);
        }
    }

    pub(super) fn handle_transport_error(&self, error: &io::Error) -> bool {
        if !honk_outbound::proxy::vless::is_vless_source_post_admission_cancel(error) {
            self.intentional_sender.store(0, Ordering::Release);
            return false;
        }
        if self.intentional_sender.swap(0, Ordering::AcqRel) == 0 {
            return false;
        }
        if let Some(pool) = self.pool.upgrade() {
            pool.retire_interrupted_source(self);
        }
        true
    }
    fn note_reply(&self) {
        let state = self.state.lock();
        if state.admitting {
            self.has_reply.store(true, Ordering::Release);
        }
    }

    fn report_available(&self) {
        let state = self.state.lock();
        if !state.admitting {
            return;
        }
        let now = monotonic_nanos();
        self.has_reply.store(true, Ordering::Release);
        if now < self.next_alive_report_at.load(Ordering::Relaxed) {
            return;
        }
        self.next_alive_report_at.store(
            now + nanos_from_dur(TRAFFIC_ALIVE_REPORT_INTERVAL),
            Ordering::Relaxed,
        );
        self.alive_set.report_available_traffic(
            self.node_id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            self.health_family,
        );
    }

    fn flow_idle_expired(&self) {
        if let Some(pool) = self.pool.upgrade()
            && self.start_retiring_without_reply()
        {
            pool.finish_source_failure(self, ScoreOutcome::Timeout);
        }
    }

    fn idle_expired(&self) {
        if let Some(pool) = self.pool.upgrade() {
            if !self.sent.load(Ordering::Acquire) {
                pool.retire_source_neutral(self, ScoreOutcome::Cancelled);
            } else if self.has_reply.load(Ordering::Acquire) {
                pool.retire_replied_source(self);
            } else {
                pool.fail_source(self, ScoreOutcome::Timeout);
            }
        }
    }
}

pub(in crate::control) struct SourceAttachment {
    owner: Arc<SourceOwner>,
    committed: bool,
}

impl SourceAttachment {
    fn commit(&mut self) -> bool {
        if self.committed || !self.owner.commit_attachment() {
            return false;
        }
        self.committed = true;
        true
    }

    #[cfg(test)]
    pub(super) fn owner(&self) -> Arc<SourceOwner> {
        Arc::clone(&self.owner)
    }
}

impl Drop for SourceAttachment {
    fn drop(&mut self) {
        if !self.committed {
            self.owner.drop_attachment();
        }
    }
}

pub(in crate::control) enum VlessSourcePreparation {
    Reused(SourceAttachment),
    Fresh {
        scope: SourceScope,
        prepared: PreparedUdpTransport<VlessXudpTransport>,
        source_permit: OwnedSemaphorePermit,
        runtime: Arc<NodeRuntime>,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        stats: Arc<StatsManager>,
        node_id: uuid::Uuid,
        node_name: String,
        health_family: honk_outbound::alive::IpVersion,
    },
}

impl VlessSourcePreparation {
    #[cfg(test)]
    pub(super) fn attached_owner(&self) -> Option<Arc<SourceOwner>> {
        match self {
            Self::Reused(attachment) => Some(attachment.owner()),
            Self::Fresh { .. } => None,
        }
    }

    pub(in crate::control) async fn commit(
        self,
        pool: &Arc<UdpEndpointPool>,
    ) -> anyhow::Result<SourceAttachment> {
        match self {
            Self::Reused(attachment) => {
                if attachment.owner.is_ready() {
                    Ok(attachment)
                } else {
                    Err(honk_outbound::proxy::PacketRejection::Cancelled.into())
                }
            }
            Self::Fresh {
                scope,
                prepared,
                source_permit,
                runtime,
                alive_set,
                stats,
                node_id,
                node_name,
                health_family,
            } => {
                let mut prepared = Some(prepared);
                let mut transport = None;
                loop {
                    if pool.terminal.load(Ordering::Acquire) {
                        return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
                    }
                    let changed = pool.source_changed.notified();
                    if let Some(owner) = pool
                        .sources
                        .get(&scope)
                        .map(|entry| Arc::clone(entry.value()))
                    {
                        if let Some(attachment) = owner.attach() {
                            return Ok(attachment);
                        }
                        changed.await;
                        continue;
                    }

                    if let Some(prepared) = prepared.take() {
                        transport = Some(prepared.commit().await?);
                    }

                    {
                        let mut tasks = pool.source_tasks.lock();
                        while let Some(result) = tasks.tasks.try_join_next() {
                            if let Err(error) = result {
                                debug!("VLESS UDP source receiver join failed: {}", error);
                            }
                        }
                        if tasks.closed || pool.terminal.load(Ordering::Acquire) {
                            return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
                        }
                        match pool.sources.entry(scope.clone()) {
                            dashmap::mapref::entry::Entry::Occupied(entry) => {
                                let owner = Arc::clone(entry.get());
                                drop(entry);
                                drop(tasks);
                                if let Some(attachment) = owner.attach() {
                                    return Ok(attachment);
                                }
                            }
                            dashmap::mapref::entry::Entry::Vacant(entry) => {
                                let owner = SourceOwner::new(
                                    pool.next_source_owner.fetch_add(1, Ordering::Relaxed),
                                    scope.clone(),
                                    transport.expect("prepared VLESS source transport"),
                                    runtime,
                                    pool,
                                    alive_set,
                                    node_id,
                                    health_family,
                                    stats.outbound_tracker(&node_name),
                                    stats,
                                    source_permit,
                                );
                                entry.insert(Arc::clone(&owner));
                                drop(tasks.tasks.spawn(run_source_receiver(
                                    Arc::clone(pool),
                                    Arc::clone(&owner),
                                )));
                                drop(tasks);
                                return Ok(SourceAttachment {
                                    owner,
                                    committed: false,
                                });
                            }
                        }
                    }
                    changed.await;
                }
            }
        }
    }
}

pub(super) struct SourceEndpoint {
    owner: Arc<SourceOwner>,
    view: u64,
    retired: AtomicBool,
    target: SocketAddr,
    target_domain: Option<Box<str>>,
    reply_socket: Arc<ReplySocket>,
    flow_tracker: OutboundTracker,
    binding: Mutex<SourceEndpointBinding>,
}

struct SourceEndpointBinding {
    attachment: Option<SourceAttachment>,
    bound: bool,
    _endpoint_permit: Option<OwnedSemaphorePermit>,
}

impl SourceEndpoint {
    pub(super) fn new(
        attachment: SourceAttachment,
        target: SocketAddr,
        target_domain: Option<&str>,
        reply_socket: Arc<ReplySocket>,
        flow_tracker: OutboundTracker,
    ) -> Self {
        let view = attachment.owner.next_view.fetch_add(1, Ordering::Relaxed);
        Self {
            owner: Arc::clone(&attachment.owner),
            view,
            retired: AtomicBool::new(false),
            target,
            target_domain: target_domain.map(Box::from),
            reply_socket,
            flow_tracker,
            binding: Mutex::new(SourceEndpointBinding {
                attachment: Some(attachment),
                bound: false,
                _endpoint_permit: None,
            }),
        }
    }

    pub(super) fn owner_id(&self) -> u64 {
        self.owner.id
    }

    #[cfg(test)]
    pub(super) fn mark_send_active_for_test(&self) {
        self.owner.active_sender.store(self.view, Ordering::Release);
    }

    pub(super) fn commit_binding(&self, endpoint_permit: OwnedSemaphorePermit) -> bool {
        let mut binding = self.binding.lock();
        let Some(attachment) = binding.attachment.as_mut() else {
            return false;
        };
        if !attachment.commit() {
            return false;
        }
        binding.attachment.take();
        binding.bound = true;
        binding._endpoint_permit = Some(endpoint_permit);
        true
    }

    pub(super) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        let mut binding = self.binding.lock();
        binding.attachment.take();
        if binding.bound {
            self.owner.mark_intentional_sender(self.view);
            binding.bound = false;
            self.owner.release_binding();
        }
    }

    pub(super) fn reply_socket(&self) -> &Arc<ReplySocket> {
        &self.reply_socket
    }

    pub(super) fn record_reply(&self, len: u64) {
        self.flow_tracker.add_bytes(0, len);
    }

    pub(super) async fn send(&self, data: &[u8], admitted: Option<&AtomicBool>) -> io::Result<()> {
        let _send = self.owner.send_gate.lock().await;
        if self.owner.transport.source_send_usable().await {
            self.owner.intentional_sender.store(0, Ordering::Release);
        }
        self.owner.active_sender.store(self.view, Ordering::Release);
        let mut active = ActiveSourceSend {
            owner: &self.owner,
            view: self.view,
            completed: false,
        };
        if self.retired.load(Ordering::Acquire) {
            active.completed = true;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "VLESS UDP flow retired before source send",
            ));
        }
        if !self.owner.is_ready() {
            active.completed = true;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "VLESS UDP source retired before send",
            ));
        }
        if !self.owner.sent.load(Ordering::Acquire) && data.is_empty() {
            active.completed = true;
            return Err(honk_outbound::proxy::PacketRejection::InvalidSize.into());
        }
        self.owner.begin_receive();
        let result = self
            .owner
            .transport
            .send_to(self.target, self.target_domain.as_deref(), data, admitted)
            .await;
        if result.is_ok() {
            // A later successful write proves a cancelled pre-admission command
            // rolled back without poisoning the shared SID.
            self.owner.intentional_sender.store(0, Ordering::Release);
            self.owner.note_sent();
        } else if let Err(error) = &result {
            self.owner.handle_transport_error(error);
        }
        active.completed = true;
        result
    }

    pub(super) fn send_timeout(&self) -> Duration {
        #[cfg(test)]
        {
            let timeout = self.owner.send_timeout_nanos.load(Ordering::Acquire);
            if timeout != 0 {
                return Duration::from_nanos(timeout);
            }
        }
        TRANSPORT_SEND_TIMEOUT
    }

    pub(super) fn fail(&self, outcome: ScoreOutcome) {
        self.owner.fail(outcome);
    }

    pub(super) fn flow_idle_expired(&self) {
        self.owner.flow_idle_expired();
    }
}

struct ActiveSourceSend<'a> {
    owner: &'a SourceOwner,
    view: u64,
    completed: bool,
}

impl Drop for ActiveSourceSend<'_> {
    fn drop(&mut self) {
        let _ = self.owner.active_sender.compare_exchange(
            self.view,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        if self.completed {
            let _ = self.owner.intentional_sender.compare_exchange(
                self.view,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

impl Drop for SourceEndpoint {
    fn drop(&mut self) {
        let binding = self.binding.get_mut();
        binding.attachment.take();
        if binding.bound {
            self.owner.mark_intentional_sender(self.view);
            binding.bound = false;
            self.owner.release_binding();
        }
    }
}

struct SourceReplyLease {
    pool: Arc<UdpEndpointPool>,
    owner: Arc<SourceOwner>,
}

impl Drop for SourceReplyLease {
    fn drop(&mut self) {
        self.owner.start_retiring();
        match self.pool.sources.entry(self.owner.scope.clone()) {
            dashmap::mapref::entry::Entry::Occupied(entry) if entry.get().id == self.owner.id => {
                entry.remove();
            }
            _ => {}
        }
        self.pool.source_changed.notify_waiters();
    }
}

async fn run_source_receiver(pool: Arc<UdpEndpointPool>, owner: Arc<SourceOwner>) {
    let _reply_lease = SourceReplyLease {
        pool: Arc::clone(&pool),
        owner: Arc::clone(&owner),
    };
    let mut buf = [0u8; 65536];
    let mut alternate_reply_sockets = Vec::new();

    loop {
        let retired = owner.retire_notify.notified();
        let receive_started = owner.receive_notify.notified();
        if !owner.is_ready() {
            return;
        }
        if owner.receive_started.load(Ordering::Acquire) {
            break;
        }
        tokio::select! {
            biased;
            _ = retired => return,
            _ = receive_started => {}
        }
    }

    let reply_idle_timeout = tokio::time::sleep(REPLY_IDLE_TIMEOUT);
    tokio::pin!(reply_idle_timeout);
    loop {
        let retired = owner.retire_notify.notified();
        if !owner.is_ready() {
            return;
        }
        tokio::select! {
            biased;
            _ = retired => return,
            packet = owner.transport.recv_packet(&mut buf) => {
                let (len, peer) = match packet {
                    Ok(packet) => packet,
                    Err(error) => {
                        if !owner.handle_transport_error(&error) {
                            owner.fail(ScoreOutcome::Io(error.kind()));
                        }
                        return;
                    }
                };
                match deliver_source_reply(
                    &pool,
                    &owner,
                    peer,
                    &buf[..len],
                    &mut alternate_reply_sockets,
                ).await {
                    SourceReplyDisposition::Delivered if owner.is_ready() => {
                        owner.report_available();
                        reply_idle_timeout
                            .as_mut()
                            .reset(tokio::time::Instant::now() + REPLY_IDLE_TIMEOUT);
                    }
                    SourceReplyDisposition::Observed if owner.is_ready() => {
                        owner.note_reply();
                        reply_idle_timeout
                            .as_mut()
                            .reset(tokio::time::Instant::now() + REPLY_IDLE_TIMEOUT);
                    }
                    SourceReplyDisposition::Delivered | SourceReplyDisposition::Observed => {}
                    SourceReplyDisposition::Drop => {}
                }
            }
            _ = reply_idle_timeout.as_mut() => {
                owner.idle_expired();
                return;
            }
        }
    }
}

impl UdpEndpointPool {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::control) async fn prepare_vless_source(
        self: &Arc<Self>,
        generation: Arc<OutboundRuntimeRegistry>,
        runtime: Arc<NodeRuntime>,
        client: SocketAddr,
        path: VlessUdpPath,
        reply_destination: Option<SocketAddr>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        stats: Arc<StatsManager>,
        health_family: honk_outbound::alive::IpVersion,
    ) -> anyhow::Result<VlessSourcePreparation> {
        let scope = SourceScope::new(&runtime, client, path, reply_destination);
        loop {
            if generation.is_shutdown() || self.terminal.load(Ordering::Acquire) {
                return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
            }
            let changed = self.source_changed.notified();
            if let Some(owner) = self
                .sources
                .get(&scope)
                .map(|entry| Arc::clone(entry.value()))
            {
                if let Some(attachment) = owner.attach() {
                    return Ok(VlessSourcePreparation::Reused(attachment));
                }
                changed.await;
                continue;
            }

            let source_permit =
                self.source_slots.clone().try_acquire_owned().map_err(|_| {
                    anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                })?;
            let global_id = runtime.vless_source_id(scope.client, path, reply_destination)?;
            let prepared = generation
                .scope_dials(VLessHandler::prepare_source_udp(
                    Arc::clone(&runtime),
                    target,
                    target_domain,
                    connect_timeout,
                    global_id,
                ))
                .await?;
            if generation.is_shutdown() {
                return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
            }
            return Ok(VlessSourcePreparation::Fresh {
                scope,
                prepared,
                source_permit,
                runtime: Arc::clone(&runtime),
                alive_set,
                stats,
                node_id: runtime.node.id,
                node_name: runtime.node.name.clone(),
                health_family,
            });
        }
    }

    fn retire_replied_source(&self, owner: &SourceOwner) {
        self.retire_source_neutral(owner, ScoreOutcome::Timeout);
    }

    fn retire_interrupted_source(&self, owner: &SourceOwner) {
        self.retire_source_neutral(owner, ScoreOutcome::Cancelled);
    }

    fn retire_source_neutral(&self, owner: &SourceOwner, no_reply: ScoreOutcome) {
        if !owner.start_retiring() {
            return;
        }
        let stale: Vec<(EndpointKey, u32, u64, Arc<UdpEndpoint>)> = self
            .endpoints
            .iter()
            .filter_map(|entry| match entry.value() {
                EndpointEntry::Ready(ready)
                    if ready.endpoint.source_owner_id() == Some(owner.id) =>
                {
                    Some((
                        *entry.key(),
                        ready.decision_token,
                        ready.generation,
                        Arc::clone(&ready.endpoint),
                    ))
                }
                _ => None,
            })
            .collect();
        for (key, token, generation, endpoint) in stale {
            endpoint.finish_score(if endpoint.has_reply() {
                ScoreOutcome::Success
            } else {
                no_reply
            });
            self.retire_if_same(key, token, generation);
        }
    }

    fn fail_source(&self, owner: &SourceOwner, outcome: ScoreOutcome) {
        if owner.start_retiring() {
            self.finish_source_failure(owner, outcome);
        }
    }

    fn finish_source_failure(&self, owner: &SourceOwner, outcome: ScoreOutcome) {
        let terminal = self.terminal.load(Ordering::Acquire);
        let outcome = if terminal {
            ScoreOutcome::Shutdown
        } else {
            outcome
        };
        let stale: Vec<(EndpointKey, u32, u64, Arc<UdpEndpoint>)> = self
            .endpoints
            .iter()
            .filter_map(|entry| match entry.value() {
                EndpointEntry::Ready(ready)
                    if ready.endpoint.source_owner_id() == Some(owner.id) =>
                {
                    Some((
                        *entry.key(),
                        ready.decision_token,
                        ready.generation,
                        Arc::clone(&ready.endpoint),
                    ))
                }
                _ => None,
            })
            .collect();
        for (_, _, _, endpoint) in &stale {
            endpoint.finish_score(outcome);
        }
        for (key, token, generation, _) in stale {
            self.retire_if_same(key, token, generation);
        }
        if !terminal {
            owner.alive_set.report_unavailable_traffic(
                owner.node_id,
                honk_outbound::alive::ProbeDomain::DataUdp,
                owner.health_family,
            );
        }
    }
}
