use super::*;

/// At most 64 datagrams, including the initializer's first packet, may be
/// retained for one flow.
pub(super) const FLOW_QUEUE_CAPACITY: usize = 64;
/// All retained payload bytes across UDP flows are bounded exactly by permits.
pub(super) const GLOBAL_PAYLOAD_CAPACITY: usize = 8 * 1024 * 1024;

/// Key for the endpoint pool: (client address, destination address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct EndpointKey {
    pub(super) client_ip: [u8; 16],
    pub(super) client_port: u16,
    pub(super) dst_ip: [u8; 16],
    pub(super) dst_port: u16,
}

impl EndpointKey {
    pub(super) fn new(client: SocketAddr, dst: SocketAddr) -> Self {
        let mut cip = [0u8; 16];
        let mut dip = [0u8; 16];
        match client.ip() {
            std::net::IpAddr::V4(ip) => {
                cip[10] = 0xff;
                cip[11] = 0xff;
                cip[12..16].copy_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => cip.copy_from_slice(&ip.octets()),
        }
        match dst.ip() {
            std::net::IpAddr::V4(ip) => {
                dip[10] = 0xff;
                dip[11] = 0xff;
                dip[12..16].copy_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => dip.copy_from_slice(&ip.octets()),
        }
        Self {
            client_ip: cip,
            client_port: client.port(),
            dst_ip: dip,
            dst_port: dst.port(),
        }
    }

    /// Convert a stored 16-byte address back to `IpAddr`, unwrapping the
    /// v4-mapped form written by `new()`.
    fn ip_addr(bytes: &[u8; 16]) -> std::net::IpAddr {
        if bytes[0..10].iter().all(|&b| b == 0) && bytes[10] == 0xff && bytes[11] == 0xff {
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[12], bytes[13], bytes[14], bytes[15],
            ))
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(*bytes))
        }
    }

    pub(super) fn client_ip(&self) -> std::net::IpAddr {
        Self::ip_addr(&self.client_ip)
    }

    pub(super) fn dst_ip(&self) -> std::net::IpAddr {
        Self::ip_addr(&self.dst_ip)
    }
}

/// One retained packet owns all permits that account for it. Socket ingress
/// acquires them before copying; owned ingress transfers its allocation only
/// after the same bounded admission succeeds.
pub(in crate::control) struct QueuedDatagram {
    pub(super) data: Bytes,
    accounting: DatagramAccounting,
}

struct DatagramAccounting {
    _flow_permit: OwnedSemaphorePermit,
    global_payload_bytes: Arc<Semaphore>,
    payload_bytes: u32,
    enqueued_at: u32,
}

impl Drop for DatagramAccounting {
    fn drop(&mut self) {
        self.global_payload_bytes
            .add_permits(self.payload_bytes as usize);
    }
}

impl QueuedDatagram {
    pub(in crate::control) fn payload(&self) -> &[u8] {
        &self.data
    }

    pub(super) fn expired(&self, max_age: Duration) -> bool {
        queue_now().wrapping_sub(self.accounting.enqueued_at) >= duration_millis(max_age)
    }

    #[cfg(test)]
    pub(super) fn age_for_test(&mut self, age: Duration) {
        self.accounting.enqueued_at = queue_now().wrapping_sub(duration_millis(age));
    }
}

fn duration_millis(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
}

pub(in crate::control) fn queue_now() -> u32 {
    // ponytail: u32 milliseconds wrap every 49 days; queued packets live for seconds.
    (monotonic_nanos() / 1_000_000) as u32
}

#[cfg(any(feature = "ebpf", test))]
fn queue_timestamp(received_at: Instant) -> u32 {
    queue_now().wrapping_sub(duration_millis(received_at.elapsed()))
}

enum DatagramPayload<'a> {
    Borrowed(&'a [u8]),
    #[cfg(any(feature = "ebpf", test))]
    Owned(Bytes),
}

impl DatagramPayload<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Borrowed(data) => data.len(),
            #[cfg(any(feature = "ebpf", test))]
            Self::Owned(data) => data.len(),
        }
    }

    fn into_bytes(self) -> Bytes {
        match self {
            Self::Borrowed(data) => Bytes::copy_from_slice(data),
            #[cfg(any(feature = "ebpf", test))]
            Self::Owned(data) => data,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketAdmissionError {
    FlowQueueFull,
    GlobalPayloadFull,
}
pub(super) struct InitializingEndpoint {
    pub(super) decision_token: u32,
    pub(super) generation: u64,
    pub(super) queue_tx: mpsc::Sender<QueuedDatagram>,
    pub(super) queue_rx: Mutex<Option<mpsc::Receiver<QueuedDatagram>>>,
    pub(super) flow_slots: Arc<Semaphore>,
    pub(super) endpoint_permit: Mutex<Option<OwnedSemaphorePermit>>,
    /// A tracker registered after route selection but before the Ready
    /// transition. It must be removed if this initialization is cancelled.
    pub(super) tracker_id: Mutex<Option<String>>,
    /// Finalized transport winner for this generation. Bound only after
    /// speculative preparation has drained, so a death callback can
    /// generation-safely retire the entry before `commit_ready` publishes Ready.
    pub(super) selected_node: Mutex<Option<uuid::Uuid>>,
    pub(super) cancelled: AtomicBool,
    pub(super) cancel_notify: Notify,
}

impl InitializingEndpoint {
    pub(super) fn take_receiver(&self) -> Option<mpsc::Receiver<QueuedDatagram>> {
        self.queue_rx.lock().take()
    }

    pub(super) fn take_endpoint_permit(&self) -> Option<OwnedSemaphorePermit> {
        self.endpoint_permit.lock().take()
    }

    pub(super) fn set_tracker_id(&self, tracker_id: String) -> bool {
        let mut current = self.tracker_id.lock();
        if current.is_some() {
            return false;
        }
        *current = Some(tracker_id);
        true
    }

    pub(super) fn take_tracker_id(&self) -> Option<String> {
        self.tracker_id.lock().take()
    }

    pub(super) fn bind_selected_node(&self, node_id: uuid::Uuid) {
        *self.selected_node.lock() = Some(node_id);
    }

    pub(super) fn clear_selected_node(&self) {
        *self.selected_node.lock() = None;
    }

    pub(super) fn selected_node_is(&self, node_id: uuid::Uuid) -> bool {
        *self.selected_node.lock() == Some(node_id)
    }

    pub(super) fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.cancel_notify.notify_waiters();
        }
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.cancel_notify.notified();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

pub(super) struct ReadyEndpoint {
    pub(super) decision_token: u32,
    pub(super) generation: u64,
    pub(super) endpoint: Arc<UdpEndpoint>,
    pub(super) queue_tx: mpsc::Sender<QueuedDatagram>,
    pub(super) flow_slots: Arc<Semaphore>,
    pub(super) _endpoint_permit: OwnedSemaphorePermit,
    pub(super) _connection_guard: Option<ActiveConnectionGuard>,
    pub(super) alive: AtomicBool,
}

pub(super) enum EndpointEntry {
    Initializing(Arc<InitializingEndpoint>),
    Ready(Arc<ReadyEndpoint>),
    Retiring { generation: u64, token: u32 },
}

impl EndpointEntry {
    pub(super) fn generation(&self) -> u64 {
        match self {
            Self::Initializing(entry) => entry.generation,
            Self::Ready(entry) => entry.generation,
            Self::Retiring { generation, .. } => *generation,
        }
    }

    pub(super) fn decision_token(&self) -> u32 {
        match self {
            Self::Initializing(entry) => entry.decision_token,
            Self::Ready(entry) => entry.decision_token,
            Self::Retiring { token, .. } => *token,
        }
    }

    pub(super) fn matches_identity(&self, generation: u64, token: u32) -> bool {
        self.generation() == generation && self.decision_token() == token
    }

    pub(super) fn retire(&self) -> Option<String> {
        match self {
            Self::Initializing(entry) => entry.take_tracker_id(),
            Self::Ready(entry) => {
                entry.alive.store(false, Ordering::Release);
                entry.endpoint.kill();
                entry.endpoint.take_tracker_id()
            }
            Self::Retiring { .. } => None,
        }
    }
}

/// Result of the synchronous reservation performed by the UDP receive loop.
/// `Initializing` owns the first packet and the slow-path permit; all other
/// variants have released the permit before returning to the receive loop.
/// The lease stays inline to avoid another allocation on every new UDP flow.
#[allow(clippy::large_enum_variant)]
pub(in crate::control) enum EndpointReservation {
    Initializing(UdpInitLease),
    Enqueued,
    CapacityRejected,
    QueueFull,
    QueueClosed,
    #[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
    IdentityMismatch,
}

#[cfg(any(feature = "ebpf", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::control) enum OwnedEnqueueError {
    IdentityMismatch,
    QueueFull,
    QueueClosed,
}

/// Owns an uncommitted Initializing incarnation. Dropping it transactionally
/// tombstones only this identity, closes followers, returns all permits, and
/// wakes reload waiters. It can never retire a newer entry for the key.
pub(in crate::control) struct UdpInitLease {
    pool: Arc<UdpEndpointPool>,
    pub(super) key: EndpointKey,
    generation: u64,
    decision_token: u32,
    /// Cancellation epoch captured while publishing this Initializing entry.
    /// `commit_ready` compares it under the pool's shared epoch gate, so a
    /// cancellation that linearizes first can never publish Ready afterwards.
    epoch: u64,
    first: Option<QueuedDatagram>,
    _slow_permit: OwnedSemaphorePermit,
    cancellation: watch::Receiver<u64>,
    initializer: Arc<InitializingEndpoint>,
    _initializer_guard: UdpInitializerGuard,
    connection_guard: Option<ActiveConnectionGuard>,
    /// The DNS controller already examined this first datagram before the
    /// lease was created. A continuation must not invoke it a second time.
    dns_checked: bool,
    committed: bool,
}

impl UdpInitLease {
    pub(in crate::control) fn client_addr(&self) -> SocketAddr {
        SocketAddr::new(self.key.client_ip(), self.key.client_port)
    }

    pub(in crate::control) fn original_dst(&self) -> SocketAddr {
        SocketAddr::new(self.key.dst_ip(), self.key.dst_port)
    }

    pub(in crate::control) fn generation(&self) -> u64 {
        self.generation
    }

    pub(in crate::control) fn decision_token(&self) -> u32 {
        self.decision_token
    }

    #[cfg(test)]
    pub(in crate::control) fn cancellation(&self) -> watch::Receiver<u64> {
        self.cancellation.clone()
    }

    pub(in crate::control) fn wait_cancellation(
        &self,
    ) -> impl Future<Output = ()> + Send + 'static {
        let mut epoch = self.cancellation.clone();
        let initializer = Arc::clone(&self.initializer);
        async move {
            tokio::select! {
                _ = epoch.changed() => {}
                _ = initializer.cancelled() => {}
            }
        }
    }

    pub(in crate::control) fn set_connection_guard(&mut self, guard: ActiveConnectionGuard) {
        debug_assert!(self.connection_guard.is_none());
        self.connection_guard = Some(guard);
    }

    pub(in crate::control) fn mark_dns_checked(&mut self) {
        self.dns_checked = true;
    }

    pub(in crate::control) fn dns_checked(&self) -> bool {
        self.dns_checked
    }

    /// Associate a tracker created after route selection with this exact
    /// Initializing incarnation. If commit never happens, `Drop` transfers it
    /// to the removal sink; Ready cleanup continues to use `UdpEndpoint`.
    pub(in crate::control) fn set_tracker_id(&self, tracker_id: String) -> bool {
        let Some(entry) = self.pool.endpoints.get(&self.key) else {
            return false;
        };
        match entry.value() {
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token =>
            {
                initializing.set_tracker_id(tracker_id)
            }
            _ => false,
        }
    }

    /// Bind the finalized transport winner (NodeId) to this Initializing
    /// generation after speculative preparation drains and before endpoint
    /// setup. Returns false when a newer generation or death/cancel path
    /// retired this entry.
    pub(in crate::control) fn bind_selected_node(&self, node_id: uuid::Uuid) -> bool {
        let _binding_gate = self.pool.node_binding_gate.lock();
        let Some(entry) = self.pool.endpoints.get(&self.key) else {
            return false;
        };
        match entry.value() {
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token =>
            {
                initializing.bind_selected_node(node_id);
                true
            }
            _ => false,
        }
    }

    /// Clear the finalized winner's binding if it becomes ineligible before
    /// endpoint setup. This generation will retire; no later candidate rebinds.
    pub(in crate::control) fn clear_selected_node(&self) {
        let Some(entry) = self.pool.endpoints.get(&self.key) else {
            return;
        };
        if let EndpointEntry::Initializing(initializing) = entry.value()
            && initializing.generation == self.generation
            && initializing.decision_token == self.decision_token
        {
            initializing.clear_selected_node();
        }
    }

    /// True while this lease still owns the map's Initializing entry. Used as
    /// the post-bind / post-dial eligibility check so a death that won the
    /// race cannot proceed to dial or application send.
    pub(in crate::control) fn still_initializing(&self) -> bool {
        let Some(entry) = self.pool.endpoints.get(&self.key) else {
            return false;
        };
        matches!(
            entry.value(),
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token
        )
    }

    pub(in crate::control) fn take_queue_receiver(&self) -> Option<mpsc::Receiver<QueuedDatagram>> {
        let entry = self.pool.endpoints.get(&self.key)?;
        match entry.value() {
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token =>
            {
                initializing.take_receiver()
            }
            _ => None,
        }
    }

    pub(in crate::control) fn first_payload(&self) -> Bytes {
        self.first
            .as_ref()
            .expect("uncommitted UDP lease must retain its first datagram")
            .data
            .clone()
    }

    pub(in crate::control) fn take_first(&mut self) -> Option<QueuedDatagram> {
        self.first.take()
    }

    /// Replace the occupied Initializing entry in place. This is deliberately
    /// not an insert-after-lookup: a cancelled/old initializer cannot publish
    /// over a newer incarnation.
    pub(in crate::control) fn commit_ready(&mut self, endpoint: Arc<UdpEndpoint>) -> bool {
        // Keep the map-entry → epoch-gate order shared with reservation. The
        // cancellation path takes only the epoch gate, so it cannot form a
        // map/gate cycle and neither guard crosses an await.
        let mut occupied = match self.pool.endpoints.entry(self.key) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => occupied,
            dashmap::mapref::entry::Entry::Vacant(_) => return false,
        };
        let _epoch_gate = self.pool.initialization_epoch.lock();
        if self.pool.terminal.load(Ordering::Acquire) || self.epoch != *_epoch_gate {
            return false;
        }
        let initializing = match occupied.get() {
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token =>
            {
                Arc::clone(initializing)
            }
            _ => return false,
        };
        let Some(endpoint_permit) = initializing.take_endpoint_permit() else {
            return false;
        };
        occupied.insert(EndpointEntry::Ready(Arc::new(ReadyEndpoint {
            generation: self.generation,
            decision_token: self.decision_token,
            endpoint,
            queue_tx: initializing.queue_tx.clone(),
            flow_slots: initializing.flow_slots.clone(),
            _endpoint_permit: endpoint_permit,
            _connection_guard: self.connection_guard.take(),
            alive: AtomicBool::new(true),
        })));
        self.committed = true;
        true
    }

    /// Retire a direct or blocked staged flow after its terminal conn_state is
    /// published. The exact tombstone prevents this tuple from being reused
    /// until the removal worker acknowledges the kernel handoff.
    #[cfg(any(feature = "ebpf", test))]
    pub(in crate::control) fn commit_kernel_handoff(&mut self) -> bool {
        let mut occupied = match self.pool.endpoints.entry(self.key) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => occupied,
            dashmap::mapref::entry::Entry::Vacant(_) => return false,
        };
        let _epoch_gate = self.pool.initialization_epoch.lock();
        if self.pool.terminal.load(Ordering::Acquire) || self.epoch != *_epoch_gate {
            return false;
        }
        if !matches!(
            occupied.get(),
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token
        ) {
            return false;
        }
        self.pool.active_retirements.fetch_add(1, Ordering::AcqRel);
        let entry = occupied.insert(EndpointEntry::Retiring {
            generation: self.generation,
            token: self.decision_token,
        });
        drop(occupied);
        let conn_id = entry.retire();
        drop(entry);
        drop(self.first.take());
        drop(self.connection_guard.take());
        self.pool.notify_removed(
            SocketAddr::new(self.key.client_ip(), self.key.client_port),
            SocketAddr::new(self.key.dst_ip(), self.key.dst_port),
            conn_id,
            RemovalReason::KernelHandoff,
            self.decision_token,
            self.generation,
        );
        self.committed = true;
        true
    }
}

impl Drop for UdpInitLease {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.first.take());
            drop(self.connection_guard.take());
            self.pool
                .retire_if_same(self.key, self.decision_token, self.generation);
        }
    }
}

struct UdpInitializerGuard {
    pool: Arc<UdpEndpointPool>,
}

#[cfg(test)]
#[derive(Debug)]
pub(super) struct ReservationPublicationHook {
    pub(super) published: Arc<std::sync::Barrier>,
    pub(super) resume: Arc<std::sync::Barrier>,
}
#[cfg(test)]
#[derive(Debug)]
pub(super) struct ReservationGateHook {
    pub(super) entered: Arc<std::sync::Barrier>,
    pub(super) resume: Arc<std::sync::Barrier>,
}

impl UdpEndpointPool {
    #[cfg(test)]
    fn pause_before_reservation_gate(&self) {
        let hook = self.reservation_gate_hook.lock().clone();
        if let Some(hook) = hook {
            hook.entered.wait();
            hook.resume.wait();
        }
    }

    #[cfg(test)]
    pub(super) fn set_reservation_gate_hook(&self, hook: Option<Arc<ReservationGateHook>>) {
        *self.reservation_gate_hook.lock() = hook;
    }
}

impl UdpInitializerGuard {
    fn new(pool: Arc<UdpEndpointPool>) -> Self {
        pool.active_initializers.fetch_add(1, Ordering::AcqRel);
        Self { pool }
    }
}

impl Drop for UdpInitializerGuard {
    fn drop(&mut self) {
        if self.pool.active_initializers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.pool.initializers_empty.notify_waiters();
        }
    }
}

impl UdpEndpointPool {
    #[cfg(test)]
    pub(super) fn set_reservation_publication_hook(
        &self,
        hook: Option<Arc<ReservationPublicationHook>>,
    ) {
        *self.reservation_publication_hook.lock() = hook;
    }

    #[cfg(test)]
    pub(super) fn pause_after_reservation_publication(&self) {
        let hook = self.reservation_publication_hook.lock().clone();
        if let Some(hook) = hook {
            hook.published.wait();
            hook.resume.wait();
        }
    }

    fn packet_accounting(
        &self,
        len: usize,
        flow_slots: &Arc<Semaphore>,
        enqueued_at: u32,
    ) -> Result<DatagramAccounting, PacketAdmissionError> {
        let flow_permit = flow_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| PacketAdmissionError::FlowQueueFull)?;
        let payload_bytes =
            u32::try_from(len).map_err(|_| PacketAdmissionError::GlobalPayloadFull)?;
        let global_payload_bytes = Arc::clone(&self.global_payload_bytes);
        if payload_bytes != 0 {
            let permit = global_payload_bytes
                .try_acquire_many(payload_bytes)
                .map_err(|_| PacketAdmissionError::GlobalPayloadFull)?;
            permit.forget();
        }
        Ok(DatagramAccounting {
            _flow_permit: flow_permit,
            global_payload_bytes,
            payload_bytes,
            enqueued_at,
        })
    }

    fn make_packet_at(
        &self,
        data: DatagramPayload<'_>,
        flow_slots: &Arc<Semaphore>,
        enqueued_at: u32,
    ) -> Result<QueuedDatagram, PacketAdmissionError> {
        let accounting = self.packet_accounting(data.len(), flow_slots, enqueued_at)?;
        Ok(QueuedDatagram {
            data: data.into_bytes(),
            accounting,
        })
    }

    fn enqueue_at(
        &self,
        sender: &mpsc::Sender<QueuedDatagram>,
        flow_slots: &Arc<Semaphore>,
        data: DatagramPayload<'_>,
        enqueued_at: u32,
        stats: &StatsManager,
    ) -> EndpointReservation {
        if sender.is_closed() {
            stats.record_udp_queue_closed();
            return EndpointReservation::QueueClosed;
        }
        let packet = match self.make_packet_at(data, flow_slots, enqueued_at) {
            Ok(packet) => packet,
            Err(PacketAdmissionError::FlowQueueFull) => {
                stats.record_udp_flow_queue_full();
                return EndpointReservation::QueueFull;
            }
            Err(PacketAdmissionError::GlobalPayloadFull) => {
                stats.record_udp_global_payload_full();
                return EndpointReservation::QueueFull;
            }
        };
        match sender.try_send(packet) {
            Ok(()) => {
                stats.record_udp_queue_accepted();
                EndpointReservation::Enqueued
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                stats.record_udp_flow_queue_full();
                EndpointReservation::QueueFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                stats.record_udp_queue_closed();
                EndpointReservation::QueueClosed
            }
        }
    }

    fn reserve_new_at(
        self: &Arc<Self>,
        vacant: dashmap::mapref::entry::VacantEntry<'_, EndpointKey, EndpointEntry>,
        data: DatagramPayload<'_>,
        decision_token: u32,
        slow_permit: OwnedSemaphorePermit,
        enqueued_at: u32,
        stats: &StatsManager,
    ) -> EndpointReservation {
        let reservation_epoch = *self.initialization_epoch.lock();
        #[cfg(test)]
        self.pause_before_reservation_gate();
        let epoch_gate = self.initialization_epoch.lock();
        if self.terminal.load(Ordering::Acquire) || reservation_epoch != *epoch_gate {
            stats.record_udp_queue_closed();
            return EndpointReservation::QueueClosed;
        }
        let cancellation = self.cancel_epoch.subscribe();
        let initializer_guard = UdpInitializerGuard::new(Arc::clone(self));
        drop(epoch_gate);
        let endpoint_permit = match self.endpoint_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                stats.record_udp_capacity_rejection();
                return EndpointReservation::CapacityRejected;
            }
        };
        let flow_slots = Arc::new(Semaphore::new(FLOW_QUEUE_CAPACITY));
        let first = match self.make_packet_at(data, &flow_slots, enqueued_at) {
            Ok(packet) => packet,
            Err(PacketAdmissionError::FlowQueueFull) => {
                stats.record_udp_flow_queue_full();
                return EndpointReservation::QueueFull;
            }
            Err(PacketAdmissionError::GlobalPayloadFull) => {
                stats.record_udp_global_payload_full();
                return EndpointReservation::QueueFull;
            }
        };
        let (queue_tx, queue_rx) = mpsc::channel(FLOW_QUEUE_CAPACITY);
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let epoch_gate = self.initialization_epoch.lock();
        if self.terminal.load(Ordering::Acquire) || reservation_epoch != *epoch_gate {
            stats.record_udp_queue_closed();
            return EndpointReservation::QueueClosed;
        }
        let epoch = *epoch_gate;
        let initializer = Arc::new(InitializingEndpoint {
            decision_token,
            generation,
            queue_tx,
            queue_rx: Mutex::new(Some(queue_rx)),
            flow_slots,
            endpoint_permit: Mutex::new(Some(endpoint_permit)),
            tracker_id: Mutex::new(None),
            selected_node: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            cancel_notify: Notify::new(),
        });
        let key = *vacant.key();
        vacant.insert(EndpointEntry::Initializing(Arc::clone(&initializer)));
        drop(epoch_gate);
        #[cfg(test)]
        self.pause_after_reservation_publication();
        EndpointReservation::Initializing(UdpInitLease {
            pool: Arc::clone(self),
            key,
            generation,
            decision_token,
            epoch,
            first: Some(first),
            _slow_permit: slow_permit,
            cancellation,
            initializer,
            _initializer_guard: initializer_guard,
            connection_guard: None,
            dns_checked: decision_token != 0,
            committed: false,
        })
    }
    #[cfg(test)]
    /// Atomically reserve a cold tuple or synchronously enqueue onto its
    /// existing Initializing/Ready incarnation. No map or std-mutex guard is
    /// held across await because this entire operation is synchronous.
    pub(in crate::control) fn reserve_or_enqueue(
        self: &Arc<Self>,
        client: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
        slow_permit: OwnedSemaphorePermit,
        stats: &StatsManager,
    ) -> EndpointReservation {
        self.reserve_or_enqueue_at(client, dst, data, slow_permit, queue_now(), stats)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::control) fn reserve_or_enqueue_at(
        self: &Arc<Self>,
        client: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
        slow_permit: OwnedSemaphorePermit,
        enqueued_at: u32,
        stats: &StatsManager,
    ) -> EndpointReservation {
        let key = EndpointKey::new(client, dst);
        loop {
            if self.terminal.load(Ordering::Acquire) {
                stats.record_udp_queue_closed();
                return EndpointReservation::QueueClosed;
            }
            match self.endpoints.entry(key) {
                dashmap::mapref::entry::Entry::Occupied(occupied) => {
                    let (stale_token, stale_generation) = match occupied.get() {
                        EndpointEntry::Initializing(initializing) => {
                            match self.enqueue_at(
                                &initializing.queue_tx,
                                &initializing.flow_slots,
                                DatagramPayload::Borrowed(data),
                                enqueued_at,
                                stats,
                            ) {
                                EndpointReservation::QueueClosed => {
                                    (initializing.decision_token, initializing.generation)
                                }
                                other => return other,
                            }
                        }
                        EndpointEntry::Ready(ready)
                            if ready.alive.load(Ordering::Acquire)
                                && !ready.endpoint.dead.load(Ordering::Acquire) =>
                        {
                            match self.enqueue_at(
                                &ready.queue_tx,
                                &ready.flow_slots,
                                DatagramPayload::Borrowed(data),
                                enqueued_at,
                                stats,
                            ) {
                                EndpointReservation::QueueClosed => {
                                    (ready.decision_token, ready.generation)
                                }
                                other => return other,
                            }
                        }
                        EndpointEntry::Ready(ready) => (ready.decision_token, ready.generation),
                        EndpointEntry::Retiring { .. } => {
                            stats.record_udp_queue_closed();
                            return EndpointReservation::QueueClosed;
                        }
                    };
                    drop(occupied);
                    self.retire_if_same(key, stale_token, stale_generation);
                }
                dashmap::mapref::entry::Entry::Vacant(vacant) => {
                    return self.reserve_new_at(
                        vacant,
                        DatagramPayload::Borrowed(data),
                        0,
                        slow_permit,
                        enqueued_at,
                        stats,
                    );
                }
            }
        }
    }

    /// Admit a retained NFQUEUE allocation without duplicating its payload.
    /// A fresh call uses `None`; followers name the exact published generation.
    #[cfg(any(feature = "ebpf", test))]
    #[allow(clippy::too_many_arguments)]
    pub(in crate::control) fn reserve_owned_or_enqueue(
        self: &Arc<Self>,
        client: SocketAddr,
        dst: SocketAddr,
        data: Bytes,
        decision_token: u32,
        expected_generation: Option<u64>,
        slow_permit: OwnedSemaphorePermit,
        stats: &StatsManager,
    ) -> EndpointReservation {
        self.reserve_owned_or_enqueue_at(
            client,
            dst,
            data,
            decision_token,
            expected_generation,
            slow_permit,
            std::time::Instant::now(),
            stats,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(any(feature = "ebpf", test))]
    pub(in crate::control) fn reserve_owned_or_enqueue_at(
        self: &Arc<Self>,
        client: SocketAddr,
        dst: SocketAddr,
        data: Bytes,
        decision_token: u32,
        expected_generation: Option<u64>,
        slow_permit: OwnedSemaphorePermit,
        enqueued_at: std::time::Instant,
        stats: &StatsManager,
    ) -> EndpointReservation {
        let enqueued_at = queue_timestamp(enqueued_at);
        if self.terminal.load(Ordering::Acquire) {
            stats.record_udp_queue_closed();
            return EndpointReservation::QueueClosed;
        }
        if decision_token == 0 {
            return EndpointReservation::IdentityMismatch;
        }

        let key = EndpointKey::new(client, dst);
        match self.endpoints.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                let Some(generation) = expected_generation else {
                    return if matches!(occupied.get(), EndpointEntry::Retiring { .. }) {
                        EndpointReservation::QueueClosed
                    } else {
                        EndpointReservation::IdentityMismatch
                    };
                };
                if !occupied.get().matches_identity(generation, decision_token) {
                    return EndpointReservation::IdentityMismatch;
                }
                match occupied.get() {
                    EndpointEntry::Initializing(initializing) => self.enqueue_at(
                        &initializing.queue_tx,
                        &initializing.flow_slots,
                        DatagramPayload::Owned(data),
                        enqueued_at,
                        stats,
                    ),
                    EndpointEntry::Ready(ready)
                        if ready.alive.load(Ordering::Acquire)
                            && !ready.endpoint.dead.load(Ordering::Acquire) =>
                    {
                        self.enqueue_at(
                            &ready.queue_tx,
                            &ready.flow_slots,
                            DatagramPayload::Owned(data),
                            enqueued_at,
                            stats,
                        )
                    }
                    EndpointEntry::Ready(_) | EndpointEntry::Retiring { .. } => {
                        stats.record_udp_queue_closed();
                        EndpointReservation::QueueClosed
                    }
                }
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                if expected_generation.is_some() {
                    return EndpointReservation::IdentityMismatch;
                }
                self.reserve_new_at(
                    vacant,
                    DatagramPayload::Owned(data),
                    decision_token,
                    slow_permit,
                    enqueued_at,
                    stats,
                )
            }
        }
    }

    /// Reconstruct an expired terminal Proxy cell from the same-token live
    /// initializer or Ready entry and return its generation with the enqueue.
    #[cfg(any(feature = "ebpf", test))]
    pub(in crate::control) fn enqueue_owned_by_token(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        data: Bytes,
        decision_token: u32,
        stats: &StatsManager,
    ) -> Result<u64, OwnedEnqueueError> {
        self.enqueue_owned_by_token_at(
            client,
            dst,
            data,
            decision_token,
            std::time::Instant::now(),
            stats,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(any(feature = "ebpf", test))]
    pub(in crate::control) fn enqueue_owned_by_token_at(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        data: Bytes,
        decision_token: u32,
        enqueued_at: std::time::Instant,
        stats: &StatsManager,
    ) -> Result<u64, OwnedEnqueueError> {
        let enqueued_at = queue_timestamp(enqueued_at);
        if decision_token == 0 {
            return Err(OwnedEnqueueError::IdentityMismatch);
        }
        if self.terminal.load(Ordering::Acquire) {
            stats.record_udp_queue_closed();
            return Err(OwnedEnqueueError::QueueClosed);
        }
        let Some(entry) = self.endpoints.get(&EndpointKey::new(client, dst)) else {
            return Err(OwnedEnqueueError::IdentityMismatch);
        };
        let (generation, result) = match entry.value() {
            EndpointEntry::Initializing(initializing)
                if initializing.decision_token == decision_token =>
            {
                (
                    initializing.generation,
                    self.enqueue_at(
                        &initializing.queue_tx,
                        &initializing.flow_slots,
                        DatagramPayload::Owned(data),
                        enqueued_at,
                        stats,
                    ),
                )
            }
            EndpointEntry::Ready(ready)
                if ready.decision_token == decision_token
                    && ready.alive.load(Ordering::Acquire)
                    && !ready.endpoint.dead.load(Ordering::Acquire) =>
            {
                (
                    ready.generation,
                    self.enqueue_at(
                        &ready.queue_tx,
                        &ready.flow_slots,
                        DatagramPayload::Owned(data),
                        enqueued_at,
                        stats,
                    ),
                )
            }
            EndpointEntry::Retiring { token, .. } if *token == decision_token => {
                stats.record_udp_queue_closed();
                return Err(OwnedEnqueueError::QueueClosed);
            }
            _ => return Err(OwnedEnqueueError::IdentityMismatch),
        };
        match result {
            EndpointReservation::Enqueued => Ok(generation),
            EndpointReservation::QueueFull => Err(OwnedEnqueueError::QueueFull),
            EndpointReservation::QueueClosed => Err(OwnedEnqueueError::QueueClosed),
            EndpointReservation::Initializing(_)
            | EndpointReservation::CapacityRejected
            | EndpointReservation::IdentityMismatch => {
                unreachable!("enqueue-by-token returned an impossible reservation")
            }
        }
    }

    /// Receive-loop fast path: only a live Ready entry may be enqueued here.
    /// Initializing followers must take the slow admission path so they
    /// acquire the bounded slow permit before any payload copy/queue work.
    /// Closed entries are tombstoned by exact identity and reject the packet;
    /// the tuple remains fenced until the removal worker acknowledges cleanup.
    /// Terminal shutdown returns `QueueClosed` directly
    /// so the listener drops the datagram instead of attempting slow admission.
    #[cfg(test)]
    pub(in crate::control) fn fast_path_enqueue(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
        stats: &StatsManager,
    ) -> Option<EndpointReservation> {
        self.fast_path_enqueue_at(client, dst, data, queue_now(), stats)
    }

    pub(in crate::control) fn fast_path_enqueue_at(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
        enqueued_at: u32,
        stats: &StatsManager,
    ) -> Option<EndpointReservation> {
        if self.terminal.load(Ordering::Acquire) {
            stats.record_udp_queue_closed();
            return Some(EndpointReservation::QueueClosed);
        }
        let key = EndpointKey::new(client, dst);
        let entry = self.endpoints.get(&key)?;
        let (result, identity) = match entry.value() {
            EndpointEntry::Initializing(_) => return None,
            EndpointEntry::Ready(ready)
                if ready.alive.load(Ordering::Acquire)
                    && !ready.endpoint.dead.load(Ordering::Acquire) =>
            {
                (
                    self.enqueue_at(
                        &ready.queue_tx,
                        &ready.flow_slots,
                        DatagramPayload::Borrowed(data),
                        enqueued_at,
                        stats,
                    ),
                    (ready.decision_token, ready.generation),
                )
            }
            EndpointEntry::Ready(ready) => (
                EndpointReservation::QueueClosed,
                (ready.decision_token, ready.generation),
            ),
            EndpointEntry::Retiring { .. } => {
                stats.record_udp_queue_closed();
                return Some(EndpointReservation::QueueClosed);
            }
        };
        drop(entry);
        if matches!(result, EndpointReservation::QueueClosed) {
            self.retire_if_same(key, identity.0, identity.1);
        }
        Some(result)
    }

    #[cfg(test)]
    pub(in crate::control) fn get(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
    ) -> Option<Arc<UdpEndpoint>> {
        let entry = self.endpoints.get(&EndpointKey::new(client, dst))?;
        match entry.value() {
            EndpointEntry::Ready(ready)
                if ready.alive.load(Ordering::Acquire)
                    && !ready.endpoint.dead.load(Ordering::Acquire) =>
            {
                Some(Arc::clone(&ready.endpoint))
            }
            _ => None,
        }
    }

    pub(super) fn advance_initialization_epoch(&self, terminal: bool) {
        // This synchronous gate is the cancellation linearization point. It
        // is shared with reservation publication and commit_ready, and is
        // released before waiting for leases to drop.
        let next = {
            let mut epoch = self.initialization_epoch.lock();
            if terminal {
                self.terminal.store(true, Ordering::Release);
            }
            *epoch = epoch
                .checked_add(1)
                .expect("UDP initializer epoch overflow");
            self.cancel_epoch.send_replace(*epoch);
            *epoch
        };
        debug_assert_ne!(next, 0);
    }

    pub(super) async fn wait_for_initializers(&self) -> bool {
        let wait = async {
            loop {
                if self.active_initializers.load(Ordering::Acquire) == 0 {
                    return;
                }
                let notified = self.initializers_empty.notified();
                if self.active_initializers.load(Ordering::Acquire) == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .is_ok()
    }

    pub(in crate::control) fn spawn_slow_path<F>(&self, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut tasks = self.slow_tasks.lock();
        while let Some(result) = tasks.tasks.try_join_next() {
            if let Err(error) = result
                && !error.is_cancelled()
            {
                debug!("UDP slow-path task join failed: {}", error);
            }
        }
        if tasks.closed {
            return false;
        }
        drop(tasks.tasks.spawn(future));
        true
    }

    pub(in crate::control) async fn cancel_initializers_and_wait(&self) -> bool {
        self.advance_initialization_epoch(false);
        self.wait_for_initializers().await
    }
}
